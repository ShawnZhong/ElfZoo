use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::paths::Source;

pub const ELF_SCHEMA_VERSION: u32 = 1;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_CORE: u16 = 4;

const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_FLAGS: i64 = 30;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS_1: i64 = 0x6ffffffb;

const DF_1_PIE: u64 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfKind {
    WrongFormat,
    WrongMachine,
    Relocatable,
    Core,
    DynamicProgram,
    StaticProgram,
    Dso,
    LoadImage,
    MalformedImage,
    Other,
}

#[derive(Clone, Debug, Serialize)]
pub struct ElfReport {
    pub schema_version: u32,
    pub source: Source,
    pub kind: ElfKind,
    pub format: FormatReport,
    pub header: Option<EhdrReport>,
    pub program_headers: Vec<PhdrReport>,
    pub interpreter: Option<String>,
    pub dynamic: Option<DynamicReport>,
    pub role_evidence: RoleEvidence,
    pub issues: Vec<String>,
}

impl ElfReport {
    pub fn is_x86_load_candidate(&self) -> bool {
        let Some(header) = &self.header else {
            return false;
        };
        header.machine == EM_X86_64
            && matches!(header.elf_type, ET_EXEC | ET_DYN)
            && self.program_headers.iter().any(|ph| ph.p_type == PT_LOAD)
            && self.kind != ElfKind::WrongFormat
            && self.kind != ElfKind::WrongMachine
    }

    pub fn is_program_entry(&self) -> bool {
        matches!(self.kind, ElfKind::DynamicProgram | ElfKind::StaticProgram)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FormatReport {
    pub magic: bool,
    pub class: u8,
    pub class_name: String,
    pub data: u8,
    pub data_name: String,
    pub ident_version: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct EhdrReport {
    pub elf_type: u16,
    pub elf_type_name: String,
    pub machine: u16,
    pub machine_name: String,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhdrReport {
    pub index: usize,
    pub p_type: u32,
    pub p_type_name: String,
    pub flags: u32,
    pub flags_names: Vec<String>,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DynamicReport {
    pub entries: Vec<DynamicEntryReport>,
    pub terminated: bool,
    pub strtab_addr: Option<u64>,
    pub strtab_size: Option<u64>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub flags: u64,
    pub flags_1: u64,
    pub flags_1_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DynamicEntryReport {
    pub index: usize,
    pub tag: i64,
    pub tag_name: String,
    pub value: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RoleEvidence {
    pub has_pt_load: bool,
    pub has_pt_dynamic: bool,
    pub has_pt_interp: bool,
    pub entry_in_executable_load: bool,
    pub has_soname: bool,
    pub df_1_pie: bool,
}

#[derive(Clone, Copy)]
struct EhdrRaw {
    elf_type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

pub fn analyze_file(path: &Path, rel: &Path) -> Result<Option<ElfReport>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if !is_elf_bytes(&bytes) {
        return Ok(None);
    }
    let sha256 = sha256_hex(&bytes);
    let source = Source::new(rel, bytes.len() as u64, sha256);
    Ok(Some(analyze_bytes(&bytes, source)))
}

fn is_elf_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == ELF_MAGIC
}

fn analyze_bytes(bytes: &[u8], source: Source) -> ElfReport {
    let mut issues = Vec::new();

    let class = bytes.get(4).copied().unwrap_or(0);
    let data = bytes.get(5).copied().unwrap_or(0);
    let ident_version = bytes.get(6).copied().unwrap_or(0);
    let format = FormatReport {
        magic: true,
        class,
        class_name: class_name(class).to_string(),
        data,
        data_name: data_name(data).to_string(),
        ident_version,
    };

    if bytes.len() < 64 {
        issues.push(format!("ELF header is truncated: {} bytes", bytes.len()));
        return empty_report(source, format, ElfKind::WrongFormat, issues);
    }
    if class != ELFCLASS64 || data != ELFDATA2LSB || ident_version != EV_CURRENT {
        issues.push("only ELF64 little-endian EV_CURRENT files are parsed".to_string());
        return empty_report(source, format, ElfKind::WrongFormat, issues);
    }

    let Some(ehdr_raw) = parse_ehdr(bytes) else {
        issues.push("ELF header is truncated".to_string());
        return empty_report(source, format, ElfKind::WrongFormat, issues);
    };
    let header = EhdrReport {
        elf_type: ehdr_raw.elf_type,
        elf_type_name: elf_type_name(ehdr_raw.elf_type).to_string(),
        machine: ehdr_raw.machine,
        machine_name: machine_name(ehdr_raw.machine).to_string(),
        version: ehdr_raw.version,
        entry: ehdr_raw.entry,
        phoff: ehdr_raw.phoff,
        shoff: ehdr_raw.shoff,
        flags: ehdr_raw.flags,
        ehsize: ehdr_raw.ehsize,
        phentsize: ehdr_raw.phentsize,
        phnum: ehdr_raw.phnum,
        shentsize: ehdr_raw.shentsize,
        shnum: ehdr_raw.shnum,
        shstrndx: ehdr_raw.shstrndx,
    };

    if ehdr_raw.version != 1 {
        issues.push(format!(
            "e_version={} (expected EV_CURRENT=1)",
            ehdr_raw.version
        ));
    }

    if ehdr_raw.machine != EM_X86_64 {
        let mut report = report_with_header(
            source,
            format,
            ElfKind::WrongMachine,
            header,
            Vec::new(),
            None,
            None,
            RoleEvidence::default(),
            issues,
        );
        report.program_headers = parse_phdrs_lossy(bytes, ehdr_raw, &mut report.issues).0;
        return report;
    }

    if ehdr_raw.elf_type == ET_REL {
        return report_with_header(
            source,
            format,
            ElfKind::Relocatable,
            header,
            Vec::new(),
            None,
            None,
            RoleEvidence::default(),
            issues,
        );
    }
    if ehdr_raw.elf_type == ET_CORE {
        return report_with_header(
            source,
            format,
            ElfKind::Core,
            header,
            Vec::new(),
            None,
            None,
            RoleEvidence::default(),
            issues,
        );
    }

    let (phdrs, phdr_malformed) = parse_phdrs_lossy(bytes, ehdr_raw, &mut issues);
    let interpreter = read_interpreter(bytes, &phdrs, &mut issues);
    let dynamic = read_dynamic(bytes, &phdrs, &mut issues);

    let role = role_evidence(ehdr_raw, &phdrs, interpreter.is_some(), dynamic.as_ref());
    let mut critical_malformed = phdr_malformed;
    if matches!(ehdr_raw.elf_type, ET_EXEC | ET_DYN) && !role.has_pt_load {
        critical_malformed = true;
        issues.push("ET_EXEC/ET_DYN image has no PT_LOAD segment".to_string());
    }

    let kind = classify(ehdr_raw, &role, critical_malformed);

    report_with_header(
        source,
        format,
        kind,
        header,
        phdrs,
        interpreter,
        dynamic,
        role,
        issues,
    )
}

fn empty_report(
    source: Source,
    format: FormatReport,
    kind: ElfKind,
    issues: Vec<String>,
) -> ElfReport {
    ElfReport {
        schema_version: ELF_SCHEMA_VERSION,
        source,
        kind,
        format,
        header: None,
        program_headers: Vec::new(),
        interpreter: None,
        dynamic: None,
        role_evidence: RoleEvidence::default(),
        issues,
    }
}

#[allow(clippy::too_many_arguments)]
fn report_with_header(
    source: Source,
    format: FormatReport,
    kind: ElfKind,
    header: EhdrReport,
    program_headers: Vec<PhdrReport>,
    interpreter: Option<String>,
    dynamic: Option<DynamicReport>,
    role_evidence: RoleEvidence,
    issues: Vec<String>,
) -> ElfReport {
    ElfReport {
        schema_version: ELF_SCHEMA_VERSION,
        source,
        kind,
        format,
        header: Some(header),
        program_headers,
        interpreter,
        dynamic,
        role_evidence,
        issues,
    }
}

fn classify(ehdr: EhdrRaw, role: &RoleEvidence, malformed: bool) -> ElfKind {
    if malformed {
        return ElfKind::MalformedImage;
    }
    match ehdr.elf_type {
        ET_EXEC => {
            if role.has_pt_interp && role.has_pt_dynamic {
                ElfKind::DynamicProgram
            } else if role.entry_in_executable_load {
                ElfKind::StaticProgram
            } else {
                ElfKind::LoadImage
            }
        }
        ET_DYN => {
            if role.has_pt_interp && role.has_pt_dynamic {
                ElfKind::DynamicProgram
            } else if role.entry_in_executable_load && (role.df_1_pie || !role.has_soname) {
                ElfKind::StaticProgram
            } else if role.has_pt_dynamic {
                ElfKind::Dso
            } else {
                ElfKind::LoadImage
            }
        }
        _ => ElfKind::Other,
    }
}

fn role_evidence(
    ehdr: EhdrRaw,
    phdrs: &[PhdrReport],
    has_interp: bool,
    dynamic: Option<&DynamicReport>,
) -> RoleEvidence {
    let entry = ehdr.entry;
    let entry_in_executable_load = phdrs.iter().any(|ph| {
        ph.p_type == PT_LOAD
            && (ph.flags & PF_X) != 0
            && entry >= ph.vaddr
            && entry < ph.vaddr.saturating_add(ph.memsz)
    });
    let has_soname = dynamic.and_then(|dyns| dyns.soname.as_ref()).is_some();
    let df_1_pie = dynamic
        .map(|dyns| (dyns.flags_1 & DF_1_PIE) != 0)
        .unwrap_or(false);

    RoleEvidence {
        has_pt_load: phdrs.iter().any(|ph| ph.p_type == PT_LOAD),
        has_pt_dynamic: phdrs.iter().any(|ph| ph.p_type == PT_DYNAMIC),
        has_pt_interp: has_interp,
        entry_in_executable_load,
        has_soname,
        df_1_pie,
    }
}

fn parse_ehdr(bytes: &[u8]) -> Option<EhdrRaw> {
    Some(EhdrRaw {
        elf_type: u16_at(bytes, 16)?,
        machine: u16_at(bytes, 18)?,
        version: u32_at(bytes, 20)?,
        entry: u64_at(bytes, 24)?,
        phoff: u64_at(bytes, 32)?,
        shoff: u64_at(bytes, 40)?,
        flags: u32_at(bytes, 48)?,
        ehsize: u16_at(bytes, 52)?,
        phentsize: u16_at(bytes, 54)?,
        phnum: u16_at(bytes, 56)?,
        shentsize: u16_at(bytes, 58)?,
        shnum: u16_at(bytes, 60)?,
        shstrndx: u16_at(bytes, 62)?,
    })
}

fn parse_phdrs_lossy(
    bytes: &[u8],
    ehdr: EhdrRaw,
    issues: &mut Vec<String>,
) -> (Vec<PhdrReport>, bool) {
    let mut malformed = false;
    if ehdr.phnum == 0 {
        return (Vec::new(), false);
    }
    if ehdr.phentsize < 56 {
        issues.push(format!(
            "program-header entry size {} is smaller than ELF64 size 56",
            ehdr.phentsize
        ));
        return (Vec::new(), true);
    }

    let Some(table_size) = u64::from(ehdr.phentsize).checked_mul(u64::from(ehdr.phnum)) else {
        issues.push("program-header table size overflows u64".to_string());
        return (Vec::new(), true);
    };
    let Some(table_end) = ehdr.phoff.checked_add(table_size) else {
        issues.push("program-header table end overflows u64".to_string());
        return (Vec::new(), true);
    };
    if table_end > bytes.len() as u64 {
        issues.push(format!(
            "program-header table [{:#x}, {:#x}) exceeds file size {:#x}",
            ehdr.phoff,
            table_end,
            bytes.len()
        ));
        malformed = true;
    }

    let mut out = Vec::new();
    for index in 0..usize::from(ehdr.phnum) {
        let off = ehdr
            .phoff
            .saturating_add(index as u64 * u64::from(ehdr.phentsize));
        if off.saturating_add(56) > bytes.len() as u64 {
            break;
        }
        let off = off as usize;
        let p_type = u32_at(bytes, off).unwrap_or(0);
        let flags = u32_at(bytes, off + 4).unwrap_or(0);
        let ph = PhdrReport {
            index,
            p_type,
            p_type_name: phdr_type_name(p_type).to_string(),
            flags,
            flags_names: flags_names(flags),
            offset: u64_at(bytes, off + 8).unwrap_or(0),
            vaddr: u64_at(bytes, off + 16).unwrap_or(0),
            paddr: u64_at(bytes, off + 24).unwrap_or(0),
            filesz: u64_at(bytes, off + 32).unwrap_or(0),
            memsz: u64_at(bytes, off + 40).unwrap_or(0),
            align: u64_at(bytes, off + 48).unwrap_or(0),
        };
        if ph.p_type == PT_LOAD && ph.filesz > ph.memsz {
            issues.push(format!(
                "PT_LOAD[{}] has p_filesz={} > p_memsz={}",
                index, ph.filesz, ph.memsz
            ));
            malformed = true;
        }
        out.push(ph);
    }
    (out, malformed)
}

fn read_interpreter(
    bytes: &[u8],
    phdrs: &[PhdrReport],
    issues: &mut Vec<String>,
) -> Option<String> {
    let ph = phdrs.iter().find(|ph| ph.p_type == PT_INTERP)?;
    let Some(blob) = file_range(bytes, ph.offset, ph.filesz) else {
        issues.push(format!(
            "PT_INTERP range [{:#x}, +{:#x}) is outside the file",
            ph.offset, ph.filesz
        ));
        return None;
    };
    Some(trim_nul_string(blob))
}

fn read_dynamic(
    bytes: &[u8],
    phdrs: &[PhdrReport],
    issues: &mut Vec<String>,
) -> Option<DynamicReport> {
    let ph = phdrs.iter().find(|ph| ph.p_type == PT_DYNAMIC)?;
    let Some(blob) = file_range(bytes, ph.offset, ph.filesz) else {
        issues.push(format!(
            "PT_DYNAMIC range [{:#x}, +{:#x}) is outside the file",
            ph.offset, ph.filesz
        ));
        return None;
    };
    if blob.len() % 16 != 0 {
        issues.push(format!(
            "PT_DYNAMIC size {} is not a multiple of 16",
            blob.len()
        ));
    }

    let mut entries = Vec::new();
    let mut terminated = false;
    let mut strtab_addr = None;
    let mut strtab_size = None;
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut rpath_offsets = Vec::new();
    let mut runpath_offsets = Vec::new();
    let mut flags = 0;
    let mut flags_1 = 0;

    for (index, chunk) in blob.chunks_exact(16).enumerate() {
        let tag = i64::from_le_bytes(chunk[..8].try_into().unwrap());
        let value = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        entries.push(DynamicEntryReport {
            index,
            tag,
            tag_name: dyn_tag_name(tag).to_string(),
            value,
        });
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => needed_offsets.push(value),
            DT_STRTAB => strtab_addr = Some(value),
            DT_STRSZ => strtab_size = Some(value),
            DT_SONAME => soname_offset = Some(value),
            DT_RPATH => rpath_offsets.push(value),
            DT_RUNPATH => runpath_offsets.push(value),
            DT_FLAGS => flags |= value,
            DT_FLAGS_1 => flags_1 |= value,
            _ => {}
        }
    }

    let strtab = match (strtab_addr, strtab_size) {
        (Some(addr), Some(size)) => {
            let file_off = vaddr_to_file_offset(phdrs, addr, size);
            match file_off.and_then(|off| bytes.get(off..off.saturating_add(size as usize))) {
                Some(blob) => Some(blob),
                None => {
                    issues.push(format!(
                        "DT_STRTAB address {:#x} with size {} cannot be mapped to file bytes",
                        addr, size
                    ));
                    None
                }
            }
        }
        (Some(_), None) => {
            issues.push("DT_STRTAB present without DT_STRSZ".to_string());
            None
        }
        _ => None,
    };

    let read_dynstr = |off: u64| -> Option<String> {
        let tab = strtab?;
        read_cstr(tab, off as usize)
    };

    let needed = needed_offsets
        .into_iter()
        .filter_map(read_dynstr)
        .collect::<Vec<_>>();
    let soname = soname_offset.and_then(read_dynstr);
    let rpath = rpath_offsets
        .into_iter()
        .filter_map(read_dynstr)
        .collect::<Vec<_>>();
    let runpath = runpath_offsets
        .into_iter()
        .filter_map(read_dynstr)
        .collect::<Vec<_>>();

    Some(DynamicReport {
        entries,
        terminated,
        strtab_addr,
        strtab_size,
        needed,
        soname,
        rpath,
        runpath,
        flags,
        flags_1,
        flags_1_names: flags_1_names(flags_1),
    })
}

fn file_range(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    if end > bytes.len() as u64 {
        return None;
    }
    bytes.get(offset as usize..end as usize)
}

fn vaddr_to_file_offset(phdrs: &[PhdrReport], vaddr: u64, size: u64) -> Option<usize> {
    for ph in phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_mem_end = ph.vaddr.checked_add(ph.memsz)?;
        let seg_file_end = ph.vaddr.checked_add(ph.filesz)?;
        let want_end = vaddr.checked_add(size)?;
        if vaddr >= ph.vaddr && want_end <= seg_mem_end && want_end <= seg_file_end {
            let delta = vaddr.checked_sub(ph.vaddr)?;
            let file_off = ph.offset.checked_add(delta)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

fn read_cstr(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn trim_nul_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

fn class_name(value: u8) -> &'static str {
    match value {
        1 => "ELF32",
        2 => "ELF64",
        _ => "unknown",
    }
}

fn data_name(value: u8) -> &'static str {
    match value {
        1 => "little_endian",
        2 => "big_endian",
        _ => "unknown",
    }
}

fn elf_type_name(value: u16) -> &'static str {
    match value {
        0 => "ET_NONE",
        ET_REL => "ET_REL",
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        ET_CORE => "ET_CORE",
        _ => "unknown",
    }
}

fn machine_name(value: u16) -> &'static str {
    match value {
        EM_X86_64 => "EM_X86_64",
        0 => "EM_NONE",
        3 => "EM_386",
        40 => "EM_ARM",
        183 => "EM_AARCH64",
        243 => "EM_RISCV",
        _ => "unknown",
    }
}

fn phdr_type_name(value: u32) -> &'static str {
    match value {
        0 => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474_e550 => "PT_GNU_EH_FRAME",
        0x6474_e551 => "PT_GNU_STACK",
        0x6474_e552 => "PT_GNU_RELRO",
        0x6474_e553 => "PT_GNU_PROPERTY",
        _ => "unknown",
    }
}

fn dyn_tag_name(value: i64) -> &'static str {
    match value {
        DT_NULL => "DT_NULL",
        DT_NEEDED => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        DT_STRTAB => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        DT_STRSZ => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        DT_SONAME => "DT_SONAME",
        DT_RPATH => "DT_RPATH",
        16 => "DT_SYMBOLIC",
        17 => "DT_REL",
        18 => "DT_RELSZ",
        19 => "DT_RELENT",
        20 => "DT_PLTREL",
        21 => "DT_DEBUG",
        22 => "DT_TEXTREL",
        23 => "DT_JMPREL",
        DT_RUNPATH => "DT_RUNPATH",
        DT_FLAGS => "DT_FLAGS",
        DT_FLAGS_1 => "DT_FLAGS_1",
        _ => "unknown",
    }
}

fn flags_names(flags: u32) -> Vec<String> {
    let mut out = Vec::new();
    if flags & PF_R != 0 {
        out.push("PF_R".to_string());
    }
    if flags & PF_W != 0 {
        out.push("PF_W".to_string());
    }
    if flags & PF_X != 0 {
        out.push("PF_X".to_string());
    }
    out
}

fn flags_1_names(flags: u64) -> Vec<String> {
    let known = [
        (0x0000_0001, "DF_1_NOW"),
        (0x0000_0002, "DF_1_GLOBAL"),
        (0x0000_0004, "DF_1_GROUP"),
        (0x0000_0008, "DF_1_NODELETE"),
        (0x0000_0010, "DF_1_LOADFLTR"),
        (0x0000_0020, "DF_1_INITFIRST"),
        (0x0000_0040, "DF_1_NOOPEN"),
        (0x0000_0080, "DF_1_ORIGIN"),
        (0x0000_0100, "DF_1_DIRECT"),
        (0x0000_0200, "DF_1_TRANS"),
        (0x0000_0400, "DF_1_INTERPOSE"),
        (0x0000_0800, "DF_1_NODEFLIB"),
        (0x0000_1000, "DF_1_NODUMP"),
        (0x0000_2000, "DF_1_CONFALT"),
        (0x0000_4000, "DF_1_ENDFILTEE"),
        (0x0000_8000, "DF_1_DISPRELDNE"),
        (0x0001_0000, "DF_1_DISPRELPND"),
        (0x0002_0000, "DF_1_NODIRECT"),
        (0x0004_0000, "DF_1_IGNMULDEF"),
        (0x0008_0000, "DF_1_NOKSYMS"),
        (0x0010_0000, "DF_1_NOHDR"),
        (0x0020_0000, "DF_1_EDITED"),
        (0x0040_0000, "DF_1_NORELOC"),
        (0x0080_0000, "DF_1_SYMINTPOSE"),
        (0x0100_0000, "DF_1_GLOBAUDIT"),
        (0x0200_0000, "DF_1_SINGLETON"),
        (DF_1_PIE, "DF_1_PIE"),
    ];
    known
        .into_iter()
        .filter_map(|(bit, name)| {
            if flags & bit != 0 {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}
