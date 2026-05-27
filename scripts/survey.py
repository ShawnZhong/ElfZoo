#!/usr/bin/env python3
"""
Corpus-wide survey of the per-ELF llvm-readobj dumps.

Walks every corpus/analysis/**/*.json and aggregates the
distributions that matter for a loader spec:

  * ELF type / machine / OS-ABI
  * Program-header types (with PT_INTERP string resolved from the
    original ELF), PT_LOAD permission combos, PT_GNU_STACK exec bit
  * Dynamic-tag types + DT_FLAGS / DT_FLAGS_1 bits + DT_NEEDED libs,
    hash style (DT_HASH / DT_GNU_HASH / both / neither), DT_BIND_NOW,
    init/fini array sizes
  * Relocation type frequency (corpus-wide and per-arch); IFUNC /
    COPY / TLS / RELATIVE / JUMP_SLOT category counts
  * Dynamic-symbol bindings / visibilities / IFUNC count / weak-undef
  * Symbol-versioning provision and requirement
  * .note.gnu.property features
  * Build-id presence
  * Per-file top-N rankings (reloc count, NEEDED count, segment count)
  * Per-package totals (file count, reloc total, NEEDED total)

  * Spec anomalies (gabi 04 ELF header, 07 program header, plus
    DT spec): unusual ehsize / phentsize / shentsize, W+X PT_LOAD,
    p_filesz > p_memsz, executable PT_GNU_STACK, non-power-of-2
    p_align, multiple PT_PHDR / DYNAMIC / INTERP / TLS, DT_RPATH +
    DT_RUNPATH coexistence, missing hash table on dynamic ELF,
    unknown machine / unknown dyn tag, TEXTREL, empty DynamicSection,
    arch mismatch between file header and corpus path.

Writes the structured result to corpus/survey.json and prints a
Markdown summary to stdout.

Usage:
    scripts/survey.py
    scripts/survey.py --root corpus/analysis --jobs 32
    scripts/survey.py --top 30          # top-N rows in markdown
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import multiprocessing as mp
import os
import re
import struct
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


# ---- per-file extraction ----------------------------------------------------


# PT_INTERP is the loader path; for survey purposes we deduplicate it
# globally, but to limit memory we never keep more than this many
# distinct strings per file (we only ever expect one).
def _read_interp(elf_path: str, offset: int, size: int) -> str | None:
    if size <= 0 or size > 256:
        return None
    try:
        with open(elf_path, "rb") as fh:
            fh.seek(offset)
            blob = fh.read(size)
    except OSError:
        return None
    return blob.rstrip(b"\x00").decode("utf-8", "replace") or None


def _elf_src_path(analysis_path: Path) -> str:
    """Map a corpus/analysis/<rel>.json path back to the source ELF
    under corpus/unpacked/<rel>. Mirrors the layout one-for-one so it
    survives renames of the unpacked tree (no embedded path strings)."""
    s = str(analysis_path)
    for tag in ("/corpus/analysis/", "corpus/analysis/"):
        i = s.find(tag)
        if i != -1:
            head = s[:i]
            tail = s[i + len(tag):]
            if tail.endswith(".json"):
                tail = tail[:-5]
            sep = "/" if head and not head.endswith("/") else ""
            return f"{head}{sep}corpus/unpacked/{tail}" if head \
                else f"corpus/unpacked/{tail}"
    return s


def _name(field: Any) -> str:
    """llvm-readobj sometimes emits enum-ish fields as `{Name,Value}` dicts
    and sometimes as bare strings like ``"SharedObject (0x3)"``.  Normalise
    to a plain name."""
    if isinstance(field, dict):
        return field.get("Name", "")
    if isinstance(field, str):
        return field.split(" (")[0] if " (" in field else field
    return str(field)


_ISA_RANK = {
    "x86-64-baseline": 1,
    "x86-64-v2": 2,
    "x86-64-v3": 3,
    "x86-64-v4": 4,
}


def _isa_rank(name: str) -> int:
    """Order the x86-64 micro-architecture levels defined in the psABI
    supplement (gabi 16 § GNU note property)."""
    return _ISA_RANK.get(name, 0)


_VER_RE = re.compile(r"^\d+(?:\.\d+)*$")


def _parse_version_tuple(s: str) -> tuple[int, ...] | None:
    """Parse "2.34" / "1.3.7" / "4.2.0" into a comparable tuple. Returns
    None for anything that isn't pure dotted decimals (e.g. PRIVATE,
    debian-specific tags)."""
    if not s or not _VER_RE.match(s):
        return None
    try:
        return tuple(int(p) for p in s.split("."))
    except ValueError:
        return None


def extract(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as g:
            doc = json.load(g)[0]
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}", "_path": str(path)}

    hdr = doc["ElfHeader"]
    fs = doc["FileSummary"]
    # Derive the ELF source path from the analysis path —
    # FileSummary.File is only set when the dump runs, and would go
    # stale on any corpus/unpacked/ rename. Mirror the analysis tree
    # one-for-one: corpus/analysis/<rel>.json → corpus/unpacked/<rel>.
    src = _elf_src_path(path)
    arch = fs.get("Arch", "")

    out: dict[str, Any] = {
        "arch_dir": arch,
        "elf_type": _name(hdr["Type"]),
        "machine": _name(hdr["Machine"]),
        "osabi": _name(hdr["Ident"]["OS/ABI"]),
        "class": _name(hdr["Ident"]["Class"]),
        "data": _name(hdr["Ident"]["DataEncoding"]),
        "e_entry": hdr.get("Entry", 0),
        "e_ehsize": hdr.get("HeaderSize", 0),
        "e_phentsize": hdr.get("ProgramHeaderEntrySize", 0),
        "e_phnum": hdr.get("ProgramHeaderCount", 0),
        "e_shentsize": hdr.get("SectionHeaderEntrySize", 0),
        "e_shnum": hdr.get("SectionHeaderCount", 0),
        "phdr_types": Counter(),
        "phdr_perm_combos": Counter(),      # for PT_LOAD only
        "interp": None,
        "n_pt_load": 0,
        "n_pt_tls": 0,
        "n_pt_phdr": 0,
        "n_pt_interp": 0,
        "n_pt_dynamic": 0,
        "exec_stack": False,
        "tls_memsz": 0,
        "tls_align": 0,
        "dyn_tags": Counter(),
        "dyn_flags": Counter(),
        "dyn_flags_1": Counter(),
        "needed_libs": Counter(),
        "n_needed": 0,
        "runpath_count": 0,
        "rpath_count": 0,
        "init_array_sz": 0,
        "preinit_array_sz": 0,
        "fini_array_sz": 0,
        "has_dt_hash": False,
        "has_dt_gnu_hash": False,
        "has_bind_now": False,
        "has_textrel": False,
        "reloc_types": Counter(),
        "ifunc_relocs": 0,
        "copy_relocs": 0,
        "tls_relocs": 0,
        "relative_relocs": 0,
        "jump_slot_relocs": 0,
        "total_relocs": 0,
        "has_relr": False,
        "has_jmprel": False,
        "no_relocations": False,
        "sym_binding": Counter(),
        "sym_visibility": Counter(),
        "sym_type": Counter(),
        "n_dynsym": 0,
        "n_ifunc_sym": 0,
        "n_weak_undef": 0,
        "has_verdef": False,
        "has_verneed": False,
        "n_verdef": 0,
        "n_verneed_libs": 0,
        "verneed_versions": Counter(),
        "gnu_property": Counter(),
        "has_build_id": False,
        "build_id_bytes": 0,           # 16/20/32/64 for MD5/SHA1/SHA256/SHA512
        # Parsed .note.gnu.property features. Split per category so a
        # per-arch hardening-adoption histogram works.
        "cet_features": Counter(),     # IBT / SHSTK / LAM_U48 / LAM_U57
        "x86_feature2": Counter(),     # "XMM (used)", "ZMM (needed)", …
        "aarch64_features": Counter(), # "BTI" / "PAC" / …
        "x86_64_isa_level": "",        # "baseline" / "v2" / "v3" / "v4"
        "soname": None,                # DT_SONAME string, if present
        "runpath_values": [],          # raw DT_RUNPATH strings
        "rpath_values": [],            # raw DT_RPATH strings
        # PT_GNU_STACK full flag triplet (one of "RW", "RWX", "R", "RWE",
        # "absent" — captures more than just the exec-stack boolean).
        "gnu_stack_flags": "absent",
        # PT_LOAD p_align values, max BSS ratio, max memsz expansion.
        "pt_load_aligns": Counter(),
        "max_bss_ratio": 0.0,          # max (memsz-filesz)/memsz across LOAD
        # Required-version tracking. For each library mentioned in
        # VersionRequirements, keep the highest version tuple seen.
        # versioned_deps: list[(libname, version_string, version_tuple)]
        "versioned_deps": [],
        "note_types": Counter(),
        "n_segments": 0,
        "outliers": [],
        "anomalies": [],   # list[(kind, detail)] — spec deviations
        "_path": str(path),
    }

    # --- ehdr anomalies (gabi 04 § ELF Header; elfutils elflint.c
    #     check_elf_header). gabi 04 + System V gABI rev 1.0 §1-9. ---
    cls = out["class"]
    if cls == "64-bit":
        if out["e_ehsize"] not in (0, 64):
            out["anomalies"].append(("ehdr_ehsize_nonstandard",
                f"e_ehsize={out['e_ehsize']} (expected 64)"))
        if out["e_phentsize"] not in (0, 56):
            out["anomalies"].append(("ehdr_phentsize_nonstandard",
                f"e_phentsize={out['e_phentsize']} (expected 56)"))
        if out["e_shentsize"] not in (0, 64):
            out["anomalies"].append(("ehdr_shentsize_nonstandard",
                f"e_shentsize={out['e_shentsize']} (expected 64)"))
    elif cls == "32-bit":
        if out["e_ehsize"] not in (0, 52):
            out["anomalies"].append(("ehdr_ehsize_nonstandard",
                f"e_ehsize={out['e_ehsize']} (expected 52)"))
        if out["e_phentsize"] not in (0, 32):
            out["anomalies"].append(("ehdr_phentsize_nonstandard",
                f"e_phentsize={out['e_phentsize']} (expected 32)"))
        if out["e_shentsize"] not in (0, 40):
            out["anomalies"].append(("ehdr_shentsize_nonstandard",
                f"e_shentsize={out['e_shentsize']} (expected 40)"))

    # File / object version: must be EV_CURRENT (== 1).
    # gabi 04 § ELF Header (e_version, EI_VERSION).
    file_ver = hdr["Ident"].get("FileVersion", 1)
    obj_ver = hdr.get("Version", 1)
    if file_ver != 1:
        out["anomalies"].append(("ehdr_ident_version",
            f"e_ident[EI_VERSION]={file_ver} (expected EV_CURRENT=1)"))
    if obj_ver != 1:
        out["anomalies"].append(("ehdr_object_version",
            f"e_version={obj_ver} (expected EV_CURRENT=1)"))

    # Non-zero ABI version. elfutils restricts this to 0; some
    # platforms (FreeBSD) do use it, so flag only as informational.
    abi_ver = hdr["Ident"].get("ABIVersion", 0)
    if abi_ver != 0:
        out["anomalies"].append(("ehdr_nonzero_abiversion",
            f"e_ident[EI_ABIVERSION]={abi_ver}"))

    # Non-zero padding bytes in e_ident[EI_PAD..EI_NIDENT].
    # gabi 04 § ELF Identification: "These bytes are reserved and set
    # to zero".
    pad = hdr["Ident"].get("Unused", {}).get("Bytes", [])
    if any(b != 0 for b in pad):
        out["anomalies"].append(("ehdr_padding_nonzero",
            f"e_ident pad bytes = {pad}"))

    # e_type not in the spec set.
    if out["elf_type"] not in ("Relocatable", "Executable",
                                "SharedObject", "Core",
                                "Loadable proc-specific",   # ET_LOPROC..HIPROC
                                "Loadable os-specific"):
        # llvm renders unknowns as e.g. "0xfeed"; the membership above
        # covers the documented set.
        if out["elf_type"] and not out["elf_type"].startswith("0x"):
            pass  # known but unusual; don't spam
        else:
            out["anomalies"].append(("ehdr_unknown_etype",
                f"e_type={out['elf_type']!r}"))

    # Phdr / shdr count vs offset coherence. gabi 04: "If the file has
    # no program header table, e_phoff holds zero" (and dually for
    # shoff). Executable / shared object MUST have phdrs.
    phoff = hdr.get("ProgramHeaderOffset", 0)
    shoff = hdr.get("SectionHeaderOffset", 0)
    # llvm-readobj stringifies large counts; coerce.
    phnum = int(out["e_phnum"] or 0)
    shnum = int(out["e_shnum"] or 0)
    if phoff == 0 and phnum != 0:
        out["anomalies"].append(("ehdr_phoff_zero_phnum_nonzero",
            f"e_phoff=0 but e_phnum={phnum}"))
    if phoff != 0 and phnum == 0:
        out["anomalies"].append(("ehdr_phoff_nonzero_phnum_zero",
            f"e_phoff={phoff} but e_phnum=0"))
    if phoff == 0 and out["elf_type"] in ("Executable", "SharedObject"):
        out["anomalies"].append(("ehdr_exec_no_phdr",
            f"{out['elf_type']} with e_phoff=0"))
    if shoff == 0 and shnum != 0:
        out["anomalies"].append(("ehdr_shoff_zero_shnum_nonzero",
            f"e_shoff=0 but e_shnum={shnum}"))

    # --- program headers + PT_INTERP string ---
    # Known PT_* types: gabi 07 § Program Header, plus the well-known
    # GNU-specific extensions. Anything outside this set (and outside
    # the PT_LOOS..PT_HIOS / PT_LOPROC..PT_HIPROC reserved ranges)
    # is flagged as ph_unknown_type.
    KNOWN_PHTYPES = {
        "PT_NULL", "PT_LOAD", "PT_DYNAMIC", "PT_INTERP", "PT_NOTE",
        "PT_SHLIB", "PT_PHDR", "PT_TLS", "PT_NUM",
        "PT_GNU_EH_FRAME", "PT_GNU_STACK", "PT_GNU_RELRO",
        "PT_GNU_PROPERTY", "PT_GNU_MBIND_NUM", "PT_GNU_MBIND_LO",
        "PT_GNU_MBIND_HI", "PT_OPENBSD_RANDOMIZE", "PT_OPENBSD_WXNEEDED",
        "PT_OPENBSD_BOOTDATA", "PT_SUNW_EH_FRAME", "PT_SUNWBSS",
        "PT_SUNWSTACK",
    }
    interp_off = interp_sz = 0
    phs = doc.get("ProgramHeaders", [])
    out["n_segments"] = len(phs)
    n_pt_relro = 0
    n_pt_eh_frame = 0
    prev_load_vaddr = None
    load_sorted = True
    saw_load_before_interp = False
    pt_phdr_off = None
    pt_phdr_vaddr = None
    pt_phdr_memsz = None
    load_extents = []   # list[(vaddr_lo, vaddr_hi, flagset)]
    for idx, ph in enumerate(phs):
        p = ph["ProgramHeader"]
        t = _name(p["Type"])
        out["phdr_types"][t] += 1
        # The phdr type may be machine-specific (e.g. PT_RISCV_ATTRIBUTES,
        # PT_ARM_EXIDX, PT_MIPS_REGINFO, PT_AARCH64_MEMTAG_MTE); those
        # are processor-defined and not anomalies. llvm-readobj renders
        # unknown PT_* numeric values as "Unknown" or hex strings.
        if (t not in KNOWN_PHTYPES
                and not t.startswith(("PT_LOOS", "PT_HIOS",
                                      "PT_LOPROC", "PT_HIPROC",
                                      "PT_ARM", "PT_MIPS", "PT_RISCV",
                                      "PT_AARCH64", "PT_HP", "PT_IA_64",
                                      "PT_S390"))
                and (t.startswith("Unknown") or t.startswith("0x")
                     or t.startswith("PT_LO") or t.startswith("PT_HI"))):
            out["anomalies"].append(("ph_unknown_type",
                f"phdr[{idx}].p_type={t}"))

        flags = p.get("Flags", {})
        flagset = {_name(f) for f in flags.get("Flags", []) or []}
        align = p.get("Alignment", 0)
        offset = p.get("Offset", 0)
        vaddr = p.get("VirtualAddress", 0)
        filesz, memsz = p.get("FileSize", 0), p.get("MemSize", 0)
        if t == "PT_LOAD":
            out["n_pt_load"] += 1
            combo = ("R" if "PF_R" in flagset else "") + \
                    ("W" if "PF_W" in flagset else "") + \
                    ("X" if "PF_X" in flagset else "")
            out["phdr_perm_combos"][combo or "(none)"] += 1
            out["pt_load_aligns"][align] += 1
            if "PF_W" in flagset and "PF_X" in flagset:
                out["anomalies"].append(("ph_load_wx",
                    f"PT_LOAD with W+X at offset 0x{offset:x}"))
            # filesz > memsz also covered below for the general case,
            # but for LOAD it is unambiguously malformed.
            if filesz > memsz:
                out["anomalies"].append(("ph_load_filesz_gt_memsz",
                    f"p_filesz={filesz} > p_memsz={memsz}"))
            # BSS-style expansion: (memsz - filesz) / memsz. Track the
            # max ratio across this file's LOAD segments. Useful for
            # spotting binaries with huge zero-init regions.
            if memsz > 0 and memsz > filesz:
                ratio = (memsz - filesz) / memsz
                if ratio > out["max_bss_ratio"]:
                    out["max_bss_ratio"] = ratio
            # elfutils elflint.c:4609: LOAD segments must be sorted by
            # vaddr (loaders rely on this for the brk / link-map
            # placement).
            if prev_load_vaddr is not None and vaddr <= prev_load_vaddr:
                load_sorted = False
            prev_load_vaddr = vaddr
            load_extents.append((vaddr, vaddr + memsz, flagset))
        elif t == "PT_INTERP":
            interp_off, interp_sz = offset, filesz
            out["n_pt_interp"] += 1
            # elfutils elflint.c:4626: INTERP entry must precede any
            # LOAD entry (so the kernel can locate it without a full
            # phdr walk).
            if out["n_pt_load"] > 0:
                saw_load_before_interp = True
        elif t == "PT_PHDR":
            out["n_pt_phdr"] += 1
            pt_phdr_off = offset
            pt_phdr_vaddr = vaddr
            pt_phdr_memsz = memsz
        elif t == "PT_DYNAMIC":
            out["n_pt_dynamic"] += 1
        elif t == "PT_TLS":
            out["n_pt_tls"] += 1
            out["tls_memsz"] = memsz
            out["tls_align"] = align
        elif t == "PT_GNU_STACK":
            # Capture the full flag triplet, not just the exec bit, so
            # we can distinguish "absent" / "RW" (NX, normal) / "RWX"
            # (executable stack) / unusual combos.
            r = "R" if "PF_R" in flagset else ""
            w = "W" if "PF_W" in flagset else ""
            x = "X" if "PF_X" in flagset else ""
            out["gnu_stack_flags"] = (r + w + x) or "(none)"
            if "PF_X" in flagset:
                out["exec_stack"] = True
                out["anomalies"].append(("ph_exec_stack",
                    "PT_GNU_STACK has PF_X"))
        elif t == "PT_GNU_RELRO":
            n_pt_relro += 1
        elif t == "PT_GNU_EH_FRAME":
            n_pt_eh_frame += 1
            # elfutils elflint.c:4801..4823: eh_frame_hdr must be R,
            # not W, not X.
            if "PF_W" in flagset:
                out["anomalies"].append(("ph_eh_frame_writable",
                    "PT_GNU_EH_FRAME has PF_W"))
            if "PF_X" in flagset:
                out["anomalies"].append(("ph_eh_frame_executable",
                    "PT_GNU_EH_FRAME has PF_X"))
            if "PF_R" not in flagset:
                out["anomalies"].append(("ph_eh_frame_not_readable",
                    "PT_GNU_EH_FRAME missing PF_R"))

        # gabi 07: "p_align must be a positive, integral power of 2"
        # and "p_vaddr and p_offset must be congruent modulo p_align".
        if align > 1:
            if (align & (align - 1)) != 0:
                out["anomalies"].append(("ph_align_not_pow2",
                    f"{t}.p_align=0x{align:x}"))
            elif (vaddr - offset) % align != 0:
                out["anomalies"].append(("ph_offset_vaddr_misaligned",
                    f"{t}: (p_vaddr=0x{vaddr:x} - p_offset=0x{offset:x}) mod p_align=0x{align:x} != 0"))

        # General filesz>memsz (PT_NOTE excepted per elfutils 4831).
        if (t != "PT_LOAD" and t != "PT_NOTE"
                and memsz != 0 and filesz > memsz):
            out["anomalies"].append(("ph_filesz_gt_memsz",
                f"{t}: p_filesz={filesz} > p_memsz={memsz}"))

    if interp_off:
        out["interp"] = _read_interp(src, interp_off, interp_sz)

    # Cross-phdr checks (after the loop because they depend on the
    # collected LOAD extents).

    # LOAD ordering by vaddr (elfutils 4611).
    if not load_sorted:
        out["anomalies"].append(("ph_load_not_sorted",
            "PT_LOAD segments not sorted by p_vaddr"))

    # PT_INTERP must precede any PT_LOAD (elfutils 4626).
    if saw_load_before_interp:
        out["anomalies"].append(("ph_interp_after_load",
            "PT_INTERP entry preceded by a PT_LOAD"))

    # PT_PHDR coherence (elfutils 4744..4752): must be contained in
    # some PT_LOAD and its p_offset must equal e_phoff.
    if pt_phdr_off is not None:
        if phoff and pt_phdr_off != phoff:
            out["anomalies"].append(("ph_phdr_offset_mismatch",
                f"PT_PHDR.p_offset=0x{pt_phdr_off:x} != e_phoff=0x{phoff:x}"))
        if pt_phdr_vaddr is not None and load_extents:
            covered = any(lo <= pt_phdr_vaddr
                          and pt_phdr_vaddr + (pt_phdr_memsz or 0) <= hi
                          for lo, hi, _ in load_extents)
            if not covered:
                out["anomalies"].append(("ph_phdr_not_in_load",
                    "PT_PHDR not contained in any PT_LOAD"))

    # Multiplicity anomalies (gabi 07 / elfutils): at most one
    # PT_PHDR / PT_DYNAMIC / PT_INTERP / PT_TLS / PT_GNU_RELRO.
    for key, label in (("n_pt_phdr", "PT_PHDR"),
                       ("n_pt_interp", "PT_INTERP"),
                       ("n_pt_dynamic", "PT_DYNAMIC"),
                       ("n_pt_tls", "PT_TLS")):
        if out[key] > 1:
            out["anomalies"].append(("ph_multiple_" + label.lower(),
                f"{out[key]}× {label}"))
    if n_pt_relro > 1:
        out["anomalies"].append(("ph_multiple_pt_gnu_relro",
            f"{n_pt_relro}× PT_GNU_RELRO"))

    # --- dynamic section ---
    # elfutils elflint.c:1640..1968 — dependencies, mandatory tags,
    # ordering, DT_PLTREL value check.
    dyn = doc.get("DynamicSection", [])
    seen_null = False
    non_null_after_null = False
    seen_tags = Counter()           # for "more than one entry with tag X"
    has_tag: set[str] = set()       # presence set for dependency checks
    pltrel_value = None
    for e in dyn:
        t = e["Type"]
        out["dyn_tags"][t] += 1
        seen_tags[t] += 1
        has_tag.add(t)
        if seen_null and t != "NULL":
            non_null_after_null = True
        if t == "NULL":
            seen_null = True
        if t == "NEEDED":
            out["needed_libs"][e.get("Library", "?")] += 1
            out["n_needed"] += 1
        elif t == "FLAGS":
            for f in e.get("Flags", []) or []:
                out["dyn_flags"][f if isinstance(f, str) else f.get("Name", str(f))] += 1
            for f in e.get("Flags", []) or []:
                fn = f if isinstance(f, str) else f.get("Name", "")
                if fn == "BIND_NOW":
                    out["has_bind_now"] = True
        elif t == "FLAGS_1":
            for f in e.get("Flags", []) or []:
                out["dyn_flags_1"][f if isinstance(f, str) else f.get("Name", str(f))] += 1
            for f in e.get("Flags", []) or []:
                fn = f if isinstance(f, str) else f.get("Name", "")
                if fn == "NOW":
                    out["has_bind_now"] = True
        elif t == "RUNPATH":
            out["runpath_count"] += 1
            v = e.get("Path") or []
            for s in v:
                if isinstance(s, str) and s:
                    out["runpath_values"].append(s)
        elif t == "RPATH":
            out["rpath_count"] += 1
            v = e.get("Path") or []
            for s in v:
                if isinstance(s, str) and s:
                    out["rpath_values"].append(s)
        elif t == "SONAME":
            v = e.get("Name")
            if isinstance(v, str) and v:
                out["soname"] = v
        elif t == "RELR" or t == "RELRSZ" or t == "RELRENT":
            out["has_relr"] = True
        elif t == "JMPREL":
            out["has_jmprel"] = True
        elif t == "HASH":
            out["has_dt_hash"] = True
        elif t == "GNU_HASH":
            out["has_dt_gnu_hash"] = True
        elif t == "BIND_NOW":
            out["has_bind_now"] = True
        elif t == "TEXTREL":
            out["has_textrel"] = True
            out["outliers"].append(("text_relocs", str(path)))
            out["anomalies"].append(("dyn_textrel",
                "DT_TEXTREL: writable relocations in text segment"))
        elif t == "INIT_ARRAYSZ":
            out["init_array_sz"] = e.get("Value", 0)
        elif t == "PREINIT_ARRAYSZ":
            out["preinit_array_sz"] = e.get("Value", 0)
        elif t == "FINI_ARRAYSZ":
            out["fini_array_sz"] = e.get("Value", 0)
        elif t == "PLTREL":
            pltrel_value = e.get("Value")

        # Unknown dynamic tag (llvm renders these as "Unknown (0x…)" or
        # an integer fallback).
        if isinstance(t, str) and t.startswith("Unknown"):
            out["anomalies"].append(("dyn_unknown_tag", f"d_tag={t}"))

    # elfutils elflint.c:1741: "non-DT_NULL entries follow DT_NULL".
    # (NULL marks the end of the dynamic vector per gabi.)
    if non_null_after_null:
        out["anomalies"].append(("dyn_entries_after_null",
            "non-DT_NULL entries follow DT_NULL"))

    # elfutils elflint.c:1759: more than one entry with the same tag,
    # except DT_NEEDED, DT_NULL, DT_POSFLAG_1. RPATH/RUNPATH are also
    # multi-allowed in practice (binutils emits them once but spec
    # tolerates merging).
    for tag, n in seen_tags.items():
        if n > 1 and tag not in ("NEEDED", "NULL", "POSFLAG_1", "AUXILIARY", "FILTER"):
            out["anomalies"].append(("dyn_duplicate_tag",
                f"tag {tag} appears {n} times"))

    # elfutils elflint.c:1786: DT_PLTREL value must be DT_REL or DT_RELA.
    # llvm-readobj exposes this as either an int (7 / 17) or a hex string.
    if pltrel_value is not None:
        v = pltrel_value
        if isinstance(v, str):
            try:
                v = int(v, 0)
            except ValueError:
                v = -1
        if v not in (7, 17):    # DT_REL=17, DT_RELA=7
            out["anomalies"].append(("dyn_pltrel_bad_value",
                f"DT_PLTREL value={pltrel_value} (expected DT_REL=17 or DT_RELA=7)"))

    # Mandatory tags for any dynamic ELF (elfutils elflint.c:1888).
    # DT_NULL handled above implicitly; check the rest.
    if dyn and out["elf_type"] in ("SharedObject", "Executable"):
        for needed in ("STRTAB", "SYMTAB", "STRSZ", "SYMENT"):
            if needed not in has_tag:
                out["anomalies"].append(("dyn_missing_mandatory",
                    f"missing mandatory DT_{needed}"))

    # elfutils elflint.c:1873: tag-to-tag dependency requirements.
    DT_DEPS = [
        ("NEEDED",  ("STRTAB",)),
        ("PLTRELSZ", ("JMPREL",)),
        ("HASH",    ("SYMTAB",)),
        ("STRTAB",  ("STRSZ",)),
        ("SYMTAB",  ("STRTAB", "SYMENT")),
        ("RELA",    ("RELASZ", "RELAENT")),
        ("RELASZ",  ("RELA",)),
        ("RELAENT", ("RELA",)),
        ("STRSZ",   ("STRTAB",)),
        ("SYMENT",  ("SYMTAB",)),
        ("SONAME",  ("STRTAB",)),
        ("RPATH",   ("STRTAB",)),
        ("REL",     ("RELSZ", "RELENT")),
        ("RELSZ",   ("REL",)),
        ("RELENT",  ("REL",)),
        ("JMPREL",  ("PLTRELSZ", "PLTREL")),
        ("RUNPATH", ("STRTAB",)),
        ("PLTREL",  ("JMPREL",)),
        ("GNU_HASH", ("SYMTAB",)),
    ]
    if dyn:
        for needs, deps in DT_DEPS:
            if needs in has_tag:
                for dep in deps:
                    if dep not in has_tag:
                        out["anomalies"].append(("dyn_missing_dependency",
                            f"DT_{needs} present without DT_{dep}"))

    # Coexistence of DT_RPATH and DT_RUNPATH: glibc and the LSB spec
    # say DT_RPATH is ignored when DT_RUNPATH is present, but having
    # both in the same DSO is malformed (binutils refuses to emit them
    # together).
    if out["runpath_count"] and out["rpath_count"]:
        out["anomalies"].append(("dyn_rpath_and_runpath",
            "both DT_RPATH and DT_RUNPATH present"))

    # Dynamic ELF with no hash table at all → no symbol resolution
    # possible by name. Allowed only for objects nobody dlopens, but
    # surprising for a regular shared object / executable.
    if dyn and not out["has_dt_hash"] and not out["has_dt_gnu_hash"]:
        if out["elf_type"] in ("SharedObject", "Executable"):
            out["anomalies"].append(("dyn_no_hash",
                "dynamic ELF without DT_HASH or DT_GNU_HASH"))

    # elfutils elflint.c:4640: a static executable (ET_EXEC, no
    # PT_INTERP) must not have a dynamic section.
    if (out["elf_type"] == "Executable"
            and out["n_pt_interp"] == 0
            and out["n_pt_dynamic"] > 0):
        out["anomalies"].append(("dyn_static_exec_with_dynamic",
            "ET_EXEC without PT_INTERP has PT_DYNAMIC"))

    # --- relocations ---
    reloc_groups = doc.get("Relocations", [])
    if not reloc_groups:
        out["no_relocations"] = True
    for grp in reloc_groups:
        for r in grp.get("Relocs", []):
            rel = r["Relocation"]
            tn = _name(rel["Type"])
            out["reloc_types"][tn] += 1
            out["total_relocs"] += 1
            # Category counts (case-insensitive token match on type name).
            tu = tn.upper()
            if "IRELATIVE" in tu:                # R_*_IRELATIVE
                out["ifunc_relocs"] += 1
            elif "RELATIVE" in tu:               # R_*_RELATIVE
                out["relative_relocs"] += 1
            if tu.endswith("_COPY") or tu == "R_COPY":
                out["copy_relocs"] += 1
            if "JUMP_SLOT" in tu or "JMP_SLOT" in tu:
                out["jump_slot_relocs"] += 1
            if ("TLS" in tu or "TPOFF" in tu or "DTPOFF" in tu
                    or "DTPMOD" in tu or "TLSDESC" in tu):
                out["tls_relocs"] += 1

    # --- dynamic symbols ---
    dynsyms = doc.get("DynamicSymbols", [])
    out["n_dynsym"] = len(dynsyms)
    for s in dynsyms:
        sym = s["Symbol"]
        binding = _name(sym["Binding"])
        sym_type = _name(sym["Type"])
        section = _name(sym.get("Section", {})) if isinstance(sym.get("Section"), dict) else sym.get("Section", "")
        out["sym_binding"][binding] += 1
        out["sym_type"][sym_type] += 1
        for f in sym.get("Other", {}).get("Flags", []) or []:
            out["sym_visibility"][_name(f)] += 1
        if sym_type == "GNU_IFunc" or sym_type == "STT_GNU_IFUNC":
            out["n_ifunc_sym"] += 1
        if binding == "Weak" and section == "Undefined":
            out["n_weak_undef"] += 1

    # --- version info ---
    vdefs = doc.get("VersionDefinitions") or []
    if vdefs:
        out["has_verdef"] = True
        out["n_verdef"] = len(vdefs)
    for vn in doc.get("VersionRequirements", []) or []:
        dep = vn.get("Dependency", {})
        if not dep:
            continue
        out["has_verneed"] = True
        out["n_verneed_libs"] += 1
        # gabi 16 § Symbol Versioning: each Verneed records a needed
        # file (FileName, e.g. "libtiff.so.6") and a list of versions
        # required from it (Entry.Name, e.g. "LIBTIFF_4.0").
        lib = dep.get("FileName") or ""
        for entry in dep.get("Entries", []) or []:
            ent = entry.get("Entry", {})
            name = ent.get("Name", "")
            if name:
                out["verneed_versions"][name] += 1
                if "_" in name:
                    base, _, ver = name.partition("_")
                    nums = _parse_version_tuple(ver)
                    if nums:
                        out["versioned_deps"].append(
                            {"lib": lib, "verset": base,
                             "version": ver, "tuple": nums})

    # --- notes ---
    for ns in doc.get("NoteSections", []) or []:
        n = ns["NoteSection"]
        for note in n.get("Notes", []) or []:
            bid = note.get("Build ID")
            if isinstance(bid, str) and bid:
                out["has_build_id"] = True
                # Hex string; two chars per byte.
                out["build_id_bytes"] = len(bid) // 2
            # Note "Type" is e.g. "NT_GNU_BUILD_ID" or "NT_GNU_PROPERTY_TYPE_0".
            nt_type = note.get("Type")
            if nt_type:
                out["note_types"][_name(nt_type)] += 1
            props = note.get("Property")
            if isinstance(props, list):
                for p in props:
                    out["gnu_property"][p] += 1
                    if not isinstance(p, str):
                        continue
                    # llvm-readobj formats four distinct GNU-property
                    # kinds with very similar prefixes — be exact:
                    #
                    #   GNU_PROPERTY_X86_FEATURE_1_AND
                    #     → "x86 feature: IBT, SHSTK[, LAM_U48, LAM_U57]"
                    #       (CET hardening bits)
                    #   GNU_PROPERTY_X86_FEATURE_2_USED / _NEEDED
                    #     → "x86 feature used: x86, XMM, YMM, ZMM, …"
                    #     → "x86 feature needed: …"
                    #       (register-class info, *not* hardening)
                    #   GNU_PROPERTY_X86_ISA_1_USED / _NEEDED
                    #     → "x86 ISA used: x86-64-{baseline,v2,v3,v4}"
                    #     → "x86 ISA needed: …"
                    #   GNU_PROPERTY_AARCH64_FEATURE_1_AND
                    #     → "AArch64 feature: BTI[, PAC]"
                    #
                    # Match by exact head, not prefix, so the FEATURE_2
                    # strings never end up in the CET bucket.
                    head, _, tail = p.partition(":")
                    head = head.strip()
                    items = [s.strip() for s in tail.split(",") if s.strip()]
                    if not items:
                        continue
                    h = head.lower()
                    if h == "x86 feature":
                        for it in items:
                            out["cet_features"][it] += 1
                    elif h in ("x86 feature used", "x86 feature needed"):
                        suffix = "used" if h.endswith("used") else "needed"
                        for it in items:
                            out["x86_feature2"][f"{it} ({suffix})"] += 1
                    elif h in ("x86 isa used", "x86 isa needed"):
                        # Levels of the form x86-64-{baseline,v2,v3,v4}.
                        # Keep the max across used/needed as one string.
                        best = out["x86_64_isa_level"] or ""
                        for it in items:
                            if _isa_rank(it) > _isa_rank(best):
                                best = it
                        out["x86_64_isa_level"] = best
                    elif h == "aarch64 feature":
                        for it in items:
                            out["aarch64_features"][it] += 1

    # --- arch-mismatch outlier ---
    # FileSummary.Arch is set from e_machine by llvm-readobj. The corpus
    # is hard-pinned to Alpine x86_64 (see README §Scope), so any file
    # whose ELF header names a different real architecture is a
    # cross-arch artefact shipped inside an x86_64 .apk (typical
    # examples: AVR core firmware, embedded riscv toolchain testdata).
    # We ignore "unknown" e_machine values — those are Guile .go
    # bytecode, palcode, etc., already visible in the Machine histogram
    # and tracked separately via ehdr_unknown_machine.
    CORPUS_ARCH = "x86_64"
    if (arch and arch != "unknown" and arch != CORPUS_ARCH):
        msg = f"header={arch} corpus={CORPUS_ARCH}"
        out["outliers"].append(("arch_mismatch", f"{path}: {msg}"))
        out["anomalies"].append(("arch_mismatch", msg))

    if not dyn and out["elf_type"] not in ("Relocatable", "Core"):
        out["outliers"].append(("empty_dynamic", str(path)))
        out["anomalies"].append(("dyn_empty",
            f"no DynamicSection on {out['elf_type']}"))

    # llvm-readobj reports unknown e_machine via our patcher; the value
    # then comes through as a bare integer (e.g. {"Value": 36902}).
    mname = _name(hdr["Machine"])
    if mname.startswith("Unknown") or mname == "" or mname.startswith("0x"):
        msg = f"e_machine={hdr['Machine']}"
        out["outliers"].append(("unknown_machine", f"{path}: {msg}"))
        out["anomalies"].append(("ehdr_unknown_machine", msg))

    # --- 5-bucket classification (priority order; loader spec applies
    #     only to the `loadable` bucket). See README §Categories.
    out["category"] = _classify(out, path, arch, mname)

    return out


# Bucket priority: debuginfo > relocatable > other (core / unknown
# machine) > cross_arch > loadable. The first matching rule wins.
_DEBUG_PATH_SUFFIX = (".debug", ".dbg")


def _classify(out: dict[str, Any], path: Path, arch: str, mname: str) -> str:
    """Tag the ELF as loadable / debuginfo / relocatable / cross_arch /
    other. The loader spec only applies to `loadable`."""
    rel_path = str(path)
    # Separate debug objects live under /usr/lib/debug/ or end in
    # .debug / .dbg. They are never dlopened.
    if "/usr/lib/debug/" in rel_path or rel_path.endswith(_DEBUG_PATH_SUFFIX):
        return "debuginfo"
    et = out["elf_type"]
    if et == "Relocatable":
        return "relocatable"
    if et == "Core":
        return "other"
    # Unknown / bogus e_machine. Includes:
    #   - "Unknown<N>" / "0x…" — llvm-readobj failed to name e_machine
    #   - "" — no Machine.Name at all
    #   - "EM_NONE" (e_machine = 0) — Guile .go bytecode wraps itself
    #     in an ELF container with EM_NONE; same for some palcode and
    #     toolchain test artefacts. The real ELF loader never accepts
    #     EM_NONE, so these are not loader-spec material.
    if (not mname
            or mname == "EM_NONE"
            or mname.startswith("Unknown")
            or mname.startswith("0x")):
        return "other"
    # llvm-readobj reports FileSummary.Arch = "unknown" when it can't
    # map e_machine to a Triple — corroborates the EM_NONE / Unknown
    # check above and catches a few stragglers.
    if arch == "unknown":
        return "other"
    # Cross-arch object shipped inside an x86_64 .apk (AVR firmware,
    # embedded riscv toolchain testdata, …).
    CORPUS_ARCH = "x86_64"
    if arch and arch != CORPUS_ARCH:
        return "cross_arch"
    return "loadable"


# ---- reduction --------------------------------------------------------------


def _merge_counter(dst: Counter, src: dict | Counter) -> None:
    for k, v in src.items():
        dst[k] += v


def _new_agg() -> dict[str, Any]:
    """Empty aggregate over an arbitrary file set."""
    return {
        "n_files": 0,
        "elf_type": Counter(),
        "machine": Counter(),
        "osabi": Counter(),
        "class": Counter(),
        "data_encoding": Counter(),
        "phdr_types": Counter(),
        "phdr_perm_combos": Counter(),
        "interps": Counter(),
        "n_static_pie": 0,
        "n_static_exec": 0,
        "files_with_tls": 0,
        "files_with_exec_stack": 0,
        "dyn_tags": Counter(),
        "dyn_flags": Counter(),
        "dyn_flags_1": Counter(),
        "needed_libs": Counter(),
        "files_with_runpath": 0,
        "files_with_rpath": 0,
        "files_with_dt_hash": 0,
        "files_with_dt_gnu_hash": 0,
        "files_with_both_hash": 0,
        "files_with_neither_hash": 0,   # over dynamic ELFs only
        "files_with_bind_now": 0,
        "files_with_textrel": 0,
        "reloc_types": Counter(),
        "reloc_types_per_arch": {},     # arch -> Counter
        "files_with_relr": 0,
        "files_with_jmprel": 0,
        "files_with_ifunc_reloc": 0,
        "files_with_copy_reloc": 0,
        "files_with_tls_reloc": 0,
        "files_no_relocations": 0,
        "sym_binding": Counter(),
        "sym_type": Counter(),
        "sym_visibility": Counter(),
        "files_with_ifunc_sym": 0,
        "files_with_verdef": 0,
        "files_with_verneed": 0,
        "verneed_versions": Counter(),
        "gnu_property": Counter(),
        "note_types": Counter(),
        "files_with_build_id": 0,
        "build_id_size_dist": Counter(),     # bytes -> count
        "cet_adoption": Counter(),           # IBT/SHSTK/LAM_U48/LAM_U57 -> files
        "x86_feature2_dist": Counter(),      # "XMM (used)" -> files
        "aarch64_adoption": Counter(),       # BTI/PAC/… -> files
        "x86_64_isa_level_dist": Counter(),  # baseline/v2/v3/v4 -> files
        "soname_count": 0,
        "runpath_pattern_dist": Counter(),   # $ORIGIN / absolute / …
        "gnu_stack_flags_dist": Counter(),   # absent / RW / RWX / …
        "pt_load_align_dist": Counter(),     # alignment -> count
        "bss_ratio_buckets": Counter(),      # <0.1 / 0.1-0.5 / 0.5-0.9 / >0.9
        "versioned_lib_max": {},             # lib -> (verset, version_str)
        "segment_count_histogram": Counter(),
        "pt_load_count_histogram": Counter(),
        "needed_count_histogram": Counter(),
        "outliers": Counter(),
        "outlier_samples": {},
        "anomalies": Counter(),
        "anomaly_files": {},
        "pkg_n_files": Counter(),
        "pkg_total_relocs": Counter(),
        "_top_reloc": [],
        "_top_needed": [],
        "_top_segments": [],
    }


# Per-aggregate cap on (anomaly_kind, file) rows we keep in memory.
_ANOM_CAP = 200


def _classify_runpath(rp: str) -> str:
    """Bucket a DT_RUNPATH/DT_RPATH directory string for the site."""
    if "$ORIGIN" in rp or "${ORIGIN}" in rp:
        return "$ORIGIN"
    if rp.startswith("/"):
        return "absolute"
    if "/" in rp:
        return "relative-multi"
    return "relative-bare"


def _bss_bucket(ratio: float) -> str:
    if ratio <= 0.1:
        return "≤0.1"
    if ratio <= 0.5:
        return "0.1-0.5"
    if ratio <= 0.9:
        return "0.5-0.9"
    return ">0.9"


def _absorb(agg: dict[str, Any], r: dict[str, Any]) -> None:
    """Fold one per-file result into one aggregate. Pure data-plane —
    no policy on which aggregate this is."""
    agg["n_files"] += 1
    agg["elf_type"][r["elf_type"]] += 1
    agg["machine"][r["machine"]] += 1
    agg["osabi"][r["osabi"]] += 1
    agg["class"][r.get("class", "")] += 1
    agg["data_encoding"][r.get("data", "")] += 1
    _merge_counter(agg["phdr_types"], r["phdr_types"])
    _merge_counter(agg["phdr_perm_combos"], r["phdr_perm_combos"])
    if r["interp"]:
        agg["interps"][r["interp"]] += 1
    elif r["elf_type"] == "SharedObject" and not r["needed_libs"]:
        agg["n_static_pie"] += 1
    elif r["elf_type"] == "Executable":
        agg["n_static_exec"] += 1
    if r["n_pt_tls"]:
        agg["files_with_tls"] += 1
    if r["exec_stack"]:
        agg["files_with_exec_stack"] += 1
    _merge_counter(agg["dyn_tags"], r["dyn_tags"])
    _merge_counter(agg["dyn_flags"], r["dyn_flags"])
    _merge_counter(agg["dyn_flags_1"], r["dyn_flags_1"])
    _merge_counter(agg["needed_libs"], r["needed_libs"])
    if r["runpath_count"]:
        agg["files_with_runpath"] += 1
    if r["rpath_count"]:
        agg["files_with_rpath"] += 1
    if r["has_dt_hash"] and r["has_dt_gnu_hash"]:
        agg["files_with_both_hash"] += 1
    elif r["has_dt_hash"]:
        agg["files_with_dt_hash"] += 1
    elif r["has_dt_gnu_hash"]:
        agg["files_with_dt_gnu_hash"] += 1
    elif r["dyn_tags"] and r["elf_type"] in ("SharedObject", "Executable"):
        agg["files_with_neither_hash"] += 1
    if r["has_bind_now"]:
        agg["files_with_bind_now"] += 1
    if r["has_textrel"]:
        agg["files_with_textrel"] += 1
    _merge_counter(agg["reloc_types"], r["reloc_types"])
    # per-arch reloc breakdown
    arch = r["machine"]
    per_arch = agg["reloc_types_per_arch"].setdefault(arch, Counter())
    _merge_counter(per_arch, r["reloc_types"])
    if r["has_relr"]:
        agg["files_with_relr"] += 1
    if r["has_jmprel"]:
        agg["files_with_jmprel"] += 1
    if r["ifunc_relocs"]:
        agg["files_with_ifunc_reloc"] += 1
    if r["copy_relocs"]:
        agg["files_with_copy_reloc"] += 1
    if r["tls_relocs"]:
        agg["files_with_tls_reloc"] += 1
    if r["no_relocations"]:
        agg["files_no_relocations"] += 1
    _merge_counter(agg["sym_binding"], r["sym_binding"])
    _merge_counter(agg["sym_type"], r["sym_type"])
    _merge_counter(agg["sym_visibility"], r["sym_visibility"])
    if r["n_ifunc_sym"]:
        agg["files_with_ifunc_sym"] += 1
    if r["has_verdef"]:
        agg["files_with_verdef"] += 1
    if r["has_verneed"]:
        agg["files_with_verneed"] += 1
    _merge_counter(agg["verneed_versions"], r["verneed_versions"])
    _merge_counter(agg["gnu_property"], r["gnu_property"])
    _merge_counter(agg["note_types"], r["note_types"])
    if r["has_build_id"]:
        agg["files_with_build_id"] += 1
        agg["build_id_size_dist"][r.get("build_id_bytes", 0)] += 1

    # Hardening features.
    for feat in r.get("cet_features", {}):
        agg["cet_adoption"][feat] += 1
    for feat in r.get("x86_feature2", {}):
        agg["x86_feature2_dist"][feat] += 1
    for feat in r.get("aarch64_features", {}):
        agg["aarch64_adoption"][feat] += 1
    isa = r.get("x86_64_isa_level") or ""
    if isa:
        agg["x86_64_isa_level_dist"][isa] += 1

    if r.get("soname"):
        agg["soname_count"] += 1

    for rp in r.get("runpath_values", []):
        agg["runpath_pattern_dist"][_classify_runpath(rp)] += 1
    for rp in r.get("rpath_values", []):
        agg["runpath_pattern_dist"][_classify_runpath(rp)] += 1

    agg["gnu_stack_flags_dist"][r.get("gnu_stack_flags", "absent")] += 1
    _merge_counter(agg["pt_load_align_dist"], r.get("pt_load_aligns", {}))
    if r["n_pt_load"]:
        agg["bss_ratio_buckets"][_bss_bucket(r.get("max_bss_ratio", 0.0))] += 1

    # Track the highest version per (lib, verset) tuple.
    for vd in r.get("versioned_deps", []):
        key = (vd["lib"], vd["verset"])
        prev = agg["versioned_lib_max"].get(key)
        if prev is None or tuple(vd["tuple"]) > prev[1]:
            agg["versioned_lib_max"][key] = (vd["version"], tuple(vd["tuple"]))

    agg["segment_count_histogram"][r["n_segments"]] += 1
    agg["pt_load_count_histogram"][r["n_pt_load"]] += 1
    agg["needed_count_histogram"][r["n_needed"]] += 1
    for i, (kind, sample) in enumerate(r["outliers"]):
        agg["outliers"][kind] += 1
        heap = agg["outlier_samples"].setdefault(kind, [])
        score = _sample_score(f"outlier|{kind}|{r['_path']}|{i}")
        _reservoir_push(heap, 5, score, f"{r['_path']}#{i}", sample)
    for i, (kind, detail) in enumerate(r["anomalies"]):
        agg["anomalies"][kind] += 1
        heap = agg["anomaly_files"].setdefault(kind, [])
        score = _sample_score(f"anomaly|{kind}|{r['_path']}|{i}")
        item = {"path": _short(r["_path"]),
                "detail": detail,
                "category": r.get("category", "loadable")}
        _reservoir_push(heap, _ANOM_CAP, score, f"{r['_path']}#{i}", item)

    # Per-package rollup. Derive pkg name from path:
    # corpus/analysis/<repo>/<pkg>/...
    try:
        parts = Path(r["_path"]).parts
        ai = parts.index("analysis")
        pkg = parts[ai + 2]
        agg["pkg_n_files"][pkg] += 1
        agg["pkg_total_relocs"][pkg] += r["total_relocs"]
    except (ValueError, IndexError):
        pass

    _push_top(agg["_top_reloc"], 100, r["total_relocs"], r["_path"])
    _push_top(agg["_top_needed"], 100, r["n_needed"], r["_path"])
    _push_top(agg["_top_segments"], 100, r["n_segments"], r["_path"])


CATEGORIES = ("loadable", "debuginfo", "relocatable", "cross_arch", "other")


def reduce_results(results) -> dict[str, Any]:
    """Bucket the per-file results by their 5-way `category`, then reduce
    each bucket separately. Also produces an `all` aggregate over every
    file. The loader-spec metrics on `loadable` are what users typically
    want; the per-bucket split prevents debuginfo / cross_arch noise from
    drowning out the signal."""
    top: dict[str, Any] = {
        "n_files": 0,
        "n_errors": 0,
        "errors": [],
        "category_counts": Counter(),
        "by_category": {c: _new_agg() for c in CATEGORIES},
        "all": _new_agg(),
    }
    for r in results:
        if r is None:
            continue
        if "_error" in r:
            top["n_errors"] += 1
            if len(top["errors"]) < 20:
                top["errors"].append(f"{r['_path']}: {r['_error']}")
            continue
        top["n_files"] += 1
        cat = r.get("category", "loadable")
        top["category_counts"][cat] += 1
        _absorb(top["by_category"][cat], r)
        _absorb(top["all"], r)
    return top


def _short(p: str) -> str:
    """Strip the corpus/analysis/ prefix and .json suffix."""
    s = p
    for tag in ("/corpus/analysis/", "corpus/analysis/"):
        if tag in s:
            s = s.split(tag, 1)[1]
            break
    if s.endswith(".json"):
        s = s[:-5]
    return s


def _push_top(lst: list, cap: int, val: int, path: str) -> None:
    """Maintain a top-cap list of (val, short_path), descending by val."""
    sp = _short(path)
    if len(lst) < cap:
        lst.append((val, sp))
        lst.sort(key=lambda x: -x[0])
        return
    if val <= lst[-1][0]:
        return
    lst[-1] = (val, sp)
    lst.sort(key=lambda x: -x[0])


# ---- reservoir sampling -----------------------------------------------------
#
# `imap_unordered` returns results in completion order — biased toward
# small / fast-to-parse files and non-deterministic across runs. The old
# "if len(lst) < N: lst.append(...)" pattern then produced a sample that
# was both biased and unreproducible. Replace it with reservoir sampling
# keyed by a stable hash of (kind, path): each (kind, path) pair gets a
# pseudo-random score in [0,1); we keep the N items with the smallest
# scores. The result is:
#
#  - uniform-random across files (blake2b output is uniform);
#  - independent of mp scheduling (depends only on path strings);
#  - reproducible across runs (no RNG state, no `random.seed`);
#  - per-kind independent (the kind is mixed into the hash key, so two
#    different anomaly buckets don't end up with correlated samples).


def _sample_score(key: str) -> float:
    """Deterministic uniform [0,1) hash for reservoir sampling."""
    h = hashlib.blake2b(key.encode(), digest_size=8).digest()
    return int.from_bytes(h, "big") / (1 << 64)


def _reservoir_push(heap: list, cap: int, score: float,
                    sortkey: str, item: Any) -> None:
    """Keep at most `cap` items with the smallest `score`. Stored as
    (-score, sortkey, item) so Python's min-heap places the next
    eviction candidate (the largest score) at heap[0]. `sortkey`
    breaks score ties deterministically and ensures heapq never has
    to compare `item` payloads."""
    entry = (-score, sortkey, item)
    if len(heap) < cap:
        heapq.heappush(heap, entry)
    elif entry > heap[0]:
        heapq.heapreplace(heap, entry)


def _reservoir_to_list(heap: list) -> list:
    """Drain a reservoir to a stable, sortkey-ascending list."""
    return [item for _, _, item in sorted(heap, key=lambda t: t[1])]


# ---- output -----------------------------------------------------------------


def _agg_to_json(agg: dict[str, Any]) -> dict[str, Any]:
    """Serialise one _new_agg() dict to a JSON-clean dict."""
    out: dict[str, Any] = {}
    for k, v in agg.items():
        if k.startswith("_top_"):
            out[k.lstrip("_")] = [{"count": n, "path": p} for n, p in v]
        elif k == "reloc_types_per_arch":
            out[k] = {arch: dict(c.most_common())
                      for arch, c in v.items()}
        elif k in ("anomaly_files", "outlier_samples"):
            # Drain reservoir heaps to stable, sortkey-ascending lists.
            out[k] = {kind: _reservoir_to_list(heap)
                      for kind, heap in v.items()}
        elif k == "versioned_lib_max":
            # tuple keys aren't JSON-able; explode to list of records.
            out[k] = [
                {"lib": lib, "verset": vs,
                 "version": ver, "tuple": list(tup)}
                for (lib, vs), (ver, tup) in sorted(v.items())
            ]
        elif isinstance(v, Counter):
            out[k] = dict(v.most_common())
        else:
            out[k] = v
    return out


def to_json(agg: dict[str, Any]) -> dict[str, Any]:
    """Top-level: bucket-aware shape.

    {
      "n_files":         <total>,
      "n_errors":        <…>,
      "errors":          [<…>],
      "category_counts": {loadable:…, debuginfo:…, …},
      "by_category":     {<cat>: <reduced agg>, …},
      "all":             <reduced agg over every file>,
    }
    """
    return {
        "n_files":         agg["n_files"],
        "n_errors":        agg["n_errors"],
        "errors":          agg["errors"],
        "category_counts": dict(agg["category_counts"].most_common()),
        "by_category":     {c: _agg_to_json(agg["by_category"][c])
                            for c in CATEGORIES},
        "all":             _agg_to_json(agg["all"]),
    }


def _bar(n: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return ""
    filled = int(round(n / total * width))
    return "█" * filled + "·" * (width - filled)


def _print_section(title: str, counter: Counter, total: int, top: int, *, indent: str = "  ") -> None:
    print(f"\n## {title}")
    items = counter.most_common(top)
    if not items:
        print(f"{indent}(none)")
        return
    keylen = max(len(str(k)) for k, _ in items)
    for k, n in items:
        pct = n / total * 100 if total else 0.0
        print(f"{indent}{str(k):<{keylen}}  {n:>9,}  {pct:5.1f}%  {_bar(n, total)}")
    rest = sum(counter.values()) - sum(n for _, n in items)
    if rest:
        print(f"{indent}{'(other)':<{keylen}}  {rest:>9,}")


def _print_agg(agg: dict[str, Any], top: int) -> None:
    """Print one _new_agg() to stdout in human-friendly form."""
    n = agg["n_files"]
    if n == 0:
        print("\n  (no files)")
        return
    _print_section("ELF type", agg["elf_type"], n, top)
    _print_section("ELF class", agg["class"], n, top)
    _print_section("Data encoding", agg["data_encoding"], n, top)
    _print_section("Machine (e_machine)", agg["machine"], n, top)
    _print_section("OS / ABI", agg["osabi"], n, top)

    _print_section("Program-header types", agg["phdr_types"], n, top)
    _print_section("PT_LOAD permission combinations",
                   agg["phdr_perm_combos"],
                   sum(agg["phdr_perm_combos"].values()), top)
    print(f"\n  static-PIE (ET_DYN, no PT_INTERP, no NEEDED): {agg['n_static_pie']:,}")
    print(f"  static EXE (ET_EXEC, no PT_INTERP):           {agg['n_static_exec']:,}")
    print(f"  files with PT_TLS:                            {agg['files_with_tls']:,}")
    print(f"  files with executable stack (PT_GNU_STACK X): {agg['files_with_exec_stack']:,}")

    _print_section("PT_INTERP strings", agg["interps"], n, top)
    _print_section("PT_GNU_STACK flag triplet", agg["gnu_stack_flags_dist"], n, top)
    _print_section("PT_LOAD p_align", agg["pt_load_align_dist"],
                   sum(agg["pt_load_align_dist"].values()), top)
    _print_section("BSS-extension fraction buckets",
                   agg["bss_ratio_buckets"],
                   sum(agg["bss_ratio_buckets"].values()), top)

    _print_section("Dynamic tags", agg["dyn_tags"], n, top)
    _print_section("DT_FLAGS bits", agg["dyn_flags"], n, top)
    _print_section("DT_FLAGS_1 bits", agg["dyn_flags_1"], n, top)
    print(f"\n  files with RUNPATH:           {agg['files_with_runpath']:,}")
    print(f"  files with RPATH:              {agg['files_with_rpath']:,}")
    print(f"  files with BIND_NOW (eager):   {agg['files_with_bind_now']:,}")
    print(f"  files with DT_TEXTREL:         {agg['files_with_textrel']:,}")
    print(f"  files with DT_SONAME:          {agg['soname_count']:,}")
    _print_section("RUNPATH/RPATH directory styles",
                   agg["runpath_pattern_dist"],
                   sum(agg["runpath_pattern_dist"].values()), top)

    print(f"\n## Hash table style")
    print(f"  files with both DT_HASH and DT_GNU_HASH:  {agg['files_with_both_hash']:,}")
    print(f"  files with DT_HASH only:                  {agg['files_with_dt_hash']:,}")
    print(f"  files with DT_GNU_HASH only:              {agg['files_with_dt_gnu_hash']:,}")
    print(f"  dynamic ELFs with neither:                {agg['files_with_neither_hash']:,}")

    _print_section("Top DT_NEEDED libraries", agg["needed_libs"], n, top)

    reloc_total = sum(agg["reloc_types"].values())
    print(f"\n## Relocation types  ({reloc_total:,} total relocations)")
    _print_section("(by type)", agg["reloc_types"], reloc_total, top, indent="  ")
    print(f"\n  files with PT_DYNAMIC + RELR:    {agg['files_with_relr']:,}")
    print(f"  files with PLT relocs (JMPREL):  {agg['files_with_jmprel']:,}")
    print(f"  files with IFUNC relocs:         {agg['files_with_ifunc_reloc']:,}")
    print(f"  files with COPY relocs:          {agg['files_with_copy_reloc']:,}")
    print(f"  files with TLS relocs:           {agg['files_with_tls_reloc']:,}")
    print(f"  files with no relocations:       {agg['files_no_relocations']:,}")

    _print_section("Dynamic-symbol bindings", agg["sym_binding"],
                   sum(agg["sym_binding"].values()), top)
    _print_section("Dynamic-symbol types", agg["sym_type"],
                   sum(agg["sym_type"].values()), top)
    n_sym_total = sum(agg["sym_binding"].values())
    n_nondefault = sum(agg["sym_visibility"].values())
    print(f"\n## Dynamic-symbol visibilities  ({n_nondefault:,} non-default of {n_sym_total:,})")
    for k, v in agg["sym_visibility"].most_common(top):
        pct = v / n_sym_total * 100 if n_sym_total else 0.0
        print(f"  {k:<18}  {v:>9,}  {pct:5.2f}%  {_bar(v, n_sym_total)}")
    n_default = n_sym_total - n_nondefault
    pct = n_default / n_sym_total * 100 if n_sym_total else 0.0
    print(f"  {'STV_DEFAULT':<18}  {n_default:>9,}  {pct:5.2f}%  {_bar(n_default, n_sym_total)}")
    print(f"\n  files with STT_GNU_IFUNC symbols: {agg['files_with_ifunc_sym']:,}")

    print(f"\n## Symbol versioning")
    print(f"  files with VerDef (provides):   {agg['files_with_verdef']:,}")
    print(f"  files with VerNeed (requires):  {agg['files_with_verneed']:,}")
    _print_section("Top required versions", agg["verneed_versions"], n, top)

    _print_section("Note types", agg["note_types"], n, top)
    _print_section(".note.gnu.property features", agg["gnu_property"], n, top)
    print(f"\n  files with NT_GNU_BUILD_ID:  {agg['files_with_build_id']:,}")
    _print_section("Build-ID byte length",
                   agg["build_id_size_dist"],
                   sum(agg["build_id_size_dist"].values()), top)
    _print_section("CET adoption (Intel CET hardening)",
                   agg["cet_adoption"], n, top)
    _print_section("x86 FEATURE_2 (register classes used/needed)",
                   agg["x86_feature2_dist"], n, top)
    _print_section("AArch64 PAuth/BTI adoption",
                   agg["aarch64_adoption"], n, top)
    _print_section("x86_64 ISA level (from GNU property)",
                   agg["x86_64_isa_level_dist"], n, top)

    _print_section("Outliers (file counts)", agg["outliers"], n, top)
    for kind, heap in (agg.get("outlier_samples") or {}).items():
        print(f"\n  {kind}:")
        for s in _reservoir_to_list(heap):
            print(f"    - {s}")

    _print_section("Anomalies (gabi / spec deviations)", agg["anomalies"], n, top)


def print_markdown(agg: dict[str, Any], top: int) -> None:
    n = agg["n_files"]
    print(f"# ElfZoo corpus survey")
    print(f"\n* scanned: **{n:,}** ELFs, **{agg['n_errors']}** errors")
    print(f"* generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    print(f"\n## Categories")
    for c in CATEGORIES:
        cnt = agg["category_counts"].get(c, 0)
        pct = cnt / n * 100 if n else 0.0
        print(f"  {c:<12}  {cnt:>9,}  {pct:5.1f}%  {_bar(cnt, n)}")

    print(f"\n\n----- all ELFs -----")
    _print_agg(agg["all"], top)
    for c in CATEGORIES:
        sub = agg["by_category"][c]
        if sub["n_files"] == 0:
            continue
        print(f"\n\n===== category: {c} ({sub['n_files']:,} files) =====")
        _print_agg(sub, top)


# ---- driver -----------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default="corpus/analysis",
                    help="root of the dump tree (default: corpus/analysis)")
    ap.add_argument("--out", default="corpus/survey.json",
                    help="JSON output path (default: corpus/survey.json)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--top", type=int, default=20,
                    help="top-N rows per section in the markdown report")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap at N files (for quick smoke tests)")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"survey: {root} is not a directory", file=sys.stderr)
        return 2

    t0 = time.time()
    files = sorted(root.rglob("*.json"))
    if args.limit:
        files = files[: args.limit]
    print(f"found {len(files):,} dumps in {time.time()-t0:.1f}s", file=sys.stderr)
    if not files:
        return 1

    t0 = time.time()
    with mp.Pool(args.jobs) as pool:
        results = list(pool.imap_unordered(extract, files, chunksize=64))
    print(f"extracted in {time.time()-t0:.1f}s", file=sys.stderr)

    t0 = time.time()
    agg = reduce_results(results)
    print(f"reduced in {time.time()-t0:.1f}s", file=sys.stderr)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_json(agg), indent=2, sort_keys=False) + "\n")
    print(f"wrote {out_path}", file=sys.stderr)

    print_markdown(agg, top=args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
