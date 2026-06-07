use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::elf::{self, DynamicReport, EhdrReport, ElfKind};
use crate::output;
use crate::paths::{self, Results, Source};
use crate::walk;

const PROGRAM_SCHEMA_VERSION: u32 = 1;

#[derive(ClapArgs)]
pub struct Args {
    #[command(flatten)]
    analyze: super::analyze::Options,
}

#[derive(Serialize)]
struct ProgramReport {
    schema_version: u32,
    source: Source,
    elf_kind: ElfKind,
    entry: u64,
    interpreter: Option<String>,
    soname: Option<String>,
    needed: Vec<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
    role_evidence: crate::elf::RoleEvidence,
    closure: AnalysisStatus,
    relocation_plan: AnalysisStatus,
}

#[derive(Serialize)]
struct AnalysisStatus {
    status: &'static str,
}

impl ProgramReport {
    fn from_elf(report: crate::elf::ElfReport) -> Option<Self> {
        if !report.is_program_entry() {
            return None;
        }
        let EhdrReport { entry, .. } = report.header.as_ref()?.clone();
        let dyns = report.dynamic.as_ref();
        Some(Self {
            schema_version: PROGRAM_SCHEMA_VERSION,
            source: report.source,
            elf_kind: report.kind,
            entry,
            interpreter: report.interpreter,
            soname: dyns.and_then(|d| d.soname.clone()),
            needed: clone_dynamic_vec(dyns, |d| &d.needed),
            rpath: clone_dynamic_vec(dyns, |d| &d.rpath),
            runpath: clone_dynamic_vec(dyns, |d| &d.runpath),
            role_evidence: report.role_evidence,
            closure: AnalysisStatus {
                status: "not_computed",
            },
            relocation_plan: AnalysisStatus {
                status: "not_computed",
            },
        })
    }
}

fn clone_dynamic_vec<F>(dynamic: Option<&DynamicReport>, f: F) -> Vec<String>
where
    F: Fn(&DynamicReport) -> &Vec<String>,
{
    dynamic.map(f).cloned().unwrap_or_default()
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let extracted = results.extracted();
    let out_root = results.programs();
    let mut files = walk::files(&extracted)?;
    args.analyze.apply_limit(&mut files);
    let processed = super::analyze::run_items(
        &args.analyze,
        "analyze-programs",
        "files",
        &files,
        |path| -> Result<usize> {
            let rel = walk::relative(&extracted, path)?;
            let Some(report) = elf::analyze_file(path, &rel)? else {
                return Ok(0);
            };
            let Some(program) = ProgramReport::from_elf(report) else {
                return Ok(0);
            };
            let out = paths::mirrored_json(&out_root, &rel);
            if !args.analyze.force() && output::has_schema_version(&out, PROGRAM_SCHEMA_VERSION) {
                return Ok(0);
            }
            output::write_json_atomic(&out, &program)?;
            Ok(1)
        },
    )?
    .into_iter()
    .sum::<usize>();

    eprintln!(
        "analyze-programs: wrote {processed} result files under {}",
        out_root.display()
    );
    Ok(())
}
