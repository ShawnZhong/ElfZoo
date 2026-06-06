use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use rayon::prelude::*;
use serde::Serialize;

use crate::elf::{self, DynamicReport, EhdrReport, ElfKind};
use crate::output;
use crate::paths::{self, Results, Source};
use crate::walk;

const RESOLVE_SCHEMA_VERSION: u32 = 1;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value_t = num_cpus_default())]
    jobs: usize,

    #[arg(long, help = "Rewrite current-schema output files")]
    force: bool,

    #[arg(long, help = "Limit files processed; useful for smoke tests")]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ResolveReport {
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

impl ResolveReport {
    fn from_elf(report: crate::elf::ElfReport) -> Option<Self> {
        if !report.is_program_entry() {
            return None;
        }
        let EhdrReport { entry, .. } = report.header.as_ref()?.clone();
        let dyns = report.dynamic.as_ref();
        Some(Self {
            schema_version: RESOLVE_SCHEMA_VERSION,
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
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("building worker pool")?;

    let extracted = results.extracted();
    let out_root = results.resolutions();
    let mut files = walk::files(&extracted)?;
    if let Some(limit) = args.limit {
        files.truncate(limit);
    }

    let processed = pool.install(|| {
        files
            .par_iter()
            .map(|path| -> Result<usize> {
                let rel = walk::relative(&extracted, path)?;
                let Some(report) = elf::analyze_file(path, &rel)? else {
                    return Ok(0);
                };
                let Some(program) = ResolveReport::from_elf(report) else {
                    return Ok(0);
                };
                let out = paths::mirrored_json(&out_root, &rel);
                if !args.force && output::has_schema_version(&out, RESOLVE_SCHEMA_VERSION) {
                    return Ok(0);
                }
                output::write_json_atomic(&out, &program)?;
                Ok(1)
            })
            .try_reduce(|| 0usize, |a, b| Ok(a + b))
    })?;

    eprintln!(
        "resolve: wrote {processed} result files under {}",
        out_root.display()
    );
    Ok(())
}

fn num_cpus_default() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
