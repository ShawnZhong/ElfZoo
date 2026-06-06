use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use rayon::prelude::*;

use crate::elf::{self, ELF_SCHEMA_VERSION};
use crate::output;
use crate::paths::{self, Results};
use crate::walk;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value_t = num_cpus_default())]
    jobs: usize,

    #[arg(long, help = "Rewrite current-schema output files")]
    force: bool,

    #[arg(long, help = "Limit files processed; useful for smoke tests")]
    limit: Option<usize>,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("building worker pool")?;

    let extracted = results.extracted();
    let out_root = results.descriptions();
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
                let out = paths::mirrored_json(&out_root, &rel);
                if !args.force && output::has_schema_version(&out, ELF_SCHEMA_VERSION) {
                    return Ok(0);
                }
                output::write_json_atomic(&out, &report)?;
                Ok(1)
            })
            .try_reduce(|| 0usize, |a, b| Ok(a + b))
    })?;

    eprintln!(
        "describe: wrote {processed} result files under {}",
        out_root.display()
    );
    Ok(())
}

fn num_cpus_default() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
