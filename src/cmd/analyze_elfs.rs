use anyhow::Result;
use clap::Args as ClapArgs;

use crate::elf::{self, ELF_SCHEMA_VERSION};
use crate::output;
use crate::paths::{self, Results};
use crate::walk;

#[derive(ClapArgs)]
pub struct Args {
    #[command(flatten)]
    analyze: super::analyze::Options,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let extracted = results.extracted();
    let out_root = results.elfs();
    let mut files = walk::files(&extracted)?;
    args.analyze.apply_limit(&mut files);
    let processed = super::analyze::run_items(
        &args.analyze,
        "analyze-elfs",
        "files",
        &files,
        |path| -> Result<usize> {
            let rel = walk::relative(&extracted, path)?;
            let Some(report) = elf::analyze_file(path, &rel)? else {
                return Ok(0);
            };
            let out = paths::mirrored_json(&out_root, &rel);
            if !args.analyze.force() && output::has_schema_version(&out, ELF_SCHEMA_VERSION) {
                return Ok(0);
            }
            output::write_json_atomic(&out, &report)?;
            Ok(1)
        },
    )?
    .into_iter()
    .sum::<usize>();

    eprintln!(
        "analyze-elfs: wrote {processed} result files under {}",
        out_root.display()
    );
    Ok(())
}
