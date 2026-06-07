mod cmd;
mod elf;
mod output;
mod paths;
mod walk;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "elfzoo")]
#[command(about = "ELF corpus tooling for loader analysis")]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "results",
        help = "Generated results directory"
    )]
    results: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Mirror Alpine APKs into results/apks")]
    Fetch(cmd::fetch::Args),

    #[command(about = "Extract ELF files and symlinks into results/extracted")]
    Extract(cmd::extract::Args),

    #[command(about = "Analyze APK package metadata")]
    AnalyzePackages(cmd::analyze_packages::Args),

    #[command(about = "Analyze each ELF object in isolation")]
    AnalyzeElfs(cmd::analyze_elfs::Args),

    #[command(about = "Analyze each executable program as a loader input")]
    AnalyzePrograms(cmd::analyze_programs::Args),

    #[command(name = "elflint", about = "Run eu-elflint and write JSON results")]
    Elflint(cmd::elflint::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let results = paths::Results::new(cli.results);

    match cli.command {
        Command::Fetch(args) => cmd::fetch::run(&results, args),
        Command::Extract(args) => cmd::extract::run(&results, args),
        Command::AnalyzePackages(args) => cmd::analyze_packages::run(&results, args),
        Command::AnalyzeElfs(args) => cmd::analyze_elfs::run(&results, args),
        Command::AnalyzePrograms(args) => cmd::analyze_programs::run(&results, args),
        Command::Elflint(args) => cmd::elflint::run(&results, args),
    }
}
