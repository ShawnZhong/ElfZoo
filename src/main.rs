mod cmd_describe;
mod cmd_elflint;
mod cmd_extract;
mod cmd_fetch;
mod cmd_resolve;
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
    Fetch(cmd_fetch::Args),

    #[command(about = "Extract APK contents into results/extracted")]
    Extract(cmd_extract::Args),

    #[command(about = "Describe each ELF object in isolation")]
    Describe(cmd_describe::Args),

    #[command(about = "Resolve each executable as a loader input")]
    Resolve(cmd_resolve::Args),

    #[command(name = "elflint", about = "Run eu-elflint and write JSON results")]
    Elflint(cmd_elflint::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let results = paths::Results::new(cli.results);

    match cli.command {
        Command::Fetch(args) => cmd_fetch::run(&results, args),
        Command::Extract(args) => cmd_extract::run(&results, args),
        Command::Describe(args) => cmd_describe::run(&results, args),
        Command::Resolve(args) => cmd_resolve::run(&results, args),
        Command::Elflint(args) => cmd_elflint::run(&results, args),
    }
}
