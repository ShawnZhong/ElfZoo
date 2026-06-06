use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use tempfile::TempDir;
use wait_timeout::ChildExt;

use crate::elf::{self, ElfKind};
use crate::output;
use crate::paths::{self, Results, Source};
use crate::walk;

const ELFLINT_SCHEMA_VERSION: u32 = 1;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value_t = num_cpus_default())]
    jobs: usize,

    #[arg(long, default_value = "eu-elflint")]
    elflint: String,

    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,

    #[arg(long, help = "Run elflint on all ELF files, not just x86 load images")]
    all_elfs: bool,

    #[arg(long, help = "Rewrite current-schema output files")]
    force: bool,

    #[arg(long, help = "Limit files processed; useful for smoke tests")]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ElflintReport {
    schema_version: u32,
    source: Source,
    elf_kind: ElfKind,
    candidate: bool,
    status: ElflintStatus,
    skip_reason: Option<String>,
    return_code: Option<i32>,
    findings: Vec<String>,
    normalized_findings: Vec<String>,
    stderr_first_line: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ElflintStatus {
    Skipped,
    Clean,
    Dirty,
    Timeout,
    Failed,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    if Command::new(&args.elflint)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("running {} --version", args.elflint))?
        .success()
        == false
    {
        bail!("{} --version returned a non-zero status", args.elflint);
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("building worker pool")?;

    let extracted = results.extracted();
    let out_root = results.oracle_elflint();
    let mut files = walk::files(&extracted)?;
    if let Some(limit) = args.limit {
        files.truncate(limit);
    }

    let timeout = Duration::from_secs(args.timeout_secs);
    let processed = pool.install(|| {
        files
            .par_iter()
            .map(|path| -> Result<usize> {
                let rel = walk::relative(&extracted, path)?;
                let Some(report) = elf::analyze_file(path, &rel)? else {
                    return Ok(0);
                };
                let out = paths::mirrored_json(&out_root, &rel);
                if !args.force && output::has_schema_version(&out, ELFLINT_SCHEMA_VERSION) {
                    return Ok(0);
                }

                let candidate = args.all_elfs || report.is_x86_load_candidate();
                let result = if candidate {
                    run_one(&args.elflint, path, timeout, report.source, report.kind)?
                } else {
                    ElflintReport {
                        schema_version: ELFLINT_SCHEMA_VERSION,
                        source: report.source,
                        elf_kind: report.kind,
                        candidate: false,
                        status: ElflintStatus::Skipped,
                        skip_reason: Some(
                            "not an ELF64 little-endian x86_64 ET_EXEC/ET_DYN load image"
                                .to_string(),
                        ),
                        return_code: None,
                        findings: Vec::new(),
                        normalized_findings: Vec::new(),
                        stderr_first_line: None,
                    }
                };
                output::write_json_atomic(&out, &result)?;
                Ok(1)
            })
            .try_reduce(|| 0usize, |a, b| Ok(a + b))
    })?;

    eprintln!(
        "elflint: wrote {processed} result files under {}",
        out_root.display()
    );
    Ok(())
}

fn run_one(
    tool: &str,
    path: &Path,
    timeout: Duration,
    source: Source,
    elf_kind: ElfKind,
) -> Result<ElflintReport> {
    let temp = TempDir::new().context("creating elflint temp dir")?;
    let stdout_path = temp.path().join("stdout");
    let stderr_path = temp.path().join("stderr");
    let stdout = File::create(&stdout_path).context("creating elflint stdout temp file")?;
    let stderr = File::create(&stderr_path).context("creating elflint stderr temp file")?;

    let mut child = Command::new(tool)
        .arg("-q")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("spawning {tool} for {}", path.display()))?;

    let status = match child
        .wait_timeout(timeout)
        .context("waiting for eu-elflint")?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(ElflintReport {
                schema_version: ELFLINT_SCHEMA_VERSION,
                source,
                elf_kind,
                candidate: true,
                status: ElflintStatus::Timeout,
                skip_reason: None,
                return_code: None,
                findings: Vec::new(),
                normalized_findings: Vec::new(),
                stderr_first_line: Some(format!("timeout after {}s", timeout.as_secs())),
            });
        }
    };

    let stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    let text = format!("{stdout}{stderr}");
    let findings = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let normalized_findings = findings
        .iter()
        .map(|line| normalize_msg(line))
        .collect::<Vec<_>>();
    let status_kind = if findings.is_empty() {
        if status.success() || status.code() == Some(1) {
            ElflintStatus::Clean
        } else {
            ElflintStatus::Failed
        }
    } else {
        ElflintStatus::Dirty
    };

    Ok(ElflintReport {
        schema_version: ELFLINT_SCHEMA_VERSION,
        source,
        elf_kind,
        candidate: true,
        status: status_kind,
        skip_reason: None,
        return_code: status.code(),
        findings,
        normalized_findings,
        stderr_first_line: stderr.lines().next().map(ToString::to_string),
    })
}

fn normalize_msg(line: &str) -> String {
    static BRACKET: OnceLock<Regex> = OnceLock::new();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static PAREN: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static NUM: OnceLock<Regex> = OnceLock::new();
    static WS: OnceLock<Regex> = OnceLock::new();

    let s = BRACKET
        .get_or_init(|| Regex::new(r"\[\s*\d+\s*\]").unwrap())
        .replace_all(line, "[N]");
    let s = QUOTED
        .get_or_init(|| Regex::new(r"'[^']*'").unwrap())
        .replace_all(&s, "'STR'");
    let s = PAREN
        .get_or_init(|| Regex::new(r"\(([^()]+)\)").unwrap())
        .replace_all(&s, "(STR)");
    let s = HEX
        .get_or_init(|| Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap())
        .replace_all(&s, "0xN");
    let s = NUM
        .get_or_init(|| Regex::new(r"\b\d+\b").unwrap())
        .replace_all(&s, "N");
    WS.get_or_init(|| Regex::new(r"\s+").unwrap())
        .replace_all(&s, " ")
        .trim()
        .to_string()
}

fn num_cpus_default() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
