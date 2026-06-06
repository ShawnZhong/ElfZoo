use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use rayon::prelude::*;

use crate::paths::Results;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value_t = num_cpus_default())]
    jobs: usize,

    #[arg(long, help = "Remove and recreate already-extracted packages")]
    force: bool,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let repos = ["main", "community"];
    let mut apks = Vec::new();
    for repo in &repos {
        let root = results.apks().join(repo);
        if !root.is_dir() {
            eprintln!("skip {repo}: {} does not exist", root.display());
            continue;
        }
        for entry in fs::read_dir(&root).with_context(|| format!("reading {}", root.display()))? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "apk") {
                apks.push((repo.to_string(), path));
            }
        }
    }
    apks.sort_by(|a, b| a.1.cmp(&b.1));
    let total = apks.len();
    eprintln!(
        "extract: found {total} APKs under {} (jobs={})",
        results.apks().display(),
        args.jobs.max(1)
    );
    if total == 0 {
        return Ok(());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.jobs.max(1))
        .build()
        .context("building worker pool")?;
    let extracted = results.extracted();
    let force = args.force;
    let cleaned = cleanup_stale_temp_dirs(&extracted)?;
    if cleaned > 0 {
        eprintln!("extract: removed {cleaned} stale temp dirs");
    }
    let done = AtomicUsize::new(0);
    let materialized = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);

    pool.install(|| {
        apks.par_iter().try_for_each(|(repo, apk)| {
            let changed = extract_one(&extracted, repo, apk, force)?;
            if changed == 0 {
                skipped.fetch_add(1, Ordering::Relaxed);
            } else {
                materialized.fetch_add(1, Ordering::Relaxed);
            }
            let current = done.fetch_add(1, Ordering::Relaxed) + 1;
            if should_report_progress(current, total) {
                eprintln!(
                    "extract: {current}/{total} packages ({:.1}%)",
                    current as f64 / total as f64 * 100.0
                );
            }
            Ok::<(), anyhow::Error>(())
        })
    })?;

    eprintln!(
        "extract: done: {} materialized, {} skipped under {}",
        materialized.load(Ordering::Relaxed),
        skipped.load(Ordering::Relaxed),
        extracted.display()
    );
    Ok(())
}

fn should_report_progress(current: usize, total: usize) -> bool {
    current == total || current <= 10 || current % 100 == 0
}

fn cleanup_stale_temp_dirs(extracted: &Path) -> Result<usize> {
    if !extracted.is_dir() {
        return Ok(0);
    }
    let mut cleaned = 0;
    for repo in
        fs::read_dir(extracted).with_context(|| format!("reading {}", extracted.display()))?
    {
        let repo = repo?;
        if !repo.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(repo.path())
            .with_context(|| format!("reading {}", repo.path().display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(".tmp-") {
                fs::remove_dir_all(entry.path())
                    .with_context(|| format!("removing stale {}", entry.path().display()))?;
                cleaned += 1;
            }
        }
    }
    Ok(cleaned)
}

fn extract_one(extracted: &Path, repo: &str, apk: &Path, force: bool) -> Result<usize> {
    let file_name = apk
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("invalid APK path {}", apk.display()))?;
    let pkg = file_name
        .strip_suffix(".apk")
        .with_context(|| format!("APK filename does not end in .apk: {file_name}"))?;
    let repo_out = extracted.join(repo);
    let out = repo_out.join(pkg);

    if out.exists() {
        if !force {
            return Ok(0);
        }
        fs::remove_dir_all(&out).with_context(|| format!("removing {}", out.display()))?;
    }
    fs::create_dir_all(&repo_out).with_context(|| format!("creating {}", repo_out.display()))?;

    let tmp = temp_dir_path(&repo_out, pkg);
    if tmp.exists() {
        fs::remove_dir_all(&tmp).with_context(|| format!("removing stale {}", tmp.display()))?;
    }
    fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;

    let status = Command::new("tar")
        .arg("--warning=no-unknown-keyword")
        .arg("-xzf")
        .arg(apk)
        .arg("-C")
        .arg(&tmp)
        .status()
        .with_context(|| format!("extracting {}", apk.display()))?;
    if !status.success() {
        let _ = fs::remove_dir_all(&tmp);
        bail!("tar failed for {} with {status}", apk.display());
    }

    fs::rename(&tmp, &out)
        .with_context(|| format!("renaming {} to {}", tmp.display(), out.display()))?;
    Ok(1)
}

fn temp_dir_path(parent: &Path, pkg: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".tmp-{}-{pkg}-{nanos}", std::process::id()))
}

fn num_cpus_default() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}
