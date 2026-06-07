use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use flate2::read::MultiGzDecoder;
use rayon::prelude::*;
use tar::Archive;

use crate::paths::Results;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, default_value_t = num_cpus_default())]
    jobs: usize,
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
    let extracted_root = results.extracted();
    let cleaned = cleanup_stale_temp_dirs(&extracted_root)?;
    if cleaned > 0 {
        eprintln!("extract: removed {cleaned} stale temp dirs");
    }
    let done = AtomicUsize::new(0);
    let extracted_count = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);

    pool.install(|| {
        apks.par_iter().try_for_each(|(repo, apk)| {
            match extract_one(&extracted_root, repo, apk)? {
                Some(()) => {
                    extracted_count.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
            let current = done.fetch_add(1, Ordering::Relaxed) + 1;
            if current == total || current <= 10 || current % 100 == 0 {
                eprintln!(
                    "extract: {current}/{total} packages ({:.1}%)",
                    current as f64 / total as f64 * 100.0
                );
            }
            Ok::<(), anyhow::Error>(())
        })
    })?;
    eprintln!(
        "extract: done: {} packages extracted, {} skipped under {}",
        extracted_count.load(Ordering::Relaxed),
        skipped.load(Ordering::Relaxed),
        extracted_root.display()
    );
    Ok(())
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

fn extract_one(extracted: &Path, repo: &str, apk: &Path) -> Result<Option<()>> {
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
        return Ok(None);
    }
    fs::create_dir_all(&repo_out).with_context(|| format!("creating {}", repo_out.display()))?;

    let tmp = temp_dir_path(&repo_out, pkg);
    if tmp.exists() {
        fs::remove_dir_all(&tmp).with_context(|| format!("removing stale {}", tmp.display()))?;
    }
    fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;

    match extract_elf_entries(apk, &tmp) {
        Ok(()) => {}
        Err(error) => {
            let _ = fs::remove_dir_all(&tmp);
            return Err(error).with_context(|| format!("extracting {}", apk.display()));
        }
    };

    fs::rename(&tmp, &out)
        .with_context(|| format!("renaming {} to {}", tmp.display(), out.display()))?;
    Ok(Some(()))
}

fn extract_elf_entries(apk: &Path, tmp: &Path) -> Result<()> {
    let file = File::open(apk).with_context(|| format!("opening {}", apk.display()))?;
    let decoder = MultiGzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.set_ignore_zeros(true);

    for entry in archive
        .entries()
        .with_context(|| format!("reading archive {}", apk.display()))?
    {
        let mut entry = entry.with_context(|| format!("reading entry from {}", apk.display()))?;
        let entry_type = entry.header().entry_type();
        let rel = {
            let path = entry
                .path()
                .with_context(|| format!("reading entry path from {}", apk.display()))?;
            sanitize_archive_path(path.as_ref())?
        };

        if entry_type.is_file() {
            let mode = entry
                .header()
                .mode()
                .with_context(|| format!("reading mode for {}", rel.display()))?;
            copy_if_elf(&mut entry, &tmp.join(&rel), mode)?;
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .with_context(|| format!("reading symlink target for {}", rel.display()))?
                .with_context(|| format!("missing symlink target for {}", rel.display()))?;
            let target = normalize_symlink_target(&rel, target.as_ref()).with_context(|| {
                format!(
                    "normalizing symlink {} -> {}",
                    rel.display(),
                    target.display()
                )
            })?;
            create_symlink(&tmp.join(rel), &target)?;
        }
    }
    Ok(())
}

fn copy_if_elf<R: Read>(input: &mut R, out: &Path, mode: u32) -> Result<bool> {
    let mut magic = [0u8; 4];
    match input.read_exact(&mut magic) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error).context("reading ELF magic"),
    }
    if magic != ELF_MAGIC {
        return Ok(false);
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
    file.write_all(&magic)
        .with_context(|| format!("writing {}", out.display()))?;
    io::copy(input, &mut file).with_context(|| format!("writing {}", out.display()))?;
    #[cfg(unix)]
    fs::set_permissions(out, fs::Permissions::from_mode(mode & 0o7777))
        .with_context(|| format!("setting mode on {}", out.display()))?;
    Ok(true)
}

#[cfg(unix)]
fn create_symlink(link_path: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    if fs::symlink_metadata(&link_path).is_ok() {
        return Ok(());
    }
    symlink(target, &link_path).with_context(|| {
        format!(
            "creating symlink {} -> {}",
            link_path.display(),
            target.display()
        )
    })
}

#[cfg(not(unix))]
fn create_symlink(_link_path: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

fn sanitize_archive_path(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe archive path {}", path.display())
            }
        }
    }
    if out.as_os_str().is_empty() {
        bail!("empty archive path");
    }
    Ok(out)
}

fn normalize_symlink_target(link: &Path, target: &Path) -> Result<PathBuf> {
    if target.as_os_str().is_empty() {
        bail!("empty symlink target");
    }

    let target = if target.is_absolute() {
        normalize_package_path(target)?
    } else {
        let mut path = link.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
        path.push(target);
        normalize_package_path(&path)?
    };

    Ok(relative_path(
        link.parent().unwrap_or_else(|| Path::new("")),
        &target,
    ))
}

fn normalize_package_path(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                if !out.pop() {
                    bail!("symlink target escapes package root");
                }
            }
            Component::Prefix(_) => bail!("unsupported symlink target {}", path.display()),
        }
    }
    Ok(out)
}

fn relative_path(from_dir: &Path, target: &Path) -> PathBuf {
    let from = normal_components(from_dir);
    let to = normal_components(target);
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();

    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for component in &to[common..] {
        out.push(component);
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn normal_components(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect()
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
