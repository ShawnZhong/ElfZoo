use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;

use crate::paths::Results;

#[derive(ClapArgs)]
pub struct Args {
    #[arg(long, env = "ALPINE_BRANCH", default_value = "v3.23")]
    branch: String,

    #[arg(long, env = "ALPINE_ARCH", default_value = "x86_64")]
    arch: String,

    #[arg(long, env = "ALPINE_RSYNC_MIRROR")]
    mirror: Option<String>,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let repos = ["main", "community"];
    let mirror = pick_mirror(args.mirror.as_deref(), &args.branch, &args.arch)
        .context("selecting Alpine rsync mirror")?;
    eprintln!("mirror: {mirror}");
    eprintln!(
        "release: {} {} repos: {}",
        args.branch,
        args.arch,
        repos.join(" ")
    );

    for repo in repos {
        let src = format!("{mirror}/{}/{}/{}/", args.branch, repo, args.arch);
        let dst = results.apks().join(repo);
        std::fs::create_dir_all(&dst).with_context(|| format!("creating {}", dst.display()))?;

        eprintln!("=== {repo} ===");
        let status = Command::new("rsync")
            .args([
                "-rlt",
                "--partial",
                "--partial-dir=.rsync-partial",
                "--delete",
                "--info=progress2",
            ])
            .arg(&src)
            .arg(with_trailing_slash(&dst))
            .status()
            .with_context(|| format!("running rsync for {repo}"))?;
        if !status.success() {
            bail!("rsync failed for {repo} with {status}");
        }

        let index = dst.join("APKINDEX.tar.gz");
        if !index.is_file() || index.metadata()?.len() == 0 {
            bail!("{} missing or empty", index.display());
        }
    }
    Ok(())
}

fn pick_mirror(override_mirror: Option<&str>, branch: &str, arch: &str) -> Result<String> {
    let mirrors = [
        override_mirror.unwrap_or(""),
        "rsync://rsync.alpinelinux.org/alpine",
        "rsync://mirror.csclub.uwaterloo.ca/alpine",
        "rsync://mirrors.edge.kernel.org/alpine",
    ];
    for mirror in mirrors.into_iter().filter(|mirror| !mirror.is_empty()) {
        let probe = format!("{mirror}/{branch}/main/{arch}/APKINDEX.tar.gz");
        let status = Command::new("timeout")
            .arg("10")
            .arg("rsync")
            .arg("--list-only")
            .arg(&probe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|status| status.success()) {
            return Ok(mirror.to_string());
        }
    }
    bail!("no reachable rsync mirror")
}

fn with_trailing_slash(path: &Path) -> String {
    let mut s = path.display().to_string();
    if !s.ends_with('/') {
        s.push('/');
    }
    s
}
