use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

pub fn files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_file()) {
            out.push(entry.into_path());
        }
    }
    out.sort();
    Ok(out)
}

pub fn relative(root: &Path, path: &Path) -> Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))
}
