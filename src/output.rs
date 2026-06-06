use std::fs::{self, File};
use std::io::BufWriter;
use std::path::Path;
use std::process;

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

pub fn has_schema_version(path: &Path, version: u32) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_reader::<_, Value>(file) else {
        return false;
    };
    value
        .get("schema_version")
        .and_then(Value::as_u64)
        .is_some_and(|found| found == u64::from(version))
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating output directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    let tmp = parent.join(format!(
        ".tmp-{}-{}-{file_name}",
        process::id(),
        unique_suffix()
    ));

    let file = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .with_context(|| format!("serializing {}", path.display()))?;
    use std::io::Write;
    writer
        .write_all(b"\n")
        .with_context(|| format!("writing {}", tmp.display()))?;
    writer
        .into_inner()
        .with_context(|| format!("flushing {}", tmp.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", tmp.display()))?;

    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

fn unique_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
