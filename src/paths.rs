use std::path::{Component, Path, PathBuf};

use serde::Serialize;

#[derive(Clone)]
pub struct Results {
    root: PathBuf,
}

impl Results {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn apks(&self) -> PathBuf {
        self.root.join("apks")
    }

    pub fn extracted(&self) -> PathBuf {
        self.root.join("extracted")
    }

    pub fn packages(&self) -> PathBuf {
        self.root.join("packages")
    }

    pub fn elfs(&self) -> PathBuf {
        self.root.join("elfs")
    }

    pub fn programs(&self) -> PathBuf {
        self.root.join("programs")
    }

    pub fn oracle_elflint(&self) -> PathBuf {
        self.root.join("oracle").join("elflint")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub relative: String,
    pub repo: Option<String>,
    pub package: Option<String>,
    pub path: Option<String>,
    pub size: u64,
    pub sha256: String,
}

impl Source {
    pub fn new(relative: &Path, size: u64, sha256: String) -> Self {
        let relative_string = slash(relative);
        let mut components = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let repo = components.first().cloned();
        let package = components.get(1).cloned();
        let path = if components.len() > 2 {
            Some(slash(Path::new(&components.split_off(2).join("/"))))
        } else {
            None
        };

        Self {
            relative: relative_string,
            repo,
            package,
            path,
            size,
            sha256,
        }
    }
}

pub fn append_json_extension(path: &Path) -> PathBuf {
    let mut out = path.to_path_buf();
    let Some(name) = out.file_name() else {
        return out.join(".json");
    };
    let name = format!("{}.json", name.to_string_lossy());
    out.set_file_name(name);
    out
}

pub fn mirrored_json(root: &Path, rel: &Path) -> PathBuf {
    root.join(append_json_extension(rel))
}

pub fn slash(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}
