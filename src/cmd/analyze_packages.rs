use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use tar::Archive;
use walkdir::WalkDir;

use crate::output;
use crate::paths::{self, Results};

const PACKAGE_SCHEMA_VERSION: u32 = 2;
const PACKAGE_SUMMARY_SCHEMA_VERSION: u32 = 2;

#[derive(ClapArgs)]
pub struct Args {
    #[command(flatten)]
    analyze: super::analyze::Options,
}

#[derive(Clone)]
struct PackageInput {
    repo: String,
    package: String,
    extracted: PathBuf,
    apk: PathBuf,
}

struct PackageOutcome {
    report: PackageReport,
    wrote: bool,
}

#[derive(Clone, Deserialize, Serialize)]
struct PackageReport {
    schema_version: u32,
    source: PackageSource,
    pkginfo: BTreeMap<String, Vec<String>>,
    extracted: ExtractedSummary,
    elfs: ElfSummary,
}

#[derive(Clone, Deserialize, Serialize)]
struct PackageSource {
    repo: String,
    package: String,
    apk: String,
    apk_size: u64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ExtractedSummary {
    directories: usize,
    regular_files: usize,
    symlinks: usize,
    other: usize,
    file_paths: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct ElfSummary {
    regular_files: usize,
    symlink_paths: usize,
    file_paths: usize,
    bytes: u64,
}

#[derive(Serialize)]
struct PackageSummaryReport {
    schema_version: u32,
    packages: usize,
    extracted: ExtractedSummary,
    elfs: ElfSummary,
}

pub fn run(results: &Results, args: Args) -> Result<()> {
    let extracted_root = results.extracted();
    let apks_root = results.apks();
    let out_root = results.packages();
    let mut packages = find_packages(&extracted_root, &apks_root)?;
    args.analyze.apply_limit(&mut packages);
    let outcomes = super::analyze::run_items(
        &args.analyze,
        "analyze-packages",
        "packages",
        &packages,
        |package| analyze_one(&extracted_root, &out_root, package, args.analyze.force()),
    )?;

    let summary = summarize(outcomes.iter().map(|outcome| &outcome.report));
    output::write_json_atomic(&out_root.join("summary.json"), &summary)?;
    write_html_report(&out_root.join("index.html"), &summary)?;

    let written = outcomes.iter().filter(|outcome| outcome.wrote).count();
    let reused = outcomes.len() - written;
    eprintln!(
        "analyze-packages: done: {} reports written, {} reused under {}",
        written,
        reused,
        out_root.display()
    );
    print_summary(&summary);
    Ok(())
}

fn find_packages(extracted_root: &Path, apks_root: &Path) -> Result<Vec<PackageInput>> {
    let repos = ["main", "community"];
    let mut packages = Vec::new();
    for repo in repos {
        let root = extracted_root.join(repo);
        if !root.is_dir() {
            eprintln!("skip {repo}: {} does not exist", root.display());
            continue;
        }
        for entry in fs::read_dir(&root).with_context(|| format!("reading {}", root.display()))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let package = entry.file_name().to_string_lossy().into_owned();
            packages.push(PackageInput {
                repo: repo.to_string(),
                apk: apks_root.join(repo).join(format!("{package}.apk")),
                package,
                extracted: entry.path(),
            });
        }
    }
    packages.sort_by(|a, b| a.repo.cmp(&b.repo).then_with(|| a.package.cmp(&b.package)));
    Ok(packages)
}

fn analyze_one(
    extracted_root: &Path,
    out_root: &Path,
    package: &PackageInput,
    force: bool,
) -> Result<PackageOutcome> {
    let out = out_root
        .join(&package.repo)
        .join(format!("{}.json", package.package));
    if !force && output::has_schema_version(&out, PACKAGE_SCHEMA_VERSION) {
        let report = read_package_report(&out)?;
        return Ok(PackageOutcome {
            report,
            wrote: false,
        });
    }

    let report = analyze_package(extracted_root, package)?;
    output::write_json_atomic(&out, &report)?;
    Ok(PackageOutcome {
        report,
        wrote: true,
    })
}

fn read_package_report(path: &Path) -> Result<PackageReport> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    serde_json::from_reader(file).with_context(|| format!("reading {}", path.display()))
}

fn analyze_package(extracted_root: &Path, package: &PackageInput) -> Result<PackageReport> {
    let apk_size = fs::metadata(&package.apk)
        .with_context(|| format!("stat {}", package.apk.display()))?
        .len();
    let pkginfo = read_pkginfo(&package.apk)?;
    let (extracted, elfs) = analyze_extracted_tree(&package.extracted)?;

    Ok(PackageReport {
        schema_version: PACKAGE_SCHEMA_VERSION,
        source: PackageSource {
            repo: package.repo.clone(),
            package: package.package.clone(),
            apk: paths::slash(
                package
                    .apk
                    .strip_prefix(extracted_root.parent().unwrap_or_else(|| Path::new("")))
                    .unwrap_or(&package.apk),
            ),
            apk_size,
        },
        pkginfo,
        extracted,
        elfs,
    })
}

fn analyze_extracted_tree(package_root: &Path) -> Result<(ExtractedSummary, ElfSummary)> {
    let mut extracted = ExtractedSummary::default();
    let mut elfs = ElfSummary::default();
    for entry in WalkDir::new(package_root).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", package_root.display()))?;
        if entry.path() == package_root {
            continue;
        }
        let file_type = entry.file_type();
        if file_type.is_dir() {
            extracted.directories += 1;
        } else if file_type.is_file() {
            extracted.regular_files += 1;
        } else if file_type.is_symlink() {
            extracted.symlinks += 1;
        } else {
            extracted.other += 1;
        }

        if file_type.is_file() {
            elfs.regular_files += 1;
            elfs.bytes += fs::metadata(entry.path())
                .with_context(|| format!("stat {}", entry.path().display()))?
                .len();
        }
        if fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_file()) {
            extracted.file_paths += 1;
            elfs.file_paths += 1;
            if file_type.is_symlink() {
                elfs.symlink_paths += 1;
            }
        }
    }
    Ok((extracted, elfs))
}

fn summarize<'a>(reports: impl Iterator<Item = &'a PackageReport>) -> PackageSummaryReport {
    let mut summary = PackageSummaryReport {
        schema_version: PACKAGE_SUMMARY_SCHEMA_VERSION,
        packages: 0,
        extracted: ExtractedSummary::default(),
        elfs: ElfSummary::default(),
    };
    for report in reports {
        summary.packages += 1;
        add_extracted_summary(&mut summary.extracted, &report.extracted);
        add_elf_summary(&mut summary.elfs, &report.elfs);
    }
    summary
}

fn add_extracted_summary(total: &mut ExtractedSummary, package: &ExtractedSummary) {
    total.directories += package.directories;
    total.regular_files += package.regular_files;
    total.symlinks += package.symlinks;
    total.other += package.other;
    total.file_paths += package.file_paths;
}

fn add_elf_summary(total: &mut ElfSummary, package: &ElfSummary) {
    total.regular_files += package.regular_files;
    total.symlink_paths += package.symlink_paths;
    total.file_paths += package.file_paths;
    total.bytes += package.bytes;
}

fn read_pkginfo(apk: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    let file = File::open(apk).with_context(|| format!("opening {}", apk.display()))?;
    let decoder = MultiGzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.set_ignore_zeros(true);

    for entry in archive
        .entries()
        .with_context(|| format!("reading archive {}", apk.display()))?
    {
        let mut entry = entry.with_context(|| format!("reading entry from {}", apk.display()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = {
            let path = entry
                .path()
                .with_context(|| format!("reading entry path from {}", apk.display()))?;
            archive_path(path.as_ref())?
        };
        if path == Path::new(".PKGINFO") {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading .PKGINFO from {}", apk.display()))?;
            return Ok(parse_pkginfo(&String::from_utf8_lossy(&bytes)));
        }
    }
    Ok(BTreeMap::new())
}

fn parse_pkginfo(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        out.entry(key.to_string())
            .or_insert_with(Vec::new)
            .push(value.to_string());
    }
    out
}

fn print_summary(summary: &PackageSummaryReport) {
    println!("Package analysis report");
    println!("packages: {}", summary.packages);
    println!(
        "extracted entries: {} regular files, {} symlinks, {} directories",
        summary.extracted.regular_files, summary.extracted.symlinks, summary.extracted.directories
    );
    println!(
        "ELF files: {} regular files, {} symlink paths, {} total file paths, {} bytes",
        summary.elfs.regular_files,
        summary.elfs.symlink_paths,
        summary.elfs.file_paths,
        summary.elfs.bytes
    );
}

fn write_html_report(path: &Path, summary: &PackageSummaryReport) -> Result<()> {
    let mut html = String::new();
    html.push_str("<!doctype html><meta charset=\"utf-8\"><title>ElfZoo package analysis</title>");
    html.push_str("<style>body{font-family:sans-serif;max-width:960px;margin:2rem auto}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.25rem .5rem;text-align:left}td.count{text-align:right}</style>");
    html.push_str("<h1>ElfZoo package analysis</h1>");
    html.push_str("<table><tbody>");
    summary_row(&mut html, "packages", summary.packages);
    summary_row(&mut html, "regular files", summary.extracted.regular_files);
    summary_row(&mut html, "symlinks", summary.extracted.symlinks);
    summary_row(&mut html, "directories", summary.extracted.directories);
    summary_row(&mut html, "ELF regular files", summary.elfs.regular_files);
    summary_row(&mut html, "ELF symlink paths", summary.elfs.symlink_paths);
    summary_row(&mut html, "ELF file paths", summary.elfs.file_paths);
    summary_row(&mut html, "ELF bytes", summary.elfs.bytes);
    html.push_str("</tbody></table>");
    fs::write(path, html).with_context(|| format!("writing {}", path.display()))
}

fn summary_row(html: &mut String, name: &str, value: impl std::fmt::Display) {
    html.push_str("<tr><th>");
    html.push_str(&escape_html(name));
    html.push_str("</th><td class=\"count\">");
    html.push_str(&value.to_string());
    html.push_str("</td></tr>");
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn archive_path(path: &Path) -> Result<PathBuf> {
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
