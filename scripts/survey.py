#!/usr/bin/env python3
"""
Corpus-wide survey of the per-ELF llvm-readobj dumps.

Walks every corpus/analysis/**/*.json.gz and aggregates the
distributions that matter for a loader spec:

  * ELF type / machine / OS-ABI
  * Program-header types (with PT_INTERP string resolved from the
    original ELF)
  * Dynamic-tag types + DT_FLAGS / DT_FLAGS_1 bits + DT_NEEDED libs
  * Relocation type frequency (corpus-wide and per-arch)
  * Dynamic-symbol bindings / visibilities
  * Symbol-versioning provision and requirement
  * .note.gnu.property features
  * Build-id presence
  * A short list of structural outliers (unknown e_machine,
    text relocs, empty DynamicSection, cross-arch files)

Writes the structured result to corpus/survey.json and prints a
Markdown summary to stdout.

Usage:
    scripts/survey.py
    scripts/survey.py --root corpus/analysis --jobs 32
    scripts/survey.py --top 30          # top-N rows in markdown
"""
from __future__ import annotations

import argparse
import gzip
import json
import multiprocessing as mp
import os
import struct
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


# ---- per-file extraction ----------------------------------------------------


# PT_INTERP is the loader path; for survey purposes we deduplicate it
# globally, but to limit memory we never keep more than this many
# distinct strings per file (we only ever expect one).
def _read_interp(elf_path: str, offset: int, size: int) -> str | None:
    if size <= 0 or size > 256:
        return None
    try:
        with open(elf_path, "rb") as fh:
            fh.seek(offset)
            blob = fh.read(size)
    except OSError:
        return None
    return blob.rstrip(b"\x00").decode("utf-8", "replace") or None


def _name(field: Any) -> str:
    """llvm-readobj sometimes emits enum-ish fields as `{Name,Value}` dicts
    and sometimes as bare strings like ``"SharedObject (0x3)"``.  Normalise
    to a plain name."""
    if isinstance(field, dict):
        return field.get("Name", "")
    if isinstance(field, str):
        return field.split(" (")[0] if " (" in field else field
    return str(field)


def extract(path: Path) -> dict[str, Any]:
    try:
        with gzip.open(path, "rb") as g:
            doc = json.load(g)[0]
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}", "_path": str(path)}

    hdr = doc["ElfHeader"]
    fs = doc["FileSummary"]
    src = fs["File"]
    arch = fs.get("Arch", "")

    out: dict[str, Any] = {
        "arch_dir": arch,
        "elf_type": _name(hdr["Type"]),
        "machine": _name(hdr["Machine"]),
        "osabi": _name(hdr["Ident"]["OS/ABI"]),
        "phdr_types": Counter(),
        "interp": None,
        "dyn_tags": Counter(),
        "dyn_flags": Counter(),
        "dyn_flags_1": Counter(),
        "needed_libs": Counter(),
        "runpath_count": 0,
        "rpath_count": 0,
        "reloc_types": Counter(),
        "has_relr": False,
        "has_jmprel": False,
        "no_relocations": False,
        "sym_binding": Counter(),
        "sym_visibility": Counter(),
        "sym_type": Counter(),
        "n_dynsym": 0,
        "has_verdef": False,
        "has_verneed": False,
        "verneed_versions": Counter(),
        "gnu_property": Counter(),
        "has_build_id": False,
        "n_segments": 0,
        "outliers": [],
    }

    # --- program headers + PT_INTERP string ---
    interp_off = interp_sz = 0
    phs = doc.get("ProgramHeaders", [])
    out["n_segments"] = len(phs)
    for ph in phs:
        p = ph["ProgramHeader"]
        t = _name(p["Type"])
        out["phdr_types"][t] += 1
        if t == "PT_INTERP":
            interp_off, interp_sz = p["Offset"], p["FileSize"]
    if interp_off:
        out["interp"] = _read_interp(src, interp_off, interp_sz)

    # --- dynamic section ---
    dyn = doc.get("DynamicSection", [])
    for e in dyn:
        t = e["Type"]
        out["dyn_tags"][t] += 1
        if t == "NEEDED":
            out["needed_libs"][e.get("Library", "?")] += 1
        elif t == "FLAGS":
            for f in e.get("Flags", []) or []:
                out["dyn_flags"][f if isinstance(f, str) else f.get("Name", str(f))] += 1
        elif t == "FLAGS_1":
            for f in e.get("Flags", []) or []:
                out["dyn_flags_1"][f if isinstance(f, str) else f.get("Name", str(f))] += 1
        elif t == "RUNPATH":
            out["runpath_count"] += 1
        elif t == "RPATH":
            out["rpath_count"] += 1
        elif t == "RELR" or t == "RELRSZ" or t == "RELRENT":
            out["has_relr"] = True
        elif t == "JMPREL":
            out["has_jmprel"] = True
        elif t == "TEXTREL":
            out["outliers"].append(("text_relocs", str(path)))

    # --- relocations ---
    reloc_groups = doc.get("Relocations", [])
    if not reloc_groups:
        out["no_relocations"] = True
    for grp in reloc_groups:
        for r in grp.get("Relocs", []):
            rel = r["Relocation"]
            out["reloc_types"][_name(rel["Type"])] += 1

    # --- dynamic symbols ---
    dynsyms = doc.get("DynamicSymbols", [])
    out["n_dynsym"] = len(dynsyms)
    for s in dynsyms:
        sym = s["Symbol"]
        out["sym_binding"][_name(sym["Binding"])] += 1
        out["sym_type"][_name(sym["Type"])] += 1
        for f in sym.get("Other", {}).get("Flags", []) or []:
            out["sym_visibility"][_name(f)] += 1

    # --- version info ---
    if doc.get("VersionDefinitions"):
        out["has_verdef"] = True
    for vn in doc.get("VersionRequirements", []) or []:
        dep = vn.get("Dependency", {})
        if not dep:
            continue
        out["has_verneed"] = True
        for entry in dep.get("Entries", []) or []:
            name = entry.get("Entry", {}).get("Name", "")
            if name:
                out["verneed_versions"][name] += 1

    # --- notes ---
    for ns in doc.get("NoteSections", []) or []:
        n = ns["NoteSection"]
        for note in n.get("Notes", []) or []:
            if "Build ID" in note:
                out["has_build_id"] = True
            props = note.get("Property")
            if isinstance(props, list):
                for p in props:
                    out["gnu_property"][p] += 1

    # --- arch-mismatch outlier ---
    # FileSummary.Arch is set from e_machine by llvm-readobj; the dump
    # tree path itself carries the arch from the original Alpine repo
    # (corpus/analysis/<branch>/<repo>/<arch>/…).  We flag mismatches
    # where the file is a real ELF for a *different* architecture
    # (i.e. ignore "unknown" — those are Guile .go bytecode files,
    # palcode, etc., already visible in the Machine distribution).
    parts = path.parts
    try:
        i = parts.index("analysis")
        repo_arch = parts[i + 3]
    except (ValueError, IndexError):
        repo_arch = ""
    if (repo_arch and arch and arch != "unknown" and arch != repo_arch):
        out["outliers"].append(("arch_mismatch", f"{path}: header={arch} dir={repo_arch}"))

    if not dyn and out["elf_type"] not in ("Relocatable", "Core"):
        out["outliers"].append(("empty_dynamic", str(path)))

    # llvm-readobj reports unknown e_machine via our patcher; the value
    # then comes through as a bare integer (e.g. {"Value": 36902}).
    mname = _name(hdr["Machine"])
    if mname.startswith("Unknown") or mname == "" or mname.startswith("0x"):
        out["outliers"].append(("unknown_machine", f"{path}: e_machine={hdr['Machine']}"))

    return out


# ---- reduction --------------------------------------------------------------


def _merge_counter(dst: Counter, src: dict | Counter) -> None:
    for k, v in src.items():
        dst[k] += v


def reduce_results(results) -> dict[str, Any]:
    agg: dict[str, Any] = {
        "n_files": 0,
        "n_errors": 0,
        "errors": [],
        "elf_type": Counter(),
        "machine": Counter(),
        "osabi": Counter(),
        "phdr_types": Counter(),
        "interps": Counter(),
        "n_static_pie": 0,  # ET_DYN with no PT_INTERP, no DT_NEEDED
        "n_static_exec": 0,  # ET_EXEC with no PT_INTERP
        "dyn_tags": Counter(),
        "dyn_flags": Counter(),
        "dyn_flags_1": Counter(),
        "needed_libs": Counter(),
        "files_with_runpath": 0,
        "files_with_rpath": 0,
        "reloc_types": Counter(),
        "files_with_relr": 0,
        "files_with_jmprel": 0,
        "files_no_relocations": 0,
        "sym_binding": Counter(),
        "sym_type": Counter(),
        "sym_visibility": Counter(),
        "files_with_verdef": 0,
        "files_with_verneed": 0,
        "verneed_versions": Counter(),
        "gnu_property": Counter(),
        "files_with_build_id": 0,
        "segment_count_histogram": Counter(),
        "outliers": Counter(),
        "outlier_samples": {},
    }
    for r in results:
        if r is None:
            continue
        if "_error" in r:
            agg["n_errors"] += 1
            if len(agg["errors"]) < 20:
                agg["errors"].append(f"{r['_path']}: {r['_error']}")
            continue
        agg["n_files"] += 1
        agg["elf_type"][r["elf_type"]] += 1
        agg["machine"][r["machine"]] += 1
        agg["osabi"][r["osabi"]] += 1
        _merge_counter(agg["phdr_types"], r["phdr_types"])
        if r["interp"]:
            agg["interps"][r["interp"]] += 1
        elif r["elf_type"] == "SharedObject" and not r["needed_libs"]:
            agg["n_static_pie"] += 1
        elif r["elf_type"] == "Executable":
            agg["n_static_exec"] += 1
        _merge_counter(agg["dyn_tags"], r["dyn_tags"])
        _merge_counter(agg["dyn_flags"], r["dyn_flags"])
        _merge_counter(agg["dyn_flags_1"], r["dyn_flags_1"])
        _merge_counter(agg["needed_libs"], r["needed_libs"])
        if r["runpath_count"]:
            agg["files_with_runpath"] += 1
        if r["rpath_count"]:
            agg["files_with_rpath"] += 1
        _merge_counter(agg["reloc_types"], r["reloc_types"])
        if r["has_relr"]:
            agg["files_with_relr"] += 1
        if r["has_jmprel"]:
            agg["files_with_jmprel"] += 1
        if r["no_relocations"]:
            agg["files_no_relocations"] += 1
        _merge_counter(agg["sym_binding"], r["sym_binding"])
        _merge_counter(agg["sym_type"], r["sym_type"])
        _merge_counter(agg["sym_visibility"], r["sym_visibility"])
        if r["has_verdef"]:
            agg["files_with_verdef"] += 1
        if r["has_verneed"]:
            agg["files_with_verneed"] += 1
        _merge_counter(agg["verneed_versions"], r["verneed_versions"])
        _merge_counter(agg["gnu_property"], r["gnu_property"])
        if r["has_build_id"]:
            agg["files_with_build_id"] += 1
        agg["segment_count_histogram"][r["n_segments"]] += 1
        for kind, sample in r["outliers"]:
            agg["outliers"][kind] += 1
            agg["outlier_samples"].setdefault(kind, [])
            if len(agg["outlier_samples"][kind]) < 5:
                agg["outlier_samples"][kind].append(sample)
    return agg


# ---- output -----------------------------------------------------------------


def to_json(agg: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in agg.items():
        if isinstance(v, Counter):
            out[k] = dict(v.most_common())
        else:
            out[k] = v
    return out


def _bar(n: int, total: int, width: int = 20) -> str:
    if total <= 0:
        return ""
    filled = int(round(n / total * width))
    return "█" * filled + "·" * (width - filled)


def _print_section(title: str, counter: Counter, total: int, top: int, *, indent: str = "  ") -> None:
    print(f"\n## {title}")
    items = counter.most_common(top)
    if not items:
        print(f"{indent}(none)")
        return
    keylen = max(len(str(k)) for k, _ in items)
    for k, n in items:
        pct = n / total * 100 if total else 0.0
        print(f"{indent}{str(k):<{keylen}}  {n:>9,}  {pct:5.1f}%  {_bar(n, total)}")
    rest = sum(counter.values()) - sum(n for _, n in items)
    if rest:
        print(f"{indent}{'(other)':<{keylen}}  {rest:>9,}")


def print_markdown(agg: dict[str, Any], top: int) -> None:
    n = agg["n_files"]
    print(f"# ElfZoo corpus survey")
    print(f"\n* scanned: **{n:,}** ELFs, **{agg['n_errors']}** errors")
    print(f"* generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    _print_section("ELF type", agg["elf_type"], n, top)
    _print_section("Machine (e_machine)", agg["machine"], n, top)
    _print_section("OS / ABI", agg["osabi"], n, top)

    _print_section("Program-header types", agg["phdr_types"], n, top)
    print(f"\n  static-PIE (ET_DYN, no PT_INTERP, no NEEDED): {agg['n_static_pie']:,}")
    print(f"  static EXE (ET_EXEC, no PT_INTERP):           {agg['n_static_exec']:,}")

    _print_section("PT_INTERP strings", agg["interps"], n, top)

    _print_section("Dynamic tags", agg["dyn_tags"], n, top)
    _print_section("DT_FLAGS bits", agg["dyn_flags"], n, top)
    _print_section("DT_FLAGS_1 bits", agg["dyn_flags_1"], n, top)
    print(f"\n  files with RUNPATH: {agg['files_with_runpath']:,}")
    print(f"  files with RPATH:   {agg['files_with_rpath']:,}")

    _print_section("Top DT_NEEDED libraries", agg["needed_libs"], n, top)

    reloc_total = sum(agg["reloc_types"].values())
    print(f"\n## Relocation types  ({reloc_total:,} total relocations)")
    _print_section("(by type)", agg["reloc_types"], reloc_total, top, indent="  ")
    print(f"\n  files with PT_DYNAMIC + RELR:    {agg['files_with_relr']:,}")
    print(f"  files with PLT relocs (JMPREL):  {agg['files_with_jmprel']:,}")
    print(f"  files with no relocations:       {agg['files_no_relocations']:,}")

    _print_section("Dynamic-symbol bindings", agg["sym_binding"], sum(agg["sym_binding"].values()), top)
    _print_section("Dynamic-symbol types", agg["sym_type"], sum(agg["sym_type"].values()), top)
    n_sym_total = sum(agg["sym_binding"].values())
    n_nondefault = sum(agg["sym_visibility"].values())
    print(f"\n## Dynamic-symbol visibilities  ({n_nondefault:,} non-default of {n_sym_total:,})")
    for k, v in agg["sym_visibility"].most_common(top):
        pct = v / n_sym_total * 100 if n_sym_total else 0.0
        print(f"  {k:<18}  {v:>9,}  {pct:5.2f}%  {_bar(v, n_sym_total)}")
    n_default = n_sym_total - n_nondefault
    pct = n_default / n_sym_total * 100 if n_sym_total else 0.0
    print(f"  {'STV_DEFAULT':<18}  {n_default:>9,}  {pct:5.2f}%  {_bar(n_default, n_sym_total)}")

    print(f"\n## Symbol versioning")
    print(f"  files with VerDef (provides):   {agg['files_with_verdef']:,}")
    print(f"  files with VerNeed (requires):  {agg['files_with_verneed']:,}")
    _print_section("Top required versions", agg["verneed_versions"], n, top)

    _print_section(".note.gnu.property features", agg["gnu_property"], n, top)
    print(f"\n  files with NT_GNU_BUILD_ID:  {agg['files_with_build_id']:,}")

    _print_section("Outliers (file counts)", agg["outliers"], n, top)
    for kind, samples in (agg.get("outlier_samples") or {}).items():
        print(f"\n  {kind}:")
        for s in samples:
            print(f"    - {s}")


# ---- driver -----------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default="corpus/analysis",
                    help="root of the dump tree (default: corpus/analysis)")
    ap.add_argument("--out", default="corpus/survey.json",
                    help="JSON output path (default: corpus/survey.json)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--top", type=int, default=20,
                    help="top-N rows per section in the markdown report")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap at N files (for quick smoke tests)")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"survey: {root} is not a directory", file=sys.stderr)
        return 2

    t0 = time.time()
    files = sorted(root.rglob("*.json.gz"))
    if args.limit:
        files = files[: args.limit]
    print(f"found {len(files):,} dumps in {time.time()-t0:.1f}s", file=sys.stderr)
    if not files:
        return 1

    t0 = time.time()
    with mp.Pool(args.jobs) as pool:
        results = list(pool.imap_unordered(extract, files, chunksize=64))
    print(f"extracted in {time.time()-t0:.1f}s", file=sys.stderr)

    t0 = time.time()
    agg = reduce_results(results)
    print(f"reduced in {time.time()-t0:.1f}s", file=sys.stderr)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_json(agg), indent=2, sort_keys=False) + "\n")
    print(f"wrote {out_path}", file=sys.stderr)

    print_markdown(agg, top=args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
