#!/usr/bin/env python3
"""
Per-ELF llvm-readobj JSON dump.

For every ELF under one of the given package dirs, runs
`llvm-readobj-20 --elf-output-style=JSON …` with an explicit set of
section flags (avoiding `--all`, which produces invalid JSON), then
writes the result to corpus/analysis/<repo>/<pkg>/<elf>.json.

The output tree mirrors corpus/unpacked/ so any ELF at
    corpus/unpacked/main/busybox-1.37.0-r30/bin/busybox
has its dump at
    corpus/analysis/main/busybox-1.37.0-r30/bin/busybox.json

Usage:
    scripts/dump.py PKG_NAME [PKG_NAME ...]
    scripts/dump.py --all                                 # full corpus
    scripts/dump.py --repo main busybox                   # one repo
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Per-section flags that produce valid JSON in llvm-readobj-20.
# See README — `--all` is broken (mixes JSON and text); these can be
# combined in one invocation and the result is well-formed JSON.
#
# Scope: this dump is for a *loader* differential test, so we only ask
# for what the loader actually consumes.
#   --file-header / --program-headers : segments, e_entry, e_type
#   --dynamic-table                   : DT_NEEDED / DT_REL* / DT_BIND_NOW / …
#   --relocations / --dyn-symbols     : rela.{dyn,plt} + .dynsym
#   --version-info                    : symbol-version resolution
#   --notes                           : GNU_PROPERTY (BTI/IBT/SHSTK)
# Deliberately NOT requested:
#   --symbols           : .symtab is link-time only, never read by ld.so,
#                         and dominates -dbg packages (2.4 MB+ per file).
#   --needed-libs       : strictly redundant with the DT_NEEDED rows of
#                         --dynamic-table (same string, same source).
#   --section-headers   : the loader runs on segments; reloc-section
#                         identification under --relocations carries the
#                         SectionIndex either way.
READOBJ_FLAGS = [
    "--elf-output-style=JSON",
    "--file-header",
    "--program-headers",
    "--dynamic-table",
    "--relocations",
    "--dyn-symbols",
    "--notes",
    "--version-info",
]

ELF_MAGIC = b"\x7fELF"

# llvm-readobj-20 has two JSON-output bugs we patch in post-processing:
#
# (1) --version-info emits Verdef.Predecessors as raw text instead of JSON:
#     `..."Name":"libfoo.so.1"Predecessors: []\n}` or with a single bare
#     identifier like `Predecessors: [ACL_1.0]\n`.
#
# (2) For an Elf header with an unknown e_machine (e.g. EM_ALPHA on a QEMU
#     pal-code binary), the Machine field is emitted as `Machine: 0x9026\n`
#     in raw text — again jammed into an otherwise valid JSON object.
#
# Both forms are rewritten to the structurally-equivalent JSON before parsing.
_VERDEF_PREDS_RE = re.compile(rb'Predecessors: \[([^\]\n]*)\]\n')
_BAD_MACHINE_RE  = re.compile(rb'Machine: (0x[0-9a-fA-F]+|\d+)\n')


def _patch_readobj_json(blob: bytes) -> bytes:
    def repl_preds(m: "re.Match[bytes]") -> bytes:
        body = m.group(1)
        if not body:
            return b',"Predecessors":[]'
        parts = [p.strip() for p in body.split(b",")]
        quoted = b",".join(b'"' + p + b'"' for p in parts)
        return b',"Predecessors":[' + quoted + b']'

    def repl_machine(m: "re.Match[bytes]") -> bytes:
        raw = m.group(1).decode()
        val = int(raw, 16) if raw.startswith("0x") else int(raw)
        return b',"Machine":{"Name":"Unknown","Value":' + str(val).encode() + b'}'

    blob = _VERDEF_PREDS_RE.sub(repl_preds, blob)
    blob = _BAD_MACHINE_RE.sub(repl_machine, blob)
    return blob


def is_elf(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def find_elfs(pkg_dir: Path):
    for dirpath, _, filenames in os.walk(pkg_dir):
        for fn in filenames:
            if fn.startswith(".") and (fn in (".unpacked", ".PKGINFO")
                                       or fn.startswith(".SIGN.")
                                       or fn.startswith(".post-")
                                       or fn.startswith(".pre-")
                                       or fn.startswith(".trigger")):
                continue
            p = Path(dirpath) / fn
            if is_elf(p):
                yield p


def dump_one(args):
    elf_path, in_root, out_root, readobj, force = args
    rel = elf_path.relative_to(in_root)
    out = out_root / rel.with_name(rel.name + ".json")
    if not force and out.exists():
        return (elf_path, None)
    out.parent.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            [readobj, *READOBJ_FLAGS, str(elf_path)],
            check=False, capture_output=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return (elf_path, "timeout")

    if proc.returncode != 0 and not proc.stdout:
        return (elf_path, f"readobj_failed (rc={proc.returncode}): "
                + proc.stderr.decode(errors='replace')[:200])

    blob = _patch_readobj_json(proc.stdout)

    try:
        json.loads(blob)
    except json.JSONDecodeError as e:
        err_path = out.with_suffix(".err")
        err_path.write_bytes(proc.stdout)
        return (elf_path, f"invalid_json: {e}")

    # Clear any stale .err from a previous run.
    err_path = out.with_suffix(".err")
    if err_path.exists():
        err_path.unlink()

    out.write_bytes(blob)
    return (elf_path, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--repo", default="main",
                    help="repo (main/community). Multi-repo: pass --all.")
    ap.add_argument("--all", action="store_true",
                    help="dump every ELF in main+community")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--readobj", default="llvm-readobj-20")
    ap.add_argument("--force", action="store_true",
                    help="re-dump even if output already exists")
    ap.add_argument("pkgs", nargs="*",
                    help="package name prefixes (e.g. 'busybox' matches "
                         "'busybox-1.37.0-r30')")
    args = ap.parse_args()

    root = Path(args.root)
    in_root = root / "corpus" / "unpacked"
    out_root = root / "corpus" / "analysis"

    pkg_dirs: list[Path] = []
    if args.all:
        for repo in ("main", "community"):
            base = in_root / repo
            if base.is_dir():
                pkg_dirs.extend(d for d in sorted(base.iterdir())
                                if d.is_dir() and (d / ".unpacked").exists())
    else:
        base = in_root / args.repo
        if not base.is_dir():
            sys.exit(f"no such dir: {base}")
        if not args.pkgs:
            sys.exit("specify package names or --all")
        for pkg in args.pkgs:
            matches = sorted(d for d in base.glob(f"{pkg}*")
                             if d.is_dir() and (d / ".unpacked").exists())
            if not matches:
                print(f"warn: no match for {pkg!r} in {base}", file=sys.stderr)
            pkg_dirs.extend(matches)

    if not pkg_dirs:
        sys.exit("no packages to process")

    print(f"packages: {len(pkg_dirs)}")
    for p in pkg_dirs[:10]:
        print(f"  {p.name}")
    if len(pkg_dirs) > 10:
        print(f"  ... and {len(pkg_dirs)-10} more")

    # Enumerate ELFs across all selected packages.
    t0 = time.time()
    elfs: list[Path] = []
    for d in pkg_dirs:
        elfs.extend(find_elfs(d))
    print(f"found {len(elfs):,} ELFs in {time.time()-t0:.1f}s")
    if not elfs:
        return

    # Dump in parallel.
    t0 = time.time()
    jobs = [(e, in_root, out_root, args.readobj, args.force) for e in elfs]
    ok = 0
    errs: list[tuple[Path, str]] = []
    with mp.Pool(args.jobs) as pool:
        for i, (elf, err) in enumerate(
            pool.imap_unordered(dump_one, jobs, chunksize=8), start=1
        ):
            if err is None:
                ok += 1
            else:
                errs.append((elf, err))
            if i % 500 == 0:
                rate = i / (time.time() - t0)
                print(f"  {i:,}/{len(elfs):,}  ok={ok}  err={len(errs)}  "
                      f"({rate:.0f} elf/s)")

    print(f"\ndone: {ok}/{len(elfs)} ok, {len(errs)} errors "
          f"in {time.time()-t0:.1f}s")
    if errs:
        print("first errors:")
        for e, msg in errs[:10]:
            print(f"  {e}: {msg}")

    # Size summary
    total = 0
    n = 0
    for j in out_root.rglob("*.json"):
        total += j.stat().st_size
        n += 1
    print(f"\nanalysis/ now: {n:,} json files, "
          f"{total/1024/1024:.1f} MB total "
          f"({total/n if n else 0:.0f} bytes avg)")


if __name__ == "__main__":
    main()
