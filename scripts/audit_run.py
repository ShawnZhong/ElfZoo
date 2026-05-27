#!/usr/bin/env python3
"""
Drive audit/audit.so across a subset of the corpus.

For each candidate ELF:
  1. Compute the source apk package from its unpacked-tree path.
  2. Build (or reuse) a per-package sysroot via sysroot.py's apk-closure
     materialiser. Cached at corpus/sysroots/<pkg>/.
  3. Invoke glibc's rtld (/lib64/ld-linux-x86-64.so.2) with
       LD_AUDIT=audit/audit.so
       AUDIT_LOG=corpus/audit/<…>/<elf>.jsonl
       LD_LIBRARY_PATH=<sysroot>/lib:<sysroot>/usr/lib
     and let audit.so dump every reloc slot at LA_ACT_CONSISTENT, then
     _exit(0) — never reaching the foreign libc's _start, so musl /
     klibc binaries don't SIGSEGV.

A binary is "loadable" iff its dump has PT_INTERP and a non-empty
DynamicSection. We sample uniformly across the 19k-ish such ELFs in
main + community.

Outputs:
  corpus/audit/<repo>/<pkg>/<rel>.jsonl    on success
  corpus/audit/<repo>/<pkg>/<rel>.err      on failure

Usage:
  scripts/audit_run.py                  # default: 100 random ELFs
  scripts/audit_run.py --sample 500
  scripts/audit_run.py --pkg busybox coreutils
  scripts/audit_run.py --all
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus"
UNPACKED = CORPUS / "unpacked"
ANALYSIS = CORPUS / "analysis"
SYSROOTS = CORPUS / "sysroots"
AUDIT_OUT = CORPUS / "audit"

AUDIT_SO = REPO / "audit" / "audit.so"
GLIBC_RTLD = "/lib64/ld-linux-x86-64.so.2"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sysroot as sr  # noqa: E402


# corpus/unpacked/<repo>/<pkg-ver-rel>/<rest>
_PKG_PATH_RE = re.compile(r"^([^/]+)/([^/]+)/(.*)$")
# strip "-<ver>-r<rel>" suffix from a package dir name → bare pkg name
_PKG_VER_SUFFIX_RE = re.compile(r"-[^-]+-r\d+$")


def parse_pkg_path(elf: Path):
    """(repo, pkg_dir, rel_inside_pkg) or None."""
    try:
        rel = elf.relative_to(UNPACKED)
    except ValueError:
        return None
    m = _PKG_PATH_RE.match(str(rel))
    return m.groups() if m else None


def pkg_name(pkg_dir_name: str) -> str:
    return _PKG_VER_SUFFIX_RE.sub("", pkg_dir_name)


def _name(field):
    """llvm-readobj enum: dict {Name, Value} or string 'PT_INTERP (3)'."""
    if isinstance(field, dict):
        return field.get("Name", "")
    if isinstance(field, str):
        return field.split(" (", 1)[0]
    return ""


def _scan_one(jpath: Path):
    """Return ELF path if json says PT_INTERP + non-empty Dynamic, else None."""
    try:
        with open(jpath, "rb") as f:
            doc = json.load(f)[0]
    except Exception:
        return None
    phs = doc.get("ProgramHeaders", [])
    has_interp = False
    for ph in phs:
        body = ph.get("ProgramHeader", ph)
        if _name(body.get("Type")) == "PT_INTERP":
            has_interp = True
            break
    if not has_interp:
        return None
    if not doc.get("DynamicSection"):
        return None
    rel = jpath.relative_to(ANALYSIS)
    elf = UNPACKED / rel.with_suffix("")  # strip .json
    if not elf.exists():
        return None
    return str(elf)


def select_loadable(limit: int | None, seed: int, jobs: int, repos):
    """Walk analysis/<repo>/ in parallel; return loadable ELFs."""
    jsons: list[Path] = []
    for repo in repos:
        root = ANALYSIS / repo
        if root.exists():
            jsons.extend(root.rglob("*.json"))
    jsons.sort()
    if not jsons:
        print(f"no .json under {ANALYSIS} for {repos} — "
              f"run scripts/dump.py first", file=sys.stderr)
        sys.exit(2)
    with mp.Pool(jobs) as pool:
        loadable = [p for p in pool.imap_unordered(_scan_one, jsons,
                                                   chunksize=64)
                    if p]
    loadable.sort()
    if limit and limit < len(loadable):
        rng = random.Random(seed)
        loadable = rng.sample(loadable, limit)
    return [Path(p) for p in loadable]


def ensure_sysroot(pkg: str, pkg_by_name, provider_by_tag, pkg_dir):
    """Materialise sysroot for `pkg` if missing. Return its Path."""
    out = SYSROOTS / pkg
    if out.exists() and (out / "lib").exists():
        return out
    pkgs, _unres, _picks, _conf = sr.closure(
        [pkg], pkg_by_name, provider_by_tag)
    sr.materialize(pkgs, pkg_dir, out, on_conflict="first")
    return out


def extract_runpath(elf: Path) -> list[str]:
    """Return DT_RUNPATH / DT_RPATH directory entries from the analysis JSON.

    Returned strings are exactly as recorded by the binary (absolute path,
    `$ORIGIN`-prefixed, or relative). Callers rewrite absolute paths into
    the sysroot via translate_runpath."""
    rel = elf.relative_to(UNPACKED)
    jpath = ANALYSIS / (str(rel) + ".json")
    if not jpath.exists():
        return []
    try:
        doc = json.loads(jpath.read_text())[0]
    except Exception:
        return []
    out: list[str] = []
    for ent in doc.get("DynamicSection", []):
        if ent.get("Type") in ("RUNPATH", "RPATH"):
            for p in ent.get("Path") or []:
                for q in p.split(":"):           # defensive; llvm already splits
                    if q:
                        out.append(q)
    return out


def translate_runpath(paths: list[str], sysroot: Path) -> list[str]:
    """Rewrite each absolute DT_RUNPATH entry to live inside sysroot.

    LD_LIBRARY_PATH does not expand `$ORIGIN`, so we drop those — they're
    already searched correctly via the unmodified DT_RUNPATH (glibc
    expands $ORIGIN relative to the executable's actual directory, which
    is the per-pkg unpacked tree). Relative entries are left as-is."""
    out: list[str] = []
    for p in paths:
        if p.startswith("/"):
            out.append(str(sysroot) + p)
        elif "$ORIGIN" in p or "${ORIGIN}" in p:
            continue
        else:
            out.append(p)
    return out


def run_one(args):
    elf, sysroot, out, timeout, ld_debug = args
    out.parent.mkdir(parents=True, exist_ok=True)
    err_path = out.with_suffix(".err")
    env = os.environ.copy()
    env["LD_AUDIT"] = str(AUDIT_SO)
    env["AUDIT_LOG"] = str(out)
    lp = [f"{sysroot}/lib", f"{sysroot}/usr/lib"]
    lp.extend(translate_runpath(extract_runpath(elf), sysroot))
    env["LD_LIBRARY_PATH"] = ":".join(lp)
    if ld_debug:
        # Glibc appends ".<pid>" to LD_DEBUG_OUTPUT, so pass the prefix.
        env["LD_DEBUG"] = ld_debug
        env["LD_DEBUG_OUTPUT"] = str(out.with_suffix(".lddebug"))
    try:
        proc = subprocess.run(
            [GLIBC_RTLD, "--argv0", elf.name, str(elf)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        rc = proc.returncode
        err = proc.stderr.decode(errors="replace") if proc.stderr else ""
    except subprocess.TimeoutExpired:
        rc = -1
        err = f"timeout after {timeout}s"
    except Exception as e:
        rc = -2
        err = f"{type(e).__name__}: {e}"

    n_lines = n_relocs = 0
    saw_consistent = False
    if out.exists():
        try:
            with open(out) as f:
                for line in f:
                    n_lines += 1
                    if '"event":"reloc"' in line:
                        n_relocs += 1
                    elif '"event":"consistent"' in line:
                        saw_consistent = True
        except Exception:
            pass

    ok = saw_consistent and n_relocs > 0
    if ok:
        if err_path.exists():
            err_path.unlink()
    else:
        # Persist diagnostic so we can triage failures without re-running.
        msg = f"rc={rc}\n--- stderr ---\n{err[:4000]}\n"
        err_path.write_text(msg)

    return {
        "elf": str(elf),
        "rc": rc,
        "n_lines": n_lines,
        "n_relocs": n_relocs,
        "ok": ok,
        "err1": err.split("\n", 1)[0][:160],
    }


def main():
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    ap.add_argument("--sample", type=int, default=100,
                    help="Random sample size from loadable ELFs (default 100)")
    ap.add_argument("--all", action="store_true",
                    help="Audit every loadable ELF (ignores --sample).")
    ap.add_argument("--pkg", nargs="+",
                    help="Audit every ELF inside these packages only.")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--repo", nargs="+", default=["main", "community"],
                    choices=["main", "community"],
                    help="Alpine repos to audit (default: both).")
    ap.add_argument("--force", action="store_true",
                    help="Re-audit even if .jsonl already exists.")
    ap.add_argument("--lddebug", nargs="?", const="files,scopes,bindings",
                    default="",
                    help="Capture LD_DEBUG=<categories> to <out>.lddebug.<pid>. "
                         "Default categories if flag given without value: "
                         "files,scopes,bindings. Pass --lddebug=all for "
                         "everything (very verbose).")
    args = ap.parse_args()

    if not AUDIT_SO.exists():
        print(f"build audit.so first: gcc -shared -fPIC -O2 -o {AUDIT_SO} "
              f"audit/audit.c", file=sys.stderr)
        return 2

    limit = None if (args.all or args.pkg) else args.sample

    print(f"scanning analysis/ for loadable ELFs in {args.repo} …",
          file=sys.stderr)
    t0 = time.time()
    elves = select_loadable(limit, args.seed, args.jobs, args.repo)
    print(f"  {len(elves):,} candidates in {time.time() - t0:.1f}s",
          file=sys.stderr)

    if args.pkg:
        wanted = set(args.pkg)
        elves = [e for e in elves
                 if (m := parse_pkg_path(e)) and pkg_name(m[1]) in wanted]
        print(f"  filtered to {len(elves):,} ELFs in {len(wanted)} packages",
              file=sys.stderr)

    # Group by pkg so we build each sysroot once.
    by_pkg: dict[str, list] = {}
    for e in elves:
        meta = parse_pkg_path(e)
        if meta is None:
            continue
        by_pkg.setdefault(pkg_name(meta[1]), []).append((e, meta))

    print(f"  {len(by_pkg)} unique packages", file=sys.stderr)

    print("loading APKINDEX …", file=sys.stderr)
    pkg_by_name, provider_by_tag, pkg_dir = sr.load_index(args.repo)

    print("ensuring sysroots …", file=sys.stderr)
    t0 = time.time()
    skip_pkgs = set()
    for pname in sorted(by_pkg):
        try:
            ensure_sysroot(pname, pkg_by_name, provider_by_tag, pkg_dir)
        except Exception as ex:
            print(f"  sysroot {pname}: {type(ex).__name__}: {ex}",
                  file=sys.stderr)
            skip_pkgs.add(pname)
    print(f"  done in {time.time() - t0:.1f}s "
          f"({len(by_pkg) - len(skip_pkgs)} ok, {len(skip_pkgs)} skipped)",
          file=sys.stderr)

    # Build job list.
    AUDIT_OUT.mkdir(parents=True, exist_ok=True)
    jobs = []
    for pname, items in by_pkg.items():
        if pname in skip_pkgs:
            continue
        sysroot = SYSROOTS / pname
        for elf, meta in items:
            repo, pdir, rel = meta
            out = AUDIT_OUT / repo / pdir / rel
            out = out.with_name(out.name + ".jsonl")
            if out.exists() and not args.force:
                continue
            jobs.append((elf, sysroot, out, args.timeout, args.lddebug))

    if not jobs:
        print("nothing to do (all targets cached; pass --force to redo)",
              file=sys.stderr)
        return 0

    print(f"running {len(jobs)} audit jobs on {args.jobs} workers "
          f"(timeout {args.timeout}s) …", file=sys.stderr)
    t0 = time.time()
    with mp.Pool(args.jobs) as pool:
        results = pool.map(run_one, jobs, chunksize=1)
    dt = time.time() - t0

    ok = [r for r in results if r["ok"]]
    bad = [r for r in results if not r["ok"]]
    total_relocs = sum(r["n_relocs"] for r in ok)
    print(f"\n=== summary ({dt:.1f}s, {len(jobs) / dt:.1f} ELFs/s) ===",
          file=sys.stderr)
    print(f"  ok:        {len(ok):>4}/{len(results)}", file=sys.stderr)
    print(f"  failed:    {len(bad):>4}", file=sys.stderr)
    print(f"  relocs:    {total_relocs:>12,}  "
          f"(avg {total_relocs / max(len(ok), 1):.0f}/ELF)",
          file=sys.stderr)

    if bad:
        # Bucket failures by first-line stderr signature.
        from collections import Counter
        buckets = Counter()
        for r in bad:
            sig = r["err1"]
            for pat in ("symbol lookup error", "cannot open shared object",
                        "undefined symbol", "no version information",
                        "timeout after"):
                if pat in sig:
                    sig = pat
                    break
            buckets[(r["rc"], sig)] += 1
        print(f"\n  top failure modes:", file=sys.stderr)
        for (rc, sig), n in buckets.most_common(10):
            print(f"    {n:>4}  rc={rc:<4}  {sig}", file=sys.stderr)


if __name__ == "__main__":
    main()
