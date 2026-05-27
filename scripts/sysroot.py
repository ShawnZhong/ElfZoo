#!/usr/bin/env python3
"""
APKINDEX-driven per-package sysroot builder.

Given one or more "root" package names, compute the apk dependency
closure (transitively following `D:` entries via the global
soname/cmd/pkg provider map), then materialise a symlink farm at
    corpus/sysroots/<key>/
that mirrors the Alpine filesystem layout (so PT_INTERP
`/lib/ld-musl-x86_64.so.1` resolves naturally inside the sysroot).

Within a single apk closure there are no path collisions by
construction — Alpine refuses to install two packages whose paths
conflict. The 40k cross-package collisions in the full corpus all
sit between *mutually-exclusive* package families (coreutils vs
uutils-coreutils, php83 vs php84, emacs-gtk3 vs emacs-x11, …) and
the apk graph never pulls both into one closure.

Usage:
    scripts/sysroot.py openssl
    scripts/sysroot.py --out /tmp/foo busybox musl
    scripts/sysroot.py --print-closure openssl     # just list pkgs
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "corpus"

# Strip everything from the first version-constraint operator onward.
# Dep tokens in APKINDEX look like `pkg`, `pkg=1.2`, `pkg>=1.2`,
# `so:libfoo.so.1`, `so:libfoo.so.1=1.2.3-r0`, `cmd:foo`, `pc:foo`.
_VERSION_RE = re.compile(r"[<>=~].*$")


def parse_apkindex(path: Path):
    """Yield package-record dicts from one APKINDEX.tar.gz."""
    with tarfile.open(path, "r:gz") as tf:
        f = tf.extractfile("APKINDEX")
        if f is None:
            return
        rec: dict[str, str] = {}
        for raw in f:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if not line:
                if rec:
                    yield rec
                    rec = {}
                continue
            tag, _, val = line.partition(":")
            rec[tag] = val
        if rec:
            yield rec


def _strip_constraint(tok: str) -> str:
    return _VERSION_RE.sub("", tok)


def _split_field(field: str) -> list[str]:
    """Split a space-separated D:/p:/i: field, dropping conflicts (`!pkg`)."""
    if not field:
        return []
    out = []
    for tok in field.split():
        if tok.startswith("!"):
            continue
        out.append(_strip_constraint(tok))
    return out


def _split_conflicts(field: str) -> list[str]:
    """Yield the bare names of `!pkg` conflict tokens in a D: field."""
    if not field:
        return []
    return [_strip_constraint(t[1:]) for t in field.split()
            if t.startswith("!")]


def _priority(rec: dict[str, str]) -> int:
    try:
        return int(rec.get("k", "0"))
    except ValueError:
        return 0


def load_index(repos: list[str]):
    """Parse APKINDEXes; return (pkg_by_name, provider_by_tag, pkg_dir).

    Provider lists are sorted by (-provider_priority, name) so the
    highest-priority provider is first. This matches apk-tools'
    selection for multi-provider tags (e.g. `/bin/sh` is provided by
    busybox-binsh @100, dash-binsh @0, yash-binsh @0 → busybox-binsh).
    """
    pkg_by_name: dict[str, dict[str, str]] = {}
    provider_by_tag: dict[str, list[str]] = defaultdict(list)
    pkg_dir: dict[str, Path] = {}
    for repo in repos:
        idx = CORPUS / "mirror" / repo / "APKINDEX.tar.gz"
        unpacked_root = CORPUS / "unpacked" / repo
        if not idx.is_file():
            print(f"warning: missing {idx}", file=sys.stderr)
            continue
        for rec in parse_apkindex(idx):
            name = rec.get("P")
            ver = rec.get("V")
            if not name or not ver:
                continue
            rec["_repo"] = repo
            pkg_by_name[name] = rec
            pkg_dir[name] = unpacked_root / f"{name}-{ver}"
            # Self-name is implicitly a provider.
            provider_by_tag[name].append(name)
            for prov in _split_field(rec.get("p", "")):
                provider_by_tag[prov].append(name)
    for tag, names in provider_by_tag.items():
        provider_by_tag[tag] = sorted(
            set(names),
            key=lambda n: (-_priority(pkg_by_name[n]), n),
        )
    return pkg_by_name, provider_by_tag, pkg_dir


def resolve_dep(tag, provider_by_tag, pkg_by_name):
    if tag in provider_by_tag:
        return provider_by_tag[tag]
    if tag in pkg_by_name:
        return [tag]
    return []


def closure(roots, pkg_by_name, provider_by_tag):
    """Transitive apk closure of `roots`.

    Selection rule for multi-provider tags matches apk-tools:
      1. prefer a candidate already in the closure (no churn);
      2. otherwise pick the highest-priority provider — which is the
         first element since `provider_by_tag` is presorted by
         (-priority, name) in `load_index`.

    Returns (pkgs, unresolved, picks, conflicts) where `conflicts` is
    the list of `!pkg` markers whose target is in the closure.
    """
    seen: set[str] = set()
    queue: list[str] = list(roots)
    unresolved: list[str] = []
    picks: list[tuple[str, list[str], str]] = []
    conflict_decls: list[tuple[str, str]] = []  # (declarer, !target)
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        rec = pkg_by_name.get(name)
        if rec is None:
            unresolved.append(name)
            continue
        seen.add(name)
        for dep in _split_field(rec.get("D", "")):
            cands = resolve_dep(dep, provider_by_tag, pkg_by_name)
            if not cands:
                unresolved.append(dep)
                continue
            picked = next((c for c in cands if c in seen), cands[0])
            if len(cands) > 1:
                picks.append((dep, cands, picked))
            queue.append(picked)
        for bad in _split_conflicts(rec.get("D", "")):
            conflict_decls.append((name, bad))
    # A conflict bites only if both declarer and target end up in the closure.
    conflicts = [(d, t) for (d, t) in conflict_decls if t in seen]
    return seen, unresolved, picks, conflicts


def materialize(pkgs, pkg_dir, out_dir: Path, *, on_conflict="error"):
    """
    Symlink the union of every file in every closure pkg into out_dir,
    preserving the apk-relative path as the syspath.

    on_conflict ∈ {"error","first","last"}:
      error  — record but do not overwrite (callers should treat any
               collision as a graph bug)
      first  — keep the first-seen entry (alphabetical pkg order)
      last   — overwrite with the latest entry
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    owner: dict[str, str] = {}
    n_links = 0
    collisions: list[tuple[str, str, str]] = []

    for name in sorted(pkgs):
        pdir = pkg_dir.get(name)
        if pdir is None or not pdir.is_dir():
            continue
        for root, dirs, files in os.walk(pdir, followlinks=False):
            rel_root = Path(root).relative_to(pdir)
            dst_root = out_dir / rel_root

            # Symlinks to dirs: treat as file entries (don't recurse).
            sym_dirs = [d for d in dirs if (Path(root) / d).is_symlink()]
            real_dirs = [d for d in dirs if d not in sym_dirs]
            dirs[:] = real_dirs

            dst_root.mkdir(parents=True, exist_ok=True)

            for entry in files + sym_dirs:
                if rel_root == Path(".") and entry.startswith("."):
                    continue  # .PKGINFO etc. shouldn't be here, but skip
                src = (Path(root) / entry).resolve(strict=False)
                dst = dst_root / entry
                syspath = "/" + str(rel_root / entry).replace("\\", "/")
                if syspath.startswith("/./"):
                    syspath = syspath[2:]
                if dst.is_symlink() or dst.exists():
                    prior = owner.get(syspath, "?")
                    collisions.append((syspath, prior, name))
                    if on_conflict == "last":
                        dst.unlink()
                    else:
                        continue
                dst.symlink_to(src)
                owner[syspath] = name
                n_links += 1

    return n_links, collisions


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", action="append",
                   help="Repos to load (default: main, community)")
    p.add_argument("--out", help="Sysroot output dir "
                                 "(default: corpus/sysroots/<first-root>)")
    p.add_argument("--manifest", help="Write the closure manifest here")
    p.add_argument("--print-closure", action="store_true",
                   help="Just print the closure; don't materialise.")
    p.add_argument("--on-conflict", default="error",
                   choices=["error", "first", "last"])
    p.add_argument("--force", action="store_true",
                   help="Remove existing sysroot before materialising.")
    p.add_argument("roots", nargs="+", help="Root package names.")
    args = p.parse_args()

    repos = args.repo or ["main", "community"]
    print(f"loading APKINDEX for {repos} …", file=sys.stderr)
    pkg_by_name, provider_by_tag, pkg_dir = load_index(repos)
    print(f"  {len(pkg_by_name)} packages, "
          f"{len(provider_by_tag)} provider tags",
          file=sys.stderr)

    pkgs, unresolved, picks, conflicts = closure(
        args.roots, pkg_by_name, provider_by_tag)
    print(f"closure({' '.join(args.roots)}) → {len(pkgs)} packages",
          file=sys.stderr)
    if unresolved:
        uniq = sorted(set(unresolved))
        print(f"  {len(uniq)} unresolved deps "
              f"({', '.join(uniq[:6])}{'…' if len(uniq) > 6 else ''})",
              file=sys.stderr)
    if picks:
        print(f"  {len(picks)} multi-provider picks "
              f"(first ex: {picks[0][0]!r} chose {picks[0][2]!r} "
              f"from {picks[0][1]!r})",
              file=sys.stderr)
    if conflicts:
        print(f"  {len(conflicts)} conflicts inside the closure "
              f"(first ex: {conflicts[0][0]} !{conflicts[0][1]})",
              file=sys.stderr)

    if args.print_closure:
        for name in sorted(pkgs):
            print(name)
        return

    out_dir = (Path(args.out) if args.out
               else CORPUS / "sysroots" / args.roots[0])
    if args.force and out_dir.exists():
        shutil.rmtree(out_dir)
    print(f"materialising into {out_dir} …", file=sys.stderr)
    n, collisions = materialize(pkgs, pkg_dir, out_dir,
                                on_conflict=args.on_conflict)
    print(f"  {n} symlinks created, {len(collisions)} collisions",
          file=sys.stderr)
    for sp, prior, new in collisions[:5]:
        print(f"  collision: {sp}  prior={prior}  new={new}", file=sys.stderr)

    if args.manifest:
        Path(args.manifest).write_text(
            "# closure of " + " ".join(args.roots) + "\n"
            + "\n".join(sorted(pkgs)) + "\n"
        )


if __name__ == "__main__":
    main()
