#!/usr/bin/env python3
"""Run eu-elflint over every ELF in the corpus and aggregate findings.

elfutils' elflint is a far more thorough conformance checker than we
care to (re-)implement in Python — it covers section-header consistency,
hash / gnu-hash bucket validity, version-table walks, group sections,
note format parsing, per-arch quirks, etc. (~4900 lines of C in
../third_party/impl-tool/elfutils/src/elflint.c). We use it as a second-opinion
oracle next to scripts/survey.py:

  - per-file output: corpus/elflint/<repo>/<pkg>/<rel>.txt
    (only written when eu-elflint emitted at least one finding)
  - corpus aggregate: corpus/elflint_summary.json
    {kind, count, samples} for every distinct message template, plus
    n_files / n_clean / n_dirty / n_timeout / n_failed.

The "kind" of a finding is its message template with all numbers,
hex addresses, and quoted strings (section names, etc.) stripped out
— so e.g.

  section [ 7] '.relro_padding' has wrong type: expected RELR, is NOBITS
  section [12] '.foo' has wrong type: expected RELR, is NOBITS

both reduce to

  section [N] 'STR' has wrong type: expected RELR, is NOBITS

which gives us a stable bucket key.

Reuses the analysis tree as the authoritative ELF list (one .json per
ELF; same relative path under corpus/unpacked/).
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UNPACKED = ROOT / "corpus" / "unpacked"
ANALYSIS = ROOT / "corpus" / "analysis"
ELFLINT_OUT = ROOT / "corpus" / "elflint"

EU_ELFLINT = os.environ.get("EU_ELFLINT", "eu-elflint")


# --- message normalization ---------------------------------------------------

# Strip bracketed indices like "[ 7]" or "[12]" → "[N]"
_RE_BRACKET = re.compile(r"\[\s*\d+\s*\]")
# Strip single-quoted strings (section names, etc.)
_RE_QUOTED = re.compile(r"'[^']*'")
# Strip parenthesized identifiers (symbol names like "(arguments)",
# "(size->number@guix/ui)") so they collapse into one bucket per
# template. We accept any non-paren content, which folds the very
# long Guile/Guix symbol-name tail.
_RE_PAREN = re.compile(r"\(([^()]+)\)")
# Strip hex literals
_RE_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
# Strip standalone decimal numbers
_RE_NUM = re.compile(r"\b\d+\b")
# Collapse runs of whitespace
_RE_WS = re.compile(r"\s+")


def normalise_msg(line: str) -> str:
    s = _RE_BRACKET.sub("[N]", line)
    s = _RE_QUOTED.sub("'STR'", s)
    s = _RE_PAREN.sub("(STR)", s)
    s = _RE_HEX.sub("0xN", s)
    s = _RE_NUM.sub("N", s)
    s = _RE_WS.sub(" ", s).strip()
    return s


# --- per-ELF runner ---------------------------------------------------------


def _run_one(args: tuple[str, str, bool]) -> dict:
    """Run eu-elflint on one ELF and return a result record."""
    elf_path, rel, force = args
    out_path = ELFLINT_OUT / (rel + ".txt")
    rec = {"rel": rel, "n_findings": 0, "kinds": [],
           "status": "ok", "error": None}

    if out_path.exists() and not force:
        # Reuse cached output.
        try:
            text = out_path.read_text(errors="replace")
        except OSError as e:
            rec["status"] = "read_err"
            rec["error"] = str(e)
            return rec
        rec["status"] = "cached"
        lines = [ln for ln in text.splitlines() if ln.strip()]
        rec["n_findings"] = len(lines)
        rec["kinds"] = [normalise_msg(ln) for ln in lines]
        return rec

    try:
        p = subprocess.run(
            [EU_ELFLINT, "-q", elf_path],
            capture_output=True, text=True, timeout=60,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        rec["status"] = "timeout"
        return rec
    except FileNotFoundError as e:
        rec["status"] = "no_binary"
        rec["error"] = str(e)
        return rec
    except OSError as e:
        rec["status"] = "exec_err"
        rec["error"] = str(e)
        return rec

    # eu-elflint -q exits 0 even on findings; stdout has them, stderr
    # is usually empty (or "cannot read ELF" on outright invalid input).
    text = (p.stdout or "") + (p.stderr or "")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text)
        rec["n_findings"] = len(lines)
        rec["kinds"] = [normalise_msg(ln) for ln in lines]
    elif out_path.exists():
        # Was dirty before, now clean → drop stale file.
        out_path.unlink()
    if p.returncode != 0 and p.returncode != 1:
        rec["status"] = f"rc{p.returncode}"
    return rec


# --- enumerate ELFs ---------------------------------------------------------


def enumerate_elfs(repo: str | None, pkg: str | None) -> list[tuple[str, str]]:
    """Return [(absolute_elf_path, rel_path_under_unpacked), ...]."""
    base = ANALYSIS
    if not base.is_dir():
        print(f"elflint_run: {base} not found", file=sys.stderr)
        sys.exit(2)
    roots = [base / repo] if repo else [base / r for r in ("main", "community")]
    out: list[tuple[str, str]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for j in root.rglob("*.json"):
            rel = str(j.relative_to(ANALYSIS))[:-5]   # drop ".json"
            if pkg and f"/{pkg}/" not in "/" + rel + "/":
                continue
            elf = UNPACKED / rel
            if elf.exists():
                out.append((str(elf), rel))
    out.sort()
    return out


# --- driver -----------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", choices=("main", "community"), default=None)
    ap.add_argument("--pkg", default=None, help="restrict to package <name>")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--limit", type=int, default=0,
                    help="cap N (for smoke tests)")
    ap.add_argument("--force", action="store_true",
                    help="re-run even when per-file output is cached")
    ap.add_argument("--out", default="corpus/elflint_summary.json",
                    help="aggregate JSON path")
    ap.add_argument("--top-samples", type=int, default=10,
                    help="store at most N sample file paths per kind")
    args = ap.parse_args()

    if subprocess.run([EU_ELFLINT, "--version"],
                      capture_output=True).returncode != 0:
        print(f"elflint_run: {EU_ELFLINT} not runnable", file=sys.stderr)
        return 2

    t0 = time.time()
    elfs = enumerate_elfs(args.repo, args.pkg)
    if args.limit:
        elfs = elfs[: args.limit]
    print(f"found {len(elfs):,} ELFs in {time.time()-t0:.1f}s",
          file=sys.stderr)
    if not elfs:
        return 1

    ELFLINT_OUT.mkdir(parents=True, exist_ok=True)
    work = [(e, r, args.force) for e, r in elfs]

    # Deterministic, order-independent reservoir sampling for per-kind
    # representative files (see scripts/survey.py:_reservoir_push for
    # full rationale). imap_unordered means worker completion order
    # depends on file size + scheduling, so naïve first-N sampling is
    # biased and unreproducible. Hashing (kind, path) into a uniform
    # score and keeping the N smallest gives uniform-random samples
    # that are stable across runs.
    def _score(kind: str, rel: str) -> float:
        h = hashlib.blake2b(f"elflint|{kind}|{rel}".encode(),
                            digest_size=8).digest()
        return int.from_bytes(h, "big") / (1 << 64)

    def _push(heap: list, cap: int, kind: str, rel: str) -> None:
        s = _score(kind, rel)
        entry = (-s, rel)
        if len(heap) < cap:
            heapq.heappush(heap, entry)
        elif entry > heap[0]:
            heapq.heapreplace(heap, entry)

    t0 = time.time()
    n_dirty = n_clean = n_timeout = n_failed = n_cached = 0
    kind_count: Counter[str] = Counter()
    kind_samples: dict[str, list] = {}     # kind -> max-heap reservoir
    findings_per_file: Counter[int] = Counter()
    with mp.Pool(args.jobs) as pool:
        for rec in pool.imap_unordered(_run_one, work, chunksize=16):
            s = rec["status"]
            if s == "ok":
                if rec["n_findings"]:
                    n_dirty += 1
                else:
                    n_clean += 1
            elif s == "cached":
                if rec["n_findings"]:
                    n_dirty += 1
                else:
                    n_clean += 1
                n_cached += 1
            elif s == "timeout":
                n_timeout += 1
                continue
            else:
                n_failed += 1
                continue

            findings_per_file[rec["n_findings"]] += 1
            seen_in_file: set[str] = set()
            for k in rec["kinds"]:
                kind_count[k] += 1
                if k in seen_in_file:
                    continue
                seen_in_file.add(k)
                _push(kind_samples.setdefault(k, []),
                      args.top_samples, k, rec["rel"])
    print(f"scanned in {time.time()-t0:.1f}s "
          f"({n_dirty} dirty / {n_clean} clean / "
          f"{n_timeout} timeout / {n_failed} failed, "
          f"{n_cached} reused from cache)", file=sys.stderr)

    summary = {
        "n_files": n_dirty + n_clean,
        "n_clean": n_clean,
        "n_dirty": n_dirty,
        "n_timeout": n_timeout,
        "n_failed": n_failed,
        "n_cached": n_cached,
        "n_total_findings": sum(kind_count.values()),
        "n_distinct_kinds": len(kind_count),
        "findings_per_file_histogram":
            dict(sorted(findings_per_file.items())),
        "kinds": [
            {"kind": k, "count": n,
             "samples": sorted(rel for _, rel in kind_samples.get(k, []))}
            for k, n in kind_count.most_common()
        ],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"wrote {out_path}", file=sys.stderr)

    # Brief stdout report.
    print(f"\n# eu-elflint summary  ({summary['n_files']:,} ELFs scanned)")
    print(f"  clean files :  {n_clean:>7,}")
    print(f"  dirty files :  {n_dirty:>7,}")
    print(f"  total finds :  {summary['n_total_findings']:>7,}")
    print(f"  distinct kinds: {summary['n_distinct_kinds']:>6,}")
    print(f"\n## Top 25 finding kinds")
    for entry in summary["kinds"][:25]:
        k, n = entry["kind"], entry["count"]
        print(f"  {n:>7,}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
