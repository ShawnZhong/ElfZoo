#!/usr/bin/env python3
"""Build and analyse the corpus-wide DT_NEEDED graph.

Walks every corpus/analysis/**/*.json once, extracts each ELF's
SONAME / DT_NEEDED / DT_VERNEED / DT_VERDEF, and emits
`corpus/dep_graph.json` plus a stdout markdown summary.

Restricted to ELFs that look like real load-graph participants
(ET_EXEC / ET_DYN with PT_DYNAMIC and EM_X86_64). Debug-only,
relocatable, cross-arch, and EM_NONE files are skipped — they
don't have meaningful runtime NEEDED edges.

The output JSON contains:

    {
      "n_files":       <int>,              # ELFs that contributed nodes
      "n_providers":   <int>,              # ELFs that declared a SONAME
      "n_consumers":   <int>,              # ELFs with at least one NEEDED
      "providers":     {soname: [path, …]},
      "consumers":     {path:   [soname, …]},
      "verneed":       {path:   {soname: [verset, …]}},
      "verdef":        {path:   [verset, …]},
      "soname_use":    {soname: <count of files NEEDING it>},
      "conflicts":     [{soname, providers: [path, …]}, …],
      "external":      [soname, …],        # NEEDED but no in-corpus provider
      "closures":      {path: {dsos: [path, …], external: [soname, …],
                               unresolved: [soname, …], depth: <int>}},
      "closure_size_histogram": {<size>: <count>, …},
      "cycles":        [[soname, …], …],   # one entry per non-trivial SCC
      "top_in_degree": [{soname, in_degree}, …],
      "top_out_degree":[{path, out_degree, soname}, …],
      "version_mismatches": [{soname, verset, requesters: [path, …]}, …],
    }

Usage:

    scripts/dep_graph.py [--root corpus/analysis] [--jobs N]
                         [--out corpus/dep_graph.json]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any


ROOT_DEFAULT = "corpus/analysis"
OUT_DEFAULT = "corpus/dep_graph.json"

# Match survey.py's loadable-bucket predicate. We only build the graph
# for files the dynamic loader would actually consume.
def _is_loadable(doc: dict) -> bool:
    hdr = doc.get("ElfHeader", {})
    et = hdr.get("Type", "")
    if isinstance(et, dict):
        et = et.get("Name", "")
    if isinstance(et, str) and "(" in et:
        et = et.split("(", 1)[0].strip()
    if et not in ("SharedObject", "Executable"):
        return False
    em = hdr.get("Machine", "")
    if isinstance(em, dict):
        em = em.get("Name", "")
    if isinstance(em, str) and "(" in em:
        em = em.split("(", 1)[0].strip()
    if em != "EM_X86_64":
        return False
    fs = doc.get("FileSummary", {})
    if fs.get("Arch") == "unknown":
        return False
    # Debuginfo files: dropped by the path heuristic at the caller
    # level (the analysis-path string check), since we don't have
    # the source path in the dump itself.
    return True


def _rel(p: Path, root: Path) -> str:
    """Strip the analysis root + .json suffix, leaving the original
    relative path under corpus/unpacked/."""
    s = str(p.relative_to(root))
    return s[:-5] if s.endswith(".json") else s


def _looks_like_debuginfo(rel: str) -> bool:
    return ("/usr/lib/debug/" in rel
            or rel.endswith(".debug")
            or rel.endswith(".dbg"))


def _extract_one(args: tuple[str, str]) -> dict[str, Any] | None:
    """Worker: open one analysis JSON, return per-file dep info,
    or None if the file should be skipped."""
    abspath, rel = args
    if _looks_like_debuginfo(rel):
        return None
    try:
        with open(abspath, "rb") as f:
            doc = json.load(f)[0]
    except Exception:
        return None
    if not _is_loadable(doc):
        return None

    soname: str | None = None
    needed: list[str] = []
    for e in doc.get("DynamicSection", []) or []:
        t = e.get("Type", "")
        if t == "SONAME":
            soname = e.get("Name") or e.get("Value")
        elif t == "NEEDED":
            lib = e.get("Library")
            if lib:
                needed.append(lib)

    verneed: dict[str, list[str]] = {}
    for vr in doc.get("VersionRequirements", []) or []:
        dep = vr.get("Dependency", {})
        lib = dep.get("FileName")
        if not lib:
            continue
        sets = []
        for ent in dep.get("Entries", []) or []:
            entry = ent.get("Entry", {})
            name = entry.get("Name")
            if name:
                sets.append(name)
        if sets:
            verneed.setdefault(lib, []).extend(sets)

    verdef: list[str] = []
    for vd in doc.get("VersionDefinitions", []) or []:
        defn = vd.get("Definition", {})
        flags = defn.get("Flags", {})
        flag_names = {f.get("Name") for f in (flags.get("Flags") or [])
                      if isinstance(f, dict)}
        if "Base" in flag_names:
            # The "Base" def is just the file's own SONAME, not a real
            # version-set. Skip it so verdef lists only actual sets.
            continue
        name = defn.get("Name")
        if name:
            verdef.append(name)

    return {
        "path": rel,
        "soname": soname,
        "needed": needed,
        "verneed": verneed,
        "verdef": verdef,
    }


def _walk(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for p in root.rglob("*.json"):
        out.append((str(p), _rel(p, root)))
    return out


# ---- graph analyses --------------------------------------------------------

def _build_providers(records: list[dict]) -> dict[str, list[str]]:
    """soname -> sorted list of file paths declaring it as DT_SONAME."""
    providers: dict[str, list[str]] = defaultdict(list)
    for r in records:
        s = r["soname"]
        if s:
            providers[s].append(r["path"])
    for v in providers.values():
        v.sort()
    return dict(providers)


def _closure(start: str, edges: dict[str, list[str]],
             providers: dict[str, list[str]]
             ) -> dict[str, Any]:
    """BFS closure from one path. edges[path] = NEEDED sonames.
    Resolution: NEEDED soname -> providers[soname][0] (first provider
    by sort order, deterministic). Tracks unresolved sonames."""
    seen: set[str] = {start}
    external: set[str] = set()
    unresolved: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    depth = 0
    while queue:
        cur, d = queue.popleft()
        depth = max(depth, d)
        for s in edges.get(cur, ()):
            provs = providers.get(s)
            if not provs:
                external.add(s)
                continue
            pick = provs[0]
            if pick not in seen:
                seen.add(pick)
                queue.append((pick, d + 1))
    seen.discard(start)
    return {
        "dsos": sorted(seen),
        "external": sorted(external),
        "unresolved": sorted(unresolved),
        "depth": depth,
    }


def _scc_tarjan(nodes: list[str],
                edges: dict[str, list[str]]) -> list[list[str]]:
    """Standard iterative Tarjan SCC on the SONAME-level graph
    (provider-soname -> NEEDED-soname). Returns non-trivial SCCs
    (size >= 2 OR size == 1 with a self-loop)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []
    counter = [0]

    def strongconnect(v: str) -> None:
        # Iterative variant: simulate the recursion with an explicit
        # work stack of (node, iterator-of-neighbors).
        work: list[tuple[str, list[str], int]] = []
        # (v, neighbors, i)
        index[v] = counter[0]
        low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        work.append((v, edges.get(v, []), 0))
        while work:
            v, nb, i = work[-1]
            if i < len(nb):
                w = nb[i]
                work[-1] = (v, nb, i + 1)
                if w not in index:
                    index[w] = counter[0]
                    low[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, edges.get(w, []), 0))
                elif w in on_stack:
                    low[v] = min(low[v], index[w])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[v])
                if low[v] == index[v]:
                    comp: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    sccs.append(comp)

    for n in nodes:
        if n not in index:
            strongconnect(n)

    out: list[list[str]] = []
    for c in sccs:
        if len(c) >= 2:
            out.append(sorted(c))
        elif len(c) == 1 and c[0] in edges.get(c[0], ()):
            out.append(sorted(c))
    return out


def _analyse(records: list[dict]) -> dict[str, Any]:
    providers = _build_providers(records)
    consumers = {r["path"]: list(r["needed"]) for r in records
                 if r["needed"]}
    verneed = {r["path"]: r["verneed"] for r in records if r["verneed"]}
    verdef = {r["path"]: r["verdef"] for r in records if r["verdef"]}

    soname_use: Counter[str] = Counter()
    for needed in consumers.values():
        for s in needed:
            soname_use[s] += 1

    conflicts = [
        {"soname": s, "providers": ps, "n": len(ps)}
        for s, ps in sorted(providers.items())
        if len(ps) > 1
    ]
    conflicts.sort(key=lambda d: (-d["n"], d["soname"]))

    external = sorted(s for s in soname_use if s not in providers)

    # ---- closures -----------------------------------------------------------
    # SONAME-level edges: provider_soname -> NEEDED sonames.
    soname_edges: dict[str, list[str]] = {}
    soname_provider: dict[str, dict[str, list[str]]] = {}
    for r in records:
        if r["soname"]:
            soname_edges.setdefault(r["soname"], []).extend(r["needed"])
            soname_provider.setdefault(r["soname"], {"paths": [], "needed": []})
            soname_provider[r["soname"]]["paths"].append(r["path"])
            soname_provider[r["soname"]]["needed"] = r["needed"]
    # Deduplicate
    for s, lst in soname_edges.items():
        soname_edges[s] = sorted(set(lst))

    sccs = _scc_tarjan(sorted(soname_edges), soname_edges)

    # Path-level edges for closure walk: path -> NEEDED sonames.
    edges = {r["path"]: r["needed"] for r in records}

    closures: dict[str, dict[str, Any]] = {}
    size_hist: Counter[int] = Counter()
    for r in records:
        if not r["needed"]:
            continue
        c = _closure(r["path"], edges, providers)
        closures[r["path"]] = c
        size_hist[len(c["dsos"])] += 1

    # ---- ranks --------------------------------------------------------------
    top_in = [
        {"soname": s, "in_degree": n}
        for s, n in soname_use.most_common(50)
    ]
    top_out = sorted(
        (
            {"path": r["path"], "out_degree": len(r["needed"]),
             "soname": r["soname"] or ""}
            for r in records if r["needed"]
        ),
        key=lambda d: -d["out_degree"],
    )[:50]
    biggest_closure = sorted(
        ({"path": p, "closure_size": len(c["dsos"]),
          "external": len(c["external"])}
         for p, c in closures.items()),
        key=lambda d: -d["closure_size"],
    )[:50]

    # ---- versioned-symbol mismatches ---------------------------------------
    # For each NEEDED (soname, verset) requested by some file, check
    # that *some* provider of that soname declares that verset.
    provided_versets: dict[str, set[str]] = defaultdict(set)
    for path, vsets in verdef.items():
        # find the file's soname
        s = next((r["soname"] for r in records
                  if r["path"] == path and r["soname"]), None)
        if s:
            provided_versets[s].update(vsets)

    mismatch: dict[tuple[str, str], list[str]] = defaultdict(list)
    for path, vn in verneed.items():
        for soname, vsets in vn.items():
            have = provided_versets.get(soname)
            for vs in vsets:
                if have is None:
                    # External provider — can't verify, skip.
                    continue
                if vs not in have:
                    mismatch[(soname, vs)].append(path)
    version_mismatches = [
        {"soname": s, "verset": v, "requesters": sorted(reqs),
         "n": len(reqs)}
        for (s, v), reqs in mismatch.items()
    ]
    version_mismatches.sort(key=lambda d: (-d["n"], d["soname"], d["verset"]))

    n_files = len(records)
    n_providers = sum(1 for r in records if r["soname"])
    n_consumers = len(consumers)

    return {
        "n_files":       n_files,
        "n_providers":   n_providers,
        "n_consumers":   n_consumers,
        "n_sonames":     len(providers),
        "n_external":    len(external),
        "n_conflicts":   len(conflicts),
        "n_cycles":      len(sccs),
        "n_version_mismatches": len(version_mismatches),
        "providers":     providers,
        "consumers":     consumers,
        "verneed":       verneed,
        "verdef":        verdef,
        "soname_use":    dict(soname_use.most_common()),
        "conflicts":     conflicts,
        "external":      external,
        "closures":      closures,
        "closure_size_histogram": dict(sorted(size_hist.items())),
        "cycles":        sccs,
        "top_in_degree": top_in,
        "top_out_degree": top_out,
        "biggest_closure": biggest_closure,
        "version_mismatches": version_mismatches,
    }


# ---- main ------------------------------------------------------------------

def _print_summary(g: dict[str, Any]) -> None:
    print()
    print("# Dep-graph summary")
    print(f"  files in graph:      {g['n_files']:,}")
    print(f"  with SONAME:         {g['n_providers']:,}")
    print(f"  with ≥1 NEEDED:      {g['n_consumers']:,}")
    print(f"  distinct sonames:    {g['n_sonames']:,}")
    print(f"  external sonames:    {g['n_external']:,}")
    print(f"  provider conflicts:  {g['n_conflicts']:,}")
    print(f"  non-trivial SCCs:    {g['n_cycles']:,}")
    print(f"  version mismatches:  {g['n_version_mismatches']:,}")
    print()

    print("## Top SONAMEs by in-degree (most-NEEDED libs)")
    for d in g["top_in_degree"][:20]:
        print(f"  {d['in_degree']:>6,}  {d['soname']}")
    print()

    print("## Top out-degree (most NEEDED entries per file)")
    for d in g["top_out_degree"][:10]:
        s = f" [{d['soname']}]" if d["soname"] else ""
        print(f"  {d['out_degree']:>3}  {d['path']}{s}")
    print()

    print("## Top closure size (transitive DSO count)")
    for d in g["biggest_closure"][:10]:
        print(f"  {d['closure_size']:>4}  "
              f"({d['external']} external)  {d['path']}")
    print()

    print("## Closure-size histogram")
    h = g["closure_size_histogram"]
    if h:
        buckets = [(0, 0), (1, 1), (2, 5), (6, 10), (11, 20),
                   (21, 50), (51, 100), (101, 200), (201, 10_000)]
        rolled: dict[str, int] = {}
        for size, n in h.items():
            size = int(size)
            for lo, hi in buckets:
                if lo <= size <= hi:
                    label = f"{lo}-{hi}" if lo != hi else f"{lo}"
                    rolled[label] = rolled.get(label, 0) + n
                    break
        order = ["0", "1", "2-5", "6-10", "11-20", "21-50",
                 "51-100", "101-200", "201-10000"]
        for k in order:
            if k in rolled:
                print(f"  {k:>10s}  {rolled[k]:>6,}")
    print()

    print(f"## Provider conflicts (top 10 of {g['n_conflicts']:,})")
    for d in g["conflicts"][:10]:
        print(f"  ×{d['n']:<2} {d['soname']}")
        for p in d["providers"][:3]:
            print(f"        {p}")
        if len(d["providers"]) > 3:
            print(f"        … and {len(d['providers']) - 3} more")
    print()

    if g["cycles"]:
        print(f"## Non-trivial cycles ({len(g['cycles'])} found)")
        for c in g["cycles"][:5]:
            print(f"  {' ↔ '.join(c)}")
        print()

    print(f"## External sonames (NEEDED but unprovided, top 20 of "
          f"{g['n_external']:,})")
    use = g["soname_use"]
    ext = sorted(g["external"], key=lambda s: -use.get(s, 0))[:20]
    for s in ext:
        print(f"  {use.get(s, 0):>6,}  {s}")
    print()

    if g["version_mismatches"]:
        print(f"## Versioned-symbol mismatches "
              f"(top 10 of {g['n_version_mismatches']:,})")
        for d in g["version_mismatches"][:10]:
            print(f"  ×{d['n']:<3} {d['soname']} :: {d['verset']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=ROOT_DEFAULT)
    ap.add_argument("--out", default=OUT_DEFAULT)
    ap.add_argument("--jobs", type=int, default=None)
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"dep_graph: {root} is not a directory", file=sys.stderr)
        return 2

    print(f"# Walking {root} …", file=sys.stderr)
    items = _walk(root)
    print(f"# Found {len(items):,} analysis files; extracting …",
          file=sys.stderr)

    jobs = args.jobs or (mp.cpu_count() or 1)
    records: list[dict] = []
    with mp.Pool(jobs) as pool:
        for i, r in enumerate(
            pool.imap_unordered(_extract_one, items, chunksize=64), 1
        ):
            if r is not None:
                records.append(r)
            if i % 5000 == 0:
                print(f"  … {i:,}/{len(items):,}", file=sys.stderr)

    print(f"# Kept {len(records):,} loadable ELFs; analysing …",
          file=sys.stderr)
    g = _analyse(records)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(g, indent=2) + "\n")
    print(f"# Wrote {out_path} "
          f"({out_path.stat().st_size / 1024 / 1024:.1f} MB)",
          file=sys.stderr)

    _print_summary(g)
    return 0


if __name__ == "__main__":
    sys.exit(main())
