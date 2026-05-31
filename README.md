# ElfZoo

Differential-testing corpus and harnesses for ELF loaders, sourced from
Alpine Linux v3.23 `main` + `community` (x86_64).

The corpus is the world; the harnesses ask two questions of every ELF:

- **Static structural diff** — do *we* parse this ELF the same way two
  independent reference parsers (`llvm-readobj`, `eu-elflint`) do?
- **Differential state diff** — does *loading* this ELF leave the process
  in the same state our reference loader (`ld-musl-x86_64.so.1`) does,
  right before user code begins?

Anything that passes both, for tens of thousands of unrelated programs
and libraries, is a loader we can trust.

## Layout

```
ElfZoo/
├── corpus/                    # bulk data, gitignored
│   ├── mirror/                # downloaded .apk files (~59 GB)
│   ├── unpacked/<repo>/<pkg>/ # per-package extraction trees
│   ├── analysis/<repo>/<pkg>/ # per-ELF llvm-readobj JSON dumps
│   ├── sysroots/<pkg>/        # per-package sysroots (built on demand)
│   ├── audit/<repo>/<pkg>/    # LD_AUDIT runtime traces (JSONL)
│   ├── elflint/<repo>/<pkg>/  # per-ELF eu-elflint text cache
│   ├── survey.json            # aggregated static survey
│   ├── elflint_summary.json   # aggregated elflint findings
│   └── dep_graph.json         # corpus-wide DT_NEEDED graph
├── scripts/                   # all tooling (bash + python)
├── audit/                    # audit.c LD_AUDIT library
└── docs/                     # generated static HTML site (committed; served by GitHub Pages)
```

The elfutils source oracle lives in the umbrella checkout at
`../third_party/impl-tool/elfutils/`.

## Corpus

| repo | packages | ELFs | compressed |
|---|---|---|---|
| Alpine v3.23 main / x86_64 | 5,868 | 50,162 | 6.6 GB |
| Alpine v3.23 community / x86_64 | 21,710 | 13,788 | 52.4 GB |
| **total** | **27,578** | **63,950** | **~59 GB** |

Source: `https://dl-cdn.alpinelinux.org/alpine/v3.23/{main,community}/x86_64/`.

Every ELF is sorted into exactly one of five buckets by
`scripts/survey.py::_classify()`. The first three columns are
load-bearing for the loader-spec project; the other two are kept for
transparency.

| bucket | count | what it is |
|---|---|---|
| **loadable** | 52,945 | ET_EXEC / ET_DYN targeting x86_64 — real loader inputs |
| debuginfo | 5,344 | `/usr/lib/debug/**` + `.debug` / `.dbg` files (PT_DYNAMIC empty) |
| relocatable | 3,807 | ET_REL — mostly `avr-libc`, cross-elf-binutils, kernel sources |
| cross_arch | 85 | ET_EXEC/DYN but `e_machine != EM_X86_64` (qemu firmware, etc.) |
| other | 1,769 | EM_NONE (Guile `.go` bytecode), bogus `e_machine` values |

## Quickstart

```bash
# 1. Mirror + unpack the corpus (~59 GB download, ~30 min on a fast link)
scripts/fetch.sh
scripts/unpack.sh

# 2. Reference static dump: one llvm-readobj JSON per ELF (~150 s, ~34 GB)
scripts/dump.py --all

# 3. Static-survey aggregate (~2 min, writes corpus/survey.json)
scripts/survey.py --jobs 40

# 4. eu-elflint second opinion (~30 s, writes corpus/elflint_summary.json)
scripts/elflint_run.py --jobs 40

# 5. Corpus-wide DT_NEEDED graph (~2 min, writes corpus/dep_graph.json)
scripts/dep_graph.py --jobs 40

# 6. Runtime LD_AUDIT traces (~5 min for repo=main; ~80 GB of JSONL)
scripts/audit_run.py --all --repo main --jobs 40

# 7. Build the static analysis website (output: docs/)
scripts/build_site.py
python3 -m http.server --directory docs 8000
```

Sample-file lists shown in the survey and on the site are
uniform-random and **deterministic** — `blake2b(kind, path, idx)` drawn
into a fixed-size reservoir per kind, stable across re-runs.

## Audit oracle

`audit/audit.c` is an `LD_AUDIT` library loaded by glibc rtld.
It exits before user code runs and emits one JSONL event stream per
ELF. The schema covers eight event types:

| event | source | what it captures |
|---|---|---|
| `version` | `la_version` | the audit ABI version negotiated |
| `auxv` | `la_version` | `/proc/self/auxv` (AT_PHDR, AT_HWCAP, AT_RANDOM, …) — the loader's input |
| `objopen` | `la_objopen` | every DSO opened, with `l_addr` and `l_name` |
| `search` | `la_objsearch` | every path probed during DT_NEEDED resolution, with `LA_SER_*` flag |
| `consistent` | `la_activity(LA_ACT_CONSISTENT)` | a fence — everything below is from the consistent state |
| `r_debug` | `la_activity` | `_r_debug` snapshot (`r_state`, `r_version`, `r_brk`, `r_ldbase`) |
| `serinfo` | `dlinfo(RTLD_DI_SERINFO)` | per-DSO search-path order with `LA_SER_*` flags |
| `reloc` | walking each DSO's `l_ld` | every observed reloc slot value, decoded to `(dso, file_offset)` via `/proc/self/maps` — ASLR-invariant and diff-ready |

The reloc walker captures *every* type the dynamic loader handles
(JUMP_SLOT, GLOB_DAT, 64, RELATIVE, IRELATIVE, RELR, TPOFF64,
DTPMOD64, COPY, …), not just the JUMP_SLOT slots that `la_symbind64`
fires for. COPY reloc events carry `size` and `bytes` instead of a
single `value`.

`scripts/audit_run.py --lddebug=files,scopes,bindings` opts in to a
parallel `LD_DEBUG` channel for second-opinion confirmation of init
order, scope construction, and lazy binds.

## Status

Phases 1–4 (corpus + reference dump + LD_AUDIT oracle) and phase 4½
(survey + elflint + static website) are working end-to-end on the
full corpus. Phase 3 (in-Python static structural diff against our
own frontend) and phase 4's snapshot-at-`e_entry` harness for
musl-only binaries are the remaining work — tracked in the session
plan.

## Third-party

`../third_party/impl-tool/elfutils/` is the shared LeanLoad umbrella
submodule for elfutils. It is referenced as the source-of-truth for
both the in-Python anomaly checks and the linter oracle.

Clone with submodules, or initialise after the fact:

```bash
git clone --recurse-submodules https://github.com/LeanLoad/LeanLoad.git
# or
git submodule update --init ElfZoo third_party/impl-tool/elfutils
```
