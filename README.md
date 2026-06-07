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
├── src/                      # Rust CLI (`elfzoo`)
├── scripts/                  # legacy Python/shell tooling
├── audit/                    # LD_AUDIT prototype
└── docs/                     # generated static HTML site (committed; served by GitHub Pages)
```

Generated data lives under `results/` and is gitignored:

```
results/
├── apks/<repo>/                         # downloaded .apk files + APKINDEX
├── extracted/<repo>/<pkg>/              # ELF-only per-package extraction trees
├── packages/<repo>/<pkg>.json           # package metadata and shallow ELF counts
├── elfs/<repo>/<pkg>/<rel>.json         # single-ELF structural analysis
├── programs/<repo>/<pkg>/<rel>.json     # executable program analysis
└── oracle/
    └── elflint/<repo>/<pkg>/<rel>.json  # eu-elflint oracle result
```

The extracted tree mirrors package paths but only materializes regular files
whose contents start with ELF magic, plus all package symlinks normalized under
the package extraction root. A result file's existence means that result is
available; JSON writes use temp-file + atomic rename, and every JSON schema
carries a `schema_version` so stale outputs can be regenerated.

The elfutils source oracle lives in the umbrella checkout at
`../third_party/impl-tool/elfutils/`.

## Corpus

| repo | packages | ELFs | compressed |
|---|---|---|---|
| Alpine v3.23 main / x86_64 | 5,868 | 50,162 | 6.6 GB |
| Alpine v3.23 community / x86_64 | 21,710 | 13,788 | 52.4 GB |
| **total** | **27,578** | **63,950** | **~59 GB** |

Source: `https://dl-cdn.alpinelinux.org/alpine/v3.23/{main,community}/x86_64/`.

The Rust tooling classifies ELFs from file structure rather than path. The
load-bearing buckets for loader work are dynamic programs, static programs,
DSOs, and other x86-64 load images; non-x86 files, relocatables, cores, and
malformed images remain visible but are filtered out before runtime/program
analysis by default.

| bucket | what it is |
|---|---|
| `dynamic_program` | `ET_EXEC` / PIE-like `ET_DYN` with `PT_INTERP` + `PT_DYNAMIC` |
| `static_program` | executable-looking load image with no `PT_INTERP` and `e_entry` inside executable `PT_LOAD` |
| `dso` | `ET_DYN` + `PT_DYNAMIC` with no interpreter |
| `load_image` | x86-64 `ET_EXEC` / `ET_DYN` with `PT_LOAD`, but no stronger role |
| `wrong_format` / `wrong_machine` / `relocatable` / `core` / `malformed_image` | structurally excluded from x86 loader analysis |

## Quickstart

```bash
# 1. Mirror + extract the corpus (~59 GB download)
./fetch.sh
./extract.sh

# 2. Package metadata, shallow ELF counts, and packages/index.html
./analyze-packages.sh

# 3. Primary structural analysis: analyze each ELF object
./analyze-elfs.sh

# 4. Loader-input analysis: analyze each executable program
./analyze-programs.sh

# 5. eu-elflint oracle, also JSON per ELF
./elflint.sh
```

The legacy `scripts/` directory is kept for now because the Rust CLI does not
yet replace the old survey, dependency-graph, site-generation, sysroot, and
runtime tracing helpers.

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
