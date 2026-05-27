# ElfZoo

Differential-testing corpus and harnesses for ELF loaders, sourced from
Alpine Linux v3.23 `main` + `community` (x86_64).

The corpus is the world; the harnesses ask two questions of every ELF:

- **Static structural diff** — do *we* parse this ELF the same way two
  independent reference parsers (`pyelftools`, `LIEF`, `llvm-readobj`) do?
- **Differential state diff** — does *loading* this ELF leave the process
  in the same state our reference loader (`ld-musl-x86_64.so.1`) does,
  right before user code begins?

Anything that passes both, for tens of thousands of unrelated programs
and libraries, is a loader we can trust.

## Layout

```
ElfZoo/
├── corpus/          # bulk data (gitignored)
│   ├── mirror/      # downloaded .apk files
│   ├── unpacked/    # per-package extraction trees
│   └── index.sqlite # one row per ELF (path, pkg, e_machine, e_type, …)
├── scripts/         # fetch, unpack, index, scan
├── static_diff/     # static structural diff harness
├── state_diff/      # differential state diff harness
└── results/         # per-run test outputs (gitignored)
```

## Corpus

| | packages | compressed |
|---|---|---|
| Alpine v3.23 main / x86_64 | 5,868 | 6.6 GB |
| Alpine v3.23 community / x86_64 | 21,710 | 52.4 GB |
| **total** | **27,578** | **~59 GB** |

Source: `https://dl-cdn.alpinelinux.org/alpine/v3.23/{main,community}/x86_64/`.

## Status

Scaffolding. See the session plan for current state.
