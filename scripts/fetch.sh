#!/usr/bin/env bash
# Fetch Alpine packages into corpus/mirror/<repo>/.
#
# Hard-pinned to Alpine v3.23 x86_64; ElfZoo only tracks a single
# release / arch (see README §Scope). To target a different release or
# arch, change ALPINE_BRANCH / ALPINE_ARCH below — and remember that
# the analysis tree must be regenerated from scratch.
#
# Usage:
#   scripts/fetch.sh                 # default: main + community
#   scripts/fetch.sh main            # just one repo
#
# Idempotent — re-running only transfers changed files. Resumable
# via rsync --partial. Verifies APKINDEX is present at the end.

set -euo pipefail

ALPINE_BRANCH="${ALPINE_BRANCH:-v3.23}"
ALPINE_ARCH="${ALPINE_ARCH:-x86_64}"
REPOS=("${@:-main community}")

# Allow override; defaults try a few known-good rsync mirrors in order.
MIRRORS=(
  "${ALPINE_RSYNC_MIRROR:-}"
  "rsync://rsync.alpinelinux.org/alpine"
  "rsync://mirror.csclub.uwaterloo.ca/alpine"
  "rsync://mirrors.edge.kernel.org/alpine"
)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_ROOT="$ROOT/corpus/mirror"

pick_mirror() {
  for m in "${MIRRORS[@]}"; do
    [[ -z "$m" ]] && continue
    if timeout 10 rsync --list-only \
         "$m/$ALPINE_BRANCH/main/$ALPINE_ARCH/APKINDEX.tar.gz" \
         >/dev/null 2>&1; then
      echo "$m"
      return 0
    fi
  done
  echo "no reachable rsync mirror" >&2
  return 1
}

MIRROR="$(pick_mirror)"
echo "mirror: $MIRROR"
echo "release: $ALPINE_BRANCH $ALPINE_ARCH  repos: ${REPOS[*]}"

for repo in ${REPOS[*]}; do
  src="$MIRROR/$ALPINE_BRANCH/$repo/$ALPINE_ARCH/"
  dst="$DEST_ROOT/$repo/"
  mkdir -p "$dst"
  echo
  echo "=== $repo ==="
  # --partial-dir keeps interrupted transfers tidy under .rsync-partial/.
  # --delete keeps the local mirror exactly matching upstream.
  # --info=progress2 gives one rolling progress line per repo.
  rsync -rlt \
        --partial --partial-dir=.rsync-partial \
        --delete \
        --info=progress2 \
        "$src" "$dst"

  if [[ ! -s "$dst/APKINDEX.tar.gz" ]]; then
    echo "ERROR: $dst/APKINDEX.tar.gz missing or empty" >&2
    exit 1
  fi

  apk_count=$(find "$dst" -maxdepth 1 -name '*.apk' | wc -l)
  total_size=$(du -sh "$dst" | cut -f1)
  echo "  $repo: $apk_count apks, $total_size"
done

echo
echo "done. corpus/mirror at $(du -sh "$DEST_ROOT" | cut -f1)."
