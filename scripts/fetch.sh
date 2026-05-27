#!/usr/bin/env bash
# Fetch Alpine packages into corpus/mirror/<branch>/<repo>/<arch>/.
#
# Usage:
#   scripts/fetch.sh                 # default: v3.23, main+community, x86_64
#   scripts/fetch.sh v3.23 x86_64 main community
#
# Idempotent — re-running only transfers changed files. Resumable
# via rsync --partial. Verifies APKINDEX is present at the end.

set -euo pipefail

BRANCH="${1:-v3.23}"
ARCH="${2:-x86_64}"
shift $(( $# > 0 ? 1 : 0 ))
shift $(( $# > 0 ? 1 : 0 ))
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
    if timeout 10 rsync --list-only "$m/$BRANCH/main/$ARCH/APKINDEX.tar.gz" \
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
echo "branch: $BRANCH  arch: $ARCH  repos: ${REPOS[*]}"

for repo in ${REPOS[*]}; do
  src="$MIRROR/$BRANCH/$repo/$ARCH/"
  dst="$DEST_ROOT/$BRANCH/$repo/$ARCH/"
  mkdir -p "$dst"
  echo
  echo "=== $repo ==="
  # --partial-dir keeps interrupted transfers tidy under .partial/.
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
echo "done. corpus/mirror/$BRANCH at $(du -sh "$DEST_ROOT/$BRANCH" | cut -f1)."
