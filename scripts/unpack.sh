#!/usr/bin/env bash
# Unpack each .apk under corpus/mirror/<branch>/<repo>/<arch>/ into
# corpus/unpacked/<branch>/<repo>/<arch>/<pkgname-version-rev>/.
#
# Per-apk extraction directory (no merging) avoids file-path collisions
# between packages that legitimately install to the same paths (virtual
# providers, -dev subpackages, etc.).
#
# Usage:
#   scripts/unpack.sh                 # default: v3.23, x86_64, main+community
#   scripts/unpack.sh v3.23 x86_64 main
#   JOBS=8 scripts/unpack.sh          # cap parallelism
#
# Idempotent: existing dirs with a .unpacked marker are skipped.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRANCH="${1:-v3.23}"
ARCH="${2:-x86_64}"
shift $(( $# > 0 ? 1 : 0 ))
shift $(( $# > 0 ? 1 : 0 ))
REPOS=("${@:-main community}")
JOBS="${JOBS:-$(nproc)}"

unpack_apk() {
  local apk="$1"
  local outdir="${apk/\/mirror\//\/unpacked\/}"
  outdir="${outdir%.apk}"

  if [[ -f "$outdir/.unpacked" ]]; then
    return 0
  fi

  rm -rf "$outdir"
  mkdir -p "$outdir"
  # apk = three concatenated gzip-tar streams (sig, .PKGINFO, data);
  # tar -xzf transparently reads all three.
  if tar -xzf "$apk" -C "$outdir" 2>/dev/null; then
    touch "$outdir/.unpacked"
  else
    echo "FAIL: $apk" >&2
    rm -rf "$outdir"
    return 1
  fi
}
export -f unpack_apk

for repo in ${REPOS[*]}; do
  src="$ROOT/corpus/mirror/$BRANCH/$repo/$ARCH"
  if [[ ! -d "$src" ]]; then
    echo "skip $repo: $src does not exist"
    continue
  fi

  count=$(find "$src" -maxdepth 1 -name '*.apk' | wc -l)
  echo "=== $repo: $count apks (jobs=$JOBS) ==="

  find "$src" -maxdepth 1 -name '*.apk' -print0 \
    | xargs -0 -n1 -P "$JOBS" bash -c 'unpack_apk "$0"'

  dst="$ROOT/corpus/unpacked/$BRANCH/$repo/$ARCH"
  ok=$(find "$dst" -mindepth 2 -maxdepth 2 -name '.unpacked' 2>/dev/null | wc -l)
  echo "  $repo: $ok packages unpacked OK"
done

echo
echo "unpacked tree at: $ROOT/corpus/unpacked/$BRANCH"
du -sh "$ROOT/corpus/unpacked/$BRANCH" 2>/dev/null | sed 's/^/total: /'
