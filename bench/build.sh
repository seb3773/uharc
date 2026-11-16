#!/usr/bin/env bash
# Build an encoder variant into its own directory without touching build/.
# Usage: bench/build.sh OUT_DIR [extra CFLAGS...]
#   bench/build.sh /tmp/uh_cand                      # production flags
#   bench/build.sh /tmp/uh_chk -DUHA_CHECK_C08_CACHE  # with self-checks
# The binary is written to OUT_DIR/linux/uharc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$1"; shift || true
rm -rf "$OUT"
make -s -C "$ROOT" BUILD_DIR="$OUT" EXTRA_CFLAGS="$*" "$OUT/linux/uharc"
echo "$OUT/linux/uharc"
