#!/usr/bin/env bash
# Build a decoder variant (CLI binary + in-process harness) into OUT_DIR.
# Usage: bench/build_dec.sh OUT_DIR [SRC_ROOT] [extra CFLAGS...]
#   OUT_DIR/uharc        production CLI (same flags as the Makefile)
#   OUT_DIR/dec_harness  in-process decoder harness (bench/dec_harness.c)
# PGO=1 builds a profile-guided variant (evaluation only; see
# bench/DECODER_OPTIMIZATIONS.md for why it is not used).
# SRC_ROOT defaults to this checkout; pass another checkout (e.g. a
# `git worktree` of the reference commit) to build the baseline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$1"; shift
SRC="${1:-$ROOT}"; [ $# -gt 0 ] && shift
SRC="$(cd "$SRC" && pwd)"
CC="${CC:-gcc}"
CFLAGS="-std=c99 -Wall -Wextra -O3 -flto=auto -fuse-linker-plugin -fomit-frame-pointer -fno-math-errno -fno-trapping-math -fno-semantic-interposition -fmerge-all-constants -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -ffunction-sections -fdata-sections -fno-strict-aliasing -DNDEBUG"
LDFLAGS="-flto=auto -fuse-linker-plugin -Wl,--gc-sections -Wl,-O1 -lm"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
SRCS=$(ls "$SRC"/src/*.c)
LIBSRCS=$(ls "$SRC"/src/*.c | grep -v '/uharc\.c$')

build() {   # build EXTRA_FLAGS...  (both binaries, in parallel)
    $CC $CFLAGS "$@" -I"$SRC/src" -o "$OUT/uharc" $SRCS $LDFLAGS &
    $CC $CFLAGS "$@" -I"$SRC/src" -o "$OUT/dec_harness" "$ROOT/bench/dec_harness.c" $LIBSRCS $LDFLAGS &
    wait
}

if [ "${PGO:-0}" = "1" ]; then
    # Profile-guided variant, trained on the reference
    # archives (PGO_TRAIN overrides the training set).
    PROF="$OUT/pgo-profile"
    rm -rf "$PROF"; mkdir -p "$PROF"
    build "$@" -fprofile-generate -fprofile-update=single -fprofile-dir="$PROF"
    for a in ${PGO_TRAIN:-$ROOT/corpus/archives/*.uha}; do
        pw=(); case "$a" in *_pw*) pw=(-p secret42);; esac
        "$OUT/dec_harness" -q -w 0 -n 1 "${pw[@]}" "$a" >/dev/null 2>&1 || true
        pw=(); case "$a" in *_pw*) pw=(-pwsecret42);; esac
        "$OUT/uharc" t -y -d0 "${pw[@]}" "$a" >/dev/null 2>&1 || true
    done
    build "$@" -fprofile-use -fprofile-partial-training -Wno-missing-profile -fprofile-dir="$PROF"
else
    build "$@"
fi
echo "$OUT"
