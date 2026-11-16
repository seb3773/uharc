#!/usr/bin/env bash
# Build the extended benchmark corpus used by bench/verify.py and bench/bench.py.
#
# Contents:
#   - every file of corpus/input (the legacy reference corpus)
#   - the first 1 MiB of each Silesia corpus file (text, xml, exe, db, image, ...)
#   - a 6 MiB slice of mozilla (exceeds the default 4 MiB dictionary -> window wrap)
#   - synthetic 16-bit PCM WAV and 24-bit BMP files (multimedia detection paths)
#
# All files get the fixed mtime used by the legacy reference archives so that
# the archive trailer (DOS timestamps) is deterministic.
#
# Usage: bench/make_corpus.sh [out_dir]   (default: bench/corpus)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/bench/corpus}"
CACHE="${UHARC_BENCH_CACHE:-$ROOT/bench/.cache}"
mkdir -p "$OUT" "$CACHE"

if [ ! -d "$CACHE/silesia" ]; then
    if [ ! -f "$CACHE/silesia.zip" ]; then
        curl -fsSL -o "$CACHE/silesia.zip" https://sun.aei.polsl.pl/~sdeor/corpus/silesia.zip
    fi
    mkdir -p "$CACHE/silesia"
    unzip -oq "$CACHE/silesia.zip" -d "$CACHE/silesia"
fi

for f in "$CACHE"/silesia/*; do
    head -c 1048576 "$f" > "$OUT/$(basename "$f").1m"
done
mkdir -p "$OUT/large"
head -c 6291456 "$CACHE/silesia/mozilla" > "$OUT/large/mozilla.6m"

cp "$ROOT"/corpus/input/* "$OUT/"
python3 "$ROOT/bench/gen_media.py" "$OUT"

find "$OUT" -type f -exec touch -d '2026-09-23 00:35:44 UTC' {} +
echo "Benchmark corpus ready in $OUT"
