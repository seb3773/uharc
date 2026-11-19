#!/usr/bin/env bash
# Fetch the external native-encoder archives used by the decoder bench:
#   * UHARC 0.4 BETA archives (UHARC04.EXE output, every method, filters,
#     multimedia, dictionary sizes, passwords "secret") from
#     https://github.com/roytam1/unuharc_recon (uharc-rs-04/arc)
#   * D3X.UHA: a native UHARC 0.6 multi-file archive (method 34)
#   * the 48 native UHARC 0.2 archives (uharc-rs-02/arc) -> bench/ext02_corpus
# They are copied to bench/ext_corpus/ (ignored by Git). Every member carries
# its CRC-32, so correctness is checked against the archive itself.
#
# Usage: bench/fetch_ext_corpus.sh [OUT_DIR]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/bench/ext_corpus}"
CACHE="${UHARC_BENCH_CACHE:-$ROOT/bench/.cache}"
REPO="$CACHE/unuharc_recon"
mkdir -p "$OUT" "$CACHE"
if [ ! -d "$REPO" ]; then
    git clone --depth 1 https://github.com/roytam1/unuharc_recon "$REPO"
fi
for f in "$REPO"/uharc-rs-04/arc/*.uha; do
    cp "$f" "$OUT/v04_$(basename "$f")"
done
cp "$REPO/D3X.UHA" "$OUT/v06_D3X.uha"
# Full native UHARC 0.2 set (UHARC02.EXE output, 48 archives, superset of
# corpus/archives_02 with the large multi-file EXE/MED archives).
OUT02="$(dirname "$OUT")/ext02_corpus"
mkdir -p "$OUT02"
cp "$REPO"/uharc-rs-02/arc/*.UHA "$OUT02/"
echo "External corpus ready in $OUT ($(ls "$OUT" | grep -c '\.uha$') archives)"
