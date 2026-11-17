#!/usr/bin/env bash
# Build the decoder benchmark/verification corpus: archives produced by the C
# encoder (bit-exact with UHARC.EXE 0.6b for the legacy modes) from the bench
# corpus (bench/make_corpus.sh must have been run first).
#
# Contents of OUT_DIR (default bench/dec_corpus):
#   <file>__<mode>.uha            every bench corpus file x every mode
#                                 (m0 mr mw mz mx m1 m2 m3), incl. the 6 MiB file
#   SOLID_all__<mode>.uha         one solid archive of the whole bench corpus
#                                 per mode (multi-member boundaries)
#   <file>__<mode>_<variant>.uha  dictionary sizes, -mm-, passwords (-pwsecret42)
#
# Existing archives are kept (the -mx encoder is slow on some inputs); delete
# OUT_DIR to rebuild from scratch.
#
# Usage: bench/make_dec_corpus.sh ENCODER_BIN [OUT_DIR] [JOBS]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENC="$(readlink -f "$1")"
OUT="$(mkdir -p "${2:-$ROOT/bench/dec_corpus}" && cd "${2:-$ROOT/bench/dec_corpus}" && pwd)"
JOBS="${3:-$(nproc)}"
CORPUS="$ROOT/bench/corpus"
[ -d "$CORPUS" ] || { echo "run bench/make_corpus.sh first" >&2; exit 1; }
cd "$CORPUS"

FILES=$(find . -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' ')
{
  for m in m0 mr mw mz mx m1 m2 m3; do
    for f in $FILES large/mozilla.6m; do
      echo "$(basename "$f")__$m.uha -$m $f"
    done
    echo "SOLID_all__$m.uha -$m $FILES"
  done
  echo "mozilla.6m__m3_md64.uha -m3 -md64 large/mozilla.6m"
  echo "mozilla.6m__m2_md32768.uha -m2 -md32768 large/mozilla.6m"
  echo "mozilla.6m__m1_md1024.uha -m1 -md1024 large/mozilla.6m"
  echo "mozilla.6m__mx_md1024.uha -mx -md1024 large/mozilla.6m"
  echo "mozilla.6m__mz_md32768.uha -mz -md32768 large/mozilla.6m"
  echo "mozilla.6m__mw_md32768.uha -mw -md32768 large/mozilla.6m"
  echo "nci.1m__mx_md64.uha -mx -md64 nci.1m"
  echo "audio16.wav__m3_mmoff.uha -m3 -mm- audio16.wav"
  echo "image24.bmp__m3_mmoff.uha -m3 -mm- image24.bmp"
  echo "x-ray.1m__m2_mmoff.uha -m2 -mm- x-ray.1m"
  echo "samba.1m__m2_pw.uha -m2 -pwsecret42 samba.1m"
  echo "code.c__mx_pw.uha -mx -pwsecret42 -ph- code.c"
  echo "xml.1m__mz_pw.uha -mz -pwsecret42 xml.1m"
} | while read -r name args; do
  [ -s "$OUT/$name" ] && continue
  echo "$name $args"
done | xargs -P"$JOBS" -L1 bash -c '
  name=$0
  sw=(); while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do sw+=("$1"); shift; done
  "'"$ENC"'" a -y -d0 "${sw[@]}" "'"$OUT"'/$name.tmp.uha" "$@" >/dev/null 2>&1 \
    && mv "'"$OUT"'/$name.tmp.uha" "'"$OUT"'/$name" || echo "FAIL $name" >&2'
echo "Decoder corpus ready in $OUT ($(ls "$OUT" | grep -c '\.uha$') archives)"
