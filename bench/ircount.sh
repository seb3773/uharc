#!/usr/bin/env bash
# Deterministic instruction counts (valgrind/callgrind "Ir") for A/B checks.
# Timing on shared/virtualized machines is noisy; Ir counts are exact and
# reproducible, which helps to judge small micro-optimizations. A change is
# only kept if the timing harness (bench.py) also shows it is not slower.
#
# Usage: bench/ircount.sh A_BIN B_BIN MODE FILE [FILE...]
#   VALGRIND=/path/to/valgrind may be set if valgrind is not on PATH.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VALGRIND="${VALGRIND:-valgrind}"
A="$1"; B="$2"; MODE="$3"; shift 3
cd "$ROOT/bench/corpus"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
count() {
    "$VALGRIND" --tool=callgrind --callgrind-out-file="$tmp/cg.$1.$2" \
        "$3" a -y -d0 "-$MODE" "$tmp/o.$1.$2.uha" "$4" > /dev/null 2> "$tmp/log.$1.$2"
    sed -n 's/.*Collected : \([0-9]*\).*/\1/p' "$tmp/log.$1.$2"
}
printf "%-16s %16s %16s %8s\n" file A_Ir B_Ir B/A
for f in "$@"; do
    ( count a "$(basename "$f")" "$A" "$f" > "$tmp/ra.$(basename "$f")" ) &
    ( count b "$(basename "$f")" "$B" "$f" > "$tmp/rb.$(basename "$f")" ) &
done
wait
for f in "$@"; do
    b="$(basename "$f")"
    ia="$(cat "$tmp/ra.$b")"; ib="$(cat "$tmp/rb.$b")"
    printf "%-16s %16s %16s %8.4f\n" "$b" "$ia" "$ib" "$(echo "$ib / $ia" | bc -l)"
done
