#!/usr/bin/env bash
# Deterministic instruction counts (valgrind/callgrind "Ir") of the decoder
# for A/B checks of small changes. Wall-clock timing on shared/virtualized
# machines can be noisy by +-15% per run; Ir counts are exact. Ir does not
# capture branch-prediction, cache or code-layout effects, so a change is only
# kept if bench/dec_bench.py also shows it is not slower.
#
# Usage: bench/dec_ircount.sh A_HARNESS B_HARNESS ARCHIVE [ARCHIVE...]
#   (harnesses built by bench/build_dec.sh; VALGRIND=/path/to/valgrind)
set -euo pipefail
VALGRIND="${VALGRIND:-valgrind}"
A="$1"; B="$2"; shift 2
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
count() {   # count TAG HARNESS ARCHIVE
    local pw=()
    case "$3" in *_pw*) pw=(-p secret42);; esac
    "$VALGRIND" --tool=callgrind --callgrind-out-file="$tmp/cg.$1" \
        "$2" -q -w 0 -n 1 "${pw[@]}" "$3" > "$tmp/out.$1" 2> "$tmp/log.$1"
    sed -n 's/.*Collected : \([0-9]*\).*/\1/p' "$tmp/log.$1" > "$tmp/ir.$1"
    cut -f1-6 "$tmp/out.$1" > "$tmp/res.$1"
}
i=0
for f in "$@"; do
    count "a$i" "$A" "$f" &
    count "b$i" "$B" "$f" &
    i=$((i + 1))
done
wait
printf "%-34s %15s %15s %8s %s\n" archive A_Ir B_Ir B/A output
i=0; ta=0; tb=0
for f in "$@"; do
    ia="$(cat "$tmp/ir.a$i")"; ib="$(cat "$tmp/ir.b$i")"
    same=same; cmp -s "$tmp/res.a$i" "$tmp/res.b$i" || same=DIFFERENT
    printf "%-34s %15s %15s %8.4f %s\n" "$(basename "$f")" "$ia" "$ib" \
        "$(echo "$ib / $ia" | bc -l)" "$same"
    ta=$((ta + ia)); tb=$((tb + ib)); i=$((i + 1))
done
printf "%-34s %15s %15s %8.4f\n" TOTAL "$ta" "$tb" "$(echo "$tb / $ta" | bc -l)"
