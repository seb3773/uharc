# Encoder performance bench

Tools used to evaluate encoder optimizations. The golden rule of the project
applies to every change: **the encoder output must stay bit-exact** with the
legacy `UHARC.EXE` 0.6b encoder (and therefore with the last known-good build).
A speedup is only retained when the timing harness shows a real gain, not noise.

## Workflow

```sh
# 0. One-time: build the extended corpus (downloads the Silesia corpus once,
#    ~68 MB, cached in bench/.cache) and set reference mtimes.
bench/make_corpus.sh
touch -d '2026-09-23 00:35:44 UTC' corpus/input/*   # needed by tests/test_parity.py

# 1. Build the reference (unmodified) encoder and the candidate.
bench/build.sh /tmp/uh_base          # from a clean checkout of the reference
bench/build.sh /tmp/uh_cand          # from the working tree

# 2. Bit-exactness gate (hard requirement).
bench/verify.py /tmp/uh_base/linux/uharc /tmp/uh_cand/linux/uharc

# 3. Timing (A = reference, B = candidate).
bench/bench.py /tmp/uh_base/linux/uharc /tmp/uh_cand/linux/uharc \
    --modes m1,m2,m3,mx,mz,mw,mr --files all --reps 7

# Optional: deterministic instruction counts (valgrind), useful as a hint
# for micro-optimizations; timing remains the acceptance criterion.
bench/ircount.sh /tmp/uh_base/linux/uharc /tmp/uh_cand/linux/uharc m2 dickens.1m
```

## Tools

| Tool | Purpose |
| :--- | :--- |
| `make_corpus.sh` | Builds `bench/corpus/`: `corpus/input/*`, 1 MiB slices of the 12 Silesia files (text, XML, executables, databases, medical images, ...), a 6 MiB slice of `mozilla` (larger than the default 4 MiB dictionary) and synthetic 16-bit WAV / 24-bit BMP samples (`gen_media.py`). |
| `build.sh OUT [CFLAGS]` | Builds a variant with the production flags into `OUT/linux/uharc` (extra flags allowed, e.g. `-DUHA_CHECK_C08_CACHE`). |
| `verify.py BASE CAND` | Compares `arc[39..]` of every archive produced by the candidate with the baseline: every corpus file x every mode (`m0 mz mx m1 m2 m3 mr mw`), switch variants (`-md16/256/1024/64`, `-mm-`, `-pw`, `-ph-`), the large file, and one solid archive of the whole corpus per mode. Then runs `tests/test_parity.py` against the legacy reference archives. Baseline outputs are cached per baseline binary hash. |
| `bench.py A B` | A/B timing on CPU-pinned lanes, ABBA-interleaved repetitions, child CPU time from `wait4`. Per mode: `sum(median A) / sum(median B)` with a 95% bootstrap confidence interval. Verdict `GAIN` only when the CI lower bound exceeds `1 + --min-gain` (default 1%). `--solid`, `--solid-only` and `--large` add the whole-corpus solid archive and the large files. |
| `ircount.sh A B MODE FILES` | Callgrind instruction counts (exact, reproducible). |

## Notes

- `corpus/input/*` must carry the mtime `2026-09-23 00:35:44 UTC` for the
  legacy parity test: the archive trailer stores DOS timestamps
  (`make_corpus.sh` sets it on the bench corpus automatically).

## Decoder bench

Decoder optimizations are gated by bit exactness first and paired timing
second.

```sh
bench/build_dec.sh /tmp/ref  /path/to/reference/checkout   # baseline harness
bench/build_dec.sh /tmp/cand                               # candidate harness
bench/dec_verify.py /tmp/ref/dec_harness /tmp/cand/dec_harness   # 530 archives, must PASS
bench/dec_abpair.py /tmp/ref/dec_harness /tmp/cand/dec_harness ARCHIVES.. --reps 9
make && python3 tests/test_04.py ./uharc && python3 tests/test_all.py ./uharc
```

`dec_verify.py` decodes every archive of `bench/dec_corpus`,
`corpus/archives`, `corpus/archives_04`, `corpus/archives_02` and
`bench/ext_corpus` with both harnesses and requires identical payloads
(FNV-1a 64 + CRC-32), sizes, member counts and CRC status. A change is kept
only when `dec_abpair.py` reports the whole 95% CI above 1 (GAIN); an A/A run
on a shared VM is about +-5% wide. `bench/dec_ircount.sh` (Callgrind
instruction counts) is used to locate work, not to accept a change.
