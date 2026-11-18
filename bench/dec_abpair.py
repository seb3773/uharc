#!/usr/bin/env python3
"""Paired A/B decoder timing (single lane, interleaved).

Usage: bench/dec_abpair.py HARNESS_A HARNESS_B ARCHIVE... [--reps N] [--cpu C]

For every archive the two harnesses decode it alternately (A B, B A, ...),
one decode per run, pinned to one CPU. Each adjacent pair gives a ratio
time(A) / time(B), so slow phases of the machine hit both sides of a pair.
Per archive the median of the log ratios is reported; the overall speedup is
the mean of the per-archive medians with a 95% bootstrap confidence interval
(resampling the pairs of every archive). A speedup > 1 means B is faster.

On the shared VM used for this work an A/A run (same binary twice) gives
per-archive medians within about +-4% and overall CIs about +-5% wide, so a
change is accepted only when the whole CI is above 1.
"""
import argparse
import math
import os
import random
import statistics
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dec_common import password  # noqa: E402


def run(harness, arc, cpu):
    cmd = ['taskset', '-c', str(cpu), harness, '-q', '-n', '1']
    pw = password(arc)
    if pw:
        cmd += ['-p', pw]
    out = subprocess.run(cmd + [arc], capture_output=True, text=True).stdout
    return float(out.strip().split('\t')[6])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('a')
    ap.add_argument('b')
    ap.add_argument('archives', nargs='+')
    ap.add_argument('--reps', type=int, default=9)
    ap.add_argument('--cpu', type=int, default=5)
    args = ap.parse_args()

    per = []
    for arc in args.archives:
        logs = []
        for i in range(args.reps):
            if i % 2:
                tb = run(args.b, arc, args.cpu)
                ta = run(args.a, arc, args.cpu)
            else:
                ta = run(args.a, arc, args.cpu)
                tb = run(args.b, arc, args.cpu)
            logs.append(math.log(ta / tb))
        per.append(logs)
        print(f"{os.path.basename(arc):36s} median {math.exp(statistics.median(logs)):6.3f}x"
              f"  mean {math.exp(statistics.mean(logs)):6.3f}x", flush=True)
    est = statistics.mean(statistics.median(r) for r in per)
    rnd = random.Random(1)
    boot = sorted(statistics.mean(statistics.median([rnd.choice(r) for _ in r]) for r in per)
                  for _ in range(2000))
    lo, hi = math.exp(boot[50]), math.exp(boot[1949])
    verdict = 'GAIN' if lo > 1 else ('LOSS' if hi < 1 else 'noise')
    print(f"OVERALL speedup {math.exp(est):6.3f}x  95% CI [{lo:6.3f}, {hi:6.3f}]  {verdict}")


if __name__ == '__main__':
    main()
