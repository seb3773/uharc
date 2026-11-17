#!/usr/bin/env python3
"""A/B timing harness for decoder optimizations.

Runs two builds of bench/dec_harness (A = baseline, B = candidate, see
bench/build_dec.sh) on the decoder corpus (bench/make_dec_corpus.sh). Each
process decodes one archive INNER times in-process (no file I/O in the timed
region); the minimum (--stat min, default; more robust on shared machines)
or the median of those decodes is one sample. A and B processes are
interleaved in ABBA order on CPU-pinned lanes so that machine drift affects
both builds equally, and the whole schedule is repeated ROUNDS times.

Per group (codec/mode), the speedup is  sum(median A) / sum(median B)  over
all archives of the group, with a 95% bootstrap confidence interval obtained
by resampling the samples of each archive. Verdicts:
    GAIN   CI lower bound > 1 + --min-gain   (real improvement)
    LOSS   CI upper bound < 1 - --min-gain   (real regression)
    noise  otherwise
Only GAIN results (and no LOSS anywhere) qualify a change for retention.

This harness does not check output equality: always run bench/dec_verify.py.

Usage:
    bench/dec_bench.py A_HARNESS B_HARNESS [--groups m1,mx,...] [--set quick|all]
        [--rounds 5] [--inner 3] [--lanes 6] [--cpu-stride 1] [--stat min|median]
        [--match REGEX] [--min-gain 0.01] [--json out.json]

On virtual machines, many parallel lanes share caches and memory bandwidth
and widen the confidence intervals considerably; prefer few lanes spread
with --cpu-stride, and run an A/A comparison first to see the noise floor.
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GROUPS = ["m0", "mr", "mw", "mz", "mx", "m1", "m2", "m3"]
# Representative subset: text, xml, executable, database, image, audio,
# binary records, large (window wrap) and the solid archive.
QUICK = ["dickens.1m", "xml.1m", "mozilla.1m", "ooffice.1m", "osdb.1m", "sao.1m",
         "x-ray.1m", "audio16.wav", "image24.bmp", "records.bin", "code.c",
         "mozilla.6m", "SOLID_all"]
PASSWORD = "secret42"


def group_of(name):
    m = re.match(r"^(.*)__(m[0-9a-z])(?:_(.+))?\.uha$", name)
    if not m:
        return None, None, None
    return m.group(1), m.group(2), m.group(3)


def collect(corpus, groups, subset):
    out = []
    for p in sorted(Path(corpus).glob("*.uha")):
        base, g, var = group_of(p.name)
        if g not in groups:
            continue
        if subset == "quick" and (base not in QUICK or var is not None):
            continue
        out.append((g, p))
    return out


STAT_COL = 7   # harness column: 6 = min, 7 = median of the inner repeats


def run(harness, cpu, archive, inner):
    cmd = ["taskset", "-c", str(cpu), str(harness), "-q", "-w", "1", "-n", str(inner)]
    if "_pw" in archive.name:
        cmd += ["-p", PASSWORD]
    cmd.append(str(archive))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{harness} failed on {archive.name}: {res.stderr[-300:]}")
    f = res.stdout.strip().split("\t")
    return int(f[STAT_COL]) / 1e9, f[5]


def lane_job(args):
    a, b, cpu, archive, inner, rounds = args
    ta, tb = [], []
    for r in range(rounds):
        order = [(a, ta), (b, tb)]
        if r % 2:
            order.reverse()
        for h, tl in order:
            t, _ = run(h, cpu, archive, inner)
            tl.append(t)
    return archive, ta, tb


def bootstrap(per, iters=2000, seed=12345):
    rng = random.Random(seed)
    rs = []
    for _ in range(iters):
        sa = sb = 0.0
        for ta, tb in per:
            sa += statistics.median([rng.choice(ta) for _ in ta])
            sb += statistics.median([rng.choice(tb) for _ in tb])
        rs.append(sa / sb if sb > 0 else 1.0)
    rs.sort()
    return rs[int(0.025 * iters)], rs[int(0.975 * iters) - 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--corpus", default=str(ROOT / "bench" / "dec_corpus"))
    ap.add_argument("--groups", default=",".join(GROUPS))
    ap.add_argument("--set", default="quick")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--inner", type=int, default=3)
    ap.add_argument("--lanes", type=int, default=6)
    ap.add_argument("--first-cpu", type=int, default=2)
    ap.add_argument("--cpu-stride", type=int, default=1,
                    help="CPU distance between lanes (2 avoids SMT siblings)")
    ap.add_argument("--stat", choices=["min", "median"], default="min",
                    help="per-run statistic over the inner repeats")
    ap.add_argument("--match", default=None,
                    help="regex filter on archive names")
    ap.add_argument("--min-gain", type=float, default=0.01)
    ap.add_argument("--json")
    ap.add_argument("--per-file", action="store_true")
    args = ap.parse_args()

    global STAT_COL
    STAT_COL = 6 if args.stat == "min" else 7
    groups = args.groups.split(",")
    items = collect(args.corpus, groups, args.set)
    if args.match:
        items = [it for it in items if re.search(args.match, it[1].name)]
    if not items:
        sys.exit("no archives selected (run bench/make_dec_corpus.sh)")
    # Longest jobs first for better lane packing (archive size as a proxy).
    items.sort(key=lambda x: -x[1].stat().st_size)
    gmap = {p: g for g, p in items}
    jobs = []
    for i, (g, p) in enumerate(items):
        jobs.append((args.a, args.b, args.first_cpu + (i % args.lanes) * args.cpu_stride, p,
                     args.inner, args.rounds))
    results = {}
    # One worker per lane; jobs on the same lane run sequentially.
    lanes = {}
    for j in jobs:
        lanes.setdefault(j[2], []).append(j)

    def lane_runner(lj):
        return [lane_job(j) for j in lj]

    with cf.ThreadPoolExecutor(max_workers=len(lanes)) as ex:
        for lst in ex.map(lane_runner, lanes.values()):
            for archive, ta, tb in lst:
                results[archive] = (ta, tb)

    report = {}
    print(f"{'group':6s} {'n':>3s} {'A (s)':>9s} {'B (s)':>9s} {'speedup':>8s}  {'95% CI':17s} verdict")
    tot_a = tot_b = 0.0
    all_per = []
    for g in groups:
        per = [results[p] for p in results if gmap[p] == g]
        if not per:
            continue
        sa = sum(statistics.median(ta) for ta, _ in per)
        sb = sum(statistics.median(tb) for _, tb in per)
        lo, hi = bootstrap(per)
        sp = sa / sb if sb else 1.0
        if lo > 1 + args.min_gain:
            v = "GAIN"
        elif hi < 1 - args.min_gain:
            v = "LOSS"
        else:
            v = "noise"
        print(f"{g:6s} {len(per):3d} {sa:9.4f} {sb:9.4f} {sp:8.3f}x [{lo:6.3f}, {hi:6.3f}] {v}")
        report[g] = {"n": len(per), "a": sa, "b": sb, "speedup": sp, "ci": [lo, hi], "verdict": v}
        tot_a += sa
        tot_b += sb
        all_per += per
    lo, hi = bootstrap(all_per, iters=1000)
    print(f"{'TOTAL':6s} {len(all_per):3d} {tot_a:9.4f} {tot_b:9.4f} {tot_a / tot_b:8.3f}x [{lo:6.3f}, {hi:6.3f}]")
    if args.per_file:
        for p in sorted(results, key=lambda p: (gmap[p], p.name)):
            ta, tb = results[p]
            ma, mb = statistics.median(ta), statistics.median(tb)
            print(f"  {gmap[p]:4s} {p.name:34s} {ma * 1e3:9.2f} ms {mb * 1e3:9.2f} ms {ma / mb:7.3f}x")
    if args.json:
        Path(args.json).write_text(json.dumps({"groups": report, "files": {
            p.name: {"a": results[p][0], "b": results[p][1]} for p in results}}, indent=1))


if __name__ == "__main__":
    main()
