#!/usr/bin/env python3
"""A/B timing harness for encoder optimizations.

Runs a baseline binary (A) and a candidate binary (B) on the benchmark corpus
for a set of modes, interleaving A and B runs (ABBA order) on CPU-pinned lanes
so that machine drift affects both equally. CPU time (user+sys of the child,
from wait4) is the metric; wall time is reported too.

For every mode, the speedup is  sum(median A) / sum(median B)  over all
targets, with a 95% bootstrap confidence interval obtained by resampling the
repetitions of each target. Verdicts:
    GAIN   CI lower bound > 1 + --min-gain      (real improvement)
    LOSS   CI upper bound < 1                   (real regression)
    noise  otherwise                            (not distinguishable)
Only GAIN results should be retained as optimizations.

This harness does not check output equality: always run bench/verify.py.

Usage:
    bench/bench.py A_BIN B_BIN [--modes m1,m3,mx] [--files quick|all|f1,f2]
                   [--solid] [--reps 5] [--lanes 4] [--json out.json]
"""
import argparse
import concurrent.futures as cf
import json
import os
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALL_MODES = ["m1", "m2", "m3", "mx", "mz", "mr", "mw"]
QUICK_FILES = ["dickens.1m", "mozilla.1m", "x-ray.1m", "xml.1m", "ooffice.1m",
               "audio16.wav", "image24.bmp", "records.bin", "code.c"]


def run_once(binary, cpu, mode, files, cwd, out):
    cmd = ["taskset", "-c", str(cpu), str(binary), "a", "-y", "-d0", f"-{mode}", str(out)] + files
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _, status, ru = os.wait4(p.pid, 0)
    wall = time.perf_counter() - t0
    if status != 0:
        raise RuntimeError(f"{binary} failed on {mode} {files[:3]}")
    return ru.ru_utime + ru.ru_stime, wall


def lane_job(args):
    a_bin, b_bin, cpu, mode, name, files, cwd, reps = args
    ta, tb, wa, wb = [], [], [], []
    with tempfile.TemporaryDirectory(prefix="uhb_") as td:
        out = Path(td) / "o.uha"
        for r in range(reps):
            order = [(a_bin, ta, wa), (b_bin, tb, wb)]
            if r % 2:
                order.reverse()
            for binary, tl, wl in order:
                c, w = run_once(binary, cpu, mode, files, cwd, out)
                tl.append(c)
                wl.append(w)
    return mode, name, ta, tb, wa, wb


def bootstrap_ci(per_target, iters=2000, seed=12345):
    rng = random.Random(seed)
    ratios = []
    for _ in range(iters):
        sa = sb = 0.0
        for ta, tb in per_target:
            sa += statistics.median(rng.choice(ta) for _ in ta)
            sb += statistics.median(rng.choice(tb) for _ in tb)
        ratios.append(sa / sb if sb > 0 else 1.0)
    ratios.sort()
    return ratios[int(0.025 * iters)], ratios[int(0.975 * iters) - 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a_bin")
    ap.add_argument("b_bin")
    ap.add_argument("--modes", default=",".join(ALL_MODES))
    ap.add_argument("--files", default="quick", help="quick | all | comma list")
    ap.add_argument("--solid", action="store_true", help="add the whole corpus as one solid archive")
    ap.add_argument("--solid-only", action="store_true")
    ap.add_argument("--large", action="store_true", help="add corpus/large/* files")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--lanes", type=int, default=4)
    ap.add_argument("--cpus", default="", help="comma list of CPUs for the lanes")
    ap.add_argument("--min-gain", type=float, default=0.01)
    ap.add_argument("--corpus", default=str(ROOT / "bench" / "corpus"))
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    corpus = Path(a.corpus).resolve()
    all_files = sorted(p.name for p in corpus.iterdir() if p.is_file() and p.stat().st_size > 0)
    if a.files == "all":
        files = all_files
    elif a.files == "quick":
        files = [f for f in QUICK_FILES if f in all_files]
    else:
        files = a.files.split(",")
    targets = [] if a.solid_only else [(f, [f]) for f in files]
    if a.large and (corpus / "large").is_dir():
        targets += [(f"large/{p.name}", [f"large/{p.name}"]) for p in sorted((corpus / "large").iterdir())]
    if a.solid or a.solid_only:
        targets.append(("SOLID", all_files))
    modes = a.modes.split(",")
    ncpu = os.cpu_count() or 4
    cpus = [int(c) for c in a.cpus.split(",")] if a.cpus else \
        [(2 + i * max(1, ncpu // a.lanes)) % ncpu for i in range(a.lanes)]

    a_bin, b_bin = Path(a.a_bin).resolve(), Path(a.b_bin).resolve()
    jobs = [(m, n, fl) for m in modes for n, fl in targets]
    # Big jobs first; each job keeps its own lane CPU for all its repetitions.
    jobs.sort(key=lambda j: -sum((corpus / f).stat().st_size for f in j[2]) * (4 if j[0] == "mx" else 1))
    print(f"bench: {len(jobs)} jobs x {a.reps} reps x 2 bins on CPUs {cpus}", flush=True)
    results = {}
    t_start = time.time()
    with cf.ThreadPoolExecutor(max_workers=len(cpus)) as ex:
        free = list(cpus)
        futs = {}
        pending = list(jobs)
        while pending or futs:
            while pending and free:
                m, n, fl = pending.pop(0)
                cpu = free.pop(0)
                f = ex.submit(lane_job, (a_bin, b_bin, cpu, m, n, fl, corpus, a.reps))
                futs[f] = cpu
            done, _ = cf.wait(list(futs), return_when=cf.FIRST_COMPLETED)
            for f in done:
                free.append(futs.pop(f))
                m, n, ta, tb, wa, wb = f.result()
                results.setdefault(m, []).append((n, ta, tb, wa, wb))

    print(f"\n{'mode':5s} {'targets':>7s} {'A cpu(s)':>9s} {'B cpu(s)':>9s} {'speedup':>8s} {'95% CI':>17s}  verdict")
    report = {"a": str(a_bin), "b": str(b_bin), "reps": a.reps, "modes": {}}
    tot_a = tot_b = 0.0
    for m in modes:
        rows = results.get(m, [])
        sa = sum(statistics.median(r[1]) for r in rows)
        sb = sum(statistics.median(r[2]) for r in rows)
        tot_a += sa
        tot_b += sb
        lo, hi = bootstrap_ci([(r[1], r[2]) for r in rows])
        sp = sa / sb if sb > 0 else 1.0
        verdict = "GAIN" if lo > 1.0 + a.min_gain else ("LOSS" if hi < 1.0 else "noise")
        print(f"{m:5s} {len(rows):7d} {sa:9.2f} {sb:9.2f} {sp:8.3f}  [{lo:6.3f}, {hi:6.3f}]  {verdict}")
        report["modes"][m] = {"a": sa, "b": sb, "speedup": sp, "ci": [lo, hi], "verdict": verdict,
                              "targets": {r[0]: {"a": r[1], "b": r[2]} for r in rows}}
    if tot_b > 0:
        print(f"{'TOTAL':5s} {'':7s} {tot_a:9.2f} {tot_b:9.2f} {tot_a / tot_b:8.3f}")
    print(f"(elapsed {time.time() - t_start:.0f}s)")
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
