#!/usr/bin/env python3
"""Bit-exactness gate for encoder optimizations.

Compares the archives produced by a candidate binary against those produced by
a baseline binary (the last known-good encoder) on the extended benchmark
corpus, for every compression mode and a set of switch variants. Archives are
compared from offset 39 onwards (the first 39 bytes hold the archive creation
time). The legacy reference suite (tests/test_parity.py) is run as well.

Any single byte difference is a hard failure: the golden rule of the project
is bit-exact output with the legacy encoder.

Usage:
    bench/verify.py BASELINE_BIN CANDIDATE_BIN [--corpus DIR] [--jobs N] [--quick]

Baseline outputs are cached in bench/.cache/ref-<sha256 of baseline>/ so that
repeated verifications only run the candidate.
"""
import argparse
import concurrent.futures as cf
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODES = ["m0", "mz", "mx", "m1", "m2", "m3", "mr", "mw"]

# (label, files, switches) extra variants exercised on top of the mode matrix.
VARIANTS = [
    ("md16", ["records.bin", "dickens.1m"], ["-m3", "-md16"]),
    ("md256", ["records.bin", "samba.1m"], ["-m3", "-md256"]),
    ("md1024", ["records.bin", "mozilla.1m"], ["-m2", "-md1024"]),
    ("md64_m1", ["xml.1m", "ooffice.1m"], ["-m1", "-md64"]),
    ("mm-", ["image24.bmp", "audio16.wav", "x-ray.1m", "image24.raw"], ["-m3", "-mm-"]),
    ("mm-_m1", ["audio16.wav", "mr.1m"], ["-m1", "-mm-"]),
    ("pw", ["hello.txt", "dickens.1m"], ["-m1", "-pwsecret42"]),
    ("pw_mx", ["code.c"], ["-mx", "-pwsecret42", "-ph-"]),
    ("mx_md1024", ["nci.1m", "webster.1m"], ["-mx", "-md1024"]),
]
LARGE_MODES = ["m1", "m2", "m3", "mx", "mz", "mw"]


def sha256(path):
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


def run_case(binary, cwd, out_path, switches, files):
    cmd = [str(binary), "a", "-y", "-d0"] + switches + [str(out_path)] + files
    res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if res.returncode != 0 or not Path(out_path).exists():
        return None, res.stderr.decode(errors="replace")[-300:]
    return Path(out_path).read_bytes()[39:], ""


def build_cases(corpus, quick):
    files = sorted(p.name for p in corpus.iterdir() if p.is_file())
    cases = []
    modes = ["m1", "m3", "mx", "mz"] if quick else MODES
    for f in files:
        for m in modes:
            cases.append((f"{f}__{m}", [f"-{m}"], [f]))
    if not quick:
        for label, vfiles, sw in VARIANTS:
            for f in vfiles:
                if (corpus / f).exists():
                    cases.append((f"{f}__{label}", sw, [f]))
        large = corpus / "large"
        if large.is_dir():
            for p in sorted(large.iterdir()):
                for m in LARGE_MODES:
                    cases.append((f"large_{p.name}__{m}", [f"-{m}"], [f"large/{p.name}"]))
    # Solid multi-file archive of the whole top-level corpus, every mode.
    for m in modes:
        cases.append((f"SOLID__{m}", [f"-{m}"], files))
    return cases


def job(args):
    name, sw, files, base, cand, corpus, refdir = args
    ref_file = refdir / f"{name}.bin"
    with tempfile.TemporaryDirectory(prefix="uhv_") as td:
        if ref_file.exists():
            ref = ref_file.read_bytes()
        else:
            ref, err = run_case(base, corpus, Path(td) / "b.uha", sw, files)
            if ref is None:
                return name, "BASEFAIL", err
            tmp = ref_file.with_suffix(".tmp%d" % os.getpid())
            tmp.write_bytes(ref)
            tmp.replace(ref_file)
        got, err = run_case(cand, corpus, Path(td) / "c.uha", sw, files)
    if got is None:
        return name, "CRASH", err
    if got != ref:
        n = min(len(got), len(ref))
        first = next((i for i in range(n) if got[i] != ref[i]), n)
        return name, "DIFF", f"size ours={len(got)+39} ref={len(ref)+39} first_diff@{first+39}"
    return name, "OK", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--corpus", default=str(ROOT / "bench" / "corpus"))
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--quick", action="store_true", help="reduced matrix (m1,m3,mx,mz)")
    ap.add_argument("--no-legacy", action="store_true", help="skip tests/test_parity.py")
    a = ap.parse_args()

    base = Path(a.baseline).resolve()
    cand = Path(a.candidate).resolve()
    corpus = Path(a.corpus).resolve()
    if not corpus.is_dir():
        sys.exit(f"corpus {corpus} missing: run bench/make_corpus.sh first")
    refdir = ROOT / "bench" / ".cache" / f"ref-{sha256(base)[:16]}"
    refdir.mkdir(parents=True, exist_ok=True)

    cases = build_cases(corpus, a.quick)
    # Longest jobs first (solid and large archives) for better packing.
    cases.sort(key=lambda c: (not c[0].startswith(("SOLID", "large")), c[0]))
    bad = 0
    with cf.ProcessPoolExecutor(max_workers=a.jobs) as ex:
        work = [(n, sw, fl, base, cand, corpus, refdir) for n, sw, fl in cases]
        for name, status, info in ex.map(job, work):
            if status != "OK":
                bad += 1
                print(f"  [{status}] {name} {info}")
    print(f"verify: {len(cases) - bad}/{len(cases)} cases bit-identical to baseline")

    legacy_ok = True
    if not a.no_legacy:
        res = subprocess.run([sys.executable, str(ROOT / "tests" / "test_parity.py"), str(cand)],
                             capture_output=True, text=True)
        summary = [l for l in res.stdout.splitlines() if "Parity Summary" in l]
        print("legacy:", summary[0].strip() if summary else "no summary")
        legacy_ok = res.returncode == 0
        if not legacy_ok:
            print("\n".join(l for l in res.stdout.splitlines() if "FAIL" in l or "CRASH" in l))
            print("hint: corpus/input mtimes must be 2026-09-23 00:35:44 UTC "
                  "(touch -d '2026-09-23 00:35:44 UTC' corpus/input/*)")
    ok = bad == 0 and legacy_ok
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
