#!/usr/bin/env python3
"""Bit-exactness gate for decoder optimizations.

Decodes every archive of the decoder corpus (bench/dec_corpus, see
bench/make_dec_corpus.sh), of the legacy reference corpus (corpus/archives,
produced by UHARC.EXE 0.6b) and of the external native corpus
(bench/ext_corpus: UHARC 0.4 archives + a native 0.6 archive, see
bench/fetch_ext_corpus.sh) with a baseline and a candidate build of
bench/dec_harness, and requires, for every archive:

  * identical return code, payload size, member count and member CRC status;
  * identical decoded payload (FNV-1a 64 and CRC-32 of the whole payload).

The candidate must therefore reproduce the baseline output byte for byte on
every input, including inputs that the baseline itself does not round-trip
(those are reported separately as pre-existing issues, they are not caused
by the candidate). For mono-file archives the decoded payload is also
compared with the original input file (round-trip status).

Optionally (--cli), the candidate CLI is run through tests/test_all.py (MD5 of
extracted files against corpus/input for the 89 legacy archives) and through
an extract (`e`) pass on the decoder corpus that compares every extracted
file with its original.

Baseline results are cached per harness hash in bench/.cache/dec-ref-<hash>.

Usage:
    bench/dec_verify.py BASE_HARNESS CAND_HARNESS [--cli CAND_UHARC] [--jobs N]
"""
import argparse
import concurrent.futures as cf
import filecmp
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dec_common import ROOT, archives, password  # noqa: E402


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


def run_one(harness, arc):
    cmd = [str(harness), "-q"]
    if password(arc):
        cmd += ["-p", password(arc)]
    cmd.append(str(arc))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return f"CRASH({res.returncode})"
    f = res.stdout.strip().split("\t")
    if len(f) < 9:
        return f[1] if len(f) > 1 else "ERR"
    # rc usize members crc_ok fnv64 crc32  (timings excluded)
    return "\t".join([f[1], f[2], f[3], f[4], f[5], f[8]])


def run_all(harness, arcs, jobs):
    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        res = list(ex.map(lambda a: run_one(harness, a), arcs))
    return {str(a.relative_to(ROOT)): r for a, r in zip(arcs, res)}


def original_of(arc):
    m = re.match(r"^(.*)__m[0-9a-z](?:_.+)?\.uha$", arc.name)
    if (not m or arc.name.startswith("SOLID_") or arc.name.startswith("ALL__")
            or "bench/ext_corpus" in str(arc)):
        return None
    base = m.group(1)
    for d in (ROOT / "bench" / "corpus", ROOT / "bench" / "corpus" / "large", ROOT / "corpus" / "input"):
        if (d / base).is_file():
            return d / base
    return None


def cli_extract_check(cli, arcs, jobs):
    """Extract each mono-file decoder-corpus archive and compare with its original."""
    def one(arc):
        orig = original_of(arc)
        if orig is None or "bench/dec_corpus" not in str(arc):
            return None
        with tempfile.TemporaryDirectory(prefix="uhv_") as td:
            cmd = [str(cli), "e", "-y", "-d0", str(arc), f"-t{td}"]
            if password(arc):
                cmd.append(f"-pw{password(arc)}")
            subprocess.run(cmd, capture_output=True)
            out = Path(td) / orig.name
            ok = out.is_file() and filecmp.cmp(out, orig, shallow=False)
            return (arc.name, ok)
    with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
        return [r for r in ex.map(one, arcs) if r is not None]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("cand")
    ap.add_argument("--cli")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    args = ap.parse_args()

    arcs = archives()
    cache = ROOT / "bench" / ".cache" / f"dec-ref-{sha(args.base)}-{len(arcs)}.json"
    if cache.exists():
        base = json.loads(cache.read_text())
    else:
        base = run_all(args.base, arcs, args.jobs)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(base, indent=0))
    cand = run_all(args.cand, arcs, args.jobs)

    diffs = [k for k in base if base[k] != cand.get(k)]
    pre = []
    rt_ok = 0
    for a in arcs:
        k = str(a.relative_to(ROOT))
        f = base[k].split("\t")
        bad = len(f) < 6 or f[0] != "0" or f[2] != f[3]
        orig = original_of(a)
        if not bad and orig is not None:
            bad = int(f[5], 16) != (zlib.crc32(orig.read_bytes()) & 0xFFFFFFFF)
        if bad:
            pre.append(k)
        else:
            rt_ok += 1

    print(f"archives checked: {len(arcs)}")
    print(f"baseline round-trip OK: {rt_ok}, pre-existing baseline failures: {len(pre)}")
    for k in pre:
        print(f"   [pre-existing] {k}: {base[k]}")
    if diffs:
        print(f"FAIL: {len(diffs)} archive(s) decode differently from the baseline:")
        for k in diffs:
            print(f"   {k}\n      base: {base[k]}\n      cand: {cand.get(k)}")
    else:
        print("PASS: candidate output is byte-identical to the baseline on every archive")

    rc = 1 if diffs else 0
    if args.cli:
        r = subprocess.run([sys.executable, str(ROOT / "tests" / "test_all.py"), args.cli],
                           capture_output=True, text=True)
        last = [l for l in r.stdout.splitlines() if "Summary" in l]
        print("tests/test_all.py:", last[-1] if last else r.stdout[-300:])
        if r.returncode != 0:
            rc = 1
        ex = cli_extract_check(args.cli, arcs, args.jobs)
        bad = [n for n, ok in ex if not ok]
        known = {Path(k).name for k in pre}
        new_bad = [n for n in bad if n not in known]
        print(f"CLI extract vs original: {len(ex) - len(bad)}/{len(ex)} identical"
              f" ({len(bad) - len(new_bad)} pre-existing, {len(new_bad)} new)")
        for n in new_bad:
            print("   [NEW FAILURE]", n)
        if new_bad:
            rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
