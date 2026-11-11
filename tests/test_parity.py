#!/usr/bin/env python3
"""Encoder bit-exact parity test suite for UHARC 0.6b.

Compresses input files from corpus/input/ with `./uharc a -<mode>` and
compares the compressed stream (arc[39..], excluding DOS timestamp)
against historical reference archives in corpus/archives/.
Strict requirement: identical size and 0 byte diffs.
"""
import glob
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "build" / "linux" / "uharc"
IN_DIR = ROOT / "corpus" / "input"
ARC_DIR = ROOT / "corpus" / "archives"

MODES = ["m0", "mz", "mx", "m1", "m2", "m3"]


def main():
    if not BIN.exists():
        print(f"Error: binary {BIN} not found. Run 'make' first.")
        sys.exit(1)

    modes_to_test = [m.lstrip("-") for m in sys.argv[2:]] if len(sys.argv) > 2 else MODES
    total_pass = 0
    total_cases = 0

    print(f"=== Running Encoder Parity Test Suite (bin={BIN.name}) ===")

    for mode in modes_to_test:
        mode_pass = 0
        mode_tot = 0
        print(f"\n--- Mode -{mode} ---")

        for src_path in sorted(IN_DIR.glob("*")):
            if not src_path.is_file():
                continue
            name = src_path.name
            ref_path = ARC_DIR / f"{name}__{mode}.uha"
            if not ref_path.exists():
                continue

            mode_tot += 1
            total_cases += 1
            ref_data = ref_path.read_bytes()

            with tempfile.NamedTemporaryFile(suffix=".uha") as tmp:
                cmd = [str(BIN), "a", f"-{mode}", tmp.name, str(src_path)]
                res = subprocess.run(cmd, capture_output=True)
                if res.returncode != 0 or not os.path.exists(tmp.name) or os.path.getsize(tmp.name) == 0:
                    print(f"  [CRASH] {name:15s} -{mode}: exit code {res.returncode}")
                    continue

                gen_data = Path(tmp.name).read_bytes()
                n = min(len(gen_data), len(ref_data))
                diffs = sum(1 for i in range(39, n) if gen_data[i] != ref_data[i])
                diffs += max(0, len(gen_data) - n) + max(0, len(ref_data) - n)

                if len(gen_data) == len(ref_data) and diffs == 0:
                    mode_pass += 1
                    total_pass += 1
                    print(f"  [PASS]  {name:15s} -{mode}: EXACT (size={len(gen_data)}, diffs=0)")
                else:
                    diff_sz = len(gen_data) - len(ref_data)
                    print(f"  [FAIL]  {name:15s} -{mode}: diffs={diffs:6d} (ours={len(gen_data)}, ref={len(ref_data)}, delta={diff_sz:+d})")

        print(f"--> Mode -{mode}: {mode_pass}/{mode_tot} PASS")

    print("\n" + "=" * 60)
    print(f"Parity Summary: {total_pass}/{total_cases} PASS")
    print("=" * 60)
    return 0 if total_pass == total_cases else 1


if __name__ == "__main__":
    sys.exit(main())

