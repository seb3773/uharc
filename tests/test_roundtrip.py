#!/usr/bin/env python3
"""Roundtrip compression and verification test suite for UHARC 0.6b.

Compresses input files under all compression modes (-m0, -m1, -m2, -m3, -mx, -mz),
tests archive integrity with `uharc t`, extracts with `uharc x`, and verifies
byte-identical MD5 match.

Usage: python3 tests/test_roundtrip.py [path/to/uharc]
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "uharc"
INPUT = ROOT / "corpus" / "input"

MODES = ["-m0", "-m1", "-m2", "-m3", "-mx", "-mz"]
TEST_FILES = ["hello.txt", "code.c", "pattern.bin", "zeros.bin"]


def compute_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    if not BIN.exists():
        print(f"Error: binary {BIN} not found. Run 'make' first.")
        sys.exit(1)

    print("Running round-trip compression test suite...")
    ok = 0
    bad = 0

    with tempfile.TemporaryDirectory(prefix="uha_rt_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        for tf in TEST_FILES:
            src_file = INPUT / tf
            if not src_file.exists():
                continue
            orig_md5 = compute_md5(src_file)

            for mode in MODES:
                arc_file = tmp_path / f"test_{tf}_{mode[1:]}.uha"
                out_dir = tmp_path / f"out_{tf}_{mode[1:]}"
                out_dir.mkdir(parents=True, exist_ok=True)

                # 1. Compress
                cmd_add = [str(BIN), "a", mode, str(arc_file), str(src_file)]
                res_add = subprocess.run(cmd_add, capture_output=True, text=True)
                if res_add.returncode != 0 or not arc_file.exists():
                    print(f"  [FAIL COMPRESS] {tf:15s} {mode:4s}: code {res_add.returncode}")
                    bad += 1
                    continue

                # 2. Test integrity
                cmd_t = [str(BIN), "t", str(arc_file)]
                res_t = subprocess.run(cmd_t, capture_output=True, text=True)
                if res_t.returncode != 0:
                    print(f"  [FAIL TEST]     {tf:15s} {mode:4s}: code {res_t.returncode}")
                    bad += 1
                    continue

                # 3. Extract flat
                cmd_ext = [str(BIN), "e", str(arc_file), f"-t{out_dir}"]
                res_ext = subprocess.run(cmd_ext, capture_output=True, text=True)
                if res_ext.returncode != 0:
                    print(f"  [FAIL EXTRACT]  {tf:15s} {mode:4s}: code {res_ext.returncode}")
                    bad += 1
                    continue

                extracted_file = out_dir / tf
                if not extracted_file.exists():
                    print(f"  [FAIL NOTFOUND] {tf:15s} {mode:4s}: file {extracted_file} missing")
                    bad += 1
                    continue

                ext_md5 = compute_md5(extracted_file)
                if ext_md5 != orig_md5:
                    print(f"  [FAIL MD5]      {tf:15s} {mode:4s}: MD5 mismatch ({ext_md5} != {orig_md5})")
                    bad += 1
                else:
                    ok += 1
                    print(f"  [PASS]          {tf:15s} {mode:4s}: Roundtrip OK ({ext_md5})")

    print("\n" + "=" * 60)
    print(f"Roundtrip Summary: {ok} passed, {bad} failed")
    print("=" * 60)

    if bad > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

