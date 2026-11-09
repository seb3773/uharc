#!/usr/bin/env python3
"""Decompression and verification test suite for UHARC 0.6b.

Extracts every corpus/archives/*.uha using `uharc` and verifies MD5 hashes
against reference files in corpus/input/.

Usage: python3 tests/test_all.py [path/to/uharc]
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
ARCHIVES = ROOT / "corpus" / "archives"
INPUT = ROOT / "corpus" / "input"


def compute_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_expected_hashes():
    hashes = {}
    for p in INPUT.glob("*"):
        if p.is_file():
            hashes[p.name] = compute_md5(p)
    return hashes


def main():
    if not BIN.exists():
        print(f"Error: binary {BIN} not found. Run 'make' first.")
        sys.exit(1)

    expected = get_expected_hashes()
    archives = sorted(ARCHIVES.glob("*.uha"))
    if not archives:
        print(f"Error: no archives found in {ARCHIVES}")
        sys.exit(1)

    print(f"Testing {len(archives)} reference archives using {BIN}...")
    ok = 0
    bad = 0
    skipped = 0

    for arc in archives:
        arc_name = arc.name
        pw_args = ["-pwsecret42"] if "_pw" in arc_name else []

        # Test integrity command first: uharc t <arc>
        cmd_test = [str(BIN), "t", str(arc)] + pw_args
        res_test = subprocess.run(cmd_test, capture_output=True, text=True)
        if res_test.returncode != 0:
            print(f"  [FAIL t] {arc_name:35s}: integrity test failed (code {res_test.returncode})")
            bad += 1
            continue

        # Extract to temporary directory: uharc x <arc> -t <tmp_dir>
        # For all_pathfull.uha (which stores absolute DOS drive paths Z:/...),
        # zip-slip protection safely blocks extracting full paths under `x`.
        # We verify this security rejection, then use `e` (flat extract) to check MD5.
        extract_mode = "x"
        if arc_name == "all_pathfull.uha":
            res_sec = subprocess.run(
                [str(BIN), "x", str(arc), f"-t/tmp/uha_sec_test"] + pw_args,
                capture_output=True, text=True
            )
            if "Security warning: skipping unsafe path traversal" not in res_sec.stderr:
                print(f"  [FAIL sec] {arc_name:35s}: zip-slip protection did not trigger")
                bad += 1
                continue
            extract_mode = "e"

        with tempfile.TemporaryDirectory(prefix="uha_test_") as tmp_dir:
            cmd_extract = [str(BIN), extract_mode, str(arc), f"-t{tmp_dir}"] + pw_args
            res_ext = subprocess.run(cmd_extract, capture_output=True, text=True)
            if res_ext.returncode != 0:
                print(f"  [FAIL {extract_mode}] {arc_name:35s}: extraction failed (code {res_ext.returncode})")
                bad += 1
                continue

            # Verify extracted files
            extracted_files = [p for p in Path(tmp_dir).rglob("*") if p.is_file()]
            mismatch = False
            for ef in extracted_files:
                base = ef.name
                if base not in expected:
                    continue
                actual_hash = compute_md5(ef)
                if actual_hash != expected[base]:
                    print(f"  [MD5 MISMATCH] {arc_name}: {base} got {actual_hash} expected {expected[base]}")
                    mismatch = True
                    break

            if mismatch:
                bad += 1
            else:
                ok += 1
                print(f"  [PASS] {arc_name:35s}: OK ({len(extracted_files)} file(s))")

    print("\n" + "=" * 60)
    print(f"Test Summary: {ok} passed, {bad} failed, {skipped} skipped (Total: {len(archives)})")
    print("=" * 60)

    if bad > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
