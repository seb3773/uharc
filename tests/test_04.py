#!/usr/bin/env python3
"""Test suite for UHARC 0.4 archive decompression and integrity.

Tests all UHARC 0.4 archives in corpus/archives_04/ using `uharc t` and `uharc x`.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else ROOT / "uharc"
DEFAULT_ARC_DIR = ROOT / "corpus" / "archives_04"
FALLBACK_FULL_DIR = Path("/home/seb/_PROJETS/unuharc_recon/uharc-rs-04/arc")

if "--full" in sys.argv and FALLBACK_FULL_DIR.exists():
    ARC_DIR = FALLBACK_FULL_DIR
elif DEFAULT_ARC_DIR.exists():
    ARC_DIR = DEFAULT_ARC_DIR
elif FALLBACK_FULL_DIR.exists():
    ARC_DIR = FALLBACK_FULL_DIR
else:
    ARC_DIR = None


def main():
    if not BIN.exists():
        print(f"Error: binary {BIN} not found.")
        sys.exit(1)
    if ARC_DIR is None or not ARC_DIR.exists():
        print("Skipping UHARC 0.4 tests: archive directory not found.")
        sys.exit(0)

    archives = sorted(list(ARC_DIR.glob("*.uha")) + list(ARC_DIR.glob("*.UHA")))
    print(f"Testing {len(archives)} UHARC 0.4 archives in {ARC_DIR.name} using {BIN}...")
    ok = 0
    bad = 0

    for arc in archives:
        pw_args = ["-pwsecret"] if arc.name.startswith("pw") else []

        # 1. Test archive integrity
        res = subprocess.run([str(BIN), "t", str(arc)] + pw_args,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0 or "All files OK" not in res.stdout:
            print(f"  [FAIL t] {arc.name:<32} : Integrity test failed (code {res.returncode})")
            bad += 1
            continue

        # 2. Test extraction to temporary folder
        with tempfile.TemporaryDirectory(prefix="uha04_") as tmp_dir:
            res_x = subprocess.run([str(BIN), "x", str(arc), f"-t{tmp_dir}"] + pw_args,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res_x.returncode != 0:
                print(f"  [FAIL x] {arc.name:<32} : Extraction failed (code {res_x.returncode})")
                bad += 1
                continue

            extracted = list(Path(tmp_dir).rglob("*"))
            if not extracted:
                print(f"  [FAIL x] {arc.name:<32} : No files extracted")
                bad += 1
                continue

        print(f"  [PASS]   {arc.name:<32} : OK (integrity + extraction)")
        ok += 1

    print("\n" + "=" * 60)
    print(f"UHARC 0.4 Summary: {ok} passed, {bad} failed (Total: {len(archives)})")
    print("=" * 60)

    if bad > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

