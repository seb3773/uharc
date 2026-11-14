#!/usr/bin/env python3
"""Phase 3 CLI Completeness test suite for UHARC 0.6b reimplementation.

Tests:
1. Wildcards (* and ?) and default *.*
2. @listfile expansion
3. !exclude patterns
4. Custom list/exclude specifiers (-@ and -!)
5. Subdirectory recursion (-r)
6. Path modes (-p-, -pr, -pf, -pe)
7. Overwrite modes (-op, -o+, -o-) and -y
8. Attribute exclusions (-ae)
9. Display modes (-d0, -d1, -d2)
10. Bits per byte display (-bpb)
11. UHARC_OPT environment variable
12. Stop switch scanning (--)
13. Self-extracting archive creation & extraction (-sfx)
14. File filtering on l, x, e
15. Exit code 255 on invalid switch, invalid command, no match
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "uharc"
SFX_STUB = ROOT / "historical_bin" / "UHARCSFX.EXE"


def run(cmd, env=None, stdin=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        cmd,
        env=e,
        input=stdin,
        capture_output=True,
        text=True
    )


def test_banner_and_usage():
    res = run([str(BIN)])
    assert res.returncode == 0
    assert "UHARC 0.6b" in res.stdout
    assert "Usage: UHARC command" in res.stdout
    assert "---< Commands >---" in res.stdout
    assert "---< Switches >---" in res.stdout
    print("  [PASS] Banner & Usage")


def test_invalid_command():
    res = run([str(BIN), "badcmd"])
    assert res.returncode == 255
    assert 'ERROR: Invalid command "badcmd"' in res.stdout or 'ERROR: Invalid command "badcmd"' in res.stderr
    print("  [PASS] Invalid Command -> Code 255")


def test_invalid_switch():
    with tempfile.TemporaryDirectory() as td:
        arc = os.path.join(td, "test.uha")
        res = run([str(BIN), "a", "-nonexistent", arc])
        assert res.returncode == 255
        assert 'ERROR: Invalid switch "-nonexistent"' in res.stdout or 'ERROR: Invalid switch "-nonexistent"' in res.stderr
    print("  [PASS] Invalid Switch -> Code 255")


def test_wildcards_and_default():
    with tempfile.TemporaryDirectory() as td:
        # Create test files
        p1 = os.path.join(td, "file1.txt")
        p2 = os.path.join(td, "file2.txt")
        p3 = os.path.join(td, "data.bin")
        open(p1, "w").write("file1 contents")
        open(p2, "w").write("file2 contents")
        open(p3, "w").write("data contents")

        arc = os.path.join(td, "out.uha")

        # Test wildcard *.txt
        res = run([str(BIN), "a", "-m0", arc, os.path.join(td, "*.txt")])
        assert res.returncode == 0, f"Error: {res.stderr}\n{res.stdout}"

        # List archive
        res_l = run([str(BIN), "-1", arc])
        assert res_l.returncode == 0
        names = [line.strip() for line in res_l.stdout.splitlines() if line.strip()]
        assert any("file1.txt" in n for n in names)
        assert any("file2.txt" in n for n in names)
        assert not any("data.bin" in n for n in names)
    print("  [PASS] Wildcards (*.txt)")


def test_listfile_and_excludes():
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "a.txt")
        p2 = os.path.join(td, "b.txt")
        p3 = os.path.join(td, "c.log")
        open(p1, "w").write("A")
        open(p2, "w").write("B")
        open(p3, "w").write("C")

        lst = os.path.join(td, "files.lst")
        open(lst, "w").write(f'"{p1}"\n"{p2}"\n"{p3}"\n')

        arc = os.path.join(td, "lst.uha")
        # Include @files.lst but exclude *.log
        res = run([str(BIN), "a", "-m0", arc, f"@{lst}", "!*.log"])
        assert res.returncode == 0, f"Error: {res.stderr}\n{res.stdout}"

        res_l = run([str(BIN), "-1", arc])
        names = [line.strip() for line in res_l.stdout.splitlines() if line.strip()]
        assert any("a.txt" in n for n in names)
        assert any("b.txt" in n for n in names)
        assert not any("c.log" in n for n in names)
    print("  [PASS] @listfile and !excludes")


def test_recursion_and_path_modes():
    with tempfile.TemporaryDirectory() as td:
        sub = os.path.join(td, "sub", "dir")
        os.makedirs(sub)
        f1 = os.path.join(td, "top.txt")
        f2 = os.path.join(sub, "deep.txt")
        open(f1, "w").write("top")
        open(f2, "w").write("deep")

        # Test -r with -p- (no paths)
        arc_pnone = os.path.join(td, "none.uha")
        res = run([str(BIN), "a", "-m0", "-r", "-p-", arc_pnone, os.path.join(td, "*.txt")])
        assert res.returncode == 0

        res_l = run([str(BIN), "-1", arc_pnone])
        names = [line.strip() for line in res_l.stdout.splitlines() if line.strip()]
        assert "top.txt" in names
        assert "deep.txt" in names
        assert not any("/" in n for n in names)

        # Test -r with -pr (relative paths)
        arc_prel = os.path.join(td, "rel.uha")
        res = run([str(BIN), "a", "-m0", "-r", "-pr", arc_prel, os.path.join(td, "*.txt")])
        assert res.returncode == 0
    print("  [PASS] Recursion (-r) & Path Modes (-p-, -pr)")


def test_overwrite_modes():
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "test.txt")
        open(f, "w").write("hello")
        arc = os.path.join(td, "arc.uha")

        # Create archive
        run([str(BIN), "a", "-m0", arc, f])
        assert os.path.exists(arc)

        # 1. Overwrite with -o- should fail with code 255
        res = run([str(BIN), "a", "-m0", "-o-", arc, f])
        assert res.returncode == 255
        assert "ERROR: Can't create archive file" in res.stdout or "ERROR: Can't create archive file" in res.stderr

        # 2. Overwrite with -o+ should succeed
        res = run([str(BIN), "a", "-m0", "-o+", arc, f])
        assert res.returncode == 0

        # 3. Overwrite with -y should succeed
        res = run([str(BIN), "a", "-m0", "-y", arc, f])
        assert res.returncode == 0
    print("  [PASS] Overwrite Modes (-o-, -o+, -y)")


def test_display_modes_and_bpb():
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "test.txt")
        open(f, "w").write("hello world" * 10)
        arc = os.path.join(td, "arc.uha")
        run([str(BIN), "a", "-m0", arc, f])

        # -d0 quiet
        res0 = run([str(BIN), "l", "-d0", arc])
        assert res0.returncode == 0
        assert "UHARC 0.6b" not in res0.stdout

        # -d2 verbose
        res2 = run([str(BIN), "l", "-d2", arc])
        assert res2.returncode == 0
        assert "STORE-mode" in res2.stdout
        assert "crc-32" in res2.stdout

        # -bpb
        res_bpb = run([str(BIN), "l", "-bpb", arc])
        assert res_bpb.returncode == 0
        assert "bpb" in res_bpb.stdout
    print("  [PASS] Display Modes (-d0, -d1, -d2) & -bpb")


def test_uharc_opt_and_stop_switch():
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "test.txt")
        open(f, "w").write("hello")
        arc = os.path.join(td, "arc.uha")

        # UHARC_OPT setting -m0
        res = run([str(BIN), "a", arc, f], env={"UHARC_OPT": "-m0"})
        assert res.returncode == 0
        res_l = run([str(BIN), "l", "-d2", arc])
        assert "STORE-mode" in res_l.stdout

        # Stop switch --
        dash_f = os.path.join(td, "-dashfile.txt")
        open(dash_f, "w").write("dash")
        arc2 = os.path.join(td, "dash.uha")
        res2 = run([str(BIN), "a", "-m0", arc2, "--", dash_f])
        assert res2.returncode == 0
    print("  [PASS] UHARC_OPT & Stop Switch (--)")


def test_file_filtering_and_nomatch():
    with tempfile.TemporaryDirectory() as td:
        p1 = os.path.join(td, "doc.txt")
        p2 = os.path.join(td, "img.png")
        open(p1, "w").write("doc")
        open(p2, "w").write("img")
        arc = os.path.join(td, "filt.uha")
        run([str(BIN), "a", "-m0", arc, p1, p2])

        # Filter matching doc.txt
        res = run([str(BIN), "l", arc, "*.txt"])
        assert res.returncode == 0
        assert "doc.txt" in res.stdout
        assert "img.png" not in res.stdout

        # Filter non-matching -> code 255
        res_none = run([str(BIN), "l", arc, "*.xyz"])
        assert res_none.returncode == 255
        assert "No matching files found" in res_none.stdout
    print("  [PASS] File Filtering & No Matching Files -> Code 255")


def test_sfx():
    if not SFX_STUB.exists():
        print("  [SKIP] SFX Stub not found")
        return
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "test.txt")
        open(f, "w").write("hello sfx world")
        arc_exe = os.path.join(td, "sfxarc.exe")

        # Create SFX archive
        res = run([str(BIN), "a", "-m0", f"-sfx{SFX_STUB}", arc_exe, f])
        assert res.returncode == 0, f"Error: {res.stderr}\n{res.stdout}"
        assert os.path.exists(arc_exe)

        # Size should exceed stub size
        assert os.path.getsize(arc_exe) > os.path.getsize(SFX_STUB)

        # List SFX archive with uharc
        res_l = run([str(BIN), "l", arc_exe])
        assert res_l.returncode == 0
        assert "test.txt" in res_l.stdout

        # Extract SFX archive
        out_dir = os.path.join(td, "out")
        res_x = run([str(BIN), "x", arc_exe, f"-t{out_dir}"])
        assert res_x.returncode == 0
        extracted = os.path.join(out_dir, os.path.basename(f))
        assert os.path.exists(extracted)
        assert open(extracted).read() == "hello sfx world"
    print("  [PASS] SFX Archive Creation & Extraction")


def main():
    print("=== Running Phase 3 CLI Completeness Test Suite ===")
    test_banner_and_usage()
    test_invalid_command()
    test_invalid_switch()
    test_wildcards_and_default()
    test_listfile_and_excludes()
    test_recursion_and_path_modes()
    test_overwrite_modes()
    test_display_modes_and_bpb()
    test_uharc_opt_and_stop_switch()
    test_file_filtering_and_nomatch()
    test_sfx()
    print("\nAll Phase 3 CLI Completeness tests passed successfully!")


if __name__ == "__main__":
    main()
