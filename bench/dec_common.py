"""Shared helpers of the decoder bench scripts (dec_verify.py, dec_bench.py).

Archive sets:
  bench/dec_corpus    C-encoder archives, every bench corpus file x every
                      UHARC 0.6 mode (bench/make_dec_corpus.sh)
  corpus/archives     legacy UHARC.EXE 0.6b reference archives
  bench/ext_corpus    native UHARC 0.4 archives + a native 0.6 archive
                      (bench/fetch_ext_corpus.sh)
  corpus/archives_04  legacy UHARC 0.4 reference archives (in the repository)
  corpus/archives_02  legacy UHARC 0.2 reference archives (in the repository)
  bench/ext02_corpus  all 48 native UHARC 0.2 archives (UHARC02.EXE output,
                      incl. the large EXE/MED multi-file sets), fetched by
                      bench/fetch_ext_corpus.sh

Groups are derived from the archive header (format version + codec order),
e.g. "v6:ppm", "v6:alz2", "v4:lzp", so every codec of both decoders gets its
own timing verdict.
"""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETS = {
    "dec": ROOT / "bench" / "dec_corpus",
    "legacy": ROOT / "corpus" / "archives",
    "ext": ROOT / "bench" / "ext_corpus",
    "ref04": ROOT / "corpus" / "archives_04",
    "ref02": ROOT / "corpus" / "archives_02",
    "ext02": ROOT / "bench" / "ext02_corpus",
}
GROUP_ORDER = ["store", "rle", "lz78", "lzp", "ppm", "alz1", "alz2", "alz3"]

# Representative subset for quick A/B timing.
QUICK = {
    # C-encoder archives: text, xml, executable, database, image, audio,
    # star catalogue, records, source, large (window wrap), solid.
    "dec": ["dickens.1m", "xml.1m", "mozilla.1m", "ooffice.1m", "osdb.1m", "sao.1m",
            "x-ray.1m", "audio16.wav", "image24.bmp", "records.bin", "code.c",
            "mozilla.6m", "SOLID_all"],
    # Native 0.4 / 0.6 archives.
    "ext": ["v04_full_m0_mmon", "v04_full_mr", "v04_full_mw", "v04_full_mz_mmoff",
            "v04_full_mz_mmon", "v04_full_mx_mmoff", "v04_full_mx_mmon",
            "v04_full_m1_mmoff", "v04_full_m2_mmon", "v04_full_m3_mmoff", "v04_full_m3_mmon",
            "v04_ppm_cant", "v04_filt_exe_mx", "v04_filt_exe_mz", "v04_alz_mm_all",
            "v04_ppm_media", "v04_lz78_md1024", "v04_lzp_md32m", "v06_D3X"],
}


def password(arc):
    arc = Path(arc).resolve()
    if arc.parent == SETS["ext"] and arc.name.startswith("v04_pw"):
        return "secret"
    if arc.parent == SETS["ref04"] and arc.name.startswith("pw"):
        return "secret"
    if "_pw" in arc.name:
        return "secret42"
    return None


def archives(sets=("dec", "legacy", "ext", "ref04", "ref02", "ext02")):
    out = []
    for s in sets:
        d = SETS[s]
        if d.is_dir():
            out += sorted(p for p in d.iterdir()
                          if p.suffix.lower() == ".uha" and not p.name.endswith(".tmp.uha"))
    return out


def codec(version, order):
    if order == 0:
        c = "store"
    elif order == 1:
        c = "rle"
    elif order <= 7:
        c = "lz78"
    elif order <= 23:
        c = "lzp"
    elif order <= 39:
        c = "ppm"
    elif order <= 87:
        c = "alz%d" % ((order - 40) // 16 + 1)
    else:
        c = "unknown"
    return "v%d:%s" % (version if version in (2, 4) else 6, c)


def groups_of(harness, arcs):
    """Map archive path -> group label, using `dec_harness -I` (cached)."""
    cache = ROOT / "bench" / ".cache" / "dec-groups.json"
    known = json.loads(cache.read_text()) if cache.exists() else {}
    todo = [a for a in arcs if str(a) not in known]
    for i in range(0, len(todo), 200):
        chunk = todo[i:i + 200]
        res = subprocess.run([str(harness), "-I"] + [str(a) for a in chunk],
                             capture_output=True, text=True)
        lines = res.stdout.splitlines()
        for a, line in zip(chunk, lines):
            f = line.split("\t")
            known[str(a)] = codec(int(f[1]), int(f[2])) if len(f) >= 5 else "v?:unknown"
    if todo:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(known, indent=0))
    return {a: known[str(a)] for a in arcs}


def group_sort_key(g):
    v, c = g.split(":")
    return ({"v6": 0, "v4": 1, "v2": 2}.get(v, 3), GROUP_ORDER.index(c) if c in GROUP_ORDER else 99)


def is_quick(arc):
    arc = Path(arc)
    stem = arc.name[:-4]
    if arc.parent == SETS["dec"]:
        base, _, rest = stem.partition("__")
        return base in QUICK["dec"] and "_" not in rest
    if arc.parent == SETS["ext"]:
        return stem in QUICK["ext"]
    return False
