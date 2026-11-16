#!/usr/bin/env python3
"""Generate deterministic synthetic multimedia samples for the benchmark corpus.

Produces a 16-bit stereo PCM WAV and a 24-bit BMP so that the multimedia
detection / side-channel code paths of every mode are exercised.
"""
import math
import random
import struct
import sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
out.mkdir(parents=True, exist_ok=True)
random.seed(1)

n = 262144
data = bytearray()
for i in range(n):
    left = int(8000 * math.sin(i * 0.01) + 3000 * math.sin(i * 0.37) + random.randint(-200, 200))
    right = int(7000 * math.sin(i * 0.013) + random.randint(-200, 200))
    data += struct.pack("<hh", left, right)
hdr = (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
       + struct.pack("<IHHIIHH", 16, 1, 2, 44100, 44100 * 4, 4, 16)
       + b"data" + struct.pack("<I", len(data)))
(out / "audio16.wav").write_bytes(hdr + data)

w = h = 512
row = (w * 3 + 3) & ~3
px = bytearray()
for y in range(h):
    for x in range(w):
        px += bytes(((x + random.randint(-3, 3)) & 255,
                     (y + random.randint(-3, 3)) & 255,
                     ((x ^ y) >> 1) & 255))
    px += b"\0" * (row - w * 3)
bmp = (b"BM" + struct.pack("<IHHI", 54 + len(px), 0, 0, 54)
       + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(px), 2835, 2835, 0, 0))
(out / "image24.bmp").write_bytes(bmp + px)
