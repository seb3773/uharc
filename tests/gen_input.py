#!/usr/bin/env python3
"""Generate a varied corpus of input files used as UHARC ground truth."""
import os, random, struct, math

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus", "input")
os.makedirs(OUT, exist_ok=True)


def w(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


random.seed(0xC0FFEE)

# 1. plain short text
w("hello.txt", b"Hello UHARC world!\nThis is a test of the UHARC compression format.\n")

# 2. empty file
w("empty.dat", b"")

# 3. repetitive english text
words = ("the quick brown fox jumps over the lazy dog and then runs away into "
         "the deep dark forest where nobody can find him easily ").split()
w("eng.txt", (" ".join(random.choice(words) for _ in range(4000))).encode())

# 4. natural-ish source code
lines = []
for i in range(600):
    lines.append(f"static int func_{i}(int a, int b) {{ return a * {i} + b; }} /* comment {i} */")
w("code.c", ("\n".join(lines) + "\n").encode())

# 5. all zeros (max compressible)
w("zeros.bin", bytes(200000))

# 6. repeating 16-byte pattern
w("pattern.bin", (b"ABCDEFGHIJKLMNOP" * 12000))

# 7. incompressible random
w("random.bin", bytes(random.randrange(256) for _ in range(120000)))

# 8. low-entropy random (biased bytes)
w("biased.bin", bytes(random.choice(b"ABCDE") for _ in range(120000)))

# 9. synthetic "image": smooth gradients + mild noise (tests multimedia filter)
w_, h_ = 256, 256
img = bytearray()
for y in range(h_):
    for x in range(w_):
        img.append(int(127 + 60 * math.sin(x / 40.0) + 40 * math.cos(y / 30.0)) & 0xFF)
w("image.raw", bytes(img))

# 10. 24-bit synthetic image with row correlation
img2 = bytearray()
for y in range(128):
    base = int(100 + 80 * math.sin(y / 20.0))
    for x in range(256):
        img2 += bytes(((base + x) & 0xFF, (base + 2 * x) & 0xFF, (base + 3 * x) & 0xFF))
w("image24.raw", bytes(img2))

# 11. structured binary records
rec = bytearray()
for i in range(20000):
    rec += struct.pack("<IIHH", i, (i * 2654435761) & 0xFFFFFFFF, i & 0xFFFF, 0x1234)
w("records.bin", bytes(rec))

# 12. mixed text/binary
w("mixed.bin", (b"\x00\x01\x02" + b"text line here\n" * 2000 + os.urandom(5000)))

print("generated in", os.path.abspath(OUT))
for fn in sorted(os.listdir(OUT)):
    print(f"  {fn:16s} {os.path.getsize(os.path.join(OUT, fn)):>9d}")
