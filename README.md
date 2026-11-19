# uharc -- UHARC 0.6b Multimedia Archiver (Pure C99 Reimplementation)

Pure C99 standalone reimplementation of the legendary **UHARC 0.6b archiver** (1997-2005, by Uwe Herklotz).

> **Reverse Engineering & Legal Notice:** This work was conducted strictly for the purposes of software interoperability and digital data preservation (under European Directive 2009/24/EC) to reconstruct the proprietary compression algorithms, container format, and transformations of an obsolete 32-bit DOS/Windows archiver.

This repository provides a complete, self-contained C99 implementation (standard C library + `-lm`, zero external third-party dependencies) combining both **compressor** (`uharc a` / `uharc m`) and **decompressor** (`uharc x` / `uharc e`) into a single unified binary (`uharc`), designed for **bidirectional bit-exact compatibility** with the original historical Windows x86 binary (`UHARC.EXE` 0.6b), with **transparent read/list/test/extract support for legacy UHARC 0.2 (`UHA\x02`) and 0.4 (`UHA\x04`) archives**.

---

## About UHARC -- A piece of compression history

UHARC (Uwe Herklotz ARChiver) is a file archiver developed by Uwe Herklotz, whose development dates back to 1997. Over the years, it gained a reputation among compression enthusiasts for its exceptionally high compression ratios, particularly with its ALZ compression method.
At a time when ZIP, RAR and ACE dominated the archiving landscape, UHARC stood out as an unusually ambitious compression tool. It combined several compression techniques, including ALZ, LZP and PPM, with dedicated multimedia detection and preprocessing capabilities designed to extract as much redundancy as possible from different types of data.

Its compression capabilities could be remarkable, sometimes achieving results significantly beyond those of mainstream archivers. This came at a cost: compression could be extremely CPU-intensive and considerably slower than more conventional alternatives. UHARC was therefore never intended to be an everyday archiver for everyone, but rather a specialized tool for users willing to trade processing time for smaller archives.
The last publicly released version, UHARC 0.6b, dates from October 1, 2005.
Despite its technical ambitions and its place in the history of high-compression archivers, UHARC remained a relatively niche, proprietary format. Its internal compression mechanisms were never widely documented, and support outside its original Windows environment remained limited.

### Project Goals

This project aims to preserve UHARC's technology and make its functionality accessible on modern systems through an independent C implementation.
Beyond simply providing another way to extract legacy archives, the objective is to reproduce the original archiver's compression and decompression behaviour, preserving compatibility with the historical UHARC format.
**The goal is not merely format compatibility, but exact reproduction of the original encoder's output.**
The project is also an opportunity to document and study a largely undocumented piece of compression engineering from an era when experimental archivers pushed the limits of data compression.

UHARC is more than an old archiver: it is a small piece of compression history worth preserving ;-)

### Reverse Engineering & Reconstruction Methodology

Because UHARC 0.6b was distributed exclusively as closed-source 32-bit x86 Windows binaries with no public bitstream specification, this reimplementation was achieved through systematic reverse engineering:

- **Static Binary Analysis**: Targeted disassembly and decompilation of `UHARC.EXE` and `UNUHARC.EXE` using IDA Pro, Ghidra, and GNU `objdump` to map internal dispatch tables, range coder primitives, Fenwick binary indexed trees, secondary symbol estimation (SSE) tables, and sliding window ring buffers.
- **Dynamic Instrumentation & Debugging**: Executing the original binaries under Wine with `winedbg` and dynamic breakpoint harnesses to monitor intermediate execution states, inspect register values, and trace control flow.
- **Differential State Tracing & Captures**: Fine-grained memory and execution capture harnesses (including custom instrumentation scripts and state dump probes) comparing internal coder states at every critical decision point:
  - Match evaluation costs, parser tie-breaking, and MRU slot promotion in ALZ.
  - Fenwick tree cumulative frequency updates and escape probability scaling in PPM-II.
  - S-box key schedule derivation and additive keystream generation.
  - Audio and image delta-filter phase transformations.
- **Pure Standard C99 Reconstruction**: Translating all recovered algorithms and state machines into portable standard C99 with zero third-party dependencies (standard C library + `-lm`), continuously verified by automated bit-for-bit regression tests against historical `UHARC.EXE` 0.6b archives.

### Why is the historical dictionary limit set at 32 MB?

The era-specific constraint (2005) was memory consumption in -m3 (ALZ Best): the ALZ Best model allocates a binary search tree (BST), hash tables, and node arenas proportional to the window. For a 32 MB dictionary, the encoder consumes roughly 247 MB of RAM (an expansion factor of about 7.7×).

DOS / 32-bit DPMI (XMS) environment: back then, under DOS/4GW or CWSDPMI, the contiguous virtual address space available to DPMI applications rarely exceeded 256 MB to 512 MB. Attempting to allocate a 192 MB dictionary would have required more than 1.5 GB of contiguous RAM, which was impossible under DOS and would have saturated most Windows XP machines of 2005. However, this was not merely an artificial command-line cap. The 32 MB limit is baked deep into the mathematics of the UHARC format, due to the format's architectural locks: if anyone tries to patch the executable to force a larger dictionary, here are the three insurmountable structural barriers they would encounter:

**The ALZ distance table is mathematically capped at 32 MB**  
In the ALZ codec (alz_tables.c and alz_const.inc), repeat distances are encoded via an arithmetic coding tree (AlzFullDistanceNext) tied to two static 44-element tables:  
AlzDistanceBase[44] and AlzDistanceSpan[44]  
For the 44th and final slot:  
Base[43] = 25165824 (24 MB)  
Span[43] = 8388608 (8 MB)  
Base + Span = 33554432 bytes = 32 MB  
Consequence: ALZ's Range Coder has no symbol, no slot, and no tree path to encode or decode a distance greater than 33,554,432 bytes. Any match beyond 32 MB returns −1 in dist_to_bucket() (alz_match.c). To exceed 32 MB in ALZ, one would have to invent new slots (45, 46…), design a new Huffman/Range Coding tree, and recompute the probabilities, which would break the grammar of the bitstream.

**The other problem: the container's order byte and the destructive modulo 16**  
In the archive header (FORMAT.md), the order byte (offset 0x0A) encodes both the method class and the dictionary size:  
For ALZ: order = 40 + 16 × class + k, where k ∈ [0..15] represents the power of 2: 2^(k+10) = 1 KB .. 32 MB.  
Now, in the official UHARC.EXE decoder, the window size formula is hard-wired as follows:  
dict_size = 1 << (((order - 40) % 16) + 10);  
If one used a k >= 16 (for example k=16 → 64 MB, k=17 → 128 MB), there would be order collisions with the following classes (ALZ orders occupy 40..87).  
The legacy decoder's modulo 16 would wrap around: an order requesting 64 MB (k=16) would be interpreted by the legacy code as 16 (mod 16) = 0 → 1 KB! The legacy decoder would allocate 1 KB and instantly crash (buffer overflow or corruption).

For PPM-II (-mx) and LZP (-mz): same thing; the sliding buffer is computed as 1 << (((order - 24) % 16) + 10). PPM orders occupy 24..39 (exactly 16 values), so going beyond 39 would collide with ALZ (which starts at 40).  
LZP (-mz): LZP does not encode explicit distances (it is a ring buffer with context prediction). It is the only algorithm whose bitstream could support a wider window (2^(order+2)) without mathematical modification, but its orders range from 8..23; order 24 is already reserved for PPM-II...

In the end, thinking about the "feasibility" of implementing a "large dictionary" extension:  
The UHARC container has an unallocated order range from 88 to 255 (the official modes stop at 87).  
We could define extended orders (for example order = 88..100 for LZP extended to 64 MB, 128 MB, 256 MB, 512 MB); our encoder and our decoder would know perfectly well how to write and read them back.  
What is very complex, however: we would have to create brand-new distance slots in AlzDistanceBase / AlzDistanceSpan from scratch and extend the AlzFullDistanceNext state tree. That would amount to inventing a new, undocumented sub-codec. Moreover, there would inevitably be a compatibility problem with legacy UHARC.EXE: any archive produced with a dictionary > 32 MB would be 100% incompatible with the historical UHARC.EXE (which would display either "unknown compression method" or a fatal error)...

In conclusion, I will not attempt to implement support for larger dictionaries: the purpose of this reimplementation is to be a drop-in replacement, 100% faithful and compliant with Uwe Herklotz's original specifications, for digital preservation. At the time of writing (2026), if anyone needs 128 MB, 256 MB, or 1 GB dictionaries to maximize compression, it makes far more sense to turn naturally to LZMA2 (7-Zip) or FreeArc-c, which compress much faster and with far better ratios than the 32-bit UHARC algorithms of 2005.

---

## Highlights

- **Bidirectional Parity with Original `UHARC.EXE` 0.6b**:
  - **Decompression**: 100% bit-exact extraction verified across all **89** primary reference archives plus **4** extended solid multi-file archives (`corpus/archives/extra/`).
  - **Mono-File Encoding**: **72 / 72** bit-identical archives (`arc[39..]`, 0 byte diffs) across all 12 reference corpus files and all 6 modes (`-m0`, `-mz`, `-mx`, `-m1`, `-m2`, `-m3`), plus `-md*`, `-mm-`, `-p-`, `-pr`, and `-pw`/`-ph+`.
  - **Multi-File Solid Encoding**: `0` payload byte diffs for Store (`-m0`), LZP (`-mz`), and PPM-II (`-mx`).
- **Transparent Legacy UHARC 0.2 & 0.4 Decompression (`UHA\x02` and `UHA\x04`)**:
  - Automatically detects UHARC 0.2 and 0.4 archives (including SFX) during `l`, `v`, `t`, `x`, and `e` operations — no extra flags required.
  - Supports all 0.2 compression methods (Store, RLE, LZ78, PPM/LZ methods 8..43) and executable filters, verified across **48 / 48 (100%)** UHARC 0.2 test archives.
  - Supports all 0.4 compression methods (Store, RLE, LZ78, LZP, PPM, ALZ), password-protected archives (`-pw`), and EXE/multimedia/fax post-filters, verified across **103 / 103** UHARC 0.4 test archives (and ASan/UBSan clean).
  - High degree of code reuse with the modern engine (shared CRC-32 table/engine, shared RLE codec, shared LZ78 LSB bitstream engine, shared container entry reconstruction).
- **Complete Feature Set**:
  - **All Compression Modes**: Store (`-m0`), ALZ Fast (`-m1`), ALZ Normal (`-m2`, default), ALZ Best (`-m3`), PPM-II (`-mx`), LZP (`-mz`), RLE (`-mr`), and LZ78 (`-mw`).
  - **Multimedia & Text Modeling**: Built-in ALZ in-stream adaptive side-channel prediction (`-mm+` / `-mm-`), PPM `detr` word transform and multimedia classes, plus x86 BCJ & LZP multimedia preprocessing transforms.
  - **Cryptographic Suite**: Stream cipher encryption for archive payload (`-pw<password>`) and metadata headers (`-ph+` default ON when `-pw` is set, `-ph-` to disable).
  - **Path Storage & Security**: Supports `-p-` (none), `-pr` (relative), and `-pf` (full) path storage on compress, paired with strict zip-slip traversal protection on extract.
  - **Configurable Dictionaries**: Scalable power-of-two sliding window dictionaries from `1 KB` up to `32768 KB` (`-md1` .. `-md32768`, default `-md4096`).
- **Compact & Self-Contained Builds**:
  - Pure standard C99 (`-lm`), compiling cleanly with zero warnings (`-O3 -flto` + stripped) to ~756 KB on native Linux (`build/linux/uharc`) and ~832 KB statically linked on Windows 64-bit via MinGW-w64 (`build/win64/uharc.exe`) — including both the full 0.6b compressor/decompressor and the 0.4 legacy decoders.
- **Extended 4 GB Capacity (Breaking the Historical 2 GB Barrier)**:
  - The historical 2005 `UHARC.EXE` 0.6b binary could not process archives exceeding 2 GB due to 32-bit signed CRT file seeking (`long` in `fseek`/`ftell`), 32-bit address space limits, and a hardcoded scanner check (`ERROR: Archives larger than 2 GB are not supported !`).
  - The underlying UHA 0.6b on-disk container format natively uses 32-bit unsigned integers (`uint32_t`) for both uncompressed (`usize`) and packed (`psize`) stream sizes, supporting containers up to 4 GB (4,294,967,295 bytes).
  - Using 64-bit file I/O and 32-bit unsigned container counters unlocks the container's full **4 GB - 1** architectural capacity on 64-bit Linux and Windows systems.
- **Comprehensive Documentation**:
  - [`FORMAT.md`](FORMAT.md): Exhaustive binary layout, container architecture, Range Coder, and codec bitstream specification.

---

## Parity & Validation Matrix

The engine is verified continuously via built-in self-tests and Python compliance harnesses against historical `UHARC.EXE` 0.6b reference archives:

| Test Suite | Parameters & Scope | Scope / Count | Verified Result |
| :--- | :--- | :---: | :--- |
| **Built-In Self-Tests** | `./uharc --selftest` (CRC-32, v0.6 & v0.4 header parser, EXE/MM filter roundtrip, zip-slip check) | **4 / 4** | **PASS** |
| **Reference Corpus Decompression** | `tests/test_all.py` across `corpus/archives/*.uha` (+ 4 `extra/*.uha`) | **89 / 89** (+4) | **100% MD5 PASS** |
| **Legacy UHARC 0.4 Decompression** | `tests/test_04.py` across `corpus/archives_04/` (Store, RLE, LZ78, LZP, PPM, ALZ, `-pw`, EXE/MM/FAX) | **68 / 68** (103/103 full) | **100% PASS (ASan/UBSan clean)** |
| **Legacy UHARC 0.2 Decompression** | `tests/test_02.py` across `corpus/archives_02/` (Store, RLE, LZ78, PPM/LZ 8..43, EXE unfilter) | **32 / 32** (48/48 full) | **100% PASS (Bit-Exact)** |
| **Roundtrip Suite** | `tests/test_roundtrip.py` (4 files $\times$ 6 modes, also ASan/UBSan clean) | **24 / 24** | **100% MD5 PASS** |
| **Mono-File Standard Parity** | `tests/test_parity.py`: 12 files (`empty.dat`..`zeros.bin`) $\times$ `-m0,-mz,-mx,-m1,-m2,-m3` | **72 / 72** | **100% Bit-Identical (`arc[39..]`, 0 diffs)** |
| **Dictionary Scaling** | `records.bin` with `-m3` across `-md16`, `-md256`, `-md1024`, `-md4096` | **4 / 4** | **100% Bit-Identical (`arc[39..]`, 0 diffs)** |
| **Multimedia Filtering** | `image24.raw` with `-m3 -mm-` (`image24__m3_nomm.uha`) and default `-mm+` (`image24.raw__m3.uha`) | **2 / 2** | **100% Bit-Identical (`arc[39..]`, 0 diffs)** |
| **Cryptographic Protection** | `hello.txt` with `-m1 -pwsecret42 -ph+` (`hello__m1_pw`, `hello__m1_ph_pw`) | **2 / 2** | **100% Bit-Identical (`arc[39..]`, 0 diffs)** |
| **Path Handling Modes** | `-p-` (`all_pathnone`), `-pr` (`all_pathrel`), `-pf` (`all_pathfull`, `-m1`) | **3 / 3** | **`-p-`, `-pr` Bit-Identical** |
| **Multi-File Solid Suites** | `ALL__m0..m3,mx,mz` (12 members) + 4 `extra/*.uha` | **10 archives** | `-m0`, `-mz`, `-mx`, 4 `extra/`: **0 payload diffs** (`S_hzi__mx` 0 diffs) |

---

## Quick Start & Build

### Using `build.sh`

```sh
./build.sh            # Production Linux build -> build/linux/uharc (symlink ./uharc)
./build.sh win64      # Production Windows 64-bit static build -> build/win64/uharc.exe
./build.sh all        # Build both Linux and Windows 64-bit binaries
./build.sh debug      # Build with debug symbols (-g -O0)
./build.sh asan       # Build with AddressSanitizer / UBSan
./build.sh test       # Run self-test and reference corpus verification
./build.sh deb        # Build standalone Debian installer package
./build.sh dist       # Build full release distribution (tar.gz, zip, deb, sha256sums)
./build.sh clean      # Clean build artifacts
```

### Using `make`

```sh
make                  # Build native Linux binary (default)
make win64            # Cross-compile Windows 64-bit binary (MinGW-w64)
make test             # Run test suite
make deb              # Build Debian package
make dist             # Package release bundles
sudo make install     # Install to /usr/local/bin
```

---

## Command-Line Usage

```text
Usage: uharc <command> [-<switch>...] <archive>[.uha] [files...]
```

### Commands

| Command | Description |
| :---: | :--- |
| `a` | **Add** files to archive (create or append) |
| `m` | **Move** files to archive (compress and delete originals upon success) |
| `x` | **Extract** files with full preserved directory tree |
| `e` | **Extract flat** to target directory (ignoring stored path components) |
| `l` | **List** archive contents in tabular view |
| `v` | **Verbose list** of archive contents with ratios and CRC-32 checksums |
| `t` | **Test** archive integrity in memory without writing to disk |

### Switches

| Switch | Description | Default |
| :--- | :--- | :---: |
| `-m<0,1,2,3,x,z,r,w>` | Compression mode: `0`=Store, `1`=ALZ Fast, `2`=ALZ Normal, `3`=ALZ Best, `x`=PPM-II, `z`=LZP, `r`=RLE, `w`=LZ78 | `-m2` |
| `-md<size>` | Maximum dictionary size in KB (power of 2: `1 .. 32768`, `-md-` to disable) | `-md4096` |
| `-mm[-,+]` | Disable/enable built-in multimedia detection/compression | `-mm+` (Enabled) |
| `-o[-,+,p]` | Overwrite mode (`-` never, `+` always, `p` prompt) | `-op` |
| `-p<-,r,f,e>` | Stored pathnames: `-`=none, `r`=relative, `f`=full, `e`=excluded | `-pr` |
| `-pw[password]` | Encrypt archive with specified password (prompts if omitted) | None |
| `-ph[-,+]` | Header/metadata encryption (when `-pw` is active) | `-ph+` (Enabled) |
| `-r[-,+]` | Recurse subdirectories on add/extract/test (`-r+` to enable) | `-r-` (Disabled) |
| `-ed[-,+]` | Store/extract empty directories (`-ed+` to enable) | `-ed-` (Disabled) |
| `-d<0..2>` | Display output mode: `0`=silent, `1`=normal, `2`=detailed progress | `-d1` |
| `-bpb[-,+]` | Beep speaker on user prompt / completion | `-bpb+` (Enabled) |
| `-sfx[stub]` | Create self-extracting archive (optional custom SFX stub path) | Standard archive |
| `-t<dir>` | Specify target extraction directory | Current directory |
| `-y[-,+]` | Assume Yes on queries | `-y-` |
| `-lg<file>` | Write operational log output to specified file | None |
| `-u`, `--unix` | Format paths as Unix relative paths (`/` slashes, lowercase) | Disabled |
| `-1`, `--bare` | Bare output format (one path per line, ideal for scripts, xargs, grep) | Disabled |
| `@listfile` | Read list of input files from specified text file | -- |
| `!exclude` | Exclude files matching wildcard mask from operation | -- |
| `--` | Stop switch scanning (treat subsequent arguments as literal filenames) | -- |
| `--selftest` | Execute internal algorithmic verification self-tests | -- |

### Security & Zip-Slip Protection

- **Path Traversal & Zip-Slip Protection**: Validates all extraction paths with `is_safe_relpath()`.
- **Nesting Depth Tracking**: Continuously tracks directory nesting depth; any attempt to ascend above the destination root via `../` (or `..\`) is intercepted and safely rejected with a security warning (`Security warning: skipping unsafe path traversal`).
- **Drive Identifier & Absolute Path Rejection**: Immediately rejects leading absolute slashes (`/`, `\`) and DOS drive identifiers (`C:`).
- **DOS Backslash Sanitization**: Automatically normalizes historical DOS backslashes (`DIR\SUBDIR\FILE.TXT`) to forward slashes `/` on POSIX systems, ensuring safe, seamless directory hierarchy recreation.

---

## Examples

### Creating Archives

```sh
# Compress files using default ALZ Normal mode (-m2)
./uharc a backup.uha document.pdf photo.raw

# Maximum compression with 4096 KB dictionary (ALZ Best, -m3)
./uharc a -m3 -md4096 archive.uha source_code/

# Fast archiving with Prediction by Partial Matching (PPM-II, -mx)
./uharc a -mx book.uha text.txt

# Fast archiving with Run-Length Encoding (-mr) or LZ78 (-mw)
./uharc a -mr quick.uha raw_stream.bin
./uharc a -mw -md32 lz78.uha source_files/

# Password-protected encrypted archive with encrypted headers
./uharc a -pwSecretKey42 -ph+ secure.uha secret_records.bin
```

### Listing & Testing Archives

```sh
# Standard table listing
./uharc l archive.uha

# Verbose technical listing with CRC-32 and compression ratios
./uharc v archive.uha

# Bare listing (one filename per line, ideal for scripts and piping)
./uharc l -1 archive.uha

# Unix-formatted listing (forward slashes, lowercase)
./uharc l -u archive.uha

# Combined bare Unix listing for shell processing
./uharc l -1 -u archive.uha | grep '\.c$'

# Test integrity of all files in archive
./uharc t archive.uha
```

### Extracting Archives

```sh
# Extract preserving directory structure (with automatic zip-slip protection)
./uharc x archive.uha -t/path/to/destination

# Extract flat into current directory
./uharc e archive.uha

# Extract and normalize paths to lowercase Unix relative paths
./uharc x -u archive.uha -t/path/to/destination

# Extract encrypted archive
./uharc x -pwSecretKey42 secure.uha
```

---

## Benchmarks & Performance

The `bench/` directory contains a self-contained benchmarking and bit-exactness verification suite (see [bench/README.md](bench/README.md), [bench/OPTIMIZATIONS.md](bench/OPTIMIZATIONS.md), and [bench/DECODER_OPTIMIZATIONS.md](bench/DECODER_OPTIMIZATIONS.md)):

- **Corpus & harnesses**: `make_corpus.sh`, `make_dec_corpus.sh`, `fetch_ext_corpus.sh` (Silesia 1 MiB slices, media, executables, and 103 native UHARC 0.4 archives), plus an in-process decoder harness (`dec_harness.c`).
- **Bit-exactness gates**: `verify.py` (encoder) and `dec_verify.py` (decoder across 400+ archives).
- **A/B timing & instruction counting**: `bench.py`, `dec_bench.py`, `dec_abpair.py` (interleaved paired runs with 95% bootstrap CIs), and `ircount.sh` / `dec_ircount.sh` (deterministic Callgrind instruction counts).

### Encoding Speed vs. Legacy `UHARC.EXE` 0.6b

Measured on 4 × 1 MiB diverse inputs (`dickens.1m`, `mozilla.1m`, `audio16.wav`, `ooffice.1m` — 4 MiB per mode, 20 MiB total, median of 3 runs). Comparing both Windows binaries under the same Wine environment provides an apples-to-apples baseline alongside the native Linux build:

| Mode | Legacy `UHARC.EXE` (Wine) | This build Win64 (Wine) | Win64 vs. Legacy | This build Linux (native) | Linux vs. Legacy |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`-m1`** (ALZ Fast) | 2.83 s | 2.57 s | **1.10x** | 1.99 s | **1.42x** |
| **`-m2`** (ALZ Normal) | 3.02 s | 2.77 s | **1.09x** | 2.02 s | **1.50x** |
| **`-m3`** (ALZ Best) | 3.07 s | 2.77 s | **1.11x** | 2.07 s | **1.49x** |
| **`-mz`** (LZP) | 1.12 s | 1.22 s | 0.92x | 0.66 s | **1.70x** |
| **`-mx`** (PPM-II) | 4.57 s | 4.24 s | **1.08x** | 3.67 s | **1.24x** |
| **Total (20 MiB)** | **14.61 s** | **13.57 s** | **1.08x** | **10.40 s** | **1.40x** |

*Note: Subsequent PPM prefetching added in `v0.6b.1` accelerates `-mx` encoding by an additional ~13% (~1.4x vs. legacy on native Linux). In decompression, SSE2 literal/escape models, hashed LZ78 tries, inlined range decoding, and PPM prefetching deliver 1.4x–6x speedups over the baseline C port across all 0.6b and 0.4 codecs (see [bench/DECODER_OPTIMIZATIONS.md](bench/DECODER_OPTIMIZATIONS.md)).*

---

## Project Structure

```text
uharc/
|-- build.sh                 # Unified build script (Linux native, Windows 64, packaging)
|-- build_deb.sh             # Debian package generator (.deb)
|-- build_dist.sh            # Complete release bundle generator (tar.gz, zip, deb, sha256)
|-- Makefile                 # Top-level GNU Makefile
|-- .gitignore               # Strict exclusion of build, local work, and temp files
|-- README.md                # Project documentation and CLI reference
|-- FORMAT.md                # Technical specification of UHARC 0.6b format and codecs
|-- src/                     # Pure C99 source code
|   |-- Makefile             # Internal C Makefile
|   |-- uharc.c              # Unified single CLI binary (a, m, x, e, l, v, t)
|   |-- uha.h / encode.h     # Public container, decode, and encode APIs
|   |-- decode.c / encode.c  # Core decompression and compression dispatchers
|   |-- container.c          # Header parsing, names & attributes blocks, CRC table
|   |-- crypto.c / crypto.h  # Stream cipher key schedule and keystream
|   |-- crc32.c / crc32.h    # IEEE 802.3 CRC-32 checksums
|   |-- rangecoder.c / .h    # 32-bit adaptive binary Range Coder
|   |-- alz*.c / alz*.h      # ALZ adaptive 2D matrix engine (-m1, -m2, -m3)
|   |-- ppm*.c / ppm*.h      # PPM-II Prediction by Partial Matching engine (-mx)
|   |-- lzp.c / lzp.h        # LZP predictive engine (-mz)
|   |-- filter.c / filter.h  # Executable x86 BCJ, multimedia delta & fax filters
|   |-- frontier.c / selclk.c # Multi-file frontier analysis and classification models
|   |-- uha02/               # Legacy UHARC 0.2 decoder (PPM/LZ core 3) + C99 facade
|   `-- uha04/               # Legacy UHARC 0.4 decoders (LZ78-LSB, LZP, PPM, ALZ) + C99 facade
|-- bench/                   # Benchmarking, Callgrind, and bit-exactness verification tools
|   |-- bench.py / dec_bench.py / dec_abpair.py  # A/B timing harnesses
|   |-- verify.py / dec_verify.py                # Bit-exactness verification gates
|   `-- OPTIMIZATIONS.md / DECODER_OPTIMIZATIONS.md
|-- corpus/
|   |-- input/               # 12 original reference input files
|   |-- archives/            # 89 reference archives (UHARC 0.6b)
|   |-- archives_02/         # 32 reference test archives (UHARC 0.2, all modes & filters)
|   `-- archives_04/         # 68 reference test archives (UHARC 0.4, all modes & filters)
|-- historical_bin/          # Original 1997-2005 Windows/DOS binaries by Uwe Herklotz
|   |-- UHARC.EXE / UHARCD.EXE / UNUHARC.EXE / UNUHARCD.EXE / UHARCSFX.EXE
|   `-- UHARC.DOC / LICENSE.DOC
|-- tests/                   # Automated compliance test suite
|   |-- test_all.py          # Decompress and MD5-verify all 89 reference archives (0.6b)
|   |-- test_02.py           # Integrity and extraction tests for UHARC 0.2 corpus
|   |-- test_04.py           # Integrity and extraction tests for UHARC 0.4 corpus
|   |-- test_roundtrip.py    # Multi-mode roundtrip compression test (24 cases)
|   |-- test_parity.py       # Mono-file bit-exact encoder parity vs corpus (72 cases)
|   `-- gen_input.py         # Ground-truth corpus input generator
`-- _work/                   # Local reverse-engineering scratch directory (ignored by Git)
```

---

## License & Credits

- Original UHARC algorithms and concepts Copyright (c) 1997-2005 by **Uwe Herklotz**.
- Reverse engineering and modern pure C99 reimplementation by **[seb3773](https://github.com/seb3773)**.
- Special thanks to **[roytam1](https://github.com/roytam1)** for the excellent reverse-engineering work on **[unuharc_recon](https://github.com/roytam1/unuharc_recon)**, which served as the foundation for integrating legacy UHARC 0.2 and 0.4 archive decompression support (with the 0.2 Core 3 decompressor integrated almost directly from unuharc_recon).
- Distributed for educational, interoperability, and digital preservation purposes under the terms of the MIT License.

