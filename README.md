# uharc -- UHARC 0.6b Multimedia Archiver (Pure C99 Reimplementation)

Pure C99 standalone reimplementation of the legendary **UHARC 0.6b archiver** (1997-2005, by Uwe Herklotz).

> **Reverse Engineering & Legal Notice:** This work was conducted strictly for the purposes of software interoperability and digital data preservation (under European Directive 2009/24/EC) to reconstruct the proprietary compression algorithms, container format, and transformations of an obsolete 32-bit DOS/Windows archiver.

This repository provides a complete, self-contained C99 implementation (standard C library + `-lm`, zero external third-party dependencies) combining both **compressor** (`uharc a` / `uharc m`) and **decompressor** (`uharc x` / `uharc e`) into a single unified binary (`uharc`), designed for **bidirectional bit-exact compatibility** with the original historical Windows x86 binary (`UHARC.EXE` 0.6b).

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

---

## Highlights

- **Bidirectional Parity with Original `UHARC.EXE` 0.6b**:
  - **Decompression**: 100% bit-exact extraction verified across all **89** primary reference archives plus **4** extended solid multi-file archives (`corpus/archives/extra/`).
  - **Mono-File Encoding**: **72 / 72** bit-identical archives (`arc[39..]`, 0 byte diffs) across all 12 reference corpus files and all 6 modes (`-m0`, `-mz`, `-mx`, `-m1`, `-m2`, `-m3`), plus `-md*`, `-mm-`, `-p-`, `-pr`, and `-pw`/`-ph+`.
  - **Multi-File Solid Encoding**: `0` payload byte diffs for Store (`-m0`), LZP (`-mz`), and PPM-II (`-mx`).
- **Complete Feature Set**:
  - **All Compression Modes**: Store (`-m0`), ALZ Fast (`-m1`), ALZ Normal (`-m2`, default), ALZ Best (`-m3`), PPM-II (`-mx`), and LZP (`-mz`).
  - **Multimedia & Text Modeling**: Built-in ALZ in-stream adaptive side-channel prediction (`-mm+` / `-mm-`), PPM `detr` word transform and multimedia classes, plus x86 BCJ & LZP multimedia preprocessing transforms.
  - **Cryptographic Suite**: Stream cipher encryption for archive payload (`-pw<password>`) and metadata headers (`-ph+` default ON when `-pw` is set, `-ph-` to disable).
  - **Path Storage & Security**: Supports `-p-` (none), `-pr` (relative), and `-pf` (full) path storage on compress, paired with strict zip-slip traversal protection on extract.
  - **Configurable Dictionaries**: Scalable power-of-two sliding window dictionaries from `1 KB` up to `32768 KB` (`-md1` .. `-md32768`, default `-md4096`).
- **Compact & Self-Contained Builds**:
  - Pure standard C99 (`-lm`), compiling cleanly with zero warnings (`-O3 -flto` + stripped) to ~416 KB on native Linux (`build/linux/uharc`) and ~484 KB statically linked on Windows 64-bit via MinGW-w64 (`build/win64/uharc.exe`).
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
| **Built-In Self-Tests** | `./uharc --selftest` (CRC-32 vector, header parser, zip-slip check) | **3 / 3** | **PASS** |
| **Reference Corpus Decompression** | `tests/test_all.py` across `corpus/archives/*.uha` (+ 4 `extra/*.uha`) | **89 / 89** (+4) | **100% MD5 PASS** |
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
| `-m<0,1,2,3,x,z>` | Compression mode: `0`=Store, `1`=ALZ Fast, `2`=ALZ Normal, `3`=ALZ Best, `x`=PPM-II, `z`=LZP | `-m2` |
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
|   |-- filter.c / filter.h  # Executable x86 BCJ & multimedia delta filters
|   `-- frontier.c / selclk.c # Multi-file frontier analysis and classification models
|-- corpus/
|   |-- input/               # 12 original reference input files
|   `-- archives/            # 89 reference archives (+ 4 solid -mx archives in extra/)
|-- historical_bin/          # Original 1997-2005 Windows/DOS binaries by Uwe Herklotz
|   |-- UHARC.EXE / UHARCD.EXE / UNUHARC.EXE / UNUHARCD.EXE / UHARCSFX.EXE
|   `-- UHARC.DOC / LICENSE.DOC
|-- tests/                   # Automated compliance test suite
|   |-- test_all.py          # Decompress and MD5-verify all 89 reference archives
|   |-- test_roundtrip.py    # Multi-mode roundtrip compression test (24 cases)
|   |-- test_parity.py       # Mono-file bit-exact encoder parity vs corpus (72 cases)
|   `-- gen_input.py         # Ground-truth corpus input generator
`-- _work/                   # Local reverse-engineering scratch directory (ignored by Git)
```

---

## License & Credits

- Original UHARC algorithms and concepts Copyright (c) 1997-2005 by **Uwe Herklotz**.
- Reverse engineering and modern pure C99 reimplementation by **[seb3773](https://github.com/seb3773)**.
- Distributed for educational, interoperability, and digital preservation purposes under the terms of the MIT License.

