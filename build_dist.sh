#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

VERSION="0.6b"
DEB_VERSION="0.6.1-1"
DIST_DIR="${SCRIPT_DIR}/dist"
STAGE_DIR="${SCRIPT_DIR}/build/dist_stage"

TAR_NAME="uharc-v${VERSION}-linux-x86_64.tar.gz"
ZIP_NAME="uharc-v${VERSION}-windows-x86_64.zip"
DEB_NAME="uharc_${DEB_VERSION}_amd64.deb"

echo "=========================================================="
echo "  Building UHARC ${VERSION} Distribution Packages"
echo "=========================================================="

mkdir -p "${DIST_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

echo "=== Building Debian Package ==="
chmod +x ./build_deb.sh
./build_deb.sh

echo "=== Building Windows 64-bit Binary ==="
make win64 || true

echo "=== Packaging Linux Tarball (${TAR_NAME}) ==="
mkdir -p "${STAGE_DIR}/linux"
cp -f "${SCRIPT_DIR}/build/linux/uharc" "${STAGE_DIR}/linux/uharc"
strip -s "${STAGE_DIR}/linux/uharc" || true
chmod 755 "${STAGE_DIR}/linux/uharc"
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp -f "${SCRIPT_DIR}/README.md" "${STAGE_DIR}/linux/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT.md" ]; then
    cp -f "${SCRIPT_DIR}/FORMAT.md" "${STAGE_DIR}/linux/"
fi

tar -czf "${DIST_DIR}/${TAR_NAME}" -C "${STAGE_DIR}/linux" uharc $([ -f "${SCRIPT_DIR}/README.md" ] && echo "README.md") $([ -f "${SCRIPT_DIR}/FORMAT.md" ] && echo "FORMAT.md")

if [ -f "${SCRIPT_DIR}/build/win64/uharc.exe" ]; then
    echo "=== Packaging Windows Zip (${ZIP_NAME}) ==="
    mkdir -p "${STAGE_DIR}/windows"
    cp -f "${SCRIPT_DIR}/build/win64/uharc.exe" "${STAGE_DIR}/windows/uharc.exe"
    x86_64-w64-mingw32-strip -s "${STAGE_DIR}/windows/uharc.exe" 2>/dev/null || true
    chmod 755 "${STAGE_DIR}/windows/uharc.exe"
    if [ -f "${SCRIPT_DIR}/README.md" ]; then
        cp -f "${SCRIPT_DIR}/README.md" "${STAGE_DIR}/windows/"
    fi
    if [ -f "${SCRIPT_DIR}/FORMAT.md" ]; then
        cp -f "${SCRIPT_DIR}/FORMAT.md" "${STAGE_DIR}/windows/"
    fi

    (cd "${STAGE_DIR}/windows" && zip -9 "${DIST_DIR}/${ZIP_NAME}" uharc.exe $([ -f "${SCRIPT_DIR}/README.md" ] && echo "README.md") $([ -f "${SCRIPT_DIR}/FORMAT.md" ] && echo "FORMAT.md"))
fi

rm -rf "${STAGE_DIR}"

echo "=== Computing SHA-256 Checksums ==="
cd "${DIST_DIR}"
rm -f sha256sums.txt
for f in *; do
    if [ -f "$f" ] && [ "$f" != "sha256sums.txt" ] && [ "$f" != "release_notes.md" ]; then
        sha256sum "$f" >> sha256sums.txt
    fi
done
cat sha256sums.txt

echo "=== Generating Release Notes ==="
cat << EOF > "${DIST_DIR}/release_notes.md"
## UHARC 0.6b - Freestanding C Reimplementation

Pure freestanding C reimplementation of historical UHARC 0.6b archiver (Uwe Herklotz, 1997-2005).

- **100% Bit-Exact Compatibility**: Bit-exact decompression and re-compression matching original 32-bit reference archives across all compression modes (Store, ALZ Fast/Normal/Best, PPM-II, LZP).
- **All Algorithmic Families**: ALZ adaptive 2D matrix matching, order-4 Prediction by Partial Matching (PPM-II) with update exclusions, LZP predictive coding, multimedia audio/image filters (-mm).
- **Cryptographic Keystreams**: Header and payload encryption with S-box scrambling (-pw, -ph).
- **Multi-File Permutation Frontier**: Complete autonomous ordering and scheduling model for multi-file archives.
- **Path Traversal & Zip-Slip Protection**: Safe extraction verifying all paths with \`is_safe_relpath()\` to reject directory traversal and absolute paths.
- **Modern CLI Additions**: \`-u, --unix\` (format paths as Unix relative paths, lowercase) and \`-1, --bare\` (bare listing for scripts, xargs, grep).
- **Standalone Single Tool**: Unified \`uharc\` command-line interface supporting add (\`a\`), move (\`m\`), extract (\`x\`), flat extract (\`e\`), list (\`l\`), verbose list (\`v\`), and test (\`t\`).

### Release Assets

- \`${TAR_NAME}\` : Standalone 64-bit Linux binary (\`uharc\`) + documentation
- \`${DEB_NAME}\` : Debian / Ubuntu installer package (amd64)
EOF

if [ -f "${ZIP_NAME}" ]; then
    echo "- \`${ZIP_NAME}\` : Standalone 64-bit Windows static binary (\`uharc.exe\`) + documentation" >> "${DIST_DIR}/release_notes.md"
fi

cat << EOF >> "${DIST_DIR}/release_notes.md"

### SHA-256 Checksums

\`\`\`
$(cat "${DIST_DIR}/sha256sums.txt")
\`\`\`
EOF

echo ""
echo "=== Distribution Assets Summary ==="
ls -lh "${DIST_DIR}"
echo "=========================================================="
echo "Distribution packaging completed successfully!"

