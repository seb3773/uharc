#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="${SCRIPT_DIR}/build/pkg_root"
VERSION="0.6.1-1"
ARCH="amd64"
DEB_NAME="uharc_${VERSION}_${ARCH}.deb"

echo "=== Building UHARC 0.6b from source ==="
cd "${SCRIPT_DIR}"
make clean
make -j"$(nproc)" all

echo "=== Running test suite before packaging ==="
make test

echo "=== Packaging DEB ==="
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/doc/uharc"
mkdir -p "${PKG_DIR}/DEBIAN"

# Install binary
if [ -f "${SCRIPT_DIR}/build/linux/uharc" ]; then
    cp -f "${SCRIPT_DIR}/build/linux/uharc" "${PKG_DIR}/usr/bin/uharc"
else
    cp -L -f "${SCRIPT_DIR}/uharc" "${PKG_DIR}/usr/bin/uharc"
fi
strip -s "${PKG_DIR}/usr/bin/uharc" || true
chmod 755 "${PKG_DIR}/usr/bin/uharc"

# Documentation
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/uharc/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT.md" "${PKG_DIR}/usr/share/doc/uharc/"
fi

# DEBIAN/control
cat << 'CTRL_EOF' > "${PKG_DIR}/DEBIAN/control"
Package: uharc
Version: 0.6.1-1
Section: utils
Priority: optional
Architecture: amd64
Maintainer: seb3773 <https://github.com/seb3773/uharc>
Depends: libc6 (>= 2.15)
Provides: uharc
Description: Modern freestanding C reimplementation of historical UHARC 0.6b archiver
 Complete, standalone freestanding C tool combining both compressor and
 decompressor into a single binary (uharc), achieving 100% bidirectional
 bit-exact compatibility with the original 32-bit archiver (UHARC.EXE).
 Features:
  - 6 compression modes: Store (M0), ALZ Fast (M1), ALZ Normal (M2), ALZ Best (M3), PPM-II (Mx), LZP (Mz)
  - Multimedia audio and image delta pre-filters (-mm)
  - High-order Prediction by Partial Matching with update exclusions
  - S-box keystream encryption for header and data payload (-pw, -ph)
  - Multi-file frontier permutation models and optimal scheduling
  - Pure C99 implementation with zero third-party dependencies
  - Historical digital preservation & software interoperability (EU 2009/24/EC)
CTRL_EOF

# Build DEB
mkdir -p "${SCRIPT_DIR}/dist"
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${SCRIPT_DIR}/dist/${DEB_NAME}"
cp -f "${SCRIPT_DIR}/dist/${DEB_NAME}" "${SCRIPT_DIR}/${DEB_NAME}"
echo "Package created: ${SCRIPT_DIR}/dist/${DEB_NAME} (and ${SCRIPT_DIR}/${DEB_NAME})"

# Clean temp packaging dir
rm -rf "${PKG_DIR}"

echo ""
echo "=== Package Information ==="
dpkg-deb -I "${SCRIPT_DIR}/dist/${DEB_NAME}"
echo ""
echo "=== Package Contents ==="
dpkg-deb -c "${SCRIPT_DIR}/dist/${DEB_NAME}"

echo ""
echo "=== UHARC packaging finished successfully ==="

