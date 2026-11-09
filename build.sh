#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="release"
TARGET_PLATFORM="linux"
MAKE_ARGS=()

for arg in "$@"; do
    case "$arg" in
        win64|win|windows|--win64)
            TARGET_PLATFORM="win64"
            ;;
        linux|--linux)
            TARGET_PLATFORM="linux"
            ;;
        all|all-platforms|--all)
            TARGET_PLATFORM="all-platforms"
            ;;
        asan|--asan)
            MODE="asan"
            ;;
        debug|-DEBUG|--debug|DEBUG=1)
            MODE="debug"
            ;;
        clean)
            make clean
            exit 0
            ;;
        test)
            make test
            exit 0
            ;;
        deb)
            make deb
            exit 0
            ;;
        dist)
            make dist
            exit 0
            ;;
        help|-h|--help)
            make help
            exit 0
            ;;
        *)
            MAKE_ARGS+=("$arg")
            ;;
    esac
done

echo "=========================================================="
if [ "$MODE" = "debug" ]; then
    echo "  Building UHARC 0.6b (DEBUG mode: $TARGET_PLATFORM)"
else
    echo "  Building UHARC 0.6b (Target: $TARGET_PLATFORM)"
fi
echo "=========================================================="

if [ "$MODE" = "debug" ]; then
    make debug
elif [ "$MODE" = "asan" ]; then
    make asan
else
    make clean >/dev/null 2>&1 || true
    make -j"$(nproc)" "$TARGET_PLATFORM" "${MAKE_ARGS[@]}"
fi

echo ""
echo "=== Summary of Generated Binaries ==="
if [ -f "$SCRIPT_DIR/build/linux/uharc" ]; then
    ls -lh "$SCRIPT_DIR/build/linux/uharc"
fi
if [ -f "$SCRIPT_DIR/build/win64/uharc.exe" ]; then
    ls -lh "$SCRIPT_DIR/build/win64/uharc.exe"
fi
echo "Done."

