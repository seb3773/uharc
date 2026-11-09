CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -O3 -flto -fomit-frame-pointer -fno-strict-aliasing -ffunction-sections -fdata-sections -DNDEBUG -Isrc
WIN64_CFLAGS ?= -std=c99 -Wall -Wextra -O3 -flto -fomit-frame-pointer -fno-strict-aliasing -ffunction-sections -DNDEBUG -Isrc
LDFLAGS ?= -Wl,--gc-sections -s -lm
BUILD_DIR ?= build
LINUX_DIR = $(BUILD_DIR)/linux
WIN64_DIR = $(BUILD_DIR)/win64

TARGET_LINUX = $(LINUX_DIR)/uharc
TARGET_WIN64 = $(WIN64_DIR)/uharc.exe
TARGET = $(TARGET_LINUX)

CROSS_WIN64_CC ?= x86_64-w64-mingw32-gcc

PREFIX ?= /usr/local
DESTDIR ?=

SRC_FILES = $(wildcard src/*.c)
SRC_HEADERS = $(wildcard src/*.h src/*.inc)

.PHONY: all linux win64 all-platforms clean install uninstall deb dist test asan help debug

all: linux

linux: $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc

asan: CFLAGS = -std=c99 -Wall -Wextra -O2 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Isrc
asan: clean $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc
	@echo "Built AddressSanitizer/UBSan instrumented binary (uharc)"

win64: $(TARGET_WIN64)

all-platforms: linux win64

$(LINUX_DIR):
	mkdir -p $(LINUX_DIR)

$(WIN64_DIR):
	mkdir -p $(WIN64_DIR)

$(TARGET_LINUX): $(SRC_FILES) $(SRC_HEADERS) | $(LINUX_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LDFLAGS)
	@strip -s $@ 2>/dev/null || true
	@ln -sf linux/uharc $(BUILD_DIR)/uharc
	@ln -sf build/linux/uharc uharc

$(TARGET_WIN64): $(SRC_FILES) $(SRC_HEADERS) | $(WIN64_DIR)
	@if which $(CROSS_WIN64_CC) >/dev/null 2>&1; then \
		$(CROSS_WIN64_CC) $(WIN64_CFLAGS) -static -o $@ $(SRC_FILES) $(LDFLAGS); \
		x86_64-w64-mingw32-strip -s $@ 2>/dev/null || true; \
		echo "Windows 64-bit binary built: $@"; \
	else \
		echo "WARNING: $(CROSS_WIN64_CC) not found, skipping win64 target."; \
		echo "Install with: sudo apt install gcc-mingw-w64-x86-64"; \
	fi

debug: CFLAGS = -std=c99 -Wall -Wextra -g -O0 -Isrc
debug: clean $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc

test: $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc
	@echo "=== Running internal self-tests ==="
	./$(TARGET_LINUX) --selftest
	@echo "=== Running decompression and integrity test on reference corpus ==="
	python3 tests/test_all.py ./$(TARGET_LINUX)
	@echo "=== Running round-trip compression test suite ==="
	python3 tests/test_roundtrip.py ./$(TARGET_LINUX)
	@echo "All tests passed successfully."

deb:
	@chmod +x build_deb.sh
	./build_deb.sh

dist:
	@chmod +x build_dist.sh
	./build_dist.sh

clean:
	rm -rf $(BUILD_DIR) uharc dist *.deb src/*.o src/uharc

install: $(TARGET_LINUX)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET_LINUX) $(DESTDIR)$(PREFIX)/bin/uharc

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/uharc

help:
	@echo "Available build targets:"
	@echo "  make linux         - Build native Linux binary (default)"
	@echo "  make win64         - Cross-compile static Windows 64-bit binary (MinGW)"
	@echo "  make all-platforms - Build both Linux and Windows 64-bit binaries"
	@echo "  make debug         - Build Linux binary with debug symbols (-g -O0)"
	@echo "  make asan          - Build with AddressSanitizer and UndefinedBehaviorSanitizer"
	@echo "  make test          - Run self-test and reference corpus verification"
	@echo "  make deb           - Build standalone Debian .deb package"
	@echo "  make dist          - Build full release distribution (tar.gz, zip, deb)"
	@echo "  make install       - Install uharc to $(DESTDIR)$(PREFIX)/bin"
	@echo "  make uninstall     - Remove uharc from $(DESTDIR)$(PREFIX)/bin"
	@echo "  make clean         - Remove build artifacts"

