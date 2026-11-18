CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -O3 -flto=auto -fuse-linker-plugin -fomit-frame-pointer -fno-math-errno -fno-trapping-math -fno-semantic-interposition -fmerge-all-constants -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -ffunction-sections -fdata-sections -fno-strict-aliasing -DNDEBUG -Isrc -Isrc/uha04
WIN64_CFLAGS ?= -std=c99 -Wall -Wextra -O3 -flto=auto -fuse-linker-plugin -fomit-frame-pointer -fno-math-errno -fno-trapping-math -fmerge-all-constants -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -ffunction-sections -fno-strict-aliasing -DNDEBUG -Isrc -Isrc/uha04
LDFLAGS ?= -flto=auto -fuse-linker-plugin -Wl,--gc-sections -Wl,-O1 -Wl,--as-needed -Wl,--exclude-libs,ALL -s -lm
WIN64_LDFLAGS ?= -static -flto=auto -fuse-linker-plugin -Wl,--gc-sections -Wl,-O1 -Wl,--exclude-all-symbols -s -lm
STRIP_LINUX ?= strip --strip-all
BUILD_DIR ?= build
LINUX_DIR = $(BUILD_DIR)/linux
WIN64_DIR = $(BUILD_DIR)/win64

TARGET_LINUX = $(LINUX_DIR)/uharc
TARGET_WIN64 = $(WIN64_DIR)/uharc.exe
TARGET = $(TARGET_LINUX)

CROSS_WIN64_CC ?= x86_64-w64-mingw32-gcc

PREFIX ?= /usr/local
DESTDIR ?=

SRC_FILES = $(wildcard src/*.c src/uha04/*.c)
SRC_HEADERS = $(wildcard src/*.h src/*.inc src/uha04/*.h)

# Cold CLI/container/helper translation units compiled with -Os (codecs stay at -O3)
COLD_SRCS = src/uharc.c src/container.c src/wildcard.c src/crypto.c \
            src/filter.c src/rle.c src/selclk.c src/frontier.c
HOT_SRCS  = $(filter-out $(COLD_SRCS),$(SRC_FILES))

COLD_CFLAGS       = $(subst -O3,-Os,$(CFLAGS))
WIN64_COLD_CFLAGS = $(subst -O3,-Os,$(WIN64_CFLAGS))

LINUX_OBJ_DIR = $(LINUX_DIR)/obj
WIN64_OBJ_DIR = $(WIN64_DIR)/obj

LINUX_HOT_OBJS  = $(patsubst %.c,$(LINUX_OBJ_DIR)/%.o,$(HOT_SRCS))
LINUX_COLD_OBJS = $(patsubst %.c,$(LINUX_OBJ_DIR)/%.o,$(COLD_SRCS))
LINUX_OBJS      = $(LINUX_HOT_OBJS) $(LINUX_COLD_OBJS)

WIN64_HOT_OBJS  = $(patsubst %.c,$(WIN64_OBJ_DIR)/%.o,$(HOT_SRCS))
WIN64_COLD_OBJS = $(patsubst %.c,$(WIN64_OBJ_DIR)/%.o,$(COLD_SRCS))
WIN64_OBJS      = $(WIN64_HOT_OBJS) $(WIN64_COLD_OBJS)

HAVE_WIN64 := $(shell command -v $(CROSS_WIN64_CC) 2>/dev/null)

.PHONY: all linux win64 all-platforms clean install uninstall deb dist test asan help debug

all: linux

linux: $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc

asan: CFLAGS = -std=c99 -Wall -Wextra -O2 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-strict-aliasing -Isrc -Isrc/uha04
asan: LDFLAGS = -fsanitize=address,undefined -lm
asan: STRIP_LINUX = true
asan: clean $(TARGET_LINUX)
	@ln -sf build/linux/uharc uharc
	@echo "Built AddressSanitizer/UBSan instrumented binary (uharc)"

win64: $(TARGET_WIN64)

all-platforms: linux win64

$(LINUX_DIR):
	mkdir -p $(LINUX_DIR)

$(WIN64_DIR):
	mkdir -p $(WIN64_DIR)

$(LINUX_HOT_OBJS): $(LINUX_OBJ_DIR)/%.o: %.c $(SRC_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

$(LINUX_COLD_OBJS): $(LINUX_OBJ_DIR)/%.o: %.c $(SRC_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(COLD_CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

$(TARGET_LINUX): $(LINUX_OBJS) | $(LINUX_DIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LINUX_OBJS) -o $@ $(LDFLAGS)
	@$(STRIP_LINUX) $@ 2>/dev/null || true
	@ln -sf linux/uharc $(BUILD_DIR)/uharc
	@ln -sf build/linux/uharc uharc

ifneq ($(HAVE_WIN64),)
$(WIN64_HOT_OBJS): $(WIN64_OBJ_DIR)/%.o: %.c $(SRC_HEADERS)
	@mkdir -p $(dir $@)
	@$(CROSS_WIN64_CC) $(WIN64_CFLAGS) -c $< -o $@

$(WIN64_COLD_OBJS): $(WIN64_OBJ_DIR)/%.o: %.c $(SRC_HEADERS)
	@mkdir -p $(dir $@)
	@$(CROSS_WIN64_CC) $(WIN64_COLD_CFLAGS) -c $< -o $@

$(TARGET_WIN64): $(WIN64_OBJS) | $(WIN64_DIR)
	@$(CROSS_WIN64_CC) $(WIN64_CFLAGS) $(WIN64_OBJS) -o $@ $(WIN64_LDFLAGS)
	@x86_64-w64-mingw32-strip --strip-all $@ 2>/dev/null || true
	@echo "Windows 64-bit binary built: $@"
else
$(TARGET_WIN64): | $(WIN64_DIR)
	@echo "WARNING: $(CROSS_WIN64_CC) not found, skipping win64 target."
	@echo "Install with: sudo apt install gcc-mingw-w64-x86-64"
endif

debug: CFLAGS = -std=c99 -Wall -Wextra -g -O0 -Isrc -Isrc/uha04
debug: LDFLAGS = -lm
debug: STRIP_LINUX = true
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

