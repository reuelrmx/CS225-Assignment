# ============================================================================
#  CS225 - user-space FAT file system
#
#  Targets
#  -------
#    make            build the library and the `fatfs` CLI into build/
#    make test       build, then run the integration test suite
#    make check      alias for `make test`
#    make clean      remove build output
#    make windows    cross-compile with MinGW if it is installed
#
#  Everything lands in build/ so the source tree stays clean.
# ============================================================================

CC      ?= cc
BUILD   := build

CPPFLAGS += -Iinclude -D_FILE_OFFSET_BITS=64
CFLAGS   += -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
            -Wno-sign-conversion -Wstrict-prototypes -Wmissing-prototypes
LDFLAGS  +=

SRC      := $(filter-out src/main.c,$(wildcard src/*.c))
OBJ      := $(SRC:src/%.c=$(BUILD)/%.o)
DEP      := $(OBJ:.o=.d) $(BUILD)/main.d

# Header dependencies are tracked, so editing an include/ header rebuilds
# every object that needs it.  Without this a changed structure layout leaves
# stale objects that disagree about it, which fails in confusing ways at run
# time (a mismatched struct size corrupts the heap).
CPPFLAGS += -MMD -MP

LIB      := $(BUILD)/libfatfs.a
BIN      := $(BUILD)/fatfs
API      := $(BUILD)/api_test

# Raw-device access on Windows needs no extra library beyond the Win32 API.
ifeq ($(OS),Windows_NT)
  BIN := $(BUILD)/fatfs.exe
endif

.PHONY: all test check clean windows

all: $(BIN)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJ)
	@rm -f $@
	ar rcs $@ $(OBJ)

$(BUILD)/main.o: src/main.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN): $(BUILD)/main.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test check: $(BIN) $(API)
	@bash tests/run_tests.sh

# The API tests link against the library and need the same flags as the tool.
$(API): tests/api_test.c $(LIB) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

# Cross-compile a self-contained Windows binary (needs mingw-w64 installed).
windows:
	@mkdir -p $(BUILD)/win
	i686-w64-mingw32-gcc -Iinclude -std=c11 -O2 -Wall -Wextra \
	    src/*.c -o $(BUILD)/win/fatfs.exe

clean:
	@rm -rf $(BUILD)

-include $(DEP)
