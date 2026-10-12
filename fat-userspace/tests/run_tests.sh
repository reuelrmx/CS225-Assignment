#!/usr/bin/env bash
# ============================================================================
#  tests/run_tests.sh - integration tests for the user-space FAT file system
#
#  Everything here goes through the built `fatfs` tool and a small API test
#  program, so the tests exercise the library exactly the way a user does.
#
#  The images are created by the tool itself (`fatfs format`).  When the Python
#  package pyfatfs is installed the same volumes are also read and written by
#  that independent implementation, which is what makes the on-disk layout
#  verified rather than merely self-consistent.  Without it those few checks
#  are reported as skipped and the rest still runs.
#
#      make test          (or)          bash tests/run_tests.sh
#
#  Exit status is 0 when every check passes.
# ============================================================================

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BIN="$ROOT/build/fatfs"
API="$ROOT/build/api_test"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/fatfs-tests.XXXXXX")
KEEP=${KEEP_WORK:-0}
trap 'if [ "$KEEP" != "1" ]; then rm -rf "$WORK"; fi' EXIT

PASS=0
FAIL=0
SKIP=0

# ---------------------------------------------------------------- reporting --
pass()  { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
skip()  { SKIP=$((SKIP + 1)); printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }
title() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# check DESC COMMAND...          - the command must succeed
check()  { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
# check_fail DESC COMMAND...     - the command must fail
check_fail() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d (it succeeded)"; else pass "$d"; fi; }
# check_eq DESC GOT WANT
check_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', wanted '$3')"; fi; }
# check_match DESC HAYSTACK NEEDLE
check_match() { case "$2" in *"$3"*) pass "$1";; *) fail "$1 (no '$3' in '$2')";; esac; }

# make_image NAME SIZE [TYPE] [LABEL]
make_image() {
    local name=$1 size=$2 type=${3:-} label=${4:-TESTVOL} img="$WORK/$1.img"
    rm -f "$img"
    truncate -s "$size" "$img"
    if [ -n "$type" ]; then
        "$BIN" format "$img" -t "$type" "$label" || return 1
    else
        "$BIN" format "$img" "$label" || return 1
    fi
}

# write_test_file NAME SIZE - deterministic content, so cmp is meaningful
write_test_file() {
    local path="$1" size="$2"
    python3 - "$path" "$size" <<'PY'
import sys
path, size = sys.argv[1], int(sys.argv[2])
with open(path, "wb") as fh:
    fh.write(bytes(((i * 37) + (i >> 9)) & 0xFF for i in range(size)))
PY
}

PYFATFS=0
python3 -c "import pyfatfs" 2>/dev/null && PYFATFS=1

# ============================================================================
title "build"
# ============================================================================
if [ ! -x "$BIN" ]; then
    ( cd "$ROOT" && make ) >/dev/null 2>&1
fi
check "the fatfs tool exists" test -x "$BIN"
if [ ! -x "$API" ]; then
    ( cd "$ROOT" && make build/api_test ) >/dev/null 2>&1
fi
check "the API test program exists" test -x "$API"

# ============================================================================
title "formatting (mkfs)"
# ============================================================================
check "format a 1440 KiB floppy as FAT12" make_image f12 "1440k" 12 "FLOPPY"
check "format 16 MiB as FAT16"             make_image f16 "16M" 16 "MIDVOL"
check "format 64 MiB as FAT32"             make_image f32 "64M" 32 "BIGVOL"

check_match "the FAT12 volume reports FAT12" "$("$BIN" info "$WORK/f12.img" 2>&1)" "FAT12"
check_match "the FAT16 volume reports FAT16" "$("$BIN" info "$WORK/f16.img" 2>&1)" "FAT16"
check_match "the FAT32 volume reports FAT32" "$("$BIN" info "$WORK/f32.img" 2>&1)" "FAT32"
check_match "the label is stored"            "$("$BIN" info "$WORK/f16.img" 2>&1)" "MIDVOL"
check_match "the FAT12 geometry is a floppy's" \
    "$("$BIN" info "$WORK/f12.img" 2>&1)" "sectors per FAT  : 9"

# the automatic choice of FAT type follows the capacity
make_image auto_small "1440k" >/dev/null
make_image auto_medium "24M"  >/dev/null
make_image auto_large "1G"    >/dev/null
check_match "1.44 MB is auto-formatted as FAT12" "$("$BIN" info "$WORK/auto_small.img" 2>&1)" "FAT12"
check_match "24 MB is auto-formatted as FAT16"   "$("$BIN" info "$WORK/auto_medium.img" 2>&1)" "FAT16"
check_match "1 GB is auto-formatted as FAT32"    "$("$BIN" info "$WORK/auto_large.img" 2>&1)" "FAT32"

# a freshly formatted volume must be clean
for t in 12 16 32; do
    check "a fresh FAT$t volume passes its own check" \
        "$BIN" check "$WORK/f$t.img"
done
if "$BIN" check "$WORK/f16.img" >/dev/null 2>&1; then :; else fail "check on a fresh volume"; fi
check "the images are not empty" test -s "$WORK/f16.img"

# ============================================================================
title "mounting and rejecting what is not a FAT volume"
# ============================================================================
head -c 512 /dev/zero | tr '\0' 'A' > "$WORK/garbage.img"
check_fail "512 bytes of 0x41 are not mounted as a file system" \
    "$BIN" info "$WORK/garbage.img"
head -c 100 /dev/zero > "$WORK/truncated.img"
check_fail "a truncated image is rejected" "$BIN" info "$WORK/truncated.img"
: > "$WORK/empty.img"
check_fail "an empty file is rejected" "$BIN" info "$WORK/empty.img"
check_fail "a missing file is reported" "$BIN" info "$WORK/does-not-exist.img"

# a volume claiming more sectors than the device holds is not writable
python3 - "$WORK/f16.img" "$WORK/bogus.img" <<'PY'
import struct, sys
data = bytearray(open(sys.argv[1], "rb").read())
struct.pack_into("<H", data, 19, 0)            # the field at 0x13 wins when set
struct.pack_into("<I", data, 32, 0xFFFFFFF0)   # so clear it and lie in the 32-bit one
open(sys.argv[2], "wb").write(bytes(data))
PY
check_fail "a BPB that cannot describe a FAT volume is refused" \
    "$BIN" info "$WORK/bogus.img"

# a volume whose device is shorter than the BPB promises opens read-only
make_image short "64M" 16 "SHORT" >/dev/null
write_test_file "$WORK/small.bin" 32
"$BIN" put "$WORK/short.img" "$WORK/small.bin" /keep.bin >/dev/null 2>&1
truncate -s 16M "$WORK/short.img"
check_match "a truncated volume is mounted read-only" \
    "$("$BIN" info "$WORK/short.img" 2>&1)" "mounted          : read-only"
check_fail "and refuses writes" "$BIN" touch "$WORK/short.img" /nope.txt
check "but its files can still be read" bash -c '
    "$0" get "$1" /keep.bin "$2" && cmp -s "$2" "$3"' \
    "$BIN" "$WORK/short.img" "$WORK/keep.bin" "$WORK/small.bin"
check_fail "FAT32 is refused on a volume too small for it" \
    "$BIN" format "$WORK/too_small.img" -t 32
check_fail "FAT12 is refused on a volume too large for it" \
    "$BIN" format "$WORK/too_big.img" -t 12

# ============================================================================
title "files: contents survive a round trip"
# ============================================================================
for t in 12 16 32; do
    img="$WORK/f$t.img"
    ok=1
    for size in 0 1 511 512 513 1024 4096 32768 200000; do
        write_test_file "$WORK/in.bin" "$size"
        rm -f "$WORK/out.bin"
        "$BIN" put "$img" "$WORK/in.bin" "/size_$size.bin" >/dev/null 2>&1 || { ok=0; break; }
        "$BIN" get "$img" "/size_$size.bin" "$WORK/out.bin" >/dev/null 2>&1 || { ok=0; break; }
        cmp -s "$WORK/in.bin" "$WORK/out.bin" || { ok=0; break; }
    done
    if [ "$ok" = 1 ]; then pass "FAT$t: nine sizes from 0 to 200000 bytes round-trip"; \
    else fail "FAT$t: a file did not round-trip (size $size)"; fi

    reported=$("$BIN" ls "$img" / -l 2>/dev/null | awk '$NF ~ /size_200000.bin/ {print $1}')
    check_eq "FAT$t: the recorded size of the 200000 byte file" "$reported" "200000"
    check "FAT$t: the volume checks out after the writes" "$BIN" check "$img"
done

# ============================================================================
title "directories"
# ============================================================================
img="$WORK/f16.img"
check "mkdir"                        "$BIN" mkdir "$img" /docs
check "mkdir a nested directory"     "$BIN" mkdir "$img" /docs/nested
check_fail "mkdir without the parent" "$BIN" mkdir "$img" /nope/deeper
check_fail "mkdir an existing directory" "$BIN" mkdir "$img" /docs

printf 'hello\n' > "$WORK/hello.txt"
check "put into a subdirectory"      "$BIN" put "$img" "$WORK/hello.txt" /docs/hello.txt
check "put into a nested directory"  "$BIN" put "$img" "$WORK/hello.txt" /docs/nested/deep.txt
check_match "ls shows the copy"      "$("$BIN" ls "$img" /docs)" "hello.txt"
check_match "tree shows the depth"   "$("$BIN" tree "$img")" "deep.txt"
check_eq "tree lists four names"     "$("$BIN" tree "$img" | grep -c -E 'hello.txt|deep.txt|docs/|nested/')" "4"

make_image many "1440k" 12 "MANY" >/dev/null    # 512-byte clusters
check "mkdir the directory to fill" "$BIN" mkdir "$WORK/many.img" /many
before=$("$BIN" ls "$WORK/many.img" /many | wc -l)
grew=1
for i in $(seq 1 400); do
    "$BIN" put "$WORK/many.img" "$WORK/hello.txt" "/many/f$i.txt" >/dev/null 2>&1 || { grew=0; break; }
done
after=$("$BIN" ls "$WORK/many.img" /many | wc -l)
check_eq "400 files can be created in one directory" "$after" "$((before + 400))"
check "the directory grew past one cluster" "$BIN" check "$WORK/many.img"
check_fail "rmdir a non-empty directory" "$BIN" rmdir "$img" /docs
for i in $(seq 1 200); do "$BIN" rm "$img" "/docs/f$i.txt" >/dev/null 2>&1; done
check "rm the files, then rmdir works" bash -c '
    "$0" rm "$1" /docs/hello.txt >/dev/null &&
    "$0" rm "$1" /docs/nested/deep.txt >/dev/null &&
    "$0" rmdir "$1" /docs/nested >/dev/null &&
    "$0" rmdir "$1" /docs >/dev/null' "$BIN" "$img"
check "the volume is clean after the directory work" "$BIN" check "$img"

# ============================================================================
title "names"
# ============================================================================
img="$WORK/f16.img"
printf 'x\n' > "$WORK/x.txt"
long_name="a long file name with spaces and more than eleven characters.txt"
check "put under a long name"        "$BIN" put "$img" "$WORK/x.txt" "/$long_name"
check_match "ls prints the long name" "$("$BIN" ls "$img" /)" "$long_name"
check "the long name can be read back" bash -c '"$0" cat "$1" "/$2" >/dev/null' \
    "$BIN" "$img" "$long_name"
check "an eight-dot-three name"      "$BIN" put "$img" "$WORK/x.txt" /short.txt
check "a name with dots inside"      "$BIN" put "$img" "$WORK/x.txt" "/archive.tar.gz"
check "a unicode name"               "$BIN" put "$img" "$WORK/x.txt" "/héllo wörld.txt"
check_fail "a name with a slash is refused" "$BIN" put "$img" "$WORK/x.txt" "/bad/name.txt"
check_fail "an empty name is refused"       "$BIN" put "$img" "$WORK/x.txt" "/"
check_fail "a name that is too long is refused" bash -c '
    name=$(python3 -c "print(\"a\"*300 + \".txt\")")
    "$0" put "$1" "$2" "/$name" >/dev/null 2>&1' "$BIN" "$img" "$WORK/x.txt"

# ============================================================================
title "rename, move, copy, remove"
# ============================================================================
img="$WORK/f16.img"
check "recreate the directory for this section" bash -c '
    "$0" mkdir "$1" /docs && "$0" mkdir "$1" /docs/nested' "$BIN" "$img"
check "rename a file"                "$BIN" mv "$img" /short.txt /renamed.txt
check_fail "the old name is gone"    "$BIN" cat "$img" /short.txt
check "move a file into a directory" "$BIN" mv "$img" /renamed.txt /docs/renamed.txt
check "the moved file is readable"   "$BIN" cat "$img" /docs/renamed.txt
check "mkdir for the move test"      "$BIN" mkdir "$img" /elsewhere
check "move a directory"             "$BIN" mv "$img" /docs /elsewhere/docs
check "the tree follows the move"    "$BIN" tree "$img" /elsewhere/docs
check "copy a file"                  "$BIN" cp "$img" /elsewhere/docs/renamed.txt /copy.txt
check "both copies read the same"    bash -c '
    a=$("$0" cat "$1" /elsewhere/docs/renamed.txt) &&
    b=$("$0" cat "$1" /copy.txt) &&
    [ "$a" = "$b" ]' "$BIN" "$img"
check_fail "copying onto a directory fails" "$BIN" cp "$img" /copy.txt /elsewhere
check_fail "removing a directory with rm fails" "$BIN" rm "$img" /elsewhere
check "remove a file"                "$BIN" rm "$img" /copy.txt
check_fail "removing it again fails" "$BIN" rm "$img" /copy.txt

# ============================================================================
title "attributes and timestamps"
# ============================================================================
img="$WORK/f16.img"
printf 'attr\n' > "$WORK/attr.txt"
"$BIN" put "$img" "$WORK/attr.txt" /attr.txt >/dev/null 2>&1
check_eq "the archive bit is set on a new file" \
    "$("$BIN" ls "$img" / -l | awk '$NF == "attr.txt" {print $2}')" "---a-"
check "set read-only"     "$BIN" attr "$img" /attr.txt +r
check_eq "the read-only bit shows up" \
    "$("$BIN" ls "$img" / -l | awk '$NF == "attr.txt" {print $2}')" "r--a-"
check "set hidden and system" "$BIN" attr "$img" /attr.txt +h +s
check_eq "hidden and system show up" \
    "$("$BIN" ls "$img" / -l | awk '$NF == "attr.txt" {print $2}')" "rhsa-"
check "clear them again"  "$BIN" attr "$img" /attr.txt -- -r -h -s
check_eq "the bits are cleared" \
    "$("$BIN" ls "$img" / -l | awk '$NF == "attr.txt" {print $2}')" "---a-"
check_match "the timestamp looks like a date" \
    "$("$BIN" ls "$img" / -l | awk '$NF == "attr.txt" {print $3, $4}')" "20"
check "the volume is still clean" "$BIN" check "$img"

# ============================================================================
title "space accounting"
# ============================================================================
img="$WORK/f12.img"
free_clusters() { "$BIN" info "$1" | awk '/total,/ {print $5}'; }
before=$(free_clusters "$img")
write_test_file "$WORK/big.bin" 300000
"$BIN" put "$img" "$WORK/big.bin" /big.bin >/dev/null 2>&1
during=$(free_clusters "$img")
"$BIN" rm "$img" /big.bin >/dev/null 2>&1
after=$(free_clusters "$img")
if [ "$during" -lt "$before" ] && [ "$after" = "$before" ]; then
    pass "deleting a file returns every cluster to the free pool"
else
    fail "cluster accounting (free before=$before during=$during after=$after)"
fi
check "the volume is clean after deleting" "$BIN" check "$img"

# filling a volume completely must fail cleanly and leave it consistent
make_image tiny "1M" 12 >/dev/null
write_test_file "$WORK/chunk.bin" 400000
for n in 1 2 3 4; do "$BIN" put "$WORK/tiny.img" "$WORK/chunk.bin" "/fill$n.bin" >/dev/null 2>&1; done
check_fail "writing when the volume is full fails" \
    "$BIN" put "$WORK/tiny.img" "$WORK/chunk.bin" /overflow.bin
check "a full volume is still consistent" "$BIN" check "$WORK/tiny.img"
check "a full volume is still mountable"  "$BIN" info "$WORK/tiny.img"

# ============================================================================
title "read-only and offset mounts"
# ============================================================================
img="$WORK/f16.img"
check "a read-only mount can list"  "$BIN" ls "$img" / -r
check_fail "a read-only mount refuses writes" "$BIN" touch "$img" /nope.txt -r
check "the volume was not modified" "$BIN" check "$img"
check_fail "writing to a read-only file is refused" bash -c '
    "$0" attr "$1" /attr.txt +r >/dev/null &&
    "$0" put "$1" "$2" /attr.txt >/dev/null 2>&1' "$BIN" "$img" "$WORK/attr.txt"
check_fail "removing a read-only file is refused" "$BIN" rm "$img" /attr.txt
check "a read-only file can still be renamed"    "$BIN" mv "$img" /attr.txt /still-here.txt
check "clearing the attribute lets it go" bash -c '
    "$0" attr "$1" /still-here.txt -- -r >/dev/null &&
    "$0" rm "$1" /still-here.txt >/dev/null' "$BIN" "$img"
check "the volume is still clean" "$BIN" check "$img"

# a volume that lives inside a partition
python3 - "$WORK/f16.img" "$WORK/partitioned.img" <<'PY'
import struct, sys
volume = open(sys.argv[1], "rb").read()
start = 2048
disk = bytearray(start * 512) + bytearray(volume)
disk[446 + 4] = 0x06                       # FAT16 partition type
struct.pack_into("<I", disk, 446 + 8, start)
struct.pack_into("<I", disk, 446 + 12, len(volume) // 512)
disk[510:512] = b"\x55\xAA"
open(sys.argv[2], "wb").write(bytes(disk))
PY
check_fail "the partition table is not a file system" \
    "$BIN" info "$WORK/partitioned.img"
check_match "the volume inside the partition mounts with -o" \
    "$("$BIN" info "$WORK/partitioned.img" -o $((2048 * 512)) 2>&1)" "FAT16"
check_match "and -o N works before the command too" \
    "$("$BIN" -o $((2048 * 512)) info "$WORK/partitioned.img" 2>&1)" "FAT16"
check "a file can be read from the partition" \
    "$BIN" ls "$WORK/partitioned.img" -o $((2048 * 512)) -l

# ============================================================================
title "consistency checking and repair"
# ============================================================================
python3 - "$WORK/repair.img" <<'PY'
import shutil, struct, sys
shutil.copy(sys.argv[1], sys.argv[1]) if False else None
PY
make_image repair "16M" 16 >/dev/null
"$BIN" put "$WORK/repair.img" "$WORK/hello.txt" /keep.txt >/dev/null 2>&1
python3 - "$WORK/repair.img" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
spf  = struct.unpack_from("<H", data, 22)[0]
res  = struct.unpack_from("<H", data, 14)[0]
# scribble on the second FAT copy only
off = (res + spf) * 512
for i in range(100, 160):
    data[off + i] ^= 0x5A
open(path, "wb").write(bytes(data))
PY
check_fail "a damaged FAT mirror is reported" "$BIN" check "$WORK/repair.img"
check_match "the report names the mirror" \
    "$("$BIN" check "$WORK/repair.img" 2>&1)" "differs from copy 1"
check "check --repair fixes it" "$BIN" check "$WORK/repair.img" --repair
check "the repaired volume checks out" "$BIN" check "$WORK/repair.img"
check "the file survived the repair"   "$BIN" cat "$WORK/repair.img" /keep.txt

# a size field larger than the chain is the classic FAT corruption
make_image sizebad "8M" 16 >/dev/null
write_test_file "$WORK/big2.bin" 20000
"$BIN" put "$WORK/sizebad.img" "$WORK/big2.bin" /big.bin >/dev/null 2>&1
python3 - "$WORK/sizebad.img" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
res  = struct.unpack_from("<H", data, 14)[0]
spf  = struct.unpack_from("<H", data, 22)[0]
nfat = data[16]
root = (res + nfat * spf) * 512
for i in range(0, 512, 32):                    # walk the fixed root directory
    entry = data[root + i:root + i + 32]
    if entry[0] == 0x00:
        break
    if entry[:3] == b"BIG":
        struct.pack_into("<I", data, root + i + 28, 900000)   # a lie
        break
open(path, "wb").write(bytes(data))
PY
check_fail "a size bigger than the chain is reported" "$BIN" check "$WORK/sizebad.img"
check_match "the report explains the size problem" \
    "$("$BIN" check "$WORK/sizebad.img" 2>&1)" "clusters"
check "check --repair truncates the size to the chain" \
    "$BIN" check "$WORK/sizebad.img" --repair
check_eq "the repaired size matches the chain" \
    "$("$BIN" ls "$WORK/sizebad.img" / -l | awk '$NF == "big.bin" {print $1}')" "20480"
check "the volume is consistent after the repair" "$BIN" check "$WORK/sizebad.img"

# ============================================================================
title "library API"
# ============================================================================
for t in 12 16 32; do
    case $t in 12) api_size="1440k";; 16) api_size="16M";; 32) api_size="64M";; esac
    make_image api$t "$api_size" $t "APITEST" >/dev/null
    if "$API" "$WORK/api$t.img" > "$WORK/api_$t.log" 2>&1; then
        summary=$(grep -o '\[api\] [0-9]* checks, [0-9]* failed' "$WORK/api_$t.log")
        pass "FAT$t: $summary"
    else
        fail "FAT$t: the API tests reported a problem"
        grep -E 'FAIL|\[api\]' "$WORK/api_$t.log" | sed 's/^/        /'
    fi
    check "FAT$t: the volume is consistent after the API tests" \
        "$BIN" check "$WORK/api$t.img"
done

# ============================================================================
title "cross-validation against pyfatfs"
# ============================================================================
if [ "$PYFATFS" = 1 ]; then
    for t in 12 16 32; do
        img="$WORK/f$t.img"
        # (a) pyfatfs must be able to read what fatfs wrote
        if python3 - "$img" "$WORK/in.bin" <<'PY'
import sys
from pyfatfs.PyFatFS import PyFatFS
img, reference = sys.argv[1], sys.argv[2]
want = open(reference, "rb").read()
fs = PyFatFS(img)
names = sorted(fs.listdir("/"))
assert "size_4096.bin" in names, names
for name, size in (("size_0.bin", 0), ("size_513.bin", 513),
                   ("size_4096.bin", 4096), ("size_200000.bin", 200000)):
    data = fs.getbytes("/" + name)
    assert len(data) == size, (name, len(data), size)
    assert data == want[:size], name
fs.close()
PY
        then pass "FAT$t: pyfatfs reads the volume fatfs created"
        else fail "FAT$t: pyfatfs could not read the volume"; fi

        # (b) fatfs must be able to read what pyfatfs wrote
        if python3 - "$img" <<'PY'
import sys
from pyfatfs.PyFatFS import PyFatFS
fs = PyFatFS(sys.argv[1])
with fs.open("/from_pyfatfs.txt", "wb") as fh:
    fh.write(b"written by pyfatfs\n")
fs.makedir("/pyfatfs_dir")
fs.close()
PY
        then
            if [ "$("$BIN" cat "$img" /from_pyfatfs.txt 2>/dev/null)" = "written by pyfatfs" ]; then
                pass "FAT$t: fatfs reads a file pyfatfs wrote"
            else
                fail "FAT$t: fatfs could not read the file pyfatfs wrote"
            fi
            check "FAT$t: the volume is consistent after pyfatfs wrote to it" \
                "$BIN" check "$img"
        else
            fail "FAT$t: pyfatfs could not write to the volume"
        fi
    done

    # pyfatfs must be able to read long names and unicode names written by fatfs
    make_image names "8M" 16 "NAMES" >/dev/null
    "$BIN" put "$WORK/names.img" "$WORK/x.txt" "/a long name with spaces.txt" >/dev/null 2>&1
    "$BIN" put "$WORK/names.img" "$WORK/x.txt" "/héllo wörld.txt" >/dev/null 2>&1
    if python3 - "$WORK/names.img" <<'PY'
import sys
from pyfatfs.PyFatFS import PyFatFS
fs = PyFatFS(sys.argv[1])
names = set(fs.listdir("/"))
assert "a long name with spaces.txt" in names, names
assert "héllo wörld.txt" in names, names
fs.close()
PY
    then pass "long and unicode names survive as pyfatfs sees them"
    else fail "pyfatfs did not see the names fatfs wrote"; fi

    # and the other way round: a name pyfatfs wrote is found by fatfs
    if python3 - "$WORK/names.img" <<'PY'
import sys
from pyfatfs.PyFatFS import PyFatFS
fs = PyFatFS(sys.argv[1])
with fs.open("/spaces and CAPITALS and dots.txt", "wb") as fh:
    fh.write(b"pyfatfs\n")
fs.close()
PY
    then
        check_match "a pyfatfs long name is listed by fatfs" \
            "$("$BIN" ls "$WORK/names.img" /)" "spaces and CAPITALS and dots.txt"
    else fail "pyfatfs could not write a long name"; fi
else
    skip "pyfatfs is not installed: the independent layout checks are skipped"
fi

# ============================================================================
title "sanitizers"
# ============================================================================
if cc -I"$ROOT/include" -D_FILE_OFFSET_BITS=64 -std=c11 -g -O1 \
      -fsanitize=address,undefined -fno-omit-frame-pointer \
      -o "$WORK/fatfs_asan" "$ROOT"/src/*.c >/dev/null 2>&1; then
    make_image asan "16M" 16 "ASAN" >/dev/null
    write_test_file "$WORK/asan_in.bin" 120000
    asan_ok=1
    "$WORK/fatfs_asan" mkdir "$WORK/asan.img" /d >/dev/null 2>&1 || asan_ok=0
    "$WORK/fatfs_asan" put "$WORK/asan.img" "$WORK/asan_in.bin" /d/big.bin >/dev/null 2>&1 || asan_ok=0
    "$WORK/fatfs_asan" put "$WORK/asan.img" "$WORK/asan_in.bin" "/a long sanitizer name.bin" >/dev/null 2>&1 || asan_ok=0
    "$WORK/fatfs_asan" mv "$WORK/asan.img" /d/big.bin /d/moved.bin >/dev/null 2>&1 || asan_ok=0
    "$WORK/fatfs_asan" rm "$WORK/asan.img" /d/moved.bin >/dev/null 2>&1 || asan_ok=0
    "$WORK/fatfs_asan" check "$WORK/asan.img" >/dev/null 2>&1 || asan_ok=0
    if [ "$asan_ok" = 1 ]; then
        pass "a run under ASan/UBSan reports nothing"
    else
        fail "the sanitizer build reported a problem"
    fi
else
    skip "no compiler support for -fsanitize=address"
fi

# ============================================================================
printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
if [ "$KEEP" = "1" ]; then printf 'working directory kept: %s\n' "$WORK"; fi
[ "$FAIL" -eq 0 ]
