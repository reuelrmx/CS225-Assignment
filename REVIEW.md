# Code Review — `fat-userspace` (CS225 FAT file system)

Review of `main` @ `27075c7` ("Update fat_fs.h"). Scope: the entire repository (9 tracked files, ~1,950 lines).
Method: full read of every file, compile/link analysis with GCC + `-Wall -Wextra`, symbol analysis, and an
execution harness that links the repo's real `src/main.c` against a hand-built FAT16 image. All findings below
are reproduced, not inferred — see [Appendix A](#appendix-a--reproducing-the-findings).

---

## 1. Verdict

**This is not a file system (yet).** It is three mutually incompatible drafts of FAT primitives that
(a) do not compile as committed, (b) cannot be linked together even if they did, and (c) do not implement
the API they advertise. The only entry point is `int main() { return 0; }`.

The most useful framing is: `src/fat.c` is the closest thing to a real design, `src/main.c` contains the
most *actual algorithm work* (correct FAT12/16/32 entry math, real path parsing helpers), and `src/fat_fs.c`
is a pure skeleton of stubs — but they are three separate answers to the same problem, all using the same
function names, and nothing sits on top of any of them. There is no mount state, no path resolution, no
directory-tree traversal, and no CLI.

| Area | Status |
|---|---|
| Compiles as committed | ❌ hard errors in `fat.c` and `main.c` |
| Links into one binary | ❌ 15 duplicate symbols, 14 undefined functions |
| Implements the documented API (`fat_*`) | ❌ 16 of 17 declared functions have no definition |
| Reads a file correctly | ❌ returns boot-sector bytes (proven, §4.1) |
| Locates file data correctly | ❌ cluster→sector math off by 34 sectors on FAT16 (proven, §4.2) |
| Writes a file correctly | ❌ writes at file offset 0 → overwrites the volume boot record |
| Directory entry management | ❌ three independent bugs; new entries are never inserted, deletes never match |
| Boot sector validation | ❌ accepts arbitrary bytes as a "FAT16 filesystem" (proven, §4.3) |
| Build system | ❌ `makefile.mk` is empty (1 blank line) |
| Tests | ❌ none |
| Documentation matches code | ❌ README claims a working system incl. "FUSE" |

---

## 2. What is actually in the repo

```
README.md                       31 lines   promises mount/open/read/write/mkdir/rename/copy/attrs + FUSE
.gitattributes                  2 lines    text=auto
fat-userspace/makefile.mk       1 line     empty
fat-userspace/include/fat.h            113  BPB, DirEntry, FATEntry, prototypes (Windows-only)
fat-userspace/include/fat_fs.h          98  dir_entry_t, file_desc_t, 17 `fat_*` prototypes
fat-userspace/include/fat_util.h        64  SECTOR_SIZE, FAT types, sector I/O prototypes
fat-userspace/src/fat.c                575  draft A
fat-userspace/src/main.c               861  draft B (+ all the real logic + all the missing calls)
fat-userspace/src/fat_fs.c             207  draft C (stubs)
```

Git history is a single squashed commit, so there is no incremental story to review — this is a snapshot.

**Draft A (`fat.c`)** — lowest-level, `FILE*`/`fopen` for init then Win32 `HANDLE` everywhere else.
Assumes the root directory lives at cluster 2 for every FAT flavour, and its own
`cluster_to_sector()` omits the FAT *and* root-directory regions entirely.

**Draft B (`main.c`)** — redefines everything in draft A, adds a correct textbook FAT12/16/32
`read_fat_entry`/`write_fat_entry`, correct-ish path splitting, and then calls 14 helper functions
(`find_free_cluster`, `get_next_cluster`, `init_cluster_chain`, `update_directory_entry`, …) that exist
nowhere in the repository. This file is where the intent of the project lives.

**Draft C (`fat_fs.c`)** — a stub skeleton whose two `static` helpers (`find_empty_dir_entry`,
`locate_file`) `return FAT_SUCCESS` without doing anything, so every function above them operates on
uninitialised/zeroed data and reports success.

The headers describe a *fourth* design: `fat_fs.h` declares a clean `fat_mount` / `fat_open` / `fat_read`
/ `fat_lseek` / `fat_getattr` API around a `file_desc_t` with a `file_handle` — none of which exists in
any `.c` file. Two competing on-disk directory-entry structs (`DirEntry` in `fat.h`, `dir_entry_t` in
`fat_fs.h`) describe the same 32 bytes with different member names.

---

## 3. It does not build, and it cannot link

### 3.1 Compile-time hard errors (as committed)

`fat.c:2` includes `"FAT.h"`; the file on disk is `fat.h`. Case-insensitive filesystems (Windows) hide
this; anything else fails immediately:

```
src/fat.c:2:10: fatal error: FAT.h: No such file or directory
```

With that one include corrected, GCC still stops on real errors:

| File:line | Error |
|---|---|
| `main.c:327` | `'bytesWritten' undeclared` — `create_file()` writes a directory sector through a variable that was never declared |
| `main.c:470,471,501` | `assignment of member ... in read-only object` — `write_file()` takes `const DirEntry *entry` and then assigns `entry->first_cluster_high/low` and `entry->file_size` |
| `main.c:626` | `'DIR_ENTRY_FREE' undeclared`, `'DIR_ENTRY_DELETED' undeclared` |
| `main.c:659` | `'MAX_PATH_LENGTH' undeclared` |
| `main.c:723` | `'MAX_DIRECTORY_ENTRIES' undeclared` |
| `fat.c:348` | `'DirEntry' has no member named 'entry_sector'` — `write_file()` reads `entry->entry_sector`, a field that no implementation of `DirEntry` has |

Missing includes add ~30 more implicit-declaration diagnostics (`strrchr`, `strncpy`, `strncmp`,
`memset`, `memcpy`, `strcmp` in `main.c`; `malloc`/`free` in `fat.c`). Note `fat.c` uses `malloc` with no
`<stdlib.h>`: under a C89-era implicit-int declaration that truncates the pointer to 32 bits on x64 —
a crash, not a warning, in the very first call.

`fat_fs.c` has the opposite problem: it uses `__attribute__((packed))` and a variable-length array
(`uint8_t buffer[sector_size]` in `main.c:618`), both of which are GCC extensions. In an MSVC
toolchain — the toolchain the README implies with `windows.h` — these are errors.

### 3.2 Link-time: 15 colliding symbols, 14 missing functions

Every FAT primitive is defined in two or three translation units with identical names:

```
cluster_to_sector   -> main.c, fat.c          read_fat_entry   -> main.c, fat.c
sector_to_cluster   -> main.c, fat.c          write_fat_entry  -> main.c, fat.c
init_fat            -> main.c, fat.c          copy_file        -> main.c, fat_fs.c
create_file         -> main.c, fat.c, fat_fs.c    rename_file   -> main.c, fat_fs.c
delete_file         -> main.c, fat.c, fat_fs.c    move_file     -> main.c, fat_fs.c
read_file           -> main.c, fat.c, fat_fs.c
write_file          -> main.c, fat.c, fat_fs.c
read_directory      -> main.c, fat.c, fat_fs.c
create_directory    -> main.c, fat.c, fat_fs.c
delete_directory    -> main.c, fat.c, fat_fs.c
```

All 15 are external symbols with no `static` and no namespacing, so linking all three objects fails with
"multiple definition". Independently, `main.c` calls 14 functions that are *never defined anywhere*:
`allocate_new_cluster`, `append_cluster_to_chain`, `delete_directory_entry`, `find_directory_entry`,
`find_free_cluster`, `free_cluster_chain`, `get_filename_from_path`, `get_first_cluster`,
`get_next_cluster`, `get_parent_directory`, `init_cluster_chain`, `set_current_date_time`,
`update_directory_entry`, `write_directory_entry`. (Note `find_directory_entry` *is* defined in `fat.c`,
but `main.c` never includes a prototype for it, so it is implicitly declared and then taken from
`main.c`'s own definition in draft B's world.)

### 3.3 The advertised API has no implementation

All 17 `fat_*` functions declared in `fat_fs.h`/`fat_util.h`, and whether a definition exists:

| Declared | Defined? |
|---|---|
| `fat_mount`, `fat_unmount`, `fat_open`, `fat_close`, `fat_read`, `fat_write`, `fat_lseek`, `fat_list_dir`, `fat_mkdir`, `fat_remove`, `fat_rmdir`, `fat_rename`, `fat_move`, `fat_copy`, `fat_getattr`, `fat_setattr` | ❌ none |
| `fat_time_to_string` | ✅ (only one) |

So mounting, listing, creating, deleting, renaming, attribute access — the entire README feature list —
has no implementation behind it. `file_desc_t.file_handle` and `fat_lseek` imply a seekable,
stateful file-descriptor layer that has no mount state to hang off; `init_fat` closes its handle
immediately on success, which is why every caller has to re-open the device by hand.

---

## 4. Correctness: proven failures

The harness (`/home/user/fat-harness/run.sh`) builds a valid 1.44 MB FAT16 image
(512 B/sector, 1 sector/cluster, 1 reserved sector, 2 FATs × 1 sector, 512 root entries → root directory
at sector 3, **data area starts at sector 35**), writes `HELLO-FAT-DATA` at cluster 2, and calls the
repository's real `init_fat`, `cluster_to_sector`, and `read_file` with a `DirEntry` pointing at cluster 2.

### 4.1 `read_file` never seeks → returns the boot sector

`main.c:406-441` loops over clusters and sectors, calls `ReadFile` into `sector_buffer`, and copies into
the caller's buffer. There is **no `SetFilePointer` anywhere in the function**. `ReadFile` reads from the
handle's current position, so the "file" is read from wherever the pointer happens to be — offset 0 for a
freshly opened device.

```
read_file(size=14) returned 14 bytes
  requested: "HELLO-FAT-DATA"  (at the real cluster 2, sector 35)
  got      : "........@....."
  got hex  : 00 02 01 01 00 02 00 02 40 0B F0 01 00 00
  bytes at offset 0 of the device: 00 02 01 01 00 02 00 02 40 0B F0 01 00 00
VERDICT: read_file returned the bytes at offset 0 of the device (the boot sector), not the file.
```

Those bytes are the BPB: `bytes_per_sector=0x0200`, `sectors_per_cluster=1`, `reserved=1`, …

`write_file` (`main.c:449`) has the identical defect — it never seeks either — so a write of a file
overwrites the **volume boot record** and the FAT. That is silent, total filesystem destruction, and
nothing in the code path checks. (`fat.c`'s `write_cluster` and `fat_fs.c`'s `write_file` do seek;
`main.c`'s does not. Three implementations, three behaviours.)

### 4.2 `cluster_to_sector` ignores the FAT and root-directory regions

`fat.c:569`:

```c
uint32_t cluster_to_sector(const BPB *bpb, uint32_t cluster) {
    return bpb->reserved_sectors + (cluster - 2) * bpb->sectors_per_cluster;
}
```

Missing entirely: the `num_fats × sectors_per_fat` region and (FAT12/16) the fixed root-directory region.
`main.c:750` is closer — it adds `num_fats * sectors_per_fat_32` — but uses the FAT32 field
unconditionally, so FAT12/16 volumes are wrong there too. Measured on the test image:

```
cluster_to_sector(cluster=2) -> sector 1   (correct answer: 35)
  sector 1 is the first FAT copy, not file data
```

The same two functions are also used backwards in `main.c:322` and `main.c:375`
(`sector_to_cluster(bpb, read_directory(...))`), passing a directory *entry count* where a sector number
is expected — and then blindly writing `sizeof(entries) == 8192` bytes to whatever location that
arithmetic lands on (`main.c:327`, `main.c:381`). `create_file` and `delete_file` therefore write 8 KB of
garbage at an address derived from a length, instead of updating one 32-byte slot.

### 4.3 `init_fat` accepts anything as a filesystem

`main.c:13-54` (validation at `main.c:30-34`) reads 79 bytes (the `BPB` struct as laid out by `#pragma pack`) and validates only that
`total_sectors_16` or `total_sectors_32` is non-zero. There is no `0x55AA` signature check, no
`bytes_per_sector` sanity check (must be a power of two ≥ 512), no `sectors_per_cluster` check, and no
FAT-count/table-size cross-check:

```
init_fat() on a 512-byte blob of 0x41 (not a filesystem): FAT16 filesystem detected.
returned 0 (reported SUCCESS)
```

That matters more here than in most projects, because this code's failure mode on a malformed BPB is
`ReadFile`/`WriteFile` at computed offsets on a raw device — corrupting whatever the volume actually was.

### 4.4 FAT-type detection is inverted *and* partially dead code

`main.c:38` (and the two copies in `read_fat_entry`/`write_fat_entry`):

```c
if (bpb->sectors_per_fat_32 != 0)          fatType = FAT32;
else if (bpb->total_sectors_16 < 65536)    fatType = FAT16;   // ← uint16_t is never ≥ 65536
else                                       fatType = FAT12;   // ← unreachable
```

`total_sectors_16` is `uint16_t`, so `< 65536` is a tautology: the `FAT12` arm is dead and GCC says so
(`-Wtype-limits`). Every FAT12 volume (whose BPB has `total_sectors_16 = 2880`, `sectors_per_fat_16 = 9`)
is therefore treated as FAT16, i.e. indexed with 2-byte entries instead of 1.5-byte entries — reads
return wrong clusters and writes corrupt the allocation table. Conversely, the intended FAT16-large
volume path lands in the `FAT12` arm.

The same two `if` chains also end with `else { fprintf(stderr, "Error: Unsupported FAT type"); }` on a
variable that has already been assigned in every branch, and `main.c:38` prints "FAT16 filesystem
detected" for FAT12 media and "FAT12" for large FAT16 volumes — the type detection just needs to be
replaced, not patched (use the Microsoft FAT spec's cluster-count rule).

### 4.5 Allocation is FAT32-only and links nothing

`fat.c:253-289` (`allocate_cluster`) sizes its FAT read as `sectors_per_fat_32 * bytes_per_sector` and
iterates `i < fat_size / 4`. For FAT12/FAT16 `sectors_per_fat_32 == 0`, so it does `malloc(0)`, the loop
body never executes, and it returns "No free clusters available" on an empty volume. It also decides
"free" by comparing a 4-byte entry to `FAT_FREE_CLUSTER`, ignoring the FAT12/16 width, and treats the
reserved high nibble of FAT32 entries as if it were part of the cluster number.

`main.c:463-466` then calls `allocate_new_cluster()` (never defined) and, when a new cluster is needed,
updates only the in-memory copy of the directory entry — it never writes a FAT entry linking the
previous cluster to the new one, so any multi-cluster file has a dangling chain. `read_file`'s
EOF check is also mismatched: `read_fat_entry` returns `& 0x0FFFFFFF` (`main.c:135`) and `fat.c` returns
the raw 32-bit value, but EOF is compared against `FAT_EOF_CLUSTER == 0xFFFFFFFF` (`fat.h:86`) in
`while (cluster != FAT_EOF_CLUSTER)` and `< FAT_EOF_CLUSTER` loops — so the end of a chain is never
recognized and both readers run past EOF. Depending on the volume, that is either garbage output or an
unbounded loop over a raw device handle.

### 4.6 Directory entry management is broken three different ways

1. **New entries are marked free, then discarded.** `fat.c:73` finds a free slot and then does
   `dirEntry.name[0] = 0x00; // Mark as used`. `0x00` in byte 0 of a directory entry is the FAT
   end-of-directory marker — the comment says "used", the effect is "not used". The slot is also written
   back with its name destroyed (`memcpy(&dirEntry, entry, …)` happens first, then byte 0 is zeroed, so
   even the caller's name is lost) and the returned `entry` is then poked to cluster 0.
2. **Deleted entries are never recognized.** `name` is declared `char name[11]` (`fat.h:62`), which is
   *signed* on x86/MSVC, so `dirEntry.name[0] == 0xE5` is always false — GCC flags it
   (`fat.c:70`, `main.c:315`). Free-slot reuse and the deleted-entry skip both silently fail: `0xE5`
   slots are treated as live files with garbage names, and slots are never reclaimed. The field must be
   read as `unsigned char` (or the comparison cast to `(uint8_t)`).
3. **In `main.c` the new entry is never inserted at all.** `read_directory` *skips* free entries
   (`if (name[0] == 0x00 || name[0] == 0xE5) continue;`), so no element of the returned `entries[]`
   array can ever have `name[0] == 0x00`; the "find a free slot" loop at `main.c:313-318` therefore can never
   take its branch. What gets written back is the unmodified earlier read, at a garbage offset (§4.2).

Also: `create_file` builds the entry with `strncpy(entry->name, fileName, 11)` from the raw path
component, so a name shorter than 11 characters keeps embedded `0x00` bytes (the spec requires
0x20 padding; embedded NULs make the entry look like end-of-directory to other drivers), and a name
longer than 11 is either truncated into garbage or needs an LFN generator that does not exist.
No `.`/`..` entries are ever created for new directories. Timestamps are never set on create/write
(`set_current_date_time` is undefined), so every entry reports 1980-00-00.

### 4.7 Path handling

There is no path resolution. `fat.c:124` compares a full user-supplied path against an 8.3 field with
`strncmp(dirEntry.name, path, 11)` — `"\\dir\\file.txt"` can never equal `"FILE    TXT"`. `fat.c:90`
and `fat.c:134` then walk "the directory" by incrementing the cluster number (`cluster++`), with the
wrong bound (`cluster >= total_sectors_32 / sectors_per_cluster`) at `fat.c:91` and `135` instead of
following the FAT chain, and they start at cluster 2 regardless of FAT flavour. In `main.c` the
equivalent traversal delegates to `find_directory_entry`, `get_parent_directory`, `get_filename_from_path`
and `get_next_cluster` — none of which are defined. Net effect: **no subdirectory can ever be reached, in
any of the three drafts**; everything only ever looks at (its idea of) the root directory.

`main.c:770`'s `read_sector(char drive, …)` builds a `\\.\X:` path from a drive *letter*, but
`main.c:619` calls it with a `HANDLE` — the compiler reports `passing argument 1 … makes integer from
pointer without a cast`. Depending on the handle value it opens a random drive letter, or fails.

### 4.8 Order-dependent constants

`fat.h:78-80` defines `FAT12 12 / FAT16 16 / FAT32 32`; `fat_util.h:13-15` defines
`FAT12 1 / FAT16 2 / FAT32 3` for the same names. Both are included by `main.c`, and the winner depends
on include order (currently `fat_util.h` wins, so `fatType` holds 1/2/3). The `switch (fatType)` arms
happen to agree within one translation unit — until someone reorders two `#include` lines or links these
files together, at which point the offset arithmetic silently changes meaning with no compile error.
`FAT_SUCCESS`/`FAT_ERROR` are likewise defined in both headers. These must be one definition, in one
place, with a `#error` guard or a project prefix.

---

## 5. Robustness and memory safety

- **Stack buffer sized by a hard-coded constant, filled by a BPB field.** `main.c:618` declares
  `uint8_t buffer[sector_size]` but `fat.c` uses `uint8_t buffer[512]` / `sector_buffer[512]` in seven
  places while reading and writing `bpb->bytes_per_sector` bytes. On a legitimate 4096-byte-sector
  volume (large SD cards, modern USB sticks, exFAT-adjacent layouts) every one of those is a stack
  overflow of up to 3.5 KB. `SECTOR_SIZE 512` in `fat_util.h:12` is used interchangeably with
  `bpb->bytes_per_sector`; they are not the same thing.
- **Unvalidated lengths.** `create_file` does `strncpy(fileName, lastSlash + 1, 11)` and
  `strncpy(dirPath, path, lastSlash - path)` with no bound on `path` (`main.c:264-267`) — a path whose
  directory part exceeds 255 bytes overflows `dirPath[256]`. `fat_fs.c` does
  `strncpy(entry->name, path, sizeof(entry->name))` with a full path.
- **`malloc` without `<stdlib.h>`** (`fat.c:256`) as noted — implicit declaration, pointer truncated to
  `int` on 64-bit targets, immediate undefined behaviour.
- **`malloc` size from the on-disk BPB** (`fat.c:255`, `sectors_per_fat_32 * bytes_per_sector`) with no
  upper bound: a crafted BPB asking for a 4 GB FAT is an unchecked allocation, and the subsequent
  `ReadFile` of `fat_size` bytes is likewise unchecked.
- **No `fclose`/`NULL` discipline in the two I/O models.** `fat.c` mixes `FILE*` (`init_fat`) with
  `HANDLE` (everything else) for the same path; `main.c`'s `read_sector`/`write_sector` open and close a
  raw device on every single sector access (`\\.\C:`), which is both slow and a privilege-heavy way to
  do buffered I/O — and it re-opens with `GENERIC_WRITE` for reads of a device that may be mounted.
- **Only the first FAT copy is ever updated.** `read_fat_entry`/`write_fat_entry` compute
  `reserved_sectors + fat_offset/bytes_per_sector`, i.e. always FAT #1, while `num_fats` is typically 2;
  the mirror is left stale, so the volume will be reported as corrupt by any other driver.
- **No concurrency/locking, no journaling, no free-space accounting**, and `fat.c:91`'s
  "no free entries" check compares `cluster` against `total_sectors_32 / sectors_per_cluster` — a
  cluster count compared against a sector count, so the bound is wrong by `sectors_per_cluster`.
- Nothing is `static` that could be, and there is no `const` discipline for read-only parameters.

---

## 6. Design issues

1. **Three implementations of one module.** Pick one. `main.c` should hold `main()` and argument
   parsing only; the primitives belong in `fat.c`; the public API belongs in `fat_fs.c`. Right now the
   "library" (`fat.c`) and the "program" (`main.c`) define the same 11 functions.
2. **Two structs for one on-disk format.** `DirEntry` (`fat.h:61-74`) and `dir_entry_t` (`fat_fs.h:38`)
   are the same 32 bytes; `FileDescriptor`-style `file_desc_t` is unused. One definition, in one header,
   with a compile-time assertion on the size (`_Static_assert(sizeof(DirEntry) == 32)`).
3. **No mount state.** `init_fat` reads a BPB and closes the handle; nothing owns the device, the
   geometry, or the mount point, which is why every function re-derives and re-opens. The
   `fat_mount`/`fat_unmount` pair already in the header is the right abstraction; there is just no
   struct behind it.
4. **Three different conventions for errors.** `0/-1` in `fat.c`, `FAT_SUCCESS/FAT_ERROR` in the
   headers, and "returns a byte count, or `-1`" in the read/write paths — the last one is ambiguous for
   a `uint32_t` return type and is exactly where the FAT12/EOF bugs hide.
5. **`BPB` conflates FAT12/16 and FAT32 layouts.** The struct has one set of fields for both; the
   FAT12/16 BPB has `sectors_per_fat_16` where the FAT32 EBPB has `sectors_per_fat_32`, and the
   offset of every field after `sectors_per_fat_16` differs. The code half-handles this by checking
   which field is non-zero, which is the source of §4.4. Either model the two layouts explicitly
   (`BPB16`/`BPB32`, validated by the FAT-type determination) or parse fields by offset.
6. **No partition support.** No partition-table parsing and no partition-start offset, so the code
   addresses a whole disk image as if it began with a VBR. Fine for a floppy image, wrong for anything real.
7. **Windows-only by construction.** `<windows.h>`, `CreateFile`/`ReadFile`, `HANDLE`, `#pragma pack`,
   `char drive`, and a "dependencies: Windows API" README — while the code is otherwise portable
   (`stdint.h`, `stdio.h`). A small `io_ops` layer (open/read/write/seek/close) behind one interface
   would let the actual FAT logic be tested on any host, which is the single highest-leverage change for
   this project's testability.

---

## 7. What is actually good

Worth keeping, and worth saying plainly:

- **`main.c:58-141`'s `read_fat_entry` is textbook-correct** for all three flavours: `cluster + cluster/2`
  for the 12-bit offset, `cluster * 2` for 16-bit, `cluster * 4` for 32-bit, the `& 0x0FFFFFFF` mask on
  FAT32, the 4-bit shift on odd FAT12 clusters, and the cross-sector FAT12 read at
  `fatEntryOffset == SECTOR_SIZE - 1`. The FAT12 odd/even bit-fiddling in `write_fat_entry` (preserving
  the neighbouring entry's nibble) is also correct, which is the part most implementations get wrong.
- **The `BPB` and `DirEntry` field layouts** in `fat.h` match the on-disk format, including
  `#pragma pack(push, 1)` and the correct 32-byte directory entry with the FAT32 high-word split.
- **`fat.c`'s decomposition** (find entry → release chain → mark free; `allocate_cluster` →
  `write_cluster`) is the right shape, and `release_clusters` walks the chain correctly.
- **`fat_time_to_string`** implements the FAT timestamp bitfields correctly (7-bit year from 1980,
  5/6/5 time, 2-second granularity).
- **The intent is legible.** With the FAT spec open, every function maps to a clause in it; this is a
  half-finished implementation, not a misunderstanding of the format.

---

## 8. Suggested order of work

1. **Make it build and link.** One implementation per symbol (`static` for helpers), real includes,
   `const` correctness, delete dead declarations from the headers — or delete the stub bodies in
   `fat_fs.c` and keep the prototypes. Delete the duplicate `FAT12/16/32` macros and keep one set.
2. **Add a build system** (`makefile.mk` currently has one blank line) plus a `main()` that takes a path
   and a command, and a test image. `mkfs.fat` / `dd`-built images with `fsck.fat` validation give you a
   real oracle for every operation: *does `fsck.fat` say the image is clean after your create/write/delete?*
   That single test catches §4.1, §4.2, §4.5 and the 0xE5/0x00 bugs.
3. **Fix the three functions everything else depends on**, in this order: `cluster_to_sector` /
   `sector_to_cluster` (add the FAT region *and* the root-directory region), a single BPB validator
   (power-of-two sector size, `0x55AA`, FAT-type by cluster count, cross-checks), and the
   `SetFilePointer`-before-`ReadFile`/`WriteFile` fix in every I/O path. Add
   `_Static_assert(sizeof(DirEntry) == 32)`.
4. **Introduce mount state** (`fat_mount` fills a context struct owning the handle and geometry; every
   function takes it instead of re-deriving `HANDLE`+`BPB`), and make `read_file`/`write_file` position
   from `(cluster, offset)` rather than from wherever the file pointer was left.
5. **Then** directory entries: unsigned-byte comparisons, space-padded 8.3 names, `.`/`..` entries,
   real slot allocation, timestamps, and only then LFN.
6. **Last:** the API in `fat_fs.h` (`fat_open`/`fat_read`/`fat_lseek`/…), `+` `fat_copy`/`fat_move`/
   `fat_getattr`, `ifdef`s for a cross-platform I/O layer, and only after all of that, the FUSE mention
   in the README.

---

## Appendix A — Reproducing the findings

Compile checks need only a minimal `<windows.h>` stand-in plus `-Iinclude`:

```bash
mkdir -p /tmp/shim && cat > /tmp/shim/windows.h <<'EOF'   # see /home/user/fat-harness/windows.h
...  # typedefs, HANDLE/DWORD, ReadFile/WriteFile/SetFilePointer prototypes
EOF
cp -r fat-userspace /tmp/build && cd /tmp/build
sed -i 's|#include "FAT.h"|#include "fat.h"|' src/fat.c      # only edit needed to get past the top
gcc -c -Iinclude -I/tmp/shim -Wall -Wextra -o /dev/null src/main.c   # -> the errors in §3.1
```

The runtime findings are reproduced by `bash /home/user/fat-harness/run.sh`, which copies the repo to
`/tmp` (the checkout is never modified), applies the minimum edits needed to make the source compile,
links the repo's real `src/main.c` against stub definitions for the 14 undefined functions, and runs it
against a generated 1.44 MB FAT16 image. It runs without any Windows dependency.

**Caveats on scope:** this review did not exercise a real device or a real FAT32 volume, so the FAT32
code paths are assessed by reading only (the FAT32 arithmetic is correct, the I/O and EOF handling are
not). Two claims above are compiler-diagnostic-based rather than runtime-observed — the signed-`char`
`0xE5` comparison and the dead FAT12 arm — but both are unambiguous from the type widths involved.
