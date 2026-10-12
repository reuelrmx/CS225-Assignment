# CS225 Assignment — a user-space FAT file system

A complete, self-contained implementation of the FAT12, FAT16 and FAT32 file
systems in portable C, plus a command-line tool that drives it. It reads and
writes ordinary FAT volumes — images, floppies, USB sticks, partitions — with
no kernel driver, no FUSE and no third-party library: the code talks to the
bytes on the device itself.

```
fat-userspace/
├── include/        public and internal headers
│   ├── fat.h           on-disk structures and little-endian accessors
│   ├── fat_io.h        device layer (file / read-only / offset mounts)
│   ├── fat_core.h      mounted volume: BPB, geometry, FAT, chains, FSInfo
│   ├── fat_dir.h       directory iteration and modification
│   ├── fat_util.h      paths, names, timestamps, UTF-16 helpers
│   └── fat_fs.h        the public API described below
├── src/            one .c file per header, plus main.c (the CLI)
├── tests/
│   ├── api_test.c      library-level exercise of the public API
│   └── run_tests.sh    the whole-suite integration tests
└── Makefile
```

## Building

```sh
cd fat-userspace
make                 # build/libfatfs.a and build/fatfs
make test            # run every test (see "Testing" below)
make clean
```

Only a C11 compiler and `make` are required. `make test` additionally uses
Python 3, and performs independent cross-checks when the optional `pyfatfs`
package happens to be installed.

## Using the tool

Every command takes the image or device first, so the tool is easy to script:

```sh
truncate -s 16M disk.img
build/fatfs format disk.img MYVOLUME          # types chosen from the capacity
build/fatfs info disk.img
build/fatfs put disk.img notes.txt /docs/notes.txt
build/fatfs ls disk.img /docs -l
build/fatfs get disk.img /docs/notes.txt out.txt
build/fatfs check disk.img
```

| Command | What it does |
| --- | --- |
| `info <dev>` | geometry, capacity, free space, label, mount mode |
| `ls <dev> [path] [-l]` | list a directory (long listing shows size, attributes and date) |
| `cat <dev> <path>` | write a file to standard output |
| `get <dev> <src> <dst>` | copy a file out of the volume |
| `put <dev> <src> <dst>` | copy a host file into the volume |
| `mkdir`, `rmdir`, `rm`, `touch` | the expected directory and file operations |
| `mv <dev> <old> <new>` | rename, or move a file or directory into another directory |
| `cp <dev> <src> <dst>` | copy a file inside the volume |
| `attr <dev> <path> [+-RHSA]` | show or change attributes (`--` before a specification that starts with `-`) |
| `tree <dev> [path]` | recursive listing |
| `check <dev> [--repair]` | verify the volume, optionally applying the safe repairs |
| `format <dev> [label]` | create a file system (`-t 12\|16\|32`, `-c <cluster size>`) |

Options may appear anywhere and are also accepted in long form: `-r/--read-only`,
`-o/--offset N` (mount a volume that starts N bytes into the device, i.e. inside
a partitioned image), `-l/--long`, `-t/--type`, `-c/--cluster`, `-v/--verbose`,
`-h/--help`. Exit status is `0` on success, `1` on error and `2` when `check`
finds a problem.

## Using the library

`build/libfatfs.a` exposes a small, conventional API (`include/fat_fs.h`):

```c
#include "fat_fs.h"

fat_fs_t *fs;
char      err[256];

if (fat_mount("disk.img", NULL, &fs, err, sizeof err) != FAT_SUCCESS) {
    fprintf(stderr, "mount failed: %s\n", err);
    return 1;
}

fat_mkdir(fs, "/docs");

fat_file_t *f;
fat_open(fs, "/docs/readme.txt", FAT_OPEN_CREATE | FAT_OPEN_WRITE, &f);
fat_write(f, "hello", 5);
fat_close(f);

fat_unmount(fs);
```

The rest of the surface: `fat_open`, `fat_close`, `fat_read`, `fat_write`,
`fat_seek`, `fat_tell`, `fat_file_size`, `fat_set_size`, `fat_read_full`,
`fat_write_full`, `fat_mkdir`, `fat_rmdir`, `fat_remove`,
`fat_rename`, `fat_move`, `fat_copy`, `fat_list_dir`, `fat_is_directory`,
`fat_getattr`, `fat_setattr`, `fat_get_info`, `fat_check` and `fat_format`.
Errors are reported through the return value, the message from
`fat_strerror(fs)` and the optional `fat_set_warning` handler.

## What is implemented

* **FAT12, FAT16 and FAT32**, with the type derived from the cluster count
  (not from the BPB's own label) and validated against the FAT size, the
  reserved area and the device length.
* **Full read/write**: create, read, write, truncate, extend, delete, rename,
  move and copy files; create and remove directories at any depth.
* **Short and long names.** 8.3 names are generated with a `~1`-style tail
  when needed, and long names are stored as the proper UTF-16 LFN runs with
  the correct checksum; the reader also accepts what other tools wrote
  (including names with a `.` inside them and unicode names).
* **Directories that grow**: directory chains are extended, shrunk and freed
  like file chains. `mv` of a directory rewrites the `..` entry of the moved
  directory to point at its new parent.
* **Time stamps**: created / modified / accessed, and the entry's tenths-of-a-
  second field, taken from the system clock.
* **Cluster accounting**: allocation, free-chain deletion and the FAT32 FSInfo
  free count are kept in agreement (the free count is verified against the FAT
  before it is trusted, because other drivers do not always maintain it).
* **FAT32 clean-shutdown bit** and the backup boot sector: a session that
  writes clears the clean bit and sets it again on a clean unmount. Inspection
  commands (`info`, `ls`, `cat`, `tree`, `check`) leave the volume byte for
  byte unchanged.
* **A real consistency checker** (`fat_check`): walks every chain, detects
  cross-linked, lost, and out-of-range clusters, size/chain mismatches, wrong
  reserved entries, a missing clean bit, a stale FSInfo and FAT mirror
  differences. `--repair` can rewrite the FAT mirrors, fix the FSInfo count,
  and shorten a size that its chain cannot support; the tool then re-runs the
  check so a successful repair is verified rather than assumed.
* **mkfs** (`fat_format`): boot sector (and the FAT32 backup), FSInfo (and its
  backup), both FATs with the reserved entries, the root directory — fixed
  area on FAT12/16, a cluster on FAT32 — and the label in both the BPB and the
  root directory entry. The geometry is solved iteratively so that the FAT is
  always large enough for the cluster count it describes.

## Deliberate limitations

* No mounting of volumes that need the 0x55AA boot signature check bypassed on
  a device that is not a whole-disk image, no partitioning (`-o` mounts a
  volume at an offset instead).
* A volume claiming more sectors than the device holds is opened **read-only**
  rather than refused, so its data can still be salvaged.
* `fat_copy` copies files, not directory trees.
* Long names are limited to 255 characters and `FAT_PATH_MAX` (1024) for the
  whole path; cluster ids are 32-bit, so a file is capped at 4 GiB as the
  format requires.

## Testing

```sh
make test          # or: bash tests/run_tests.sh
```

The suite builds images with the tool itself and then exercises them through
the command-line tool and through `tests/api_test.c`. It covers formatting and
geometry on all three FAT types, mounting and the rejection of invalid
volumes, byte-exact round trips of nine sizes from 0 to 200 000 bytes, deep and
wide directories, long and unicode names, moves and copies, attributes,
cluster accounting, a full volume, read-only and offset mounts, the checker's
repairs, the public API against all three types, and a sanitizer build.

When `pyfatfs` (an independent Python implementation) is installed, the same
volumes are also read and written by it: files written by this implementation
must come back byte for byte, and files written by pyfatfs must be readable
here. That cross-check is what turns the suite from "self-consistent" into
"actually a FAT file system".

## A note on the original code

The initial revision in this repository contained three incompatible drafts of
the same primitives that did not compile or link and implemented none of the
advertised API. The review of that state, with the evidence, is in
[`REVIEW.md`](REVIEW.md); `fat-userspace/` is the working file system that
replaced it. The legacy draft files were removed from the build rather than
patched in place.
