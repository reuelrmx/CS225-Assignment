/* ==========================================================================
 *  fat_io.h - block-device access abstraction
 *
 *  Every read and write the file system performs goes through this layer.
 *  Two backends are provided:
 *
 *    POSIX  - open()/pread()/pwrite(), works with both image files and
 *             block devices such as /dev/sdb1 (or a loop device).
 *    Win32  - CreateFile()/ReadFile()/SetFilePointerEx().  Raw volumes
 *             (\\.\X:) require sector-aligned transfers, so the backend
 *             transparently buffers through an aligned bounce buffer.
 *
 *  Offsets are 64-bit, which lets the same code handle multi-gigabyte
 *  volumes on both platforms (the original code used 32-bit offsets).
 * ========================================================================== */

#ifndef FAT_IO_H
#define FAT_IO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes shared by the whole project. */
#define FAT_SUCCESS 0
#define FAT_ERROR   (-1)

/* Device handle.  The structure is visible so that a file system context can
 * embed it without an extra allocation; treat the fields as private. */
typedef struct fat_io {
    int      opened;
    int      read_only;
    int      is_stream;
    int      hit_eof;
    int      size_known;
    uint64_t size;
    uint64_t base;                /* added to every offset */
    char     errmsg[160];
    void    *stream;              /* stdio FILE*, when is_stream */
#ifdef _WIN32
    void    *handle;              /* HANDLE */
    int      raw_volume;          /* \\.\X: - needs aligned transfers */
    uint32_t align;
    uint8_t *bounce;
    size_t   bounce_cap;
#else
    int      fd;
    int      owns_fd;
#endif
} fat_io_t;

/* Open @path for I/O.  @read_only != 0 opens the device without write access.
 * Returns FAT_SUCCESS, or FAT_ERROR if the device could not be opened. */
int fat_io_open(fat_io_t *io, const char *path, int read_only);

/* Close the device.  Safe to call on an already-closed or zeroed handle. */
void fat_io_close(fat_io_t *io);

/* Read exactly @len bytes from absolute byte offset @offset.
 * Returns FAT_SUCCESS only if the whole request was satisfied. */
int fat_io_read(fat_io_t *io, uint64_t offset, void *buf, size_t len);

/* Write exactly @len bytes at absolute byte offset @offset.
 * Returns FAT_ERROR if the handle is read-only or the write is short. */
int fat_io_write(fat_io_t *io, uint64_t offset, const void *buf, size_t len);

/* Wrap an already-open C stdio stream (used by the test suite to exercise the
 * file system against a memory-backed or temporary stream).  The caller keeps
 * ownership of @fp. */
int fat_io_open_stream(fat_io_t *io, void *stream, int read_only);

/* Set a base offset applied to every subsequent read and write.  This makes
 * it possible to mount a volume inside a partitioned image without extracting
 * it first: pass the partition's start byte offset. */
void fat_io_set_base_offset(fat_io_t *io, uint64_t base);

/* Query the size of the device in bytes.  Returns FAT_ERROR for devices whose
 * size cannot be determined (e.g. a real volume on Windows). */
int fat_io_size(fat_io_t *io, uint64_t *size);

/* Non-zero if the handle was opened read-only. */
int fat_io_is_read_only(const fat_io_t *io);

/* Non-zero if the last error was a failed read at end-of-device, i.e. the
 * image is smaller than the file system claims.  Lets the mount code report
 * "truncated image" instead of a generic I/O failure. */
int fat_io_hit_eof(const fat_io_t *io);

/* Human-readable description of the most recent failure, for diagnostics. */
const char *fat_io_strerror(const fat_io_t *io);

#ifdef __cplusplus
}
#endif

#endif /* FAT_IO_H */
