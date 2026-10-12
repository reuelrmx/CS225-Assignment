/* ==========================================================================
 *  fat_io.c - POSIX and Win32 implementations of the device layer
 * ========================================================================== */

/* pread/pwrite/fseeko are POSIX; ask for them explicitly because the
 * project compiles with -std=c11, which hides them by default. */
#ifndef _WIN32
#  define _POSIX_C_SOURCE 200809L
#endif

#include "fat_io.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#  if defined(__linux__)
#    include <sys/ioctl.h>
#    include <linux/fs.h>
#  endif
#endif

#define FAT_IO_ALIGN 4096u   /* multiple of both 512 and 4096 sector sizes */

static void io_seterr(fat_io_t *io, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(io->errmsg, sizeof io->errmsg, fmt, ap);
    va_end(ap);
}

const char *fat_io_strerror(const fat_io_t *io)
{
    return io->errmsg[0] ? io->errmsg : "no error";
}

int fat_io_is_read_only(const fat_io_t *io) { return io->read_only; }
int fat_io_hit_eof(const fat_io_t *io)      { return io->hit_eof; }

/* --------------------------------------------------------------------------
 *  POSIX backend
 * ------------------------------------------------------------------------ */
#ifndef _WIN32

int fat_io_open(fat_io_t *io, const char *path, int read_only)
{
    struct stat st;

    memset(io, 0, sizeof *io);
    io->fd        = -1;
    io->read_only = !!read_only;
    io->owns_fd    = 1;

    io->fd = open(path, read_only ? O_RDONLY : O_RDWR);
    if (io->fd < 0 && !read_only) {
        /* Falling back keeps `cat`/`ls` usable on write-protected media. */
        io->fd = open(path, O_RDONLY);
        if (io->fd >= 0)
            io->read_only = 1;
    }
    if (io->fd < 0) {
        io_seterr(io, "cannot open '%s': %s", path, strerror(errno));
        return FAT_ERROR;
    }

    if (fstat(io->fd, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            io->size       = (uint64_t)st.st_size;
            io->size_known = 1;
        } else if (S_ISBLK(st.st_mode)) {
#if defined(__linux__) && defined(BLKGETSIZE64)
            uint64_t bytes = 0;
            if (ioctl(io->fd, BLKGETSIZE64, &bytes) == 0) {
                io->size       = bytes;
                io->size_known = 1;
            }
#endif
        }
    }

    io->opened = 1;
    return FAT_SUCCESS;
}

int fat_io_open_stream(fat_io_t *io, void *stream, int read_only)
{
    memset(io, 0, sizeof *io);
    io->fd        = -1;
    io->stream    = stream;
    io->is_stream = 1;
    io->read_only = !!read_only;
    io->opened    = 1;
    return FAT_SUCCESS;
}

void fat_io_close(fat_io_t *io)
{
    if (!io || !io->opened)
        return;
    if (io->fd >= 0 && io->owns_fd)
        close(io->fd);
    io->fd     = -1;
    io->opened = 0;
}

static int pread_full(int fd, uint64_t off, void *buf, size_t len, ssize_t *got)
{
    uint8_t *p   = buf;
    size_t   done = 0;

    while (done < len) {
        ssize_t n = pread(fd, p + done, len - done, (off_t)(off + done));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            *got = (ssize_t)done;
            return FAT_ERROR;
        }
        if (n == 0)
            break;              /* end of device */
        done += (size_t)n;
    }
    *got = (ssize_t)done;
    return FAT_SUCCESS;
}

int fat_io_read(fat_io_t *io, uint64_t offset, void *buf, size_t len)
{
    if (!io->opened) {
        io_seterr(io, "read on a closed device");
        return FAT_ERROR;
    }

    if (io->is_stream) {
        FILE *fp = (FILE *)io->stream;
        size_t n;
        if (fseeko(fp, (off_t)(offset + io->base), SEEK_SET) != 0) {
            io_seterr(io, "seek failed: %s", strerror(errno));
            return FAT_ERROR;
        }
        n = fread(buf, 1, len, fp);
        if (n != len) {
            io_seterr(io, "short read at offset %llu (%zu of %zu)",
                      (unsigned long long)offset, n, len);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }

    {
        ssize_t got = 0;
        offset += io->base;
        if (pread_full(io->fd, offset, buf, len, &got) != FAT_SUCCESS) {
            io_seterr(io, "read error at offset %llu: %s",
                      (unsigned long long)offset, strerror(errno));
            return FAT_ERROR;
        }
        if ((size_t)got != len) {
            io->hit_eof = 1;
            io_seterr(io, "short read at offset %llu (got %zd of %zu bytes)",
                      (unsigned long long)offset, got, len);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }
}

int fat_io_write(fat_io_t *io, uint64_t offset, const void *buf, size_t len)
{
    if (!io->opened) {
        io_seterr(io, "write on a closed device");
        return FAT_ERROR;
    }
    if (io->read_only) {
        io_seterr(io, "device is opened read-only");
        return FAT_ERROR;
    }

    if (io->is_stream) {
        FILE *fp = (FILE *)io->stream;
        if (fseeko(fp, (off_t)(offset + io->base), SEEK_SET) != 0) {
            io_seterr(io, "seek failed: %s", strerror(errno));
            return FAT_ERROR;
        }
        if (fwrite(buf, 1, len, fp) != len) {
            io_seterr(io, "short write at offset %llu",
                      (unsigned long long)offset);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }

    {
        const uint8_t *p    = buf;
        size_t         done = 0;
        offset += io->base;
        while (done < len) {
            ssize_t n = pwrite(io->fd, p + done, len - done,
                               (off_t)(offset + done));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                io_seterr(io, "write error at offset %llu: %s",
                          (unsigned long long)(offset + done), strerror(errno));
                return FAT_ERROR;
            }
            if (n == 0) {
                io_seterr(io, "short write at offset %llu",
                          (unsigned long long)(offset + done));
                return FAT_ERROR;
            }
            done += (size_t)n;
        }
        return FAT_SUCCESS;
    }
}

int fat_io_size(fat_io_t *io, uint64_t *size)
{
    if (!io->size_known) {
        io_seterr(io, "device size is unknown");
        return FAT_ERROR;
    }
    *size = (io->size > io->base) ? io->size - io->base : 0;
    return FAT_SUCCESS;
}

void fat_io_set_base_offset(fat_io_t *io, uint64_t base) { io->base = base; }

#else /* ---------------------------------------------------------------- */
/* --------------------------------------------------------------------------
 *  Win32 backend
 *
 *  A raw volume handle (\\.\X:) only accepts transfers that start and end on
 *  sector boundaries, so unaligned requests are serviced through a bounce
 *  buffer covering the enclosing aligned span.  Regular image files are
 *  passed straight through.
 * ------------------------------------------------------------------------ */

static void win_seterr(fat_io_t *io)
{
    io_seterr(io, "Win32 error %lu", (unsigned long)GetLastError());
}

int fat_io_open(fat_io_t *io, const char *path, int read_only)
{
    memset(io, 0, sizeof *io);
    (HANDLE)io->handle    = INVALID_HANDLE_VALUE;
    io->read_only = !!read_only;

    io->raw_volume = (strncmp(path, "\\\\.\\", 4) == 0);

    io->handle = (void *)CreateFileA(path,
                             read_only ? GENERIC_READ
                                       : (GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                             NULL);

    if ((HANDLE)io->handle == INVALID_HANDLE_VALUE && !read_only) {
        io->handle = (void *)CreateFileA(path, GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                 NULL);
        if ((HANDLE)io->handle != INVALID_HANDLE_VALUE)
            io->read_only = 1;
    }

    if ((HANDLE)io->handle == INVALID_HANDLE_VALUE) {
        io_seterr(io, "cannot open '%s' (Win32 error %lu)", path,
                  (unsigned long)GetLastError());
        return FAT_ERROR;
    }

    /* Derive the size.  Raw volumes report the end offset; some removable
     * media reject this, in which case the BPB's total_sectors is used. */
    {
        LARGE_INTEGER zero, end;
        zero.QuadPart = 0;
        if (SetFilePointerEx((HANDLE)io->handle, zero, &end, FILE_END)) {
            io->size       = (uint64_t)end.QuadPart;
            io->size_known = 1;
        }
        SetFilePointerEx((HANDLE)io->handle, zero, NULL, FILE_BEGIN);
    }

    io->opened = 1;
    return FAT_SUCCESS;
}

void fat_io_close(fat_io_t *io)
{
    if (!io || !io->opened)
        return;
    if ((HANDLE)io->handle && (HANDLE)io->handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)io->handle);
    free((uint8_t *)io->bounce);
    (uint8_t *)io->bounce = NULL;
    io->handle = (void *)INVALID_HANDLE_VALUE;
    io->opened = 0;
}

static int win_seek(fat_io_t *io, uint64_t offset)
{
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx((HANDLE)io->handle, li, NULL, FILE_BEGIN)) {
        win_seterr(io);
        return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

static int win_grow_bounce(fat_io_t *io, size_t want)
{
    if ((uint8_t *)io->bounce_cap >= want)
        return FAT_SUCCESS;
    {
        uint8_t *nb = (uint8_t *)realloc(io->bounce, want);
        if (!nb) {
            io_seterr(io, "out of memory for a %zu-byte bounce buffer", want);
            return FAT_ERROR;
        }
        (uint8_t *)io->bounce     = nb;
        (uint8_t *)io->bounce_cap = want;
    }
    return FAT_SUCCESS;
}

int fat_io_read(fat_io_t *io, uint64_t offset, void *buf, size_t len)
{
    DWORD got = 0;

    if (!io->opened) {
        io_seterr(io, "read on a closed device");
        return FAT_ERROR;
    }
    if (!len)
        return FAT_SUCCESS;

    offset += io->base;
    if (!io->raw_volume) {
        if (win_seek(io, offset) != FAT_SUCCESS)
            return FAT_ERROR;
        if (!ReadFile((HANDLE)io->handle, buf, (DWORD)len, &got, NULL) || got != len) {
            win_seterr(io);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }

    {
        uint64_t aligned_off = offset - (offset % FAT_IO_ALIGN);
        size_t   head        = (size_t)(offset - aligned_off);
        size_t   span        = ((head + len + FAT_IO_ALIGN - 1)
                                / FAT_IO_ALIGN) * FAT_IO_ALIGN;

        if (win_grow_bounce(io, span) != FAT_SUCCESS)
            return FAT_ERROR;
        if (win_seek(io, aligned_off) != FAT_SUCCESS)
            return FAT_ERROR;
        if (!ReadFile((HANDLE)io->handle, (uint8_t *)io->bounce, (DWORD)span, &got, NULL)
            || got != span) {
            io_seterr(io, "short/aligned read of %zu bytes at %llu "
                          "(got %lu)", span, (unsigned long long)aligned_off,
                      (unsigned long)got);
            return FAT_ERROR;
        }
        memcpy(buf, (uint8_t *)io->bounce + head, len);
        return FAT_SUCCESS;
    }
}

int fat_io_write(fat_io_t *io, uint64_t offset, const void *buf, size_t len)
{
    DWORD put = 0;

    if (!io->opened) {
        io_seterr(io, "write on a closed device");
        return FAT_ERROR;
    }
    if (io->read_only) {
        io_seterr(io, "device is opened read-only");
        return FAT_ERROR;
    }
    if (!len)
        return FAT_SUCCESS;

    offset += io->base;
    if (!io->raw_volume) {
        if (win_seek(io, offset) != FAT_SUCCESS)
            return FAT_ERROR;
        if (!WriteFile((HANDLE)io->handle, buf, (DWORD)len, &put, NULL) || put != len) {
            win_seterr(io);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }

    {
        uint64_t aligned_off = offset - (offset % FAT_IO_ALIGN);
        size_t   head        = (size_t)(offset - aligned_off);
        size_t   span        = ((head + len + FAT_IO_ALIGN - 1)
                                / FAT_IO_ALIGN) * FAT_IO_ALIGN;

        if (win_grow_bounce(io, span) != FAT_SUCCESS)
            return FAT_ERROR;
        if (win_seek(io, aligned_off) != FAT_SUCCESS)
            return FAT_ERROR;
        if (head || (len % FAT_IO_ALIGN)) {
            /* Partial span - read the surrounding bytes back first so we do
             * not clobber data outside [offset, offset+len). */
            if (!ReadFile((HANDLE)io->handle, (uint8_t *)io->bounce, (DWORD)span, &put, NULL)
                || put != span) {
                io_seterr(io, "read-modify-write failed at %llu",
                          (unsigned long long)aligned_off);
                return FAT_ERROR;
            }
            if (win_seek(io, aligned_off) != FAT_SUCCESS)
                return FAT_ERROR;
        }
        memset((uint8_t *)io->bounce + head, 0, len);
        memcpy((uint8_t *)io->bounce + head, buf, len);
        if (!WriteFile((HANDLE)io->handle, (uint8_t *)io->bounce, (DWORD)span, &put, NULL)
            || put != span) {
            io_seterr(io, "short/aligned write of %zu bytes at %llu "
                          "(wrote %lu)", span, (unsigned long long)aligned_off,
                      (unsigned long)put);
            return FAT_ERROR;
        }
        return FAT_SUCCESS;
    }
}

int fat_io_size(fat_io_t *io, uint64_t *size)
{
    if (!io->size_known) {
        io_seterr(io, "device size is unknown");
        return FAT_ERROR;
    }
    *size = (io->size > io->base) ? io->size - io->base : 0;
    return FAT_SUCCESS;
}

void fat_io_set_base_offset(fat_io_t *io, uint64_t base) { io->base = base; }

int fat_io_open_stream(fat_io_t *io, void *stream, int read_only)
{
    (void)stream; (void)read_only;
    memset(io, 0, sizeof *io);
    io_seterr(io, "stream backend is not available on Windows");
    return FAT_ERROR;
}

#endif /* _WIN32 */
