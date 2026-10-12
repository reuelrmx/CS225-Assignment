/* ==========================================================================
 *  fat_fs.h - public API of the user-space FAT file system
 *
 *  Usage
 *  -----
 *      fat_fs_t *fs;
 *      char      err[256];
 *
 *      fat_mount("disk.img", NULL, &fs, err, sizeof err);
 *      fat_mkdir(fs, "/docs");
 *      fat_file_t *f;
 *      fat_open(fs, "/docs/readme.txt", FAT_OPEN_CREATE | FAT_OPEN_WRITE, &f);
 *      fat_write(f, "hello", 5);
 *      fat_close(f);
 *      fat_unmount(fs);
 *
 *  All paths are absolute and use '/' (a leading '\' is also accepted).
 *  Every entry point returns FAT_SUCCESS or FAT_ERROR; on failure the last
 *  message can be obtained with fat_strerror().  fat_mount() additionally
 *  reports why a volume could not be opened through its @err buffer, which is
 *  what a caller wants to show when nothing is mounted yet.
 *
 *  Unlike the previous revision, the file system handle carries the mount
 *  state.  The original prototypes took no handle, which made it impossible
 *  for a caller to refer to a mounted volume.
 * ========================================================================== */

#ifndef FAT_FS_H
#define FAT_FS_H

#include <stddef.h>
#include <stdint.h>

#include "fat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque mount handle. */
typedef struct fat_fs fat_fs_t;

/* --------------------------------------------------------------------------
 *  Mounting
 * ------------------------------------------------------------------------ */

typedef struct {
    int      read_only;      /* never modify the volume                    */
    uint64_t base_offset;    /* byte offset of the volume inside the device */
} fat_mount_opts_t;

#define FAT_MOUNT_OPTS_INIT { 0, 0 }

/* Mount the volume at @device.  @opts may be NULL for the defaults.
 * On success *out receives the handle to pass to every other call.  When the
 * mount fails and @err is not NULL, a human-readable reason is copied there. */
int fat_mount(const char *device, const fat_mount_opts_t *opts,
              fat_fs_t **out, char *err, size_t err_size);

/* Flush caches, mark the volume cleanly unmounted and free the handle. */
int fat_unmount(fat_fs_t *fs);

/* Last error message produced by @fs (a static string when @fs is NULL). */
const char *fat_strerror(const fat_fs_t *fs);

/* Human-readable FAT type of a mounted volume ("FAT16", ...). */
const char *fat_fs_type_name(const fat_fs_t *fs);

/* Tell the library that the medium may have changed (removable media). */
int fat_fs_reread(fat_fs_t *fs);

/* --------------------------------------------------------------------------
 *  Formatting (mkfs)
 *
 *  Creates an empty file system.  The device must already exist at the right
 *  size; it is not partitioned and only its metadata is written.
 * ------------------------------------------------------------------------ */

typedef struct {
    int         fat_type;        /* 0 = choose by capacity, or FAT_TYPE_*   */
    const char *label;           /* volume label, up to 11 characters       */
    uint32_t    cluster_bytes;   /* 0 = choose, else 512/1024/.../32768     */
    uint32_t    bytes_per_sector;/* 0 = 512                                 */
    uint32_t    num_fats;        /* 0 = 2 copies                            */
} fat_format_opts_t;

#define FAT_FORMAT_OPTS_INIT { 0, NULL, 0, 0, 0 }

/* Returns FAT_SUCCESS, or FAT_ERROR with a message in @err. */
int fat_format(const char *device, const fat_format_opts_t *opts,
               char *err, size_t err_size);

/* --------------------------------------------------------------------------
 *  Volume information
 * ------------------------------------------------------------------------ */

typedef struct {
    int      fat_type;              /* FAT_TYPE_FAT12 / 16 / 32            */
    int      read_only;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t cluster_count;
    uint32_t free_clusters;
    uint32_t bad_clusters;
    uint64_t total_bytes;
    uint64_t free_bytes;
    uint32_t volume_id;
    uint16_t sectors_per_fat;
    uint32_t root_entries;
    uint32_t num_fats;
    char     label[FAT_LABEL_LEN + 1];
    char     fs_type_string[9];     /* the BPB's cosmetic "FAT16   " field  */
    int      clean_shutdown;        /* FAT32 only; -1 when unknown          */
} fat_info_t;

int fat_get_info(fat_fs_t *fs, fat_info_t *out);

/* --------------------------------------------------------------------------
 *  Files
 * ------------------------------------------------------------------------ */

/* Open flags. */
#define FAT_OPEN_READ       0x01u   /* read access                        */
#define FAT_OPEN_WRITE      0x02u   /* write access                       */
#define FAT_OPEN_CREATE     0x04u   /* create when missing                */
#define FAT_OPEN_TRUNCATE   0x08u   /* discard existing contents          */
#define FAT_OPEN_APPEND     0x10u   /* start at end of file               */

typedef struct fat_file fat_file_t;

int fat_open(fat_fs_t *fs, const char *path, int flags, fat_file_t **out);
int fat_close(fat_file_t *file);

/* Transfer at most @len bytes; the return value is the number of bytes
 * transferred, or FAT_ERROR.  A short read means end-of-file. */
int fat_read(fat_file_t *file, void *buf, uint32_t len);
int fat_write(fat_file_t *file, const void *buf, uint32_t len);

/* Error variants that report the transferred byte count through @done, which
 * makes short transfers distinguishable from failures. */
int fat_read_full(fat_file_t *file, void *buf, uint32_t len, uint32_t *done);
int fat_write_full(fat_file_t *file, const void *buf, uint32_t len,
                   uint32_t *done);

#define FAT_SEEK_SET 0
#define FAT_SEEK_CUR 1
#define FAT_SEEK_END 2

/* @offset may be negative when @whence is FAT_SEEK_CUR or FAT_SEEK_END, so a
 * backwards seek is expressible. */
int      fat_seek(fat_file_t *file, int64_t offset, int whence);
uint64_t fat_tell(const fat_file_t *file);
uint32_t fat_file_size(const fat_file_t *file);
int      fat_set_size(fat_file_t *file, uint64_t size);   /* truncate/extend */

/* --------------------------------------------------------------------------
 *  Directories
 * ------------------------------------------------------------------------ */

typedef int (*fat_list_cb_t)(const fat_dirent_t *entry, void *ctx);

/* Visit every entry in @path.  Returning non-zero from @cb stops the walk.
 * Both stopping early and reaching the end are reported as FAT_SUCCESS; use a
 * counter in @ctx if the number of entries matters. */
int fat_list_dir(fat_fs_t *fs, const char *path, fat_list_cb_t cb, void *ctx);

/* --------------------------------------------------------------------------
 *  Namespace operations
 * ------------------------------------------------------------------------ */

int fat_mkdir(fat_fs_t *fs, const char *path);
int fat_rmdir(fat_fs_t *fs, const char *path);        /* must be empty     */
int fat_remove(fat_fs_t *fs, const char *path);       /* file only         */

/* Rename within one directory; use fat_move to change directories. */
int fat_rename(fat_fs_t *fs, const char *old_path, const char *new_path);

/* Move or rename, crossing directories when required. */
int fat_move(fat_fs_t *fs, const char *old_path, const char *new_path);

int fat_copy(fat_fs_t *fs, const char *src_path, const char *dest_path);

/* --------------------------------------------------------------------------
 *  Metadata
 * ------------------------------------------------------------------------ */

int fat_getattr(fat_fs_t *fs, const char *path, fat_dirent_t *out);
int fat_setattr(fat_fs_t *fs, const char *path, uint8_t attr);
int fat_is_directory(fat_fs_t *fs, const char *path, int *out);

/* --------------------------------------------------------------------------
 *  Consistency checking
 * ------------------------------------------------------------------------ */

typedef struct {
    uint32_t files;
    uint32_t directories;
    uint32_t chains;
    uint32_t clusters_in_use;
    uint32_t free_clusters;
    uint32_t bad_clusters;
    uint32_t orphan_clusters;        /* allocated but unreachable          */
    uint32_t cross_linked_clusters;  /* reachable from two chains          */
    uint32_t invalid_entries;        /* bad cluster numbers / sizes        */
    uint32_t loops;
    uint32_t fat_mismatches;         /* FAT copies that disagree           */
    uint32_t size_mismatches;        /* size vs. chain length              */
    uint32_t lost_chains;            /* orphaned cluster chains            */
    uint32_t fs_info_wrong;
    int      was_clean;
    int      errors;                 /* total error count                  */
} fat_check_t;

/* Walk the whole volume and verify it.  @errors: 1 stops at the first error,
 * 0 collects up to 1000.  When @repair is non-zero the safe repairs are
 * applied: mirrored FATs, the FSInfo free count, and size fields that exceed
 * the allocated chain.  Orphaned chains are reported but never freed, so the
 * data is never thrown away silently.
 *
 * @log (optional) receives one line per finding. */
int fat_check(fat_fs_t *fs, fat_check_t *out, int repair,
              void (*log)(void *ctx, const char *line), void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* FAT_FS_H */
