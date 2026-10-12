/* ==========================================================================
 *  fat_core.h - internal core: mount state, geometry, FAT table engine
 *
 *  This header is internal to the library.  The public API lives in fat_fs.h.
 * ========================================================================== */

#ifndef FAT_CORE_H
#define FAT_CORE_H

#include <stdint.h>

#include "fat_io.h"
#include "fat_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A directory sector cached from disk. */
typedef struct {
    uint32_t sector;                 /* absolute sector number             */
    int      valid;
    int      dirty;
    uint8_t  data[FAT_MAX_SECTOR_SIZE];
} fat_cache_t;

/* Mounted file system state. */
struct fat_fs {
    fat_io_t io;
    fat_bpb_t bpb;

    int      mounted;
    int      read_only;
    int      fat_type;               /* FAT_TYPE_FAT12 / 16 / 32           */
    uint64_t device_size;

    /* Geometry, all derived once at mount time. */
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t bytes_per_cluster;
    uint32_t num_fats;
    uint32_t reserved_sectors;
    uint32_t root_entries;           /* 0 on FAT32                         */
    uint32_t root_dir_sectors;       /* 0 on FAT32                         */
    uint32_t sectors_per_fat;
    uint32_t total_sectors;
    uint32_t fat_start_sector;       /* absolute sector of FAT copy #1      */
    uint32_t root_dir_start_sector;
    uint32_t data_start_sector;
    uint32_t cluster_count;          /* number of data clusters             */
    uint32_t max_cluster;            /* highest valid cluster id            */
    uint32_t info_sector;            /* FAT32 FSInfo sector, 0 if none      */

    /* Allocation bookkeeping. */
    uint32_t free_clusters;          /* FAT_FSINFO_UNKNOWN when not known   */
    uint32_t next_free_hint;
    int      free_clusters_verified; /* 0 while the count is only a claim   */

    /* Clean-shutdown state (FAT32 only).  was_clean records what the volume
     * said at mount time; marked_dirty tracks whether this session has
     * modified anything yet. */
    int      was_clean;
    int      marked_dirty;

    /* One-sector cache of FAT copy #1; writes go to every copy. */
    fat_cache_t fat_cache;

    /* Mount diagnostics the caller may want to surface (warnings only). */
    char     warning[512];
};

/* --------------------------------------------------------------------------
 *  Mount / unmount
 * ------------------------------------------------------------------------ */

/* Open @path, validate the boot sector and fill in the geometry.  @base_offset
 * shifts all I/O, which allows mounting a volume inside a partitioned image.
 * @force_read_only overrides a writable open.
 * Returns FAT_SUCCESS, or FAT_ERROR with a message in fs->warning. */
int fat_core_mount(struct fat_fs *fs, const char *path, uint64_t base_offset,
                   int read_only);

/* Flush caches and mark the volume cleanly unmounted. */
void fat_core_unmount(struct fat_fs *fs);

/* Re-read the boot sector after external changes. */
int fat_core_reread(struct fat_fs *fs);

/* --------------------------------------------------------------------------
 *  Validation helpers
 * ------------------------------------------------------------------------ */

int  fat_cluster_valid(const struct fat_fs *fs, uint32_t cluster);
int  fat_cluster_is_eoc(uint32_t value);
int  fat_cluster_is_free(uint32_t value);
int  fat_cluster_is_bad(uint32_t value);

/* Statistics used by `fatfs info` and by the checker. */
typedef struct {
    uint32_t total_clusters;
    uint32_t free_clusters;
    uint32_t used_clusters;      /* clusters reachable from a chain */
    uint32_t bad_clusters;
    int      free_count_known;   /* false if we had to count by scanning */
} fat_usage_t;

int fat_core_usage(struct fat_fs *fs, fat_usage_t *out);

/* --------------------------------------------------------------------------
 *  FAT table access
 * ------------------------------------------------------------------------ */

/* Read/write one FAT entry, normalised to the low 28 bits. */
int fat_fat_get(struct fat_fs *fs, uint32_t cluster, uint32_t *value);
int fat_fat_set(struct fat_fs *fs, uint32_t cluster, uint32_t value);

/* Copy FAT #1 over the remaining copies (used by `fatfs check`). */
int fat_fat_mirror(struct fat_fs *fs);

/* Allocate a free cluster and mark it end-of-chain. */
int fat_alloc_cluster(struct fat_fs *fs, uint32_t *out);

/* Free every cluster in the chain starting at @first. */
int fat_chain_free(struct fat_fs *fs, uint32_t first);

/* Walk to the end of the chain: @count clusters, @last being the final one.
 * Guards against loops, reporting FAT_ERROR on a cycle. */
int fat_chain_walk(struct fat_fs *fs, uint32_t first,
                   uint32_t *count, uint32_t *last);

/* Extend the chain whose last cluster is @last with a fresh cluster. */
int fat_chain_append(struct fat_fs *fs, uint32_t last, uint32_t *new_cluster);

/* Return the cluster at @index within the chain, extending it when
 * @extend is non-zero.  Sets @out_last to the final cluster of the chain. */
int fat_chain_cluster_at(struct fat_fs *fs, uint32_t first, uint32_t index,
                         int extend, uint32_t *out_cluster, uint32_t *out_last);

/* --------------------------------------------------------------------------
 *  Cluster I/O
 * ------------------------------------------------------------------------ */

int fat_cluster_read(struct fat_fs *fs, uint32_t cluster, void *buf);
int fat_cluster_write(struct fat_fs *fs, uint32_t cluster, const void *buf);
int fat_cluster_zero(struct fat_fs *fs, uint32_t cluster);

/* Read/write @len bytes starting at byte @offset within the chain that starts
 * at cluster @first.  Writes extend the chain as required and report the
 * number of bytes transferred in @done.  @extend controls whether a write may
 * allocate more clusters (0 truncates at the existing chain end). */
int fat_chain_read(struct fat_fs *fs, uint32_t first, uint64_t offset,
                   void *buf, size_t len, size_t *done);
int fat_chain_write(struct fat_fs *fs, uint32_t first, uint64_t offset,
                    const void *buf, size_t len, size_t *done, uint32_t *last);

/* Raw sector access (used for boot sector / FSInfo maintenance). */
int fat_sector_read(struct fat_fs *fs, uint32_t sector, void *buf);
int fat_sector_write(struct fat_fs *fs, uint32_t sector, const void *buf);

/* Sector size rounded up to FAT_MAX_SECTOR_SIZE scratch space helper. */
uint32_t fat_sector_size(const struct fat_fs *fs);

/* --------------------------------------------------------------------------
 *  FSInfo (FAT32)
 * ------------------------------------------------------------------------ */

int  fat_fsinfo_read(struct fat_fs *fs);
int  fat_fsinfo_update(struct fat_fs *fs);

/* Clean-shutdown bit handling (FAT32 only, best effort). */
void fat_core_touched(struct fat_fs *fs);
int  fat_mark_dirty(struct fat_fs *fs);
int  fat_mark_clean(struct fat_fs *fs);
int  fat_is_clean(const struct fat_fs *fs, int *clean_out);

/* --------------------------------------------------------------------------
 *  Diagnostics
 * ------------------------------------------------------------------------ */

/* Append a warning/error message to fs->warning. */
void fat_set_warning(struct fat_fs *fs, const char *fmt, ...);

/* Name of a FAT type, e.g. "FAT16". */
const char *fat_type_name(int type);

#ifdef __cplusplus
}
#endif

#endif /* FAT_CORE_H */
