/* ==========================================================================
 *  fat_dir.h - directory-level operations (internal)
 *
 *  A fat_dir_t is a cursor over one directory.  It works for both layouts:
 *  the fixed root region of FAT12/16 (first_cluster == 0) and the ordinary
 *  cluster-chain directories of FAT32 and of every subdirectory.
 *
 *  Byte offsets inside a directory are linear and always a multiple of 32.
 * ========================================================================== */

#ifndef FAT_DIR_H
#define FAT_DIR_H

#include "fat_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    struct fat_fs *fs;
    uint32_t       first_cluster;    /* 0 => fixed FAT12/16 root           */
    uint32_t       capacity_bytes;   /* fixed root only; 0 for chain dirs  */
    int            fixed_root;
    uint32_t       last_cluster;     /* tail of the chain (append target)   */

    /* Chain cursor: directory scans walk the chain sequentially, so the
     * cluster containing the previous access is remembered to keep iteration
     * O(1) per cluster instead of O(n). */
    uint32_t       cur_cluster;
    uint32_t       cur_index;

    /* Single-sector cache. */
    uint32_t       cache_sector;     /* absolute sector, (uint32_t)-1 = none */
    int            cache_valid;
    int            cache_dirty;
    uint8_t        cache[FAT_MAX_SECTOR_SIZE];
} fat_dir_t;

/* Callback used by fat_dir_iterate.  Returning non-zero stops the walk.
 * fat_dirent_t::lfn_slots and ::ref are filled in by the iterator. */
typedef int (*fat_dir_cb_t)(const fat_dirent_t *de, void *ctx);

/* --------------------------------------------------------------------------
 *  Open / flush
 * ------------------------------------------------------------------------ */

/* Open the directory that starts at @first_cluster (0 means the fixed root on
 * FAT12/16, or the root of a FAT32 volume when @first_cluster is 0 and the
 * type is FAT32 - in that case bpb.root_cluster is substituted). */
int  fat_dir_open(struct fat_fs *fs, uint32_t first_cluster, fat_dir_t *dir);
int  fat_dir_flush(fat_dir_t *dir);
void fat_dir_discard(fat_dir_t *dir);

/* Allocate and initialise a brand new directory: one zeroed cluster holding
 * the "." and ".." entries.  @parent_cluster is the cluster of the containing
 * directory (0 when it is a FAT12/16 root). */
int fat_dir_create(struct fat_fs *fs, uint32_t parent_cluster,
                   uint32_t *out_cluster);

/* True when the directory holds no entries other than "." and "..". */
int fat_dir_is_empty(fat_dir_t *dir, int *empty_out);

/* --------------------------------------------------------------------------
 *  Iteration and lookup
 * ------------------------------------------------------------------------ */

/* Walk the directory in on-disk order, reassembling long names.  Deleted and
 * orphaned entries, volume-label entries and "." / ".." are skipped.  Returns
 * the number of entries visited, or FAT_ERROR. */
int fat_dir_iterate(fat_dir_t *dir, fat_dir_cb_t cb, void *ctx);

/* Find @name (case-insensitive, long or short form).  Returns FAT_SUCCESS and
 * fills @out, or FAT_ERROR when not present. */
int fat_dir_lookup(fat_dir_t *dir, const char *name, fat_dirent_t *out);

/* Locate a free run of @slots consecutive 32-byte slots, extending the
 * directory when it is a cluster chain.  Returns the byte offset. */
int fat_dir_find_free(fat_dir_t *dir, uint32_t slots, uint32_t *out_offset);

/* --------------------------------------------------------------------------
 *  Entry writing
 * ------------------------------------------------------------------------ */

/* Write @count raw 32-byte entries at @offset within the directory. */
int fat_dir_write_raw(fat_dir_t *dir, uint32_t offset, const uint8_t *raw,
                      uint32_t count);

/* Read @count raw entries from @offset. */
int fat_dir_read_raw(fat_dir_t *dir, uint32_t offset, uint8_t *raw,
                     uint32_t count);

/* Insert a new entry (@name may be a long name) plus any long-name slots.
 * @entry carries the remaining metadata (attr, cluster, size, times) and is
 * updated in place with the resolved short name and on-disk location. */
int fat_dir_insert(fat_dir_t *dir, const char *name, fat_dirent_t *entry);

/* Rewrite the short entry of an existing item (size, cluster, timestamps).
 * The name is left untouched unless @rename shows up in @new_name. */
int fat_dir_update(fat_dir_t *dir, const fat_dirent_t *de);

/* Rename in place: reuses the existing slots when the new name needs no more
 * of them than the old one, so a file with no long name does not gain one. */
int fat_dir_rename(fat_dir_t *dir, const fat_dirent_t *de, const char *new_name,
                   fat_dirent_t *updated);

/* Mark an entry and the long-name slots that precede it as deleted. */
int fat_dir_delete(fat_dir_t *dir, const fat_dirent_t *de);

/* Byte length of the directory stream (fixed root: the BPB's root area;
 * otherwise the capacity of the current chain). */
int fat_dir_size(fat_dir_t *dir, uint32_t *bytes_out);

#ifdef __cplusplus
}
#endif

#endif /* FAT_DIR_H */
