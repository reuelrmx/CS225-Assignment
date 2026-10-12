/* ==========================================================================
 *  fat_dir.c - directory cursors, long-name reassembly, slot management
 *
 *  A directory is treated as a linear stream of 32-byte entries.  On FAT12/16
 *  the root lives in a fixed region between the FATs and the data area;
 *  every other directory (and every FAT32 directory) is a cluster chain.
 * ========================================================================== */

#include "fat_dir.h"

#include <stdio.h>
#include <string.h>

#define DIR_NONE_SECTOR ((uint32_t)0xFFFFFFFFu)

/* ==========================================================================
 *  Open / flush
 * ========================================================================== */

static void dir_reset_cache(fat_dir_t *dir)
{
    dir->cache_valid  = 0;
    dir->cache_dirty  = 0;
    dir->cache_sector = DIR_NONE_SECTOR;
}

int fat_dir_open(struct fat_fs *fs, uint32_t first_cluster, fat_dir_t *dir)
{
    memset(dir, 0, sizeof *dir);
    dir->fs = fs;
    dir_reset_cache(dir);

    if (first_cluster == 0 && fs->fat_type == FAT_TYPE_FAT32) {
        if (!fat_cluster_valid(fs, fs->bpb.root_cluster)) {
            fat_set_warning(fs, "the FAT32 root cluster %u is out of range",
                            fs->bpb.root_cluster);
            return FAT_ERROR;
        }
        first_cluster = fs->bpb.root_cluster;
    }

    if (first_cluster == 0) {
        if (fs->root_entries == 0) {
            fat_set_warning(fs, "this volume has no fixed root directory");
            return FAT_ERROR;
        }
        dir->fixed_root     = 1;
        dir->first_cluster  = 0;
        dir->capacity_bytes = fs->root_entries * FAT_DIRENT_SIZE;
        dir->last_cluster   = 0;
        return FAT_SUCCESS;
    }

    if (!fat_cluster_valid(fs, first_cluster)) {
        fat_set_warning(fs, "directory cluster %u is out of range",
                        first_cluster);
        return FAT_ERROR;
    }

    dir->first_cluster = first_cluster;
    dir->fixed_root    = 0;
    dir->cur_cluster   = first_cluster;
    dir->cur_index     = 0;
    {
        uint32_t count = 0;
        if (fat_chain_walk(fs, first_cluster, &count, &dir->last_cluster)
            != FAT_SUCCESS)
            return FAT_ERROR;
        dir->capacity_bytes = count * fs->bytes_per_cluster;
    }
    return FAT_SUCCESS;
}

int fat_dir_flush(fat_dir_t *dir)
{
    int rc = FAT_SUCCESS;

    if (dir->cache_valid && dir->cache_dirty) {
        if (fat_sector_write(dir->fs, dir->cache_sector, dir->cache)
            != FAT_SUCCESS)
            rc = FAT_ERROR;
        dir->cache_dirty = 0;
    }
    return rc;
}

void fat_dir_discard(fat_dir_t *dir) { dir_reset_cache(dir); }

/* ==========================================================================
 *  Sector mapping
 * ========================================================================== */

/* Load the sector holding directory byte @offset into the cache. */
static int dir_load(fat_dir_t *dir, uint32_t offset)
{
    struct fat_fs *fs = dir->fs;
    uint32_t sector;

    if (dir->fixed_root) {
        if (offset >= dir->capacity_bytes) {
            fat_set_warning(fs, "offset %u is past the end of the %u-byte "
                                "root directory", offset, dir->capacity_bytes);
            return FAT_ERROR;
        }
        sector = fs->root_dir_start_sector + offset / fs->bytes_per_sector;
    } else {
        uint32_t cluster_index, cluster, sector_in_cluster;

        cluster_index = offset / fs->bytes_per_cluster;

        if (dir->capacity_bytes == 0) {
            uint32_t count = 0;
            if (fat_chain_walk(fs, dir->first_cluster, &count,
                               &dir->last_cluster) != FAT_SUCCESS)
                return FAT_ERROR;
            dir->capacity_bytes = count * fs->bytes_per_cluster;
        }
        if (offset >= dir->capacity_bytes) {
            fat_set_warning(fs, "directory offset %u is beyond the last "
                                "cluster of the chain (%u bytes)",
                            offset, dir->capacity_bytes);
            return FAT_ERROR;
        }

        /* Reuse the cursor when the access is at or just after the previous
         * one; otherwise fall back to walking from the first cluster. */
        if (cluster_index == dir->cur_index) {
            cluster = dir->cur_cluster;
        } else if (cluster_index == dir->cur_index + 1u) {
            uint32_t next;
            if (fat_fat_get(fs, dir->cur_cluster, &next) != FAT_SUCCESS)
                return FAT_ERROR;
            if (!fat_cluster_valid(fs, next))
                return FAT_ERROR;
            dir->cur_cluster = next;
            dir->cur_index   = cluster_index;
            cluster          = next;
        } else {
            if (fat_chain_cluster_at(fs, dir->first_cluster, cluster_index, 0,
                                     &cluster, NULL) != FAT_SUCCESS)
                return FAT_ERROR;
            dir->cur_cluster = cluster;
            dir->cur_index   = cluster_index;
        }
        if (!fat_cluster_valid(fs, cluster))
            return FAT_ERROR;

        sector_in_cluster = (offset % fs->bytes_per_cluster) /
                            fs->bytes_per_sector;
        sector = fs->data_start_sector +
                 (cluster - FAT_CLUSTER_FIRST) * fs->sectors_per_cluster +
                 sector_in_cluster;
    }

    if (dir->cache_valid && dir->cache_sector == sector)
        return FAT_SUCCESS;

    if (fat_dir_flush(dir) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_sector_read(fs, sector, dir->cache) != FAT_SUCCESS)
        return FAT_ERROR;

    dir->cache_sector = sector;
    dir->cache_valid  = 1;
    dir->cache_dirty  = 0;
    return FAT_SUCCESS;
}

static int dir_store(fat_dir_t *dir, uint32_t offset, const uint8_t *data,
                     uint32_t len)
{
    struct fat_fs *fs = dir->fs;

    if (fs->read_only) {
        fat_set_warning(fs, "directory update attempted on a read-only mount");
        return FAT_ERROR;
    }

    while (len > 0) {
        uint32_t in_sector = offset % fs->bytes_per_sector;
        uint32_t chunk     = fs->bytes_per_sector - in_sector;

        if (chunk > len)
            chunk = len;

        if (dir_load(dir, offset) != FAT_SUCCESS)
            return FAT_ERROR;

        memcpy(dir->cache + in_sector, data, chunk);
        dir->cache_dirty = 1;

        offset += chunk;
        data   += chunk;
        len    -= chunk;
    }
    return FAT_SUCCESS;
}

int fat_dir_read_raw(fat_dir_t *dir, uint32_t offset, uint8_t *raw,
                     uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        uint32_t o = offset + i * FAT_DIRENT_SIZE;
        if (dir_load(dir, o) != FAT_SUCCESS)
            return FAT_ERROR;
        memcpy(raw + i * FAT_DIRENT_SIZE,
               dir->cache + (o % dir->fs->bytes_per_sector), FAT_DIRENT_SIZE);
    }
    return FAT_SUCCESS;
}

int fat_dir_write_raw(fat_dir_t *dir, uint32_t offset, const uint8_t *raw,
                      uint32_t count)
{
    return dir_store(dir, offset, raw, count * FAT_DIRENT_SIZE);
}

int fat_dir_size(fat_dir_t *dir, uint32_t *bytes_out)
{
    struct fat_fs *fs = dir->fs;

    if (dir->fixed_root) {
        *bytes_out = dir->capacity_bytes;
        return FAT_SUCCESS;
    }
    {
        uint32_t count = 0, last = 0;
        if (fat_chain_walk(fs, dir->first_cluster, &count, &last)
            != FAT_SUCCESS)
            return FAT_ERROR;
        dir->last_cluster   = last;
        dir->capacity_bytes = count * fs->bytes_per_cluster;
        *bytes_out          = dir->capacity_bytes;
    }
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Iteration
 * ========================================================================== */

/* The iterator needs to hand the callback a dirent whose raw location and LFN
 * slot count are both known, so it parses entries itself. */
int fat_dir_iterate(fat_dir_t *dir, fat_dir_cb_t cb, void *ctx)
{
    struct fat_fs *fs = dir->fs;
    uint32_t       offset = 0;
    uint32_t       count  = 0;
    uint32_t       size;
    uint16_t       units[FAT_LFN_MAX_CHARS + FAT_LFN_SLOTS_PER_ENTRY];
    uint32_t       lfn_slots = 0;        /* slots collected for the next entry */
    uint32_t       lfn_total = 0;        /* ordinal of the first slot seen      */
    uint32_t       lfn_next = 0;         /* ordinal the next slot must carry    */
    uint8_t        lfn_checksum = 0;
    int            have_lfn = 0;

    if (fat_dir_size(dir, &size) != FAT_SUCCESS)
        return FAT_ERROR;

    while (offset < size) {
        uint8_t      raw[FAT_DIRENT_SIZE];
        fat_dirent_t de;
        char         long_name[FAT_NAME_MAX];
        const char  *lfn_ptr = NULL;
        uint32_t     slots_for_entry = 0;

        if (dir_load(dir, offset) != FAT_SUCCESS)
            return FAT_ERROR;
        memcpy(raw, dir->cache + (offset % fs->bytes_per_sector),
               FAT_DIRENT_SIZE);

        if (raw[0] == FAT_DIRENT_END)
            break;                                   /* end of directory */

        if (raw[0] == FAT_DIRENT_DELETED) {          /* freed */
            have_lfn  = 0;
            lfn_slots = 0;
            lfn_total = 0;
            offset += FAT_DIRENT_SIZE;
            continue;
        }

        if (raw[11] == FAT_ATTR_LFN) {               /* long-name slot */
            static const uint8_t pos[13] = {
                1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30
            };
            unsigned ordinal = raw[0] & FAT_LFN_ORD_MASK;

            if (ordinal == 0 || ordinal > FAT_LFN_MAX_SLOTS) {
                have_lfn = 0;       /* corrupt slot: drop the run */
                lfn_total = 0;
            } else if (!have_lfn) {
                /* The run is stored highest ordinal first. */
                have_lfn     = 1;
                lfn_slots    = 1;
                lfn_total    = ordinal;
                lfn_next     = ordinal - 1u;
                lfn_checksum = raw[13];
                memset(units, 0, sizeof units);
                for (uint32_t k = 0; k < FAT_LFN_SLOTS_PER_ENTRY; k++) {
                    uint32_t idx = (ordinal - 1u) *
                                   FAT_LFN_SLOTS_PER_ENTRY + k;
                    if (idx < sizeof(units) / sizeof(units[0]))
                        units[idx] = fat_rd16(raw + pos[k]);
                }
            } else if (ordinal == lfn_next) {
                lfn_slots++;
                lfn_next = ordinal - 1u;
                if (raw[13] != lfn_checksum) {
                    have_lfn  = 0;  /* inconsistent run: ignore it */
                    lfn_total = 0;
                } else {
                    for (uint32_t k = 0; k < FAT_LFN_SLOTS_PER_ENTRY; k++) {
                        uint32_t idx = (ordinal - 1u) *
                                       FAT_LFN_SLOTS_PER_ENTRY + k;
                        if (idx < sizeof(units) / sizeof(units[0]))
                            units[idx] = fat_rd16(raw + pos[k]);
                    }
                }
            } else {
                have_lfn  = 0;      /* out of order: ignore the run */
                lfn_total = 0;
            }
            offset += FAT_DIRENT_SIZE;
            continue;
        }

        if (have_lfn) {
            uint32_t total = lfn_slots * FAT_LFN_SLOTS_PER_ENTRY;
            uint32_t n;

            if (total > sizeof(units) / sizeof(units[0]))
                total = sizeof(units) / sizeof(units[0]);
            for (n = 0; n < total; n++) {
                if (units[n] == 0x0000u || units[n] == 0xFFFFu)
                    break;
            }
            /* A complete run has slot counts matching the leading ordinal and
             * a checksum that agrees with the short entry that follows. */
            if (n > 0 && lfn_slots == lfn_total && lfn_next == 0 &&
                fat_short_name_checksum(raw) == lfn_checksum &&
                fat_utf16_to_utf8(units, n, long_name, sizeof long_name) > 0)
                lfn_ptr = long_name;

            slots_for_entry = lfn_slots;
            have_lfn        = 0;
            lfn_slots       = 0;
            lfn_total       = 0;
        }

        fat_dirent_parse(raw, lfn_ptr, &de);
        de.lfn_slots  = slots_for_entry;
        de.ref.offset = offset;

        /* Volume labels and the self/parent references are not filesystem
         * objects a caller can open, so they are not reported. */
        if ((de.attr & FAT_ATTR_VOLUME_ID) && !(de.attr & FAT_ATTR_DIRECTORY))
            goto next;
        if (strcmp(de.name, ".") == 0 || strcmp(de.name, "..") == 0)
            goto next;

        count++;
        if (cb && cb(&de, ctx) != 0)
            return (int)count;

next:
        offset += FAT_DIRENT_SIZE;
    }

    return (int)count;
}

typedef struct {
    const char   *name;
    fat_dirent_t *out;
    int           found;
} lookup_ctx_t;

static int lookup_cb(const fat_dirent_t *de, void *vctx)
{
    lookup_ctx_t *c = (lookup_ctx_t *)vctx;

    if (fat_name_equals(de->name, c->name) ||
        fat_name_equals(de->short_name, c->name)) {
        *c->out  = *de;
        c->found = 1;
        return 1;
    }
    return 0;
}

int fat_dir_lookup(fat_dir_t *dir, const char *name, fat_dirent_t *out)
{
    lookup_ctx_t ctx;
    int          n;

    memset(&ctx, 0, sizeof ctx);
    ctx.name = name;
    ctx.out  = out;

    n = fat_dir_iterate(dir, lookup_cb, &ctx);
    if (n == FAT_ERROR)
        return FAT_ERROR;
    return ctx.found ? FAT_SUCCESS : FAT_ERROR;
}

/* ==========================================================================
 *  Free-slot allocation
 * ========================================================================== */

static int slot_is_free(fat_dir_t *dir, uint32_t offset)
{
    struct fat_fs *fs = dir->fs;
    uint8_t        first;

    if (dir_load(dir, offset) != FAT_SUCCESS)
        return 0;
    first = dir->cache[offset % fs->bytes_per_sector];
    return first == FAT_DIRENT_END || first == FAT_DIRENT_DELETED;
}

int fat_dir_find_free(fat_dir_t *dir, uint32_t slots, uint32_t *out_offset)
{
    struct fat_fs *fs = dir->fs;
    uint32_t       have_extended = 0;

    if (slots == 0)
        return FAT_ERROR;

    for (;;) {
        uint32_t size = 0;
        uint32_t offset = 0;
        uint32_t run_start = 0, run_len = 0;

        if (fat_dir_size(dir, &size) != FAT_SUCCESS)
            return FAT_ERROR;

        while (offset < size) {
            if (slot_is_free(dir, offset)) {
                if (run_len == 0)
                    run_start = offset;
                run_len++;
                if (run_len >= slots) {
                    *out_offset = run_start;
                    return FAT_SUCCESS;
                }
            } else {
                run_len = 0;
            }
            offset += FAT_DIRENT_SIZE;
        }

        if (dir->fixed_root) {
            fat_set_warning(fs, "the %u-entry root directory is full",
                            fs->root_entries);
            return FAT_ERROR;
        }
        if (have_extended >= 2) {
            fat_set_warning(fs, "could not grow the directory");
            return FAT_ERROR;
        }
        {
            uint32_t fresh;
            if (fat_chain_append(fs, dir->last_cluster, &fresh) != FAT_SUCCESS)
                return FAT_ERROR;
            if (fat_cluster_zero(fs, fresh) != FAT_SUCCESS)
                return FAT_ERROR;
            dir->last_cluster    = fresh;
            dir->capacity_bytes += fs->bytes_per_cluster;
            have_extended++;
        }
    }
}

/* ==========================================================================
 *  Entry writing
 * ========================================================================== */

/* Produce a short name for @name that is not in use, adding a "~n" tail when
 * the plain truncation collides.  @exclude_offset is the directory offset of
 * the entry being renamed (0 when inserting), so that a case-only rename does
 * not look like a collision with itself. */
static int make_unique_short_name(fat_dir_t *dir, const char *name,
                                  uint32_t exclude_offset,
                                  uint8_t out[FAT_SHORT_NAME_LEN])
{
    unsigned tail;
    uint8_t  candidate[FAT_SHORT_NAME_LEN];
    char     rendered[FAT_SHORT_NAME_STR];
    fat_dirent_t probe;

    for (tail = 0; tail < 1000000u; tail++) {
        if (fat_short_name_make(name, tail, candidate) != FAT_SUCCESS)
            return FAT_ERROR;
        fat_short_name_render(candidate, 0, rendered);
        if (fat_dir_lookup(dir, rendered, &probe) != FAT_SUCCESS ||
            (exclude_offset && probe.ref.offset == exclude_offset)) {
            memcpy(out, candidate, FAT_SHORT_NAME_LEN);
            return FAT_SUCCESS;
        }
    }
    return FAT_ERROR;
}

int fat_dir_insert(fat_dir_t *dir, const char *name, fat_dirent_t *entry)
{
    uint8_t      short_name[FAT_SHORT_NAME_LEN];
    uint32_t     lfn_slots = 0;
    uint8_t      lfn_raw[FAT_LFN_MAX_SLOTS * FAT_DIRENT_SIZE];
    uint32_t     offset;
    uint8_t      raw[FAT_DIRENT_SIZE];
    fat_dirent_t probe;

    if (fat_name_is_valid(name) != FAT_SUCCESS) {
        fat_set_warning(dir->fs, "invalid file name '%s'", name);
        return FAT_ERROR;
    }
    if (fat_dir_lookup(dir, name, &probe) == FAT_SUCCESS) {
        fat_set_warning(dir->fs, "'%s' already exists", name);
        return FAT_ERROR;
    }

    if (make_unique_short_name(dir, name, 0, short_name) != FAT_SUCCESS) {
        fat_set_warning(dir->fs, "cannot build a short name for '%s'", name);
        return FAT_ERROR;
    }
    if (fat_name_is_short(name) != 1)
        lfn_slots = fat_lfn_build(name, short_name, lfn_raw,
                                  FAT_LFN_MAX_SLOTS);

    if (fat_dir_find_free(dir, lfn_slots + 1, &offset) != FAT_SUCCESS)
        return FAT_ERROR;

    if (lfn_slots &&
        fat_dir_write_raw(dir, offset, lfn_raw, lfn_slots) != FAT_SUCCESS)
        return FAT_ERROR;

    memcpy(entry->short_name, short_name, FAT_SHORT_NAME_LEN);
    entry->short_name[FAT_SHORT_NAME_LEN] = '\0';
    strncpy(entry->name, name, sizeof entry->name - 1);
    entry->name[sizeof entry->name - 1] = '\0';
    entry->lfn_slots = lfn_slots;

    fat_dirent_format(raw, entry);

    if (fat_dir_write_raw(dir, offset + lfn_slots * FAT_DIRENT_SIZE, raw, 1)
        != FAT_SUCCESS)
        return FAT_ERROR;

    entry->ref.offset = offset + lfn_slots * FAT_DIRENT_SIZE;
    entry->ref.sector = (uint32_t)(entry->ref.offset / dir->fs->bytes_per_sector);
    return fat_dir_flush(dir);
}

int fat_dir_update(fat_dir_t *dir, const fat_dirent_t *de)
{
    uint8_t raw[FAT_DIRENT_SIZE];

    fat_dirent_format(raw, de);
    if (fat_dir_write_raw(dir, de->ref.offset, raw, 1) != FAT_SUCCESS)
        return FAT_ERROR;
    return fat_dir_flush(dir);
}

int fat_dir_rename(fat_dir_t *dir, const fat_dirent_t *de, const char *new_name,
                   fat_dirent_t *updated)
{
    fat_dirent_t probe;
    uint8_t      short_name[FAT_SHORT_NAME_LEN];
    int          needs_lfn;
    fat_dirent_t out;
    uint8_t      raw[FAT_DIRENT_SIZE];

    if (fat_name_is_valid(new_name) != FAT_SUCCESS) {
        fat_set_warning(dir->fs, "invalid file name '%s'", new_name);
        return FAT_ERROR;
    }
    if (fat_dir_lookup(dir, new_name, &probe) == FAT_SUCCESS &&
        probe.ref.offset != de->ref.offset) {
        fat_set_warning(dir->fs, "'%s' already exists", new_name);
        return FAT_ERROR;
    }

    needs_lfn = (fat_name_is_short(new_name) != 1);

    if (make_unique_short_name(dir, new_name, de->ref.offset, short_name)
        != FAT_SUCCESS)
        return FAT_ERROR;

    out = *de;
    strncpy(out.name, new_name, sizeof out.name - 1);
    out.name[sizeof out.name - 1] = '\0';
    memcpy(out.short_name, short_name, FAT_SHORT_NAME_LEN);
    out.short_name[FAT_SHORT_NAME_LEN] = '\0';

    if (needs_lfn && de->lfn_slots > 0) {
        /* Rewrite the existing long-name run if it still fits. */
        uint8_t  lfn_raw[FAT_LFN_MAX_SLOTS * FAT_DIRENT_SIZE];
        uint32_t base = de->ref.offset - de->lfn_slots * FAT_DIRENT_SIZE;
        uint32_t n = fat_lfn_build(new_name, short_name, lfn_raw,
                                   FAT_LFN_MAX_SLOTS);

        if (n == de->lfn_slots) {
            if (fat_dir_write_raw(dir, base, lfn_raw, n) != FAT_SUCCESS)
                return FAT_ERROR;
            fat_dirent_format(raw, &out);
            if (fat_dir_write_raw(dir, de->ref.offset, raw, 1) != FAT_SUCCESS)
                return FAT_ERROR;
            if (updated)
                *updated = out;
            return fat_dir_flush(dir);
        }
        goto relocate;
    }

    if (!needs_lfn && de->lfn_slots > 0) {
        /* The new name is plain 8.3: shorten in place and drop the old
         * long-name slots so no stale name is left behind. */
        uint32_t base = de->ref.offset - de->lfn_slots * FAT_DIRENT_SIZE;

        out.lfn_slots = 0;
        for (uint32_t i = 0; i < de->lfn_slots; i++) {
            if (dir_load(dir, base + i * FAT_DIRENT_SIZE) != FAT_SUCCESS)
                return FAT_ERROR;
            dir->cache[(base + i * FAT_DIRENT_SIZE) %
                       dir->fs->bytes_per_sector] = FAT_DIRENT_DELETED;
            dir->cache_dirty = 1;
        }
        fat_dirent_format(raw, &out);
        if (fat_dir_write_raw(dir, de->ref.offset, raw, 1) != FAT_SUCCESS)
            return FAT_ERROR;
        if (updated)
            *updated = out;
        return fat_dir_flush(dir);
    }

    if (needs_lfn && de->lfn_slots == 0)
        goto relocate;

    /* Plain 8.3 to plain 8.3: rewrite in place. */
    fat_dirent_format(raw, &out);
    if (fat_dir_write_raw(dir, de->ref.offset, raw, 1) != FAT_SUCCESS)
        return FAT_ERROR;
    if (updated)
        *updated = out;
    return fat_dir_flush(dir);

relocate:
    {
        fat_dirent_t fresh = *de;

        fresh.lfn_slots = 0;
        if (fat_dir_insert(dir, new_name, &fresh) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_dir_delete(dir, de) != FAT_SUCCESS) {
            fat_set_warning(dir->fs, "rename left a duplicate entry behind");
            return FAT_ERROR;
        }
        if (updated)
            *updated = fresh;
        return FAT_SUCCESS;
    }
}

int fat_dir_delete(fat_dir_t *dir, const fat_dirent_t *de)
{
    uint32_t slots = de->lfn_slots + 1;
    uint32_t base  = de->ref.offset - de->lfn_slots * FAT_DIRENT_SIZE;

    if (dir->fs->read_only) {
        fat_set_warning(dir->fs, "delete attempted on a read-only mount");
        return FAT_ERROR;
    }

    for (uint32_t i = 0; i < slots; i++) {
        uint32_t offset = base + i * FAT_DIRENT_SIZE;
        uint32_t in_sector;

        if (dir_load(dir, offset) != FAT_SUCCESS)
            return FAT_ERROR;
        in_sector = offset % dir->fs->bytes_per_sector;
        if (dir->cache[in_sector] == FAT_DIRENT_END)
            break;
        dir->cache[in_sector] = FAT_DIRENT_DELETED;
        dir->cache_dirty      = 1;
    }
    return fat_dir_flush(dir);
}

/* ==========================================================================
 *  Directory creation and emptiness
 * ========================================================================== */

typedef struct { int count; } count_ctx_t;

static int count_cb(const fat_dirent_t *de, void *vctx)
{
    (void)de;
    ((count_ctx_t *)vctx)->count++;
    return 0;
}

int fat_dir_is_empty(fat_dir_t *dir, int *empty_out)
{
    count_ctx_t ctx = { 0 };

    if (fat_dir_iterate(dir, count_cb, &ctx) == FAT_ERROR)
        return FAT_ERROR;
    *empty_out = (ctx.count == 0);
    return FAT_SUCCESS;
}

int fat_dir_create(struct fat_fs *fs, uint32_t parent_cluster,
                   uint32_t *out_cluster)
{
    uint32_t     first;
    uint8_t      dot[FAT_DIRENT_SIZE];
    uint8_t      dotdot[FAT_DIRENT_SIZE];
    uint8_t      pair[2 * FAT_DIRENT_SIZE];
    fat_dirent_t de;
    uint16_t     now_time, now_date;
    uint64_t     base;

    if (fs->read_only) {
        fat_set_warning(fs, "directory creation attempted on a read-only "
                            "mount");
        return FAT_ERROR;
    }

    if (fat_alloc_cluster(fs, &first) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_cluster_zero(fs, first) != FAT_SUCCESS) {
        (void)fat_fat_set(fs, first, FAT_CLUSTER_FREE);
        return FAT_ERROR;
    }

    fat_now(&now_time, &now_date);

    memset(&de, 0, sizeof de);
    de.attr          = FAT_ATTR_DIRECTORY;
    de.first_cluster = first;
    de.crt_time = de.wrt_time = now_time;
    de.crt_date = de.wrt_date = de.acc_date = now_date;

    strcpy(de.name, ".");
    strcpy(de.short_name, ".");
    fat_dirent_format(dot, &de);

    /* ".." points at the parent.  A FAT12/16 root has no cluster number, and
     * the specification requires 0 to be stored in that case. */
    strcpy(de.name, "..");
    strcpy(de.short_name, "..");
    de.first_cluster = fat_cluster_valid(fs, parent_cluster) ? parent_cluster
                                                             : 0;
    fat_dirent_format(dotdot, &de);

    memcpy(pair, dot, FAT_DIRENT_SIZE);
    memcpy(pair + FAT_DIRENT_SIZE, dotdot, FAT_DIRENT_SIZE);

    base = (uint64_t)(fs->data_start_sector +
                      (first - FAT_CLUSTER_FIRST) * fs->sectors_per_cluster) *
           fs->bytes_per_sector;

    fat_core_touched(fs);
    if (fat_io_write(&fs->io, base, pair, sizeof pair) != FAT_SUCCESS) {
        (void)fat_fat_set(fs, first, FAT_CLUSTER_FREE);
        return FAT_ERROR;
    }

    *out_cluster = first;
    return FAT_SUCCESS;
}
