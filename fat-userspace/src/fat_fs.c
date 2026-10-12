/* ==========================================================================
 *  fat_fs.c - public API: paths, files, directories, metadata, checking
 * ========================================================================== */

#include "fat_fs.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fat_core.h"
#include "fat_dir.h"

/* A file handle.  The directory handle is kept alongside so that metadata
 * updates (size, timestamps, archive bit) can be written back without
 * re-resolving the path. */
struct fat_file {
    fat_fs_t    *fs;
    fat_dirent_t de;
    fat_dir_t    dir;
    uint64_t     pos;
    int          flags;
};

/* ==========================================================================
 *  Mount / unmount
 * ========================================================================== */

int fat_mount(const char *device, const fat_mount_opts_t *opts,
              fat_fs_t **out, char *err, size_t err_size)
{
    fat_fs_t        *fs;
    fat_mount_opts_t defaults = FAT_MOUNT_OPTS_INIT;
    int              rc;

    if (err && err_size)
        err[0] = '\0';
    if (!device || !out)
        return FAT_ERROR;

    if (!opts)
        opts = &defaults;

    fs = (fat_fs_t *)calloc(1, sizeof *fs);
    if (!fs) {
        if (err && err_size)
            snprintf(err, err_size, "out of memory");
        return FAT_ERROR;
    }

    rc = fat_core_mount(fs, device, opts->base_offset, opts->read_only);
    if (rc != FAT_SUCCESS) {
        if (err && err_size)
            snprintf(err, err_size, "%s", fat_strerror(fs));
        free(fs);
        return FAT_ERROR;
    }
    *out = fs;
    return FAT_SUCCESS;
}

int fat_unmount(fat_fs_t *fs)
{
    if (!fs)
        return FAT_ERROR;
    fat_core_unmount(fs);
    free(fs);
    return FAT_SUCCESS;
}

const char *fat_strerror(const fat_fs_t *fs)
{
    if (!fs)
        return "no file system";
    if (fs->warning[0])
        return fs->warning;
    return fat_io_strerror(&fs->io);
}

const char *fat_fs_type_name(const fat_fs_t *fs)
{
    return fs ? fat_type_name(fs->fat_type) : "unknown";
}

int fat_fs_reread(fat_fs_t *fs)
{
    if (!fs)
        return FAT_ERROR;
    fs->warning[0] = '\0';
    return fat_core_reread(fs);
}

/* ==========================================================================
 *  Volume information
 * ========================================================================== */

int fat_get_info(fat_fs_t *fs, fat_info_t *out)
{
    fat_usage_t usage;

    if (!fs || !out)
        return FAT_ERROR;

    memset(out, 0, sizeof *out);
    memset(&usage, 0, sizeof usage);

    if (fat_core_usage(fs, &usage) != FAT_SUCCESS)
        return FAT_ERROR;

    out->fat_type            = fs->fat_type;
    out->read_only           = fs->read_only;
    out->bytes_per_sector    = fs->bytes_per_sector;
    out->sectors_per_cluster = fs->sectors_per_cluster;
    out->cluster_count       = fs->cluster_count;
    out->free_clusters       = usage.free_clusters;
    out->bad_clusters        = usage.bad_clusters;
    out->total_bytes         = (uint64_t)fs->total_sectors *
                               fs->bytes_per_sector;
    out->free_bytes          = (uint64_t)usage.free_clusters *
                               fs->bytes_per_cluster;
    out->volume_id           = fs->bpb.volume_id;
    out->sectors_per_fat     = (uint16_t)fs->sectors_per_fat;
    out->root_entries        = fs->root_entries;
    out->num_fats            = fs->num_fats;
    memcpy(out->label, fs->bpb.volume_label, sizeof out->label);
    memcpy(out->fs_type_string, fs->bpb.fs_type, sizeof out->fs_type_string);

    out->clean_shutdown = -1;
    {
        int clean = 0;
        if (fat_is_clean(fs, &clean) == FAT_SUCCESS)
            out->clean_shutdown = clean;
    }
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Path resolution
 *
 *  Paths are normalised (separators collapsed, "." and ".." resolved) and
 *  then walked component by component from the root directory.
 * ========================================================================== */

/* Describe the root directory of a mounted volume. */
static void root_dirent(fat_fs_t *fs, fat_dirent_t *de)
{
    memset(de, 0, sizeof *de);
    strcpy(de->name, "/");
    strcpy(de->short_name, "/");
    de->attr = FAT_ATTR_DIRECTORY;
    de->first_cluster = (fs->fat_type == FAT_TYPE_FAT32)
                            ? fs->bpb.root_cluster : 0;
    de->size = 0;
    de->ref.offset = 0;
}

/* Move into @child, given the directory entry found for it. */
static int descend(fat_fs_t *fs, const fat_dirent_t *child, uint32_t *cluster,
                   const char *where)
{
    if (!(child->attr & FAT_ATTR_DIRECTORY)) {
        fat_set_warning(fs, "'%s' is not a directory", where);
        return FAT_ERROR;
    }
    if (fs->fat_type == FAT_TYPE_FAT32 || child->first_cluster != 0) {
        if (!fat_cluster_valid(fs, child->first_cluster)) {
            fat_set_warning(fs, "'%s' has an invalid cluster number (%u)",
                            where, child->first_cluster);
            return FAT_ERROR;
        }
        *cluster = child->first_cluster;
    } else {
        *cluster = 0;                    /* a FAT12/16 root reached another way */
    }
    return FAT_SUCCESS;
}

/* Resolve @path.
 *
 *   out            receives the entry (for "/" a synthetic root entry)
 *   found          set to 0 instead of failing when the leaf does not exist
 *   parent_opt     when non-NULL, receives the *opened* parent directory
 *   leaf_opt       receives the final path component
 *
 * When the leaf does not exist and parent_opt is given, the caller can create
 * it inside the returned parent directory. */
static int walk_path(fat_fs_t *fs, const char *path, fat_dirent_t *out,
                     int *found, fat_dir_t *parent_opt, char *leaf_opt,
                     size_t leaf_size)
{
    char        norm[FAT_PATH_MAX];
    char        dirpart[FAT_PATH_MAX];
    char        leaf[FAT_NAME_MAX];
    fat_dir_t   dir;
    uint32_t    cluster = 0;
    const char *p;

    if (!fat_path_normalize(path, norm, sizeof norm)) {
        fat_set_warning(fs, "path is too long or malformed");
        return FAT_ERROR;
    }

    if (found)
        *found = 0;

    if (strcmp(norm, "/") == 0) {
        if (strlen(norm) + 1 > leaf_size && leaf_opt)
            return FAT_ERROR;
        if (leaf_opt)
            strcpy(leaf, "");
        if (!parent_opt) {
            if (out)
                root_dirent(fs, out);
            if (found)
                *found = 1;
            return FAT_SUCCESS;
        }
        /* "/" has no parent directory. */
        fat_set_warning(fs, "the root directory has no parent");
        return FAT_ERROR;
    }

    /* Split the final component from its directory. */
    {
        const char *last = strrchr(norm, '/');
        size_t      dlen = (size_t)(last - norm);

        if (!last)
            return FAT_ERROR;
        if (dlen == 0) {
            strcpy(dirpart, "/");
        } else {
            if (dlen >= sizeof dirpart)
                return FAT_ERROR;
            memcpy(dirpart, norm, dlen);
            dirpart[dlen] = '\0';
        }
        strncpy(leaf, last + 1, sizeof leaf - 1);
        leaf[sizeof leaf - 1] = '\0';
    }

    /* Walk to the parent directory. */
    if (fat_dir_open(fs, 0, &dir) != FAT_SUCCESS)
        return FAT_ERROR;

    p = dirpart;
    while (*p) {
        char         comp[FAT_NAME_MAX];
        size_t       len;
        fat_dirent_t child;

        while (*p == '/')
            p++;
        if (!*p)
            break;

        len = 0;
        while (*p && *p != '/' && len < sizeof comp - 1)
            comp[len++] = *p++;
        comp[len] = '\0';

        if (fat_dir_lookup(&dir, comp, &child) != FAT_SUCCESS) {
            fat_set_warning(fs, "directory '%s' does not exist", dirpart);
            return FAT_ERROR;
        }
        if (descend(fs, &child, &cluster, comp) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_dir_open(fs, cluster, &dir) != FAT_SUCCESS)
            return FAT_ERROR;
    }

    if (parent_opt) {
        *parent_opt = dir;
        if (leaf_opt) {
            if (strlen(leaf) + 1 > leaf_size)
                return FAT_ERROR;
            strcpy(leaf_opt, leaf);
        }
        if (!out)
            return FAT_SUCCESS;
    }

    if (fat_dir_lookup(&dir, leaf, out) == FAT_SUCCESS) {
        if (found)
            *found = 1;
        return FAT_SUCCESS;
    }

    if (found)
        *found = 0;                      /* not an error: caller decides */
    return FAT_SUCCESS;
}

/* Resolve an existing entry, failing when it is missing. */
static int resolve(fat_fs_t *fs, const char *path, fat_dirent_t *out)
{
    int found = 0;

    if (walk_path(fs, path, out, &found, NULL, NULL, 0) != FAT_SUCCESS)
        return FAT_ERROR;
    if (!found) {
        fat_set_warning(fs, "'%s' does not exist", path);
        return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Timestamps helper
 * ========================================================================== */

static void stamp_now(fat_dirent_t *de)
{
    uint16_t t, d;

    fat_now(&t, &d);
    de->wrt_time = t;
    de->wrt_date = d;
    de->acc_date = d;
}

/* ==========================================================================
 *  Directories
 * ========================================================================== */

typedef struct {
    fat_list_cb_t cb;
    void         *ctx;
} list_adapter_t;

static int list_adapter(const fat_dirent_t *de, void *vctx)
{
    list_adapter_t *a = (list_adapter_t *)vctx;
    return a->cb ? a->cb(de, a->ctx) : 0;
}

int fat_list_dir(fat_fs_t *fs, const char *path, fat_list_cb_t cb, void *ctx)
{
    fat_dirent_t    de;
    fat_dir_t       dir;
    list_adapter_t  adapter;
    int             n;

    if (!fs)
        return FAT_ERROR;

    if (resolve(fs, path, &de) != FAT_SUCCESS)
        return FAT_ERROR;
    if (!(de.attr & FAT_ATTR_DIRECTORY)) {
        fat_set_warning(fs, "'%s' is not a directory", path);
        return FAT_ERROR;
    }
    if (fat_dir_open(fs, de.first_cluster, &dir) != FAT_SUCCESS)
        return FAT_ERROR;

    adapter.cb  = cb;
    adapter.ctx = ctx;

    n = fat_dir_iterate(&dir, list_adapter, &adapter);
    fat_dir_discard(&dir);

    /* A callback that stops the walk is a success, not a failure; only a real
     * error from the directory layer is reported as one. */
    if (n < 0)
        return FAT_ERROR;
    return FAT_SUCCESS;
}

int fat_mkdir(fat_fs_t *fs, const char *path)
{
    fat_dir_t    parent;
    char         leaf[FAT_NAME_MAX];
    fat_dirent_t de;
    uint32_t     new_cluster = 0;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (walk_path(fs, path, &de, NULL, &parent, leaf, sizeof leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;

    if (fat_dir_lookup(&parent, leaf, &de) == FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' already exists", path);
        return FAT_ERROR;
    }
    if (fat_dir_create(fs, parent.first_cluster, &new_cluster) != FAT_SUCCESS)
        return FAT_ERROR;

    memset(&de, 0, sizeof de);
    de.attr          = FAT_ATTR_DIRECTORY;
    de.first_cluster = new_cluster;
    de.size          = 0;
    {
        uint16_t t, d;
        fat_now(&t, &d);
        de.crt_time = de.wrt_time = t;
        de.crt_date = de.wrt_date = de.acc_date = d;
    }

    if (fat_dir_insert(&parent, leaf, &de) != FAT_SUCCESS) {
        (void)fat_chain_free(fs, new_cluster);
        return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

int fat_rmdir(fat_fs_t *fs, const char *path)
{
    fat_dir_t    parent;
    char         leaf[FAT_NAME_MAX];
    fat_dirent_t de;
    fat_dir_t    target;
    int          empty = 0;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (walk_path(fs, path, &de, NULL, &parent, leaf, sizeof leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;

    if (fat_dir_lookup(&parent, leaf, &de) != FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' does not exist", path);
        return FAT_ERROR;
    }
    if (!(de.attr & FAT_ATTR_DIRECTORY)) {
        fat_set_warning(fs, "'%s' is not a directory", path);
        return FAT_ERROR;
    }
    if (fat_dir_open(fs, de.first_cluster, &target) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_is_empty(&target, &empty) != FAT_SUCCESS)
        return FAT_ERROR;
    fat_dir_discard(&target);
    if (!empty) {
        fat_set_warning(fs, "directory '%s' is not empty", path);
        return FAT_ERROR;
    }

    if (fat_dir_delete(&parent, &de) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_cluster_valid(fs, de.first_cluster) &&
        fat_chain_free(fs, de.first_cluster) != FAT_SUCCESS)
        return FAT_ERROR;
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Files
 * ========================================================================== */

int fat_open(fat_fs_t *fs, const char *path, int flags, fat_file_t **out)
{
    fat_dirent_t de;
    fat_dir_t    parent;
    char         leaf[FAT_NAME_MAX];
    int          found = 0;
    fat_file_t  *file;

    if (!fs || !out || !path)
        return FAT_ERROR;
    if ((flags & FAT_OPEN_WRITE) && fs->read_only) {
        fat_set_warning(fs, "the volume is mounted read-only");
        return FAT_ERROR;
    }
    if (!(flags & (FAT_OPEN_READ | FAT_OPEN_WRITE)))
        flags |= FAT_OPEN_READ;

    if (walk_path(fs, path, &de, &found, &parent, leaf, sizeof leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;

    if (found && (flags & FAT_OPEN_WRITE) && (de.attr & FAT_ATTR_READ_ONLY)) {
        fat_set_warning(fs, "'%s' is read-only; clear the attribute first", path);
        return FAT_ERROR;
    }

    if (!found) {
        uint16_t t, d;

        if (!(flags & FAT_OPEN_CREATE)) {
            fat_set_warning(fs, "'%s' does not exist", path);
            return FAT_ERROR;
        }
        memset(&de, 0, sizeof de);
        de.attr          = FAT_ATTR_ARCHIVE;
        de.first_cluster = 0;
        de.size          = 0;
        fat_now(&t, &d);
        de.crt_time = de.wrt_time = t;
        de.crt_date = de.wrt_date = de.acc_date = d;

        if (fat_dir_insert(&parent, leaf, &de) != FAT_SUCCESS)
            return FAT_ERROR;
    } else if (de.attr & FAT_ATTR_DIRECTORY) {
        fat_set_warning(fs, "'%s' is a directory", path);
        return FAT_ERROR;
    }

    if (flags & FAT_OPEN_TRUNCATE) {
        if (fat_cluster_valid(fs, de.first_cluster)) {
            if (fat_chain_free(fs, de.first_cluster) != FAT_SUCCESS)
                return FAT_ERROR;
        }
        de.first_cluster = 0;
        de.size          = 0;
        de.attr         |= FAT_ATTR_ARCHIVE;
        stamp_now(&de);
        if (fat_dir_update(&parent, &de) != FAT_SUCCESS)
            return FAT_ERROR;
    }

    file = (fat_file_t *)calloc(1, sizeof *file);
    if (!file)
        return FAT_ERROR;

    file->fs    = fs;
    file->de    = de;
    file->dir   = parent;
    file->flags = flags;
    file->pos   = (flags & FAT_OPEN_APPEND) ? de.size : 0;

    *out = file;
    return FAT_SUCCESS;
}

int fat_close(fat_file_t *file)
{
    int rc = FAT_SUCCESS;

    if (!file)
        return FAT_ERROR;
    if (fat_dir_flush(&file->dir) != FAT_SUCCESS)
        rc = FAT_ERROR;
    free(file);
    return rc;
}

int fat_read_full(fat_file_t *file, void *buf, uint32_t len, uint32_t *done)
{
    size_t avail;
    size_t want;

    if (done)
        *done = 0;
    if (!file || !buf)
        return FAT_ERROR;
    if (file->pos >= file->de.size)
        return FAT_SUCCESS;                 /* at or past EOF */
    if (!fat_cluster_valid(file->fs, file->de.first_cluster))
        return FAT_SUCCESS;

    avail = (size_t)(file->de.size - file->pos);
    want  = (len < avail) ? len : avail;

    {
        size_t got = 0;
        if (fat_chain_read(file->fs, file->de.first_cluster, file->pos, buf,
                           want, &got) != FAT_SUCCESS)
            return FAT_ERROR;
        file->pos += got;
        if (done)
            *done = (uint32_t)got;
        return FAT_SUCCESS;
    }
}

int fat_read(fat_file_t *file, void *buf, uint32_t len)
{
    uint32_t done = 0;

    if (fat_read_full(file, buf, len, &done) != FAT_SUCCESS)
        return FAT_ERROR;
    return (int)done;
}

int fat_write_full(fat_file_t *file, const void *buf, uint32_t len,
                   uint32_t *done)
{
    size_t   wrote = 0;
    uint32_t first = 0;
    int      allocated = 0;

    if (done)
        *done = 0;
    if (!file || !buf)
        return FAT_ERROR;
    if (!(file->flags & FAT_OPEN_WRITE)) {
        fat_set_warning(file->fs, "the file was not opened for writing");
        return FAT_ERROR;
    }
    if (len == 0)
        return FAT_SUCCESS;

    if (!fat_cluster_valid(file->fs, file->de.first_cluster)) {
        if (fat_alloc_cluster(file->fs, &first) != FAT_SUCCESS)
            return FAT_ERROR;
        file->de.first_cluster = first;
        allocated = 1;
    }

    /* Writing past the end of the file leaves a hole: the bytes between the
     * old end and the new position are part of the file and read back as
     * zeroes, so the hole is filled in.  Without this the reader would see
     * whatever the clusters held before they were allocated - the classic way
     * for a deleted file's contents to reappear. */
    if (file->pos > file->de.size) {
        static const uint8_t zeros[4096];
        uint64_t hole = file->pos - file->de.size;
        uint64_t at   = file->de.size;

        while (hole > 0) {
            size_t   chunk = (hole > sizeof zeros) ? sizeof zeros
                                                  : (size_t)hole;
            size_t   filled = 0;

            if (fat_chain_write(file->fs, file->de.first_cluster, at, zeros,
                                chunk, &filled, NULL) != FAT_SUCCESS)
                return FAT_ERROR;
            if (filled == 0)
                return FAT_ERROR;
            at   += filled;
            hole -= filled;
        }
        file->de.size = (uint32_t)at;
    }

    /* Appending only ever changes the tail of the chain, so the first cluster
     * of the file must not be touched here. */
    if (fat_chain_write(file->fs, file->de.first_cluster, file->pos, buf, len,
                        &wrote, NULL) != FAT_SUCCESS) {
        if (allocated) {
            (void)fat_chain_free(file->fs, file->de.first_cluster);
            file->de.first_cluster = 0;
        }
        return FAT_ERROR;
    }

    file->pos += wrote;
    if (file->pos > file->de.size)
        file->de.size = (uint32_t)file->pos;

    file->de.attr |= FAT_ATTR_ARCHIVE;
    stamp_now(&file->de);

    if (fat_dir_update(&file->dir, &file->de) != FAT_SUCCESS)
        return FAT_ERROR;

    if (done)
        *done = (uint32_t)wrote;
    return FAT_SUCCESS;
}

int fat_write(fat_file_t *file, const void *buf, uint32_t len)
{
    uint32_t done = 0;

    if (fat_write_full(file, buf, len, &done) != FAT_SUCCESS)
        return FAT_ERROR;
    return (int)done;
}

int fat_seek(fat_file_t *file, int64_t offset, int whence)
{
    int64_t base;
    int64_t target;

    if (!file)
        return FAT_ERROR;

    switch (whence) {
    case FAT_SEEK_SET: base = 0;                          break;
    case FAT_SEEK_CUR: base = (int64_t)file->pos;         break;
    case FAT_SEEK_END: base = (int64_t)file->de.size;     break;
    default:
        fat_set_warning(file->fs, "invalid seek origin %d", whence);
        return FAT_ERROR;
    }

    target = base + offset;
    if (target < 0) {
        fat_set_warning(file->fs, "cannot seek before the start of the file");
        return FAT_ERROR;
    }
    if (target > 0xFFFFFFFFLL) {
        fat_set_warning(file->fs, "seek beyond the 4 GiB limit of FAT");
        return FAT_ERROR;
    }
    file->pos = (uint64_t)target;
    return FAT_SUCCESS;
}

uint64_t fat_tell(const fat_file_t *file) { return file ? file->pos : 0; }
uint32_t fat_file_size(const fat_file_t *file)
{
    return file ? file->de.size : 0;
}

int fat_set_size(fat_file_t *file, uint64_t size)
{
    fat_fs_t *fs;
    uint32_t  bpc;
    uint32_t  needed;
    uint32_t  have = 0;
    uint32_t  tail = 0;

    if (!file)
        return FAT_ERROR;
    fs = file->fs;

    if (!(file->flags & FAT_OPEN_WRITE)) {
        fat_set_warning(fs, "the file was not opened for writing");
        return FAT_ERROR;
    }
    if (size > 0xFFFFFFFFu) {
        fat_set_warning(fs, "FAT files cannot exceed 4 GiB");
        return FAT_ERROR;
    }

    bpc    = fs->bytes_per_cluster;
    needed = (uint32_t)((size + bpc - 1) / bpc);

    if (size == 0) {
        if (fat_cluster_valid(fs, file->de.first_cluster)) {
            if (fat_chain_free(fs, file->de.first_cluster) != FAT_SUCCESS)
                return FAT_ERROR;
        }
        file->de.first_cluster = 0;
        file->de.size          = 0;
        file->pos              = 0;
        stamp_now(&file->de);
        return fat_dir_update(&file->dir, &file->de);
    }

    if (!fat_cluster_valid(fs, file->de.first_cluster)) {
        uint32_t fresh;
        if (fat_alloc_cluster(fs, &fresh) != FAT_SUCCESS)
            return FAT_ERROR;
        file->de.first_cluster = fresh;
        tail = fresh;
        have = 1;
    } else {
        uint32_t count = 0;
        if (fat_chain_walk(fs, file->de.first_cluster, &count, &tail)
            != FAT_SUCCESS)
            return FAT_ERROR;
        have = count;
    }

    /* Extend the chain so that its capacity matches the requested size. */
    while (have < needed) {
        uint32_t fresh;
        if (fat_chain_append(fs, tail, &fresh) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_zero(fs, fresh) != FAT_SUCCESS)
            return FAT_ERROR;
        tail = fresh;
        have++;
    }

    /* Shrink: cut the chain and release the remainder. */
    if (have > needed) {
        uint32_t cut = 0;
        if (fat_chain_cluster_at(fs, file->de.first_cluster, needed - 1, 0,
                                 &cut, NULL) != FAT_SUCCESS)
            return FAT_ERROR;
        {
            uint32_t next;
            if (fat_fat_get(fs, cut, &next) != FAT_SUCCESS)
                return FAT_ERROR;
            if (fat_fat_set(fs, cut, FAT_CLUSTER_EOC) != FAT_SUCCESS)
                return FAT_ERROR;
            if (!fat_cluster_is_eoc(next) && fat_cluster_valid(fs, next)) {
                if (fat_chain_free(fs, next) != FAT_SUCCESS)
                    return FAT_ERROR;
            }
        }
    }

    /* Growing a file exposes bytes that are inside an existing cluster and
     * were only ever written as an older, longer version of the file, so the
     * tail of the last old cluster is zeroed explicitly.  (Clusters added to
     * the chain were zeroed as they were allocated.) */
    if (size > file->de.size && file->de.size % bpc != 0) {
        uint32_t index  = (uint32_t)(file->de.size / bpc);
        uint32_t within = (uint32_t)(file->de.size % bpc);
        uint32_t cluster = 0;

        if (fat_chain_cluster_at(fs, file->de.first_cluster, index, 0,
                                 &cluster, NULL) != FAT_SUCCESS)
            return FAT_ERROR;

        {
            uint8_t *buf = (uint8_t *)malloc(bpc);
            uint64_t upto;

            if (!buf) {
                fat_set_warning(fs, "out of memory zeroing the extension");
                return FAT_ERROR;
            }
            if (fat_cluster_read(fs, cluster, buf) != FAT_SUCCESS) {
                free(buf);
                return FAT_ERROR;
            }
            upto = size - (uint64_t)index * bpc;
            if (upto > bpc)
                upto = bpc;
            memset(buf + within, 0, (size_t)(upto - within));
            if (fat_cluster_write(fs, cluster, buf) != FAT_SUCCESS) {
                free(buf);
                return FAT_ERROR;
            }
            free(buf);
        }
    }

    file->de.size = (uint32_t)size;
    if (file->pos > size)
        file->pos = size;
    stamp_now(&file->de);
    return fat_dir_update(&file->dir, &file->de);
}

/* ==========================================================================
 *  Namespace operations
 * ========================================================================== */

static int remove_path(fat_fs_t *fs, const char *path, int respect_read_only)
{
    fat_dir_t    parent;
    char         leaf[FAT_NAME_MAX];
    fat_dirent_t de;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (walk_path(fs, path, &de, NULL, &parent, leaf, sizeof leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_lookup(&parent, leaf, &de) != FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' does not exist", path);
        return FAT_ERROR;
    }
    if (de.attr & FAT_ATTR_DIRECTORY) {
        fat_set_warning(fs, "'%s' is a directory (use rmdir)", path);
        return FAT_ERROR;
    }
    if (respect_read_only && (de.attr & FAT_ATTR_READ_ONLY)) {
        fat_set_warning(fs, "'%s' is read-only", path);
        return FAT_ERROR;
    }

    if (fat_dir_delete(&parent, &de) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_cluster_valid(fs, de.first_cluster) &&
        fat_chain_free(fs, de.first_cluster) != FAT_SUCCESS)
        return FAT_ERROR;
    return FAT_SUCCESS;
}

int fat_remove(fat_fs_t *fs, const char *path)
{
    return remove_path(fs, path, 1);
}

int fat_rename(fat_fs_t *fs, const char *old_path, const char *new_path)
{
    char         old_norm[FAT_PATH_MAX];
    char         new_norm[FAT_PATH_MAX];
    char         old_dir[FAT_PATH_MAX], new_dir[FAT_PATH_MAX];
    char         old_leaf[FAT_NAME_MAX], new_leaf[FAT_NAME_MAX];
    fat_dir_t    parent;
    fat_dirent_t de;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (!fat_path_normalize(old_path, old_norm, sizeof old_norm) ||
        !fat_path_normalize(new_path, new_norm, sizeof new_norm)) {
        fat_set_warning(fs, "path is too long or malformed");
        return FAT_ERROR;
    }
    if (fat_path_split(old_norm, old_dir, sizeof old_dir,
                       old_leaf, sizeof old_leaf) != FAT_SUCCESS ||
        fat_path_split(new_norm, new_dir, sizeof new_dir,
                       new_leaf, sizeof new_leaf) != FAT_SUCCESS) {
        fat_set_warning(fs, "cannot split the given paths");
        return FAT_ERROR;
    }
    if (strcmp(old_dir, new_dir) != 0) {
        fat_set_warning(fs, "rename cannot change directories; use move");
        return FAT_ERROR;
    }

    if (walk_path(fs, old_norm, &de, NULL, &parent, old_leaf, sizeof old_leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_lookup(&parent, old_leaf, &de) != FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' does not exist", old_path);
        return FAT_ERROR;
    }
    return fat_dir_rename(&parent, &de, new_leaf, NULL);
}

/* Does the directory at @cluster appear at or above @path?  Used to reject
 * moving a directory into its own subtree. */
static int path_contains_cluster(fat_fs_t *fs, const char *path,
                                 uint32_t cluster, int *found)
{
    char        norm[FAT_PATH_MAX];
    fat_dir_t   dir;
    const char *p;

    *found = 0;
    if (!fat_path_normalize(path, norm, sizeof norm))
        return FAT_ERROR;
    if (fat_dir_open(fs, 0, &dir) != FAT_SUCCESS)
        return FAT_ERROR;

    if (cluster != 0 && dir.first_cluster == cluster) {
        *found = 1;
        return FAT_SUCCESS;
    }

    p = norm;
    while (*p) {
        char         comp[FAT_NAME_MAX];
        size_t       len = 0;
        fat_dirent_t child;
        uint32_t     next = 0;

        while (*p == '/')
            p++;
        if (!*p)
            break;
        while (*p && *p != '/' && len < sizeof comp - 1)
            comp[len++] = *p++;
        comp[len] = '\0';

        if (fat_dir_lookup(&dir, comp, &child) != FAT_SUCCESS)
            return FAT_SUCCESS;              /* does not exist yet: fine */
        if (!(child.attr & FAT_ATTR_DIRECTORY))
            return FAT_SUCCESS;
        if (descend(fs, &child, &next, comp) != FAT_SUCCESS)
            return FAT_ERROR;
        if (next == cluster) {
            *found = 1;
            return FAT_SUCCESS;
        }
        if (fat_dir_open(fs, next, &dir) != FAT_SUCCESS)
            return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

/* Relocate a directory entry into a different directory and repair "..". */
static int move_directory(fat_fs_t *fs, const fat_dirent_t *de,
                          fat_dir_t *dest, const char *new_name)
{
    fat_dirent_t fresh;
    fat_dir_t    moved;
    uint8_t      raw[2 * FAT_DIRENT_SIZE];
    uint32_t     want;

    fresh = *de;
    fresh.lfn_slots = 0;
    if (fat_dir_insert(dest, new_name, &fresh) != FAT_SUCCESS)
        return FAT_ERROR;

    /* Every directory starts with "." and "..", so repairing the parent
     * reference means rewriting slot 1. */
    if (fat_dir_open(fs, de->first_cluster, &moved) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_read_raw(&moved, 0, raw, 2) != FAT_SUCCESS)
        return FAT_ERROR;

    if (raw[0] != '.' || raw[FAT_DIRENT_SIZE] != '.' ||
        raw[FAT_DIRENT_SIZE + 1] != '.') {
        fat_set_warning(fs, "the directory being moved has no \"..\" entry "
                            "where the specification requires it");
        return FAT_ERROR;
    }

    /* ".." points at the new parent; 0 when that parent is a FAT12/16 root. */
    want = fat_cluster_valid(fs, dest->first_cluster) ? dest->first_cluster : 0;
    fat_wr16(raw + FAT_DIRENT_SIZE + 20, (uint16_t)((want >> 16) & 0xFFFFu));
    fat_wr16(raw + FAT_DIRENT_SIZE + 26, (uint16_t)(want & 0xFFFFu));

    if (fat_dir_write_raw(&moved, FAT_DIRENT_SIZE, raw + FAT_DIRENT_SIZE, 1)
        != FAT_SUCCESS)
        return FAT_ERROR;

    return fat_dir_flush(&moved);
}

int fat_move(fat_fs_t *fs, const char *old_path, const char *new_path)
{
    char      old_norm[FAT_PATH_MAX];
    char      new_norm[FAT_PATH_MAX];
    char      old_dir[FAT_PATH_MAX], new_dir[FAT_PATH_MAX];
    char      old_leaf[FAT_NAME_MAX], new_leaf[FAT_NAME_MAX];
    fat_dir_t src_parent, dst_parent;
    char      src_leaf[FAT_NAME_MAX];
    fat_dirent_t de;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (!fat_path_normalize(old_path, old_norm, sizeof old_norm) ||
        !fat_path_normalize(new_path, new_norm, sizeof new_norm)) {
        fat_set_warning(fs, "path is too long or malformed");
        return FAT_ERROR;
    }
    if (fat_path_split(old_norm, old_dir, sizeof old_dir,
                       old_leaf, sizeof old_leaf) != FAT_SUCCESS ||
        fat_path_split(new_norm, new_dir, sizeof new_dir,
                       new_leaf, sizeof new_leaf) != FAT_SUCCESS) {
        fat_set_warning(fs, "cannot split the given paths");
        return FAT_ERROR;
    }

    if (strcmp(old_dir, new_dir) == 0)
        return fat_rename(fs, old_norm, new_norm);

    if (walk_path(fs, old_norm, &de, NULL, &src_parent, src_leaf,
                  sizeof src_leaf) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_lookup(&src_parent, src_leaf, &de) != FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' does not exist", old_path);
        return FAT_ERROR;
    }
    if (walk_path(fs, new_norm, &de, NULL, &dst_parent, new_leaf,
                  sizeof new_leaf) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_lookup(&dst_parent, new_leaf, &de) == FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' already exists", new_path);
        return FAT_ERROR;
    }
    if (fat_dir_lookup(&src_parent, src_leaf, &de) != FAT_SUCCESS)
        return FAT_ERROR;

    if (de.attr & FAT_ATTR_DIRECTORY) {
        int contains = 0;

        if (path_contains_cluster(fs, new_norm, de.first_cluster, &contains)
            != FAT_SUCCESS)
            return FAT_ERROR;
        if (contains) {
            fat_set_warning(fs, "cannot move a directory into itself");
            return FAT_ERROR;
        }
        if (move_directory(fs, &de, &dst_parent, new_leaf) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_dir_delete(&src_parent, &de) != FAT_SUCCESS)
            return FAT_ERROR;
        return FAT_SUCCESS;
    }

    /* Files are relocated by copying, then removing the original.  A
     * read-only file may be moved: the attribute protects the contents, not
     * the location, and the copy preserves the attribute. */
    if (fat_copy(fs, old_norm, new_norm) != FAT_SUCCESS)
        return FAT_ERROR;
    if (remove_path(fs, old_norm, 0) != FAT_SUCCESS) {
        (void)remove_path(fs, new_norm, 0);
        return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

int fat_copy(fat_fs_t *fs, const char *src_path, const char *dest_path)
{
    fat_dirent_t  de;
    fat_file_t   *src = NULL;
    fat_file_t   *dst = NULL;
    uint8_t       buf[32u * 1024u];
    int           rc = FAT_ERROR;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (resolve(fs, src_path, &de) != FAT_SUCCESS)
        return FAT_ERROR;
    if (de.attr & FAT_ATTR_DIRECTORY) {
        fat_set_warning(fs, "copying directories is not supported");
        return FAT_ERROR;
    }

    if (fat_open(fs, src_path, FAT_OPEN_READ, &src) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_open(fs, dest_path,
                 FAT_OPEN_WRITE | FAT_OPEN_CREATE | FAT_OPEN_TRUNCATE,
                 &dst) != FAT_SUCCESS)
        goto out;

    for (;;) {
        int got = fat_read(src, buf, (uint32_t)sizeof buf);
        if (got == FAT_ERROR)
            goto out;
        if (got == 0)
            break;
        {
            uint32_t done = 0;
            if (fat_write_full(dst, buf, (uint32_t)got, &done) != FAT_SUCCESS)
                goto out;
            if (done != (uint32_t)got) {
                fat_set_warning(fs, "short write while copying '%s'",
                                dest_path);
                goto out;
            }
        }
    }
    rc = FAT_SUCCESS;

out:
    if (src)
        (void)fat_close(src);
    if (dst) {
        if (fat_close(dst) != FAT_SUCCESS)
            rc = FAT_ERROR;
    }
    if (rc != FAT_SUCCESS) {
        fat_dirent_t probe;
        if (walk_path(fs, dest_path, &probe, NULL, NULL, NULL, 0)
            == FAT_SUCCESS)
            /* Best effort: do not leave a half-written destination behind. */
            (void)remove_path(fs, dest_path, 0);
        return FAT_ERROR;
    }

    /* The copy carries the source's attributes (hidden/system/read-only and
     * the archive flag), which is what every other FAT tool does. */
    (void)fat_setattr(fs, dest_path, de.attr);
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Metadata
 * ========================================================================== */

int fat_getattr(fat_fs_t *fs, const char *path, fat_dirent_t *out)
{
    if (!fs || !out)
        return FAT_ERROR;
    return resolve(fs, path, out);
}

int fat_setattr(fat_fs_t *fs, const char *path, uint8_t attr)
{
    fat_dir_t    parent;
    char         leaf[FAT_NAME_MAX];
    fat_dirent_t de;

    if (!fs || fs->read_only)
        return FAT_ERROR;

    if (walk_path(fs, path, &de, NULL, &parent, leaf, sizeof leaf)
        != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_dir_lookup(&parent, leaf, &de) != FAT_SUCCESS) {
        fat_set_warning(fs, "'%s' does not exist", path);
        return FAT_ERROR;
    }

    /* Only the attribute bits, and never the volume-id or LFN markers. */
    attr &= FAT_ATTR_MASK;
    if (attr & FAT_ATTR_VOLUME_ID) {
        fat_set_warning(fs, "the volume-id attribute cannot be set here");
        return FAT_ERROR;
    }
    /* The directory bit must keep matching what the entry actually is. */
    if (de.attr & FAT_ATTR_DIRECTORY)
        attr |= FAT_ATTR_DIRECTORY;
    else
        attr &= (uint8_t)~FAT_ATTR_DIRECTORY;

    de.attr = attr;
    return fat_dir_update(&parent, &de);
}

int fat_is_directory(fat_fs_t *fs, const char *path, int *out)
{
    fat_dirent_t de;

    if (!fs || !out)
        return FAT_ERROR;
    if (resolve(fs, path, &de) != FAT_SUCCESS)
        return FAT_ERROR;
    *out = (de.attr & FAT_ATTR_DIRECTORY) ? 1 : 0;
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Consistency checking
 * ========================================================================== */

#define CHECK_MAX_DEPTH 64

typedef struct {
    fat_fs_t    *fs;
    fat_check_t *rep;
    uint8_t     *marks;        /* 1 byte per cluster: 0 free, 1 used, 2 walking */
    uint32_t     mark_count;
    void       (*log)(void *ctx, const char *line);
    void        *log_ctx;
    int          repair;
    int          depth_limit_hit;
} check_state_t;

static void check_log(check_state_t *st, const char *fmt, ...)
{
    char    line[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);

    if (st->log)
        st->log(st->log_ctx, line);
}

static void check_error(check_state_t *st, const char *fmt, ...)
{
    char    line[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);

    st->rep->errors++;
    if (st->log)
        st->log(st->log_ctx, line);
}

static int mark_of(check_state_t *st, uint32_t cluster)
{
    uint32_t idx;
    if (cluster < FAT_CLUSTER_FIRST || cluster > st->fs->max_cluster)
        return -1;
    idx = cluster - FAT_CLUSTER_FIRST;
    if (idx >= st->mark_count)
        return -1;
    return st->marks[idx];
}

static void set_mark(check_state_t *st, uint32_t cluster, uint8_t value)
{
    uint32_t idx = cluster - FAT_CLUSTER_FIRST;
    if (idx < st->mark_count)
        st->marks[idx] = value;
}

/* Walk one cluster chain, marking clusters and reporting structural damage.
 * Returns the cluster count, or FAT_ERROR. */
static uint32_t check_chain(check_state_t *st, uint32_t first,
                            const char *owner, uint32_t expected_clusters,
                            int is_directory)
{
    fat_fs_t *fs = st->fs;
    uint32_t  c = first;
    uint32_t  count = 0;
    int       damaged = 0;

    for (;;) {
        int mark = mark_of(st, c);

        if (mark < 0) {
            check_error(st, "%s: cluster %u is outside the data area",
                        owner, c);
            damaged = 1;
            break;
        }
        if (mark == 2) {
            check_error(st, "%s: cluster chain loops back to cluster %u",
                        owner, c);
            st->rep->loops++;
            damaged = 1;
            break;
        }
        if (mark == 1) {
            check_error(st, "%s: cluster %u is cross-linked (already used by "
                            "another chain)", owner, c);
            st->rep->cross_linked_clusters++;
            damaged = 1;
            break;
        }

        set_mark(st, c, 2);
        count++;
        st->rep->clusters_in_use++;

        {
            uint32_t next;
            if (fat_fat_get(fs, c, &next) != FAT_SUCCESS) {
                check_error(st, "%s: cannot read the FAT entry of cluster %u",
                            owner, c);
                damaged = 1;
                break;
            }
            if (fat_cluster_is_eoc(next))
                break;
            if (fat_cluster_is_free(next)) {
                check_error(st, "%s: cluster %u is followed by a free entry "
                                "(chain is not terminated)", owner, c);
                damaged = 1;
                break;
            }
            if (fat_cluster_is_bad(next)) {
                check_error(st, "%s: cluster %u points at a cluster marked bad",
                            owner, c);
                damaged = 1;
                break;
            }
            c = next;
        }
    }

    /* Promote the marks of this chain from "walking" to "used". */
    {
        uint32_t  cc = first;
        uint32_t  guard = count + 1;
        while (guard--) {
            if (mark_of(st, cc) != 2)
                break;
            set_mark(st, cc, 1);
            {
                uint32_t next;
                if (fat_fat_get(fs, cc, &next) != FAT_SUCCESS)
                    break;
                if (fat_cluster_is_eoc(next) || fat_cluster_is_free(next) ||
                    fat_cluster_is_bad(next))
                    break;
                cc = next;
            }
        }
    }

    /* A file whose recorded size needs more clusters than the chain holds is
     * truncated: that is the one repair that cannot lose data. */
    if (!is_directory && expected_clusters && count < expected_clusters) {
        st->rep->size_mismatches++;
        check_error(st, "%s: size needs %u clusters but the chain has %u",
                    owner, expected_clusters, count);
    } else if (!is_directory && expected_clusters && count > expected_clusters) {
        st->rep->size_mismatches++;
        check_log(st, "%s: %u clusters allocated for %u clusters of data",
                  owner, count, expected_clusters);
    }

    (void)damaged;
    return count;
}

static int check_directory(check_state_t *st, uint32_t first_cluster,
                           const char *path, int depth);

typedef struct {
    check_state_t *st;
    fat_dir_t     *dir;      /* the directory this entry lives in */
    const char    *path;
    int            depth;
} check_ctx_t;

static int check_entry_cb(const fat_dirent_t *de, void *vctx)
{
    check_ctx_t *c  = (check_ctx_t *)vctx;
    check_state_t *st = c->st;
    fat_fs_t      *fs = st->fs;
    char           full[FAT_PATH_MAX];

    if (de->name[0] == '\0') {
        /* A blank name cannot be addressed and must never be descended into. */
        st->rep->invalid_entries++;
        check_error(st, "%s: an entry with an empty name", c->path);
        return 0;
    }

    snprintf(full, sizeof full, "%s%s%s", c->path,
             (strcmp(c->path, "/") == 0) ? "" : "/", de->name);

    if (de->attr & FAT_ATTR_DIRECTORY) {
        st->rep->directories++;
        if (de->size != 0)
            check_log(st, "%s: a directory with a non-zero size (%u)",
                      full, de->size);
        if (!fat_cluster_valid(fs, de->first_cluster)) {
            /* Every directory except the root owns a cluster. */
            check_error(st, "%s: directory with invalid first cluster %u",
                        full, de->first_cluster);
            st->rep->invalid_entries++;
            return 0;
        }
        if (check_directory(st, de->first_cluster, full, c->depth + 1)
            != FAT_SUCCESS)
            return 1;
        return 0;
    }

    st->rep->files++;

    if (de->first_cluster == 0) {
        if (de->size != 0) {
            check_error(st, "%s: size %u but no cluster allocated", full,
                        de->size);
            st->rep->invalid_entries++;
        }
        return 0;
    }

    if (!fat_cluster_valid(fs, de->first_cluster)) {
        check_error(st, "%s: invalid first cluster %u", full,
                    de->first_cluster);
        st->rep->invalid_entries++;
        return 0;
    }

    st->rep->chains++;
    {
        uint32_t bpc  = fs->bytes_per_cluster;
        uint32_t want = (de->size + bpc - 1) / bpc;
        uint32_t have = check_chain(st, de->first_cluster, full, want, 0);

        /* A size that needs more clusters than the chain supplies is a lie the
         * volume cannot support.  The data that exists is all there is, so the
         * recorded size is shortened to what the chain actually holds.  This
         * is the same repair fsck.fat applies, and it loses no data. */
        if (st->repair && !fs->read_only && want > 0 && have < want) {
            fat_dirent_t fixed = *de;

            fixed.size = have * bpc;
            if (fat_dir_update(c->dir, &fixed) == FAT_SUCCESS)
                check_log(st, "%s: size shortened to %u bytes to match its "
                              "%u-cluster chain", full, fixed.size, have);
            else
                check_error(st, "%s: could not shorten the size", full);
        }
    }
    return 0;
}

static int check_directory(check_state_t *st, uint32_t first_cluster,
                           const char *path, int depth)
{
    fat_fs_t     *fs = st->fs;
    fat_dir_t     dir;
    check_ctx_t   ctx;
    int           rc;

    if (depth > CHECK_MAX_DEPTH) {
        if (!st->depth_limit_hit) {
            check_error(st, "the directory tree is deeper than %d levels",
                        CHECK_MAX_DEPTH);
            st->depth_limit_hit = 1;
        }
        return FAT_SUCCESS;
    }

    /* A directory always owns its cluster chain - including the root on
     * FAT32, whose chain would otherwise look like a lost chain.  The chain
     * is accounted for here; check_entry_cb already counted the directory. */
    if (fat_cluster_valid(fs, first_cluster))
        check_chain(st, first_cluster, path, 0, 1);

    if (fat_dir_open(fs, first_cluster, &dir) != FAT_SUCCESS)
        return FAT_ERROR;

    ctx.st    = st;
    ctx.dir   = &dir;
    ctx.path  = path;
    ctx.depth = depth;

    rc = fat_dir_iterate(&dir, check_entry_cb, &ctx);
    fat_dir_discard(&dir);
    return (rc == FAT_ERROR) ? FAT_ERROR : FAT_SUCCESS;
}

int fat_check(fat_fs_t *fs, fat_check_t *out, int repair,
              void (*log)(void *ctx, const char *line), void *ctx)
{
    check_state_t st;
    fat_check_t   rep;
    uint32_t      c;
    uint32_t      free_count = 0, bad_count = 0;
    uint32_t      orphan = 0, lost = 0;
    int           rc = FAT_SUCCESS;

    if (!fs || !out)
        return FAT_ERROR;

    memset(&rep, 0, sizeof rep);
    memset(&st, 0, sizeof st);
    st.fs       = fs;
    st.rep      = &rep;
    st.log      = log;
    st.log_ctx  = ctx;
    st.repair   = repair ? 1 : 0;

    st.mark_count = fs->cluster_count;
    st.marks      = (uint8_t *)calloc(st.mark_count ? st.mark_count : 1, 1);
    if (!st.marks) {
        fat_set_warning(fs, "out of memory for the cluster bitmap");
        return FAT_ERROR;
    }

    /* --- FAT copies must agree ------------------------------------------ */
    if (fs->num_fats > 1) {
        uint8_t a[FAT_MAX_SECTOR_SIZE], b[FAT_MAX_SECTOR_SIZE];
        for (uint32_t s = 0; s < fs->sectors_per_fat; s++) {
            if (fat_sector_read(fs, fs->fat_start_sector + s, a)
                != FAT_SUCCESS)
                break;
            for (uint32_t copy = 1; copy < fs->num_fats; copy++) {
                uint32_t target = fs->fat_start_sector + s +
                                  copy * fs->sectors_per_fat;
                if (fat_sector_read(fs, target, b) != FAT_SUCCESS)
                    break;
                if (memcmp(a, b, fs->bytes_per_sector) != 0) {
                    rep.fat_mismatches++;
                    if (rep.fat_mismatches == 1)
                        check_log(&st, "FAT copy %u differs from copy 1 at "
                                       "sector %u", copy + 1u, s);
                }
            }
        }
        if (rep.fat_mismatches) {
            rep.errors += rep.fat_mismatches;
            if (repair && !fs->read_only) {
                (void)fat_fat_mirror(fs);
                check_log(&st, "repaired: FAT copies mirrored from copy 1");
            }
        }
    }

    /* --- the two reserved FAT entries ----------------------------------- */
    {
        uint32_t e0 = 0, e1 = 0;
        if (fat_fat_get(fs, 0, &e0) == FAT_SUCCESS &&
            fat_fat_get(fs, 1, &e1) == FAT_SUCCESS) {
            uint8_t want_media = fs->bpb.media_descriptor;
            uint8_t got_media;
            switch (fs->fat_type) {
            case FAT_TYPE_FAT12: got_media = (uint8_t)(e0 & 0xFFu); break;
            case FAT_TYPE_FAT16: got_media = (uint8_t)(e0 & 0xFFu); break;
            default:             got_media = (uint8_t)(e0 & 0xFFu); break;
            }
            if (got_media != want_media)
                check_log(&st, "FAT[0] media byte is 0x%02X but the BPB says "
                               "0x%02X", got_media, want_media);
            if (!fat_cluster_is_eoc(e1))
                check_log(&st, "FAT[1] is 0x%08X (expected an end-of-chain "
                               "marker)", e1);
        }
    }

    /* --- walk the directory tree ---------------------------------------- */
    /* The root directory has no cluster of its own on FAT12/16 (it lives in
     * the fixed root region), but on FAT32 it is an ordinary cluster chain and
     * has to be walked like any other directory - otherwise its own clusters
     * are reported as orphans. */
    {
        uint32_t root_first = 0;

        if (fs->fat_type == FAT_TYPE_FAT32 &&
            fat_cluster_valid(fs, fs->bpb.root_cluster))
            root_first = fs->bpb.root_cluster;
        else if (fs->fat_type == FAT_TYPE_FAT32)
            root_first = FAT_CLUSTER_FIRST;

        if (check_directory(&st, root_first, "/", 0) != FAT_SUCCESS) {
            rc = FAT_ERROR;
            check_error(&st, "the directory tree could not be walked");
        }
    }

    /* --- classify every cluster ----------------------------------------- */
    for (c = FAT_CLUSTER_FIRST; c <= fs->max_cluster; c++) {
        uint32_t value;
        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            break;
        if (fat_cluster_is_free(value)) {
            free_count++;
            continue;
        }
        if (fat_cluster_is_bad(value)) {
            bad_count++;
            continue;
        }
        if (mark_of(&st, c) == 0) {
            orphan++;
            if (fat_cluster_is_eoc(value))
                lost++;
        }
    }

    rep.free_clusters = free_count;
    rep.bad_clusters  = bad_count;
    rep.orphan_clusters = orphan;
    rep.lost_chains     = lost;

    if (orphan) {
        check_log(&st, "%u clusters are allocated but not reachable from any "
                       "directory (%u chain heads)", orphan, lost);
        rep.errors += lost ? lost : 1;
    }

    /* --- FSInfo --------------------------------------------------------- */
    if (fs->fat_type == FAT_TYPE_FAT32 && fs->info_sector) {
        uint32_t stored = fs->free_clusters;
        if (stored != FAT_FSINFO_UNKNOWN && stored != free_count) {
            rep.fs_info_wrong = 1;
            check_log(&st, "FSInfo records %u free clusters but %u are free",
                      stored, free_count);
            if (repair && !fs->read_only) {
                fs->free_clusters = free_count;
                if (fat_fsinfo_update(fs) == FAT_SUCCESS)
                    check_log(&st, "repaired: FSInfo free count updated");
            }
        }
    }

    /* --- clean shutdown flag -------------------------------------------- */
    {
        int clean = 0;
        if (fat_is_clean(fs, &clean) == FAT_SUCCESS) {
            rep.was_clean = clean;
            if (!clean)
                check_log(&st, "the volume was not unmounted cleanly");
        } else {
            rep.was_clean = 1;
        }
    }

    free(st.marks);

    rep.clusters_in_use = fs->cluster_count - free_count - bad_count - orphan;
    *out = rep;
    return rc;
}
