/* ==========================================================================
 *  fat_core.c - mount/geometry validation and the FAT table engine
 *
 *  Everything in this file follows "FAT: General Overview of On-Disk Format"
 *  rev 1.02 and the "FAT32 File System Specification" rev 1.03.  Field offsets
 *  and the FAT12/16/32 entry encodings are cited inline.
 * ========================================================================== */

#include "fat_core.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ==========================================================================
 *  Boot sector parsing / formatting
 * ========================================================================== */

void fat_bpb_parse(const uint8_t *sector, fat_bpb_t *bpb)
{
    /* The fields that exist on every FAT flavour. */
    memset(bpb, 0, sizeof *bpb);

    bpb->bytes_per_sector     = fat_rd16(sector + FAT_BPB_BYTES_PER_SECTOR);
    bpb->sectors_per_cluster  = sector[FAT_BPB_SECTORS_PER_CLUSTER];
    bpb->reserved_sectors     = fat_rd16(sector + FAT_BPB_RESERVED_SECTORS);
    bpb->num_fats             = sector[FAT_BPB_NUM_FATS];
    bpb->root_entries         = fat_rd16(sector + FAT_BPB_ROOT_ENTRIES);
    bpb->total_sectors16      = fat_rd16(sector + FAT_BPB_TOTAL_SECTORS16);
    bpb->media_descriptor     = sector[FAT_BPB_MEDIA_DESCRIPTOR];
    bpb->sectors_per_fat16    = fat_rd16(sector + FAT_BPB_SECTORS_PER_FAT16);
    bpb->sectors_per_track    = fat_rd16(sector + FAT_BPB_SECTORS_PER_TRACK);
    bpb->num_heads            = fat_rd16(sector + FAT_BPB_NUM_HEADS);
    bpb->hidden_sectors       = fat_rd32(sector + FAT_BPB_HIDDEN_SECTORS);
    bpb->total_sectors32      = fat_rd32(sector + FAT_BPB_TOTAL_SECTORS32);

    /* A FAT32 volume always has a cluster-based root directory, so an empty
     * root_entries field is what tells the two layouts apart. */
    if (bpb->root_entries == 0) {
        bpb->sectors_per_fat32  = fat_rd32(sector + FAT_BPB_SECTORS_PER_FAT32);
        bpb->ext_flags          = fat_rd16(sector + FAT_BPB_EXT_FLAGS);
        bpb->fs_version         = fat_rd16(sector + FAT_BPB_FS_VERSION);
        bpb->root_cluster       = fat_rd32(sector + FAT_BPB_ROOT_CLUSTER);
        bpb->fs_info_sector     = fat_rd16(sector + FAT_BPB_FS_INFO);
        bpb->backup_boot_sector = fat_rd16(sector + FAT_BPB_BACKUP_BOOT);
        bpb->drive_number       = sector[FAT_BPB32_DRIVE_NUMBER];
        bpb->boot_signature     = sector[FAT_BPB32_BOOT_SIG];
        bpb->volume_id          = fat_rd32(sector + FAT_BPB32_VOLUME_ID);
        memcpy(bpb->volume_label, sector + FAT_BPB32_VOLUME_LABEL,
               FAT_LABEL_LEN);
        memcpy(bpb->fs_type, sector + FAT_BPB32_FS_TYPE, 8);
    } else {
        /* On FAT12/16 the bytes at 0x24.. are boot code, never a FAT size,
         * which is why they must not be interpreted as such. */
        bpb->drive_number   = sector[FAT_BPB16_DRIVE_NUMBER];
        bpb->boot_signature = sector[FAT_BPB16_BOOT_SIG];
        bpb->volume_id      = fat_rd32(sector + FAT_BPB16_VOLUME_ID);
        memcpy(bpb->volume_label, sector + FAT_BPB16_VOLUME_LABEL,
               FAT_LABEL_LEN);
        memcpy(bpb->fs_type, sector + FAT_BPB16_FS_TYPE, 8);
    }

    bpb->volume_label[FAT_LABEL_LEN] = '\0';
    bpb->fs_type[8] = '\0';

    /* Trim the space padding so the strings can be printed directly. */
    {
        int i;
        for (i = (int)FAT_LABEL_LEN - 1; i >= 0 && bpb->volume_label[i] == ' ';
             i--)
            bpb->volume_label[i] = '\0';
        for (i = 7; i >= 0 && bpb->fs_type[i] == ' '; i--)
            bpb->fs_type[i] = '\0';
    }
}

/* Write a boot sector.  The layout is chosen the same way the parser chooses
 * it: FAT32 when the root directory is cluster based. */
void fat_bpb_format(uint8_t *sector, const fat_bpb_t *bpb)
{
    int   fat32 = (bpb->root_entries == 0);
    char  label[FAT_LABEL_LEN];
    char  fstype[8];

    memset(sector, 0, FAT_SECTOR_SIZE);

    sector[0] = 0xEB;
    sector[1] = fat32 ? 0x58 : 0x3C;
    sector[2] = 0x90;
    memcpy(sector + 3, "MSWIN4.1", 8);

    fat_wr16(sector + FAT_BPB_BYTES_PER_SECTOR, bpb->bytes_per_sector);
    sector[FAT_BPB_SECTORS_PER_CLUSTER] = bpb->sectors_per_cluster;
    fat_wr16(sector + FAT_BPB_RESERVED_SECTORS, bpb->reserved_sectors);
    sector[FAT_BPB_NUM_FATS]            = bpb->num_fats;
    fat_wr16(sector + FAT_BPB_ROOT_ENTRIES, bpb->root_entries);
    fat_wr16(sector + FAT_BPB_TOTAL_SECTORS16, bpb->total_sectors16);
    sector[FAT_BPB_MEDIA_DESCRIPTOR]    = bpb->media_descriptor;
    fat_wr16(sector + FAT_BPB_SECTORS_PER_FAT16, bpb->sectors_per_fat16);
    fat_wr16(sector + FAT_BPB_SECTORS_PER_TRACK, bpb->sectors_per_track);
    fat_wr16(sector + FAT_BPB_NUM_HEADS, bpb->num_heads);
    fat_wr32(sector + FAT_BPB_HIDDEN_SECTORS, bpb->hidden_sectors);
    fat_wr32(sector + FAT_BPB_TOTAL_SECTORS32, bpb->total_sectors32);

    memset(label, ' ', sizeof label);
    if (bpb->volume_label[0])
        memcpy(label, bpb->volume_label, strlen(bpb->volume_label) < 11
                                               ? strlen(bpb->volume_label) : 11);
    memset(fstype, ' ', sizeof fstype);
    memcpy(fstype, bpb->fs_type, strlen(bpb->fs_type) < 8
                                     ? strlen(bpb->fs_type) : 8);

    if (fat32) {
        fat_wr32(sector + FAT_BPB_SECTORS_PER_FAT32, bpb->sectors_per_fat32);
        fat_wr16(sector + FAT_BPB_EXT_FLAGS, bpb->ext_flags);
        fat_wr16(sector + FAT_BPB_FS_VERSION, bpb->fs_version);
        fat_wr32(sector + FAT_BPB_ROOT_CLUSTER, bpb->root_cluster);
        fat_wr16(sector + FAT_BPB_FS_INFO, bpb->fs_info_sector);
        fat_wr16(sector + FAT_BPB_BACKUP_BOOT, bpb->backup_boot_sector);
        sector[FAT_BPB32_DRIVE_NUMBER] = bpb->drive_number;
        sector[FAT_BPB32_BOOT_SIG]     = bpb->boot_signature;
        fat_wr32(sector + FAT_BPB32_VOLUME_ID, bpb->volume_id);
        memcpy(sector + FAT_BPB32_VOLUME_LABEL, label, FAT_LABEL_LEN);
        memcpy(sector + FAT_BPB32_FS_TYPE, fstype, 8);
    } else {
        sector[FAT_BPB16_DRIVE_NUMBER] = bpb->drive_number;
        sector[FAT_BPB16_BOOT_SIG]     = bpb->boot_signature;
        fat_wr32(sector + FAT_BPB16_VOLUME_ID, bpb->volume_id);
        memcpy(sector + FAT_BPB16_VOLUME_LABEL, label, FAT_LABEL_LEN);
        memcpy(sector + FAT_BPB16_FS_TYPE, fstype, 8);
    }

    fat_wr16(sector + FAT_BOOT_SIGNATURE_OFFSET, FAT_BOOT_SIGNATURE);
}

/* ==========================================================================
 *  Small helpers
 * ========================================================================== */

const char *fat_type_name(int type)
{
    switch (type) {
    case FAT_TYPE_FAT12: return "FAT12";
    case FAT_TYPE_FAT16: return "FAT16";
    case FAT_TYPE_FAT32: return "FAT32";
    default:             return "unknown";
    }
}

uint32_t fat_sector_size(const struct fat_fs *fs) { return fs->bytes_per_sector; }

int fat_cluster_valid(const struct fat_fs *fs, uint32_t cluster)
{
    return cluster >= FAT_CLUSTER_FIRST && cluster <= fs->max_cluster;
}

int fat_cluster_is_eoc(uint32_t value)   { return value >= FAT_CLUSTER_EOC_MIN; }
int fat_cluster_is_free(uint32_t value)  { return value == FAT_CLUSTER_FREE; }
int fat_cluster_is_bad(uint32_t value)   { return value == FAT_CLUSTER_BAD; }

void fat_set_warning(struct fat_fs *fs, const char *fmt, ...)
{
    va_list ap;
    size_t  used = strlen(fs->warning);

    if (used >= sizeof fs->warning - 2)
        return;

    if (used) {
        fs->warning[used++] = '\n';
        fs->warning[used]   = '\0';
    }

    va_start(ap, fmt);
    vsnprintf(fs->warning + used, sizeof fs->warning - used, fmt, ap);
    va_end(ap);
}

static int is_power_of_two(uint32_t v) { return v != 0 && (v & (v - 1)) == 0; }

/* Defined with the clean-shutdown helpers at the end of this file. */
static int clean_bit_get(struct fat_fs *fs);

/* Defined with the file-system-info helpers at the end of this file. */
static int ensure_free_count_verified(struct fat_fs *fs);

/* ==========================================================================
 *  Raw sector I/O
 * ========================================================================== */

int fat_sector_read(struct fat_fs *fs, uint32_t sector, void *buf)
{
    uint64_t off = (uint64_t)sector * fs->bytes_per_sector;

    if (!fs->mounted) {
        fat_set_warning(fs, "sector read on an unmounted file system");
        return FAT_ERROR;
    }
    return fat_io_read(&fs->io, off, buf, fs->bytes_per_sector);
}

int fat_sector_write(struct fat_fs *fs, uint32_t sector, const void *buf)
{
    fat_core_touched(fs);
    uint64_t off = (uint64_t)sector * fs->bytes_per_sector;

    if (!fs->mounted) {
        fat_set_warning(fs, "sector write on an unmounted file system");
        return FAT_ERROR;
    }
    if (fs->read_only) {
        fat_set_warning(fs, "write attempted on a read-only mount");
        return FAT_ERROR;
    }
    return fat_io_write(&fs->io, off, buf, fs->bytes_per_sector);
}

/* ==========================================================================
 *  Mount
 * ========================================================================== */

/* Derive the geometry from an already-parsed BPB.  Returns FAT_SUCCESS and
 * fills the geometry fields, or FAT_ERROR with fs->warning set. */
static int derive_geometry(struct fat_fs *fs, int quiet)
{
    const fat_bpb_t *bpb = &fs->bpb;
    uint32_t total_sectors, data_sectors, cluster_count;
    uint32_t spf16 = bpb->sectors_per_fat16;
    uint32_t spf32 = bpb->sectors_per_fat32;
    int      looks_fat32;
    uint32_t bytes_per_cluster;

    /* --- sanity checks on the fields we are about to do arithmetic with --- */
    if (!is_power_of_two(bpb->bytes_per_sector) ||
        bpb->bytes_per_sector < FAT_MIN_SECTOR_SIZE ||
        bpb->bytes_per_sector > FAT_MAX_SECTOR_SIZE) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: bytes_per_sector = %u "
                                "(expected a power of two in [%u, %u])",
                            bpb->bytes_per_sector, FAT_MIN_SECTOR_SIZE,
                            FAT_MAX_SECTOR_SIZE);
        return FAT_ERROR;
    }

    if (!is_power_of_two(bpb->sectors_per_cluster) ||
        bpb->sectors_per_cluster == 0 ||
        bpb->sectors_per_cluster > 128) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: sectors_per_cluster = %u "
                                "(expected a power of two in [1, 128])",
                            bpb->sectors_per_cluster);
        return FAT_ERROR;
    }

    bytes_per_cluster = bpb->bytes_per_sector * bpb->sectors_per_cluster;
    if (bytes_per_cluster > 64u * 1024u) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: cluster size %u bytes exceeds "
                                "the 64 KiB maximum", bytes_per_cluster);
        return FAT_ERROR;
    }

    if (bpb->reserved_sectors == 0) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: reserved_sectors is zero");
        return FAT_ERROR;
    }

    if (bpb->num_fats == 0 || bpb->num_fats > 8) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: num_fats = %u (expected 1-8)",
                            bpb->num_fats);
        return FAT_ERROR;
    }

    total_sectors = bpb->total_sectors16 ? bpb->total_sectors16
                                         : bpb->total_sectors32;
    if (total_sectors == 0) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: total sector count is zero");
        return FAT_ERROR;
    }

    /* Which FAT flavour is this?  A FAT32 BPB has root_entries == 0 and uses
     * the 32-bit sectors_per_fat field at offset 0x24.  On FAT12/16 that
     * offset is part of the boot code, so its contents must never be
     * interpreted as a FAT size. */
    looks_fat32 = (bpb->root_entries == 0);

    if (looks_fat32) {
        if (spf32 == 0) {
            if (spf16 != 0) {
                spf32 = spf16;    /* tolerated: some tools only set 0x16 */
                if (!quiet)
                    fat_set_warning(fs, "warning: FAT32 volume with a zero "
                                        "sectors_per_fat at 0x24; using the "
                                        "16-bit field (%u)", spf16);
            } else {
                if (!quiet)
                    fat_set_warning(fs, "invalid BPB: no FAT size given");
                return FAT_ERROR;
            }
        }
        if (bpb->fs_info_sector == 0) {
            if (!quiet)
                fat_set_warning(fs, "warning: FAT32 volume without an FSInfo "
                                    "sector");
        }
    } else {
        if (spf16 == 0) {
            if (!quiet)
                fat_set_warning(fs, "invalid BPB: sectors_per_fat is zero");
            return FAT_ERROR;
        }
        spf32 = 0;
    }

    /* --- derived geometry --- */
    {
        uint32_t spf = looks_fat32 ? spf32 : spf16;
        uint64_t root_dir_bytes = (uint64_t)bpb->root_entries * FAT_DIRENT_SIZE;
        uint64_t root_dir_secs  = (root_dir_bytes + bpb->bytes_per_sector - 1)
                                  / bpb->bytes_per_sector;
        uint64_t root_start, data_start;

        fs->bytes_per_sector    = bpb->bytes_per_sector;
        fs->sectors_per_cluster = bpb->sectors_per_cluster;
        fs->bytes_per_cluster   = bytes_per_cluster;
        fs->num_fats            = bpb->num_fats;
        fs->reserved_sectors    = bpb->reserved_sectors;
        fs->root_entries        = bpb->root_entries;
        fs->root_dir_sectors    = (uint32_t)root_dir_secs;
        fs->sectors_per_fat     = spf;
        fs->total_sectors       = total_sectors;
        fs->fat_start_sector    = bpb->reserved_sectors;

        root_start = (uint64_t)bpb->reserved_sectors +
                     (uint64_t)bpb->num_fats * spf;
        data_start = root_start + root_dir_secs;

        if (root_start >= total_sectors) {
            if (!quiet)
                fat_set_warning(fs, "invalid BPB: the FAT region (%llu sectors)"
                                    " does not fit in %u total sectors",
                                (unsigned long long)root_start, total_sectors);
            return FAT_ERROR;
        }
        if (data_start >= total_sectors) {
            if (!quiet)
                fat_set_warning(fs, "invalid BPB: the data region starts at "
                                    "sector %llu but the volume is only %u "
                                    "sectors long",
                                (unsigned long long)data_start, total_sectors);
            return FAT_ERROR;
        }

        fs->root_dir_start_sector = (uint32_t)root_start;
        fs->data_start_sector     = (uint32_t)data_start;

        data_sectors  = total_sectors - (uint32_t)data_start;
        cluster_count = data_sectors / bpb->sectors_per_cluster;
    }

    if (cluster_count < 1) {
        if (!quiet)
            fat_set_warning(fs, "invalid BPB: the volume has no data clusters");
        return FAT_ERROR;
    }

    /* The cluster count - not the BPB's own label - defines the type. */
    if (cluster_count < FAT12_MAX_CLUSTERS)
        fs->fat_type = FAT_TYPE_FAT12;
    else if (cluster_count < FAT16_MAX_CLUSTERS)
        fs->fat_type = FAT_TYPE_FAT16;
    else
        fs->fat_type = FAT_TYPE_FAT32;

    if ((fs->fat_type == FAT_TYPE_FAT32) != (looks_fat32 != 0)) {
        if (!quiet)
            fat_set_warning(fs, "warning: the BPB fields suggest %s but the "
                                "volume has %u clusters, which makes it %s",
                            looks_fat32 ? "FAT32" : "FAT12/16",
                            cluster_count, fat_type_name(fs->fat_type));
    }

    /* Cluster ids run from 2 to cluster_count + 1. */
    fs->cluster_count = cluster_count;
    fs->max_cluster   = cluster_count + 1;

    /* The FAT must be large enough to hold an entry per cluster (plus the two
     * reserved entries).  A short FAT is the classic cause of the "cluster
     * number walks off the end of the table" bug. */
    {
        uint64_t fat_bytes    = (uint64_t)fs->sectors_per_fat *
                                fs->bytes_per_sector;
        uint64_t needed_entries = (uint64_t)cluster_count + 2;
        uint64_t capacity;

        switch (fs->fat_type) {
        case FAT_TYPE_FAT12: capacity = fat_bytes * 2u / 3u; break;
        case FAT_TYPE_FAT16: capacity = fat_bytes / 2u;      break;
        default:             capacity = fat_bytes / 4u;      break;
        }

        if (capacity < needed_entries) {
            if (!quiet)
                fat_set_warning(fs, "invalid BPB: a %u-sector %s FAT holds "
                                    "%llu entries but %llu are required",
                                fs->sectors_per_fat,
                                fat_type_name(fs->fat_type),
                                (unsigned long long)capacity,
                                (unsigned long long)needed_entries);
            return FAT_ERROR;
        }
    }

    /* Cross-check the volume against the device size when it is known. */
    if (fs->device_size > 0) {
        uint64_t claimed = (uint64_t)total_sectors * fs->bytes_per_sector;
        if (claimed > fs->device_size) {
            if (!quiet)
                fat_set_warning(fs, "warning: the volume claims %llu bytes but "
                                    "the device holds only %llu - mounting "
                                    "read-only",
                                (unsigned long long)claimed,
                                (unsigned long long)fs->device_size);
            fs->read_only = 1;
        }
    }

    fs->info_sector = (fs->fat_type == FAT_TYPE_FAT32 && bpb->fs_info_sector)
                          ? bpb->fs_info_sector : 0;
    fs->free_clusters  = FAT_FSINFO_UNKNOWN;
    fs->next_free_hint = FAT_CLUSTER_FIRST;
    return FAT_SUCCESS;
}

int fat_core_mount(struct fat_fs *fs, const char *path, uint64_t base_offset,
                   int read_only)
{
    uint8_t  sector[FAT_MAX_SECTOR_SIZE];
    uint16_t sig;
    int      rc;

    memset(fs, 0, sizeof *fs);
    fs->fat_cache.sector = UINT32_MAX;

    rc = fat_io_open(&fs->io, path, read_only);
    if (rc != FAT_SUCCESS) {
        fat_set_warning(fs, "%s", fat_io_strerror(&fs->io));
        return FAT_ERROR;
    }
    if (base_offset)
        fat_io_set_base_offset(&fs->io, base_offset);

    fs->read_only = fat_io_is_read_only(&fs->io);

    if (fat_io_size(&fs->io, &fs->device_size) != FAT_SUCCESS)
        fs->device_size = 0;      /* unknown size is fine; skip that check */

    if (fat_io_read(&fs->io, 0, sector, FAT_SECTOR_SIZE) != FAT_SUCCESS) {
        fat_set_warning(fs, "cannot read the boot sector: %s",
                        fat_io_strerror(&fs->io));
        fat_io_close(&fs->io);
        return FAT_ERROR;
    }

    fat_bpb_parse(sector, &fs->bpb);

    /* The 0x55AA signature is checked but not fatal: plenty of loopback images
     * in the wild omit it, and refusing to mount would be unhelpful. */
    sig = fat_rd16(sector + FAT_BOOT_SIGNATURE_OFFSET);
    if (sig != FAT_BOOT_SIGNATURE)
        fat_set_warning(fs, "warning: missing 0x55AA boot signature "
                            "(found 0x%04X)", sig);

    fs->mounted = 1;

    if (derive_geometry(fs, 0) != FAT_SUCCESS) {
        /* Report the failure without the accumulated warnings masking it. */
        fat_io_close(&fs->io);
        fs->mounted = 0;
        return FAT_ERROR;
    }

    /* A device smaller than one cluster cannot be a FAT volume in practice. */
    if (fs->device_size > 0 &&
        fs->device_size < (uint64_t)fs->data_start_sector * fs->bytes_per_sector) {
        fat_set_warning(fs, "the device is smaller than the file system's own "
                            "data area");
        fat_io_close(&fs->io);
        fs->mounted = 0;
        return FAT_ERROR;
    }

    if (fs->bpb.media_descriptor != 0xF0 &&
        (fs->bpb.media_descriptor < 0xF8)) {
        fat_set_warning(fs, "warning: unusual media descriptor 0x%02X",
                        fs->bpb.media_descriptor);
    }
    if (fs->num_fats != 2) {
        fat_set_warning(fs, "warning: %u FAT copies (2 is the norm for "
                            "interoperability)", fs->num_fats);
    }

    if (fs->fat_type == FAT_TYPE_FAT32)
        (void)fat_fsinfo_read(fs);

    /* The clean-shutdown bit is deliberately NOT cleared here.  Inspection
     * commands (info, ls, cat, check) mount writable but never write, and
     * clearing the bit on mount would both modify a volume the user only
     * wanted to look at and make `check` report the dirty state it had just
     * created.  The bit is cleared by fat_core_touched() the first time
     * anything is really written. */
    {
        int clean = clean_bit_get(fs);

        /* clean_bit_get() returns -1 when the volume has no such bit or it
         * cannot be read; treat that as "clean" so no false alarm is raised. */
        fs->was_clean = (clean != 0);
    }

    return FAT_SUCCESS;
}

void fat_core_unmount(struct fat_fs *fs)
{
    if (!fs->mounted)
        return;

    /* Only a session that actually wrote something has anything to flush and
     * a clean-shutdown bit to set.  Inspection commands (info, ls, cat, tree,
     * check) therefore leave the volume byte for byte as they found it. */
    if (!fs->read_only && fs->marked_dirty) {
        if (fs->fat_type == FAT_TYPE_FAT32)
            (void)fat_fsinfo_update(fs);
        (void)fat_mark_clean(fs);
    }
    fat_io_close(&fs->io);
    fs->mounted = 0;
}

int fat_core_reread(struct fat_fs *fs)
{
    uint8_t sector[FAT_MAX_SECTOR_SIZE];

    if (fat_io_read(&fs->io, 0, sector, FAT_SECTOR_SIZE) != FAT_SUCCESS)
        return FAT_ERROR;
    fat_bpb_parse(sector, &fs->bpb);
    fs->fat_cache.valid = 0;
    return derive_geometry(fs, 1);
}

/* ==========================================================================
 *  FAT table access
 * ========================================================================== */

/* The canonical (FAT32-style) end-of-chain and bad markers are translated to
 * and from the width of the FAT in use, so that the rest of the code can
 * compare against a single set of constants:
 *
 *     FAT12  end of chain 0xFF8-0xFFF   bad 0xFF7
 *     FAT16  end of chain 0xFFF8-0xFFFF bad 0xFFF7
 *     FAT32  end of chain 0xFFFFFFF8..  bad 0xFFFFFFF7
 */
static uint32_t fat_type_eoc_min(const struct fat_fs *fs)
{
    switch (fs->fat_type) {
    case FAT_TYPE_FAT12: return 0x0FF8u;
    case FAT_TYPE_FAT16: return 0xFFF8u;
    default:             return FAT_CLUSTER_EOC_MIN;
    }
}

static uint32_t fat_type_bad(const struct fat_fs *fs)
{
    switch (fs->fat_type) {
    case FAT_TYPE_FAT12: return 0x0FF7u;
    case FAT_TYPE_FAT16: return 0xFFF7u;
    default:             return FAT_CLUSTER_BAD;
    }
}

static uint32_t fat_type_eoc(const struct fat_fs *fs)
{
    switch (fs->fat_type) {
    case FAT_TYPE_FAT12: return 0x0FFFu;
    case FAT_TYPE_FAT16: return 0xFFFFu;
    default:             return FAT_CLUSTER_EOC;
    }
}

/* Type-specific value -> canonical value. */
static uint32_t fat_norm(const struct fat_fs *fs, uint32_t raw)
{
    if (fs->fat_type == FAT_TYPE_FAT32)
        return raw;
    if (raw == 0)
        return 0;
    if (raw >= fat_type_eoc_min(fs))
        return FAT_CLUSTER_EOC;
    if (raw == fat_type_bad(fs))
        return FAT_CLUSTER_BAD;
    return raw;
}

/* Canonical value -> type-specific value. */
static uint32_t fat_denorm(const struct fat_fs *fs, uint32_t value)
{
    if (fs->fat_type == FAT_TYPE_FAT32)
        return value & 0x0FFFFFFFu;
    if (value >= FAT_CLUSTER_EOC_MIN)
        return fat_type_eoc(fs);
    if (value == FAT_CLUSTER_BAD)
        return fat_type_bad(fs);
    return value;
}

/* Byte offset of @cluster's entry within a FAT copy, and the encoded width. */
static uint32_t fat_entry_offset(const struct fat_fs *fs, uint32_t cluster)
{
    switch (fs->fat_type) {
    case FAT_TYPE_FAT12: return cluster + (cluster / 2u);   /* 1.5 bytes each */
    case FAT_TYPE_FAT16: return cluster * 2u;
    default:             return cluster * 4u;
    }
}

/* Load FAT copy #1's sector that holds @cluster into the cache. */
static int fat_cache_load(struct fat_fs *fs, uint32_t cluster)
{
    uint32_t entry_off = fat_entry_offset(fs, cluster);
    uint32_t sector_of = entry_off / fs->bytes_per_sector;
    uint32_t abs_sector = fs->fat_start_sector + sector_of;

    if (fs->fat_cache.valid && fs->fat_cache.sector == abs_sector)
        return FAT_SUCCESS;

    if (fat_sector_read(fs, abs_sector, fs->fat_cache.data) != FAT_SUCCESS) {
        fat_set_warning(fs, "cannot read FAT sector %u: %s", abs_sector,
                        fat_io_strerror(&fs->io));
        fs->fat_cache.valid = 0;
        return FAT_ERROR;
    }
    fs->fat_cache.sector = abs_sector;
    fs->fat_cache.valid  = 1;
    fs->fat_cache.dirty  = 0;
    return FAT_SUCCESS;
}

int fat_fat_get(struct fat_fs *fs, uint32_t cluster, uint32_t *value)
{
    uint32_t entry_off, in_sector, raw;

    if (!fat_cluster_valid(fs, cluster)) {
        fat_set_warning(fs, "FAT lookup for invalid cluster %u "
                            "(valid range 2..%u)", cluster, fs->max_cluster);
        return FAT_ERROR;
    }

    entry_off = fat_entry_offset(fs, cluster);
    in_sector = entry_off % fs->bytes_per_sector;

    if (fat_cache_load(fs, cluster) != FAT_SUCCESS)
        return FAT_ERROR;

    switch (fs->fat_type) {
    case FAT_TYPE_FAT12:
        /* Two 12-bit entries share three bytes, so which half of the 16-bit
         * window holds this entry depends on the parity of the cluster.  The
         * whole window is needed for the odd case: shifting right by four
         * first and masking afterwards.  Masking to 12 bits up front would
         * discard the top nibble of the value (0xFFF would read back as
         * 0x0FF). */
        {
            uint32_t word;

            if (in_sector == fs->bytes_per_sector - 1) {
                /* The entry straddles two sectors. */
                uint8_t  next[FAT_MAX_SECTOR_SIZE];
                uint32_t abs_next = fs->fat_cache.sector + 1;

                word = fs->fat_cache.data[in_sector];
                if (fat_sector_read(fs, abs_next, next) != FAT_SUCCESS)
                    return FAT_ERROR;
                word |= (uint32_t)next[0] << 8;
            } else {
                word = (uint32_t)fat_rd16(fs->fat_cache.data + in_sector);
            }

            raw = (cluster & 1u) ? (word >> 4) : word;
            raw &= 0x0FFFu;
        }
        *value = fat_norm(fs, raw);
        break;

    case FAT_TYPE_FAT16:
        *value = fat_norm(fs, fat_rd16(fs->fat_cache.data + in_sector));
        break;

    default: /* FAT32: the top 4 bits are reserved and must be ignored. */
        *value = fat_rd32(fs->fat_cache.data + in_sector) & 0x0FFFFFFFu;
        break;
    }
    return FAT_SUCCESS;
}

int fat_fat_set(struct fat_fs *fs, uint32_t cluster, uint32_t value)
{
    uint32_t entry_off, in_sector, copy;
    uint8_t  buf[FAT_MAX_SECTOR_SIZE];
    uint32_t abs_sector;
    uint32_t masked;

    if (fs->read_only) {
        fat_set_warning(fs, "FAT update on a read-only mount");
        return FAT_ERROR;
    }
    if (!fat_cluster_valid(fs, cluster)) {
        fat_set_warning(fs, "FAT update for invalid cluster %u", cluster);
        return FAT_ERROR;
    }

    /* The FAT32 clean-shutdown bit lives in the very first FAT sector this
     * function is about to rewrite.  Clearing it is therefore done *here*,
     * before any buffer is taken from the FAT cache: otherwise the caller
     * would compute its copy-0 sector from a cache entry that still carries
     * the old clean bit and would write it back over the cleared one,
     * leaving FAT copy 1 the only copy that looks dirty. */
    fat_core_touched(fs);

    masked = fat_denorm(fs, value);
    if (fs->fat_type == FAT_TYPE_FAT12)
        masked &= 0x0FFFu;
    else if (fs->fat_type == FAT_TYPE_FAT16)
        masked &= 0xFFFFu;

    entry_off  = fat_entry_offset(fs, cluster);
    in_sector  = entry_off % fs->bytes_per_sector;
    abs_sector = fs->fat_start_sector + (entry_off / fs->bytes_per_sector);

    /* Every FAT copy is updated; leaving a mirror stale makes the volume look
     * corrupt to every other driver. */
    for (copy = 0; copy < fs->num_fats; copy++) {
        uint32_t target = abs_sector + copy * fs->sectors_per_fat;
        int      from_cache = (copy == 0 && fs->fat_cache.valid &&
                               fs->fat_cache.sector == target);

        if (from_cache) {
            memcpy(buf, fs->fat_cache.data, fs->bytes_per_sector);
        } else if (fat_sector_read(fs, target, buf) != FAT_SUCCESS) {
            fat_set_warning(fs, "cannot read FAT copy %u sector %u", copy,
                            target);
            return FAT_ERROR;
        }

        switch (fs->fat_type) {
        case FAT_TYPE_FAT12: {
            uint32_t word;
            if (in_sector == fs->bytes_per_sector - 1) {
                /* The entry straddles this sector and the next one. */
                uint8_t next[FAT_MAX_SECTOR_SIZE];

                if (fat_sector_read(fs, target + 1, next) != FAT_SUCCESS)
                    return FAT_ERROR;
                word = (uint32_t)buf[in_sector] | ((uint32_t)next[0] << 8);

                if (cluster & 1u) {
                    /* An odd entry owns the high nibble of the shared byte
                     * and the whole of the byte that follows it, so the low
                     * nibble of the shared byte (the neighbouring entry) and
                     * the unused padding are the only bits to preserve. */
                    word = (word & 0x000Fu) | ((masked & 0x0FFFu) << 4);
                    buf[in_sector] = (uint8_t)(word & 0xFFu);
                    next[0]        = (uint8_t)((word >> 8) & 0xFFu);
                } else {
                    /* An even entry owns the whole of the shared byte and only
                     * the low nibble of the next one.  The high nibble of that
                     * next byte belongs to the following (odd) entry and must
                     * survive: overwriting the byte outright would silently
                     * truncate the next chain link. */
                    word = (word & 0xF000u) | (masked & 0x0FFFu);
                    buf[in_sector] = (uint8_t)(word & 0xFFu);
                    next[0] = (uint8_t)((next[0] & 0xF0u) |
                                        ((word >> 8) & 0x0Fu));
                }

                if (fat_sector_write(fs, target, buf) != FAT_SUCCESS)
                    return FAT_ERROR;
                if (fat_sector_write(fs, target + 1, next) != FAT_SUCCESS)
                    return FAT_ERROR;
                if (copy == 0)
                    fs->fat_cache.valid = 0;   /* the cache is now stale */
                continue;                      /* this copy is done */
            }
            word = (uint32_t)fat_rd16(buf + in_sector);
            if (cluster & 1u)
                word = (word & 0x000Fu) | ((masked & 0x0FFFu) << 4);
            else
                word = (word & 0xF000u) | (masked & 0x0FFFu);
            fat_wr16(buf + in_sector, (uint16_t)word);
            break;
        }

        case FAT_TYPE_FAT16:
            fat_wr16(buf + in_sector, (uint16_t)masked);
            break;

        default:
            /* The reserved high nibble must be preserved. */
            fat_wr32(buf + in_sector,
                     (fat_rd32(buf + in_sector) & 0xF0000000u) | masked);
            break;
        }

        if (fat_sector_write(fs, target, buf) != FAT_SUCCESS) {
            fat_set_warning(fs, "cannot write FAT copy %u sector %u", copy,
                            target);
            return FAT_ERROR;
        }

        if (copy == 0) {
            memcpy(fs->fat_cache.data, buf, fs->bytes_per_sector);
            fs->fat_cache.sector = target;
            fs->fat_cache.valid  = 1;
        }
    }
    return FAT_SUCCESS;
}

int fat_fat_mirror(struct fat_fs *fs)
{
    uint32_t copy;
    uint8_t  buf[FAT_MAX_SECTOR_SIZE];

    if (fs->read_only)
        return FAT_ERROR;
    if (fs->num_fats < 2)
        return FAT_SUCCESS;

    for (uint32_t s = 0; s < fs->sectors_per_fat; s++) {
        if (fat_sector_read(fs, fs->fat_start_sector + s, buf) != FAT_SUCCESS)
            return FAT_ERROR;
        for (copy = 1; copy < fs->num_fats; copy++) {
            uint32_t target = fs->fat_start_sector + s +
                              copy * fs->sectors_per_fat;
            if (fat_sector_write(fs, target, buf) != FAT_SUCCESS)
                return FAT_ERROR;
        }
    }
    fs->fat_cache.valid = 0;
    return FAT_SUCCESS;
}

int fat_alloc_cluster(struct fat_fs *fs, uint32_t *out)
{
    uint32_t total;
    uint32_t hint;

    if (fs->read_only) {
        fat_set_warning(fs, "allocation attempted on a read-only mount");
        return FAT_ERROR;
    }
    if (!out)
        return FAT_ERROR;

    if (ensure_free_count_verified(fs) != FAT_SUCCESS)
        return FAT_ERROR;

    hint = fs->next_free_hint;
    if (!fat_cluster_valid(fs, hint))
        hint = FAT_CLUSTER_FIRST;

    /* Walk every cluster exactly once, starting at the hint and wrapping at
     * the end of the data area.  Iterating over a known count rather than
     * testing for "have I wrapped and passed the start?" keeps the search
     * honest at both ends of the volume. */
    total = fs->max_cluster - FAT_CLUSTER_FIRST + 1;

    for (uint32_t i = 0; i < total; i++) {
        uint32_t c = FAT_CLUSTER_FIRST +
                     ((hint - FAT_CLUSTER_FIRST + i) % total);
        uint32_t value;

        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;
        if (!fat_cluster_is_free(value))
            continue;

        if (fat_fat_set(fs, c, FAT_CLUSTER_EOC) != FAT_SUCCESS)
            return FAT_ERROR;

        fs->next_free_hint = (c < fs->max_cluster) ? c + 1 : FAT_CLUSTER_FIRST;
        if (fs->free_clusters != FAT_FSINFO_UNKNOWN && fs->free_clusters > 0)
            fs->free_clusters--;
        *out = c;
        return FAT_SUCCESS;
    }

    fat_set_warning(fs, "no free clusters left on the volume");
    return FAT_ERROR;
}

int fat_chain_walk(struct fat_fs *fs, uint32_t first, uint32_t *count,
                   uint32_t *last)
{
    uint32_t c = first;
    uint32_t n = 0;
    uint32_t guard = fs->max_cluster + 2;

    if (!fat_cluster_valid(fs, first)) {
        fat_set_warning(fs, "chain starts at invalid cluster %u", first);
        return FAT_ERROR;
    }

    for (;;) {
        uint32_t value;

        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;

        n++;
        if (fat_cluster_is_eoc(value)) {
            *count = n;
            *last  = c;
            return FAT_SUCCESS;
        }
        if (fat_cluster_is_bad(value) || fat_cluster_is_free(value)) {
            fat_set_warning(fs, "chain broken at cluster %u (entry 0x%08X)",
                            c, value);
            return FAT_ERROR;
        }
        if (!fat_cluster_valid(fs, value)) {
            fat_set_warning(fs, "chain points at invalid cluster %u "
                                "(from cluster %u)", value, c);
            return FAT_ERROR;
        }
        if (--guard == 0) {
            fat_set_warning(fs, "cluster chain from %u loops back on itself",
                            first);
            return FAT_ERROR;
        }
        c = value;
    }
}

int fat_chain_free(struct fat_fs *fs, uint32_t first)
{
    uint32_t c = first;
    uint32_t guard = fs->max_cluster + 2;

    if (fs->read_only)
        return FAT_ERROR;
    if (!fat_cluster_valid(fs, first))
        return FAT_ERROR;
    if (ensure_free_count_verified(fs) != FAT_SUCCESS)
        return FAT_ERROR;

    for (;;) {
        uint32_t value;

        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_fat_set(fs, c, FAT_CLUSTER_FREE) != FAT_SUCCESS)
            return FAT_ERROR;

        if (fs->free_clusters != FAT_FSINFO_UNKNOWN)
            fs->free_clusters++;
        if (c < fs->next_free_hint)
            fs->next_free_hint = c;

        if (fat_cluster_is_eoc(value))
            return FAT_SUCCESS;
        if (!fat_cluster_valid(fs, value) || fat_cluster_is_free(value)) {
            fat_set_warning(fs, "chain broken while freeing cluster %u", c);
            return FAT_ERROR;
        }
        if (--guard == 0)
            return FAT_ERROR;
        c = value;
    }
}

int fat_chain_append(struct fat_fs *fs, uint32_t last, uint32_t *new_cluster)
{
    uint32_t fresh;

    if (fat_alloc_cluster(fs, &fresh) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fat_fat_set(fs, last, fresh) != FAT_SUCCESS)
        return FAT_ERROR;

    *new_cluster = fresh;
    return FAT_SUCCESS;
}

int fat_chain_cluster_at(struct fat_fs *fs, uint32_t first, uint32_t index,
                         int extend, uint32_t *out_cluster, uint32_t *out_last)
{
    uint32_t c = first;
    uint32_t i = 0;

    if (!fat_cluster_valid(fs, first))
        return FAT_ERROR;

    for (;;) {
        uint32_t value;

        if (i == index) {
            if (out_cluster)
                *out_cluster = c;
            if (out_last) {
                uint32_t dummy;
                if (fat_chain_walk(fs, c, &dummy, out_last) != FAT_SUCCESS)
                    return FAT_ERROR;
            }
            return FAT_SUCCESS;
        }

        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;

        if (fat_cluster_is_eoc(value)) {
            if (!extend) {
                if (out_last)
                    *out_last = c;
                return FAT_ERROR;         /* chain is shorter than index */
            }
            /* Grow the chain by one and continue from the new cluster. */
            {
                uint32_t fresh;
                if (fat_chain_append(fs, c, &fresh) != FAT_SUCCESS)
                    return FAT_ERROR;
                c = fresh;
                i++;
                continue;
            }
        }

        if (!fat_cluster_valid(fs, value)) {
            fat_set_warning(fs, "chain points outside the data area while "
                                "seeking to index %u", index);
            return FAT_ERROR;
        }
        c = value;
        i++;
    }
}

/* ==========================================================================
 *  Cluster I/O
 * ========================================================================== */

static uint64_t cluster_offset(const struct fat_fs *fs, uint32_t cluster)
{
    uint32_t sector = fs->data_start_sector +
                      (cluster - FAT_CLUSTER_FIRST) * fs->sectors_per_cluster;
    return (uint64_t)sector * fs->bytes_per_sector;
}

int fat_cluster_read(struct fat_fs *fs, uint32_t cluster, void *buf)
{
    if (!fat_cluster_valid(fs, cluster)) {
        fat_set_warning(fs, "read of invalid cluster %u", cluster);
        return FAT_ERROR;
    }
    return fat_io_read(&fs->io, cluster_offset(fs, cluster), buf,
                       fs->bytes_per_cluster);
}

int fat_cluster_write(struct fat_fs *fs, uint32_t cluster, const void *buf)
{
    if (!fat_cluster_valid(fs, cluster)) {
        fat_set_warning(fs, "write to invalid cluster %u", cluster);
        return FAT_ERROR;
    }
    fat_core_touched(fs);
    return fat_io_write(&fs->io, cluster_offset(fs, cluster), buf,
                        fs->bytes_per_cluster);
}

int fat_cluster_zero(struct fat_fs *fs, uint32_t cluster)
{
    static uint8_t zeros[64u * 1024u];   /* max cluster size, zero-initialised */
    return fat_cluster_write(fs, cluster, zeros);
}

int fat_chain_read(struct fat_fs *fs, uint32_t first, uint64_t offset,
                   void *buf, size_t len, size_t *done)
{
    uint8_t *out   = (uint8_t *)buf;
    size_t   total = 0;
    uint64_t skip  = offset;
    uint32_t c;

    *done = 0;
    if (!fat_cluster_valid(fs, first))
        return FAT_ERROR;

    c = first;
    while (skip >= fs->bytes_per_cluster) {
        uint32_t next;
        if (fat_fat_get(fs, c, &next) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_is_eoc(next))
            return FAT_SUCCESS;            /* read past the end of the file */
        if (!fat_cluster_valid(fs, next))
            return FAT_ERROR;
        c = next;
        skip -= fs->bytes_per_cluster;
    }

    {
        uint8_t cluster_buf[64u * 1024u];

        while (total < len) {
            size_t   chunk = fs->bytes_per_cluster - (size_t)skip;
            uint32_t next;

            if (chunk > len - total)
                chunk = len - total;

            if (fat_cluster_read(fs, c, cluster_buf) != FAT_SUCCESS)
                return FAT_ERROR;
            memcpy(out + total, cluster_buf + skip, chunk);
            total += chunk;
            skip   = 0;

            if (total == len)
                break;

            if (fat_fat_get(fs, c, &next) != FAT_SUCCESS)
                return FAT_ERROR;
            if (fat_cluster_is_eoc(next))
                break;                     /* short read at end of chain */
            if (!fat_cluster_valid(fs, next))
                return FAT_ERROR;
            c = next;
        }
    }

    *done = total;
    return FAT_SUCCESS;
}

int fat_chain_write(struct fat_fs *fs, uint32_t first, uint64_t offset,
                    const void *buf, size_t len, size_t *done, uint32_t *last)
{
    const uint8_t *in   = (const uint8_t *)buf;
    size_t         total = 0;
    uint64_t       skip  = offset;
    uint32_t       c     = first;
    uint32_t       tail  = first;
    uint8_t        cluster_buf[64u * 1024u];

    *done = 0;
    if (last)
        *last = first;
    if (!fat_cluster_valid(fs, first))
        return FAT_ERROR;
    {
        uint32_t chain_len = 0;
        if (fat_chain_walk(fs, first, &chain_len, &tail) != FAT_SUCCESS)
            return FAT_ERROR;
    }
    if (last)
        *last = tail;
    skip = offset;

    /* Position at the cluster containing @offset. */
    while (skip >= fs->bytes_per_cluster) {
        uint32_t next;
        if (fat_fat_get(fs, c, &next) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_is_eoc(next)) {
            uint32_t fresh;
            if (fat_chain_append(fs, c, &fresh) != FAT_SUCCESS)
                return FAT_ERROR;
            if (last)
                *last = fresh;
            c = fresh;
        } else if (!fat_cluster_valid(fs, next)) {
            return FAT_ERROR;
        } else {
            c = next;
        }
        skip -= fs->bytes_per_cluster;
    }

    while (total < len) {
        size_t   chunk = fs->bytes_per_cluster - (size_t)skip;
        uint32_t next;
        int      needs_rw = (skip != 0 || chunk > len - total);

        if (chunk > len - total)
            chunk = len - total;

        /* A partial cluster must be read first: the remainder of the cluster
         * belongs to the file and must not be zeroed. */
        if (needs_rw) {
            if (fat_cluster_read(fs, c, cluster_buf) != FAT_SUCCESS)
                return FAT_ERROR;
        }
        memcpy(cluster_buf + skip, in + total, chunk);
        if (needs_rw) {
            if (fat_cluster_write(fs, c, cluster_buf) != FAT_SUCCESS)
                return FAT_ERROR;
        } else {
            if (fat_cluster_write(fs, c, in + total) != FAT_SUCCESS)
                return FAT_ERROR;
        }

        total += chunk;
        skip   = 0;

        if (total == len)
            break;

        if (fat_fat_get(fs, c, &next) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_is_eoc(next)) {
            uint32_t fresh;
            if (fat_chain_append(fs, c, &fresh) != FAT_SUCCESS)
                return FAT_ERROR;
            if (last)
                *last = fresh;
            c = fresh;
        } else if (!fat_cluster_valid(fs, next)) {
            return FAT_ERROR;
        } else {
            c = next;
            if (last)
                *last = c;
        }
    }

    *done = total;
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Usage statistics
 * ========================================================================== */

int fat_core_usage(struct fat_fs *fs, fat_usage_t *out)
{
    uint32_t c;
    uint32_t free_count = 0;
    uint32_t bad_count  = 0;
    uint32_t eoc_count  = 0;   /* chain heads only */

    memset(out, 0, sizeof *out);

    for (c = FAT_CLUSTER_FIRST; c <= fs->max_cluster; c++) {
        uint32_t value;
        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_is_free(value))
            free_count++;
        else if (fat_cluster_is_bad(value))
            bad_count++;
        else if (fat_cluster_is_eoc(value))
            eoc_count++;
    }

    out->total_clusters  = fs->cluster_count;
    out->free_clusters   = free_count;
    out->bad_clusters    = bad_count;
    out->used_clusters   = fs->cluster_count - free_count - bad_count;
    out->free_count_known = 1;
    (void)eoc_count;

    if (fs->free_clusters == FAT_FSINFO_UNKNOWN)
        fs->free_clusters = free_count;

    return FAT_SUCCESS;
}

/* ==========================================================================
 *  FSInfo and the clean-shutdown bit (FAT32)
 * ========================================================================== */

int fat_fsinfo_read(struct fat_fs *fs)
{
    uint8_t buf[FAT_MAX_SECTOR_SIZE];
    uint32_t lead, sig, trail;

    if (fs->fat_type != FAT_TYPE_FAT32 || fs->info_sector == 0)
        return FAT_ERROR;
    if (fs->info_sector >= fs->bpb.reserved_sectors)
        return FAT_ERROR;

    if (fat_sector_read(fs, fs->info_sector, buf) != FAT_SUCCESS)
        return FAT_ERROR;

    lead  = fat_rd32(buf + 0);
    sig   = fat_rd32(buf + 484);
    trail = fat_rd32(buf + 508);

    if (lead != FAT_FSINFO_LEAD_SIG || sig != FAT_FSINFO_STRUCT_SIG ||
        trail != FAT_FSINFO_TRAIL_SIG)
        return FAT_ERROR;

    {
        uint32_t free_count = fat_rd32(buf + 488);
        uint32_t next_free  = fat_rd32(buf + 492);

        if (free_count != FAT_FSINFO_UNKNOWN && free_count <= fs->cluster_count)
            fs->free_clusters = free_count;

        if (next_free != FAT_FSINFO_UNKNOWN &&
            fat_cluster_valid(fs, next_free))
            fs->next_free_hint = next_free;
    }
    return FAT_SUCCESS;
}

/* Count the free and bad clusters by scanning the FAT.  The sector cache makes
 * this a few hundred reads even on a large volume. */
static int count_free_clusters(struct fat_fs *fs, uint32_t *free_out,
                               uint32_t *bad_out)
{
    uint32_t free_count = 0;
    uint32_t bad_count  = 0;

    for (uint32_t c = FAT_CLUSTER_FIRST; c <= fs->max_cluster; c++) {
        uint32_t value;

        if (fat_fat_get(fs, c, &value) != FAT_SUCCESS)
            return FAT_ERROR;
        if (fat_cluster_is_free(value))
            free_count++;
        else if (fat_cluster_is_bad(value))
            bad_count++;
    }
    *free_out = free_count;
    if (bad_out)
        *bad_out = bad_count;
    return FAT_SUCCESS;
}

/* Make the in-memory free count authoritative, scanning the FAT once if the
 * only thing we have is what the FSInfo sector claimed.  A stale FSInfo (they
 * are common - other implementations only update the sector on a clean
 * unmount) must never be propagated further. */
static int ensure_free_count_verified(struct fat_fs *fs)
{
    if (fs->free_clusters != FAT_FSINFO_UNKNOWN && fs->free_clusters_verified)
        return FAT_SUCCESS;
    if (fs->fat_type != FAT_TYPE_FAT32) {
        fs->free_clusters = FAT_FSINFO_UNKNOWN;
        return FAT_SUCCESS;
    }
    if (count_free_clusters(fs, &fs->free_clusters, NULL) != FAT_SUCCESS)
        return FAT_ERROR;
    fs->free_clusters_verified = 1;
    return FAT_SUCCESS;
}

int fat_fsinfo_update(struct fat_fs *fs)
{
    uint8_t buf[FAT_MAX_SECTOR_SIZE];

    if (fs->read_only)
        return FAT_ERROR;
    if (fs->fat_type != FAT_TYPE_FAT32 || fs->info_sector == 0)
        return FAT_SUCCESS;               /* nothing to do on FAT12/16 */
    if (fs->info_sector >= fs->bpb.reserved_sectors)
        return FAT_ERROR;

    /* Never record a guess: the FSInfo value is what every other
     * implementation trusts, so the count is verified before it is written. */
    if (ensure_free_count_verified(fs) != FAT_SUCCESS)
        return FAT_ERROR;
    if (fs->free_clusters == FAT_FSINFO_UNKNOWN)
        return FAT_ERROR;

    if (fat_sector_read(fs, fs->info_sector, buf) != FAT_SUCCESS)
        return FAT_ERROR;

    if (fat_rd32(buf)         != FAT_FSINFO_LEAD_SIG ||
        fat_rd32(buf + 484)   != FAT_FSINFO_STRUCT_SIG ||
        fat_rd32(buf + 508)   != FAT_FSINFO_TRAIL_SIG)
        return FAT_ERROR;

    fat_wr32(buf + 488, fs->free_clusters);
    fat_wr32(buf + 492, fat_cluster_valid(fs, fs->next_free_hint)
                            ? fs->next_free_hint : FAT_CLUSTER_FIRST);

    if (fat_sector_write(fs, fs->info_sector, buf) != FAT_SUCCESS)
        return FAT_ERROR;

    /* Keep the backup FSInfo consistent when one is configured. */
    if (fs->bpb.backup_boot_sector &&
        fs->bpb.backup_boot_sector < fs->bpb.reserved_sectors) {
        uint32_t backup_info = fs->bpb.backup_boot_sector + 1;
        if (backup_info < fs->bpb.reserved_sectors)
            (void)fat_sector_write(fs, backup_info, buf);
    }
    return FAT_SUCCESS;
}

/* The clean-shutdown bit lives in the FAT32 entry for cluster 1: bit 27 is
 * ClnShutBitMask, bit 26 is HrdErrBitMask.  FAT12/16 have no documented
 * equivalent, so this is a no-op there. */
int fat_is_clean(const struct fat_fs *fs, int *clean_out)
{
    if (fs->fat_type != FAT_TYPE_FAT32)
        return FAT_ERROR;
    {
        uint8_t buf[FAT_MAX_SECTOR_SIZE];
        uint32_t entry;
        struct fat_fs *mutable_fs = (struct fat_fs *)fs;

        if (fat_sector_read(mutable_fs, fs->fat_start_sector, buf)
            != FAT_SUCCESS)
            return FAT_ERROR;
        entry = fat_rd32(buf + 4);        /* entry #1 */
        *clean_out = (entry & 0x08000000u) ? 1 : 0;
        return FAT_SUCCESS;
    }
}

/* Read the FAT32 clean-shutdown bit: 1 clean, 0 dirty, -1 not applicable. */
static int clean_bit_get(struct fat_fs *fs)
{
    uint8_t buf[FAT_MAX_SECTOR_SIZE];

    if (fs->fat_type != FAT_TYPE_FAT32)
        return -1;
    if (fat_sector_read(fs, fs->fat_start_sector, buf) != FAT_SUCCESS)
        return -1;
    return (fat_rd32(buf + 4) & 0x08000000u) ? 1 : 0;
}

static int set_clean_bit(struct fat_fs *fs, int clean)
{
    uint8_t  buf[FAT_MAX_SECTOR_SIZE];
    uint32_t entry;

    if (fs->read_only || fs->fat_type != FAT_TYPE_FAT32)
        return FAT_ERROR;

    if (fat_sector_read(fs, fs->fat_start_sector, buf) != FAT_SUCCESS)
        return FAT_ERROR;

    entry = fat_rd32(buf + 4);
    if (clean)
        entry |= 0x08000000u;
    else
        entry &= ~0x08000000u;

    fat_wr32(buf + 4, entry);

    if (fat_sector_write(fs, fs->fat_start_sector, buf) != FAT_SUCCESS)
        return FAT_ERROR;

    for (uint32_t copy = 1; copy < fs->num_fats; copy++)
        (void)fat_sector_write(fs, fs->fat_start_sector +
                                   copy * fs->sectors_per_fat, buf);
    fs->fat_cache.valid = 0;
    return FAT_SUCCESS;
}

/* Note that the volume is being modified: the FAT32 clean-shutdown bit is
 * cleared once, on the first genuine write. */
void fat_core_touched(struct fat_fs *fs)
{
    if (fs->read_only || fs->marked_dirty)
        return;
    fs->marked_dirty = 1;
    if (fs->fat_type == FAT_TYPE_FAT32)
        (void)set_clean_bit(fs, 0);
}

int fat_mark_dirty(struct fat_fs *fs)
{
    fs->marked_dirty = 1;
    return set_clean_bit(fs, 0);
}

int fat_mark_clean(struct fat_fs *fs)
{
    return set_clean_bit(fs, 1);
}
