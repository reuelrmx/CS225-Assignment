/* ==========================================================================
 *  fat_format.c - create a FAT12/16/32 volume (mkfs)
 *
 *  Geometry selection follows the conventions used by mkfs.fat(8):
 *
 *      FAT12   fewer than 4085 clusters, up to 4 MiB by default
 *      FAT16   up to 65524 clusters, up to 512 MiB by default
 *      FAT32   at least 65525 clusters, larger volumes
 *
 *  Only the file system metadata is written - boot sector, FATs, FSInfo and
 *  the root directory.  The data area is deliberately left as it is (stale
 *  file contents are not readable because the FAT says those clusters are
 *  free), which is what every mkfs does on a quick format.
 * ========================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fat_core.h"
#include "fat_fs.h"

#define FAT_FORMAT_MAX_SPC 64          /* 64 sectors * 512 B = 32 KiB max */

/* --------------------------------------------------------------------------
 *  Geometry
 * ------------------------------------------------------------------------ */

static uint32_t div_round_up(uint64_t value, uint32_t divisor)
{
    return (uint32_t)((value + divisor - 1) / divisor);
}

static int is_pow2(uint32_t v)
{
    return v != 0 && (v & (v - 1u)) == 0;
}

static uint32_t entry_bits(int type)
{
    switch (type) {
    case FAT_TYPE_FAT12: return 12;
    case FAT_TYPE_FAT16: return 16;
    default:             return 32;
    }
}

static uint32_t type_eoc(int type)
{
    switch (type) {
    case FAT_TYPE_FAT12: return 0x0FFFu;
    case FAT_TYPE_FAT16: return 0xFFFFu;
    default:             return 0x0FFFFFFFu;
    }
}

static int cluster_count_ok(int type, uint32_t clusters)
{
    switch (type) {
    case FAT_TYPE_FAT12: return clusters < FAT12_MAX_CLUSTERS;
    case FAT_TYPE_FAT16:
        return clusters >= FAT12_MAX_CLUSTERS &&
               clusters < FAT16_MAX_CLUSTERS;
    default:
        return clusters >= FAT16_MAX_CLUSTERS;
    }
}

typedef struct {
    int      type;
    uint32_t bps;              /* bytes per sector                        */
    uint32_t spc;              /* sectors per cluster                     */
    uint32_t reserved;         /* reserved sectors                        */
    uint32_t num_fats;
    uint32_t root_entries;     /* 0 for FAT32                             */
    uint32_t total_sectors;
    uint32_t spf;              /* sectors per FAT copy                    */
    uint32_t cluster_count;
    uint32_t fat_start;
    uint32_t root_start;
    uint32_t root_sectors;
    uint32_t data_start;
    uint8_t  media;
} mkgeom_t;

/* Solve for sectors-per-FAT and the cluster count.  The two depend on each
 * other, so this iterates; the FAT size only ever grows, which guarantees
 * both termination and a FAT that can address every cluster it describes. */
static int solve_geometry(mkgeom_t *g)
{
    uint32_t spf = 1;
    uint32_t root_sectors;

    root_sectors = div_round_up((uint64_t)g->root_entries * FAT_DIRENT_SIZE,
                                g->bps);

    for (int pass = 0; pass < 16; pass++) {
        uint64_t fat_bytes;
        uint32_t clusters;
        uint32_t needed;
        uint32_t next_spf;
        uint64_t data_start;

        g->fat_start  = g->reserved;
        g->root_start = g->reserved + g->num_fats * spf;
        data_start    = (uint64_t)g->root_start + root_sectors;

        if (data_start >= g->total_sectors)
            return FAT_ERROR;

        clusters = (uint32_t)((g->total_sectors - data_start) / g->spc);
        if (clusters < 1)
            return FAT_ERROR;

        needed    = clusters + 2;
        fat_bytes = ((uint64_t)needed * entry_bits(g->type) + 7) / 8;
        next_spf  = div_round_up(fat_bytes, g->bps);
        if (next_spf == 0)
            next_spf = 1;

        if (next_spf <= spf)
            break;
        spf = next_spf;
    }

    g->spf           = spf;
    g->root_start    = g->reserved + g->num_fats * spf;
    g->root_sectors  = root_sectors;
    g->data_start    = g->root_start + root_sectors;
    if (g->data_start >= g->total_sectors)
        return FAT_ERROR;
    g->cluster_count = (g->total_sectors - g->data_start) / g->spc;
    return g->cluster_count ? FAT_SUCCESS : FAT_ERROR;
}

/* Pick the cluster size, then the FAT size, for the requested type. */
static int choose_geometry(mkgeom_t *g, int type, uint32_t total_sectors,
                           uint32_t bps, uint32_t num_fats,
                           uint32_t want_cluster_bytes)
{
    uint32_t start = 1;
    uint32_t only  = 0;

    memset(g, 0, sizeof *g);
    g->type          = type;
    g->bps           = bps;
    g->num_fats      = num_fats;
    g->total_sectors = total_sectors;
    g->reserved      = (type == FAT_TYPE_FAT32) ? 32u : 1u;
    g->root_entries  = (type == FAT_TYPE_FAT32) ? 0u : 512u;
    g->media         = (total_sectors <= 2880) ? 0xF0u : 0xF8u;

    if (type == FAT_TYPE_FAT32) {
        /* Windows will not mount a FAT32 volume above 260 MiB that uses less
         * than 4 KiB clusters, so start there on large media. */
        uint64_t bytes = (uint64_t)total_sectors * bps;

        if (bytes > 260ull * 1024u * 1024u)
            start = 4096u / bps > start ? 4096u / bps : start;
    }

    /* An explicitly requested cluster size is honoured exactly: only that one
     * candidate is tried, and the caller is told when the volume cannot be
     * described with it. */
    if (want_cluster_bytes) {
        if (want_cluster_bytes < bps || want_cluster_bytes % bps != 0) {
            return FAT_ERROR;
        }
        only = want_cluster_bytes / bps;
        if (only == 0 || only > FAT_FORMAT_MAX_SPC ||
            (only & (only - 1u)) != 0) {
            return FAT_ERROR;
        }
        start = only;
    }

    for (uint32_t spc = start; spc <= FAT_FORMAT_MAX_SPC; spc <<= 1) {
        if (spc * bps > 32u * 1024u)
            break;
        g->spc = spc;
        if (solve_geometry(g) != FAT_SUCCESS)
            continue;
        if (!cluster_count_ok(type, g->cluster_count))
            continue;
        return FAT_SUCCESS;
    }
    return FAT_ERROR;
}

/* --------------------------------------------------------------------------
 *  Writing helpers
 * ------------------------------------------------------------------------ */

static int write_sector(struct fat_io *io, uint32_t sector, uint32_t bps,
                        const void *buf)
{
    return fat_io_write(io, (uint64_t)sector * bps, buf, bps);
}

static int zero_sectors(struct fat_io *io, uint32_t first, uint32_t count,
                        uint32_t bps)
{
    static const uint8_t zeros[FAT_MAX_SECTOR_SIZE];

    for (uint32_t i = 0; i < count; i++) {
        if (write_sector(io, first + i, bps, zeros) != FAT_SUCCESS)
            return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

/* Write one entry into a FAT image buffer (used to build the first sector). */
static void put_entry(uint8_t *fat, int type, uint32_t index, uint32_t value)
{
    switch (type) {
    case FAT_TYPE_FAT12: {
        uint32_t off  = index + index / 2u;
        uint32_t word = (uint32_t)fat[off] | ((uint32_t)fat[off + 1] << 8);

        if (index & 1u)
            word = (word & 0x0Fu) | ((value & 0x0FFFu) << 4);
        else
            word = (word & 0xF000u) | (value & 0x0FFFu);
        fat[off]     = (uint8_t)(word & 0xFFu);
        fat[off + 1] = (uint8_t)((word >> 8) & 0xFFu);
        break;
    }
    case FAT_TYPE_FAT16:
        fat_wr16(fat + index * 2u, (uint16_t)value);
        break;
    default:
        fat_wr32(fat + index * 4u, value & 0x0FFFFFFFu);
        break;
    }
}

/* The label is written both into the boot sector and as a volume-id entry in
 * the root directory, because Explorer shows the root entry when it is
 * present.  Returns a pointer to the 11-character padded form. */
static void pad_label(const char *label, uint8_t out[FAT_LABEL_LEN])
{
    size_t n = 0;

    memset(out, ' ', FAT_LABEL_LEN);
    if (!label)
        return;
    n = strlen(label);
    if (n > FAT_LABEL_LEN)
        n = FAT_LABEL_LEN;
    for (size_t i = 0; i < n; i++) {
        char c = label[i];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 'a' + 'A');
        out[i] = (uint8_t)c;
    }
}

/* --------------------------------------------------------------------------
 *  Public entry point
 * ------------------------------------------------------------------------ */

int fat_format(const char *device, const fat_format_opts_t *opts, char *err,
               size_t err_size)
{
    fat_format_opts_t defaults = FAT_FORMAT_OPTS_INIT;
    fat_io_t          io;
    mkgeom_t          g;
    uint64_t          device_size = 0;
    uint32_t          bps;
    uint32_t          num_fats;
    uint32_t          total_sectors;
    int               type;
    uint8_t           sector[FAT_MAX_SECTOR_SIZE];
    uint8_t           label[FAT_LABEL_LEN];
    int               rc = FAT_ERROR;

#define FAIL(...)                                                              \
    do {                                                                       \
        if (err && err_size)                                                   \
            snprintf(err, err_size, __VA_ARGS__);                              \
        goto out;                                                              \
    } while (0)

    if (err && err_size)
        err[0] = '\0';
    if (!device)
        return FAT_ERROR;

    if (!opts)
        opts = &defaults;

    memset(&io, 0, sizeof io);
    if (fat_io_open(&io, device, 0) != FAT_SUCCESS) {
        if (err && err_size)
            snprintf(err, err_size, "cannot open '%s': %s", device,
                     fat_io_strerror(&io));
        return FAT_ERROR;
    }
    if (fat_io_is_read_only(&io) != 0) {
        FAIL("'%s' is write protected", device);
    }
    if (fat_io_size(&io, &device_size) != FAT_SUCCESS || device_size == 0) {
        FAIL("the size of '%s' cannot be determined", device);
    }

    if (opts->bytes_per_sector &&
        (!is_pow2(opts->bytes_per_sector) ||
         opts->bytes_per_sector < FAT_MIN_SECTOR_SIZE ||
         opts->bytes_per_sector > FAT_MAX_SECTOR_SIZE)) {
        snprintf(err, err_size, "bytes_per_sector must be a power of two "
                                "between %u and %u",
                 (unsigned)FAT_MIN_SECTOR_SIZE, (unsigned)FAT_MAX_SECTOR_SIZE);
        return FAT_ERROR;
    }
    if (opts->cluster_bytes &&
        (opts->cluster_bytes < 512u || opts->cluster_bytes > 32u * 1024u ||
         !is_pow2(opts->cluster_bytes))) {
        snprintf(err, err_size, "cluster_bytes must be a power of two between "
                                "512 and 32768");
        return FAT_ERROR;
    }

    bps      = opts->bytes_per_sector ? opts->bytes_per_sector : 512;
    num_fats = opts->num_fats ? opts->num_fats : 2;

    total_sectors = (uint32_t)(device_size / bps);
    if (total_sectors < 8) {
        FAIL("'%s' is too small for a file system (%u sectors of %u bytes)",
             device, total_sectors, bps);
    }

    /* Default FAT type by capacity: FAT12 for floppy sized media, FAT16 up to
     * 512 MiB, FAT32 beyond that. */
    type = opts->fat_type;
    if (type == 0) {
        if (device_size <= 4ull * 1024u * 1024u)
            type = FAT_TYPE_FAT12;
        else if (device_size <= 512ull * 1024u * 1024u)
            type = FAT_TYPE_FAT16;
        else
            type = FAT_TYPE_FAT32;
    }
    if (type != FAT_TYPE_FAT12 && type != FAT_TYPE_FAT16 &&
        type != FAT_TYPE_FAT32) {
        FAIL("unsupported FAT type %d", type);
    }

    /* FAT12/16 usually describe their size with the 16-bit total-sector
     * field, but the 32-bit field is legal for them too - a FAT16 volume can
     * be up to 2 GiB.  The cluster count, not the sector count, is what
     * constrains the FAT flavour, and choose_geometry() enforces that. */

    {
        if (choose_geometry(&g, type, total_sectors, bps, num_fats,
                            opts->cluster_bytes) != FAT_SUCCESS) {
            FAIL("no usable geometry for %s on a %llu byte device",
                 fat_type_name(type), (unsigned long long)device_size);
        }
    }

    /* --- boot sector --------------------------------------------------- */
    {
        fat_bpb_t bpb;
        uint32_t  volume_id = (uint32_t)time(NULL) ^
                              ((uint32_t)total_sectors << 13);

        pad_label(opts->label, label);

        memset(&bpb, 0, sizeof bpb);
        bpb.bytes_per_sector    = (uint16_t)g.bps;
        bpb.sectors_per_cluster = (uint8_t)g.spc;
        bpb.reserved_sectors    = (uint16_t)g.reserved;
        bpb.num_fats            = (uint8_t)g.num_fats;
        bpb.root_entries        = (uint16_t)g.root_entries;
        bpb.total_sectors16     = (total_sectors <= 0xFFFFu)
                                      ? (uint16_t)total_sectors : 0;
        bpb.total_sectors32     = (total_sectors > 0xFFFFu)
                                      ? total_sectors : 0;
        bpb.media_descriptor    = g.media;
        bpb.sectors_per_fat16   = (type == FAT_TYPE_FAT32)
                                      ? 0 : (uint16_t)g.spf;
        bpb.sectors_per_track   = 32;
        bpb.num_heads           = 64;
        bpb.hidden_sectors      = 0;
        bpb.sectors_per_fat32   = (type == FAT_TYPE_FAT32) ? g.spf : 0;
        bpb.ext_flags           = 0;         /* both FATs are kept in sync  */
        bpb.fs_version          = 0;
        bpb.root_cluster        = (type == FAT_TYPE_FAT32) ? 2u : 0u;
        bpb.fs_info_sector      = (type == FAT_TYPE_FAT32) ? 1u : 0u;
        bpb.backup_boot_sector  = (type == FAT_TYPE_FAT32) ? 6u : 0u;
        bpb.drive_number        = 0x80;
        bpb.boot_signature      = 0x29;
        bpb.volume_id           = volume_id;
        memcpy(bpb.volume_label, label, FAT_LABEL_LEN);
        memcpy(bpb.fs_type, (type == FAT_TYPE_FAT12) ? "FAT12   " :
                            (type == FAT_TYPE_FAT16) ? "FAT16   " :
                                                       "FAT32   ", 8);

        fat_bpb_format(sector, &bpb);

        if (write_sector(&io, 0, bps, sector) != FAT_SUCCESS)
            FAIL("cannot write the boot sector: %s", fat_io_strerror(&io));

        if (type == FAT_TYPE_FAT32) {
            if (write_sector(&io, 6, bps, sector) != FAT_SUCCESS)
                FAIL("cannot write the backup boot sector: %s",
                     fat_io_strerror(&io));
        }
    }

    /* --- FSInfo (FAT32) ------------------------------------------------- */
    if (type == FAT_TYPE_FAT32) {
        memset(sector, 0, bps);
        fat_wr32(sector, FAT_FSINFO_LEAD_SIG);
        fat_wr32(sector + 484, FAT_FSINFO_STRUCT_SIG);
        fat_wr32(sector + 488, g.cluster_count - 1);   /* minus the root */
        fat_wr32(sector + 492, 3);                     /* first free hint */
        fat_wr32(sector + 508, FAT_FSINFO_TRAIL_SIG);

        if (write_sector(&io, 1, bps, sector) != FAT_SUCCESS ||
            write_sector(&io, 7, bps, sector) != FAT_SUCCESS) {
            FAIL("cannot write the FSInfo sector: %s", fat_io_strerror(&io));
        }
    }

    /* --- FATs ----------------------------------------------------------- */
    for (uint32_t copy = 0; copy < g.num_fats; copy++) {
        uint32_t first = g.fat_start + copy * g.spf;

        if (zero_sectors(&io, first, g.spf, bps) != FAT_SUCCESS)
            FAIL("cannot clear FAT copy %u: %s", copy + 1,
                 fat_io_strerror(&io));

        /* The first sector carries the reserved entries. */
        memset(sector, 0, bps);
        switch (type) {
        case FAT_TYPE_FAT12:
            put_entry(sector, type, 0, 0x0F00u | g.media);
            put_entry(sector, type, 1, type_eoc(type));
            break;
        case FAT_TYPE_FAT16:
            put_entry(sector, type, 0, 0xFF00u | g.media);
            put_entry(sector, type, 1, type_eoc(type));
            break;
        default:
            put_entry(sector, type, 0, 0x0FFFFF00u | g.media);
            /* Entry 1 holds the clean-shutdown and hard-error bits; a freshly
             * formatted volume is clean. */
            put_entry(sector, type, 1, 0x0FFFFFFFu);
            put_entry(sector, type, 2, type_eoc(type));   /* the root */
            break;
        }
        if (write_sector(&io, first, bps, sector) != FAT_SUCCESS)
            FAIL("cannot initialise FAT copy %u: %s", copy + 1,
                 fat_io_strerror(&io));
    }

    /* --- root directory ------------------------------------------------- */
    if (type == FAT_TYPE_FAT32) {
        uint32_t cluster_bytes = g.spc * bps;
        uint8_t *zeros = (uint8_t *)calloc(1, cluster_bytes);

        if (!zeros) {
            FAIL("out of memory clearing the root directory");
        }
        if (opts->label)
            memcpy(zeros, label, FAT_LABEL_LEN);       /* volume-id entry */
        if (opts->label)
            zeros[11] = FAT_ATTR_VOLUME_ID;

        rc = fat_io_write(&io, (uint64_t)g.data_start * bps, zeros,
                          cluster_bytes);
        free(zeros);
        if (rc != FAT_SUCCESS)
            FAIL("cannot initialise the root directory: %s",
                 fat_io_strerror(&io));
    } else {
        if (zero_sectors(&io, g.root_start, g.root_sectors, bps)
            != FAT_SUCCESS) {
            FAIL("cannot clear the root directory: %s", fat_io_strerror(&io));
        }
        if (opts->label) {
            uint8_t entry[FAT_DIRENT_SIZE];

            memset(entry, 0, sizeof entry);
            memcpy(entry, label, FAT_LABEL_LEN);
            entry[11] = FAT_ATTR_VOLUME_ID;
            if (fat_io_write(&io, (uint64_t)g.root_start * bps, entry,
                             sizeof entry) != FAT_SUCCESS) {
                FAIL("cannot write the volume label: %s",
                     fat_io_strerror(&io));
            }
        }
    }

    rc = FAT_SUCCESS;

out:
    fat_io_close(&io);
#undef FAIL
    return rc;
}
