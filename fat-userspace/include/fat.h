/* ==========================================================================
 *  fat.h - on-disk format definitions for FAT12 / FAT16 / FAT32
 *
 *  Design note
 *  -----------
 *  Nothing in this project casts a byte buffer to a packed struct.  On-disk
 *  fields are read and written through explicit little-endian accessors and
 *  the two structures that matter (boot sector, directory entry) have
 *  parse/format functions that marshal field by field.  That keeps the code
 *  correct regardless of compiler, struct padding, aliasing rules and host
 *  endianness - all of which the previous revision got wrong.
 *
 *  References:
 *    - Microsoft Extensible Firmware Initiative, "FAT32 File System
 *      Specification", revision 1.03
 *    - Microsoft, "FAT: General Overview of On-Disk Format", revision 1.02
 * ========================================================================== */

#ifndef FAT_H
#define FAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 *  Constants
 * ------------------------------------------------------------------------ */

#define FAT_SECTOR_SIZE        512u   /* assumed size, used before the BPB is
                                         trusted (the real size comes from the
                                         BPB's bytes_per_sector field)       */
#define FAT_MAX_SECTOR_SIZE   4096u
#define FAT_MIN_SECTOR_SIZE    512u
#define FAT_DIRENT_SIZE         32u   /* every directory entry is 32 bytes   */

#define FAT_SHORT_NAME_LEN      11u   /* raw 8.3 field: 8 + 3, space padded  */
#define FAT_SHORT_NAME_STR     13u    /* "NAME.EXT" + NUL                    */
#define FAT_LFN_MAX_CHARS      255u   /* max length of a long name (UTF-16)  */
#define FAT_LFN_SLOTS_PER_ENTRY  13u  /* UTF-16 units carried by one entry   */
#define FAT_LFN_MAX_SLOTS        20u  /* ceil(255 / 13)                      */
#define FAT_NAME_MAX            768u  /* UTF-8 buffer: 255 * 3 bytes + NUL   */
#define FAT_PATH_MAX            1024u
#define FAT_LABEL_LEN            11u

/* Errors.  FAT_SUCCESS/FAT_ERROR match fat_io.h and the original header. */
#define FAT_SUCCESS    0
#define FAT_ERROR     (-1)

/* FAT type discriminants - note these are *not* the bit widths; use the
 * FAT_TYPE_* values consistently instead of the old duplicate macros. */
#define FAT_TYPE_FAT12  12
#define FAT_TYPE_FAT16  16
#define FAT_TYPE_FAT32  32
#define FAT_TYPE_UNKNOWN 0

/* Cluster-count thresholds from the FAT spec (these define the type). */
#define FAT12_MAX_CLUSTERS   4084u
#define FAT16_MAX_CLUSTERS  65524u

/* Special cluster values (already normalised to the low 28 bits). */
#define FAT_CLUSTER_FREE        0x00000000u
#define FAT_CLUSTER_RESERVED    0x0FFFFFF0u
#define FAT_CLUSTER_BAD         0x0FFFFFF7u
#define FAT_CLUSTER_EOC_MIN     0x0FFFFFF8u   /* >= this means end-of-chain */
#define FAT_CLUSTER_EOC         0x0FFFFFFFu
#define FAT_CLUSTER_FIRST       2u            /* clusters 0 and 1 are reserved */

/* Directory entry attributes. */
#define FAT_ATTR_READ_ONLY  0x01u
#define FAT_ATTR_HIDDEN     0x02u
#define FAT_ATTR_SYSTEM     0x04u
#define FAT_ATTR_VOLUME_ID  0x08u
#define FAT_ATTR_DIRECTORY  0x10u
#define FAT_ATTR_ARCHIVE    0x20u
#define FAT_ATTR_LFN        0x0Fu   /* all four low bits set = LFN slot */
#define FAT_ATTR_MASK       0x3Fu

/* Special first bytes of the short-name field. */
#define FAT_DIRENT_END      0x00u   /* no further entries in this directory */
#define FAT_DIRENT_DELETED  0xE5u   /* entry is free for reuse */
#define FAT_DIRENT_ESCAPE   0x05u   /* real first byte is 0xE5 */

/* Layout constants for the LFN entry. */
#define FAT_LFN_LAST        0x40u   /* OR-ed into the ordinal of the final slot */
#define FAT_LFN_ORD_MASK    0x1Fu
#define FAT_LFN_TYPE_OFFSET 12u     /* must be 0 for valid LFN slots */

/* --------------------------------------------------------------------------
 *  Little-endian accessors
 * ------------------------------------------------------------------------ */

static inline uint16_t fat_rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t fat_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void fat_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void fat_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/* --------------------------------------------------------------------------
 *  Boot sector
 * ------------------------------------------------------------------------ */

/* Boot sector field offsets (identical for FAT12/16/32 up to 0x24). */
#define FAT_BPB_BYTES_PER_SECTOR     0x0B
#define FAT_BPB_SECTORS_PER_CLUSTER  0x0D
#define FAT_BPB_RESERVED_SECTORS     0x0E
#define FAT_BPB_NUM_FATS             0x10
#define FAT_BPB_ROOT_ENTRIES         0x11
#define FAT_BPB_TOTAL_SECTORS16      0x13
#define FAT_BPB_MEDIA_DESCRIPTOR     0x15
#define FAT_BPB_SECTORS_PER_FAT16    0x16
#define FAT_BPB_SECTORS_PER_TRACK    0x18
#define FAT_BPB_NUM_HEADS            0x1A
#define FAT_BPB_HIDDEN_SECTORS       0x1C
#define FAT_BPB_TOTAL_SECTORS32      0x20
#define FAT_BPB_SECTORS_PER_FAT32    0x24
#define FAT_BPB_EXT_FLAGS            0x28
#define FAT_BPB_FS_VERSION           0x2A
#define FAT_BPB_ROOT_CLUSTER         0x2C
#define FAT_BPB_FS_INFO              0x30
#define FAT_BPB_BACKUP_BOOT          0x32
/* The extended BPB sits at different offsets depending on the FAT flavour.
 * On FAT12/16 it starts at 0x24; on FAT32 the extra EBPB fields push it to
 * 0x40.  Using the wrong set reads boot code as a volume label. */
#define FAT_BPB16_DRIVE_NUMBER       0x24
#define FAT_BPB16_BOOT_SIG           0x26
#define FAT_BPB16_VOLUME_ID          0x27
#define FAT_BPB16_VOLUME_LABEL       0x2B
#define FAT_BPB16_FS_TYPE            0x36
#define FAT_BPB32_DRIVE_NUMBER       0x40
#define FAT_BPB32_BOOT_SIG           0x42
#define FAT_BPB32_VOLUME_ID          0x43
#define FAT_BPB32_VOLUME_LABEL       0x47
#define FAT_BPB32_FS_TYPE            0x52
#define FAT_BOOT_SIGNATURE_OFFSET    0x1FE
#define FAT_BOOT_SIGNATURE           0xAA55u

#define FAT_FSINFO_LEAD_SIG  0x41615252u
#define FAT_FSINFO_STRUCT_SIG 0x61417272u
#define FAT_FSINFO_TRAIL_SIG 0xAA550000u
#define FAT_FSINFO_UNKNOWN   0xFFFFFFFFu

/* Boot sector in host form. */
typedef struct {
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  num_fats;
    uint16_t root_entries;
    uint16_t total_sectors16;
    uint8_t  media_descriptor;
    uint16_t sectors_per_fat16;
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors32;
    /* FAT32 extended BPB */
    uint32_t sectors_per_fat32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info_sector;
    uint16_t backup_boot_sector;
    uint8_t  drive_number;
    uint8_t  boot_signature;
    uint32_t volume_id;
    char     volume_label[FAT_LABEL_LEN + 1];
    char     fs_type[9];
} fat_bpb_t;

/* Parse/format a 512-byte (or larger) boot sector buffer.  fat_bpb_parse()
 * performs no validation beyond field extraction - fat_core.c owns the
 * consistency checks. */
void fat_bpb_parse(const uint8_t *sector, fat_bpb_t *bpb);
void fat_bpb_format(uint8_t *sector, const fat_bpb_t *bpb);

/* --------------------------------------------------------------------------
 *  Directory entries
 * ------------------------------------------------------------------------ */

/* Where a directory entry physically lives.  The offset is measured within
 * the directory, whose size is itself a 32-bit quantity (see fat_dir_size),
 * so a 32-bit offset is sufficient and avoids casts everywhere. */
typedef struct {
    uint32_t offset;   /* byte offset of the 32-byte entry in the directory */
    uint32_t sector;   /* absolute sector number, for diagnostics          */
} fat_dirent_ref_t;

/* A directory entry in host form. */
typedef struct {
    char     name[FAT_NAME_MAX];       /* display name: LFN, or rendered 8.3 */
    char     short_name[FAT_SHORT_NAME_STR];
    uint8_t  attr;
    uint32_t first_cluster;
    uint32_t size;
    uint16_t crt_time;                 /* FAT time/date stamps */
    uint16_t crt_date;
    uint8_t  crt_time_tenth;
    uint16_t acc_date;
    uint16_t wrt_time;
    uint16_t wrt_date;
    uint32_t lfn_slots;                /* LFN entries owned by this entry    */
    fat_dirent_ref_t ref;              /* where to find it on disk           */
} fat_dirent_t;

/* Parse one raw 32-byte entry plus the name it should be shown under.  If the
 * caller has already reassembled a long name it passes it via @long_name;
 * passing NULL renders the 8.3 name (honouring the NT lowercase flags). */
void fat_dirent_parse(const uint8_t *raw, const char *long_name,
                      fat_dirent_t *out);

/* Render a directory entry back to its 32 raw bytes. */
void fat_dirent_format(uint8_t *raw, const fat_dirent_t *de);

/* Reassemble the long name carried by an LFN slot sequence.  @raw is the
 * buffer holding @slots entries with the slot at index 0 being the LAST one
 * (0x40 flag).  Returns FAT_SUCCESS and fills @name (UTF-8) if the ordinal
 * sequence and checksum are consistent, FAT_ERROR otherwise. */
int fat_lfn_collect(const uint8_t *raw, uint32_t slots,
                    uint8_t expected_checksum, char *name, size_t name_size);

/* Build the LFN slot sequence for @name into @raw (slots * 32 bytes), with the
 * entries stored in the on-disk order (last slot first).  Returns the number
 * of slots used, or 0 if @name cannot be represented or is a valid 8.3 name
 * that needs no long entry. */
uint32_t fat_lfn_build(const char *name,
                       const uint8_t short_name[FAT_SHORT_NAME_LEN],
                       uint8_t *raw, uint32_t max_slots);

/* Checksum of an 11-byte short name, as used by LFN entries. */
uint8_t fat_short_name_checksum(const uint8_t short_name[FAT_SHORT_NAME_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* FAT_H */
