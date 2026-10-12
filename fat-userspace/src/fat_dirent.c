/* ==========================================================================
 *  fat_dirent.c - directory entry marshalling and long-name encoding
 *
 *  A directory entry is 32 bytes:
 *
 *    0-10   short name, space padded ("NAME    EXT") or ".", ".."
 *    11     attributes
 *    12     reserved (NT case flags)
 *    13     creation time, tenths of a second
 *    14-15  creation time      16-17  creation date
 *    18-19  last access date
 *    20-21  first cluster, high word (FAT32 only, always 0 on FAT12/16)
 *    22-23  write time         24-25  write date
 *    26-27  first cluster, low word
 *    28-31  file size in bytes
 *
 *  A long name is stored as a run of entries with attribute 0x0F immediately
 *  *before* the short entry, highest ordinal first.  Each carries 13 UTF-16
 *  code units plus a checksum of the short name:
 *
 *    0      ordinal (bit 6 set on the last slot)   1-10    5 units
 *    11     0x0F                                   12      type, 0
 *    13     short-name checksum                    14-25   6 units
 *    26-27  first cluster, must be 0               28-31   2 units
 * ========================================================================== */

#include "fat.h"

#include <string.h>

#include "fat_util.h"

/* Byte offsets of the 13 UTF-16 units inside an LFN slot. */
static const uint8_t lfn_unit_pos[13] = {
    1, 3, 5, 7, 9,          /* units 1-5  */
    14, 16, 18, 20, 22, 24, /* units 6-11 */
    28, 30                  /* units 12-13 */
};

/* ==========================================================================
 *  Parsing
 * ========================================================================== */

void fat_dirent_parse(const uint8_t *raw, const char *long_name,
                      fat_dirent_t *out)
{
    uint16_t hi, lo;

    memset(out, 0, sizeof *out);

    out->attr           = raw[11];
    out->crt_time_tenth = raw[13];
    out->crt_time       = fat_rd16(raw + 14);
    out->crt_date       = fat_rd16(raw + 16);
    out->acc_date       = fat_rd16(raw + 18);
    hi                  = fat_rd16(raw + 20);
    out->wrt_time       = fat_rd16(raw + 22);
    out->wrt_date       = fat_rd16(raw + 24);
    lo                  = fat_rd16(raw + 26);
    out->size           = fat_rd32(raw + 28);
    out->first_cluster  = ((uint32_t)hi << 16) | lo;

    /* The short name is always rendered: it is what an 8.3-only driver will
     * show, and it is the name that must be matched on lookup. */
    fat_short_name_render_raw(raw, raw[12], long_name ? 1 : 0,
                              out->short_name);

    if (long_name && *long_name)
        strncpy(out->name, long_name, sizeof out->name - 1);
    else
        strncpy(out->name, out->short_name, sizeof out->name - 1);
    out->name[sizeof out->name - 1] = '\0';

    out->lfn_slots = 0;
    out->ref.offset = 0;
    out->ref.sector = 0;
}

/* ==========================================================================
 *  Formatting
 * ========================================================================== */

/* Render a "NAME.EXT" string into the 11-byte space-padded field. */
static int short_name_from_string(const char *name,
                                 uint8_t out[FAT_SHORT_NAME_LEN])
{
    const char *dot = strrchr(name, '.');
    size_t      i;
    size_t      base_len, ext_len;

    /* The self and parent references are literal 11-byte name fields.  Running
     * them through the 8.3 split below would store ".." as ".", giving every
     * directory two "." entries and no working parent link. */
    if ((name[0] == '.' && name[1] == '\0') ||
        (name[0] == '.' && name[1] == '.' && name[2] == '\0')) {
        memset(out, ' ', FAT_SHORT_NAME_LEN);
        memcpy(out, name, strlen(name));
        return FAT_SUCCESS;
    }

    if (dot && dot != name) {
        base_len = (size_t)(dot - name);
        ext_len  = strlen(dot + 1);
    } else {
        base_len = strlen(name);
        ext_len  = 0;
    }
    if (base_len == 0 || base_len > 8 || ext_len > 3)
        return FAT_ERROR;

    memset(out, ' ', FAT_SHORT_NAME_LEN);
    for (i = 0; i < base_len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == ' ')
            return FAT_ERROR;
        out[i] = (uint8_t)((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
    }
    for (i = 0; i < ext_len; i++) {
        unsigned char c = (unsigned char)dot[1 + i];
        if (c == ' ')
            return FAT_ERROR;
        out[8 + i] = (uint8_t)((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
    }

    /* 0xE5 as the first byte of a name would read as "deleted"; 0x05 is the
     * documented escape for it. */
    if (out[0] == 0xE5u)
        out[0] = FAT_DIRENT_ESCAPE;
    return FAT_SUCCESS;
}

void fat_dirent_format(uint8_t *raw, const fat_dirent_t *de)
{
    uint8_t name[FAT_SHORT_NAME_LEN];

    memset(raw, 0, FAT_DIRENT_SIZE);

    /* The short name is authoritative when it is given; otherwise it is
     * derived from the display name.  Failing both, the entry would carry a
     * blank name field, which is never useful, so the "~1" form is used. */
    if (de->short_name[0] == '\0' ||
        short_name_from_string(de->short_name, name) != FAT_SUCCESS) {
        if (fat_short_name_make(de->name, 0, name) != FAT_SUCCESS) {
            const char *dot = strrchr(de->name, '.');
            char        scratch[FAT_NAME_MAX];
            size_t      take;

            /* Last resort: keep the first 8 characters of the name. */
            take = dot ? (size_t)(dot - de->name) : strlen(de->name);
            if (take > 8)
                take = 8;
            if (take == 0)
                take = 1;
            memcpy(scratch, de->name, take);
            scratch[take] = '\0';
            if (fat_short_name_make(scratch, 0, name) != FAT_SUCCESS)
                memset(name, 'A', FAT_SHORT_NAME_LEN);
        }
    }
    memcpy(raw, name, FAT_SHORT_NAME_LEN);

    raw[11] = de->attr;
    raw[12] = 0;                       /* NT case flags: unused */
    raw[13] = de->crt_time_tenth;
    fat_wr16(raw + 14, de->crt_time);
    fat_wr16(raw + 16, de->crt_date);
    fat_wr16(raw + 18, de->acc_date);
    fat_wr16(raw + 20, (uint16_t)((de->first_cluster >> 16) & 0xFFFFu));
    fat_wr16(raw + 22, de->wrt_time);
    fat_wr16(raw + 24, de->wrt_date);
    fat_wr16(raw + 26, (uint16_t)(de->first_cluster & 0xFFFFu));
    fat_wr32(raw + 28, de->size);
}

/* ==========================================================================
 *  Long names
 * ========================================================================== */

uint32_t fat_lfn_build(const char *name,
                       const uint8_t short_name[FAT_SHORT_NAME_LEN],
                       uint8_t *raw, uint32_t max_slots)
{
    uint16_t units[FAT_LFN_MAX_CHARS + 1];
    size_t   len;
    uint32_t slots, s, k;
    uint8_t  checksum;

    len = fat_utf8_to_utf16(name, units, FAT_LFN_MAX_CHARS + 1);
    if (len == 0 || len > FAT_LFN_MAX_CHARS)
        return 0;

    slots = (uint32_t)((len + FAT_LFN_SLOTS_PER_ENTRY - 1) /
                       FAT_LFN_SLOTS_PER_ENTRY);
    if (slots == 0 || slots > max_slots || slots > FAT_LFN_MAX_SLOTS)
        return 0;

    checksum = fat_short_name_checksum(short_name);

    /* Slot ordinals run high to low across the run, and the highest ordinal
     * carries the LAST flag. */
    for (s = 0; s < slots; s++) {
        uint8_t *e = raw + s * FAT_DIRENT_SIZE;
        uint32_t ordinal = slots - s;

        memset(e, 0, FAT_DIRENT_SIZE);
        e[0]  = (uint8_t)ordinal;
        if (ordinal == slots)
            e[0] |= FAT_LFN_LAST;
        e[11] = FAT_ATTR_LFN;
        e[12] = 0;                       /* type: always 0 */
        e[13] = checksum;
        fat_wr16(e + 26, 0);             /* first cluster must be zero */

        for (k = 0; k < FAT_LFN_SLOTS_PER_ENTRY; k++) {
            uint32_t idx = (ordinal - 1u) * FAT_LFN_SLOTS_PER_ENTRY + k;
            uint16_t unit;

            if (idx < (uint32_t)len)
                unit = units[idx];
            else if (idx == (uint32_t)len)
                unit = 0x0000u;          /* terminator */
            else
                unit = 0xFFFFu;          /* padding */

            fat_wr16(e + lfn_unit_pos[k], unit);
        }
    }
    return slots;
}

int fat_lfn_collect(const uint8_t *raw, uint32_t slots,
                    uint8_t expected_checksum, char *name, size_t name_size)
{
    uint16_t units[FAT_LFN_MAX_CHARS + FAT_LFN_SLOTS_PER_ENTRY];
    uint32_t total = slots * FAT_LFN_SLOTS_PER_ENTRY;
    uint32_t s, n;

    if (slots == 0 || slots > FAT_LFN_MAX_SLOTS)
        return FAT_ERROR;
    if (total > sizeof(units) / sizeof(units[0]))
        return FAT_ERROR;

    memset(units, 0, sizeof units);

    for (s = 0; s < slots; s++) {
        const uint8_t *e = raw + s * FAT_DIRENT_SIZE;
        uint32_t ordinal = e[0] & FAT_LFN_ORD_MASK;
        uint32_t k;

        if (e[11] != FAT_ATTR_LFN || ordinal == 0 ||
            ordinal > FAT_LFN_MAX_SLOTS)
            return FAT_ERROR;
        if (e[13] != expected_checksum)
            return FAT_ERROR;
        if (ordinal != slots - s)         /* ordinals must descend by one */
            return FAT_ERROR;

        for (k = 0; k < FAT_LFN_SLOTS_PER_ENTRY; k++) {
            uint32_t idx = (ordinal - 1u) * FAT_LFN_SLOTS_PER_ENTRY + k;
            if (idx < total)
                units[idx] = fat_rd16(e + lfn_unit_pos[k]);
        }
    }

    for (n = 0; n < total; n++) {
        if (units[n] == 0x0000u || units[n] == 0xFFFFu)
            break;
    }
    if (n == 0)
        return FAT_ERROR;

    return fat_utf16_to_utf8(units, n, name, name_size) > 0
               ? FAT_SUCCESS : FAT_ERROR;
}
