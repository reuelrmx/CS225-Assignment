/* ==========================================================================
 *  fat_util.h - shared helpers: FAT timestamps, long-name encoding, paths
 * ========================================================================== */

#ifndef FAT_UTIL_H
#define FAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "fat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 *  Timestamps
 *
 *  FAT stores a date as  year-1980 (7 bits) | month (4) | day (5)
 *  and a time as  hours (5) | minutes (6) | seconds/2 (5).
 * ------------------------------------------------------------------------ */

#define FAT_DATE(y, m, d) \
    ((uint16_t)((((uint32_t)(y) - 1980u) << 9) | ((uint32_t)(m) << 5) | \
                (uint32_t)(d)))
#define FAT_TIME(h, m, s) \
    ((uint16_t)(((uint32_t)(h) << 11) | ((uint32_t)(m) << 5) | \
                ((uint32_t)(s) / 2u)))

/* Current local time as a FAT date/time pair. */
void fat_now(uint16_t *out_time, uint16_t *out_date);

/* "YYYY-MM-DD HH:MM:SS".  Returns FAT_SUCCESS, or FAT_ERROR if the buffer is
 * too small.  Keeps the name and signature of the original header. */
int fat_time_to_string(uint16_t fat_time, uint16_t fat_date,
                       char *buffer, size_t buffer_size);

/* --------------------------------------------------------------------------
 *  Names
 * ------------------------------------------------------------------------ */

/* Validate a long name.  Rejects the characters the FAT specification
 * reserves, control characters, a trailing dot or space, over-long names and
 * the special names "." and "..".  Returns FAT_SUCCESS or FAT_ERROR. */
int fat_name_is_valid(const char *name);

/* Case-insensitive ASCII comparison, which is how FAT resolves names. */
int fat_name_equals(const char *a, const char *b);

/* Is @name already a well-formed 8.3 name (so no LFN slot is needed)? */
int fat_name_is_short(const char *name);

/* Build the 11-byte short name for @name.  @tail is the numeric disambiguator
 * used when the name does not fit in 8.3 (0 = no tail, 1 => "~1", ...).
 * Writes 11 bytes, space padded, upper case; returns FAT_SUCCESS, or
 * FAT_ERROR if no representation is possible. */
int fat_short_name_make(const char *name, unsigned tail,
                        uint8_t out[FAT_SHORT_NAME_LEN]);

/* Render 11 raw bytes into "NAME.EXT" form, applying the NT lowercase flags
 * in @nt_flags (bit 3 = base lower case, bit 4 = extension lower case). */
void fat_short_name_render(const uint8_t raw[FAT_SHORT_NAME_LEN],
                           uint8_t nt_flags, char out[FAT_SHORT_NAME_STR]);

/* Raw 11-byte field to a string; the 0x05 escape is translated back to 0xE5
 * and the trailing spaces are stripped.  @has_lfn suppresses the lowercase
 * handling, because Windows ignores the NT flags when an LFN is present. */
void fat_short_name_render_raw(const uint8_t raw[FAT_SHORT_NAME_LEN],
                               uint8_t nt_flags, int has_lfn,
                               char out[FAT_SHORT_NAME_STR]);

/* --------------------------------------------------------------------------
 *  UTF-8 <-> UTF-16 (long names are stored as UTF-16 code units)
 * ------------------------------------------------------------------------ */

/* Convert @utf8 to UTF-16 units.  Returns the number of units written, or 0 on
 * malformed input or if it would not fit in @max_units. */
size_t fat_utf8_to_utf16(const char *utf8, uint16_t *out, size_t max_units);

/* Convert @units UTF-16 units to UTF-8.  Invalid sequences become U+FFFD.
 * Returns the number of bytes written, or 0 if the output does not fit. */
size_t fat_utf16_to_utf8(const uint16_t *units, size_t unit_count,
                         char *out, size_t out_size);

/* --------------------------------------------------------------------------
 *  Paths
 * ------------------------------------------------------------------------ */

/* Split @path into the parent directory and the final component.  Both '/'
 * and '\' are accepted as separators.  @dir receives "." for a bare name.
 * Returns FAT_SUCCESS, or FAT_ERROR if @path is empty or purely separators. */
int fat_path_split(const char *path, char *dir, size_t dir_size,
                   char *leaf, size_t leaf_size);

/* Collapse repeated separators and resolve "." and ".." components
 * textually.  @out always starts with '/'.  Returns @out. */
char *fat_path_normalize(const char *path, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* FAT_UTIL_H */
