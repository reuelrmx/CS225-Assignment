/* ==========================================================================
 *  fat_util.c - timestamps, name handling, UTF-16 conversion, path helpers
 * ========================================================================== */

#include "fat_util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* ==========================================================================
 *  Timestamps
 * ========================================================================== */

void fat_now(uint16_t *out_time, uint16_t *out_date)
{
    int year, month, day, hour, minute, second;

#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    year   = st.wYear;
    month  = st.wMonth;
    day    = st.wDay;
    hour   = st.wHour;
    minute = st.wMinute;
    second = st.wSecond;
#else
    time_t     t = time(NULL);
    struct tm  tm_now;
    struct tm *tmp = localtime(&t);

    if (!tmp) {
        /* Deterministic fallback keeps callers free of error handling. */
        year = 1980; month = 1; day = 1; hour = 0; minute = 0; second = 0;
    } else {
        tm_now = *tmp;
        year   = tm_now.tm_year + 1900;
        month  = tm_now.tm_mon + 1;
        day    = tm_now.tm_mday;
        hour   = tm_now.tm_hour;
        minute = tm_now.tm_min;
        second = tm_now.tm_sec;
    }
#endif

    if (year < 1980)
        year = 1980;
    if (year > 2107)          /* 7-bit year field, relative to 1980 */
        year = 2107;
    if (month  < 1 || month  > 12) month  = 1;
    if (day    < 1 || day    > 31) day    = 1;
    if (hour   < 0 || hour   > 23) hour   = 0;
    if (minute < 0 || minute > 59) minute = 0;
    if (second < 0 || second > 59) second = 0;

    *out_time = FAT_TIME(hour, minute, second);
    *out_date = FAT_DATE(year, month, day);
}

int fat_time_to_string(uint16_t fat_time, uint16_t fat_date,
                       char *buffer, size_t buffer_size)
{
    unsigned year   = ((fat_date >> 9) & 0x7Fu) + 1980u;
    unsigned month  = (fat_date >> 5) & 0x0Fu;
    unsigned day    = fat_date & 0x1Fu;
    unsigned hour   = (fat_time >> 11) & 0x1Fu;
    unsigned minute = (fat_time >> 5) & 0x3Fu;
    unsigned second = (fat_time & 0x1Fu) * 2u;

    if (!buffer || buffer_size < 20)
        return FAT_ERROR;

    snprintf(buffer, buffer_size, "%04u-%02u-%02u %02u:%02u:%02u",
             year, month, day, hour, minute, second);
    return FAT_SUCCESS;
}

/* ==========================================================================
 *  Names
 * ========================================================================== */

static int is_separator(int c) { return c == '/' || c == '\\'; }

/* Characters the FAT specification forbids in any name.  Note this is the
 * long-name set: it is also applied to 8.3 names, which is stricter and
 * therefore safe. */
static int name_char_forbidden(unsigned char c)
{
    if (c < 0x20 || c == 0x7F)
        return 1;
    switch (c) {
    case '"': case '*': case '/': case ':': case '<':
    case '>': case '?': case '\\': case '|':
        return 1;
    default:
        return 0;
    }
}

/* Extra characters that a *short* (8.3) name may not contain. */
static int short_char_forbidden(unsigned char c)
{
    switch (c) {
    case '+': case ',': case ';': case '=': case '[': case ']':
        return 1;
    default:
        return name_char_forbidden(c);
    }
}

int fat_name_is_valid(const char *name)
{
    size_t i, len;

    if (!name || !*name)
        return FAT_ERROR;

    len = strlen(name);
    if (len > FAT_LFN_MAX_CHARS)
        return FAT_ERROR;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return FAT_ERROR;

    /* A trailing dot or space cannot be represented consistently: Windows
     * strips them when creating a file, so an image containing such a name
     * would be ambiguous. */
    if (name[len - 1] == '.' || name[len - 1] == ' ')
        return FAT_ERROR;

    for (i = 0; i < len; i++) {
        if (name_char_forbidden((unsigned char)name[i]))
            return FAT_ERROR;
    }
    return FAT_SUCCESS;
}

static unsigned char to_upper_ascii(unsigned char c)
{
    return (c >= 'a' && c <= 'z') ? (unsigned char)(c - 'a' + 'A') : c;
}

int fat_name_equals(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        if (to_upper_ascii((unsigned char)*a) !=
            to_upper_ascii((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int fat_name_is_short(const char *name)
{
    const char *dot;
    size_t      base, ext, i;

    if (!name || !*name)
        return 0;

    dot = strrchr(name, '.');
    if (dot) {
        base = (size_t)(dot - name);
        ext  = strlen(dot + 1);
        if (dot == name || base == 0 || ext == 0 || ext > 3)
            return 0;
    } else {
        base = strlen(name);
        ext  = 0;
        if (base == 0 || base > 8)
            return 0;
    }
    if (base > 8)
        return 0;

    for (i = 0; name[i]; i++) {
        if (name[i] == '.') {
            if (i != base)     /* only the single separator dot is allowed */
                return 0;
            continue;
        }
        if (short_char_forbidden((unsigned char)name[i]))
            return 0;
        if (name[i] == ' ')
            return 0;
        /* A name that is not already upper case needs an LFN slot to carry
         * the lower case bits (or the NT case flags). */
        if (name[i] >= 'a' && name[i] <= 'z')
            return 0;
    }
    return 1;
}

int fat_short_name_make(const char *name, unsigned tail,
                        uint8_t out[FAT_SHORT_NAME_LEN])
{
    char     base[9], ext[4];
    size_t   bi = 0, ei = 0, i;
    const char *dot;
    size_t   base_src, ext_src;

    if (!name || !out || !*name)
        return FAT_ERROR;

    /* "." and ".." are literal name fields, not 8.3 names: the dot-splitting
     * below would turn ".." into a base name of "." and an empty extension,
     * which is how a directory ends up with two "." entries and no parent
     * reference at all. */
    if ((name[0] == '.' && name[1] == '\0') ||
        (name[0] == '.' && name[1] == '.' && name[2] == '\0')) {
        memset(out, ' ', FAT_SHORT_NAME_LEN);
        memcpy(out, name, strlen(name));
        return FAT_SUCCESS;
    }

    memset(base, 0, sizeof base);
    memset(ext, 0, sizeof ext);

    dot = strrchr(name, '.');
    if (dot && dot != name) {
        base_src = (size_t)(dot - name);
        ext_src  = strlen(dot + 1);
    } else {
        base_src = strlen(name);
        ext_src  = 0;
    }
    if (base_src == 0)
        return FAT_ERROR;

    /* Base name, up to 8 characters; the tail is appended at the end. */
    {
        char tailbuf[12];
        size_t tail_len = 0;

        if (tail) {
            /* Bounded to 6 digits by the caller's retry loop; anything that
             * would not fit is an error rather than a silent truncation. */
            if (tail > 999999u)
                return FAT_ERROR;
            snprintf(tailbuf, sizeof tailbuf, "~%u", tail);
            tail_len = strlen(tailbuf);
            if (tail_len >= 8)
                return FAT_ERROR;
        }
        {
            size_t keep = 8u - tail_len;
            for (i = 0; i < base_src && bi < keep; i++) {
                unsigned char c = (unsigned char)name[i];
                if (c == ' ' || c == '.')
                    continue;
                if (short_char_forbidden(c))
                    return FAT_ERROR;
                base[bi++] = (char)to_upper_ascii(c);
            }
            if (bi == 0)
                return FAT_ERROR;
            if (tail) {
                for (i = 0; i < tail_len; i++)
                    base[bi++] = tailbuf[i];
            }
        }
    }

    for (i = 0; i < ext_src && ei < 3; i++) {
        unsigned char c = (unsigned char)dot[1 + i];
        if (short_char_forbidden(c) || c == ' ')
            return FAT_ERROR;
        ext[ei++] = (char)to_upper_ascii(c);
    }

    memset(out, ' ', FAT_SHORT_NAME_LEN);
    for (i = 0; i < bi && i < 8; i++)
        out[i] = (uint8_t)base[i];
    for (i = 0; i < ei && i < 3; i++)
        out[8 + i] = (uint8_t)ext[i];
    return FAT_SUCCESS;
}

void fat_short_name_render_raw(const uint8_t raw[FAT_SHORT_NAME_LEN],
                               uint8_t nt_flags, int has_lfn,
                               char out[FAT_SHORT_NAME_STR])
{
    char     base[9];
    char     ext[4];
    size_t   base_len = 8, ext_len = 3, w = 0;
    uint8_t  first;
    int      i;

    first = raw[0];
    /* 0x05 in the first byte is the escape for a real 0xE5 (used as a KANJI
     * lead byte); without this it would read as a deleted entry. */
    if (first == FAT_DIRENT_ESCAPE)
        first = FAT_DIRENT_DELETED;

    memcpy(base, raw, 8);
    base[0] = (char)first;
    memcpy(ext, raw + 8, 3);

    if (!has_lfn) {
        /* NT keeps per-name lower-case hints in the reserved byte, but they
         * are only meaningful when no long name is present. */
        if (nt_flags & 0x08u)
            for (i = 0; i < 8; i++)
                if (base[i] >= 'A' && base[i] <= 'Z')
                    base[i] = (char)(base[i] - 'A' + 'a');
        if (nt_flags & 0x10u)
            for (i = 0; i < 3; i++)
                if (ext[i] >= 'A' && ext[i] <= 'Z')
                    ext[i] = (char)(ext[i] - 'A' + 'a');
    }

    /* The field is space padded; keep whatever the directory actually holds
     * (including internal spaces in the base name) and drop only the padding. */
    while (base_len > 0 && base[base_len - 1] == ' ')
        base_len--;
    while (ext_len > 0 && ext[ext_len - 1] == ' ')
        ext_len--;

    for (i = 0; i < (int)base_len; i++)
        out[w++] = base[i];
    if (ext_len) {
        out[w++] = '.';
        for (i = 0; i < (int)ext_len; i++)
            out[w++] = ext[i];
    }
    out[w] = '\0';
}

void fat_short_name_render(const uint8_t raw[FAT_SHORT_NAME_LEN],
                           uint8_t nt_flags, char out[FAT_SHORT_NAME_STR])
{
    fat_short_name_render_raw(raw, nt_flags, 0, out);
}

uint8_t fat_short_name_checksum(const uint8_t short_name[FAT_SHORT_NAME_LEN])
{
    uint8_t sum = 0;
    int     i;

    for (i = 0; i < (int)FAT_SHORT_NAME_LEN; i++)
        sum = (uint8_t)(((sum & 1u) << 7) + (sum >> 1) + short_name[i]);
    return sum;
}

/* ==========================================================================
 *  UTF-8 <-> UTF-16
 * ========================================================================== */

size_t fat_utf8_to_utf16(const char *utf8, uint16_t *out, size_t max_units)
{
    size_t              n = 0;
    const unsigned char *p = (const unsigned char *)utf8;

    if (!utf8 || !out)
        return 0;

    while (*p) {
        uint32_t cp;
        int      extra_bytes;

        if (p[0] < 0x80u) {
            cp          = p[0];
            extra_bytes = 0;
        } else if ((p[0] & 0xE0u) == 0xC0u) {
            cp          = (uint32_t)(p[0] & 0x1Fu);
            extra_bytes = 1;
        } else if ((p[0] & 0xF0u) == 0xE0u) {
            cp          = (uint32_t)(p[0] & 0x0Fu);
            extra_bytes = 2;
        } else if ((p[0] & 0xF8u) == 0xF0u) {
            cp          = (uint32_t)(p[0] & 0x07u);
            extra_bytes = 3;
        } else {
            return 0;                       /* invalid lead byte */
        }
        p++;

        for (int i = 0; i < extra_bytes; i++) {
            if ((*p & 0xC0u) != 0x80u)
                return 0;                   /* truncated sequence */
            cp = (cp << 6) | (uint32_t)(*p & 0x3Fu);
            p++;
        }

        /* Reject overlong encodings and out-of-range code points. */
        static const uint32_t min_cp[4] = { 0u, 0x80u, 0x800u, 0x10000u };
        if (cp < min_cp[extra_bytes])
            return 0;
        if (cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu))
            return 0;
        if (cp == 0)
            return 0;

        if (cp < 0x10000u) {
            if (n + 1 > max_units)
                return 0;
            out[n++] = (uint16_t)cp;
        } else {
            uint32_t v = cp - 0x10000u;
            if (n + 2 > max_units)
                return 0;
            out[n++] = (uint16_t)(0xD800u + (v >> 10));
            out[n++] = (uint16_t)(0xDC00u + (v & 0x3FFu));
        }
    }
    return n;
}

size_t fat_utf16_to_utf8(const uint16_t *units, size_t unit_count,
                         char *out, size_t out_size)
{
    size_t w = 0;
    size_t i = 0;

    if (!units || !out || out_size == 0)
        return 0;

    while (i < unit_count) {
        uint32_t cp = units[i++];

        if (cp >= 0xD800u && cp <= 0xDBFFu) {         /* high surrogate */
            if (i < unit_count && units[i] >= 0xDC00u && units[i] <= 0xDFFFu) {
                cp = 0x10000u + ((cp - 0xD800u) << 10) +
                     (uint32_t)(units[i] - 0xDC00u);
                i++;
            } else {
                cp = 0xFFFDu;                         /* lone surrogate */
            }
        } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
            cp = 0xFFFDu;                             /* lone low surrogate */
        }

        if (cp < 0x80u) {
            if (w + 1 >= out_size) return 0;
            out[w++] = (char)cp;
        } else if (cp < 0x800u) {
            if (w + 2 >= out_size) return 0;
            out[w++] = (char)(0xC0u | (cp >> 6));
            out[w++] = (char)(0x80u | (cp & 0x3Fu));
        } else if (cp < 0x10000u) {
            if (w + 3 >= out_size) return 0;
            out[w++] = (char)(0xE0u | (cp >> 12));
            out[w++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
            out[w++] = (char)(0x80u | (cp & 0x3Fu));
        } else {
            if (w + 4 >= out_size) return 0;
            out[w++] = (char)(0xF0u | (cp >> 18));
            out[w++] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
            out[w++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
            out[w++] = (char)(0x80u | (cp & 0x3Fu));
        }
    }
    out[w] = '\0';
    return w;
}

/* ==========================================================================
 *  Paths
 * ========================================================================== */

int fat_path_split(const char *path, char *dir, size_t dir_size,
                   char *leaf, size_t leaf_size)
{
    const char *p;
    const char *sep = NULL;
    size_t      dir_len;

    if (!path || !dir || !leaf || !*path)
        return FAT_ERROR;

    for (p = path; *p; p++) {
        if (is_separator((unsigned char)*p))
            sep = p;
    }

    if (!sep) {
        dir_len = 1u;
        if (dir_size < 2)
            return FAT_ERROR;
        dir[0] = '.';
        dir[1] = '\0';
        if (strlen(path) + 1 > leaf_size)
            return FAT_ERROR;
        strcpy(leaf, path);
        return FAT_SUCCESS;
    }

    if (strlen(sep + 1) + 1 > leaf_size)
        return FAT_ERROR;

    dir_len = (size_t)(sep - path);
    while (dir_len > 0 && is_separator((unsigned char)path[dir_len - 1]))
        dir_len--;                              /* trailing separators */

    if (dir_len == 0)
        dir_len = 1;                            /* "\\file" or "/file" */

    if (dir_len + 1 > dir_size)
        return FAT_ERROR;

    memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    strcpy(leaf, sep + 1);
    return FAT_SUCCESS;
}

char *fat_path_normalize(const char *path, char *out, size_t out_size)
{
    size_t   w = 0;
    const char *p;
    /* Stack of component offsets so ".." can pop the previous component. */
    size_t   marks[FAT_PATH_MAX / 2];
    size_t   depth = 0;

    if (!out || out_size < 2)
        return NULL;

    out[w++] = '/';

    if (!path)
        path = "";

    p = path;
    while (*p) {
        const char *start;
        size_t      len;

        while (*p && is_separator((unsigned char)*p))
            p++;
        if (!*p)
            break;

        start = p;
        while (*p && !is_separator((unsigned char)*p))
            p++;
        len = (size_t)(p - start);

        if (len == 1 && start[0] == '.')
            continue;

        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth > 0) {
                w = marks[--depth];
                if (w == 0)
                    w = 1;              /* never remove the leading '/' */
            }
            continue;
        }

        if (w > 1) {
            if (w + 1 >= out_size)
                return NULL;
            out[w++] = '/';
        }
        if (w + len >= out_size)
            return NULL;
        memcpy(out + w, start, len);
        w += len;
        out[w] = '\0';

        if (depth < sizeof(marks) / sizeof(marks[0]))
            marks[depth++] = (w > 1) ? w - len - 1 : 1;
    }

    out[w] = '\0';
    return out;
}
