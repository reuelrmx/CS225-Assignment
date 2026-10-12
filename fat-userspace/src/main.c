/* ==========================================================================
 *  main.c - the `fatfs` command line tool
 *
 *  Commands
 *  --------
 *    info    <dev>                 volume geometry, free space and label
 *    ls      <dev> [path]          list a directory
 *    cat     <dev> <path>          write a file to stdout
 *    get     <dev> <src> <dst>     copy a file out of the volume
 *    put     <dev> <src> <dst>     copy a host file into the volume
 *    mkdir   <dev> <path>          create a directory
 *    rmdir   <dev> <path>          remove an empty directory
 *    rm      <dev> <path>          remove a file
 *    mv      <dev> <old> <new>     move or rename
 *    cp      <dev> <src> <dst>     copy inside the volume
 *    touch   <dev> <path>          create an empty file
 *    attr    <dev> <path> [flags]  show or set attributes (R H S A)
 *    tree    <dev> [path]          recursive listing
 *    check   <dev> [--repair]      verify the volume, optionally repairing
 *
 *  Options
 *  -------
 *    -r, --read-only     never write to the device
 *    -o, --offset N      mount the volume N bytes into the device
 *    -l, --long          long listing
 *    -v, --verbose       extra diagnostics
 *    -h, --help
 *
 *  Exit status: 0 success, 1 usage or operational error, 2 the volume failed
 *  its consistency check.
 * ========================================================================== */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fat_core.h"
#include "fat_fs.h"
#include "fat_util.h"

#define EXIT_OK      0
#define EXIT_FAIL    1
#define EXIT_CHECK   2

typedef struct {
    int      read_only;
    int      long_format;
    int      verbose;
    uint64_t offset;
    int      repair;
    int      format_type;      /* FAT_TYPE_* for `format`, 0 = automatic */
    uint32_t cluster_bytes;    /* 0 = let `format` choose                 */
} options_t;

static void usage(FILE *out)
{
    fprintf(out,
"usage: fatfs [options] <command> <device> [arguments]\n"
"\n"
"commands:\n"
"  info   <dev>                 show volume geometry, free space and label\n"
"  ls     <dev> [path]          list a directory (default /)\n"
"  cat    <dev> <path>          write a file to standard output\n"
"  get    <dev> <src> <dst>     copy a file out of the volume\n"
"  put    <dev> <src> <dst>     copy a host file into the volume\n"
"  mkdir  <dev> <path>          create a directory\n"
"  rmdir  <dev> <path>          remove an empty directory\n"
"  rm     <dev> <path>          remove a file\n"
"  mv     <dev> <old> <new>     move or rename\n"
"  cp     <dev> <src> <dst>     copy a file inside the volume\n"
"  touch  <dev> <path>          create an empty file\n"
"  attr   <dev> <path> [+-RHSA] show or set attributes; a specification\n"
"                               that starts with '-' needs a leading --\n"
"  tree   <dev> [path]          recursive listing\n"
"  check  <dev> [--repair]      verify the volume; --repair applies the\n"
"                               safe fixes (FAT mirror, FSInfo, sizes)\n"
"\n"
"  format <dev> [label]         create a file system on <dev> (destroys it);\n"
"                               -t picks fat12/fat16/fat32, the default is\n"
"                               the type that suits the device size\n"
"\n"
"options:\n"
"  -r, --read-only     open the device read-only\n"
"  -o, --offset N      start the volume N bytes into the device\n"
"  -l, --long          long listing (size, attributes, date)\n"
"  -t, --type N        FAT type for `format`: 12, 16 or 32\n"
"  -c, --cluster N     cluster size for `format`, in bytes or with a k\n"
"                      suffix (512 ... 32768)\n"
"  -v, --verbose       print library diagnostics\n"
"  -h, --help          this text\n");
}

/* Case-insensitive comparison for the small set of ASCII keywords we accept
 * (avoids depending on strcasecmp, which is POSIX-only). */
static int eq_nocase(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = (*a >= 'A' && *a <= 'Z') ? *a - 'A' + 'a' : *a;
        int cb = (*b >= 'A' && *b <= 'Z') ? *b - 'A' + 'a' : *b;
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int is_flag(const char *arg, const char *short_form,
                   const char *long_form)
{
    return strcmp(arg, short_form) == 0 || strcmp(arg, long_form) == 0;
}

/* Options may appear anywhere on the command line; everything that is not an
 * option is collected, in order, into @rest. */
static int parse_options(int argc, char **argv, options_t *opt,
                         const char **rest, int *rest_count)
{
    int i;
    int n = 0;
    int end_of_options = 0;

    memset(opt, 0, sizeof *opt);

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        /* A bare '+' is how attribute masks are written, and everything after
         * "--" is data rather than options, so neither can be mistaken for a
         * flag. */
        if (end_of_options || arg[0] == '+' || arg[0] == '\0' ||
            (arg[0] != '-' && arg[0] != '+')) {
            rest[n++] = arg;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            end_of_options = 1;
            continue;
        }
        if (arg[1] == '\0') {           /* "-" alone is a file name */
            rest[n++] = arg;
            continue;
        }
        if (is_flag(arg, "-r", "--read-only")) {
            opt->read_only = 1;
        } else if (is_flag(arg, "-l", "--long") ||
                   is_flag(arg, "-p", "--long")) {
            opt->long_format = 1;
        } else if (is_flag(arg, "-v", "--verbose")) {
            opt->verbose = 1;
        } else if (is_flag(arg, "-h", "--help")) {
            usage(stdout);
            exit(EXIT_OK);
        } else if (is_flag(arg, "-o", "--offset")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "fatfs: %s needs a value\n", arg);
                return EXIT_FAIL;
            }
            opt->offset = strtoull(argv[++i], NULL, 0);
        } else if (is_flag(arg, "-c", "--cluster")) {
            const char *v;
            char       *end = NULL;
            unsigned long long want;

            if (i + 1 >= argc) {
                fprintf(stderr, "fatfs: %s needs a value\n", arg);
                return EXIT_FAIL;
            }
            v = argv[++i];
            want = strtoull(v, &end, 0);
            if (end && (*end == 'k' || *end == 'K')) {
                want *= 1024ull;
                end++;
            }
            if (!end || *end != '\0' || want == 0 || want > 0xFFFFFFFFull) {
                fprintf(stderr, "fatfs: bad cluster size '%s'\n", v);
                return EXIT_FAIL;
            }
            opt->cluster_bytes = (uint32_t)want;
        } else if (strcmp(arg, "--repair") == 0) {
            opt->repair = 1;
        } else if (is_flag(arg, "-t", "--type")) {
            const char *t;

            if (i + 1 >= argc) {
                fprintf(stderr, "fatfs: %s needs a value\n", arg);
                return EXIT_FAIL;
            }
            t = argv[++i];
            if (strcmp(t, "12") == 0 || eq_nocase(t, "fat12"))
                opt->format_type = FAT_TYPE_FAT12;
            else if (strcmp(t, "16") == 0 || eq_nocase(t, "fat16"))
                opt->format_type = FAT_TYPE_FAT16;
            else if (strcmp(t, "32") == 0 || eq_nocase(t, "fat32"))
                opt->format_type = FAT_TYPE_FAT32;
            else {
                fprintf(stderr, "fatfs: unknown FAT type '%s' "
                                "(expected 12, 16 or 32)\n", t);
                return EXIT_FAIL;
            }
        } else {
            fprintf(stderr, "fatfs: unknown option '%s'\n", arg);
            usage(stderr);
            return EXIT_FAIL;
        }
    }
    *rest_count = n;
    return EXIT_OK;
}

static int fail(fat_fs_t *fs, const char *what)
{
    const char *msg = fat_strerror(fs);

    fprintf(stderr, "fatfs: %s: %s\n", what, msg ? msg : "unknown error");
    return EXIT_FAIL;
}

static void print_attributes(uint8_t attr, char out[7])
{
    out[0] = (attr & FAT_ATTR_READ_ONLY) ? 'r' : '-';
    out[1] = (attr & FAT_ATTR_HIDDEN)    ? 'h' : '-';
    out[2] = (attr & FAT_ATTR_SYSTEM)    ? 's' : '-';
    out[3] = (attr & FAT_ATTR_ARCHIVE)   ? 'a' : '-';
    out[4] = (attr & FAT_ATTR_DIRECTORY) ? 'd' : '-';
    out[5] = '\0';
}

static void print_entry(const fat_dirent_t *de, int long_format)
{
    if (!long_format) {
        printf("%s%s\n", de->name, (de->attr & FAT_ATTR_DIRECTORY) ? "/" : "");
        return;
    }
    {
        char     attr[7];
        char     when[24] = "                   ";
        uint16_t t = de->wrt_time;
        uint16_t d = de->wrt_date;

        if (d == 0 && t == 0) {
            t = de->crt_time;
            d = de->crt_date;
        }
        if ((d != 0 || t != 0) &&
            fat_time_to_string(t, d, when, sizeof when) != FAT_SUCCESS)
            strcpy(when, "          (no date)");

        print_attributes(de->attr, attr);
        printf("%10u  %s  %s  %s%s\n",
               (unsigned)((de->attr & FAT_ATTR_DIRECTORY) ? 0 : de->size),
               attr, when, de->name,
               (de->attr & FAT_ATTR_DIRECTORY) ? "/" : "");
    }
}

/* ==========================================================================
 *  ls
 * ========================================================================== */

typedef struct {
    int  long_format;
    int  count;
    long total_bytes;
} list_state_t;

static int list_cb(const fat_dirent_t *de, void *vctx)
{
    list_state_t *st = (list_state_t *)vctx;

    print_entry(de, st->long_format);
    st->count++;
    if (!(de->attr & FAT_ATTR_DIRECTORY))
        st->total_bytes += de->size;
    return 0;
}

static int cmd_ls(fat_fs_t *fs, const char *path, const options_t *opt)
{
    list_state_t st;
    int          n;

    memset(&st, 0, sizeof st);
    st.long_format = opt->long_format;

    if (opt->long_format)
        printf("      size  attr  modified             name\n");

    n = fat_list_dir(fs, path, list_cb, &st);
    if (n == FAT_ERROR)
        return fail(fs, "ls");

    if (opt->long_format)
        printf("\n%ld bytes in %d entries\n", st.total_bytes, st.count);
    return EXIT_OK;
}

/* ==========================================================================
 *  tree
 * ========================================================================== */

typedef struct {
    fat_fs_t        *fs;
    const options_t *opt;
    char             path[FAT_PATH_MAX];
    int              depth;
} tree_iter_t;

static int tree_walk(fat_fs_t *fs, const char *path, int depth,
                     const options_t *opt);

static int tree_cb(const fat_dirent_t *de, void *vctx)
{
    tree_iter_t *t = (tree_iter_t *)vctx;
    int          i;

    for (i = 0; i < t->depth; i++)
        fputs("    ", stdout);

    if (de->attr & FAT_ATTR_DIRECTORY) {
        printf("%s/\n", de->name);
        if (t->depth < 32) {
            char child[FAT_PATH_MAX];
            int  n = snprintf(child, sizeof child, "%s%s%s", t->path,
                              strcmp(t->path, "/") == 0 ? "" : "/", de->name);

            if (n < 0 || (size_t)n >= sizeof child)
                printf("%*s(name too long to descend)\n",
                       (t->depth + 1) * 4, "");
            else
                (void)tree_walk(t->fs, child, t->depth + 1, t->opt);
        } else {
            printf("%*s(too deep, not descending)\n", (t->depth + 1) * 4, "");
        }
    } else {
        printf("%s (%u bytes)\n", de->name, de->size);
    }
    return 0;
}

static int tree_walk(fat_fs_t *fs, const char *path, int depth,
                     const options_t *opt)
{
    tree_iter_t t;

    memset(&t, 0, sizeof t);
    t.fs    = fs;
    t.opt   = opt;
    t.depth = depth;
    if (strlen(path) >= sizeof t.path)
        return EXIT_FAIL;
    strcpy(t.path, path);

    if (fat_list_dir(fs, path, tree_cb, &t) == FAT_ERROR)
        return EXIT_FAIL;
    return EXIT_OK;
}

static int cmd_tree(fat_fs_t *fs, const char *path, const options_t *opt)
{
    int rc;

    printf("%s\n", path);
    rc = tree_walk(fs, path, 1, opt);
    if (rc != EXIT_OK)
        return fail(fs, "tree");
    return EXIT_OK;
}

/* ==========================================================================
 *  Commands
 * ========================================================================== */

static int cmd_format(const options_t *opt, const char *device,
                      const char *label)
{
    fat_format_opts_t fopts = FAT_FORMAT_OPTS_INIT;
    char              err[256] = "";

    fopts.fat_type      = opt->format_type;
    fopts.label         = label;
    fopts.cluster_bytes = opt->cluster_bytes;

    if (fat_format(device, &fopts, err, sizeof err) != FAT_SUCCESS) {
        fprintf(stderr, "fatfs: format: %s\n", err[0] ? err : "failed");
        return EXIT_FAIL;
    }

    if (opt->verbose) {
        printf("formatted '%s' as %s%s%s\n", device,
               opt->format_type ? fat_type_name(opt->format_type)
                                : "the type chosen for that capacity",
               label ? ", label " : "", label ? label : "");
    }
    return EXIT_OK;
}

static int cmd_info(fat_fs_t *fs)
{
    fat_info_t info;

    if (fat_get_info(fs, &info) != FAT_SUCCESS)
        return fail(fs, "info");

    printf("file system      : %s", fat_fs_type_name(fs));
    if (info.fs_type_string[0])
        printf("   (BPB field: \"%s\")", info.fs_type_string);
    putchar('\n');

    printf("volume label     : %s\n",
           info.label[0] ? info.label : "(none)");
    printf("volume id        : %08X\n", info.volume_id);
    printf("bytes per sector : %u\n", info.bytes_per_sector);
    printf("sectors/cluster  : %u  (%u bytes per cluster)\n",
           info.sectors_per_cluster,
           info.bytes_per_sector * info.sectors_per_cluster);
    printf("sectors per FAT  : %u\n", info.sectors_per_fat);
    printf("FAT copies       : %u\n", info.num_fats);
    if (info.root_entries)
        printf("root directory   : %u fixed entries\n", info.root_entries);
    else
        printf("root directory   : cluster chain (FAT32)\n");
    printf("clusters         : %u total, %u free, %u bad\n",
           info.cluster_count, info.free_clusters, info.bad_clusters);
    printf("capacity         : %llu bytes\n",
           (unsigned long long)info.total_bytes);
    printf("free space       : %llu bytes",
           (unsigned long long)info.free_bytes);
    if (info.total_bytes)
        printf(" (%u%%)", (unsigned)((info.free_bytes * 100) /
                                    info.total_bytes));
    putchar('\n');
    printf("mounted          : %s\n",
           info.read_only ? "read-only" : "read-write");
    if (info.clean_shutdown >= 0)
        printf("clean shutdown   : %s\n", info.clean_shutdown ? "yes" : "NO");
    return EXIT_OK;
}

static int cmd_cat(fat_fs_t *fs, const char *path)
{
    fat_file_t *file = NULL;
    uint8_t     buf[16384];

    if (fat_open(fs, path, FAT_OPEN_READ, &file) != FAT_SUCCESS)
        return fail(fs, "cat");

    for (;;) {
        int got = fat_read(file, buf, (uint32_t)sizeof buf);
        if (got == FAT_ERROR) {
            (void)fat_close(file);
            return fail(fs, "cat");
        }
        if (got == 0)
            break;
        if (fwrite(buf, 1, (size_t)got, stdout) != (size_t)got) {
            (void)fat_close(file);
            fprintf(stderr, "fatfs: writing to stdout failed\n");
            return EXIT_FAIL;
        }
    }
    (void)fat_close(file);
    return EXIT_OK;
}

static int cmd_get(fat_fs_t *fs, const char *src, const char *dst)
{
    fat_file_t *file = NULL;
    FILE       *out  = NULL;
    uint8_t     buf[32768];
    int         rc   = EXIT_OK;

    if (fat_open(fs, src, FAT_OPEN_READ, &file) != FAT_SUCCESS)
        return fail(fs, "get");

    out = fopen(dst, "wb");
    if (!out) {
        (void)fat_close(file);
        fprintf(stderr, "fatfs: cannot create '%s': %s\n", dst,
                strerror(errno));
        return EXIT_FAIL;
    }

    for (;;) {
        int got = fat_read(file, buf, (uint32_t)sizeof buf);
        if (got == FAT_ERROR) {
            rc = fail(fs, "get");
            break;
        }
        if (got == 0)
            break;
        if (fwrite(buf, 1, (size_t)got, out) != (size_t)got) {
            fprintf(stderr, "fatfs: writing '%s' failed: %s\n", dst,
                    strerror(errno));
            rc = EXIT_FAIL;
            break;
        }
    }

    if (fclose(out) != 0 && rc == EXIT_OK) {
        fprintf(stderr, "fatfs: closing '%s' failed: %s\n", dst,
                strerror(errno));
        rc = EXIT_FAIL;
    }
    (void)fat_close(file);
    return rc;
}

static int cmd_put(fat_fs_t *fs, const char *src, const char *dst,
                   const options_t *opt)
{
    FILE       *in   = NULL;
    fat_file_t *file = NULL;
    uint8_t     buf[32768];
    uint64_t    total = 0;
    int         rc    = EXIT_OK;

    in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "fatfs: cannot open '%s': %s\n", src, strerror(errno));
        return EXIT_FAIL;
    }

    if (fat_open(fs, dst,
                 FAT_OPEN_WRITE | FAT_OPEN_CREATE | FAT_OPEN_TRUNCATE,
                 &file) != FAT_SUCCESS) {
        (void)fclose(in);
        return fail(fs, "put");
    }

    for (;;) {
        size_t   got  = fread(buf, 1, sizeof buf, in);
        uint32_t done = 0;

        if (got == 0)
            break;
        if (fat_write_full(file, buf, (uint32_t)got, &done) != FAT_SUCCESS) {
            rc = fail(fs, "put");
            break;
        }
        if (done != (uint32_t)got) {
            fprintf(stderr, "fatfs: short write (%u of %u bytes)\n",
                    done, (unsigned)got);
            rc = EXIT_FAIL;
            break;
        }
        total += done;
    }

    if (ferror(in)) {
        fprintf(stderr, "fatfs: reading '%s' failed\n", src);
        rc = EXIT_FAIL;
    }
    (void)fclose(in);

    if (fat_close(file) != FAT_SUCCESS && rc == EXIT_OK)
        rc = fail(fs, "put");

    if (rc == EXIT_OK && opt->verbose)
        printf("stored %s -> %s (%llu bytes)\n", src, dst,
               (unsigned long long)total);
    return rc;
}

static int cmd_mkdir(fat_fs_t *fs, const char *path)
{
    return fat_mkdir(fs, path) == FAT_SUCCESS ? EXIT_OK : fail(fs, "mkdir");
}

static int cmd_rmdir(fat_fs_t *fs, const char *path)
{
    return fat_rmdir(fs, path) == FAT_SUCCESS ? EXIT_OK : fail(fs, "rmdir");
}

static int cmd_rm(fat_fs_t *fs, const char *path)
{
    return fat_remove(fs, path) == FAT_SUCCESS ? EXIT_OK : fail(fs, "rm");
}

static int cmd_mv(fat_fs_t *fs, const char *from, const char *to)
{
    return fat_move(fs, from, to) == FAT_SUCCESS ? EXIT_OK : fail(fs, "mv");
}

static int cmd_cp(fat_fs_t *fs, const char *from, const char *to)
{
    return fat_copy(fs, from, to) == FAT_SUCCESS ? EXIT_OK : fail(fs, "cp");
}

static int cmd_touch(fat_fs_t *fs, const char *path)
{
    fat_file_t *file = NULL;

    if (fat_open(fs, path, FAT_OPEN_WRITE | FAT_OPEN_CREATE, &file)
        != FAT_SUCCESS)
        return fail(fs, "touch");
    (void)fat_close(file);
    return EXIT_OK;
}


static int cmd_attr(fat_fs_t *fs, const char *path, const char *spec)
{
    fat_dirent_t de;
    char         attr[7];

    if (fat_getattr(fs, path, &de) != FAT_SUCCESS)
        return fail(fs, "attr");

    if (!spec) {
        print_attributes(de.attr, attr);
        printf("%s  %s  (%u bytes)\n", attr, path,
               (unsigned)((de.attr & FAT_ATTR_DIRECTORY) ? 0 : de.size));
        return EXIT_OK;
    }

    {
        /* Only the attributes the caller names are touched, the way attrib(1)
         * behaves: "+r" makes a file read-only without dropping the archive
         * bit that records "this file changed since the last backup".  The
         * directory and volume-id bits are never settable this way. */
        uint8_t     want = de.attr;
        const char *p;
        int         set = 1;      /* '+' sets, '-' and '0' clear */

        for (p = spec; *p; p++) {
            uint8_t bit;

            switch (*p) {
            case '+': set = 1; continue;
            case '-':
            case '0': set = 0; continue;
            case 'r': case 'R': bit = FAT_ATTR_READ_ONLY; break;
            case 'h': case 'H': bit = FAT_ATTR_HIDDEN;    break;
            case 's': case 'S': bit = FAT_ATTR_SYSTEM;    break;
            case 'a': case 'A': bit = FAT_ATTR_ARCHIVE;   break;
            default:
                fprintf(stderr, "fatfs: unknown attribute '%c'\n", *p);
                return EXIT_FAIL;
            }
            if (set)
                want |= bit;
            else
                want &= (uint8_t)~bit;
        }
        if (fat_setattr(fs, path, want) != FAT_SUCCESS)
            return fail(fs, "attr");
    }
    return EXIT_OK;
}

/* ==========================================================================
 *  check
 * ========================================================================== */

static void check_logger(void *ctx, const char *line)
{
    (void)ctx;
    printf("  %s\n", line);
}


static int cmd_check(fat_fs_t *fs, const options_t *opt)
{
    fat_check_t rep;

    printf("checking %s ...\n", fat_fs_type_name(fs));

    if (fat_check(fs, &rep, opt->repair, check_logger, NULL) != FAT_SUCCESS)
        return fail(fs, "check");

    /* A repair is only believable if a fresh pass over the repaired volume
     * comes back clean, so the verdict is taken from a second look. */
    if (opt->repair && rep.errors) {
        fat_check_t after;

        printf("\nrepairs applied to %u problem(s); checking again\n",
               rep.errors);
        if (fat_check(fs, &after, 0, check_logger, NULL) == FAT_SUCCESS)
            rep = after;
    }

    printf("\n%u files, %u directories, %u chains\n", rep.files,
           rep.directories, rep.chains);
    printf("%u clusters in use, %u free, %u bad\n", rep.clusters_in_use,
           rep.free_clusters, rep.bad_clusters);

    if (rep.errors == 0) {
        printf("\nthe volume is consistent%s\n",
               rep.was_clean ? " and was unmounted cleanly" : "");
        return EXIT_OK;
    }

    printf("\nfound %u problem(s):\n", rep.errors);
    if (rep.cross_linked_clusters)
        printf("  %u cross-linked cluster(s)\n", rep.cross_linked_clusters);
    if (rep.loops)
        printf("  %u looping chain(s)\n", rep.loops);
    if (rep.invalid_entries)
        printf("  %u invalid directory entr(ies)\n", rep.invalid_entries);
    if (rep.size_mismatches)
        printf("  %u size/chain mismatch(es)\n", rep.size_mismatches);
    if (rep.orphan_clusters)
        printf("  %u orphaned cluster(s) in %u lost chain(s)\n",
               rep.orphan_clusters, rep.lost_chains);
    if (rep.fat_mismatches)
        printf("  %u FAT sector(s) differ between copies\n",
               rep.fat_mismatches);
    if (rep.fs_info_wrong)
        printf("  the FSInfo free-space count is wrong\n");
    if (!rep.was_clean)
        printf("  the volume was not unmounted cleanly\n");
    printf("\nrun `fatfs check --repair <device>` to apply the safe repairs\n");
    return EXIT_CHECK;
}

/* ==========================================================================
 *  Entry point
 * ========================================================================== */

static void missing(const char *command, const char *what)
{
    fprintf(stderr, "fatfs: %s needs %s\n", command, what);
}

int main(int argc, char **argv)
{
    options_t        opt;
    const char      *rest[64];
    int              nrest = 0;
    const char      *command;
    const char      *device;
    fat_mount_opts_t mopts = FAT_MOUNT_OPTS_INIT;
    fat_fs_t        *fs    = NULL;
    int              rc;

    if (argc < 2) {
        usage(stderr);
        return EXIT_FAIL;
    }

    rc = parse_options(argc, argv, &opt, rest, &nrest);
    if (rc != EXIT_OK)
        return rc;

    if (nrest == 0) {
        usage(stderr);
        return EXIT_FAIL;
    }
    command = rest[0];

    if (strcmp(command, "help") == 0) {
        usage(stdout);
        return EXIT_OK;
    }
    if (nrest < 2) {
        fprintf(stderr, "fatfs: '%s' needs a device\n", command);
        return EXIT_FAIL;
    }
    device = rest[1];

    /* `format` operates on the raw device, so it runs before mounting. */
    if (strcmp(command, "format") == 0) {
        const char *label = (nrest > 2) ? rest[2] : NULL;

        if (label && label[0] == '-')
            label = NULL;
        return cmd_format(&opt, device, label);
    }

    mopts.read_only   = opt.read_only;
    mopts.base_offset = opt.offset;

    {
        char err[256] = "";

        if (fat_mount(device, &mopts, &fs, err, sizeof err) != FAT_SUCCESS) {
            fprintf(stderr, "fatfs: cannot mount '%s': %s\n", device,
                    err[0] ? err : "not a FAT file system");
            return EXIT_FAIL;
        }
    }

    {
        const char *a1 = (nrest > 2) ? rest[2] : NULL;
        const char *a2 = (nrest > 3) ? rest[3] : NULL;

        if (strcmp(command, "info") == 0) {
            rc = cmd_info(fs);
        } else if (strcmp(command, "ls") == 0) {
            rc = cmd_ls(fs, a1 ? a1 : "/", &opt);
        } else if (strcmp(command, "tree") == 0) {
            rc = cmd_tree(fs, a1 ? a1 : "/", &opt);
        } else if (strcmp(command, "check") == 0) {
            rc = cmd_check(fs, &opt);
        } else if (strcmp(command, "cat") == 0) {
            if (!a1) { missing("cat", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_cat(fs, a1);
        } else if (strcmp(command, "get") == 0) {
            if (!a1 || !a2) { missing("get", "<src> <dst>"); rc = EXIT_FAIL; }
            else rc = cmd_get(fs, a1, a2);
        } else if (strcmp(command, "put") == 0) {
            if (!a1 || !a2) { missing("put", "<src> <dst>"); rc = EXIT_FAIL; }
            else rc = cmd_put(fs, a1, a2, &opt);
        } else if (strcmp(command, "mkdir") == 0) {
            if (!a1) { missing("mkdir", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_mkdir(fs, a1);
        } else if (strcmp(command, "rmdir") == 0) {
            if (!a1) { missing("rmdir", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_rmdir(fs, a1);
        } else if (strcmp(command, "rm") == 0) {
            if (!a1) { missing("rm", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_rm(fs, a1);
        } else if (strcmp(command, "touch") == 0) {
            if (!a1) { missing("touch", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_touch(fs, a1);
        } else if (strcmp(command, "mv") == 0) {
            if (!a1 || !a2) { missing("mv", "<old> <new>"); rc = EXIT_FAIL; }
            else rc = cmd_mv(fs, a1, a2);
        } else if (strcmp(command, "cp") == 0) {
            if (!a1 || !a2) { missing("cp", "<src> <dst>"); rc = EXIT_FAIL; }
            else rc = cmd_cp(fs, a1, a2);
        } else if (strcmp(command, "attr") == 0) {
            /* Every remaining argument is an attribute specification, so both
             * `attr /f +r+h` and `attr /f -- +r +h` work. */
            char   spec[64];
            size_t w = 0;

            for (int i = 3; i < nrest; i++) {
                size_t len = strlen(rest[i]);

                if (w + len >= sizeof spec)
                    len = sizeof spec - 1 - w;
                memcpy(spec + w, rest[i], len);
                w += len;
                if (w >= sizeof spec - 1)
                    break;
            }
            spec[w] = '\0';

            if (!a1) { missing("attr", "a path"); rc = EXIT_FAIL; }
            else rc = cmd_attr(fs, a1, w ? spec : NULL);
        } else {
            fprintf(stderr, "fatfs: unknown command '%s'\n", command);
            usage(stderr);
            rc = EXIT_FAIL;
        }
    }

    (void)fat_unmount(fs);
    return rc;
}
