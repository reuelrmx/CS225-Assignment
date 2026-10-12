/* ==========================================================================
 *  api_test.c - exercises the file system through its own API
 *
 *  tests/run_tests.sh drives the `fatfs` command line tool; this program
 *  covers what a command line cannot easily reach: seeking, writing at an
 *  offset, truncation and extension through the handle, directory iteration,
 *  the volume statistics and the consistency checker.
 *
 *      build/api_test <image>
 *
 *  The image must already exist and be formatted; this program only adds,
 *  changes and removes files inside it.  Exit status 0 means every check
 *  passed.
 * ========================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fat_core.h"
#include "fat_fs.h"

static int checks_run;
static int checks_failed;

static void check(int ok, const char *what)
{
    checks_run++;
    if (!ok) {
        checks_failed++;
        printf("   FAIL  %s\n", what);
    } else {
        printf("   ok    %s\n", what);
    }
}

/* A deterministic byte pattern, so a mismatch is meaningful. */
static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(seed + (uint8_t)(i * 31u) + (uint8_t)(i >> 8));
}

static int pattern_matches_at(const uint8_t *buf, size_t got, uint8_t seed,
                              size_t offset)
{
    for (size_t i = 0; i < got; i++) {
        size_t j = offset + i;
        if (buf[i] != (uint8_t)(seed + (uint8_t)(j * 31u) +
                                (uint8_t)(j >> 8)))
            return 0;
    }
    return 1;
}

static int pattern_matches(const uint8_t *buf, size_t got, uint8_t seed)
{
    return pattern_matches_at(buf, got, seed, 0);
}

static void api_check_log(void *ctx, const char *line)
{
    (void)ctx;
    printf("        | %s\n", line);
}

/* A quiet consistency probe used to localise a problem to one step. */
static void checkpoint(fat_fs_t *fs, const char *step)
{
    fat_check_t rep;

    memset(&rep, 0, sizeof rep);
    (void)fat_check(fs, &rep, 0, NULL, NULL);
    if (rep.errors)
        printf("        ! %s: %u error(s)\n", step, rep.errors);
}

static void check_eq_int(long got, long want, const char *what)
{
    checks_run++;
    if (got != want) {
        checks_failed++;
        printf("   FAIL  %s (got %ld, wanted %ld)\n", what, got, want);
    } else {
        printf("   ok    %s\n", what);
    }
}

/* Read a whole file through the API.  Returns 0 on success. */
static int read_file(fat_fs_t *fs, const char *path, uint8_t *out, size_t cap,
                     size_t *len_out, size_t *mismatch_at)
{
    fat_file_t *file = NULL;
    size_t      total = 0;

    *mismatch_at = (size_t)-1;
    if (fat_open(fs, path, FAT_OPEN_READ, &file) != FAT_SUCCESS)
        return -1;
    while (total < cap) {
        uint32_t done = 0;
        int      want = (int)(cap - total);

        if (fat_read_full(file, out + total, (uint32_t)want, &done)
            != FAT_SUCCESS) {
            fat_close(file);
            return -1;
        }
        if (done == 0)
            break;
        total += done;
    }
    fat_close(file);
    *len_out = total;
    return 0;
}

typedef struct {
    int count;
    int saw_dir;
} list_state_t;

static int list_cb(const fat_dirent_t *de, void *vctx)
{
    list_state_t *st = (list_state_t *)vctx;

    st->count++;
    if (de->attr & FAT_ATTR_DIRECTORY)
        st->saw_dir++;
    return 0;
}

int main(int argc, char **argv)
{
    fat_fs_t   *fs = NULL;
    fat_file_t *file = NULL;
    fat_info_t  info;
    char        err[256] = "";
    const char *device;
    uint8_t     block[70000];
    uint8_t     expect[70000];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <image>\n", argv[0]);
        return 2;
    }
    device = argv[1];

    if (fat_mount(device, NULL, &fs, err, sizeof err) != FAT_SUCCESS) {
        fprintf(stderr, "api_test: cannot mount '%s': %s\n", device, err);
        return 2;
    }
    printf("  [api] %s is %s\n", device, fat_fs_type_name(fs));

    /* The tests below build a small tree under /api and expect it to be empty
     * to begin with, so refuse to run on a volume that has one. */
    {
        fat_dirent_t existing;

        if (fat_getattr(fs, "/api", &existing) == FAT_SUCCESS) {
            fprintf(stderr, "api_test: '%s' already contains /api - run this "
                            "on a freshly formatted image\n", device);
            fat_unmount(fs);
            return 2;
        }
    }

    /* --- volume information -------------------------------------------- */
    if (fat_get_info(fs, &info) == FAT_SUCCESS) {
        check(info.cluster_count > 0, "info reports a cluster count");
        check(info.free_clusters <= info.cluster_count,
              "the free count is within the volume");
        check(info.bytes_per_sector >= 512, "a sensible sector size");
    } else {
        check(0, "fat_get_info()");
    }

    /* --- the parent directory has to exist first ----------------------- */
    check(fat_mkdir(fs, "/api") == FAT_SUCCESS, "fat_mkdir() makes a directory");
    check(fat_mkdir(fs, "/api") != FAT_SUCCESS,
          "creating the same directory twice fails cleanly");
    check(fat_mkdir(fs, "/no_such_parent/child") != FAT_SUCCESS,
          "a directory cannot be created under a missing parent");
    check(fat_open(fs, "/missing/file.txt", FAT_OPEN_CREATE | FAT_OPEN_WRITE,
                   &file) != FAT_SUCCESS,
          "a file cannot be created under a missing parent");
    check(fat_mkdir(fs, "/api/nested") == FAT_SUCCESS, "nested directory");
    check(fat_mkdir(fs, "/api/nested/more") == FAT_SUCCESS,
          "one level further down");

    checkpoint(fs, "before: create, write, read");

    /* --- create, write, read ------------------------------------------- */
    if (fat_open(fs, "/api/basic.bin",
                 FAT_OPEN_WRITE | FAT_OPEN_CREATE | FAT_OPEN_TRUNCATE,
                 &file) == FAT_SUCCESS) {
        uint32_t done = 0;
        uint32_t got;

        fill_pattern(block, sizeof block, 7);
        check(fat_write_full(file, block, 5000, &done) == FAT_SUCCESS,
              "write 5000 bytes");
        check(done == 5000, "the write reports 5000 bytes accepted");
        check(fat_write_full(file, block + 5000, 1000, &done) == FAT_SUCCESS,
              "append another 1000 bytes");
        check(fat_file_size(file) == 6000, "the handle reports 6000 bytes");
        check(fat_tell(file) == 6000, "the position is at 6000");
        check(fat_seek(file, 0, FAT_SEEK_SET) == FAT_SUCCESS, "rewind");
        got = (uint32_t)fat_read(file, block, sizeof block);
        check(got == 6000, "read back all 6000 bytes");
        check(pattern_matches(block, got, 7), "the bytes match what was written");
        check(fat_seek(file, 3, FAT_SEEK_SET) == FAT_SUCCESS,
              "seek to offset 3");
        got = (uint32_t)fat_read(file, block, 10);
        check(got == 10, "read 10 bytes from offset 3");
        check(pattern_matches_at(block, got, 7, 3),
              "the bytes read from offset 3 are the right ones");
        check(fat_seek(file, -4, FAT_SEEK_END) == FAT_SUCCESS,
              "seek four bytes before the end");
        got = (uint32_t)fat_read(file, block, 100);
        check_eq_int(got, 4, "only the last four bytes are readable there");
        check(pattern_matches_at(block, got, 7, 5996),
              "those four bytes are the tail of the file");
        check(fat_seek(file, 6000, FAT_SEEK_SET) == FAT_SUCCESS,
              "seek to the end");
        got = (uint32_t)fat_read(file, block, 8);
        check(got == 0, "reading at the end returns nothing");
        fat_close(file);
    } else {
        check(0, "create /api/basic.bin");
    }

    {
        fat_dirent_t de;

        if (fat_getattr(fs, "/api/basic.bin", &de) == FAT_SUCCESS)
            check(de.size == 6000, "the directory entry records 6000 bytes");
        else
            check(0, "fat_getattr(/api/basic.bin)");
    }

    checkpoint(fs, "before: the data comes back through a fresh handle");

    /* --- the data comes back through a fresh handle --------------------- */
    {
        size_t len = 0;
        size_t mismatch = 0;

        fill_pattern(expect, sizeof expect, 7);
        if (read_file(fs, "/api/basic.bin", block, sizeof block, &len,
                      &mismatch) == 0) {
            check(len == 6000, "a fresh handle reads 6000 bytes");
            check(memcmp(block, expect, 6000) == 0,
                  "the contents survive closing and reopening");
        } else {
            check(0, "re-reading /api/basic.bin");
        }
    }

    checkpoint(fs, "before: writing past the end fills the hole with zeroes");

    /* --- writing past the end fills the hole with zeroes ---------------- */
    if (fat_open(fs, "/api/hole.bin",
                 FAT_OPEN_WRITE | FAT_OPEN_CREATE | FAT_OPEN_TRUNCATE,
                 &file) == FAT_SUCCESS) {
        uint32_t done = 0;
        uint8_t  tail[16];

        memset(tail, 0xAB, sizeof tail);
        check(fat_seek(file, 4096, FAT_SEEK_SET) == FAT_SUCCESS,
              "seek 4096 bytes past the end of an empty file");
        check(fat_write_full(file, tail, sizeof tail, &done) == FAT_SUCCESS,
              "write at that offset");
        check(fat_file_size(file) == 4112, "the file is now 4112 bytes long");
        fat_close(file);

        if (fat_open(fs, "/api/hole.bin", FAT_OPEN_READ, &file)
            == FAT_SUCCESS) {
            uint8_t buf[4200];
            int     zeroes = 1;

            memset(buf, 0x5A, sizeof buf);
            {
                uint32_t got = (uint32_t)fat_read(file, buf, sizeof buf);
                check(got == 4112, "the whole file is readable");
            }
            for (size_t i = 0; i < 4096; i++)
                if (buf[i] != 0)
                    zeroes = 0;
            check(zeroes, "the hole reads back as zeroes, not stale data");
            check(buf[4096] == 0xAB, "the data after the hole is intact");
            fat_close(file);
        } else {
            check(0, "reopen /api/hole.bin");
        }
    } else {
        check(0, "create /api/hole.bin");
    }

    checkpoint(fs, "before: truncate and extend");

    /* --- truncate and extend ------------------------------------------- */
    if (fat_open(fs, "/api/basic.bin", FAT_OPEN_WRITE | FAT_OPEN_READ,
                 &file) == FAT_SUCCESS) {
        check(fat_set_size(file, 100) == FAT_SUCCESS, "shrink to 100 bytes");
        check(fat_file_size(file) == 100, "the size is 100");
        fat_close(file);
    } else {
        check(0, "reopen /api/basic.bin for truncation");
    }
    {
        fat_dirent_t de;

        if (fat_getattr(fs, "/api/basic.bin", &de) == FAT_SUCCESS)
            check(de.size == 100, "the truncated size reached the directory");
    }
    if (fat_open(fs, "/api/basic.bin", FAT_OPEN_WRITE | FAT_OPEN_READ,
                 &file) == FAT_SUCCESS) {
        check(fat_set_size(file, 300) == FAT_SUCCESS, "extend to 300 bytes");
        check(fat_file_size(file) == 300, "the size is 300");
        fat_close(file);

        {
            size_t len = 0;
            size_t mismatch = 0;

            memset(block, 0x11, sizeof block);
            if (read_file(fs, "/api/basic.bin", block, sizeof block, &len,
                          &mismatch) == 0) {
                int tail_zero = 1;

                check(len == 300, "300 bytes are readable");
                for (size_t i = 100; i < 300; i++)
                    if (block[i] != 0)
                        tail_zero = 0;
                check(tail_zero, "the bytes added by the extension are zeroes");
            }
        }
    }

    checkpoint(fs, "before: directories");

    /* --- directories --------------------------------------------------- */
    {
        int is_dir = 0;

        check(fat_is_directory(fs, "/api/nested/more", &is_dir)
                  == FAT_SUCCESS && is_dir,
              "the new path resolves to a directory");
        check(fat_is_directory(fs, "/api/basic.bin", &is_dir) == FAT_SUCCESS
                  && !is_dir,
              "a file is not reported as a directory");
    }
    {
        list_state_t st;

        memset(&st, 0, sizeof st);
        if (fat_list_dir(fs, "/api", list_cb, &st) == FAT_SUCCESS) {
            check_eq_int(st.count, 3, "/api holds exactly three entries");
            check_eq_int(st.saw_dir, 1, "one of them is a directory");
        } else {
            check(0, "fat_list_dir(/api)");
        }
    }
    check(fat_rmdir(fs, "/api/nested") != FAT_SUCCESS,
          "removing a non-empty directory fails");
    check(fat_mkdir(fs, "/api") != FAT_SUCCESS,
          "an existing directory cannot be created again");
    check(fat_remove(fs, "/api/nested") != FAT_SUCCESS,
          "fat_remove() refuses a directory");
    check(fat_remove(fs, "/api/hole.bin") == FAT_SUCCESS, "remove a file");
    check(fat_remove(fs, "/api/hole.bin") != FAT_SUCCESS,
          "removing a file that is gone fails cleanly");

    checkpoint(fs, "before: rename and move");

    /* --- rename and move ------------------------------------------------ */
    check(fat_rename(fs, "/api/basic.bin", "/api/renamed.bin") == FAT_SUCCESS,
          "rename inside one directory");
    check(fat_getattr(fs, "/api/basic.bin", &(fat_dirent_t){0}) != FAT_SUCCESS,
          "the old name is gone");
    check(fat_move(fs, "/api/renamed.bin", "/api/nested/moved.bin")
              == FAT_SUCCESS,
          "move a file into another directory");
    check(fat_copy(fs, "/api/nested/moved.bin", "/api/copied.bin")
              == FAT_SUCCESS,
          "copy a file");
    {
        /* the copy must have the same contents but its own clusters */
        size_t len_a = 0, len_b = 0, mismatch = 0;
        uint8_t buf_b[4096];

        if (read_file(fs, "/api/nested/moved.bin", block, sizeof block, &len_a,
                      &mismatch) == 0 &&
            read_file(fs, "/api/copied.bin", buf_b, sizeof buf_b, &len_b,
                      &mismatch) == 0) {
            check(len_a == len_b && memcmp(block, buf_b, len_a) == 0,
                  "the copy has the same contents");
        } else {
            check(0, "reading the copy");
        }
    }

    checkpoint(fs, "before: statistics");

    /* --- statistics and the checker ------------------------------------- */
    {
        fat_check_t rep;

        memset(&rep, 0, sizeof rep);
        if (fat_check(fs, &rep, 0, api_check_log, NULL) == FAT_SUCCESS) {
            check(rep.errors == 0,
                  "the volume is consistent after every API operation");
            if (rep.errors)
                printf("        (%u errors, %u size mismatches, %u orphans)\n",
                       rep.errors, rep.size_mismatches, rep.orphan_clusters);
            check(rep.clusters_in_use + rep.free_clusters + rep.bad_clusters
                      == info.cluster_count ||
                      info.cluster_count == 0,
                  "the checker accounts for every cluster");
        } else {
            check(0, "fat_check()");
        }
    }

    check(fat_unmount(fs) == FAT_SUCCESS, "unmount");

    printf("  [api] %d checks, %d failed\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
