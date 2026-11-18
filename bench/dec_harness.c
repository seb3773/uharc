/*
 * In-process decoder benchmark and fingerprint harness.
 *
 * Links the decoder sources (all C files in src/ except the CLI in src/uharc.c) and
 * decodes each archive given on the command line N times in the same process.
 * This removes process start-up, page-fault and file-I/O noise from the
 * measurement and makes it possible to fingerprint the decoded payload even
 * when the decoder output does not match the stored CRC (so a candidate can
 * be compared byte-for-byte with the baseline on every archive, including
 * archives that the baseline decodes incorrectly).
 *
 * Usage:
 *   dec_harness [-n REPS] [-w WARMUP] [-p PASSWORD] [-o DUMP_DIR] [-q] ARCHIVE...
 *   dec_harness -I ARCHIVE...     (header info only: name version order family usize)
 *
 * Output: one line per archive, tab separated:
 *   name  rc  usize  members  crc_ok  fnv64  min_ns  median_ns  crc32  all_ns(comma list)
 * rc is the uha_decode_payload() return value, crc_ok is the number of
 * members whose CRC matches the archive table, fnv64 the FNV-1a hash of the
 * whole decoded payload and crc32 its IEEE CRC-32 (same as zlib.crc32, so
 * scripts can compare it with the original input cheaply). -o writes the decoded payload of every archive to
 * DUMP_DIR/<basename>.out (used to compare with the original input files).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uha.h"
#include "crypto.h"

int uha_decode_payload(const uint8_t *raw, size_t rawlen, const uha_header *h,
                       const uha_entrylist *entries, uint8_t *out);

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long n;
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0 || (n = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *len = (size_t)n;
    return buf;
}

static uint64_t fnv64(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

int main(int argc, char **argv)
{
    int reps = 1, warm = 0, quiet = 0, info = 0, ai;
    const char *pw = NULL, *dump = NULL;

    for (ai = 1; ai < argc && argv[ai][0] == '-'; ai++) {
        if (!strcmp(argv[ai], "-n") && ai + 1 < argc)
            reps = atoi(argv[++ai]);
        else if (!strcmp(argv[ai], "-w") && ai + 1 < argc)
            warm = atoi(argv[++ai]);
        else if (!strcmp(argv[ai], "-p") && ai + 1 < argc)
            pw = argv[++ai];
        else if (!strcmp(argv[ai], "-o") && ai + 1 < argc)
            dump = argv[++ai];
        else if (!strcmp(argv[ai], "-q"))
            quiet = 1;
        else if (!strcmp(argv[ai], "-I"))
            info = 1;
        else {
            fprintf(stderr, "unknown option %s\n", argv[ai]);
            return 2;
        }
    }
    if (reps < 1)
        reps = 1;

    for (; ai < argc; ai++) {
        const char *path = argv[ai];
        size_t rawlen = 0;
        uint8_t *raw = slurp(path, &rawlen), *out = NULL;
        uha_header h;
        uha_entrylist el;
        uint64_t *t, hash = 0;
        int r, rc = -100, crc_ok = 0, i;

        if (!raw || uha_parse_header(raw, rawlen, &h) != 0) {
            printf("%s\tERR_HEADER\n", base_name(path));
            free(raw);
            continue;
        }
        if (info) {
            printf("%s\t%u\t%u\t%u\t%u\n", base_name(path), (unsigned)h.version,
                   (unsigned)h.order, (unsigned)h.family, (unsigned)h.usize);
            free(raw);
            continue;
        }
        if (uha_decrypt(raw, rawlen, &h, pw) != 0) {
            printf("%s\tERR_DECRYPT\n", base_name(path));
            free(raw);
            continue;
        }
        memset(&el, 0, sizeof(el));
        if (uha_read_entries(raw, rawlen, &el) < 0) {
            printf("%s\tERR_ENTRIES\n", base_name(path));
            free(raw);
            continue;
        }
        out = malloc(h.usize ? h.usize : 1);
        t = calloc((size_t)reps, sizeof(*t));
        for (r = 0; r < warm + reps; r++) {
            uint64_t t0, t1, hh;
            int rr;
            memset(out, 0, h.usize ? h.usize : 1);
            t0 = now_ns();
            rr = uha_decode_payload(raw, rawlen, &h, &el, out);
            t1 = now_ns();
            hh = fnv64(out, h.usize);
            if (r == 0) {
                rc = rr;
                hash = hh;
            } else if (rr != rc || hh != hash) {
                /* The decoder must be a pure function of its input. */
                fprintf(stderr, "%s: non-deterministic decode (rep %d)\n", path, r);
                return 3;
            }
            if (r >= warm)
                t[r - warm] = t1 - t0;
        }
        {
            uint64_t ofs = 0;
            for (i = 0; i < el.count; i++) {
                uint32_t sz = el.items[i].size;
                if (ofs + sz > h.usize)
                    break;
                if (!el.items[i].has_crc || uha_crc32(out + ofs, sz) == el.items[i].crc)
                    crc_ok++;
                ofs += sz;
            }
        }
        if (dump) {
            char fn[4096];
            FILE *fp;
            snprintf(fn, sizeof(fn), "%s/%s.out", dump, base_name(path));
            fp = fopen(fn, "wb");
            if (fp) {
                fwrite(out, 1, h.usize, fp);
                fclose(fp);
            }
        }
        {
            uint64_t *s = malloc((size_t)reps * sizeof(*s));
            memcpy(s, t, (size_t)reps * sizeof(*s));
            qsort(s, (size_t)reps, sizeof(*s), cmp_u64);
            printf("%s\t%d\t%u\t%d\t%d\t%016llx\t%llu\t%llu\t%08x", base_name(path), rc,
                   h.usize, el.count, crc_ok, (unsigned long long)hash,
                   (unsigned long long)s[0], (unsigned long long)s[reps / 2],
                   (unsigned)uha_crc32(out, h.usize));
            if (!quiet) {
                printf("\t");
                for (r = 0; r < reps; r++)
                    printf("%s%llu", r ? "," : "", (unsigned long long)t[r]);
            }
            printf("\n");
            fflush(stdout);
            free(s);
        }
        free(t);
        free(out);
        uha_entrylist_free(&el);
        free(raw);
    }
    return 0;
}
