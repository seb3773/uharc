#define _DEFAULT_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "uha.h"
#include "encode.h"
#include "crypto.h"
#include "crc32.h"
#include "frontier.h"
#include "selclk.h"

#define UHARC_VERSION_STR "0.6b"

static void print_banner(void)
{
    printf("\nUHARC 0.6b\n");
    printf("by Uwe Herklotz\n");
    printf("pure C reimplementation by seb3773\n");
    printf("https://github.com/seb3773/uharc\n\n");
}

static void print_usage(void)
{
    print_banner();
    printf("Usage: uharc command [-switches..] archive[.uha] [files...]\n");
    printf("---< Commands >----------------------------------------------------------------\n");
    printf(" a  create archive and Add files         e  Extract files to current directory\n");
    printf(" m  create archive and Move files        x  eXtract files with full pathname\n");
    printf(" l  List files in archive                t  Test files in archive\n");
    printf("---< Switches >----------------------------------------------------------------\n");
    printf(" m<0..3,x,z> Set cmp.mode (0 = STORE, 1..3 = ALZ:fast..best, x = PPM, z = LZP)\n");
    printf(" md<n>       Set dictionary size in KByte (must be power of 2 : 1 .. 32768)\n");
    printf(" mm[-,+]     Disable/enable built-in multimedia detection/compression\n");
    printf(" o[-,+,p]    Overwrite existing files (- = never, + = always, p = prompt)\n");
    printf(" p<-,r,f>    Store (- = no, r = relative, f = full) pathnames\n");
    printf(" ph[-,+]     Archive header encryption (requires password)\n");
    printf(" pw[passwd]  Set password\n");
    printf(" t<dir>      Set extract target dir\n");
    printf(" y[-,+]      Assume yes on all queries\n");
    printf(" -u, --unix  Format paths as Unix relative paths (/ slashes, lowercase)\n");
    printf(" -1, --bare  Bare output format (one path per line, ideal for scripts, xargs, grep)\n");
    printf(" --selftest  Run built-in verification self-tests\n");
    printf("-------------------------------------------------------------------------------\n\n");
}

static uint8_t *read_file(const char *path, size_t *outlen)
{
    FILE *fp;
    uint8_t *buf;
    long n;

    fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    n = ftell(fp);
    if (n < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *outlen = (size_t)n;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t n)
{
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;
    if (n > 0 && fwrite(buf, 1, n, fp) != n) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
#if defined(_WIN32)
    return mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

static inline int uha_setenv(const char *name, const char *value, int overwrite)
{
#if defined(_WIN32)
    if (!overwrite && getenv(name))
        return 0;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s=%s", name, value);
    return _putenv(buf);
#else
    return setenv(name, value, overwrite);
#endif
}

static const char *basename_of(const char *s)
{
    const char *p;
    if (!s || !s[0])
        return "file";
    p = s;
    while (*p) {
        if (*p == '/' || *p == '\\')
            s = p + 1;
        p++;
    }
    return s[0] ? s : "file";
}

/* Check for path traversal: reject absolute paths, Windows drive letters, and components navigating above root */
static int is_safe_relpath(const char *path)
{
    if (!path || !path[0])
        return 0;
    if (path[0] == '/' || path[0] == '\\')
        return 0;
    if (isalpha((unsigned char)path[0]) && path[1] == ':')
        return 0;

    int depth = 0;
    const char *p = path;
    while (*p) {
        while (*p == '/' || *p == '\\')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != '/' && *p != '\\')
            p++;
        size_t len = (size_t)(p - start);
        if (len == 1 && start[0] == '.') {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            depth--;
            if (depth < 0)
                return 0;
        } else {
            depth++;
        }
    }
    return 1;
}

/* Format path: optionally convert to unix relative path (/ slashes, lowercase) */
static void format_path(char *dst, size_t dst_sz, const char *src, int unix_mode)
{
    if (!dst || dst_sz == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i + 1 < dst_sz) {
        char c = src[i];
        if (unix_mode) {
            if (c == '\\')
                c = '/';
            c = (char)tolower((unsigned char)c);
        }
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

/* Sanitize path for filesystem extraction: convert DOS backslashes to forward slashes, optional lowercase */
static void sanitize_extract_path(char *dst, size_t dst_sz, const char *src, int unix_mode)
{
    if (!dst || dst_sz == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i + 1 < dst_sz) {
        char c = src[i];
        if (c == '\\')
            c = '/';
        if (unix_mode)
            c = (char)tolower((unsigned char)c);
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

static int test_path_safety(void)
{
    /* Safe paths */
    if (!is_safe_relpath("hello.txt")) return 1;
    if (!is_safe_relpath("dir/sub/file.bin")) return 1;
    if (!is_safe_relpath("dir\\sub\\file.bin")) return 1;
    if (!is_safe_relpath("a/b/../c/file.txt")) return 1;

    /* Unsafe paths */
    if (is_safe_relpath(NULL)) return 1;
    if (is_safe_relpath("")) return 1;
    if (is_safe_relpath("/etc/passwd")) return 1;
    if (is_safe_relpath("\\windows\\system32")) return 1;
    if (is_safe_relpath("c:/boot.ini")) return 1;
    if (is_safe_relpath("D:\\autoexec.bat")) return 1;
    if (is_safe_relpath("../evil.txt")) return 1;
    if (is_safe_relpath("..\\evil.txt")) return 1;
    if (is_safe_relpath("dir/../../evil.txt")) return 1;
    if (is_safe_relpath("dir\\..\\..\\evil.txt")) return 1;

    return 0;
}

static int mkdir_p(const char *path)
{
    char tmp[1024];
    size_t i, n;

    if (!path || !path[0] || strcmp(path, ".") == 0)
        return 0;
    n = strlen(path);
    if (n >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, n + 1);
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char sep = tmp[i];
            tmp[i] = 0;
            if (tmp[0] && ensure_dir(tmp) != 0)
                return -1;
            tmp[i] = sep;
        }
    }
    return ensure_dir(tmp);
}

static int ensure_parent(const char *path)
{
    char tmp[1024];
    char *slash1, *slash2, *slash;
    size_t n = strlen(path);

    if (n >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, n + 1);
    slash1 = strrchr(tmp, '/');
    slash2 = strrchr(tmp, '\\');
    slash = slash1 > slash2 ? slash1 : slash2;
    if (!slash || slash == tmp)
        return 0;
    *slash = 0;
    if (!tmp[0] || strcmp(tmp, ".") == 0)
        return 0;
    return mkdir_p(tmp);
}

static void normalize_archive_name(const char *src, char *dst, size_t dst_sz)
{
    size_t len = strlen(src);
    if (len >= dst_sz) {
        strncpy(dst, src, dst_sz - 1);
        dst[dst_sz - 1] = '\0';
        return;
    }
    strcpy(dst, src);
    if (len < 4 || (strcasecmp(dst + len - 4, ".uha") != 0)) {
        if (len + 4 < dst_sz)
            strcat(dst, ".uha");
    }
}

/* --------------------------------------------------------------------------
 * Built-in self tests
 * -------------------------------------------------------------------------- */
static int run_selftest(void)
{
    printf("Running UHARC built-in self-tests...\n");

    /* CRC32 check */
    {
        const char *t = "123456789";
        uint32_t c = uha_crc32((const uint8_t *)t, 9);
        if (c != 0xCBF43926u) {
            fprintf(stderr, "FAIL: CRC32 check failed (expected 0xCBF43926, got 0x%08X)\n", c);
            return 1;
        }
        printf("  [OK] CRC32 self-test passed (0x%08X)\n", c);
    }

    /* Header signature check */
    {
        uha_header h;
        uint8_t dummy[39];
        memset(dummy, 0, sizeof(dummy));
        memcpy(dummy, "UHA", 3);
        dummy[3] = 0x06;
        if (uha_parse_header(dummy, sizeof(dummy), &h) != 0) {
            fprintf(stderr, "FAIL: uha_parse_header dummy test failed\n");
            return 1;
        }
        printf("  [OK] Header parser self-test passed\n");
    }

    /* Path traversal safety check */
    {
        if (test_path_safety() != 0) {
            fprintf(stderr, "FAIL: Path traversal safety self-test failed\n");
            return 1;
        }
        printf("  [OK] Path traversal safety self-test passed\n");
    }

    printf("All built-in self-tests passed successfully.\n");
    return 0;
}

/* --------------------------------------------------------------------------
 * Command: List (l) & Verbose List (v)
 * -------------------------------------------------------------------------- */
static int cmd_list(const char *arc, const char *pw, int verbose, int unix_paths, int bare_list)
{
    uint8_t *raw;
    size_t rawlen;
    uha_header h;
    uha_entrylist el;
    int rc, i;
    uint32_t total_usize = 0;
    uint32_t total_psize = 0;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        fprintf(stderr, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        fprintf(stderr, "Error: invalid UHARC header in %s (code %d)\n", arc, rc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        fprintf(stderr, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        fprintf(stderr, "Error: decryption failed (code %d)\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        fprintf(stderr, "Error: failed to read file table (code %d)\n", rc);
        free(raw);
        return 1;
    }

    if (bare_list) {
        for (i = 0; i < el.count; i++) {
            char p[1024];
            format_path(p, sizeof(p), el.items[i].name ? el.items[i].name : "", unix_paths);
            printf("%s\n", p);
        }
        uha_entrylist_free(&el);
        free(raw);
        return 0;
    }

    print_banner();
    printf(" Archive: %s\n", arc);
    printf(" Details: %s (order 0x%02X), %d file(s), header v%02X\n",
           uha_codec_name(&h), h.order, el.count, h.version);
    if (h.flags & 0x06) {
        printf(" Security: encrypted (%s%s)\n",
               (h.flags & 0x04) ? "header" : "",
               (h.flags & 0x02) ? "+payload" : "");
    }
    printf("\n");

    if (verbose) {
        printf("   Size (bytes)    Packed (bytes)    Ratio     CRC-32    Filename\n");
        printf(" --------------  ----------------  ---------  --------  --------------------\n");
    } else {
        printf("   Size (bytes)      Ratio     CRC-32    Filename\n");
        printf(" --------------    ---------  --------  --------------------\n");
    }

    for (i = 0; i < el.count; i++) {
        uint32_t sz = el.items[i].size;
        uint32_t psz = el.items[i].psize;
        uint32_t crc = el.items[i].crc;
        char disp_name[1024];
        format_path(disp_name, sizeof(disp_name), el.items[i].name ? el.items[i].name : "<unknown>", unix_paths);
        double ratio = sz ? ((double)psz / (double)sz * 100.0) : 0.0;

        total_usize += sz;
        total_psize += psz;

        if (verbose) {
            printf(" %14u    %14u   %6.1f%%   %08X  %s\n",
                   sz, psz, ratio, crc, disp_name);
        } else {
            printf(" %14u      %6.1f%%   %08X  %s\n",
                   sz, ratio, crc, disp_name);
        }
    }

    if (verbose) {
        printf(" --------------  ----------------  ---------  --------  --------------------\n");
        double tot_ratio = total_usize ? ((double)h.psize / (double)total_usize * 100.0) : 0.0;
        printf(" %14u    %14u   %6.1f%%             %d file(s)\n",
               total_usize, h.psize, tot_ratio, el.count);
    } else {
        printf(" --------------    ---------  --------  --------------------\n");
        double tot_ratio = total_usize ? ((double)h.psize / (double)total_usize * 100.0) : 0.0;
        printf(" %14u      %6.1f%%             %d file(s)\n",
               total_usize, tot_ratio, el.count);
    }
    printf("\n");

    uha_entrylist_free(&el);
    free(raw);
    return 0;
}

/* --------------------------------------------------------------------------
 * Command: Extract (x) & Extract Flat (e)
 * -------------------------------------------------------------------------- */
static int cmd_extract(const char *arc, const char *outdir, const char *pw, int flat, int unix_paths)
{
    uint8_t *raw, *plain;
    size_t rawlen;
    uha_header h;
    uha_entrylist el;
    int rc, i;
    uint32_t ofs;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        fprintf(stderr, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        fprintf(stderr, "Error: header error %d in %s\n", rc, arc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        fprintf(stderr, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        fprintf(stderr, "Error: decryption error %d\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        fprintf(stderr, "Error: entries error %d\n", rc);
        free(raw);
        return 1;
    }

    plain = NULL;
    if (h.usize > 0) {
        plain = (uint8_t *)malloc(h.usize);
        if (!plain) {
            fprintf(stderr, "Error: out of memory allocating %u bytes\n", h.usize);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
        rc = uha_decode_payload(raw, rawlen, &h, &el, plain);
        if (rc != 0) {
            fprintf(stderr, "Error: payload decoding error %d (codec=%s order=0x%02X)\n",
                    rc, uha_codec_name(&h), h.order);
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
    }

    if (ensure_dir(outdir) != 0) {
        fprintf(stderr, "Error: cannot create target directory %s\n", outdir);
        free(plain);
        uha_entrylist_free(&el);
        free(raw);
        return 1;
    }

    printf("Extracting from %s (%s, %d file(s), %u bytes)...\n",
           arc, uha_codec_name(&h), el.count, h.usize);

    ofs = 0;
    for (i = 0; i < el.count; i++) {
        char clean_name[1024];
        char path[1200];
        const char *raw_name = el.items[i].name ? el.items[i].name : "file";
        uint32_t sz = el.items[i].size;

        if (flat) {
            const char *bname = basename_of(raw_name);
            sanitize_extract_path(clean_name, sizeof(clean_name), bname, unix_paths);
        } else {
            /* Path traversal & zip-slip protection */
            if (!is_safe_relpath(raw_name)) {
                fprintf(stderr, "Security warning: skipping unsafe path traversal: %s\n", raw_name);
                ofs += sz;
                continue;
            }
            sanitize_extract_path(clean_name, sizeof(clean_name), raw_name, unix_paths);
        }

        if (ofs + sz > h.usize && sz != 0) {
            fprintf(stderr, "Error: member size exceeds payload boundary\n");
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        if (strcmp(outdir, ".") == 0)
            snprintf(path, sizeof(path), "%s", clean_name);
        else
            snprintf(path, sizeof(path), "%s/%s", outdir, clean_name);

        if (ensure_parent(path) != 0) {
            fprintf(stderr, "Error: failed to create parent directory for %s\n", path);
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        if (write_file(path, plain ? plain + ofs : (const uint8_t *)"", sz) != 0) {
            fprintf(stderr, "Error: failed to write %s\n", path);
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        /* Check CRC32 if available */
        uint32_t computed_crc = uha_crc32(plain ? plain + ofs : (const uint8_t *)"", sz);
        if (el.items[i].crc != 0 && computed_crc != el.items[i].crc) {
            fprintf(stderr, "  %-40s [CRC MISMATCH: computed %08X, expected %08X]\n",
                    clean_name, computed_crc, el.items[i].crc);
        } else {
            printf("  %-40s %10u bytes -> %s\n", clean_name, sz, path);
        }

        ofs += sz;
    }

    free(plain);
    uha_entrylist_free(&el);
    free(raw);
    printf("Extraction completed successfully.\n");
    return 0;
}

/* --------------------------------------------------------------------------
 * Command: Test (t)
 * -------------------------------------------------------------------------- */
static int cmd_test(const char *arc, const char *pw)
{
    uint8_t *raw, *plain;
    size_t rawlen;
    uha_header h;
    uha_entrylist el;
    int rc, i;
    uint32_t ofs;
    int errors = 0;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        fprintf(stderr, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        fprintf(stderr, "Error: header error %d in %s\n", rc, arc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        fprintf(stderr, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        fprintf(stderr, "Error: decryption error %d\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        fprintf(stderr, "Error: entries error %d\n", rc);
        free(raw);
        return 1;
    }

    plain = NULL;
    if (h.usize > 0) {
        plain = (uint8_t *)malloc(h.usize);
        if (!plain) {
            fprintf(stderr, "Error: out of memory allocating %u bytes\n", h.usize);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
        rc = uha_decode_payload(raw, rawlen, &h, &el, plain);
        if (rc != 0) {
            fprintf(stderr, "Error: payload decoding error %d (codec=%s order=0x%02X)\n",
                    rc, uha_codec_name(&h), h.order);
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
    }

    printf("Testing integrity of %s (%s, %d file(s), %u bytes)...\n",
           arc, uha_codec_name(&h), el.count, h.usize);

    ofs = 0;
    for (i = 0; i < el.count; i++) {
        uint32_t sz = el.items[i].size;
        const char *nm = el.items[i].name ? el.items[i].name : "<unknown>";
        uint32_t computed_crc = uha_crc32(plain ? plain + ofs : (const uint8_t *)"", sz);

        if (el.items[i].crc != 0 && computed_crc != el.items[i].crc) {
            printf("  %-40s %10u bytes  FAILED (CRC %08X != %08X)\n",
                   nm, sz, computed_crc, el.items[i].crc);
            errors++;
        } else {
            printf("  %-40s %10u bytes  OK (CRC %08X)\n", nm, sz, computed_crc);
        }
        ofs += sz;
    }

    int total_files = el.count;
    free(plain);
    uha_entrylist_free(&el);
    free(raw);

    if (errors == 0) {
        printf("Integrity test passed: all %d file(s) OK.\n", total_files);
        return 0;
    } else {
        fprintf(stderr, "Integrity test FAILED: %d error(s) detected.\n", errors);
        return 1;
    }
}

/* --------------------------------------------------------------------------
 * Command: Add (has) & Move (m)
 * -------------------------------------------------------------------------- */
static int cmd_add(const char *arc, int nfiles, char **file_list,
                   int method, int alz_class, int move_files)
{
    uha_member *members;
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = 0, i;
    const char *mode_str = "STORE";

    members = (uha_member *)calloc((size_t)nfiles, sizeof(uha_member));
    if (!members)
        return 1;

    for (i = 0; i < nfiles; i++) {
        size_t n = 0;
        uint8_t *d = read_file(file_list[i], &n);
        struct stat st;

        if (!d) {
            fprintf(stderr, "Error: cannot read source file %s\n", file_list[i]);
            while (i-- > 0)
                free((void *)members[i].data);
            free(members);
            return 1;
        }

        const char *pfx = getenv("UHA_PATH_PREFIX");
        if (pfx && pfx[0]) {
            char fullarc[512];
            snprintf(fullarc, sizeof(fullarc), "%s%s", pfx, file_list[i]);
            members[i].arcname = strdup(fullarc);
        } else {
            members[i].arcname = file_list[i];
        }

        members[i].data = d;
        members[i].size = (uint32_t)n;
        if (stat(file_list[i], &st) == 0)
            members[i].mtime = (uint32_t)st.st_mtime;
        else
            members[i].mtime = 0;
        members[i].cmd_rank = (uint32_t)i;
    }

    /* Multi-file frontier permutation model */
    int use_frontier = (nfiles > 1);
    const char *fr_env = getenv("UHA_FRONTIER");
    if (fr_env && fr_env[0])
        use_frontier = (fr_env[0] != '0');

    if (use_frontier && nfiles > 0) {
        static const char *EXTS[5] = { "dat", "txt", "c", "bin", "raw" };
        int arena = (method == 2);      /* -mx = PPM = arena */
        uha_member *ord = (uha_member *)calloc((size_t)nfiles, sizeof(*ord));
        int *taken = (int *)calloc((size_t)nfiles, sizeof(*taken));
        if (ord && taken) {
            int w = 0, pass, k;
            for (pass = 0; pass < 2; pass++) {   /* 0 = head (promoted), 1 = tail */
                for (;;) {
                    int best = -1, bei = 99, bsz = -1;
                    const char *bnm = NULL;
                    for (k = 0; k < nfiles; k++) {
                        int inP, ei;
                        const char *bn, *dot, *e;
                        if (taken[k])
                            continue;
                        inP = arena && uha_frontier_promu(members[k].data, members[k].size);
                        if ((pass == 0) != (inP != 0))
                            continue;
                        bn = members[k].arcname;
                        for (const char *q = bn; *q; q++) {
                            if (*q == '/' || *q == '\\')
                                bn = q + 1;
                        }
                        dot = strrchr(bn, '.');
                        e = dot ? dot + 1 : "";
                        ei = 5;
                        for (int t = 0; t < 5; t++) {
                            if (e[0] && !strcmp(e, EXTS[t])) {
                                ei = t;
                                break;
                            }
                        }
                        if (best < 0 || ei < bei ||
                            (ei == bei && (int)members[k].size > bsz) ||
                            (ei == bei && (int)members[k].size == bsz && strcmp(bn, bnm) < 0)) {
                            best = k;
                            bei = ei;
                            bsz = (int)members[k].size;
                            bnm = bn;
                        }
                    }
                    if (best < 0)
                        break;
                    taken[best] = 1;
                    ord[w++] = members[best];
                }
            }
            memcpy(members, ord, (size_t)nfiles * sizeof(*ord));

            if (arena) {
                uint64_t armement = 0, tot = 0;
                uint32_t f;
                uint8_t *concat;
                for (f = 0; f < (uint32_t)nfiles; f++)
                    tot += members[f].size;
                concat = (uint8_t *)malloc(tot ? (size_t)tot : 1);
                if (concat) {
                    size_t off = 0;
                    for (f = 0; f < (uint32_t)nfiles; f++) {
                        if (members[f].size) {
                            memcpy(concat + off, members[f].data, members[f].size);
                            off += members[f].size;
                        }
                        if (uha_frontier_addoue(members[f].data, members[f].size))
                            armement += members[f].size;
                    }
                    uint32_t sel = uha_selclk_delta(concat, (uint32_t)tot, (uint32_t)armement);
                    uha_selclk_set(sel);
                    free(concat);
                }
            }
        }
        free(taken);
        free(ord);
    }

    /* Compression dispatch */
    if (method == 3) {
        int lzorder = 8;
        const char *o = getenv("UHA_MZ_ORDER");
        if (o && atoi(o) > 0)
            lzorder = atoi(o);
        rc = uha_encode_lzp(members, nfiles, lzorder, &raw, &rawlen);
        mode_str = "LZP";
    } else if (method == 2) {
        rc = uha_encode_ppm(members, nfiles, 0x1E, &raw, &rawlen);
        mode_str = "PPM";
    } else if (method == 1) {
        rc = uha_encode_alz(members, nfiles, alz_class, &raw, &rawlen);
        mode_str = (alz_class == 1) ? "ALZ-m2" : (alz_class == 2) ? "ALZ-m3" : "ALZ-m1";
    } else {
        rc = uha_encode_store(members, nfiles, &raw, &rawlen);
        mode_str = "STORE";
    }

    for (i = 0; i < nfiles; i++)
        free((void *)members[i].data);
    free(members);

    if (rc != 0) {
        fprintf(stderr, "Error: compression failed (code %d)\n", rc);
        free(raw);
        return 1;
    }

    if (write_file(arc, raw, rawlen) != 0) {
        fprintf(stderr, "Error: cannot write archive %s\n", arc);
        free(raw);
        return 1;
    }

    printf("Created %s (%zu bytes, %d file(s), %s)\n", arc, rawlen, nfiles, mode_str);
    free(raw);

    /* If move command (m), delete original files upon success */
    if (move_files) {
        for (i = 0; i < nfiles; i++) {
            if (remove(file_list[i]) != 0) {
                fprintf(stderr, "Warning: could not delete %s\n", file_list[i]);
            }
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Main Entry Not
 * -------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage();
        return 0;
    }

    /* Help switches */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "/?") == 0 ||
        strcmp(argv[1], "help") == 0) {
        print_usage();
        return 0;
    }

    /* Self-test switch */
    if (strcmp(argv[1], "--selftest") == 0 || strcmp(argv[1], "--test") == 0) {
        return run_selftest();
    }

    int start_arg = 2;
    char cmd;
    int unix_paths = 0;
    int bare_list = 0;

    if (strcmp(argv[1], "-1") == 0 || strcmp(argv[1], "--bare") == 0) {
        cmd = 'l';
        bare_list = 1;
        start_arg = 2;
    } else {
        if (strlen(argv[1]) != 1 || !strchr("amxelvth", tolower((unsigned char)argv[1][0]))) {
            fprintf(stderr, "Error: invalid command '%s'. Run 'uharc --help' for usage.\n", argv[1]);
            return 1;
        }
        cmd = (char)tolower((unsigned char)argv[1][0]);
    }

    const char *arc_raw = NULL;
    char arc_path[1024];
    const char *target_dir = ".";
    const char *pw = NULL;
    int method = 1;      /* Default: -m2 (ALZ Normal) */
    int alz_class = 1;   /* 0=-m1, 1=-m2, 2=-m3 */
    int assume_yes = 0;
    (void)assume_yes;

    char **file_list = (char **)calloc((size_t)argc, sizeof(char *));
    int nfiles = 0;

    int a;
    for (a = start_arg; a < argc; a++) {
        const char *arg = argv[a];
        int is_sw = 0;
        if (arg[0] == '-') {
            is_sw = 1;
        } else if (arg[0] == '/' && !strchr(arg + 1, '/')) {
            /* Only treat as DOS switch if it doesn't contain further path slashes */
            is_sw = 1;
        }

        if (strcmp(arg, "-u") == 0 || strcmp(arg, "--unix") == 0 ||
            strcmp(arg, "/u") == 0 || strcmp(arg, "/U") == 0) {
            unix_paths = 1;
        } else if (strcmp(arg, "-1") == 0 || strcmp(arg, "--bare") == 0 ||
                   strcmp(arg, "/1") == 0) {
            bare_list = 1;
        } else if (is_sw) {
            const char *sw = arg + 1;
            if (strcmp(sw, "m0") == 0) {
                method = 0;
            } else if (strcmp(sw, "m1") == 0) {
                method = 1; alz_class = 0;
            } else if (strcmp(sw, "m2") == 0) {
                method = 1; alz_class = 1;
            } else if (strcmp(sw, "m3") == 0) {
                method = 1; alz_class = 2;
            } else if (strcmp(sw, "mx") == 0) {
                method = 2;
            } else if (strcmp(sw, "mz") == 0) {
                method = 3;
            } else if (strncmp(sw, "md", 2) == 0) {
                uha_setenv("UHA_ALZ_DICT_KB", sw + 2, 1);
            } else if (strncmp(sw, "pw", 2) == 0) {
                if (sw[2])
                    pw = sw + 2;
                else if (a + 1 < argc)
                    pw = argv[++a];
                if (pw)
                    uha_setenv("UHA_PASSWORD", pw, 1);
            } else if (strcmp(sw, "ph+") == 0) {
                uha_setenv("UHA_HEADER_ENCRYPT", "1", 1);
            } else if (strcmp(sw, "ph-") == 0) {
                uha_setenv("UHA_HEADER_ENCRYPT", "0", 1);
            } else if (strcmp(sw, "mm-") == 0) {
                uha_setenv("UHA_NOMM", "1", 1);
            } else if (strcmp(sw, "mm+") == 0 || strcmp(sw, "mm") == 0) {
                uha_setenv("UHA_NOMM", "0", 1);
            } else if (strcmp(sw, "p-") == 0) {
                uha_setenv("UHA_PATH_MODE", "none", 1);
            } else if (strcmp(sw, "pr") == 0) {
                uha_setenv("UHA_PATH_MODE", "rel", 1);
            } else if (strcmp(sw, "pf") == 0) {
                uha_setenv("UHA_PATH_MODE", "full", 1);
            } else if (sw[0] == 't') {
                if (sw[1])
                    target_dir = sw + 1;
                else if (a + 1 < argc)
                    target_dir = argv[++a];
            } else if (sw[0] == 'y' || strcmp(sw, "yes") == 0) {
                assume_yes = 1;
            }
        } else {
            if (!arc_raw) {
                arc_raw = arg;
            } else {
                file_list[nfiles++] = (char *)arg;
            }
        }
    }

    if (!arc_raw) {
        fprintf(stderr, "Error: missing archive filename. Run 'uharc --help' for usage.\n");
        free(file_list);
        return 1;
    }

    normalize_archive_name(arc_raw, arc_path, sizeof(arc_path));

    int res = 0;
    switch (cmd) {
    case 'a':
        if (nfiles == 0) {
            fprintf(stderr, "Error: no input files specified to compress into %s\n", arc_path);
            res = 1;
            break;
        }
        res = cmd_add(arc_path, nfiles, file_list, method, alz_class, 0);
        break;

    case 'm':
        if (nfiles == 0) {
            fprintf(stderr, "Error: no input files specified to move into %s\n", arc_path);
            res = 1;
            break;
        }
        res = cmd_add(arc_path, nfiles, file_list, method, alz_class, 1);
        break;

    case 'x':
        res = cmd_extract(arc_path, target_dir, pw, 0, unix_paths);
        break;

    case 'e':
        res = cmd_extract(arc_path, target_dir, pw, 1, unix_paths);
        break;

    case 'l':
        res = cmd_list(arc_path, pw, 0, unix_paths, bare_list);
        break;

    case 'v':
        res = cmd_list(arc_path, pw, 1, unix_paths, bare_list);
        break;

    case 't':
        res = cmd_test(arc_path, pw);
        break;

    default:
        fprintf(stderr, "Error: unknown command '%c'\n", cmd);
        res = 1;
        break;
    }

    free(file_list);
    return res;
}
