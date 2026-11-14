#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#ifdef _WIN32
#include <io.h>
#include <conio.h>
#include <sys/utime.h>
#include <windows.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <strings.h>
#endif

#include "uha.h"
#include "encode.h"
#include "crypto.h"
#include "crc32.h"
#include "filter.h"
#include "frontier.h"
#include "selclk.h"
#include "wildcard.h"

#define UHARC_VERSION_STR "0.6b"

static FILE *g_log_fp = NULL;
static int g_display_mode = 1; /* 0 = quiet, 1 = default, 2 = verbose */

static void uha_msg(int min_level, const char *fmt, ...)
{
    if (g_display_mode >= min_level) {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    if (g_log_fp) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(g_log_fp, fmt, ap);
        va_end(ap);
    }
}

static void print_banner(void)
{
    uha_msg(1, "\nUHARC 0.6b  -----   high compression multimedia archiver   -----   BETA version\n");
    uha_msg(1, "Copyright (c) 1997-2005 by Uwe Herklotz     All rights reserved     01 Oct 2005\n");
    uha_msg(1, "****  Freeware for non-commercial use  ****  contact: uwe.herklotz@gmx.de  ****\n\n");
}

static void print_usage(void)
{
    print_banner();
    printf("Usage: UHARC command [-switches..] archive[.uha] [files..@listfile..!exclude..]\n");
    printf("---< Commands >----------------------------------------------------------------\n");
    printf(" a  create archive and Add files         e  Extract files to current directory\n");
    printf(" m  create archive and Move files        x  eXtract files with full pathname\n");
    printf(" l  List files in archive                t  Test files in archive\n");
    printf("---< Switches >----------------------------------------------------------------\n");
    printf(" d<0..2>     Set display mode (0 = quiet, 1 = default, 2 = verbose)\n");
    printf(" m<0..3,x,z> Set cmp.mode (0 = STORE, 1..3 = ALZ:fast..best, x = PPM, z = LZP)\n");
    printf(" md<n>       Set dictionary size in KByte (must be power of 2 : 1 .. 32768)\n");
    printf(" mm[-,+]     Disable/enable built-in multimedia detection/compression\n");
    printf(" o[-,+,p]    Overwrite existing files (- = never, + = always, p = prompt)\n");
    printf(" p<-,r,f,e>  Store (- = no, r = relative, f = full, e = excluded) pathnames\n");
    printf(" ph[-,+]     Archive header encryption   |  ac[-,+]    Clear file archive attr\n");
    printf(" pw[passwd]  Set password                |  ae<attr>   Set attr exclusion mask\n");
    printf(" r[-,+]      Recurse subdirectories      |  b<n>       Set max filebuffer size\n");
    printf(" t<dir>      Set extract target dir      |  bpb[-,+]   bpb instead of %c ratio\n", '%');
    printf(" vm[-,+]     Set virtual memory usage    |  ed[-,+]    Store empty directories\n");
    printf(" y[-,+]      Assume yes on all queries   |  lg<file>   Log output to <file>\n");
    printf("-------------------------------------------------------------------------------\n\n");
}

static void log_open(const char *log_path, const char *cmdline, const char *uharc_opt)
{
    if (!log_path || !*log_path)
        return;
    if (strcasecmp(log_path, "NUL") == 0 || strcmp(log_path, "/dev/null") == 0)
        return;
    g_log_fp = fopen(log_path, "a");
    if (!g_log_fp)
        return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    static const char *const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    char dt[64];
    if (tm) {
        snprintf(dt, sizeof(dt), "%02d-%s-%04d  %02d:%02d:%02d",
                 tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
                 tm->tm_hour, tm->tm_min, tm->tm_sec);
    } else {
        snprintf(dt, sizeof(dt), "01-Jan-2000  00:00:00");
    }
    fprintf(g_log_fp, "\n=== UHARC 0.6 LOG =================================== %s ===\n", dt);
    fprintf(g_log_fp, "Environment: \"%s\"\n", uharc_opt ? uharc_opt : "");
    fprintf(g_log_fp, "Commandline: \"%s\"\n\n", cmdline ? cmdline : "");
    fflush(g_log_fp);
}

static void log_close(void)
{
    if (g_log_fp) {
        fprintf(g_log_fp, "===============================================================================\n\n");
        fclose(g_log_fp);
        g_log_fp = NULL;
    }
}

static uint8_t *read_file(const char *path, size_t *outlen)
{
    FILE *fp;
    uint8_t *buf;
    int64_t n64;
    size_t total, done;

    fp = fopen(path, "rb");
    if (!fp)
        return NULL;
#ifdef _WIN32
    if (_fseeki64(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    n64 = (int64_t)_ftelli64(fp);
    if (n64 < 0 || _fseeki64(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
#else
    if (fseeko(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    n64 = (int64_t)ftello(fp);
    if (n64 < 0 || fseeko(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
#endif
    if ((uint64_t)n64 > (uint64_t)SIZE_MAX) {
        fclose(fp);
        return NULL;
    }
    total = (size_t)n64;
    buf = (uint8_t *)malloc(total ? total : 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    done = 0;
    while (done < total) {
        size_t chunk = total - done;
        size_t got;
        if (chunk > (16u << 20))
            chunk = (16u << 20);
        got = fread(buf + done, 1, chunk, fp);
        if (got == 0) {
            free(buf);
            fclose(fp);
            return NULL;
        }
        done += got;
    }
    fclose(fp);
    *outlen = total;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t n)
{
    FILE *fp = fopen(path, "wb");
    size_t done = 0;

    if (!fp)
        return -1;
    while (done < n) {
        size_t chunk = n - done;
        size_t put;
        if (chunk > (16u << 20))
            chunk = (16u << 20);
        put = fwrite(buf + done, 1, chunk, fp);
        if (put != chunk) {
            fclose(fp);
            return -1;
        }
        done += put;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    int64_t era, yoe, doy, doe;
    y -= (m <= 2);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (int64_t)(m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + (int64_t)d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int dos_to_unix_time(uint16_t dos_date, uint16_t dos_time, int64_t *out_sec)
{
    unsigned sec, min, hour, day, mon, year;
    int64_t days;

    if (dos_date == 0 && dos_time == 0)
        return 0;
    sec  = (unsigned)(dos_time & 0x1Fu) * 2u;
    min  = (unsigned)((dos_time >> 5) & 0x3Fu);
    hour = (unsigned)((dos_time >> 11) & 0x1Fu);
    day  = (unsigned)(dos_date & 0x1Fu);
    mon  = (unsigned)((dos_date >> 5) & 0x0Fu);
    year = (unsigned)((dos_date >> 9) & 0x7Fu) + 1980u;
    if (mon < 1u || mon > 12u || day < 1u || day > 31u ||
        hour > 23u || min > 59u || sec > 59u)
        return 0;
    days = days_from_civil((int64_t)year, mon, day);
    *out_sec = days * 86400LL + (int64_t)hour * 3600LL +
               (int64_t)min * 60LL + (int64_t)sec - 3600LL;
    return 1;
}

static void restore_file_meta(const char *path, uint16_t dos_date, uint16_t dos_time, uint8_t dos_attr)
{
    int64_t tsec = 0;

    if (dos_to_unix_time(dos_date, dos_time, &tsec)) {
#ifdef _WIN32
        struct __utimbuf64 ut;
        ut.actime = (__time64_t)tsec;
        ut.modtime = (__time64_t)tsec;
        _utime64(path, &ut);
#else
        struct timespec ts[2];
        ts[0].tv_sec = (time_t)tsec;
        ts[0].tv_nsec = 0;
        ts[1].tv_sec = (time_t)tsec;
        ts[1].tv_nsec = 0;
        utimensat(AT_FDCWD, path, ts, 0);
#endif
    }
    if (dos_attr & 0x01u) {
#ifdef _WIN32
        _chmod(path, _S_IREAD);
#else
        struct stat st;
        if (stat(path, &st) == 0)
            chmod(path, st.st_mode & ~(mode_t)0222);
        else
            chmod(path, 0444);
#endif
    }
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

static void normalize_archive_name(const char *src, char *dst, size_t dst_sz, int is_sfx, int is_create)
{
    size_t len = strlen(src);
    if (len >= dst_sz) {
        strncpy(dst, src, dst_sz - 1);
        dst[dst_sz - 1] = '\0';
        return;
    }
    strcpy(dst, src);

    if (!is_create) {
        struct stat st;
        if (stat(src, &st) == 0)
            return;
    }

    const char *bn = basename_of(src);
    const char *ext = strrchr(bn, '.');
    if (!ext) {
        const char *add_ext = is_sfx ? ".exe" : ".uha";
        if (len + strlen(add_ext) < dst_sz)
            strcat(dst, add_ext);
    }
}

static void format_dos_datetime(uint16_t dos_date, uint16_t dos_time,
                                char *out_date, size_t out_date_sz,
                                char *out_time, size_t out_time_sz,
                                int with_sec)
{
    static const char *const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    unsigned sec  = (unsigned)(dos_time & 0x1Fu) * 2u;
    unsigned min  = (unsigned)((dos_time >> 5) & 0x3Fu);
    unsigned hour = (unsigned)((dos_time >> 11) & 0x1Fu);
    unsigned day  = (unsigned)(dos_date & 0x1Fu);
    unsigned mon  = (unsigned)((dos_date >> 5) & 0x0Fu);
    unsigned year = (unsigned)((dos_date >> 9) & 0x7Fu) + 1980u;
    if (mon < 1 || mon > 12) mon = 1;
    if (day < 1 || day > 31) day = 1;

    snprintf(out_date, out_date_sz, "%02u-%s-%04u", day, months[mon - 1], year);
    if (with_sec)
        snprintf(out_time, out_time_sz, "%02u:%02u:%02u", hour, min, sec);
    else
        snprintf(out_time, out_time_sz, "%02u:%02u", hour, min);
}

static void format_dos_attr(uint8_t attr, char *out_attr, size_t out_sz)
{
    if (out_sz < 5) return;
    out_attr[0] = (attr & 0x01) ? 'R' : '-';
    out_attr[1] = (attr & 0x02) ? 'H' : '-';
    out_attr[2] = (attr & 0x04) ? 'S' : '-';
    out_attr[3] = (attr & 0x20) ? 'A' : '-';
    out_attr[4] = '\0';
}

static void format_archive_created(const char *arc_path, char *out_buf, size_t out_sz)
{
    struct stat st;
    time_t t = time(NULL);
    if (stat(arc_path, &st) == 0 && st.st_mtime > 0)
        t = (time_t)st.st_mtime;
    struct tm *tm = localtime(&t);
    static const char *const months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    if (tm) {
        snprintf(out_buf, out_sz, "%02d-%s-%04d, %02d:%02d",
                 tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
                 tm->tm_hour, tm->tm_min);
    } else {
        snprintf(out_buf, out_sz, "01-Jan-2000, 00:00");
    }
}

static int check_archive_overwrite(const char *arc_path, int overwrite_mode, int assume_yes)
{
    struct stat st;
    if (stat(arc_path, &st) != 0)
        return 1;

    if (overwrite_mode == 2) {
        uha_msg(0, "\nERROR: Can't create archive file\n\nProcess aborted.\n");
        return 0;
    }
    if (overwrite_mode == 1 || assume_yes) {
        return 1;
    }

    if (st.st_size == 0) {
        return 1;
    }

    uha_msg(0, "\nArchive \"%s\" already exists. Overwrite (y/n) ? ", arc_path);
    fflush(stdout);
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        uha_msg(0, "\nProcess aborted.\n");
        return 0;
    }
    if (tolower((unsigned char)line[0]) == 'y')
        return 1;

    uha_msg(0, "Process aborted.\n");
    return 0;
}

static int query_file_overwrite(const char *file_path, int overwrite_mode, int assume_yes, int *always_yes)
{
    struct stat st;
    if (stat(file_path, &st) != 0)
        return 1;

    if (overwrite_mode == 1 || assume_yes || *always_yes)
        return 1;
    if (overwrite_mode == 2)
        return 0;

#if defined(_WIN32)
    int is_tty = _isatty(_fileno(stdin));
#else
    int is_tty = isatty(STDIN_FILENO);
#endif

    if (!is_tty) {
        return 0;
    }

    uha_msg(0, "File \"%s\" already exists. Overwrite (y/n/a/c) ? ", file_path);
    fflush(stdout);
    char line[64];
    if (!fgets(line, sizeof(line), stdin))
        return -1;
    char c = (char)tolower((unsigned char)line[0]);
    if (c == 'y')
        return 1;
    if (c == 'a') {
        *always_yes = 1;
        return 1;
    }
    if (c == 'c')
        return -1;
    return 0;
}

static int read_password_interactive(char *out_pw, size_t max_len)
{
    char p1[128], p2[128];
    p1[0] = '\0'; p2[0] = '\0';

#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    printf("Enter password: ");
    fflush(stdout);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    if (!fgets(p1, sizeof(p1), stdin)) { SetConsoleMode(hStdin, mode); return -1; }
    SetConsoleMode(hStdin, mode);
    printf("\nRe-enter password: ");
    fflush(stdout);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    if (!fgets(p2, sizeof(p2), stdin)) { SetConsoleMode(hStdin, mode); return -1; }
    SetConsoleMode(hStdin, mode);
    printf("\n");
#else
    struct termios oldt, newt;
    int is_t = isatty(STDIN_FILENO);
    if (is_t) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ECHO);
    }
    printf("Enter password: ");
    fflush(stdout);
    if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(p1, sizeof(p1), stdin)) { if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &oldt); return -1; }
    if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\nRe-enter password: ");
    fflush(stdout);
    if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(p2, sizeof(p2), stdin)) { if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &oldt); return -1; }
    if (is_t) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
#endif

    char *n1 = strpbrk(p1, "\r\n"); if (n1) *n1 = '\0';
    char *n2 = strpbrk(p2, "\r\n"); if (n2) *n2 = '\0';

    if (strcmp(p1, p2) != 0) {
        uha_msg(0, "\nERROR: Passwords don't match !\n\nProcess aborted.\n");
        return -1;
    }
    strncpy(out_pw, p1, max_len - 1);
    out_pw[max_len - 1] = '\0';
    return 0;
}

static void pause_exit(void)
{
    printf("Press any key to continue ...\n");
    fflush(stdout);
#if defined(_WIN32)
    _getch();
#else
    getchar();
#endif
}

static void set_idle_priority(void)
{
#if defined(_WIN32)
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
#else
    int r = nice(10);
    (void)r;
#endif
}

static void clear_archive_attr_if_requested(const char *path, int clear_flag)
{
    if (!clear_flag || !path)
        return;
#if defined(_WIN32)
    DWORD a = GetFileAttributesA(path);
    if (a != INVALID_FILE_ATTRIBUTES)
        SetFileAttributesA(path, a & ~FILE_ATTRIBUTE_ARCHIVE);
#else
    (void)path;
#endif
}

static uint8_t *load_sfx_stub(const char *stub_path, size_t *out_len)
{
    FILE *fp = NULL;
    if (stub_path && stub_path[0]) {
        fp = fopen(stub_path, "rb");
    } else {
        fp = fopen("UHARCSFX.EXE", "rb");
        if (!fp) fp = fopen("uharcsfx.exe", "rb");
        if (!fp) fp = fopen("historical_bin/UHARCSFX.EXE", "rb");
    }
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz <= 0 || fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_len = (size_t)sz;
    return buf;
}

static int maybe_pause_page(int *line_count, int assume_yes)
{
    if (assume_yes) return 0;
#if defined(_WIN32)
    if (!_isatty(_fileno(stdout))) return 0;
#else
    if (!isatty(STDOUT_FILENO)) return 0;
#endif
    if (++(*line_count) >= 23) {
        *line_count = 0;
        printf("Press RETURN for next line, ESCAPE to cancel, other key for next page ... ");
        fflush(stdout);
        int ch = getchar();
        if (ch == 27)
            return -1;
    }
    return 0;
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

    /* Header signature & checksum check */
    {
        uha_header h;
        uint8_t dummy[39];
        uint16_t check16;
        int k;

        memset(dummy, 0, sizeof(dummy));
        memcpy(dummy, "UHA", 3);
        dummy[3] = 0x06;
        check16 = (uint16_t)(uha_crc32(dummy + 4, 31) & 0xFFFFu);
        for (k = 0; k < 31; k++)
            dummy[4 + k] ^= (uint8_t)(((check16 & 0xFFu) + (uint32_t)k * (uint32_t)k) & 0xFFu);
        dummy[37] = (uint8_t)(check16 & 0xFFu);
        dummy[38] = (uint8_t)(check16 >> 8);
        if (uha_parse_header(dummy, sizeof(dummy), &h) != 0) {
            fprintf(stderr, "FAIL: uha_parse_header dummy test failed\n");
            return 1;
        }
        dummy[37] ^= 1;
        if (uha_parse_header(dummy, sizeof(dummy), &h) == 0) {
            fprintf(stderr, "FAIL: uha_parse_header accepted corrupted check16\n");
            return 1;
        }
        dummy[37] ^= 1;
        dummy[3] = 0x05;
        if (uha_parse_header(dummy, sizeof(dummy), &h) == 0) {
            fprintf(stderr, "FAIL: uha_parse_header accepted bad version\n");
            return 1;
        }
        printf("  [OK] Header parser & checksum self-test passed\n");
    }

    /* EXE & Multimedia pre-filter roundtrip check */
    {
        uint8_t ref[4096], work[4096];
        int swap, k;

        for (k = 0; k < (int)sizeof(ref); k++)
            ref[k] = (uint8_t)((k * 37 + 13) & 0xFF);
        ref[0] = 'M'; ref[1] = 'Z';
        ref[6] = 0x10; ref[7] = 0x00;
        ref[0x18] = 0x40; ref[0x19] = 0x00;
        for (k = 0; k < 16; k++) {
            uint16_t off = (uint16_t)(k * 17);
            uint16_t seg = (uint16_t)(k / 2);
            ref[0x40 + k * 4] = (uint8_t)(off & 0xFF);
            ref[0x40 + k * 4 + 1] = (uint8_t)(off >> 8);
            ref[0x40 + k * 4 + 2] = (uint8_t)(seg & 0xFF);
            ref[0x40 + k * 4 + 3] = (uint8_t)(seg >> 8);
        }
        ref[200] = 0xE8; ref[201] = 0x00; ref[202] = 0x02; ref[203] = 0x00; ref[204] = 0x00;
        ref[300] = 0xE9; ref[301] = 0xB0; ref[302] = 0xFF; ref[303] = 0xFF; ref[304] = 0xFF;
        ref[400] = 0xE8; ref[401] = 0x10; ref[402] = 0x20; ref[403] = 0x34; ref[404] = 0x12;
        ref[500] = 0xE8; ref[501] = (uint8_t)((0x2010 + 400 - 500) & 0xFF);
        ref[502] = (uint8_t)(((0x2010 + 400 - 500) >> 8) & 0xFF);
        ref[503] = 0x56; ref[504] = 0x78;
        ref[600] = 0xE8; ref[601] = 0x00; ref[602] = 0x80; ref[603] = 0x99; ref[604] = 0x88;

        for (swap = 0; swap <= 1; swap++) {
            memcpy(work, ref, sizeof(ref));
            if (!uha_apply_forward_filter(work, (uint32_t)sizeof(work), swap) ||
                !uha_restore_filter(work, (uint32_t)sizeof(work), swap) ||
                memcmp(work, ref, sizeof(ref)) != 0) {
                fprintf(stderr, "FAIL: EXE filter roundtrip failed (swap=%d)\n", swap);
                return 1;
            }
        }

        memset(ref, 0, sizeof(ref));
        ref[0] = 'B'; ref[1] = 'M';
        ref[26] = 1; ref[28] = 24;
        for (k = 36; k < 2048; k++)
            ref[k] = (uint8_t)((k * 5 + (k / 3)) & 0xFF);
        memcpy(work, ref, 2048);
        uha_apply_forward_multimedia(work, 2048);
        uha_restore_multimedia(work, 2048);
        if (memcmp(work, ref, 2048) != 0) {
            fprintf(stderr, "FAIL: BMP multimedia filter roundtrip failed\n");
            return 1;
        }

        memset(ref, 0, sizeof(ref));
        memcpy(ref, "RIFF\0\0\0\0WAVEfmt ", 16);
        ref[20] = 1; ref[22] = 2; ref[34] = 16;
        for (k = 36; k < 2048; k++)
            ref[k] = (uint8_t)((k * 11) & 0xFF);
        memcpy(work, ref, 2048);
        uha_apply_forward_multimedia(work, 2048);
        uha_restore_multimedia(work, 2048);
        if (memcmp(work, ref, 2048) != 0) {
            fprintf(stderr, "FAIL: WAV multimedia filter roundtrip failed\n");
            return 1;
        }
        printf("  [OK] EXE & multimedia filter self-test passed\n");
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
 * Command: List (l)
 * -------------------------------------------------------------------------- */
static int cmd_list(const char *arc, const char *pw, int verbose, int unix_paths,
                    int bare_list, int bpb_mode, int n_filter_args, char **filter_args,
                    int assume_yes)
{
    uint8_t *raw;
    size_t rawlen;
    uha_header h;
    uha_entrylist el;
    int rc, i;
    uint64_t total_usize = 0;
    int matched_count = 0;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        uha_msg(0, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        uha_msg(0, "Error: invalid UHARC header in %s (code %d)\n", arc, rc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        uha_msg(0, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        uha_msg(0, "Error: decryption failed (code %d)\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        uha_msg(0, "Error: failed to read file table (code %d)\n", rc);
        free(raw);
        return 1;
    }

    /* Separate filter patterns and excludes */
    char **pos_patterns = NULL;
    int n_pos = 0;
    char **excludes = NULL;
    int n_excl = 0;
    if (n_filter_args > 0) {
        pos_patterns = (char **)malloc((size_t)n_filter_args * sizeof(char *));
        excludes = (char **)malloc((size_t)n_filter_args * sizeof(char *));
        for (i = 0; i < n_filter_args; i++) {
            if (filter_args[i][0] == '!' && filter_args[i][1])
                excludes[n_excl++] = filter_args[i] + 1;
            else
                pos_patterns[n_pos++] = filter_args[i];
        }
    }

    for (i = 0; i < el.count; i++) {
        const char *nm = el.items[i].name ? el.items[i].name : "";
        if (n_filter_args > 0 && !uha_matches_masks(nm, pos_patterns, n_pos, excludes, n_excl))
            continue;
        matched_count++;
    }

    if (n_filter_args > 0 && matched_count == 0) {
        uha_msg(0, "\nNo matching files found !\n\nProcess aborted.\n");
        free(pos_patterns);
        free(excludes);
        uha_entrylist_free(&el);
        free(raw);
        return 255;
    }

    if (bare_list) {
        for (i = 0; i < el.count; i++) {
            const char *nm = el.items[i].name ? el.items[i].name : "";
            if (n_filter_args > 0 && !uha_matches_masks(nm, pos_patterns, n_pos, excludes, n_excl))
                continue;
            char p[1024];
            format_path(p, sizeof(p), nm, unix_paths);
            printf("%s\n", p);
        }
        free(pos_patterns);
        free(excludes);
        uha_entrylist_free(&el);
        free(raw);
        return 0;
    }

    print_banner();
    char created_str[64];
    format_archive_created(arc, created_str, sizeof(created_str));
    uha_msg(1, "Processing archive \"%s\" (created: %s).\n\n", arc, created_str);

    if (verbose) {
        uha_msg(1, "file                                size     date        time    attr   crc-32 \n");
        uha_msg(1, "-------------------------------------------------------------------------------\n");
    } else {
        uha_msg(1, "file                                             size     date      time   attr\n");
        uha_msg(1, "-------------------------------------------------------------------------------\n");
    }

    int line_count = 0;
    for (i = 0; i < el.count; i++) {
        const char *nm = el.items[i].name ? el.items[i].name : "<unknown>";
        if (n_filter_args > 0 && !uha_matches_masks(nm, pos_patterns, n_pos, excludes, n_excl))
            continue;

        uint32_t sz = el.items[i].size;
        char disp_name[1024];
        format_path(disp_name, sizeof(disp_name), nm, unix_paths);

        char d_str[32], t_str[32], a_str[8];
        format_dos_datetime(el.items[i].dos_date, el.items[i].dos_time,
                            d_str, sizeof(d_str), t_str, sizeof(t_str), verbose);
        format_dos_attr(el.items[i].dos_attr, a_str, sizeof(a_str));

        total_usize += sz;

        if (verbose) {
            uha_msg(1, "%s\n", disp_name);
            uha_msg(1, "                               %10u  %s  %s  %s  %08X\n",
                    sz, d_str, t_str, a_str, el.items[i].crc);
        } else {
            char short_name[49];
            if (strlen(disp_name) > 48) {
                strncpy(short_name, disp_name, 45);
                strcpy(short_name + 45, "...");
            } else {
                snprintf(short_name, sizeof(short_name), "%-48s", disp_name);
            }
            uha_msg(1, "%-48s %9u  %s  %s  %s\n",
                    short_name, sz, d_str, t_str, a_str);
        }

        if (maybe_pause_page(&line_count, assume_yes) < 0) {
            uha_msg(1, "\nListing cancelled.\n");
            break;
        }
    }

    uha_msg(1, "-------------------------------------------------------------------------------\n");
    if (verbose) {
        if (bpb_mode) {
            double bpb = total_usize ? ((double)h.psize * 8.0 / (double)total_usize) : 0.0;
            uha_msg(1, "%d file%s                               %10" PRIu64 "\n",
                    matched_count, matched_count == 1 ? "" : "s", total_usize);
            uha_msg(1, "                               %10u packed (%s-mode), ratio: %.3f bpb\n\n",
                    h.psize, uha_codec_name(&h), bpb);
        } else {
            double ratio = total_usize ? ((double)h.psize / (double)total_usize * 100.0) : 0.0;
            uha_msg(1, "%d file%s                               %10" PRIu64 "\n",
                    matched_count, matched_count == 1 ? "" : "s", total_usize);
            uha_msg(1, "                               %10u packed (%s-mode), ratio: %.1f%%\n\n",
                    h.psize, uha_codec_name(&h), ratio);
        }
    } else {
        if (bpb_mode) {
            double bpb = total_usize ? ((double)h.psize * 8.0 / (double)total_usize) : 0.0;
            uha_msg(1, "%d file%s                               %10" PRIu64 "\n",
                    matched_count, matched_count == 1 ? "" : "s", total_usize);
            uha_msg(1, "                               %10u packed, ratio: %.3f bpb\n\n",
                    h.psize, bpb);
        } else {
            double ratio = total_usize ? ((double)h.psize / (double)total_usize * 100.0) : 0.0;
            uha_msg(1, "%d file%s                               %10" PRIu64 "\n",
                    matched_count, matched_count == 1 ? "" : "s", total_usize);
            uha_msg(1, "                               %10u packed, ratio: %.1f%%\n\n",
                    h.psize, ratio);
        }
    }

    free(pos_patterns);
    free(excludes);
    uha_entrylist_free(&el);
    free(raw);
    return 0;
}

/* --------------------------------------------------------------------------
 * Command: Extract (x) & Extract Flat (e)
 * -------------------------------------------------------------------------- */
static int cmd_extract(const char *arc, const char *outdir, const char *pw, int flat,
                       int unix_paths, int overwrite_mode, int assume_yes,
                       int n_filter_args, char **filter_args)
{
    uint8_t *raw, *plain;
    size_t rawlen;
    uha_header h;
    uha_entrylist el;
    int rc, i;
    int errors = 0;
    uint64_t ofs;
    int always_yes = 0;
    int matched_count = 0;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        uha_msg(0, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        uha_msg(0, "Error: header error %d in %s\n", rc, arc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        uha_msg(0, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        uha_msg(0, "Error: decryption error %d\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        uha_msg(0, "Error: entries error %d\n", rc);
        free(raw);
        return 1;
    }

    /* Separate filter patterns and excludes */
    char **pos_patterns = NULL;
    int n_pos = 0;
    char **excludes = NULL;
    int n_excl = 0;
    if (n_filter_args > 0) {
        pos_patterns = (char **)malloc((size_t)n_filter_args * sizeof(char *));
        excludes = (char **)malloc((size_t)n_filter_args * sizeof(char *));
        for (i = 0; i < n_filter_args; i++) {
            if (filter_args[i][0] == '!' && filter_args[i][1])
                excludes[n_excl++] = filter_args[i] + 1;
            else
                pos_patterns[n_pos++] = filter_args[i];
        }
    }

    for (i = 0; i < el.count; i++) {
        const char *nm = el.items[i].name ? el.items[i].name : "";
        if (n_filter_args > 0 && !uha_matches_masks(nm, pos_patterns, n_pos, excludes, n_excl))
            continue;
        matched_count++;
    }

    if (n_filter_args > 0 && matched_count == 0) {
        uha_msg(0, "\nNo matching files found !\n\nProcess aborted.\n");
        free(pos_patterns);
        free(excludes);
        uha_entrylist_free(&el);
        free(raw);
        return 255;
    }

    plain = NULL;
    if (h.usize > 0) {
        plain = (uint8_t *)malloc(h.usize);
        if (!plain) {
            uha_msg(0, "Error: out of memory allocating %u bytes\n", h.usize);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
        rc = uha_decode_payload(raw, rawlen, &h, &el, plain);
        if (rc != 0) {
            uha_msg(0, "Error: payload decoding error %d (codec=%s order=0x%02X)\n",
                    rc, uha_codec_name(&h), h.order);
            free(plain);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
    }

    if (ensure_dir(outdir) != 0) {
        uha_msg(0, "Error: cannot create target directory %s\n", outdir);
        free(plain);
        free(pos_patterns);
        free(excludes);
        uha_entrylist_free(&el);
        free(raw);
        return 1;
    }

    print_banner();
    char created_str[64];
    format_archive_created(arc, created_str, sizeof(created_str));
    uha_msg(1, "Processing archive \"%s\" (created: %s).\n\n", arc, created_str);
    uha_msg(1, "Extracting %d file%s (%u bytes)\n", matched_count, matched_count == 1 ? "" : "s", h.usize);
    uha_msg(1, "-------------------------------------------------------------------------------\n");

    ofs = 0;
    for (i = 0; i < el.count; i++) {
        char clean_name[1024];
        char path[1200];
        const char *raw_name = el.items[i].name ? el.items[i].name : "file";
        uint32_t sz = el.items[i].size;

        if ((uint64_t)ofs + sz > h.usize) {
            uha_msg(0, "Error: member size exceeds payload boundary\n");
            free(plain);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        if (n_filter_args > 0 && !uha_matches_masks(raw_name, pos_patterns, n_pos, excludes, n_excl)) {
            ofs += sz;
            continue;
        }

        if (flat) {
            const char *bname = basename_of(raw_name);
            sanitize_extract_path(clean_name, sizeof(clean_name), bname, unix_paths);
        } else {
            if (!is_safe_relpath(raw_name)) {
                fprintf(stderr, "Security warning: skipping unsafe path traversal: %s\n", raw_name);
                ofs += sz;
                continue;
            }
            sanitize_extract_path(clean_name, sizeof(clean_name), raw_name, unix_paths);
        }

        if (strcmp(outdir, ".") == 0)
            snprintf(path, sizeof(path), "%s", clean_name);
        else
            snprintf(path, sizeof(path), "%s/%s", outdir, clean_name);

        int ow = query_file_overwrite(path, overwrite_mode, assume_yes, &always_yes);
        if (ow == 0) {
            ofs += sz;
            continue;
        }
        if (ow < 0) {
            uha_msg(0, "Process aborted.\n");
            free(plain);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 255;
        }

        if (ensure_parent(path) != 0) {
            uha_msg(0, "Error: failed to create parent directory for %s\n", path);
            free(plain);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        if (write_file(path, plain ? plain + ofs : (const uint8_t *)"", sz) != 0) {
            uha_msg(0, "Error: failed to write %s\n", path);
            free(plain);
            free(pos_patterns);
            free(excludes);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }

        uint32_t computed_crc = uha_crc32(plain ? plain + ofs : (const uint8_t *)"", sz);
        if (el.items[i].has_crc && computed_crc != el.items[i].crc) {
            fprintf(stderr, "  %-40s [CRC MISMATCH: computed %08X, expected %08X]\n",
                    clean_name, computed_crc, el.items[i].crc);
            errors++;
        } else {
            uha_msg(1, "Extracting %-40s                                     OK\n", clean_name);
        }
        restore_file_meta(path, el.items[i].dos_date, el.items[i].dos_time, el.items[i].dos_attr);

        ofs += sz;
    }

    free(pos_patterns);
    free(excludes);
    free(plain);
    uha_entrylist_free(&el);
    free(raw);
    if (errors > 0) {
        uha_msg(0, "\nExtraction FAILED: %d CRC error(s) detected.\n", errors);
        return 1;
    }
    uha_msg(1, "Completed successfully (0.0 sec)                                   All files OK\n");
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
    uint64_t ofs;
    int errors = 0;

    raw = read_file(arc, &rawlen);
    if (!raw) {
        uha_msg(0, "Error: cannot open archive %s\n", arc);
        return 1;
    }

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0) {
        uha_msg(0, "Error: header error %d in %s\n", rc, arc);
        free(raw);
        return 1;
    }

    rc = uha_decrypt(raw, rawlen, &h, pw);
    if (rc == -5) {
        uha_msg(0, "Error: archive is password-protected (use -pw<password>)\n");
        free(raw);
        return 1;
    }
    if (rc != 0) {
        uha_msg(0, "Error: decryption error %d\n", rc);
        free(raw);
        return 1;
    }

    rc = uha_read_entries(raw, rawlen, &el);
    if (rc < 0) {
        uha_msg(0, "Error: entries error %d\n", rc);
        free(raw);
        return 1;
    }

    plain = NULL;
    if (h.usize > 0) {
        plain = (uint8_t *)malloc(h.usize);
        if (!plain) {
            uha_msg(0, "Error: out of memory allocating %u bytes\n", h.usize);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
        rc = uha_decode_payload(raw, rawlen, &h, &el, plain);
        if (rc != 0) {
            uha_msg(0, "Error: payload decoding error %d (codec=%s order=0x%02X)\n",
                    rc, uha_codec_name(&h), h.order);
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
    }

    print_banner();
    char created_str[64];
    format_archive_created(arc, created_str, sizeof(created_str));
    uha_msg(1, "Processing archive \"%s\" (created: %s).\n\n", arc, created_str);
    uha_msg(1, "Testing %d file%s (%u bytes)\n", el.count, el.count == 1 ? "" : "s", h.usize);
    uha_msg(1, "-------------------------------------------------------------------------------\n");

    ofs = 0;
    for (i = 0; i < el.count; i++) {
        uint32_t sz = el.items[i].size;
        const char *nm = el.items[i].name ? el.items[i].name : "<unknown>";
        uint32_t computed_crc;

        if ((uint64_t)ofs + sz > h.usize) {
            uha_msg(0, "Error: member size exceeds payload boundary\n");
            free(plain);
            uha_entrylist_free(&el);
            free(raw);
            return 1;
        }
        computed_crc = uha_crc32(plain ? plain + ofs : (const uint8_t *)"", sz);

        if (el.items[i].has_crc && computed_crc != el.items[i].crc) {
            uha_msg(0, "Testing %-40s FAILED (CRC %08X != %08X)\n", nm, computed_crc, el.items[i].crc);
            errors++;
        } else {
            uha_msg(1, "Testing %-40s                                       OK\n", nm);
        }
        ofs += sz;
    }

    free(plain);
    uha_entrylist_free(&el);
    free(raw);

    if (errors == 0) {
        uha_msg(1, "Completed successfully (0.0 sec)                                   All files OK\n");
        return 0;
    } else {
        uha_msg(0, "\nIntegrity test FAILED: %d error(s) detected.\n", errors);
        return 1;
    }
}

static int uha_ascii_tolower_cmp(const char *a, const char *b)
{
    for (;;) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z')
            ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == 0)
            return 0;
    }
}

typedef struct {
    uha_member member;
    const char *bn;
    uint32_t score;
    int empty;
} uha_sort_item;

static int uha_cmp_sort_item(const void *pa, const void *pb)
{
    const uha_sort_item *a = (const uha_sort_item *)pa;
    const uha_sort_item *b = (const uha_sort_item *)pb;
    int c;

    if (a->empty != b->empty)
        return a->empty - b->empty;
    if (a->empty == 0) {
        c = uha_ascii_tolower_cmp(a->bn, b->bn);
        if (c != 0)
            return c;
        return (a->member.cmd_rank < b->member.cmd_rank) ? -1 :
               (a->member.cmd_rank > b->member.cmd_rank) ? 1 : 0;
    }
    if (a->score != b->score)
        return (a->score < b->score) ? -1 : 1;
    if (a->member.size != b->member.size)
        return (a->member.size > b->member.size) ? -1 : 1;
    c = uha_ascii_tolower_cmp(a->bn, b->bn);
    if (c != 0)
        return c;
    return (a->member.cmd_rank < b->member.cmd_rank) ? -1 :
           (a->member.cmd_rank > b->member.cmd_rank) ? 1 : 0;
}

static uint32_t uha_ext_group_key(const char *bn)
{
    /* Canonical 170-entry UHARC extension table: 0..67 -> group 0x0D, 68..169 -> group 0x0F */
    static const char *const EXTS[170] = {
        /* 0x0D (0..67): text, source, executables */
        "TXT", "FAQ", "ME",  "1ST", "FRM", "DIZ", "BAT", "CMD",
        "CNT", "INF", "INI", "URL", "HTM", "DOK", "DOC", "DOT",
        "RTF", "WRI", "HLP", "GID", "GRP", "LNK", "PIF", "PS",
        "TEX", "LST", "LOG", "MAK", "CFG", "REG", "H",   "HPP",
        "HXX", "C",   "CPP", "CXX", "CC",  "ASM", "INC", "PAS",
        "BAS", "BIN", "FLT", "DLL", "EXE", "COM", "OVL", "OVR",
        "OCX", "VXD", "DRV", "ACM", "CPL", "SYS", "OBJ", "LIB",
        "VBX", "OLB", "MPD", "PDR", "3GR", "386", "TTF", "FON",
        "FNT", "BGI", "CHR", "CPI",
        /* 0x0F (68..169): compressed, audio, image, archive */
        "PDF", "PFB", "RMI", "MID", "SMP", "RAW", "WAV", "VOC",
        "MOD", "669", "STM", "ULT", "UWF", "S3I", "S3M", "MTM",
        "XM",  "OKT", "SND", "SOU", "XI",  "AIF", "DSF", "SF",
        "FSM", "PAT", "SAM", "SDX", "AU",  "IFF", "LBM", "PCX",
        "CUR", "ICO", "BMP", "TGA", "RAS", "TIF", "FLI", "FLC",
        "AVI", "GIF", "PNG", "JPE", "JPG", "MPG", "MP2", "MP3",
        "MPE", "MOV", "WA",  "X",   "Z",   "777", "ACE", "AIN",
        "ARC", "ARI", "ARJ", "BIX", "BOA", "B58", "CAB", "DWC",
        "ESP", "ERI", "GZ",  "HA",  "HAP", "HPK", "HYP", "ICT",
        "LG",  "LHA", "LIM", "LZH", "PAK", "Q",   "RAR", "SLC",
        "SQZ", "UC2", "UFA", "YC",  "ZIP", "ZOO", "ACB", "BMF",
        "BA",  "BC",  "BZ",  "BZ2", "DST", "IMP", "J",   "PMD",
        "RK",  "RKV", "SZ",  "UHA", "TGZ", "TAZ"
    };
    const char *dot = strrchr(bn, '.');
    char ext3[4] = {0, 0, 0, 0};
    int i;

    if (dot && dot[1]) {
        for (i = 0; i < 3 && dot[1 + i]; i++) {
            unsigned char ch = (unsigned char)dot[1 + i];
            if (ch >= 'a' && ch <= 'z')
                ch = (unsigned char)(ch - 'a' + 'A');
            ext3[i] = (char)ch;
        }
    }
    if (ext3[0]) {
        for (i = 0; i < 170; i++) {
            if (strcmp(ext3, EXTS[i]) == 0) {
                uint32_t grp = (i < 68) ? 0x0Du : 0x0Fu;
                return (grp << 24) | (uint32_t)i;
            }
        }
    }
    return (0x0Eu << 24) |
           ((uint32_t)(uint8_t)ext3[0] << 16) |
           ((uint32_t)(uint8_t)ext3[1] << 8) |
           (uint32_t)(uint8_t)ext3[2];
}

/* --------------------------------------------------------------------------
 * Command: Add (a) & Move (m)
 * -------------------------------------------------------------------------- */
static int cmd_add(const char *arc, int n_file_args, char **file_args,
                   int method, int alz_class, int move_files,
                   int recurse, int empty_dirs, const char *ae_mask,
                   char list_char, char excl_char, int path_mode,
                   int overwrite_mode, int assume_yes,
                   int clear_archive_attr, int sfx, const char *sfx_stub,
                   const char *pw, int ph_mode, int buf_kb)
{
    (void)buf_kb;
    if (!check_archive_overwrite(arc, overwrite_mode, assume_yes))
        return 255;

    uha_scan_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.recurse = recurse;
    opts.empty_dirs = empty_dirs;
    opts.ae_mask = ae_mask;
    opts.list_spec = list_char;
    opts.exclude_spec = excl_char;

    uha_file_list disk_paths, arc_names;
    uha_file_list_init(&disk_paths);
    uha_file_list_init(&arc_names);

    uha_collect_files(n_file_args, file_args, &opts, &disk_paths, &arc_names, path_mode);
    if (disk_paths.count == 0) {
        uha_msg(0, "\nNo matching files found !\n\nProcess aborted.\n");
        uha_file_list_free(&disk_paths);
        uha_file_list_free(&arc_names);
        return 255;
    }

    uint8_t *sfx_stub_data = NULL;
    size_t sfx_stub_len = 0;
    if (sfx) {
        sfx_stub_data = load_sfx_stub(sfx_stub, &sfx_stub_len);
        if (!sfx_stub_data) {
            uha_msg(0, "\nERROR: Can't create archive file\n\nProcess aborted.\n");
            uha_file_list_free(&disk_paths);
            uha_file_list_free(&arc_names);
            return 255;
        }
    }

    int nfiles = disk_paths.count;
    uha_member *members = (uha_member *)calloc((size_t)nfiles, sizeof(uha_member));
    if (!members) {
        free(sfx_stub_data);
        uha_file_list_free(&disk_paths);
        uha_file_list_free(&arc_names);
        return 1;
    }

    uint64_t total_add_size = 0;
    int i;
    for (i = 0; i < nfiles; i++) {
        size_t n = 0;
        uint8_t *d;
        uint64_t file_size = 0;
        uint32_t file_mtime = 0;
        uint8_t dattr = 0x20;
        int have_stat = 0;

#ifdef _WIN32
        struct __stat64 st64;
        if (_stat64(disk_paths.items[i], &st64) == 0) {
            have_stat = 1;
            if (st64.st_size < 0) st64.st_size = 0;
            file_size = (uint64_t)st64.st_size;
            file_mtime = (st64.st_mtime > 0) ? (uint32_t)st64.st_mtime : 0u;
            dattr = (st64.st_mode & _S_IWRITE) ? 0x20 : 0x21;
        }
#else
        struct stat st;
        if (stat(disk_paths.items[i], &st) == 0) {
            have_stat = 1;
            if (st.st_size < 0) st.st_size = 0;
            file_size = (uint64_t)st.st_size;
            file_mtime = (st.st_mtime > 0) ? (uint32_t)st.st_mtime : 0u;
            dattr = (st.st_mode & 0222) ? 0x20 : 0x21;
        }
#endif
        if (have_stat && (file_size > 0xFFFFFFFFULL || total_add_size + file_size > 0xFFFFFFFFULL)) {
            uha_msg(0, "Error: total uncompressed size exceeds UHA 4 GiB limit (file: %s)\n",
                    disk_paths.items[i]);
            while (i-- > 0)
                free((void *)members[i].data);
            free(members);
            free(sfx_stub_data);
            uha_file_list_free(&disk_paths);
            uha_file_list_free(&arc_names);
            return 1;
        }

        d = read_file(disk_paths.items[i], &n);
        if (!d || (uint64_t)n > 0xFFFFFFFFULL || total_add_size + (uint64_t)n > 0xFFFFFFFFULL) {
            uha_msg(0, d ? "Error: total uncompressed size exceeds UHA 4 GiB limit (%s)\n"
                         : "Error: cannot read source file %s\n", disk_paths.items[i]);
            free(d);
            while (i-- > 0)
                free((void *)members[i].data);
            free(members);
            free(sfx_stub_data);
            uha_file_list_free(&disk_paths);
            uha_file_list_free(&arc_names);
            return 1;
        }
        total_add_size += (uint64_t)n;

        members[i].arcname = arc_names.items[i];
        members[i].data = d;
        members[i].size = (uint32_t)n;
        members[i].mtime = file_mtime;
        members[i].cmd_rank = (uint32_t)i;
        members[i].dos_attr = dattr;
    }

    /* Multi-file frontier permutation model */
    int use_frontier = (nfiles > 1);

    if (use_frontier && nfiles > 0) {
        int arena = (method == 2);      /* -mx = PPM = arena */
        uha_sort_item *items = (uha_sort_item *)calloc((size_t)nfiles, sizeof(*items));
        if (items) {
            int k;
            for (k = 0; k < nfiles; k++) {
                const char *bn = members[k].arcname;
                const char *q;
                for (q = bn; *q; q++) {
                    if (*q == '/' || *q == '\\')
                        bn = q + 1;
                }
                items[k].member = members[k];
                items[k].bn = bn;
                if (members[k].size == 0) {
                    items[k].empty = 0;
                    items[k].score = 0;
                } else {
                    uint32_t base_key = uha_ext_group_key(bn);
                    uint32_t pal = arena ? uha_frontier_pal(members[k].data, members[k].size) : 0u;
                    items[k].empty = 1;
                    items[k].score = base_key - pal;
                }
            }
            qsort(items, (size_t)nfiles, sizeof(*items), uha_cmp_sort_item);
            for (k = 0; k < nfiles; k++)
                members[k] = items[k].member;

            if (arena) {
                uint64_t armement = 0, tot = 0;
                uint32_t f;
                uint8_t *concat;
                for (f = 0; f < (uint32_t)nfiles; f++)
                    tot += members[f].size;
                if (tot <= 0xFFFFFFFFULL) {
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
            free(items);
        }
    }

    /* Configure password & header encryption */
    uha_set_password(pw, ph_mode);

    print_banner();
    uha_msg(1, "Searching files ...\n");
    uha_msg(1, "Analysing files ...  0%%99%%\n");
    uha_msg(1, "Creating archive \"%s\".\n\n", arc);

    const char *mode_str = "STORE";
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    int rc = 0;

    if (method == 4) {
        rc = uha_encode_rle(members, nfiles, &raw, &rawlen);
        mode_str = "RLE";
    } else if (method == 3) {
        int lzorder = 8;
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
        uha_msg(0, "Error: compression failed (code %d)\n", rc);
        free(raw);
        free(sfx_stub_data);
        uha_file_list_free(&disk_paths);
        uha_file_list_free(&arc_names);
        return 1;
    }

    /* Write output archive file (prepended with SFX stub if requested) */
    FILE *fp = fopen(arc, "wb");
    if (!fp) {
        uha_msg(0, "\nERROR: Can't create archive file\n\nProcess aborted.\n");
        free(raw);
        free(sfx_stub_data);
        uha_file_list_free(&disk_paths);
        uha_file_list_free(&arc_names);
        return 255;
    }
    if (sfx_stub_data && sfx_stub_len > 0) {
        if (fwrite(sfx_stub_data, 1, sfx_stub_len, fp) != sfx_stub_len) {
            fclose(fp);
            uha_msg(0, "\nERROR: Can't create archive file\n\nProcess aborted.\n");
            free(raw);
            free(sfx_stub_data);
            uha_file_list_free(&disk_paths);
            uha_file_list_free(&arc_names);
            return 255;
        }
    }
    if (fwrite(raw, 1, rawlen, fp) != rawlen) {
        fclose(fp);
        uha_msg(0, "\nERROR: Can't create archive file\n\nProcess aborted.\n");
        free(raw);
        free(sfx_stub_data);
        uha_file_list_free(&disk_paths);
        uha_file_list_free(&arc_names);
        return 255;
    }
    fclose(fp);

    uha_msg(1, "Adding %d file%s (%" PRIu64 " bytes)                                 size     packed   ratio\n",
            nfiles, nfiles == 1 ? "" : "s", total_add_size);
    uha_msg(1, "-------------------------------------------------------------------------------\n");
    uha_msg(1, "Completed successfully (0.0 sec)           Total:          %10" PRIu64 " %10zu  %s\n",
            total_add_size, rawlen, mode_str);

    free(raw);
    free(sfx_stub_data);

    /* Clear archive attribute if requested */
    if (clear_archive_attr) {
        for (i = 0; i < nfiles; i++)
            clear_archive_attr_if_requested(disk_paths.items[i], 1);
    }

    /* Move command: delete original files */
    if (move_files) {
        for (i = 0; i < nfiles; i++) {
            if (remove(disk_paths.items[i]) != 0)
                uha_msg(0, "Warning: could not delete %s\n", disk_paths.items[i]);
        }
    }

    uha_file_list_free(&disk_paths);
    uha_file_list_free(&arc_names);
    return 0;
}

static int parse_md_switch(const char *arg, const char *val, int *dict_kb)
{
    if (!val[0] || strcmp(val, "+") == 0) {
        *dict_kb = 0;
        return 0;
    }
    if (strcmp(val, "-") == 0) {
        *dict_kb = -1;
        return 0;
    }
    if (isalpha((unsigned char)val[0]) && val[1] == '\0') {
        int c = tolower((unsigned char)val[0]);
        if (c >= 'a' && c <= 'p') {
            *dict_kb = 1 << (c - 'a');
            return 0;
        }
        uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
        return -1;
    }
    if (isdigit((unsigned char)val[0])) {
        unsigned long v = 0;
        for (const char *p = val; *p; p++) {
            if (!isdigit((unsigned char)*p)) {
                uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
                return -1;
            }
            v = v * 10ul + (unsigned long)(*p - '0');
            if (v > 32768ul) {
                uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
                return -1;
            }
        }
        if (v < 1ul || (v & (v - 1ul)) != 0ul) {
            uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
            return -1;
        }
        *dict_kb = (int)v;
        return 0;
    }
    uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
    return -1;
}

typedef struct {
    int display_mode;       /* 0, 1, 2 */
    int method;             /* 0..4 */
    int alz_class;          /* 0=-m1, 1=-m2, 2=-m3 */
    int dict_kb;
    int have_md;
    int nomm;               /* -1=auto, 0=mm+, 1=mm- */
    int overwrite_mode;     /* 0=prompt (-op), 1=always (-o+), 2=never (-o-) */
    int assume_yes;         /* -y */
    int path_mode;          /* 0=-p-, 1=-pr, 2=-pf, 3=-pe */
    int ph_mode;            /* -ph */
    char password[256];
    int have_pw;            /* 0=no, 1=inline, 2=interactive */
    int recurse;            /* -r */
    int empty_dirs;         /* -ed */
    int clear_archive_attr; /* -ac */
    char ae_mask[64];       /* -ae */
    int bpb_mode;           /* -bpb */
    int buffer_kb;          /* -b<n> */
    int pause_exit;         /* -px */
    int sfx;                /* -sfx */
    char sfx_stub[1024];
    char target_dir[1024];  /* -t */
    char log_file[1024];    /* -lg */
    char list_char;         /* -@ */
    char excl_char;         /* -! */
    int unix_paths;         /* -u, --unix */
    int bare_list;          /* -1, --bare */
    int idle_priority;      /* -idle */
    int vm_mode;            /* -vm */
} uha_cli_options;

static void tokenize_options(const char *opt_str, int *argc_out, char ***argv_out)
{
    if (!opt_str || !*opt_str) {
        *argc_out = 0;
        *argv_out = NULL;
        return;
    }
    int cap = 16;
    int count = 0;
    char **arr = (char **)malloc((size_t)cap * sizeof(char *));
    const char *p = opt_str;

    while (*p) {
        while (*p && isspace((unsigned char)*p))
            p++;
        if (!*p)
            break;

        char tok[1024];
        int ti = 0;
        if (*p == '"') {
            p++;
            while (*p && *p != '"' && ti < (int)sizeof(tok) - 1)
                tok[ti++] = *p++;
            if (*p == '"')
                p++;
        } else {
            while (*p && !isspace((unsigned char)*p) && ti < (int)sizeof(tok) - 1)
                tok[ti++] = *p++;
        }
        tok[ti] = '\0';
        if (ti > 0) {
            if (count >= cap) {
                cap *= 2;
                arr = (char **)realloc(arr, (size_t)cap * sizeof(char *));
            }
#if defined(_WIN32)
            arr[count++] = _strdup(tok);
#else
            arr[count++] = strdup(tok);
#endif
        }
    }
    *argc_out = count;
    *argv_out = arr;
}

static int parse_switch_arg(const char *arg, uha_cli_options *opts)
{
    const char *sw = arg + 1;
    if (strcmp(sw, "-") == 0) {
        return 100; /* stop scanning */
    }
    if (strcmp(sw, "m0") == 0) {
        opts->method = 0; return 0;
    }
    if (strcasecmp(sw, "mr") == 0) {
        opts->method = 4; return 0;
    }
    if (strcmp(sw, "m1") == 0) {
        opts->method = 1; opts->alz_class = 0; return 0;
    }
    if (strcmp(sw, "m2") == 0) {
        opts->method = 1; opts->alz_class = 1; return 0;
    }
    if (strcmp(sw, "m3") == 0) {
        opts->method = 1; opts->alz_class = 2; return 0;
    }
    if (strcmp(sw, "mx") == 0) {
        opts->method = 2; return 0;
    }
    if (strcmp(sw, "mz") == 0) {
        opts->method = 3; return 0;
    }
    if (strncmp(sw, "md", 2) == 0) {
        if (parse_md_switch(arg, sw + 2, &opts->dict_kb) != 0)
            return -1;
        opts->have_md = 1;
        return 0;
    }
    if (strcmp(sw, "mm-") == 0) {
        opts->nomm = 1; return 0;
    }
    if (strcmp(sw, "mm+") == 0 || strcmp(sw, "mm") == 0) {
        opts->nomm = 0; return 0;
    }
    if (strncmp(sw, "pw", 2) == 0) {
        if (sw[2]) {
            strncpy(opts->password, sw + 2, sizeof(opts->password) - 1);
            opts->have_pw = 1;
        } else {
            opts->have_pw = 2;
        }
        return 0;
    }
    if (strcmp(sw, "ph+") == 0 || strcmp(sw, "ph") == 0) {
        opts->ph_mode = 1; return 0;
    }
    if (strcmp(sw, "ph-") == 0) {
        opts->ph_mode = 0; return 0;
    }
    if (strcmp(sw, "p-") == 0) {
        opts->path_mode = 0; return 0;
    }
    if (strcmp(sw, "pr") == 0) {
        opts->path_mode = 1; return 0;
    }
    if (strcmp(sw, "pf") == 0) {
        opts->path_mode = 2; return 0;
    }
    if (strcmp(sw, "pe") == 0) {
        opts->path_mode = 3; return 0;
    }
    if (strcmp(sw, "op") == 0) {
        opts->overwrite_mode = 0; return 0;
    }
    if (strcmp(sw, "o+") == 0 || strcmp(sw, "o") == 0) {
        opts->overwrite_mode = 1; return 0;
    }
    if (strcmp(sw, "o-") == 0) {
        opts->overwrite_mode = 2; return 0;
    }
    if (sw[0] == 't') {
        strncpy(opts->target_dir, sw + 1, sizeof(opts->target_dir) - 1);
        return 0;
    }
    if (strcmp(sw, "y+") == 0 || strcmp(sw, "y") == 0 || strcmp(sw, "yes") == 0) {
        opts->assume_yes = 1; return 0;
    }
    if (strcmp(sw, "y-") == 0) {
        opts->assume_yes = 0; return 0;
    }
    if (strcmp(sw, "ac+") == 0 || strcmp(sw, "ac") == 0) {
        opts->clear_archive_attr = 1; return 0;
    }
    if (strcmp(sw, "ac-") == 0) {
        opts->clear_archive_attr = 0; return 0;
    }
    if (strncmp(sw, "ae", 2) == 0) {
        strncpy(opts->ae_mask, sw + 2, sizeof(opts->ae_mask) - 1);
        return 0;
    }
    if (strcmp(sw, "bpb+") == 0 || strcmp(sw, "bpb") == 0) {
        opts->bpb_mode = 1; return 0;
    }
    if (strcmp(sw, "bpb-") == 0) {
        opts->bpb_mode = 0; return 0;
    }
    if (sw[0] == 'b' && isdigit((unsigned char)sw[1])) {
        opts->buffer_kb = atoi(sw + 1);
        if (opts->buffer_kb < 50) opts->buffer_kb = 50;
        return 0;
    }
    if (strcmp(sw, "d0") == 0) {
        opts->display_mode = 0; return 0;
    }
    if (strcmp(sw, "d1") == 0) {
        opts->display_mode = 1; return 0;
    }
    if (strcmp(sw, "d2") == 0) {
        opts->display_mode = 2; return 0;
    }
    if (strcmp(sw, "ed+") == 0 || strcmp(sw, "ed") == 0) {
        opts->empty_dirs = 1; return 0;
    }
    if (strcmp(sw, "ed-") == 0) {
        opts->empty_dirs = 0; return 0;
    }
    if (strcmp(sw, "idle") == 0) {
        opts->idle_priority = 1; return 0;
    }
    if (strncmp(sw, "lg", 2) == 0) {
        strncpy(opts->log_file, sw + 2, sizeof(opts->log_file) - 1);
        return 0;
    }
    if (strcmp(sw, "px") == 0) {
        opts->pause_exit = 1; return 0;
    }
    if (strcmp(sw, "r+") == 0 || strcmp(sw, "r") == 0) {
        opts->recurse = 1; return 0;
    }
    if (strcmp(sw, "r-") == 0) {
        opts->recurse = 0; return 0;
    }
    if (strncmp(sw, "sfx", 3) == 0) {
        opts->sfx = 1;
        if (sw[3])
            strncpy(opts->sfx_stub, sw + 3, sizeof(opts->sfx_stub) - 1);
        return 0;
    }
    if (strcmp(sw, "vm+") == 0 || strcmp(sw, "vm") == 0) {
        opts->vm_mode = 1; return 0;
    }
    if (strcmp(sw, "vm-") == 0) {
        opts->vm_mode = 0; return 0;
    }
    if (sw[0] == '@') {
        opts->list_char = sw[1];
        return 0;
    }
    if (sw[0] == '!') {
        opts->excl_char = sw[1];
        return 0;
    }
    if (strcmp(sw, "u") == 0 || strcmp(sw, "-unix") == 0) {
        opts->unix_paths = 1; return 0;
    }
    if (strcmp(sw, "1") == 0 || strcmp(sw, "-bare") == 0) {
        opts->bare_list = 1; return 0;
    }

    uha_msg(0, "\nERROR: Invalid switch \"%s\"\n\nProcess aborted.\n", arg);
    return -1;
}

/* --------------------------------------------------------------------------
 * Main Entry Point
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

    uha_cli_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.display_mode = 1;
    opts.method = 1;
    opts.alz_class = 1;
    opts.ph_mode = 1;
    opts.path_mode = -1; /* default: canonical / basename */
    opts.buffer_kb = 1024;
    opts.list_char = '@';
    opts.excl_char = '!';
    strcpy(opts.target_dir, ".");

    /* Parse UHARC_OPT environment variable */
    const char *env_opt = getenv("UHARC_OPT");
    if (env_opt && *env_opt) {
        int e_argc = 0;
        char **e_argv = NULL;
        tokenize_options(env_opt, &e_argc, &e_argv);
        for (int i = 0; i < e_argc; i++) {
            if (e_argv[i][0] == '-' || e_argv[i][0] == '/') {
                if (parse_switch_arg(e_argv[i], &opts) < 0) {
                    for (int j = 0; j < e_argc; j++) free(e_argv[j]);
                    free(e_argv);
                    return 255;
                }
            }
        }
        for (int j = 0; j < e_argc; j++) free(e_argv[j]);
        free(e_argv);
    }

    /* Command */
    int start_arg = 2;
    char cmd = 0;

    if (strcmp(argv[1], "-1") == 0 || strcmp(argv[1], "--bare") == 0) {
        cmd = 'l';
        opts.bare_list = 1;
        start_arg = 2;
    } else {
        if (strlen(argv[1]) != 1 || !strchr("amxelvth", tolower((unsigned char)argv[1][0]))) {
            print_banner();
            uha_msg(0, "ERROR: Invalid command \"%s\"\n\nProcess aborted.\n", argv[1]);
            return 255;
        }
        cmd = (char)tolower((unsigned char)argv[1][0]);
    }

    /* Parse argv switches and arguments */
    const char *arc_raw = NULL;
    char **pos_args = (char **)calloc((size_t)argc, sizeof(char *));
    int n_pos = 0;
    int stop_switches = 0;

    for (int a = start_arg; a < argc; a++) {
        const char *arg = argv[a];
        int is_sw = 0;
        if (!stop_switches) {
            if (arg[0] == '-')
                is_sw = 1;
            else if (arg[0] == '/' && !strchr(arg + 1, '/'))
                is_sw = 1;
        }

        if (is_sw) {
            if (strcmp(arg, "-t") == 0 || strcmp(arg, "/t") == 0) {
                if (a + 1 < argc) {
                    strncpy(opts.target_dir, argv[++a], sizeof(opts.target_dir) - 1);
                    continue;
                }
            } else if (strcmp(arg, "-lg") == 0 || strcmp(arg, "/lg") == 0) {
                if (a + 1 < argc) {
                    strncpy(opts.log_file, argv[++a], sizeof(opts.log_file) - 1);
                    continue;
                }
            }
            int prc = parse_switch_arg(arg, &opts);
            if (prc == 100) {
                stop_switches = 1;
            } else if (prc < 0) {
                free(pos_args);
                return 255;
            }
        } else {
            if (!arc_raw)
                arc_raw = arg;
            else
                pos_args[n_pos++] = (char *)arg;
        }
    }

    if (!arc_raw) {
        print_banner();
        uha_msg(0, "ERROR: No archive specified\n\nProcess aborted.\n");
        free(pos_args);
        return 255;
    }

    /* Apply global display mode and logging */
    g_display_mode = opts.display_mode;
    if (opts.log_file[0]) {
        char full_cmd[2048] = "";
        for (int i = 0; i < argc; i++) {
            if (i > 0) strncat(full_cmd, " ", sizeof(full_cmd) - strlen(full_cmd) - 1);
            strncat(full_cmd, argv[i], sizeof(full_cmd) - strlen(full_cmd) - 1);
        }
        log_open(opts.log_file, full_cmd, env_opt);
    }

    /* Apply process priority */
    if (opts.idle_priority)
        set_idle_priority();

    /* Apply compression tuning settings */
    if (opts.have_md)
        uha_set_dict_kb(opts.dict_kb);
    if (opts.nomm >= 0)
        uha_set_nomm(opts.nomm);
    if (opts.recurse && opts.path_mode < 0)
        opts.path_mode = 1;
    uha_set_path_mode(opts.path_mode);

    /* Normalize archive name */
    char arc_path[1024];
    int is_create = (cmd == 'a' || cmd == 'm');
    normalize_archive_name(arc_raw, arc_path, sizeof(arc_path), opts.sfx, is_create);

    /* Handle password interactive query if needed */
    if (opts.have_pw == 2) {
        if (read_password_interactive(opts.password, sizeof(opts.password)) != 0) {
            free(pos_args);
            log_close();
            if (opts.pause_exit) pause_exit();
            return 255;
        }
        opts.have_pw = 1;
    }

    const char *pw_arg = opts.have_pw ? opts.password : NULL;
    int res = 0;

    switch (cmd) {
    case 'a':
        res = cmd_add(arc_path, n_pos, pos_args, opts.method, opts.alz_class, 0,
                      opts.recurse, opts.empty_dirs, opts.ae_mask,
                      opts.list_char, opts.excl_char, opts.path_mode,
                      opts.overwrite_mode, opts.assume_yes,
                      opts.clear_archive_attr, opts.sfx, opts.sfx_stub,
                      pw_arg, opts.ph_mode, opts.buffer_kb);
        break;

    case 'm':
        res = cmd_add(arc_path, n_pos, pos_args, opts.method, opts.alz_class, 1,
                      opts.recurse, opts.empty_dirs, opts.ae_mask,
                      opts.list_char, opts.excl_char, opts.path_mode,
                      opts.overwrite_mode, opts.assume_yes,
                      opts.clear_archive_attr, opts.sfx, opts.sfx_stub,
                      pw_arg, opts.ph_mode, opts.buffer_kb);
        break;

    case 'x':
        res = cmd_extract(arc_path, opts.target_dir, pw_arg, 0, opts.unix_paths,
                          opts.overwrite_mode, opts.assume_yes,
                          n_pos, pos_args);
        break;

    case 'e':
        res = cmd_extract(arc_path, opts.target_dir, pw_arg, 1, opts.unix_paths,
                          opts.overwrite_mode, opts.assume_yes,
                          n_pos, pos_args);
        break;

    case 'l':
        res = cmd_list(arc_path, pw_arg, (opts.display_mode == 2), opts.unix_paths,
                       opts.bare_list, opts.bpb_mode, n_pos, pos_args,
                       opts.assume_yes);
        break;

    case 't':
        res = cmd_test(arc_path, pw_arg);
        break;

    default:
        uha_msg(0, "ERROR: Invalid command \"%c\"\n\nProcess aborted.\n", cmd);
        res = 255;
        break;
    }

    free(pos_args);
    log_close();
    if (opts.pause_exit)
        pause_exit();
    return res;
}
