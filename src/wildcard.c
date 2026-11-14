#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "wildcard.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

int uha_has_wildcard(const char *pattern)
{
    if (!pattern)
        return 0;
    return (strchr(pattern, '*') != NULL || strchr(pattern, '?') != NULL);
}

static int char_match(char p, char s)
{
    if (p == '/' || p == '\\')
        return (s == '/' || s == '\\');
    return tolower((unsigned char)p) == tolower((unsigned char)s);
}

int uha_wildcard_match(const char *pat, const char *str)
{
    if (!pat || !str)
        return 0;
    if (strcmp(pat, "*") == 0)
        return 1;

    const char *p = pat;
    const char *s = str;
    const char *star = NULL;
    const char *ss = s;

    while (*s) {
        if (*p == '?') {
            if (*s == '/' || *s == '\\') {
                if (star) {
                    p = star + 1;
                    s = ++ss;
                    continue;
                }
                return 0;
            }
            p++;
            s++;
        } else if (*p == '*') {
            star = p++;
            ss = s;
        } else if (char_match(*p, *s)) {
            p++;
            s++;
        } else if (star) {
            p = star + 1;
            s = ++ss;
        } else {
            return 0;
        }
    }

    while (*p == '*')
        p++;
    return (*p == '\0');
}

int uha_matches_masks(const char *filename,
                      char **patterns, int num_patterns,
                      char **excludes, int num_excludes)
{
    int i;
    const char *bn = filename;
    const char *q;

    if (!filename)
        return 0;

    for (q = filename; *q; q++) {
        if (*q == '/' || *q == '\\')
            bn = q + 1;
    }

    /* Check exclude masks first: if any exclude matches, reject */
    if (excludes && num_excludes > 0) {
        for (i = 0; i < num_excludes; i++) {
            const char *ex = excludes[i];
            if (!ex || !*ex)
                continue;
            if (uha_wildcard_match(ex, filename) || uha_wildcard_match(ex, bn))
                return 0;
        }
    }

    /* Check inclusion patterns: if no patterns given, default match */
    if (!patterns || num_patterns <= 0)
        return 1;

    for (i = 0; i < num_patterns; i++) {
        const char *pat = patterns[i];
        if (!pat || !*pat)
            continue;
        if (uha_wildcard_match(pat, filename) || uha_wildcard_match(pat, bn))
            return 1;
    }

    return 0;
}

void uha_file_list_init(uha_file_list *fl)
{
    if (!fl)
        return;
    fl->items = NULL;
    fl->count = 0;
    fl->cap = 0;
}

void uha_file_list_add(uha_file_list *fl, const char *path)
{
    if (!fl || !path)
        return;
    if (fl->count >= fl->cap) {
        int nc = fl->cap ? fl->cap * 2 : 16;
        char **p = (char **)realloc(fl->items, (size_t)nc * sizeof(char *));
        if (!p)
            return;
        fl->items = p;
        fl->cap = nc;
    }
#if defined(_WIN32)
    fl->items[fl->count++] = _strdup(path);
#else
    fl->items[fl->count++] = strdup(path);
#endif
}

void uha_file_list_free(uha_file_list *fl)
{
    int i;
    if (!fl)
        return;
    for (i = 0; i < fl->count; i++)
        free(fl->items[i]);
    free(fl->items);
    fl->items = NULL;
    fl->count = 0;
    fl->cap = 0;
}

int uha_read_listfile(const char *listfile_path, uha_file_list *fl)
{
    FILE *fp;
    char line[4096];

    if (!listfile_path || !fl)
        return -1;

    fp = fopen(listfile_path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p) {
            /* Skip whitespace */
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!*p)
                break;

            char token[4096];
            int ti = 0;
            if (*p == '"') {
                p++; /* skip opening quote */
                while (*p && *p != '"' && *p != '\r' && *p != '\n' && ti < (int)sizeof(token) - 1)
                    token[ti++] = *p++;
                if (*p == '"')
                    p++;
            } else {
                while (*p && !isspace((unsigned char)*p) && ti < (int)sizeof(token) - 1)
                    token[ti++] = *p++;
            }
            token[ti] = '\0';
            if (ti > 0)
                uha_file_list_add(fl, token);
        }
    }

    fclose(fp);
    return 0;
}

uint8_t uha_get_file_dos_attr(const char *path)
{
#if defined(_WIN32)
    DWORD a = GetFileAttributesA(path);
    if (a == INVALID_FILE_ATTRIBUTES)
        return 0x20;
    uint8_t attr = 0;
    if (a & FILE_ATTRIBUTE_READONLY)  attr |= 0x01;
    if (a & FILE_ATTRIBUTE_HIDDEN)    attr |= 0x02;
    if (a & FILE_ATTRIBUTE_SYSTEM)    attr |= 0x04;
    if (a & FILE_ATTRIBUTE_DIRECTORY) attr |= 0x10;
    if (a & FILE_ATTRIBUTE_ARCHIVE)   attr |= 0x20;
    return attr;
#else
    struct stat st;
    if (stat(path, &st) != 0)
        return 0x20;
    uint8_t attr = 0x20; /* default archive */
    if (S_ISDIR(st.st_mode))
        attr |= 0x10;
    if (!(st.st_mode & S_IWUSR))
        attr |= 0x01; /* read-only */
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    if (bn[0] == '.' && bn[1] != '\0')
        attr |= 0x02; /* hidden */
    return attr;
#endif
}

int uha_attr_excluded(const char *path, uint8_t dos_attr, const char *ae_mask)
{
    (void)path;
    if (!ae_mask || !*ae_mask)
        return 0;
    const char *p = ae_mask;
    while (*p) {
        char attr_char = (char)toupper((unsigned char)*p++);
        char sign = '+';
        if (*p == '+' || *p == '-')
            sign = *p++;
        uint8_t bit = 0;
        if (attr_char == 'A') bit = 0x20;
        else if (attr_char == 'H') bit = 0x02;
        else if (attr_char == 'R') bit = 0x01;
        else if (attr_char == 'S') bit = 0x04;
        if (bit != 0) {
            if (sign == '+' && (dos_attr & bit))
                return 1;
            if (sign == '-' && !(dos_attr & bit))
                return 1;
        }
    }
    return 0;
}

static void make_arc_name(const char *disk_path, const char *prefix_to_strip,
                          int path_mode, char *out_name, size_t out_sz)
{
    if (path_mode <= 0) {
        /* -p- or default: basename only */
        const char *bn = disk_path;
        const char *q;
        for (q = disk_path; *q; q++) {
            if (*q == '/' || *q == '\\')
                bn = q + 1;
        }
        snprintf(out_name, out_sz, "%s", bn);
    } else if (path_mode == 2) {
        /* -pf : full path */
#if defined(_WIN32)
        char full[1024];
        if (GetFullPathNameA(disk_path, sizeof(full), full, NULL)) {
            for (char *c = full; *c; c++) if (*c == '\\') *c = '/';
            snprintf(out_name, out_sz, "%s", full);
        } else {
            snprintf(out_name, out_sz, "%s", disk_path);
        }
#else
        char full[PATH_MAX];
        if (realpath(disk_path, full))
            snprintf(out_name, out_sz, "%.*s", (int)(out_sz - 1), full);
        else
            snprintf(out_name, out_sz, "%.*s", (int)(out_sz - 1), disk_path);
#endif
    } else if (path_mode == 3 && prefix_to_strip && *prefix_to_strip) {
        /* -pe : strip prefix */
        size_t plen = strlen(prefix_to_strip);
        if (strncmp(disk_path, prefix_to_strip, plen) == 0) {
            const char *sub = disk_path + plen;
            while (*sub == '/' || *sub == '\\')
                sub++;
            snprintf(out_name, out_sz, "%s", sub);
        } else {
            snprintf(out_name, out_sz, "%s", disk_path);
        }
    } else {
        /* -pr (default): relative path */
        const char *p = disk_path;
        if (p[0] == '.' && (p[1] == '/' || p[1] == '\\'))
            p += 2;
        snprintf(out_name, out_sz, "%s", p);
    }

    /* Normalize all slashes in archive name to / */
    for (char *c = out_name; *c; c++) {
        if (*c == '\\')
            *c = '/';
    }
}

static void scan_dir_recursive(const char *dir_path,
                               const char *pattern,
                               const char *prefix_to_strip,
                               const uha_scan_options *opts,
                               int path_mode,
                               uha_file_list *out_disk,
                               uha_file_list *out_arc)
{
    DIR *d = opendir(dir_path);
    if (!d)
        return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char subpath[1024];
        if (strcmp(dir_path, ".") == 0)
            snprintf(subpath, sizeof(subpath), "%s", ent->d_name);
        else
            snprintf(subpath, sizeof(subpath), "%s/%s", dir_path, ent->d_name);

        uint8_t attr = uha_get_file_dos_attr(subpath);
        int is_dir = (attr & 0x10) != 0;

        if (is_dir) {
            if (opts->recurse) {
                scan_dir_recursive(subpath, pattern, prefix_to_strip, opts, path_mode, out_disk, out_arc);
            }
        } else {
            /* Check if matches pattern */
            if (pattern && *pattern && !uha_wildcard_match(pattern, ent->d_name))
                continue;

            /* Check exclude masks */
            if (!uha_matches_masks(subpath, NULL, 0, opts->excludes, opts->num_excludes))
                continue;

            /* Check attribute mask */
            if (uha_attr_excluded(subpath, attr, opts->ae_mask))
                continue;

            char arc_name[1024];
            make_arc_name(subpath, prefix_to_strip, path_mode, arc_name, sizeof(arc_name));

            uha_file_list_add(out_disk, subpath);
            uha_file_list_add(out_arc, arc_name);
        }
    }
    closedir(d);
}

int uha_collect_files(int argc_files, char **argv_files,
                      const uha_scan_options *opts,
                      uha_file_list *out_disk,
                      uha_file_list *out_arc,
                      int path_mode)
{
    int i;
    uha_file_list raw_inputs;
    uha_file_list_init(&raw_inputs);

    char list_char = opts->list_spec ? opts->list_spec : '@';
    char excl_char = opts->exclude_spec ? opts->exclude_spec : '!';

    /* Collect all raw arguments, expanding @listfiles */
    for (i = 0; i < argc_files; i++) {
        const char *arg = argv_files[i];
        if (opts->list_spec && arg[0] == list_char && arg[1]) {
            uha_read_listfile(arg + 1, &raw_inputs);
        } else {
            uha_file_list_add(&raw_inputs, arg);
        }
    }

    /* Separate positive items from !excludes */
    uha_file_list pos_items;
    uha_file_list_init(&pos_items);

    uha_file_list active_excludes;
    uha_file_list_init(&active_excludes);

    /* Copy inherited excludes */
    if (opts->excludes && opts->num_excludes > 0) {
        for (i = 0; i < opts->num_excludes; i++)
            uha_file_list_add(&active_excludes, opts->excludes[i]);
    }

    for (i = 0; i < raw_inputs.count; i++) {
        const char *item = raw_inputs.items[i];
        if (opts->exclude_spec && item[0] == excl_char && item[1]) {
            uha_file_list_add(&active_excludes, item + 1);
        } else {
            uha_file_list_add(&pos_items, item);
        }
    }

    uha_scan_options local_opts = *opts;
    local_opts.excludes = active_excludes.items;
    local_opts.num_excludes = active_excludes.count;

    if (pos_items.count == 0) {
        /* Default: all files "*.*" */
        scan_dir_recursive(".", NULL, NULL, &local_opts, path_mode, out_disk, out_arc);
    } else {
        for (i = 0; i < pos_items.count; i++) {
            const char *item = pos_items.items[i];
            if (uha_has_wildcard(item)) {
                /* Split directory and pattern */
                char dir_part[1024];
                const char *pat_part = item;
                const char *last_slash = NULL;
                for (const char *q = item; *q; q++) {
                    if (*q == '/' || *q == '\\')
                        last_slash = q;
                }
                if (last_slash) {
                    size_t dlen = (size_t)(last_slash - item);
                    if (dlen >= sizeof(dir_part)) dlen = sizeof(dir_part) - 1;
                    memcpy(dir_part, item, dlen);
                    dir_part[dlen] = '\0';
                    pat_part = last_slash + 1;
                } else {
                    strcpy(dir_part, ".");
                }
                scan_dir_recursive(dir_part, pat_part, (path_mode == 3 ? dir_part : NULL),
                                   &local_opts, path_mode, out_disk, out_arc);
            } else {
                /* Specific path */
                uint8_t attr = uha_get_file_dos_attr(item);
                if (attr & 0x10) {
                    /* Directory */
                    scan_dir_recursive(item, NULL, (path_mode == 3 ? item : NULL),
                                       &local_opts, path_mode, out_disk, out_arc);
                } else {
                    /* File */
                    if (!uha_matches_masks(item, NULL, 0, local_opts.excludes, local_opts.num_excludes))
                        continue;
                    if (uha_attr_excluded(item, attr, local_opts.ae_mask))
                        continue;

                    char arc_name[1024];
                    make_arc_name(item, NULL, path_mode, arc_name, sizeof(arc_name));

                    uha_file_list_add(out_disk, item);
                    uha_file_list_add(out_arc, arc_name);
                }
            }
        }
    }

    uha_file_list_free(&raw_inputs);
    uha_file_list_free(&pos_items);
    uha_file_list_free(&active_excludes);
    return 0;
}
