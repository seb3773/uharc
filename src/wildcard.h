#ifndef UHA_WILDCARD_H
#define UHA_WILDCARD_H

#include <stddef.h>
#include <stdint.h>

/* DOS-compatible wildcard matching (*, ?). Case-insensitive. */
int uha_wildcard_match(const char *pattern, const char *text);

/* Check if string contains wildcard characters (* or ?). */
int uha_has_wildcard(const char *pattern);

/* Check if a filename matches any of the positive masks and NONE of the exclude masks. */
int uha_matches_masks(const char *filename,
                      char **patterns, int num_patterns,
                      char **excludes, int num_excludes);

/* Structure for collected file paths */
typedef struct {
    char **items;
    int    count;
    int    cap;
} uha_file_list;

void uha_file_list_init(uha_file_list *fl);
void uha_file_list_add(uha_file_list *fl, const char *path);
void uha_file_list_free(uha_file_list *fl);

/* Parse @listfile with custom list specifier and 4095 chars max per line. */
int uha_read_listfile(const char *listfile_path, uha_file_list *fl);

/* Get MS-DOS attributes for path */
uint8_t uha_get_file_dos_attr(const char *path);

/* Check file against attribute exclusion mask (-ae). Returns 1 if excluded, 0 if kept. */
int uha_attr_excluded(const char *path, uint8_t dos_attr, const char *ae_mask);

/*
 * Collect files matching input patterns, with recursion (-r), empty dirs (-ed),
 * attribute exclusions (-ae), and exclude patterns (!...).
 */
typedef struct {
    int         recurse;         /* -r[-,+] */
    int         empty_dirs;      /* -ed[-,+] */
    const char *ae_mask;         /* -ae<attr> */
    char      **excludes;        /* !exclude patterns */
    int         num_excludes;
    char        list_spec;       /* default '@', '\0' if disabled */
    char        exclude_spec;    /* default '!', '\0' if disabled */
} uha_scan_options;

int uha_collect_files(int argc_files, char **argv_files,
                      const uha_scan_options *opts,
                      uha_file_list *out_disk_paths,
                      uha_file_list *out_arc_names,
                      int path_mode); /* 0=-p-, 1=-pr, 2=-pf, 3=-pe */

#endif /* UHA_WILDCARD_H */
