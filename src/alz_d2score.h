#ifndef ALZ_D2SCORE_H
#define ALZ_D2SCORE_H

#include <stdint.h>

/*
 * alz_d2score - Scorer delta-2D 5-classes of legacy UHARC ALZ (B-full).
 *
 * Reproduces the geste of l'argmin by-position (0x413ea0) which selects
 * dynamiquement there meilleure class of context (among 5) for each byte.
 * each class maintains has arena freq[row][delta] auto-entrainee.
 * The cost by class = Sigma cum[(freq14)/total] (table alz_score_cum / 0x43f154).
 *
 * Gated by env UHA_D2SCORER, NO-WIRED by default.
 * 13.69/70 : cause root of the +47 = gap qualite predictive side model.
 */

#define D2_ROWS       4096u
#define D2_COLS       256u
#define D2_NCLASS     5
#define D2_UPDATE     0x20u     /* increment promo (32, GT arena2d 13.90) */
#define D2_RESCALE    0x4000u
#define D2_INIT_VAL   1u        /* init total[row] and counter[row] (arena2d GT) */
/* Snapshot cold of the scorer (memory 8e2332f6) : seeds fraiches num/total=(2,512)
 * -> proba64 -> LUT[64]=0x9240 universel cls0..4 au block 1. The cost COLD of legacy is
 * DOUBLE-TERM : LUT[(214)/512] + LUT[(counter[row]14)/total[row]]. */
#define D2_SNAP_NUM   2u
#define D2_SNAP_TOTAL 512u

/* arena by class : freq[ROWS*COLS] + total[ROWS] + counter[ROWS] (mirror arena2d). */
typedef struct {
    uint16_t freq[D2_ROWS * D2_COLS];
    uint16_t total[D2_ROWS];
    uint16_t counter[D2_ROWS];      /* numerateur cold + pilote halving (arena2d validated) */
} d2_arena;

/* State complete of the scorer 5-classes (allocates sure heap via d2_scorer_create). */
typedef struct {
    d2_arena  *arena;           /* [D2_NCLASS] alloues dynamiquement */
    /* Records of context by class (weight, history, base). */
    int32_t    w[D2_NCLASS][5];        /* weight w0..w4 */
    uint32_t   h[D2_NCLASS][4];        /* history h0..h3 */
    uint32_t   base[D2_NCLASS];        /* base byte */
    uint32_t   counter[D2_NCLASS];     /* counter for min-scan periodique */
} d2_scorer;

/* Fabrique/destroy (allocation heap some arenas). */
d2_scorer *d2_scorer_create(void);
void d2_scorer_destroy(d2_scorer *s);

/* Init : zero-fill + creation arenas (for usage static/stack leger). */
void d2_scorer_init(d2_scorer *s);

/* Advances has class : rotation history + hash -> row. */
uint32_t d2_advance_class(d2_scorer *s, int cls, uint32_t base_octet, int32_t delta);

/* Scoring : evaluates the cost cumule of [start,end) for has class donnee,
 * with snapshot/self-training/restore. returns the cost total (uint64). */
uint64_t d2_score_run(d2_scorer *s, int cls, const uint8_t *plain,
                      uint32_t start, uint32_t end);

/* Argmin : for there position pos (byte current), returns l'index of class
 * minimale and updates l'arena of the winner (training persistant). */
int d2_argmin_update(d2_scorer *s, const uint8_t *plain, uint32_t usize, uint32_t pos);

/* returns the side_bias predit by there class winning (byte prevu). */
uint8_t d2_predict(const d2_scorer *s, int cls, uint32_t row, uint32_t delta);

/* Self-test. returns 0 = OK. */
int d2_scorer_selftest(void);

/* [A5.3-d, GATED UHA_COSTDUMP, read-only, NO-WIRED] validation of the portage
 * of l'arena CM 2D-delta adaptative : replays l'argmin 5-classes sure the plaintext
 * (block 1 = plain[0..npos)) and compares the cost BY byte of the winner au cost
 * legacy reconstruit since there table of cost cumule GT (deltas of 0x45cb60[p]).
 * gt_path = search/gt_scorer/image_raw_block1_costtable.txt (u16 espaces).
 * returns 0 ; n'affecte NOT l'encoding. */
int d2_costdump_validate(const char *plain_path, const char *gt_path,
                         uint32_t npos);

/* [A5.3-f, GATED UHA_PSCOST, read-only, NO-WIRED] validation class-wise : for
 * each class 0..4, produces the cost by position sure there line validated (via
 * alz_ps_class_sigma, machine ctx 13.132 + cold double-term) and the compares to the deltas
 * legacy reconstruits of the GT `0x45cb60[p]`. Identifie which class matches au GT (the
 * winner argmin by-block of image.raw is cls3). returns 0 ; n'affecte NOT l'encoding. */
int d2_costdump_ps(const char *plain_path, const char *gt_path, uint32_t npos);

/* [A5.3-g, GATED UHA_PSCOST2] Comparateur au TRUE stream cost-by-byte : parse the log
 * 0x414985 (cols `0x414985 pos Has B C D cum`), en drifts the cost by byte (diffs of cum),
 * and the diff au percost of each class (line validated alz_ps_class_sigma) for identifier
 * there class scoree AND to measure l'match % clean (l'old `exact` was false by there
 * reconstruction by deltas of has mauvaise table). returns 0 ; no-wired. */
int d2_costdump_ps2(const char *plain_path, const char *pcost_log, uint32_t npos);

/* [A5.3-h, GATED UHA_PSDUMP, read-only, NO-WIRED] Dump of the cost LITERAL faithful by
 * position (the 5 classes, line validated 13.132 + cold double-term) sure plain[0..n),
 * more there class winning (block_argmin), writes en TSV (pos, byte, c0..c4, winner).
 * Sert has to validate OUT-line there rule READS-vs-MATCH contre there trace oracle. returns 0. */
int d2_costdump_dump(const char *plain_path, const char *out_path, uint32_t n);

#endif /* ALZ_D2SCORE_H */
