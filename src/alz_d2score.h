#ifndef ALZ_D2SCORE_H
#define ALZ_D2SCORE_H

#include <stdint.h>

/*
 * alz_d2score — Scorer delta-2D 5-classes du legacy UHARC ALZ (B-plein).
 *
 * Reproduit le geste de l'argmin par-position (0x413ea0) qui sélectionne
 * dynamiquement la meilleure classe de contexte (parmi 5) pour chaque octet.
 * Chaque classe maintient une arène freq[row][delta] auto-entraînée.
 * Le coût par classe = Σ cum[(freq≪14)/total] (table alz_score_cum / 0x43f154).
 *
 * Gated par env UHA_D2SCORER, NON-WIRED par défaut.
 * §13.69/70 : cause racine du +47 = écart qualité prédictive side model.
 */

#define D2_ROWS       4096u
#define D2_COLS       256u
#define D2_NCLASS     5
#define D2_UPDATE     0x20u     /* incrément promo (32, GT arena2d §13.90) */
#define D2_RESCALE    0x4000u
#define D2_INIT_VAL   1u        /* init total[row] et counter[row] (arena2d GT) */
/* Snapshot cold du scoreur (mémoire 8e2332f6) : graines fraîches num/total=(2,512)
 * → proba64 → LUT[64]=0x9240 universel cls0..4 au BLOC 1. Le coût COLD du legacy est
 * DOUBLE-TERME : LUT[(2≪14)/512] + LUT[(counter[row]≪14)/total[row]]. */
#define D2_SNAP_NUM   2u
#define D2_SNAP_TOTAL 512u

/* Arène par classe : freq[ROWS×COLS] + total[ROWS] + counter[ROWS] (miroir arena2d). */
typedef struct {
    uint16_t freq[D2_ROWS * D2_COLS];
    uint16_t total[D2_ROWS];
    uint16_t counter[D2_ROWS];      /* numérateur cold + pilote halving (arena2d validé) */
} d2_arena;

/* État complet du scorer 5-classes (alloué sur tas via d2_scorer_create). */
typedef struct {
    d2_arena  *arena;           /* [D2_NCLASS] alloués dynamiquement */
    /* Records de contexte par classe (poids, history, base). */
    int32_t    w[D2_NCLASS][5];        /* poids w0..w4 */
    uint32_t   h[D2_NCLASS][4];        /* history h0..h3 */
    uint32_t   base[D2_NCLASS];        /* base octet */
    uint32_t   counter[D2_NCLASS];     /* compteur pour min-scan périodique */
} d2_scorer;

/* Fabrique/destroy (allocation tas des arenas). */
d2_scorer *d2_scorer_create(void);
void d2_scorer_destroy(d2_scorer *s);

/* Init : zero-fill + création arenas (pour usage statique/stack léger). */
void d2_scorer_init(d2_scorer *s);

/* Avance une classe : rotation history + hash → row. */
uint32_t d2_advance_class(d2_scorer *s, int cls, uint32_t base_octet, int32_t delta);

/* Scoring : évalue le coût cumulé de [start,end) pour une classe donnée,
 * avec snapshot/self-training/restore. Retourne le coût total (uint64). */
uint64_t d2_score_run(d2_scorer *s, int cls, const uint8_t *plain,
                      uint32_t start, uint32_t end);

/* Argmin : pour la position pos (byte courant), renvoie l'index de classe
 * minimale et met à jour l'arène du gagnant (training persistant). */
int d2_argmin_update(d2_scorer *s, const uint8_t *plain, uint32_t usize, uint32_t pos);

/* Retourne le side_bias prédit par la classe gagnante (octet prévu). */
uint8_t d2_predict(const d2_scorer *s, int cls, uint32_t row, uint32_t delta);

/* Self-test. Retourne 0 = OK. */
int d2_scorer_selftest(void);

/* [A5.3-d, GATED UHA_COSTDUMP, lecture seule, NON-WIRED] Validation du portage
 * de l'arène CM 2D-delta adaptative : rejoue l'argmin 5-classes sur le plaintext
 * (bloc 1 = plain[0..npos)) et compare le COÛT PAR OCTET du gagnant au coût
 * legacy reconstruit depuis la table de coût cumulé GT (deltas de 0x45cb60[p]).
 * gt_path = recherche/gt_scorer/image_raw_block1_costtable.txt (u16 espacés).
 * Retourne 0 ; n'affecte PAS l'encodage. */
int d2_costdump_validate(const char *plain_path, const char *gt_path,
                         uint32_t npos);

/* [A5.3-f, GATED UHA_PSCOST, lecture seule, NON-WIRED] Validation class-wise : pour
 * CHAQUE classe 0..4, produit le coût par position sur la LIGNE VALIDÉE (via
 * alz_ps_class_sigma, machine ctx §13.132 + cold double-terme) et le compare aux deltas
 * legacy reconstruits de la GT `0x45cb60[p]`. Identifie quelle classe colle au GT (le
 * gagnant argmin par-bloc de image.raw est cls3). Retourne 0 ; n'affecte PAS l'encodage. */
int d2_costdump_ps(const char *plain_path, const char *gt_path, uint32_t npos);

/* [A5.3-g, GATED UHA_PSCOST2] Comparateur au VRAI flux coût-par-octet : parse le log
 * 0x414985 (cols `0x414985 pos A B C D cum`), en dérive le coût par octet (diffs de cum),
 * et le diff au percost de CHAQUE classe (ligne validée alz_ps_class_sigma) pour identifier
 * la classe scorée ET mesurer l'accord % propre (l'ancien `exact` était faussé par la
 * reconstruction par deltas d'une mauvaise table). Retourne 0 ; non-wired. */
int d2_costdump_ps2(const char *plain_path, const char *pcost_log, uint32_t npos);

/* [A5.3-h, GATED UHA_PSDUMP, lecture seule, NON-WIRED] Dump du coût LITTÉRAL fidèle par
 * position (les 5 classes, ligne validée §13.132 + cold double-terme) sur plain[0..n),
 * plus la classe gagnante (block_argmin), écrit en TSV (pos, byte, c0..c4, winner).
 * Sert à valider HORS-LIGNE la règle LIT-vs-MATCH contre la trace oracle. Retourne 0. */
int d2_costdump_dump(const char *plain_path, const char *out_path, uint32_t n);

#endif /* ALZ_D2SCORE_H */
