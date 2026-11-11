/*
 * alz_arena2d.h — couche (2) du scoreur delta-2D ALZ : l'ARÈNE ADAPTATIVE de fréquences
 * (portage fidèle UHARC 0.6b). Voir UHARC_RE_REPORT.md §13.82..89 (structure), §13.90 (règle
 * VALIDÉE pos-à-pos 80/80 contre le ground-truth legacy).
 *
 * RÔLE. Le scoreur legacy, À CHAQUE POSITION, évalue le coût d'un symbole delta via un modèle
 * adaptatif à plat (distinct du hash de SÉLECTEUR alz_cm, qui fournit la « ligne »/contexte) :
 *     ctx        = (relrow << 8) | delta            (relrow = row - base de bloc ; delta canalisé)
 *     freq[ctx]  : u16, initialisé à 0
 *     total[row] : u16, initialisé à 1
 *     counter[row]: u16, initialisé à 1  (sert de numérateur sur le chemin COLD ; pilote le halving)
 *     inc        : u16 promo[row]  (= 32 observé pour les lignes de image.raw)
 *   Chemin COLD (freq[ctx]==0, 1re fois que ce ctx apparaît dans cette ligne) :
 *     num = counter[row] ; freq[ctx] = inc ; counter[row] += inc ; total[row] += 2*inc
 *   Chemin WARM :
 *     num = freq[ctx] ; freq[ctx] += inc ; total[row] += inc
 *   proba = (num << 14) / total(row AVANT mise à jour) ;  cost = alz_score_cost-style = LUT[proba]
 *   Si total[row] >= 0x4000 : RESCALE (§13.84, halversic vers pair ; voir .c).
 *
 * STATUT : SPÉCIFIÉ, TESTÉ (self-test rejoue le GT legacy 80 positions, attend 80/80), NON-WIRED
 * (aucun effet sur l'encodage standard). Le câblage comme critère LIT-vs-match + le cumul
 * multi-ordres (0x45cb60) + argmin (0x413ea0) + porte-budget (§13.78) restent à faire (d7b/d8).
 */
#ifndef ALZ_ARENA2D_H
#define ALZ_ARENA2D_H

#include <stdint.h>

/* Dimensions de l'arène. relrow = index de ligne relatif (row - base). delta in [0,256).
 * 512 lignes relatives x 256 deltas = 131072 compteurs freq (u16) ; total/counter 512. */
#define ALZ_ARENA2D_MAX_ROW   512u
#define ALZ_ARENA2D_MAX_CTX   (ALZ_ARENA2D_MAX_ROW * 256u)
#define ALZ_ARENA2D_RESCALE   0x4000u   /* 16384 : seuil de halving (0x4000, §13.83/84). */
#define ALZ_ARENA2D_INIT_VAL   1u        /* init de total[row] et counter[row] (GT §13.90). */

typedef struct alz_arena2d {
    uint16_t freq[ALZ_ARENA2D_MAX_CTX];   /* par ctx (relrow<<8|delta)   */
    uint16_t total[ALZ_ARENA2D_MAX_ROW];  /* par ligne relative          */
    uint16_t counter[ALZ_ARENA2D_MAX_ROW];/* compteur secondaire par ligne */
    uint16_t promo[ALZ_ARENA2D_MAX_ROW];  /* inc par ligne (0x45e4c0)     */
    /* [C6-ter aging — GATED via aging_on, défaut-OFF] budget de rescale maître (0x45cc94,
     * DWORD signé) + master_total (0x4373d4) par ligne. Utilisé UNIQUEMENT par
     * alz_arena2d_master_learn quand aging_on=1. Init : aging=256 (0x100, cold C6-ter c),
     * mtot=0. Zéro effet ailleurs (hot/score ignorent ces champs). */
    uint32_t aging[ALZ_ARENA2D_MAX_ROW];
    uint32_t mtot[ALZ_ARENA2D_MAX_ROW];
    int      aging_on;
} alz_arena2d_t;

/* (Ré)initialise l'arène : freq=0 ; total=counter=INIT_VAL ; promo=default_inc (32 observé). */
void alz_arena2d_init(alz_arena2d_t *a, uint16_t default_inc);

/* Fixe l'incrément (promotion) d'une ligne (u16[0x45e4c0 + 2*row] du legacy). */
void alz_arena2d_set_inc(alz_arena2d_t *a, uint32_t relrow, uint16_t inc);

/*
 * Score une position (relrow, delta) : renvoie la proba 14 bits (num<<14/total) et, si p_total
 * != NULL, y écrit le total[row] utilisé (AVANT mise à jour). Met à jour freq/counter/total
 * (chemin cold/warm) et déclenche le rescale si total >= 0x4000. C'est l'opération atomique du
 * scoreur legacy (0x415444..0x41563b), validée GT 80/80 (§13.90).
 */
uint32_t alz_arena2d_score(alz_arena2d_t *a, uint32_t relrow, uint32_t delta, uint32_t *p_total);

/* Coût 16-bit correspondant = LUT[proba] (délégation à la LUT alz_score déjà validée). */
uint32_t alz_arena2d_cost(alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Accesseur PUR (lecture seule, aucun effet de bord) : freq[relrow<<8|delta] courante.
 * Sert à detecter un symbole FROID (==0, jamais vu) sans muter l'arène. */
uint32_t alz_arena2d_freq(const alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Rescale d'une ligne (halving vers pair, §13.84). Exposée pour le self-test. */
void alz_arena2d_rescale(alz_arena2d_t *a, uint32_t relrow);

/* Rescale MAÎTRE (0x40ffa0/0x4100b1, §13.727) : loi DISTINCTE du working 0x414590.
 * pour chaque des 256 colonnes : f>16 → f>>=1 ; sinon f=0. total = Σ f (SANS counter).
 * (Rebuild arbre Fenwick [0x4373c8] non modélisé ici — hors portée du score.) */
void alz_arena2d_rescale_master(alz_arena2d_t *a, uint32_t relrow);

/* Learn d'émission maître (0x4111a0 core, §13.727) : même règle cold/warm que score
 * (isolant leffet de la loi de rescale), mais rescale MAÎTRE. Reconstruit master@bloc1. */
uint32_t alz_arena2d_master_learn(alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Self-test : rejoue le ground-truth legacy (image.raw, 80 positions) et vérifie proba+total.
 * Renvoie 0 si 80/80, sinon le nombre de divergences. Gated par env UHA_ARENATEST dans uha_c. */
int alz_arena2d_selftest(void);

#endif /* ALZ_ARENA2D_H */
