/*
 * alz_arena2d.h - layer (2) of the scorer delta-2D ALZ : l'arena ADAPTATIVE of frequencies
 * (faithful port UHARC 0.6b). Voir UHARC_RE_REPORT.md 13.82..89 (structure), 13.90 (rule
 * validated pos-has-pos 80/80 contre the ground-truth legacy).
 *
 * ROLE. The scorer legacy, at each position, evaluates the cost of has symbole delta via has model
 * adaptatif has plat (distinct of the hash of SELECTEUR alz_cm, which fournit there " line "/context) :
 *     ctx        = (relrow << 8) | delta            (relrow = row - base of block ; delta canalise)
 *     freq[ctx]  : u16, initialise has 0
 *     total[row] : u16, initialise has 1
 *     counter[row]: u16, initialise has 1  (sert of numerateur sure the path COLD ; pilote the halving)
 *     inc        : u16 promo[row]  (= 32 observe for the lines of image.raw)
 *   path COLD (freq[ctx]==0, 1re fois that this ctx apparait in this line) :
 *     num = counter[row] ; freq[ctx] = inc ; counter[row] += inc ; total[row] += 2*inc
 *   path WARM :
 *     num = freq[ctx] ; freq[ctx] += inc ; total[row] += inc
 *   proba = (num << 14) / total(row BEFORE update) ;  cost = alz_score_cost-style = LUT[proba]
 *   if total[row] >= 0x4000 : RESCALE (13.84, halversic towards pair ; voir .c).
 *
 * STATUT : SPECIFIE, TESTE (self-test replays the GT legacy 80 positions, attend 80/80), NO-WIRED
 * (no effect on l'encoding standard). The cablage as critere READS-vs-match + the cumul
 * multi-orders (0x45cb60) + argmin (0x413ea0) + porte-budget (13.78) restent has to do (d7b/d8).
 */
#ifndef ALZ_ARENA2D_H
#define ALZ_ARENA2D_H

#include <stdint.h>

/* Dimensions of l'arena. relrow = index of line relatif (row - base). delta in [0,256).
 * 512 lines relatives x 256 deltas = 131072 counters freq (u16) ; total/counter 512. */
#define ALZ_ARENA2D_MAX_ROW   512u
#define ALZ_ARENA2D_MAX_CTX   (ALZ_ARENA2D_MAX_ROW * 256u)
#define ALZ_ARENA2D_RESCALE   0x4000u   /* 16384 : threshold of halving (0x4000, 13.83/84). */
#define ALZ_ARENA2D_INIT_VAL   1u        /* init of total[row] and counter[row] (GT 13.90). */

typedef struct alz_arena2d {
    uint16_t freq[ALZ_ARENA2D_MAX_CTX];   /* by ctx (relrow<<8|delta)   */
    uint16_t total[ALZ_ARENA2D_MAX_ROW];  /* by line relative          */
    uint16_t counter[ALZ_ARENA2D_MAX_ROW];/* counter secondaire by line */
    uint16_t promo[ALZ_ARENA2D_MAX_ROW];  /* inc by line (0x45e4c0)     */
    /* [C6-ter aging - GATED via aging_on, default-OFF] budget of rescale master (0x45cc94,
     * DWORD signe) + master_total (0x4373d4) by line. Uses ONLY by
     * alz_arena2d_master_learn when aging_on=1. Init : aging=256 (0x100, cold C6-ter c),
     * mtot=0. Zero effet ailleurs (hot/score ignores these fields). */
    uint32_t aging[ALZ_ARENA2D_MAX_ROW];
    uint32_t mtot[ALZ_ARENA2D_MAX_ROW];
    int      aging_on;
} alz_arena2d_t;

/* (Re)initialise l'arena : freq=0 ; total=counter=INIT_VAL ; promo=default_inc (32 observe). */
void alz_arena2d_init(alz_arena2d_t *a, uint16_t default_inc);

/* Fixe l'increment (promotion) of has line (u16[0x45e4c0 + 2*row] of legacy). */
void alz_arena2d_set_inc(alz_arena2d_t *a, uint32_t relrow, uint16_t inc);

/*
 * Score has position (relrow, delta) : returns there proba 14 bits (num<<14/total) and, if p_total
 * != NULL, y writes the total[row] uses (BEFORE update). updates freq/counter/total
 * (path cold/warm) and triggers the rescale if total >= 0x4000. C'is l'operation atomique of the
 * scorer legacy (0x415444..0x41563b), validated GT 80/80 (13.90).
 */
uint32_t alz_arena2d_score(alz_arena2d_t *a, uint32_t relrow, uint32_t delta, uint32_t *p_total);

/* cost 16-bit correspondant = LUT[proba] (delegation at the LUT alz_score already validated). */
uint32_t alz_arena2d_cost(alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Accesseur PUR (read-only, no effect of bord) : freq[relrow<<8|delta] current.
 * Sert has detecter has symbole COLD (==0, never vu) without muter l'arena. */
uint32_t alz_arena2d_freq(const alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Rescale of has line (halving towards pair, 13.84). Exposee for the self-test. */
void alz_arena2d_rescale(alz_arena2d_t *a, uint32_t relrow);

/* Rescale MASTER (0x40ffa0/0x4100b1, 13.727) : law DISTINCTE of the working 0x414590.
 * for each some 256 columns : f>16 -> f>>=1 ; otherwise f=0. total = Sigma f (without counter).
 * (Rebuild tree Fenwick [0x4373c8] no modelise here - out portee of the score.) */
void alz_arena2d_rescale_master(alz_arena2d_t *a, uint32_t relrow);

/* Learn d'emission master (0x4111a0 core, 13.727) : same rule cold/warm that score
 * (isolant leffet of the law of rescale), but rescale MASTER. Reconstruit master@bloc1. */
uint32_t alz_arena2d_master_learn(alz_arena2d_t *a, uint32_t relrow, uint32_t delta);

/* Self-test : replays the ground-truth legacy (image.raw, 80 positions) and verified proba+total.
 * returns 0 if 80/80, otherwise the number of divergences. Gated by env UHA_ARENATEST in uha_c. */
int alz_arena2d_selftest(void);

#endif /* ALZ_ARENA2D_H */
