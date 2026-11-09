/*
 * alz_score.h - coeur of the scorer of cost of the model delta-2D ALZ (faithful port UHARC 0.6b).
 *
 * This module isole there primitve CENTRALE of the scoring by symbole of legacy, localisee en RE :
 *   - scorer delta-2D  @ VA 0x415444 (index 2D = (row<<8)|delta), and son entry by-class
 *     0x414630 (file 0x13a30) - voir UHARC_RE_REPORT.md 13.65/13.66/13.67.
 *   - normalisation of proba 14 bits :  proba = (freq << 14) / total   (`div` unsigned, troncature).
 *   - cost (unites 16-bit) via there table CUMULATIVE extracted :  cost = alz_score_cum[proba].
 *     (table @ DGROUP VA 0x43f154, 16384 words u16, extractible byte-for-byte, 13.66).
 *
 * STATUT : primitives arithmetiques SPECIFIEES and TESTEES, NO-WIRED (no effect on l'encoding
 * standard). There update d'arena (freq += 0x20) and the rescale (total >= 0x4000 -> halving) are
 * volontairement laisses outside of this socle as long as leur semantique exact n'is not RE (voir
 * 13.67) - for not not encoder d'hypothese no verified.
 */
#ifndef ALZ_SCORE_H
#define ALZ_SCORE_H

#include <stdint.h>

/* Nombre d'inputs of the table cumulative (bounds of proba 14 bits, 0..16384 inclus).
 * L'index 16384 is ATTEIGNABLE (freq == total -> proba = (freq<<14)/total = 16384,
 * symbole " certain ", cost = cum[16384] = 1). the legacy engine indexe 0x43f154[proba] without
 * clamp towards the low : there table doit couvrir [0..16384] (13.88, off-by-one fixes). */
#define ALZ_SCORE_CUM_N 16385u

/* Shift of normalisation of proba (14 bits), conforme to legacy (`shl $0xe`). */
#define ALZ_SCORE_PROB_SHIFT 14

/*
 * Normalisation of proba 14 bits of legacy : proba = (freq << 14) / total.
 * Division entiere NO signee (troncature), as l'instruction `div` observee.
 * Keeps : total == 0 -> returns ALZ_SCORE_CUM_N - 1 (probe defensive ; not doit not advenir
 * in has state sain now total = sum some frequencies > 0). freq <= total always, therefore
 * proba in [0, 16384] = [0, ALZ_SCORE_CUM_N-1] ; the clamp high not sert qu'at the keeps.
 */
static inline uint32_t alz_score_proba(uint32_t freq, uint32_t total)
{
    uint32_t p;
    if (total == 0u)
        return ALZ_SCORE_CUM_N - 1u;
    p = (freq << ALZ_SCORE_PROB_SHIFT) / total;
    if (p >= ALZ_SCORE_CUM_N)
        p = ALZ_SCORE_CUM_N - 1u;
    return p;
}

/*
 * cost 16-bit of has symbole of frequency `freq` in has line of total `total`,
 * via lookup in there table cumulative extracted (alz_score_cum, 13.66).
 * C'is l'operation centrale of the scorer legacy : `mov 0x43f154(,%proba,2),%ax`.
 */
uint32_t alz_score_cost(uint32_t freq, uint32_t total);

/*
 * cost 16-bit directement has partir of has proba 14 bits already computed (index LUT bounded).
 * Uses by l'arena delta-2D (alz_arena2d) which computes sa clean proba (path cold/warm)
 * and not veut NOT re-diviser. Equivalent strict of `mov 0x43f154(,%proba,2),%ax`.
 */
uint32_t alz_score_proba_to_cost(uint32_t proba);

/*
 * Self-test deterministe and autonome (gated by env UHA_SCORETEST in uha_c).
 * Verified l'integrite of the table extracted + l'arithmetique proba->cost.
 * returns 0 if OK, no-zero otherwise.
 */
int alz_score_selftest(void);

/*
 * [GATED UHA_ALZ_RATIODBG, default-OFF - PROBE K1, NO EMISSIVE] Observation of the ratio
 * which fabrique l'index of the table of cost. `alz_score_proba_to_cost` is the not of
 * passage unique of all term `(counter  14) / sous_compteur` consumes by there table
 * `alz_score_cum` (mirror of `[0x43f154]`) : there probe y memorise, for the single calls
 * accomplis DURING son armement, the number of terms, l'index maximal vu and has histogramme
 * by decades of puissance two.  No threshold of corpus nor of table n'is code here : the
 * bounds which decident (first index now there table rend son maximum, first trou `0x0000`)
 * are DERIVEES of the table by the judge, not recopiees in the port. Out armement : no
 * effet, no write, output muette - the path of cost is strictement unchanged.
 */
void alz_score_ratio_reset(void);
void alz_score_ratio_arm(int on);
void alz_score_ratio_report(const char *file, uint32_t cls, uint32_t n);

#endif /* ALZ_SCORE_H */
