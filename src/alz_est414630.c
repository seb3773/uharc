/*
 * a3_est414630.c — estimateur complet 0x414630 (2D + échappement). Voir .h et
 * OUT/A3_loi_cout_414630.md. NON WIRÉ : aucun appel depuis le produit.
 */
#include "alz_est414630.h"
#include "alz_score.h"
#include <stddef.h>   /* NULL */

uint32_t a3_est_cost(alz_arena2d_t *a, const a3_esc_line_t *e,
                     uint32_t relrow, uint32_t delta, a3_est_step_t *out)
{
    uint32_t f, T, num, proba, p_esc = 0u, c2d, cesc = 0u, cost;

    delta &= 0xffu;

    /* --- état AVANT écriture (c'est l'ordre du legacy : 0x4148ED puis 0x414903) --- */
    f = alz_arena2d_freq(a, relrow, delta);
    T = a->total[relrow];
    num = (f != 0u) ? f : (uint32_t)a->counter[relrow];

    /* --- échappement : payé SEULEMENT sur le chemin froid (esi reste à 0 en chaud, 0x41490E) --- */
    if (f == 0u) {
        p_esc = a3_esc_line_proba(e, delta);   /* (freq << 14) / racine, 0x41493F */
        cesc  = alz_score_proba_to_cost(p_esc);
    }

    /* --- terme 2D + mises à jour de l'arène (freq/counter/total, rescale) --- */
    proba = alz_arena2d_score(a, relrow, delta, NULL);
    c2d   = alz_score_proba_to_cost(proba);

    cost = cesc + c2d;

    if (out) {
        out->f        = f;
        out->T        = T;
        out->num      = num;
        out->proba    = proba;
        out->p_esc    = p_esc;
        out->cost2d   = c2d;
        out->cost_esc = cesc;
        out->cost     = cost;
    }
    return cost;
}
