/*
 * alz_est414630.h — estimateur COMPLET du coût de position, port fidèle de 0x414630
 *                  (terme 2D de src/alz_arena2d.c + terme d'échappement de la ligne 0x402+cl).
 *
 * Loi fermée et validée : OUT/A3_loi_cout_414630.md, OUT/A3_capture9_resultats.md.
 *
 *   f     = HOT[row][delta]                 lu AVANT écriture
 *   T     = TOTAL[row]                      lu AVANT écriture
 *   froid (f == 0) :
 *       p_esc = (PERM_esc[delta] << 14) / FEN_esc      (dénominateur = racine Fenwick de la ligne)
 *       cost  = t[p_esc] + t[(COUNTER[row] << 14) / T]
 *   chaud (f != 0) :
 *       cost  = t[(f << 14) / T]                       (échappement NON payé)
 *   puis (dans les deux cas) : freq += 0x20 ; counter += 0x20 si froid ; total += 0x20 si chaud,
 *                              + 0x40 si froid ; rescale de la ligne si total >= 0x4000.
 *
 * STATUT : module de LANE, NON WIRÉ — compilé uniquement par les tests (work/), aucun fichier de
 * `src/` modifié. Prêt à être déplacé dans `src/` sous une gate `UHA_A3_*` le jour du câblage.
 */
#ifndef A3_EST414630_H
#define A3_EST414630_H

#include <stdint.h>
#include "alz_arena2d.h"
#include "alz_esc_line.h"   /* a3_esc_line_t : PERM 0x402+cl + arbre Fenwick (fen[0] = racine) */

/* Trace d'un pas (facultative, sortie seule). */
typedef struct a3_est_step {
    uint32_t f;        /* HOT[row][delta] AVANT */
    uint32_t T;        /* TOTAL[row] AVANT */
    uint32_t num;      /* numérateur 2D : f si chaud, COUNTER[row] si froid */
    uint32_t proba;    /* p2d = (num << 14) / T */
    uint32_t p_esc;    /* (perm << 14) / fen, 0 si chaud */
    uint32_t cost2d;   /* t[p2d] */
    uint32_t cost_esc; /* t[p_esc] si froid, 0 sinon */
    uint32_t cost;     /* cost_esc + cost2d */
} a3_est_step_t;

/* Un pas de l'estimateur : met à jour l'arène, rend le coût de la position.
 * `out` peut être NULL. Aucune valeur codée en dur, aucun état global. */
uint32_t a3_est_cost(alz_arena2d_t *a, const a3_esc_line_t *e,
                     uint32_t relrow, uint32_t delta, a3_est_step_t *out);

#endif /* A3_EST414630_H */
