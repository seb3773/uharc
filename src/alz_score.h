/*
 * alz_score.h — coeur du scoreur de coût du modèle delta-2D ALZ (portage fidèle UHARC 0.6b).
 *
 * Ce module isole la primitve CENTRALE du scoring par symbole du legacy, localisée en RE :
 *   - scoreur delta-2D  @ VA 0x415444 (index 2D = (row<<8)|delta), et son entry par-classe
 *     0x414630 (file 0x13a30) — voir UHARC_RE_REPORT.md §13.65/§13.66/§13.67.
 *   - normalisation de proba 14 bits :  proba = (freq << 14) / total   (`div` unsigned, troncature).
 *   - coût (unités 16-bit) via la table CUMULATIVE extraite :  coût = alz_score_cum[proba].
 *     (table @ DGROUP VA 0x43f154, 16384 mots u16, extractible octet-pour-octet, §13.66).
 *
 * STATUT : primitives arithmétiques SPÉCIFIÉES et TESTÉES, NON-WIRED (aucun effet sur l'encodage
 * standard). La mise à jour d'arène (freq += 0x20) et le rescale (total >= 0x4000 → halving) sont
 * volontairement laissés hors de ce socle tant que leur sémantique exacte n'est pas RE (voir
 * §13.67) — pour ne pas encoder d'hypothèse non vérifiée.
 */
#ifndef ALZ_SCORE_H
#define ALZ_SCORE_H

#include <stdint.h>

/* Nombre d'entrées de la table cumulative (bornes de proba 14 bits, 0..16384 inclus).
 * L'index 16384 est ATTEIGNABLE (freq == total -> proba = (freq<<14)/total = 16384,
 * symbole « certain », coût = cum[16384] = 1). Le legacy indexe 0x43f154[proba] sans
 * clamp vers le bas : la table doit couvrir [0..16384] (§13.88, off-by-one corrige). */
#define ALZ_SCORE_CUM_N 16385u

/* Décalage de normalisation de proba (14 bits), conforme au legacy (`shl $0xe`). */
#define ALZ_SCORE_PROB_SHIFT 14

/*
 * Normalisation de proba 14 bits du legacy : proba = (freq << 14) / total.
 * Division entière NON signée (troncature), comme l'instruction `div` observée.
 * Garde : total == 0 → renvoie ALZ_SCORE_CUM_N - 1 (sonde défensive ; ne doit pas advenir
 * dans un état sain où total = somme des fréquences > 0). freq <= total toujours, donc
 * proba in [0, 16384] = [0, ALZ_SCORE_CUM_N-1] ; le clamp haut ne sert qu'à la garde.
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
 * Coût 16-bit d'un symbole de fréquence `freq` dans une ligne de total `total`,
 * via lookup dans la table cumulative extraite (alz_score_cum, §13.66).
 * C'est l'opération centrale du scoreur legacy : `mov 0x43f154(,%proba,2),%ax`.
 */
uint32_t alz_score_cost(uint32_t freq, uint32_t total);

/*
 * Coût 16-bit directement à partir d'une proba 14 bits déjà calculée (index LUT borné).
 * Utilisé par l'arène delta-2D (alz_arena2d) qui calcule sa propre proba (chemin cold/warm)
 * et ne veut PAS re-diviser. Équivalent strict de `mov 0x43f154(,%proba,2),%ax`.
 */
uint32_t alz_score_proba_to_cost(uint32_t proba);

/*
 * Self-test déterministe et autonome (gated par env UHA_SCORETEST dans uha_c).
 * Vérifie l'intégrité de la table extraite + l'arithmétique proba→coût.
 * Renvoie 0 si OK, non-zero sinon.
 */
int alz_score_selftest(void);

#endif /* ALZ_SCORE_H */
