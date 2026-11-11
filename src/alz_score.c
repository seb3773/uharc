/*
 * alz_score.c — coeur du scoreur de coût delta-2D ALZ (portage fidèle UHARC 0.6b).
 * Voir alz_score.h pour la portée et le statut (NON-WIRED, self-testé).
 * RE ancrée : UHARC_RE_REPORT.md §13.65 (scorer 0x414630), §13.66 (table 0x43f154 DGROUP),
 *             §13.67 (index 2D (row<<8)|delta ; table cumulative confirmée).
 */
#include "alz_score.h"
#include <stdio.h>

/* Table cumulative extraite octet-pour-octet du binaire (16384 mots u16). */
#include "alz_score_table.inc"

uint32_t alz_score_cost(uint32_t freq, uint32_t total)
{
    uint32_t p = alz_score_proba(freq, total);
    return (uint32_t)alz_score_cum[p];
}

uint32_t alz_score_proba_to_cost(uint32_t proba)
{
    if (proba >= ALZ_SCORE_CUM_N)
        proba = ALZ_SCORE_CUM_N - 1u;
    return (uint32_t)alz_score_cum[proba];
}

/*
 * Vérifie que la table embarquée est bien conforme aux ancres relevées AU RUNTIME
 * dans le process (0x43f154, §13.133/13.134) et que l'arithmétique proba->coût est
 * déterministe / bornée.
 */
int alz_score_selftest(void)
{
    int fails = 0;

    /* (1) Intégrité de la table capturée au runtime : ancres connues du dump. */
    if (alz_score_cum[0]   != 0u)     { printf("[SCORE-TEST] FAIL cum[0]=%u\n", alz_score_cum[0]);     fails++; }
    if (alz_score_cum[1]   != 65520u) { printf("[SCORE-TEST] FAIL cum[1]=%u\n", alz_score_cum[1]);     fails++; }
    if (alz_score_cum[2]   != 60840u) { printf("[SCORE-TEST] FAIL cum[2]=%u\n", alz_score_cum[2]);     fails++; }
    if (alz_score_cum[3]   != 58102u) { printf("[SCORE-TEST] FAIL cum[3]=%u\n", alz_score_cum[3]);     fails++; }
    if (alz_score_cum[4]   != 56160u) { printf("[SCORE-TEST] FAIL cum[4]=%u\n", alz_score_cum[4]);     fails++; }
    /* Symbole vraiment froid : proba 64 -> coût 0x9240 = 37440 (§13.133). */
    if (alz_score_cum[64]  != 37440u) { printf("[SCORE-TEST] FAIL cum[64]=%u\n", alz_score_cum[64]);   fails++; }
    /* Sonde coût froid réel relevée sur l'oracle (§13.133) : proba 8318 -> 4576 (0x11e0). */
    if (alz_score_cum[8318] != 4576u) { printf("[SCORE-TEST] FAIL cum[8318]=%u\n", alz_score_cum[8318]); fails++; }
    /* Table embarquée : 16385 entrées (0..16384), conforme au dump runtime mot-à-mot (§13.134). */
    if (alz_score_cum[16383] != 0u) { printf("[SCORE-TEST] FAIL cum[16383]=%u\n", alz_score_cum[16383]); fails++; }

    /* (2) Arithmétique de proba : troncature et bornage. */
    if (alz_score_proba(1u,    16384u) != 1u)    { printf("[SCORE-TEST] FAIL proba(1,16384)=%u\n",    alz_score_proba(1u, 16384u));    fails++; }
    if (alz_score_proba(8192u, 16384u) != 8192u) { printf("[SCORE-TEST] FAIL proba(8192,16384)=%u\n", alz_score_proba(8192u, 16384u)); fails++; }
    if (alz_score_proba(0u,    16384u) != 0u)    { printf("[SCORE-TEST] FAIL proba(0,16384)=%u\n",     alz_score_proba(0u, 16384u));    fails++; }
    /* freq == total -> proba = 16384 = index valide le plus haut (symbole certain, §13.134). */
    if (alz_score_proba(16384u, 16384u) != 16384u) { printf("[SCORE-TEST] FAIL proba haut=%u\n", alz_score_proba(16384u, 16384u)); fails++; }
    /* Le mot d'index 16384 doit valoir 0 (coût d'un symbole certain = 0 unité, table runtime). */
    if (alz_score_cum[16384] != 0u) { printf("[SCORE-TEST] FAIL cum[16384]=%u\n", alz_score_cum[16384]); fails++; }
    if (alz_score_cost(16384u, 16384u) != 0u) { printf("[SCORE-TEST] FAIL cost(certain)=%u\n", alz_score_cost(16384u, 16384u)); fails++; }
    /* total == 0 -> garde défensive. */
    if (alz_score_proba(5u, 0u) != ALZ_SCORE_CUM_N - 1u) { printf("[SCORE-TEST] FAIL proba total=0\n"); fails++; }

    /* (3) coût == lookup à l'index de proba (cohérence fonction/table). */
    if (alz_score_cost(1u, 16384u) != (uint32_t)alz_score_cum[1])  { printf("[SCORE-TEST] FAIL cost(1,16384)\n");   fails++; }
    if (alz_score_cost(0u, 16384u) != 0u)                          { printf("[SCORE-TEST] FAIL cost(0,16384)!=0\n"); fails++; }

    if (fails == 0)
        printf("[SCORE-TEST] all scorer primitives OK (table %u entrees)\n", ALZ_SCORE_CUM_N);
    else
        printf("[SCORE-TEST] %d echec(s)\n", fails);
    return fails ? 1 : 0;
}
