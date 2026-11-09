/*
 * alz_score.c - coeur of the scorer of cost delta-2D ALZ (faithful port UHARC 0.6b).
 * Voir alz_score.h for there portee and the statut (NO-WIRED, self-teste).
 * RE ancree : UHARC_RE_REPORT.md 13.65 (scorer 0x414630), 13.66 (table 0x43f154 DGROUP),
 *             13.67 (index 2D (row<<8)|delta ; table cumulative confirmee).
 */
#include "alz_score.h"
#include <stdio.h>

/* Table cumulative extracted byte-for-byte of the binary (16384 words u16). */
#include "alz_score_table.inc"

/* Probe K1 (gated UHA_ALZ_RATIODBG) - definitions more low, in the block of probe. */
static int      s_ratio_armed;
static uint64_t s_ratio_terms;
static uint32_t s_ratio_max;
static uint64_t s_ratio_hist[18];
static void alz_ratio_observe(uint32_t idx);

uint32_t alz_score_cost(uint32_t freq, uint32_t total)
{
    uint32_t p = alz_score_proba(freq, total);
    return (uint32_t)alz_score_cum[p];
}

uint32_t alz_score_proba_to_cost(uint32_t proba)
{
    if (proba >= ALZ_SCORE_CUM_N)
        proba = ALZ_SCORE_CUM_N - 1u;
    if (s_ratio_armed)                 /* [GATED UHA_ALZ_RATIODBG] observation pure */
        alz_ratio_observe(proba);
    return (uint32_t)alz_score_cum[proba];
}

/*
 * --- [GATED UHA_ALZ_RATIODBG, default-OFF] PROBE K1 : the ratio rend-il has index
 * sain ? Voir the contrat in alz_score.h. Has single counter d'state, arme by the
 * driver of probe ; never of output nor d'write out armement.
 */
#define ALZ_RATIO_NBUCKET 18u            /* decades 2^0 .. 2^17 (l'index < 2^15 by construction) */

static void alz_ratio_observe(uint32_t idx)
{
    uint32_t b = 0u, v = idx;
    /* seau 0 = {0,1} ; seau b >= 1 = [2^b , 2^(b+1)[ - bounds arithmetiques, no
     * bound of table nor of corpus. */
    while (b + 1u < ALZ_RATIO_NBUCKET && v >= 2u) { v >>= 1; b++; }
    s_ratio_hist[b]++;
    s_ratio_terms++;
    if (idx > s_ratio_max)
        s_ratio_max = idx;
}

void alz_score_ratio_reset(void)
{
    uint32_t i;
    s_ratio_terms = 0u;
    s_ratio_max   = 0u;
    for (i = 0u; i < ALZ_RATIO_NBUCKET; i++)
        s_ratio_hist[i] = 0u;
}

void alz_score_ratio_arm(int on)
{
    s_ratio_armed = on ? 1 : 0;
}

/* Rend Has line by (file, class) : the max is there grandeur which decide, l'histogramme
 * en gives there forme. The judge relit there table for borner, the port not cite no threshold. */
void alz_score_ratio_report(const char *file, uint32_t cls, uint32_t n)
{
    uint32_t i;
    printf("[RATIO] file=%s n=%u cls=%u terms=%llu max=%u hist=", file, n, cls,
           (unsigned long long)s_ratio_terms, s_ratio_max);
    for (i = 0u; i < ALZ_RATIO_NBUCKET; i++)
        printf("%u:%llu ", i, (unsigned long long)s_ratio_hist[i]);
    printf("\n");
    fflush(stdout);
}

/*
 * Verified that there table embarquee is well conforme to the ancres recorded AU RUNTIME
 * in the process (0x43f154, 13.133/13.134) and that l'arithmetique proba->cost is
 * deterministe / bounded.
 */
int alz_score_selftest(void)
{
    int fails = 0;

    /* (1) Integrite of the table capturee au runtime : ancres connues of the dump. */
    if (alz_score_cum[0]   != 0u)     { printf("[SCORE-TEST] FAIL cum[0]=%u\n", alz_score_cum[0]);     fails++; }
    if (alz_score_cum[1]   != 65520u) { printf("[SCORE-TEST] FAIL cum[1]=%u\n", alz_score_cum[1]);     fails++; }
    if (alz_score_cum[2]   != 60840u) { printf("[SCORE-TEST] FAIL cum[2]=%u\n", alz_score_cum[2]);     fails++; }
    if (alz_score_cum[3]   != 58102u) { printf("[SCORE-TEST] FAIL cum[3]=%u\n", alz_score_cum[3]);     fails++; }
    if (alz_score_cum[4]   != 56160u) { printf("[SCORE-TEST] FAIL cum[4]=%u\n", alz_score_cum[4]);     fails++; }
    /* Symbole vraiment cold : proba 64 -> cost 0x9240 = 37440 (13.133). */
    if (alz_score_cum[64]  != 37440u) { printf("[SCORE-TEST] FAIL cum[64]=%u\n", alz_score_cum[64]);   fails++; }
    /* Probe cost cold reel recorded sure l'oracle (13.133) : proba 8318 -> 4576 (0x11e0). */
    if (alz_score_cum[8318] != 4576u) { printf("[SCORE-TEST] FAIL cum[8318]=%u\n", alz_score_cum[8318]); fails++; }
    /* Table embarquee : 16385 inputs (0..16384), conforme au dump runtime word-has-word (13.134). */
    if (alz_score_cum[16383] != 0u) { printf("[SCORE-TEST] FAIL cum[16383]=%u\n", alz_score_cum[16383]); fails++; }

    /* (2) Arithmetique of proba : troncature and bornage. */
    if (alz_score_proba(1u,    16384u) != 1u)    { printf("[SCORE-TEST] FAIL proba(1,16384)=%u\n",    alz_score_proba(1u, 16384u));    fails++; }
    if (alz_score_proba(8192u, 16384u) != 8192u) { printf("[SCORE-TEST] FAIL proba(8192,16384)=%u\n", alz_score_proba(8192u, 16384u)); fails++; }
    if (alz_score_proba(0u,    16384u) != 0u)    { printf("[SCORE-TEST] FAIL proba(0,16384)=%u\n",     alz_score_proba(0u, 16384u));    fails++; }
    /* freq == total -> proba = 16384 = index validates the more high (symbole certain, 13.134). */
    if (alz_score_proba(16384u, 16384u) != 16384u) { printf("[SCORE-TEST] FAIL proba haut=%u\n", alz_score_proba(16384u, 16384u)); fails++; }
    /* The word d'index 16384 doit valoir 0 (cost of has symbole certain = 0 unite, table runtime). */
    if (alz_score_cum[16384] != 0u) { printf("[SCORE-TEST] FAIL cum[16384]=%u\n", alz_score_cum[16384]); fails++; }
    if (alz_score_cost(16384u, 16384u) != 0u) { printf("[SCORE-TEST] FAIL cost(certain)=%u\n", alz_score_cost(16384u, 16384u)); fails++; }
    /* total == 0 -> keeps defensive. */
    if (alz_score_proba(5u, 0u) != ALZ_SCORE_CUM_N - 1u) { printf("[SCORE-TEST] FAIL proba total=0\n"); fails++; }

    /* (3) cost == lookup at the index of proba (coherence function/table). */
    if (alz_score_cost(1u, 16384u) != (uint32_t)alz_score_cum[1])  { printf("[SCORE-TEST] FAIL cost(1,16384)\n");   fails++; }
    if (alz_score_cost(0u, 16384u) != 0u)                          { printf("[SCORE-TEST] FAIL cost(0,16384)!=0\n"); fails++; }

    if (fails == 0)
        printf("[SCORE-TEST] all scorer primitives OK (table %u entrees)\n", ALZ_SCORE_CUM_N);
    else
        printf("[SCORE-TEST] %d echec(s)\n", fails);
    return fails ? 1 : 0;
}
