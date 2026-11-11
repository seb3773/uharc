/*
 * alz_block.c — couche (a) BLOCK multi-catégories du scoreur ALZ (portage §13.119/§13.120).
 * Gated, NON-WIRED : aucun appel depuis le chemin d'encodage standard. Voir alz_block.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alz_block.h"

/* --- Géométrie de catégorie STATIQUE (extraite du binaire UHARC.EXE, off=VA-0x402000) */
/* [0x437884] base d'arène par catégorie idx 0..9 (idx0=0x000 → fallback catégorie 0). */
const uint16_t alz_block_arena[ALZ_BLOCK_NCAT] = {
    0x000u, 0x301u, 0x321u, 0x341u, 0x3a1u, 0x3e1u, 0x3e5u, 0x3e9u, 0x3f1u, 0x3f4u
};
/* [0x4378ac] tableA (param de ligne/taille) idx 0..9. */
const uint16_t alz_block_tblA[ALZ_BLOCK_NCAT] = {
    0x000u, 0x020u, 0x020u, 0x060u, 0x040u, 0x004u, 0x004u, 0x008u, 0x003u, 0x005u
};
/* [0x43785c] tableC (compte/lignes relatif) idx 0..9. */
const uint8_t alz_block_tblC[ALZ_BLOCK_NCAT] = {
    1u, 1u, 2u, 3u, 4u, 1u, 1u, 2u, 2u, 4u
};
/* [0x4378d4] octet escape par classe (idx 0..19). */
const uint8_t alz_block_escape[20] = {
    0u, 0u, 8u, 16u, 24u, 0u, 0u, 0u, 0u, 0u,
    0u, 1u, 2u, 3u, 4u, 1u, 1u, 2u, 2u, 4u
};

/* --- Cycle de vie --------------------------------------------------------------- */

alz_block_t *alz_block_create(uint16_t default_inc)
{
    alz_block_t *b = calloc(1, sizeof *b);
    uint32_t i;
    if (!b)
        return NULL;
    b->model    = calloc(ALZ_BLOCK_NCAT, sizeof(alz_arena2d_t));
    b->snapshot = calloc(ALZ_BLOCK_NCAT, sizeof(alz_arena2d_t));
    if (!b->model || !b->snapshot) {
        alz_block_destroy(b);
        return NULL;
    }
    for (i = 0; i < ALZ_BLOCK_NCAT; i++) {
        alz_arena2d_init(&b->model[i],    default_inc);
        alz_arena2d_init(&b->snapshot[i], default_inc);
    }
    b->active_cat = 0u;   /* catégorie 0 = arène de repli (§13.120 item 1) */
    b->flag_snap  = 0u;   /* [0x45ecc8]=0 hors commit de match long        */
    return b;
}

void alz_block_destroy(alz_block_t *b)
{
    if (!b)
        return;
    free(b->model);
    free(b->snapshot);
    free(b);
}

/* --- Transaction load/score/restore (motif §13.120 item 5) ---------------------- */

void alz_block_save(alz_block_t *b, uint32_t cat)
{
    if (cat < ALZ_BLOCK_NCAT)
        memcpy(&b->snapshot[cat], &b->model[cat], sizeof(alz_arena2d_t));
}

void alz_block_restore(alz_block_t *b, uint32_t cat)
{
    if (cat < ALZ_BLOCK_NCAT)
        memcpy(&b->model[cat], &b->snapshot[cat], sizeof(alz_arena2d_t));
}

void alz_block_commit_cat(alz_block_t *b, uint32_t cat, uint8_t snap_flag)
{
    b->active_cat = (cat < ALZ_BLOCK_NCAT) ? cat : 0u; /* [0x45ecc0] */
    b->flag_snap  = snap_flag;                          /* [0x45ecc8] */
}

/* --- SONDE de coût cumulé par catégorie (STUB non émissif) ---------------------- */
/*
 * index delta-2D = (relrow<<8 | delta). Ici relrow = octet précédent borné (placeholder
 * de la « ligne de contexte »), delta = écart courant-précédent (0..255). La correspondance
 * EXACTE avec la récurrence legacy 0x415444 et le tableau 0x45cb60[] = incrément suivant.
 */
uint64_t alz_block_score_class_stub(alz_block_t *b, uint32_t cat,
                                    const uint8_t *win, uint32_t len,
                                    uint64_t *out_cost)
{
    uint64_t cost = 0u;
    uint32_t i;
    uint8_t prev = 0u;
    alz_arena2d_t *m;

    if (!b || cat >= ALZ_BLOCK_NCAT || !win) {
        if (out_cost) *out_cost = 0u;
        return 0u;
    }
    m = &b->model[cat];
    for (i = 0; i < len; i++) {
        uint32_t relrow = (uint32_t)prev & (ALZ_ARENA2D_MAX_ROW - 1u);
        uint32_t delta  = (uint32_t)((int32_t)win[i] - (int32_t)prev) & 0xFFu;
        cost += alz_arena2d_cost(m, relrow, delta);   /* auto-entraîne m en place */
        prev  = win[i];
    }
    if (out_cost) *out_cost = cost;
    return cost;
}

/* --- Argmin de coût cumulé sur les classes (§13.119 item 2) --------------------- */
int alz_block_argmin(alz_block_t *b, const uint8_t *win, uint32_t len,
                     uint32_t nclass, uint64_t *costs)
{
    uint32_t c;
    int best = -1;
    uint64_t bestcost = 0u;

    if (!b || len == 0u || nclass == 0u)
        return -1;
    if (nclass > ALZ_BLOCK_NCAT)
        nclass = ALZ_BLOCK_NCAT;

    for (c = 0u; c < nclass; c++) {
        uint64_t cost;
        alz_block_restore(b, c);                    /* chaque catégorie repart du snapshot */
        cost = alz_block_score_class_stub(b, c, win, len, NULL);
        if (costs)
            costs[c] = cost;
        if (best < 0 || cost < bestcost) {          /* argmin STRICT (comme 0x413fde jae keep) */
            bestcost = cost;
            best = (int)c;
        }
    }
    /* Le vainqueur conserve son entraînement (coûts positionnels commit 0x45cb60→0x45cb7c) :
     * on rejoue son score sans restore, puis on le pose catégorie active. */
    alz_block_save(b, (uint32_t)best);              /* snapshot pré-bloc du gagnant        */
    (void)alz_block_score_class_stub(b, (uint32_t)best, win, len, NULL);
    alz_block_commit_cat(b, (uint32_t)best, 0u);
    return best;
}

/* --- Self-test (structurel ; géométrie = valeurs extraites du binaire) ----------- */
int alz_block_selftest(void)
{
    int fail = 0;
    alz_block_t *b;
    uint8_t win[16];
    uint64_t costs[ALZ_BLOCK_NCAT];
    int winner;
    uint32_t i;

    /* (1) géométrie : cohérence interne + bornes (les constantes viennent du dump). */
    if (alz_block_arena[0] != 0x000u || alz_block_arena[9] != 0x3f4u ||
        alz_block_arena[7] != 0x3e9u || alz_block_arena[8] != 0x3f1u)
        fail++;
    if (alz_block_tblA[1] != 0x20u || alz_block_tblA[3] != 0x60u ||
        alz_block_tblA[9] != 5u)
        fail++;
    if (alz_block_tblC[4] != 4u || alz_block_tblC[9] != 4u || alz_block_tblC[5] != 1u)
        fail++;
    if (alz_block_escape[4] != 24u || alz_block_escape[13] != 3u || alz_block_escape[19] != 4u)
        fail++;

    b = alz_block_create(32u);
    if (!b) {
        fprintf(stderr, "[BLOCK-TEST] create OOM\n");
        return 1;
    }

    /* (2) save/restore idempotent : muter model[0], restaurer depuis snapshot[0]. */
    for (i = 0; i < 16; i++) win[i] = (uint8_t)(200u + i);
    alz_block_save(b, 0u);                                   /* snapshot[0] <- model[0] froid */
    (void)alz_block_score_class_stub(b, 0u, win, 16u, NULL);  /* model[0] entraîné            */
    if (memcmp(&b->model[0], &b->snapshot[0], sizeof(alz_arena2d_t)) == 0)
        fail++;                                              /* l'entraînement a bien muté   */
    alz_block_restore(b, 0u);                                /* model[0] <- snapshot[0]       */
    if (memcmp(&b->model[0], &b->snapshot[0], sizeof(alz_arena2d_t)) != 0)
        fail++;                                              /* restore exact                 */

    /* (3) argmin : CONTRACT structurel = retourner l'index du cout minimal de costs[]
     *     et le committer comme categorie active. Independant de la sémantique de la
     *     table de cout (la recurrence exacte = incrément suivant). */
    for (i = 0; i < 16; i++) win[i] = (uint8_t)(10u + i * 3u);
    /* differencier les snapshots pour eviter un tie degenere : entrainer la categorie 1 */
    {
        uint32_t k;
        for (k = 0u; k < 8u; k++)
            (void)alz_block_score_class_stub(b, 1u, win, 16u, NULL);
        alz_block_save(b, 1u);
    }
    winner = alz_block_argmin(b, win, 16u, ALZ_BLOCK_NCLASS, costs);
    if (winner < 0 || (uint32_t)winner >= ALZ_BLOCK_NCLASS) {
        fail++;
    } else {
        uint64_t mn = costs[winner];
        for (i = 0u; i < ALZ_BLOCK_NCLASS; i++)
            if (costs[i] < mn)
                mn = costs[i];
        if (costs[winner] != mn)      /* l'argmin a bien choisi le minimum     */
            fail++;
        if (b->active_cat != (uint32_t)winner)  /* commit categorie active     */
            fail++;
    }

    alz_block_destroy(b);
    fprintf(stderr, "[BLOCK-TEST] %s (fail=%d)\n", fail ? "ECHEC" : "OK", fail);
    return fail ? 1 : 0;
}
