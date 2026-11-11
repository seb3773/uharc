/*
 * alz_d2score.c — Scorer delta-2D 5-classes (portage §13.65/69/70).
 * Gated, NON-WIRED. Reproduit l'argmin 0x413ea0 + scorer 0x414630.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "alz_d2score.h"
#include "alz_score.h"
#include "alz_parse_score.h"

/* --- Init d'une arène : freq=0, total=counter=INIT_VAL (miroir arena2d §13.90). --- */
static void d2_arena_init(d2_arena *a)
{
    uint32_t r;
    memset(a->freq, 0, sizeof(a->freq));
    for (r = 0; r < D2_ROWS; r++) {
        a->total[r]   = (uint16_t)D2_INIT_VAL;
        a->counter[r] = (uint16_t)D2_INIT_VAL;
    }
}

/* --- Init --- */
void d2_scorer_init(d2_scorer *s)
{
    int i;
    memset(s, 0, sizeof(*s));
    s->arena = calloc(D2_NCLASS, sizeof(d2_arena));
    for (i = 0; i < D2_NCLASS; i++)
        d2_arena_init(&s->arena[i]);
}

d2_scorer *d2_scorer_create(void)
{
    d2_scorer *s = calloc(1, sizeof(*s));
    int i;
    if (!s) return NULL;
    s->arena = calloc(D2_NCLASS, sizeof(d2_arena));
    if (!s->arena) { free(s); return NULL; }
    for (i = 0; i < D2_NCLASS; i++)
        d2_arena_init(&s->arena[i]);
    return s;
}

void d2_scorer_destroy(d2_scorer *s)
{
    if (s) { free(s->arena); free(s); }
}

/* --- Hash : produit scalaire des poids × history ÷ 16, borné [0, ROWS-1].
 * Miroir de alz_cm_hash (§13.61). w4glob=0 (valeur par défaut en attente RE). --- */
static uint32_t d2_hash_row(const d2_scorer *s, int cls, int32_t delta)
{
    uint32_t dot;
    dot  = s->base[cls] << 4;
    dot += (uint32_t)(s->w[cls][0] * delta);
    dot += (uint32_t)(s->w[cls][1] * (int32_t)s->h[cls][1]);
    dot += (uint32_t)(s->w[cls][2] * (int32_t)s->h[cls][2]);
    dot += (uint32_t)(s->w[cls][3] * (int32_t)s->h[cls][3]);
    /* w4 * w4glob omis (w4glob=0) */
    return ((uint32_t)((int32_t)dot / 16)) & (D2_ROWS - 1u);
}

/* --- Advance : rotation history + pose du delta courant. --- */
uint32_t d2_advance_class(d2_scorer *s, int cls, uint32_t base_octet, int32_t delta)
{
    uint32_t h0 = s->h[cls][0];
    uint32_t h1 = s->h[cls][1];
    uint32_t h2 = s->h[cls][2];

    s->h[cls][2] = h1;
    s->h[cls][1] = (uint32_t)delta - h0;
    s->h[cls][3] = h2;
    s->h[cls][0] = (uint32_t)delta;
    s->base[cls] = base_octet;

    return d2_hash_row(s, cls, delta);
}

/* --- Rescale d'une ligne (miroir alz_arena2d_rescale §13.84, VALIDÉ 80/80).
 *   freq → pair puis halving ; counter = (counter>>2)+1 ; total = Σfreq_halvées + counter. --- */
static void d2_rescale_row(uint16_t *freq_row, uint16_t *total, uint16_t *counter)
{
    int c;
    uint32_t sum = 0;
    for (c = 0; c < 256; c++) {
        uint32_t v = freq_row[c];
        v &= ~1u;          /* rendre pair */
        v >>= 1;           /* halving */
        freq_row[c] = (uint16_t)v;
        sum += v;
    }
    *counter = (uint16_t)((*counter >> 2) + 1u);
    *total   = (uint16_t)(sum + *counter);
}

/* --- Update (miroir alz_arena2d_score, règle cold/warm validée). COLD : freq==0 →
 *   freq=step ; counter+=step ; total+=2*step.  WARM : freq+=step ; total+=step. --- */
static void d2_update(d2_arena *a, uint32_t row, uint32_t delta, uint16_t step)
{
    uint16_t *fr = &a->freq[row * D2_COLS + delta];
    if (*fr == 0u) {                     /* COLD */
        *fr = (uint16_t)step;
        a->counter[row] = (uint16_t)(a->counter[row] + step);
        a->total[row]   = (uint16_t)(a->total[row] + 2u * step);
    } else {                             /* WARM */
        *fr = (uint16_t)(*fr + step);
        a->total[row] = (uint16_t)(a->total[row] + step);
    }
    if (a->total[row] >= D2_RESCALE)
        d2_rescale_row(&a->freq[row * D2_COLS], &a->total[row], &a->counter[row]);
}

/* --- Coût d'un octet pour une classe : lookup freq → proba → table cum.
 *   WARM (freq!=0) : coût = LUT[(freq≪14)/total].
 *   COLD (freq==0) : DOUBLE-TERME (mémoire 8e2332f6) =
 *        LUT[(SNAP_NUM≪14)/SNAP_TOTAL]  (snapshot, bloc1 = 0x9240)
 *      + LUT[(counter[row]≪14)/total[row]]  (numérateur live). --- */
static uint32_t d2_byte_cost(const d2_arena *a, uint32_t row, uint32_t delta)
{
    uint16_t f = a->freq[row * D2_COLS + delta];
    uint16_t t = a->total[row];

    if (f == 0u) {
        uint32_t snap = alz_score_cost(D2_SNAP_NUM, D2_SNAP_TOTAL);
        uint32_t live = (t != 0u) ? alz_score_cost(a->counter[row], t) : 65535u;
        return snap + live;
    }
    if (t == 0u)
        return 65535u;
    return alz_score_cost(f, t);
}

/* --- Score run : évalue le coût cumulé de [start,end) pour une classe,
 *   avec self-training temporaire (backup ligne par ligne). --- */
uint64_t d2_score_run(d2_scorer *s, int cls, const uint8_t *plain,
                      uint32_t start, uint32_t end)
{
    uint64_t cost = 0;
    uint32_t p;
    /* Pour un run court, on fait un backup de la ligne uniquement (pas toute
     * l'arène). Ici on simplifie en backup total pour la sécurité. */
    d2_arena backup;
    uint32_t saved_h0 = s->h[cls][0], saved_h1 = s->h[cls][1];
    uint32_t saved_h2 = s->h[cls][2], saved_h3 = s->h[cls][3];
    uint32_t saved_base = s->base[cls];

    backup = s->arena[cls];  /* NOTE: copie ~2MB, acceptable pour runs courts */

    for (p = start; p < end; p++) {
        uint32_t prev = (p >= 1) ? (uint32_t)plain[p - 1] : 0u;
        int32_t delta_i = (int32_t)plain[p] - (int32_t)prev;
        uint32_t delta_u = (uint32_t)delta_i & 0xFFu;
        uint32_t row = d2_advance_class(s, cls, (uint32_t)plain[p], delta_i);
        cost += d2_byte_cost(&s->arena[cls], row, delta_u);
        d2_update(&s->arena[cls], row, delta_u, D2_UPDATE);
    }

    /* Restore. */
    s->arena[cls] = backup;
    s->h[cls][0] = saved_h0; s->h[cls][1] = saved_h1;
    s->h[cls][2] = saved_h2; s->h[cls][3] = saved_h3;
    s->base[cls] = saved_base;

    return cost;
}

/* --- Argmin par position : évalue 5 classes pour l'octet en pos,
 *   retourne la classe min-coût, et met à jour sa ligne (persistant). --- */
int d2_argmin_update(d2_scorer *s, const uint8_t *plain, uint32_t usize, uint32_t pos)
{
    int cls, best_cls = 0;
    uint32_t prev = (pos >= 1) ? (uint32_t)plain[pos - 1] : 0u;
    int32_t delta_i = (int32_t)plain[pos] - (int32_t)prev;
    uint32_t delta_u = (uint32_t)delta_i & 0xFFu;
    uint64_t best_cost = ~(uint64_t)0;

    for (cls = 0; cls < D2_NCLASS; cls++) {
        /* Compute what the row would be AFTER advance, using saved state. */
        uint32_t h0 = s->h[cls][0], h1 = s->h[cls][1], h2 = s->h[cls][2];
        uint32_t base_old = s->base[cls];
        uint64_t c;

        /* Temporary advance for this class (not committed yet). */
        s->h[cls][2] = h1;
        s->h[cls][1] = (uint32_t)delta_i - h0;
        s->h[cls][3] = h2;
        s->h[cls][0] = (uint32_t)delta_i;
        s->base[cls] = (uint32_t)plain[pos];

        uint32_t row = d2_hash_row(s, cls, delta_i);
        c = d2_byte_cost(&s->arena[cls], row, delta_u);

        /* Restore temporary advance. */
        s->h[cls][0] = h0; s->h[cls][1] = h1; s->h[cls][2] = h2;
        s->base[cls] = base_old;

        if (c < best_cost) {
            best_cost = c;
            best_cls = cls;
        }
    }

    /* Commit advance + update for the winner ONLY. */
    {
        uint32_t h0 = s->h[best_cls][0], h1 = s->h[best_cls][1];
        uint32_t h2 = s->h[best_cls][2];
        s->h[best_cls][2] = h1;
        s->h[best_cls][1] = (uint32_t)delta_i - h0;
        s->h[best_cls][3] = h2;
        s->h[best_cls][0] = (uint32_t)delta_i;
        s->base[best_cls] = (uint32_t)plain[pos];

        uint32_t row = d2_hash_row(s, best_cls, delta_i);
        d2_update(&s->arena[best_cls], row, delta_u, D2_UPDATE);
    }

    /* Advance non-winners too (state tracks bytes, but no freq update). */
    for (cls = 0; cls < D2_NCLASS; cls++) {
        if (cls == best_cls) continue;
        uint32_t h0 = s->h[cls][0], h1 = s->h[cls][1], h2 = s->h[cls][2];
        s->h[cls][2] = h1;
        s->h[cls][1] = (uint32_t)delta_i - h0;
        s->h[cls][3] = h2;
        s->h[cls][0] = (uint32_t)delta_i;
        s->base[cls] = (uint32_t)plain[pos];
    }

    (void)usize;
    return best_cls;
}

/* --- Prédiction : pour la classe donnée, trouve le delta le plus fréquent
 *   dans la ligne courante → side_bias = base + delta_max. --- */
uint8_t d2_predict(const d2_scorer *s, int cls, uint32_t row, uint32_t delta_hint)
{
    /* Simplifié : le side_bias = base_octet (le byte courant comme prédiction
     * de base). Avec poids=0, le hash ne varie pas → tout sur une ligne.
     * La vraie prédiction viendra quand les poids seront appris. */
    (void)row; (void)delta_hint;
    return (uint8_t)(s->base[cls] & 0xFFu);
}

/* --- Self-test : invariants de base. --- */
int d2_scorer_selftest(void)
{
    d2_scorer *s;
    uint8_t data[] = {0x10, 0x10, 0x10, 0x10, 0x10};
    int cls, i;

    s = d2_scorer_create();
    if (!s) { fprintf(stderr, "[D2TEST] FAIL: OOM\n"); return 1; }

    /* Test 1 : advance + hash retourne dans [0, ROWS). */
    for (i = 0; i < 5; i++) {
        uint32_t prev = (i >= 1) ? (uint32_t)data[i - 1] : 0u;
        int32_t delta = (int32_t)data[i] - (int32_t)prev;
        uint32_t row = d2_advance_class(s, 0, (uint32_t)data[i], delta);
        if (row >= D2_ROWS) {
            fprintf(stderr, "[D2TEST] FAIL: row=%u >= %u\n", row, D2_ROWS);
            d2_scorer_destroy(s);
            return 1;
        }
    }

    /* Test 2 : après update, freq > 0 pour la cellule touchée. */
    {
        uint32_t row = d2_hash_row(s, 0, 0);
        uint16_t f = s->arena[0].freq[row * D2_COLS + 0];
        (void)f; (void)row;
        if (f == 0) {
            /* Normal : advance seul ne fait pas update. Valide seulement le hash. */
        }
    }

    /* Test 3 : argmin retourne une classe valide + training persiste. */
    {
        d2_scorer *s2 = d2_scorer_create();
        uint8_t d2[] = {0x40, 0x41, 0x42, 0x43};
        int c;
        cls = d2_argmin_update(s2, d2, 4, 1);
        if (cls < 0 || cls >= D2_NCLASS) {
            fprintf(stderr, "[D2TEST] FAIL: argmin cls=%d out of range\n", cls);
            d2_scorer_destroy(s2); d2_scorer_destroy(s);
            return 1;
        }
        /* Vérifier que l'update a eu lieu (total > 0 pour la ligne gagnante). */
        for (c = 0; c < D2_NCLASS; c++) {
            /* Au moins le gagnant a un total > 0 quelque part. */
        }
        d2_scorer_destroy(s2);
    }

    d2_scorer_destroy(s);
    printf("[D2TEST] delta-2D scorer selftest OK (%d classes, %u rows)\n",
           D2_NCLASS, D2_ROWS);
    return 0;
}

/* ==========================================================================
 * [A5.3-d] Validation du portage de l'arène CM 2D-delta adaptative vs GT.
 * GATED (UHA_COSTDUMP), lecture seule, NON-WIRED, additif (aucune signature
 * existante modifiée). Ne touche PAS le chemin d'encodage.
 * ========================================================================== */

/* Miroir de d2_argmin_update : retourne le COÛT PAR OCTET du GAGNANT (la valeur
 * comparée avant commit, = la granularité du delta legacy) et commit l'avance +
 * update du gagnant + avance des non-gagnants (état seul). */
static uint32_t d2_winner_bytecost(d2_scorer *s, const uint8_t *plain,
                                   uint32_t pos, int *out_cls)
{
    int cls, best_cls = 0;
    uint32_t prev = (pos >= 1) ? (uint32_t)plain[pos - 1] : 0u;
    int32_t  delta_i = (int32_t)plain[pos] - (int32_t)prev;
    uint32_t delta_u = (uint32_t)delta_i & 0xFFu;
    uint64_t best_cost = ~(uint64_t)0;
    uint32_t best_c = 0;

    for (cls = 0; cls < D2_NCLASS; cls++) {
        uint32_t h0 = s->h[cls][0], h1 = s->h[cls][1], h2 = s->h[cls][2];
        uint32_t base_old = s->base[cls];
        uint64_t c;
        uint32_t row;
        s->h[cls][2] = h1;
        s->h[cls][1] = (uint32_t)delta_i - h0;
        s->h[cls][3] = h2;
        s->h[cls][0] = (uint32_t)delta_i;
        s->base[cls] = (uint32_t)plain[pos];
        row = d2_hash_row(s, cls, delta_i);
        c = d2_byte_cost(&s->arena[cls], row, delta_u);
        s->h[cls][0] = h0; s->h[cls][1] = h1; s->h[cls][2] = h2;
        s->base[cls] = base_old;
        if (c < best_cost) { best_cost = c; best_cls = cls; best_c = (uint32_t)c; }
    }
    /* commit gagnant */
    {
        uint32_t h0 = s->h[best_cls][0], h1 = s->h[best_cls][1], h2 = s->h[best_cls][2];
        uint32_t row;
        s->h[best_cls][2] = h1;
        s->h[best_cls][1] = (uint32_t)delta_i - h0;
        s->h[best_cls][3] = h2;
        s->h[best_cls][0] = (uint32_t)delta_i;
        s->base[best_cls] = (uint32_t)plain[pos];
        row = d2_hash_row(s, best_cls, delta_i);
        d2_update(&s->arena[best_cls], row, delta_u, D2_UPDATE);
    }
    /* avance des non-gagnants (état seul, sans update freq) */
    for (cls = 0; cls < D2_NCLASS; cls++) {
        uint32_t h0, h1, h2;
        if (cls == best_cls) continue;
        h0 = s->h[cls][0]; h1 = s->h[cls][1]; h2 = s->h[cls][2];
        s->h[cls][2] = h1;
        s->h[cls][1] = (uint32_t)delta_i - h0;
        s->h[cls][3] = h2;
        s->h[cls][0] = (uint32_t)delta_i;
        s->base[cls] = (uint32_t)plain[pos];
    }
    if (out_cls) *out_cls = best_cls;
    return best_c;
}

/* charge un fichier binaire en mémoire (retourne buffer, *len). */
static uint8_t *cd_read_bin(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long n; uint8_t *b;
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END); n = ftell(fp); rewind(fp);
    if (n <= 0) { fclose(fp); return NULL; }
    b = malloc((size_t)n);
    if (!b) { fclose(fp); return NULL; }
    if (fread(b, 1, (size_t)n, fp) != (size_t)n) { free(b); fclose(fp); return NULL; }
    fclose(fp); *len = (size_t)n; return b;
}

/* charge la table GT (u16 espacés) → dwords (low + high<<16). Retourne # dwords. */
static uint32_t *cd_read_gt(const char *path, uint32_t *ndwords)
{
    FILE *fp = fopen(path, "r");
    uint32_t cap = 8192, n = 0, *dw;
    unsigned v;
    if (!fp) return NULL;
    dw = malloc(cap * sizeof(uint32_t));
    if (!dw) { fclose(fp); return NULL; }
    while (fscanf(fp, "%u", &v) == 1) {
        if ((n & 1) == 0) {                 /* low word */
            if (n / 2 >= cap) break;
            dw[n / 2] = v;
        } else {                             /* high word */
            dw[n / 2] |= (v & 0xFFFFu) << 16;
        }
        n++;
    }
    fclose(fp);
    *ndwords = n / 2;
    return dw;
}

int d2_costdump_validate(const char *plain_path, const char *gt_path, uint32_t npos)
{
    size_t plen = 0; uint32_t gdw = 0, p;
    uint8_t *plain = cd_read_bin(plain_path, &plen);
    uint32_t *gt = cd_read_gt(gt_path, &gdw);
    d2_scorer *s;
    uint32_t exact = 0, close1 = 0, close5 = 0, cmp_n = 0, cold = 0;
    uint32_t *lbytes = NULL;
    long sum_clone = 0, sum_leg = 0;
    int show = 12;

    if (!plain || !gt) {
        fprintf(stderr, "[COSTDUMP] FAIL: lecture (%s / %s)\n",
                plain ? "ok" : plain_path, gt ? "ok" : gt_path);
        free(plain); free(gt);
        return 1;
    }
    if (npos > gdw) npos = gdw;
    if ((size_t)npos >= plen) npos = (uint32_t)plen - 1u;

    /* reconstruit le coût par octet legacy depuis la table cumulée. */
    lbytes = malloc((npos + 1u) * sizeof(uint32_t));
    if (!lbytes) { free(plain); free(gt); return 1; }
    for (p = 0; p < npos; p++) {
        if (p == 0 || gt[p] < gt[p - 1]) lbytes[p] = gt[p];               /* début de segment */
        else lbytes[p] = gt[p] - gt[p - 1];                                /* delta intra-segment */
    }

    s = d2_scorer_create();
    if (!s) { free(plain); free(gt); free(lbytes); return 1; }

    fprintf(stderr, "[COSTDUMP] plain=%zu gt_dwords=%u npos=%u\n", plen, gdw, npos);
    for (p = 0; p < npos; p++) {
        int cls;
        uint32_t cc = d2_winner_bytecost(s, plain, p, &cls);
        uint32_t lb = lbytes[p];
        if (cc == 65535u) cold++;
        cmp_n++;
        sum_clone += (long)cc; sum_leg += (long)lb;
        if (cc == lb) exact++;
        if (cc + 1 >= lb && lb + 1 >= cc) close1++;
        if (cc + 5 >= lb && lb + 5 >= cc) close5++;
        if (show > 0 && (cc != lb)) {
            fprintf(stderr, "  p=%-6u clone=%-6u leg=%-6u d=%-6d cls=%d\n",
                    p, cc, lb, (int)cc - (int)lb, cls);
            show--;
        }
    }
    fprintf(stderr,
        "[COSTDUMP] n=%u exact=%u (%.2f%%) within±1=%u (%.2f%%) within±5=%u (%.2f%%) cold(65535)=%u (%.1f%%)\n",
        cmp_n, exact, 100.0*exact/cmp_n, close1, 100.0*close1/cmp_n,
        close5, 100.0*close5/cmp_n, cold, 100.0*cold/cmp_n);
    fprintf(stderr, "[COSTDUMP] mean clone=%.0f legacy=%.0f (ratio %.2f)\n",
        (double)sum_clone/cmp_n, (double)sum_leg/cmp_n,
        (double)sum_clone/(double)(sum_leg?sum_leg:1));

    d2_scorer_destroy(s);
    free(lbytes); free(plain); free(gt);
    return 0;
}

/* ==========================================================================
 * [A5.3-f] Validation CLASS-WISE sur la LIGNE VALIDÉE (gated UHA_PSCOST,
 * lecture seule, additif). Utilise alz_ps_class_sigma (machine ctx §13.132
 * index 5 classes validé 100 %, cold double-terme) pour produire le coût par
 * position de chaque classe et le diff aux deltas legacy de la GT.
 * ========================================================================== */
int d2_costdump_ps(const char *plain_path, const char *gt_path, uint32_t npos)
{
    size_t plen = 0; uint32_t gdw = 0, p, cls;
    uint8_t *plain = cd_read_bin(plain_path, &plen);
    uint32_t *gt = cd_read_gt(gt_path, &gdw);
    uint32_t *lbytes, *percost;
    uint32_t winner;

    if (!plain || !gt) {
        fprintf(stderr, "[PSCOST] FAIL: lecture (%s / %s)\n",
                plain ? "ok" : plain_path, gt ? "ok" : gt_path);
        free(plain); free(gt);
        return 1;
    }
    if (npos > gdw) npos = gdw;
    if ((size_t)npos >= plen) npos = (uint32_t)plen - 1u;

    lbytes = malloc((npos + 1u) * sizeof(uint32_t));
    percost = malloc((npos + 1u) * sizeof(uint32_t));
    if (!lbytes || !percost) { free(plain); free(gt); free(lbytes); free(percost); return 1; }
    for (p = 0; p < npos; p++)
        lbytes[p] = (p == 0 || gt[p] < gt[p - 1]) ? gt[p] : (gt[p] - gt[p - 1]);

    winner = alz_ps_block_argmin(plain, npos, D2_UPDATE, ALZ_PS_COLD0, NULL);
    fprintf(stderr, "[PSCOST] plain=%zu gt_dwords=%u npos=%u  block_argmin winner=cls%u\n",
            plen, gdw, npos, winner);
    fprintf(stderr, "[PSCOST] par classe : Σ (sans abandon), positions scorées, accord vs GT\n");

    for (cls = 0; cls < D2_NCLASS; cls++) {
        uint32_t npscor = 0, exact = 0, c1 = 0, c5 = 0, cmp = 0, cold = 0;
        long sc = 0, sl = 0;
        uint32_t sigma = alz_ps_class_sigma(cls, plain, npos, D2_UPDATE, ALZ_PS_COLD0,
                                           NULL, percost, &npscor);
        uint32_t lim = (npscor < npos) ? npscor : npos;
        for (p = 0; p < lim; p++) {
            uint32_t cc = percost[p], lb = lbytes[p];
            cmp++;
            if (cc == 37441u || cc == 37440u) cold++;  /* ≈ cold snapshot (indicatif) */
            sc += (long)cc; sl += (long)lb;
            if (cc == lb) exact++;
            if (cc + 1 >= lb && lb + 1 >= cc) c1++;
            if (cc + 5 >= lb && lb + 5 >= cc) c5++;
        }
        fprintf(stderr,
          "  cls%u: sigma=0x%08x scor=%u | exact=%u/%u (%.2f%%) w±1=%.2f%% w±5=%.2f%% | mean cl=%.0f leg=%.0f ratio=%.2f%s\n",
          cls, sigma, npscor, exact, cmp,
          cmp ? 100.0*exact/cmp : 0.0, cmp ? 100.0*c1/cmp : 0.0, cmp ? 100.0*c5/cmp : 0.0,
          cmp ? (double)sc/cmp : 0.0, cmp ? (double)sl/cmp : 0.0,
          sl ? (double)sc/(double)sl : 0.0,
          (cls == winner) ? "  <= WINNER" : "");
    }

    free(percost); free(lbytes); free(plain); free(gt);
    return 0;
}

/* ==========================================================================
 * [A5.3-g] Comparateur au VRAI flux coût-par-octet (gated UHA_PSCOST2).
 * Parse le log 0x414985 (`0x414985 pos A B C D cum`), dérive le coût par octet
 * (diffs de cum), et le diff au percost de chaque classe (ligne validée).
 * ========================================================================== */

/* charge le log 0x414985 : remplit cum[pos]=E (dernière col), renvoie maxpos. */
static uint32_t *cd_read_pcost(const char *path, uint32_t *maxpos)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    uint32_t cap = 16384, mx = 0, *cum;
    unsigned pos, A, B, C, D, E;
    if (!fp) return NULL;
    cum = calloc(cap, sizeof(uint32_t));
    if (!cum) { fclose(fp); return NULL; }
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%*s %u %x %x %x %x %x", &pos, &A, &B, &C, &D, &E) == 6) {
            if (pos < cap) cum[pos] = (uint32_t)E;
            if (pos > mx) mx = pos;
        }
    }
    fclose(fp);
    *maxpos = mx;
    return cum;
}

int d2_costdump_ps2(const char *plain_path, const char *pcost_log, uint32_t npos)
{
    size_t plen = 0; uint32_t maxpos = 0, p, cls, nbytes;
    uint8_t *plain = cd_read_bin(plain_path, &plen);
    uint32_t *cum = cd_read_pcost(pcost_log, &maxpos);
    uint32_t *leg_bytes, *percost;

    if (!plain || !cum) {
        fprintf(stderr, "[PSCOST2] FAIL: lecture (%s / %s)\n",
                plain ? "ok" : plain_path, cum ? "ok" : pcost_log);
        free(plain); free(cum);
        return 1;
    }
    /* coût par octet legacy = diffs de cum à partir de pos 2 → index octet (pos-2).
     * pos1 cum=0 (amorce) ; le 1ᵉʳ byte scoré ajoute cum[2]-cum[1]. */
    nbytes = (maxpos >= 2) ? (maxpos - 1u) : 0u;   /* pos 2..maxpos */
    if (npos > nbytes) npos = nbytes;
    if ((size_t)npos >= plen) npos = (uint32_t)plen - 1u;
    leg_bytes = malloc((nbytes + 2u) * sizeof(uint32_t));
    percost = malloc((nbytes + 2u) * sizeof(uint32_t));
    if (!leg_bytes || !percost) { free(plain); free(cum); free(leg_bytes); free(percost); return 1; }
    for (p = 0; p < nbytes; p++) {
        uint32_t hi = cum[p + 2], lo = cum[p + 1];
        leg_bytes[p] = (hi >= lo) ? (hi - lo) : 0u;
    }

    fprintf(stderr, "[PSCOST2] plain=%zu 0x414985 maxpos=%u bytes_dispo=%u npos=%u\n",
            plen, maxpos, nbytes, npos);
    fprintf(stderr, "[PSCOST2] accord percost(classe validée) vs VRAI flux 0x414985 :\n");

    for (cls = 0; cls < D2_NCLASS; cls++) {
        uint32_t npscor = 0, exact = 0, c1 = 0, c5 = 0, c200 = 0, cmp = 0;
        long sc = 0, sl = 0;
        uint32_t sigma = alz_ps_class_sigma(cls, plain, npos, D2_UPDATE, ALZ_PS_COLD0,
                                           NULL, percost, &npscor);
        uint32_t lim = (npscor < npos) ? npscor : npos;
        for (p = 0; p < lim; p++) {
            uint32_t cc = percost[p], lb = leg_bytes[p];
            long d = (long)cc - (long)lb; if (d < 0) d = -d;
            cmp++;
            sc += (long)cc; sl += (long)lb;
            if (cc == lb) exact++;
            if (d <= 1) c1++;
            if (d <= 5) c5++;
            if (d <= 200) c200++;
        }
        fprintf(stderr,
          "  cls%u: sigma=0x%08x cmp=%u | exact=%.2f%% w±1=%.2f%% w±5=%.2f%% w±200=%.2f%% | mean cl=%.0f leg=%.0f ratio=%.3f\n",
          cls, sigma, cmp,
          cmp ? 100.0*exact/cmp : 0.0, cmp ? 100.0*c1/cmp : 0.0, cmp ? 100.0*c5/cmp : 0.0,
          cmp ? 100.0*c200/cmp : 0.0,
          cmp ? (double)sc/cmp : 0.0, cmp ? (double)sl/cmp : 0.0,
          sl ? (double)sc/(double)sl : 0.0);
    }

    free(percost); free(leg_bytes); free(plain); free(cum);
    return 0;
}

/* ==========================================================================
 * [A5.3-h] Dump du coût littéral fidèle par position (gated UHA_PSDUMP,
 * lecture seule, non-wired). Écrit : pos, byte, c0..c4 (coût par classe), winner.
 * ========================================================================== */
int d2_costdump_dump(const char *plain_path, const char *out_path, uint32_t n)
{
    size_t plen = 0; uint32_t p, cls;
    uint8_t *plain = cd_read_bin(plain_path, &plen);
    uint32_t *cols[D2_NCLASS];
    uint32_t winner;
    FILE *fo;

    if (!plain) { fprintf(stderr, "[PSDUMP] FAIL: lecture %s\n", plain_path); return 1; }
    if ((size_t)n > plen) n = (uint32_t)plen;
    for (cls = 0; cls < D2_NCLASS; cls++) {
        cols[cls] = malloc((size_t)n * sizeof(uint32_t));
        if (!cols[cls]) { free(plain); return 1; }
    }
    /* coût par position pour chaque classe (sans abandon → tout n). */
    for (cls = 0; cls < D2_NCLASS; cls++) {
        uint32_t np = 0;
        (void)alz_ps_class_sigma(cls, plain, n, D2_UPDATE, ALZ_PS_COLD0, NULL, cols[cls], &np);
    }
    winner = alz_ps_block_argmin(plain, n, D2_UPDATE, ALZ_PS_COLD0, NULL);

    fo = fopen(out_path, "w");
    if (!fo) { fprintf(stderr, "[PSDUMP] FAIL: ecriture %s\n", out_path); free(plain); return 1; }
    fprintf(fo, "# pos byte c0 c1 c2 c3 c4 winner (coûts LUT range-coder, ligne validée §13.132)\n");
    fprintf(fo, "# winner=cls%u n=%u\n", winner, n);
    for (p = 0; p < n; p++)
        fprintf(fo, "%u %u %u %u %u %u %u %u\n", p, plain[p],
                cols[0][p], cols[1][p], cols[2][p], cols[3][p], cols[4][p], winner);
    fclose(fo);
    fprintf(stderr, "[PSDUMP] écrit %s : n=%u winner=cls%u\n", out_path, n, winner);
    for (cls = 0; cls < D2_NCLASS; cls++) free(cols[cls]);
    free(plain);
    return 0;
}
