/*
 * alz_parse_score.c - scorer of PARSE ALZ (driver of block 0x413f7f/0x413ea0 + category
 * 0x414630). Reproduction bit-exact of the pipeline validated from-scratch 13.132/13.137..13.141.
 * GATED, NO-WIRED. Voir alz_parse_score.h for there specification.
 */
#include "alz_parse_score.h"
#include "alz_score.h"
#include "alz_cm.h"   /* [GATED UHA_CM_WIRE] engine CM dense (alz_arb/alz_arena/alz_cm) for there law sym->row (13.796) */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Tables static of the machine ctx (generees, 13.132). */
#include "alz_parse_score_tables.inc"

/* [GATED UHA_AADUMP, probe read-only 13.722(4)/13.724] Pointer of dump
 * (row,freq,total) pos-has-pos of the pass cls3, ouvert ONLY by
 * alz_ps_emiprod_percost when UHA_AADUMP=path. NULL otherwise => no effect. */
static FILE *g_adump = NULL;
/* [GATED UHA_WLEARNLIT, default-OFF, 14.126] mask of learn by position global
 * (index base+i). NULL => learn PARTOUT (behavior actuel, no regressif).
 * when sets : there pass not MUT l'arena (freq/total/rescale) that there now mask!=0
 * (ex. literals emis), all en SCORANT each position (percost intact).
 * Teste l'hypothese " the legacy engine n'learns that sure the stream d'emission ". */
static const uint8_t *g_ps_learn_mask = NULL;
/* [GATED UHA_LIVEWALK_BOUNDRESCALE] if !=0, ps_learn NOT rescale NOT inline ; the rescale
 * is applies at the FRONTIER of block (cadence commit legacy `0x414590`, loop columns
 * `0x414806-0x414871`), not as soon as total>=0x4000 during l'learning. */
static int g_ps_no_inline_rescale = 0;
/* [GATED UHA_PHASEFIX, default-OFF, 13.739] Phase cls3 corrigee = (abs+2)%3
 * (measured 29943/29944 = 100 % vs stream learn reel 0x411bb8) au lieu of the counter
 * ebp threade by block. Affecte ONLY cls3, and only when there porte is ON. */
static int g_ps_phasefix = 0;

/* [GATED UHA_PFILE, default-OFF, ISOLAT, M33->razor -m3] Pre-substrat `P[pos]` of the
 * cm-engine (laws M33 closes by #2, psim.py 159/159, produces since image.raw SINGLE),
 * loads en has pass since the file (1 byte/prediction). when sets, gen_ctxs(cls==3)
 * uses `ctx = P[i]` (there TRUE prediction) au lieu of `ctx=(rolling>>esc)&0xff`
 * (approx lag3), therefore the `delta = zigzag(value  P)` devient faithful => intra16
 * peuple (M31 : base 0x351) and there PAIRE (row,sym) is coherente EN write AND EN READING
 * (all the consommateurs read `ctxc[3]`), contrairement to the gates refutees
 * FEEDSELF_LAG3/PHASE2 which ecrivaient horsctxc. DefautOFF = behavior strictement
 * unchanged (banque 16685). */
/*  measured NEGATIF (20261021, main) for THIS integration en prepasse : FEEDSELF+AGING
 * (razor ref 18432) + UHA_PFILE -> **firstdiv 18432 -> 12679** (regresse). Cause double :
 * (has) the scorer 0x412c30/0x414630, ALREADY clos/faithful, CONSUMES ctxc[3] with the ctx lag3 ;
 *     substituer P partout the perturbe -> nearties renversees more tot ; (b) the ROW law M31
 *     (base 0x351 / ctx_roulant=[0x45cbc8]) is no clos -> there paire (row,sym) remainder incoherente.
 *  => P faithful is NECESSARY but NO SUFFISANT en prepasse ; the levier reel = SINGLEPASS
 *  (TASK16) now score+learn+row partagent has same ctx en order d'emission REEL. Gate laissee
 *  defautOFF (brique P reutilisable for TASK16), no cablee au default. */
static uint8_t *g_pfile = NULL;
static uint32_t g_pfile_n = 0;
static int g_pfile_tried = 0;
static const uint8_t *alz_ps_pfile_try(uint32_t n)
{
    if (!g_pfile_tried) {
        const char *e = getenv("UHA_PFILE");
        g_pfile_tried = 1;
        if (e) {
            FILE *f = fopen(e, "rb");
            if (f) {
                uint8_t *b = (uint8_t *)malloc(n ? n : 1u);
                if (b && fread(b, 1u, n, f) == n) { g_pfile = b; g_pfile_n = n; }
                else free(b);
                fclose(f);
                if (g_pfile)
                    fprintf(stderr, "[UHA_PFILE] cm-engine P charge: %u positions\n", (unsigned)n);
            }
        }
    }
    return (g_pfile && n == g_pfile_n) ? g_pfile : NULL;
}

/* [GATED UHA_CM_WIRE, default-OFF, 13.787/789] tables of there machine-registre d'affinite
 * image (extracted of the binary UHARC.EXE, off = VA-0x402000) :
 *   f74 = (f74<<8) + T1[sym]   (T1 @ 0x438310)
 *   f78 = (f78<<8) + T2[sym]   (T2 @ 0x438b10)
 * Same categorie of provenance that alz_ps_t1/t3 and alz_block_arena (tables STATIC
 * of the mecanisme, NOT some captures runtime). Utilisees ONLY when UHA_CM_WIRE is ON. */
static const uint32_t ALZ_REG_T1[256]={0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,6,6,6,6,7,7,7,7,8,8,8,8,9,9,9,9,10,10,10,10,11,11,11,11,12,12,12,12,13,13,13,13,14,14,14,14,15,15,15,15,16,16,16,16,17,17,17,17,18,18,18,18,19,19,19,19,20,20,20,20,21,21,21,21,22,22,22,22,23,23,23,23,24,24,24,24,25,25,25,25,26,26,26,26,27,27,27,27,28,28,28,28,29,29,29,29,30,30,30,30,31,31,31,31,32,31,31,31,31,30,30,30,30,29,29,29,29,28,28,28,28,27,27,27,27,26,26,26,26,25,25,25,25,24,24,24,24,23,23,23,23,22,22,22,22,21,21,21,21,20,20,20,20,19,19,19,19,18,18,18,18,17,17,17,17,16,16,16,16,15,15,15,15,14,14,14,14,13,13,13,13,12,12,12,12,11,11,11,11,10,10,10,10,9,9,9,9,8,8,8,8,7,7,7,7,6,6,6,6,5,5,5,5,4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1,0,0,0};
static const uint32_t ALZ_REG_T2[256]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static inline uint32_t rb(const uint8_t *d, uint32_t i, uint32_t k)
{
    return (i >= k) ? (uint32_t)d[i - k] : 0u;
}

void alz_ps_gen_ctxs(uint32_t cls, const uint8_t *data, uint32_t n, uint32_t *out)
{
    uint32_t i;
    if (cls == 0u) {
        /* Path order-2 (0x414b2e) : row = prev1 + (0x100 if same class some 2 MSB). */
        for (i = 0; i < n; i++) {
            uint32_t b  = data[i];
            uint32_t p1 = rb(data, i, 1);
            uint32_t p2 = rb(data, i, 2);
            uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
            out[i] = (row << 8) | b;
        }
        return;
    }
    {
        uint32_t ebx = 0u, flag = 0u, ebp = 0u;
        uint32_t esc = alz_ps_escape[cls];
        /* [GATED UHA_PFILE, M33] for cls3, there prediction cm-engine replaces the ctx lag3. */
        const uint8_t *pc = (cls == 3u) ? alz_ps_pfile_try(n) : NULL;
        for (i = 0; i < n; i++) {
            uint32_t b = data[i];
            uint32_t ctx;
            if (pc) {
                ctx = pc[i];
            } else {
                uint32_t rolling = rb(data, i, 1) | (rb(data, i, 2) << 8) |
                                   (rb(data, i, 3) << 16) | (rb(data, i, 4) << 24);
                ctx = (rolling >> esc) & 0xffu;
            }
            uint32_t delta = flag ? ((ctx + 0x100u - b) & 0xffu) : ((b + 0x100u - ctx) & 0xffu);
            out[i] = (ebx << 8) | delta;
            if (delta >= 0x80u) flag ^= 1u;
            switch (cls) {
                case 1: ebx = alz_ps_t1[delta] + ((uint32_t)alz_ps_tnib[ebx & 0xfu] << 4); break;
                case 2: ebx = alz_ps_t1[delta] + ((ebp & 1u) << 4); break;
                case 3: ebx = alz_ps_t3[delta] + ((ebp % 3u) << 5); break;
                default: ebx = alz_ps_t1[delta] + ((ebp & 3u) << 4); break; /* cls>=4 */
            }
            ebp++;
        }
    }
}

uint32_t alz_ps_class_sigma(uint32_t cls, const uint8_t *data, uint32_t n,
                            uint32_t default_inc, uint32_t cold_first,
                            const uint32_t *best_in,
                            uint32_t *percost, uint32_t *pnpos)
{
    uint32_t *ctxs;
    alz_arena2d_t *a;
    uint32_t i, acc = 0u;

    ctxs = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)n);
    a    = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!ctxs || !a) { free(ctxs); free(a); if (pnpos) *pnpos = 0; return 0u; }

    alz_ps_gen_ctxs(cls, data, n, ctxs);
    alz_arena2d_init(a, (uint16_t)default_inc);

    for (i = 0; i < n; i++) {
        uint32_t ctx = ctxs[i];
        uint32_t row = ctx >> 8;
        uint32_t delta = ctx & 0xffu;
        uint32_t T, f, c, inc, cs;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u; /* keeps */
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];

        if (f != 0u) {                                   /* --- WARM : 1 term --- */
            cs = alz_score_proba_to_cost((f << 14) / T);
        } else {                                         /* --- COLD : 2 terms --- */
            cs = alz_score_proba_to_cost(cold_first)
               + alz_score_proba_to_cost((c << 14) / T);
        }
        acc += cs;
        if (percost) percost[i] = cs;

        if (best_in && acc > *best_in) {                 /* abandon precoce (0x4149c2) */
            if (pnpos) *pnpos = i + 1u;
            free(ctxs); free(a);
            return acc;
        }

        /* update d'arena (identical has alz_arena2d_score) */
        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE)
            alz_arena2d_rescale(a, row);
        (void)delta;
    }
    if (pnpos) *pnpos = n;
    free(ctxs); free(a);
    return acc;
}

uint32_t alz_ps_block_argmin(const uint8_t *data, uint32_t n,
                             uint32_t default_inc, uint32_t cold_first,
                             uint32_t *sigma_out)
{
    uint32_t cls, best = 0xffffffffu, winner = 0u;
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++) {
        uint32_t bi = best, s;
        s = alz_ps_class_sigma(cls, data, n, default_inc, cold_first,
                               (cls == 0u) ? NULL : &bi, NULL, NULL);
        if (sigma_out) sigma_out[cls] = s;
        if (s < best) { best = s; winner = cls; }
    }
    return winner;
}

/* ============================================================================
 * [A5.1 it2] path PERSISTANT : machine ctx + arena threadees cross-blocks.
 * Voir alz_parse_score.h for there specification (gated, read-only).
 * ========================================================================== */

/* Has not of the machine ctx : returns ctx=(row<<8)|delta for there position ABSOLUE
 * abs in the buffer global g, and advances st-state (ebx/flag/ebp). cls0 = order-2 direct. */
static inline uint32_t ps_ctx_step(uint32_t cls, const uint8_t *g, uint32_t abs,
                                   uint32_t *ebx, uint32_t *flag, uint32_t *ebp)
{
    if (cls == 0u) {
        uint32_t b  = g[abs];
        uint32_t p1 = rb(g, abs, 1);
        uint32_t p2 = rb(g, abs, 2);
        uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
        (*ebp)++;
        return (row << 8) | b;
    } else {
        uint32_t b = g[abs];
        uint32_t rolling = rb(g, abs, 1) | (rb(g, abs, 2) << 8) |
                           (rb(g, abs, 3) << 16) | (rb(g, abs, 4) << 24);
        uint32_t esc = alz_ps_escape[cls];
        uint32_t ctx   = (rolling >> esc) & 0xffu;
        uint32_t e = *ebx, f = *flag, p = *ebp;
        uint32_t delta = f ? ((ctx + 0x100u - b) & 0xffu) : ((b + 0x100u - ctx) & 0xffu);
        uint32_t out = (e << 8) | delta;
        if (delta >= 0x80u) f ^= 1u;
        switch (cls) {
            case 1: e = alz_ps_t1[delta] + ((uint32_t)alz_ps_tnib[e & 0xfu] << 4); break;
            case 2: e = alz_ps_t1[delta] + ((p & 1u) << 4); break;
            case 3: e = alz_ps_t3[delta] + ((p % 3u) << 5); break;
            default: e = alz_ps_t1[delta] + ((p & 3u) << 4); break; /* cls>=4 */
        }
        p++;
        *ebx = e; *flag = f; *ebp = p;
        return out;
    }
}

/* [a5-e briquet 1] wrappers d'state machine for the scan of couverture legacy. */
uint32_t alz_ps_ctx_step_run(uint32_t cls, const uint8_t *g, uint32_t abs, uint32_t *mm)
{
    return ps_ctx_step(cls, g, abs, &mm[0], &mm[1], &mm[2]);
}

uint32_t alz_ps_ctx_scan3(const uint8_t *g, uint32_t abs, uint32_t *mm, uint32_t delta)
{
    uint32_t b     = g[abs];                    /* roule ctx machine (as cls3) */
    uint32_t roll  = rb(g, abs, 1) | (rb(g, abs, 2) << 8) |
                     (rb(g, abs, 3) << 16) | (rb(g, abs, 4) << 24);
    uint32_t ctx   = (roll >> alz_ps_escape[3]) & 0xffu;
    uint32_t e = mm[0], f = mm[1], p = mm[2];
    uint32_t d;
    uint32_t out;
    (void)b; (void)ctx;                          /* the scan fournit son clean delta */
    d   = delta & 0xffu;
    out = (e << 8) | d;                          /* line BEFORE reading (mirror) */
    if (d >= 0x80u) f ^= 1u;
    e = alz_ps_t3[d] + ((p % 3u) << 5);          /* machine advances sure delta-scan */
    p++;
    mm[0] = e; mm[1] = f; mm[2] = p;
    return out;
}

uint32_t alz_ps_class_sigma_carry(alz_ps_carry_t *st, uint32_t cls,
                                  const uint8_t *g, uint32_t base, uint32_t n,
                                  uint32_t default_inc, uint32_t cold_first,
                                  const uint32_t *best_in,
                                  uint32_t *percost, uint32_t *pnpos)
{
    alz_arena2d_t *a;
    uint32_t i, acc = 0u;

    if (!st->arena) {
        st->arena = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
        if (!st->arena) { if (pnpos) *pnpos = 0; return 0u; }
        alz_arena2d_init(st->arena, (uint16_t)default_inc);
    }
    a = st->arena;

    for (i = 0; i < n; i++) {
        uint32_t ctx = ps_ctx_step(cls, g, base + i, &st->ebx, &st->flag, &st->ebp);
        uint32_t row, delta, T, f, c, inc, cs;
        /* [GATED UHA_PHASEFIX] fixes the term of phase of the row cls3 = (abs+2)%3. */
        if (g_ps_phasefix && cls == 3u) {
            static int s_phrel = -1;   /* [GATED UHA_PHASEFIX_REL, default-OFF, 14.147] */
            uint32_t e = ctx >> 8;
            uint32_t pbase;
            if (s_phrel < 0) s_phrel = getenv("UHA_PHASEFIX_REL") ? 1 : 0;
            pbase = s_phrel ? i : (base + i);   /* relatif-au-block vs absolu */
            e = (e & 0x1fu) + (((pbase + 2u) % 3u) << 5);
            ctx = (e << 8) | (ctx & 0xffu);
        }
        row = ctx >> 8;
        delta = ctx & 0xffu;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];

        if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / T);
        else         cs = alz_score_proba_to_cost(cold_first)
                            + alz_score_proba_to_cost((c << 14) / T);
        if (g_adump && cls == 3u)
            fprintf(g_adump, "%u\t%u\t%u\t%u\t%u\t%u\n",
                    (unsigned)(base + i), (unsigned)row, (unsigned)f,
                    (unsigned)T, (unsigned)c, (unsigned)cs);
        acc += cs;
        if (percost) percost[i] = cs;

        if (best_in && acc > *best_in) {          /* abandon : machine avancee, arena NO entrainee */
            if (pnpos) *pnpos = i + 1u;
            return acc;
        }
        /* [GATED UHA_WLEARNLIT] skip there MUTATION d'arena out some positions masquees
         * (the cost/percost ci-dessus remainder computed for all positions). */
        if (g_ps_learn_mask && !g_ps_learn_mask[base + i]) continue;

        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE)
            alz_arena2d_rescale(a, row);
        (void)delta;
    }
    if (pnpos) *pnpos = n;
    return acc;
}

uint32_t alz_ps_block_argmin_carry(alz_ps_carry_t *st, uint32_t seed_cls,
                                   const uint8_t *g, uint32_t base, uint32_t n,
                                   uint32_t default_inc, uint32_t cold_first,
                                   uint32_t *sigma_out, uint32_t *npos_out)
{
    uint32_t order[ALZ_PS_NCLASS];
    uint32_t k, cls, best = 0xffffffffu, winner = 0u, cnt = 0u;

    /* seed_cls en first (best_in=NULL, never aborts), then the others en order croissant. */
    order[cnt++] = seed_cls;
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++)
        if (cls != seed_cls) order[cnt++] = cls;

    for (k = 0; k < cnt; k++) {
        uint32_t c = order[k];
        uint32_t bi = best, s, np = 0;
        s = alz_ps_class_sigma_carry(&st[c], c, g, base, n, default_inc, cold_first,
                                     (k == 0u) ? NULL : &bi, NULL, &np);
        if (sigma_out) sigma_out[c] = s;
        if (npos_out)  npos_out[c]  = np;
        if (s < best) { best = s; winner = c; }
    }
    return winner;
}

void alz_ps_carry_free(alz_ps_carry_t *st)
{
    uint32_t c;
    for (c = 0; c < ALZ_PS_NCLASS; c++) {
        free(st[c].arena);
        st[c].arena = NULL;
    }
}

/* ---- Self-test : image.raw bloc1, Sigma_cls from-scratch == oracles + argmin cls3 (13.141). ---- */
int alz_parse_score_selftest(void)
{
#include "alz_parse_score_vecs.inc"   /* alz_ps_testdata[12544] */
    static const uint32_t oracle[ALZ_PS_NCLASS] = {
        0x086c23ecu, 0x04a50d90u, 0x04a521c4u, 0x046a185cu, 0x046a4476u
    };
    uint32_t sigma[ALZ_PS_NCLASS];
    uint32_t n = (uint32_t)(sizeof(alz_ps_testdata) / sizeof(alz_ps_testdata[0]));
    uint32_t winner, cls;
    int fails = 0;

    winner = alz_ps_block_argmin(alz_ps_testdata, n, 32u, ALZ_PS_COLD0, sigma);
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++) {
        if (sigma[cls] != oracle[cls]) {
            printf("[PARSE-TEST] FAIL cls%u: got 0x%08x exp 0x%08x\n",
                   cls, sigma[cls], oracle[cls]);
            fails++;
        }
    }
    if (winner != 3u) { printf("[PARSE-TEST] FAIL argmin: winner cls%u exp cls3\n", winner); fails++; }

    if (fails == 0)
        printf("[PARSE-TEST] scoreur 0x414630 from-plain OK (%u/%u classes == oracle ; argmin=cls3)\n",
               (unsigned)ALZ_PS_NCLASS, (unsigned)ALZ_PS_NCLASS);
    else
        printf("[PARSE-TEST] %d divergence(s)\n", fails);
    return fails ? 1 : 0;
}

/* ---- [A5.1 it1] Multitest by blocks (gated UHA_PARSEMULTI=<image.raw>) : rolle P1
 * (alz_ps_block_argmin, INIT COLD = hypothese zero " no persistance ") sure the
 * 6 blocks of scoring d'image.raw and compares to the Sigma_cls ORACLE (blockcost_perclass.log,
 * 13.118/13.165). Objectif : (has) confirmer winner cls3 robuste, (b) quantifier
 * l'impact of the seed inter-blocks. read-only, n'affecte NOT l'encoding. ---- */
static const uint32_t am_blk_pos[6] = {0x0000u, 0x3100u, 0x620cu, 0x931cu, 0xc4ffu, 0xff00u};
static const uint32_t am_blk_len[6] = {0x3100u, 0x3100u, 0x3100u, 0x3100u, 0x3a01u, 0x100u};
static const uint32_t am_blk_oracle[6][ALZ_PS_NCLASS] = {
    { 0x086c23ecu, 0x04a50d90u, 0x04a521c4u, 0x046a185cu, 0x046a4476u },
    { 0x0433d5bbu, 0x0433c900u, 0x0433cbb1u, 0x0433c605u, 0x0433ce95u },
    { 0x042d808bu, 0x042d7932u, 0x042d8158u, 0x042d7095u, 0x042d93aau },
    { 0x042d3e19u, 0x042d3708u, 0x042eb482u, 0x042d2ac8u, 0x042d32f3u },
    { 0x04f184d0u, 0x04f1aac0u, 0x04f1a865u, 0x04f17ab6u, 0x04f1a7f0u },
    { 0x001647c0u, 0x0015d3a5u, 0x0015eb5bu, 0x0015d16cu, 0x0015f426u },
};
int alz_parse_score_multitest(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    if (!fp) { printf("[PARSE-MULTI] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI] read fail\n"); return 1; }
    fclose(fp);
    printf("[PARSE-MULTI] %s sz=%ld, 6 blocs, init COLD (hyp. nulle non-persistance)\n", path, sz);
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS];
        uint32_t pos = am_blk_pos[b], len = am_blk_len[b], w;
        int exact = 1, wsmatch;
        if ((long)(pos + len) > sz) { printf("  blk%d OUT-OF-BOUNDS\n", b); free(buf); return 1; }
        w = alz_ps_block_argmin(buf + pos, len, 32u, ALZ_PS_COLD0, sigma);
        wsmatch = (w == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d pos=0x%05x len=0x%05x : gagnant=cls%u (%s cls3) | "
               "gotallo=%s | Sigma[0..4]=",
               b, pos, len, w, wsmatch ? "==" : "!=", exact ? "==ORACLE" : ">=1 ecart");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            printf(" %s0x%08x%s", k ? "" : "", sigma[k], k < 4 ? "" : "");
        printf(" vs oracle:");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI] gagnant==cls3 : %d/6 blocs | Sigma 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    free(buf);
    return 0;
}

/* ---- [A5.1 it2] Multitest PERSISTANCE (gated UHA_PARSEMULTI2=<image.raw>) : same decoupage
 * that it1 but arenas + machine ctx threadees of has block at the other (vainqueur score en first,
 * context global, ebp absolu). Objectif : to verify convergence Sigma_cls -> oracle (target exact).
 * read-only, n'affecte NOT l'encoding. ---- */
static int s_pm2_machine_reset = 0;
int alz_parse_score_multitest2(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    alz_ps_carry_t st[ALZ_PS_NCLASS];
    uint32_t seed_cls = 0u;
    if (!fp) { printf("[PARSE-MULTI2] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI2] read fail\n"); return 1; }
    fclose(fp);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        st[k].arena = NULL; st[k].ebx = 0; st[k].flag = 0; st[k].ebp = 0;
    }
    printf("[PARSE-MULTI2] %s sz=%ld, 6 blocs, PERSISTANCE arene+machine (vainqueur d'abord)\n", path, sz);
    {
        const char *mm = getenv("UHA_PM2");   /* "m" = machine reinit/by-block (arena single carry) */
        s_pm2_machine_reset = (mm && mm[0] == 'm') ? 1 : 0;
        printf("[PARSE-MULTI2] mode carry = %s\n", s_pm2_machine_reset ? "ARENE seule (machine reset/bloc)" : "arene+machine");
    }
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS], npos[ALZ_PS_NCLASS];
        uint32_t base = am_blk_pos[b], len = am_blk_len[b], w;
        int exact = 1, wsmatch;
        double dev = 0.0;
        if ((long)(base + len) > sz) { printf("  blk%d OUT-OF-BOUNDS\n", b); free(buf); return 1; }
        if (s_pm2_machine_reset && b > 0) {
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) { st[k].ebx = 0; st[k].flag = 0; st[k].ebp = 0; }
        }
        w = alz_ps_block_argmin_carry(st, seed_cls, buf, base, len, 32u, ALZ_PS_COLD0, sigma, npos);
        seed_cls = w;
        wsmatch = (w == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
            if (am_blk_oracle[b][k])
                dev += (double)sigma[k] / (double)am_blk_oracle[b][k] - 1.0;
        }
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d base=0x%05x len=0x%05x seed=cls%u : gagnant=cls%u (%s cls3) | %s | "
               "devSigma moy=%+.2f%% | npos=", b, base, len, w, w,
               wsmatch ? "==" : "!=", exact ? "==ORACLE" : ">=1 ecart", dev * 20.0);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" %u", npos[k]);
        printf("\n      Sigma   =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", sigma[k]);
        printf("\n      orc =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI2] gagnant==cls3 : %d/6 blocs | \u03a3 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    alz_ps_carry_free(st);
    free(buf);
    return 0;
}

/* ============================================================================
 * [A5.1 it3] Modelisation SNAPSHOT : at each call of scoring 0x414630, there class
 * copie l'arena-SNAPSHOT current in has arena LIVE jetable (13.13/14 " copie
 * snapshot->live at each call, rep movsb ") ; l'entrainement of has class not pollue
 * therefore NOT the others classes of the block. The snapshot n'advances only to  SINGLE FOIS by block,
 * entraine sure the stream of there class WINNING (argmin). There machine ctx (ebx/flag/ebp)
 * remainder GLOBAL by class and advances of all the block, abandon now not (from-plain).
 * C'is there granularity of persistance correcte attendue of a5-d3b. read-only, gated.
 * ========================================================================== */

/* Score has class sure has stream ctxs already genere, in l'arena has (m.has.j + rescale),
 * abandon optionnel contre *best_in. returns l'accunulateur 32 bits.
 * percost (optionnel, size n) : y writes the cost of each position (cs). */
static uint32_t ps_score_ctxs(alz_arena2d_t *a, const uint32_t *ctxs, uint32_t n,
                              uint32_t default_inc, uint32_t cold_first,
                              const uint32_t *best_in, uint32_t *pnpos,
                              uint32_t *percost)
{
    uint32_t i, acc = 0u;
    (void)default_inc;
    for (i = 0u; i < n; i++) {
        uint32_t ctx = ctxs[i];
        uint32_t row = ctx >> 8;
        uint32_t T, f, c, inc, cs;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];
        if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / T);
        else         cs = alz_score_proba_to_cost(cold_first)
                            + alz_score_proba_to_cost((c << 14) / T);
        acc += cs;
        if (percost) percost[i] = cs;
        if (best_in && acc > *best_in) { if (pnpos) *pnpos = i + 1u; return acc; }
        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, row);
    }
    if (pnpos) *pnpos = n;
    return acc;
}

/* --- briques of the producteur per-position argmin (13.729, UHA_PERPOS) ------------
 * cost READ-ONLY of has ctx in l'arena (mirror exact of the branch cost of
 * ps_score_ctxs, without mutation) ; and ps_learn = MAJ d'arena (mutation) mirror of
 * ps_score_ctxs. Indexation f=has->freq[ctx] (ctx no clampe) / total=row clampe,
 * identical has ps_score_ctxs for rester conforme au model validated. */
static uint32_t ps_cost_of(const alz_arena2d_t *a, uint32_t ctx, uint32_t cold_first)
{
    uint32_t row = ctx >> 8, T, f, c, cs;
    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
    T = a->total[row]; f = a->freq[ctx]; c = a->counter[row];
    if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / T);
    else         cs = alz_score_proba_to_cost(cold_first)
                        + alz_score_proba_to_cost((c << 14) / T);
    return cs;
}
static void ps_learn(alz_arena2d_t *a, uint32_t ctx)
{
    uint32_t row = ctx >> 8, T, f, c, inc;
    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
    T = a->total[row]; f = a->freq[ctx]; c = a->counter[row]; inc = a->promo[row];
    if (f == 0u) {
        a->freq[ctx]    = (uint16_t)inc;
        a->counter[row] = (uint16_t)(c + inc);
        a->total[row]   = (uint16_t)(T + 2u * inc);
    } else {
        a->freq[ctx]    = (uint16_t)(f + inc);
        a->total[row]   = (uint16_t)(T + inc);
    }
    if (!g_ps_no_inline_rescale && a->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, row);
}

/* rescale by line at the frontier (total>=0x4000), mirror of the reload/commit legacy. */
static void ps_rescale_all(alz_arena2d_t *a)
{
    uint32_t r; for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++)
        if (a->total[r] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, r);
}

int alz_parse_score_multitest3(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];   /* ebx, flag, ebp by class */
    uint32_t seed_cls = 0u;
    uint32_t maxlen;
    if (!fp) { printf("[PARSE-MULTI3] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI3] read fail\n"); return 1; }
    fclose(fp);
    snap = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!snap || !live) { free(buf); free(snap); free(live); printf("[PARSE-MULTI3] oom\n"); return 1; }
    alz_arena2d_init(snap, (uint16_t)32u);
    maxlen = 0u;
    for (b = 0; b < 6; b++) if (am_blk_len[b] > maxlen) maxlen = am_blk_len[b];
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        ctxs[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)maxlen);
    }
    printf("[PARSE-MULTI3] %s sz=%ld, 6 blocks, SNAPSHOT (per-class copy, snap advanced by winner)\n", path, sz);
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS], npos[ALZ_PS_NCLASS];
        uint32_t base = am_blk_pos[b], len = am_blk_len[b], order[ALZ_PS_NCLASS];
        uint32_t best = 0xffffffffu, winner = 0u, cnt = 0u, c;
        int exact = 1, wsmatch;
        double dev = 0.0;
        if ((long)(base + len) > sz) { printf("  blk%d OUT-OF-BOUNDS\n", b); break; }
        /* (1) generer the stream ctxs by class sure all the block (machine advances full). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++) {
            uint32_t i;
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, buf, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        }
        /* (2) order : seed (= winner block previous) d'abord, then ascending. */
        order[cnt++] = seed_cls;
        for (c = 0u; c < ALZ_PS_NCLASS; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) each class copie the snapshot in live, score, jette live. */
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cc = order[(uint32_t)k], s, np = 0;
            *live = *snap;
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, &np, NULL);
            sigma[cc] = s; npos[cc] = np;
            if (s < best) { best = s; winner = cc; }
        }
        /* (4) to advance the snapshot en entrainant the stream of there winning (full).
         * Override env UHA_PM3ADV=<0..4> for tester which class alimente the snapshot. */
        {
            uint32_t adv = winner;
            const char *ae = getenv("UHA_PM3ADV");
            if (ae && ae[0] >= '0' && ae[0] <= '4') adv = (uint32_t)(ae[0] - '0');
            ps_score_ctxs(snap, ctxs[adv], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        }
        seed_cls = winner;
        wsmatch = (winner == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
            if (am_blk_oracle[b][k]) dev += (double)sigma[k] / (double)am_blk_oracle[b][k] - 1.0;
        }
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d base=0x%05x len=0x%05x seed=cls%u : gagnant=cls%u (%s cls3) | %s | dev\u03a3 moy=%+.3f%% | npos=",
               b, base, len, winner, winner, wsmatch ? "==" : "!=",
               exact ? "==ORACLE" : ">=1 ecart", dev * 20.0);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" %u", npos[k]);
        printf("\n      \u03a3   =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", sigma[k]);
        printf("\n      orc =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI3] gagnant==cls3 : %d/6 blocs | \u03a3 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(snap); free(live); free(buf);
    return (sigma_ok == 6) ? 0 : 2;
}

/* ==========================================================================
 * [cost-literal-live SNAPSHOT dens - GATED by l'appelant alz.c UHA_COSTSNAP]
 * Reproduces there granularity SNAPSHOT of MULTI3 (it3) but fills `out[base+i]`
 * of the cost BY position of the class WINNING (argmin) of the block, for alimenter
 * g_lmin_dens of has cost d'arena of PARSE position-indexe PASSIF faithful to legacy
 * (validated +/-0,4 % under oracle t9-sim-arena), au lieu of the cold0-by-block (24 %).
 * Machine ctx (ebx/flag/ebp) threadee GLOBALEMENT by class via ps_ctx_step.
 * Pur : n'affecte no arena global, buffers local. returns 0 OK, <0 error. */
/* [GATED UHA_SNAPINC=<n>, default-OFF] Fixe the inc (promo) some lines of has arena.
 * 0 = not touche not (behavior actuel, promo issu d'alz_arena2d_init). No-regressif. */
static void ps_set_promo_all(alz_arena2d_t *a, uint32_t inc)
{
    uint32_t r;
    if (!a || inc == 0u) return;
    for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++) a->promo[r] = (uint16_t)inc;
}

int alz_ps_snapshot_percost(const uint8_t *g, uint32_t usize,
                            const uint32_t *blkpos, const uint32_t *blklen,
                            int nblk, uint32_t *out)
{
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t seed_cls = 0u, maxlen = 0u;
    uint32_t snap_inc = 0u;   /* [GATED UHA_SNAPINC] inc d'learning of the SNAPSHOT persiste */
    uint32_t snap_adv = 0xffffffffu;  /* [GATED UHA_SNAPADV=<0..4>] class which alimente l'avancement of the carry; sentinel=winner (default) */
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    {
        const char *se = getenv("UHA_SNAPINC");
        if (se && *se) snap_inc = (uint32_t)strtoul(se, NULL, 10);
    }
    {
        const char *ae = getenv("UHA_SNAPADV");
        if (ae && ae[0] >= '0' && ae[0] <= '4') snap_adv = (uint32_t)(ae[0] - '0');
    }
    /* [GATED UHA_PHASEFIX, default-OFF, 13.739] phase cls3 corrigee (abs+2)%3. */
    if (getenv("UHA_PHASEFIX")) g_ps_phasefix = 1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    snap = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!snap || !live) { free(snap); free(live); return -1; }
    alz_arena2d_init(snap, (uint16_t)32u);
    ps_set_promo_all(snap, snap_inc);   /* snapshot learns has inc=N if probe (otherwise 32) */
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        ctxs[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
        if (!ctxs[k]) { int j; for (j = 0; j < k; j++) free(ctxs[j]); free(snap); free(live); return -1; }
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], order[ALZ_PS_NCLASS];
        uint32_t best = 0xffffffffu, winner = 0u, cnt = 0u, c, np = 0;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) generer stream ctxs by class sure all the block (machine advances full). */
        /* [GATED UHA_SNAPCTXROW, default-OFF, 14.066] Seed : to advance the moteur CM live
         * once by position (cmlive_symrow advances+returns there line vecue) and memoriser
         * the lines, then the injecter in ctxs[] (au lieu of the delta2D). Reset if base==0. */
        static uint32_t s_sx_buf[ALZ_ARENA2D_MAX_ROW * 64u];
        static int s_sx_on = -1, s_sx_ready = 0;
        if (s_sx_on < 0) s_sx_on = getenv("UHA_SNAPCTXROW") ? 1 : 0;
        if (base == 0u && s_sx_on) { alz_ps_cmlive_reset(0u); s_sx_ready = 0; }
        if (s_sx_on) {
            uint32_t j;
            for (j = 0u; j < len && (base + j) < (uint32_t)(ALZ_ARENA2D_MAX_ROW * 64u); j++) {
                uint32_t fr, fs;
                if (alz_ps_cmlive_symrow(g, base + j, 0u, &fr, &fs) == 0) {
                    if (fr >= ALZ_ARENA2D_MAX_ROW) fr = ALZ_ARENA2D_MAX_ROW - 1u;
                    s_sx_buf[base + j] = fr; s_sx_ready = 1;
                }
            }
        }
        for (c = 0u; c < ALZ_PS_NCLASS; c++) {
            uint32_t i;
            for (i = 0u; i < len; i++) {
                uint32_t cx = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
                /* [GATED UHA_PHASEFIX] row cls3 : phase = (abs+2)%3 (au lieu of ebp%3). */
                if (g_ps_phasefix && c == 3u) {
                    uint32_t e = (cx >> 8) & 0x1fu;
                    e += (((base + i + 2u) % 3u) << 5);
                    cx = (e << 8) | (cx & 0xffu);
                }
                /* [GATED UHA_SNAPCTXROW, default-OFF, 14.064] To replace there line
                 * delta2D by there line `ctx` VECUE (moteur CM live), mirror of the scan
                 * legacy (row=(ctx>>8)&0x1ff sure the recon). DefautOFF = delta2D unchanged. */
                if (s_sx_on && s_sx_ready && (base + i) < (ALZ_ARENA2D_MAX_ROW * 64u)) {
                    cx = (s_sx_buf[base + i] << 8) | (cx & 0xffu);
                }
                ctxs[c][i] = cx;
            }
        }
        /* (2) order : seed (winner block previous) d'abord, then ascending. */
        order[cnt++] = seed_cls;
        for (c = 0u; c < ALZ_PS_NCLASS; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) argmin : each class copie snap->live, score (abandon precoce). */
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cc = order[(uint32_t)k], s;
            *live = *snap;
            ps_set_promo_all(live, 32u);   /* scorer LIVE always inc=32 (13.270) */
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, &np, NULL);
            if (s < best) { best = s; winner = cc; }
        }
        /* (4) RE-score there winning sure copie fraiche of snap (without abandon) en
         * ecrivant the cost BY position in out[base..base+len). */
        *live = *snap;
        ps_set_promo_all(live, 32u);   /* scorer LIVE always inc=32 (out dens) */
        ps_score_ctxs(live, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
        /* (5) to advance the snapshot en entrainant the stream of the winner (full).
         * [GATED UHA_SNAPADV] : surcharge which class alimente the carry cross-block,
         * without toucher au dens by block (out[] remainder sure `winner`). Default = winner. */
        /* [GATED UHA_SNAPLITMASK=<maskfile>, default-OFF, 14.017] Porter the MASTER sure the
         * STREAM EMIS (literals single) au lieu of the rescan full-ctx : mirror of the update
         * of the master by l'emission reelle (block0 emis == legacy because firstdiv>12544). */
        {
            static uint8_t *s_slm = NULL; static int s_slm_load = 0; static uint32_t s_slm_n = 0u;
            if (!s_slm_load) {
                const char *mk = getenv("UHA_SNAPLITMASK");
                if (mk && *mk) {
                    FILE *mf = fopen(mk, "r");
                    s_slm_n = usize;
                    if (mf) { s_slm = (uint8_t *) calloc(usize ? usize : 1u, 1u); s_slm_load = 1;
                        if (s_slm) { long v; while (fscanf(mf, "%ld", &v) == 1)
                            if (v >= 0 && (uint32_t)v < usize) s_slm[(uint32_t)v] = 1u; }
                        fclose(mf);
                    }
                }
                s_slm_load = 1;
            }
            if (s_slm && s_slm_n == usize) {
                uint32_t i;
                for (i = 0u; i < len; i++)
                    if (s_slm[base + i])
                        (void) ps_score_ctxs(snap, ctxs[(snap_adv <= 4u) ? snap_adv : winner] + i,
                                             1u, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
            } else
                ps_score_ctxs(snap, ctxs[(snap_adv <= 4u) ? snap_adv : winner],
                              len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        }
        seed_cls = winner;
    }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(snap); free(live);
    return 0;
}

/* ==========================================================================
 * [13.729 GATED UHA_PERPOS, default-OFF] Producteur dens per-position argmin.
 * the legacy engine selects THERE class by position (argmin 5 classes 0x413ea0), not
 * by block. model : Has arena global continue + machines ctx threadees by class
 * ; at each position i, cost READ-ONLY some 5 ctx (by class) in l'arena,
 * winner = argmin, dens[i] = min, THEN learning (ps_learn) of the ctx of the winner
 * ONLY. learning DENSE (all positions) in this 1 variante (there
 * sparse by-literal-emis remainder has coupler au parse). Pur, buffers local. 0 OK <0 err. */
int alz_ps_perpos_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, uint32_t *out)
{
    alz_arena2d_t *a;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t maxlen = 0u;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    a = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!a) return -1;
    alz_arena2d_init(a, (uint16_t)32u);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        ctxs[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
        if (!ctxs[k]) { int j; for (j = 0; j < k; j++) free(ctxs[j]); free(a); return -1; }
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i, c;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) generer the stream ctx of each class sure all the block (machines advance full). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++)
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        /* (2) by position : argmin some 5 costs of class in l'arena current ;
         *     dens = min ; then apprendre the ctx of the winner (mutates arena). */
        for (i = 0u; i < len; i++) {
            uint32_t best = 0xffffffffu, win = 0u, cs;
            for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                cs = ps_cost_of(a, ctxs[c][i], ALZ_PS_COLD0);
                if (cs < best) { best = cs; win = c; }
            }
            out[base + i] = best;
            ps_learn(a, ctxs[win][i]);
        }
    }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(a);
    return 0;
}

/* [GATED UHA_SNAPWALK, validation reading-single] Producteur `dens` faithful au model
 * TWO-ARENAS (memory d2229f89, 13.270/271) : the snapshot PERSISTE n'advances only to the 
 * positions LITERAL EMISES (is_lit[abs]==1) has inc=16 (pass EMISSION sparse), NOT dense ;
 * dens[pos] = scorer DENSE (copie live of the snapshot, inc=32) au stream cls3 (winner
 * universel 13.593). Machine ctx cls3 GLOBAL threadee cross-blocks. is_lit size
 * usize (0/1). returns 0 OK, <0 error. ZERO effet sure l'encoding (path gated). */
int alz_ps_snapshot_percost_sparse(const uint8_t *g, uint32_t usize,
                                   const uint32_t *blkpos, const uint32_t *blklen,
                                   int nblk, const uint8_t *is_lit, uint32_t *out)
{
    alz_arena2d_t *snap, *live;
    uint32_t *ctx;
    uint32_t mm[3] = {0u, 0u, 0u};
    uint32_t maxlen = 0u;
    int b;

    if (!g || !blkpos || !blklen || !is_lit || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    snap = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    ctx  = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!snap || !live || !ctx) { free(snap); free(live); free(ctx); return -1; }
    alz_arena2d_init(snap, (uint16_t)16u);   /* SNAPSHOT learns has inc=16 (13.271) */
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) stream ctx cls3 sure all the block (machine GLOBAL advances full). */
        for (i = 0u; i < len; i++)
            ctx[i] = ps_ctx_step(3u, g, base + i, &mm[0], &mm[1], &mm[2]);
        /* (2) dens[pos] = scorer dense (live copie snap, inc=32) writes in out. */
        *live = *snap;
        ps_set_promo_all(live, 32u);
        ps_score_ctxs(live, ctx, len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
        /* (3) to advance the SNAPSHOT sure the single positions LITERAL emes, inc=16. */
        for (i = 0u; i < len; i++) {
            uint32_t c = ctx[i], row = c >> 8;
            if (!is_lit[base + i]) continue;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            (void) alz_arena2d_score(snap, row, c & 0xffu, NULL);
        }
    }
    free(snap); free(live); free(ctx);
    return 0;
}

/* ==========================================================================
 * [13.723 GATED UHA_EMIPROD, default-OFF, FRONTIER emission-walk-producer]
 * model FAITHFUL decode : there pre-pass `0x414630` is READ-ONLY vs master (restore
 * `rep movs` master->working by call, no store towards master) ; the master is
 * advances ONLY by the LIVE `0x415ab0` which LEARNS by LITERAL EMIS (sparse).
 * Producteur : by block, W = copie(master M) then scan DENSE intra-block cls3
 * (score+learn in W) => `out[i]` = cost fige lu by the decider ; THEN to advance M
 * en n'apprenant only to the  positions `is_lit` of the block (nothing sure the matchs). Machine
 * cls3 relative-block (seed ebp=1) ALIGNEE between W (reading) and M (write) for
 * that the carry tombe in the same cellules. Pur, buffers local. 0 OK, <0 error. */

/* [GATED UHA_CM_WIRE, 13.796] delta/base section-relatifs (sentinelle 0x80 before `base`). */
static int32_t ps_q(const uint8_t *g, long base, long k)
{
    if (k < base) return 0;
    return (int32_t)g[k] - ((k >= base + 1) ? (int32_t)g[k - 1] : 0x80);
}
static int32_t ps_b(const uint8_t *g, long base, long k)
{
    if (k < base) return 0;
    return (int32_t)g[k] - 0x80;
}

/* [GATED UHA_CM_WIRE, 13.796] Advances faithful of the master sure there law image sym->row.
 * Deroule l'engine CM (alz_arena+alz_arb+alz_cm) DENSEMENT by rc sure there section
 * [base,base+len) and reproduces EXACTEMENT the harnais validated _scratch/cm_closed.c
 * (sym 12700/12700, idx/ref/b8 15000/15000). master_learn(M, relrow=aff, sym)
 * ONLY to the literals. Reset engine+registres+flag at the frontier of section. */
static void ps_cmwire_advance_master(alz_arena2d_t *M, const uint8_t *g,
                                     uint32_t base, uint32_t len,
                                     const uint8_t *is_lit, uint32_t usize)
{
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u}; /* tbl 0x437af8/idx */
    alz_cm_learner L; memset(&L, 0, sizeof L);
    alz_arena A; alz_arena_init(&A);
    alz_arb   R; alz_arb_init(&R);
    uint32_t rf70 = 0xffffffffu, rf74 = 0xffffffffu, rf78 = 0xffffffffu; /* 13.796 reset section */
    int rflag = 0, last_prev_idx_for_P = 0;
    int32_t prev_rh_sim = 0;
    uint32_t i;
    for (i = 0; i < len; i++) {
        uint32_t abs = base + i;
        uint8_t b_cur   = g[abs];
        uint8_t b_prev  = (i >= 1u) ? g[abs - 1u] : 0x80u;
        uint8_t b_prev2 = (i >= 2u) ? g[abs - 2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur  - 0x80;
        int32_t base_p1 = ps_b(g, (long)base, (long)abs - 1);
        int32_t base_p2 = ps_b(g, (long)base, (long)abs - 2);
        int32_t dl      = ps_q(g, (long)base, (long)abs);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref_arb = ps_q(g, (long)base, (long)abs - ref_prev);
        int32_t dr_b8_arb  = ps_q(g, (long)base, (long)abs - b8_prev);
        int32_t row_hash_model = prev_rh_sim;
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & abs) == 0u);
        A.line = abs;
        alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = abs;
        alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref_arb, dr_b8_arb, row_hash_model);
        uint32_t idx_i = R.idx;
        int32_t dr_ref_learn = ps_q(g, (long)base, (long)(abs + 1) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_ref_learn);
        int32_t rh_sim = L.prev_dot_full;
        /* law sym->row (13.796) : taps en domaine base, ref/b8 BEFORE update, idx lag. */
        {
            uint32_t taps6[6];
            uint8_t vp1 = (uint8_t)(base_p1);
            uint8_t vp2 = (uint8_t)(base_p2);
            taps6[0] = 0;
            taps6[1] = vp1;
            taps6[2] = (uint8_t)(2 * (int32_t)vp1 - (int32_t)vp2);
            taps6[3] = (uint8_t)row_hash_model;
            taps6[4] = (uint8_t)A.dr[(abs - (uint32_t)ref_prev) & 0x7fu];
            taps6[5] = (uint8_t)A.dr[(abs - (uint32_t)b8_prev)  & 0x7fu];
            int ip = last_prev_idx_for_P;
            uint32_t Pcur = ((taps6[ip % 6u] & 0xffu) + ((ip >= 4) ? (uint32_t)vp1 : 0u) + 0x80u) & 0xffu;
            uint32_t Pprev = (i == 0u) ? 0u : Pcur;   /* 1ere line section : [0x45ecbf]=reset 0 */
            uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
            uint8_t sym = rflag ? (uint8_t)(0u - (uint32_t)d) : d;
            rf70 = (rf70 << 8) | sym;
            rf74 = (rf74 << 8) + ALZ_REG_T1[sym];
            rf78 = (rf78 << 8) + ALZ_REG_T2[sym];
            if (sym >= 0x80u) rflag ^= 1;
            uint32_t aff = (rf70 == 0u) ? 1u : (rf74 == 0u) ? 2u : (rf78 == 0u) ? 3u : 0u;
            if (is_lit[abs]) {
                /* [GATED UHA_CMROWHASH, default-OFF, ARENA_TASK16] index of the master = row_hash_cm
                 * (0x44d8d8 = L->prev_dot_full, & 0x1ff) - there LAW validated M11, au lieu of
                 * `aff` (band 4lines). DefaultOFF = behavior cmwire unchanged (aff). */
                if (getenv("UHA_CMROWHASH") != NULL)
                    alz_arena2d_master_learn(M, ((uint32_t)rh_sim) & 0x1FFu, sym);
                else
                    alz_arena2d_master_learn(M, aff, sym);   /* relrow=aff (band 4-lines cls5), sym dir-flippe */
            }
            last_prev_idx_for_P = (int)idx_i;
        }
        prev_rh_sim = rh_sim;
    }
    (void)usize;
}

/* ==========================================================================
 * [ARENA_TASK16 - GATED default-OFF] alz_ps_livewalk_cm : the MASTER D'EMISSION indexe
 * by `row_hash_cm` (0x44d8d8 = alz_cm prev_dot_full, validated 83/83 13.115). arena P
 * SEPAREE (not touche NOT the path EMIPROD/bloc0). Deroule the moteur CM densement sure
 * [0,usize) ; to the LITERALS of the bloc0 (q<0x3100) learns P[row_hash_cm&0x1ff][sym]
 * (cold/warm +32, rescale @0x4000) = the PERM d'emission legacy. Then, if `out` no NULL,
 * recharge W:=P and score DENSE gen_ctxs(3) sure [0x3100,usize) -> cost pre-learn publie.
 * Digeste has fingerprint P (rows 37/68) sure stderr if UHA_LIVEWALK_STATS (validation vs
 * dumps GT : freq[68]=7 cell. Sigma~11130 +/-2..+/-5 ; freq[37]=0). returns 0. */
int alz_ps_livewalk_cm(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                       uint32_t from, uint32_t *out)
{
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u};
    alz_cm_learner L; alz_arena A; alz_arb R;
    alz_arena2d_t *P;
    uint32_t rf70=0xffffffffu, rf74=0xffffffffu, rf78=0xffffffffu;
    int rflag=0, last_prev_idx=0; int32_t prev_rh=0;
    uint32_t i, stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    if (!g || !is_lit || usize > 0x10000u) return -1;
    memset(&L,0,sizeof L); alz_arena_init(&A); alz_arb_init(&R);
    P = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t));
    if (!P) return -1;
    alz_arena2d_init(P, 32u);
    /* (1)+(2) moteur CM (conduiteur EXACT cmwire, section base=0) ; learn P to the
     * literals of the bloc0 (i<0x3100), row = row_hash_cm(prev_dot_full)&0x1ff. */
    for (i = 0; i < usize; i++) {
        uint8_t b_cur = g[i];
        uint8_t b_prev  = (i>=1u)? g[i-1u] : 0x80u;
        uint8_t b_prev2 = (i>=2u)? g[i-2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur - 0x80;
        int32_t base_p1 = ps_b(g, 0L, (long)i - 1);
        int32_t base_p2 = ps_b(g, 0L, (long)i - 2);
        int32_t dl      = ps_q(g, 0L, (long)i);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref_arb = ps_q(g, 0L, (long)i - ref_prev);
        int32_t dr_b8_arb  = ps_q(g, 0L, (long)i - b8_prev);
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & i) == 0u);
        A.line = i; alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = i; alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref_arb, dr_b8_arb, prev_rh);
        uint32_t idx_i = R.idx;
        int32_t dr_ref_learn = ps_q(g, 0L, (long)(i + 1u) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_ref_learn);
        int32_t rh = L.prev_dot_full;
        /* sym = dir-flip(b_cur - P) via taps (idem cmwire). */
        {
            uint32_t taps6[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
            taps6[0]=0; taps6[1]=vp1; taps6[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
            taps6[3]=(uint8_t)prev_rh;
            taps6[4]=(uint8_t)A.dr[(i-(uint32_t)ref_prev)&0x7fu];
            taps6[5]=(uint8_t)A.dr[(i-(uint32_t)b8_prev)&0x7fu];
            int ip = last_prev_idx;
            uint32_t Pcur = ((taps6[ip%6u]&0xffu) + ((ip>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
            uint32_t Pprev = (i==0u)?0u:Pcur;
            uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
            uint8_t sym = rflag ? (uint8_t)(0u-(uint32_t)d) : d;
            rf70=(rf70<<8)|sym; rf74=(rf74<<8)+ALZ_REG_T1[sym]; rf78=(rf78<<8)+ALZ_REG_T2[sym];
            if (sym>=0x80u) rflag^=1;
            if (i < 0x3100u && is_lit[i])              /* PERM d'emission = literals bloc0 */
                alz_arena2d_master_learn(P, ((uint32_t)rh)&0x1FFu, sym);
            last_prev_idx = (int)idx_i;
        }
        prev_rh = rh;
    }
    if (stats) {
        uint32_t c, s68=0,s37=0,n68=0,n37=0;
        for (c=0;c<256u;c++){ if(P->freq[(68u<<8)+c]){s68+=P->freq[(68u<<8)+c];n68++;} if(P->freq[(37u<<8)+c]){s37+=P->freq[(37u<<8)+c];n37++;} }
        fprintf(stderr, "[LWC] P-perm@b1 freq68 SUM=%u nz=%u | freq37 SUM=%u nz=%u\n",
                (unsigned)s68,(unsigned)n68,(unsigned)s37,(unsigned)n37);
    }
    /* (4) reload W:=P, scan dense gen_ctxs(3) sure block>=from -> cost pre-learn. */
    if (out) {
        uint32_t *ctx3 = (uint32_t*)malloc(sizeof(uint32_t)*(size_t)usize);
        alz_arena2d_t W;
        if (ctx3) {
            alz_ps_gen_ctxs(3u, g, usize, ctx3);
            W = *P;
            for (i = from; i < usize; i++) {
                uint32_t sc = ctx3[i], row = (sc>>8)&0x1FFu, sym = sc&0xffu, T=0u, proba;
                if (row>=ALZ_ARENA2D_MAX_ROW) row=ALZ_ARENA2D_MAX_ROW-1u;
                proba = alz_arena2d_score(&W, row, sym, &T);
                out[i] = alz_score_proba_to_cost(proba);
            }
            free(ctx3);
        }
    }
    free(P);
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16/17 - GATED defautOFF, side B] alz_ps_livewalk_dual : producteur
 * DOUBLEBUFFER `P`(PERM/master, persiste) / `H`(HOT/working, recharge by block),
 * contrat `DUAL_INTEGRATION.md`. 1 RELOAD `H:=copy(P)` by block ; SCORAGE DENSE
 * `gen_ctxs(3)` in H (score+learn, rescale @0x4000) -> cost PRElearn writes in
 * `out` if `base>=from` (bloc0 keeps EMIPROD). 2 EMISSIONLEARN of the P = **NOT
 * D'INJECTION** (#17 fournit row/subset/increment/coldvswarm) ; STUB baseline =
 * learn to the LITERALS sure row `gen_ctxs(3)` ( EMIPROD/16685). Probe _STATS :
 * fingerprint freq[68]/[37] of P (target 11130/0). returns 0 ; zero effet out gate. */
int alz_ps_livewalk_dual(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                         uint32_t from, uint32_t *out)
{
    static const uint32_t bp[6] = {0x0000u,0x3100u,0x620cu,0x931cu,0xc4ffu,0xff00u};
    static const uint32_t bl[6] = {0x3100u,0x3100u,0x3100u,0x3100u,0x3a01u,0x100u};
    alz_arena2d_t *P, *H;
    uint32_t *ctx3, *tmp;
    uint32_t i, b, c, stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    int feed_used = 0;
    int brscale = getenv("UHA_LIVEWALK_BOUNDRESCALE") ? 1 : 0;
    g_ps_no_inline_rescale = brscale;   /* decroche the rescale of the learn if boundaryrescale ON */
    /* feed parblock (contrat #17) : evenements stockes with leur block (marqueur `#B <n>`,
     * invisible for dual_sim which ignores the lines '#'). */
    int fcap = 0, fn = 0; int *fblk = NULL, *frow = NULL, *fsym = NULL, *flrn = NULL;
    uint32_t rctx = 0u;   /* [RECON] ctx roulant 17 bits continu sure all the file */
    if (!g || !is_lit || !out || usize > 0x10000u) return -1;
    P = (alz_arena2d_t*) malloc(sizeof(alz_arena2d_t));
    H = (alz_arena2d_t*) malloc(sizeof(alz_arena2d_t));
    ctx3 = (uint32_t*) malloc(sizeof(uint32_t)*(size_t)usize);
    tmp  = (uint32_t*) malloc(sizeof(uint32_t)*(size_t)0x3a01u);
    if (!P||!H||!ctx3||!tmp){ free(P);free(H);free(ctx3);free(tmp); return -1; }
    alz_arena2d_init(P, 32u);
    alz_ps_gen_ctxs(3u, g, usize, ctx3);
    /* [CONTRAT #17] UHA_LIVEWALK_FEED=<file> : feed d'evenements d'emission by block.
     * lines : `#B <n>` = currentblock ; `<row> <sym> [learn]` = evenement (2 now 3 fields).
     * Retrocompatible dual_sim (which ignores `#`). P recoit the evenements of the block b AFTER the
     * traitement of b -> at the input cls3 of b+1, P = emission some blocks 0..b (oracle exact). */
    {
        const char *ff = getenv("UHA_LIVEWALK_FEED");
        if (ff && *ff) {
            FILE *fp = fopen(ff, "r");
            if (fp) {
                char ln[128]; int curblk = 0;
                fcap = 65536; fblk=malloc(sizeof(int)*fcap); frow=malloc(sizeof(int)*fcap);
                fsym=malloc(sizeof(int)*fcap); flrn=malloc(sizeof(int)*fcap);
                feed_used = 1;
                while (fn < fcap && fgets(ln, sizeof ln, fp)) {
                    if (ln[0]=='\n') continue;
                    if (ln[0]=='#') { int nb; if (sscanf(ln, "#B %d", &nb)==1) curblk=nb; continue; }
                    int row, sym, lrn = 1, k;
                    k = sscanf(ln, "%d %d %d", &row, &sym, &lrn);
                    if (k < 2) continue;
                    if (row < 0 || row >= (int)ALZ_ARENA2D_MAX_ROW || sym < 0 || sym > 255) continue;
                    fblk[fn]=curblk; frow[fn]=row; fsym[fn]=sym; flrn[fn]=lrn?1:0; fn++;
                }
                fclose(fp);
            }
        }
    }
    for (b = 0; b < 6; b++) {
        uint32_t base = bp[b], len = bl[b];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        if (stats && base >= from) {
            uint32_t s68=0,n68=0,s37=0,n37=0;
            for(c=0;c<256u;c++){ if(P->freq[(68u<<8)+c]){s68+=P->freq[(68u<<8)+c];n68++;} if(P->freq[(37u<<8)+c]){s37+=P->freq[(37u<<8)+c];n37++;} }
            fprintf(stderr, "[DUAL] reload@0x%05x P freq68 SUM=%u nz=%u | freq37 SUM=%u nz=%u\n",
                    (unsigned)base,(unsigned)s68,(unsigned)n68,(unsigned)s37,(unsigned)n37);
        }
        /* [B#17 DIFF] dump l'state COMPLETE of P (master) at the input of the 1er block>=from (=cls3 b1)
         * -> "row total freqsum nonzero" by line, for diff automatique contre the bitmap of
         * reference dumpe by #17 has 0x413ea0. Gated UHA_LIVEWALK_DUMPOUT=<file>, 1 single fois. */
        {
            const char *dop = getenv("UHA_LIVEWALK_DUMPOUT");
            static int dumped_once = 0;
            if (dop && *dop && base >= from && !dumped_once) {
                FILE *dp = fopen(dop, "w");
                dumped_once = 1;
                if (dp) {
                    uint32_t rr;
                    fprintf(dp, "# row total freqsum nonzero (P master @entry 0x%05x)\n", (unsigned)base);
                    for (rr = 0u; rr < ALZ_ARENA2D_MAX_ROW; rr++) {
                        uint32_t cc, fsum = 0u, fnz = 0u;
                        for (cc = 0u; cc < 256u; cc++) { uint32_t fq = P->freq[(rr<<8)|cc]; if (fq) { fsum += fq; fnz++; } }
                        fprintf(dp, "%u\t%u\t%u\t%u\n", (unsigned)rr, (unsigned)P->total[rr], (unsigned)fsum, (unsigned)fnz);
                    }
                    fclose(dp);
                }
            }
        }
        /* 1 RELOAD HOT := PERM(P) ; SCORAGE dense gen_ctxs(3) in H -> cost pre-learn */
        if (brscale && b > 0u) ps_rescale_all(P);   /* [BOUNDRESCALE] rescale by column at the frontier (cadence commit legacy) */
        *H = *P;
        (void) ps_score_ctxs(H, ctx3 + base, len, 32u, ALZ_PS_COLD0, NULL, NULL, tmp);
        if (base >= from) memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        /* [validation B, gated UHA_LIVEWALK_TRAJ, out `out`] replays the scan bloc1 sure has copie
         * of P and trace H->total[68]/[37] by position -> confront `leg_b1_tot68` (test of bout
         * en bout of the consommateur, n'affecte NOT there output). */
        if (getenv("UHA_LIVEWALK_TRAJ") && base == from && ctx3) {
            alz_arena2d_t H2 = *P; uint32_t jj;
            for (jj = 0u; jj < len && jj < 1300u; jj++) {
                uint32_t sc = ctx3[base + jj], rw = (sc >> 8) & 0x1FFu, dl = sc & 0xffu, T0;
                if (rw >= ALZ_ARENA2D_MAX_ROW) rw = ALZ_ARENA2D_MAX_ROW - 1u;
                T0 = H2.total[68u];
                (void) alz_arena2d_score(&H2, rw, dl, NULL);          /* score+learn+rescale */
                fprintf(stderr, "[DUALTRAJ] %u\t%u\t%u\t%u\t%u\n", (unsigned)jj,
                        (unsigned)(base + jj), (unsigned)T0, (unsigned)H2.total[68u], (unsigned)H2.total[37u]);
            }
        }
        /* 2 EMISSIONLEARN of the P  >>> DUAL_LAW (#17) <<<  applies AFTER the scan of the block b,
         * therefore P reflete l'emission some blocks 0..b at the input cls3 of b+1. SOURCE = feed #17
         * (by block) if fourni ; otherwise STUB baseline = literals sure row gen_ctxs(3). */
        if (feed_used) {
            int e;
            for (e = 0; e < fn; e++)
                if (fblk[e] == (int)b && flrn[e]) ps_learn(P, (frow[e] << 8) | fsym[e]);
        } else if (getenv("UHA_LIVEWALK_RECON") != NULL) {
            /* [TEST B] law reconlag (as s_acl.mem of the clone) but DENSE (all positions).
             * erow = (rctx>>8)&0x1ff, rctx=((rctx<<8)|g[q])&0x1FFFF ; sym = g[q].
             * Test : dense reconlag chauffetil row68 towards 11130 en epargnant row37 ? */
            for (i = 0u; i < len; i++) {
                uint32_t q = base + i, erow;
                rctx = ((rctx << 8) | (g[q] & 0xffu)) & 0x1FFFFu;
                erow = (rctx >> 8) & 0x1FFu;
                ps_learn(P, (erow << 8) | (g[q] & 0xffu));
            }
        } else if (getenv("UHA_LIVEWALK_CMROW") != NULL) {
            /* [TEST B] prime P via the moteur CM (row_hash_cm&0x1ff if UHA_CMROWHASH, otherwise aff) ;
             * teste if there law of row CM reproduces the bitmap oracle. */
            ps_cmwire_advance_master(P, g, base, len, is_lit, usize);
        } else if (getenv("UHA_LIVEWALK_ALLCLASS") != NULL) {
            /* [TEST B] hypothese : the master accumule the 5 PASSES of class (each position
             * contribue au row of each class), not only cls3. Recharge carry mm by class. */
            static uint32_t mm5[ALZ_PS_NCLASS][3] = {{0,0,1},{0,0,1},{0,0,1},{0,0,1},{0,0,1}};
            uint32_t cc;
            int only_lit = getenv("UHA_LIVEWALK_ALLCLASS_LIT") ? 1 : 0;
            const char *cl_env = getenv("UHA_LIVEWALK_CLASS");
            int single_class = cl_env ? atoi(cl_env) : -1;   /* -1 = the 5 classes ; otherwise Has single */
            for (cc = 0u; cc < ALZ_PS_NCLASS; cc++) {
                if (single_class >= 0 && (int)cc != single_class) continue;
                for (i = 0u; i < len; i++) {
                    uint32_t sc = ps_ctx_step(cc, g, base + i, &mm5[cc][0], &mm5[cc][1], &mm5[cc][2]);
                    uint32_t row = (sc >> 8) & 0x1FFu;
                    if (only_lit && !is_lit[base + i]) continue;   /* ctx advances, n'learns only to the  literals emis */
                    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
                    ps_learn(P, (row << 8) | (sc & 0xffu));
                }
            }
        } else { int dense_stub = getenv("UHA_LIVEWALK_DENSESTUB") ? 1 : 0; for (i = 0u; i < len; i++) {
            uint32_t q = base + i, sc = ctx3[q], row = (sc >> 8) & 0x1FFu;
            if (!dense_stub && !is_lit[q]) continue;   /* default: literals; DENSESTUB: all positions */
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            ps_learn(P, (row << 8) | (sc & 0xffu));
        } }
    }
    free(fblk); free(frow); free(fsym); free(flrn);
    free(P); free(H); free(ctx3); free(tmp);
    return 0;
}


/* [GATED UHA_CM_WIRE, 13.798] Moteur CM persistant INCREMENTAL for l'arena LIVE
 * (acclive_event_once -> alz_arena_c4). Reproduces there law validated cm_closed (sym 100 %)
 * position by position (rc dense), for has section donnee (sec_start). The caller
 * (acclive) calls reset at each frontier of section and symrow for each pos.
 * returns row_abs = row_base + aff and sym = dirflip(valueP). State module-static. */
typedef struct {
    int      started;
    uint32_t done;        /* last rc advances (inclus) */
    long     sec;         /* start of section current */
    alz_cm_learner L; alz_arena A; alz_arb R;
    uint32_t rf70, rf74, rf78; int rflag, last_prev_idx; int32_t prev_rh;
    uint32_t last_sym, last_aff;
} ps_cmlive_t;
static ps_cmlive_t s_cml;
static const uint32_t PS_MASKW[6] = {127u,127u,127u,127u,7u,3u}; /* tbl 0x437af8/idx */

void alz_ps_cmlive_reset(uint32_t sec_start)
{
    memset(&s_cml, 0, sizeof s_cml);
    alz_arena_init(&s_cml.A);
    alz_arb_init(&s_cml.R);
    s_cml.rf70 = s_cml.rf74 = s_cml.rf78 = 0xffffffffu;   /* 13.796 reset registres section */
    s_cml.sec = (long)sec_start;
    s_cml.done = sec_start > 0u ? sec_start - 1u : 0u;
    s_cml.started = 1;
}

static void ps_cmlive_step(const uint8_t *g, uint32_t k)
{
    long base = s_cml.sec;
    uint32_t i = k - (uint32_t)base;
    uint8_t b_cur   = g[k];
    uint8_t b_prev  = (i >= 1u) ? g[k - 1u] : 0x80u;
    uint8_t b_prev2 = (i >= 2u) ? g[k - 2u] : 0x80u;
    int32_t base_i  = (int32_t)b_cur - 0x80;
    int32_t base_p1 = ps_b(g, base, (long)k - 1);
    int32_t base_p2 = ps_b(g, base, (long)k - 2);
    int32_t dl      = ps_q(g, base, (long)k);
    int32_t ref_prev = (int32_t)s_cml.A.ref, b8_prev = (int32_t)s_cml.A.b8;
    int32_t dr_ref = ps_q(g, base, (long)k - ref_prev);
    int32_t dr_b8  = ps_q(g, base, (long)k - b8_prev);
    int32_t rh = s_cml.prev_rh;
    uint32_t idx_gate = s_cml.R.idx;
    int entered = ((PS_MASKW[idx_gate % 6u] & k) == 0u);
    s_cml.A.line = k; alz_arena_step(&s_cml.A, b_cur, b_prev, entered);
    s_cml.R.line = k;
    alz_arb_predict(&s_cml.R, base_i, base_p1, base_p2, dl, dr_ref, dr_b8, rh);
    uint32_t idx_i = s_cml.R.idx;
    int32_t dr_learn = ps_q(g, base, (long)(k + 1) - (int32_t)s_cml.A.ref);
    alz_cm_learn_byte(&s_cml.L, b_cur, b_prev, b_prev2, dr_learn);
    uint32_t taps6[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
    taps6[0]=0; taps6[1]=vp1;
    taps6[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
    taps6[3]=(uint8_t)rh;
    taps6[4]=(uint8_t)s_cml.A.dr[(k-(uint32_t)ref_prev)&0x7fu];
    taps6[5]=(uint8_t)s_cml.A.dr[(k-(uint32_t)b8_prev )&0x7fu];
    int ip = s_cml.last_prev_idx;
    uint32_t Pcur = ((taps6[ip%6u]&0xffu) + ((ip>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
    uint32_t Pprev = (i == 0u) ? 0u : Pcur;
    uint8_t d = (uint8_t)(b_cur - Pprev);
    uint8_t sym = s_cml.rflag ? (uint8_t)(0u-(uint32_t)d) : d;
    s_cml.rf70 = (s_cml.rf70<<8)|sym;
    s_cml.rf74 = (s_cml.rf74<<8) + ALZ_REG_T1[sym];
    s_cml.rf78 = (s_cml.rf78<<8) + ALZ_REG_T2[sym];
    if (sym >= 0x80u) s_cml.rflag ^= 1;
    s_cml.last_sym = sym;
    s_cml.last_aff = (s_cml.rf70==0u)?1u:(s_cml.rf74==0u)?2u:(s_cml.rf78==0u)?3u:0u;
    s_cml.last_prev_idx = (int)idx_i;
    s_cml.prev_rh = s_cml.L.prev_dot_full;
    s_cml.done = k;
}

int alz_ps_cmlive_symrow(const uint8_t *g, uint32_t pos, uint32_t row_base,
                         uint32_t *row_abs, uint32_t *sym_out)
{
    uint32_t k;
    if (!s_cml.started)
        return -1;
    if ((long)pos < s_cml.sec)
        return -1;                        /* out section current without reset */
    for (k = s_cml.done + 1u; k <= pos; k++)
        ps_cmlive_step(g, k);
    *row_abs = row_base + s_cml.last_aff;
    *sym_out = s_cml.last_sym;
    return 0;
}

/* [GATED UHA_CM_EMISS, default-OFF, 13.909] returns there line d'emission = window
 * glissante of the registre `rf70` (roule by `ps_cmlive_step`, `rf70=(rf70<<8|sym)`),
 * analogue structurel of the `ctx` `[0x45dca8]` of legacy : `row=(rf70>>8)&0x1ff`. */
int alz_ps_cmlive_ctxrow(const uint8_t *g, uint32_t pos, uint32_t *row_out, uint32_t *sym_out)
{
    uint32_t k;
    if (!s_cml.started || (long)pos < s_cml.sec)
        return -1;
    for (k = s_cml.done + 1u; k <= pos; k++)
        ps_cmlive_step(g, k);
    *row_out = (s_cml.rf70 >> 8) & 0x1FFu;
    *sym_out = s_cml.last_sym;
    return 0;
}

/* [GATED UHA_CM_EMCARRY, default-OFF, 13.896/897] Carry MASTER d'emission (mecanisme
 * validated m13 91,5 %) : has `arena2d` M persistant (by file), recharge en working
 * `W:=copy(M)` at the beginning of each block, then scan DENSE (score+learn, rescale **working
 * 0x414590**) ecrivant `out[]=prod_dens` (there window pass#0 of the `sm`). `M` is ensuite
 * advances by the carry d'emission of the block. The `(row,sym)` viennent of the law ctx->row
 * (M14) ; here on branch `ps_ctx_step` (delta2D) as SOURCE EN ATTENTE of M14.
 * DefautOFF : never appele if no requis -> zero effet / zero regression. */
int alz_ps_emission_master_carry(const uint8_t *g, uint32_t base, uint32_t len,
                                 uint32_t *out_dens)
{
    static alz_arena2d_t M, W;
    static int m_init = 0;
    static uint32_t s_ctx_seed = 0u;
    uint32_t i, ctx_run;
    if (!g || !out_dens || len == 0u)
        return -1;
    if (!m_init) { alz_arena2d_init(&M, 32u); alz_arena2d_init(&W, 32u); m_init = 1; }
    if (base == 0u) { alz_arena2d_init(&M, 32u); alz_arena2d_init(&W, 32u); s_ctx_seed = 0u;
        alz_ps_cmlive_reset(0u); }   /* relance the moteur CM live (source row/sym) */
    /* (1) reload W:=copy(M) ; (2) scan dense : lines = `ctx` of the moteur CM (`rf70`) if
     * dispo, otherwise roulage position of the recon ; arena2d rescale working. */
    W = M;
    ctx_run = s_ctx_seed;
    for (i = 0u; i < len; i++) {
        uint32_t row, sym;
        if (alz_ps_cmlive_ctxrow(g, base + i, &row, &sym) != 0) {
            ctx_run = ((ctx_run << 8) | ((uint32_t) g[base + i] & 0xffu)) & 0x1FFFFu;
            row = (ctx_run >> 8) & 0x1FFu;
            sym = (uint32_t) g[base + i] & 0xffu;
        }
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        out_dens[base + i] = alz_arena2d_score(&W, row, sym & 0xffu, NULL);
    }
    /* (3) to advance the MASTER by the same lines (carry d'emission).
     * [GATED UHA_CMCARRY_LEARN, default-OFF, 14.061] the producteur LEGACY LEARNS in
     * the master (`add WORD[edx],0x20` @0x414966) : without LEARN, `M` remainder cold and the
     * reload block1 recharge has master static -> EMISS mediocre. Gate ON => M s'accumule
     * (promo +0x20), mirror of the carry reel. DefautOFF = NULL (unchanged, no regressif). */
    {
        static int s_ccl = -1;
        int cl;
        if (s_ccl < 0) s_ccl = (getenv("UHA_CMCARRY_LEARN") != NULL) ? 1 : 0;
        cl = s_ccl;
        for (i = 0u; i < len; i++) {
            uint32_t row, sym, lo = 0u;
            if (alz_ps_cmlive_symrow(g, base + i, 0u, &row, &sym) != 0) { row = 0u; sym = (uint32_t) g[base + i] & 0xffu; }
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            (void) alz_arena2d_score(&M, row, sym & 0xffu, cl ? &lo : NULL);
        }
    }
    s_ctx_seed = ctx_run;
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16 - GATED default-OFF, path faithful datadriven] alz_ps_livewalk_master.
 * Recette validated `Sigma==ORACLE` by `alz_ps_multi3` (l.605611) : has SNAPSHOT master
 * `snap` PERSISTANT, RECHARGE `live:=snap` by block, each class copiant snap->live
 * and SCORANT son stream (argmin 5 classes -> winner). The `snap` n'is advances THAT by the
 * stream DENSE of the class WINNING (cls3 for image.raw) - not by all the literals,
 * not by `gen_ctxs` - via `ps_score_ctxs` (cold/warm promo=32 + `rescale @0x4000`).
 * L'advances machine ctx (`ps_ctx_step(c,...)`) is has CARRY which roule sure all the file.
 * output = cost PRElearn by position of the `live` winner (mirror of the `sm`). N'WRITES
 * `out` that for the blocks whose `base >= from` (overlay ; the bloc0 keeps EMIPROD).
 * returns 0 OK, <0 error. Zero effet out gate (appele under `UHA_LIVEWALK`). */
int alz_ps_livewalk_master(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, uint32_t from, uint32_t *out)
{
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS], *tmp;
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t maxlen = 0u, seed_cls = 0u, stats = 0u;
    int b, k;
    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    snap = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    tmp  = (uint32_t *) malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!snap || !live || !tmp) { free(snap); free(live); free(tmp); return -1; }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        ctxs[k] = (uint32_t *) malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
        mm[k][0] = mm[k][1] = 0u; mm[k][2] = 1u;   /* init carry (idem alz.c advances M) */
        if (!ctxs[k]) { while (--k >= 0) free(ctxs[k]); free(snap); free(live); free(tmp); return -1; }
    }
    alz_arena2d_init(snap, 32u);
    stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i, c, order[ALZ_PS_NCLASS], cnt = 0u;
        uint32_t best = 0xffffffffu, winner = 0u;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* [probe] reload of the master at the input of THIS block (= total after blocks previous). */
        if (stats && base >= from)
            fprintf(stderr, "[LWM] reload@0x%05x t68=%u(tree68 cnt68=%u) t37=%u(tree37 cnt37=%u)\n",
                    (unsigned) base, (unsigned) snap->total[68u], (unsigned) snap->counter[68u],
                    (unsigned) snap->total[37u], (unsigned) snap->counter[37u]);
        /* (1) generer the stream ctx by class sure all the block (carry machine). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++)
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        /* (2) order : seed (winner block previous) d'abord, then ascendant. */
        order[cnt++] = seed_cls;
        for (c = 0u; c < ALZ_PS_NCLASS; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) argmin : each class copie snap->live and score (abandon precoce). */
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cc = order[(uint32_t)k], s;
            *live = *snap;
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, NULL, NULL);
            if (s < best) { best = s; winner = cc; }
        }
        /* (4) output : cost by position of the `live` winner (recharge since snap). */
        *live = *snap;
        (void) ps_score_ctxs(live, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, tmp);
        if (base >= from) memcpy(out + base, tmp, (size_t) len * sizeof(uint32_t));
        /* (5) to advance the SNAP master by the stream DENSE of the winner (persiste interblocks). */
        (void) ps_score_ctxs(snap, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        seed_cls = winner;
    }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(snap); free(live); free(tmp);
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16 - MEASURES, gated UHA_LIVEWALK_LC, N'WRITES NOT `out`] master " literalcarry ".
 * Hypothese datadriven (hit68 729 vs GT 420) : the legacy engine does to advance there machine ctx
 * (`ps_ctx_step(3)` carry ebx/flag/ebp) ONLY to the EMISSIONS of LITERAL (carry gele
 * during the runs of match), and n'LEARNS the master (0x4111a0) qu'has these same emissions.
 * Here : `snap` master persistant (init 32), mm[3] carry pasapas ; for q croissant, if
 * is_lit[q] -> ctx=ps_ctx_step(3,...,&mm) then learn snap (cold/warm + rescale @0x4000).
 * Digite tree/counter/hit of rows 68/37 at the input of each block (via _STATS) for
 * confront has GT (tree68=13438 tree37=4496, hit420/140). returns 0. */
int alz_ps_livewalk_litcarry(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, uint32_t *out_stats)
{
    alz_arena2d_t *snap;
    uint32_t mm[3] = {0u, 0u, 1u};
    uint32_t hit68 = 0u, hit37 = 0u;
    int b; uint32_t i, q, c;
    (void)out_stats;
    if (!g || !is_lit || nblk <= 0) return -1;
    snap = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    if (!snap) return -1;
    alz_arena2d_init(snap, 32u);
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], r, sum68 = 0u, sum37 = 0u, col;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        /* input of block : snapshot of the master (reload total:=tree+counter is there law of
         * rescale(); here on reads l'state cumule). */
        for (col = 0u; col < 256u; col++) { sum68 += snap->freq[(68u<<8)+col]; sum37 += snap->freq[(37u<<8)+col]; }
        (void)r;
        fprintf(stderr, "[LC] blk%d base=0x%05x t68=%u(tree68=%u cnt68=%u hit68=%u) t37=%u(tree37=%u cnt37=%u hit37=%u)\n",
                b, (unsigned)base, (unsigned)snap->total[68u], (unsigned)sum68, (unsigned)snap->counter[68u], (unsigned)hit68,
                (unsigned)snap->total[37u], (unsigned)sum37, (unsigned)snap->counter[37u], (unsigned)hit37);
        for (i = 0u; i < len; i++) {
            uint32_t ctx, row, delta;
            q = base + i;
            if (!is_lit[q]) continue;                 /* carry GELE during the matchs */
            ctx = ps_ctx_step(3u, g, q, &mm[0], &mm[1], &mm[2]);
            row = ctx >> 8; delta = ctx & 0xffu;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            if (q >= 0x3100u) { }                      /* (learn bloc0 only for there measures of the reload b1) */
            /* learn master = cold/warm + rescale @0x4000 (reutilise via has miniinline) */
            {
                uint32_t T = snap->total[row], f = snap->freq[(row<<8)|delta], inc = snap->promo[row];
                if (f == 0u) { snap->freq[(row<<8)|delta]=(uint16_t)inc; snap->counter[row]=(uint16_t)(snap->counter[row]+inc); snap->total[row]=(uint16_t)(T+2u*inc); }
                else         { snap->freq[(row<<8)|delta]=(uint16_t)(f+inc); snap->total[row]=(uint16_t)(T+inc); }
                if (snap->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(snap, row);
            }
            if (row == 68u) hit68++;
            else if (row == 37u) hit37++;
        }
    }
    (void)c;
    free(snap);
    return 0;
}

/* [GATED UHA_CM_WIRE, 13.803 M5] Produces g_lmin = cost[rc] BIT-EXACT sure there section
 * [base,base+len). Recette validated 100 % by ISOL_M5/m5_harness.c : CM engine dense sure
 * the literals (is_lit) -> sym/aff (row d'affinite R1), with LAG of line (relrow=aff[i-1]),
 * arena2d WORKING (score+learn, rescale 0x414590), WARM=1 LUT / COLD=LUT[64]+LUT[(cnt<<14)/total]
 * (master fenwick has sa seed freqM=4/fenwick=1024). Not TOUCHE NOT the master M. */
static void ps_cmwire_dens(const uint8_t *g, uint32_t base, uint32_t len,
                           const uint8_t *is_lit, uint32_t *out)
{
    (void)is_lit;
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u};
    alz_cm_learner L; memset(&L, 0, sizeof L);
    alz_arena A; alz_arena_init(&A);
    alz_arb   R; alz_arb_init(&R);
    alz_arena2d_t S; alz_arena2d_init(&S, 32u);   /* arena of SCORAGE working (section) */
    uint32_t rf70 = 0xffffffffu, rf74 = 0xffffffffu, rf78 = 0xffffffffu; int rflag = 0;
    int lpi = 0; int32_t prev_rh = 0;
    uint32_t aff_cost = 0, idx_cost = 0;          /* LAG line i-1 */
    uint32_t i;
    for (i = 0; i < len; i++) {
        uint32_t abs = base + i;
        /* M5 : the scorer advances has all rc (dense) ; is_lit-advances under-advances l'arena
         * and does to drift cost[rc] some ~rc544. (m5_harness advances has gt_have_engine  dense.) */
        uint8_t b_cur   = g[abs];
        uint8_t b_prev  = (i >= 1u) ? g[abs - 1u] : 0x80u;
        uint8_t b_prev2 = (i >= 2u) ? g[abs - 2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur - 0x80;
        int32_t base_p1 = ps_b(g, (long)base, (long)abs - 1);
        int32_t base_p2 = ps_b(g, (long)base, (long)abs - 2);
        int32_t dl      = ps_q(g, (long)base, (long)abs);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref = ps_q(g, (long)base, (long)abs - ref_prev);
        int32_t dr_b8  = ps_q(g, (long)base, (long)abs - b8_prev);
        int32_t row_hash_model = prev_rh;
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & abs) == 0u);
        A.line = abs; alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = abs;
        alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref, dr_b8, row_hash_model);
        uint32_t idx_i = R.idx;
        int32_t dr_learn = ps_q(g, (long)base, (long)(abs + 1) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_learn);
        /* machine registre -> sym, aff (R1) */
        uint32_t tap[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
        tap[0]=0; tap[1]=vp1; tap[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
        tap[3]=(uint8_t)row_hash_model;
        tap[4]=(uint8_t)A.dr[(abs-(uint32_t)ref_prev)&0x7fu];
        tap[5]=(uint8_t)A.dr[(abs-(uint32_t)b8_prev )&0x7fu];
        uint32_t Pcur = ((tap[lpi%6]&0xffu) + ((lpi>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
        uint32_t Pprev = (i == 0u) ? 0u : Pcur;
        uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
        uint8_t sym = rflag ? (uint8_t)(0u-(uint32_t)d) : d;
        rf70 = (rf70<<8)|sym; rf74 = (rf74<<8)+ALZ_REG_T1[sym]; rf78 = (rf78<<8)+ALZ_REG_T2[sym];
        if (sym >= 0x80u) rflag ^= 1;
        uint32_t aff = (rf70==0u)?1u:(rf74==0u)?2u:(rf78==0u)?3u:0u;
        lpi = (int)idx_i; prev_rh = L.prev_dot_full;
        /* cost = cost[rc] with LAG (relrow = aff of the line previous), sym current */
        uint32_t rel = aff_cost;                 /* LAG */
        uint32_t freqF = alz_arena2d_freq(&S, rel, sym);
        uint32_t cnt   = S.counter[rel];
        uint32_t T_before = S.total[rel];
        uint32_t cost;
        if (freqF != 0u) {                        /* WARM 1 term */
            uint32_t p2 = (T_before!=0u)?((freqF<<14)/T_before):(ALZ_SCORE_CUM_N-1u);
            if (p2 >= ALZ_SCORE_CUM_N) p2 = ALZ_SCORE_CUM_N-1u;
            cost = alz_score_proba_to_cost(p2);
        } else {                                  /* COLD 2 terms (master has sa seed) */
            uint32_t p1 = (1024u!=0u)?((4u<<14)/1024u):(ALZ_SCORE_CUM_N-1u);   /* freqM=4,fenwick=1024 -> 64 */
            if (p1 >= ALZ_SCORE_CUM_N) p1 = ALZ_SCORE_CUM_N-1u;
            uint32_t p2 = (T_before!=0u)?((cnt<<14)/T_before):(ALZ_SCORE_CUM_N-1u);
            if (p2 >= ALZ_SCORE_CUM_N) p2 = ALZ_SCORE_CUM_N-1u;
            cost = alz_score_proba_to_cost(p1) + alz_score_proba_to_cost(p2);
        }
        (void)alz_arena2d_score(&S, rel, sym, NULL);   /* advances (learn+rescale working) */
        aff_cost = aff; idx_cost = idx_i;
        out[abs] = cost;
    }
    (void)idx_cost;
}

int alz_ps_emiprod_percost(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, const uint8_t *is_lit, uint32_t *out)
{
    alz_arena2d_t *M, *W;
    uint32_t *tmp, maxlen = 0u;
    int b, dense = 0, masterlaw = 0, cmwire = 0, cmwire_prod = 0, emcarry = 0, mbound = 0, mcold = 0, litcarry = 0;
    FILE *cd = NULL;   /* [GATED UHA_CTXDUMP, default-OFF] journal pos/relrow/delta/byte. */

    if (!g || !blkpos || !blklen || !is_lit || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    M   = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    W   = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    tmp = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!M || !W || !tmp) { free(M); free(W); free(tmp); return -1; }
    alz_arena2d_init(M, 32u);
    {   /* [GATED UHA_AADUMP, read-only] opens there probe (row,freq,total) cls3. */
        const char *ad = getenv("UHA_AADUMP");
        if (ad && *ad) g_adump = fopen(ad, "w");
        /* [GATED UHA_EMIPROD_DENSE] master learns has all positions (otherwise lits single). */
        if (getenv("UHA_EMIPROD_DENSE")) dense = 1;
        /* [GATED UHA_EMIPROD_LITCARRY, defautOFF, ARENA_TASK16] the master advances sa machine
         * ctx (carry mm) AND learns ONLY to the emissions of LITERAL (carry gele during
         * the runs of match) - mirror of the learn d'emission `0x4111a0`. Reduit `reload[68]` of
         * 15248 (sourceorder) towards ~14257 (GT 13501, gap +5,6 % vs +13 %). */
        if (getenv("UHA_EMIPROD_LITCARRY")) litcarry = 1;
        /* [GATED UHA_EMIPROD_MASTERLAW] rescale of the master = law 0x40ffa0 (!= working). */
        if (getenv("UHA_EMIPROD_MASTERLAW")) masterlaw = 1;
        /* [GATED UHA_MCOLD, default-OFF, 14.127] not NOT to advance the master (M remainder
         * cold) : teste l'hypothese " there legacy keeps M cold, single W accumule ".
         * Combine has UHA_WLEARNLIT for there pass of output. */
        if (getenv("UHA_MCOLD")) mcold = 1;
        /* [GATED UHA_CM_WIRE, default-OFF] band registre (affin{0..3}) vs proxy cls3. */
        if (getenv("UHA_CM_WIRE")) cmwire = 1;
        /* [GATED UHA_CMWIRE_PROD, defautOFF] Surcharge producteur g_lmin=cost[rc] (M5/argmin).
         * Desactivable for tester there feed CM acclive SINGLE (13.859). */
        if (getenv("UHA_CMWIRE_PROD")) cmwire_prod = 1;
        /* [GATED UHA_CM_EMCARRY, defautOFF] carry master d'emission arena2d (13.897). */
        if (getenv("UHA_CM_EMCARRY")) emcarry = 1;
        /* [GATED UHA_CM_MBOUND, defautOFF] rescale master to the frontiers of block (13.911) ;
         * value = NB of rescales at each frontier (cadence of the scribe). */
        { const char *mb = getenv("UHA_CM_MBOUND"); if (mb) mbound = atoi(mb); }
        /* [GATED UHA_CTXDUMP=path, default-OFF] journal (pos,relrow=e,delta,byte) by
         * position of the machine cls3, for diff vs stream reel learn 0x411bb8 (13.738). */
        {   const char *cx = getenv("UHA_CTXDUMP");
            if (cx && *cx) cd = fopen(cx, "w");
        }
        /* [GATED UHA_PHASEFIX, default-OFF] phase cls3 = (abs+2)%3 (scan OUT + advances M). */
        if (getenv("UHA_PHASEFIX")) g_ps_phasefix = 1;
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i;
        alz_ps_carry_t stW;
        uint32_t mm[3];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* [GATED UHA_CM_MBOUND, default-OFF, 13.911] rescale of the MASTER at the frontier of
         * block (the scribe re-echelle `M` between blocks) : refroidit the working reloade au
         * block1 -> target `esi` front  towards 58364. Mecanisme, not reglage. */
        if (mbound && b > 0) {
            uint32_t rr, nb; for (nb = 0u; nb < (uint32_t)mbound; nb++)
                for (rr = 0u; rr < ALZ_ARENA2D_MAX_ROW; rr++) alz_arena2d_rescale(M, rr);
        }
        /* (1) snapshot working = copie of the master, then scan DENSE intra-block cls3
         *     (score + learn) => cost fige by position in `tmp`. */
        *W = *M;
        memset(&stW, 0, sizeof stW);
        stW.ebp = 1u;
        stW.arena = W;
        /* [GATED UHA_WLEARNLIT, default-OFF] there pass of output (cls3) n'learns that
         * sure the LITERALS emis (is_lit), all en scorant each position. */
        if (getenv("UHA_WLEARNLIT") && base >= 0x3100u) g_ps_learn_mask = is_lit;
        (void) alz_ps_class_sigma_carry(&stW, 3u, g, base, len, 32u, ALZ_PS_COLD0,
                                       NULL, tmp, NULL);
        g_ps_learn_mask = NULL;
        memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        /* [GATED UHA_CM_EMCARRY, 13.897] surcharge by there dens of the carry master d'emission. */
        if (emcarry) (void) alz_ps_emission_master_carry(g, base, len, out);
        /* [GATED UHA_CM_WIRE, 13.803] AFTER the memcpy of the proxy : SURCHARGE g_lmin[pos]
         * = cost[rc] BIT-EXACT (M5) to the single literals (no-literals keep the proxy). */
        if (cmwire && cmwire_prod) ps_cmwire_dens(g, base, len, is_lit, out);
        /* (2) to advance the MASTER : machine cls3 relative-block (ebp=1, alignee), but
         *     n'APPRENDRE only to the  LITERALS EMIS (nothing sure the matchs).
         *     [GATED UHA_CM_WIRE] : path faithful sym->row (engine CM dense) at the place of the proxy. */
        if (cmwire) {
            ps_cmwire_advance_master(M, g, base, len, is_lit, usize);
        } else {
        mm[0] = 0u; mm[1] = 0u; mm[2] = 1u;
        for (i = 0u; !mcold && i < len; i++) {
            uint32_t c;
            /* [LITCARRY] carry GELE + no learn during the bytes couverts by MATCH. */
            if (litcarry && !is_lit[base + i]) continue;
            c = ps_ctx_step(3u, g, base + i, &mm[0], &mm[1], &mm[2]);
            uint32_t row;
            /* [GATED UHA_PHASEFIX] same correction of phase that the scan OUT. */
            if (g_ps_phasefix) {
                uint32_t e = (c >> 8) & 0x1fu;
                e += (((base + i + 2u) % 3u) << 5);
                c = (e << 8) | (c & 0xffu);
            }
            row = c >> 8;
            if (cd && is_lit[base + i])
                fprintf(cd, "%u 0x%x 0x%x 0x%x\n", base + i, row, c & 0xffu, g[base + i]);
            if (!dense && !is_lit[base + i]) continue;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            if (masterlaw) (void) alz_arena2d_master_learn(M, row, c & 0xffu);
            else           (void) alz_arena2d_score(M, row, c & 0xffu, NULL);
        }
        }
    }
    free(M); free(W); free(tmp);
    if (cd) { fclose(cd); cd = NULL; }
    g_ps_phasefix = 0;
    if (g_adump) { fclose(g_adump); g_adump = NULL; }
    return 0;
}

/* ==========================================================================
 * [13.722 classpass producteur dens - GATED by l'appelant alz.c UHA_CLASSPASS,
 * default-OFF] Producteur FAITHFUL to legacy `0x414630` : Has single arena SHARED
 * monotone (13.717 " 1 buffer monotone ") traversee by 5 PASSES of class by
 * block, each pass SCORANT + APPRENNANT (promo=32, rescale 0x4000 - mirror some
 * apprentissages `0x4149d0..0x4149f2` of `0x414630`). Order some passes :
 * `0,1,2,3,4` (bloc0) then `3,0,1,2,4` (blocks >= 1) (13.717(2)/13.721).
 * There machine ctx (ebx/flag/ebp) is RE-AMORCEE at each pass (setup `0x414645`
 * by call), l'arena N'is NEVER reinitialisee. The snapshot consumes by the
 * decidez = output of the pass `cls3` (1 copie figee, 13.719(2)/13.721(1))
 * => `out[base+i]` n'is writes that durant there pass cls3. Formule of cost validated
 * EXACT 11/11 sure there window @13070 (13.722(2)). Pur : n'affecte no arena
 * global, buffers local. returns 0 OK, <0 error. */
int alz_ps_classpass_percost(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, uint32_t *out)
{
    static const uint32_t ord0[ALZ_PS_NCLASS] = { 0u, 1u, 2u, 3u, 4u };
    static const uint32_t ord1[ALZ_PS_NCLASS] = { 3u, 0u, 1u, 2u, 4u };
    alz_arena2d_t *ar;
    uint32_t *tmp, maxlen = 0u;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    ar  = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    tmp = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!ar || !tmp) { free(ar); free(tmp); return -1; }
    alz_arena2d_init(ar, 32u);
    /* [GATED UHA_CLASSPASS_COLD, default-OFF, diagnostic 13.723] Hypothese :
     * master@bloc1 quasi-EMPTY for the cellules cls3 (the LIVE of block0 learns
     * surtout d'others rows) => producteur faithful = arena COLD by block + scan
     * DENSE intra-block cls3 (nothing of cross-block, no some 5 others passes).
     * Test : at each block, RE-INIT `ar` (master cold) and not courir THAT cls3. */
    if (getenv("UHA_CLASSPASS_COLD") != NULL) {
        for (b = 0; b < nblk; b++) {
            uint32_t base = blkpos[b], len = blklen[b];
            alz_ps_carry_t st;
            if (base >= usize) continue;
            if (base + len > usize) len = usize - base;
            if (!len) continue;
            alz_arena2d_init(ar, 32u);          /* master cold by block (restore=) */
            memset(&st, 0, sizeof st);
            st.ebp = 1u;
            st.arena = ar;
            (void) alz_ps_class_sigma_carry(&st, 3u, g, base, len, 32u, ALZ_PS_COLD0,
                                            NULL, tmp, NULL);
            memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        }
        free(ar); free(tmp);
        return 0;
    }
    /* [GATED UHA_CPADV=<0..3>, default-OFF, 13.733 fix-classpass-model]
     * model RESTORE faithful at the ASM (`full.asm` l.24140-25010) : MASTER `M`
     * persistant ; by block * by class, WORKING `W := copie fraiche of M` then
     * scan DENSE of the class in W (jete). `out` = pass winning (argmin,cls3).
     * The MASTER is advances between blocks by there law d'emission UHA_CPADV (balayage) :
     *   0 = cold (no advances => restore-only, master empty) ;
     *   1 = dense-cls3 (1 ev/pos sure the row cls3)  avancement COSTSNAP ;
     *   2 = dense ALL classes (5 ev/pos, file some 5 stream) ;
     *   3 = dense by-position argmin-class (1 ev/pos, row of the class WINNING
     *       of THIS position, argmin read-only in M) - same DENSITE that 1 but
     *       ROWS heterogenes (13.726 " densite by-row ", the levier no refute).
     * Machine ctx threadee GLOBALEMENT by class (as COSTSNAP). No-regressif :
     * UHA_CLASSPASS single keeps the path partage. SUBSTITUTION interdite. */
    {
        const char *advs = getenv("UHA_CPADV");
        if (advs && advs[0] >= '0' && advs[0] <= '3') {
            int law = advs[0] - '0';
            alz_arena2d_t *M = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
            alz_arena2d_t *W = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
            uint32_t *ctxp[ALZ_PS_NCLASS];
            uint32_t cmm[ALZ_PS_NCLASS][3];
            int ok = (M != NULL && W != NULL);
            if (!ok) { free(M); free(W); free(ar); free(tmp); return -1; }
            {
                uint32_t minc = 32u;
                const char *me = getenv("UHA_CPADV_INC");
                if (me) minc = (uint32_t) atoi(me);
                alz_arena2d_init(M, (uint16_t) minc);
            }
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
                cmm[k][0] = cmm[k][1] = cmm[k][2] = 0u;
                ctxp[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
                if (!ctxp[k]) ok = 0;
            }
            if (!ok) { for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxp[k]); free(M); free(W); free(ar); free(tmp); return -1; }
            for (b = 0; b < nblk; b++) {
                uint32_t base = blkpos[b], len = blklen[b], i, c;
                uint32_t best = 0xffffffffu, winner = 3u;
                if (base >= usize) continue;
                if (base + len > usize) len = usize - base;
                if (!len) continue;
                /* (1) generer the 5 stream ctx sure all the block (machines global). */
                /* [GATED UHA_CPCTX, default-OFF, 13.881] lines d'emission by `ctx` roulant
                 * (M11b : ctx=(ctx<<8)|byte ; row=(ctx>>8)&0x1ff ; sym=byte), resets
                 * by pass of class (reload M10). Replaces the delta2D `ps_ctx_step`. */
                if (getenv("UHA_CPCTX") != NULL) {
                    for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                        uint32_t ctxr = 0u;
                        for (i = 0u; i < len; i++) {
                            uint32_t bytev = g[base + i];
                            ctxr = ((ctxr << 8) | bytev) & 0xffffffffu;
                            ctxp[c][i] = (((ctxr >> 8) & 0x1ffu) << 8) | (bytev & 0xffu);
                        }
                    }
                } else
                for (c = 0u; c < ALZ_PS_NCLASS; c++)
                    for (i = 0u; i < len; i++)
                        ctxp[c][i] = ps_ctx_step(c, g, base + i, &cmm[c][0], &cmm[c][1], &cmm[c][2]);
                /* (2) argmin by RESTORE : W := copie(M), scan dense class, jeter. */
                for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                    uint32_t s, np = 0;
                    *W = *M;
                    ps_set_promo_all(W, 32u);
                    s = ps_score_ctxs(W, ctxp[c], len, 32u, ALZ_PS_COLD0,
                                      (c == 0u) ? NULL : &best, &np, NULL);
                    if (s < best) { best = s; winner = c; }
                }
                /* (3) out = pass winning sure copie fraiche of M (without abandon). */
                if (base >= 0x3100u && base < 0x3101u && getenv("UHA_CPADV_STATS"))
                    fprintf(stderr, "[CPADV] reload@0x%05x M t68=%u t37=%u\n",
                            (unsigned) base, (unsigned) M->total[68u], (unsigned) M->total[37u]);
                *W = *M;
                ps_set_promo_all(W, 32u);
                ps_score_ctxs(W, ctxp[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
                /* (4) to advance the MASTER according to there law UHA_CPADV. */
                if (law == 1) {
                    ps_score_ctxs(M, ctxp[3u], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
                } else if (law == 2) {
                    for (c = 0u; c < ALZ_PS_NCLASS; c++)
                        ps_score_ctxs(M, ctxp[c], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
                } else if (law == 3) {
                    for (i = 0u; i < len; i++) {
                        uint32_t bb = 0xffffffffu, wc = 0u, cs;
                        for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                            cs = ps_cost_of(M, ctxp[c][i], ALZ_PS_COLD0);
                            if (cs < bb) { bb = cs; wc = c; }
                        }
                        ps_learn(M, ctxp[wc][i]);
                    }
                }
                /* law == 0 : master never advances (restore-only). */
            }
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxp[k]);
            free(M); free(W);
            free(ar); free(tmp);
            return 0;
        }
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b];
        /* [GATED UHA_CP3LAST, default-OFF, 14.138] order cls3 EN last for blocks>=1
         * (l'arena SHARED is d'abord rechauffee by the 4 others classes, then cls3
         * writes out) -> teste if the warm multiclasses intrablock atteint cost[rc] legacy. */
        static const uint32_t ordL[ALZ_PS_NCLASS] = { 0u, 1u, 2u, 4u, 3u };
        const uint32_t *ord = (b == 0) ? ord0
                            : (getenv("UHA_CP3LAST") ? ordL : ord1);
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        if (base >= 0x3100u && base < 0x3101u && getenv("UHA_CPSTATS"))
            fprintf(stderr, "[CP] shared ar@b1 t68=%u t37=%u\n",
                    (unsigned) ar->total[68u], (unsigned) ar->total[37u]);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cls = ord[k];
            alz_ps_carry_t st;
            memset(&st, 0, sizeof st);      /* machine ctx re-amorcee by pass */
            /* Legacy : `0x414a51 inc ebp` BEFORE the computation machine (`0x414bde`),
             * ebp re-seme au counter RELATIF block => row(i) = table[(i-1)] +
             * phase(i%3). Seed 1 (and no 0 of the ps_ctx_step default) prouvee by
             * there window 13.722 : row(526)=t3[5]+32*(526%3)=37  11/11. */
            st.ebp = 1u;
            st.arena = ar;                  /* arena SHARED monotone */
            (void) alz_ps_class_sigma_carry(&st, cls, g, base, len, 32u, ALZ_PS_COLD0,
                                            NULL, (cls == 3u) ? tmp : NULL, NULL);
            if (cls == 3u)
                memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        }
    }
    free(ar); free(tmp);
    return 0;
}

/* [TEST hook] Enables au harness offline d'aligner there correction of phase cls3
 * (g_ps_phasefix) without passer by getenv ; without effet sure l'encoding standard. */
void alz_ps_set_phasefix(int v) { g_ps_phasefix = v; }

