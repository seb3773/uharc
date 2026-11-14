#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ppm.h"
#include "encode.h"
#include "ppm_priv.h"
#include "ppm_blocklen.h"
#include "ppm_legacy_cost.h"
#include "ppm_blk_cost.h"

static const uint32_t CLS_NCTX10[10] = { 8u, 32u, 32u, 96u, 64u, 4u, 4u, 8u, 3u, 5u };
static int ppm_blk_class(int cl, const uint8_t *w, uint32_t len);

extern void ppm_cost_set_avail(size_t n);
extern void ppm_cost_set_outpos(uint32_t);
extern void ppm_cost_set_outarm(void);

static void blk_scan_step(void *ud, ppm_blk_state *st, uint8_t raw, uint8_t sym)
{
    ppm_model *m = (ppm_model *)ud;
    (void)sym;
    m->cls_neg = st->flag ? 1u : 0u;
    ppm_scan_step(m, (int)raw);
    st->last = m->cls_base;
    st->flag = m->cls_neg;
    st->ctx_abs = m->cls_ctx;
}

static ppm_blocklen_ctx g_blc;
static const uint8_t *g_blk_raw;
static int64_t g_lenb_bound = -1;

int64_t ppm_lenb_sym_bound(void)
{
    return g_lenb_bound;
}

static void lenb_compute(ppm_model *m, const uint8_t *raw, uint32_t start, uint32_t end)
{
    (void)m; (void)raw; (void)start; (void)end;
    g_lenb_bound = -1;
}

static uint32_t g_blk_usize;
static uint32_t g_blk_next;
static uint32_t g_blk_bound;
static uint32_t g_blk_start;
static uint32_t g_blk_initctx;
static int g_blklaw;

static int g_e0law = 0;
static uint32_t g_e0law_val = 0;

void uha_ppm_set_e0law(int mode, uint32_t e0)
{
    g_e0law = mode;
    g_e0law_val = e0;
}

static uint32_t member_fin_at(uint32_t p, const uint32_t *member_ends, uint32_t nmembers,
                              uint32_t *fin)
{
    uint32_t f;
    if (!member_ends || !nmembers)
        return 0u;
    for (f = 0; f < nmembers; f++)
        if ((f ? member_ends[f - 1] : 0u) == p) {
            if (member_ends[f] <= p)
                return 0u;
            *fin = member_ends[f];
            return 1u;
        }
    return 0u;
}

static int ppm_family_veto(ppm_model *m, uint32_t pos, uint32_t len, int ncls, uint64_t bud)
{
    static ppm_cost_arena *SC;
    static ppm_model *s_save;
    ppm_live_arena SL;
    ppm_blk_scan_in sin;
    ppm_blk_scan_out sout;

    if (!m || !g_blk_raw || ncls < 0 || ncls >= 10 || !bud || !len)
        return 0;
    if (!SC)
        SC = (ppm_cost_arena *)calloc(1, sizeof *SC);
    if (!s_save)
        s_save = (ppm_model *)malloc(sizeof *s_save);
    if (!SC || !s_save)
        return 0;

    SL.freq = (const uint16_t *)m->freq;
    SL.cum = (const uint16_t *)m->cum;
    SL.ent = m->ent_wt;
    SL.base = CLS_CTXBASE[ncls];
    SL.n = CLS_NCTX10[ncls];
    SL.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)ncls) * 256u;
    SL.prior_total = m->cum[772u + (uint32_t)ncls][0];

    if (!ppm_cost_arena_load_live(SC, &SL))
        return 0;

    memset(&sin, 0, sizeof sin);
    sin.hist = g_blk_raw;
    sin.win = g_blk_raw + pos + 0x100u;
    sin.len = len;
    sin.base = SL.base;
    sin.nctx = SL.n;
    sin.step2 = m->tstep2;
    sin.st.ctx_abs = m->cls_ctx;
    sin.st.last = 0u;
    sin.st.flag = 0u;
    sin.st.win_idx = pos;
    sin.step = blk_scan_step;
    sin.ud = m;

    *s_save = *m;
    memset(&sout, 0, sizeof sout);
    (void)ppm_blk_cost_scan(SC, &sin, (uint32_t)bud, &sout);
    *m = *s_save;

    return sout.ebp >= bud;
}

static void blk_set_payload(ppm_model *m)
{
    if (m && m->w)
        ppm_cost_set_payload(m->w->buf, m->w->pos, (size_t)g_blk_usize);
}

static void blk_set_flag(ppm_model *m, uint32_t j)
{
    if ((uint32_t)j != (uint32_t)m->flag3934)
        ppm_cost_set_flag(0u);
    else
        ppm_cost_set_flag(((uint32_t)j == (uint32_t)m->flag3934) ? m->cls_neg : ppm_cost_get_flag());
}

int ppm_detr_inverse(const uint8_t *in, uint32_t len,
                     uint8_t *out, uint32_t *nout);
int ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                     uint8_t *out, uint32_t *nout);

static int ppm_blk_bias(const uint8_t *w, uint32_t n, int complement)
{
    uint32_t i;
    int s = 0;

    for (i = 0; i < n; i++) {
        uint8_t b = complement ? (uint8_t)(~w[i] & 0xFF) : w[i];
        s += (b < 0x40 || b >= 0xC0) ? 1 : -1;
    }
    return s;
}

static int ppm_blk_class(int cl, const uint8_t *w, uint32_t len)
{
    if (cl == 1)
        return 5 + (ppm_blk_bias(w, len < 0x100u ? len : 0x100u, 0)
                    + ppm_blk_bias(w + (len < 0x100u ? len : 0x100u),
                                   len > 0x100u ? len - 0x100u : 0u, 1) > 0);
    if (cl == 2) {
        int esi = ppm_blk_bias(w, len < 0x100u ? len : 0x100u, 0);
        int ecx = ppm_blk_bias(w + (len < 0x100u ? len : 0x100u),
                                len > 0x100u ? len - 0x100u : 0u, 1);
        return 7 + ((esi > 0 || ecx > 0) ? 1 : 0);
    }
    if (cl == 4)
        return 9;
    return -1;
}

#define FEN 0x3100u

static int ppm_frontier_class(ppm_model *m, uint32_t p,
                              const uint32_t *member_ends, uint32_t nmembers)
{
    uint32_t reste, fin = 0;

    if (!g_blk_raw || !g_blk_usize || g_blk_usize <= p)
        return -1;
    if (m->byte_class == 0)
        return -1;
    reste = g_blk_usize - p;
    if (member_fin_at(p, member_ends, nmembers, &fin))
        reste = fin - p;
    if (reste <= 0x100u)
        return -1;

    ppm_cost_set_prectx(0u);
    ppm_cost_set_window(0u, 0u);
    ppm_cost_set_flag(0u);
    ppm_cost_set_avail((size_t)reste);

    {
        uint32_t cb, fact, len = (uint32_t)FEN;
        uint64_t best = 0ull;
        int cl, e1, a = -1, chg = 0, ncls;
        uint32_t seed = (g_blk_start & 15u);
        static ppm_blocklen_ctx *s_fbt_F = NULL;
        uint32_t ft[5], f5[5], lrest, lret;
        const uint32_t *r5;

        r5 = g_blc.t;
        if (g_blk_usize > p) {
            if (!s_fbt_F)
                s_fbt_F = (ppm_blocklen_ctx *)malloc(sizeof *s_fbt_F);
            if (!s_fbt_F) return 0;
            lrest = g_blk_usize - p;
            if (lrest >= 0x4b00u)
                lrest = 0x3200u;
            *s_fbt_F = g_blc;
            ppm_blocklen_roll(s_fbt_F);
            lret = (lrest > 0x100u) ? ppm_blocklen(s_fbt_F, g_blk_raw + p, lrest - 0x100u) : lrest;
            memcpy(ft, s_fbt_F->t, sizeof ft);
            memcpy(f5, s_fbt_F->t5, sizeof f5);
            r5 = ft;
            len = lret;
        }

        cl = (int)ppm_legacy_cost_select_class(g_blk_raw + p, len,
                                               seed, ppm_legacy_cost, &best);
        e1 = cl;
        cb = len ? (uint32_t)(best / len / 0x249u) : 0x0Au;
        if (cb > 0x0Au)
            cb = 0x0Au;
        fact = (uint32_t)((cl == 1 ? 0x50 : 0x4b) - (0x0Au - cb) * 4u);
        if (cl != 0 && cl != 3 &&
            (uint32_t)(fact * r5[cl]) > (uint32_t)(r5[0] << 6)) {
            chg = 1;
        } else {
            a = 1;
            if (r5[2] > r5[a]) a = 2;
            if (r5[3] > r5[a]) a = 3;
            if (r5[4] > r5[a]) a = 4;
            else if (a == 3) a = -1;
            if (a >= 0) {
                fact = ((len >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
                if ((uint32_t)(r5[a] << 6) > (uint32_t)(fact * r5[0])) {
                    cl = a;
                    chg = 1;
                }
            }
        }
        ncls = chg ? ppm_blk_class(cl, g_blk_raw + p, len) : -1;
        if (ncls < 0)
            ncls = e1;
        else if (ppm_family_veto(m, p, len, ncls, best)) {
            ncls = e1;
        }
        return ncls;
    }
}

static void ppm_arm_frontier_class(ppm_model *m, uint32_t p,
                                   const uint32_t *member_ends, uint32_t nmembers)
{
    extern int uharc_ppm_class;
    int c = ppm_frontier_class(m, p, member_ends, nmembers);
    if (c >= 0)
        uharc_ppm_class = c;
    if (c >= 0 && g_blk_usize > p) {
        uint32_t reste = g_blk_usize - p;
        uint32_t ebp;
        if (reste >= 0x4b00u)
            reste = 0x3200u;
        if (g_blk_bound > p && g_blk_bound - p < reste)
            reste = g_blk_bound - p;
        if (p > 0u) {
            ppm_blocklen_roll(&g_blc);
            ebp = (reste > 0x100u)
                ? ppm_blocklen(&g_blc, g_blk_raw + p + 0x100u, reste - 0x100u)
                : reste;
        } else {
            ebp = (reste > 0x100u) ? reste - 0x100u : reste;
        }
        g_blk_next = p + ebp;
    }
}

int ppm_blk_node_encode(ppm_model *m, uint32_t start, int lzp_ctx)
{
    uint32_t reste, ret, cb = 0x0Au, fact;
    uint64_t bud = 0;
    int j, cl = 1, ncls = -1, chg;
    int stage1 = 1;

    if (!m || !g_blk_raw || g_blklaw < 3)
        return 0;
    if (start < g_blk_next)
        return 0;
    if (start >= g_blk_usize)
        return 0;

    reste = g_blk_usize - start;
    if (g_blk_bound > start && g_blk_bound - start < reste)
        reste = g_blk_bound - start;
    if (reste >= 0x4b00u)
        reste = 0x3200u;

    if (m->byte_class == 0) {
        static const uint8_t TBL[10] = { 0, 1, 2, 3, 4, 1, 1, 2, 2, 4 };
        int cand = (int)TBL[m->flag3934 % 10u];
        g_blk_next = start + reste;

        if (g_blklaw >= 4 && lzp_ctx >= 0 && cand != (int)m->flag3934) {
            int erc = ppm_lzp_encode_escape(m, lzp_ctx, cand);
            if (erc < 0)
                return -1;
        }
        return 0;
    }

    ppm_blocklen_roll(&g_blc);
    if (reste > 0x100u)
        ret = ppm_blocklen(&g_blc, g_blk_raw + start + 256, reste - 0x100u);
    else
        ret = reste;
    g_blk_next = start + ret;

    if (g_blklaw >= 4) {
        uint32_t cost[5];
        uint32_t init, len;
        int a;
        int live = 0;
        static ppm_cost_arena *s_arena;
        static const uint32_t CLS_NCTX[5] = { 8u, 0x20u, 0x20u, 0x60u, 0x40u };
        ppm_live_arena L;

        len = ret;
        {
            static const uint8_t TBL[10] = { 0, 1, 2, 3, 4, 1, 1, 2, 2, 4 };
            init = (uint32_t)TBL[m->flag3934 % 10u];
        }
        if (init >= 5u)
            init = 0u;

        if (g_blklaw >= 5) {
            if (!s_arena)
                s_arena = (ppm_cost_arena *)calloc(1, sizeof *s_arena);
            if (s_arena) {
                L.freq = (const uint16_t *)m->freq;
                L.cum = (const uint16_t *)m->cum;
                L.ent = m->ent_wt;
                L.base = CLS_CTXBASE[init];
                L.n = CLS_NCTX[init];
                L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + init) * 256u;
                L.prior_total = m->cum[772u + init][0];
                live = 1;
            }
        }
        cl = (int)init;
        {
            uint32_t pc = 0u;
            if (start >= 4u)
                pc = (uint32_t)((~g_blk_raw[start - 1u]) & 0xffu)
                   | ((uint32_t)((~g_blk_raw[start - 2u]) & 0xffu) << 8)
                   | ((uint32_t)((~g_blk_raw[start - 3u]) & 0xffu) << 16)
                   | ((uint32_t)((~g_blk_raw[start - 4u]) & 0xffu) << 24);
            ppm_cost_set_prectx(pc);
        }
        {
            uint32_t cc = (uint32_t)m->flag3934;
            ppm_cost_set_window(start, 0u);
            ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum));
            ppm_cost_set_outarm();
            ppm_cost_set_outpos((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum));
            if (g_blk_usize)
                ppm_cost_set_avail((size_t)g_blk_usize);
            blk_set_payload(m);
            if (cc < 10u && m->cls_ctx >= CLS_CTXBASE[cc])
                g_blk_initctx = m->cls_ctx - CLS_CTXBASE[cc];
            else
                g_blk_initctx = 0u;
        }

        if (g_blklaw >= 6 && live) {
            static int seeded = 0;
            uint32_t sc = (uint32_t)m->flag3934;
            if (sc >= 5u)
                sc = 0u;
            if (!seeded) {
                ppm_live_arena S = L;
                S.base = CLS_CTXBASE[sc];
                S.n = CLS_NCTX[sc];
                (void)ppm_cost_arena_load_live(s_arena, &S);
                seeded = 1;
            }
        }

        if (live && ppm_cost_rowsel_on() && s_arena) {
            if (init == 0u)
                ppm_cost_rowsel_feed_live(s_arena, g_blk_raw, (size_t)start);
        }

        cost[init] = (uint32_t)(live
            ? (ppm_cost_set_window(start, ((uint32_t)init == (uint32_t)m->flag3934) ? g_blk_initctx : 0u),
               ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum)),
               blk_set_payload(m),
               blk_set_flag(m, init),
               ppm_legacy_cost_live(s_arena, g_blk_raw + start, len, init, 0xFFFFFFFFu, &L, 1))
            : ppm_legacy_cost(g_blk_raw + start, len, init, 0xFFFFFFFFu));

        for (j = 0; j < 5; j++) {
            if ((uint32_t)j == init)
                continue;
            if (live && g_blklaw >= 7) {
                L.base = CLS_CTXBASE[(uint32_t)j];
                L.n = CLS_NCTX[(uint32_t)j];
                L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)j) * 256u;
                L.prior_total = m->cum[772u + (uint32_t)j][0];
                ppm_cost_set_window(start, ((uint32_t)j == (uint32_t)m->flag3934) ? g_blk_initctx : 0u);
                ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum));
                blk_set_payload(m);
                blk_set_flag(m, (uint32_t)j);
                cost[j] = (uint32_t)ppm_legacy_cost_live(s_arena, g_blk_raw + start, len,
                                                        (uint32_t)j, cost[cl], &L, 1);
            } else {
                cost[j] = (uint32_t)(live
                    ? ppm_legacy_cost_live(s_arena, g_blk_raw + start, len, (uint32_t)j,
                                           cost[cl], &L, 0)
                    : ppm_legacy_cost(g_blk_raw + start, len, (uint32_t)j, cost[cl]));
            }
            if (cost[j] < cost[cl])
                cl = j;
        }

        stage1 = cl;
        bud = cost[cl];
        cb = len ? (cost[cl] / len / 0x249u) : 0x0Au;
        if (cb > 0x0Au)
            cb = 0x0Au;
        fact = (uint32_t)((cl == 1 ? 0x50 : 0x4b) - (0x0Au - cb) * 4u);
        chg = 0;
        if (cl != 0 && cl != 3 &&
            (uint32_t)(fact * g_blc.t[cl]) > (uint32_t)(g_blc.t[0] << 6)) {
            chg = 1;
        } else {
            a = 1;
            if (g_blc.t[2] > g_blc.t[a])
                a = 2;
            if (g_blc.t[3] > g_blc.t[a])
                a = 3;
            if (g_blc.t[4] > g_blc.t[a])
                a = 4;
            else if (a == 3)
                a = -1;
            if (a >= 0) {
                fact = ((len >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
                if ((uint32_t)(g_blc.t[a] << 6) > (uint32_t)(fact * g_blc.t[0])) {
                    cl = a;
                    chg = 1;
                }
            }
        }
        if (chg)
            ncls = ppm_blk_class(cl, g_blk_raw + start, len);
    }

    {
        int cand = (ncls >= 0) ? ncls : (int)cl;
        int entrer = (cand != (int)m->flag3934 && lzp_ctx >= 0);
        if (!entrer && lzp_ctx >= 0 && ncls >= 0 && bud && g_blklaw >= 8 &&
            stage1 != (int)m->flag3934)
            entrer = 1;

        if (entrer) {
            int erc;
            int go = 1;
            if (g_blklaw >= 8 && ncls >= 0 && ncls < 10 && bud) {
                static ppm_cost_arena *s_scan;
                static ppm_model *s_save;
                static ppm_model *s_rest;
                if (!s_scan)
                    s_scan = (ppm_cost_arena *)calloc(1, sizeof *s_scan);
                if (!s_save)
                    s_save = (ppm_model *)malloc(sizeof *s_save);
                if (!s_rest)
                    s_rest = (ppm_model *)malloc(sizeof *s_rest);
                if (s_scan && s_save && s_rest) {
                    ppm_live_arena SL;
                    ppm_blk_scan_in sin;
                    ppm_blk_scan_out sout;
                    int cs = ncls;
                    SL.freq = (const uint16_t *)m->freq;
                    SL.cum = (const uint16_t *)m->cum;
                    SL.ent = m->ent_wt;
                    SL.base = CLS_CTXBASE[cs];
                    SL.n = CLS_NCTX10[cs];
                    SL.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)cs) * 256u;
                    SL.prior_total = m->cum[772u + (uint32_t)cs][0];
                    if (ppm_cost_arena_load_live(s_scan, &SL)) {
                        memset(&sin, 0, sizeof sin);
                        sin.hist = g_blk_raw;
                        sin.win = g_blk_raw + start + 0x100u;
                        sin.len = ret;
                        sin.base = SL.base;
                        sin.nctx = SL.n;
                        sin.step2 = m->tstep2;
                        sin.st.ctx_abs = m->cls_ctx;
                        sin.st.last = 0u;
                        sin.st.flag = 0u;
                        sin.st.win_idx = start;
                        sin.step = blk_scan_step;
                        sin.ud = m;
                        *s_save = *m;
                        *s_rest = *m;
                        m->flag3934 = (uint8_t)cs;
                        m->cls_ctx = CLS_CTXBASE[cs];
                        m->cls_neg = 0u;
                        sin.st.ctx_abs = CLS_CTXBASE[cs];
                        (void)ppm_blk_cost_scan(s_scan, &sin, (uint32_t)bud, &sout);
                        *m = *s_rest;
                        if (sout.ebp >= bud)
                            go = 0;
                    }
                }
            }
            if (!go) {
                cand = stage1;
                if (cand == (int)m->flag3934)
                    return 0;
            } else if (cand == (int)m->flag3934) {
                return 0;
            }
            erc = ppm_lzp_encode_escape(m, lzp_ctx, cand);
            if (erc < 0)
                return -1;
        }
    }
    return 0;
}

static int ppm_encode_core(const uint8_t *syms, uint32_t nsyms,
                           uint32_t usize, int order, int bc_mode,
                           const uint32_t *member_ends, int nmembers,
                           const uint8_t *raw,
                           uint8_t **out, size_t *outlen)
{
    ppm_model m;
    uha_rcw w;
    uint8_t *work;
    ppm_match mr;
    int in_pos = 0, out_pos = 0, route, sym, member, rc, target, n, dl;
    uint32_t next_boundary, boundary_target, period;
    int blklaw;

    *out = NULL;
    *outlen = 0;
    if (order < 0x18 || order > 0x27)
        return PPM_ERR_ORDER;
    if (usize == 0) {
        *out = malloc(1);
        return *out ? PPM_OK : PPM_ERR_NOMEM;
    }
    if (!syms || nsyms == 0)
        return PPM_ERR_CORRUPT;

    memset(&m, 0, sizeof(m));
    if (!ppm_model_alloc(&m, order))
        return PPM_ERR_NOMEM;

    rc = PPM_ERR_CORRUPT;
    m.blk_len4 = usize;
    m.byte_class = (uint8_t)(bc_mode ? 1 : 0);
    m.e0_blk_len = (g_e0law && bc_mode == 0 && g_e0law_val) ? g_e0law_val : usize;

    if (uha_rcw_init(&w) != 0) {
        ppm_model_free(&m);
        return PPM_ERR_NOMEM;
    }
    m.w = &w;

    ppm_write_block_header(&m, &w);
    if (w.error)
        goto done;

    next_boundary = usize;
    member = 0;
    period = 0x40000u >> (m.byte_class * 2);
    boundary_target = (usize > period) ? period : usize;
    if (boundary_target > m.e0_blk_len)
        boundary_target = m.e0_blk_len;
    if (boundary_target > m.detr_thr1)
        boundary_target = m.detr_thr1;
    while (member < nmembers && member_ends && member_ends[member] < boundary_target)
        member++;
    if (member < nmembers && member_ends)
        next_boundary = member_ends[member];
    g_blk_bound = next_boundary;
    lenb_compute(&m, raw, 0u, next_boundary);

    blklaw = uha_get_nomm() ? 0 : 8;
    if (blklaw) {
        ppm_blocklen_init(&g_blc);
    }
    if (blklaw >= 3) {
        g_blk_raw = raw;
        g_blk_usize = usize;
        g_blk_next = 0u;
        g_blk_start = 0u;
        g_blklaw = blklaw;
    } else {
        g_blk_raw = NULL;
        g_blklaw = blklaw;
    }
    ppm_block_reset_tables(&m);
    ppm_arm_frontier_class(&m, 0u, member_ends, nmembers);
    if (!ppm_block_reset_encode(&m))
        goto done;
    if (m.byte_class != 0)
        ppm_bc1_reset();

    work = malloc((size_t)usize + 0x1000);
    if (!work) {
        rc = PPM_ERR_NOMEM;
        goto done;
    }

    in_pos = 0;
    out_pos = 0;
    if (blklaw >= 3) {
        if (ppm_blk_node_encode(&m, 0u, -1) < 0) {
            free(work);
            goto done;
        }
    }
    while (in_pos < (int)nsyms) {
        if (g_e0law && (uint32_t)out_pos < usize && (uint32_t)out_pos >= m.e0_blk_len) {
            ppm_promote_to_bc1(&m);
            ppm_bc1_reset();
            next_boundary = (uint32_t)out_pos;
        }
        while ((uint32_t)out_pos >= next_boundary && (uint32_t)in_pos < nsyms) {
            period = 0x40000u >> (m.byte_class * 2);
            boundary_target = (usize - next_boundary > period)
                ? next_boundary + period : usize;
            if (boundary_target > m.e0_blk_len)
                boundary_target = m.e0_blk_len;
            if (boundary_target > m.detr_thr1)
                boundary_target = m.detr_thr1;
            while (member < nmembers && member_ends && member_ends[member] < boundary_target)
                member++;
            if (member < nmembers && member_ends)
                next_boundary = member_ends[member];
            else
                next_boundary = usize;
            g_blk_bound = next_boundary;
            lenb_compute(&m, raw, (uint32_t)out_pos, next_boundary);
            ppm_arm_frontier_class(&m, (uint32_t)out_pos, member_ends, nmembers);
            if (!ppm_block_reset_encode(&m)) {
                free(work);
                goto done;
            }
            if (m.byte_class != 0)
                ppm_bc1_block_reset();
            m.out_count = (uint32_t)out_pos;
        }

        m.out_count = (uint32_t)out_pos;
        if (ppm_matchfinder_encode(&m, &mr, syms, nsyms,
                                   (uint32_t)in_pos) < 0) {
            free(work);
            goto done;
        }
        if (mr.lzp_ctx >= 0) {
            ppm_lzp_apply_update(&m, mr.lzp_ctx, mr.lzp_cls);
            if (mr.lzp_cls != 1)
                ppm_lzp_nomatch_tail(&m);
        }

        if (mr.is_match) {
            int ii;
            n = mr.raw_len;
            for (ii = 0; ii < n; ii++) {
                if ((uint32_t)out_pos >= usize)
                    break;
                dl = (n - ii) <= 8;
                ppm_match_maintain(&m, mr.raw_syms[ii], dl, work, &out_pos);
            }
            in_pos += n;
            if (w.error) {
                free(work);
                goto done;
            }
            continue;
        }

        target = syms[in_pos];
        ppm_matchfinder_literal_tail(&m);
        {
            uint32_t lit0 = (uint32_t)out_pos;
            if (!ppm_encode_literal_cascade(&m, work, &out_pos, target,
                                            &route, &sym)) {
                free(work);
                goto done;
            }
            (void)lit0;
        }
        if (sym != target) {
            free(work);
            goto done;
        }
        in_pos++;
        if (w.error) {
            free(work);
            goto done;
        }
    }

    free(work);
    if (uha_rcw_flush(&w) != 0)
        goto done;
    *out = w.buf;
    *outlen = w.pos;
    w.buf = NULL;
    rc = PPM_OK;

done:
    uha_rcw_free(&w);
    ppm_model_free(&m);
    return rc;
}

int uha_ppm_encode(const uint8_t *plain, uint32_t usize,
                   int order, int bc_mode,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t **out, size_t *outlen)
{
    uint8_t *syms;
    uint32_t nsyms;
    int rc;

    if (!out || !outlen)
        return PPM_ERR_CORRUPT;
    *out = NULL;
    *outlen = 0;
    if (usize == 0) {
        *out = malloc(1);
        return *out ? PPM_OK : PPM_ERR_NOMEM;
    }
    if (!plain)
        return PPM_ERR_CORRUPT;

    syms = malloc((size_t)usize * 4 + 16);
    if (!syms)
        return PPM_ERR_NOMEM;
    nsyms = 0;
    if (bc_mode == 1) {
        uint32_t i;
        for (i = 0; i < usize; i++)
            syms[i] = (uint8_t)(~plain[i]);
        nsyms = usize;
    } else if (g_e0law && g_e0law_val && g_e0law_val < usize) {
        if (!ppm_detr_forward(plain, usize, g_e0law_val, syms, &nsyms)) {
            free(syms);
            return PPM_ERR_CORRUPT;
        }
    } else if (!ppm_detr_inverse(plain, usize, syms, &nsyms)) {
        free(syms);
        return PPM_ERR_CORRUPT;
    }
    rc = ppm_encode_core(syms, nsyms, usize, order, bc_mode, member_ends, nmembers,
                         plain, out, outlen);
    free(syms);
    return rc;
}

int uha_ppm_encode_syms(const uint8_t *syms, uint32_t nsyms, uint32_t usize,
                        int order,
                        const uint32_t *member_ends, int nmembers,
                        uint8_t **out, size_t *outlen)
{
    return ppm_encode_core(syms, nsyms, usize, order, 0, member_ends, nmembers,
                           NULL, out, outlen);
}
