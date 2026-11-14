#include <stdlib.h>
#include <string.h>
#include "alz_priv.h"
#include "alz_tables.h"

typedef struct {
    uint32_t K[5];
    uint32_t K_mir[5];
    uint8_t  prev_b;
} a3_live_k_state;

typedef struct {
    uint16_t w_freq[512][256];
    uint16_t w_ctr[512];
    uint16_t w_tot[512];
    uint32_t out_costs[0x3200];
    uint8_t  kbuf[5][2048];
    uint32_t khist[5][256];
    uint32_t khist_mir[5][256];
} a3_live_ws;

static a3_live_ws *g_a3_live_ws = NULL;

int a3_live_blksel_on(void)
{
    return 1;
}

static unsigned live_order_shift(int order)
{
    if (order >= 40 && order <= 55) return 1u;
    if (order >= 56 && order <= 71) return 2u;
    if (order >= 72 && order <= 87) return 3u;
    return 0u;
}

static unsigned live_delta_cost(unsigned d)
{
    static const uint32_t s_dbornes[13] = {0u, 1u, 2u, 3u, 4u, 5u, 7u, 10u, 15u, 23u, 36u, 57u, 91u};
    unsigned m = (d <= 128u) ? d : (256u - d);
    unsigned c = 0u;
    size_t i;
    for (i = 0u; i < 13u; i++) {
        if (m >= s_dbornes[i]) c = (unsigned)i;
        else break;
    }
    return c;
}

static a3_live_ws *a3_get_live_ws(void)
{
    if (!g_a3_live_ws)
        g_a3_live_ws = (a3_live_ws *)calloc(1, sizeof(*g_a3_live_ws));
    return g_a3_live_ws;
}

static void a3_live_w_rescale(uint16_t (*w_freq)[256], uint16_t *w_ctr,
                              uint16_t *w_tot, uint32_t row)
{
    uint32_t s, sum = 0u;
    for (s = 0u; s < 256u; s++) {
        uint16_t v = (uint16_t)(w_freq[row][s] >> 1);
        w_freq[row][s] = v;
        sum += v;
    }
    w_ctr[row] = (uint16_t)((w_ctr[row] >> 2) + 1u);
    w_tot[row] = (uint16_t)(sum + w_ctr[row]);
}

static uint32_t a3_live_k_changepoint(a3_live_ws *ws, const uint8_t *plain,
                                      uint32_t pos, uint32_t blen,
                                      a3_live_k_state *ks)
{
    uint32_t c, i, pos_in;
    uint8_t saved_prev_b = ks->prev_b;
    uint32_t base;

    if (blen <= 0x800u)
        return blen;

    base = pos + 256u;
    memset(ws->khist, 0, sizeof(ws->khist));
    memset(ws->khist_mir, 0, sizeof(ws->khist_mir));

    for (c = 0u; c < 5u; c++) {
        uint64_t s1 = 0ull, s2 = 0ull;
        for (i = 0u; i < 2048u; i++) {
            uint32_t b = base + i;
            uint8_t v = plain[b];
            if (c > 0u && i >= c)
                v = (uint8_t)(plain[b] - plain[b - c]);
            ws->kbuf[c][i] = v;
            if (i < 1024u)
                ws->khist[c][v]++;
            else
                ws->khist_mir[c][v]++;
        }
        for (i = 0u; i < 256u; i++) {
            uint64_t f1 = ws->khist[c][i];
            uint64_t f2 = ws->khist_mir[c][i];
            s1 += f1 * f1;
            s2 += f2 * f2;
        }
        ks->K[c] = (uint32_t)s1;
        ks->K_mir[c] = (uint32_t)s2;
    }

    for (pos_in = 0x800u; pos_in < blen; pos_in++) {
        uint32_t O = pos_in - 0x800u;
        uint32_t k_old = O & 0x7ffu;
        uint32_t k_new = (O + 0x400u) & 0x7ffu;
        uint32_t bpos = base + pos_in;
        uint8_t b1 = 0u, b2 = 0u;

        for (c = 0u; c < 5u; c++) {
            uint8_t v_old = ws->kbuf[c][k_old];
            uint8_t v_new = ws->kbuf[c][k_new];
            uint8_t v_cur = (c == 0u) ? plain[bpos]
                                      : (uint8_t)(plain[bpos] - plain[bpos - c]);
            uint32_t f_old = ws->khist[c][v_old];
            uint32_t f_new;
            uint32_t m_old, m_new;

            ks->K[c] -= 2u * f_old - 1u;
            ws->khist[c][v_old] = f_old - 1u;
            f_new = ws->khist[c][v_new];
            ks->K[c] += 2u * f_new + 1u;
            ws->khist[c][v_new] = f_new + 1u;

            m_old = ws->khist_mir[c][v_new];
            ks->K_mir[c] -= 2u * m_old - 1u;
            ws->khist_mir[c][v_new] = m_old - 1u;
            m_new = ws->khist_mir[c][v_cur];
            ks->K_mir[c] += 2u * m_new + 1u;
            ws->khist_mir[c][v_cur] = m_new + 1u;

            ws->kbuf[c][k_old] = v_cur;
        }

        for (c = 1u; c < 5u; c++) {
            if (ks->K[c] > ks->K[b1])
                b1 = (uint8_t)c;
            if (ks->K_mir[c] > ks->K_mir[b2])
                b2 = (uint8_t)c;
        }
        if (b1 != ks->prev_b && 3u * ks->K[b1] < 4u * ks->K[ks->prev_b])
            b1 = ks->prev_b;
        if (b2 != ks->prev_b && 3u * ks->K_mir[b2] < 4u * ks->K_mir[ks->prev_b])
            b2 = ks->prev_b;
        if (b1 != b2) {
            ks->prev_b = b1;
            return pos_in - 0x200u;
        }
        ks->prev_b = b1;
    }

    ks->prev_b = saved_prev_b;
    return blen;
}

static uint32_t a3_live_eval_cm(a3_live_ws *ws, const alz_dec *d,
                                const uint8_t *plain, uint32_t pos, uint32_t blen,
                                int cls, int sel10, uint32_t budget,
                                unsigned order_shift, uint32_t *p_dc94)
{
    static const uint32_t s_secbase[10] = {0, 769, 801, 833, 929, 993, 997, 1001, 1009, 1012};
    static const uint32_t s_nctx[10]    = {512, 32, 32, 96, 64, 4, 4, 8, 3, 5};
    static const uint8_t  s_litbias[5]  = {0, 0, 8, 16, 24};
    static const uint8_t  s_tab16[16]   = {0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0};
    static const uint8_t  s_s3tab[256]  = {
        0, 1, 2, 3, 4, 5, 6, 7, 7, 8, 8, 9, 9, 10, 10, 10,
        11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
        18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19,
        19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21,
        21, 22, 22, 22, 23, 23, 24, 24, 25, 25, 26, 27, 28, 29, 30, 31,
    };
    uint32_t nctx = sel10 ? 256u : s_nctx[cls];
    uint32_t src0 = sel10 ? 0x200u : s_secbase[cls];
    uint32_t r, i;
    uint32_t rh = d->st.rolling_history;
    uint32_t epos = d->st.output_pos;
    uint32_t row = 0u, dir = 0u;
    uint32_t sum = 0u;
    uint32_t den = (blen >> order_shift) + 1u;
    uint32_t perpos = budget / den;

    for (r = 0u; r < nctx; r++) {
        memcpy(ws->w_freq[r], d->bm_freq[src0 + r], 256u * sizeof(uint16_t));
        ws->w_ctr[r] = d->bm_ew[src0 + r];
        ws->w_tot[r] = (uint16_t)(d->bm_tree[src0 + r][0] + ws->w_ctr[r]);
    }
    if (sel10) {
        for (r = 0u; r < 256u; r++)
            a3_live_w_rescale(ws->w_freq, ws->w_ctr, ws->w_tot, r);
    }

    dir = d->st.side_dir;
    if (cls != 0 && cls == (int)d->st.escape_selector) {
        row = d->st.side_secondary - s_secbase[cls];
    }

    for (i = 0u; i < blen; i++) {
        uint8_t ch = plain[pos + i];
        uint32_t esc_row, sym, bc;
        uint16_t fq;

        if (cls == 0) {
            uint8_t last = (uint8_t)(rh & 0xffu);
            uint8_t prev = (uint8_t)((rh >> 8) & 0xffu);
            sym = ch;
            if (!sel10) {
                *p_dc94 += 12u - live_delta_cost((uint32_t)((last - ch) & 0xffu));
                row = (uint32_t)last + (((last & 0xc0u) == (prev & 0xc0u)) ? 0x100u : 0u);
                esc_row = 0x3f9u + ((last & 0xe0u) >> 5);
            } else {
                row = (uint32_t)last;
                esc_row = 0x401u;
            }
        } else {
            uint8_t bias = (uint8_t)(rh >> s_litbias[cls]);
            sym = dir ? (uint8_t)(bias - ch) : (uint8_t)(ch - bias);
            esc_row = 0x402u + (uint32_t)cls;
        }

        fq = ws->w_freq[row][sym];
        if (fq == 0u) {
            uint32_t et = d->bm_tree[esc_row][0];
            uint32_t ef = d->bm_freq[esc_row][sym];
            uint32_t idx1 = et ? ((ef << 14) / et) : 0u;
            uint32_t idx2 = ws->w_tot[row] ? (((uint32_t)ws->w_ctr[row] << 14) / ws->w_tot[row]) : 0u;
            bc = (uint32_t)AlzSseMap[idx1] + (uint32_t)AlzSseMap[idx2];
            ws->w_ctr[row] = (uint16_t)(ws->w_ctr[row] + 0x20u);
            ws->w_tot[row] = (uint16_t)(ws->w_tot[row] + 0x20u);
        } else {
            uint32_t idx = ws->w_tot[row] ? (((uint32_t)fq << 14) / ws->w_tot[row]) : 0u;
            bc = (uint32_t)AlzSseMap[idx];
        }

        ws->out_costs[i] = bc;
        sum += bc;
        if (i == 0x22bu && (sum >> 9) > perpos)
            return 0xFFFFFFFFu;
        if (sum > budget)
            return sum;

        ws->w_freq[row][sym] = (uint16_t)(ws->w_freq[row][sym] + 0x20u);
        ws->w_tot[row] = (uint16_t)(ws->w_tot[row] + 0x20u);
        if (ws->w_tot[row] >= 0x4000u)
            a3_live_w_rescale(ws->w_freq, ws->w_ctr, ws->w_tot, row);

        if (cls != 0) {
            if (sym >= 0x80u)
                dir ^= 1u;
            if (cls == 1)
                row = ((uint32_t)s_tab16[row & 0xFu] << 4) + AlzSelTab2[sym];
            else if (cls == 2)
                row = ((epos & 1u) << 4) + AlzSelTab2[sym];
            else if (cls == 3)
                row = ((epos % 3u) << 5) + s_s3tab[sym];
            else
                row = ((epos & 3u) << 4) + AlzSelTab2[sym];
        }
        epos++;
        rh = (rh << 8) | ch;
    }
    return sum;
}

static int a3_live_eval_mm(a3_live_ws *ws, const alz_dec *d,
                           const uint8_t *plain, uint32_t pos, uint32_t blen,
                           int cls_src, uint32_t bud, unsigned order_shift)
{
    static const uint32_t s_secbase[10] = {0, 769, 801, 833, 929, 993, 997, 1001, 1009, 1012};
    static const uint32_t s_nctx[10]    = {512, 32, 32, 96, 64, 4, 4, 8, 3, 5};
    int hint = 0;
    uint32_t i, r, nctx, src0, esc_row, sum = 0u;
    uint32_t den = (blen >> order_shift) + 1u;
    uint32_t perpos = bud / den;
    alz_dec sim_d;

    if (cls_src == 1) {
        int32_t sc = 0;
        for (i = 0u; i < blen; i++) {
            uint8_t b = plain[pos + i];
            sc += (b < 0x40u || b >= 0xC0u) ? 1 : -1;
        }
        hint = 5 + (sc > 0 ? 1 : 0);
    } else if (cls_src == 2) {
        int32_t s0 = 0, s1 = 0;
        for (i = 0u; i < blen; i++) {
            uint8_t b = plain[pos + i];
            int32_t v = (b < 0x40u || b >= 0xC0u) ? 1 : -1;
            if ((i & 1u) == 0u) s0 += v;
            else s1 += v;
        }
        hint = (s0 > 0 || s1 > 0) ? 8 : 7;
    } else if (cls_src == 4) {
        hint = 9;
    } else {
        return 0;
    }

    nctx = s_nctx[hint];
    src0 = s_secbase[hint];
    for (r = 0u; r < nctx; r++) {
        memcpy(ws->w_freq[r], d->bm_freq[src0 + r], 256u * sizeof(uint16_t));
        ws->w_ctr[r] = d->bm_ew[src0 + r];
        ws->w_tot[r] = (uint16_t)(d->bm_tree[src0 + r][0] + ws->w_ctr[r]);
    }
    for (r = nctx; r < 8u; r++) {
        memset(ws->w_freq[r], 0, 256u * sizeof(uint16_t));
        ws->w_ctr[r] = 1u;
        ws->w_tot[r] = 1u;
    }

    memset(&sim_d, 0, sizeof(sim_d));
    sim_d.st = d->st;
    if (hint != (int)d->st.escape_selector || d->st.escape_changed)
        alz_apply_escape(&sim_d, hint);

    esc_row = 0x402u + (uint32_t)hint;

    for (i = 0u; i < blen; i++) {
        uint8_t ch = plain[pos + i];
        uint8_t delta = (uint8_t)(ch - sim_d.st.side_bias);
        uint32_t abs_row = sim_d.st.side_secondary;
        uint32_t row = abs_row - src0;
        uint16_t inc = AlzEntryStep[abs_row];
        uint16_t fq;
        uint32_t bc;

        if (sim_d.st.side_dir != 0u)
            delta = (uint8_t)(-(int)delta);
        if (row >= 8u) row = 0u;

        fq = ws->w_freq[row][delta];
        if (fq == 0u) {
            uint32_t et = d->bm_tree[esc_row][0];
            uint32_t ef = d->bm_freq[esc_row][delta];
            uint32_t idx1 = et ? ((ef << 14) / et) : 0u;
            uint32_t idx2 = ws->w_tot[row] ? (((uint32_t)ws->w_ctr[row] << 14) / ws->w_tot[row]) : 0u;
            bc = (uint32_t)AlzSseMap[idx1] + (uint32_t)AlzSseMap[idx2];
            ws->w_ctr[row] = (uint16_t)(ws->w_ctr[row] + inc);
            ws->w_tot[row] = (uint16_t)(ws->w_tot[row] + inc);
        } else {
            uint32_t idx = ws->w_tot[row] ? (((uint32_t)fq << 14) / ws->w_tot[row]) : 0u;
            bc = (uint32_t)AlzSseMap[idx];
        }

        ws->out_costs[i] = bc;
        sum += bc;
        if (i == 0x22bu && (sum >> 9) > perpos)
            sum = 0xFFFFFFFFu;
        if (sum > bud)
            return 0;

        ws->w_freq[row][delta] = (uint16_t)(ws->w_freq[row][delta] + inc);
        ws->w_tot[row] = (uint16_t)(ws->w_tot[row] + inc);
        if (ws->w_tot[row] >= 0x4000u)
            a3_live_w_rescale(ws->w_freq, ws->w_ctr, ws->w_tot, row);

        if (delta >= 0x80u)
            sim_d.st.side_dir ^= 1u;
        sim_d.st.rolling_history = (sim_d.st.rolling_history << 8) | ch;
        alz_side_mm_step_sim(&sim_d, ch, delta);
    }
    return (sum < bud) ? hint : 0;
}

void a3_live_block_eval(const alz_dec *d, const uint8_t *plain,
                        uint32_t usize, uint32_t pos, int order,
                        int nomm, a3_live_k_state *ks,
                        int *out_sel, uint32_t *out_blen,
                        uint32_t **p_dens, uint32_t *p_dens_cap, int *p_dens_ready)
{
    static const uint8_t s_prim[10] = {0, 1, 2, 3, 4, 1, 1, 2, 2, 4};
    a3_live_ws *ws = a3_get_live_ws();
    uint32_t rest = usize - pos;
    uint32_t ebp = (rest >= 0x4b00u) ? 0x3200u : rest;
    uint32_t blen;
    unsigned shift = live_order_shift(order);
    uint32_t cost[5] = {0, 0, 0, 0, 0};
    uint32_t dc94 = 0u;
    int cur_sel = d->st.escape_changed ? 10 : (int)d->st.escape_selector;
    int prim_start, best, cand, c, mm_res = 0;

    (void)p_dens_cap;
    (void)p_dens_ready;
    if (!ws) {
        *out_sel = d->st.escape_selector;
        *out_blen = (rest >= 0x4b00u) ? 0x3100u : rest;
        return;
    }

    if (nomm) {
        blen = ebp;
        a3_live_eval_cm(ws, d, plain, pos, blen, 0, 0, 0xFFFFFFFFu, shift, &dc94);
        if (*p_dens && pos + blen <= usize)
            memcpy(*p_dens + pos, ws->out_costs, (size_t)blen * sizeof(uint32_t));
        *out_sel = 0;
        *out_blen = blen;
        return;
    }

    memcpy(ks->K, ks->K_mir, sizeof(ks->K));
    if (rest <= 0x100u) {
        blen = rest;
    } else {
        blen = ebp - 0x100u;
        blen = a3_live_k_changepoint(ws, plain, pos, blen, ks);
    }

    prim_start = (cur_sel >= 0 && cur_sel < 10) ? (int)s_prim[cur_sel] : 0;
    cost[prim_start] = a3_live_eval_cm(ws, d, plain, pos, blen, prim_start, 0,
                                       0xFFFFFFFFu, shift, &dc94);
    best = prim_start;
    if (*p_dens && pos + blen <= usize)
        memcpy(*p_dens + pos, ws->out_costs, (size_t)blen * sizeof(uint32_t));

    for (c = 0; c <= 4; c++) {
        if (c == prim_start)
            continue;
        cost[c] = a3_live_eval_cm(ws, d, plain, pos, blen, c, 0,
                                  cost[best], shift, &dc94);
        if (cost[c] < cost[best]) {
            best = c;
            if (*p_dens && pos + blen <= usize)
                memcpy(*p_dens + pos, ws->out_costs, (size_t)blen * sizeof(uint32_t));
        }
    }

    {
        uint32_t q = (blen > 0u) ? (cost[best] / blen / 0x249u) : 0u;
        if (q > 10u) q = 10u;
        if (best != 0 && best != 3) {
            uint32_t T = (best == 1 ? 0x50u : 0x4bu) - 4u * (10u - q);
            if ((uint64_t)T * (uint64_t)ks->K[best] > 64ull * (uint64_t)ks->K[0]) {
                uint32_t bud = (best == 4) ? (cost[4] - (cost[4] >> 6)) : cost[best];
                mm_res = a3_live_eval_mm(ws, d, plain, pos, blen, best, bud, shift);
            }
        } else {
            int b_max = 1, k;
            for (k = 2; k <= 4; k++) {
                if (ks->K[k] > ks->K[b_max])
                    b_max = k;
            }
            if (b_max != 3) {
                uint32_t T_req = ((blen >= 0x800u) ? 0x50u : 0x41u) + 4u * (10u - q);
                if (64ull * (uint64_t)ks->K[b_max] > (uint64_t)T_req * (uint64_t)ks->K[0]) {
                    mm_res = a3_live_eval_mm(ws, d, plain, pos, blen, b_max,
                                             cost[best], shift);
                }
            }
        }
    }

    if (mm_res != 0) {
        cand = mm_res;
        if (*p_dens && pos + blen <= usize)
            memcpy(*p_dens + pos, ws->out_costs, (size_t)blen * sizeof(uint32_t));
    } else {
        cand = best;
    }

    if (cand <= 1 && blen >= 0x800u && (dc94 >> 2) > blen) {
        uint32_t c10 = a3_live_eval_cm(ws, d, plain, pos, blen, 0, 1,
                                       cost[cand], shift, &dc94);
        uint32_t eax = (uint32_t)(c10 + (blen << 6) + (cost[0] >> 6));
        if (eax < cost[cand]) {
            cand = 10;
            if (*p_dens && pos + blen <= usize)
                memcpy(*p_dens + pos, ws->out_costs, (size_t)blen * sizeof(uint32_t));
        }
    }

    *out_sel = cand;
    *out_blen = blen;
}
