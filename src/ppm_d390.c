#include "ppm_priv.h"

static uint32_t f154w(const ppm_model *m, uint32_t key)
{
    return m->f154[(key * 2) & PPM_M32] & 0xFFFF;
}

static uint32_t f154i2(const ppm_model *m, uint32_t key)
{
    if (key > 0x3FFF)
        key = 0x3FFF;
    return m->f154[key] & 0xFFFF;
}

static int in_excl_l(const uint8_t *excl, int n, uint8_t sym)
{
    int i;
    for (i = 0; i < n; i++)
        if (excl[i] == sym)
            return 1;
    return 0;
}

static uint32_t rem_after_excl(const ppm_model *m, int ctx_id, const uint8_t *excl, int n)
{
    uint32_t result = m->cum[ctx_id][0];
    int i;
    for (i = 0; i < n; i++)
        result = (result - m->freq[ctx_id][excl[i]]) & 0xFFFF;
    return result;
}

static uint32_t total_from_rem(const ppm_model *m, int ctx_id, uint32_t rem)
{
    uint32_t c, idx, sse2, t;
    if (ctx_id >= 0x301)
        return rem & PPM_M32;
    c = m->ent_wt[ctx_id];
    if (ctx_id >= 0x200 || rem >= 0x2000)
        return (rem + c) & PPM_M32;
    if (((rem + c) & PPM_M32) == 0)
        return rem & PPM_M32;
    idx = ((c << 5) / ((rem + c) & PPM_M32)) & PPM_M32;
    if (idx > 0x1F)
        idx = 0x1F;
    sse2 = m->sse2[idx];
    if (sse2 == 0)
        return rem & PPM_M32;
    t = ((rem << 13) / sse2) + 1;
    if (t >= 0x4000)
        t = 0x3FFF;
    return t;
}

static uint32_t present_contribution(const ppm_model *m, int ctx_id, int sym,
                                     const uint8_t *excl, int n)
{
    uint32_t rem, total, freq;
    rem = rem_after_excl(m, ctx_id, excl, n);
    total = total_from_rem(m, ctx_id, rem);
    if (total == 0)
        return 0;
    freq = m->freq[ctx_id][sym];
    return f154i2(m, (freq << 14) / total);
}

static int ineligible(const ppm_model *m, int ctx, const uint8_t *excl, int n, int bb)
{
    return (m->freq[ctx][bb] != 0) || in_excl_l(excl, n, (uint8_t)bb);
}

static uint32_t novel_workctx_contribution(const ppm_model *m, int ctx, int work_ctx,
                                           int sym, const uint8_t *excl, int n)
{
    int b;
    uint32_t rem, total, freq;
    rem = m->cum[work_ctx][0];
    for (b = 0; b <= 255; b++)
        if (ineligible(m, ctx, excl, n, b))
            rem = (rem - m->freq[work_ctx][b]) & 0xFFFF;
    total = total_from_rem(m, work_ctx, rem);
    if (total == 0)
        return 0;
    freq = m->freq[work_ctx][sym];
    return f154i2(m, (freq << 14) / total);
}

static uint32_t sse_index(const ppm_model *m, int ctx, int pb, uint32_t freq_pred, uint32_t rem)
{
    uint32_t w, c, sse;
    w = m->wtab[m->cls_idx[ctx]];
    c = m->ent_wt[ctx];
    sse = (((w + freq_pred) & PPM_M32) << 4) / ((w + c + rem) & PPM_M32);
    if (freq_pred > 0x600)
        ;
    else if (freq_pred > 0x100)
        sse |= 0x30;
    else if (freq_pred > 0x40)
        sse |= 0x20;
    else
        sse |= 0x10;
    if ((ctx & 0xC0) == 0xC0)
        sse |= 0x40;
    if ((pb & 0xC0) == 0xC0) {
        if (pb == 0xFF)
            sse |= 0x100;
        else
            sse |= 0x80;
    }
    if (m->byte_class != 0) {
        if (((m->win_pos - m->recency[pb]) & PPM_M32) <= 0x40)
            sse |= 0x200;
    } else if (m->novel[pb] != 0)
        sse |= 0x200;
    if (m->last_ctx == m->last_sym[pb])
        sse |= 0x400;
    return sse;
}

ppm_d390 ppm_d390_update(ppm_model *m, int ctx, int sym)
{
    ppm_d390 res;
    uint32_t e268, wt, tot, freq_pred, rem, total, idx, old;
    int no_mps, pb, i, n;
    uint8_t excl[PPM_MAX_EXCL];

    res.acc_add = 0;
    res.sse_idx = -1;
    res.sse_val = 0;
    res.excl = -1;
    n = m->nexcl;
    for (i = 0; i < n; i++)
        excl[i] = m->excl[i];
    e268 = m->ent_wt[ctx];
    wt = (e268 * m->order0_wt[ctx]) & PPM_M32;
    tot = m->cum[ctx][0];
    if (tot <= wt) {
        res.acc_add = present_contribution(m, m->work_ctx, sym, excl, n);
        return res;
    }

    no_mps = ctx >= (int)(0x200u >> m->byte_class);
    pb = m->pred_byte[ctx];
    if (!no_mps && in_excl_l(excl, n, (uint8_t)pb))
        no_mps = 1;
    if (!no_mps) {
        freq_pred = m->freq[ctx][pb];
        rem = rem_after_excl(m, ctx, excl, n);
        idx = sse_index(m, ctx, pb, freq_pred, rem);
        old = m->sse_prob[idx];
        if (pb == sym) {
            res.acc_add = f154w(m, old);
            res.sse_idx = (int)idx;
            res.sse_val = (old + ((0x2000 - old) >> 6)) & PPM_M32;
            return res;
        }
        res.acc_add = f154w(m, (0x2000 - old) & PPM_M32);
        res.sse_idx = (int)idx;
        res.sse_val = (old - (old >> 6)) & PPM_M32;
        excl[n] = (uint8_t)pb;
        n++;
    }

    if (m->freq[ctx][sym] != 0) {
        res.acc_add = (res.acc_add + present_contribution(m, ctx, sym, excl, n)) & PPM_M32;
        return res;
    }

    rem = rem_after_excl(m, ctx, excl, n);
    if (rem != 0) {
        total = total_from_rem(m, ctx, rem);
        res.acc_add = (res.acc_add + f154i2(m, ((total - rem) << 14) / total)) & PPM_M32;
    }
    total = novel_workctx_contribution(m, ctx, m->work_ctx, sym, excl, n);
    res.acc_add = (res.acc_add + total) & PPM_M32;
    return res;
}
