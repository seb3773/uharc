#include "ppm_priv.h"
#include <stdio.h>
#include <stdlib.h>

static int decode_work_ctx(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                           const uint8_t *excl, int nexcl);
static int search_and_decode(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                             int row_ctx, uint32_t total, uint32_t freq,
                             const uint8_t *excl, int nexcl);
static int cont_cebf(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                     int ctx, uint32_t rem, const uint8_t *excl, int nexcl);
static int secondary(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                     int ctx, uint32_t rem, const uint8_t *excl, int nexcl);
static int novel(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                 int ctx, uint32_t rem, uint32_t total,
                 const uint8_t *excl, int nexcl);

static int decode_work_ctx(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                           const uint8_t *excl, int nexcl)
{
    int wc, i;
    uint32_t total, freq;

    wc = m->work_ctx;
    total = m->cum[wc][0];
    for (i = 0; i < nexcl; i++)
        total = (total - m->freq[wc][excl[i]]) & 0xFFFFu;
    if (total == 0) {
        ks->supported = 0;
        return -1;
    }
    r->range /= total;
    ks->last_total = total;
    freq = r->code / r->range;
    return search_and_decode(m, r, ks, wc, total, freq, excl, nexcl);
}

static int search_and_decode(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                             int row_ctx, uint32_t total, uint32_t freq,
                             const uint8_t *excl, int nexcl)
{
    int symbol;
    uint32_t rem, high, low_word, low;

    if (nexcl == 0)
        symbol = ppm_fenwick_bsearch(m->cum[row_ctx], total, freq, &rem);
    else
        symbol = ppm_fenwick_mixsearch(m->cum[row_ctx], m->freq[row_ctx],
                                       total, freq, excl, nexcl, &rem);
    high = (rem + freq) & 0xFFFFu;
    low_word = m->freq[row_ctx][symbol] & 0xFFFFu;
    low = (high - low_word) & PPM_M32;

    if (((high - low) & PPM_M32) == 0) {
        ks->supported = 0;
        return -1;
    }
    uha_rc_remove(r, low, high);

    if (ks->last_total != 0)
        ks->weight = (ks->weight + ppm_f154_2(m, (low_word << 14) / ks->last_total)) & PPM_M32;
    return symbol;
}

static int cont_cebf(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                     int ctx, uint32_t rem, const uint8_t *excl, int nexcl)
{
    if (rem == 0)
        return decode_work_ctx(m, r, ks, excl, nexcl);
    return secondary(m, r, ks, ctx, rem, excl, nexcl);
}

static int secondary(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                     int ctx, uint32_t rem, const uint8_t *excl, int nexcl)
{
    uint32_t c, total, idx, sse2, freq, t;
    int have_idx;

    c = m->ent_wt[ctx];
    have_idx = 0;
    idx = 0;
    if (ctx >= 0x200 || rem >= 0x2000) {
        total = (rem + c) & PPM_M32;
    } else {
        idx = ((c << 5) / ((rem + c) & PPM_M32)) & PPM_M32;
        sse2 = m->sse2[idx];
        t = ((rem << 13) / sse2) + 1;
        if (t >= 0x4000)
            t = 0x3FFF;
        total = t;
        have_idx = 1;
    }
    r->range /= total;
    ks->last_total = total;
    freq = r->code / r->range;
    if ((freq & 0xFFFFu) < rem) {
        int result = search_and_decode(m, r, ks, ctx, rem, freq, excl, nexcl);
        if (have_idx)
            ks->sse2_up_idx = (int)idx;
        return result;
    }
    if (have_idx)
        ks->sse2_idx = (int)idx;
    ks->weight = (ks->weight + ppm_f154_2(m, ((total - rem) << 14) / total)) & PPM_M32;
    return novel(m, r, ks, ctx, rem, total, excl, nexcl);
}

static int novel(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                 int ctx, uint32_t rem, uint32_t total,
                 const uint8_t *excl, int nexcl)
{
    int bitmap[256];
    int wc, b, i;
    uint32_t si, novel_total, freq2, dx, high, fb, low;

    if (((total - rem) & PPM_M32) != 0)
        uha_rc_remove(r, rem, total);
    for (i = 0; i < 256; i++)
        bitmap[i] = 0;
    for (i = 0; i < nexcl; i++)
        bitmap[excl[i]] = 1;
    wc = m->work_ctx;
    si = 0;
    for (b = 0; b < 256; b++)
        if (m->freq[ctx][b] != 0 || bitmap[b])
            si = (si + m->freq[wc][b]) & 0xFFFFu;
    novel_total = (m->cum[wc][0] - si) & 0xFFFFu;
    if (novel_total == 0) {
        ks->supported = 0;
        return -1;
    }
    r->range /= novel_total;
    ks->last_total = novel_total;
    freq2 = (r->code / r->range) & 0xFFFFu;
    dx = 0;
    b = 0x100;
    for (;;) {
        b--;
        if (!(m->freq[ctx][b] != 0 || bitmap[b]))
            dx = (dx + m->freq[wc][b]) & 0xFFFFu;
        if (dx > freq2 || b == 0)
            break;
    }
    high = dx & 0xFFFFu;
    fb = m->freq[wc][b] & 0xFFFFu;
    low = (high - fb) & PPM_M32;
    uha_rc_remove(r, low, high);

    if (ks->last_total != 0)
        ks->weight = (ks->weight + ppm_f154_2(m, (fb << 14) / ks->last_total)) & PPM_M32;
    return b;
}

static int low_count_sse(ppm_model *m, uha_rc *r, ppm_kstate *ks,
                         int ctx, uint32_t ent_total,
                         const uint8_t *excl, int nexcl)
{
    uint32_t rem, freq_pred, w, c, sse, prob, fdec;
    int pb, i;
    uint8_t excl2[PPM_MAX_EXCL];
    int n2;

    rem = ent_total;
    for (i = 0; i < nexcl; i++)
        rem = (rem - m->freq[ctx][excl[i]]) & 0xFFFFu;
    if ((uint32_t)ctx >= (0x200u >> m->byte_class))
        return cont_cebf(m, r, ks, ctx, rem, excl, nexcl);
    pb = m->pred_byte[ctx];
    if (ppm_in_excl(excl, nexcl, (uint8_t)pb))
        return cont_cebf(m, r, ks, ctx, rem, excl, nexcl);

    freq_pred = m->freq[ctx][pb];
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
    } else {
        if (m->novel[pb] != 0)
            sse |= 0x200;
    }
    if (m->last_ctx == m->last_sym[pb])
        sse |= 0x400;
    prob = m->sse_prob[sse];
    r->range /= 0x2000;
    fdec = (r->code / r->range) & 0xFFFFu;
    if (fdec < prob) {
        uha_rc_remove(r, 0, prob);
        ks->weight = (ks->weight + ppm_f154_4(m, prob)) & PPM_M32;
        return pb;
    }

    uha_rc_remove(r, prob, 0x2000);
    ks->weight = (ks->weight + ppm_f154_4(m, (0x2000 - prob) & PPM_M32)) & PPM_M32;
    ks->kernel_excl = pb;
    rem = (rem - freq_pred) & 0xFFFFu;
    for (i = 0; i < nexcl; i++)
        excl2[i] = excl[i];
    excl2[nexcl] = (uint8_t)pb;
    n2 = nexcl + 1;
    return cont_cebf(m, r, ks, ctx, rem, excl2, n2);
}

int ppm_kernel_decode(ppm_model *m, uha_rc *r, int ctx, ppm_kstate *ks)
{
    uint32_t ent_total, ent_weight;

    ks->weight = 0;
    ks->last_total = 0;
    ks->sse2_idx = -1;
    ks->sse2_up_idx = -1;
    ks->kernel_excl = -1;
    ks->supported = 1;
    ent_total = m->cum[ctx][0];
    ent_weight = ((uint32_t)m->ent_wt[ctx] * m->order0_wt[ctx]) & PPM_M32;
    if (ent_total > ent_weight)
        return low_count_sse(m, r, ks, ctx, ent_total, m->excl, m->nexcl);
    return decode_work_ctx(m, r, ks, m->excl, m->nexcl);
}

static uint32_t fenwick_prefix(const uint16_t *row, int sym)
{
    uint32_t sum = 0;
    int idx = sym;

    while (idx != 0) {
        sum = (sum + row[idx]) & 0xFFFFu;
        idx -= idx & -idx;
    }
    return sum;
}

static uint32_t mix_prefix(const uint16_t *freq_row, int sym,
                           const uint8_t *excl, int nexcl)
{
    uint32_t sum = 0;
    int s;

    for (s = 0; s < sym; s++) {
        if (!ppm_in_excl(excl, nexcl, (uint8_t)s))
            sum = (sum + freq_row[s]) & 0xFFFFu;
    }
    return sum;
}

static int encode_in_row(ppm_model *m, ppm_kstate *ks, int row_ctx,
                         uint32_t fenwick_total, uint32_t scale_total, int sym,
                         const uint8_t *excl, int nexcl)
{
    uint32_t prefix, width, low, high;

    if (!m->w || fenwick_total == 0 || scale_total == 0)
        return -1;
    if (ppm_in_excl(excl, nexcl, (uint8_t)sym))
        return -1;
    width = m->freq[row_ctx][sym] & 0xFFFFu;
    if (width == 0)
        return -1;
    if (nexcl == 0)
        prefix = fenwick_prefix(m->cum[row_ctx], sym);
    else
        prefix = mix_prefix(m->freq[row_ctx], sym, excl, nexcl);
    if (fenwick_total < prefix + width)
        return -1;
    low = (fenwick_total - prefix - width) & PPM_M32;
    high = (fenwick_total - prefix) & PPM_M32;
    if (high <= low)
        return -1;
    if (uha_rcw_encode(m->w, low, high, scale_total) != 0)
        return -1;
    ks->last_total = scale_total;
    if (ks->last_total != 0)
        ks->weight = (ks->weight + ppm_f154_2(m, (width << 14) / ks->last_total)) & PPM_M32;
    return sym;
}

static int encode_work_ctx(ppm_model *m, ppm_kstate *ks, int sym,
                           const uint8_t *excl, int nexcl)
{
    int wc, i;
    uint32_t total;

    wc = m->work_ctx;
    total = m->cum[wc][0];
    for (i = 0; i < nexcl; i++)
        total = (total - m->freq[wc][excl[i]]) & 0xFFFFu;
    if (total == 0) {
        ks->supported = 0;
        return -1;
    }
    return encode_in_row(m, ks, wc, total, total, sym, excl, nexcl);
}

static int encode_novel(ppm_model *m, ppm_kstate *ks,
                        int ctx, uint32_t rem, uint32_t total, int sym,
                        const uint8_t *excl, int nexcl)
{
    int bitmap[256];
    int wc, b, i;
    uint32_t si, novel_total, acc, stp;

    if (!m->w)
        return -1;
    if (((total - rem) & PPM_M32) != 0) {
        if (uha_rcw_encode(m->w, rem, total, total) != 0)
            return -1;
    }
    for (i = 0; i < 256; i++)
        bitmap[i] = 0;
    for (i = 0; i < nexcl; i++)
        bitmap[excl[i]] = 1;
    wc = m->work_ctx;
    si = 0;
    for (b = 0; b < 256; b++)
        if (m->freq[ctx][b] != 0 || bitmap[b])
            si = (si + m->freq[wc][b]) & 0xFFFFu;
    novel_total = (m->cum[wc][0] - si) & 0xFFFFu;
    if (novel_total == 0) {
        ks->supported = 0;
        return -1;
    }
    if (m->freq[ctx][sym] != 0 || bitmap[sym])
        return -1;
    acc = 0;
    for (b = 255; b >= 0; b--) {
        if (m->freq[ctx][b] != 0 || bitmap[b])
            continue;
        stp = m->freq[wc][b] & 0xFFFFu;
        if (b == (int)sym) {
            if (stp == 0)
                return -1;
            if (uha_rcw_encode(m->w, acc, acc + stp, novel_total) != 0)
                return -1;
            ks->last_total = novel_total;
            if (ks->last_total != 0)
                ks->weight = (ks->weight + ppm_f154_2(m, (stp << 14) / ks->last_total)) & PPM_M32;
            return b;
        }
        acc = (acc + stp) & 0xFFFFu;
        if (b == 0)
            break;
    }
    return -1;
}

static int encode_secondary(ppm_model *m, ppm_kstate *ks,
                            int ctx, uint32_t rem, int sym,
                            const uint8_t *excl, int nexcl)
{
    uint32_t c, total, idx, sse2, t;
    int have_idx, present;

    c = m->ent_wt[ctx];
    have_idx = 0;
    idx = 0;
    if (ctx >= 0x200 || rem >= 0x2000) {
        total = (rem + c) & PPM_M32;
    } else {
        idx = ((c << 5) / ((rem + c) & PPM_M32)) & PPM_M32;
        sse2 = m->sse2[idx];
        t = ((rem << 13) / sse2) + 1;
        if (t >= 0x4000)
            t = 0x3FFF;
        total = t;
        have_idx = 1;
    }
    present = (m->freq[ctx][sym] != 0) && !ppm_in_excl(excl, nexcl, (uint8_t)sym);
    if (present) {
        if (encode_in_row(m, ks, ctx, rem, total, sym, excl, nexcl) < 0)
            return -1;
        if (have_idx)
            ks->sse2_up_idx = (int)idx;
        return sym;
    }
    if (have_idx)
        ks->sse2_idx = (int)idx;
    ks->weight = (ks->weight + ppm_f154_2(m, ((total - rem) << 14) / total)) & PPM_M32;
    return encode_novel(m, ks, ctx, rem, total, sym, excl, nexcl);
}

static int encode_cont_cebf(ppm_model *m, ppm_kstate *ks,
                            int ctx, uint32_t rem, int sym,
                            const uint8_t *excl, int nexcl)
{
    if (rem == 0)
        return encode_work_ctx(m, ks, sym, excl, nexcl);
    return encode_secondary(m, ks, ctx, rem, sym, excl, nexcl);
}

static int encode_low_count_sse(ppm_model *m, ppm_kstate *ks,
                                int ctx, uint32_t ent_total, int sym,
                                const uint8_t *excl, int nexcl)
{
    uint32_t rem, freq_pred, w, c, sse, prob;
    int pb, i;
    uint8_t excl2[PPM_MAX_EXCL];
    int n2;

    rem = ent_total;
    for (i = 0; i < nexcl; i++)
        rem = (rem - m->freq[ctx][excl[i]]) & 0xFFFFu;
    if ((uint32_t)ctx >= (0x200u >> m->byte_class))
        return encode_cont_cebf(m, ks, ctx, rem, sym, excl, nexcl);
    pb = m->pred_byte[ctx];
    if (ppm_in_excl(excl, nexcl, (uint8_t)pb))
        return encode_cont_cebf(m, ks, ctx, rem, sym, excl, nexcl);

    freq_pred = m->freq[ctx][pb];
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
    } else {
        if (m->novel[pb] != 0)
            sse |= 0x200;
    }
    if (m->last_ctx == m->last_sym[pb])
        sse |= 0x400;
    prob = m->sse_prob[sse];
    if (sym == pb) {
        if (uha_rcw_encode(m->w, 0, prob, 0x2000) != 0)
            return -1;
        ks->weight = (ks->weight + ppm_f154_4(m, prob)) & PPM_M32;
        return pb;
    }
    if (uha_rcw_encode(m->w, prob, 0x2000, 0x2000) != 0)
        return -1;
    ks->weight = (ks->weight + ppm_f154_4(m, (0x2000 - prob) & PPM_M32)) & PPM_M32;
    ks->kernel_excl = pb;
    rem = (rem - freq_pred) & 0xFFFFu;
    for (i = 0; i < nexcl; i++)
        excl2[i] = excl[i];
    excl2[nexcl] = (uint8_t)pb;
    n2 = nexcl + 1;
    return encode_cont_cebf(m, ks, ctx, rem, sym, excl2, n2);
}

int ppm_kernel_encode(ppm_model *m, int ctx, int sym, ppm_kstate *ks)
{
    uint32_t ent_total, ent_weight;
    int result;

    ks->weight = 0;
    ks->last_total = 0;
    ks->sse2_idx = -1;
    ks->sse2_up_idx = -1;
    ks->kernel_excl = -1;
    ks->supported = 1;
    if (!m->w)
        return -1;
    ent_total = m->cum[ctx][0];
    ent_weight = ((uint32_t)m->ent_wt[ctx] * m->order0_wt[ctx]) & PPM_M32;
    if (ent_total > ent_weight)
        result = encode_low_count_sse(m, ks, ctx, ent_total, sym, m->excl, m->nexcl);
    else
        result = encode_work_ctx(m, ks, sym, m->excl, m->nexcl);
    if (result < 0)
        ks->supported = 0;
    return result;
}
