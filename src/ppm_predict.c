#include "ppm_priv.h"

int ppm_ctx_res(const ppm_model *m)
{
    int b = m->c48 & 0xFF;
    if (m->byte_class == 0 && m->novel[(m->c48 >> 8) & 0xFF] != 0)
        b += 0x100;
    return b;
}

static int bin_decode(uha_rc *r, uint32_t prob)
{
    uint32_t runit, freq, low, high;
    int hit;

    runit = r->range / 0x2000;
    freq = (r->code / runit) & 0xFFFF;
    hit = freq < prob;
    if (hit) {
        low = 0;
        high = prob;
    } else {
        low = prob;
        high = 0x2000;
    }
    r->code = (r->code - low * runit) & PPM_M32;
    r->range = ((high - low) * runit) & PPM_M32;
    uha_rc_normalize(r);
    return hit;
}

int ppm_predicted_decode(ppm_model *m, uha_rc *r, uint32_t rec1_idx, int *sym)
{
    uint32_t rollctx, rec2idx, idx, sse, prob, pidx;
    int ctx, rd, local_b8, local_d0, d0slot;

    rollctx = m->c48;
    rec2idx = rollctx & 0xFFFF;
    if (m->byte_class == 0 && m->novel[(rollctx >> 16) & 0xFF] != 0)
        rec2idx += 0x10000;
    ctx = ppm_ctx_res(m);
    local_b8 = m->pred_byte[ctx];
    d0slot = m->rec2s[rec2idx][0x13] & 0xF;
    local_d0 = m->rec2s[rec2idx][d0slot + 9];
    rd = m->rec1s[rec1_idx][0xD];

    idx = m->rec1s[rec1_idx][1];
    if (rd == local_d0)
        idx += m->rec2s[rec2idx][0x13] >> 4;
    if (rd == local_b8)
        idx += m->cls_idx[ctx];

    sse = 0;
    if (rd == local_d0)
        sse = 1;
    if (rd == local_b8)
        sse |= 1;
    if (m->rec2s[rec2idx][7] != 0 && m->c54 < 6)
        sse |= 0x10;

    if (m->byte_class == 0) {
        if (m->novel[rd] != 0)
            sse |= 2;
    } else {
        if (m->win_pos <= m->t46a[rd & 0xFF])
            sse |= 0x100;
        if (rd == (int)(rollctx & 0xFF))
            sse |= 2;
    }
    if (idx < 0x1E) {
        sse |= (rollctx & 0xE0);
        if (m->byte_class == 0) {
            sse |= ((uint32_t)m->novel[(rollctx >> 8) & 0xFF] << 2);
            sse |= ((uint32_t)m->novel[rollctx & 0xFF] << 3);
        } else {
            if ((rollctx & 0xE0) == ((rollctx >> 8) & 0xE0))
                sse |= 8;
            if ((rollctx & 0xE0) == ((uint32_t)rd & 0xE0))
                sse |= 4;
        }
    }
    if (m->last_ctx == m->last_sym[rd])
        sse |= 0x200;

    pidx = PPMS_PAGETAB[idx] * 0x400 + sse;
    prob = m->pred_prob[pidx] & 0xFFFF;
    if (bin_decode(r, prob)) {
        *sym = rd;
        m->pred_prob[pidx] = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        return 1;
    }
    *sym = -1;
    m->pred_prob[pidx] = (prob - (prob >> 6)) & PPM_M32;
    return 0;
}

static int bin_encode(uha_rcw *w, uint32_t prob, int hit)
{
    if (!w)
        return 0;
    if (hit)
        return uha_rcw_encode(w, 0, prob, 0x2000) == 0;
    return uha_rcw_encode(w, prob, 0x2000, 0x2000) == 0;
}

int ppm_predicted_encode(ppm_model *m, uint32_t rec1_idx, int target, int *sym)
{
    uint32_t rollctx, rec2idx, idx, sse, prob, pidx;
    int ctx, rd, local_b8, local_d0, d0slot, hit;

    rollctx = m->c48;
    rec2idx = rollctx & 0xFFFF;
    if (m->byte_class == 0 && m->novel[(rollctx >> 16) & 0xFF] != 0)
        rec2idx += 0x10000;
    ctx = ppm_ctx_res(m);
    local_b8 = m->pred_byte[ctx];
    d0slot = m->rec2s[rec2idx][0x13] & 0xF;
    local_d0 = m->rec2s[rec2idx][d0slot + 9];
    rd = m->rec1s[rec1_idx][0xD];

    idx = m->rec1s[rec1_idx][1];
    if (rd == local_d0)
        idx += m->rec2s[rec2idx][0x13] >> 4;
    if (rd == local_b8)
        idx += m->cls_idx[ctx];

    sse = 0;
    if (rd == local_d0)
        sse = 1;
    if (rd == local_b8)
        sse |= 1;
    if (m->rec2s[rec2idx][7] != 0 && m->c54 < 6)
        sse |= 0x10;

    if (m->byte_class == 0) {
        if (m->novel[rd] != 0)
            sse |= 2;
    } else {
        if (m->win_pos <= m->t46a[rd & 0xFF])
            sse |= 0x100;
        if (rd == (int)(rollctx & 0xFF))
            sse |= 2;
    }
    if (idx < 0x1E) {
        sse |= (rollctx & 0xE0);
        if (m->byte_class == 0) {
            sse |= ((uint32_t)m->novel[(rollctx >> 8) & 0xFF] << 2);
            sse |= ((uint32_t)m->novel[rollctx & 0xFF] << 3);
        } else {
            if ((rollctx & 0xE0) == ((rollctx >> 8) & 0xE0))
                sse |= 8;
            if ((rollctx & 0xE0) == ((uint32_t)rd & 0xE0))
                sse |= 4;
        }
    }
    if (m->last_ctx == m->last_sym[rd])
        sse |= 0x200;

    pidx = PPMS_PAGETAB[idx] * 0x400 + sse;
    prob = m->pred_prob[pidx] & 0xFFFF;
    hit = (target == rd);
    if (!bin_encode(m->w, prob, hit))
        return 0;
    if (hit) {
        *sym = rd;
        m->pred_prob[pidx] = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        return 1;
    }
    *sym = -1;
    m->pred_prob[pidx] = (prob - (prob >> 6)) & PPM_M32;
    return 0;
}

int ppm_entry_decode(ppm_model *m, uha_rc *r, uint32_t rec2_idx, uint32_t *prob_out)
{
    int ctx, r9, local_b8;
    uint32_t idx, sse, prob, pidx;

    r9 = m->rec2s[rec2_idx][9];
    ctx = ppm_ctx_res(m);
    if (m->byte_class != 0)
        local_b8 = ppm_bc1_st.pred[ctx & 0xFF];
    else
        local_b8 = m->pred_byte[ctx];
    sse = 0;
    if (r9 == local_b8)
        sse = 1;
    idx = m->rec2s[rec2_idx][1] >> 1;
    if (r9 == local_b8)
        idx += m->cls_idx[ctx];
    if (idx < 0x10) {
        if (m->byte_class == 0) {
            sse |= ((uint32_t)m->novel[(m->c48 >> 8) & 0xFF] << 1);
            sse |= ((uint32_t)m->novel[m->c48 & 0xFF] << 2);
        } else
            sse |= ((m->c48 & 0xC0) >> 5);
    }
    if (m->win_pos <= m->t46a[r9 & 0xFF])
        sse |= 0x8;
    if (m->last_ctx == m->last_sym[r9])
        sse |= 0x10;
    pidx = PPMS_PAGETAB[idx] * 0x20 + sse;
    prob = m->entry_prob[pidx] & 0xFFFF;
    *prob_out = prob;
    if (bin_decode(r, prob)) {
        m->entry_prob[pidx] = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        return 1;
    }
    m->entry_prob[pidx] = (prob - (prob >> 6)) & PPM_M32;
    return 0;
}

int ppm_entry_encode(ppm_model *m, uint32_t rec2_idx, int target, uint32_t *prob_out)
{
    int ctx, r9, local_b8, hit;
    uint32_t idx, sse, prob, pidx;

    r9 = m->rec2s[rec2_idx][9];
    ctx = ppm_ctx_res(m);
    if (m->byte_class != 0)
        local_b8 = ppm_bc1_st.pred[ctx & 0xFF];
    else
        local_b8 = m->pred_byte[ctx];
    sse = 0;
    if (r9 == local_b8)
        sse = 1;
    idx = m->rec2s[rec2_idx][1] >> 1;
    if (r9 == local_b8)
        idx += m->cls_idx[ctx];
    if (idx < 0x10) {
        if (m->byte_class == 0) {
            sse |= ((uint32_t)m->novel[(m->c48 >> 8) & 0xFF] << 1);
            sse |= ((uint32_t)m->novel[m->c48 & 0xFF] << 2);
        } else
            sse |= ((m->c48 & 0xC0) >> 5);
    }
    if (m->win_pos <= m->t46a[r9 & 0xFF])
        sse |= 0x8;
    if (m->last_ctx == m->last_sym[r9])
        sse |= 0x10;
    pidx = PPMS_PAGETAB[idx] * 0x20 + sse;
    prob = m->entry_prob[pidx] & 0xFFFF;
    *prob_out = prob;
    hit = (target == r9);
    if (!bin_encode(m->w, prob, hit))
        return 0;
    if (hit) {
        m->entry_prob[pidx] = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        return 1;
    }
    m->entry_prob[pidx] = (prob - (prob >> 6)) & PPM_M32;
    return 0;
}
