#include "ppm_priv.h"
#include <stdio.h>
#include <stdlib.h>

/* [GATED UHA_C550DBG, M90] tag of route of the learn (set at the input some post), for nommer the doublelearn encode. */
int g_upd_route = 0;

void ppm_recency_update(uint32_t *tbl, int flag, uint32_t bec)
{
    uint32_t old = tbl[flag];
    tbl[flag] = (bec + ((old * 31) >> 5)) & PPM_M32;
}

void ppm_agering_commit(ppm_model *m, int idx, uint32_t bec)
{
    uint32_t old_ring;
    m->age_ctr = (uint32_t)idx;
    old_ring = m->age_ring[idx];
    m->age = (m->age - old_ring + bec) & PPM_M32;
    m->age_ring[idx] = bec;
}

void ppm_update_predbyte(ppm_model *m, int ctx, int sym)
{
    uint8_t c;
    if (sym == m->pred_byte[ctx]) {
        c = m->cls_idx[ctx];
        if (c < 0xF)
            m->cls_idx[ctx] = (uint8_t)(c + 1);
    } else {
        m->pred_byte[ctx] = (uint8_t)(sym & 0xFF);
        m->cls_idx[ctx] = 0;
    }
}

void ppm_update_rolling_ctx(ppm_model *m, int sym)
{
    uint32_t c0, c1, c2;
    if (m->byte_class == 0 && sym >= 0x04 && sym <= 0x06) {
        if ((m->roll_ctx0 & 0xFF) == 0xDF)
            return;
        sym = 0xDF;
    }
    c0 = m->roll_ctx0;
    c1 = m->roll_ctx1;
    c2 = m->roll_ctx2;
    m->roll_ctx0 = ((c0 << 8) | (sym & 0xFF)) & PPM_M32;
    m->roll_ctx1 = ((c1 << 8) | ((c0 >> 24) & 0xFF)) & PPM_M32;
    m->roll_ctx2 = ((c2 << 8) | ((c1 >> 24) & 0xFF)) & PPM_M32;
}

int ppm_lzp_decode_class(ppm_model *m, uha_rc *r, int ctx_byte)
{
    int order, total, freq, counter, idx, sel;
    uint32_t low, high;

    ctx_byte &= 0xFF;
    order = m->flag3934;
    (void)order;
    for (;;) {
        total = m->lzp_class_rec[ctx_byte][3];
        r->range /= (uint32_t)total;
        freq = (int)((r->code / r->range) & 0xFFFF);
        counter = 3;
        idx = 3;
        while (counter != 0) {
            counter--;
            idx--;
            if (freq >= m->lzp_class_rec[ctx_byte][idx])
                break;
        }
        low = m->lzp_class_rec[ctx_byte][idx];
        high = m->lzp_class_rec[ctx_byte][idx + 1];
        uha_rc_remove(r, low, high);
        if (counter != 0)
            return counter;
        r->range /= 0xA;
        sel = (int)((r->code / r->range) & 0xFFFF);
        uha_rc_remove(r, (uint32_t)sel, (uint32_t)sel + 1);
        if (!ppm_select_class(m, sel))
            return -1;
        order = m->flag3934;
        (void)order;
    }
}

int ppm_lzp_encode_escape(ppm_model *m, int ctx_byte, int sel)
{
    int total;

    if (!m || !m->w || sel < 0 || sel > 9)
        return -1;
    ctx_byte &= 0xFF;
    total = m->lzp_class_rec[ctx_byte][3];
    if (total <= 0)
        return -1;
    if (uha_rcw_encode(m->w, m->lzp_class_rec[ctx_byte][0],
                       m->lzp_class_rec[ctx_byte][1], (uint32_t)total) != 0)
        return -1;
    if (uha_rcw_encode(m->w, (uint32_t)sel, (uint32_t)sel + 1, 10) != 0)
        return -1;
    if (!ppm_select_class(m, sel))
        return -1;
    return sel;
}

int ppm_lzp_encode_class(ppm_model *m, int ctx_byte, int cls)
{
    int total;
    uint32_t low, high;

    if (!m || !m->w)
        return -1;
    ctx_byte &= 0xFF;
    total = m->lzp_class_rec[ctx_byte][3];
    if (total <= 0)
        return -1;
    if (cls == 1) {
        low = m->lzp_class_rec[ctx_byte][1];
        high = m->lzp_class_rec[ctx_byte][2];
    } else if (cls == 2) {
        low = m->lzp_class_rec[ctx_byte][2];
        high = m->lzp_class_rec[ctx_byte][3];
    } else
        return -1;
    if (high <= low)
        return -1;
    if (uha_rcw_encode(m->w, low, high, (uint32_t)total) != 0)
        return -1;
    return cls;
}

void ppm_lzp_apply_update(ppm_model *m, int ctx_byte, int cls)
{
    uint32_t tot, cx, bx, ebx, ecx;

    ctx_byte &= 0xFF;
    if (cls == 1)
        m->lzp_class_rec[ctx_byte][2] = (uint16_t)((m->lzp_class_rec[ctx_byte][2] + 0x20) & 0xFFFF);
    tot = (m->lzp_class_rec[ctx_byte][3] + 0x20) & 0xFFFF;
    m->lzp_class_rec[ctx_byte][3] = (uint16_t)tot;
    if (tot >= 0x4000) {
        cx = m->lzp_class_rec[ctx_byte][2];
        bx = m->lzp_class_rec[ctx_byte][1];
        ebx = ((cx - bx) + 1) >> 1;
        ecx = ((m->lzp_class_rec[ctx_byte][3] - cx) + 1) >> 1;
        ebx = ebx + m->lzp_class_rec[ctx_byte][1];
        m->lzp_class_rec[ctx_byte][2] = (uint16_t)(ebx & 0xFFFF);
        m->lzp_class_rec[ctx_byte][3] = (uint16_t)((ecx + ebx) & 0xFFFF);
    }
    m->base46 = PPMS_LZPTRANS[m->base46 * 2 + cls];
}
