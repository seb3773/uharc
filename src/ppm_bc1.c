#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include "ppm_priv.h"

ppm_bc1 ppm_bc1_st;
int ppm_bc1_ring_ran;
int ppm_bc1_post_armed;
int ppm_bc1_rec_ok;
int ppm_bc1_f154_pending;
uint32_t ppm_bc1_f154_key;

static uint32_t rec_base(int level, uint32_t ctx)
{
    return BC1_LVLOFF[level] + ctx * 4;
}

void ppm_bc1_block_reset(void)
{
    int i;
    if (!ppm_bc1_st.lvl) {
        ppm_bc1_st.lvl = calloc(PPM_BC1_LVLBYTES, 1);
        if (!ppm_bc1_st.lvl)
            return;
    } else
        memset(ppm_bc1_st.lvl, 0, PPM_BC1_LVLBYTES);
    for (i = 0; i <= 0x7F; i++)
        ppm_bc1_st.ring[i] = 1;
    for (i = 0; i <= 0xFF; i++) {
        ppm_bc1_st.conf[i] = 0;
        ppm_bc1_st.pred[i] = 0xFF;
    }
}

void ppm_bc1_reset(void)
{
    int i;
    ppm_bc1_block_reset();
    for (i = 0; i <= 0xFFF; i++)
        ppm_bc1_st.win[i] = 0;
    ppm_bc1_st.wpos = 0x140;
    ppm_bc1_st.ring_ptr = -1;
    ppm_bc1_st.best = 8;
    ppm_bc1_st.last_best = 0;
    ppm_bc1_st.best_pred = 0;
    ppm_bc1_st.best_flags = 0;
}

static void bc1_nomatch_exit(ppm_model *m)
{
    if (m->br18 > 1)
        m->rank_small[m->rank_ptr_small] >>= 1;
}

int ppm_bc1_predecode(ppm_model *m, uint32_t r0, uint32_t r1)
{
    uint32_t b0, b1, b2, b3, c3, depth, byte_a, byte_b, flag;
    int level;
    uint32_t rb, c0, c1, c3f, score, best, bh;

    b0 = r0 & 0xFF;
    b1 = (r0 >> 8) & 0xFF;
    b2 = (r0 >> 16) & 0xFF;
    b3 = (r0 >> 24) & 0xFF;
    c3 = (r1 >> 24) & 0xFF;

    if ((r0 & 0xFFFF0000) == 0xFFFF0000)
        depth = 0x10000;
    else if ((r0 & 0xFFFF) == 0xFFFF)
        depth = 0x20000;
    else if ((r0 & 0xFF000000) == 0xFF000000)
        depth = 0x30000;
    else if ((r0 & 0xFF0000) == 0xFF0000)
        depth = 0x40000;
    else if ((r0 & 0xFF00) == 0xFF00)
        depth = 0x50000;
    else if ((r0 & 0xFF) == 0xFF)
        depth = 0x60000;
    else
        depth = 0;

    ppm_bc1_st.ctx[0] = (b3 << 8) + c3;
    ppm_bc1_st.ctx[1] = (r0 >> 8) & 0xFFFF;
    ppm_bc1_st.ctx[2] = (r0 >> 16) & 0xFFFF;
    ppm_bc1_st.ctx[3] = (b2 << 8) + b0;
    ppm_bc1_st.ctx[4] = (b3 << 8) + b1;
    ppm_bc1_st.ctx[5] = (b3 << 8) + b0;
    ppm_bc1_st.ctx[6] = (r1 & 0xFFFF) + depth;

    if (m->brf0 != 0 && m->flag3939 != m->brf0) {
        flag = ((m->last_ctx % m->brf0) << 8) & 0xFFFF;
        byte_a = m->window[(m->win_pos - m->brf0) & m->win_mask];
        byte_b = m->window[(m->win_pos - 2 * m->brf0) & m->win_mask];
    } else {
        byte_a = ppm_bc1_st.win[(ppm_bc1_st.wpos - 1) & 0xFFF];
        byte_b = ppm_bc1_st.win[(ppm_bc1_st.wpos - 2) & 0xFFF];
        flag = (((r0 >> 16) & 0xFFFF) == 0xF6FF) ? 0x100 : 0;
    }
    ppm_bc1_st.ctx[7] = (flag + ((byte_a - byte_b) & 0xFF)) & 0xFFFF;
    ppm_bc1_f154_pending = 0;
    if (ppm_bc1_st.lvl)
        ppm_bc1_st.lvl[rec_base(7, ppm_bc1_st.ctx[7]) + 2] = (uint8_t)((2 * byte_a - byte_b) & 0xFF);

    if (b0 == 0xFF) {
        ppm_bc1_st.ctx[1] += 0x10000;
        ppm_bc1_st.ctx[2] += 0x10000;
    }

    ppm_bc1_st.ring_ptr = -1;
    ppm_bc1_rec_ok = 0;
    ppm_bc1_st.fired393c = 0;
    best = 0;
    bh = 8;
    if (!ppm_bc1_st.lvl) {
        ppm_bc1_st.ring_flag = 1;
        return 0;
    }
    for (level = 0; level <= 7; level++) {
        rb = rec_base(level, ppm_bc1_st.ctx[level]);
        c0 = ppm_bc1_st.lvl[rb];
        c1 = ppm_bc1_st.lvl[rb + 1];
        c3f = ppm_bc1_st.lvl[rb + 3];
        if (c0 == 0)
            continue;
        if (c3f >= 0x80)
            continue;
        score = ((c1 << 8) * c3f) / c0;
        if (score > best) {
            best = score;
            bh = (uint32_t)level;
        }
    }
    ppm_bc1_st.best = (int)bh;
    if (bh >= 8) {
        bc1_nomatch_exit(m);
        ppm_bc1_st.ring_flag = 1;
        return 0;
    }

    rb = rec_base((int)bh, ppm_bc1_st.ctx[bh]);
    ppm_bc1_st.best_pred = ppm_bc1_st.lvl[rb + 2];
    ppm_bc1_st.best_flags = ppm_bc1_st.lvl[rb + 3];
    c0 = ppm_bc1_st.lvl[rb];
    c1 = ppm_bc1_st.lvl[rb + 1];
    ppm_bc1_st.best_c0 = (uint8_t)(c0 & 0xFF);
    ppm_bc1_st.best_c1 = (uint8_t)(c1 & 0xFF);

    if ((c1 <= c0) && ((ppm_bc1_st.best_flags & 0x7F) <= 1)) {
        bc1_nomatch_exit(m);
        ppm_bc1_st.ring_flag = 1;
        return 0;
    }

    ppm_bc1_st.fired393c = (m->brf0 > 1) && (bh == 7);
    ppm_bc1_st.last_best = (int)bh;
    ppm_bc1_rec_ok = 1;

    if ((c0 * 5 <= c1 * 3) || ((ppm_bc1_st.best_flags & 0x7F) > 2))
        ppm_bc1_st.ring_flag = 0;
    else
        ppm_bc1_st.ring_flag = 1;
    if (c0 == 2) {
        if (c1 >= 3 && c1 <= 6)
            ppm_bc1_st.ring_ptr = (int)(((c1 << 3) - 0x18 + bh) * 2);
    } else if (c0 == 3) {
        if (c1 >= 4 && c1 <= 7)
            ppm_bc1_st.ring_ptr = (int)(((c1 << 3) - 0x20 + bh) * 2 + 0x40);
    }
    return 1 || (ppm_bc1_st.ring_ptr >= 0);
}

void ppm_bc1_ring_masses(const uint32_t *w, const uint8_t *y, uint32_t *m0, uint32_t *m1)
{
    int i;
    uint32_t rp;
    if (ppm_bc1_st.ring_ptr < 0) {
        *m0 = ppm_bc1_st.best_c0;
        *m1 = ppm_bc1_st.best_c1 + BC1_WT070[(ppm_bc1_st.best_flags >> 3) & 0xF];
    } else {
        rp = (uint32_t)ppm_bc1_st.ring_ptr;
        *m0 = ppm_bc1_st.ring[rp];
        *m1 = ppm_bc1_st.ring[rp + 1] + BC1_WT070[(ppm_bc1_st.best_flags >> 3) & 0xF];
    }
    for (i = 0; i <= 2; i++) {
        if (ppm_bc1_st.best_pred == y[i])
            *m1 += w[i];
        else
            *m0 += w[i];
    }
    /* [GATED UHA_BC1DBG, default-OFF, M164] masses of the ring bc1 by call : the 2 lectures
     * `(x,x+1)` sure total 256 of l'archive legacy @pos=34748 are has ring bc1 (m0+m1=256).
     * `n` = numero d'call (1 by node literal) : has correler with there trace `[TR2 dec]`.
     * (no `m` here : there function not recoit that w/y). */
    { static int b1 = -1; static unsigned long n = 0;
      if (b1 < 0) { const char *e = getenv("UHA_BC1DBG"); b1 = (e && e[0] != '0') ? 1 : 0; }
      if (b1) fprintf(stderr, "[BC1] n=%lu rp=%d c0=%u c1=%u m0=%u m1=%u tot=%u\n",
                      n++, ppm_bc1_st.ring_ptr, ppm_bc1_st.best_c0,
                      ppm_bc1_st.best_c1, *m0, *m1, *m0 + *m1); }
}

int ppm_bc1_ring_decode(uha_rc *r, uint32_t m0, uint32_t m1)
{
    uint32_t total, freq, low, width;
    total = m0 + m1;
    if (total == 0)
        return 0;
    freq = uha_rc_threshold(r, total);
    if (freq < m0) {
        low = 0;
        width = m0;
        uha_rc_remove(r, low, low + width);
        return 0;
    }
    low = m0;
    width = m1;
    uha_rc_remove(r, low, low + width);
    return 1;
}

/* t12g - mirror encoder of ppm_bc1_ring_decode (intervals [0,m0)=miss and
 * [m0,m0+m1)=hit sure total=m0+m1 ; total==0 = no cost RC side decodeur). */
int ppm_bc1_ring_encode(ppm_model *m, uint32_t m0, uint32_t m1, int hit)
{
    uint32_t total = m0 + m1;

    if (total == 0)
        return 0;
    if (hit)
        return uha_rcw_encode(m->w, m0, total, total) == 0 ? 1 : -1;
    if (m0 == 0)
        return -1;
    return uha_rcw_encode(m->w, 0, m0, total) == 0 ? 0 : -1;
}

void ppm_bc1_post_update(ppm_model *m, uint8_t sym)
{
    int level;
    uint32_t rb, rp, hit;
    uint8_t c0, c1, c2, c3;

    if (!ppm_bc1_st.lvl)
        return;
    for (level = 0; level <= 7; level++) {
        rb = rec_base(level, ppm_bc1_st.ctx[level]);
        c0 = ppm_bc1_st.lvl[rb];
        if (c0 == 0) {
            ppm_bc1_st.lvl[rb] = 2;
            ppm_bc1_st.lvl[rb + 1] = 2;
            ppm_bc1_st.lvl[rb + 2] = sym;
            ppm_bc1_st.lvl[rb + 3] = 0;
            continue;
        }
        if (level == ppm_bc1_st.last_best) {
            c1 = ppm_bc1_st.lvl[rb + 1];
            c2 = ppm_bc1_st.lvl[rb + 2];
            if (ppm_bc1_ring_ran && ((uint32_t)c0 + (uint32_t)c1) != 0) {
                if (sym == c2) {
                    m->flag3943 = 0;
                    ppm_bc1_f154_key = ((uint32_t)c1 << 14) / ((uint32_t)c0 + (uint32_t)c1);
                } else
                    ppm_bc1_f154_key = ((uint32_t)c0 << 14) / ((uint32_t)c0 + (uint32_t)c1);
                ppm_bc1_f154_pending = 1;
                if (ppm_bc1_f154_key < 0x4000)
                    m->bfc = (m->bfc + (m->f154[ppm_bc1_f154_key] & 0xFFFF)) & PPM_M32;
            }
            if (ppm_bc1_st.ring_ptr >= 0) {
                rp = (uint32_t)ppm_bc1_st.ring_ptr;
                hit = (uint32_t)(sym == c2);
                ppm_bc1_st.ring[rp + hit]++;
                if (ppm_bc1_st.ring[rp + 1] >= 0xFE || ppm_bc1_st.ring[rp] >= 0xFE) {
                    ppm_bc1_st.ring[rp] = (uint8_t)((ppm_bc1_st.ring[rp] + 1) >> 1);
                    ppm_bc1_st.ring[rp + 1] = (uint8_t)((ppm_bc1_st.ring[rp + 1] + 1) >> 1);
                }
            }
        }
        c3 = ppm_bc1_st.lvl[rb + 3] & 0x7F;
        c2 = ppm_bc1_st.lvl[rb + 2];
        ppm_bc1_st.lvl[rb + 3] = c3;
        c0 = ppm_bc1_st.lvl[rb];
        c1 = ppm_bc1_st.lvl[rb + 1];
        if (sym == c2) {
            if (c1 >= 0xFE) {
                c0 = (uint8_t)((c0 + 1) >> 1);
                c1 = (uint8_t)((c1 + 1) >> 1);
            }
            c1++;
            ppm_bc1_st.lvl[rb] = c0;
            ppm_bc1_st.lvl[rb + 1] = c1;
            if (c3 < 0x7F)
                ppm_bc1_st.lvl[rb + 3] = (uint8_t)(c3 + 1);
        } else {
            if (c0 >= 0xFE) {
                c0 = (uint8_t)((c0 + 1) >> 1);
                c1 = (uint8_t)((c1 + 1) >> 1);
            }
            c0++;
            ppm_bc1_st.lvl[rb] = c0;
            ppm_bc1_st.lvl[rb + 1] = c1;
            if (c3 < 2) {
                ppm_bc1_st.lvl[rb + 2] = sym;
                ppm_bc1_st.lvl[rb + 3] = 0x80;
            } else
                ppm_bc1_st.lvl[rb + 3] = (uint8_t)((c3 >> 1) + 0x80);
        }
    }
}

void ppm_bc1_sub2_update(uint8_t ctx_byte, uint8_t sym)
{
    if (sym == ppm_bc1_st.pred[ctx_byte]) {
        if (ppm_bc1_st.conf[ctx_byte] < 0xF)
            ppm_bc1_st.conf[ctx_byte]++;
    } else {
        ppm_bc1_st.pred[ctx_byte] = sym;
        ppm_bc1_st.conf[ctx_byte] = 0;
    }
}

void ppm_bc1_push_window(uint8_t sym)
{
    ppm_bc1_st.win[ppm_bc1_st.wpos & 0xFFF] = sym;
    ppm_bc1_st.wpos++;
}
