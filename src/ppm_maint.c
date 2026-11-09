#include "ppm_priv.h"
#include <stdlib.h>

void ppm_ring_recompute(ppm_model *m)
{
    uint32_t c0 = m->roll_ctx0, c1 = m->roll_ctx1;
    m->ring_off[0] = (((c0 >> 0x10) & 0xFF00) + (c1 >> 0x18)) & PPM_M32;
    m->ring_off[1] = (((c0 >> 8) & 0xFFFF) + 0x10000) & PPM_M32;
    m->ring_off[2] = (((c0 >> 8) & 0xFF00) + 0x20000 + (c0 & 0xFF)) & PPM_M32;
    m->ring_off[3] = (((c0 << 8) & 0xFF00) + 0x30000 + (c1 & 0xFF)) & PPM_M32;
}

void ppm_ring_store(ppm_model *m, int sym)
{
    int i;
    for (i = 0; i <= 3; i++)
        m->ring_buf[m->ring_off[i]] = (uint8_t)(sym & 0xFF);
}

void ppm_lastsym_predict(ppm_model *m)
{
    int i;
    uint8_t b;
    for (i = 0; i <= 3; i++) {
        b = m->ring_buf[m->ring_off[i]];
        m->last_sym[b] = m->last_ctx;
    }
}

void ppm_marker_machine(ppm_model *m, int sym)
{
    int bh, obh;
    uint8_t ch, other;

    bh = m->last_ctx & 1;
    obh = 1 - bh;
    m->marker_c[bh] = (uint8_t)((m->marker_c[bh] * 2) & 0xF);
    m->marker_c[2 + bh] = (uint8_t)((m->marker_c[2 + bh] * 2) & 0xF);
    m->marker_fl = 0;
    if (sym < 0x80)
        return;
    if (sym == 0xFF) {
        m->marker_c[2 + bh] = (uint8_t)((m->marker_c[2 + bh] + 1) & 0xFF);
        other = m->marker_c[obh];
        if (other == 0xF && other == m->marker_c[2 + bh])
            m->marker_fl = 2;
        return;
    }
    if ((sym >= 0x80 && sym <= 0xDF) || (sym >= 0xF2 && sym <= 0xF6)) {
        ch = (uint8_t)((m->marker_c[bh] + 1) & 0xFF);
        m->marker_c[bh] = ch;
        other = m->marker_c[2 + obh];
        if (other == 0xF && ch == other)
            m->marker_fl = 1;
    }
}

void ppm_rank_machinery(ppm_model *m, int sym)
{
    uint32_t mask, winpos, eax, ebp, edx, edx2, ecx, a;
    int i;

    /* [GATED UHA_LASTCTX, defautOFF, M207] `m->last_ctx` n'had NO ecrivain then that the
     * legacy en pulls `[0x4803c0] % k` (0x41a30a) for `rank_ptr_small` (0x41a340) - therefore there
     * cellule lue by `[[0x481c30]] <= 0x3FE` (0x41a3a0). ON : `last_ctx` = position d'bytes.
     * No emissif by default. */
    { static int lc = -1; if (lc < 0) { const char *e = getenv("UHA_LASTCTX"); lc = (e && e[0] != '0') ? 1 : 0; }
      if (lc) m->last_ctx = m->out_count + 1u; }

    mask = m->win_mask;
    winpos = m->win_pos;

    if (sym == 0 || sym == 0xFF)
        goto stamp;
    eax = (winpos - m->recency[sym]) & mask;
    if (eax >= 0x100) {
        eax = (winpos - m->recency[(sym - 1) & 0xFF]) & mask;
        if (eax >= 0x100)
            eax = (winpos - m->recency[(sym + 1) & 0xFF]) & mask;
    }
    if (eax != 0 && eax < 0x100) {
        m->hist[eax] = (m->hist[eax] + 1) & PPM_M32;
        ebp = m->br18;
        if (eax != ebp) {
            edx = (winpos - ebp) & mask;
            if (sym == m->window[edx])
                m->hist[ebp] = (m->hist[ebp] + 1) & PPM_M32;
            else
                m->br10 = (m->br10 + 2) & PPM_M32;
            edx2 = m->br14;
            if (eax == edx2) {
                ecx = m->br18;
                if (m->hist[edx2] >= m->hist[ecx]) {
                    m->br14 = ecx;
                    m->br18 = eax;
                    if (eax > 1)
                        m->brf0 = eax;
                }
            } else {
                m->br14 = eax;
            }
        }
    }
    m->br10 = (m->br10 + 1) & PPM_M32;
    if (m->br10 >= 0x28) {
        for (i = 0; i <= 0xFF; i++)
            m->hist[i] >>= 1;
        a = m->br18;
        m->hist[a] = (m->hist[a] + 1) & PPM_M32;
        m->br10 = 0;
        if (a == 1) {
            ebp = m->hist[1];
            if (ebp < 4)
                m->hist[1] = (a + ebp) & PPM_M32;
        }
    }
    m->recency[sym] = winpos;
stamp:
    if (m->byte_class != 0)
        m->t46a[sym & 0xFF] = (winpos + 0x40) & PPM_M32;
}
