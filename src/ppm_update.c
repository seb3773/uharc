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
    /* [GATED UHA_C550DBG, defautOFF, M90] trace MRU pred_byte (path post/ppm_update). */
    { static int u = -1; if (u < 0) { const char *e = getenv("UHA_C550DBG"); u = (e && e[0] != '0') ? 1 : 0; }
      if (u) fprintf(stderr, "[UPDP] route=%d ctx=%d sym=%d pred_before=%d\n", g_upd_route, ctx, sym, m->pred_byte[ctx]); }
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
    /* [GATED UHA_CTXROLL, defautOFF, M207] law EXACT lue en `0x41922b..0x41928d` :
     *   if (bc != 0 || sym < 4 || sym > 6) -> NO update ;
     *   otherwise if (roll_ctx0 & 0xFF) == 0xDF -> nothing ;
     *   otherwise rotation some 3 registres with, for `0x48269c`, l'byte CONSTANT 0xDF.
     * L'old code tournait at each symbole with the symbole current : invisible en bc=0
     * (`c38`/`c40` n'y servent not) but measured false au 1er symbole of the block 2 (bc=1). */
    { static int cr = -1;
      if (cr < 0) { const char *e = getenv("UHA_CTXROLL"); cr = (e && e[0] != '0') ? 1 : 0; }
      if (cr) {
          if (!(m->byte_class == 0 && sym >= 0x04 && sym <= 0x06))
              return;
          if ((m->roll_ctx0 & 0xFF) == 0xDF)
              return;
          c0 = m->roll_ctx0; c1 = m->roll_ctx1; c2 = m->roll_ctx2;
          m->roll_ctx0 = ((c0 << 8) | 0xDFu) & PPM_M32;
          m->roll_ctx1 = ((c1 << 8) | ((c0 >> 24) & 0xFF)) & PPM_M32;
          m->roll_ctx2 = ((c2 << 8) | ((c1 >> 24) & 0xFF)) & PPM_M32;
          return;
      } }
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
        /* [GATED UHA_LZPCDBG, default-OFF, M164] escape of class : value `sel` and class before/after.
         * `sel` = new class ; not change nothing au contenu en bc=1 (has to verify by this trace). */
        { static int lzd = -1;
          if (lzd < 0) { const char *e = getenv("UHA_LZPCDBG"); lzd = (e && e[0] != '0') ? 1 : 0; }
          if (lzd) fprintf(stderr, "[LZE] pos=%u ctxb=%d sel=%d cur_avant=%d st=%d rec=%u,%u,%u,%u\n",
                          m->out_count, ctx_byte, sel, (int)m->flag3934, (int)m->base46,
                          m->lzp_class_rec[ctx_byte][0], m->lzp_class_rec[ctx_byte][1],
                          m->lzp_class_rec[ctx_byte][2], m->lzp_class_rec[ctx_byte][3]); }
        if (!ppm_select_class(m, sel))
            return -1;
        order = m->flag3934;
        (void)order;
    }
}

/* [M178, GATED UHA_LZPCDBG, defautOFF] Diagnostic some FAILURES of l'escape of class : en
 * multimembre l'encoder peut sortir en `encode error -1` without other trace. */
static int lzf_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_LZPCDBG"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

int ppm_lzp_encode_escape(ppm_model *m, int ctx_byte, int sel)
{
    /* [M169 lot 2] ESCAPE of class, mecanisme of 0x421dd8..0x421e04 (PROUVE 12/12 by UHA_LZP_ESC) :
     *   encode [rec0, rec1) / rec3   (column 0)
     *   encode sel / 10             (selecteur)
     *   select_class(sel)           (0x422d00 writes there class current)
     * The decodewr RE-READS ensuite there class (for(;;) of ppm_lzp_decode_class), therefore there class of the
     * node doit to be encodee NORMALEMENT after this call (ppm_lzp_encode_class). */
    int total;

    /* [M178, GATED UHA_LZPCDBG, defautOFF] Diagnostic some FAILURES of l'escape of class : the
     * multimembre peut sortir en `encode error -1` without other trace. Imprime there branch fautive
     * with ses operandes (no effect on l'state). */
    { if (lzf_on()) {
          int bad = (!m) ? 1 : (!m->w) ? 1 : (sel < 0 || sel > 9) ? 2
                  : (m->lzp_class_rec[ctx_byte & 0xFF][3] <= 0) ? 3 : 0;
          if (bad) fprintf(stderr, "[LZEF] pos=%u ctxb=%d sel=%d cur=%d rec=%u,%u,%u,%u branche=%d\n",
                           m ? m->out_count : 0u, ctx_byte, sel, m ? (int)m->flag3934 : -1,
                           m ? m->lzp_class_rec[ctx_byte & 0xFF][0] : 0u,
                           m ? m->lzp_class_rec[ctx_byte & 0xFF][1] : 0u,
                           m ? m->lzp_class_rec[ctx_byte & 0xFF][2] : 0u,
                           m ? m->lzp_class_rec[ctx_byte & 0xFF][3] : 0u, bad);
      } }
    if (!m->w || sel < 0 || sel > 9)
        return -1;
    ctx_byte &= 0xFF;
    total = m->lzp_class_rec[ctx_byte][3];
    if (total <= 0)
        return -1;
    if (uha_rcw_encode(m->w, m->lzp_class_rec[ctx_byte][0],
                       m->lzp_class_rec[ctx_byte][1], (uint32_t)total) != 0)
        { if (lzf_on()) fprintf(stderr, "[LZEF] branche=4 rc1 pos=%u ctxb=%d sel=%d total=%d rec=%u,%u\n",
                           m->out_count, ctx_byte, sel, total,
                           m->lzp_class_rec[ctx_byte][0], m->lzp_class_rec[ctx_byte][1]);
          return -1; }
    if (uha_rcw_encode(m->w, (uint32_t)sel, (uint32_t)sel + 1, 10) != 0)
        { if (lzf_on()) fprintf(stderr, "[LZEF] branche=5 rc2 pos=%u ctxb=%d sel=%d total=%d\n",
                           m->out_count, ctx_byte, sel, total);
          return -1; }
    if (!ppm_select_class(m, sel))
        { if (lzf_on()) fprintf(stderr, "[LZEF] branche=6 sel=%d\n", sel);
          return -1; }
    return sel;
}

int ppm_lzp_encode_class(ppm_model *m, int ctx_byte, int cls)
{
    int total;
    uint32_t low, high;

    if (!m->w)
        return -1;
    ctx_byte &= 0xFF;
    total = m->lzp_class_rec[ctx_byte][3];
    /* [GATED UHA_LZPCDBG, default-OFF, M164] masses of class LZP au node : the residu
     * `mixed.bin` @pos=34748 is has ESCAPE of class (legacy l.80+l.83) that nous n'encodons not. */
    { static int lz = -1;
      if (lz < 0) { const char *e = getenv("UHA_LZPCDBG"); lz = (e && e[0] != '0') ? 1 : 0; }
      if (lz) fprintf(stderr, "[LZC] pos=%u ctxb=%d cls=%d cur=%d rec=%u,%u,%u,%u\n",
                      m->out_count, ctx_byte, cls, (int)m->flag3934,
                      m->lzp_class_rec[ctx_byte][0], m->lzp_class_rec[ctx_byte][1],
                      m->lzp_class_rec[ctx_byte][2], m->lzp_class_rec[ctx_byte][3]); }
    if (total <= 0)
        return -1;
    /* [GATED UHA_LZP_ESC, default-OFF, M167] emission FORCEE of the path escape legacy
     * (column 0 -> selecteur 10 -> relecture of class), has (pos, ctx, sel) donnes.
     * But : PROUVER the mecanisme of ppm_lzp_decode_class l.80/l.83 without connaitre there law
     * of declenchement. Format : "pos:ctx:sel". Not change nothing if there gate is absente. */
    { static int lzesc = -1, epos = -1, ectx = -1, esel = 0;
      if (lzesc < 0) {
          const char *e = getenv("UHA_LZP_ESC");
          lzesc = 0;
          if (e && e[0] && e[0] != '0') {
              int p = -1, c = -1, s = -1;
              if (sscanf(e, "%d:%d:%d", &p, &c, &s) == 3) { epos = p; ectx = c; esel = s; lzesc = 1; }
          }
      }
      if (lzesc && (int)m->out_count == epos && ctx_byte == ectx) {
          if (uha_rcw_encode(m->w, m->lzp_class_rec[ctx_byte][0],
                             m->lzp_class_rec[ctx_byte][1], (uint32_t)total) != 0)
              return -1;
          if (uha_rcw_encode(m->w, (uint32_t)esel, (uint32_t)esel + 1, 10) != 0)
              return -1;
          if (fprintf(stderr, "[LZF] pos=%u ctxb=%d sel=%d cur_avant=%d\n",
                      m->out_count, ctx_byte, esel, (int)m->flag3934) < 0)
              return -1;
          if (!ppm_select_class(m, esel))
              return -1;
          total = m->lzp_class_rec[ctx_byte][3];
      } }
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
