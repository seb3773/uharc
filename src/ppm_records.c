#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ppm_priv.h"

extern int g_upd_route;
extern int g_promo_silent;   /* [M211] 1 = the warm-up of promotion bc1 not touche not rec_globals */

long g_recg_calls = 0;   /* [M211] nombre d'calls of rec_globals (diagnostic) */

static void rec_globals(ppm_model *m)
{
    uint32_t edx = (m->dcg + 2) & PPM_M32;
    g_recg_calls++;
    /* [M212 GATED UHA_RECGRID] grille of 4096 bytes in [937 696, 1 071 004] : there first
     * divergence d'calls with the legacy engine designe the path fautif (matches courts ? literals ?). */
    /* [M213 GATED UHA_RECGTRACE="lo:hi"] has line by call in there range (out, dcg, c4g) :
     * sequence comparable 1:1 to legacy (sites 0x418a5e and 0x418f4b reunis). */
    { static long tlo = -1, thi = -1;
      if (tlo == -1) {
          const char *e = getenv("UHA_RECGTRACE");
          if (e && e[0] != '0') {
              const char *c = strchr(e, ':');
              tlo = atol(e); thi = c ? atol(c + 1) : tlo + 10;
          } else { tlo = 0; thi = -2; }
      }
      if (thi >= tlo && (long)m->out_count >= tlo && (long)m->out_count <= thi)
          fprintf(stderr, "[RECGT] out=%u dcg=%u c4g=%u a8g=%u\n",
                  m->out_count, (unsigned)m->dcg, (unsigned)m->c4g, (unsigned)m->a8g); }
    /* [M214 GATED UHA_RECS] creations of record in there range : counter + has line by cas. */
    { static long slo = -1;
      if (slo == -1) {
          const char *e = getenv("UHA_RECS");
          if (e && e[0] != '0') {
              slo = atol(e);
          } else { slo = 0; }
      } }
    { static int rg = -1; static uint32_t next = 937696u;
      if (rg < 0) { const char *e = getenv("UHA_RECGRID"); rg = (e && e[0] != '0') ? 1 : 0; }
      if (rg && m->out_count >= next && m->out_count <= 1071004u) {
          fprintf(stderr, "[RECGRID] out=%u dcg=%u c4g=%u a8g=%u recg=%ld\n",
                  m->out_count, (unsigned)m->dcg, (unsigned)m->c4g, (unsigned)m->a8g, g_recg_calls);
          next += 4096u;
      } }
    if (g_promo_silent)
        return;
    m->dcg = edx;
    if (edx > 0x800) {
        m->dcg = edx >> 1;
        m->c4g >>= 1;
        m->a8g >>= 1;
    }
}

static int rec1_sort(uint8_t *r, int cl)
{
    uint8_t t;
    while (cl > 0 && r[1 + cl] >= r[cl]) {
        t = r[1 + cl];
        r[1 + cl] = r[cl];
        r[cl] = t;
        t = r[0xD + cl];
        r[0xD + cl] = r[0xC + cl];
        r[0xC + cl] = t;
        r[0x1A] = (uint8_t)((r[0x1A] - 1) & 0xFF);
        cl--;
    }
    return cl;
}

static void rec1_special(ppm_model *m, int sym, uint32_t c38)
{
    uint32_t ctx, best, edx, cur, cur_cnt_plus, best_score, cur_run, idx;
    (void)sym;

    ctx = c38 & 0x7FFF;
    edx = 0;
    best = 0;
    if (m->rec1s[ctx][0] != 0) {
        cur = ctx;
        for (;;) {
            cur_cnt_plus = (m->rec1s[cur][1] + 1) & PPM_M32;
            best_score = m->rec1s[ctx + best][0x19] & 0x3F;
            if (m->rec1s[ctx + best][1] > cur_cnt_plus)
                best_score++;
            cur_run = m->rec1s[cur][0x19] & 0x3F;
            if (best_score > cur_run)
                best = edx;
            edx += 0x8000;
            cur += 0x8000;
            if (edx >= 0x40000)
                break;
            if (m->rec1s[cur][0] == 0) {
                best = edx;
                break;
            }
        }
    }
    if (edx < 0x38000)
        m->rec1s[ctx + edx + 0x8000][0] = 0;
    idx = ctx + best;
    memset(m->rec1s[idx], 0, sizeof(ppm_rec1));
    m->rec1s[idx][0] = 1;
    m->rec1s[idx][0x1A] = 0x20;
    m->rec1s[idx][1] = (uint8_t)((m->s48 + 1) & 0xFF);
    m->rec1s[idx][0xD] = (uint8_t)(sym & 0xFF);
    m->rec1s[idx][0x1C] = (uint8_t)(m->c48 & 0xFF);
    m->rec1s[idx][0x1D] = (uint8_t)((m->c48 >> 8) & 0xFF);
    m->rec1s[idx][0x1E] = (uint8_t)((m->c48 >> 16) & 0xFF);
    m->rec1s[idx][0x1F] = (uint8_t)((m->c48 >> 24) & 0xFF);
    m->c38 = ctx;
    m->link_tab[m->link_ptr] = m->rec1s[idx][0x1A];
    /* [M208 GATED UHA_RECNEW, default-OFF] creation of has record : position + index + sym. C'is
     * there single path of creation (c38 >= 0x40000) ; the diff dec/enc designe the context fautif. */
    { static long slo = -1, shi = -1;
      if (slo == -1) {
          const char *e = getenv("UHA_RECS");
          if (e && e[0] != '0') {
              const char *c = strchr(e, ':');
              slo = atol(e); shi = c ? atol(c + 1) : slo + 10;
          } else { slo = 0; shi = -2; }
      }
      if (shi >= slo && (long)m->out_count >= slo && (long)m->out_count <= shi)
          fprintf(stderr, "[RECS] out=%u idx=%u sym=%u\n",
                  m->out_count, (unsigned)idx, (unsigned)(sym & 0xFF)); }
    { static int rn = -1;
      if (rn < 0) { const char *e = getenv("UHA_RECNEW"); rn = (e && e[0] != '0') ? 1 : 0; }
      if (rn && m->out_count < 45337u)
          fprintf(stderr, "[RECNEW] pos=%u win=%u c38=%u ctx=%u idx=%u sym=%u del=%u\n",
                  m->out_count, m->win_pos, (unsigned)c38, (unsigned)ctx, (unsigned)idx,
                  (unsigned)(sym & 0xFF), edx < 0x38000 ? (unsigned)(ctx + edx + 0x8000) : 0u); }
}

static int rec1_main(ppm_model *m, uint8_t *r, int sym, int s47_hint, int *bump_c4)
{
    int cl, fcl, i, ah, run_cond;
    uint32_t flags, low6, newcnt;

    *bump_c4 = 0;
    if (s47_hint != 0xFF)
        cl = s47_hint;
    else {
        cl = 0;
        while (cl < 0xC && r[0xD + cl] != (sym & 0xFF))
            cl++;
    }
    if (cl >= 0xC) {
        ah = PPMS_REC1THR[r[0]] < m->c1c;
        if (ah)
            for (i = 0; i <= 0xC; i++)
                r[i] = (uint8_t)(((r[i] + 1) >> 1) & 0xFF);
        r[0] = (uint8_t)((r[0] + 2) & 0xFF);
        r[0x1B] >>= 1;
        fcl = 1;
        while (fcl < 0xB && r[1 + fcl] != 0)
            fcl++;
        newcnt = (m->s48 + 2) & 0xFF;
        r[1 + fcl] = (uint8_t)newcnt;
        r[0xD + fcl] = (uint8_t)(sym & 0xFF);
        r[0x1A] = (uint8_t)fcl;
        low6 = r[0x19] & 0x3F;
        r[0x19] = (uint8_t)((r[0x19] & 0xC0) | (low6 >> 1));
        return rec1_sort(r, fcl);
    }
    *bump_c4 = 1;
    ah = PPMS_REC1THR[r[0]] < m->c1c;
    flags = r[0x19] & 0xC0;
    if ((uint32_t)r[1 + cl] + 1 < ((uint32_t)r[1] >> 1)) {
        if (flags == 0xC0)
            ah = 1;
        flags = (flags + 0x40) & 0xFF;
    } else
        flags = (flags >> 1) & 0xC0;
    r[0x19] = (uint8_t)((r[0x19] & 0x3F) | flags);
    run_cond = (cl != 0) && ((r[0x1A] >> 4) >= 4) && ((r[0x1A] & 0xF) == (uint32_t)cl);
    if (run_cond || ah)
        for (i = 0; i <= 0xC; i++)
            r[i] = (uint8_t)(((r[i] + 1) >> 1) & 0xFF);
    r[1 + cl] = (uint8_t)((r[1 + cl] + 2) & 0xFF);
    low6 = r[0x19] & 0x3F;
    if (low6 < 0x3F)
        r[0x19] = (uint8_t)((r[0x19] & 0xC0) | (low6 + 1));
    if ((r[0x1A] & 0xF) == (uint32_t)cl) {
        if (r[0x1A] < 0xF0)
            r[0x1A] = (uint8_t)((r[0x1A] + 0x10) & 0xFF);
        if (r[0x1B] < 0xF8)
            r[0x1B] = (uint8_t)((r[0x1B] + 8) & 0xFF);
    } else {
        r[0x1A] = (uint8_t)cl;
        r[0x1B] >>= 1;
    }
    return rec1_sort(r, cl);
}

long g_special_calls = 0;   /* [M214] calls of rec1_special (path without rec_globals) */
long g_rec1_calls = 0;      /* [M215] calls of ppm_rec1_apply (input) */

/* [M216] acces public has rec_globals for tester the path " end of match ". */
void ppm_rec_globals_pub(ppm_model *m) { rec_globals(m); }

void ppm_rec1_apply(ppm_model *m, int sym, uint32_t c38, int s47_hint)
{
    int slot, aslot, bump_c4;
    uint32_t q, base_cnt;

    g_rec1_calls++;
    { static long rlo = -1, rhi = -1;
      if (rlo == -1) {
          const char *e = getenv("UHA_REC1TRACE");
          if (e && e[0] != '0') {
              const char *c = strchr(e, ':');
              rlo = atol(e); rhi = c ? atol(c + 1) : rlo + 10;
          } else { rlo = 0; rhi = -2; }
      }
      if (rhi >= rlo && (long)m->out_count >= rlo && (long)m->out_count <= rhi)
          fprintf(stderr, "[REC1T] out=%u c38=%u special=%d\n",
                  m->out_count, (unsigned)c38, (c38 >= 0x40000u) ? 1 : 0);
    }

    /* [M208 GATED UHA_LASTSYM, default-OFF] which calls rec1_apply au bord of the member 1 ? */
    { static int ls = -1;
      if (ls < 0) { const char *e = getenv("UHA_LASTSYM"); ls = (e && e[0] != '0') ? 1 : 0; }
      if (ls && m->out_count >= 45330u && m->out_count <= 45340u)
          fprintf(stderr, "[LASTSYM] pos=%u win=%u route=%d c38=%u s47h=%d sym=%u f38=%u f3b=%u bc=%u\n",
                  m->out_count, m->win_pos, g_upd_route, (unsigned)c38, s47_hint,
                  (unsigned)(sym & 0xFF), (unsigned)m->flag3938, (unsigned)m->flag393b,
                  (unsigned)m->byte_class); }

    if (c38 >= 0x40000) {
        rec1_special(m, sym, c38);
        g_special_calls++;
        /* [M214 GATED UHA_RECGS, default-OFF] the path " new record " calls-t-il also
         * `rec_globals` in the legacy engine ? Nos 263 literals without `rec_globals` by pass the suggerent. */
        { static int rg = -1;
          if (rg < 0) { const char *e = getenv("UHA_RECGS"); rg = (e && e[0] != '0') ? 1 : 0; }
          if (rg) rec_globals(m); }
        return;
    }
    if (m->flag3938 != 0) {
        aslot = s47_hint;
        if (aslot == 0xFF) {
            aslot = 0;
            while (aslot < 0xC && m->rec1s[c38][0xD + aslot] != (sym & 0xFF))
                aslot++;
        }
        /* [M211 GATED UHA_A8G] counters : `a8g` ([0x4826a8]) remainder-t-il has 0 at nous then that
         * son increment legacy (0x418813, condition `(r[slot+1]>>6) > r[0]`) is porte ? */
        { static long n38 = 0, ninc = 0; static int on = -1;
          if (on < 0) { const char *e = getenv("UHA_A8G"); on = (e && e[0] != '0') ? 1 : 0; }
          if (on) {
              n38++;
              if (aslot < 0xC && ((m->rec1s[c38][aslot + 1] >> 6) > m->rec1s[c38][0])
                  && ninc < 5)
                  fprintf(stderr, "[A8G] pos=%u c38=%u slot=%d r=%u/%u a8g=%u\n",
                          m->out_count, (unsigned)c38, aslot, m->rec1s[c38][aslot + 1],
                          m->rec1s[c38][0], (unsigned)m->a8g);
              if (aslot < 0xC && ((m->rec1s[c38][aslot + 1] >> 6) > m->rec1s[c38][0]))
                  ninc++;
              if ((m->out_count & 0x3FFFFu) == 0)
                  fprintf(stderr, "[A8G] pos=%u flag38=%ld inc=%ld a8g=%u dcg=%u c4g=%u\n",
                          m->out_count, n38, ninc, (unsigned)m->a8g,
                          (unsigned)m->dcg, (unsigned)m->c4g);
          } }
        if (aslot < 0xC && ((m->rec1s[c38][aslot + 1] >> 6) > m->rec1s[c38][0]))
            m->a8g = (m->a8g + 4) & PPM_M32;
    }
    if (m->flag393b != 0) {
        slot = s47_hint;
        if (slot == 0xFF) {
            slot = 0;
            while (slot < 0xC && m->rec1s[c38][0xD + slot] != (sym & 0xFF))
                slot++;
        }
        if (slot >= 0 && slot < 0xC) {
            base_cnt = m->rec1s[c38][slot + 1];
            m->s3e = 0;
            ppm_bc1_ring_ran = 0;
            m->flag3943 = 0;
        } else
            base_cnt = m->rec1s[c38][0];
        if (m->c3c != 0) {
            q = (base_cnt << 0xE) / m->c3c;
            if (q < 0x4000)
                m->bfc = (m->bfc + (m->f154[q] & 0xFFFF)) & PPM_M32;
        }
    }
    slot = rec1_main(m, m->rec1s[c38], sym, s47_hint, &bump_c4);
    if (bump_c4)
        m->c4g = (m->c4g + 5) & PPM_M32;
    m->s47 = (uint8_t)(slot & 0xFF);
    rec_globals(m);
    m->link_tab[m->link_ptr] = m->rec1s[c38][0x1A];
}

static int rec2_sort(uint8_t *r, int cl)
{
    uint8_t cnt, prev, s8, s9;
    while (cl > 0) {
        cnt = r[cl + 1];
        prev = r[cl];
        if (cnt < prev)
            break;
        r[cl + 1] = prev;
        r[cl] = cnt;
        s8 = r[cl + 8];
        s9 = r[cl + 9];
        r[cl + 8] = s9;
        r[cl + 9] = s8;
        r[0x13] = (uint8_t)((r[0x13] - 1) & 0xFF);
        cl--;
    }
    return cl;
}

void ppm_rec2_apply_heavy(ppm_model *m, int sym)
{
    int ch, cl, ci, i, a;
    uint32_t base_cnt, q, dh;
    uint8_t *r;

    ch = sym & 0xFF;
    r = m->rec2s[m->c40];
    if (r[0] == 0) {
        memset(r, 0, sizeof(ppm_rec2));
        r[0] = 3;
        r[1] = 3;
        r[0x12] = 6;
        r[9] = (uint8_t)ch;
        return;
    }
    cl = m->s49;
    if (cl == 0xFF) {
        cl = 0;
        while (cl < 8 && ch != r[cl + 9])
            cl++;
    }
    if (m->s3e != 0) {
        if (cl < 8) {
            ppm_bc1_ring_ran = 0;
            m->flag3943 = 0;
        }
        if (cl >= 8)
            base_cnt = r[0];
        else
            base_cnt = r[cl + 1];
        if (m->c4c != 0)
            q = ((base_cnt << 0xE) / m->c4c) & PPM_M32;
        else
            q = 0;
        q &= 0x1FFFF;
        if (q < 0x4000)
            m->bfc = (m->bfc + (m->f154[q] & 0xFFFF)) & PPM_M32;
    }
    if (r[0x12] > PPMS_REC2THR[r[0]]) {
        r[0x12] = 0;
        for (a = 8; a >= 0; a--) {
            dh = ((r[a] + 1) & 0xFF) >> 1;
            r[a] = (uint8_t)dh;
            r[0x12] = (uint8_t)((r[0x12] + dh) & 0xFF);
        }
    }
    r[0x12] = (uint8_t)((r[0x12] + 4) & 0xFF);
    if (cl < 8) {
        m->c50 = ((m->c50 * 4 - m->c50) >> 2) & PPM_M32;
        r[0x11] = (uint8_t)((r[0x11] >> 1) & 0xFF);
        r[cl + 1] = (uint8_t)((r[cl + 1] + 4) & 0xFF);
        if ((r[0x13] & 0xF) == (uint32_t)cl) {
            if (r[0x13] < 0xF0)
                r[0x13] = (uint8_t)((r[0x13] + 0x10) & 0xFF);
            m->c4g = (m->c4g + 5) & PPM_M32;
        } else {
            r[0x13] = (uint8_t)cl;
            m->c4g = (m->c4g + 5) & PPM_M32;
        }
        cl = rec2_sort(r, cl);
    } else {
        m->c50 = (m->c50 + 1) & PPM_M32;
        r[0x11] = (uint8_t)((r[0x11] + 1) & 0xFF);
        r[0] = (uint8_t)((r[0] + 4) & 0xFF);
        ci = 1;
        while (ci < 7 && r[ci + 1] != 0)
            ci++;
        if (r[ci + 1] < 0xC) {
            dh = r[ci + 1];
            r[0x12] = (uint8_t)((r[0x12] + ((4 - dh) & 0xFF)) & 0xFF);
            r[ci + 1] = 4;
            r[ci + 9] = (uint8_t)ch;
            r[0x13] = (uint8_t)ci;
            cl = rec2_sort(r, ci);
        } else {
            r[ci + 1] = 4;
            r[ci + 9] = (uint8_t)ch;
            r[0x13] = (uint8_t)ci;
            cl = rec2_sort(r, 0);
        }
    }
    m->s49 = (uint8_t)(cl & 0xFF);
    { static long hlo = -1, hhi = -1;
      if (hlo == -1) {
          const char *e = getenv("UHA_REC2TH");
          if (e && e[0] != '0') {
              const char *c = strchr(e, ':');
              hlo = atol(e); hhi = c ? atol(c + 1) : hlo + 10;
          } else { hlo = 0; hhi = -2; }
      }
      if (hhi >= hlo && (long)m->out_count >= hlo && (long)m->out_count <= hhi)
          fprintf(stderr, "[REC2H] out=%u\n", m->out_count); }
    { static int r2n = -1;
      if (r2n < 0) { const char *e = getenv("UHA_REC2NO"); r2n = (e && e[0] != '0') ? 1 : 0; }
      if (!r2n) rec_globals(m); }
    (void)i;
}

void ppm_rec2_apply_light(ppm_model *m, int sym)
{
    int ch, cl, ci, a;
    uint32_t v, dh;
    uint8_t *r;

    ch = sym & 0xFF;
    r = m->rec2s[m->c40];
    if (r[0] == 0) {
        memset(r, 0, sizeof(ppm_rec2));
        r[0] = 2;
        r[1] = 2;
        r[0x12] = 4;
        r[9] = (uint8_t)ch;
        { static int rl = -1;
          if (rl < 0) { const char *e = getenv("UHA_REC2LG"); rl = (e && e[0] != '0') ? 1 : 0; }
          if (rl) rec_globals(m); }
        return;
    }
    m->s49 = 0;
    cl = 0;
    while (cl < 8 && ch != r[cl + 9])
        cl++;
    if (r[0x12] > PPMS_REC2THR[r[0]]) {
        r[0x12] = 0;
        for (a = 8; a >= 0; a--) {
            v = ((r[a] + 1) & 0xFF) >> 1;
            r[a] = (uint8_t)v;
            r[0x12] = (uint8_t)((r[0x12] + v) & 0xFF);
        }
    }
    r[0x12] = (uint8_t)((r[0x12] + 1) & 0xFF);
    if (cl < 8) {
        r[cl + 1] = (uint8_t)((r[cl + 1] + 1) & 0xFF);
        if ((r[0x13] & 0xF) == (uint32_t)cl) {
            if (r[0x13] < 0x40)
                r[0x13] = (uint8_t)((r[0x13] + 0x10) & 0xFF);
        } else
            r[0x13] = (uint8_t)cl;
        m->s49 = (uint8_t)(rec2_sort(r, cl) & 0xFF);
    } else {
        r[0x11] = (uint8_t)((r[0x11] + 1) & 0xFF);
        r[0] = (uint8_t)((r[0] + 1) & 0xFF);
        ci = 1;
        while (ci < 7 && r[ci + 1] != 0)
            ci++;
        dh = r[ci + 1];
        if (dh < 0xC)
            r[0x12] = (uint8_t)((r[0x12] + ((1 - dh) & 0xFF)) & 0xFF);
        r[ci + 1] = 1;
        r[ci + 9] = (uint8_t)ch;
        r[0x13] = (uint8_t)ci;
        m->s49 = (uint8_t)(rec2_sort(r, ci) & 0xFF);
    }
    /* [M215 GATED UHA_REC2LG, default-OFF] the path LIGHT of rec2 calls-t-il also rec_globals
     * in the legacy engine ? Nos 728 calls (356 rec1 + 372 rec2-heavy) contre 1 013 at lui the suggerent. */
    { static int rl = -1;
      if (rl < 0) { const char *e = getenv("UHA_REC2LG"); rl = (e && e[0] != '0') ? 1 : 0; }
      if (rl) rec_globals(m); }
    /* [M215 GATED UHA_REC2BUMP, default-OFF] the path LIGHT bump-il `c4g += 5` as the heavy ?
     * `c4g` legacy = 2 006 contre 1 309 with the model " 1 call/literal " : il manque ~139 bumps. */
    { static int rb = -1;
      if (rb < 0) { const char *e = getenv("UHA_REC2BUMP"); rb = (e && e[0] != '0') ? 1 : 0; }
      if (rb && cl < 8) m->c4g = (m->c4g + 5) & PPM_M32; }
    { static long llo = -1, lhi = -1;
      if (llo == -1) {
          const char *e = getenv("UHA_REC2T");
          if (e && e[0] != '0') {
              const char *c = strchr(e, ':');
              llo = atol(e); lhi = c ? atol(c + 1) : llo + 10;
          } else { llo = 0; lhi = -2; }
      }
      if (lhi >= llo && (long)m->out_count >= llo && (long)m->out_count <= lhi)
          fprintf(stderr, "[REC2T] out=%u\n", m->out_count); }
}
