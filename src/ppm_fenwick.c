#include "ppm_priv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* [GATED UHA_T268B2, defautOFF, M207] counter d'updates by row, restreint au block 2
 * (45 337 <= out_count < 305 696) for to compare the 5 rows " empty " (0x202..0x207) at the GT
 * (master : ~12..21 updates chacune). No emissif by default. */
static uint32_t s_t268b2[1024];
static int s_t268b2_on = -1;
static void s_t268b2_dump(void)
{
    int i;
    if (s_t268b2_on <= 0)
        return;
    fprintf(stderr, "[T268B2]");
    for (i = 0; i < 1024; i++)
        if (s_t268b2[i])
            fprintf(stderr, " %d:%u", i, s_t268b2[i]);
    fprintf(stderr, "\n");
}

static uint32_t halve_rebuild_ex(ppm_model *m, int ctx, int bc1_drop)
{
    uint32_t total, hw, f;
    int i, twok, fourk, a;

    total = 0;
    for (i = 0; i <= 0xFF; i++) {
        f = m->freq[ctx][i];
        if (f == 0)
            continue;
        /* [M286, GATED UHA_HALVE2, default-OFF] THERE LAW "f > 16 ? (f+1)>>1 : 0" N'EXISTE NOT in THE
         * BINARY. `0x417e40` has TWO branches according to `[0x483936]` :
         *   (Has) [0x483936] == 0 -> `0x417fd4..e5` : `(w+1)>>1`, without threshold ;
         *   (B) [0x483936] != 0 -> `0x417e7e/0x417fc0` : `w > 0x10 ? w>>1 : 0` (shr without +1).
         * The port applies `(f+1)>>1` with threshold when `byte_class == 0` : sure all value
         * IMPAIRE > 16 il rend 1 of more that there branch B -> drifts of `low` -> l'byte emis
         * pass of `20` has `21` (measures M283). `=1` forces there branch B partout. */
        { static int h2 = -1;
          if (h2 < 0) { const char *e = getenv("UHA_HALVE2"); h2 = (e && e[0] != '0') ? 1 : 0; }
          if (h2) {
              hw = (f > 0x10) ? (f >> 1) : 0;
          } else if (bc1_drop && m->byte_class != 0) {
            if (f > 0x10)
                hw = f >> 1;
            else
                hw = 0;
        } else {
            hw = (f + 1) >> 1;
        } }
        m->freq[ctx][i] = (uint16_t)(hw & PPM_M16);
        total = (total + hw) & PPM_M32;
    }
    for (i = 0; i <= 0xFE; i++)
        m->cum[ctx][i + 1] = m->freq[ctx][i];
    m->cum[ctx][0] = (uint16_t)(total & PPM_M16);
    twok = 2;
    while (twok <= 0x80) {
        fourk = 2 * twok;
        a = 0x200 - fourk;
        while (a != 0) {
            m->cum[ctx][a >> 1] = (uint16_t)((m->cum[ctx][a >> 1] + m->cum[ctx][(a - twok) >> 1]) & PPM_M16);
            a -= fourk;
        }
        twok *= 2;
    }
    return total;
}

uint32_t ppm_halve_rebuild(ppm_model *m, int ctx)
{
    /* [M288, GATED UHA_HALVEDROP, default-OFF] the legacy engine has only Has RESCALE (`0x417e40`), and il
     * commute sure `[0x483936]` : measures M288, `[0x483936] = 1` sure all the run after there toggles
     * 0->1 has `pos = 38 121` (branch B : `w > 0x10 ? w>>1 : 0`). The port, lui, has TWO rescales :
     * `ppm_t268_rescale` (bc1_drop=1, suit `byte_class`) and THIS function (bc1_drop=0, branch Has
     * `(w+1)>>1` without threshold, therefore never of mise has 0 some small cellules).
     * `=1` aligne this rescale-ci sure there branch B (same commutateur that l'other). */
    { static int hd = -1;
      if (hd < 0) { const char *e = getenv("UHA_HALVEDROP"); hd = (e && e[0] != '0') ? 1 : 0; }
      if (hd)
          return halve_rebuild_ex(m, ctx, 1); }
    return halve_rebuild_ex(m, ctx, 0);
}

/* [M283, GATED via UHA_CLSRESCALE] RESCALE GLOBAL of has class. Measures M283 : between
 * `pos = 1 070 747` and `1 083 561`, **75 some 87 rows no zero** of the class 3 have
 * `cum[r][0]` after == `before / 2` exactement (and the 12 others less, has cause of the threshold
 * `f > 16` which puts the small cellules has 0). The master has therefore rescale there class ENTIERE, not has
 * row. Law verified : `f > 16 ? (f+1)>>1 : 0` (variante `bc1_drop` of `halve_rebuild_ex`). */
void ppm_cls_rescale(ppm_model *m, int base, int nctx)
{
    int r;
    if (!m || nctx <= 0)
        return;
    for (r = 0; r < nctx; r++)
        (void)halve_rebuild_ex(m, base + r, 1);
}

void ppm_apply_fenwick(ppm_model *m, int sym, int order)
{
    uint32_t wc, al, step, tot;

    wc = (uint32_t)m->work_ctx;
    /* [M286, GATED UHA_ROWSEQ=<min>:<max>, default OFF] SEQUENCE SOME ROWS visitees by the codec
     * d'order, fenetree by `win_pos`. Judge : there sequence of the port doit to be identical has the one of the
     * legacy (BP `0x418080`, `[0x481c34]`). Measures M283 : in `[1 070 747, 1 071 003]` the two
     * encodeurs not visitent not the same rows (`cls3` : port 84 787 / master 18 529). */
    { static long lo = -2, hi = 0;
      if (lo == -2) { const char *e = getenv("UHA_ROWSEQ");
                      if (e && e[0]) { lo = atol(e); const char *c = strchr(e, ':'); hi = c ? atol(c + 1) : lo; }
                      else { lo = -1; hi = -1; } }
      if (lo >= 0 && (long)m->win_pos >= lo && (long)m->win_pos <= hi)
          fprintf(stderr, "[ROWSEQ] pos=%u row=%u order=%d sym=%u\n",
                  (unsigned)m->win_pos, (unsigned)wc, order, (unsigned)(sym & 0xFF)); }
    step = m->tstep[order];
    m->freq[wc][sym] = (uint16_t)((m->freq[wc][sym] + step) & PPM_M16);
    al = (sym + 1) & 0xFFu;
    while (al != 0) {
        m->cum[wc][al] = (uint16_t)((m->cum[wc][al] + step) & PPM_M16);
        al = (al + ppm_lowbit(al)) & 0xFFu;
    }
    tot = (m->cum[wc][0] + step) & PPM_M16;
    m->cum[wc][0] = (uint16_t)tot;
    if (tot >= 0x4000)
        ppm_halve_rebuild(m, (int)wc);
}

void ppm_t268_rescale(ppm_model *m, int ctx_idx)
{
    uint32_t total, ht, budget;
    uint8_t bc;

    total = halve_rebuild_ex(m, ctx_idx, 1);
    if (total == 0)
        return;
    ht = (m->ent_wt[ctx_idx] + 1) >> 1;
    m->ent_wt[ctx_idx] = (uint16_t)(ht & PPM_M16);
    budget = (ht + total) & PPM_M32;
    m->budget[ctx_idx] = budget;
    bc = m->byte_class;
    if ((uint32_t)ctx_idx >= (0x200u >> bc))
        m->budget[ctx_idx] = (budget << 8) & PPM_M32;
    else
        m->budget[ctx_idx] = ((budget * 3) << 5) & PPM_M32;
    if (m->flag3934 == 3)
        if (total > (ht << 3))
            m->budget[ctx_idx] = (m->budget[ctx_idx] << 4) & PPM_M32;
}

void ppm_apply_t268(ppm_model *m, int sym, int ctx_idx)
{
    /* [M289, GATED UHA_ROWSEQ2=<min>:<max>, default OFF] SEQUENCE SOME ROWS of the trafic of class
     * (the single which alimente the rows 585..680 : measures M283, port 84 787 contre 18 529 at the
     * master in `pos in [1 070 747, 1 071 003]`). `UHA_ROWSEQ` not voit that `ppm_apply_fenwick`
     * (`row = 769` constant) : c'is here that pass the trafic of class. Horloge = `win_pos`
     * (equivalent port of `[0x4803c0]`, M286) - never `0x4826ac`. */
    { static long lo2 = -2, hi2 = 0;
      if (lo2 == -2) { const char *e = getenv("UHA_ROWSEQ2");
                       if (e && e[0]) { lo2 = atol(e); const char *c = strchr(e, ':'); hi2 = c ? atol(c + 1) : lo2; }
                       else { lo2 = -1; hi2 = -1; } }
      if (lo2 >= 0 && (long)m->win_pos >= lo2 && (long)m->win_pos <= hi2)
          fprintf(stderr, "[ROWSEQ2] pos=%u row=%d sym=%u cls=%u\n",
                  (unsigned)m->win_pos, ctx_idx, (unsigned)(sym & 0xFF), (unsigned)m->flag3934); }
    if (s_t268b2_on < 0) {
        const char *e = getenv("UHA_T268B2");
        s_t268b2_on = (e && e[0] != '0') ? 1 : 0;
        if (s_t268b2_on)
            atexit(s_t268b2_dump);
    }
    if (s_t268b2_on > 0 && m->out_count >= 45337u && m->out_count < 305696u)
        s_t268b2[ctx_idx & 1023]++;
    uint32_t si, entry_freq, persym0, combo, sub_amt, ef, weight, rowtot, al;
    int predbyte, bh;
    int32_t budget_signed;

    si = m->tstep2[ctx_idx];
    /* [GATED UHA_STEP16, defautOFF, M96] test d'hypothese measured (M95 legacy=+16 vs clone tstep2=+32).
     * Not change NOTHING by default ; sert only has trancher by cmp. */
    { static int s16 = -1; if (s16 < 0) { const char *e = getenv("UHA_STEP16"); s16 = (e && e[0] != '0') ? 1 : 0; }
      if (s16) si = m->tstep[ctx_idx]; }
    entry_freq = m->ent_wt[ctx_idx];
    persym0 = m->freq[ctx_idx][sym];
    predbyte = m->pred_byte[ctx_idx];
    /* [GATED UHA_C550DBG, defautOFF, M90] trace MRU pred_byte (path fenwick apply_t268). */
    { static int u = -1; if (u < 0) { const char *e = getenv("UHA_C550DBG"); u = (e && e[0] != '0') ? 1 : 0; }
      if (u) fprintf(stderr, "[UPDF] ctx=%d sym=%d pred_before=%d\n", ctx_idx, sym, predbyte); }
    combo = (entry_freq + persym0) & PPM_M32;
    if (sym == predbyte) {
        bh = m->cls_idx[ctx_idx];
        if (bh < 0xF)
            m->cls_idx[ctx_idx] = (uint8_t)(bh + 1);
        sub_amt = (combo << 5) & PPM_M32;
    } else {
        m->pred_byte[ctx_idx] = (uint8_t)(sym & 0xFF);
        m->cls_idx[ctx_idx] = 0;
        sub_amt = combo;
    }
    m->budget[ctx_idx] = (m->budget[ctx_idx] - sub_amt) & PPM_M32;

    if (persym0 != 0) {
        ef = m->ent_wt[ctx_idx];
        weight = (m->order0_wt[ctx_idx] * ef) & PPM_M32;
        rowtot = m->cum[ctx_idx][0];
        if (rowtot <= weight)
            ppm_apply_fenwick(m, sym, ctx_idx);
        m->order0_wt[ctx_idx] = m->order0_wt[ctx_idx] >> 4;
    } else {
        ppm_apply_fenwick(m, sym, ctx_idx);
        m->ent_wt[ctx_idx] = (uint16_t)((m->ent_wt[ctx_idx] + si) & PPM_M16);
        m->order0_wt[ctx_idx] = (m->order0_wt[ctx_idx] + m->byte_class) & PPM_M32;
    }

    m->freq[ctx_idx][sym] = (uint16_t)((m->freq[ctx_idx][sym] + si) & PPM_M16);
    al = (sym + 1) & 0xFFu;
    while (al != 0) {
        m->cum[ctx_idx][al] = (uint16_t)((m->cum[ctx_idx][al] + si) & PPM_M16);
        al = (al + ppm_lowbit(al)) & 0xFFu;
    }
    rowtot = (m->cum[ctx_idx][0] + si) & PPM_M16;
    m->cum[ctx_idx][0] = (uint16_t)rowtot;

    ef = m->ent_wt[ctx_idx];
    budget_signed = (int32_t)m->budget[ctx_idx];
    { static int rdbg = -1; if (rdbg < 0) { const char *e = getenv("UHA_C550DBG"); rdbg = (e && e[0] != '0') ? 1 : 0; }
      if (rdbg) fprintf(stderr, "[RESCALE?] ctx=%d winpos=%u rowtot=%u ef=%u budget=%d fire=%d\n",
                        ctx_idx, m->win_pos, rowtot, ef, budget_signed,
                        (((ef + rowtot) >= 0x4000) || (budget_signed < 0)) ? 1 : 0); }
    /* [M283, GATED UHA_T268THR=<v>, default 0 = threshold historique 0x4000] SENSIBILITE of the threshold of
     * rescale. Measures M283 : in there zone `pos in [1 070 747, 1 071 003]` the master RESCALE
     * (29 rows of the class 3 divisees, law `f>16 ? (f+1)>>1 : 0` verified exactement) then
     * that the port not triggers NOTHING (`[RESCALE?] fire=0` sure 1028 nodes, `rowtot` <= ~5 400).
     * Sert has balayer the threshold reel ; `=0` preserves the behavior historique. */
    { static long th = -2;
      uint32_t lim;
      if (th == -2) { const char *e = getenv("UHA_T268THR"); th = (e && e[0]) ? atol(e) : 0; }
      lim = (th > 0) ? (uint32_t)th : 0x4000u;
      if (((ef + rowtot) >= lim) || (budget_signed < 0))
          ppm_t268_rescale(m, ctx_idx); }
}

void ppm_apply_literal_updates(ppm_model *m, int entry_ctx, int next_ctx, int sym)
{
    int flag;

    flag = (next_ctx == 0x301) ? 1 : 0;
    m->work_ctx = next_ctx;
    ppm_apply_t268(m, sym, entry_ctx);
    m->work_ctx = 0x302 + flag;
    ppm_apply_fenwick(m, sym, 0x200);
}
