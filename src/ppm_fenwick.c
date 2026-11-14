#include "ppm_priv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t halve_rebuild_ex(ppm_model *m, int ctx, int bc1_drop)
{
    uint32_t total, hw, f;
    int i, twok, fourk, a;

    total = 0;
    for (i = 0; i <= 0xFF; i++) {
        f = m->freq[ctx][i];
        if (f == 0)
            continue;
        if (bc1_drop && m->byte_class != 0) {
            if (f > 0x10)
                hw = f >> 1;
            else
                hw = 0;
        } else {
            hw = (f + 1) >> 1;
        }
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
    uint32_t si, entry_freq, persym0, combo, sub_amt, ef, weight, rowtot, al;
    int predbyte, bh;
    int32_t budget_signed;

    si = m->tstep2[ctx_idx];
    entry_freq = m->ent_wt[ctx_idx];
    persym0 = m->freq[ctx_idx][sym];
    predbyte = m->pred_byte[ctx_idx];
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
    if (((ef + rowtot) >= 0x4000u) || (budget_signed < 0))
        ppm_t268_rescale(m, ctx_idx);
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
