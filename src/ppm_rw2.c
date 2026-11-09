#include "ppm_priv.h"

enum { TAB_A = 1, TAB_B = 2, TAB_E = 3, TAB_ESC = 4 };

typedef struct {
    int tab;
    uint32_t idx;
    int slot;
} adapt_entry;

void ppm_rec2_total_flags(ppm_model *m, uint32_t rec2_idx, uint8_t *rec,
                          int *active_count, uint8_t *flags, uint32_t *total)
{
    int slot, i;
    uint8_t xs;

    for (i = 0; i <= 0x13; i++)
        rec[i] = m->rec2s[rec2_idx][i];
    *total = rec[0x12];
    *active_count = 0;
    for (slot = 0; slot <= 7; slot++) {
        if (slot > 0 && rec[slot + 1] == 0)
            break;
        (*active_count)++;
    }
    for (slot = 0; slot <= 7; slot++)
        flags[slot] = 1;
    for (i = 0; i < m->nexcl; i++) {
        xs = m->excl[i];
        for (slot = 0; slot < *active_count; slot++) {
            if (flags[slot] != 0 && rec[9 + slot] == xs) {
                flags[slot] = 0;
                *total = (*total - rec[slot + 1]) & PPM_M32;
                break;
            }
        }
    }
}

static int rec2_context(const ppm_model *m)
{
    int r = m->c48 & 0xFF;
    if (m->byte_class == 0 && m->novel[(m->c48 >> 8) & 0xFF] != 0)
        r += 0x100;
    return r;
}

static int newc_std(uint32_t prob, uint32_t mult, uint32_t count, uint32_t *nc)
{
    uint32_t den = (0x2000 - prob) & PPM_M32;
    if (den == 0 || den > 0x2000) {
        *nc = 0xFF;
        return 1;
    }
    *nc = (prob * mult) / den + 1;
    if (*nc <= count)
        return 0;
    if (*nc >= 0x100)
        *nc = 0xFF;
    return 1;
}

static void adapt_by_entry(ppm_model *m, const adapt_entry *e, int up)
{
    uint32_t v;
    switch (e->tab) {
    case TAB_A: v = m->r2_a[e->idx]; break;
    case TAB_B: v = m->r2_b[e->idx]; break;
    case TAB_E: v = m->r2_e[e->idx]; break;
    default:    v = m->r2_esc[e->idx]; break;
    }
    if (up)
        v = (v + ((0x2000 - v) >> 6)) & PPM_M32;
    else
        v = (v - (v >> 6)) & PPM_M32;
    switch (e->tab) {
    case TAB_A: m->r2_a[e->idx] = v; break;
    case TAB_B: m->r2_b[e->idx] = v; break;
    case TAB_E: m->r2_e[e->idx] = v; break;
    default:    m->r2_esc[e->idx] = v; break;
    }
}

int ppm_rw2_decode(ppm_model *m, uha_rc *r, uint32_t rec2_idx, int sel_hint, int *sym)
{
    uint8_t rec[0x14], recw[0x14], flags[8];
    adapt_entry adapt[4];
    int n_adapt, active_count, a0, sel, s, slot, ctx, i, escaped, hit;
    uint32_t base_total, total, diff, idx, p, nc, w30, w34, b38, count, mult, ecx, q;
    uint32_t runit, freq, cum, nxt, lowc, highc, cnt;
    uint8_t local_b8, local_d0, symb;

    *sym = -1;
    ppm_rec2_total_flags(m, rec2_idx, rec, &active_count, flags, &base_total);
    m->c4c = base_total;
    if (active_count == 0)
        return 0;

    a0 = (m->a8g >= m->dcg) ? 8 : (rec[0x13] & 0x0F);
    for (i = 0; i <= 0x13; i++)
        recw[i] = rec[i];
    total = base_total;
    n_adapt = 0;

    ctx = rec2_context(m);
    local_b8 = m->pred_byte[ctx];
    b38 = ((m->c48 & 0xC0) == 0xC0) ? 0x10 : 0;
    w30 = PPMS_43E0B0[rec[0x13] >> 4];
    w34 = PPMS_43E070[m->cls_idx[ctx]];

    diff = (base_total - rec[0]) & PPM_M32;
    if (active_count < 8 && diff < 0x10) {
        idx = PPMS_43A570[active_count] + (diff & 0x0C) + (uint32_t)(rec[0x12] == base_total);
        p = m->r2_esc[idx];
        if (p != 0) {
            adapt[n_adapt].tab = TAB_ESC;
            adapt[n_adapt].idx = idx;
            adapt[n_adapt].slot = 8;
            n_adapt++;
            total = (((diff << 13) / p) + 1 + (rec[0] / 2)) & PPM_M32;
        }
    }

    if (a0 < 8 && flags[a0] != 0 && recw[a0 + 1] != 0) {
        count = recw[a0 + 1];
        symb = recw[a0 + 9];
        local_d0 = symb;
        (void)local_d0;
        mult = (base_total - count) & PPM_M32;
        ecx = count + w30;
        q = 0;
        if (symb == local_b8) {
            ecx += w34;
            q = 0x80;
        }
        idx = q;
        q = ecx << 4;
        if ((mult + ecx) != 0)
            q = q / (mult + ecx);
        else
            q = 0;
        idx |= q;
        if (a0 != 0)
            idx |= 0x100;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (ppm_bc1_rec_ok && symb == ppm_bc1_st.best_pred)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x200;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x400;
        idx |= b38;
        adapt[n_adapt].tab = TAB_A;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = a0;
        n_adapt++;
        if (newc_std(m->r2_a[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[a0 + 1] = (uint8_t)nc;
        }
    }

    sel = sel_hint;
    if (sel < 8 && flags[sel] != 0 && sel != a0 && recw[sel + 1] != 0) {
        count = recw[sel + 1];
        symb = recw[sel + 9];
        mult = (base_total - count) & PPM_M32;
        ecx = count + w34;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x40;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x80;
        idx |= b38;
        adapt[n_adapt].tab = TAB_B;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = sel;
        n_adapt++;
        if (newc_std(m->r2_b[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[sel + 1] = (uint8_t)nc;
        }
    }

    if (flags[0] != 0 && a0 != 0 && sel != 0 && recw[1] != 0) {
        count = recw[1];
        symb = recw[9];
        q = base_total != 0 ? (count << 4) / base_total : 0;
        idx = q;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (ppm_bc1_rec_ok && symb == ppm_bc1_st.best_pred)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_E;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = 0;
        n_adapt++;
        nc = ((base_total * m->r2_e[idx]) >> 13) + 1;
        if (nc >= 0x100)
            nc = 0xFF;
        total = (total + nc - count) & PPM_M32;
        recw[1] = (uint8_t)nc;
    }

    escaped = 1;
    slot = 8;
    lowc = PPM_M32;
    highc = 0;
    if (total != 0) {
        runit = r->range / total;
        if (runit != 0) {
            freq = (r->code / runit) & 0xFFFF;
            cum = 0;
            escaped = 0;
            lowc = PPM_M32;
            for (s = 0; s <= 7; s++) {
                if (flags[s] == 0)
                    continue;
                cnt = recw[s + 1];
                if (cnt == 0) {
                    escaped = 1;
                    lowc = cum;
                    highc = total;
                    break;
                }
                nxt = cum + cnt;
                if (freq < nxt) {
                    slot = s;
                    *sym = recw[s + 9];
                    lowc = cum;
                    highc = nxt;
                    break;
                }
                ppm_append_excl(m, recw[s + 9]);
                cum = nxt;
            }
            if (lowc == PPM_M32) {
                escaped = 1;
                lowc = cum;
                highc = total;
            }
            m->c20 = total;
            m->c24 = lowc & PPM_M32;
            m->c28 = highc & PPM_M32;
            m->s49 = escaped ? 8 : (uint8_t)(slot & 0xFF);
            r->code = (r->code - lowc * runit) & PPM_M32;
            r->range = ((highc - lowc) * runit) & PPM_M32;
            uha_rc_normalize(r);
        }
    }

    for (i = 0; i < n_adapt; i++) {
        if (adapt[i].slot == 8)
            hit = !escaped;
        else
            hit = (!escaped) && (adapt[i].slot == slot);
        adapt_by_entry(m, &adapt[i], hit);
    }
    return !escaped;
}

int ppm_rw2_encode(ppm_model *m, uint32_t rec2_idx, int sel_hint, int target, int *sym)
{
    uint8_t rec[0x14], recw[0x14], flags[8];
    adapt_entry adapt[4];
    int n_adapt, active_count, a0, sel, s, slot, ctx, i, escaped, hit, found;
    uint32_t base_total, total, diff, idx, p, nc, w30, w34, b38, count, mult, ecx, q;
    uint32_t cum, nxt, lowc, highc, cnt;
    uint8_t local_b8, local_d0, symb;

    *sym = -1;
    if (!m->w)
        return 0;
    ppm_rec2_total_flags(m, rec2_idx, rec, &active_count, flags, &base_total);
    m->c4c = base_total;
    if (active_count == 0)
        return 0;

    a0 = (m->a8g >= m->dcg) ? 8 : (rec[0x13] & 0x0F);
    for (i = 0; i <= 0x13; i++)
        recw[i] = rec[i];
    total = base_total;
    n_adapt = 0;

    ctx = rec2_context(m);
    local_b8 = m->pred_byte[ctx];
    b38 = ((m->c48 & 0xC0) == 0xC0) ? 0x10 : 0;
    w30 = PPMS_43E0B0[rec[0x13] >> 4];
    w34 = PPMS_43E070[m->cls_idx[ctx]];

    diff = (base_total - rec[0]) & PPM_M32;
    if (active_count < 8 && diff < 0x10) {
        idx = PPMS_43A570[active_count] + (diff & 0x0C) + (uint32_t)(rec[0x12] == base_total);
        p = m->r2_esc[idx];
        if (p != 0) {
            adapt[n_adapt].tab = TAB_ESC;
            adapt[n_adapt].idx = idx;
            adapt[n_adapt].slot = 8;
            n_adapt++;
            total = (((diff << 13) / p) + 1 + (rec[0] / 2)) & PPM_M32;
        }
    }

    if (a0 < 8 && flags[a0] != 0 && recw[a0 + 1] != 0) {
        count = recw[a0 + 1];
        symb = recw[a0 + 9];
        local_d0 = symb;
        (void)local_d0;
        mult = (base_total - count) & PPM_M32;
        ecx = count + w30;
        q = 0;
        if (symb == local_b8) {
            ecx += w34;
            q = 0x80;
        }
        idx = q;
        q = ecx << 4;
        if ((mult + ecx) != 0)
            q = q / (mult + ecx);
        else
            q = 0;
        idx |= q;
        if (a0 != 0)
            idx |= 0x100;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (ppm_bc1_rec_ok && symb == ppm_bc1_st.best_pred)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x200;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x400;
        idx |= b38;
        adapt[n_adapt].tab = TAB_A;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = a0;
        n_adapt++;
        if (newc_std(m->r2_a[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[a0 + 1] = (uint8_t)nc;
        }
    }

    sel = sel_hint;
    if (sel < 8 && flags[sel] != 0 && sel != a0 && recw[sel + 1] != 0) {
        count = recw[sel + 1];
        symb = recw[sel + 9];
        mult = (base_total - count) & PPM_M32;
        ecx = count + w34;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x40;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x80;
        idx |= b38;
        adapt[n_adapt].tab = TAB_B;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = sel;
        n_adapt++;
        if (newc_std(m->r2_b[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[sel + 1] = (uint8_t)nc;
        }
    }

    if (flags[0] != 0 && a0 != 0 && sel != 0 && recw[1] != 0) {
        count = recw[1];
        symb = recw[9];
        q = base_total != 0 ? (count << 4) / base_total : 0;
        idx = q;
        if ((symb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (ppm_bc1_rec_ok && symb == ppm_bc1_st.best_pred)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[symb])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[symb])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_E;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = 0;
        n_adapt++;
        nc = ((base_total * m->r2_e[idx]) >> 13) + 1;
        if (nc >= 0x100)
            nc = 0xFF;
        total = (total + nc - count) & PPM_M32;
        recw[1] = (uint8_t)nc;
    }

    escaped = 1;
    slot = 8;
    lowc = PPM_M32;
    highc = 0;
    found = 0;
    if (total != 0) {
        cum = 0;
        escaped = 0;
        lowc = PPM_M32;
        for (s = 0; s <= 7; s++) {
            if (flags[s] == 0)
                continue;
            cnt = recw[s + 1];
            if (cnt == 0) {
                escaped = 1;
                lowc = cum;
                highc = total;
                break;
            }
            nxt = cum + cnt;
            if ((int)recw[s + 9] == target) {
                slot = s;
                *sym = recw[s + 9];
                lowc = cum;
                highc = nxt;
                found = 1;
                escaped = 0;
                break;
            }
            ppm_append_excl(m, recw[s + 9]);
            cum = nxt;
        }
        if (!found) {
            escaped = 1;
            if (lowc == PPM_M32) {
                lowc = cum;
                highc = total;
            }
        }
        if (highc <= lowc)
            return 0;
        if (uha_rcw_encode(m->w, lowc, highc, total) != 0)
            return 0;
        m->c20 = total;
        m->c24 = lowc & PPM_M32;
        m->c28 = highc & PPM_M32;
        m->s49 = escaped ? 8 : (uint8_t)(slot & 0xFF);
    }

    for (i = 0; i < n_adapt; i++) {
        if (adapt[i].slot == 8)
            hit = !escaped;
        else
            hit = (!escaped) && (adapt[i].slot == slot);
        adapt_by_entry(m, &adapt[i], hit);
    }
    return !escaped;
}
