#include "ppm_priv.h"

enum { TAB_A = 1, TAB_B = 2, TAB_C = 3, TAB_E = 4 };

typedef struct {
    int tab;
    uint32_t idx;
    int slot;
} adapt_entry;

static int escmass_index(const ppm_model *m, uint8_t rec0, uint32_t edx,
                         uint32_t roll, int b7, int ge6, uint32_t *idx)
{
    uint32_t ctxbits;
    if (edx >= 0x80)
        return 0;
    if (m->byte_class != 0) {
        ctxbits = (roll & 0xC0) >> 5;
        if ((roll & 0xE0) == ((roll >> 8) & 0xE0))
            ctxbits++;
    } else {
        ctxbits = ((roll & 0xFF) == 0xDF)
                + (uint32_t)m->novel[roll & 0xFF] * 4
                + (uint32_t)m->novel[(roll >> 8) & 0xFF] * 2;
    }
    ctxbits += ((uint32_t)b7 << 3) + ((uint32_t)ge6 << 4);
    *idx = PPMS_43A590[rec0] * 0x100 + PPMS_43A590[edx & 0xFF] * 0x20 + ctxbits;
    return 1;
}

static int newc_std(uint32_t prob, uint32_t mult, uint32_t count, uint32_t *nc)
{
    *nc = (prob * mult) / (0x2000 - prob) + 1;
    if (*nc <= count)
        return 0;
    if (*nc >= 0x100)
        *nc = 0xFF;
    return 1;
}

static void adapt_by_entry(ppm_model *m, const adapt_entry *e, int up)
{
    uint32_t p;
    switch (e->tab) {
    case TAB_A: p = m->rw_a[e->idx]; break;
    case TAB_B: p = m->rw_b[e->idx]; break;
    case TAB_C: p = m->rw_c[e->idx]; break;
    default:    p = m->rw_e[e->idx]; break;
    }
    if (up)
        p = (p + ((0x2000 - p) >> 6)) & PPM_M32;
    else
        p = (p - (p >> 6)) & PPM_M32;
    switch (e->tab) {
    case TAB_A: m->rw_a[e->idx] = p; break;
    case TAB_B: m->rw_b[e->idx] = p; break;
    case TAB_C: m->rw_c[e->idx] = p; break;
    default:    m->rw_e[e->idx] = p; break;
    }
}

int ppm_rw1_decode(ppm_model *m, uha_rc *r, uint32_t rec1_idx, uint32_t rec2_idx,
                   int ctx28, int *sym)
{
    uint8_t recb[0x20], recw[0x20], flags[0xC];
    adapt_entry adapt[8];
    int n_adapt, sl, ps, ds, s, slot, dslot, i;
    uint32_t roll, c3c, total, edx, base, wA, wB, b38, count, mult, ecx, q, idx, flg, nc;
    uint32_t em_idx, runit, freq, cum, nxt, lowc, highc, cnt, prob;
    int b7, ge6, escaped, hit;
    uint8_t rec2marker, pb, d0, mainsym;

    *sym = -1;
    roll = m->c48;
    for (i = 0; i <= 0x1F; i++)
        recb[i] = m->rec1s[rec1_idx][i];

    rec2marker = m->rec2s[rec2_idx][0x13];
    pb = m->pred_byte[ctx28];
    d0 = m->rec2s[rec2_idx][(rec2marker & 0xF) + 9];
    sl = recb[0x1A] & 0xF;
    if (m->dcg <= m->a8g)
        sl = 0xC;

    ps = 0xC;
    ds = 0xC;
    for (s = 0; s <= 0xB; s++) {
        if (s > 0 && recb[s + 1] == 0)
            break;
        if (recb[0xD + s] == pb)
            ps = s;
        if (recb[0xD + s] == d0)
            ds = s;
    }
    mainsym = (sl < 0xC) ? recb[0xD + sl] : 0;

    for (s = 0; s <= 0xB; s++)
        flags[s] = 1;
    c3c = m->c1c;
    if (m->nexcl != 0) {
        for (s = 0; s <= 0xB; s++) {
            if (s > 0 && recb[s + 1] == 0)
                break;
            if (recb[0xD + s] == m->excl[0]) {
                flags[s] = 0;
                c3c = (c3c - recb[s + 1]) & PPM_M32;
                break;
            }
        }
    }

    edx = (c3c - recb[0]) & PPM_M32;
    b7 = m->rec2s[rec2_idx][7] != 0;
    ge6 = m->c54 >= 6;

    if (escmass_index(m, recb[0], edx, roll, b7, ge6, &em_idx))
        total = ((edx << 0xD) / m->esc_mass[em_idx]) + 1;
    else
        total = c3c & PPM_M32;

    base = PPMS_43E0F0[recb[0x1A] >> 4];
    wA = PPMS_43E0B0[rec2marker >> 4];
    wB = PPMS_43E070[m->cls_idx[ctx28]];
    b38 = ((roll & 0xC0) == 0xC0) ? 0x10 : 0;

    m->c3c = c3c;
    for (i = 0; i <= 0x1F; i++)
        recw[i] = recb[i];
    n_adapt = 0;

    if (sl < 0xC && flags[sl] != 0) {
        count = recw[sl + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = base + (count - (uint32_t)(count == 2)) + (recw[0x1B] >> 4);
        flg = 0;
        if (mainsym == d0) {
            ecx += wA;
            flg = 0x40;
        }
        if (mainsym == pb) {
            ecx += wB;
            flg |= 0x80;
        }
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if (sl != 0)
            idx |= 0x100;
        if ((mainsym & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[mainsym])
            idx |= 0x200;
        if (m->last_ctx == m->last_sym[mainsym])
            idx |= 0x400;
        idx |= flg | b38;
        adapt[n_adapt].tab = TAB_A;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = sl;
        n_adapt++;
        if (newc_std(m->rw_a[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[sl + 1] = (uint8_t)nc;
        }
    }

    if (ps < 0xC && flags[ps] != 0 && sl != ps) {
        count = recw[ps + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = count + wB;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((pb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (pb == d0)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[pb])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[pb])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_B;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = ps;
        n_adapt++;
        if (newc_std(m->rw_b[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[ps + 1] = (uint8_t)nc;
        }
    }

    if (ds < 0xC && flags[ds] != 0 && sl != ds && ds != ps) {
        count = recw[ds + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = count + wA;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((d0 & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[d0])
            idx |= 0x40;
        if (m->last_ctx == m->last_sym[d0])
            idx |= 0x80;
        idx |= b38;
        adapt[n_adapt].tab = TAB_C;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = ds;
        n_adapt++;
        if (newc_std(m->rw_c[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[ds + 1] = (uint8_t)nc;
        }
    }

    if (sl != 0 && ps != 0 && ds != 0 && flags[0] != 0 && recw[1] != 0) {
        count = recw[1];
        q = c3c != 0 ? (count << 4) / c3c : 0;
        idx = q;
        if ((recw[0xD] & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[recw[0xD]])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[recw[0xD]])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_E;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = 0;
        n_adapt++;
        nc = ((c3c * m->rw_e[idx]) >> 0xD) + 1;
        if (nc >= 0x100)
            nc = 0xFF;
        total = (total + nc - count) & PPM_M32;
        recw[1] = (uint8_t)nc;
    }

    m->c20 = total & PPM_M32;
    escaped = 1;
    slot = -1;
    dslot = -1;
    lowc = PPM_M32;
    highc = 0;
    if (total != 0) {
        runit = r->range / total;
        if (runit != 0) {
            freq = (r->code / runit) & 0xFFFF;
            cum = 0;
            escaped = 0;
            lowc = PPM_M32;
            for (s = 0; s <= 0xB; s++) {
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
                    *sym = recw[0xD + s];
                    dslot = s;
                    slot = s;
                    lowc = cum;
                    highc = nxt;
                    break;
                }
                ppm_append_excl(m, recw[0xD + s]);
                cum = nxt;
            }
            if (lowc == PPM_M32) {
                escaped = 1;
                lowc = cum;
                highc = total;
            }
            m->s47 = escaped ? 0x0C : (uint8_t)(dslot & 0xFF);
            m->c24 = lowc & PPM_M32;
            m->c28 = highc & PPM_M32;
            r->code = (r->code - lowc * runit) & PPM_M32;
            r->range = ((highc - lowc) * runit) & PPM_M32;
            uha_rc_normalize(r);
        }
    }

    for (i = 0; i < n_adapt; i++) {
        hit = (!escaped) && (adapt[i].slot == dslot) && (dslot >= 0);
        adapt_by_entry(m, &adapt[i], hit);
    }
    if (escmass_index(m, recb[0], edx, roll, b7, ge6, &em_idx)) {
        prob = m->esc_mass[em_idx];
        if (escaped)
            prob = (prob - (prob >> 6)) & PPM_M32;
        else
            prob = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        m->esc_mass[em_idx] = prob;
    }
    (void)slot;
    return !escaped;
}

int ppm_rw1_encode(ppm_model *m, uint32_t rec1_idx, uint32_t rec2_idx,
                   int ctx28, int target, int *sym)
{
    uint8_t recb[0x20], recw[0x20], flags[0xC];
    adapt_entry adapt[8];
    int n_adapt, sl, ps, ds, s, slot, dslot, i;
    uint32_t roll, c3c, total, edx, base, wA, wB, b38, count, mult, ecx, q, idx, flg, nc;
    uint32_t em_idx, cum, nxt, lowc, highc, cnt, prob;
    int b7, ge6, escaped, hit, found;
    uint8_t rec2marker, pb, d0, mainsym;

    *sym = -1;
    if (!m->w)
        return 0;
    roll = m->c48;
    for (i = 0; i <= 0x1F; i++)
        recb[i] = m->rec1s[rec1_idx][i];

    rec2marker = m->rec2s[rec2_idx][0x13];
    pb = m->pred_byte[ctx28];
    d0 = m->rec2s[rec2_idx][(rec2marker & 0xF) + 9];
    sl = recb[0x1A] & 0xF;
    if (m->dcg <= m->a8g)
        sl = 0xC;

    ps = 0xC;
    ds = 0xC;
    for (s = 0; s <= 0xB; s++) {
        if (s > 0 && recb[s + 1] == 0)
            break;
        if (recb[0xD + s] == pb)
            ps = s;
        if (recb[0xD + s] == d0)
            ds = s;
    }
    mainsym = (sl < 0xC) ? recb[0xD + sl] : 0;

    for (s = 0; s <= 0xB; s++)
        flags[s] = 1;
    c3c = m->c1c;
    if (m->nexcl != 0) {
        for (s = 0; s <= 0xB; s++) {
            if (s > 0 && recb[s + 1] == 0)
                break;
            if (recb[0xD + s] == m->excl[0]) {
                flags[s] = 0;
                c3c = (c3c - recb[s + 1]) & PPM_M32;
                break;
            }
        }
    }

    edx = (c3c - recb[0]) & PPM_M32;
    b7 = m->rec2s[rec2_idx][7] != 0;
    ge6 = m->c54 >= 6;

    if (escmass_index(m, recb[0], edx, roll, b7, ge6, &em_idx))
        total = ((edx << 0xD) / m->esc_mass[em_idx]) + 1;
    else
        total = c3c & PPM_M32;

    base = PPMS_43E0F0[recb[0x1A] >> 4];
    wA = PPMS_43E0B0[rec2marker >> 4];
    wB = PPMS_43E070[m->cls_idx[ctx28]];
    b38 = ((roll & 0xC0) == 0xC0) ? 0x10 : 0;

    m->c3c = c3c;
    for (i = 0; i <= 0x1F; i++)
        recw[i] = recb[i];
    n_adapt = 0;

    if (sl < 0xC && flags[sl] != 0) {
        count = recw[sl + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = base + (count - (uint32_t)(count == 2)) + (recw[0x1B] >> 4);
        flg = 0;
        if (mainsym == d0) {
            ecx += wA;
            flg = 0x40;
        }
        if (mainsym == pb) {
            ecx += wB;
            flg |= 0x80;
        }
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if (sl != 0)
            idx |= 0x100;
        if ((mainsym & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[mainsym])
            idx |= 0x200;
        if (m->last_ctx == m->last_sym[mainsym])
            idx |= 0x400;
        idx |= flg | b38;
        adapt[n_adapt].tab = TAB_A;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = sl;
        n_adapt++;
        if (newc_std(m->rw_a[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[sl + 1] = (uint8_t)nc;
        }
    }

    if (ps < 0xC && flags[ps] != 0 && sl != ps) {
        count = recw[ps + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = count + wB;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((pb & 0xC0) == 0xC0)
            idx |= 0x20;
        if (pb == d0)
            idx |= 0x40;
        if (m->win_pos <= m->t46a[pb])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[pb])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_B;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = ps;
        n_adapt++;
        if (newc_std(m->rw_b[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[ps + 1] = (uint8_t)nc;
        }
    }

    if (ds < 0xC && flags[ds] != 0 && sl != ds && ds != ps) {
        count = recw[ds + 1];
        mult = (c3c - count) & PPM_M32;
        ecx = count + wA;
        q = (mult + ecx) != 0 ? (ecx << 4) / (mult + ecx) : 0;
        idx = q;
        if ((d0 & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[d0])
            idx |= 0x40;
        if (m->last_ctx == m->last_sym[d0])
            idx |= 0x80;
        idx |= b38;
        adapt[n_adapt].tab = TAB_C;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = ds;
        n_adapt++;
        if (newc_std(m->rw_c[idx], mult, count, &nc)) {
            total = (total + nc - count) & PPM_M32;
            recw[ds + 1] = (uint8_t)nc;
        }
    }

    if (sl != 0 && ps != 0 && ds != 0 && flags[0] != 0 && recw[1] != 0) {
        count = recw[1];
        q = c3c != 0 ? (count << 4) / c3c : 0;
        idx = q;
        if ((recw[0xD] & 0xC0) == 0xC0)
            idx |= 0x20;
        if (m->win_pos <= m->t46a[recw[0xD]])
            idx |= 0x80;
        if (m->last_ctx == m->last_sym[recw[0xD]])
            idx |= 0x100;
        idx |= b38;
        adapt[n_adapt].tab = TAB_E;
        adapt[n_adapt].idx = idx;
        adapt[n_adapt].slot = 0;
        n_adapt++;
        nc = ((c3c * m->rw_e[idx]) >> 0xD) + 1;
        if (nc >= 0x100)
            nc = 0xFF;
        total = (total + nc - count) & PPM_M32;
        recw[1] = (uint8_t)nc;
    }

    m->c20 = total & PPM_M32;
    escaped = 1;
    slot = -1;
    dslot = -1;
    lowc = PPM_M32;
    highc = 0;
    found = 0;
    if (total != 0) {
        cum = 0;
        escaped = 0;
        lowc = PPM_M32;
        for (s = 0; s <= 0xB; s++) {
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
            if ((int)recw[0xD + s] == target) {
                *sym = recw[0xD + s];
                dslot = s;
                slot = s;
                lowc = cum;
                highc = nxt;
                found = 1;
                escaped = 0;
                break;
            }
            ppm_append_excl(m, recw[0xD + s]);
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
        m->s47 = escaped ? 0x0C : (uint8_t)(dslot & 0xFF);
        m->c24 = lowc & PPM_M32;
        m->c28 = highc & PPM_M32;
    }

    for (i = 0; i < n_adapt; i++) {
        hit = (!escaped) && (adapt[i].slot == dslot) && (dslot >= 0);
        adapt_by_entry(m, &adapt[i], hit);
    }
    if (escmass_index(m, recb[0], edx, roll, b7, ge6, &em_idx)) {
        prob = m->esc_mass[em_idx];
        if (escaped)
            prob = (prob - (prob >> 6)) & PPM_M32;
        else
            prob = (prob + ((0x2000 - prob) >> 6)) & PPM_M32;
        m->esc_mass[em_idx] = prob;
    }
    (void)slot;
    return !escaped;
}
