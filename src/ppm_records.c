#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ppm_priv.h"

static void rec_globals(ppm_model *m)
{
    uint32_t edx = (m->dcg + 2) & PPM_M32;
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
                r[i] = (uint8_t)(((r[i] + 1) & 0xFF) >> 1);
        r[0] = (uint8_t)((r[0] + 2) & 0xFF);
        r[0x1B] >>= 1;
        fcl = 1;
        while (fcl < 0xB && r[1 + fcl] != 0)
            fcl++;
        if (r[1 + fcl] < 6) {
            newcnt = (m->s48 + 2) & 0xFF;
            r[1 + fcl] = (uint8_t)newcnt;
            r[0xD + fcl] = (uint8_t)(sym & 0xFF);
            r[0x1A] = (uint8_t)fcl;
        } else {
            fcl = 0;
        }
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
            r[i] = (uint8_t)(((r[i] + 1) & 0xFF) >> 1);
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

void ppm_rec_globals_pub(ppm_model *m) { rec_globals(m); }

void ppm_rec1_apply(ppm_model *m, int sym, uint32_t c38, int s47_hint)
{
    int slot, aslot, bump_c4;
    uint32_t q, base_cnt;

    if (c38 >= 0x40000) {
        rec1_special(m, sym, c38);
        return;
    }
    if (m->flag3938 != 0) {
        aslot = s47_hint;
        if (aslot == 0xFF) {
            aslot = 0;
            while (aslot < 0xC && m->rec1s[c38][0xD + aslot] != (sym & 0xFF))
                aslot++;
        }
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
            cl = 0;
        }
    }
    m->s49 = (uint8_t)(cl & 0xFF);
    rec_globals(m);
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
        if (dh < 0xC) {
            r[0x12] = (uint8_t)((r[0x12] + ((1 - dh) & 0xFF)) & 0xFF);
            r[ci + 1] = 1;
            r[ci + 9] = (uint8_t)ch;
            r[0x13] = (uint8_t)ci;
            m->s49 = (uint8_t)(rec2_sort(r, ci) & 0xFF);
        }
    }
}
