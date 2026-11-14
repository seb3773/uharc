#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ppm_priv.h"
#include "encode.h"

static uint32_t hash1(uint32_t ctx0)
{
    return ((ctx0 >> 0xD) ^ ctx0) & 0x3FFFF;
}

/* [M257c, **PROMUE EN DEFAULT** the 2026-10-30 ; `UHA_PPM_CUTPOS=0` = behavior historique]
 * COORDONNE of the TESTE OF CUT. M257b had etabli that the master teste at the position of the STREAM
 * EMIS (`[0x4826ac]`) then that the port testait has `winpos` (l'advances d'write of the window, which
 * ecrasait there target GT `57 881` armee CORRECTEMENT at the frontier 45 337 by `next=96 322`).
 * MEASUREMENTS at the PROMOTION : grille of the port = positions GT has has has (57 883, 70 427, 82 971, 95 515,
 * 108 059, ..., 296 219, 305 440) * **firstdiv 1 319 -> 58 741** * size 191 350 -> **191 329**
 * (GT 191 159) * parse unchanged (strict 1 071 005 / decision 1 073 409) * mono **12/12** * costs
 * **16/16** * `an_costcmp` **22/22** * tetes **16/16** * queues **15/15** * nodes **0/324** * arena
 * **7 672/7 680 = 99,90 %** * `t169` all OK * `t170` OK * `e3_gate` 16685/7036 * `dflt/e3`
 * 13809/6988 * `difftest` 88 OK + 1 NOREF * roundtrip multi 12/12 * carte 7/8 (inchangee).
 *  `UHA_PPM_CUTEMIT` (tester OF MORE has `out_pos` au site d'emission) remainder INERT (md5 of the corps
 * identical au default) : there variable which counts is the COORDONNE, not the site. */
static inline int ppm_cutpos_on(void)
{
    return 1;
}

static uint32_t hash2(uint32_t ctx0, uint32_t ctx1, uint32_t ctx2)
{
    return ((((ctx0 >> 0xF) ^ ctx0) << 4) ^
            (((ctx1 >> 0xF) ^ ctx1) << 6) ^
            ((ctx2 >> 0xF) ^ ctx2)) & 0x3FFFF;
}

static void register_entry(ppm_model *m, uint32_t ctx0, uint32_t ctx1,
                           uint32_t ctx2, uint32_t winpos)
{
    uint32_t h1 = hash1(ctx0);
    uint32_t h2 = hash2(ctx0, ctx1, ctx2);
    m->link_ptr = h1;
    m->ht1_pos[h1] = winpos;
    m->ht1_ctx[h1] = ctx0;
    m->ht2_prev[h2] = m->ht2_new[h2];
    m->ht2_new[h2] = winpos;
}

void ppm_matchfinder_literal_tail(ppm_model *m)
{
    m->b8 = 0;
}

/* t14c - mirror exact of the loop of decodage of length (ppm_matchfinder_
 * decode, tree PPMS_LENTREE + probas len_prob[bank][node]) : as long as
 * declen <= maxlen there walk is forcee (bit 1, no cost RC) ; au-dela,
 * has choice binary stop/continue is code. code=0 : simulation pure (test of
 * representabilite of `want`, no cost nor update) ; code=1 : emission
 * + updates identical au decodeur. returns 0 if length_ == want. */
static int ppm_len_walk(ppm_model *m, int bank, int maxlen, uint32_t want, int code)
{
    uint32_t node = 0xE, declen, pidx, prob;
    int bit, nxt;

    for (;;) {
        declen = (node + 1) & 0xFF;
        if ((uint32_t)maxlen < declen) {
            int cont = (want >= declen);
            pidx = (uint32_t)bank * 0x100 + node;
            prob = m->len_prob[pidx];
            if (cont) {
                if (code) {
                    if (uha_rcw_encode(m->w, prob, 0x1000, 0x1000) != 0)
                        return -1;
                    m->len_prob[pidx] = (prob - (prob >> 4)) & PPM_M32;
                }
            } else {
                if (code) {
                    if (uha_rcw_encode(m->w, 0, prob, 0x1000) != 0)
                        return -1;
                    m->len_prob[pidx] = (prob + ((0x1000 - prob) >> 4)) & PPM_M32;
                }
                declen = node;
            }
        } else if (want < declen) {
            return -1;
        }
        bit = (declen > node) ? 1 : 0;
        nxt = PPMS_LENTREE[node * 2 + bit];
        if (nxt == 0)
            break;
        node = (uint32_t)nxt;
    }
    return (declen == want) ? 0 : -1;
}

void ppm_lzp_nomatch_tail(ppm_model *m)
{
    uint32_t h1 = hash1(m->roll_ctx0);
    m->d8 = (m->d8 + 1) & PPM_M32;
    m->len_tab[h1] = 0;
}

static int ptr1_check(const ppm_model *m, uint32_t ctx0, uint32_t h1, uint32_t *edi)
{
    if (ctx0 != m->ht1_ctx[h1]) {
        if (*edi != PPM_M32)
            return 0x1F;
        return 0;
    }
    *edi = m->ht1_pos[h1];
    if (*edi != PPM_M32)
        return 1;
    return 0;
}

static int classify_low(const ppm_model *m, uint32_t ctx0, uint32_t winpos,
                        uint32_t mask, uint32_t h1, uint8_t saved18, uint32_t *edi)
{
    uint32_t base, w, c0, dist;

    *edi = (winpos - m->d4) & mask;
    dist = (*edi - winpos) & mask;
    if (dist >= 0x104) {
        base = (*edi - 4) & mask;
        w = (uint32_t)m->window[base + 3]
          | ((uint32_t)m->window[base + 2] << 8)
          | ((uint32_t)m->window[base + 1] << 16)
          | ((uint32_t)m->window[base] << 24);
        c0 = ctx0;
        if ((w & 0xFFFF) == (c0 & 0xFFFF))
            return 0x0B;
        if ((w & 0xFFFF00FF) == (c0 & 0xFFFF00FF))
            return 0x0B;
        if ((w & 0xFFFFFF00) == (c0 & 0xFFFFFF00))
            return 0x0B;
    }
    if (saved18 >= 0x40)
        if (m->len_tab[h1] == 0)
            return 0;
    return ptr1_check(m, ctx0, h1, edi);
}

void ppm_matchfinder_decode(ppm_model *m, uha_rc *r, uint8_t *raw_syms, ppm_match *mr)
{
    uint32_t ctx0, ctx1, ctx2, mask, wrap, winpos;
    uint32_t h1, h2, saved18, type1c, flag30, depth;
    uint32_t bestlen, matchlen, edi, cand, dist, cur, cur14, ebx;
    uint32_t a, b, n, inprog, ddc, d4a8, v, pidx, length_, eedi, ov_base;
    int cls, bank, node, declen, bit, nxt, i, maxlen;
    uint32_t runit, freq, prob;

    mr->is_match = 0;
    mr->lzp_ctx = -1;
    mr->lzp_cls = 0;
    mr->raw_len = 0;

    ctx0 = m->roll_ctx0;
    ctx1 = m->roll_ctx1;
    ctx2 = m->roll_ctx2;
    mask = m->win_mask;
    wrap = m->win_wrap;
    winpos = m->win_pos;

    h1 = hash1(ctx0);
    h2 = hash2(ctx0, ctx1, ctx2);
    m->link_ptr = h1;
    saved18 = m->link_tab[h1];

    type1c = 0;
    flag30 = 0;
    bestlen = 0;
    edi = 0;
    cur = winpos;
    while (cur < 0x40)
        cur += wrap;
    cur14 = cur - 1;

    for (depth = 0; depth <= 1; depth++) {
        cand = (depth == 0) ? m->ht2_prev[h2] : m->ht2_new[h2];
        if (cand != PPM_M32) {
            dist = (cand - winpos) & mask;
            if (dist >= 0x140) {
                ebx = cand;
                if (ebx < 0x40)
                    ebx += wrap;
                if (m->window[cur - 0xC] == m->window[ebx - 0xC]) {
                    n = 0;
                    a = cur14;
                    b = ebx - 1;
                    while (n < 0x40 && m->window[a] == m->window[b]) {
                        n++;
                        a--;
                        b--;
                    }
                    matchlen = n;
                    if (matchlen >= bestlen) {
                        bestlen = matchlen;
                        edi = cand;
                    }
                }
            }
        }
    }

    inprog = m->b8;
    if (inprog != 0) {
        edi = (winpos - m->d4) & mask;
        type1c = 0x50 + (inprog > 2);
        flag30 = 1;
    } else {
        v = (m->d8 >= 0x10) ? 0xC : 0x30;
        if (bestlen >= v)
            type1c = 0x15;
        else {
            type1c = (uint32_t)classify_low(m, ctx0, winpos, mask, h1, (uint8_t)saved18, &edi);
            if (type1c == 0x0B)
                flag30 = 1;
        }
    }

    register_entry(m, ctx0, ctx1, ctx2, winpos);
    if (type1c == 0)
        return;
    if (((edi - winpos) & mask) < 0x100)
        return;
    if (inprog == 0) {
        if (m->len_tab[h1] == 0)
            type1c = (type1c + m->base46 + 0x27) & 0xFF;
        else
            type1c = (type1c + m->base46 - 1) & 0xFF;
    }

    if (m->has_cont) {
        if (m->window[m->cont_ofs] == m->window[edi & mask]) {
            ppm_lzp_apply_update(m, (int)(type1c & 0xFF), 2);
            m->len_tab[h1] = 0;
            m->b8 = 0;
            return;
        }
    }

    cls = ppm_lzp_decode_class(m, r, (int)(type1c & 0xFF));
    mr->lzp_ctx = (int)(type1c & 0xFF);
    mr->lzp_cls = cls;
    if (cls != 1)
        return;

    ddc = m->dcg;
    if (flag30 != 0) {
        maxlen = PPMS_MAXLEN20[(m->c4g << 2) / ddc];
        bank = (m->b8 > 0) + 3 + (m->b8 > 2);
    } else {
        d4a8 = m->a8g;
        if (d4a8 > ddc)
            maxlen = PPMS_MAXLEN10[(d4a8 << 2) / ddc];
        else {
            v = (PPMS_MAXLEN30[(m->c4g << 2) / ddc] - m->byte_class) & 0xFF;
            if (m->marker_fl != 0)
                v = (v + v) & 0xFF;
            maxlen = (int)v;
        }
        v = m->len_tab[h1];
        bank = (v > 0xE) + (v > 0x3E);
    }

    node = 0xE;
    declen = 0;
    for (;;) {
        declen = (node + 1) & 0xFF;
        if ((uint32_t)maxlen < (uint32_t)declen) {
            runit = r->range / 0x1000;
            r->range = runit;
            freq = (r->code / runit) & 0xFFFF;
            pidx = (uint32_t)bank * 0x100 + (uint32_t)node;
            prob = m->len_prob[pidx];
            if (freq < prob) {
                declen = node;
                m->len_prob[pidx] = (prob + ((0x1000 - prob) >> 4)) & PPM_M32;
                r->range = (r->range * prob) & PPM_M32;
                uha_rc_normalize(r);
            } else {
                m->len_prob[pidx] = (prob - (prob >> 4)) & PPM_M32;
                r->code = (r->code - prob * r->range) & PPM_M32;
                r->range = (r->range * ((0x1000 - prob) & PPM_M32)) & PPM_M32;
                uha_rc_normalize(r);
            }
        }
        bit = (declen > node) ? 1 : 0;
        nxt = PPMS_LENTREE[node * 2 + bit];
        if (nxt == 0)
            break;
        node = nxt;
    }
    length_ = (uint32_t)declen;
    dist = (winpos - (edi & mask)) & mask;
    if (dist == m->d4)
        m->d8 >>= 1;
    else {
        m->d4 = dist;
        m->d8 = (m->d8 + length_) & PPM_M32;
    }
    m->len_tab[h1] = (uint8_t)(length_ & 0xFF);
    if (length_ == 0xFF) {
        m->has_cont = 0;
        m->cont_ofs = 0;
        m->b8 = (m->b8 + 1) & PPM_M32;
    } else {
        m->cont_ofs = ((edi & mask) + length_) & mask;
        m->has_cont = 1;
        m->b8 = 0;
    }

    mr->is_match = 1;
    mr->raw_len = 0;
    ov_base = winpos & mask;
    eedi = edi & mask;
    for (i = 1; i <= (int)length_; i++) {
        uint32_t idx = eedi & mask;
        uint32_t d = (idx - ov_base) & mask;
        if (d < (uint32_t)mr->raw_len)
            raw_syms[mr->raw_len] = raw_syms[d];
        else
            raw_syms[mr->raw_len] = m->window[idx];
        mr->raw_len++;
        eedi = (eedi + 1) & mask;
    }
}

int ppm_matchfinder_encode(ppm_model *m, ppm_match *mr,
                           const uint8_t *syms, uint32_t nsyms,
                           uint32_t in_pos)
{
    uint32_t ctx0, ctx1, ctx2, mask, wrap, winpos;
    uint32_t h1, h2, saved18, type1c, flag30, depth;
    uint32_t bestlen, matchlen, edi, cand, dist, cur, cur14, ebx;
    uint32_t a, b, n, inprog, v;
    uint32_t ddc, d4a8, maxlen, bank, mlen, want, ov_base, eedi, idx, d, i2;
    int cls;

    mr->is_match = 0;
    mr->lzp_ctx = -1;
    mr->lzp_cls = 0;
    mr->raw_len = 0;

    ctx0 = m->roll_ctx0;
    ctx1 = m->roll_ctx1;
    ctx2 = m->roll_ctx2;
    mask = m->win_mask;
    wrap = m->win_wrap;
    winpos = m->win_pos;

    h1 = hash1(ctx0);
    h2 = hash2(ctx0, ctx1, ctx2);
    m->link_ptr = h1;
    saved18 = m->link_tab[h1];

    type1c = 0;
    flag30 = 0;
    bestlen = 0;
    edi = 0;
    cur = winpos;
    while (cur < 0x40)
        cur += wrap;
    cur14 = cur - 1;

    for (depth = 0; depth <= 1; depth++) {
        cand = (depth == 0) ? m->ht2_prev[h2] : m->ht2_new[h2];
        if (cand != PPM_M32) {
            dist = (cand - winpos) & mask;
            if (dist >= 0x140) {
                ebx = cand;
                if (ebx < 0x40)
                    ebx += wrap;
                if (m->window[cur - 0xC] == m->window[ebx - 0xC]) {
                    n = 0;
                    a = cur14;
                    b = ebx - 1;
                    while (n < 0x40 && m->window[a] == m->window[b]) {
                        n++;
                        a--;
                        b--;
                    }
                    matchlen = n;
                    if (matchlen >= bestlen) {
                        bestlen = matchlen;
                        edi = cand;
                    }
                }
            }
        }
    }

    inprog = m->b8;
    if (inprog != 0) {
        edi = (winpos - m->d4) & mask;
        type1c = 0x50 + (inprog > 2);
        flag30 = 1;
    } else {
        v = (m->d8 >= 0x10) ? 0xC : 0x30;
        if (bestlen >= v)
            type1c = 0x15;
        else {
            type1c = (uint32_t)classify_low(m, ctx0, winpos, mask, h1, (uint8_t)saved18, &edi);
            if (type1c == 0x0B)
                flag30 = 1;
        }
    }

    register_entry(m, ctx0, ctx1, ctx2, winpos);
    if (type1c == 0)
        return 0;
    if (((edi - winpos) & mask) < 0x100)
        return 0;
    if (inprog == 0) {
        if (m->len_tab[h1] == 0)
            type1c = (type1c + m->base46 + 0x27) & 0xFF;
        else
            type1c = (type1c + m->base46 - 1) & 0xFF;
    }

    if (m->has_cont) {
        if (m->window[m->cont_ofs] == m->window[edi & mask]) {
            ppm_lzp_apply_update(m, (int)(type1c & 0xFF), 2);
            m->len_tab[h1] = 0;
            m->b8 = 0;
            return 0;
        }
    }

    /* t14c - emission of matches (mirror strict of ppm_matchfinder_decode) :
     * the decodeur reads cls in {1=match, 2=not match} ; l'encoder selects.
     * mlen = length before effective (window + repli sure the sym already
     * produits for the distances < length, mirror of the loop of
     * remplissage decode). */
    ddc = m->dcg;
    if (flag30 != 0) {
        maxlen = PPMS_MAXLEN20[(m->c4g << 2) / ddc];
        bank = (m->b8 > 0) + 3 + (m->b8 > 2);
    } else {
        d4a8 = m->a8g;
        if (d4a8 > ddc)
            maxlen = PPMS_MAXLEN10[(d4a8 << 2) / ddc];
        else {
            v = (PPMS_MAXLEN30[(m->c4g << 2) / ddc] - m->byte_class) & 0xFF;
            if (m->marker_fl != 0)
                v = (v + v) & 0xFF;
            maxlen = (int)v;
        }
        v = m->len_tab[h1];
        bank = (v > 0xE) + (v > 0x3E);
    }

    ov_base = winpos & mask;
    eedi = edi & mask;
    mlen = 0;
    for (i2 = 0; i2 < 0xFF && (in_pos + i2) < nsyms; i2++) {
        uint8_t byte;
        idx = eedi & mask;
        d = (idx - ov_base) & mask;
        if (d < i2)
            byte = syms[in_pos + d];
        else
            byte = m->window[idx];
        if (byte != syms[in_pos + i2])
            break;
        eedi = (eedi + 1) & mask;
        mlen++;
    }
    want = (mlen > 0xFF) ? 0xFF : mlen;

    if (uha_get_dict_kb() >= 0 && want >= maxlen && ppm_len_walk(m, (int)bank, (int)maxlen, want, 0) == 0) {
        if (ppm_lzp_encode_class(m, (int)(type1c & 0xFF), 1) == 1) {
            uint32_t length_;
            if (ppm_len_walk(m, (int)bank, (int)maxlen, want, 1) != 0)
                return -1;
            length_ = want;
            dist = (winpos - (edi & mask)) & mask;
            if (dist == m->d4)
                m->d8 >>= 1;
            else {
                m->d4 = dist;
                m->d8 = (m->d8 + length_) & PPM_M32;
            }
            m->len_tab[h1] = (uint8_t)(length_ & 0xFF);
            if (length_ == 0xFF) {
                m->has_cont = 0;
                m->cont_ofs = 0;
                m->b8 = (m->b8 + 1) & PPM_M32;
            } else {
                m->cont_ofs = ((edi & mask) + length_) & mask;
                m->has_cont = 1;
                m->b8 = 0;
            }
            mr->lzp_ctx = (int)(type1c & 0xFF);
            mr->lzp_cls = 1;
            mr->is_match = 1;
            mr->raw_len = 0;
            eedi = edi & mask;
            for (i2 = 1; i2 <= length_; i2++) {
                idx = eedi & mask;
                d = (idx - ov_base) & mask;
                if (d < (uint32_t)mr->raw_len)
                    mr->raw_syms[mr->raw_len] = mr->raw_syms[d];
                else
                    mr->raw_syms[mr->raw_len] = m->window[idx];
                mr->raw_len++;
                eedi = (eedi + 1) & mask;
            }
            return 0;
        }
    }

    /* [M170] cut of block + ESCAPE of class BEFORE there column of class of the node :
     * the decodeur reads escape -> sel -> class (for(;;) of ppm_lzp_decode_class), and the
     * legacy teste there cut en 0x421973, before 0x4219a1. Gated UHA_BLKLAW>=3. */
    if (ppm_blk_node_encode(m, ppm_cutpos_on() ? m->out_count : winpos,
                            (int)(type1c & 0xFF)) < 0)
        return -1;

    cls = ppm_lzp_encode_class(m, (int)(type1c & 0xFF), 2);
    mr->lzp_ctx = (int)(type1c & 0xFF);
    mr->lzp_cls = cls;
    if (cls < 0)
        return -1;
    return 0;
}
