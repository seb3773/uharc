#include "alz_priv.h"
#include "alz_const.inc"

static int m_dist_slot(alz_dec *d, uint16_t *prob, const uint8_t *trans,
                       int init_state, int fallback)
{
    int state, slot, branch;

    state = init_state;
    slot = fallback;
    while (state != 0) {
        if (uha_rc_bit12_shift(&d->rc, &prob[state], 6) == 0)
            slot = state;
        branch = (slot > state) ? 1 : 0;
        state = trans[2 * state + branch];
    }
    return slot;
}

static uint32_t m_class1_dist(alz_dec *d)
{
    int slot, k, low_bit, nblocks;
    uint32_t base, span, limit, extra, v;

    slot = m_dist_slot(d, d->m_slot_long, AlzFullDistanceNext, 0x10, 0x2C);
    k = slot - 1;
    base = AlzDistanceBase[k];
    if (k == 0)
        return base;
    span = AlzDistanceSpan[k];
    limit = d->st.output_pos;
    if (base + span - 1 > limit)
        span = limit - base + 1;
    low_bit = -1;
    extra = 0;
    if (span >= 4) {
        low_bit = uha_rc_bit12_shift(&d->rc, &d->m_low_bit, 6);
        span >>= 1;
    }
    if (span > 0x800) {
        nblocks = (int)(((span - 1) >> 11) + 1);
        v = uha_rc_uniform(&d->rc, (uint32_t)nblocks);
        extra += v << 11;
        if (nblocks != (int)v + 1)
            span = 0x800;
        else
            span -= v << 11;
    }
    if (span >= 2)
        extra += uha_rc_uniform(&d->rc, span);
    if (low_bit != -1)
        extra = extra * 2 + (uint32_t)low_bit;
    return base + extra;
}

static int m_length_decode(alz_dec *d, int cls, uint32_t dist)
{
    int edi_state, m, eax, esi, last, b, pred_byte, sec;
    uint32_t rep, mask, pos, ctx, pred_ptr, addr, b0, b1;
    int has_pred;

    edi_state = 2;
    pred_byte = 0;
    sec = 0;
    pred_ptr = 0;
    has_pred = 0;
    if (cls == 1) {
        if (dist < 0x100)
            m = 0;
        else if (dist < 0x1000)
            m = 1;
        else if (dist < 0x10000)
            m = 2;
        else if (dist < 0x100000)
            m = 3;
        else
            m = 4;
        edi_state = m + 3;
        eax = m;
    } else {
        rep = d->st.repeat_run;
        eax = 5;
        if (rep != 0)
            eax = (rep > 2) ? 7 : 6;
    }
    if (eax <= 5 && dist > 1) {
        mask = d->mode.dict_mask;
        pos = d->st.window_pos;
        b0 = d->window[(pos - dist) & mask];
        b1 = d->window[(pos - dist + 1) & mask];
        ctx = (b0 << 8) | b1;
        if (eax == 5)
            ctx += 0x10000;
        pred_ptr = ctx;
        has_pred = 1;
        pred_byte = d->m_len_pred[pred_ptr];
        sec = d->m_len_pred[pred_ptr + 0x20000];
        d->m_len_pred[pred_ptr + 0x20000] = (uint8_t)pred_byte;
    }
    esi = 10;
    last = esi + 1;
    for (;;) {
        last = esi + 1;
        if (edi_state < esi + 1) {
            addr = (uint32_t)eax * 1024;
            if (esi >= pred_byte)
                addr += 256;
            if (sec <= esi)
                addr += 512;
            addr += (uint32_t)esi;
            if (uha_rc_bit12_shift(&d->rc, &d->m_length[addr], 5) == 0)
                last = esi;
        }
        b = (esi < last) ? 1 : 0;
        esi = AlzLengthNext[2 * esi + b];
        if (esi == 0)
            break;
    }
    if (has_pred)
        d->m_len_pred[pred_ptr] = (uint8_t)(last & 0xFF);
    return last & 0xFF;
}

int alz_m_decode_match(alz_dec *d, int token, uint32_t *dist, uint32_t *count)
{
    int slot_mark, slot, idx, i;
    uint32_t rep;

    if (token == 1) {
        *dist = m_class1_dist(d);
        slot_mark = 0xFF;
    } else if (token == 2) {
        *dist = d->st.recent_distance[0];
        slot_mark = 0;
    } else {
        slot = m_dist_slot(d, d->m_slot_short, AlzShortDistanceNext, 1, 0xB);
        *dist = d->st.recent_distance[slot];
        slot_mark = slot;
    }
    *count = (uint32_t)m_length_decode(d, token, *dist);

    rep = d->st.repeat_run;
    if ((*dist > 1) || (rep > 1)) {
        if (slot_mark != 0) {
            idx = (slot_mark == 0xFF) ? 11 : slot_mark;
            for (i = idx; i >= 1; i--)
                d->st.recent_distance[i] = d->st.recent_distance[i - 1];
            d->st.recent_distance[0] = *dist;
        }
    }
    return !d->rc.corrupt;
}

static int m_bit12(alz_dec *d, uint16_t *prob, int shift, int bit)
{
    if (!d->w)
        return -1;
    if (shift < 1)
        shift = 1;
    else if (shift > 12)
        shift = 12;
    if (bit == 0) {
        if (uha_rcw_encode_fixed12(d->w, 0, *prob) != 0)
            return -1;
        *prob = (uint16_t)(*prob + ((4096u - *prob) >> shift));
    } else {
        if (uha_rcw_encode_fixed12(d->w, *prob, 4096) != 0)
            return -1;
        *prob = (uint16_t)(*prob - (*prob >> shift));
    }
    return 0;
}

static int slot_find_path(const uint8_t *trans, int state, int slot, int target,
                          int *bits, int *nbits)
{
    int ns, nslot;

    if (*nbits > 48)
        return 0;
    if (state == 0)
        return slot == target;

    nslot = state;
    ns = trans[2 * state];
    bits[*nbits] = 0;
    (*nbits)++;
    if (slot_find_path(trans, ns, nslot, target, bits, nbits))
        return 1;
    (*nbits)--;

    nslot = slot;
    ns = trans[2 * state + ((nslot > state) ? 1 : 0)];
    bits[*nbits] = 1;
    (*nbits)++;
    if (slot_find_path(trans, ns, nslot, target, bits, nbits))
        return 1;
    (*nbits)--;
    return 0;
}

typedef struct {
    uint8_t ok;
    uint8_t nbits;
    uint8_t bits[50];
} alz_path_lut;

static alz_path_lut s_short_slot_lut[16];
static int s_short_slot_lut_ready;
static int s_full_dist_reach[64];
static alz_path_lut s_full_slot_lut[64];
static int s_full_dist_reach_ready;

static void short_slot_lut_init(void)
{
    int t, i, nbits;
    int bits[50];
    if (s_short_slot_lut_ready)
        return;
    for (t = 1; t < ALZ_MAX_RECENT; t++) {
        nbits = 0;
        if (slot_find_path(AlzShortDistanceNext, 1, 0xB, t, bits, &nbits)) {
            s_short_slot_lut[t].ok = 1;
            s_short_slot_lut[t].nbits = (uint8_t)nbits;
            for (i = 0; i < nbits; i++)
                s_short_slot_lut[t].bits[i] = (uint8_t)bits[i];
        }
    }
    s_short_slot_lut_ready = 1;
}

/* [a5c2f perf, BIT-EXACT] `m_class1_dist_ok` / `slot_encode` / `mc_slot_cost` :
 * Precalcul une seule fois les slots atteignables dans AlzFullDistanceNext (BFS
 * borne <=64*64) ainsi que les chemins DFS exacts s_full_slot_lut[0..63]. */
static void full_dist_reach_init(void)
{
    unsigned char vis[64][64];
    int st_stack[4096], sl_stack[4096];
    int bits[50];
    int top = 0, i, st, sl, ns, nslot, br, t, nbits;

    for (i = 0; i < 64 * 64; i++)
        ((unsigned char *)vis)[i] = 0;
    /* amorce (state=0x10, slot=0x2C), comme slot_find_path. */
    vis[0x10][0x2C] = 1;
    st_stack[top] = 0x10;
    sl_stack[top] = 0x2C;
    top++;
    while (top > 0) {
        top--;
        st = st_stack[top];
        sl = sl_stack[top];
        if (st == 0) {
            s_full_dist_reach[sl] = 1;
            continue;
        }
        /* branche 0 : bit=0 -> nslot=state, ns=trans[2*state]. */
        ns = AlzFullDistanceNext[2 * st];
        nslot = st;
        if (ns < 64 && nslot < 64 && !vis[ns][nslot]) {
            vis[ns][nslot] = 1;
            st_stack[top] = ns;
            sl_stack[top] = nslot;
            top++;
        }
        /* branche 1 : bit=1 -> nslot=slot, ns=trans[2*state+(slot>state)]. */
        br = (sl > st) ? 1 : 0;
        ns = AlzFullDistanceNext[2 * st + br];
        nslot = sl;
        if (ns < 64 && nslot < 64 && !vis[ns][nslot]) {
            vis[ns][nslot] = 1;
            st_stack[top] = ns;
            sl_stack[top] = nslot;
            top++;
        }
    }
    for (t = 0; t < 64; t++) {
        if (!s_full_dist_reach[t])
            continue;
        nbits = 0;
        if (slot_find_path(AlzFullDistanceNext, 0x10, 0x2C, t, bits, &nbits)) {
            s_full_slot_lut[t].ok = 1;
            s_full_slot_lut[t].nbits = (uint8_t)nbits;
            for (i = 0; i < nbits; i++)
                s_full_slot_lut[t].bits[i] = (uint8_t)bits[i];
        }
    }
    s_full_dist_reach_ready = 1;
}

static int slot_encode(alz_dec *d, uint16_t *prob, const uint8_t *trans,
                       int init_state, int fallback, int target)
{
    int bits[50];
    const alz_path_lut *pl = NULL;
    const uint8_t *lut_bits = NULL;
    int nbits = 0;
    int state, slot, branch, i;

    if (trans == AlzShortDistanceNext && init_state == 1 && fallback == 0xB &&
        target >= 0 && target < 16) {
        if (!s_short_slot_lut_ready)
            short_slot_lut_init();
        pl = &s_short_slot_lut[target];
    } else if (trans == AlzFullDistanceNext && init_state == 0x10 && fallback == 0x2C &&
               target >= 0 && target < 64) {
        if (!s_full_dist_reach_ready)
            full_dist_reach_init();
        pl = &s_full_slot_lut[target];
    }
    if (pl) {
        if (!pl->ok)
            return -1;
        nbits = (int)pl->nbits;
        lut_bits = pl->bits;
    } else {
        if (!slot_find_path(trans, init_state, fallback, target, bits, &nbits))
            return -1;
    }
    state = init_state;
    slot = fallback;
    for (i = 0; i < nbits; i++) {
        int bit = lut_bits ? (int)lut_bits[i] : bits[i];
        if (m_bit12(d, &prob[state], 6, bit) != 0)
            return -1;
        if (bit == 0)
            slot = state;
        branch = (slot > state) ? 1 : 0;
        state = trans[2 * state + branch];
    }
    return 0;
}

static int extra_encodable(uint32_t extra, uint32_t span)
{
    uint32_t nblocks, v;

    if (span == 0)
        return 0;
    if (span >= 4) {
        extra >>= 1;
        span >>= 1;
    }
    if (span > 0x800) {
        nblocks = ((span - 1) >> 11) + 1;
        v = extra >> 11;
        if (v >= nblocks)
            return 0;
        extra -= v << 11;
        if (nblocks != v + 1)
            span = 0x800;
        else
            span -= v << 11;
    }
    if (span >= 2)
        return extra < span;
    return extra == 0;
}

static int dist_to_bucket(uint32_t dist, uint32_t limit, int *k_out,
                          uint32_t *base_out, uint32_t *span_out)
{
    int k;

    if (dist == 0)
        return -1;
    for (k = 0; k < 44; k++) {
        uint32_t base = AlzDistanceBase[k];
        uint32_t span = AlzDistanceSpan[k];
        if (limit < base)
            continue;
        if (base + span - 1 > limit)
            span = limit - base + 1;
        if (span == 0)
            continue;
        if (dist >= base && dist < base + span) {
            if (k != 0 && !extra_encodable(dist - base, span))
                return -1;
            *k_out = k;
            *base_out = base;
            *span_out = span;
            return 0;
        }
    }
    return -1;
}

static int m_class1_dist_ok(alz_dec *d, uint32_t dist)
{
    int k, slot;
    uint32_t base, span, limit;

    limit = d->st.output_pos;
    if (dist_to_bucket(dist, limit, &k, &base, &span) != 0)
        return 0;
    slot = k + 1;
    if (!s_full_dist_reach_ready)
        full_dist_reach_init();
    return slot < 64 ? s_full_dist_reach[slot] : 0;
}

static int m_encode_class1_dist(alz_dec *d, uint32_t dist)
{
    int k;
    uint32_t base, span, limit, extra, v;

    limit = d->st.output_pos;
    if (dist_to_bucket(dist, limit, &k, &base, &span) != 0)
        return -1;
    if (slot_encode(d, d->m_slot_long, AlzFullDistanceNext, 0x10, 0x2C, k + 1) != 0)
        return -1;
    if (k == 0)
        return 0;
    extra = dist - base;
    if (span >= 4) {
        int low_bit = (int)(extra & 1);
        extra >>= 1;
        if (m_bit12(d, &d->m_low_bit, 6, low_bit) != 0)
            return -1;
        span >>= 1;
    }
    if (span > 0x800) {
        int nblocks = (int)(((span - 1) >> 11) + 1);
        v = extra >> 11;
        if (uha_rcw_encode(d->w, v, v + 1, (uint32_t)nblocks) != 0)
            return -1;
        extra -= v << 11;
        if (nblocks != (int)v + 1)
            span = 0x800;
        else
            span -= v << 11;
    }
    if (span >= 2) {
        if (uha_rcw_encode(d->w, extra, extra + 1, span) != 0)
            return -1;
    }
    return 0;
}

static int m_len_setup(alz_dec *d, int cls, uint32_t dist, int *eax, int *edi_state,
                       int *has_pred, uint32_t *pred_ptr, int *pred_byte, int *sec)
{
    int m;
    uint32_t rep, mask, pos, ctx, b0, b1;

    *has_pred = 0;
    *pred_ptr = 0;
    *pred_byte = 0;
    *sec = 0;
    *edi_state = 2;
    if (cls == 1) {
        if (dist < 0x100)
            m = 0;
        else if (dist < 0x1000)
            m = 1;
        else if (dist < 0x10000)
            m = 2;
        else if (dist < 0x100000)
            m = 3;
        else
            m = 4;
        *edi_state = m + 3;
        *eax = m;
    } else {
        rep = d->st.repeat_run;
        *eax = 5;
        if (rep != 0)
            *eax = (rep > 2) ? 7 : 6;
    }
    if (*eax <= 5 && dist > 1) {
        mask = d->mode.dict_mask;
        pos = d->st.window_pos;
        b0 = d->window[(pos - dist) & mask];
        b1 = d->window[(pos - dist + 1) & mask];
        ctx = (b0 << 8) | b1;
        if (*eax == 5)
            ctx += 0x10000;
        *pred_ptr = ctx;
        *has_pred = 1;
        *pred_byte = d->m_len_pred[*pred_ptr];
        *sec = d->m_len_pred[*pred_ptr + 0x20000];
    }
    return 0;
}

static int len_find_path(int esi, int edi_state, int target, int *bits, int *nbits)
{
    int ns, last;

    if (*nbits > 48)
        return 0;
    if (edi_state < esi + 1) {
        last = esi;
        ns = AlzLengthNext[2 * esi];
        bits[*nbits] = 0;
        (*nbits)++;
        if (ns == 0) {
            if ((last & 0xFF) == target)
                return 1;
        } else if (len_find_path(ns, edi_state, target, bits, nbits)) {
            return 1;
        }
        (*nbits)--;

        last = esi + 1;
        ns = AlzLengthNext[2 * esi + 1];
        bits[*nbits] = 1;
        (*nbits)++;
        if (ns == 0) {
            if ((last & 0xFF) == target)
                return 1;
        } else if (len_find_path(ns, edi_state, target, bits, nbits)) {
            return 1;
        }
        (*nbits)--;
        return 0;
    }
    ns = AlzLengthNext[2 * esi + 1];
    if (ns == 0)
        return ((esi + 1) & 0xFF) == target;
    return len_find_path(ns, edi_state, target, bits, nbits);
}

static alz_path_lut s_len_lut[8][256];
static int s_len_lut_ready;

static void len_lut_init(void)
{
    int edi, cnt, i, nbits;
    int bits[50];
    if (s_len_lut_ready)
        return;
    for (edi = 2; edi <= 7; edi++) {
        for (cnt = 1; cnt <= 255; cnt++) {
            nbits = 0;
            if (len_find_path(10, edi, cnt, bits, &nbits)) {
                s_len_lut[edi][cnt].ok = 1;
                s_len_lut[edi][cnt].nbits = (uint8_t)nbits;
                for (i = 0; i < nbits; i++)
                    s_len_lut[edi][cnt].bits[i] = (uint8_t)bits[i];
            }
        }
    }
    s_len_lut_ready = 1;
}

static int m_length_ok(alz_dec *d, int cls, uint32_t dist, uint32_t count)
{
    int edi_state;

    (void)d;
    if (count == 0 || count > 255)
        return 0;
    if (cls == 1) {
        if (dist < 0x100)
            edi_state = 3;
        else if (dist < 0x1000)
            edi_state = 4;
        else if (dist < 0x10000)
            edi_state = 5;
        else if (dist < 0x100000)
            edi_state = 6;
        else
            edi_state = 7;
    } else {
        edi_state = 2;
    }
    if (!s_len_lut_ready)
        len_lut_init();
    return s_len_lut[edi_state][count].ok;
}

static int m_encode_length(alz_dec *d, int cls, uint32_t dist, uint32_t count)
{
    int eax, edi_state, has_pred, pred_byte, sec, esi, last, b, i, bit;
    uint32_t pred_ptr, addr;
    const alz_path_lut *pl;

    if (count == 0 || count > 255)
        return -1;
    m_len_setup(d, cls, dist, &eax, &edi_state, &has_pred, &pred_ptr,
                &pred_byte, &sec);
    if (!s_len_lut_ready)
        len_lut_init();
    pl = &s_len_lut[edi_state][count];
    if (!pl->ok)
        return -1;
    if (has_pred)
        d->m_len_pred[pred_ptr + 0x20000] = (uint8_t)pred_byte;
    esi = 10;
    i = 0;
    for (;;) {
        last = esi + 1;
        if (edi_state < esi + 1) {
            bit = (int)pl->bits[i++];
            addr = (uint32_t)eax * 1024;
            if (esi >= pred_byte)
                addr += 256;
            if (sec <= esi)
                addr += 512;
            addr += (uint32_t)esi;
            if (m_bit12(d, &d->m_length[addr], 5, bit) != 0)
                return -1;
            if (bit == 0)
                last = esi;
        }
        b = (esi < last) ? 1 : 0;
        esi = AlzLengthNext[2 * esi + b];
        if (esi == 0)
            break;
    }
    if (has_pred)
        d->m_len_pred[pred_ptr] = (uint8_t)(count & 0xFF);
    return 0;
}

static int m_short_slot_for(alz_dec *d, uint32_t dist)
{
    int i;

    if (!s_short_slot_lut_ready)
        short_slot_lut_init();
    for (i = 1; i < ALZ_MAX_RECENT; i++) {
        uint32_t r = d->st.recent_distance[i];
        /* t15d : plus de normalisation 0->1 — un slot a 0 (jamais tourne,
         * semantique UHARC init 0) n'est jamais une distance emettable. */
        if (r == 0 || r != dist)
            continue;
        if (s_short_slot_lut[i].ok)
            return i;
    }
    return -1;
}

int alz_m_can_encode_match(alz_dec *d, int token, uint32_t dist, uint32_t count)
{
    if (dist == 0 || count == 0 || count > 255)
        return 0;
    if (dist > d->st.output_pos || dist > d->mode.dict_mask)
        return 0;
    if (token == 1) {
        if (!m_class1_dist_ok(d, dist))
            return 0;
    } else if (token == 2) {
        uint32_t r = d->st.recent_distance[0];
        if (r == 0 || r != dist)
            return 0;
    } else if (token == 3) {
        if (m_short_slot_for(d, dist) < 0)
            return 0;
    } else {
        return 0;
    }
    return m_length_ok(d, token, dist, count);
}

int alz_m_encode_match(alz_dec *d, int token, uint32_t dist, uint32_t count)
{
    int slot_mark, slot, idx, i;
    uint32_t rep;

    if (!d->w)
        return -1;
    if (!alz_m_can_encode_match(d, token, dist, count))
        return -1;

    if (token == 1) {
        if (m_encode_class1_dist(d, dist) != 0)
            return -1;
        slot_mark = 0xFF;
    } else if (token == 2) {
        slot_mark = 0;
    } else {
        slot = m_short_slot_for(d, dist);
        if (slot < 0)
            return -1;
        if (slot_encode(d, d->m_slot_short, AlzShortDistanceNext, 1, 0xB, slot) != 0)
            return -1;
        slot_mark = slot;
    }
    if (m_encode_length(d, token, dist, count) != 0)
        return -1;

    rep = d->st.repeat_run;
    if ((dist > 1) || (rep > 1)) {
        if (slot_mark != 0) {
            idx = (slot_mark == 0xFF) ? 11 : slot_mark;
            for (i = idx; i >= 1; i--)
                d->st.recent_distance[i] = d->st.recent_distance[i - 1];
            d->st.recent_distance[0] = dist;
        }
    }
    return 0;
}

/* =====================================================================
 * [RE b3a] Estimateur de cout-match FIDELE, lecture-seule.
 *
 * Objectif : remplacer alz_match_cost (crude, sous-estimante, source de la
 * sur-selection de matches courts, cf UHARC_RE_REPORT 13.34) par une somme
 * des couts-modele reels de chaque sous-champ du token, dans les MEMES
 * unites que le littéral alz_bm_predict_cost, a savoir :
 *     idx = (width << 14) / total ;  cout = AlzSseMap[idx]  (~ 4680*(-log2 p))
 * C'est exactement ce que depense le codeur : chaque appel reel
 * uha_rcw_encode(low, low+width, total) ou uha_rcw_encode_fixed12(w, lo, hi)
 * equivaut a un symbole de largeur `width` sur un total `total`.
 *
 * On ne MUTE RIEN : on lit les frequences courantes (cout marginal pre-token,
 * coherent avec le cote litteral froid de l'arbitre). Retourne ~0u si le
 * token n'est pas codable (garde d'appel identique a alz_m_encode_match).
 * ===================================================================== */

/* Cout modele d'un symbole de largeur `width` sur alphabet `total`. */
static uint32_t mc_rc_cost(uint32_t width, uint32_t total)
{
    uint32_t idx;
    if (width == 0 || total == 0)
        return 4680u * 8u;
    idx = (width << 14) / total;
    if (idx == 0)
        idx = 1;
    if (idx > 16384)
        idx = 16384;
    return AlzSseMap[idx];
}

/* Cout d'une decision binaire adaptative fixed12 (miroir de m_bit12) : total
 * fige a 4096, largeur = prob si bit==0 sinon 4096-prob. `prob` lu, non mutate. */
static uint32_t mc_bit12_cost(uint16_t prob, int bit)
{
    uint32_t width = bit ? (4096u - (uint32_t)prob) : (uint32_t)prob;
    return mc_rc_cost(width, 4096u);
}

/* Cout d'un chemin d'arbre de slots (miroir de slot_encode) : on retrouve les
 * bits via LUT/slot_find_path puis on cumule mc_bit12_cost sur prob[state]. */
static uint32_t mc_slot_cost(alz_dec *d, uint16_t *prob, const uint8_t *trans,
                             int init_state, int fallback, int target)
{
    int bits[50];
    const alz_path_lut *pl = NULL;
    const uint8_t *lut_bits = NULL;
    int nbits = 0;
    int state, slot, branch, i;
    uint32_t cost = 0;

    (void)d;
    if (trans == AlzShortDistanceNext && init_state == 1 && fallback == 0xB &&
        target >= 0 && target < 16) {
        if (!s_short_slot_lut_ready)
            short_slot_lut_init();
        pl = &s_short_slot_lut[target];
    } else if (trans == AlzFullDistanceNext && init_state == 0x10 && fallback == 0x2C &&
               target >= 0 && target < 64) {
        if (!s_full_dist_reach_ready)
            full_dist_reach_init();
        pl = &s_full_slot_lut[target];
    }
    if (pl) {
        if (!pl->ok)
            return ~(uint32_t)0;
        nbits = (int)pl->nbits;
        lut_bits = pl->bits;
    } else {
        if (!slot_find_path(trans, init_state, fallback, target, bits, &nbits))
            return ~(uint32_t)0;
    }
    state = init_state;
    slot = fallback;
    for (i = 0; i < nbits; i++) {
        int bit = lut_bits ? (int)lut_bits[i] : bits[i];
        cost += mc_bit12_cost(prob[state], bit);
        if (bit == 0)
            slot = state;
        branch = (slot > state) ? 1 : 0;
        state = trans[2 * state + branch];
    }
    return cost;
}

/* Cout du champ distance d'un token 1 (miroir de m_encode_class1_dist). */
static uint32_t mc_class1_dist_cost(alz_dec *d, uint32_t dist)
{
    int k;
    uint32_t base, span, limit, extra, v, cost;

    limit = d->st.output_pos;
    if (dist_to_bucket(dist, limit, &k, &base, &span) != 0)
        return ~(uint32_t)0;
    cost = mc_slot_cost(d, d->m_slot_long, AlzFullDistanceNext, 0x10, 0x2C, k + 1);
    if (cost == ~(uint32_t)0)
        return ~(uint32_t)0;
    if (k == 0)
        return cost;
    extra = dist - base;
    if (span >= 4) {
        int low_bit = (int)(extra & 1);
        extra >>= 1;
        cost += mc_bit12_cost(d->m_low_bit, low_bit);
        span >>= 1;
    }
    if (span > 0x800) {
        uint32_t nblocks = ((span - 1) >> 11) + 1;
        v = extra >> 11;
        cost += mc_rc_cost(1, nblocks);
        extra -= v << 11;
        span = (nblocks != v + 1) ? 0x800u : span - (v << 11);
    }
    if (span >= 2)
        cost += mc_rc_cost(1, span);
    return cost;
}

/* Cout du champ longueur, tout token (miroir de m_encode_length). */
static uint32_t mc_length_cost(alz_dec *d, int cls, uint32_t dist, uint32_t count)
{
    int eax, edi_state, has_pred, pred_byte, sec, esi, last, b, i, bit;
    uint32_t pred_ptr, addr, cost = 0;
    const alz_path_lut *pl;

    if (count == 0 || count > 255)
        return ~(uint32_t)0;
    m_len_setup(d, cls, dist, &eax, &edi_state, &has_pred, &pred_ptr,
                &pred_byte, &sec);
    if (!s_len_lut_ready)
        len_lut_init();
    pl = &s_len_lut[edi_state][count];
    if (!pl->ok)
        return ~(uint32_t)0;
    esi = 10;
    i = 0;
    for (;;) {
        last = esi + 1;
        if (edi_state < esi + 1) {
            bit = (int)pl->bits[i++];
            addr = (uint32_t)eax * 1024;
            if (esi >= pred_byte)
                addr += 256;
            if (sec <= esi)
                addr += 512;
            addr += (uint32_t)esi;
            cost += mc_bit12_cost(d->m_length[addr], bit);
            if (bit == 0)
                last = esi;
        }
        b = (esi < last) ? 1 : 0;
        esi = AlzLengthNext[2 * esi + b];
        if (esi == 0)
            break;
    }
    return cost;
}

uint32_t alz_match_model_cost(alz_dec *d, int token, uint32_t dist,
                              uint32_t count)
{
    int ci;
    uint32_t total, low, high, c, dc, lc;

    if (dist == 0 || count == 0 || count > 255)
        return ~(uint32_t)0;
    if (token < 1 || token > 3)
        return ~(uint32_t)0;

    /* (1) classe de token */
    ci = alz_token_class_index_ro(d);
    total = d->token_class[ci][5];
    if (total == 0)
        return ~(uint32_t)0;
    low = d->token_class[ci][token];
    high = (token == 4) ? d->token_class[ci][5]
                        : d->token_class[ci][token + 1];
    c = mc_rc_cost(high - low, total);

    /* (2) distance : token1 explicite, token2 recent[0] (0 bit), token3 slot court */
    if (token == 1) {
        dc = mc_class1_dist_cost(d, dist);
        if (dc == ~(uint32_t)0)
            return ~(uint32_t)0;
        c += dc;
    } else if (token == 3) {
        int slot = m_short_slot_for(d, dist);
        if (slot < 0)
            return ~(uint32_t)0;
        dc = mc_slot_cost(d, d->m_slot_short, AlzShortDistanceNext, 1, 0xB, slot);
        if (dc == ~(uint32_t)0)
            return ~(uint32_t)0;
        c += dc;
    }

    /* (3) longueur */
    lc = mc_length_cost(d, token, dist, count);
    if (lc == ~(uint32_t)0)
        return ~(uint32_t)0;
    c += lc;
    return c;
}
