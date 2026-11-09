#include <string.h>
#include "alz_priv.h"
#include "alz_const.inc"

static int32_t alz_mmw(int32_t v)
{
    int32_t i = v & 0xFFF;
    return (i <= 0x800) ? i : (0x1000 - i);
}

static int32_t alz_sext8(uint8_t b)
{
    return (b & 0x80) ? (int32_t)b - 256 : (int32_t)b;
}

uint8_t alz_decode_literal(alz_dec *d)
{
    int last, prev, ctx, ctx2;

    last = d->st.last_byte;
    prev = d->st.prev_byte;
    if (!d->st.escape_changed) {
        ctx = last;
        if ((last & 0xC0) == (prev & 0xC0))
            ctx += 0x100;
        ctx2 = ((last & 0xE0) >> 5) + 0x3F9;
    } else {
        ctx = last + 0x200;
        ctx2 = 0x401;
    }
    d->st.bm_side_active = 0;
    return (uint8_t)alz_bm_decode_literal(d, ctx, ctx2);
}

int alz_encode_literal(alz_dec *d, uint8_t b)
{
    int last, prev, ctx, ctx2;

    last = d->st.last_byte;
    prev = d->st.prev_byte;
    if (!d->st.escape_changed) {
        ctx = last;
        if ((last & 0xC0) == (prev & 0xC0))
            ctx += 0x100;
        ctx2 = ((last & 0xE0) >> 5) + 0x3F9;
    } else {
        ctx = last + 0x200;
        ctx2 = 0x401;
    }
    d->st.bm_side_active = 0;
    return alz_bm_encode_literal(d, ctx, ctx2, b);
}

uint8_t alz_side_decode_literal(alz_dec *d)
{
    int ctx, ctx2, decoded;
    uint8_t bias;

    ctx = (int)d->st.side_secondary;
    ctx2 = 0x402 + d->st.escape_selector;
    bias = d->st.side_bias;
    if (d->bm_flag != 0) {
        if (d->st.side_dir == 0)
            d->bm_predb = (uint8_t)(d->bm_predb - bias);
        else
            d->bm_predb = (uint8_t)(bias - d->bm_predb);
    }
    d->st.bm_side_active = 1;
    decoded = alz_bm_decode_literal(d, ctx, ctx2);
    if (d->st.side_dir == 0)
        return (uint8_t)(bias + decoded);
    return (uint8_t)(bias - decoded);
}

/* Mirror encoder d'alz_side_decode_literal (t15a) : the byte b is rendu
 * by the delta code (dir 0 : b-bias ; dir 1 : bias-b), mod 256. L'ajustement
 * of bm_predb is identical (state partage) ; bm_side_active doitetre sets
 * before l'call bm as side decodeur. */
int alz_side_encode_literal(alz_dec *d, uint8_t b)
{
    int ctx, ctx2;
    uint8_t bias, delta;

    ctx = (int)d->st.side_secondary;
    ctx2 = 0x402 + d->st.escape_selector;
    bias = d->st.side_bias;
    if (d->bm_flag != 0) {
        if (d->st.side_dir == 0)
            d->bm_predb = (uint8_t)(d->bm_predb - bias);
        else
            d->bm_predb = (uint8_t)(bias - d->bm_predb);
    }
    if (d->st.side_dir == 0)
        delta = (uint8_t)(b - bias);
    else
        delta = (uint8_t)(bias - b);
    d->st.bm_side_active = 1;
    return alz_bm_encode_literal(d, ctx, ctx2, delta);
}

static void mm_slot_update(alz_dec *d, int s, uint8_t out_byte, uint8_t delta_byte)
{
    int32_t out_s, base_val, min_v, v;
    int i, k;
    alz_state *st = &d->st;

    st->slot_dir[s] = st->side_dir;
    out_s = alz_sext8(out_byte);
    base_val = alz_sext8((uint8_t)(st->mm_prev_score - out_s)) << 4;

    st->mm_acc[s][0]  += alz_mmw(base_val);
    st->mm_acc[s][1]  += alz_mmw(base_val - st->mm_hist[s][0]);
    st->mm_acc[s][2]  += alz_mmw(base_val + st->mm_hist[s][0]);
    st->mm_acc[s][3]  += alz_mmw(base_val - st->mm_hist[s][1]);
    st->mm_acc[s][4]  += alz_mmw(base_val + st->mm_hist[s][1]);
    st->mm_acc[s][5]  += alz_mmw(base_val - st->mm_hist[s][2]);
    st->mm_acc[s][6]  += alz_mmw(base_val + st->mm_hist[s][2]);
    st->mm_acc[s][7]  += alz_mmw(base_val - st->mm_hist[s][3]);
    st->mm_acc[s][8]  += alz_mmw(base_val + st->mm_hist[s][3]);
    st->mm_acc[s][9]  += alz_mmw(base_val - st->mm_global);
    st->mm_acc[s][10] += alz_mmw(base_val + st->mm_global);

    st->mm_cost5c[s] += (int32_t)AlzMMCost[(uint8_t)(st->mm_prev_score - out_s)];
    st->mm_cost60[s] += (int32_t)AlzMMCost[(uint8_t)(st->mm_last[s] - out_s)];
    st->mm_delta[s] = alz_sext8((uint8_t)(out_s - st->mm_last[s]));
    st->mm_global = st->mm_delta[s];
    st->mm_counter[s]++;
    st->mm_last[s] = out_s;

    if ((st->mm_counter[s] & 0xF) == 0) {
        min_v = st->mm_acc[s][0];
        k = 0;
        st->mm_acc[s][0] = 0;
        for (i = 1; i <= 10; i++) {
            v = st->mm_acc[s][i];
            if (min_v > v) {
                min_v = v;
                k = i;
            }
            st->mm_acc[s][i] = 0;
        }
        k--;
        switch (k) {
        case 0: if (st->mm_coef[s][0] > -0x20) st->mm_coef[s][0]--; break;
        case 1: if (st->mm_coef[s][0] <  0x20) st->mm_coef[s][0]++; break;
        case 2: if (st->mm_coef[s][1] > -0x20) st->mm_coef[s][1]--; break;
        case 3: if (st->mm_coef[s][1] <  0x20) st->mm_coef[s][1]++; break;
        case 4: if (st->mm_coef[s][2] > -0x20) st->mm_coef[s][2]--; break;
        case 5: if (st->mm_coef[s][2] <  0x20) st->mm_coef[s][2]++; break;
        case 6: if (st->mm_coef[s][3] > -0x20) st->mm_coef[s][3]--; break;
        case 7: if (st->mm_coef[s][3] <  0x20) st->mm_coef[s][3]++; break;
        case 8: if (st->mm_coef[s][3] > -0x20) st->mm_coef[s][4]--; break;
        case 9: if (st->mm_coef[s][3] <  0x20) st->mm_coef[s][4]++; break;
        }
        if ((st->mm_counter[s] & 0xFF) == 0) {
            st->mm_cost5c[s] -= st->mm_cost64[s];
            st->mm_cost64[s] = st->mm_cost5c[s];
            st->mm_cost60[s] -= st->mm_cost68[s];
            st->mm_cost68[s] = st->mm_cost60[s];
        }
    }
    if (st->escape_selector == 9) {
        i = st->mm_global;
        st->mm_global = st->mm_global2;
        st->mm_global2 = i;
    }
    st->slot_hash[s] = (st->slot_hash[s] << 8) + delta_byte;
    if (st->escape_selector == 7) {
        st->slot_hash74[s] = (st->slot_hash74[s] << 8) + (uint32_t)AlzS7BankC[delta_byte];
        st->slot_hash78[s] = (st->slot_hash78[s] << 8) + (uint32_t)AlzS7BankD[delta_byte];
    }
}

static void mm_score(alz_dec *d, int s)
{
    int32_t new_h1, h1_old, h2_old, score;
    alz_state *st = &d->st;

    h1_old = st->mm_hist[s][1];
    h2_old = st->mm_hist[s][2];
    new_h1 = st->mm_delta[s] - st->mm_hist[s][0];
    score = (st->mm_last[s] << 4)
          + st->mm_coef[s][0] * st->mm_delta[s]
          + st->mm_coef[s][1] * new_h1
          + st->mm_coef[s][2] * h1_old
          + st->mm_coef[s][3] * h2_old
          + st->mm_coef[s][4] * st->mm_global;
    st->mm_hist[s][3] = h2_old;
    st->mm_hist[s][2] = h1_old;
    st->mm_hist[s][1] = new_h1;
    st->mm_hist[s][0] = st->mm_delta[s];
    score /= 16;
    st->mm_prev_score = score;
    if (st->mm_cost5c[s] > st->mm_cost60[s])
        st->side_bias = (uint8_t)st->mm_last[s];
    else
        st->side_bias = (uint8_t)score;
}

static void mm_slot_update6(alz_dec *d, uint8_t out_byte, uint8_t delta_byte)
{
    int32_t out_s, base_val, ring_delta, min_v, v, sum, d1, d2, d3, edi_min;
    int i, k, a, cnt, ring_pos, bv, gcnt;
    int32_t res[6];
    alz_state *st = &d->st;

    gcnt = (int)st->output_pos - 1;
    out_s = alz_sext8(out_byte);
    ring_delta = out_s - st->cand_cur;
    base_val = alz_sext8((uint8_t)(st->cand_score[3] - out_s)) << 4;

    st->mm_acc[0][0]  += alz_mmw(base_val);
    st->mm_acc[0][1]  += alz_mmw(base_val - st->mm_hist[0][0]);
    st->mm_acc[0][2]  += alz_mmw(base_val + st->mm_hist[0][0]);
    st->mm_acc[0][3]  += alz_mmw(base_val - st->mm_hist[0][1]);
    st->mm_acc[0][4]  += alz_mmw(base_val + st->mm_hist[0][1]);
    st->mm_acc[0][5]  += alz_mmw(base_val - st->mm_hist[0][2]);
    st->mm_acc[0][6]  += alz_mmw(base_val + st->mm_hist[0][2]);
    st->mm_acc[0][7]  += alz_mmw(base_val - st->mm_hist[0][3]);
    st->mm_acc[0][8]  += alz_mmw(base_val + st->mm_hist[0][3]);
    st->mm_acc[0][9]  += alz_mmw(base_val - st->mm_hist[0][4]);
    st->mm_acc[0][10] += alz_mmw(base_val + st->mm_hist[0][4]);

    st->mm_counter[0]++;
    st->mm_delta[0] = alz_sext8((uint8_t)(out_s - st->mm_last[0]));
    st->mm_last[0] = out_s;

    if ((st->mm_counter[0] & 0xF) == 0) {
        min_v = st->mm_acc[0][0];
        k = 0;
        st->mm_acc[0][0] = 0;
        for (i = 1; i <= 10; i++) {
            v = st->mm_acc[0][i];
            if (min_v > v) {
                min_v = v;
                k = i;
            }
            st->mm_acc[0][i] = 0;
        }
        k--;
        switch (k) {
        case 0: if (st->mm_coef[0][0] > -0x20) st->mm_coef[0][0]--; break;
        case 1: if (st->mm_coef[0][0] <  0x20) st->mm_coef[0][0]++; break;
        case 2: if (st->mm_coef[0][1] > -0x20) st->mm_coef[0][1]--; break;
        case 3: if (st->mm_coef[0][1] <  0x20) st->mm_coef[0][1]++; break;
        case 4: if (st->mm_coef[0][2] > -0x20) st->mm_coef[0][2]--; break;
        case 5: if (st->mm_coef[0][2] <  0x20) st->mm_coef[0][2]++; break;
        case 6: if (st->mm_coef[0][3] > -0x20) st->mm_coef[0][3]--; break;
        case 7: if (st->mm_coef[0][3] <  0x20) st->mm_coef[0][3]++; break;
        case 8: if (st->mm_coef[0][3] > -0x20) st->mm_coef[0][4]--; break;
        case 9: if (st->mm_coef[0][3] <  0x20) st->mm_coef[0][4]++; break;
        }
    }

    st->delta_ring[gcnt & 0x7F] = ring_delta;
    if ((AlzCandMask[st->cand_best0] & (int32_t)gcnt) == 0) {
        st->cand_best1 = 2;
        st->cand_best2 = 2;
        edi_min = 0xFFFF;
        cnt = gcnt;
        for (a = 2; a <= 123; a++) {
            d1 = (st->delta_ring[(cnt - 1) & 0x7F] - st->delta_ring[(cnt - 1 - a) & 0x7F]) & 0xFFF;
            d2 = (st->delta_ring[cnt & 0x7F] - st->delta_ring[(cnt - a) & 0x7F]) & 0xFFF;
            d3 = (st->delta_ring[(cnt - 2) & 0x7F] - st->delta_ring[(cnt - 2 - a) & 0x7F]) & 0xFFF;
            sum = alz_mmw(d1) + alz_mmw(d2) + alz_mmw(d3);
            st->cand_acc[a] = ((st->cand_acc[a] * 13) >> 4) + sum;
            if (st->cand_acc[a] < st->cand_acc[st->cand_best1])
                st->cand_best1 = a;
            if (sum < edi_min) {
                edi_min = sum;
                st->cand_best2 = a;
            }
        }
    }
    res[0] = out_s - st->cand_score[0];
    res[1] = out_s - st->cand_score[1];
    res[2] = out_s - st->cand_score[2];
    res[3] = out_s - st->cand_score[3];
    res[4] = ring_delta - st->cand_score[4];
    res[5] = ring_delta - st->cand_score[5];
    st->cand_best0 = 0;
    ring_pos = gcnt & 0xFF;
    for (k = 0; k <= 5; k++) {
        st->res_bank[k][256] -= st->res_bank[k][ring_pos];
        bv = AlzCandBucket9[res[k] & 0x1FF];
        st->res_bank[k][ring_pos] = bv;
        st->res_bank[k][256] += bv;
        if (st->res_bank[k][256] < st->res_bank[st->cand_best0][256])
            st->cand_best0 = k;
    }
    st->cand_prev = st->cand_cur;
    st->cand_cur = out_s;
    st->slot_hash[0]   = (st->slot_hash[0]   << 8) + delta_byte;
    st->slot_hash74[0] = (st->slot_hash74[0] << 8) + (uint32_t)AlzCandByteA[delta_byte];
    st->slot_hash78[0] = (st->slot_hash78[0] << 8) + (uint32_t)AlzCandByteB[delta_byte];
}

static void mm_score6(alz_dec *d, int sel)
{
    int ring_idx1, ring_idx2, base;
    int32_t ring_v, old_h1, old_h2, new_h1, score;
    uint8_t sb;
    alz_state *st = &d->st;

    st->cand_score[0] = 0;
    st->cand_score[1] = st->cand_cur;
    st->cand_score[2] = (st->cand_cur + st->cand_cur) - st->cand_prev;
    ring_idx1 = ((int)st->output_pos - st->cand_best1) & 0x7F;
    ring_v = st->delta_ring[ring_idx1];
    old_h1 = st->mm_hist[0][1];
    old_h2 = st->mm_hist[0][2];
    new_h1 = st->mm_delta[0] - st->mm_hist[0][0];
    st->mm_hist[0][4] = ring_v;
    st->mm_hist[0][3] = old_h2;
    st->mm_hist[0][2] = old_h1;
    st->mm_hist[0][1] = new_h1;
    st->mm_hist[0][0] = st->mm_delta[0];
    score = (st->mm_last[0] << 4)
          + st->mm_coef[0][0] * st->mm_delta[0]
          + st->mm_coef[0][1] * new_h1
          + st->mm_coef[0][2] * old_h1
          + st->mm_coef[0][3] * old_h2
          + st->mm_coef[0][4] * ring_v;
    score /= 16;
    st->cand_score[3] = score;
    st->cand_score[4] = ring_v;
    ring_idx2 = ((int)st->output_pos - st->cand_best2) & 0x7F;
    st->cand_score[5] = st->delta_ring[ring_idx2];
    sb = (uint8_t)st->cand_score[st->cand_best0];
    if (st->cand_best0 >= 4)
        sb = (uint8_t)(sb + (uint8_t)st->cand_cur);
    st->side_bias = sb;
    if (sel == 5) {
        st->side_bias = (uint8_t)(st->side_bias + 0x80);
        base = 0x3E1;
    } else {
        base = 0x3E5;
    }
    if (st->slot_hash[0] == 0)
        base++;
    else if (st->slot_hash74[0] == 0)
        base += 2;
    else if (st->slot_hash78[0] == 0)
        base += 3;
    st->side_secondary = (uint32_t)base;
}

void alz_side_post_update(alz_dec *d, uint8_t output_byte)
{
    uint8_t delta;
    int old_edi, new_edi, base7, old_smc, base_idx, ref_b, idx_b, stat_idx, pred;
    int confident, active;
    alz_state *st = &d->st;

    delta = (uint8_t)(output_byte - st->side_bias);
    if (st->side_dir != 0)
        delta = (uint8_t)(-(int)delta);
    if (delta >= 0x80)
        st->side_dir = st->side_dir ? 0 : 1;

    if (st->escape_selector >= 1 && st->escape_selector <= 4
        && st->escape_selector != 3) {
        switch (st->escape_selector) {
        case 1:
            st->side_secondary = (uint32_t)(0x301
                + (AlzSelTab16[(int)(st->side_secondary - 0x301) & 0xF] << 4)
                + AlzSelTab2[delta]);
            break;
        case 2:
            st->side_secondary = (uint32_t)(0x321
                + ((int)st->side_mod_count << 4) + AlzSelTab2[delta]);
            break;
        case 4:
            st->side_secondary = (uint32_t)(0x3A1
                + ((int)st->side_mod_count << 4) + AlzSelTab2[delta]);
            break;
        }
        st->side_mod_count = st->side_primary
            ? st->output_pos % st->side_primary : 0;
        st->side_bias = (uint8_t)(st->rolling_history >> st->escape_literal_bias);
        st->mm_out_count++;
        return;
    }

    if (st->escape_selector == 5 || st->escape_selector == 6) {
        if (st->escape_selector == 5)
            mm_slot_update6(d, (uint8_t)(output_byte ^ 0x80), delta);
        else
            mm_slot_update6(d, output_byte, delta);
        st->mm_out_count++;
        st->side_mod_count = st->side_primary
            ? st->output_pos % st->side_primary : 0;
        st->side_bias = (uint8_t)(st->rolling_history >> st->escape_literal_bias);
        mm_score6(d, st->escape_selector);
        return;
    }

    if (st->escape_selector == 7) {
        old_edi = (int)st->side_mod_count & 0xF;
        mm_slot_update(d, old_edi, (uint8_t)(output_byte ^ 0x80), delta);
        st->mm_out_count++;
        new_edi = st->side_primary ? (int)(st->output_pos % st->side_primary) : 0;
        st->side_mod_count = (uint32_t)new_edi;
        mm_score(d, new_edi);
        st->side_bias = (uint8_t)(st->side_bias + 0x80);
        base7 = 0x3E9 + new_edi;
        if (st->slot_hash[new_edi & 0xF] == 0)
            base7 += 2;
        else if (st->slot_hash74[new_edi & 0xF] == 0)
            base7 += 4;
        else if (st->slot_hash78[new_edi & 0xF] == 0)
            base7 += 6;
        st->side_secondary = (uint32_t)base7;
        st->side_dir = st->slot_dir[new_edi & 0xF];
        return;
    }

    if (st->escape_selector == 3) {
        old_smc = (int)st->side_mod_count;
        if (st->s3_active != 0) {
            ref_b = ((int)st->rolling_history >> 24) & 0xFF;
            idx_b = ((int)output_byte - ref_b) & 0xFF;
            st->side_dir = st->s3_dir_saved;
            if (st->side_dir != 0)
                idx_b = (-idx_b) & 0xFF;
            if (idx_b >= 0x80)
                st->side_dir = st->side_dir ? 0 : 1;
            base_idx = idx_b;
        } else {
            base_idx = delta;
        }
        if ((int)output_byte == (int)st->s3_pred_tab[st->s3_idx])
            st->s3_counter[st->s3_idx]++;
        else
            st->s3_counter[st->s3_idx] >>= 1;
        st->side_secondary = (uint32_t)(0x341 + (old_smc << 5)
            + AlzS3Tab[base_idx & 0xFF]);
        st->mm_out_count++;
        st->side_mod_count = st->side_primary
            ? st->output_pos % st->side_primary : 0;
        st->side_bias = (uint8_t)(st->rolling_history >> st->escape_literal_bias);
        stat_idx = (int)(st->output_pos % 6);
        st->s3_idx = (uint8_t)stat_idx;
        confident = st->s3_counter[stat_idx] > 8;
        pred = ((int)st->side_bias
             + ((int)st->rolling_history & 0xFF)
             - (((int)st->rolling_history >> 24) & 0xFF)) & 0xFF;
        st->s3_pred_tab[stat_idx] = (uint8_t)pred;
        active = confident && (st->s3_streak < 5);
        st->s3_active = active ? 1 : 0;
        if (active) {
            st->s3_dir_saved = st->side_dir;
            st->side_secondary = (uint32_t)(0x351 + (old_smc << 5));
            st->side_bias = st->s3_pred_tab[stat_idx];
            st->side_dir = 0;
        }
        if (confident)
            st->s3_streak++;
        else
            st->s3_streak = 0;
        return;
    }

    if (st->escape_selector < 8) {
        d->rc.corrupt = 1;
        return;
    }

    old_edi = (int)st->side_mod_count & 0xF;
    mm_slot_update(d, old_edi, output_byte, delta);
    st->mm_out_count++;
    new_edi = st->side_primary ? (int)(st->output_pos % st->side_primary) : 0;
    st->side_mod_count = (uint32_t)new_edi;
    mm_score(d, new_edi);
    if (st->slot_hash[new_edi & 0xF] != 0)
        st->side_secondary = AlzSelectorSecondaryBase[st->escape_selector]
                           + (uint32_t)new_edi;
    else
        st->side_secondary = AlzSelectorSecondaryBase[st->escape_selector] + 4;
    st->side_dir = st->slot_dir[new_edi & 0xF];
}
