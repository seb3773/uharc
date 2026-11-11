#include <string.h>
#include "ppm_priv.h"

static int32_t alz_mmw(int32_t v)
{
    int32_t i = v & 0xFFF;
    if (i <= 0x800)
        return i;
    return 0x1000 - i;
}

void ppm_mm6_reset(ppm_mm6 *s)
{
    memset(s, 0, sizeof(*s));
    s->cand_best2 = 2;
    s->slot_hash[0] = 0xFFFFFFFFu;
    s->slot_hash74[0] = 0xFFFFFFFFu;
    s->slot_hash78[0] = 0xFFFFFFFFu;
}

void ppm_mm6_update(ppm_mm6 *s, uint8_t out_byte, uint8_t delta_byte, uint32_t position)
{
    int32_t out_s, base_val, ring_delta, min_v, v, sum, d1, d2, d3, edi_min;
    int i, k, a, cnt, ring_pos, bv, gcnt;
    int32_t res[6];

    gcnt = (int)position;
    out_s = ppm_sext8(out_byte);
    ring_delta = out_s - s->cand_cur;
    base_val = ppm_sext8((uint8_t)(s->cand_score[3] - out_s)) * 16;

    s->mm_acc[0][0]  += alz_mmw(base_val);
    s->mm_acc[0][1]  += alz_mmw(base_val - s->mm_hist[0][0]);
    s->mm_acc[0][2]  += alz_mmw(base_val + s->mm_hist[0][0]);
    s->mm_acc[0][3]  += alz_mmw(base_val - s->mm_hist[0][1]);
    s->mm_acc[0][4]  += alz_mmw(base_val + s->mm_hist[0][1]);
    s->mm_acc[0][5]  += alz_mmw(base_val - s->mm_hist[0][2]);
    s->mm_acc[0][6]  += alz_mmw(base_val + s->mm_hist[0][2]);
    s->mm_acc[0][7]  += alz_mmw(base_val - s->mm_hist[0][3]);
    s->mm_acc[0][8]  += alz_mmw(base_val + s->mm_hist[0][3]);
    s->mm_acc[0][9]  += alz_mmw(base_val - s->mm_hist[0][4]);
    s->mm_acc[0][10] += alz_mmw(base_val + s->mm_hist[0][4]);

    s->mm_counter[0]++;
    s->mm_delta[0] = ppm_sext8((uint8_t)(out_s - s->mm_last[0]));
    s->mm_last[0] = out_s;

    if ((s->mm_counter[0] & 0xF) == 0) {
        min_v = s->mm_acc[0][0];
        k = 0;
        s->mm_acc[0][0] = 0;
        for (i = 1; i <= 10; i++) {
            v = s->mm_acc[0][i];
            if (min_v > v) {
                min_v = v;
                k = i;
            }
            s->mm_acc[0][i] = 0;
        }
        k--;
        switch (k) {
        case 0: if (s->mm_coef[0][0] > -0x20) s->mm_coef[0][0]--; break;
        case 1: if (s->mm_coef[0][0] <  0x20) s->mm_coef[0][0]++; break;
        case 2: if (s->mm_coef[0][1] > -0x20) s->mm_coef[0][1]--; break;
        case 3: if (s->mm_coef[0][1] <  0x20) s->mm_coef[0][1]++; break;
        case 4: if (s->mm_coef[0][2] > -0x20) s->mm_coef[0][2]--; break;
        case 5: if (s->mm_coef[0][2] <  0x20) s->mm_coef[0][2]++; break;
        case 6: if (s->mm_coef[0][3] > -0x20) s->mm_coef[0][3]--; break;
        case 7: if (s->mm_coef[0][3] <  0x20) s->mm_coef[0][3]++; break;
        case 8: if (s->mm_coef[0][3] > -0x20) s->mm_coef[0][4]--; break;
        case 9: if (s->mm_coef[0][3] <  0x20) s->mm_coef[0][4]++; break;
        }
    }

    s->delta_ring[gcnt & 0x7F] = ring_delta;

    if ((AlzCandMask[s->cand_best0] & (int32_t)gcnt) == 0) {
        s->cand_best1 = 2;
        s->cand_best2 = 2;
        edi_min = 0xFFFF;
        cnt = gcnt;
        for (a = 2; a <= 123; a++) {
            d1 = (s->delta_ring[(cnt - 1) & 0x7F] - s->delta_ring[(cnt - 1 - a) & 0x7F]) & 0xFFF;
            d2 = (s->delta_ring[cnt & 0x7F]       - s->delta_ring[(cnt - a) & 0x7F])     & 0xFFF;
            d3 = (s->delta_ring[(cnt - 2) & 0x7F] - s->delta_ring[(cnt - 2 - a) & 0x7F]) & 0xFFF;
            sum = alz_mmw(d1) + alz_mmw(d2) + alz_mmw(d3);
            s->cand_acc[a] = ((s->cand_acc[a] * 13) >> 4) + sum;
            if (s->cand_acc[a] < s->cand_acc[s->cand_best1])
                s->cand_best1 = a;
            if (sum < edi_min) {
                edi_min = sum;
                s->cand_best2 = a;
            }
        }
    }

    res[0] = out_s - s->cand_score[0];
    res[1] = out_s - s->cand_score[1];
    res[2] = out_s - s->cand_score[2];
    res[3] = out_s - s->cand_score[3];
    res[4] = ring_delta - s->cand_score[4];
    res[5] = ring_delta - s->cand_score[5];
    s->cand_best0 = 0;
    ring_pos = gcnt & 0xFF;
    for (k = 0; k <= 5; k++) {
        s->res_bank[k][256] -= s->res_bank[k][ring_pos];
        bv = PPMS_CandBucket9[res[k] & 0x1FF];
        s->res_bank[k][ring_pos] = bv;
        s->res_bank[k][256] += bv;
        if (s->res_bank[k][256] < s->res_bank[s->cand_best0][256])
            s->cand_best0 = k;
    }

    s->cand_prev = s->cand_cur;
    s->cand_cur = out_s;

    s->slot_hash[0]   = (s->slot_hash[0]   << 8) + delta_byte;
    s->slot_hash74[0] = (s->slot_hash74[0] << 8) + (uint32_t)AlzCandByteA[delta_byte];
    s->slot_hash78[0] = (s->slot_hash78[0] << 8) + (uint32_t)AlzCandByteB[delta_byte];
}

void ppm_mm6_predict(ppm_mm6 *s, uint32_t position, uint8_t *base_byte, uint32_t *context)
{
    int ring_idx1, ring_idx2, base;
    int32_t ring_v, old_h1, old_h2, new_h1, score;
    uint8_t sb;

    s->cand_score[0] = 0;
    s->cand_score[1] = s->cand_cur;
    s->cand_score[2] = (s->cand_cur + s->cand_cur) - s->cand_prev;

    ring_idx1 = ((int)position - s->cand_best1) & 0x7F;
    ring_v = s->delta_ring[ring_idx1];

    old_h1 = s->mm_hist[0][1];
    old_h2 = s->mm_hist[0][2];
    new_h1 = s->mm_delta[0] - s->mm_hist[0][0];
    s->mm_hist[0][4] = ring_v;
    s->mm_hist[0][3] = old_h2;
    s->mm_hist[0][2] = old_h1;
    s->mm_hist[0][1] = new_h1;
    s->mm_hist[0][0] = s->mm_delta[0];

    score = (s->mm_last[0] * 16)
          + s->mm_coef[0][0] * s->mm_delta[0]
          + s->mm_coef[0][1] * new_h1
          + s->mm_coef[0][2] * old_h1
          + s->mm_coef[0][3] * old_h2
          + s->mm_coef[0][4] * ring_v;
    score = score / 16;
    s->cand_score[3] = score;
    s->cand_score[4] = ring_v;
    ring_idx2 = ((int)position - s->cand_best2) & 0x7F;
    s->cand_score[5] = s->delta_ring[ring_idx2];

    sb = (uint8_t)s->cand_score[s->cand_best0];
    if (s->cand_best0 >= 4)
        sb = (uint8_t)(sb + (uint8_t)s->cand_cur);
    *base_byte = sb;

    base = 0x2ED;
    if (s->slot_hash[0] == 0)
        base++;
    else if (s->slot_hash74[0] == 0)
        base += 2;
    else if (s->slot_hash78[0] == 0)
        base += 3;
    *context = (uint32_t)base;
}

static uint32_t mm7_distance(int32_t v)
{
    uint32_t r = (uint32_t)(v & 0xFFF);
    if (r > 0x800)
        r = 0x1000 - r;
    return r;
}

void ppm_mm7_reset(ppm_mm7 *s, uint8_t cls)
{
    int sl;
    memset(s, 0, sizeof(*s));
    s->sample_class = cls;
    for (sl = 0; sl <= 3; sl++) {
        s->hash[sl] = 0xFFFFFFFFu;
        s->hash74[sl] = 0xFFFFFFFFu;
        s->hash78[sl] = 0xFFFFFFFFu;
    }
}

void ppm_mm7_update(ppm_mm7 *s, uint32_t slot, uint8_t out_byte, uint8_t delta_byte, uint8_t neg)
{
    int sl, i, k, c, bound;
    int32_t out_s, base_val, h;
    uint32_t min_v;

    sl = (int)(slot & 3);
    s->direction[sl] = neg;
    if (s->sample_class == 7)
        out_s = (int)out_byte - 0x80;
    else
        out_s = ppm_sext8(out_byte);
    base_val = ppm_sext8((uint8_t)(s->prev_score - out_s)) * 16;
    s->acc[sl][0] += mm7_distance(base_val);
    for (i = 0; i <= 4; i++) {
        h = (i == 4) ? s->global_delta : s->hist[sl][i];
        s->acc[sl][i * 2 + 1] += mm7_distance(base_val - h);
        s->acc[sl][i * 2 + 2] += mm7_distance(base_val + h);
    }
    s->cost[sl] += PPMS_MMCost[(uint8_t)(s->prev_score - out_s)];
    s->last_cost[sl] += PPMS_MMCost[(uint8_t)(s->last[sl] - out_s)];
    s->delta[sl] = ppm_sext8((uint8_t)(out_s - s->last[sl]));
    s->global_delta = s->delta[sl];
    s->counter[sl]++;
    s->last[sl] = out_s;
    if ((s->counter[sl] & 0xF) == 0) {
        min_v = s->acc[sl][0];
        k = 0;
        s->acc[sl][0] = 0;
        for (i = 1; i <= 10; i++) {
            if (min_v > s->acc[sl][i]) {
                min_v = s->acc[sl][i];
                k = i;
            }
            s->acc[sl][i] = 0;
        }
        if (k != 0) {
            c = (k - 1) / 2;
            bound = c;
            if (c == 4)
                bound = 3;
            if (k & 1) {
                if (s->coef[sl][bound] > -0x20)
                    s->coef[sl][c]--;
            } else if (s->coef[sl][bound] < 0x20) {
                s->coef[sl][c]++;
            }
        }
        if ((s->counter[sl] & 0xFF) == 0) {
            s->cost[sl] -= s->prior_cost[sl];
            s->prior_cost[sl] = s->cost[sl];
            s->last_cost[sl] -= s->prior_last_cost[sl];
            s->prior_last_cost[sl] = s->last_cost[sl];
        }
    }
    if (s->sample_class == 9) {
        s->global_delta = s->delayed_delta;
        s->delayed_delta = s->delta[sl];
    }
    s->hash[sl] = (s->hash[sl] << 8) + delta_byte;
    if (s->sample_class == 7) {
        s->hash74[sl] = (s->hash74[sl] << 8) + (uint32_t)PPMS_S7BankC[delta_byte];
        s->hash78[sl] = (s->hash78[sl] << 8) + (uint32_t)PPMS_S7BankD[delta_byte];
    }
}

void ppm_mm7_predict(ppm_mm7 *s, uint32_t slot, uint8_t *base_byte, uint8_t *neg, uint32_t *context)
{
    int sl;
    int32_t h1, h2, new_h1, score;

    sl = (int)(slot & 3);
    h1 = s->hist[sl][1];
    h2 = s->hist[sl][2];
    new_h1 = s->delta[sl] - s->hist[sl][0];
    score = (s->last[sl] * 16) + s->coef[sl][0] * s->delta[sl]
          + s->coef[sl][1] * new_h1 + s->coef[sl][2] * h1 + s->coef[sl][3] * h2
          + s->coef[sl][4] * s->global_delta;
    s->hist[sl][3] = h2;
    s->hist[sl][2] = h1;
    s->hist[sl][1] = new_h1;
    s->hist[sl][0] = s->delta[sl];
    s->prev_score = score / 16;
    if (s->cost[sl] > s->last_cost[sl])
        *base_byte = (uint8_t)s->last[sl];
    else
        *base_byte = (uint8_t)s->prev_score;
    if (s->sample_class == 7) {
        *base_byte = (uint8_t)(*base_byte + 0x80);
        *context = 0x2F1 + (uint32_t)sl;
        if (s->hash[sl] == 0)
            *context += 2;
        else if (s->hash74[sl] == 0)
            *context += 4;
        else if (s->hash78[sl] == 0)
            *context += 6;
    } else if (s->sample_class == 8) {
        *context = 0x2F9 + (uint32_t)sl;
        if (s->hash[sl] == 0)
            *context = 0x2FB;
    } else {
        *context = 0x2FC + (uint32_t)sl;
        if (s->hash[sl] == 0)
            *context = 0x300;
    }
    *neg = s->direction[sl];
}
