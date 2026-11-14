#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "alz_priv.h"

#include "alz_const.inc"

void alz_put_byte(alz_dec *d, uint8_t b)
{
    if (d->out && d->st.output_pos < d->outlen)
        d->out[d->st.output_pos] = b;
    d->window[d->st.window_pos & d->mode.dict_mask] = b;
    d->st.output_pos++;
    d->st.window_pos = (d->st.window_pos + 1) & d->mode.dict_mask;
    d->st.rolling_history = (d->st.rolling_history << 8) | b;
    d->st.prev_delta = (uint8_t)(b - d->st.last_byte);
    d->st.prev_byte = d->st.last_byte;
    d->st.last_byte = b;
}

uint8_t alz_prev_byte(alz_dec *d, uint32_t distance)
{
    uint32_t p;

    if (distance == 0)
        distance = 1;
    p = (d->st.window_pos - distance) & d->mode.dict_mask;
    return d->window[p];
}

void alz_copy_match(alz_dec *d, uint32_t distance, uint32_t count)
{
    uint32_t i;
    uint8_t b;

    for (i = 0; i < count; i++) {
        b = alz_prev_byte(d, distance);
        alz_put_byte(d, b);
        if (d->st.escape_selector != 0)
            alz_side_post_update(d, b);
    }
}

uint8_t alz_src_after_match(alz_dec *d, uint32_t dist, uint32_t count,
                            uint32_t win_pos_before)
{
    uint32_t start, after;

    if (dist == 0)
        dist = 1;
    start = (win_pos_before - dist) & d->mode.dict_mask;
    after = (start + count) & d->mode.dict_mask;
    return d->window[after];
}

uint16_t alz_src_pair_key(alz_dec *d, uint32_t distance)
{
    uint32_t p0, p1;

    if (distance == 0)
        distance = 1;
    p0 = (d->st.window_pos - distance) & d->mode.dict_mask;
    p1 = (p0 + 1) & d->mode.dict_mask;
    return (uint16_t)(((uint32_t)d->window[p0] << 8) | d->window[p1]);
}

void alz_update_literal_mode(alz_dec *d, int decoded_class)
{
    int index, old_mode;

    if (decoded_class <= 0)
        return;
    old_mode = d->st.literal_mode & 31;
    index = ((decoded_class - 1) << 5) + old_mode;
    if (index < 0 || index > 159) {
        d->rc.corrupt = 1;
        return;
    }
    d->st.literal_mode = AlzLiteralModeNext[index];
}

static void update_token_history(alz_dec *d, uint16_t key, int decoded_class)
{
    uint8_t stored, class_m1;

    if (decoded_class <= 0)
        return;
    class_m1 = (uint8_t)((decoded_class - 1) & 3);
    stored = d->token_history[key];
    if ((stored >> 6) == class_m1) {
        if ((stored & 63) != 63)
            stored++;
    } else {
        stored = (uint8_t)(class_m1 << 6);
    }
    d->token_history[key] = stored;
}

static int token_class_index(alz_dec *d, int *probed, uint16_t *hist_key)
{
    int class_index;
    uint8_t hist_byte;

    *probed = 0;
    *hist_key = (uint16_t)(d->st.rolling_history & 0xFFFF);

    if (d->st.repeat_run != 0)
        class_index = (d->st.repeat_run > 2) ? 65 : 64;
    else {
        class_index = d->st.literal_mode;
        if (class_index <= 15) {
            *probed = 1;
            hist_byte = d->token_history[*hist_key];
            if ((hist_byte & 0x38) != 0)
                class_index = 32 + (hist_byte >> 3);
        }
        if (class_index > 63)
            class_index = 63;
    }
    return class_index;
}

/* [RE b3a] Enveloppe lecture-seule de token_class_index pour l'estimateur de
 * cout-match alz_match_model_cost (alz_match.c). Ne mute aucun etat : ne lit
 * que repeat_run/literal_mode/token_history via la logique commune. */
int alz_token_class_index_ro(alz_dec *d)
{
    int probed;
    uint16_t hist_key;
    return token_class_index(d, &probed, &hist_key);
}

static void token_class_update(alz_dec *d, int class_index, int result,
                               int probed, uint16_t hist_key)
{
    int i, first;
    uint32_t freq[5];

    /* [A3 TCUP0, GATED `UHA_A3_TCUP0`, DEFAUT-OFF] Loi lue dans le binaire
     * (`0x413318`..`0x4133a6`) : `cmp dl,4 ; jb 0x41338d`, puis la chaine
     * incrementale `C[4]` ; si dl<3 `C[3]` ; si dl<2 `C[2]` ; puis `C[5]`.
     * Donc dl=0 et dl=1 ont la MEME mise a jour (C[2],C[3],C[4],C[5]) :
     * le symbole 0 n'est PAS un cas « sans mise a jour » (C[1] reste fixe = 1).
     * Defaut-OFF = comportement historique (retour anticipe sur 0). */
    first = result + 1;
    if (result == 0)
        return;
    for (i = first; i <= 4; i++)
        d->token_class[class_index][i] =
            (uint16_t)((uint32_t)d->token_class[class_index][i] + 88);
    d->token_class[class_index][5] =
        (uint16_t)((uint32_t)d->token_class[class_index][5] + 88);
    d->st.range_model_epoch++;

    if (d->token_class[class_index][5] >= 16384) {
        freq[1] = d->token_class[class_index][2] - d->token_class[class_index][1];
        freq[2] = d->token_class[class_index][3] - d->token_class[class_index][2];
        freq[3] = d->token_class[class_index][4] - d->token_class[class_index][3];
        freq[4] = d->token_class[class_index][5] - d->token_class[class_index][4];
        for (i = 1; i <= 4; i++)
            freq[i] = (freq[i] + 1) >> 1;
        d->token_class[class_index][2] =
            (uint16_t)((uint32_t)d->token_class[class_index][1] + freq[1]);
        d->token_class[class_index][3] =
            (uint16_t)((uint32_t)d->token_class[class_index][2] + freq[2]);
        d->token_class[class_index][4] =
            (uint16_t)((uint32_t)d->token_class[class_index][3] + freq[3]);
        d->token_class[class_index][5] =
            (uint16_t)((uint32_t)d->token_class[class_index][4] + freq[4]);
    }
    if (probed)
        update_token_history(d, hist_key, result);
    alz_update_literal_mode(d, result);
}

int alz_decode_token_class(alz_dec *d)
{
    int class_index, i, result, probed;
    uint32_t total, threshold, low, high;
    uint16_t hist_key;

    class_index = token_class_index(d, &probed, &hist_key);
    total = d->token_class[class_index][5];
    if (total == 0) {
        d->rc.corrupt = 1;
        return 0;
    }
    threshold = uha_rc_threshold(&d->rc, total);
    result = 4;
    for (i = 4; i >= 0; i--) {
        if (threshold >= d->token_class[class_index][i]) {
            result = i;
            break;
        }
    }
    low = d->token_class[class_index][result];
    high = (result == 4) ? d->token_class[class_index][5]
                         : d->token_class[class_index][result + 1];
    uha_rc_remove(&d->rc, low, high);
    token_class_update(d, class_index, result, probed, hist_key);
    return result;
}

int alz_encode_token_class(alz_dec *d, int result)
{
    int class_index, probed;
    uint32_t total, low, high;
    uint16_t hist_key;

    if (!d->w)
        return -1;
    class_index = token_class_index(d, &probed, &hist_key);
    total = d->token_class[class_index][5];
    if (total == 0)
        return -1;
    if (result < 0 || result > 4)
        return -1;
    low = d->token_class[class_index][result];
    high = (result == 4) ? d->token_class[class_index][5]
                         : d->token_class[class_index][result + 1];
    if (uha_rcw_encode(d->w, low, high, total) != 0)
        return -1;
    token_class_update(d, class_index, result, probed, hist_key);
    return 0;
}

void alz_apply_escape(alz_dec *d, int selector)
{
    int i;

    if (selector < 0)
        selector = 0;
    else if (selector > 10)
        selector = 10;
    if (selector == d->st.escape_selector) {
        d->st.escape_changed = 0;
        return;
    }
    d->st.escape_changed = (selector == 10);
    if (selector == 10) {
        for (i = 0x200; i <= 0x2FF; i++)
            alz_bm_rescale_entry(d, i);
        selector = 0;
    }
    d->st.escape_selector = (uint8_t)selector;
    d->st.side_primary = AlzSelectorPrimaryKind[selector];
    d->st.side_secondary = AlzSelectorSecondaryBase[selector];
    d->st.escape_literal_bias = AlzSelectorLiteralBias[selector];
    d->st.side_dir = 0;
    d->st.side_bias = 0;
    d->st.side_mod_count = 0;

    if (selector >= 5) {
        memset(d->st.mm_hist, 0, sizeof(d->st.mm_hist));
        memset(d->st.mm_coef, 0, sizeof(d->st.mm_coef));
        memset(d->st.mm_last, 0, sizeof(d->st.mm_last));
        memset(d->st.mm_delta, 0, sizeof(d->st.mm_delta));
        memset(d->st.mm_acc, 0, sizeof(d->st.mm_acc));
        memset(d->st.mm_cost5c, 0, sizeof(d->st.mm_cost5c));
        memset(d->st.mm_cost60, 0, sizeof(d->st.mm_cost60));
        memset(d->st.mm_cost64, 0, sizeof(d->st.mm_cost64));
        memset(d->st.mm_cost68, 0, sizeof(d->st.mm_cost68));
        memset(d->st.mm_counter, 0, sizeof(d->st.mm_counter));
        d->st.mm_global = 0;
        d->st.mm_global2 = 0;
        d->st.mm_prev_score = 0;
        memset(d->st.cand_acc, 0, sizeof(d->st.cand_acc));
        memset(d->st.delta_ring, 0, sizeof(d->st.delta_ring));
        memset(d->st.cand_score, 0, sizeof(d->st.cand_score));
        memset(d->st.res_bank, 0, sizeof(d->st.res_bank));
        d->st.cand_cur = 0;
        d->st.cand_prev = 0;
        d->st.cand_best0 = 0;
        d->st.cand_best1 = 0;
        d->st.cand_best2 = 2;
        for (i = 0; i < 16; i++) {
            d->st.slot_dir[i] = 0;
            d->st.slot_hash[i] = (i <= 3) ? 0xFFFFFFFFu : 0;
            if (i <= 2) {
                d->st.slot_hash74[i] = 0xFFFFFFFFu;
                d->st.slot_hash78[i] = 0xFFFFFFFFu;
            } else {
                d->st.slot_hash74[i] = 0;
                d->st.slot_hash78[i] = 0;
            }
        }
    }
    d->st.escape_model_flag = (selector == 5 || selector == 6) ? 1 : 0;
}

void alz_handle_escape(alz_dec *d)
{
    int selector;

    selector = (int)uha_rc_uniform(&d->rc, 11);
    if (d->rc.corrupt)
        return;
    alz_apply_escape(d, selector);
}

int alz_encode_escape(alz_dec *d, int selector)
{
    if (!d->w)
        return -1;
    if (selector < 0)
        selector = 0;
    else if (selector > 10)
        selector = 10;
    if (uha_rcw_encode(d->w, (uint32_t)selector, (uint32_t)selector + 1, 11) != 0)
        return -1;
    alz_apply_escape(d, selector);
    return 0;
}

void alz_reset_match_model(alz_dec *d)
{
    int i;

    for (i = 0; i < 64; i++) {
        d->m_slot_short[i] = ALZ_INIT_PROB;
        d->m_slot_long[i] = ALZ_INIT_PROB;
    }
    d->m_low_bit = ALZ_INIT_PROB;
    for (i = 0; i < 8192; i++)
        d->m_length[i] = ALZ_INIT_PROB;
    memset(d->m_len_pred, 0, sizeof(d->m_len_pred));
}

void alz_reset_models(alz_dec *d)
{
    int i, j;

    for (i = 0; i < 66; i++) {
        const uint16_t *seed = (i < 64) ? AlzTokenSeedNormal : AlzTokenSeedRepeat;
        for (j = 0; j < 6; j++)
            d->token_class[i][j] = seed[j];
    }
    for (i = 0; i < 1036; i++)
        d->literal_adjust[i] = ALZ_INIT_PROB;
    for (i = 0; i < 32768; i++)
        d->length_tree[i] = ALZ_INIT_PROB;
    for (i = 0; i < 3076; i++)
        d->distance_tree[i] = ALZ_INIT_PROB;
    for (i = 0; i < 64; i++)
        d->dist_slot_fast[i] = ALZ_INIT_PROB;
    for (i = 0; i < 128; i++)
        d->dist_slot_normal[i] = ALZ_INIT_PROB;
    for (i = 0; i < 6; i++)
        for (j = 0; j < 64; j++)
            d->length_by_bucket[i][j] = ALZ_INIT_PROB;
    memset(d->token_history, 0, sizeof(d->token_history));
    memset(d->length_history, 0, sizeof(d->length_history));
    d->long_distance_bit = ALZ_INIT_PROB;
    alz_reset_byte_model(d);
    alz_reset_match_model(d);
}

void alz_rebuild_block_model_core(alz_dec *d)
{
    int c, s;
    uint32_t previous, current, acc;

    for (c = 0; c <= 0x300; c++) {
        memset(d->bm_tree[c], 0, sizeof(d->bm_tree[c]));
        memset(d->bm_freq[c], 0, sizeof(d->bm_freq[c]));
        d->bm_ew[c] = 1;
        d->bm_counter[c] = 0x4000;
    }
    for (c = 0; c < 66; c++) {
        previous = d->token_class[c][1];
        acc = previous;
        for (s = 2; s <= 5; s++) {
            current = d->token_class[c][s];
            acc += (current - previous + 1) >> 1;
            d->token_class[c][s] = (uint16_t)acc;
            previous = current;
        }
    }
    for (c = 0x301; c <= 0x3F8; c++)
        alz_bm_rescale_entry(d, c);
    for (c = 0x3F9; c <= 0x40B; c++)
        alz_bm_rescale_ctx2(d, c);
    for (c = 0; c < 256; c++)
        d->bm_table[c] = 0x9240;
    d->bm_pcounter = 255;
    d->bm_acc80 = 0x91ADC0;
    d->bm_acc8c = 0;
    d->bm_acc90 = 0;
}

int g_a3_esc_src = 0;   /* [A3 ESCDBG] 1=rebuild de frontiere, 2=token 0 en bande */

void alz_rebuild_block_model(alz_dec *d)
{
    g_a3_esc_src = 1;
    alz_rebuild_block_model_core(d);
    alz_handle_escape(d);
    g_a3_esc_src = 0;
}
