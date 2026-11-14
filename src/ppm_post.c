#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ppm_priv.h"

/* [M90] tag of route of the learn (defini in ppm_update.c) ; set at the input of each post. */
extern int g_upd_route;


int ppm_ctx_resolution(const ppm_model *m)
{
    int b = m->c48 & 0xFF;
    if (m->byte_class == 0 && m->novel[(m->c48 >> 8) & 0xFF] != 0)
        b += 0x100;
    return b;
}

void ppm_update_head_rank_ptrs(ppm_model *m)
{
    uint32_t k, k0;
    if (m->br18 <= 1) {
        k0 = m->brf0 & 0xFF;
        if (k0 < 2 || k0 > 4)
            return;
    }
    k = m->brf0;
    if (k == 0)
        return;
    m->rank_ptr_small = k;
    m->rank_ptr_large = k;
    if (k <= 4)
        m->rank_ptr_small = (m->rank_small_base[k] + (m->last_ctx % k)) & PPM_M32;
    if (k <= 0x10)
        m->rank_ptr_large = (m->rank_large_base[k] + (m->last_ctx % k)) & PPM_M32;
}

int ppm_window_predictor_gate(const ppm_model *m)
{
    if (m->cls_flag31 != 0)
        return (uint32_t)(m->rec_a[0] * 31) < (uint32_t)(m->rec_a[1] * 32);
    return m->rec_a[0] < m->rec_a[1];
}

int ppm_predbyte_gate(const ppm_model *m)
{
    if (m->byte_class == 0)
        return 0;
    if (m->br18 <= 1)
        return 0;
    if (m->rank_ptr_small > 0x108)
        return 0;
    return m->rank_small[m->rank_ptr_small] != 0;
}

void ppm_literal_decay_c54(ppm_model *m)
{
    m->c54 >>= 3;
}

static void put_window(ppm_model *m, int sym)
{
    uint32_t wp = m->win_pos;
    m->window[wp] = (uint8_t)(sym & 0xFF);
    if (wp < 0x100)
        m->window[wp + m->win_wrap] = (uint8_t)(sym & 0xFF);
}

static void advance_win(ppm_model *m)
{
    m->win_pos = (m->win_pos + 1) & m->win_mask;
}

static void emit_detransformed(ppm_model *m, int sym, uint8_t *outp, int *outlen)
{
    m->out_count = (uint32_t)*outlen;
    ppm_detr_emit(&m->detr, (uint8_t)(sym & 0xFF), (uint32_t)*outlen,
                  m->detr_thr1, m->detr_thr2, outp, outlen);
    m->out_count = (uint32_t)*outlen;
}

static void cls_delta_update(ppm_model *m, int sym)
{
    uint8_t delta;
    extern int ppm_scan_ctx;          /* [M279] 1 = on tourne in there machine of the SCAN of cost */
    if (m->flag3934 == 0)
        return;
    delta = (uint8_t)((uint8_t)sym - m->cls_base);
    if (m->cls_neg != 0)
        delta = (uint8_t)(-(int8_t)delta);
    if (!ppm_scan_ctx && delta >= 0x80)
        m->cls_neg = (uint8_t)(m->cls_neg == 0);
    switch (m->flag3934) {
    case 1:
        m->cls_ctx = 0x209 + ((uint32_t)CLS_T6CC[(m->cls_ctx - 0x209) & 0xF] << 4)
                   + (uint32_t)CLS_T6DC[delta];
        break;
    case 2:
        m->cls_ctx = 0x229 + (m->cls_phase << 4) + (uint32_t)CLS_T6DC[delta];
        break;
    case 3:
        if (m->cls3_active != 0) {
            delta = (uint8_t)(sym - (m->roll_ctx0 >> 16));
            m->cls_neg = m->cls3_saved_neg;
            if (m->cls_neg != 0)
                delta = (uint8_t)(-(int8_t)delta);
            if (delta >= 0x80)
                m->cls_neg = (uint8_t)(m->cls_neg == 0);
        }
        if ((uint8_t)sym == m->cls3_pred[m->cls3_index])
            m->cls3_confidence[m->cls3_index]++;
        else
            m->cls3_confidence[m->cls3_index] >>= 1;
        m->cls_ctx = 0x249 + (m->cls_phase << 5) + (uint32_t)CLS_T7DC[delta];
        break;
    case 7:
    case 8:
    case 9:
        ppm_mm7_update(&m->mm7, m->cls_phase, (uint8_t)sym, delta, m->cls_neg);
        break;
    case 5:
    case 6:
        if (m->flag3934 == 5)
            ppm_mm6_update(&m->mm6, (uint8_t)(sym ^ 0x80), delta, m->last_ctx);
        else
            ppm_mm6_update(&m->mm6, (uint8_t)sym, delta, m->last_ctx);
        break;
    case 4:
        m->cls_ctx = 0x2A9 + (m->cls_phase << 4) + (uint32_t)CLS_T6DC[delta];
        break;
    }
}

static void cls_phase_update(ppm_model *m)
{
    uint32_t old_phase;
    int confident;
    if (m->flag3934 == 0)
        return;
    if (m->flag3934 >= 7) {
        m->cls_phase = m->last_ctx % m->cls_stride;
        ppm_mm7_predict(&m->mm7, m->cls_phase, &m->cls_base, &m->cls_neg, &m->cls_ctx);
        return;
    }
    if (m->flag3934 == 5 || m->flag3934 == 6) {
        ppm_mm6_predict(&m->mm6, m->last_ctx, &m->cls_base, &m->cls_ctx);
        if (m->flag3934 == 5) {
            m->cls_base = (uint8_t)(m->cls_base + 0x80);
            m->cls_ctx -= 4;
        }
        return;
    }
    old_phase = m->cls_phase;
    if (m->cls_stride != 0)
        m->cls_phase = m->last_ctx % m->cls_stride;
    m->cls_base = (uint8_t)(m->roll_ctx0 >> m->cls_shift);
    if (m->flag3934 == 3) {
        m->cls3_index = (uint8_t)(m->last_ctx % 6);
        confident = m->cls3_confidence[m->cls3_index] > 8;
        m->cls3_pred[m->cls3_index] = (uint8_t)((m->roll_ctx0 & 0xFF)
            - (m->roll_ctx0 >> 24) + m->cls_base);
        m->cls3_active = (uint8_t)(confident && (m->cls3_streak < 5));
        if (m->cls3_active != 0) {
            m->cls3_saved_neg = m->cls_neg;
            m->cls_ctx = 0x259 + (old_phase << 5);
            m->cls_neg = 0;
            m->cls_base = m->cls3_pred[m->cls3_index];
        }
        if (confident)
            m->cls3_streak++;
        else
            m->cls3_streak = 0;
    }
}

void ppm_post_symbol_maintenance(ppm_model *m, int sym, int dl)
{
    ppm_ring_store(m, sym);
    if (dl)
        ppm_marker_machine(m, sym);
    ppm_rank_machinery(m, sym);
    cls_delta_update(m, sym);
    m->last_ctx = (m->last_ctx + 1) & PPM_M32;
    m->c54 = (m->c54 + 1) & PPM_M32;
    ppm_update_rolling_ctx(m, sym);
    cls_phase_update(m);
    ppm_ring_recompute(m);
}

/* [M170k] Machine of CONTEXT of the scan of cost (legacy `0x423650` + `0x4232a0`) : ONLY
 * the context (rolling ctx + delta + phase). On n'calls NOT the remainder of
 * `ppm_post_symbol_maintenance` (ring/marker/rank/ring_recompute) : these functions write
 * in `m->w` (stack LZP, allouee has part, therefore OUT of the `*m` that the scan sauve/restores).
 * MEASURES : there version complete corrompait the model (the roundtrip encoder/decodeur of
 * `uha_encode_ppm` echouait and l'archive n'was more produite). */
int ppm_scan_ctx = 0;   /* [M279] 1 = call since there machine of the scan of cost */

void ppm_scan_step(ppm_model *m, int sym)
{
    extern int ppm_scan_ctx;
    ppm_update_rolling_ctx(m, sym);
    ppm_scan_ctx = 1;
    cls_delta_update(m, sym);
    ppm_scan_ctx = 0;
    m->last_ctx = (m->last_ctx + 1) & PPM_M32;
    cls_phase_update(m);
}

/* [M279] Variante distinguant l'byte of output (`raw`, rolling ctx) of the DELTA (`sym`, machine
 * of class). L'ASM `0x4231e2..0x4231ea` pass the TWO : `xor edx,edx / xor eax,eax /
 * mov dl,bl (delta) / mov al,bh (byte of output) / call 0x423650`. The port n'en passait only to 
 * (`raw`) has `cls_delta_update`, this which re-basculait the flag of signe when `raw - cls_base`
 * tombait in [0x80,0xFF] then that the true delta not the franchissait not. Measures M279 :
 * has `it = 88` (`raw = 0`, `sym = 128`, `cls_base = 128`) the delta correct is 0 (no toggles)
 * but `raw - cls_base = 0x80` basculait the flag -> `flag_entrant(89) = 1` au lieu of 0. */
void ppm_scan_step_sym(ppm_model *m, int raw, int sym)
{
    extern int ppm_scan_ctx;
    ppm_update_rolling_ctx(m, raw);
    ppm_scan_ctx = 1;
    cls_delta_update(m, sym);
    ppm_scan_ctx = 0;
    m->last_ctx = (m->last_ctx + 1) & PPM_M32;
    cls_phase_update(m);
}

void ppm_match_maintain(ppm_model *m, int sym, int dl, uint8_t *outp, int *outlen)
{
    emit_detransformed(m, sym, outp, outlen);
    ppm_post_symbol_maintenance(m, sym, dl);
    put_window(m, sym);
    advance_win(m);
}

static void prepare_wp_update(ppm_model *m, int sym)
{
    int delta, saved_excl, saved_work;
    ppm_d390 d;
    if (m->byte_class == 0 || !m->wp_armed)
        return;
    delta = (sym - m->cls_base) & 0xFF;
    if (m->cls_neg != 0)
        delta = (-delta) & 0xFF;
    saved_excl = m->nexcl;
    saved_work = m->work_ctx;
    m->nexcl = 0;
    m->work_ctx = 0x304 + m->flag3934;
    d = ppm_d390_update(m, (int)m->cls_ctx, delta);
    if (d.sse_idx >= 0)
        m->sse_prob[d.sse_idx] = d.sse_val;
    m->wp_acc_add = d.acc_add;
    m->wp_pend = 1;
    m->nexcl = saved_excl;
    m->work_ctx = saved_work;
}

void ppm_emit_and_maintain(ppm_model *m, int sym, uint8_t *outp, int *outlen,
                           int pb_gate, int light, int clear_s47, int decay_c54,
                           int record_s47, int rec2_update, int rec2_before, int run_rec1)
{
    g_upd_route = 1; /* emit_and_maintain */
    int s47;
    put_window(m, sym);
    emit_detransformed(m, sym, outp, outlen);
    if (pb_gate)
        ppm_update_predbyte(m, ppm_ctx_resolution(m), sym);
    if (decay_c54)
        ppm_literal_decay_c54(m);
    if (clear_s47)
        m->s47 = 0;
    s47 = record_s47;
    if (s47 < 0)
        s47 = 0;
    if (rec2_update && rec2_before) {
        if (light)
            ppm_rec2_apply_light(m, sym);
        else
            ppm_rec2_apply_heavy(m, sym);
    }
    if (run_rec1)
        ppm_rec1_apply(m, sym, m->c38, s47);
    if (rec2_update && !rec2_before) {
        if (light)
            ppm_rec2_apply_light(m, sym);
        else
            ppm_rec2_apply_heavy(m, sym);
    }
    m->s45 = 0xFF;
    prepare_wp_update(m, sym);
    ppm_post_symbol_maintenance(m, sym, 1);
    advance_win(m);
}

void ppm_rec2_reweight_post(ppm_model *m, int sym, uint8_t *outp, int *outlen, int pb_gate)
{
    g_upd_route = 2; /* rec2_reweight_post */
    m->s45 = 0xFF;
    m->s41 = 1;
    ppm_rec1_apply(m, sym, m->c38, m->s47);
    ppm_rec2_apply_heavy(m, sym);
    prepare_wp_update(m, sym);
    emit_detransformed(m, sym, outp, outlen);
    if (pb_gate)
        ppm_update_predbyte(m, ppm_ctx_resolution(m), sym);
    if (m->byte_class == 0)
        ppm_literal_decay_c54(m);
    ppm_post_symbol_maintenance(m, sym, 1);
    put_window(m, sym);
    advance_win(m);
}

static void adapt_sse2_down(ppm_model *m, int sse2_idx)
{
    uint32_t v;
    if (sse2_idx < 0)
        return;
    v = m->sse2[sse2_idx];
    m->sse2[sse2_idx] = (v - (v >> 6)) & PPM_M32;
}

static int c550_select_path(const ppm_model *m)
{
    uint32_t idx, age;
    idx = (m->age_ctr + 1) & 0xFF;
    age = (m->age - m->age_ring[idx]) & PPM_M32;
    if (age < 0x6D4250 || age >= 0xFEFF01)
        return 'C';
    if (age < 0x91ADC0)
        return 'B';
    return 'A';
}

static void apply_sse_write(ppm_model *m, const ppm_d390 *d)
{
    if (d->sse_idx >= 0)
        m->sse_prob[d->sse_idx] = d->sse_val;
}

void ppm_c550_post(ppm_model *m, int ctx, int sym, int kctx,
                   uint8_t *outp, int *outlen, int pb_gate, int age_idx,
                   int sse2_idx, uint32_t kernel_weight, int sse2_up_idx,
                   int exact_order_loop, int wp_ctx, int wp_delta, int wp_fired,
                   int wp_base, int wp_work, int wp_mirror, int wp_armed, int nf_dec_ctx)
{
    g_upd_route = 3; /* c550_post */
    int path, wp_i, flag, taken_ctx, taken_sym, taken_wc;
    int shadow_ctx, shadow_sym, shadow_wc, shadow_flag, entry_dec, eb;
    ppm_d390 d_entry, d_order0, d_shadow;
    uint32_t bec_entry, bec_order0, bec_age, v;
    uint8_t old_s49;

    d_entry.acc_add = 0;
    d_entry.sse_idx = -1;
    d_order0.acc_add = 0;
    d_order0.sse_idx = -1;
    bec_entry = 0;
    bec_order0 = 0;

    if (wp_fired) {
        flag = 0;
        taken_ctx = wp_ctx;
        taken_sym = wp_delta;
        taken_wc = wp_work;
        shadow_ctx = ctx;
        if (nf_dec_ctx >= 0)
            shadow_ctx = nf_dec_ctx;
        shadow_sym = sym;
        shadow_wc = 0x301;
        shadow_flag = 1;
    } else {
        flag = 1;
        taken_ctx = ctx;
        taken_sym = sym;
        taken_wc = 0x301;
        shadow_ctx = wp_ctx;
        shadow_sym = wp_delta;
        shadow_wc = wp_work;
        shadow_flag = 0;
    }

    if (!wp_fired && nf_dec_ctx >= 0)
        entry_dec = nf_dec_ctx;
    else
        entry_dec = taken_ctx;

    eb = (m->rec_a[flag] <= m->rec_b[flag]);
    (void)eb;
    (void)kctx;

    if (sse2_up_idx >= 0) {
        v = m->sse2[sse2_up_idx];
        m->sse2[sse2_up_idx] = (v + ((0x2000 - v) >> 6)) & PPM_M32;
    }

    path = c550_select_path(m);

    if (m->flag3943 != 0) {
        if (path == 'A')
            m->wp_kernel_weight += 0x9240;
        else
            m->wp_kernel_weight += kernel_weight;
    }

    if (path == 'A') {
        m->work_ctx = taken_wc;
        d_entry = ppm_d390_update(m, entry_dec, taken_sym);
        apply_sse_write(m, &d_entry);
        m->bec = d_entry.acc_add;
        ppm_recency_update(m->rec_b, flag, d_entry.acc_add);
        ppm_recency_update(m->rec_a, flag, d_entry.acc_add);
        bec_age = d_entry.acc_add;
    } else if (path == 'C') {
        m->work_ctx = taken_wc;
        d_entry = ppm_d390_update(m, entry_dec, taken_sym);
        adapt_sse2_down(m, sse2_idx);
        m->bec = d_entry.acc_add;
        apply_sse_write(m, &d_entry);
        m->bec = kernel_weight;
        ppm_recency_update(m->rec_b, flag, kernel_weight);
        ppm_recency_update(m->rec_a, flag, kernel_weight);
        bec_age = kernel_weight;
    } else if (kctx == taken_ctx) {
        m->work_ctx = taken_wc;
        d_entry = ppm_d390_update(m, entry_dec, taken_sym);
        adapt_sse2_down(m, sse2_idx);
        m->work_ctx = 0x302 + flag;
        d_order0 = ppm_d390_update(m, 0x200, taken_sym);
        bec_entry = kernel_weight;
        bec_order0 = d_order0.acc_add;
    } else {
        m->work_ctx = 0x302 + flag;
        d_order0 = ppm_d390_update(m, 0x200, taken_sym);
        adapt_sse2_down(m, sse2_idx);
        m->work_ctx = taken_wc;
        d_entry = ppm_d390_update(m, entry_dec, taken_sym);
        if (m->rec_a[flag] <= m->rec_b[flag]) {
            bec_entry = kernel_weight;
            bec_order0 = d_order0.acc_add;
        } else {
            bec_entry = d_entry.acc_add;
            bec_order0 = kernel_weight;
        }
    }

    if (exact_order_loop)
        m->s45 = 2;

    if (path != 'C' && path != 'A') {
        if (kctx == taken_ctx) {
            m->bec = d_order0.acc_add;
            apply_sse_write(m, &d_order0);
            apply_sse_write(m, &d_entry);
        } else {
            m->bec = d_entry.acc_add;
            apply_sse_write(m, &d_entry);
            apply_sse_write(m, &d_order0);
        }
        if (exact_order_loop && kctx == taken_ctx)
            m->bec = kernel_weight;
        ppm_recency_update(m->rec_a, flag, bec_entry);
        ppm_recency_update(m->rec_b, flag, bec_order0);
        bec_age = kernel_weight;
    }

    ppm_agering_commit(m, age_idx, bec_age);

    if (wp_fired) {
        for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
            if (wp_mirror)
                m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
            else
                m->excl[wp_i] = (uint8_t)((m->excl[wp_i] + wp_base) & 0xFF);
        }
    }

    if (m->byte_class != 0) {
        if (!wp_fired) {
            for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
                if (wp_mirror)
                    m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
                else
                    m->excl[wp_i] = (uint8_t)((m->excl[wp_i] - wp_base) & 0xFF);
            }
        }
        m->work_ctx = shadow_wc;
        d_shadow = ppm_d390_update(m, shadow_ctx, shadow_sym);
        apply_sse_write(m, &d_shadow);
        prepare_wp_update(m, sym);
        m->wp_pend = wp_armed;
        ppm_recency_update(m->rec_a, shadow_flag, d_shadow.acc_add);
        ppm_recency_update(m->rec_b, shadow_flag, d_shadow.acc_add);
        m->work_ctx = shadow_wc;
        ppm_apply_t268(m, shadow_sym, shadow_ctx);
        if (!wp_fired) {
            for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
                if (wp_mirror)
                    m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
                else
                    m->excl[wp_i] = (uint8_t)((m->excl[wp_i] + wp_base) & 0xFF);
            }
        }
    }

    ppm_rec1_apply(m, sym, m->c38, m->s47);

    if ((m->byte_class == 0 && !exact_order_loop) || m->s41 != 0) {
        old_s49 = m->s49;
        ppm_rec2_apply_heavy(m, sym);
        if (old_s49 == 0)
            m->s49 = old_s49;
    }

    if (path == 'C' || path == 'A') {
        m->work_ctx = taken_wc;
        ppm_apply_t268(m, taken_sym, entry_dec);
    } else
        ppm_apply_literal_updates(m, entry_dec, taken_wc, taken_sym);
    if (exact_order_loop)
        m->s45 = 0xFF;

    put_window(m, sym);
    emit_detransformed(m, sym, outp, outlen);
    if (pb_gate)
        ppm_update_predbyte(m, ctx, sym);
    ppm_post_symbol_maintenance(m, sym, 1);
    advance_win(m);
}
