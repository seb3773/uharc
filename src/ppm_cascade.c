#include "ppm_priv.h"

int g_c48_site, g_c40_site;   /* [M207] site of the last ecrivain of c48/c40 (diagnostic) */
#include <stdio.h>
#include <stdlib.h>

static uint32_t ring_rec1_weight;
static uint8_t ring_rec1_pred;
static int ring_eligible;
static int ring_tried;
static int ring_wanted_flag;
static int ring_recheck_chain;
static uint32_t pre_rank_before;
static uint32_t pre_rank_after;
static int early_rec_done;
static uint32_t early_rec_idx;
static int early_rec_pred;

static int excluded(const ppm_model *m, uint8_t symb)
{
    return ppm_in_excl(m->excl, m->nexcl, symb);
}

static uint32_t record_total(const ppm_model *m, uint32_t rec_idx)
{
    uint32_t result = m->rec1s[rec_idx][0];
    int k = 0;
    while (k < 0xC && m->rec1s[rec_idx][1 + k] != 0) {
        result = (result + m->rec1s[rec_idx][1 + k]) & PPM_M32;
        k++;
    }
    return result;
}

static uint8_t rec0_at(const ppm_model *m, uint32_t rec_idx)
{
    if (rec_idx >= PPM_REC1_COUNT)
        return 0;
    return m->rec1s[rec_idx][0];
}

static int tag_matches(const ppm_model *m, uint32_t rec_idx, uint32_t c48)
{
    uint32_t tag;
    if (rec_idx >= PPM_REC1_COUNT)
        return 0;
    tag = (uint32_t)m->rec1s[rec_idx][0x1C]
        | ((uint32_t)m->rec1s[rec_idx][0x1D] << 8)
        | ((uint32_t)m->rec1s[rec_idx][0x1E] << 16)
        | ((uint32_t)m->rec1s[rec_idx][0x1F] << 24);
    return tag == c48;
}

static int select_predicted_record(ppm_model *m, uint32_t *rec_idx)
{
    uint32_t c48 = m->c48;
    uint32_t c38 = m->c38;
    if (rec0_at(m, *rec_idx) == 0) {
        if (c38 < 0x40000)
            m->c38 = (c38 + 0x40000) & PPM_M32;
        return 0;
    }
    while (rec0_at(m, *rec_idx) != 0 && !tag_matches(m, *rec_idx, c48)) {
        c38 = (c38 + 0x8000) & PPM_M32;
        *rec_idx += 0x8000;
        m->c38 = c38;
        if (c38 >= 0x40000)
            break;
    }
    if (rec0_at(m, *rec_idx) == 0 && m->c38 < 0x40000)
        m->c38 = (m->c38 + 0x40000) & PPM_M32;
    return rec0_at(m, *rec_idx) != 0 && tag_matches(m, *rec_idx, c48);
}

static int predicted_inline_gate(const ppm_model *m, uint32_t rec_idx)
{
    uint32_t high, scale;
    if (m->c44 != 0)
        return 1;
    if (m->br18 <= 1)
        return 1;
    if (m->a8g > m->dcg)
        return 1;
    if (m->rank_small[m->rank_ptr_small] <= 0x3FE)
        return 1;
    high = m->rec1s[rec_idx][0x1A] >> 4;
    scale = (uint32_t)m->rec1s[rec_idx][0x1B] << 6;
    return (high * scale) >= m->rank_large[m->rank_ptr_large];
}

static int predicted_late_gate(const ppm_model *m, uint32_t rec_idx, uint32_t rec2_idx)
{
    int ratio1;
    uint32_t left, right, r13;
    ratio1 = (m->byte_class != 0) || (m->rec2s[rec2_idx][0x13] >= 0x30);
    if (ratio1 && ((m->rec1s[rec_idx][0x19] & 0x38) == 0)) {
        left = (m->rec1s[rec_idx][0x19] & 0x04) + m->rec1s[rec_idx][1]
             + (m->rec1s[rec_idx][0x1A] >> 4);
        left *= m->rec2s[rec2_idx][0x12];
        right = m->rec2s[rec2_idx][1] + (m->rec2s[rec2_idx][0x13] >> 4);
        right *= m->c1c;
        if (left < right)
            return 0;
    }
    r13 = m->rec2s[rec2_idx][0x13];
    if (r13 >= 0x60 && ((r13 >> 2) > m->rec1s[rec_idx][0x1A]))
        return 0;
    return 1;
}

static int predicted_frequency_gate(ppm_model *m, uint32_t rec_idx)
{
    uint32_t total = m->c1c;
    uint8_t excl;
    int idx;
    if (m->nexcl != 0) {
        excl = m->excl[0];
        for (idx = 0; idx <= 0xB; idx++) {
            if (m->rec1s[rec_idx][idx + 0x0D] == excl) {
                total = (total - m->rec1s[rec_idx][idx + 1]) & PPM_M32;
                break;
            }
            if (m->rec1s[rec_idx][idx + 2] == 0)
                break;
        }
    }
    m->c3c = total;
    return m->rec1s[rec_idx][0] < total;
}

static int rec2_selector_from_predbyte(const ppm_model *m, uint32_t rec2_idx)
{
    int ctx, slot;
    uint8_t pred;
    ctx = m->c48 & 0xFF;
    if (m->byte_class == 0 && m->novel[(m->c48 >> 8) & 0xFF] != 0)
        ctx += 0x100;
    pred = m->pred_byte[ctx];
    for (slot = 0; slot <= 7; slot++) {
        if (m->rec2s[rec2_idx][9 + slot] == pred)
            return slot;
        if (slot >= 7 || m->rec2s[rec2_idx][2 + slot] == 0)
            break;
    }
    return 8;
}

static void literal_excl_reset(ppm_model *m)
{
    m->nexcl = 0;
}

static void literal_cont_excl(ppm_model *m)
{
    if (m->has_cont) {
        m->excl[0] = m->window[m->cont_ofs];
        m->nexcl = 1;
        m->has_cont = 0;
        m->cont_ofs = 0;
    }
}

static uint32_t literal_context(const ppm_model *m)
{
    if (m->marker_fl == 2)
        return ((m->roll_ctx0 >> 8) & 0xFF)
             | ((m->roll_ctx0 >> 16) & 0xFF00)
             | ((m->roll_ctx1 << 8) & 0xFF0000)
             | (m->roll_ctx1 & 0xFF000000);
    return m->roll_ctx0;
}

static void literal_setup(ppm_model *m, int *ctx, int *pb_gate, uint32_t *rec_idx)
{
    uint32_t c48, rec2idx;
    c48 = literal_context(m);
    m->c48 = c48;
    g_c48_site = 1;
    m->c38 = (c48 ^ (c48 >> 0x0D)) & 0x7FFF;
    *ctx = ppm_ctx_resolution(m);
    if (m->byte_class == 0) {
        m->s3e = 0;
        m->s41 = 0;
        literal_excl_reset(m);
        m->flag393c = 0;
        literal_cont_excl(m);
        ppm_update_head_rank_ptrs(m);
        ppm_lastsym_predict(m);
    }
    m->s45 = 0;
    m->flag3938 = 0;
    m->flag393b = 0;
    m->flag3943 = 0;
    m->s48 = 0;
    m->bfc = 0;
    rec2idx = c48 & 0xFFFF;
    if (m->byte_class == 0 && m->novel[(c48 >> 16) & 0xFF] != 0)
        rec2idx += 0x10000;
    m->c40 = rec2idx;
    g_c40_site = 1;
    if (early_rec_done)
        *rec_idx = early_rec_idx;
    else
        *rec_idx = m->c38 & 0x7FFF;
    *pb_gate = ppm_predbyte_gate(m);
}

static int wp_class_sel(const ppm_model *m)
{
    if (m->byte_class != 0)
        return m->wp_class_selected;
    return (m->flag3934 != 0)
        && ((m->br18 <= 4) || (m->rank_small[m->rank_ptr_small] <= 0x3FE));
}

static int ring_attempt(ppm_model *m, uha_rc *r, uint8_t *outp, int *outlen,
                        int *route, int *sym, int from_gate_fail)
{
    uint32_t rec2i, ctxb, m0, m1;
    uint8_t r2_13;
    uint32_t w[3];
    uint8_t y[3];

    (void)from_gate_fail;
    if (ring_tried || m->byte_class == 0)
        return 0;
    ppm_bc1_post_armed = 1;
    if (!ring_eligible) {
        ring_tried = 1;
        return 0;
    }
    ring_tried = 1;
    m->c44 >>= 2;
    if (excluded(m, ppm_bc1_st.best_pred)) {
        if ((ppm_bc1_st.best_c0 > 3) || ((ppm_bc1_st.best_c1 >> 6) > ppm_bc1_st.best_c0))
            ppm_bc1_post_armed = 0;
        return 0;
    }
    ppm_bc1_ring_ran = (m->byte_class != 0) && ppm_window_predictor_gate(m) && wp_class_sel(m);
    if (ppm_bc1_ring_ran && (m->wp_a < m->wp_b))
        return 0;

    rec2i = m->c40;
    ctxb = m->c48 & 0xFF;
    w[0] = ring_rec1_weight;
    y[0] = ring_rec1_pred;
    r2_13 = m->rec2s[rec2i][0x13];
    w[1] = BC1_WT0B0[(r2_13 >> 4) & 0xF];
    y[1] = m->rec2s[rec2i][9 + (r2_13 & 0xF)];
    w[2] = BC1_WT070[ppm_bc1_st.conf[ctxb] & 0xF];
    y[2] = ppm_bc1_st.pred[ctxb];
    ppm_bc1_ring_masses(w, y, &m0, &m1);

    if (ppm_bc1_ring_decode(r, m0, m1)) {
        if (m->flag393c != 0) {
            m->rank_small[m->rank_ptr_small] = (m->rank_small[m->rank_ptr_small] + m->c58) & PPM_M32;
            m->rank_large[m->rank_ptr_large] = (m->rank_large[m->rank_ptr_large] + m->c58) & PPM_M32;
            m->c58 *= 2;
            if (m->c58 > 0xFFFF)
                m->c58 = 0xFFFF;
        }
        *sym = ppm_bc1_st.best_pred;
        m->c40 = rec2i;
        m->nexcl = 0;
        m->s45 = 0;
        m->flag3943 = 0;
        ppm_emit_and_maintain(m, *sym, outp, outlen, 1, 0, 0, 0, m->s47, m->s41 != 0, 0, 1);
        *route = CR_ENTRY_HIT;
        return 1;
    }
    if (m->flag393c != 0) {
        m->rank_small[m->rank_ptr_small] >>= 1;
        m->rank_large[m->rank_ptr_large] >>= 1;
        m->c58 = ((m->c58 >> 1) + 0xFF) & PPM_M32;
    }
    if (m->nexcl < PPM_MAX_EXCL)
        ppm_append_excl(m, ppm_bc1_st.best_pred);
    return 2;
}

/* t12g - mirror encoder strict of ring_attempt : same gardes, same masses,
 * interval binary code according to (target == best_pred), same updates
 * d'state in the same order. Return : 1 hit (emit does), 2 miss (excl adds),
 * 0 no tente, -1 error RC. */
static int ring_attempt_encode(ppm_model *m, uint8_t *outp, int *outlen,
                               int *route, int *sym, int target)
{
    uint32_t rec2i, ctxb, m0, m1;
    uint8_t r2_13;
    uint32_t w[3];
    uint8_t y[3];
    int hit, rc;

    if (ring_tried || m->byte_class == 0)
        return 0;
    ppm_bc1_post_armed = 1;
    if (!ring_eligible) {
        ring_tried = 1;
        return 0;
    }
    ring_tried = 1;
    m->c44 >>= 2;
    if (excluded(m, ppm_bc1_st.best_pred)) {
        if ((ppm_bc1_st.best_c0 > 3) || ((ppm_bc1_st.best_c1 >> 6) > ppm_bc1_st.best_c0))
            ppm_bc1_post_armed = 0;
        return 0;
    }
    ppm_bc1_ring_ran = (m->byte_class != 0) && ppm_window_predictor_gate(m) && wp_class_sel(m);
    if (ppm_bc1_ring_ran && (m->wp_a < m->wp_b))
        return 0;

    rec2i = m->c40;
    ctxb = m->c48 & 0xFF;
    w[0] = ring_rec1_weight;
    y[0] = ring_rec1_pred;
    r2_13 = m->rec2s[rec2i][0x13];
    w[1] = BC1_WT0B0[(r2_13 >> 4) & 0xF];
    y[1] = m->rec2s[rec2i][9 + (r2_13 & 0xF)];
    w[2] = BC1_WT070[ppm_bc1_st.conf[ctxb] & 0xF];
    y[2] = ppm_bc1_st.pred[ctxb];
    ppm_bc1_ring_masses(w, y, &m0, &m1);

    hit = (target == (int)ppm_bc1_st.best_pred);
    if (m0 + m1 == 0)
        rc = 0;
    else
        rc = ppm_bc1_ring_encode(m, m0, m1, hit);
    if (rc < 0)
        return -1;
    if (rc == 1) {
        if (m->flag393c != 0) {
            m->rank_small[m->rank_ptr_small] = (m->rank_small[m->rank_ptr_small] + m->c58) & PPM_M32;
            m->rank_large[m->rank_ptr_large] = (m->rank_large[m->rank_ptr_large] + m->c58) & PPM_M32;
            m->c58 *= 2;
            if (m->c58 > 0xFFFF)
                m->c58 = 0xFFFF;
        }
        *sym = ppm_bc1_st.best_pred;
        m->c40 = rec2i;
        m->nexcl = 0;
        m->s45 = 0;
        m->flag3943 = 0;
        ppm_emit_and_maintain(m, *sym, outp, outlen, 1, 0, 0, 0, m->s47, m->s41 != 0, 0, 1);
        *route = CR_ENTRY_HIT;
        return 1;
    }
    if (rc == 0 && m0 + m1 != 0) {
        if (m->flag393c != 0) {
            m->rank_small[m->rank_ptr_small] >>= 1;
            m->rank_large[m->rank_ptr_large] >>= 1;
            m->c58 = ((m->c58 >> 1) + 0xFF) & PPM_M32;
        }
        if (m->nexcl < PPM_MAX_EXCL)
            ppm_append_excl(m, ppm_bc1_st.best_pred);
        return 2;
    }
    /* total==0 : no cost RC side decodeur, rendu = miss without update */
    if (m->nexcl < PPM_MAX_EXCL)
        ppm_append_excl(m, ppm_bc1_st.best_pred);
    return 2;
}

static int decode_literal_cascade_core(ppm_model *m, uha_rc *r, uint8_t *outp, int *outlen,
                                       int *route, int *sym, int bc1_no_ring, int pre_excl);

/* [M241, GATED UHA_M241RING, default-OFF] PROBE D'STATE PARTAGE encoder/DECODEUR.
 * But : there 1re divergence of the run BLKSCANCLS is the 3e literal after the reset of member
 * 505 696 (enc sym=188, dec sym=189) then that the empreintes [FP]/[FP2] are identical
 * au reset. The model `m` etant resynchronise, l'gap not peut venir that of has state
 * SINGLETON partage out model : the model bc1 (`ppm_bc1_st`, ppm_bc1.c) and the flags
 * global of cascade. This probe imprime these fields at the INPUT of each cascade of
 * literal, some two sides (tag E/D), in there window `UHA_M241RING=lo:hi` (win_pos).
 * No writing : read-only, no effect on the stream. */
static void m241_ring_dump(const char *tag, ppm_model *m)
{
    static int on = -1;
    static uint32_t lo = 0, hi = 0;
    if (on < 0) {
        const char *e = getenv("UHA_M241RING");
        on = 0;
        if (e && e[0] && e[0] != '0') {
            unsigned long a = 0, b = 0;
            if (sscanf(e, "%lu:%lu", &a, &b) == 2) { lo = (uint32_t)a; hi = (uint32_t)b; on = 1; }
            else { lo = 0; hi = 0xFFFFFFFFu; on = 1; }
        }
    }
    if (!on || !m)
        return;
    if (m->win_pos < lo || m->win_pos > hi)
        return;
    fprintf(stderr,
            "[M241RING %s] wp=%u cls=%u c48=%08x c40=%u s41=%u nexcl=%u br18=%u rk=%u"
            " rp=%d ring=%u,%u,%u,%u best_pred=%u bc0=%u bc1=%u bf=%u conf=%u pred=%u wpos=%u"
            " best=%d last_best=%d rran=%d\n",
            tag, (unsigned)m->win_pos, (unsigned)m->flag3934, (unsigned)m->c48,
            (unsigned)m->c40, (unsigned)m->s41, (unsigned)m->nexcl, (unsigned)m->br18,
            (unsigned)m->rank_small[m->rank_ptr_small],
            (int)ppm_bc1_st.ring_ptr,
            (unsigned)ppm_bc1_st.ring[0], (unsigned)ppm_bc1_st.ring[1],
            (unsigned)ppm_bc1_st.ring[2], (unsigned)ppm_bc1_st.ring[3],
            (unsigned)ppm_bc1_st.best_pred, (unsigned)ppm_bc1_st.best_c0,
            (unsigned)ppm_bc1_st.best_c1, (unsigned)ppm_bc1_st.best_flags,
            (unsigned)ppm_bc1_st.conf[m->c48 & 0xFF], (unsigned)ppm_bc1_st.pred[m->c48 & 0xFF],
            (unsigned)ppm_bc1_st.wpos, (int)ppm_bc1_st.best, (int)ppm_bc1_st.last_best,
            ppm_bc1_ring_ran);
}

int ppm_decode_literal_cascade(ppm_model *m, uha_rc *r, uint8_t *outp, int *outlen,
                               int *route, int *sym)
{
    uint32_t r0, r1, rec2i, ctxb;
    int ring_ptr_set, ring_wanted, chain_al, ring_stat;

    m241_ring_dump("D", m);
    if (m->byte_class == 0)
        return decode_literal_cascade_core(m, r, outp, outlen, route, sym, 0, -1);

    literal_excl_reset(m);
    literal_cont_excl(m);
    m->s3e = 0;
    m->s41 = 0;
    m->flag393c = 0;
    m->c48 = literal_context(m);
    g_c48_site = 2; g_c40_site = 2;
    m->c38 = (m->c48 ^ (m->c48 >> 0x0D)) & 0x7FFF;
    /* [GATED UHA_C40ONE, defautOFF, M207] formule UNIQUE of legacy (0x41a2a1) :
     *   c40 = (c48 & 0xFFFF) + ((bc==0 && novel[(c48>>16)&0xFF]) ? 0x10000 : 0)
     * The two sites " nus " (here and more low) ecrasaient c40 without the +0x10000, this which the rendait
     * false of has literal (measured : 117 446 au lieu of 120 272 at the input of the block 2). */
    { static int c1g = -1;
      if (c1g < 0) { const char *e = getenv("UHA_C40ONE"); c1g = (e && e[0] != '0') ? 1 : 0; }
      if (c1g) {
          uint32_t d = m->c48 & 0xFFFFu;
          if (m->byte_class == 0 && m->novel[(m->c48 >> 16) & 0xFF] != 0)
              d += 0x10000u;
          m->c40 = d;
      } else
          m->c40 = m->c48 & 0xFFFF; }
    ppm_update_head_rank_ptrs(m);
    ppm_lastsym_predict(m);

    m->wp_class_selected = (m->flag3934 != 0)
        && ((m->br18 <= 4) || (m->rank_small[m->rank_ptr_small] <= 0x3FE));
    m->wp_armed = m->wp_class_selected && ppm_window_predictor_gate(m);
    m->wp_engaged = m->wp_armed && (m->wp_a < m->wp_b);
    m->wp_kernel_weight = 0;

    ring_rec1_weight = 0;
    ring_rec1_pred = 0;
    early_rec_idx = m->c38 & 0x7FFF;
    early_rec_pred = 0;
    early_rec_done = 0;

    r0 = m->roll_ctx0;
    r1 = m->roll_ctx1;
    ctxb = m->c48 & 0xFF;
    rec2i = m->c48 & 0xFFFF;
    pre_rank_before = m->rank_small[m->rank_ptr_small];
    ring_ptr_set = ppm_bc1_predecode(m, r0, r1);
    pre_rank_after = m->rank_small[m->rank_ptr_small];
    m->flag393c = (uint8_t)ppm_bc1_st.fired393c;

    if (m->rec2s[rec2i][0x13] < 0x90) {
        if (ppm_bc1_st.ring_flag == 0)
            m->s41 = 0;
        else
            m->s41 = 1;
    } else
        m->s41 = 1;

    ring_wanted = m->s41 == 0;
    ring_recheck_chain = ring_wanted;
    if (!ring_wanted) {
        if (m->c50 == 0 || m->rec2s[rec2i][0x11] == 0)
            chain_al = 1;
        else if (m->c58 < 0xFFFF)
            chain_al = (m->rank_small[m->rank_ptr_small] > 0x3FE) ? 0 : 1;
        else
            chain_al = 0;
        m->s41 = (uint8_t)chain_al;
        ring_wanted = chain_al == 0;
    }
    if (!ring_wanted)
        ring_wanted = m->rec2s[rec2i][0] == 0;

    ring_eligible = ring_ptr_set;
    ring_tried = 0;
    ppm_bc1_ring_ran = 0;
    ppm_bc1_post_armed = 0;
    ring_wanted_flag = ring_wanted;
    ring_stat = 0;

    if (ring_stat == 2) {
        if (!decode_literal_cascade_core(m, r, outp, outlen, route, sym, 1, (int)ppm_bc1_st.best_pred))
            return 0;
    } else {
        if (!decode_literal_cascade_core(m, r, outp, outlen, route, sym, 0, -1))
            return 0;
    }

    if (ppm_bc1_post_armed)
        ppm_bc1_post_update(m, (uint8_t)*sym);

    if (m->wp_pend) {
        if (m->flag3943 != 0)
            m->bfc += m->wp_kernel_weight;
        m->wp_a = ((m->wp_a * 31) >> 5) + m->wp_acc_add;
        m->wp_b = ((m->wp_b * 31) >> 5) + m->bfc;
        m->wp_pend = 0;
    }
    ppm_bc1_sub2_update((uint8_t)ctxb, (uint8_t)*sym);
    ppm_bc1_push_window((uint8_t)*sym);
    return 1;
}

static int decode_literal_cascade_core(ppm_model *m, uha_rc *r, uint8_t *outp, int *outlen,
                                       int *route, int *sym, int bc1_no_ring, int pre_excl)
{
    int ctx, pb_gate, predicted, found, hit, entry_excluded, rec2_gate;
    uint32_t rec_idx, rec2_total, total, pe, age_idx;
    int rsym, psym, s47, sel, slot, rec2_update_flag, ring_stat;
    int skip_rec2, ring_e123, rec2_gate_failed, entry_sym;
    int c550_ctx, wp_ctx_val, wp_delta_val, wp_base, wp_i, wp_work;
    int wp_mirror, wp_fired, wp_ok;
    uint8_t rec2_copy[20], rec2_flags[8];
    int rec2_active;
    ppm_c550 res;

    *sym = -1;
    rec2_gate_failed = 0;
    skip_rec2 = 0;

    if (m->byte_class != 0 && !bc1_no_ring)
        m->rank_small[m->rank_ptr_small] = pre_rank_before;
    literal_setup(m, &ctx, &pb_gate, &rec_idx);

    if (pre_excl >= 0) {
        m->excl[0] = (uint8_t)pre_excl;
        m->nexcl = 1;
    }
    if (bc1_no_ring)
        select_predicted_record(m, &rec_idx);

    if (!bc1_no_ring) {
        if (early_rec_done) {
            early_rec_done = 0;
            predicted = early_rec_pred && (m->byte_class == 0 || 1);
        } else
            predicted = select_predicted_record(m, &rec_idx);

        if (predicted) {
            ring_rec1_weight = BC1_WT0F0[m->rec1s[rec_idx][0x1A] >> 4];
            ring_rec1_pred = m->rec1s[rec_idx][0x0D + (m->rec1s[rec_idx][0x1A] & 0xF)];
            m->s47 = 0xFF;
            m->c1c = record_total(m, rec_idx);
            if (!predicted_inline_gate(m, rec_idx))
                predicted = 0;
            else if (!predicted_late_gate(m, rec_idx, m->c40))
                predicted = 0;
            else {
                m->c54 = (m->c54 + 1) & PPM_M32;
                if (!predicted_frequency_gate(m, rec_idx))
                    predicted = 0;
                else
                    m->flag3938 = 1;
            }
        }
        if (predicted && m->byte_class != 0) {
            m->flag393b = (uint8_t)m->wp_armed;
            predicted = !m->wp_engaged;
        }
        if (predicted && m->rec1s[rec_idx][2] != 0) {
            found = ppm_rw1_decode(m, r, rec_idx, m->c40, ctx, &rsym);
            if (found) {
                s47 = m->s47;
                rec2_update_flag = (s47 < 0x0C) && (m->rec1s[rec_idx][s47 + 1] < 7);
                ppm_emit_and_maintain(m, rsym, outp, outlen, 1, 1, 0, 0, s47, rec2_update_flag, 1, 1);
                ppm_bc1_post_armed = 0;
                *route = CR_ORDER1_HIT;
                *sym = rsym;
                return 1;
            }
            m->s47 = 0x0C;
            if (m->byte_class == 0)
                m->s41 = 1;
            m->s49 = 0xFF;
            predicted = 0;
        }
        if (predicted) {
            hit = ppm_predicted_decode(m, r, rec_idx, &psym);
            if (hit) {
                ppm_emit_and_maintain(m, psym, outp, outlen, 1, 1, 1, 0, 0,
                                      m->rec1s[rec_idx][1] < 7, 1, 1);
                ppm_bc1_post_armed = 0;
                *route = CR_PREDICTED_HIT;
                *sym = psym;
                return 1;
            }
            m->c1c = record_total(m, rec_idx);
            m->s47 = 0x0C;
            m->s49 = 0xFF;
            ppm_append_excl(m, m->rec1s[rec_idx][0x0D]);
            m->c4c = m->rec2s[m->c40][0];
        }

        if (m->byte_class != 0 && !bc1_no_ring) {
            m->rank_small[m->rank_ptr_small] = pre_rank_after;
            pb_gate = ppm_predbyte_gate(m);
        }
        if (m->byte_class != 0 && !bc1_no_ring)
            ppm_literal_decay_c54(m);
        if (m->byte_class != 0 && !bc1_no_ring && ppm_bc1_rec_ok)
            m->c44 += 2;
        ring_e123 = 0;
        ring_stat = 0;
        if (ring_wanted_flag && !bc1_no_ring && m->byte_class != 0) {
            ring_e123 = 1;
            ring_stat = ring_attempt(m, r, outp, outlen, route, sym, 0);
            if (ring_stat == 1)
                return 1;
        }
        skip_rec2 = ring_e123 && (ring_stat == 0) && !ring_eligible;
        if (ring_e123 && ring_eligible && !ring_recheck_chain)
            skip_rec2 = 1;
        if (ring_e123 && ring_eligible && ring_recheck_chain) {
            if (m->c50 == 0 || m->rec2s[m->c40][0x11] == 0)
                m->s41 = 1;
            else
                m->s41 = (uint8_t)((m->c58 < 0xFFFF)
                    && (m->rank_small[m->rank_ptr_small] <= 0x3FE));
            skip_rec2 = (m->s41 == 0) || (m->rec2s[m->c40][0] == 0);
        }

        if (!skip_rec2) {
            if (m->rec2s[m->c40][0] != 0) {
                entry_excluded = 0;
                if (m->rec2s[m->c40][2] == 0)
                    entry_excluded = excluded(m, m->rec2s[m->c40][9]);
                ppm_rec2_total_flags(m, m->c40, rec2_copy, &rec2_active, rec2_flags, &rec2_total);
                m->c4c = rec2_total;
                m->s49 = 0xFF;
                rec2_gate = ((rec2_total << 2) > ((uint32_t)rec2_copy[0] * 5))
                         && ((((uint32_t)rec2_copy[0x11] << 2) + m->c50) < 0x10);
                if (rec2_gate && m->byte_class != 0) {
                    m->s3e = (uint8_t)m->wp_armed;
                    rec2_gate = !m->wp_engaged;
                }
                rec2_gate_failed = !rec2_gate;

                if (m->rec2s[m->c40][2] != 0) {
                    if (rec2_gate) {
                        sel = rec2_selector_from_predbyte(m, m->c40);
                        found = ppm_rw2_decode(m, r, m->c40, sel, &rsym);
                        if (found) {
                            slot = m->s49;
                            total = m->c4c;
                            if (slot < 8 && (((uint32_t)m->rec2s[m->c40][slot + 1] << 2) >= total)) {
                                if (total > 0x10)
                                    m->s48 = 2;
                                else
                                    m->s48 = 1;
                            }
                            ppm_rec2_reweight_post(m, rsym, outp, outlen, 1);
                            if (!ring_tried)
                                ppm_bc1_post_armed = 0;
                            *route = CR_REC2_HIT;
                            *sym = rsym;
                            return 1;
                        }
                        if (m->byte_class != 0) {
                            slot = 0;
                            while (slot < 8 && m->rec2s[m->c40][slot + 1] != 0) {
                                if (m->nexcl < PPM_MAX_EXCL && !excluded(m, m->rec2s[m->c40][9 + slot]))
                                    ppm_append_excl(m, m->rec2s[m->c40][9 + slot]);
                                slot++;
                            }
                        }
                        m->s41 = 1;
                        if (!bc1_no_ring)
                            if (ring_attempt(m, r, outp, outlen, route, sym, 1) == 1)
                                return 1;
                    }
                } else if (!entry_excluded) {
                    if (rec2_gate) {
                        hit = ppm_entry_decode(m, r, m->c40, &pe);
                        if (hit) {
                            m->s48 = 1;
                            m->s49 = 0;
                            m->s41 = 1;
                            entry_sym = m->rec2s[m->c40][9];
                            ppm_emit_and_maintain(m, entry_sym, outp, outlen, 1, 0, 0,
                                                  m->byte_class == 0, m->s47, 1, 0, 1);
                            if (!ring_tried)
                                ppm_bc1_post_armed = 0;
                            *route = CR_ENTRY_HIT;
                            *sym = entry_sym;
                            return 1;
                        }
                        ppm_append_excl(m, m->rec2s[m->c40][9]);
                        m->s49 = 8;
                        m->c28 = 0x2000;
                        m->c24 = pe;
                        if (!bc1_no_ring)
                            if (ring_attempt(m, r, outp, outlen, route, sym, 1) == 1)
                                return 1;
                    }
                } else {
                    m->s41 = 1;
                    m->s49 = 0xFF;
                }
            }
            if (rec2_gate_failed && !bc1_no_ring)
                if (ring_attempt(m, r, outp, outlen, route, sym, 1) == 1)
                    return 1;
        }
    }

    age_idx = (m->age_ctr + 1) & 0xFF;
    if (m->byte_class != 0)
        m->flag3943 = (uint8_t)m->wp_armed;
    if (m->byte_class != 0)
        pb_gate = ppm_predbyte_gate(m);
    if (pb_gate)
        c550_ctx = 0x100 + m->window[(m->win_pos - m->br18) & m->win_mask];
    else
        c550_ctx = ctx;
    if (m->byte_class == 0)
        ppm_literal_decay_c54(m);
    m->bec = 0;
    if (m->byte_class == 0 || !skip_rec2)
        m->s41 = 1;

    if (wp_class_sel(m)) {
        wp_ctx_val = (int)m->cls_ctx;
        wp_work = 0x304 + (int)m->flag3934;
    } else {
        wp_delta_val = ((int)m->window[(m->win_pos - m->br18) & m->win_mask]
            - (int)m->window[(m->win_pos - 2 * m->br18) & m->win_mask]) & 0xFF;
        wp_ctx_val = (int)PPMS_43B2CC[wp_delta_val] + 0x201;
        wp_work = 0x304;
    }
    wp_fired = (m->byte_class != 0) && ppm_window_predictor_gate(m);
    if (wp_class_sel(m))
        wp_base = (int)m->cls_base;
    else
        wp_base = (int)m->window[(m->win_pos - m->br18) & m->win_mask];
    wp_mirror = wp_class_sel(m) && (m->cls_neg != 0);

    if (wp_fired) {
        for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
            if (wp_mirror)
                m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
            else
                m->excl[wp_i] = (uint8_t)((m->excl[wp_i] - wp_base) & 0xFF);
        }
        wp_ok = ppm_c550_decode(m, r, wp_ctx_val, wp_work, &res);
        if (!wp_ok) {
            for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
                if (wp_mirror)
                    m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
                else
                    m->excl[wp_i] = (uint8_t)((m->excl[wp_i] + wp_base) & 0xFF);
            }
            return 0;
        }
    } else {
        if (pb_gate)
            c550_ctx = 0x100 + m->window[(m->win_pos - m->br18) & m->win_mask];
        else
            c550_ctx = ctx;
        { static int u = -1; if (u < 0) { const char *e = getenv("UHA_C550DBG"); u = (e && e[0] != '0') ? 1 : 0; }
          if (u) { int idx = (m->win_pos - m->br18) & m->win_mask; fprintf(stderr, "[CCTX] D pb_gate=%d winpos=%u br18=%u mask=%u idx=%u wval=%u ctx=%d\n", pb_gate, m->win_pos, m->br18, m->win_mask, idx, m->window[idx], c550_ctx); } }
        if (!ppm_c550_decode(m, r, c550_ctx, 0x301, &res))
            return 0;
    }
    if (wp_fired) {
        if (wp_mirror)
            res.sym = (wp_base - res.sym) & 0xFF;
        else
            res.sym = (res.sym + wp_base) & 0xFF;
    }
    if (wp_mirror)
        wp_delta_val = (wp_base - res.sym) & 0xFF;
    else
        wp_delta_val = (res.sym - wp_base) & 0xFF;

    ppm_c550_post(m, ctx, res.sym, res.kctx, outp, outlen, pb_gate,
                  (int)age_idx, res.sse2_idx, res.weight, res.sse2_up_idx, m->s41 != 0,
                  wp_ctx_val, wp_delta_val, wp_fired, wp_base, wp_work, wp_mirror,
                  wp_fired && wp_class_sel(m), c550_ctx);
    *route = CR_C550;
    *sym = res.sym;
    return 1;
}

static int encode_literal_cascade_core(ppm_model *m, uint8_t *outp, int *outlen,
                                       int target, int *route, int *sym,
                                       int bc1_no_ring, int pre_excl)
{
    int ctx, pb_gate, predicted, found, hit, entry_excluded, rec2_gate;
    uint32_t rec_idx, rec2_total, total, pe, age_idx;
    int rsym, psym, s47, sel, slot, rec2_update_flag;
    int skip_rec2, ring_e123, rec2_gate_failed, entry_sym;
    int c550_ctx, wp_ctx_val, wp_delta_val, wp_base, wp_work;
    int wp_mirror, wp_fired, ring_stat;
    uint8_t rec2_copy[20], rec2_flags[8];
    int rec2_active;
    ppm_c550 res;

    *sym = -1;
    rec2_gate_failed = 0;
    skip_rec2 = 0;
    pe = 0;

    if (m->byte_class != 0 && !bc1_no_ring)
        m->rank_small[m->rank_ptr_small] = pre_rank_before;
    literal_setup(m, &ctx, &pb_gate, &rec_idx);

    if (pre_excl >= 0) {
        m->excl[0] = (uint8_t)pre_excl;
        m->nexcl = 1;
    }
    if (bc1_no_ring)
        select_predicted_record(m, &rec_idx);

    if (!bc1_no_ring) {
        if (early_rec_done) {
            early_rec_done = 0;
            predicted = early_rec_pred && (m->byte_class == 0 || 1);
        } else
            predicted = select_predicted_record(m, &rec_idx);

        if (predicted) {
            ring_rec1_weight = BC1_WT0F0[m->rec1s[rec_idx][0x1A] >> 4];
            ring_rec1_pred = m->rec1s[rec_idx][0x0D + (m->rec1s[rec_idx][0x1A] & 0xF)];
            m->s47 = 0xFF;
            m->c1c = record_total(m, rec_idx);
            if (!predicted_inline_gate(m, rec_idx))
                predicted = 0;
            else if (!predicted_late_gate(m, rec_idx, m->c40))
                predicted = 0;
            else {
                m->c54 = (m->c54 + 1) & PPM_M32;
                if (!predicted_frequency_gate(m, rec_idx))
                    predicted = 0;
                else
                    m->flag3938 = 1;
            }
        }
        if (predicted && m->byte_class != 0) {
            m->flag393b = (uint8_t)m->wp_armed;
            predicted = !m->wp_engaged;
        }
        if (predicted && m->rec1s[rec_idx][2] != 0) {
            found = ppm_rw1_encode(m, rec_idx, m->c40, ctx, target, &rsym);
            if (found) {
                s47 = m->s47;
                rec2_update_flag = (s47 < 0x0C) && (m->rec1s[rec_idx][s47 + 1] < 7);
                ppm_emit_and_maintain(m, rsym, outp, outlen, 1, 1, 0, 0, s47, rec2_update_flag, 1, 1);
                ppm_bc1_post_armed = 0;
                *route = CR_ORDER1_HIT;
                *sym = rsym;
                return 1;
            }
            m->s47 = 0x0C;
            if (m->byte_class == 0)
                m->s41 = 1;
            m->s49 = 0xFF;
            predicted = 0;
        }
        if (predicted) {
            hit = ppm_predicted_encode(m, rec_idx, target, &psym);
            if (hit) {
                ppm_emit_and_maintain(m, psym, outp, outlen, 1, 1, 1, 0, 0,
                                      m->rec1s[rec_idx][1] < 7, 1, 1);
                ppm_bc1_post_armed = 0;
                *route = CR_PREDICTED_HIT;
                *sym = psym;
                return 1;
            }
            m->c1c = record_total(m, rec_idx);
            m->s47 = 0x0C;
            m->s49 = 0xFF;
            ppm_append_excl(m, m->rec1s[rec_idx][0x0D]);
            m->c4c = m->rec2s[m->c40][0];
        }

        if (m->byte_class != 0 && !bc1_no_ring) {
            m->rank_small[m->rank_ptr_small] = pre_rank_after;
            pb_gate = ppm_predbyte_gate(m);
        }
        if (m->byte_class != 0 && !bc1_no_ring)
            ppm_literal_decay_c54(m);
        if (m->byte_class != 0 && !bc1_no_ring && ppm_bc1_rec_ok)
            m->c44 += 2;
        ring_e123 = 0;
        ring_stat = 0;
        if (ring_wanted_flag && !bc1_no_ring && m->byte_class != 0) {
            ring_e123 = 1;
            ring_stat = ring_attempt_encode(m, outp, outlen, route, sym, target);
            if (ring_stat == 1)
                return 1;
            if (ring_stat < 0)
                return 0;
        }
        skip_rec2 = ring_e123 && (ring_stat == 0) && !ring_eligible;
        if (ring_e123 && ring_eligible && !ring_recheck_chain)
            skip_rec2 = 1;
        if (ring_e123 && ring_eligible && ring_recheck_chain) {
            if (m->c50 == 0 || m->rec2s[m->c40][0x11] == 0)
                m->s41 = 1;
            else
                m->s41 = (uint8_t)((m->c58 < 0xFFFF)
                    && (m->rank_small[m->rank_ptr_small] <= 0x3FE));
            skip_rec2 = (m->s41 == 0) || (m->rec2s[m->c40][0] == 0);
        }

        if (!skip_rec2) {
            if (m->rec2s[m->c40][0] != 0) {
                entry_excluded = 0;
                if (m->rec2s[m->c40][2] == 0)
                    entry_excluded = excluded(m, m->rec2s[m->c40][9]);
                ppm_rec2_total_flags(m, m->c40, rec2_copy, &rec2_active, rec2_flags, &rec2_total);
                m->c4c = rec2_total;
                m->s49 = 0xFF;
                rec2_gate = ((rec2_total << 2) > ((uint32_t)rec2_copy[0] * 5))
                         && ((((uint32_t)rec2_copy[0x11] << 2) + m->c50) < 0x10);
                if (rec2_gate && m->byte_class != 0) {
                    m->s3e = (uint8_t)m->wp_armed;
                    rec2_gate = !m->wp_engaged;
                }
                rec2_gate_failed = !rec2_gate;

                if (m->rec2s[m->c40][2] != 0) {
                    if (rec2_gate) {
                        sel = rec2_selector_from_predbyte(m, m->c40);
                        found = ppm_rw2_encode(m, m->c40, sel, target, &rsym);
                        if (found) {
                            slot = m->s49;
                            total = m->c4c;
                            if (slot < 8 && (((uint32_t)m->rec2s[m->c40][slot + 1] << 2) >= total)) {
                                if (total > 0x10)
                                    m->s48 = 2;
                                else
                                    m->s48 = 1;
                            }
                            ppm_rec2_reweight_post(m, rsym, outp, outlen, 1);
                            if (!ring_tried)
                                ppm_bc1_post_armed = 0;
                            *route = CR_REC2_HIT;
                            *sym = rsym;
                            return 1;
                        }
                        if (m->byte_class != 0) {
                            slot = 0;
                            while (slot < 8 && m->rec2s[m->c40][slot + 1] != 0) {
                                if (m->nexcl < PPM_MAX_EXCL && !excluded(m, m->rec2s[m->c40][9 + slot]))
                                    ppm_append_excl(m, m->rec2s[m->c40][9 + slot]);
                                slot++;
                            }
                        }
                        m->s41 = 1;
                        if (!bc1_no_ring) {
                            ring_stat = ring_attempt_encode(m, outp, outlen, route, sym, target);
                            if (ring_stat == 1)
                                return 1;
                            if (ring_stat < 0)
                                return 0;
                        }
                    }
                } else if (!entry_excluded) {
                    if (rec2_gate) {
                        hit = ppm_entry_encode(m, m->c40, target, &pe);
                        if (hit) {
                            m->s48 = 1;
                            m->s49 = 0;
                            m->s41 = 1;
                            entry_sym = m->rec2s[m->c40][9];
                            ppm_emit_and_maintain(m, entry_sym, outp, outlen, 1, 0, 0,
                                                  m->byte_class == 0, m->s47, 1, 0, 1);
                            if (!ring_tried)
                                ppm_bc1_post_armed = 0;
                            *route = CR_ENTRY_HIT;
                            *sym = entry_sym;
                            return 1;
                        }
                        ppm_append_excl(m, m->rec2s[m->c40][9]);
                        m->s49 = 8;
                        m->c28 = 0x2000;
                        m->c24 = pe;
                        if (!bc1_no_ring) {
                            ring_stat = ring_attempt_encode(m, outp, outlen, route, sym, target);
                            if (ring_stat == 1)
                                return 1;
                            if (ring_stat < 0)
                                return 0;
                        }
                    }
                } else {
                    m->s41 = 1;
                    m->s49 = 0xFF;
                }
            }
            if (rec2_gate_failed && !bc1_no_ring) {
                ring_stat = ring_attempt_encode(m, outp, outlen, route, sym, target);
                if (ring_stat == 1)
                    return 1;
                if (ring_stat < 0)
                    return 0;
            }
        }
    }

    age_idx = (m->age_ctr + 1) & 0xFF;
    if (m->byte_class != 0)
        m->flag3943 = (uint8_t)m->wp_armed;
    if (m->byte_class != 0)
        pb_gate = ppm_predbyte_gate(m);
    if (pb_gate)
        c550_ctx = 0x100 + m->window[(m->win_pos - m->br18) & m->win_mask];
    else
        c550_ctx = ctx;
    if (m->byte_class == 0)
        ppm_literal_decay_c54(m);
    m->bec = 0;
    if (m->byte_class == 0 || !skip_rec2)
        m->s41 = 1;

    if (wp_class_sel(m)) {
        wp_ctx_val = (int)m->cls_ctx;
        wp_work = 0x304 + (int)m->flag3934;
    } else {
        wp_delta_val = ((int)m->window[(m->win_pos - m->br18) & m->win_mask]
            - (int)m->window[(m->win_pos - 2 * m->br18) & m->win_mask]) & 0xFF;
        wp_ctx_val = (int)PPMS_43B2CC[wp_delta_val] + 0x201;
        wp_work = 0x304;
    }
    wp_fired = (m->byte_class != 0) && ppm_window_predictor_gate(m);
    if (wp_class_sel(m))
        wp_base = (int)m->cls_base;
    else
        wp_base = (int)m->window[(m->win_pos - m->br18) & m->win_mask];
    wp_mirror = wp_class_sel(m) && (m->cls_neg != 0);

    if (wp_fired) {
        int wp_i, enc_sym;
        for (wp_i = 0; wp_i < m->nexcl; wp_i++) {
            if (wp_mirror)
                m->excl[wp_i] = (uint8_t)((wp_base - m->excl[wp_i]) & 0xFF);
            else
                m->excl[wp_i] = (uint8_t)((m->excl[wp_i] - wp_base) & 0xFF);
        }
        if (wp_mirror)
            enc_sym = (wp_base - target) & 0xFF;
        else
            enc_sym = (target - wp_base) & 0xFF;
        if (!ppm_c550_encode(m, wp_ctx_val, wp_work, enc_sym, &res))
            return 0;
    } else {
        if (pb_gate)
            c550_ctx = 0x100 + m->window[(m->win_pos - m->br18) & m->win_mask];
        else
            c550_ctx = ctx;
        { static int u = -1; if (u < 0) { const char *e = getenv("UHA_C550DBG"); u = (e && e[0] != '0') ? 1 : 0; }
          if (u) { int idx = (m->win_pos - m->br18) & m->win_mask; fprintf(stderr, "[CCTX] E pb_gate=%d winpos=%u br18=%u mask=%u idx=%u wval=%u ctx=%d\n", pb_gate, m->win_pos, m->br18, m->win_mask, idx, m->window[idx], c550_ctx); } }
        if (!ppm_c550_encode(m, c550_ctx, 0x301, target, &res))
            return 0;
        { static int pt2 = -1;
          if (pt2 < 0) { const char *e = getenv("UHA_PPMTRACE"); pt2 = (e && e[0] == '2') ? 1 : 0; }
          if (pt2)
              fprintf(stderr, "[TR2 c550enc] tgt=%u ctx=%d c550ctx=%d wpf=%d win=%u\n",
                      (unsigned)target, ctx, c550_ctx, wp_fired, (unsigned)m->win_pos); }
    }
    if (wp_fired) {
        if (wp_mirror)
            res.sym = (wp_base - res.sym) & 0xFF;
        else
            res.sym = (res.sym + wp_base) & 0xFF;
    }
    if (wp_mirror)
        wp_delta_val = (wp_base - res.sym) & 0xFF;
    else
        wp_delta_val = (res.sym - wp_base) & 0xFF;

    ppm_c550_post(m, ctx, res.sym, res.kctx, outp, outlen, pb_gate,
                  (int)age_idx, res.sse2_idx, res.weight, res.sse2_up_idx, m->s41 != 0,
                  wp_ctx_val, wp_delta_val, wp_fired, wp_base, wp_work, wp_mirror,
                  wp_fired && wp_class_sel(m), c550_ctx);
    *route = CR_C550;
    *sym = res.sym;
    return 1;
}

int ppm_encode_literal_cascade(ppm_model *m, uint8_t *outp, int *outlen,
                               int target, int *route, int *sym)
{
    uint32_t r0, r1, rec2i, ctxb, ring_ptr_set;
    int ring_wanted, chain_al;

    m241_ring_dump("E", m);
    if (m->byte_class == 0)
        return encode_literal_cascade_core(m, outp, outlen, target, route, sym, 0, -1);

    literal_excl_reset(m);
    literal_cont_excl(m);
    m->s3e = 0;
    m->s41 = 0;
    m->flag393c = 0;
    m->c48 = literal_context(m);
    g_c48_site = 3; g_c40_site = 3;
    m->c38 = (m->c48 ^ (m->c48 >> 0x0D)) & 0x7FFF;
    /* [GATED UHA_C40ONE, defautOFF, M207] formule UNIQUE of legacy (0x41a2a1) :
     *   c40 = (c48 & 0xFFFF) + ((bc==0 && novel[(c48>>16)&0xFF]) ? 0x10000 : 0)
     * The two sites " nus " (here and more low) ecrasaient c40 without the +0x10000, this which the rendait
     * false of has literal (measured : 117 446 au lieu of 120 272 at the input of the block 2). */
    { static int c1g = -1;
      if (c1g < 0) { const char *e = getenv("UHA_C40ONE"); c1g = (e && e[0] != '0') ? 1 : 0; }
      if (c1g) {
          uint32_t d = m->c48 & 0xFFFFu;
          if (m->byte_class == 0 && m->novel[(m->c48 >> 16) & 0xFF] != 0)
              d += 0x10000u;
          m->c40 = d;
      } else
          m->c40 = m->c48 & 0xFFFF; }
    ppm_update_head_rank_ptrs(m);
    ppm_lastsym_predict(m);

    m->wp_class_selected = (m->flag3934 != 0)
        && ((m->br18 <= 4) || (m->rank_small[m->rank_ptr_small] <= 0x3FE));
    m->wp_armed = m->wp_class_selected && ppm_window_predictor_gate(m);
    m->wp_engaged = m->wp_armed && (m->wp_a < m->wp_b);
    m->wp_kernel_weight = 0;

    /* t12g - mirror strict of the wrapper decodeur (predecode + string s41/
     * ring_wanted + queue post-update) ; single the ring_decode reads the RC, the
     * predecode is of l'state pur, therefore identical side encoder. */
    ring_rec1_weight = 0;
    ring_rec1_pred = 0;
    early_rec_idx = m->c38 & 0x7FFF;
    early_rec_pred = 0;
    early_rec_done = 0;

    r0 = m->roll_ctx0;
    r1 = m->roll_ctx1;
    ctxb = m->c48 & 0xFF;
    rec2i = m->c48 & 0xFFFF;
    pre_rank_before = m->rank_small[m->rank_ptr_small];
    ring_ptr_set = ppm_bc1_predecode(m, r0, r1);
    pre_rank_after = m->rank_small[m->rank_ptr_small];
    m->flag393c = (uint8_t)ppm_bc1_st.fired393c;

    if (m->rec2s[rec2i][0x13] < 0x90) {
        if (ppm_bc1_st.ring_flag == 0)
            m->s41 = 0;
        else
            m->s41 = 1;
    } else
        m->s41 = 1;

    ring_wanted = m->s41 == 0;
    ring_recheck_chain = ring_wanted;
    if (!ring_wanted) {
        if (m->c50 == 0 || m->rec2s[rec2i][0x11] == 0)
            chain_al = 1;
        else if (m->c58 < 0xFFFF)
            chain_al = (m->rank_small[m->rank_ptr_small] > 0x3FE) ? 0 : 1;
        else
            chain_al = 0;
        m->s41 = (uint8_t)chain_al;
        ring_wanted = chain_al == 0;
    }
    if (!ring_wanted)
        ring_wanted = m->rec2s[rec2i][0] == 0;

    ring_eligible = ring_ptr_set;
    ring_tried = 0;
    ppm_bc1_ring_ran = 0;
    ppm_bc1_post_armed = 0;
    ring_wanted_flag = ring_wanted;

    if (!encode_literal_cascade_core(m, outp, outlen, target, route, sym, 0, -1))
        return 0;

    if (ppm_bc1_post_armed)
        ppm_bc1_post_update(m, (uint8_t)*sym);
    if (m->wp_pend) {
        if (m->flag3943 != 0)
            m->bfc += m->wp_kernel_weight;
        m->wp_a = ((m->wp_a * 31) >> 5) + m->wp_acc_add;
        m->wp_b = ((m->wp_b * 31) >> 5) + m->bfc;
        m->wp_pend = 0;
    }
    ppm_bc1_sub2_update((uint8_t)ctxb, (uint8_t)*sym);
    ppm_bc1_push_window((uint8_t)*sym);
    return 1;
}
