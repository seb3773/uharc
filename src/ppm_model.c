#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ppm_priv.h"

/* t14d : class LZP forcee at the encoding (0..9). 0 = behavior by default
 * (value historique) ; there politique of selection there pilote. */
int uharc_ppm_class = 0;

/* [M211] 1 = the warm-up of promotion bc1 not touche not `rec_globals` (gate `UHA_PROMNOREC`). */
int g_promo_silent = 0;

uint32_t ppm_window_size(int order)
{
    int shift = ((order - 0x18) % 0x10) + 0x0A;
    return 1u << shift;
}

static void ppm_block_reset_tables(ppm_model *m);

static void seed_prob_tables(ppm_model *m)
{
    int ebp, esi, ebx, i, j;
    uint32_t esi_flag, hi, val0;
    uint32_t f68, f56, f72, f76, f64, adj;

    for (ebp = 0; ebp <= 31; ebp++) {
        esi_flag = (uint32_t)ebp & 4;
        hi = (ebp >= 16) ? 8 : 0;
        for (i = 0; i <= 15; i++) {
            val0 = ((PPMS_43E130[i] + esi_flag + hi) << 7) & PPM_M32;
            m->r2_e[ebp * 16 + i] = val0;
            m->rw_e[ebp * 16 + i] = val0;
        }
        m->r2_esc[ebp] = 0x1000;
        m->sse2[ebp] = (PPMS_43E1F4[ebp] << 7) & PPM_M32;
    }

    for (esi = 0; esi <= 127; esi++) {
        f68 = (esi >= 16) ? 1 : 0;
        f56 = f68;
        f76 = f68;
        f72 = (esi >= 8) ? 4 : 0;
        if (esi >= 16)
            f76 = 4;
        f64 = (esi >= 64) ? 4 : 0;
        for (i = 0; i <= 15; i++) {
            j = esi * 16 + i;
            val0 = PPMS_43E170[i];
            if (esi < 16)
                m->r2_b[j] = ((val0 + f72) << 7) & PPM_M32;
            if (esi < 32)
                m->rw_b[j] = ((val0 + f76) << 7) & PPM_M32;
            if (esi < 16)
                m->rw_c[j] = ((val0 + f72) << 7) & PPM_M32;
            m->sse_prob[j] = ((val0 + f64) << 7) & PPM_M32;
            m->r2_a[j] = ((val0 + f68 + f64) << 7) & PPM_M32;
            m->rw_a[j] = ((val0 + f56 + f64) << 7) & PPM_M32;
        }
    }

    for (esi = 0; esi <= 7; esi++) {
        for (ebx = 0; ebx <= 7; ebx++) {
            adj = 0;
            if (ebx > esi)
                adj = PPMS_43E1B0[ebx - esi];
            else if (esi > ebx)
                adj = (0u - PPMS_43E1B0[esi - ebx]) & PPM_M32;
            for (i = 0; i <= 31; i++)
                m->esc_mass[(esi << 8) + ebx * 32 + i] = (0x1000 + adj) & PPM_M32;
        }
        for (i = 0; i <= 31; i++)
            m->entry_prob[esi * 32 + i] = (PPMS_43E1D0[(i & 1) + esi] << 7) & PPM_M32;
        for (i = 0; i <= 1023; i++)
            m->pred_prob[esi * 1024 + i] = (PPMS_43E1D0[(i & 1) + esi] << 7) & PPM_M32;
        for (i = 0; i <= 255; i++)
            m->len_prob[esi * 256 + i] = 0x800;
    }
}

void ppm_model_free(ppm_model *m)
{
    if (!m)
        return;
    free(m->cum);
    free(m->freq);
    free(m->ent_wt);
    free(m->order0_wt);
    free(m->sse_prob);
    free(m->sse2);
    free(m->pred_byte);
    free(m->cls_idx);
    free(m->wtab);
    free(m->recency);
    free(m->last_sym);
    free(m->novel);
    free(m->f154);
    free(m->window);
    free(m->ring_buf);
    free(m->budget);
    free(m->tstep);
    free(m->tstep2);
    free(m->rec1s);
    free(m->rec2s);
    free(m->ht1_pos);
    free(m->ht1_ctx);
    free(m->ht2_new);
    free(m->ht2_prev);
    free(m->len_tab);
    free(m->link_tab);
    free(m->esc_mass);
    free(m->pred_prob);
    free(m->entry_prob);
    free(m->len_prob);
    free(m->rw_a);
    free(m->rw_b);
    free(m->rw_c);
    free(m->rw_e);
    free(m->r2_a);
    free(m->r2_b);
    free(m->r2_e);
    free(m->r2_esc);
    free(m->t46a);
    memset(m, 0, sizeof(*m));
}

int ppm_model_alloc(ppm_model *m, int order)
{
    int i;
    uint32_t w;

    if (order < 0x18 || order > 0x27)
        return 0;
    memset(m, 0, sizeof(*m));
    uha_ppm_gen_tables();

    w = ppm_window_size(order);
#define ALLOC(p, n, t) do { (p) = calloc((size_t)(n), sizeof(t)); if (!(p)) goto fail; } while (0)
    ALLOC(m->cum, PPM_NUM_CTX, ppm_fenwick);
    ALLOC(m->freq, PPM_NUM_CTX, ppm_fenwick);
    ALLOC(m->ent_wt, PPM_NUM_CTX, uint16_t);
    ALLOC(m->order0_wt, PPM_NUM_CTX, uint32_t);
    ALLOC(m->sse_prob, 0x800, uint32_t);
    ALLOC(m->sse2, 0x20, uint32_t);
    ALLOC(m->pred_byte, PPM_NUM_CTX, uint8_t);
    ALLOC(m->cls_idx, PPM_NUM_CTX, uint8_t);
    ALLOC(m->wtab, 0x10, uint32_t);
    ALLOC(m->recency, 0x100, uint32_t);
    ALLOC(m->last_sym, 0x100, uint32_t);
    ALLOC(m->novel, 0x100, uint8_t);
    ALLOC(m->f154, 0x4000, uint16_t);
    ALLOC(m->window, w + 0x100, uint8_t);
    ALLOC(m->ring_buf, 0x40000, uint8_t);
    ALLOC(m->budget, PPM_NUM_CTX, uint32_t);
    ALLOC(m->tstep, PPM_NUM_CTX, uint16_t);
    ALLOC(m->tstep2, PPM_NUM_CTX, uint16_t);
    ALLOC(m->rec1s, PPM_REC1_COUNT, ppm_rec1);
    ALLOC(m->rec2s, PPM_REC2_COUNT, ppm_rec2);
    ALLOC(m->ht1_pos, PPM_HASH_COUNT, uint32_t);
    ALLOC(m->ht1_ctx, PPM_HASH_COUNT, uint32_t);
    ALLOC(m->ht2_new, PPM_HASH_COUNT, uint32_t);
    ALLOC(m->ht2_prev, PPM_HASH_COUNT, uint32_t);
    ALLOC(m->len_tab, PPM_HASH_COUNT, uint8_t);
    ALLOC(m->link_tab, PPM_HASH_COUNT, uint8_t);
    ALLOC(m->esc_mass, 0x2000, uint32_t);
    ALLOC(m->pred_prob, 0x2000, uint32_t);
    ALLOC(m->entry_prob, 0x100, uint32_t);
    ALLOC(m->len_prob, 0x800, uint32_t);
    ALLOC(m->rw_a, 0x800, uint32_t);
    ALLOC(m->rw_b, 0x200, uint32_t);
    ALLOC(m->rw_c, 0x100, uint32_t);
    ALLOC(m->rw_e, 0x200, uint32_t);
    ALLOC(m->r2_a, 0x800, uint32_t);
    ALLOC(m->r2_b, 0x100, uint32_t);
    ALLOC(m->r2_e, 0x200, uint32_t);
    ALLOC(m->r2_esc, 0x20, uint32_t);
    ALLOC(m->t46a, 0x100, uint32_t);
#undef ALLOC

    m->win_wrap = w;
    m->win_mask = w - 1;
    m->win_pos = 0;

    for (i = 0; i < PPM_HASH_COUNT; i++) {
        m->ht1_pos[i] = PPM_M32;
        m->ht1_ctx[i] = PPM_M32;
        m->ht2_new[i] = PPM_M32;
        m->ht2_prev[i] = PPM_M32;
    }
    for (i = 0; i <= 0xFF; i++)
        m->novel[i] = PPMS_NOVEL[i];
    for (i = 0; i <= 0x3FFF; i++)
        m->f154[i] = PPMS_F154[i];
    for (i = 0; i <= 0xF; i++)
        m->wtab[i] = PPMS_WTAB[i];
    for (i = 0; i < 5; i++)
        m->rank_small_base[i] = PPMS_RANKBASE_S[i];
    for (i = 0; i < 0x11; i++)
        m->rank_large_base[i] = PPMS_RANKBASE_L[i];

    for (i = 0; i <= 0x300; i++)
        m->order0_wt[i] = 1;
    for (i = 0; i <= 0x300; i++)
        m->budget[i] = 0x4000;
    for (i = 0x209; i <= 0x300; i++)
        m->ent_wt[i] = 1;
    for (i = 0; i <= 0x300; i++)
        m->tstep2[i] = 0x20;
    for (i = 0; i <= 0x300; i++)
        m->tstep[i] = 0x10;
    for (i = 0x2F9; i <= 0x300; i++)
        m->tstep2[i] = 0x0A;
    for (i = 0x2E9; i <= 0x300; i++)
        m->tstep[i] = 0x08;
    m->tstep[0x200] = 0x06;
    for (i = 0; i <= 0x300; i++)
        m->pred_byte[i] = 0xFF;

    seed_prob_tables(m);

    m->e0_blk_len = PPM_M32;
    m->d4 = PPM_M32;
    m->d8 = 0;
    m->b8 = 0;
    m->has_cont = 0;
    m->cont_ofs = 0;
    m->detr_thr1 = PPM_M32;
    m->dcg = 1;
    m->c4g = 1;
    m->a8g = 1;
    m->roll_ctx0 = 0;
    m->roll_ctx1 = 0;
    m->roll_ctx2 = 0;
    m->last_ctx = 0;
    m->base46 = 0;
    m->flag3934 = 0;
    m->cls_ctx = 0x201;
    m->cls_stride = 1;
    ppm_detr_init(&m->detr);
    return 1;

fail:
    ppm_model_free(m);
    return 0;
}

static void quarter_rec1(ppm_model *m)
{
    int base, index, next, slot, sum;

    for (base = 0; base <= 0x7FFF; base++) {
        index = base;
        while (index < 0x40000 && m->rec1s[index][0] != 0) {
            sum = 0;
            for (slot = 1; slot <= 12; slot++) {
                m->rec1s[index][slot] >>= 2;
                sum += m->rec1s[index][slot];
            }
            if (sum == 0) {
                next = index;
                while (next + 0x8000 < 0x40000 && m->rec1s[next + 0x8000][0] != 0) {
                    memcpy(m->rec1s[next], m->rec1s[next + 0x8000], sizeof(ppm_rec1));
                    next += 0x8000;
                }
                m->rec1s[next][0] = 0;
            } else {
                m->rec1s[index][0] = (uint8_t)((m->rec1s[index][0] >> 2) + 1);
                m->rec1s[index][0x19] = (uint8_t)((m->rec1s[index][0x19] & 0x3F) >> 1);
                m->rec1s[index][0x1A] = (uint8_t)(m->rec1s[index][0x1A] & 0xF);
                m->rec1s[index][0x1B] = 0;
                if (m->rec1s[index][m->rec1s[index][0x1A] + 1] == 0)
                    m->rec1s[index][0x1A] = 0;
                index += 0x8000;
            }
        }
    }
}

static void rescale_rec2_table(ppm_model *m)
{
    int idx, limit, off;
    uint32_t acc, b, cls;

    limit = (int)(0x20000u >> m->byte_class);
    if (limit > PPM_REC2_COUNT)
        limit = PPM_REC2_COUNT;
    for (idx = 0; idx < limit; idx++) {
        if (m->rec2s[idx][0] == 0)
            continue;
        acc = 0;
        for (off = 7; off >= 0; off--) {
            b = m->rec2s[idx][1 + off] >> 2;
            m->rec2s[idx][1 + off] = (uint8_t)b;
            acc = (acc + b) & 0xFF;
        }
        if (acc == 0)
            m->rec2s[idx][0] = 0;
        else
            m->rec2s[idx][0] = (uint8_t)(((m->rec2s[idx][0] >> 2) + 1) & 0xFF);
        m->rec2s[idx][0x11] >>= 1;
        cls = m->rec2s[idx][0x13] & 0x0F;
        m->rec2s[idx][0x13] = (uint8_t)cls;
        acc = (acc + m->rec2s[idx][0]) & 0xFF;
        m->rec2s[idx][0x12] = (uint8_t)acc;
        if (m->rec2s[idx][1 + cls] == 0)
            m->rec2s[idx][0x13] = 0;
    }
}

int ppm_select_class(ppm_model *m, int cls)
{
    if (cls < 0 || cls > 9)
        return 0;
    /* [M241, GATED UHA_M241CLS, default-OFF] WHICH change there class and when : there 1re divergence
     * of the run BLKSCANCLS is has class 9 installee by l'encoder au literal next the
     * reset 505 696 without that the DECODEUR there lise. Trace : old class, new, horloge
     * window, appelant (resolu by addr2line). read-only, no effect. */
    { static int on = -1;
      if (on < 0) { const char *e = getenv("UHA_M241CLS"); on = (e && e[0] != '0') ? 1 : 0; }
      if (on && cls != m->flag3934)
          fprintf(stderr, "[M241CLS] wp=%u old=%u new=%d call=%p\n",
                  (unsigned)m->win_pos, (unsigned)m->flag3934, cls, __builtin_return_address(0)); }
    if (cls != m->flag3934) {
        /* [M283, GATED UHA_CLSRESCALE, default-OFF] RESCALE of the class QUITTEE. Measures :
         * 75/87 rows no zero of the class 3 have `cum[r][0]` divise by 2 exactement between
         * `pos = 1 070 747` and `1 083 561`, with there law `f > 16 ? (f+1)>>1 : 0` ; no call of
         * rescale n'is visible in this zone legacy side. There class pass of 3 has 5 during
         * l'interval : l'hypothese testee is has rescale **global of the class quittee** au
         * changement of class. Judge : `firstdiv` > 184 232 attendu if l'hypothese is bonne. */
        { static int cr = -1;
          static const uint32_t NCTX[10] = { 8u, 32u, 32u, 96u, 64u, 4u, 4u, 8u, 3u, 5u };
          extern void ppm_cls_rescale(ppm_model *m, int base, int nctx);
          if (cr < 0) { const char *e = getenv("UHA_CLSRESCALE"); cr = (e && e[0] != '0') ? 1 : 0; }
          if (cr)
              ppm_cls_rescale(m, (int)CLS_CTXBASE[m->flag3934], (int)NCTX[m->flag3934]); }
        m->flag3934 = (uint8_t)cls;
        m->cls_ctx = CLS_CTXBASE[cls];
        m->cls_stride = CLS_STRIDE[cls];
        m->cls_shift = CLS_SHIFT[cls];
        m->cls_flag31 = (cls == 5 || cls == 6) ? 1 : 0;
        if (cls == 5 || cls == 6)
            ppm_mm6_reset(&m->mm6);
        if (cls >= 7)
            ppm_mm7_reset(&m->mm7, (uint8_t)cls);
        m->cls_phase = 0;
        m->cls_neg = 0;
        m->cls_base = 0;
    }
    /* [GATED UHA_FP, defautOFF, M207] empreinte d'state at the input of block - appelee some TWO sides
     * (`ppm_block_reset` decoder AND `ppm_block_reset_encode` encoder) : c'is l'oracle out line
     * for there 1re divergence (offset 1319 = 1er symbole of the block 2). No emissif by default. */
    { extern int g_c48_site, g_c40_site; static int fp = -1;
      if (fp < 0) { const char *e = getenv("UHA_FP"); fp = (e && e[0] != '0') ? 1 : 0; }
      if (fp) {
          int c = m->flag3934;
          fprintf(stderr, "[FP] pos=%u cls=%d clsctx=%d ent=%u cum0=%u f=%u,%u,%u,%u br=%u/%u/%u winpos=%u bc=%u c48=%u c54=%u c50=%u"
                  " r301=%u,%u,%u e301=%u\n",
                  m->out_count, c, m->cls_ctx, (unsigned)m->ent_wt[c], (unsigned)m->cum[c][0],
                  (unsigned)m->freq[c][0], (unsigned)m->freq[c][1],
                  (unsigned)m->freq[c][2], (unsigned)m->freq[c][3],
                  m->br18, m->brf0, m->br14, m->win_pos, (unsigned)m->byte_class,
                  m->roll_ctx0, (unsigned)m->c54, (unsigned)m->c50,
                  (unsigned)m->cum[0x301][0], (unsigned)m->cum[0x302][0],
                  (unsigned)m->cum[0x303][0], (unsigned)m->ent_wt[0x301]);
          fprintf(stderr, "[FP2] pos=%u rec=%u/%u c1c=%u s47=%u c40=%u c38=%u c48=%u=%08x br=%u/%u\n",
                  m->out_count, m->rec_a[0], m->rec_b[0], (unsigned)m->c1c,
                  (unsigned)m->s47, (unsigned)m->c40, (unsigned)m->c38,
                  (unsigned)m->c48, (unsigned)m->c48, m->br18, m->brf0);
          fprintf(stderr, "[FP3] pos=%u site48=%d site40=%d c48=%08x c40=%u\n",
                  m->out_count, g_c48_site, g_c40_site, (unsigned)m->c48, (unsigned)m->c40);
      } }
    return 1;
}

int ppm_block_reset(ppm_model *m, uha_rc *r)
{
    uint32_t rng0, cls, t;

    ppm_block_reset_tables(m);

    rng0 = r->range / 10;
    r->range = rng0;
    t = r->code / rng0;
    m->c20 = 10;
    m->c24 = t & 0xFF;
    m->c28 = (t + 1) & PPM_M32;
    r->code = (r->code - t * rng0) & PPM_M32;
    uha_rc_normalize(r);
    cls = t & 0xFF;
    /* [GATED UHA_PPMTRACE=2, default-OFF, M122] class LUE in the stream legacy :
     * trace no-emissive, neutre (no effect on l'state). */
    { static int bd = -1; if (bd < 0) { const char *e = getenv("UHA_PPMTRACE"); bd = (e && e[0]=='2') ? 1 : 0; }
      if (bd) fprintf(stderr, "[BLKCLS] cls=%u bc=%d outpos=%u\n",
                      cls, m->byte_class, m->out_count); }
    return ppm_select_class(m, (int)cls);
}

static void ppm_block_reset_tables(ppm_model *m)
{
    int i, row;

    for (i = 0; i <= 0x208; i++) {
        m->order0_wt[i] = m->byte_class;
        m->budget[i] = 0x4000;
    }
    for (i = 0; i <= 0x208; i++) {
        m->pred_byte[i] = 0xFF;
        m->cls_idx[i] = 0;
    }
    for (row = 0; row <= 0x208; row++) {
        memset(m->cum[row], 0, sizeof(ppm_fenwick));
        memset(m->freq[row], 0, sizeof(ppm_fenwick));
    }
    for (row = 0x301; row <= 0x30E; row++)
        for (i = 0; i <= 0xFF; i++)
            m->cum[row][i] = (uint16_t)((PPMS_ROWSEED[i] << 3) & 0xFFFF);
    for (row = 0x301; row <= 0x30E; row++)
        for (i = 0; i <= 0xFF; i++)
            m->freq[row][i] = 8;
    for (i = 0; i <= 0x208; i++)
        m->ent_wt[i] = 1;

    for (i = 0; i <= 255; i++) {
        m->lzp_class_rec[i][0] = 0;
        m->lzp_class_rec[i][1] = 0;
        m->lzp_class_rec[i][2] = 0;
        m->lzp_class_rec[i][3] = 0;
    }
    for (i = 0; i < (0x290 / 8); i++) {
        m->lzp_class_rec[i][0] = (uint16_t)(PPMS_LZPCLASS_INIT[i * 8] | (PPMS_LZPCLASS_INIT[i * 8 + 1] << 8));
        m->lzp_class_rec[i][1] = (uint16_t)(PPMS_LZPCLASS_INIT[i * 8 + 2] | (PPMS_LZPCLASS_INIT[i * 8 + 3] << 8));
        m->lzp_class_rec[i][2] = (uint16_t)(PPMS_LZPCLASS_INIT[i * 8 + 4] | (PPMS_LZPCLASS_INIT[i * 8 + 5] << 8));
        m->lzp_class_rec[i][3] = (uint16_t)(PPMS_LZPCLASS_INIT[i * 8 + 6] | (PPMS_LZPCLASS_INIT[i * 8 + 7] << 8));
    }

    for (i = 0x209; i <= 0x300; i++)
        ppm_t268_rescale(m, i);
    rescale_rec2_table(m);
    /* [GATED UHA_C40RST, defautOFF, M207] the reset of block legacy calls `0x416cb0` which recalcule the
     * context roulant then `[0x481c40] = (c48 & 0xFFFF) [+ 0x10000 if bc==0 && novel]`
     * (`0x41a253..0x41a2a1`). At nous `c40` restait PERIME at the input of block (measured : 117 446
     * contre 120 272 at the master au block 2) - and c'is the single gap d'state au 1er symbole. */
    { static int g = -1;
      if (g < 0) { const char *e = getenv("UHA_C40RST"); g = (e && e[0] != '0') ? 1 : 0; }
      if (g) {
          uint32_t d = m->c48 & 0xFFFFu;
          if (m->byte_class == 0 && m->novel[(m->c48 >> 16) & 0xFF] != 0)
              d += 0x10000u;
          m->c40 = d;
      } }

    m->c54 = 0;
    m->c50 = 0;
    m->c44 = 0;
    m->rank_ptr_small = 0;
    m->c58 = 0x1FF;
    m->flag393c = 0;
    m->rank_ptr_large = 0;
    memset(m->rank_small, 0, sizeof(m->rank_small));
    memset(m->rank_large, 0, sizeof(m->rank_large));
    for (i = 0; i <= 0xFF; i++) {
        m->t46a[i] = 0;
        m->recency[i] = 0;
        m->hist[i] = 0;
    }
    m->br10 = 0;
    m->br14 = 0;
    m->br18 = 1;
    m->brf0 = 1;
    m->flag3939 = 0;
    for (i = 0; i <= 0xFF; i++)
        m->age_ring[i] = 0x9240;
    m->age_ctr = 0xFF;
    m->rec_a[0] = 0;
    m->rec_a[1] = 0;
    m->rec_b[0] = 0;
    m->rec_b[1] = 0;
    m->age = 0x91ADC0;
    m->wp_a = 0;
    m->wp_b = 0;
    m->wp_acc_add = 0;
    m->wp_pend = 0;
    m->flag393b = 0;
    m->flag3943 = 0;
    m->nexcl = 0;
    m->s41 = 0;
    m->s45 = 0;
    m->s47 = 0;
    m->s48 = 0;
    m->s49 = 0;
    m->s3e = 0;
    m->bec = 0;
    m->bfc = 0;
    m->out_count = 0;
}

int ppm_block_reset_encode(ppm_model *m)
{
    /* t14d : there class LZP (flag3934) is emit en tete of block, mirror strict
     * of ppm_block_reset side decode (uniform/10 -> cls 0..9 -> select_class).
     * L'encoder legacy NOT fige NOT 0 : il selects cls (p.ex. 3 sure image24),
     * single regim e autorisant wp_class_selected -> window predictor (WP). */
    int cls;
    if (!m || !m->w)
        return 0;
    cls = uharc_ppm_class;
    if (cls < 0 || cls > 9)
        cls = 0;
    ppm_block_reset_tables(m);
    if (uha_rcw_encode(m->w, (uint32_t)cls, (uint32_t)cls + 1, 10) != 0)
        return 0;
    m->c20 = 10;
    m->c24 = (uint32_t)(cls & 0xFF);
    m->c28 = (uint32_t)((cls + 1) & PPM_M32);
    return ppm_select_class(m, cls);
}

void ppm_read_block_header(ppm_model *m, uha_rc *r)
{
    uint32_t bit, chunk, cont, total, shift;
    int i;

    r->code = 0;
    r->range = PPM_M32;
    r->rd.pos = 0;
    r->rd.exhausted = 0;
    r->corrupt = 0;
    for (i = 0; i < 5; i++)
        r->code = (r->code << 8) | uha_reader_byte(&r->rd);

    bit = uha_rc_threshold(r, 2);
    m->byte_class = (uint8_t)(bit & 0xFF);
    uha_rc_remove(r, bit, bit + 1);
    if (m->byte_class != 0)
        return;

    total = 0;
    shift = 0;
    for (;;) {
        chunk = uha_rc_threshold(r, 0x800);
        uha_rc_remove(r, chunk, chunk + 1);
        total = (total + ((chunk << shift) & PPM_M32)) & PPM_M32;
        shift += 0x0B;
        cont = uha_rc_threshold(r, 2);
        uha_rc_remove(r, cont, cont + 1);
        if ((cont & 0xFFFF) == 0)
            break;
    }
    m->e0_blk_len = total;
    m->detr_thr2 = total;
}

/* t12g : mirror strict of ppm_read_block_header - honore m->byte_class.
 * bc!=0 : single the uniform(2) is emis, no chunks e0, detr_thr2 remainder 0. */
void ppm_write_block_header(ppm_model *m, uha_rcw *w)
{
    uint32_t total, chunk, shift;

    if (uha_rcw_encode(w, m->byte_class, m->byte_class + 1, 2) != 0)
        return;
    if (m->byte_class != 0)
        return;
    total = m->e0_blk_len;
    shift = 0;
    for (;;) {
        chunk = (total >> shift) & 0x7FFu;
        if (uha_rcw_encode(w, chunk, chunk + 1, 0x800) != 0)
            return;
        shift += 0x0B;
        if (shift >= 32 || (total >> shift) == 0) {
            if (uha_rcw_encode(w, 0, 1, 2) != 0)
                return;
            break;
        }
        if (uha_rcw_encode(w, 1, 2, 2) != 0)
            return;
    }
    m->detr_thr2 = total;
}

/* [M208 GATED UHA_C1C, default-OFF, no emissif] date `[0x481c1c]` (c1c = total of record) has
 * l'input and at the output of the promotion bc1, with has hash some records : c'is there measures which
 * separe " l'state d'input differe " of " the warm-up lui-same differe " between decoder (oracle,
 * stream legacy) and encoder - single difference measured au 1er symbole of the block 2 (86 vs 88). */
static void c1c_probe(const char *ph, ppm_model *m, uint32_t extra)
{
    static int on = -1, dump = -1;
    uint32_t i, h = 0, n = 0;
    if (on < 0) {
        const char *e = getenv("UHA_C1C");
        on = (e && e[0] != '0') ? (e[0] == '2' ? 2 : 1) : 0;
        dump = (on == 2) ? 1 : 0;
    }
    if (!on)
        return;
    for (i = 0; i < 0x40000u; i++) {
        const uint8_t *r = m->rec1s[i];
        int k;
        if (r[0] == 0)
            continue;
        n++;
        h = h * 31u + i;
        for (k = 0; k <= 12; k++)
            h = h * 131u + r[k];
        if (dump)
            fprintf(stderr, "[C1C2] ph=%s idx=%u r0=%u t=%u\n", ph, (unsigned)i,
                    r[0], (unsigned)(r[0] + r[1] + r[2] + r[3] + r[4] + r[5] + r[6] + r[7] +
                                     r[8] + r[9] + r[10] + r[11] + r[12]));
    }
    fprintf(stderr, "[C1C] ph=%s win=%u c1c=%u extra=%u nrec=%u hrec=%08x\n",
            ph, m->win_pos, (unsigned)m->c1c, (unsigned)extra, (unsigned)n, (unsigned)h);
}

void ppm_promote_to_bc1(ppm_model *m)
{
    uint8_t saved[256];
    uint8_t expanded[32];
    ppm_detr d;
    uint32_t old_pos, start_pos, read_pos, write_pos, half, stop_pos, warm_pos;
    uint32_t h1, h2, ctx, index, saved_dc, saved_c4, saved_a8;
    int i, j, count;
    uint32_t c1c_idx = PPM_M32, c1c_tot = 0, c1c_ctx = 0;

    c1c_probe("in", m, 0);
    /* [M211 GATED UHA_PROMNOREC, default-OFF] the warm-up of promotion replays 45 657 symboles via
     * `ppm_rec1_apply` -> `rec_globals` ; the legacy engine restores c4g/dcg/a8g autour of ses calls
     * (0x417396/0x418f80). Test : geler rec_globals during there promotion. */
    { static int pn = -1;
      if (pn < 0) { const char *e = getenv("UHA_PROMNOREC"); pn = (e && e[0] != '0') ? 1 : 0; }
      g_promo_silent = pn; }
    saved_dc = m->dcg;
    saved_c4 = m->c4g;
    saved_a8 = m->a8g;
    old_pos = m->win_pos;
    for (i = 0; i <= 255; i++)
        saved[i] = m->window[(old_pos + (uint32_t)i) & m->win_mask];
    start_pos = (old_pos + 0x140) & m->win_mask;
    half = (m->win_wrap - 0x140) >> 1;
    read_pos = (start_pos + half) & m->win_mask;
    if (half > m->last_ctx)
        read_pos = 0;
    write_pos = start_pos;
    ppm_detr_init(&d);
    while (read_pos != old_pos) {
        count = 0;
        ppm_detr_emit(&d, m->window[read_pos], 0, PPM_M32, PPM_M32, expanded, &count);
        for (j = 0; j < count; j++) {
            m->window[write_pos] = (uint8_t)~expanded[j];
            write_pos = (write_pos + 1) & m->win_mask;
            if (write_pos == read_pos)
                break;
        }
        if (write_pos == read_pos)
            break;
        read_pos = (read_pos + 1) & m->win_mask;
    }
    m->win_pos = write_pos;
    for (i = 0; i <= 255; i++)
        m->window[(write_pos + (uint32_t)i) & m->win_mask] = saved[i];
    for (i = 1; i <= 0x40; i++)
        m->window[(start_pos - (uint32_t)i) & m->win_mask] = 0;
    memcpy(m->window + m->win_wrap, m->window, 0x100);
    quarter_rec1(m);
    memset(m->rec2s, 0, (size_t)PPM_REC2_COUNT * sizeof(ppm_rec2));
    for (i = 0; i < PPM_HASH_COUNT; i++) {
        m->ht1_pos[i] = PPM_M32;
        m->ht1_ctx[i] = PPM_M32;
        m->ht2_new[i] = PPM_M32;
        m->ht2_prev[i] = PPM_M32;
        m->len_tab[i] = 0;
        m->link_tab[i] = 0;
    }
    m->roll_ctx0 = 0;
    m->roll_ctx1 = 0;
    m->roll_ctx2 = 0;
    m->flag393b = 0;
    warm_pos = start_pos;
    stop_pos = PPM_M32;
    if (((m->win_pos + m->win_wrap - start_pos) & m->win_mask) > 0x8000)
        stop_pos = (m->win_pos - 0x8000) & m->win_mask;
    while (warm_pos != m->win_pos) {
        h1 = ((m->roll_ctx0 >> 13) ^ m->roll_ctx0) & 0x3FFFF;
        h2 = ((((m->roll_ctx0 >> 15) ^ m->roll_ctx0) << 4) ^
              (((m->roll_ctx1 >> 15) ^ m->roll_ctx1) << 6) ^
              ((m->roll_ctx2 >> 15) ^ m->roll_ctx2)) & 0x3FFFF;
        m->ht2_prev[h2] = m->ht2_new[h2];
        m->ht2_new[h2] = warm_pos;
        m->ht1_pos[h1] = warm_pos;
        m->ht1_ctx[h1] = m->roll_ctx0;
        if (warm_pos == stop_pos)
            stop_pos = PPM_M32;
        if (stop_pos == PPM_M32) {
            ctx = m->roll_ctx0;
            index = ((ctx >> 13) ^ ctx) & 0x7FFF;
            while (index < 0x40000) {
                if (m->rec1s[index][0] == 0) {
                    index += 0x40000;
                    break;
                }
                if (((uint32_t)m->rec1s[index][0x1C]
                    | ((uint32_t)m->rec1s[index][0x1D] << 8)
                    | ((uint32_t)m->rec1s[index][0x1E] << 16)
                    | ((uint32_t)m->rec1s[index][0x1F] << 24)) == ctx)
                    break;
                index += 0x8000;
            }
            m->c48 = ctx;
            m->c38 = index;
            if (index < 0x40000) {
                m->c1c = m->rec1s[index][0];
                for (i = 1; i <= 12; i++)
                    m->c1c += m->rec1s[index][i];
                c1c_idx = index;
                c1c_tot = m->c1c;
                c1c_ctx = ctx;
            }
            ppm_rec1_apply(m, m->window[warm_pos], index, 0xFF);
        }
        m->roll_ctx2 = (m->roll_ctx2 << 8) | (m->roll_ctx1 >> 24);
        m->roll_ctx1 = (m->roll_ctx1 << 8) | (m->roll_ctx0 >> 24);
        m->roll_ctx0 = (m->roll_ctx0 << 8) | m->window[warm_pos];
        warm_pos = (warm_pos + 1) & m->win_mask;
    }
    m->dcg = saved_dc;
    m->c4g = saved_c4;
    m->a8g = saved_a8;
    seed_prob_tables(m);
    g_promo_silent = 0;
    c1c_probe("out", m, c1c_idx);
    if (c1c_idx != PPM_M32) {
        static int on2 = -1;
        if (on2 < 0) { const char *e = getenv("UHA_C1C"); on2 = (e && e[0] != '0') ? 1 : 0; }
        if (on2)
            fprintf(stderr, "[C1C] last idx=%u ctx=%08x tot=%u\n",
                    (unsigned)c1c_idx, (unsigned)c1c_ctx, (unsigned)c1c_tot);
    }
    m->e0_blk_len = PPM_M32;
    m->byte_class = 1;
    /* [GATED UHA_C40PROMO, defautOFF, M207] there promotion legacy recalcule the context roulant then
     * `[0x481c40] = (c48 & 0xFFFF) + 0x10000` then that `bc` is STILL 0 ; at nous `c40` restait
     * the one of the last literal of the block previous (measured 117 446 au lieu of 120 272 at the input of the block 2). */
    { static int cp = -1;
      if (cp < 0) { const char *e = getenv("UHA_C40PROMO"); cp = (e && e[0] != '0') ? 1 : 0; }
      if (cp)
          m->c40 = (m->c48 & 0xFFFFu) + 0x10000u; }
}
