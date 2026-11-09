#ifndef UHA_PPM_PRIV_H
#define UHA_PPM_PRIV_H

#include <stdint.h>
#include <stddef.h>
#include "rangecoder.h"
#include "ppm_tables.h"

#define PPM_NUM_CTX     0x400
#define PPM_MAX_EXCL    23
#define PPM_REC1_COUNT  0x40000
#define PPM_REC2_COUNT  0x20000
#define PPM_HASH_COUNT  0x40000
#define PPM_M32         0xFFFFFFFFu
#define PPM_M16         0xFFFFu
#define PPM_SSE_TOTAL   0x2000u
#define PPM_BC1_LVLBYTES 0x400000

#define PPM_OK           0
#define PPM_ERR_ORDER   -1
#define PPM_ERR_CORRUPT -2
#define PPM_ERR_OUTSPACE -3
#define PPM_ERR_NOMEM   -4

typedef uint16_t ppm_fenwick[256];
typedef uint8_t  ppm_rec1[32];
typedef uint8_t  ppm_rec2[20];

typedef struct {
    uint8_t flag;
    uint8_t arg;
} ppm_detr;

typedef struct {
    int32_t mm_hist[1][5];
    int32_t mm_coef[1][5];
    int32_t mm_last[1];
    int32_t mm_delta[1];
    int32_t mm_acc[1][11];
    uint32_t mm_counter[1];
    uint32_t slot_hash[1];
    uint32_t slot_hash74[1];
    uint32_t slot_hash78[1];
    int32_t cand_acc[124];
    int32_t delta_ring[128];
    int32_t cand_score[6];
    int32_t cand_best0, cand_best1, cand_best2, cand_cur, cand_prev;
    int32_t res_bank[6][257];
} ppm_mm6;

typedef struct {
    int32_t hist[4][5];
    int32_t coef[4][5];
    int32_t last[4];
    int32_t delta[4];
    uint32_t acc[4][11];
    uint32_t cost[4], last_cost[4], prior_cost[4], prior_last_cost[4], counter[4];
    uint32_t hash[4], hash74[4], hash78[4];
    uint8_t direction[4];
    int32_t global_delta, delayed_delta, prev_score;
    uint8_t sample_class;
} ppm_mm7;

typedef struct {
    uint8_t *lvl;
    uint8_t ring[0x80];
    uint8_t conf[0x100];
    uint8_t pred[0x100];
    uint32_t ctx[8];
    uint8_t win[0x1000];
    uint32_t wpos;
    int ring_ptr;
    int ring_flag;
    int best;
    uint8_t best_pred;
    uint8_t best_flags;
    uint8_t best_c0;
    uint8_t best_c1;
    int fired393c;
    int last_best;
} ppm_bc1;

typedef struct {
    ppm_fenwick *cum;
    ppm_fenwick *freq;
    uint16_t *ent_wt;
    uint32_t *order0_wt;
    uint32_t *sse_prob;
    uint32_t *sse2;
    uint8_t  *pred_byte;
    uint8_t  *cls_idx;
    uint32_t *wtab;
    uint32_t *recency;
    uint32_t *last_sym;
    uint8_t  *novel;
    uint16_t *f154;
    uint8_t   excl[PPM_MAX_EXCL];
    int       nexcl;
    int       work_ctx;
    uint8_t   byte_class;
    uint32_t  last_ctx;
    uint32_t  win_pos;
    ppm_detr  detr;
    uint32_t  detr_thr1;
    uint32_t  detr_thr2;
    uint32_t  out_count;
    uint32_t  c38, c44, c48, c4c, c50, c54;
    uint32_t  bfc, bec;
    uint8_t   s41, s45, s47, s48, s49;
    uint32_t  rank_ptr_small, rank_ptr_large;
    uint32_t  rank_small[0x109];
    uint32_t  rank_large[0x187];
    uint32_t  rank_small_base[5];
    uint32_t  rank_large_base[0x11];
    uint32_t  age, age_ctr;
    uint32_t  age_ring[256];
    uint32_t  rec_a[4], rec_b[4];
    uint32_t  roll_ctx0, roll_ctx1, roll_ctx2;
    uint8_t  *window;
    uint32_t  win_mask, win_wrap;
    uint32_t  hist[256];
    uint32_t  br10, br14, br18, brf0;
    uint8_t   flag3939;
    uint8_t   marker_c[4];
    uint8_t   marker_fl;
    uint8_t  *ring_buf;
    uint32_t  ring_off[4];
    uint32_t *budget;
    uint16_t *tstep;
    uint16_t *tstep2;
    uint8_t   flag3934;
    uint32_t  cls_ctx, cls_stride;
    uint8_t   cls_shift;
    ppm_mm6   mm6;
    ppm_mm7   mm7;
    uint8_t   cls_flag31;
    uint32_t  cls_phase;
    uint8_t   cls_base, cls_neg;
    uint32_t  cls3_confidence[6];
    uint8_t   cls3_pred[6];
    uint8_t   cls3_index, cls3_active, cls3_saved_neg;
    uint32_t  cls3_streak;
    uint32_t  wp_a, wp_b, wp_acc_add;
    int       wp_pend;
    int       wp_class_selected, wp_armed, wp_engaged;
    uint32_t  wp_kernel_weight;
    uint8_t   flag393c;
    uint32_t  c58;
    uint16_t  lzp_class_rec[256][4];
    ppm_rec1 *rec1s;
    ppm_rec2 *rec2s;
    uint32_t *ht1_pos, *ht1_ctx, *ht2_new, *ht2_prev;
    uint8_t  *len_tab, *link_tab;
    uint32_t  link_ptr;
    uint32_t *esc_mass, *pred_prob, *entry_prob, *len_prob;
    uint32_t *rw_a, *rw_b, *rw_c, *rw_e;
    uint32_t *r2_a, *r2_b, *r2_e, *r2_esc;
    uint32_t *t46a;
    uint32_t  c1c, c20, c24, c28;
    uint32_t  d4, d8, b8;
    int       has_cont;
    uint32_t  cont_ofs;
    uint32_t  c4g, dcg, a8g;
    uint32_t  e0_blk_len, blk_len4;
    uint8_t   base46;
    uint32_t  c40, c3c;
    uint8_t   flag3938, flag393b, flag3943, s3e;
    uha_rcw  *w;
} ppm_model;

typedef struct {
    uint32_t weight;
    uint32_t last_total;
    int sse2_idx;
    int sse2_up_idx;
    int kernel_excl;
    int supported;
} ppm_kstate;

typedef struct {
    int is_match;
    int lzp_ctx;
    int lzp_cls;
    int raw_len;
    uint8_t raw_syms[256];
} ppm_match;

typedef struct {
    int sym;
    int supported;
    int kctx;
    int work_ctx;
    uint32_t weight;
    int sse2_idx;
    int sse2_up_idx;
    int kernel_excl;
    int path_a;
} ppm_c550;

typedef struct {
    uint32_t acc_add;
    int sse_idx;
    uint32_t sse_val;
    int excl;
} ppm_d390;

enum {
    CR_ORDER1_HIT = 0,
    CR_PREDICTED_HIT,
    CR_REC2_HIT,
    CR_ENTRY_HIT,
    CR_C550
};

extern ppm_bc1 ppm_bc1_st;
extern int ppm_bc1_ring_ran;
extern int ppm_bc1_post_armed;
extern int ppm_bc1_rec_ok;
extern int ppm_bc1_f154_pending;
extern uint32_t ppm_bc1_f154_key;

uint32_t ppm_window_size(int order);
int  ppm_model_alloc(ppm_model *m, int order);
void ppm_model_free(ppm_model *m);
void ppm_read_block_header(ppm_model *m, uha_rc *r);
void ppm_write_block_header(ppm_model *m, uha_rcw *w);
int  ppm_block_reset(ppm_model *m, uha_rc *r);
int  ppm_block_reset_encode(ppm_model *m);
void ppm_promote_to_bc1(ppm_model *m);
int  ppm_select_class(ppm_model *m, int cls);

void ppm_detr_init(ppm_detr *d);
void ppm_detr_emit(ppm_detr *d, uint8_t sym, uint32_t count,
                   uint32_t thr1, uint32_t thr2, uint8_t *outp, int *outlen);
int  ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                      uint8_t *out, uint32_t *nout);
int64_t ppm_lenb_sym_bound(void);   /* [UHA_LENBOUND] bound win_pos of the member, -1 = OFF */
void ppm_rec_globals_pub(ppm_model *m);   /* [M216] acces au jumeau `rec_globals` (tests gated) */

int  ppm_fenwick_bsearch(const uint16_t *row, uint32_t total, uint32_t freq, uint32_t *rem);
int  ppm_fenwick_mixsearch(const uint16_t *row, const uint16_t *freq_row,
                           uint32_t total, uint32_t freq,
                           const uint8_t *excl, int nexcl, uint32_t *rem);

uint32_t ppm_halve_rebuild(ppm_model *m, int ctx);
void ppm_apply_fenwick(ppm_model *m, int sym, int order);
void ppm_t268_rescale(ppm_model *m, int ctx_idx);
void ppm_apply_t268(ppm_model *m, int sym, int ctx_idx);
void ppm_apply_literal_updates(ppm_model *m, int entry_ctx, int next_ctx, int sym);

int  ppm_kernel_decode(ppm_model *m, uha_rc *r, int ctx, ppm_kstate *ks);
int  ppm_kernel_encode(ppm_model *m, int ctx, int sym, ppm_kstate *ks);

void ppm_mm6_reset(ppm_mm6 *s);
void ppm_mm6_update(ppm_mm6 *s, uint8_t out_byte, uint8_t delta_byte, uint32_t position);
void ppm_mm6_predict(ppm_mm6 *s, uint32_t position, uint8_t *base_byte, uint32_t *context);

void ppm_mm7_reset(ppm_mm7 *s, uint8_t cls);
void ppm_mm7_update(ppm_mm7 *s, uint32_t slot, uint8_t out_byte, uint8_t delta_byte, uint8_t neg);
void ppm_mm7_predict(ppm_mm7 *s, uint32_t slot, uint8_t *base_byte, uint8_t *neg, uint32_t *context);

void ppm_bc1_reset(void);
void ppm_bc1_block_reset(void);
int  ppm_bc1_predecode(ppm_model *m, uint32_t r0, uint32_t r1);
void ppm_bc1_ring_masses(const uint32_t *w, const uint8_t *y, uint32_t *m0, uint32_t *m1);
int  ppm_bc1_ring_decode(uha_rc *r, uint32_t m0, uint32_t m1);
int  ppm_bc1_ring_encode(ppm_model *m, uint32_t m0, uint32_t m1, int hit);
void ppm_bc1_post_update(ppm_model *m, uint8_t sym);
void ppm_bc1_sub2_update(uint8_t ctx_byte, uint8_t sym);
void ppm_bc1_push_window(uint8_t sym);

int  ppm_lzp_decode_class(ppm_model *m, uha_rc *r, int ctx_byte);
int  ppm_lzp_encode_class(ppm_model *m, int ctx_byte, int cls);
/* [M169] escape of class (0x421dd8) : [rec0,rec1)/rec3 then sel/10 then select_class(sel).
 * returns sel, now -1. There class of the node remainder has encoder by the stream normal. */
int  ppm_lzp_encode_escape(ppm_model *m, int ctx_byte, int sel);
void ppm_lzp_apply_update(ppm_model *m, int ctx_byte, int cls);

void ppm_matchfinder_decode(ppm_model *m, uha_rc *r, uint8_t *raw_syms, ppm_match *mr);
int  ppm_matchfinder_encode(ppm_model *m, ppm_match *mr,
                            const uint8_t *syms, uint32_t nsyms,
                            uint32_t in_pos);
void ppm_matchfinder_literal_tail(ppm_model *m);
void ppm_lzp_nomatch_tail(ppm_model *m);
/* [M170] node literal of the matchfinder : cut of block + selection + ESCAPE, has to call
 * BEFORE ppm_lzp_encode_class(ctx, 2) (order of legacy 0x421973 -> 0x421dd8 -> 0x4219a1,
 * and order of reading of the decodeur escape -> sel -> class). Gated UHA_BLKLAW>=3. */
int  ppm_blk_node_encode(ppm_model *m, uint32_t start, int lzp_ctx);

void ppm_rec1_apply(ppm_model *m, int sym, uint32_t c38, int s47_hint);
void ppm_rec2_apply_heavy(ppm_model *m, int sym);
void ppm_rec2_apply_light(ppm_model *m, int sym);

int  ppm_ctx_res(const ppm_model *m);
int  ppm_predicted_decode(ppm_model *m, uha_rc *r, uint32_t rec1_idx, int *sym);
int  ppm_predicted_encode(ppm_model *m, uint32_t rec1_idx, int target, int *sym);
int  ppm_entry_decode(ppm_model *m, uha_rc *r, uint32_t rec2_idx, uint32_t *prob_out);
int  ppm_entry_encode(ppm_model *m, uint32_t rec2_idx, int target, uint32_t *prob_out);

int  ppm_rw1_decode(ppm_model *m, uha_rc *r, uint32_t rec1_idx, uint32_t rec2_idx,
                    int ctx28, int *sym);
int  ppm_rw1_encode(ppm_model *m, uint32_t rec1_idx, uint32_t rec2_idx,
                    int ctx28, int target, int *sym);
void ppm_rec2_total_flags(ppm_model *m, uint32_t rec2_idx, uint8_t *rec,
                          int *active_count, uint8_t *flags, uint32_t *total);
int  ppm_rw2_decode(ppm_model *m, uha_rc *r, uint32_t rec2_idx, int sel_hint, int *sym);
int  ppm_rw2_encode(ppm_model *m, uint32_t rec2_idx, int sel_hint, int target, int *sym);

void ppm_recency_update(uint32_t *tbl, int flag, uint32_t bec);
void ppm_agering_commit(ppm_model *m, int idx, uint32_t bec);
void ppm_update_predbyte(ppm_model *m, int ctx, int sym);
void ppm_update_rolling_ctx(ppm_model *m, int sym);

void ppm_marker_machine(ppm_model *m, int sym);
void ppm_rank_machinery(ppm_model *m, int sym);
void ppm_ring_recompute(ppm_model *m);
void ppm_ring_store(ppm_model *m, int sym);
void ppm_lastsym_predict(ppm_model *m);

ppm_d390 ppm_d390_update(ppm_model *m, int ctx, int sym);
int  ppm_c550_decode(ppm_model *m, uha_rc *r, int ctx, int next_ctx, ppm_c550 *res);
int  ppm_c550_encode(ppm_model *m, int ctx, int next_ctx, int target, ppm_c550 *res);

int  ppm_ctx_resolution(const ppm_model *m);
void ppm_update_head_rank_ptrs(ppm_model *m);
int  ppm_predbyte_gate(const ppm_model *m);
int  ppm_window_predictor_gate(const ppm_model *m);
void ppm_literal_decay_c54(ppm_model *m);
void ppm_post_symbol_maintenance(ppm_model *m, int sym, int dl);
/* [M170k] machine of CONTEXT single (scan of cost 0x423650/0x4232a0) : rolling ctx +
 * cls_delta_update + cls_phase_update, without the updates which write in `m->w`. */
void ppm_scan_step(ppm_model *m, int sym);
void ppm_scan_step_sym(ppm_model *m, int raw, int sym);   /* [M279] raw=rolling ctx, sym=delta */
void ppm_match_maintain(ppm_model *m, int sym, int dl, uint8_t *outp, int *outlen);
void ppm_emit_and_maintain(ppm_model *m, int sym, uint8_t *outp, int *outlen,
                           int pb_gate, int light, int clear_s47, int decay_c54,
                           int record_s47, int rec2_update, int rec2_before, int run_rec1);
void ppm_rec2_reweight_post(ppm_model *m, int sym, uint8_t *outp, int *outlen, int pb_gate);
void ppm_c550_post(ppm_model *m, int ctx, int sym, int kctx,
                   uint8_t *outp, int *outlen, int pb_gate, int age_idx,
                   int sse2_idx, uint32_t kernel_weight, int sse2_up_idx,
                   int exact_order_loop, int wp_ctx, int wp_delta, int wp_fired,
                   int wp_base, int wp_work, int wp_mirror, int wp_armed, int nf_dec_ctx);

int  ppm_decode_literal_cascade(ppm_model *m, uha_rc *r, uint8_t *outp, int *outlen,
                                int *route, int *sym);
int  ppm_encode_literal_cascade(ppm_model *m, uint8_t *outp, int *outlen,
                                int target, int *route, int *sym);

static inline uint32_t ppm_f154_2(const ppm_model *m, uint32_t key)
{
    return m->f154[key & 0x3FFFu] & 0xFFFFu;
}

static inline uint32_t ppm_f154_4(const ppm_model *m, uint32_t key)
{
    return m->f154[(key * 2) & 0x3FFFu] & 0xFFFFu;
}

static inline int ppm_in_excl(const uint8_t *excl, int nexcl, uint8_t sym)
{
    int i;
    for (i = 0; i < nexcl; i++)
        if (excl[i] == sym)
            return 1;
    return 0;
}

static inline void ppm_append_excl(ppm_model *m, uint8_t symb)
{
    m->excl[m->nexcl] = symb;
    m->nexcl++;
}

static inline uint32_t ppm_lowbit(uint32_t al)
{
    return ((0u - al) & al) & 0xFFu;
}

static inline int32_t ppm_sext8(uint8_t b)
{
    return (b & 0x80) ? (int32_t)b - 256 : (int32_t)b;
}

#endif
