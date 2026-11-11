#ifndef UHA_ALZ_PRIV_H
#define UHA_ALZ_PRIV_H

#include <stdint.h>
#include <stddef.h>
#include "rangecoder.h"
#include "alz_tables.h"

#define ALZ_INIT_PROB     2048
#define ALZ_FIXED_SCALE   4096
#define ALZ_MAX_RECENT    12
#define ALZ_BM_NCTX       0x420
#define ALZ_FAST          1
#define ALZ_NORMAL        2
#define ALZ_BEST          3

typedef struct {
    int      method_class;
    uint32_t dict_size;
    uint32_t dict_mask;
    uint32_t rebuild_period;
} alz_mode;

typedef struct {
    uint8_t  last_byte;
    uint8_t  prev_byte;
    uint8_t  prev_delta;
    uint8_t  match_flag_byte;
    uint8_t  literal_mode;
    uint32_t repeat_run;
    uint32_t output_pos;
    uint32_t window_pos;
    uint32_t rolling_history;
    uint8_t  last_match_tail;
    uint32_t range_model_epoch;
    uint8_t  escape_selector;
    int      escape_changed;
    uint8_t  escape_model_flag;
    uint8_t  escape_literal_bias;
    uint32_t side_primary;
    uint32_t side_secondary;
    uint8_t  side_bias;
    uint8_t  side_dir;
    int      bm_side_active;
    uint32_t side_mod_count;
    uint32_t slot_hash[16];
    uint32_t slot_hash74[16];
    uint32_t slot_hash78[16];
    uint8_t  slot_dir[16];

    int32_t  mm_hist[10][5];
    int32_t  mm_coef[10][5];
    int32_t  mm_last[10];
    int32_t  mm_delta[10];
    int32_t  mm_acc[10][11];
    int32_t  mm_cost5c[10];
    int32_t  mm_cost60[10];
    int32_t  mm_cost64[10];
    int32_t  mm_cost68[10];
    uint32_t mm_counter[10];
    int32_t  mm_global;
    int32_t  mm_global2;
    int32_t  mm_prev_score;
    uint32_t mm_out_count;

    int32_t  cand_acc[124];
    int32_t  delta_ring[128];
    int32_t  cand_score[6];
    int32_t  cand_best0;
    int32_t  cand_best1;
    int32_t  cand_best2;
    int32_t  cand_cur;
    int32_t  cand_prev;
    int32_t  res_bank[6][257];

    int32_t  s3_counter[8];
    uint8_t  s3_pred_tab[8];
    int32_t  s3_streak;
    uint8_t  s3_idx;
    uint8_t  s3_active;
    uint8_t  s3_dir_saved;
    uint32_t recent_distance[ALZ_MAX_RECENT];
} alz_state;

typedef struct {
    uha_rc   rc;
    uha_rcw *w;
    alz_mode mode;
    alz_state st;
    uint8_t *window;
    uint8_t *out;
    size_t   outlen;

    uint16_t token_class[66][6];
    uint16_t literal_adjust[1036];
    uint16_t length_tree[32768];
    uint16_t distance_tree[3076];
    uint16_t dist_slot_fast[64];
    uint16_t dist_slot_normal[128];
    uint16_t length_by_bucket[6][64];
    uint8_t  token_history[65536];
    uint8_t  length_history[262144];
    uint16_t long_distance_bit;

    uint16_t bm_tree[ALZ_BM_NCTX][256];
    uint16_t bm_freq[ALZ_BM_NCTX][256];
    uint16_t bm_ew[ALZ_BM_NCTX];
    uint32_t bm_counter[ALZ_BM_NCTX];
    uint32_t bm_mixer;
    uint32_t bm_acc80, bm_acc8c, bm_acc90;
    uint32_t bm_table[256];
    uint8_t  bm_pcounter;
    uint8_t  bm_flag;
    uint8_t  bm_predb;
    int      bm_esc_ctx;

    uint16_t m_slot_short[64];
    uint16_t m_slot_long[64];
    uint16_t m_low_bit;
    uint16_t m_length[8192];
    uint8_t  m_len_pred[0x40000];

    uint8_t *in_chain;
    int      trign;
    uint32_t *bst_head;
    uint32_t *bst_tree;
    uint32_t  bst_fed;
    uint32_t  bst_max_dist;
    int       bst_depth_limit;
    uint32_t  bst_last_p;
    uint32_t  bst_last_b8;
    uint32_t  bst_last_slen[256];
} alz_dec;

void alz_state_reset(alz_state *s);
void alz_remember_distance(alz_state *s, uint32_t dist);
uint32_t alz_recall_distance(alz_state *s, int slot);

void alz_reset_byte_model(alz_dec *d);
void alz_reset_match_model(alz_dec *d);
void alz_reset_models(alz_dec *d);
void alz_rebuild_block_model(alz_dec *d);
void alz_bm_rescale_entry(alz_dec *d, int ctx);
void alz_bm_rescale_ctx2(alz_dec *d, int ctx);

void alz_apply_escape(alz_dec *d, int selector);
void alz_handle_escape(alz_dec *d);
int  alz_encode_escape(alz_dec *d, int selector);
int  alz_decode_token_class(alz_dec *d);
int  alz_encode_token_class(alz_dec *d, int result);
void alz_update_literal_mode(alz_dec *d, int decoded_class);
void alz_rebuild_block_model_core(alz_dec *d);

void alz_put_byte(alz_dec *d, uint8_t b);
uint8_t alz_prev_byte(alz_dec *d, uint32_t distance);
void alz_copy_match(alz_dec *d, uint32_t distance, uint32_t count);
uint8_t alz_src_after_match(alz_dec *d, uint32_t dist, uint32_t count,
                            uint32_t win_pos_before);
uint16_t alz_src_pair_key(alz_dec *d, uint32_t distance);

int  alz_bm_decode_literal(alz_dec *d, int ctx, int ctx2);
int  alz_bm_encode_literal(alz_dec *d, int ctx, int ctx2, int sym);
uint32_t alz_bm_predict_cost(alz_dec *d, int ctx, int ctx2, int sym);
uint32_t alz_bm_literal_cost_mix(alz_dec *d, int ctx, int ctx2, int sym);
uint32_t alz_bm_literal_cost_warm(alz_dec *d, const uint8_t *plain,
                                  uint32_t usize, uint32_t pos, uint32_t len);
/* [RE b3a] Estimateur de cout-match FIDELE (lecture-seule, unites 4680*bits,
 * miroir des uha_rcw_encode du codage reel) + enveloppe read-only du index de
 * classe de token. Retourne ~0u si le token n'est pas codable. */
int      alz_token_class_index_ro(alz_dec *d);
uint32_t alz_match_model_cost(alz_dec *d, int token, uint32_t dist,
                              uint32_t count);
uint8_t alz_decode_literal(alz_dec *d);
int  alz_encode_literal(alz_dec *d, uint8_t b);
uint8_t alz_side_decode_literal(alz_dec *d);
int  alz_side_encode_literal(alz_dec *d, uint8_t b);
void alz_side_post_update(alz_dec *d, uint8_t output_byte);

int  alz_m_decode_match(alz_dec *d, int token, uint32_t *dist, uint32_t *count);
int  alz_m_can_encode_match(alz_dec *d, int token, uint32_t dist, uint32_t count);
int  alz_m_encode_match(alz_dec *d, int token, uint32_t dist, uint32_t count);
int  alz_decode_item(alz_dec *d);

#endif
