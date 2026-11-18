/* UHARC 0.4 decompressor core 5 (methods 40..87) - portable C89 port.
 *
 * Ported from the UHARC04.lst disassembly of the UHARC 0.4 BETA decoder
 * (the Hex-Rays UHARC04.c output was used only as a map; control flow and
 * constants come from the listing).  The 0.4 core-5 codec is NOT the 0.3
 * core-5 codec: 0.4 uses the 0.4 range-coder family (5-byte init,
 * renormalise below 0x1000000), a 1041-context PPM model with one escape
 * weight per context, a 5-way literal/match decision model and 12-entry
 * distance classes.  The 0.6 core-5 codec is a descendant of this one
 * (same helper layout, same price heuristics, plus a length predictor).
 *
 * Original -> port mapping (UHARC04.lst):
 *   sub_40E380 (init)              -> uharc_dec5v_init
 *   sub_40EAB0 (free)              -> uharc_dec5v_free
 *   sub_40F530 (main loop)         -> uharc_dec5v_decode
 *   sub_40EB70 (block/group start) -> d5v_block_start
 *   sub_40FB80 (step: match/lit)   -> d5v_step
 *   sub_40FDB0 (decision model)    -> d5v_decision
 *   sub_40F580 (distance+length)   -> d5v_match
 *   sub_410010 (literal)           -> d5v_literal
 *   sub_410130 (context literal)   -> d5v_lit
 *   sub_410440 (PPM symbol)        -> d5v_sym
 *   sub_410990 (PPM price)         -> d5v_price
 *   sub_40EFE0 (count update)      -> d5v_update
 *   sub_40EE90 (context rescale)   -> d5v_rescale
 *   sub_40F110 (decision rescale)  -> d5v_drescale
 *   sub_40F190 (decision update)   -> d5v_dupdate
 *   sub_40F240 (ctx update g1..g4) -> d5v_ctxupd
 *   sub_40F500 (ctx update g0)     -> d5v_ctxupd0
 *   sub_4220B0 (input byte)        -> d5v_get
 *   sub_4221F0 (output byte)       -> d5v_put
 *   sub_422430 (output run)        -> d5v_putrun
 *   sub_426F30 (coder init)        -> d5v_rc_init
 *
 * Model layout (DGROUP in the original):
 *   0x4312B8  fen  1041 x 256 u16  Fenwick tree, word[0] = total
 *   0x4312BC  cnt  1041 x 256 u16  counts
 *   0x4312C4  ext  1027 u16        escape weight per context
 *   0x4312D0  lastctx 64K          low 16 bits of history -> decision ctx
 *   0x4312D8  win2 128K            predictor: predicted length symbol
 *   0x4312DC  wcnt 128K            predictor: confidence
 *   0x44C0F8  litm 396 x 6 u16     decision model (5 symbols)
 *   0x433734  mru 12 u32           recent distances
 *   0x437968  price 16K u16        16-bit log price table (prefix sums)
 *
 * Groups (byte_44D907): 0 = order-0 literal; 1..4 = per-position literal
 * contexts; 5..9 = byte-predictor groups (sub_414470 predict /
 * sub_414820 train); 10 = "reset and use group 0".
 * The 0.4 test modes (methods 43/59/75) decode in group 0 (method 43
 * first selects group 10, which resets the order-1 contexts to group 0).
 * Groups 5..9 use the 0.4 byte predictor: groups 5/6 are the short-range
 * linear predictor (one rate context, literal context 993..1000), groups
 * 7/8/9 are the long-range SSE variant with 2/2/4 interleaved rate
 * contexts (31 ints each) and literal contexts 1001..1016.  The predictor
 * state is zeroed whenever a group > 4 starts (sub_414420).
 *
 * STATUS (byte-exact for the uha04.UHA, 04_m1/m2/m3 and gmud-04m3 oracles):
 *  - The coder, the 1041-context PPM model, the 5-way decision model, the
 *    match/distance/length decoder, the 11-way group selector and the
 *    group 0..9 context selection / byte predictor are ported and compile
 *    cleanly (-std=c89 -pedantic).
 *  - uha04.UHA (method 62, ALZ:2): all 8 files / 43307 bytes match the
 *    native UHARC04.EXE extraction byte-for-byte (the stream selects
 *    groups 0, 10->0, 2 and 5).
 *  - 04_m1.uha (43), 04_m2.uha (59) and 04_m3.uha (75) each expand to the
 *    full 5840-byte corpus with all five CRCs matching; the 298 one/two
 *    byte oracles made by UHARC04.EXE and the generated 3..24 byte vectors
 *    also decode exactly.
 *  - gmud-04m3.uha (method 87, 32 MB dictionary, 44 files, 33705622 bytes):
 *    all 44 per-file CRCs OK and `x` is byte-identical to the native
 *    UHARC04.EXE extraction.  The stream selects groups 0/2/3/6/8, runs
 *    26 blocks (25 model resets) and therefore needs the container block
 *    table (see decode_b).
 *  - The distance class tables have 44 entries (classes 0..43), not 12;
 *    12 is only the range used by short/early streams.  Truncating them
 *    was the reason a first-class-12 match desynchronised the stream.
 *  - Details that matter for exactness (all verified against the original
 *    decoder under gdb):
 *      * block start zeroes fen/cnt for contexts 0..768 only, sets
 *        ext[0..768]=1, halves the 66 decision models 0..65, rescales
 *        contexts 769..1040 (which also halves the seeded uniform models
 *        1027..1040 from count 8 to 4) and sets all 256 hist410 entries to
 *        37440 (the first literal therefore stays below the uniform-mode
 *        threshold and is PPM-coded).
 *      * word_44D0F4 / word_44C8EE are nominally filled with 33/15, but
 *        later DGROUP initialisers overwrite parts of them, so the values
 *        the decoder really uses are 33 (10 for 1009..1016, 44 for
 *        1017..1026) and 15 (6 for context 768, 8 for 993..1016).  The
 *        768 / 1025 weights drive the literal escape and length models.
 *      * several tables in the executable are patched at initialisation
 *        time and differ from the raw DGROUP image: dbase = 1,2,4,8,...,
 *        drange[0]=1, mrate[0]=1, lenbase[0]=2, lenbits[24]=2 and
 *        stt[0]=0x10.
 *      * the literal decision between "direct" and "escape" coding compares
 *        the running prices p894/p890; both paths update the same two
 *        models, and the direct path also adds its context price to p880.
 *      * the group 5/6 predictor runs a six-order cost loop whose
 *        dword_445AD4[257*order] operand aliases its own running sum; the
 *        greedy comparison starts from order 0 on every call, so the order
 *        can move.  dword_431928[order] (0x7F for 0..3, 7 for 4, 3 for 5)
 *        paces the short-period order search that fills pred2a4/2a8.
 *      * sub_414420 (predictor reset) clears 0x1E40 bytes but then stores
 *        2 in dword_4452A8 and seeds the [28..30] sentinels of the four
 *        31-dword records (pred43[28..30], [59..61], [90..92], [121..123])
 *        with -1.  pred2a8 selects pred4bc[] and is live before the first
 *        order search of a block.
 *      * the long-path error accumulators pred43[23]/[24] are decayed by
 *        pred43[25]/[26] only when the whole low byte of pred43[27] is 0
 *        (`test byte ptr [edx+6Ch],0FFh`), i.e. every 256 calls; 16 is the
 *        cadence of the coefficient nudge only.
 *      * a group switch must not clear dword_4312D4 (last decided-context
 *        byte): only sub_40F190 clears it after consuming it.  Clearing it
 *        in the group switch silently loses decision-history updates.
 *
 * Blocks: sub_40EB70 advances dword_44C8A8 by 0x20000, clamps it to the
 * total, then walks the container's cumulative file-end table
 * (dword_44C8D0 / dword_44C8C0) to the first entry >= that value and makes
 * it the new block end.  uharc_dec5v_decode() keeps the old single-block
 * behaviour; uharc_dec5v_decode_b() takes that table and reproduces the
 * resets.  The container must pass it (see uharc_dec_decode_b).
 *
 * Return codes: 0 ok, 1 bad args, 2 nomem, 3 input short, 4 output error,
 * 7 data error.
 */

/* ------------------------------------------------------------------------
 * Semantic name map (reading aid; no identifier is renamed).
 *
 * 0.4 core 5 (methods 40..87) is the direct ancestor of 0.6 core 5 (ALZ).
 * The concepts are the same; the names below are the 0.4 DGROUP/register
 * spellings, with the equivalent 0.6 / seb3773 ALZ name on the right.
 *
 *   code, range, ct, clo, chi       range coder: code/range and the current
 *                                    interval [clo,chi) of total `ct`
 *                                    (== 0.6 low/range, f_lo/f_hi/f_total)
 *   fen, cnt, ext, escctx           literal PPM model: Fenwick tree, counts,
 *                                    escape weight, escape/secondary context
 *   s913, s914                      single-byte exclusion flag / symbol
 *                                    (== 0.6 fc2/fc3, alz bm_flag/bm_predb)
 *   litm[], mode, st911             decision model (5 symbols), last decision
 *                                    and decision-history state
 *                                    (== 0.6 state[]/fb1, token class)
 *   group, s910, s90f               escape selector 0..10 (== 0.6 fb8),
 *                                    "selector changed" flag, channel shift
 *   fam                             method family -m1/-m2/-m3 (method/16)
 *   rep, c905, mdist                repeat count, match length, match
 *                                    distance (== 0.6 e84)
 *   mru[], c901                     recent-distance ring, MRU update selector
 *   dprob                           distance-tree probability
 *   c906, s90e, c87c, s90a,
 *   s909, s90d, c8e8[], e8e0[]      multimedia side predictor: predicted
 *                                    byte, sign, rate/channel, slot, crossover
 *                                    flag and saved state (== 0.6 fb7/fbE/p43)
 *   p880, p88c, p890, p894, seq898  running probability->cost accounting
 *                                    (== 0.6 f80a, alz_score_cum)
 *   hist4, pos, wpos, prevb/hasprev byte history, output/window positions,
 *                                    previous byte
 * ------------------------------------------------------------------------ */

#include "simd_kernels.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "uharc_dec.h"

#ifndef U4_DEBUG
#define U4_DEBUG 0
#endif
#if U4_DEBUG
#include <stdio.h>
#endif

int uharc_dec5v_init(void **pctx, int method);
int uharc_dec5v_decode(void *ctx, uharc_dec_read_cb rcb, void *rctx,
                       uharc_dec_write_cb wcb, void *wctx,
                       unsigned long out_len);
int uharc_dec5v_decode_b(void *ctx, const unsigned long *cum,
                         unsigned long ncum,
                         uharc_dec_read_cb rcb, void *rctx,
                         uharc_dec_write_cb wcb, void *wctx,
                         unsigned long out_len);
void uharc_dec5v_free(void *ctx);

#define D5V_M32 0xFFFFFFFFUL
#define D5V_NCTX 1041

/* ------------------------------------------------------------------ */
/* tables extracted from the UHARC04.lst DGROUP image                 */
/* ------------------------------------------------------------------ */
/* generated from UHARC04.lst DGROUP; do not edit */
#define D5V_PRICE_N 16384
static unsigned short d5v_price[16384];
static int d5v_price_ready = 0;

static void d5v_price_init(void)
{
    unsigned int i;
    if (d5v_price_ready)
        return;
    d5v_price[0] = 0u;
    for (i = 1u; i < 16384u; i++)
        d5v_price[i] = (unsigned short)(65520 - (int)ceil(4680.0 * log((double)i) / log(2.0)));
    d5v_price_ready = 1;
}
static const unsigned char d5v_lenbase[256] = {
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x13,
    0x17, 0x1F, 0x2F, 0x3F, 0x5F, 0x7F, 0xBF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0D, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
    0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
    0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
    0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
    0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
};
static const unsigned char d5v_lenbits[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x04,
    0x08, 0x10, 0x10, 0x20, 0x20, 0x40, 0x40, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x13, 0x17, 0x1F, 0x2F, 0x3F, 0x5F, 0x7F, 0xBF, 0xFF,
    0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
    0x0D, 0x0E, 0x0E, 0x0F, 0x0F, 0x0F, 0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x14,
    0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
    0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x16,
    0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
};
static const unsigned char d5v_stt[128] = {
    0x10, 0x10, 0x10, 0x10, 0x11, 0x11, 0x11, 0x11, 0x14, 0x14, 0x14, 0x14, 0x12, 0x12, 0x12, 0x13,
    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
    0x16, 0x16, 0x16, 0x16, 0x18, 0x17, 0x17, 0x18, 0x1B, 0x1B, 0x1B, 0x1B, 0x19, 0x19, 0x19, 0x1A,
    0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C, 0x1C,
    0x1D, 0x1D, 0x1D, 0x1D, 0x1D, 0x1D, 0x1D, 0x1D, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E,
    0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x03, 0x04, 0x04, 0x07, 0x07, 0x05, 0x05, 0x05, 0x06,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x09, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0E, 0x0F, 0x0A, 0x0A, 0x0B,
};
static const unsigned char d5v_ptab[128] = {
    0x00, 0x11, 0x14, 0x14, 0x18, 0x18, 0x1D, 0x1D, 0x23, 0x00, 0x23, 0x00, 0x2A, 0x00, 0x2A, 0x00,
    0x00, 0x32, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x3E, 0x3E, 0x3F, 0x3F,
    0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x08, 0x00, 0x0A, 0x00, 0x0C, 0x00,
    0x00, 0x0E, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x3B, 0x3C, 0x3D, 0x3E,
};
static const unsigned short d5v_lseed0[6] = {
    0x0000, 0x0001, 0x0042, 0x0058, 0x006F, 0x00C7,
};
static const unsigned short d5v_lseed1[6] = {
    0x0000, 0x0001, 0x0037, 0x009B, 0x00B1, 0x00C7,
};
static const unsigned char d5v_g1tab[16] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
};
static const unsigned char d5v_gtab[256] = {
    0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F,
};
static const unsigned char d5v_g3tab[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x16, 0x16, 0x16, 0x17, 0x17, 0x18, 0x18, 0x19, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
/* distance class tables (DGROUP 0x431558 base, 0x4314A8 range): 44
 * classes, not 12.  Classes 0..11 are the ones early/short streams use;
 * larger dictionaries need the long-distance classes 12..43. */
static const unsigned long d5v_dbase[44] = {
    0x00000001UL, 0x00000002UL, 0x00000004UL, 0x00000008UL, 0x00000010UL, 0x00000020UL, 0x00000040UL, 0x00000060UL,
    0x00000080UL, 0x000000C0UL, 0x00000100UL, 0x00000180UL, 0x00000200UL, 0x00000300UL, 0x00000400UL, 0x00000600UL,
    0x00000800UL, 0x00000C00UL, 0x00001000UL, 0x00001800UL, 0x00002000UL, 0x00003000UL, 0x00004000UL, 0x00006000UL,
    0x00008000UL, 0x0000C000UL, 0x00010000UL, 0x00018000UL, 0x00020000UL, 0x00030000UL, 0x00040000UL, 0x00060000UL,
    0x00080000UL, 0x000C0000UL, 0x00100000UL, 0x00180000UL, 0x00200000UL, 0x00300000UL, 0x00400000UL, 0x00600000UL,
    0x00800000UL, 0x00C00000UL, 0x01000000UL, 0x01800000UL,
};
static const unsigned long d5v_drange[44] = {
    0x00000001UL, 0x00000002UL, 0x00000004UL, 0x00000008UL, 0x00000010UL, 0x00000020UL, 0x00000020UL, 0x00000020UL,
    0x00000040UL, 0x00000040UL, 0x00000080UL, 0x00000080UL, 0x00000100UL, 0x00000100UL, 0x00000200UL, 0x00000200UL,
    0x00000400UL, 0x00000400UL, 0x00000800UL, 0x00000800UL, 0x00001000UL, 0x00001000UL, 0x00002000UL, 0x00002000UL,
    0x00004000UL, 0x00004000UL, 0x00008000UL, 0x00008000UL, 0x00010000UL, 0x00010000UL, 0x00020000UL, 0x00020000UL,
    0x00040000UL, 0x00040000UL, 0x00080000UL, 0x00080000UL, 0x00100000UL, 0x00100000UL, 0x00200000UL, 0x00200000UL,
    0x00400000UL, 0x00400000UL, 0x00800000UL, 0x00800000UL,
};
static const unsigned long d5v_mbase[12] = {
    0x00000000UL, 0x00000301UL, 0x00000321UL, 0x00000341UL, 0x000003A1UL, 0x000003E1UL, 0x000003E5UL, 0x000003E9UL,
    0x000003F1UL, 0x000003F4UL, 0x00000000UL, 0x00000020UL,
};
static const unsigned long d5v_mrate[12] = {
    0x00000001UL, 0x00000001UL, 0x00000002UL, 0x00000003UL, 0x00000004UL, 0x00000001UL, 0x00000001UL, 0x00000002UL,
    0x00000002UL, 0x00000004UL, 0x00000000UL, 0x00000301UL,
};
static const unsigned char d5v_mshift[12] = {
    0x00, 0x00, 0x08, 0x10, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

/* dword_431940: per-order cost table for groups 5/6 */
static const unsigned short d5v_t431940[512] = {
    0x0000, 0x0001, 0x0002, 0x0002, 0x0002, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x0005, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006,
    0x0006, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000D, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010,
    0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x0010, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0006, 0x0006, 0x0006, 0x0006,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x0005, 0x0005, 0x0005, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0003,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0002, 0x0002, 0x0002, 0x0001,
};


/* predictor tables (DGROUP 0x433140, 0x432140, 0x432540, 0x432940,
 * 0x432D40); generated from UHARC04.lst DGROUP; do not edit */
static const unsigned short d5v_t433140[256] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0005, 0x0006, 0x0006, 0x0006, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0007, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0008, 0x0008, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0006, 0x0006, 0x0006, 0x0005, 0x0005,
    0x0004, 0x0003, 0x0002, 0x0001,
};
static const unsigned short d5v_t432140[256] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0004, 0x0004, 0x0004, 0x0004, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0007, 0x0007, 0x0007, 0x0007, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0009, 0x0009, 0x0009, 0x0009, 0x000A, 0x000A, 0x000A, 0x000A, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000D, 0x000D, 0x000D, 0x000D, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000F, 0x000F, 0x000F, 0x000F, 0x0010, 0x0010, 0x0010, 0x0010, 0x0011, 0x0011, 0x0011, 0x0011,
    0x0012, 0x0012, 0x0012, 0x0012, 0x0013, 0x0013, 0x0013, 0x0013, 0x0014, 0x0014, 0x0014, 0x0014,
    0x0015, 0x0015, 0x0015, 0x0015, 0x0016, 0x0016, 0x0016, 0x0016, 0x0017, 0x0017, 0x0017, 0x0017,
    0x0018, 0x0018, 0x0018, 0x0018, 0x0019, 0x0019, 0x0019, 0x0019, 0x001A, 0x001A, 0x001A, 0x001A,
    0x001B, 0x001B, 0x001B, 0x001B, 0x001C, 0x001C, 0x001C, 0x001C, 0x001D, 0x001D, 0x001D, 0x001D,
    0x001E, 0x001E, 0x001E, 0x001E, 0x001F, 0x001F, 0x001F, 0x001F, 0x0020, 0x001F, 0x001F, 0x001F,
    0x001F, 0x001E, 0x001E, 0x001E, 0x001E, 0x001D, 0x001D, 0x001D, 0x001D, 0x001C, 0x001C, 0x001C,
    0x001C, 0x001B, 0x001B, 0x001B, 0x001B, 0x001A, 0x001A, 0x001A, 0x001A, 0x0019, 0x0019, 0x0019,
    0x0019, 0x0018, 0x0018, 0x0018, 0x0018, 0x0017, 0x0017, 0x0017, 0x0017, 0x0016, 0x0016, 0x0016,
    0x0016, 0x0015, 0x0015, 0x0015, 0x0015, 0x0014, 0x0014, 0x0014, 0x0014, 0x0013, 0x0013, 0x0013,
    0x0013, 0x0012, 0x0012, 0x0012, 0x0012, 0x0011, 0x0011, 0x0011, 0x0011, 0x0010, 0x0010, 0x0010,
    0x0010, 0x000F, 0x000F, 0x000F, 0x000F, 0x000E, 0x000E, 0x000E, 0x000E, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000C, 0x000C, 0x000C, 0x000C, 0x000B, 0x000B, 0x000B, 0x000B, 0x000A, 0x000A, 0x000A,
    0x000A, 0x0009, 0x0009, 0x0009, 0x0009, 0x0008, 0x0008, 0x0008, 0x0008, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0006, 0x0006, 0x0006, 0x0006, 0x0005, 0x0005, 0x0005, 0x0005, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0003, 0x0003, 0x0003, 0x0003, 0x0002, 0x0002, 0x0002, 0x0002, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0000, 0x0000, 0x0000,
};
static const unsigned short d5v_t432540[256] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0007, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0007, 0x0007, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x000A, 0x000A, 0x000A, 0x000A,
    0x000A, 0x000A, 0x000A, 0x000A, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000D, 0x000D, 0x000D, 0x000D,
    0x000D, 0x000D, 0x000D, 0x000D, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x0010, 0x000F, 0x000F, 0x000F,
    0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E, 0x000E,
    0x000E, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000D, 0x000C, 0x000C, 0x000C,
    0x000C, 0x000C, 0x000C, 0x000C, 0x000C, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B, 0x000B,
    0x000B, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x000A, 0x0009, 0x0009, 0x0009,
    0x0009, 0x0009, 0x0009, 0x0009, 0x0009, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008,
    0x0008, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0006, 0x0006, 0x0006,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0003, 0x0003, 0x0003,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
};
static const unsigned short d5v_t432940[256] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0008, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007,
    0x0007, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006,
    0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
    0x0004, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0003,
    0x0003, 0x0003, 0x0003, 0x0003, 0x0003, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
    0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
};
static const unsigned short d5v_t432D40[256] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0002, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
    0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000,
};



/* ------------------------------------------------------------------ */

typedef struct d5v_s {
    /* buffered i/o */
    uharc_dec_read_cb rcb;
    void *rctx;
    uharc_dec_write_cb wcb;
    void *wctx;
    unsigned char *inb;
    unsigned in_pos, in_avail, in_cap;
    unsigned char *outb;
    unsigned out_fill, out_cap;
    unsigned long out_tot;       /* 45CD28 */
    unsigned long out_len;       /* 45CD14 */
    unsigned long in_tot;        /* 45CD24 */
    int err;

    /* range coder */
    unsigned long code;          /* 45D0B8 */
    unsigned long range;         /* 45D0BC */
    unsigned long ct;            /* 44C89C interval total */
    unsigned long clo;           /* 44C8A0 */
    unsigned long chi;           /* 44C8A4 */

    /* window */
    unsigned char *dict;         /* 4312AC */
    unsigned long dictsz;        /* 44C8DC */
    unsigned long dictmask;      /* 44C8E0 */
    unsigned long wpos;          /* 44C8CC */
    unsigned long pos;           /* 44C8BC */
    unsigned long hist4;         /* 44C8C8 */

    /* models */
    unsigned short *fen;         /* 4312B8 */
    unsigned short *cnt;         /* 4312BC */
    unsigned short ext[1027];    /* 4312C4 */
    unsigned char lastctx[65536];/* 4312D0 */
    unsigned char *win2;         /* 4312D8 */
    unsigned char *wcnt;         /* 4312DC */
    unsigned short litm[396 * 6];/* 44C0F8 */
    unsigned long mru[12];       /* 433734 */
    unsigned long mdist;         /* 44C844: current match distance */
    unsigned long dprob;         /* 44C848: distance-tree probability */

    /* state flags */
    unsigned char fam;           /* 44D902: method family -m1/-m2/-m3 */
    unsigned char group;         /* 44D907: escape selector / group 0..10 */
    unsigned char mode;          /* 44D904: last 5-way decision/token class */
    unsigned char c901;          /* 44D901: MRU update selector */
    unsigned char c905;          /* 44D905: match length */
    unsigned char c906;          /* 44D906: side predictor predicted byte */
    unsigned char s90e;          /* 44D90E: side predictor sign/direction */
    unsigned char s90f;          /* 44D90F: history shift for channel */
    unsigned char s910;          /* 44D910: selector-changed flag */
    unsigned char st911;         /* 44D911: decision-history state */
    unsigned char s913;          /* 44D913: single-byte exclusion flag */
    unsigned char s914;          /* 44D914: excluded byte */
    unsigned long rep;           /* 44C8D8: repeat count (dword) */
    unsigned char s909;          /* 44D909: predictor crossover flag */
    unsigned char s90a;          /* 44D90A: predictor slot index */
    unsigned char s90d;          /* 44D90D: saved predictor sign */
    unsigned char c8e8[6];       /* 44C8E8 */
    unsigned long ctx878;        /* 44C878 */
    unsigned long rate884;       /* 44C884 */
    unsigned long c87c;          /* 44C87C */
    unsigned char *lastptr;      /* 4312D4 */
    unsigned long c84c;          /* 44C84C[0] */
    unsigned long e8e0[6];       /* 4498E0 */

    /* byte predictor for groups 5..9 (sub_414470 / sub_414820) */
    long pred43[124];            /* 446EEC: 4 rate blocks x 31 ints */
    long predbc[6];              /* 4456BC..4456D0 */
    long pred4bc[128];           /* 4454BC */
    long pred2bc[124];           /* 4452BC: per-order costs, orders 2..123 */
    long pred2a0;                /* 4452A0: order 0..5 (recomputed each call) */
    long pred2a4;                /* 4452A4 */
    long pred2a8;                /* 4452A8 */
    long pred2ac;                /* 4452AC */
    long pred2b0;                /* 4452B0 */
    long pred2b4;                /* 4452B4 */
    long pred2b8;                /* 4452B8 */
    long p6cost[6 * 257];        /* 4456D4: per-order cost history+sum */
    unsigned char pred70dc[4];   /* byte_4470DC */

    /* price accounting used by the literal decoder */
    unsigned long p880;          /* 44C880 */
    unsigned long p88c;          /* 44C88C */
    unsigned long p890;          /* 44C890 */
    unsigned long p894;          /* 44C894 */
    unsigned long seq898;        /* 44C898 */
    unsigned long hist410[256];  /* 44C410 */

    unsigned long escctx;        /* 44C8D4: escape/secondary PPM context */
    unsigned long blockend;      /* 44C8A8 */
    const unsigned long *cum;    /* 44C8D0: container file-end table */
    unsigned long ncum;          /* table length */
    unsigned long cum_idx;       /* 44C8C0: current index into cum[] */
    unsigned char hasprev;       /* 44C8C4 != 0 */
    unsigned char prevb;         /* byte at 44C8C4 */

    unsigned char *pred;         /* scratch: dword_4312D8 + ctx */
    unsigned char *predc;        /* scratch: dword_4312DC + ctx */

    int method;
} d5v;

/* ------------------------------------------------------------------ */
/* buffered input / output                                             */
/* ------------------------------------------------------------------ */

static int d5v_get(d5v *d)
{
    int n;
    if (d->in_pos >= d->in_avail) {
        n = d->rcb(d->rctx, d->inb, d->in_cap);
        if (n <= 0) {
            d->err = 3;
            return 0;
        }
        d->in_avail = (unsigned)n;
        d->in_pos = 0;
    }
    d->in_tot++;
    return d->inb[d->in_pos++];
}

static void d5v_putraw(d5v *d, const unsigned char *p, unsigned long n)
{
#if U4_DEBUG
    fprintf(stderr, "    putraw n=%lu err=%d fill=%u cap=%u\n", n, d->err,
            d->out_fill, d->out_cap);
#endif
    if (d->out_tot >= d->out_len) return;
    if (n > d->out_len - d->out_tot) n = d->out_len - d->out_tot;
    while (n) {
        unsigned room = d->out_cap - d->out_fill;
        unsigned chunk = (n < (unsigned long)room) ? (unsigned)n : room;
        memcpy(d->outb + d->out_fill, p, chunk);
        d->out_fill += chunk;
        p += chunk;
        n -= chunk;
        if (d->out_fill == d->out_cap) {
            if (d->wcb(d->wctx, d->outb, d->out_fill) != 0) d->err = 4;
            d->out_fill = 0;
        }
    }
}

static void d5v_put(d5v *d, unsigned b)
{
    unsigned char c = (unsigned char)(b & 0xFFu);
    d5v_putraw(d, &c, 1);
    d->out_tot++;
}

/* ------------------------------------------------------------------ */
/* range decoder (0.4 family: 5 byte init, renorm < 0x1000000)        */
/* ------------------------------------------------------------------ */

static void d5v_rc_init(d5v *d)
{
    int i;
    unsigned long v = 0;
    for (i = 0; i < 5; i++) v = ((v << 8) | (unsigned long)d5v_get(d)) & D5V_M32;
    d->code = v;
    d->range = D5V_M32;
}

/* narrow the coder to [clo,chi) of total ct, then renormalise */
static void d5v_narrow(d5v *d)
{
    unsigned long u = d->range;
    unsigned long lo = d->clo;
#if U4_DEBUG
    fprintf(stderr, "  narrow ct=%lu lo=%lu hi=%lu code=%08lX range=%08lX\n",
            d->ct, d->clo, d->chi, d->code, d->range);
#endif
    d->code = (d->code - ((u * lo) & D5V_M32)) & D5V_M32;
    d->range = (u * (d->chi - lo)) & D5V_M32;
    while (d->range < 0x1000000UL) {
        d->code = ((d->code << 8) | (unsigned long)d5v_get(d)) & D5V_M32;
        d->range = (d->range << 8) & D5V_M32;
        if (d->err) break;
    }
#if U4_DEBUG
    fprintf(stderr, "  -> code=%08lX range=%08lX inpos=%lu\n", d->code, d->range, d->in_tot);
#endif
}

/* ------------------------------------------------------------------ */
/* PPM model                                                          */
/* ------------------------------------------------------------------ */

/* sub_40EE90: halve one context, rebuild its Fenwick tree */
static void d5v_rescale(d5v *d, unsigned ctx)
{
    unsigned short *raw = d->cnt + (size_t)ctx * 256u;
    unsigned short *fr = d->fen + (size_t)ctx * 256u;
    unsigned total = 0;
    unsigned i, k, j;
    for (i = 0; i < 256u; i++) {
        raw[i] = (unsigned short)(((unsigned)raw[i] + 1u) >> 1);
        total = (total + (unsigned)raw[i]) & 0xFFFFu;
    }
    for (i = 1; i < 256u; i++) fr[i] = raw[i - 1u];
    fr[0] = (unsigned short)total;
    for (k = 1; k < 128u; k *= 2u) {
        j = 256u - 2u * k;
        for (;;) {
            fr[j] = (unsigned short)(fr[j] + fr[j - k]);
            if (j == 2u * k) break;
            j -= 2u * k;
        }
    }
    if (ctx < 1027u)
        d->ext[ctx] = (unsigned short)(((unsigned)d->ext[ctx] >> 2) + 1u);
}

/* add 'inc' to symbol 'sym' of context 'ctx' */
static void d5v_fenadd(d5v *d, unsigned ctx, unsigned sym, unsigned inc)
{
    unsigned short *fr = d->fen + (size_t)ctx * 256u;
    unsigned short *raw = d->cnt + (size_t)ctx * 256u;
    unsigned v;
    raw[sym] = (unsigned short)(raw[sym] + inc);
    v = (sym + 1u) & 0xFFu;
    while (v) {
        fr[v] = (unsigned short)(fr[v] + inc);
        v = (v + (v & (0u - v))) & 0xFFu;
    }
    fr[0] = (unsigned short)(fr[0] + inc);
}

/* DGROUP word_44D0F4 / word_44C8EE: per-context count and escape-model
 * increments.  The original tables are 1027 words filled with 33 / 15, but
 * later initialisers of adjacent DGROUP variables overwrite parts of them,
 * so the values the decoder actually sees are:                       */
static unsigned d5v_inctab(unsigned ctx)
{
    if (ctx >= 1017u) return 44u;
    if (ctx >= 1009u) return 10u;
    return 33u;
}

static unsigned d5v_ewtab(unsigned ctx)
{
    if (ctx >= 993u && ctx <= 1016u) return 8u;
    if (ctx == 768u) return 6u;
    return 15u;
}

/* sub_40EFE0: update context 'ctx' with symbol 'sym' */
static void d5v_update(d5v *d, unsigned sym, unsigned ctx)
{
    unsigned inc = d5v_inctab(ctx);
    unsigned esc = (unsigned)d->escctx;
#if U4_DEBUG
    fprintf(stderr, "    upd ctx=%u sym=%02X esc=%u out=%lu\n", ctx, sym, esc,
            d->out_tot);
#endif
    if (d->cnt[(size_t)ctx * 256u + sym] == 0) {
        unsigned w = d5v_ewtab(ctx);
        d->ext[ctx] = (unsigned short)(d->ext[ctx] + inc);
        d5v_fenadd(d, esc, sym, w);
        if ((unsigned)d->fen[(size_t)esc * 256u] >= 0x4000u) d5v_rescale(d, esc);
    }
    if (ctx != 768u) {
        d5v_fenadd(d, ctx, sym, inc);
        if ((unsigned)((unsigned)d->ext[ctx] +
                       (unsigned)d->fen[(size_t)ctx * 256u]) >= 0x4000u)
            d5v_rescale(d, ctx);
    }
}

/* sub_410440: decode one symbol from context 'ctx' (PPM with escape) */
/* The ALZ literal byte model, equivalent to 0.6 d5_ppmdec() / seb3773
 * alz_bm_decode_literal().  A non-zero s913 excludes symbol s914; on an
 * escape the symbol is re-decoded in the secondary context `escctx` with
 * the symbols of `ctx` excluded. */
static unsigned d5v_sym(d5v *d, unsigned ctx)
{
    unsigned short *fen = d->fen + (size_t)ctx * 256u;
    unsigned short *cnt = d->cnt + (size_t)ctx * 256u;
    unsigned vctx = ctx;
    unsigned total, point, rem, sym, step;

#if U4_DEBUG
    fprintf(stderr, "sym ctx=%u fen0=%u ext=%u esc=%u p880=%lu p890=%lu p894=%lu\n",
            ctx, (unsigned)fen[0], ctx < 1027u ? (unsigned)d->ext[ctx] : 0u,
            d->escctx, d->p880, d->p890, d->p894);
#endif
    total = fen[0];
    if (d->s913) total = (unsigned)((total - cnt[d->s914]) & 0xFFFFu);
#if U4_DEBUG
    if (ctx == 1016u) {
        unsigned q;
        fprintf(stderr, "    ctx1016 total=%u: ", total);
        for (q = 0; q < 256u; q++) if (cnt[q]) fprintf(stderr, "%02X=%u ", q, cnt[q]);
        fprintf(stderr, "\n");
    }
#endif
    if (total == 0) {
        vctx = (unsigned)d->escctx;
        fen = d->fen + (size_t)vctx * 256u;
        cnt = d->cnt + (size_t)vctx * 256u;
        total = fen[0];
        if (d->s913) total = (unsigned)((total - cnt[d->s914]) & 0xFFFFu);
#if U4_DEBUG
        fprintf(stderr, "  escape-to ctx=%u total=%u\n", vctx, total);
#endif
        if (total == 0) { d->err = 7; return 0; }
        d->ct = total;
        d->range /= total;
        if (d->range == 0) { d->err = 7; return 0; }
        point = (unsigned)((d->code / d->range) & 0xFFFFu);
        rem = (total - point) & 0xFFFFu;
        goto search;
    }
    d->ct = (total + (unsigned)d->ext[ctx]) & 0xFFFFu;
    d->range /= d->ct;
    if (d->range == 0) { d->err = 7; return 0; }
    point = (unsigned)((d->code / d->range) & 0xFFFFu);
    if (point < total) {
        rem = (total - point) & 0xFFFFu;
        goto search;
    }
    /* escape interval [total, ct) */
    d->clo = total;
    d->chi = d->ct;
    {
        unsigned idx = (unsigned)(((d->ct - total) << 14) / d->ct);
        if (idx > 16383u) idx = 16383u;
        d->p88c = (d->p88c + (unsigned long)d5v_price[idx]) & D5V_M32;
    }
    d5v_narrow(d);
    if (d->err) return 0;
    {
        unsigned esc = (unsigned)d->escctx;
        unsigned short *efen = d->fen + (size_t)esc * 256u;
        unsigned short *ecnt = d->cnt + (size_t)esc * 256u;
        unsigned sum, t;

        sum = uha_sum16_where_nonzero(cnt, ecnt);
        if (d->s913 && cnt[d->s914] == 0)
            sum = (sum + (unsigned)ecnt[d->s914]) & 0xFFFFu;
        t = (unsigned)((efen[0] - sum) & 0xFFFFu);
#if U4_DEBUG
        fprintf(stderr, "    escctx=%u efen0=%u sum=%u t=%u\n",
                esc, (unsigned)efen[0], sum, t);
#endif
        if (t == 0) { d->err = 7; return 0; }
        d->ct = t;
        d->range /= t;
        if (d->range == 0) { d->err = 7; return 0; }
        point = (unsigned)((d->code / d->range) & 0xFFFFu);
        {
            /* Descending walk over the symbols absent from ctx, s914
             * excluded when s913 is set (see uha_desc_search_zero). */
            uint32_t acc;
            int s = uha_desc_search_zero(cnt, ecnt, d->s913 ? (int)d->s914 : -1, point, &acc);
            if (s < 0) { d->err = 7; return 0; }
            sym = (unsigned)s;
            sum = acc;
        }
        d->chi = sum;
        d->clo = (unsigned)((sum - (unsigned)ecnt[sym]) & 0xFFFFu);
        {
            unsigned idx = (unsigned)(((d->chi - d->clo) << 14) / d->ct);
            if (idx > 16383u) idx = 16383u;
            d->p88c = (d->p88c + (unsigned long)d5v_price[idx]) & D5V_M32;
        }
        d5v_narrow(d);
        if (d->err) return 0;
        return sym;
    }

search:
    if (!d->s913) {
        step = 128u;
        sym = 0;
        do {
            if (rem > (unsigned)fen[sym + step]) {
                rem -= (unsigned)fen[sym + step];
                sym += step;
            }
            step >>= 1;
        } while (step);
    } else {
        unsigned excl = (unsigned)d->s914;
        unsigned v43 = (unsigned)cnt[excl];
        int nofc = 0;
        step = 128u;
        sym = 0;
        do {
            unsigned cand = sym + step;
            if (nofc || cand <= excl) {
                if (rem > (unsigned)fen[cand]) {
                    rem -= (unsigned)fen[cand];
                    sym = cand;
                }
            } else if ((unsigned)fen[cand] < (v43 + rem)) {
                unsigned t = (unsigned)fen[cand];
                sym = cand;
                nofc = 1;
                rem -= t - v43;
            }
            step >>= 1;
        } while (step);
    }
    rem = (rem + point) & 0xFFFFu;
    d->chi = rem;
    d->clo = (unsigned)((rem - (unsigned)cnt[sym]) & 0xFFFFu);
    {
        unsigned idx = (unsigned)(((d->chi - d->clo) << 14) / d->ct);
        if (idx > 16383u) idx = 16383u;
        d->p88c = (d->p88c + (unsigned long)d5v_price[idx]) & D5V_M32;
    }
    d5v_narrow(d);
    return sym;
}

/* sub_410990: add the price of symbol 'sym' in context 'ctx' */
static void d5v_cost(d5v *d, unsigned ctx, unsigned sym)
{
    unsigned short *cnt = d->cnt + (size_t)ctx * 256u;
    unsigned short *fen = d->fen + (size_t)ctx * 256u;
    unsigned short *ovl = 0;    /* original ctx counts, for the overlap case */
    unsigned v = cnt[sym];
    unsigned total;

    if (v == 0) {
        unsigned t = fen[0];
        if (d->s913) t = (unsigned)((t - cnt[d->s914]) & 0xFFFFu);
        if (t != 0) {
            unsigned e = (unsigned)d->ext[ctx];
            d->p88c = (d->p88c + (unsigned long)d5v_price[
                ((e << 14) / (t + e)) & 0x3FFFu]) & D5V_M32;
            ovl = cnt;
        }
        ctx = (unsigned)d->escctx;
        cnt = d->cnt + (size_t)ctx * 256u;
        fen = d->fen + (size_t)ctx * 256u;
        v = cnt[sym];
    }
    total = fen[0];
    if (ctx < 0x403u) {
        total = (total + (unsigned)d->ext[ctx]) & 0xFFFFu;
        if (d->s913) total = (unsigned)((total - cnt[d->s914]) & 0xFFFFu);
    } else if (!ovl) {
        if (d->s913) total = (unsigned)((total - cnt[d->s914]) & 0xFFFFu);
    } else {
        total = (unsigned)((total - uha_sum16_where_nonzero(ovl, cnt)) & 0xFFFFu);
        if (d->s913 && ovl[d->s914] == 0)
            total = (unsigned)((total - cnt[d->s914]) & 0xFFFFu);
    }
    if (total == 0) return;
    d->p88c = (d->p88c + (unsigned long)d5v_price[
        (((unsigned)v << 14) / total) & 0x3FFFu]) & D5V_M32;
}

/* ------------------------------------------------------------------ */
/* decision model (5 symbols + escape)                                */
/* ------------------------------------------------------------------ */

/* sub_40F110: rescale one 5-symbol decision model */
static void d5v_drescale(unsigned short *e)
{
    unsigned v1 = e[2], v3 = e[3], v5 = e[4];
    unsigned v2 = (v1 - e[1] + 1) >> 1;
    unsigned v4 = (v3 - v1 + 1) >> 1;
    unsigned v6 = (e[5] - v5 + 1) >> 1;
    v2 = (unsigned short)(e[1] + v2);
    e[2] = (unsigned short)v2;
    v4 = (unsigned short)(v2 + v4);
    e[3] = (unsigned short)v4;
    {
        unsigned v7 = (unsigned short)(v4 + ((v5 - v3 + 1) >> 1));
        e[4] = (unsigned short)v7;
        e[5] = (unsigned short)(v7 + v6);
    }
}

/* sub_40F190: update the decision model with symbol 1..4 */
static void d5v_dupdate(d5v *d, unsigned ctx, unsigned sym)
{
    unsigned short *e = d->litm + (size_t)ctx * 6u;
    unsigned v4 = sym - 1u;
    if (sym < 2u) e[2] = (unsigned short)(e[2] + 88u);
    if (sym < 3u) e[3] = (unsigned short)(e[3] + 88u);
    if (sym < 4u) e[4] = (unsigned short)(e[4] + 88u);
    e[5] = (unsigned short)(e[5] + 88u);
    if (e[5] >= 0x4000u) d5v_drescale(e);
    if (d->lastptr) {
        unsigned char *p = d->lastptr;
        unsigned cur = (unsigned)*p;   /* byte, zero-extended like the original */
        if ((cur >> 6) == (unsigned)v4) {
            if ((*p & 0x3Fu) != 0x3Fu) ++*p;
        } else {
            *p = (unsigned char)(v4 << 6);
        }
        d->lastptr = 0;
    }
    d->st911 = d5v_stt[32u * v4 + (unsigned)d->st911];
#if U4_DEBUG
    fprintf(stderr, "  dec ctx=%u sym=%u e=%u,%u,%u,%u,%u\n", ctx, sym,
            (unsigned)e[0], (unsigned)e[1], (unsigned)e[2], (unsigned)e[3],
            (unsigned)e[4]);
#endif
}

/* ------------------------------------------------------------------ */
/* byte predictor for groups 5..9 (sub_414470 predict / 414820 train) */
/* ------------------------------------------------------------------ */

/* 32-bit helpers: the original is i386, so every int add/mul wraps */
static unsigned long d5v_u32(long v)
{
    return (unsigned long)v & D5V_M32;
}

static long d5v_s32(unsigned long u)
{
    u &= D5V_M32;
    if (u & 0x80000000UL) return -(long)((D5V_M32 - u) + 1UL);
    return (long)u;
}

static long d5v_add32(long a, long b)
{
    return d5v_s32(d5v_u32(a) + d5v_u32(b));
}

static long d5v_sub32(long a, long b)
{
    return d5v_s32(d5v_u32(a) - d5v_u32(b));
}

static long d5v_mul32(long a, long b)
{
    return d5v_s32(d5v_u32(a) * d5v_u32(b));
}

/* the original's divide-by-16 idiom truncates toward zero */
static long d5v_div16(long v)
{
    return v / 16;
}

/* dword_4412A0: |signed 12-bit| */
static unsigned d5v_abs12(long v)
{
    unsigned u = (unsigned)v & 0xFFFu;
    if (u & 0x800u) u = 0x1000u - u;
    return u;
}

/* sub_414420: zero all predictor state (called when a group > 4 starts) */
static void d5v_pred_reset(d5v *d)
{
    unsigned i;
    for (i = 0; i < 124u; i++) {
        d->pred43[i] = 0;
        d->pred2bc[i] = 0;
    }
    for (i = 0; i < 6u; i++) d->predbc[i] = 0;
    for (i = 0; i < 128u; i++) d->pred4bc[i] = 0;
    for (i = 0; i < 6u * 257u; i++) d->p6cost[i] = 0;
    for (i = 0; i < 4u; i++) d->pred70dc[i] = 0;
    d->pred2a0 = 0;
    d->pred2a4 = 0;
    /* sub_414420: after the flat 0x1E40 clear it stores 2 in dword_4452A8,
     * then seeds the [28..30] sentinels of the four 31-dword predictor
     * records (offsets 0x1F0/0x7C*k, k=1..4) with -1. */
    d->pred2a8 = 2;
    d->pred2ac = 0;
    d->pred2b0 = 0;
    d->pred2b4 = 0;
    d->pred2b8 = 0;
    for (i = 0; i < 4u; i++) {
        long *v = d->pred43 + 31u * i;
        v[28] = -1L;
        v[29] = -1L;
        v[30] = -1L;
    }
}

/* shared every-16-calls coefficient nudge (inside 414820) */
static void d5v_pred_adapt(d5v *d, long *v)
{
    unsigned long best = d5v_u32(v[12]);
    int sel = 0;
    int i;
    (void)d;
    v[12] = 0;
    for (i = 1; i < 11; i++) {
        long *pe = &v[12 + i];
        if (best > d5v_u32(*pe)) {
            best = d5v_u32(*pe);
            sel = i;
        }
        *pe = 0;
    }
    sel--;
    switch (sel) {
    case 0: if (v[5] > -32) v[5]--; break;
    case 1: if (v[5] < 32) v[5]++; break;
    case 2: if (v[6] > -32) v[6]--; break;
    case 3: if (v[6] < 32) v[6]++; break;
    case 4: if (v[7] > -32) v[7]--; break;
    case 5: if (v[7] < 32) v[7]++; break;
    case 6: if (v[8] > -32) v[8]--; break;
    case 7: if (v[8] < 32) v[8]++; break;
    case 8: if (v[8] > -32) v[9]--; break;
    case 9: if (v[8] < 32) v[9]++; break;
    default: break;
    }
    /* Long-path error-accumulator decay: the original tests the whole low
     * byte (`test byte ptr [edx+6Ch],0FFh`), i.e. it fires every 256 calls,
     * not at the 16-call coefficient nudge.  It is reached from that nudge,
     * so checking the byte here gives the same firing points. */
    if (!((unsigned char)d5v_u32(v[27]) & 0xFFu)) {
        long t;
        t = d5v_sub32(v[23], v[25]);
        v[23] = t;
        v[25] = t;
        t = d5v_sub32(v[24], v[26]);
        v[24] = t;
        v[26] = t;
    }
}

/* sub_414820: train the predictor with output byte 'sym' and delta 'dlt' */
static void d5v_pred_train(d5v *d, unsigned sym, unsigned dlt)
{
    unsigned g = (unsigned)d->group;
    unsigned rate = (unsigned)d->c87c;
    unsigned sb = sym & 0xFFu;
    unsigned db = dlt & 0xFFu;
    long sym_bias, pred_next, pred_bias;

    if (g >= 7u) {
        long *v = d->pred43 + 31u * rate;

        d->pred70dc[rate] = d->s90e;
        if (g < 8u) sym_bias = (long)sb - 128;
        else sym_bias = (long)(signed char)sb;

        pred_bias = (long)(signed char)((unsigned char)d5v_u32(d->predbc[0])
                                  - (unsigned char)sym_bias) * 16;
        v[12] += (long)d5v_abs12(pred_bias);
        v[13] += (long)d5v_abs12(d5v_sub32(pred_bias, v[0]));
        v[14] += (long)d5v_abs12(d5v_add32(pred_bias, v[0]));
        v[15] += (long)d5v_abs12(d5v_sub32(pred_bias, v[1]));
        v[16] += (long)d5v_abs12(d5v_add32(pred_bias, v[1]));
        v[17] += (long)d5v_abs12(d5v_sub32(pred_bias, v[2]));
        v[18] += (long)d5v_abs12(d5v_add32(pred_bias, v[2]));
        v[19] += (long)d5v_abs12(d5v_sub32(pred_bias, v[3]));
        v[20] += (long)d5v_abs12(d5v_add32(pred_bias, v[3]));
        v[21] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred2b4));
        v[22] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred2b4));

        v[23] += (long)d5v_t433140[(unsigned char)(
            (unsigned char)d5v_u32(d->predbc[0]) - (unsigned char)sym_bias)];
        v[24] += (long)d5v_t433140[(unsigned char)(
            (unsigned char)d5v_u32(v[10]) - (unsigned char)sym_bias)];

        v[11] = (long)(signed char)((unsigned char)sym_bias
                                    - (unsigned char)d5v_u32(v[10]));
        d->pred2b4 = v[11];
        v[27] = d5v_add32(v[27], 1);
        v[10] = sym_bias;
        if (!((unsigned char)d5v_u32(v[27]) & 0x0Fu)) d5v_pred_adapt(d, v);

        if (g == 9u) {
            long t = d->pred2b4;
            d->pred2b4 = d->pred2b8;
            d->pred2b8 = t;
        }
        v[28] = d5v_add32(d5v_u32(v[28]) << 8, (long)db);
        if (g == 7u) {
            v[29] = d5v_add32(d5v_u32(v[29]) << 8,
                              (long)d5v_t432540[db]);
            v[30] = d5v_add32(d5v_u32(v[30]) << 8,
                              (long)d5v_t432D40[db]);
        }
        return;
    }

    /* groups 5 and 6: the short-range linear predictor */
    if (g == 6u) sym_bias = (long)(signed char)sb;
    else sym_bias = (long)sb - 128;
    pred_next = d5v_sub32(sym_bias, d->pred2ac);
    pred_bias = (long)(signed char)((unsigned char)d5v_u32(d->predbc[3])
                              - (unsigned char)sym_bias) * 16;

    d->pred43[12] += (long)d5v_abs12(pred_bias);
    d->pred43[13] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred43[0]));
    d->pred43[14] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred43[0]));
    d->pred43[15] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred43[1]));
    d->pred43[16] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred43[1]));
    d->pred43[17] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred43[2]));
    d->pred43[18] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred43[2]));
    d->pred43[19] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred43[3]));
    d->pred43[20] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred43[3]));
    d->pred43[21] += (long)d5v_abs12(d5v_sub32(pred_bias, d->pred43[4]));
    d->pred43[22] += (long)d5v_abs12(d5v_add32(pred_bias, d->pred43[4]));

    d->pred43[11] = (long)(signed char)((unsigned char)sym_bias
                                        - (unsigned char)d5v_u32(d->pred43[10]));
    d->pred43[27] = d5v_add32(d->pred43[27], 1);
    d->pred43[10] = sym_bias;
    if (!((unsigned char)d5v_u32(d->pred43[27]) & 0x0Fu))
        d5v_pred_adapt(d, d->pred43);

    /* dword_4454BC history, indexed by the low 7 bits of pos */
    d->pred4bc[(unsigned)d->pos & 0x7Fu] = pred_next;

    /* order search every N bytes; the mask depends on the previous call's
     * order (dword_431928: 0x7F for 0..3, 7 for 4, 3 for 5) */
    {
        static const unsigned char osearch[6] = { 0x7F, 0x7F, 0x7F, 0x7F, 7, 3 };
        unsigned prevord = (unsigned)d->pred2a0;
        if (!((unsigned)d->pos
              & (unsigned)osearch[prevord > 5u ? 0u : prevord])) {
            unsigned long v28 = 0xFFFFUL;
            unsigned long cost_idx;
            d->pred2a4 = 2;
            d->pred2a8 = 2;
            for (cost_idx = 2; cost_idx < 0x7Cu; cost_idx++) {
                unsigned long p = (unsigned)d->pos;
                unsigned long a, b, c, v31;
                a = d5v_abs12(d->pred4bc[(p - 1u) & 0x7Fu]
                              - d->pred4bc[(p - 1u - cost_idx) & 0x7Fu]);
                b = d5v_abs12(d->pred4bc[p & 0x7Fu]
                              - d->pred4bc[(p - cost_idx) & 0x7Fu]);
                c = d5v_abs12(d->pred4bc[(p - 2u) & 0x7Fu]
                              - d->pred4bc[(p - 2u - cost_idx) & 0x7Fu]);
                v31 = a + b + c;
                d->pred2bc[cost_idx] = (long)(v31
                    + ((13UL * (unsigned long)d->pred2bc[cost_idx]) >> 4));
                if ((unsigned long)d->pred2bc[cost_idx]
                    < (unsigned long)d->pred2bc[d->pred2a4])
                    d->pred2a4 = (long)cost_idx;
                if (v31 < v28) {
                    v28 = v31;
                    d->pred2a8 = (long)cost_idx;
                }
            }
        }
    }

    /* Six-order cost loop.  dword_445AD4[257*order] in the original is a
     * mis-scaled view of the same running sum at [order*257+256], but the
     * comparison is against the current best order's sum, so the order
     * does move (greedy, first minimum wins).  dword_4452A0 is reset to 0
     * before the loop. */
    {
        unsigned char idx = (unsigned char)((unsigned)d->pos & 0xFFu);
        long diff[6];
        unsigned o;
        diff[0] = d5v_sub32(sym_bias, d->predbc[0]);
        diff[1] = d5v_sub32(sym_bias, d->predbc[1]);
        diff[2] = d5v_sub32(sym_bias, d->predbc[2]);
        diff[3] = d5v_sub32(sym_bias, d->predbc[3]);
        diff[4] = d5v_sub32(pred_next, d->predbc[4]);
        diff[5] = d5v_sub32(pred_next, d->predbc[5]);
        d->pred2a0 = 0;
        for (o = 0; o < 6u; o++) {
            long *cw = d->p6cost + (size_t)o * 257u;
            long cost_val;
            cw[256] = d5v_sub32(cw[256], cw[(unsigned)idx]);
            cost_val = (long)d5v_t431940[(unsigned long)diff[o] & 0x1FFUL];
            cw[(unsigned)idx] = cost_val;
            cw[256] = d5v_add32(cw[256], cost_val);
#if U4_DEBUG
            fprintf(stderr, "    ord o=%u sum=%ld cmp=%ld diff=%ld cost_val=%ld -> ",
                    o, cw[256], d->p6cost[(size_t)d->pred2a0 * 257u + 256u],
                    diff[o], cost_val);
#endif
            if (cw[256]
                < d->p6cost[(size_t)d->pred2a0 * 257u + 256u])
                d->pred2a0 = (long)o;
#if U4_DEBUG
            fprintf(stderr, "ord=%ld\n", d->pred2a0);
#endif
        }
    }

    d->pred2b0 = d->pred2ac;
    d->pred2ac = sym_bias;
    d->pred43[28] = d5v_add32(d5v_u32(d->pred43[28]) << 8, (long)db);
    d->pred43[29] = d5v_add32(d5v_u32(d->pred43[29]) << 8,
                              (long)d5v_t432140[db]);
    d->pred43[30] = d5v_add32(d5v_u32(d->pred43[30]) << 8,
                              (long)d5v_t432940[db]);
}

/* sub_414470: produce byte_44D906 (predicted byte), byte_44D90E (sign)
 * and dword_44C878 (literal context) for groups 5..9 */
static void d5v_pred_predict(d5v *d)
{
    unsigned g = (unsigned)d->group;
    unsigned rate = (unsigned)d->c87c;
    unsigned ctx;
    unsigned char pb;

    if (g >= 7u) {
        long *v = d->pred43 + 31u * rate;
        unsigned long acc;
        long pred;

        v[3] = v[2];
        v[2] = v[1];
        v[1] = d5v_sub32(v[11], v[0]);
        v[0] = v[11];
        acc = d5v_u32(d5v_mul32(v[3], v[8]));
        acc += d5v_u32(d5v_mul32(v[2], v[7]));
        acc += d5v_u32(d5v_mul32(v[1], v[6]));
        acc += d5v_u32(d5v_mul32(v[0], v[5]));
        acc += 16UL * d5v_u32(v[10]);
        acc += d5v_u32(d5v_mul32(d->pred2b4, v[9]));
        pred = d5v_div16(d5v_s32(acc));
        d->predbc[0] = pred;
        if ((unsigned long)d5v_u32(v[23])
            <= (unsigned long)d5v_u32(v[24]))
            pb = (unsigned char)d5v_u32(pred);
        else
            pb = (unsigned char)d5v_u32(v[10]);
        d->c906 = pb;
        if (g == 7u) {
            d->c906 = (unsigned char)(d->c906 + 0x80u);
            ctx = rate + 1001u;
            if (v[28]) {
                if (v[29]) {
                    if (!v[30]) ctx += 6u;
                } else ctx += 4u;
            } else ctx += 2u;
        } else if (g == 8u) {
            ctx = (v[28] ? rate : 2u) + 1009u;
        } else {
            ctx = (v[28] ? rate : 4u) + 1012u;
        }
        d->s90e = d->pred70dc[rate];
        d->ctx878 = ctx;
#if U4_DEBUG
        fprintf(stderr, "  predg%u out=%lu rate=%u ctx=%u pb=%02X s90e=%u b23=%ld b24=%ld\n",
                g, d->out_tot, rate, ctx, (unsigned)d->c906,
                (unsigned)d->s90e, v[23], v[24]);
#endif
        return;
    }

    /* groups 5 and 6 */
    {
        long *v = d->pred43;
        unsigned long acc;
        unsigned t;

        d->predbc[0] = 0;
        d->predbc[1] = d->pred2ac;
        t = ((unsigned)d->pos - (unsigned)d->pred2a4) & 0x7Fu;
        d->predbc[2] = d5v_sub32((long)(2UL * d5v_u32(d->pred2ac)),
                                 d->pred2b0);
        v[4] = d->pred4bc[t];
        v[3] = v[2];
        v[2] = v[1];
        v[1] = d5v_sub32(v[11], v[0]);
        v[0] = v[11];
        acc = d5v_u32(d5v_mul32(v[3], v[8]));
        acc += d5v_u32(d5v_mul32(v[2], v[7]));
        acc += d5v_u32(d5v_mul32(v[1], v[6]));
        acc += d5v_u32(d5v_mul32(v[0], v[5]));
        acc += 16UL * d5v_u32(v[10]);
        acc += d5v_u32(d5v_mul32(v[4], v[9]));
        d->predbc[3] = d5v_div16(d5v_s32(acc));
        d->predbc[4] = d->pred4bc[t];
        d->predbc[5] = d->pred4bc[
            ((unsigned)d->pos - (unsigned)d->pred2a8) & 0x7Fu];

        pb = (unsigned char)d5v_u32(d->predbc[d->pred2a0 & 7]);
        if (d->pred2a0 >= 4)
            pb = (unsigned char)(pb + (unsigned char)d->pred2ac);
        d->c906 = pb;
#if U4_DEBUG
        fprintf(stderr, "  predg%u out=%lu ord=%ld ac=%ld b0=%ld b1=%ld b2=%ld b3=%ld b4=%ld b5=%ld pb=%02X s90e=%u\n",
                g, d->out_tot, d->pred2a0, d->pred2ac, d->predbc[0],
                d->predbc[1], d->predbc[2], d->predbc[3], d->predbc[4],
                d->predbc[5], (unsigned)pb, (unsigned)d->s90e);
#endif
        if (g == 5u) d->c906 = (unsigned char)(d->c906 + 0x80u);
        ctx = (g == 5u) ? 993u : 997u;
        if (v[28]) {
            if (v[29]) {
                if (!v[30]) ctx += 3u;
            } else ctx += 2u;
        } else ctx += 1u;
        d->ctx878 = ctx;
    }
}

/* group selection shared by the decision escape and the block start */
/* sub_40EB70-adjacent: apply a new escape selector / group (0..10). */
/* Group 0 is pure order-0, 1..4 are per-position literal contexts, 5..9
 * engage the byte predictor, 10 means "reset, then use group 0".  `group`
 * here is the 0.6 `fb8` escape_selector of seb3773's ALZ model. */
static void d5v_group_switch(d5v *d, unsigned ng)
{
    unsigned i;
#if U4_DEBUG
    fprintf(stderr, "group_switch -> %u (was %u) pos=%lu out=%lu\n",
            ng, (unsigned)d->group, d->pos, d->out_tot);
#endif
    if (ng == (unsigned)d->group) {
        d->s910 = 0;
        return;
    }
    d->s910 = (unsigned char)(ng == 10u);
    if (ng == 10u) {
        for (i = 512u; i < 768u; i++) d5v_rescale(d, i);
        ng = 0;
    }
    d->group = (unsigned char)ng;
    d->ctx878 = d5v_mbase[ng];
    d->rate884 = d5v_mrate[ng];
    d->s90f = d5v_mshift[ng];
    d->s90e = 0;
    d->c906 = 0;
    d->c87c = 0;
    /* dword_4312D4 (last decided-context byte) is NOT cleared here in the
     * original: only sub_40F190 clears it after consuming it. */
    if (ng > 4u) d5v_pred_reset(d);
}

/* sub_40FDB0: decode the 5-way decision (0 = escape -> group switch) */
/* Top of the ALZ stream loop (== 0.6 d5_step, seb3773 alz_decode_token_class).
 * Returns 4 for a literal, 1..3 for a match, or 0 after an escape which
 * switches the group via an 11-way uniform selector. */
static unsigned d5v_decision(d5v *d, unsigned ctx)
{
    unsigned short *e = d->litm + (size_t)ctx * 6u;
    unsigned total = e[5];
    unsigned point, bl;

#if U4_DEBUG
    fprintf(stderr, "decision ctx=%u total=%u out=%lu\n", ctx, total, d->out_tot);
#endif
    d->ct = total;
    if (total == 0) { d->err = 7; return 4; }
    d->range /= total;
    if (d->range == 0) { d->err = 7; return 4; }
    point = (unsigned)((d->code / d->range) & 0xFFFFu);
    bl = 5u;
    do {
        bl--;
    } while (point < (unsigned)e[bl] && bl);
    d->clo = e[bl];
    d->chi = e[bl + 1u];
    d5v_narrow(d);
    if (d->err) return 4;
    if (bl != 0) {
        d5v_dupdate(d, ctx, bl);
        d->mode = (unsigned char)bl;
        return bl;
    }
    /* escape: 11-way uniform group selector */
    d->ct = 11u;
    d->range /= 11u;
    if (d->range == 0) { d->err = 7; return 4; }
    point = (unsigned)((d->code / d->range) & 0xFFu);
    d->clo = point;
    d->chi = point + 1u;
    d5v_narrow(d);
    if (d->err) return 4;
    d5v_group_switch(d, point & 0xFFu);
    d->mode = (unsigned char)d5v_decision(d, ctx);
    return d->mode;
}

/* ------------------------------------------------------------------ */
/* context selection / update                                         */
/* ------------------------------------------------------------------ */

/* sub_40F500: group-0 context update (byte history only) */
static void d5v_ctxupd0(d5v *d, unsigned sym)
{
    d->hist4 = ((d->hist4 << 8) + (sym & 0xFFu)) & D5V_M32;
    d->pos++;
}

/* sub_40F240: context update for groups 1..4 */
static void d5v_ctxupd(d5v *d, unsigned sym)
{
    unsigned v1 = sym & 0xFFu;
    unsigned v2 = (unsigned char)(v1 - (unsigned)d->c906);
    unsigned v3;

    if (d->s90e) v2 = (unsigned char)(0u - v2);
    if (v2 >= 0x80u) d->s90e = (unsigned char)(d->s90e ? 0 : 1);
    if (d->group == 1u) {
        v3 = 16u * (unsigned)d5v_g1tab[((unsigned)d->ctx878 - 1u) & 0xFu]
           + (unsigned)d5v_gtab[v2] + 769u;
        d->ctx878 = v3;
    } else if (d->group == 2u) {
        d->ctx878 = 16u * d->c87c + (unsigned)d5v_gtab[v2] + 801u;
    } else if (d->group == 3u) {
        if (d->s909) {
            v2 = (unsigned char)(v1 - (d->hist4 >> 16));
            d->s90e = d->s90d;
            if (d->s90d) v2 = (unsigned char)(0u - v2);
            if (v2 >= 0x80u) d->s90e = (unsigned char)(d->s90e ? 0 : 1);
        }
        {
            unsigned idx = (unsigned)d->s90a;
            if (v1 == (unsigned)d->c8e8[idx]) d->e8e0[idx]++;
            else d->e8e0[idx] >>= 1;
        }
        d->ctx878 = 32u * d->c87c + (unsigned)d5v_g3tab[v2] + 833u;
    } else if (d->group == 4u) {
        d->ctx878 = 16u * d->c87c + (unsigned)d5v_gtab[v2] + 929u;
    } else if (d->group >= 5u) {
        d5v_pred_train(d, v1, v2);
    } else {
        d->err = 7;
        return;
    }
    {
        unsigned v4 = d->pos + 1u;
        d->hist4 = ((d->hist4 << 8) + v1) & D5V_M32;
        d->c87c = (d->pos + 1u) % d->rate884;
        d->pos++;
        d->c906 = (unsigned char)(d->hist4 >> d->s90f);
        if (d->group == 3u) {
            unsigned v8 = v4 % 6u;
            int cross;
            d->s90a = (unsigned char)v8;
            cross = (d->e8e0[v8] > 8u);
            d->c8e8[v8] = (unsigned char)(d->hist4 - (d->hist4 >> 24) + d->c906);
            d->s909 = (unsigned char)(cross && d->c84c < 5u);
            if (d->s909) {
                d->s90d = d->s90e;
                d->ctx878 = 32u * d->c87c + 849u;
                d->s90e = 0;
                d->c906 = d->c8e8[d->s90a];
            }
            if (cross) d->c84c++; else d->c84c = 0;
        } else if (d->group >= 5u) {
            d5v_pred_predict(d);
        }
    }
}

/* ------------------------------------------------------------------ */
/* literal decode                                                     */
/* ------------------------------------------------------------------ */

/* sub_410130: decode one literal symbol (raw, before delta adjustment) */
static unsigned d5v_lit(d5v *d, unsigned ctx, unsigned model)
{
    unsigned char var18;
    unsigned f20 = 1, f1c = 1;
    unsigned char saved_s913 = d->s913;

    d->seq898 = (d->seq898 + 1u) & 0xFFu;
    d->p880 = (d->p880 - d->hist410[d->seq898]) & D5V_M32;
    d->p88c = 0;
    d->escctx = model;
#if U4_DEBUG
    fprintf(stderr, "  litin out=%lu ctx=%u model=%u p880=%lu p890=%lu p894=%lu s913=%u s914=%02X hasprev=%u\n",
            d->out_tot, ctx, model, d->p880, d->p890, d->p894,
            (unsigned)d->s913, (unsigned)d->s914, (unsigned)d->hasprev);
#endif

    if (d->p880 < 0x6D4250UL || d->p880 >= 0xFEFF01UL) {
        var18 = (unsigned char)d5v_sym(d, ctx);
        goto store;
    }
    if (d->p880 >= 0x91ADC0UL) {
        unsigned sym;
        d->ct = 256u;
        d->range /= 256u;
        if (d->range == 0) { d->err = 7; return 0; }
        sym = (unsigned)((d->code / d->range) & 0xFFu);
        d->clo = sym;
        d->chi = sym + 1u;
        d5v_narrow(d);
        if (d->err) return 0;
        d5v_cost(d, ctx, sym);
        var18 = (unsigned char)sym;
        goto store;
    }
    if (d->p894 >= d->p890) {
        /* direct: decode from the literal context, price in model 0x300 */
        unsigned raw = d5v_sym(d, ctx);
        unsigned ebp = d->p88c;
        unsigned edi;
        unsigned char sym_byte;
        if (d->err) return 0;
        d->p88c = 0;
        d->escctx = 1029u;
        d->s913 = 0;
        if (d->hasprev)
            sym_byte = d->s90e ? (unsigned char)(d->prevb - raw)
                         : (unsigned char)(d->prevb + raw);
        else sym_byte = (unsigned char)raw;
#if U4_DEBUG
        fprintf(stderr, "    direct raw=%u prevb=%02X s90e=%u sym_byte=%02X\n",
                raw, (unsigned)d->prevb, (unsigned)d->s90e, (unsigned)sym_byte);
#endif
        d5v_cost(d, 0x300u, (unsigned)sym_byte);
        edi = d->p88c;
        var18 = (unsigned char)raw;
        f20 = 1;
        d->escctx = 1029u;
        d->p88c = ebp;
        d5v_update(d, (unsigned)sym_byte, 0x300u);
        d->p894 = ((d->p894 * 31u) >> 5) + edi;
        d->escctx = model;
        f1c = 0;
        goto store;
    }
    {
        /* escape: decode from model 0x300 and price in the literal context */
        unsigned raw, ebp, edi;
        d->s913 = 0;
        d->escctx = 1029u;
        raw = d5v_sym(d, 0x300u);
        if (d->err) return 0;
        f20 = 0;
        edi = d->p88c;
        d->p880 = (d->p880 + edi) & D5V_M32;
        d->hist410[d->seq898] = edi;
        if (d->hasprev) {
            if (d->s90e) var18 = (unsigned char)(d->prevb - raw);
            else var18 = (unsigned char)(raw - d->prevb);
        } else {
            var18 = (unsigned char)raw;
        }
        d->s913 = saved_s913;
        d->escctx = model;
        d->p88c = 0;
        d5v_cost(d, ctx, (unsigned)var18);
        ebp = d->p88c;
        d->escctx = 1029u;
        d->p88c = ebp;
        d5v_update(d, (unsigned)raw, 0x300u);
        d->p894 = ((d->p894 * 31u) >> 5) + edi;
        d->escctx = model;
        f1c = 0;
    }
store:
    d5v_update(d, (unsigned)var18, ctx);
    if (f20) {
        d->hist410[d->seq898] = d->p88c;
        d->p880 = (d->p880 + d->p88c) & D5V_M32;
    }
    if (f1c) d->p894 = ((d->p894 * 31u) >> 5) + d->p88c;
    d->p890 = ((d->p890 * 31u) >> 5) + d->p88c;
    return (unsigned)var18;
}

/* sub_410010: decode and emit one literal */
/* Routes the literal through the side predictor's context when a group
 * 5..9 is active (== 0.6 d5_litdec / seb3773 alz_side_decode_literal),
 * otherwise through d5v_sym()/d5v_lit() of the plain byte model. */
static void d5v_literal(d5v *d)
{
    unsigned sym;
    unsigned char prevbyte = 0;

    d->hasprev = 0;
    if (d->group) {
        unsigned model = 0x405u + (unsigned)d->group;
        prevbyte = d->c906;
        if (d->s913) {
            if (d->s90e) d->s914 = (unsigned char)(prevbyte - d->s914);
            else d->s914 = (unsigned char)(d->s914 - prevbyte);
        }
        d->hasprev = 1;
        d->prevb = prevbyte;
        sym = d5v_lit(d, (unsigned)d->ctx878, model);
        if (d->err) return;
        sym = d->s90e ? (unsigned char)(prevbyte - sym)
                      : (unsigned char)(prevbyte + sym);
    } else {
        unsigned v = (unsigned char)d->hist4;
        if (d->s910) v += 0x200u;
        else if ((v & 0xC0u) == ((unsigned)(d->hist4 >> 8) & 0xC0u)) v += 0x100u;
        sym = d5v_lit(d, v, 0x403u);
        if (d->err) return;
        sym &= 0xFFu;
    }
    d5v_put(d, sym);
    if (d->group) d5v_ctxupd(d, sym);
    else d5v_ctxupd0(d, sym);
    d->s913 = 0;
    d->dict[d->wpos] = (unsigned char)sym;
    d->wpos = (d->wpos + 1u) & d->dictmask;
#if U4_DEBUG
    fprintf(stderr, "lit pos=%lu grp=%u sym=%02X\n", d->out_tot, (unsigned)d->group,
            (unsigned)sym);
#endif
}

/* ------------------------------------------------------------------ */
/* match decode                                                       */
/* ------------------------------------------------------------------ */

/* sub_40F580: decode distance and length of a match */
/* Walks the 12-bit distance tree (dprob, mru[], dbase/drange/dbase12) into
 * `mdist`, then the length model into `c905`.  Equivalent to 0.6
 * d5_matchdist() plus its length decode. */
static void d5v_match(d5v *d)
{
    unsigned sym = 0;
    unsigned model;
    unsigned pred = 0;

    if (d->mode == 2u) {
        d->c901 = 0;
        d->mdist = d->mru[0];
    } else {
        model = (d->mode != 1u) ? 1018u : 1017u;
        d->escctx = 1040u;
        sym = d5v_sym(d, model);
        if (d->err) return;
        sym &= 0xFFu;
#if U4_DEBUG
        fprintf(stderr, "  distsym out=%lu mode=%u model=%u sym=%u total=%u\n",
                d->out_tot, (unsigned)d->mode, model, sym, d->ct);
#endif
        d5v_update(d, sym, model);
        if (d->mode != 1u) {
            d->c901 = (unsigned char)sym;
            if (sym >= 12u) { d->err = 7; return; }
            d->mdist = d->mru[sym];
        } else {
            unsigned long off = 0;
            unsigned long rng2;
            int flag = -1;
            if (sym >= 44u) { d->err = 7; return; }
            d->mdist = d5v_dbase[sym];
            if (sym != 0) {
                unsigned long dist = d->mdist;
                rng2 = d5v_drange[sym];
                if (dist + rng2 - 1u > d->pos) rng2 = d->pos - dist + 1u;
                if (rng2 >= 4u) {
                    unsigned point;
                    d->ct = 4096u;
                    d->range /= 4096u;
                    if (d->range == 0) { d->err = 7; return; }
                    point = (unsigned)((d->code / d->range) & 0xFFFFu);
                    flag = (point >= d->dprob) ? 1 : 0;
                    if (flag) {
                        d->chi = 4096u;
                        d->clo = d->dprob;
                        d->dprob -= d->dprob >> 6;
                    } else {
                        d->chi = d->dprob;
                        d->clo = 0;
                        d->dprob += (4096u - d->dprob) >> 6;
                    }
                    d5v_narrow(d);
                    if (d->err) return;
                    rng2 >>= 1;
                }
                if (rng2 > 0x800u) {
                    unsigned long t2 = ((rng2 - 1u) >> 11) + 1u;
                    unsigned point;
                    d->ct = t2;
                    d->range /= t2;
                    if (d->range == 0) { d->err = 7; return; }
                    point = (unsigned)((d->code / d->range) & 0xFFFFu);
                    d->clo = point;
                    d->chi = point + 1u;
                    d5v_narrow(d);
                    if (d->err) return;
                    off += (unsigned long)point << 11;
                    if ((unsigned long)point + 1u != t2) rng2 = 0x800u;
                    else rng2 -= (unsigned long)point << 11;
                }
                if (rng2 >= 2u) {
                    unsigned point;
                    d->ct = rng2;
                    d->range /= rng2;
                    if (d->range == 0) { d->err = 7; return; }
                    point = (unsigned)((d->code / d->range) & 0xFFFFu);
                    d->clo = point;
                    d->chi = point + 1u;
                    d5v_narrow(d);
                    if (d->err) return;
                    off += point;
                }
                if (flag != -1) off = (unsigned long)flag + 2u * off;
                d->mdist = (dist + off) & D5V_M32;
                d->c901 = 0xFFu;
            } else {
                d->c901 = 0xFFu;
            }
        }
    }
    /* length model */
    if (d->mode == 1u) {
        unsigned long dd = d->mdist;
        if (dd < 0x100UL) model = 0x3FBu;
        else if (dd < 0x1000UL) model = 0x3FCu;
        else if (dd < 0x10000UL) model = 0x3FDu;
        else if (dd < 0x100000UL) model = 0x3FEu;
        else model = 0x3FFu;
    } else {
        model = 0x400u + (d->rep != 0 ? 1u : 0u) + (d->rep > 2u ? 1u : 0u);
    }
    if (model <= 0x400u) {
        unsigned long dd = d->mdist;
        if (dd > 1u) {
            unsigned c;
            c = (unsigned)d->dict[(d->wpos - dd) & d->dictmask] << 8;
            c += (unsigned)d->dict[(d->wpos - dd + 1u) & d->dictmask];
            if (model == 0x400u) c += 0x10000u;
            d->pred = d->win2 + c;
            d->predc = d->wcnt + c;
            pred = 1;
            if (*d->predc <= 0x32u) {
                unsigned point;
                d->ct = 256u;
                d->range /= 256u;
                if (d->range == 0) { d->err = 7; return; }
                point = (unsigned)((d->code / d->range) & 0xFFFFu);
                if (point < (unsigned)*d->predc) {
                    d->clo = 0;
                    d->chi = *d->predc;
                    d->s913 = 1;
                    d->s914 = *d->pred;
                    d5v_narrow(d);
                    if (d->err) return;
                } else {
                    sym = (unsigned)*d->pred;
                    d->clo = *d->predc;
                    d->chi = 256u;
                    d5v_narrow(d);
                    if (d->err) return;
                    model = 0;   /* do not decode from the model */
                    d->s913 = 0;
                    pred = 2;    /* predicted, no model decode */
                }
            }
        }
    }
    if (pred != 2) {
        if (model != 0) {
            d->escctx = 1039u;
            sym = d5v_sym(d, model);
            if (d->err) return;
            d5v_update(d, sym, model);
        }
    }
    if (pred) {
        unsigned ok = ((unsigned)*d->pred == sym) ? 1u : 0u;
        *d->predc = d5v_ptab[64u * ok + (unsigned)*d->predc];
        *d->pred = (unsigned char)sym;
    }
    d->c905 = d5v_lenbase[sym & 0xFFu];
    {
        unsigned nb = d5v_lenbits[sym & 0xFFu];
        if (nb) {
            unsigned point;
            d->ct = nb;
            d->range /= nb;
            if (d->range == 0) { d->err = 7; return; }
            point = (unsigned)((d->code / d->range) & 0xFFFFu);
            d->clo = point;
            d->chi = point + 1u;
            d5v_narrow(d);
            if (d->err) return;
            d->c905 = (unsigned char)(d->c905 + point);
        }
    }
}

/* sub_40FB80: one coded step (match or literal) */
/* sub_40FB80: one step — decode the decision and emit a match, or report
 * a literal for the caller to decode with d5v_literal().  Returns 1 for a
 * match, 0 for a literal.  `s913`/`s914` carry the following literal's
 * excluded byte (0.6 fc2/fc3). */
static unsigned d5v_step(d5v *d)
{
    unsigned ctx;
    unsigned len, dl;
    unsigned long src;

    if (d->rep) ctx = (d->rep > 2u ? 0x41u : 0x40u);
    else ctx = (unsigned)d->st911;
    if (ctx <= 0x0Fu) {
        unsigned char *p = d->lastctx + (unsigned)(d->hist4 & 0xFFFFu);
        d->lastptr = p;
        if (*p & 0x38u) ctx = (unsigned)(*p >> 3) + 0x20u;
    }
    ctx &= 0xFFu;
    if (d5v_decision(d, ctx) == 4u) {
        d->rep = 0;
        return 0;
    }
    if (d->err) return 1;
    d->s913 = 0;
    d5v_match(d);
    if (d->err) return 1;
    len = (unsigned)d->c905;
    src = (d->wpos - d->mdist) & d->dictmask;
    if (d->mdist > 1u) {
        unsigned char b = d->c901;
#if U4_DEBUG
        fprintf(stderr, "  mru b=%u mdist=%lu mode=%u\n", (unsigned)b,
                d->mdist, (unsigned)d->mode);
#endif
        if (b) {
            unsigned k = (b == 0xFFu) ? 11u : (unsigned)b;
            for (;;) {
                k = (k - 1u) & 0xFFu;
                if (k == 0xFFu) break;
                d->mru[k + 1u] = d->mru[k];
            }
            d->mru[0] = d->mdist;
        }
    }
    d->s913 = (unsigned char)(len != 0xFFu);
    if (len == 0xFFu) d->rep++;
    else d->rep = 0;
    {
        unsigned long end = src + (unsigned long)len;
        unsigned long dst = d->wpos + (unsigned long)len;
        unsigned long s914pos = (src + (unsigned long)len) & d->dictmask;
#if U4_DEBUG
        fprintf(stderr, "  preout err=%d len=%u src=%lu dst=%lu mask=%lu grp=%u c901=%u mode=%u\n",
                d->err, len, src, dst, d->dictmask, (unsigned)d->group,
                (unsigned)d->c901, (unsigned)d->mode);
#endif
        if (end > d->dictmask || dst > d->dictmask) {
            dl = (unsigned char)len;
            while (dl) {
                unsigned char b = d->dict[src];
                d5v_put(d, b);
                if (d->group) d5v_ctxupd(d, b);
                else d5v_ctxupd0(d, b);
                d->dict[d->wpos] = b;
                src = (src + 1u) & d->dictmask;
                d->wpos = (d->wpos + 1u) & d->dictmask;
                dl--;
            }
        } else {
            unsigned long n = len;
            unsigned char *s = d->dict + src;
            unsigned char *t = d->dict + d->wpos;
            d->wpos = (d->wpos + (unsigned long)len) & d->dictmask;
            if (d->group) {
                while (n--) {
                    unsigned char b = *s++;
                    *t++ = b;
                    d5v_ctxupd(d, b);
                }
            } else {
                d->pos += (unsigned long)len;
                while (n--) {
                    unsigned char b = *s++;
                    *t++ = b;
                    d->hist4 = ((d->hist4 << 8) + (unsigned long)b) & D5V_M32;
                }
            }
            d5v_putraw(d, d->dict + src, (unsigned long)len);
            d->out_tot += (unsigned long)len;
#if U4_DEBUG
            fprintf(stderr, "  postput err=%d out_tot=%lu fill=%u\n",
                    d->err, d->out_tot, d->out_fill);
#endif
        }
        if (d->s913)
            d->s914 = d->dict[s914pos];
    }
#if U4_DEBUG
    fprintf(stderr, "match pos=%lu m=%u dist=%lu len=%u c901=%u err=%d\n",
            d->out_tot, (unsigned)d->mode, d->mdist, len, (unsigned)d->c901,
            d->err);
#endif
    return 1;
}

/* sub_40EB70: block start (one block per stream here) */
static int d5v_block_start(d5v *d)
{
    unsigned i;
    memset(d->fen, 0, 0x60200u);
    memset(d->cnt, 0, 0x60200u);
    for (i = 0; i <= 768u; i++) d->ext[i] = 1;
    for (i = 0; i < 66u; i++) d5v_drescale(d->litm + (size_t)i * 6u);
    for (i = 769u; i < D5V_NCTX; i++) d5v_rescale(d, i);
    for (i = 0; i < 256u; i++) d->hist410[i] = 37440UL;
    d->p880 = 9547200UL;
    d->p894 = 0;
    d->p890 = 0;
    d->seq898 = 255u;
    /* Advance the block end (tail of sub_40EB70): +0x20000 clamped to the
     * total, then snap forward to the first container file end that is
     * >= that value.  Without the table the whole stream is one block. */
    if (d->cum && d->ncum) {
        unsigned long next = d->blockend + 0x20000UL;
        if (next > d->out_len) next = d->out_len;
        while (d->cum_idx < d->ncum && d->cum[d->cum_idx] < next)
            d->cum_idx++;
        if (d->cum_idx < d->ncum) d->blockend = d->cum[d->cum_idx];
        else d->blockend = d->out_len;
    } else {
        d->blockend = d->out_len;
    }
    /* 11-way uniform group selector */
    d->ct = 11u;
    d->range /= 11u;
    if (d->range == 0) { d->err = 7; return 7; }
    {
        unsigned point = (unsigned)((d->code / d->range) & 0xFFu);
        d->clo = point;
        d->chi = point + 1u;
        d5v_narrow(d);
        if (d->err) return d->err;
        d5v_group_switch(d, point);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

int uharc_dec5v_init(void **pctx, int method)
{
    d5v *d;
    unsigned long dictsz;
    unsigned i;

    if (!pctx) return 1;
    *pctx = 0;
    d5v_price_init();
    if (method < 40 || method > 87) return 1;
    dictsz = 1UL << (((method - 40) % 16) + 10);

    d = (d5v *)calloc(1, sizeof(*d));
    if (!d) return 2;
    d->method = method;
    d->fam = (unsigned char)(method <= 55 ? 1 : (method <= 71 ? 2 : 3));
    d->dictsz = dictsz;
    d->dictmask = dictsz - 1UL;
    d->dict = (unsigned char *)calloc(1, (size_t)(dictsz + 256UL));
    d->fen = (unsigned short *)calloc(1, (size_t)D5V_NCTX * 512u);
    d->cnt = (unsigned short *)calloc(1, (size_t)D5V_NCTX * 512u);
    d->win2 = (unsigned char *)calloc(1, 0x20000u);
    d->wcnt = (unsigned char *)calloc(1, 0x20000u);
    if (!d->dict || !d->fen || !d->cnt || !d->win2 || !d->wcnt) {
        uharc_dec5v_free(d);
        return 2;
    }
    /* contexts 1027..1040: uniform 8 (initialised once) */
    for (i = 1027u; i < D5V_NCTX; i++) {
        unsigned short *f = d->fen + (size_t)i * 256u;
        unsigned short *c = d->cnt + (size_t)i * 256u;
        unsigned k;
        f[0] = 2048u;
        c[0] = 8u;
        for (k = 1; k < 256u; k++) {
            c[k] = 8u;
            f[k] = (unsigned short)(8u * (k & (0u - k)));
        }
    }
    for (i = 769u; i < 1027u; i++) d->ext[i] = 1;
    memset(d->wcnt, 0x3F, 0x20000u);
    for (i = 0; i < 396u; i++) {
        const unsigned short *src;
        if (i < 64u) src = d5v_lseed0;
        else if (i < 66u) src = d5v_lseed1;
        else break;
        d->litm[i * 6u + 0u] = src[0];
        d->litm[i * 6u + 1u] = src[1];
        d->litm[i * 6u + 2u] = src[2];
        d->litm[i * 6u + 3u] = src[3];
        d->litm[i * 6u + 4u] = src[4];
        d->litm[i * 6u + 5u] = src[5];
    }
    for (i = 0; i < 12u; i++) d->mru[i] = D5V_M32;
    d->mdist = D5V_M32;
    d->dprob = 2048u;
    d->mode = 1;
    d->group = 0;
    d->c901 = 0xFFu;
    d->escctx = 1029u;
    d->ctx878 = 769u;
    d->rate884 = 0;
    d->p880 = 9547200UL;
    d->seq898 = 255u;
    d->lastptr = 0;
    d->hasprev = 0;
    d->prevb = 0;
    *pctx = d;
    return 0;
}

void uharc_dec5v_free(void *ctx)
{
    d5v *d = (d5v *)ctx;
    if (!d) return;
    free(d->dict);
    free(d->fen);
    free(d->cnt);
    free(d->win2);
    free(d->wcnt);
    free(d);
}

int uharc_dec5v_decode_b(void *ctx, const unsigned long *cum,
                         unsigned long ncum,
                         uharc_dec_read_cb rcb, void *rctx,
                         uharc_dec_write_cb wcb, void *wctx,
                         unsigned long out_len)
{
    d5v *d = (d5v *)ctx;
    int err;

    if (!d || !rcb || !wcb) return 1;
    if (ncum == 0UL) cum = 0;
    d->cum = cum;
    d->ncum = cum ? ncum : 0UL;
    d->cum_idx = 0UL;
    d->blockend = 0UL;
    if (out_len == 0) return 0;
    d->inb = (unsigned char *)malloc(65536UL);
    d->outb = (unsigned char *)malloc(65536UL);
    if (!d->inb || !d->outb) {
        free(d->inb); free(d->outb);
        d->inb = 0; d->outb = 0;
        return 2;
    }
    d->rcb = rcb; d->rctx = rctx;
    d->wcb = wcb; d->wctx = wctx;
    d->in_cap = 65536u;
    d->out_cap = 65536u;
    d->in_pos = 0; d->in_avail = 0;
    d->out_fill = 0;
    d->out_tot = 0;
    d->out_len = out_len;
    d->in_tot = 0;
    d->err = 0;
    d5v_rc_init(d);
    while (d->out_tot < d->out_len && !d->err) {
#if U4_DEBUG
        fprintf(stderr, "loop out=%lu err=%d grp=%u\n", d->out_tot, d->err,
                (unsigned)d->group);
#endif
        if (d->out_tot >= d->blockend) {
            if (d5v_block_start(d) != 0) break;
        }
        if (!d5v_step(d)) {
            d5v_literal(d);
        }
    }
    err = d->err;
#if U4_DEBUG
    fprintf(stderr, "decode end err=%d out_tot=%lu out_len=%lu blockend=%lu in_tot=%lu\n",
            err, d->out_tot, d->out_len, d->blockend, d->in_tot);
#endif
    if (err == 0 && d->out_fill) {
        if (wcb(wctx, d->outb, d->out_fill) != 0) err = 4;
    }
    free(d->inb);
    free(d->outb);
    d->inb = 0;
    d->outb = 0;
    return err;
}

/* single-block entry: no container file-end table */
int uharc_dec5v_decode(void *ctx, uharc_dec_read_cb rcb, void *rctx,
                       uharc_dec_write_cb wcb, void *wctx,
                       unsigned long out_len)
{
    return uharc_dec5v_decode_b(ctx, 0, 0UL, rcb, rctx, wcb, wctx, out_len);
}
