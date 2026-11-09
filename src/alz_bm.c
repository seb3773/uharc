#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "alz_priv.h"

static uint32_t bm_get_threshold(alz_dec *d, uint32_t total)
{
    d->rc.range /= total;
    return d->rc.code / d->rc.range;
}

static void bm_remove(alz_dec *d, uint32_t low, uint32_t width)
{
    d->rc.code -= low * d->rc.range;
    d->rc.range *= width;
    uha_rc_normalize(&d->rc);
}

static void bm_sse(alz_dec *d, uint32_t width, uint32_t total)
{
    uint32_t idx = ((width & 0xFFFF) << 14) / total;
    d->bm_mixer += AlzSseMap[idx];
}

static void bm_fenwick_add(alz_dec *d, int ctx, int sym, uint16_t step)
{
    int al = (sym + 1) & 0xFF;
    while (al != 0) {
        d->bm_tree[ctx][al] = (uint16_t)(d->bm_tree[ctx][al] + step);
        al = (al + (al & (-al & 0xFF))) & 0xFF;
    }
    d->bm_tree[ctx][0] = (uint16_t)(d->bm_tree[ctx][0] + step);
}

static void bm_rebuild_fenwick(alz_dec *d, int ctx)
{
    int s, i;
    for (i = 0; i < 256; i++)
        d->bm_tree[ctx][i] = 0;
    for (s = 0; s < 256; s++)
        if (d->bm_freq[ctx][s] != 0)
            bm_fenwick_add(d, ctx, s, d->bm_freq[ctx][s]);
}

static uint16_t bm_ctx_total(alz_dec *d, int c)
{
    uint16_t r = d->bm_tree[c][0];
    if (d->bm_flag != 0)
        r = (uint16_t)(r - d->bm_freq[c][d->bm_predb]);
    return r;
}

static int bm_in_context(alz_dec *d, int c, uint32_t bx, uint32_t threshold,
                         uint32_t sse_total)
{
    uint32_t rem, step, node_val, high, low, fsym, pred_freq;
    uint32_t base_idx;
    int ebp_idx, pred_active, sym;

    rem = (bx - threshold) & 0xFFFF;
    base_idx = 0;
    step = 0x80;
    pred_active = d->bm_flag != 0;
    ebp_idx = 0;
    pred_freq = 0;
    if (pred_active) {
        ebp_idx = d->bm_predb;
        pred_freq = d->bm_freq[c][d->bm_predb];
    }
    while (step != 0) {
        if (pred_active && (base_idx + step) > (uint32_t)ebp_idx) {
            node_val = d->bm_tree[c][base_idx + step];
            if (node_val < ((rem + pred_freq) & 0xFFFFFFFFu)) {
                base_idx += step;
                rem = (rem - ((node_val - pred_freq) & 0xFFFF)) & 0xFFFF;
                pred_active = 0;
            }
        } else {
            node_val = d->bm_tree[c][base_idx + step];
            if (rem > node_val) {
                base_idx += step;
                rem = (rem - node_val) & 0xFFFF;
            }
        }
        step >>= 1;
    }
    sym = (int)base_idx;
    high = (rem + threshold) & 0xFFFF;
    fsym = d->bm_freq[c][sym];
    low = (high - fsym) & 0xFFFFFFFFu;
    bm_sse(d, (high - low) & 0xFFFFFFFFu, sse_total);
    bm_remove(d, low, (high - low) & 0xFFFFFFFFu);
    return sym;
}

static int bm_decode_from_contexts(alz_dec *d, int ctx, int ctx2)
{
    uint32_t bx, combined, threshold, esc_total, th2, acc, stp, bx2, excl_sum;
    int s, known[256];

    bx = bm_ctx_total(d, ctx);
    if (bx != 0) {
        combined = (bx + d->bm_ew[ctx]) & 0xFFFF;
        threshold = bm_get_threshold(d, combined);
        if (threshold < bx)
            return bm_in_context(d, ctx, bx, threshold, combined);
        bm_sse(d, (combined - bx) & 0xFFFFFFFFu, combined);
        bm_remove(d, bx, (combined - bx) & 0xFFFFFFFFu);
        excl_sum = 0;
        for (s = 0; s < 256; s++) {
            known[s] = (d->bm_freq[ctx][s] != 0)
                    || ((d->bm_flag != 0) && (s == d->bm_predb));
            if (known[s])
                excl_sum += d->bm_freq[ctx2][s];
        }
        esc_total = (d->bm_tree[ctx2][0] - excl_sum) & 0xFFFF;
        if (esc_total == 0) {
            d->rc.corrupt = 1;
            return 0;
        }
        th2 = bm_get_threshold(d, esc_total);
        acc = 0;
        for (s = 255; s >= 0; s--) {
            if (known[s])
                continue;
            stp = d->bm_freq[ctx2][s];
            if (th2 < acc + stp) {
                bm_sse(d, stp, esc_total);
                bm_remove(d, acc, stp);
                return s;
            }
            acc = (acc + stp) & 0xFFFF;
        }
        d->rc.corrupt = 1;
        return 0;
    }
    bx2 = bm_ctx_total(d, ctx2);
    if (bx2 == 0) {
        d->rc.corrupt = 1;
        return 0;
    }
    threshold = bm_get_threshold(d, bx2);
    return bm_in_context(d, ctx2, bx2, threshold, bx2);
}

void alz_bm_rescale_entry(alz_dec *d, int ctx)
{
    int s;
    uint16_t new_ew;
    uint32_t total;

    for (s = 0; s < 256; s++) {
        if (d->bm_freq[ctx][s] > 0x10)
            d->bm_freq[ctx][s] >>= 1;
        else
            d->bm_freq[ctx][s] = 0;
    }
    bm_rebuild_fenwick(d, ctx);
    new_ew = (uint16_t)((d->bm_ew[ctx] + 1) >> 1);
    d->bm_ew[ctx] = new_ew;
    total = d->bm_tree[ctx][0];
    if (ctx < 0x300)
        d->bm_counter[ctx] = (total + new_ew) << 6;
    else
        d->bm_counter[ctx] = (total + new_ew) << 8;
}

void alz_bm_rescale_ctx2(alz_dec *d, int ctx)
{
    int s;
    for (s = 0; s < 256; s++)
        d->bm_freq[ctx][s] = (uint16_t)((d->bm_freq[ctx][s] + 1) >> 1);
    bm_rebuild_fenwick(d, ctx);
}

static void bm_escape_increment(alz_dec *d, int inner_ctx, int sym)
{
    int ctx2 = d->bm_esc_ctx;
    uint16_t step2 = AlzEscStep[inner_ctx];
    d->bm_freq[ctx2][sym] = (uint16_t)(d->bm_freq[ctx2][sym] + step2);
    bm_fenwick_add(d, ctx2, sym, step2);
    if (d->bm_tree[ctx2][0] >= 0x4000)
        alz_bm_rescale_ctx2(d, ctx2);
}

static void bm_update(alz_dec *d, int ctx, int sym)
{
    uint16_t step1, step2;
    uint32_t new_ctr;
    int new_sym, ctx2;

    ctx2 = d->bm_esc_ctx;
    step1 = AlzEntryStep[ctx];
    step2 = AlzEscStep[ctx];
    new_ctr = (uint32_t)(d->bm_counter[ctx] - (d->bm_freq[ctx][sym] + d->bm_ew[ctx]));
    new_sym = d->bm_freq[ctx][sym] == 0;
    if (new_sym) {
        d->bm_freq[ctx2][sym] = (uint16_t)(d->bm_freq[ctx2][sym] + step2);
        bm_fenwick_add(d, ctx2, sym, step2);
        if (d->bm_tree[ctx2][0] >= 0x4000)
            alz_bm_rescale_ctx2(d, ctx2);
        d->bm_ew[ctx] = (uint16_t)(d->bm_ew[ctx] + step1);
    }
    d->bm_freq[ctx][sym] = (uint16_t)(d->bm_freq[ctx][sym] + step1);
    bm_fenwick_add(d, ctx, sym, step1);
    d->bm_counter[ctx] = new_ctr;
    if (((d->bm_ew[ctx] + d->bm_tree[ctx][0]) >= 0x4000)
        || ((new_ctr & 0x80000000u) != 0))
        alz_bm_rescale_entry(d, ctx);
}

static uint32_t bm_known_map(alz_dec *d, int c, int sym, int exclude_ctx)
{
    uint32_t t;
    int s;

    t = d->bm_tree[c][0];
    if (c < 0x3F9)
        t = (t + d->bm_ew[c]) & 0xFFFF;
    if (exclude_ctx >= 0)
        for (s = 0; s < 256; s++)
            if (d->bm_freq[exclude_ctx][s] != 0)
                t = (t - d->bm_freq[c][s]) & 0xFFFF;
    if ((d->bm_flag != 0)
        && (exclude_ctx < 0 || d->bm_freq[exclude_ctx][d->bm_predb] == 0))
        t = (t - d->bm_freq[c][d->bm_predb]) & 0xFFFF;
    if (t == 0) {
        /* [GATED UHA_BMDUMP=path, RE 13.531, read-only, default-OFF,
         * NO-MECANISME] dump cost litterel PRIMARY (exclude_ctx<0) : empty t==0. */
        { static FILE *s_bmf = NULL; static int s_bmfinit = -1;
          if (s_bmfinit < 0) { const char *e = getenv("UHA_BMFREQ");
              s_bmfinit = e ? 1 : 0;
              if (s_bmfinit && e) { s_bmf = fopen(e, "w");
                  if (s_bmf) fprintf(s_bmf, "pos\tctx\tsym\tfreq\ttotal\tp\tcost\n"); } } }
        return 0;
    }
    {
        uint32_t bmidx = ((uint32_t)d->bm_freq[c][sym] << 14) / t;
        uint32_t tree0 = d->bm_tree[c][0];
        uint32_t ewc = (c < 0x3F9) ? d->bm_ew[c] : 0;
        /* [GATED UHA_BMFREQ] dump (pos,ctx,sym,num,den,p,cost,tree0,ew,predb,flag) of the
         * call primaire (exclude_ctx<0) for jointure vs oracle acc_cost legacy :
         * slice if c'is freq (numerateur) now total (denominateur) which drifts,
         * and decompose den = tree0 + ew - excl. read-only, default-OFF. */
        { static FILE *s_bmf = NULL; static int s_bmfinit = -1;
          if (s_bmfinit < 0) { const char *e = getenv("UHA_BMFREQ");
              s_bmfinit = e ? 1 : 0;
              if (s_bmfinit && e) { s_bmf = fopen(e, "w");
                  if (s_bmf) fprintf(s_bmf, "pos\tctx\tsym\tnum\tden\tp\tcost\ttree0\tew\tpredb\tflag\n"); } }
          if (s_bmf && exclude_ctx < 0)
              fprintf(s_bmf, "%u\t%d\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%d\t%d\n", (unsigned) d->st.output_pos, c, sym,
                  (unsigned) d->bm_freq[c][sym], (unsigned) t,
                  (unsigned) bmidx, (unsigned) AlzSseMap[bmidx],
                  (unsigned) tree0, (unsigned) ewc, (int) d->bm_predb, (int) d->bm_flag); }
        return AlzSseMap[bmidx];
    }
}

static uint32_t bm_sse_eval(alz_dec *d, int ctx, int sym)
{
    uint32_t tot0, tadj, ewc;
    int ctx2;

    if (d->bm_freq[ctx][sym] != 0)
        return bm_known_map(d, ctx, sym, -1);
    tot0 = d->bm_tree[ctx][0];
    tadj = tot0;
    if (d->bm_flag != 0)
        tadj = (tadj - d->bm_freq[ctx][d->bm_predb]) & 0xFFFF;
    ctx2 = d->bm_esc_ctx;
    if (tadj != 0) {
        ewc = d->bm_ew[ctx];
        return (uint32_t)AlzSseMap[(ewc << 14) / ((ewc + tadj) & 0xFFFFFFFFu)]
             + bm_known_map(d, ctx2, sym, ctx);
    }
    return bm_known_map(d, ctx2, sym, -1);
}

/* [RE c2] Cost literal REEL en read-only : returns AlzSseMap[idx] with
 * idx = 16384 * p(sym|ctx) (unite ~ 4680*(-log2 p)), without mutation d'state.
 * On s'appuie directement sure the frequencies bm_freq/bm_tree (all two
 * MAINTENUES at the encoding via bm_update), index strictement bound has 16384
 * for to avoid all depassement. bm_sse_eval n'is NOT uses here : il is
 * concu for l'state of the decodeur (bm_esc_ctx/bm_flag) and aurait lu out
 * bounds since l'encoder. En cas of fuite (sym absent of ctx), on tente
 * ctx2 (context d'echappement) then on planche has ~8 bits. */
uint32_t alz_bm_predict_cost(alz_dec *d, int ctx, int ctx2, int sym)
{
    uint32_t f, tot, idx;

    if (sym < 0 || sym > 255 || ctx < 0 || ctx >= ALZ_BM_NCTX)
        return 4680u * 8u;
    f = d->bm_freq[ctx][sym];
    tot = d->bm_tree[ctx][0];
    if (f == 0 || tot == 0) {
        if (ctx2 >= 0 && ctx2 < ALZ_BM_NCTX) {
            uint32_t f2 = d->bm_freq[ctx2][sym];
            uint32_t t2 = d->bm_tree[ctx2][0];
            if (f2 != 0 && t2 != 0) {
                idx = ((f2 << 14) / t2);
                if (idx == 0)
                    idx = 1;
                if (idx > 16384)
                    idx = 16384;
                return AlzSseMap[idx];
            }
        }
        return 4680u * 8u;
    }
    idx = (f << 14) / tot;
    if (idx == 0)
        idx = 1;
    if (idx > 16384)
        idx = 16384;
    return AlzSseMap[idx];
}

/* [GATED UHA_ACCMIX, RE 13.436, read-only, NO-MUTANT] Cost literal
 * FAITHFUL = the mixeur multi-context `decode_mix`/`acc` legacy (0x45cc88),
 * c.-d.-d. there sum some terms SSE (symbole primaire + echelle combinee
 * d'echappement + no echappement in ctx2), and NO the term unique
 * AlzSseMap[(f<<14)/tot] d'alz_bm_predict_cost. `bm_sse_eval` (l.230) is there
 * MIRROR reading-single utilisee by l'encoder lui-same (l.520/546/558) after
 * to have sets d->bm_esc_ctx ; on reproduces this geste then on RESTORES
 * l'state (no effect of bord sure the stream d'encoding). Return en unites
 * 4680*bits comparables has `acc`. */
uint32_t alz_bm_literal_cost_mix(alz_dec *d, int ctx, int ctx2, int sym)
{
    uint32_t c;
    int saved_esc;

    if (sym < 0 || sym > 255 || ctx < 0 || ctx >= ALZ_BM_NCTX
        || ctx2 < 0 || ctx2 >= ALZ_BM_NCTX)
        return 4680u * 8u;
    saved_esc   = d->bm_esc_ctx;
    d->bm_esc_ctx = ctx2;
    c = bm_sse_eval(d, ctx, sym);
    d->bm_esc_ctx = saved_esc;
    return c;
}

/* ===== [RE b1] Scorer literal AUTO-ENTRAINE (fidelite 0x414630, 13.20-22) =====
 * The scorer UHARC n'evaluates NOT the cost literal sure model cold : il ENTRAINE
 * the byte-model has measures qu'il scores the bytes of the run (add step + rescale
 * >= 0x4000), then RESTORES l'snapshot (rep movs 0x414a94) for not not
 * perturber l'state permanent. On reproduces exactement this geste :
 *   1. instantanet of the model (clone-once, as legacy) ;
 *   2. for each byte of the run : cost = AlzSseMap[(freq<<14)/total] sure
 *      l'state HOT current, THEN bm_update (l primitive reelle d'avancement)
 *      for that l'byte next path there distribution renforcee ;
 *   3. restore full of the model at the end (the scorer is without EFFET of
 *      bord sure l'state d'encoding).
 * There geometrie of context (ctx/ctx2, last/prev, escape) is the mirror strict
 * d'alz_encode_literal. No appele by the path d'emission (b1 = validation
 * isolee) ; branchement prevu en b3. */
static uint16_t s_warm_freq[ALZ_BM_NCTX][256];
static uint16_t s_warm_tree[ALZ_BM_NCTX][256];
static uint16_t s_warm_ew[ALZ_BM_NCTX];
static uint32_t s_warm_counter[ALZ_BM_NCTX];

uint32_t alz_bm_literal_cost_warm(alz_dec *d, const uint8_t *plain,
                                  uint32_t usize, uint32_t pos, uint32_t len)
{
    uint32_t p, end = pos + len, cost = 0;
    int esc = d->st.escape_changed;
    int last = (int)d->st.last_byte, prev = (int)d->st.prev_byte;
    int saved_flag = (int)d->bm_flag, saved_esc = d->bm_esc_ctx;

    if (end > usize)
        end = usize;
    if (pos >= end)
        return 0;

    memcpy(s_warm_freq,   d->bm_freq,   sizeof s_warm_freq);
    memcpy(s_warm_tree,   d->bm_tree,   sizeof s_warm_tree);
    memcpy(s_warm_ew,     d->bm_ew,     sizeof s_warm_ew);
    memcpy(s_warm_counter, d->bm_counter, sizeof s_warm_counter);

    d->bm_flag = 0;
    for (p = pos; p < end; p++) {
        int sym = (int)plain[p];
        int ctx, ctx2;

        if (!esc) {
            ctx = last;
            if ((last & 0xC0) == (prev & 0xC0))
                ctx += 0x100;
            ctx2 = ((last & 0xE0) >> 5) + 0x3F9;
        } else {
            ctx = last + 0x200;
            ctx2 = 0x401;
        }
        d->bm_esc_ctx = ctx2;
        cost += alz_bm_predict_cost(d, ctx, ctx2, sym);
        bm_update(d, ctx, sym);
        prev = last;
        last = sym;
    }

    memcpy(d->bm_freq,    s_warm_freq,   sizeof s_warm_freq);
    memcpy(d->bm_tree,    s_warm_tree,   sizeof s_warm_tree);
    memcpy(d->bm_ew,      s_warm_ew,     sizeof s_warm_ew);
    memcpy(d->bm_counter, s_warm_counter, sizeof s_warm_counter);
    d->bm_flag = (uint8_t)saved_flag;
    d->bm_esc_ctx = saved_esc;
    return cost;
}

static void bm_pred_tail(alz_dec *d, uint32_t mixer, int do_acc80, int do_acc90)
{
    if (do_acc80) {
        d->bm_table[d->bm_pcounter] = mixer;
        d->bm_acc80 += mixer;
    }
    if (do_acc90)
        d->bm_acc90 = ((d->bm_acc90 * 31) >> 5) + mixer;
    d->bm_acc8c = ((d->bm_acc8c * 31) >> 5) + mixer;
}

static int sse_pred_sym(alz_dec *d, int raw_sym)
{
    if (d->st.bm_side_active) {
        if (d->st.side_dir == 0)
            return (uint8_t)(d->st.side_bias + raw_sym);
        return (uint8_t)(d->st.side_bias - raw_sym);
    }
    return raw_sym;
}

static uint32_t bm_fenwick_prefix(alz_dec *d, int ctx, int sym)
{
    uint32_t sum = 0;
    int idx = sym;

    while (idx != 0) {
        sum = (sum + d->bm_tree[ctx][idx]) & 0xFFFF;
        idx -= idx & -idx;
    }
    return sum;
}

static int bm_symbol_range(alz_dec *d, int c, int sym,
                           uint32_t *low_out, uint32_t *width_out)
{
    uint32_t acc = 0;
    int s;
    int pred_active = d->bm_flag != 0;
    int pred = d->bm_predb;

    for (s = 0; s < 256; s++) {
        uint32_t fs;

        if (pred_active && s == pred)
            continue;
        fs = d->bm_freq[c][s];
        if (s == (int)sym) {
            *low_out = acc;
            *width_out = fs;
            return fs != 0 ? 0 : -1;
        }
        acc = (acc + fs) & 0xFFFF;
    }
    return -1;
}

static int bm_encode_in_context(alz_dec *d, int c, int sym, uint32_t sse_total)
{
    uint32_t bx, prefix, width, low;

    if (!d->w || sse_total == 0)
        return -1;
    if (d->bm_flag != 0 && (int)d->bm_predb == (int)sym)
        return -1;
    width = d->bm_freq[c][sym];
    if (width == 0)
        return -1;
    bx = bm_ctx_total(d, c);
    if (d->bm_flag == 0) {
        prefix = bm_fenwick_prefix(d, c, sym);
        if (bx < prefix + width)
            return -1;
        low = bx - prefix - width;
    } else if (bm_symbol_range(d, c, sym, &low, &width) != 0) {
        return -1;
    } else {
        if (bx < low + width)
            return -1;
        low = bx - low - width;
    }
    bm_sse(d, width, sse_total);
    return uha_rcw_encode(d->w, low, low + width, sse_total);
}

static int bm_encode_from_contexts(alz_dec *d, int ctx, int ctx2, int sym)
{
    uint32_t bx, combined, esc_total, acc, stp, bx2, excl_sum;
    int s, known[256];
    int in_primary;

    if (!d->w)
        return -1;
    bx = bm_ctx_total(d, ctx);
    if (bx != 0) {
        combined = (bx + d->bm_ew[ctx]) & 0xFFFF;
        in_primary = (d->bm_freq[ctx][sym] != 0)
                  && !(d->bm_flag != 0 && (int)d->bm_predb == sym);
        if (in_primary)
            return bm_encode_in_context(d, ctx, sym, combined);
        bm_sse(d, (combined - bx) & 0xFFFFFFFFu, combined);
        if (uha_rcw_encode(d->w, bx, combined, combined) != 0)
            return -1;
        excl_sum = 0;
        for (s = 0; s < 256; s++) {
            known[s] = (d->bm_freq[ctx][s] != 0)
                    || ((d->bm_flag != 0) && (s == d->bm_predb));
            if (known[s])
                excl_sum += d->bm_freq[ctx2][s];
        }
        if (known[sym])
            return -1;
        esc_total = (d->bm_tree[ctx2][0] - excl_sum) & 0xFFFF;
        if (esc_total == 0)
            return -1;
        acc = 0;
        for (s = 255; s >= 0; s--) {
            if (known[s])
                continue;
            stp = d->bm_freq[ctx2][s];
            if (s == (int)sym) {
                if (stp == 0)
                    return -1;
                bm_sse(d, stp, esc_total);
                return uha_rcw_encode(d->w, acc, acc + stp, esc_total);
            }
            acc = (acc + stp) & 0xFFFF;
        }
        return -1;
    }
    bx2 = bm_ctx_total(d, ctx2);
    if (bx2 == 0)
        return -1;
    return bm_encode_in_context(d, ctx2, sym, bx2);
}

int alz_bm_encode_literal(alz_dec *d, int ctx, int ctx2, int sym)
{
    uint32_t acc, decode_mix, sec;
    int saved_flag, sse_sym, raw;

    if (!d->w || sym < 0 || sym > 255)
        return -1;
    d->bm_esc_ctx = ctx2;
    d->bm_pcounter = (uint8_t)((d->bm_pcounter + 1) & 0xFF);
    acc = d->bm_acc80 - d->bm_table[d->bm_pcounter];
    d->bm_acc80 = acc;
    d->bm_mixer = 0;
    saved_flag = d->bm_flag;
    if (acc < 0x6D4250u || acc >= 0xFEFF01u) {
        if (bm_encode_from_contexts(d, ctx, ctx2, sym) != 0)
            return -1;
        decode_mix = d->bm_mixer;
        bm_update(d, ctx, sym);
        bm_pred_tail(d, decode_mix, 1, 1);
    } else if (acc < 0x91ADC0u) {
        if (d->bm_acc90 >= d->bm_acc8c) {
            if (bm_encode_from_contexts(d, ctx, ctx2, sym) != 0)
                return -1;
            decode_mix = d->bm_mixer;
            d->bm_mixer = 0;
            d->bm_esc_ctx = 0x402;
            d->bm_flag = 0;
            sse_sym = sse_pred_sym(d, sym);
            sec = bm_sse_eval(d, 0x300, sse_sym);
            bm_escape_increment(d, 0x300, sse_sym);
            d->bm_acc90 = ((d->bm_acc90 * 31) >> 5) + sec;
            d->bm_esc_ctx = ctx2;
            bm_update(d, ctx, sym);
            bm_pred_tail(d, decode_mix, 1, 0);
        } else {
            d->bm_flag = 0;
            d->bm_esc_ctx = 0x402;
            if (d->st.bm_side_active) {
                if (d->st.side_dir == 0)
                    raw = (uint8_t)(d->st.side_bias + sym);
                else
                    raw = (uint8_t)(d->st.side_bias - sym);
            } else {
                raw = sym;
            }
            if (bm_encode_from_contexts(d, 0x300, 0x402, raw) != 0)
                return -1;
            decode_mix = d->bm_mixer;
            d->bm_table[d->bm_pcounter] = decode_mix;
            d->bm_acc80 += decode_mix;
            d->bm_flag = (uint8_t)saved_flag;
            d->bm_esc_ctx = ctx2;
            d->bm_mixer = 0;
            sse_sym = sym;
            sec = bm_sse_eval(d, ctx, sse_sym);
            d->bm_esc_ctx = 0x402;
            bm_escape_increment(d, 0x300, raw);
            d->bm_acc90 = ((d->bm_acc90 * 31) >> 5) + decode_mix;
            d->bm_esc_ctx = ctx2;
            bm_update(d, ctx, sse_sym);
            bm_pred_tail(d, sec, 0, 0);
        }
    } else {
        if (uha_rcw_encode(d->w, (uint32_t)sym, (uint32_t)sym + 1, 0x100) != 0)
            return -1;
        d->bm_mixer = 0;
        decode_mix = bm_sse_eval(d, ctx, sym);
        bm_update(d, ctx, sym);
        bm_pred_tail(d, decode_mix, 1, 1);
    }
    return 0;
}

int alz_bm_decode_literal(alz_dec *d, int ctx, int ctx2)
{
    uint32_t acc, decode_mix, sec;
    int sym, saved_flag, sse_sym;

    d->bm_esc_ctx = ctx2;
    d->bm_pcounter = (uint8_t)((d->bm_pcounter + 1) & 0xFF);
    acc = d->bm_acc80 - d->bm_table[d->bm_pcounter];
    d->bm_acc80 = acc;
    d->bm_mixer = 0;
    saved_flag = d->bm_flag;
    if (acc < 0x6D4250u || acc >= 0xFEFF01u) {
        sym = bm_decode_from_contexts(d, ctx, ctx2);
        decode_mix = d->bm_mixer;
        bm_update(d, ctx, sym);
        bm_pred_tail(d, decode_mix, 1, 1);
    } else if (acc < 0x91ADC0u) {
        if (d->bm_acc90 >= d->bm_acc8c) {
            sym = bm_decode_from_contexts(d, ctx, ctx2);
            decode_mix = d->bm_mixer;
            d->bm_mixer = 0;
            d->bm_esc_ctx = 0x402;
            d->bm_flag = 0;
            sse_sym = sse_pred_sym(d, sym);
            sec = bm_sse_eval(d, 0x300, sse_sym);
            bm_escape_increment(d, 0x300, sse_sym);
            d->bm_acc90 = ((d->bm_acc90 * 31) >> 5) + sec;
            d->bm_esc_ctx = ctx2;
            bm_update(d, ctx, sym);
            bm_pred_tail(d, decode_mix, 1, 0);
        } else {
            d->bm_flag = 0;
            d->bm_esc_ctx = 0x402;
            sym = bm_decode_from_contexts(d, 0x300, 0x402);
            decode_mix = d->bm_mixer;
            d->bm_table[d->bm_pcounter] = decode_mix;
            d->bm_acc80 += decode_mix;
            d->bm_flag = (uint8_t)saved_flag;
            d->bm_esc_ctx = ctx2;
            d->bm_mixer = 0;
            if (d->st.bm_side_active) {
                if (d->st.side_dir == 0)
                    sse_sym = (uint8_t)(sym - d->st.side_bias);
                else
                    sse_sym = (uint8_t)(d->st.side_bias - sym);
            } else {
                sse_sym = sym;
            }
            sec = bm_sse_eval(d, ctx, sse_sym);
            d->bm_esc_ctx = 0x402;
            bm_escape_increment(d, 0x300, sym);
            d->bm_acc90 = ((d->bm_acc90 * 31) >> 5) + decode_mix;
            d->bm_esc_ctx = ctx2;
            bm_update(d, ctx, sse_sym);
            bm_pred_tail(d, sec, 0, 0);
            sym = sse_sym;
        }
    } else {
        sym = (int)(bm_get_threshold(d, 0x100) & 0xFF);
        bm_remove(d, (uint32_t)sym, 1);
        d->bm_mixer = 0;
        decode_mix = bm_sse_eval(d, ctx, sym);
        bm_update(d, ctx, sym);
        bm_pred_tail(d, decode_mix, 1, 1);
    }
    return sym;
}

void alz_reset_byte_model(alz_dec *d)
{
    int c, s;

    for (c = 0; c < ALZ_BM_NCTX; c++) {
        for (s = 0; s < 256; s++) {
            d->bm_tree[c][s] = 0;
            d->bm_freq[c][s] = 0;
        }
        d->bm_ew[c] = 1;
        d->bm_counter[c] = 16384;
    }
    for (c = 0x301; c <= 0x3F8; c++)
        d->bm_counter[c] = 256;
    for (c = 0x3F9; c <= 0x400; c++) {
        for (s = 0; s < 256; s++)
            d->bm_freq[c][s] = 2;
        bm_rebuild_fenwick(d, c);
        d->bm_ew[c] = 0;
    }
    for (c = 0x401; c < ALZ_BM_NCTX; c++) {
        for (s = 0; s < 256; s++)
            d->bm_freq[c][s] = 4;
        bm_rebuild_fenwick(d, c);
        d->bm_ew[c] = 0;
    }
    d->bm_mixer = 0;
    d->bm_acc80 = 0x91ADC0;
    d->bm_acc8c = 0;
    d->bm_acc90 = 0;
    for (c = 0; c < 256; c++)
        d->bm_table[c] = 37440;
    d->bm_pcounter = 255;
    d->bm_flag = 0;
    d->bm_predb = 0;
    d->bm_esc_ctx = 0;
}
