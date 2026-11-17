#include <stdlib.h>
#include <string.h>

#include "lzp.h"
#include "rangecoder.h"

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

#define UHA_SYMBOL_COUNT  319
#define UHA_BYTE_COUNT    256
#define UHA_ESCAPE_CTX    318
#define UHA_MODEL_LIMIT   16384

#define UHA_CTX_ALLFF     314
#define UHA_CTX_D1DF      315
#define UHA_CTX_D3DF      316
#define UHA_CTX_HIGHDF    317

#define UHA_NOPOS         0xFFFFFFFFu

typedef struct { uint16_t split, total; } uha_binprob;
typedef struct { uint16_t value; }        uha_bittree;

typedef struct {
    uint16_t freq[UHA_SYMBOL_COUNT][UHA_BYTE_COUNT];
    uint16_t tree[UHA_SYMBOL_COUNT][UHA_BYTE_COUNT];
    uint16_t escape_weight[UHA_SYMBOL_COUNT];
} uha_ctxmodel;

typedef struct {
    uint32_t position;
    uint32_t signature;
} uha_hash_entry;

#define UHA_HASH_SIZE 262144
#define UHA_PAIR_SIZE 65536

typedef struct {
    uha_rc         rc;
    uha_ctxmodel   model;

    int            order;
    uint32_t       ring_mask;
    uint32_t       ring_size;
    uint8_t       *ring;

    uha_hash_entry *hash;
    uint8_t       *hash_seen;
    uint8_t       *pair_seen;
    uint32_t      *last_pos_by_pair;

    uha_binprob    decision_prob[50];
    uha_bittree    rank_prob[10][512];

    uint32_t       out_pos;
    uint32_t       match_run_count;
    uint32_t       last_predicted_pos;
    int            previous_literal_ptr;
    uint32_t       last_word;
    uint32_t       ring_write_pos;
    uint32_t       last_match_distance;
    uint8_t        last_adjustment;
} uha_lzp;

static const uha_binprob seed_decision_probs[50] = {
    {11,99},{12,99},{13,99},{14,99},{14,99},{14,99},{14,99},{14,99},
    {11,99},{12,99},{13,99},{14,99},{14,99},{14,99},{14,99},{14,99},
    {11,99},{12,99},{13,99},{14,99},{14,99},{14,99},{14,99},{14,99},
    {6,99},{7,99},{8,99},{9,99},{9,99},{9,99},{9,99},{9,99},
    {6,99},{7,99},{8,99},{9,99},{9,99},{9,99},{9,99},{9,99},
    {6,99},{7,99},{8,99},{9,99},{9,99},{9,99},{9,99},{9,99},
    {49,99},{79,99}
};

static const uint8_t last_adjustment_transition[16] = {
    6, 0, 6, 0, 6, 1, 6, 2, 6, 3, 6, 3, 7, 4, 7, 5
};

static const uint8_t rank_next_state[512] = {
    0,0,0,0,0,4,0,0,3,5,0,0,2,14,0,0,
    7,9,0,0,8,12,0,0,11,13,0,0,10,30,0,0,
    15,17,0,0,16,20,0,0,19,21,0,0,18,26,0,0,
    23,25,0,0,24,28,0,0,27,29,0,0,22,62,0,0,
    31,33,0,0,32,36,0,0,35,37,0,0,34,42,0,0,
    39,41,0,0,40,44,0,0,43,45,0,0,38,54,0,0,
    47,49,0,0,48,52,0,0,51,53,0,0,50,58,0,0,
    55,57,0,0,56,60,0,0,59,61,0,0,46,254,0,0,
    63,65,0,0,64,68,0,0,67,69,0,0,66,74,0,0,
    71,73,0,0,72,76,0,0,75,77,0,0,70,86,0,0,
    79,81,0,0,80,84,0,0,83,85,0,0,82,90,0,0,
    87,89,0,0,88,92,0,0,91,93,0,0,78,110,0,0,
    95,97,0,0,96,100,0,0,99,101,0,0,98,106,0,0,
    103,105,0,0,104,108,0,0,107,109,0,0,102,118,0,0,
    111,113,0,0,112,116,0,0,115,117,0,0,114,122,0,0,
    119,121,0,0,120,124,0,0,123,125,0,0,94,190,0,0,
    127,129,0,0,128,132,0,0,131,133,0,0,130,138,0,0,
    135,137,0,0,136,140,0,0,139,141,0,0,134,150,0,0,
    143,145,0,0,144,148,0,0,147,149,0,0,146,154,0,0,
    151,153,0,0,152,156,0,0,155,157,0,0,142,174,0,0,
    159,161,0,0,160,164,0,0,163,165,0,0,162,170,0,0,
    167,169,0,0,168,172,0,0,171,173,0,0,166,182,0,0,
    175,177,0,0,176,180,0,0,179,181,0,0,178,186,0,0,
    183,185,0,0,184,188,0,0,187,189,0,0,158,222,0,0,
    191,193,0,0,192,196,0,0,195,197,0,0,194,202,0,0,
    199,201,0,0,200,204,0,0,203,205,0,0,198,214,0,0,
    207,209,0,0,208,212,0,0,211,213,0,0,210,218,0,0,
    215,217,0,0,216,220,0,0,219,221,0,0,206,238,0,0,
    223,225,0,0,224,228,0,0,227,229,0,0,226,234,0,0,
    231,233,0,0,232,236,0,0,235,237,0,0,230,246,0,0,
    239,241,0,0,240,244,0,0,243,245,0,0,242,250,0,0,
    247,249,0,0,248,252,0,0,251,253,0,0,126,0,0,0
};

static const uint8_t seen_to_tree_group[256] = {
    0,0,1,2,3,4,5,5,6,6,6,6,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
};

static const uint8_t text_class_map[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
};

/* ---- binary / bit-tree probability helpers ---- */

static void binprob_init(uha_binprob *p, uint16_t split, uint16_t total)
{
    p->split = split ? split : 1;
    p->total = (total <= p->split) ? (uint16_t)(p->split + 1) : total;
}

static void binprob_update_synthetic_one(uha_binprob *p)
{
    p->total = (uint16_t)(p->total + 64);
    if (p->total >= UHA_MODEL_LIMIT) {
        p->split = (uint16_t)(((uint32_t)p->split + 1) >> 1);
        p->total = (uint16_t)(((uint32_t)p->total + 2) >> 1);
        if (p->split == 0) p->split = 1;
        if (p->total <= p->split) p->total = (uint16_t)(p->split + 1);
    }
}

static int binprob_decode_bit(uha_binprob *p, uha_rc *rc)
{
    int bit = uha_rc_decode_binary(rc, p->split, p->total);

    if (bit == 0)
        p->split = (uint16_t)(p->split + 64);

    p->total = (uint16_t)(p->total + 64);
    if (p->total >= UHA_MODEL_LIMIT) {
        p->split = (uint16_t)(((uint32_t)p->split + 1) >> 1);
        p->total = (uint16_t)(((uint32_t)p->total + 2) >> 1);
        if (p->split == 0) p->split = 1;
        if (p->total <= p->split) p->total = (uint16_t)(p->split + 1);
    }
    return bit;
}

static void bittree_init(uha_bittree *b, uint16_t v)
{
    if (v == 0) v = 2048;
    if (v >= 4096) v = 4095;
    b->value = v;
}

static int bittree_decode_bit(uha_bittree *b, uha_rc *rc)
{
    if (uha_rc_decode_bit12(rc, b->value) == 0) {
        b->value = (uint16_t)(b->value + ((4096 - b->value) >> 6));
        return 0;
    }
    b->value = (uint16_t)(b->value - (b->value >> 6));
    return 1;
}

static int bittree_encode_bit(uha_bittree *b, uha_rcw *w, int bit)
{
    if (bit == 0) {
        if (uha_rcw_encode_fixed12(w, 0, b->value) != 0)
            return -1;
        b->value = (uint16_t)(b->value + ((4096 - b->value) >> 6));
    } else {
        if (uha_rcw_encode_fixed12(w, b->value, 4096) != 0)
            return -1;
        b->value = (uint16_t)(b->value - (b->value >> 6));
    }
    return 0;
}

/* Reference search that produced lzp_rank_paths.inc (self-check builds only). */
#ifdef UHA_CHECK_RANK_PATHS
static int rank_find_path(uint8_t seen, uint8_t state, uint8_t result,
                          uint8_t target, int *bits, int *nbits)
{
    int branch;
    uint8_t r, ns;

    if (*nbits > 32)
        return 0;
    if (state == 0)
        return result == target;

    branch = (seen <= state) ? 1 : 0;
    (void)branch;

    r = state;
    ns = rank_next_state[state * 2 + (r > state ? 1 : 0)];
    bits[*nbits] = 0;
    (*nbits)++;
    if (rank_find_path(seen, ns, r, target, bits, nbits))
        return 1;
    (*nbits)--;

    r = result;
    ns = rank_next_state[state * 2 + (r > state ? 1 : 0)];
    bits[*nbits] = 1;
    (*nbits)++;
    if (rank_find_path(seen, ns, r, target, bits, nbits))
        return 1;
    (*nbits)--;
    return 0;
}
#endif /* UHA_CHECK_RANK_PATHS */

/*
 * Precomputed rank paths.
 *
 * rank_find_path() is an exhaustive depth-first search whose outcome only
 * depends on the target symbol: the start state (6), the start result (0xFF)
 * and the depth limit are constants, and the `seen` argument does not
 * influence the search. The encoder used to run that search for every match
 * candidate length (and again to emit the chosen one), which dominated -mz
 * time on low-redundancy data. lzp_rank_paths.inc holds, for each target, the
 * exact bit path found by that very search (generated from it), so results
 * are identical. Build with -DUHA_CHECK_RANK_PATHS to re-derive the table
 * from rank_find_path() at start-up and abort on any mismatch.
 */
#include "lzp_rank_paths.inc"

#ifdef UHA_CHECK_RANK_PATHS
#include <stdio.h>
static void rank_path_table_check(void)
{
    static int checked = 0;
    int t, i;

    if (checked)
        return;
    checked = 1;
    for (t = 0; t < 256; t++) {
        int bits[40];
        int nbits = 0;
        int ok = rank_find_path(0, 6, 0xFF, (uint8_t)t, bits, &nbits);
        unsigned v = 0;
        for (i = 0; ok && i < nbits; i++)
            v |= (unsigned)bits[i] << i;
        if ((ok ? 1 : 0) != s_rank_path_tab[t].ok
            || (ok && (nbits != s_rank_path_tab[t].nbits || v != s_rank_path_tab[t].bits))) {
            fprintf(stderr, "UHA_CHECK_RANK_PATHS: mismatch for target %d\n", t);
            abort();
        }
    }
}
#else
#define rank_path_table_check() ((void)0)
#endif

static int lzp_encode_rank_symbol(uha_lzp *d, uha_rcw *w, int group,
                                  uint8_t seen, uint8_t target)
{
    unsigned path;
    int nbits;
    uint8_t state = 6;
    uint8_t result = 0xFF;
    int i, branch, node;

    if (group < 0)
        group = 0;
    if (group > 9)
        group = 9;
    if (!s_rank_path_tab[target].ok)
        return -1;
    nbits = s_rank_path_tab[target].nbits;
    path = s_rank_path_tab[target].bits;

    for (i = 0; i < nbits; i++) {
        const int bit = (int)((path >> i) & 1u);
        branch = (seen <= state) ? 1 : 0;
        node = state + branch * 256;
        if (bittree_encode_bit(&d->rank_prob[group][node], w, bit) != 0)
            return -1;
        if (bit == 0)
            result = state;
        state = rank_next_state[state * 2 + (result > state ? 1 : 0)];
    }
    return 0;
}

/* ---- context model ---- */

static void model_seed_escape(uha_ctxmodel *m)
{
    int s, i, low_bit;

    for (s = 0; s < UHA_BYTE_COUNT; s++)
        m->freq[UHA_ESCAPE_CTX][s] = 8;

    m->tree[UHA_ESCAPE_CTX][0] = (uint16_t)(UHA_BYTE_COUNT * 8);
    for (i = 1; i < UHA_BYTE_COUNT; i++) {
        low_bit = i & -i;
        m->tree[UHA_ESCAPE_CTX][i] = (uint16_t)(low_bit * 8);
    }
}

static void model_init(uha_ctxmodel *m)
{
    int c;

    memset(m->freq, 0, sizeof(m->freq));
    memset(m->tree, 0, sizeof(m->tree));
    memset(m->escape_weight, 0, sizeof(m->escape_weight));

    model_seed_escape(m);
    for (c = 0; c < UHA_SYMBOL_COUNT - 1; c++)
        m->escape_weight[c] = 1;
}

static void model_add_to_context(uha_ctxmodel *m, int ctx, int sym, int delta)
{
    uint32_t v;
    uint8_t idx;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT) return;
    if (sym < 0 || sym >= UHA_BYTE_COUNT) return;
    if (delta <= 0) return;

    v = (uint32_t)m->freq[ctx][sym] + (uint32_t)delta;
    if (v > 0xFFFF) v = 0xFFFF;
    m->freq[ctx][sym] = (uint16_t)v;

    idx = (uint8_t)(sym + 1);
    while (idx != 0) {
        v = (uint32_t)m->tree[ctx][idx] + (uint32_t)delta;
        if (v > 0xFFFF) v = 0xFFFF;
        m->tree[ctx][idx] = (uint16_t)v;
        idx = (uint8_t)(idx + (idx & -idx));
    }

    v = (uint32_t)m->tree[ctx][0] + (uint32_t)delta;
    if (v > 0xFFFF) v = 0xFFFF;
    m->tree[ctx][0] = (uint16_t)v;
}

static uint32_t model_total_of(uha_ctxmodel *m, int ctx, int prev)
{
    uint32_t res;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT)
        ctx = UHA_ESCAPE_CTX;

    res = m->tree[ctx][0];
    if (prev >= 0 && prev < UHA_BYTE_COUNT) {
        if (res > m->freq[ctx][prev])
            res -= m->freq[ctx][prev];
        else
            res = 0;
    }
    return res;
}

static int model_select_by_cumulative(uha_ctxmodel *m, int ctx, int prev,
                                      uint32_t threshold, int *symbol,
                                      uint32_t *low, uint32_t *high)
{
    int bitmask, next, idx;
    uint32_t acc, step;

    *symbol = 0;
    *low = 0;
    *high = 0;
    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT)
        return 0;

    if (prev < 0) {
        idx = 0;
        acc = 0;
        bitmask = 128;
        while (bitmask != 0) {
            next = idx + bitmask;
            if (next < UHA_BYTE_COUNT) {
                step = m->tree[ctx][next];
                if (acc + step <= threshold) {
                    idx = next;
                    acc += step;
                }
            }
            bitmask >>= 1;
        }
        if (idx >= UHA_BYTE_COUNT)
            return 0;
        *symbol = idx;
        *low = acc;
        *high = acc + m->freq[ctx][idx];
        return (*low <= threshold && threshold < *high);
    }

    acc = 0;
    for (idx = 0; idx < UHA_BYTE_COUNT; idx++) {
        if (idx == prev) continue;
        step = m->freq[ctx][idx];
        if (step == 0) continue;
        if (threshold < acc + step) {
            *symbol = idx;
            *low = acc;
            *high = acc + step;
            return 1;
        }
        acc += step;
    }
    return 0;
}

static int model_decode_from_context(uha_ctxmodel *m, uha_rc *rc, int ctx,
                                     int prev, uint32_t total)
{
    uint32_t threshold, low, high;
    int symbol;

    threshold = uha_rc_threshold(rc, total);
    if (model_select_by_cumulative(m, ctx, prev, threshold, &symbol, &low, &high)) {
        uha_rc_remove(rc, low, high);
        return symbol;
    }
    rc->corrupt = 1;
    return 0;
}

/*
 * Escape decode: the symbol is coded with the escape-context weights of every
 * symbol unseen in `ctx` (f[s] == 0), `prev` excluded, walking from 255 down.
 * The eligible weights are gathered once into g[] together with 16-symbol
 * block sums (branch-free, vectorizable); the top-down walk then skips whole
 * blocks and only scans the block that contains the threshold. Symbols with
 * a zero weight can never be selected by the legacy walk, so skipping them
 * gives the same symbol and the same low/high bounds.
 */
static int model_decode_excluded_escape(uha_ctxmodel *m, uha_rc *rc, int ctx, int prev)
{
    const uint16_t *f = m->freq[ctx];
    const uint16_t *e = m->freq[UHA_ESCAPE_CTX];
    uint16_t g[UHA_BYTE_COUNT];
    uint32_t bsum[UHA_BYTE_COUNT / 16];
    uint32_t total, threshold, acc;
    int s, b, j;

    total = 0;
#if defined(__SSE2__)
    {
        const __m128i zero = _mm_setzero_si128();
        (void)j;
        for (b = 0; b < UHA_BYTE_COUNT / 16; b++) {
            __m128i f0 = _mm_loadu_si128((const __m128i *)(f + b * 16));
            __m128i f1 = _mm_loadu_si128((const __m128i *)(f + b * 16 + 8));
            __m128i e0 = _mm_loadu_si128((const __m128i *)(e + b * 16));
            __m128i e1 = _mm_loadu_si128((const __m128i *)(e + b * 16 + 8));
            __m128i v0 = _mm_and_si128(_mm_cmpeq_epi16(f0, zero), e0);
            __m128i v1 = _mm_and_si128(_mm_cmpeq_epi16(f1, zero), e1);
            __m128i w;
            _mm_storeu_si128((__m128i *)(g + b * 16), v0);
            _mm_storeu_si128((__m128i *)(g + b * 16 + 8), v1);
            /* Unsigned widening sum of the 16 weights of the block. */
            w = _mm_add_epi32(_mm_add_epi32(_mm_unpacklo_epi16(v0, zero),
                                            _mm_unpackhi_epi16(v0, zero)),
                              _mm_add_epi32(_mm_unpacklo_epi16(v1, zero),
                                            _mm_unpackhi_epi16(v1, zero)));
            w = _mm_add_epi32(w, _mm_shuffle_epi32(w, 0x4E));
            w = _mm_add_epi32(w, _mm_shuffle_epi32(w, 0xB1));
            bsum[b] = (uint32_t)_mm_cvtsi128_si32(w);
            total += bsum[b];
        }
    }
#else
    for (b = 0; b < UHA_BYTE_COUNT / 16; b++) {
        uint32_t t = 0;
        for (j = 0; j < 16; j++) {
            uint16_t v = (f[b * 16 + j] == 0) ? e[b * 16 + j] : 0;
            g[b * 16 + j] = v;
            t += v;
        }
        bsum[b] = t;
        total += t;
    }
#endif
    if (prev >= 0 && prev < UHA_BYTE_COUNT && g[prev] != 0) {
        total -= g[prev];
        bsum[prev >> 4] -= g[prev];
        g[prev] = 0;
    }

    if (total == 0) {
        rc->corrupt = 1;
        return 0;
    }

    threshold = uha_rc_threshold(rc, total);
    acc = 0;
    for (b = UHA_BYTE_COUNT / 16 - 1; b >= 0; b--) {
        if (threshold >= acc + bsum[b]) {
            acc += bsum[b];
            continue;
        }
        for (s = b * 16 + 15; s >= b * 16; s--) {
            uint32_t step = g[s];
            if (threshold < acc + step) {
                uha_rc_remove(rc, acc, acc + step);
                return s;
            }
            acc += step;
        }
        break;
    }
    rc->corrupt = 1;
    return 0;
}

/*
 * Direct-context literal search.
 *
 * The legacy walk accumulates frequencies from symbol 255 down to 0
 * (skipping the excluded symbol `prev`) and returns the first symbol s with
 *     low(s) = sum_{k > s, k != prev} f[k] <= threshold < low(s) + f[s].
 * With T = direct_total and P(s) = sum_{k < s, k != prev} f[k], one has
 * low(s) = T - P(s) - f[s], so the condition is equivalent to
 *     P(s) <= T - 1 - threshold < P(s) + f[s],
 * i.e. a plain prefix search, done here in 8 steps on the Fenwick tree that
 * the model already maintains (tree[i] = sum of f[i - lowbit(i) .. i - 1]).
 * The exclusion of `prev` is applied on the fly to every candidate prefix.
 * Totals stay below the 16384 rescale limit, so the 16-bit tree never
 * saturates and its sums are exact. Returns the symbol (and low/high in the
 * legacy top-down orientation), or -1 when the search finds no symbol
 * (corrupt stream, same outcome as the legacy walk).
 * Build with -DUHA_CHECK_LZP_FENWICK to cross-check every decision against
 * the legacy walk.
 */
static int model_select_direct(const uha_ctxmodel *m, int ctx, int prev,
                               uint32_t total, uint32_t threshold,
                               uint32_t *low, uint32_t *high)
{
    const uint16_t *tree = m->tree[ctx];
    const uint16_t *freq = m->freq[ctx];
    uint32_t target = total - 1u - threshold;
    uint32_t fprev = 0, acc = 0, p, f;
    unsigned idx = 0, bitmask, next;
    /* prev < 0 never matches: use an index above every symbol. */
    unsigned pv = (prev >= 0 && prev < UHA_BYTE_COUNT) ? (unsigned)prev : 0x1000u;

    if (pv < UHA_BYTE_COUNT)
        fprev = freq[pv];
    for (bitmask = 128; bitmask != 0; bitmask >>= 1) {
        uint32_t v, ex;
        next = idx + bitmask;
        v = acc + tree[next];
        ex = (pv < next) ? fprev : 0u;
        if (v - ex <= target) {
            idx = next;
            acc = v;
        }
    }
    p = acc - ((pv < idx) ? fprev : 0u);
    f = freq[idx];
    if (idx == pv || f == 0 || p > target || target >= p + f)
        return -1;
    *low = total - p - f;
    *high = total - p;
    return (int)idx;
}

#ifdef UHA_CHECK_LZP_FENWICK
#include <stdio.h>
static void model_check_direct(const uha_ctxmodel *m, int ctx, int prev,
                               uint32_t threshold, int sym, uint32_t lo, uint32_t hi)
{
    uint32_t low = 0, high;
    int s;

    for (s = UHA_BYTE_COUNT - 1; s >= 0; s--) {
        if (s == prev) continue;
        high = low + m->freq[ctx][s];
        if (threshold < high) {
            if (s != sym || low != lo || high != hi) {
                fprintf(stderr, "UHA_CHECK_LZP_FENWICK: mismatch\n");
                abort();
            }
            return;
        }
        low = high;
    }
    if (sym != -1) {
        fprintf(stderr, "UHA_CHECK_LZP_FENWICK: mismatch (corrupt)\n");
        abort();
    }
}
#endif

static int model_decode_symbol(uha_ctxmodel *m, uha_rc *rc, int ctx, int prev)
{
    uint32_t direct_total, combined_total, threshold;
    uint32_t low = 0, high = 0;
    int s;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT)
        ctx = UHA_ESCAPE_CTX;

    direct_total = model_total_of(m, ctx, prev);

    if (ctx == UHA_ESCAPE_CTX) {
        if (direct_total == 0)
            direct_total = m->tree[UHA_ESCAPE_CTX][0];
        return model_decode_from_context(m, rc, UHA_ESCAPE_CTX, prev, direct_total);
    }

    if (direct_total != 0) {
        combined_total = direct_total + m->escape_weight[ctx];
        threshold = uha_rc_threshold(rc, combined_total);
        if (threshold < direct_total) {
            s = model_select_direct(m, ctx, prev, direct_total, threshold, &low, &high);
#ifdef UHA_CHECK_LZP_FENWICK
            model_check_direct(m, ctx, prev, threshold, s, low, high);
#endif
            if (s < 0) {
                rc->corrupt = 1;
                return 0;
            }
            uha_rc_remove(rc, low, high);
            return s;
        }
        uha_rc_remove(rc, direct_total, combined_total);
    }

    return model_decode_excluded_escape(m, rc, ctx, prev);
}

static uint16_t model_rescaled_frequency(uint16_t f)
{
    return f == 0 ? 0 : (uint16_t)(((uint32_t)f + 1) >> 1);
}

static void model_rebuild_tree(uha_ctxmodel *m, int ctx)
{
    int i, s, start, low_bit;
    uint32_t sum;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT) return;

    sum = 0;
    for (s = 0; s < UHA_BYTE_COUNT; s++)
        sum += m->freq[ctx][s];
    if (sum <= 0xFFFF) {
        /*
         * No partial sum can saturate: build every node from the running
         * prefix sums, tree[i] = pre[i] - pre[i - lowbit(i)] (O(256) instead
         * of O(256 log 256), identical values).
         */
        uint32_t pre[UHA_BYTE_COUNT + 1];
        pre[0] = 0;
        for (s = 0; s < UHA_BYTE_COUNT; s++)
            pre[s + 1] = pre[s] + m->freq[ctx][s];
        m->tree[ctx][0] = (uint16_t)sum;
        for (i = 1; i < UHA_BYTE_COUNT; i++)
            m->tree[ctx][i] = (uint16_t)(pre[i] - pre[i - (i & -i)]);
        return;
    }

    memset(m->tree[ctx], 0, sizeof(m->tree[ctx]));
    if (sum > 0xFFFF) sum = 0xFFFF;
    m->tree[ctx][0] = (uint16_t)sum;

    for (i = 1; i < UHA_BYTE_COUNT; i++) {
        low_bit = i & -i;
        start = i - low_bit;
        sum = 0;
        for (s = start; s < i; s++)
            sum += m->freq[ctx][s];
        if (sum > 0xFFFF) sum = 0xFFFF;
        m->tree[ctx][i] = (uint16_t)sum;
    }
}

static void model_rescale_context(uha_ctxmodel *m, int ctx)
{
    int s;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT) return;

    for (s = 0; s < UHA_BYTE_COUNT; s++)
        m->freq[ctx][s] = model_rescaled_frequency(m->freq[ctx][s]);

    if (ctx < UHA_ESCAPE_CTX)
        m->escape_weight[ctx] = (uint16_t)((m->escape_weight[ctx] >> 2) + 1);

    model_rebuild_tree(m, ctx);
}

static void model_update_symbol(uha_ctxmodel *m, int ctx, int sym)
{
    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT) return;
    if (sym < 0 || sym >= UHA_BYTE_COUNT) return;

    if (ctx != UHA_ESCAPE_CTX && m->freq[ctx][sym] == 0) {
        m->escape_weight[ctx] = (uint16_t)(m->escape_weight[ctx] + 32);
        model_add_to_context(m, UHA_ESCAPE_CTX, sym, 16);
        if (m->tree[UHA_ESCAPE_CTX][0] >= UHA_MODEL_LIMIT)
            model_rescale_context(m, UHA_ESCAPE_CTX);
    }

    model_add_to_context(m, ctx, sym, 32);
    if ((uint32_t)m->tree[ctx][0] + m->escape_weight[ctx] >= UHA_MODEL_LIMIT)
        model_rescale_context(m, ctx);
}

/* ---- LZP decoder ---- */

static void lzp_reset(uha_lzp *d, int order, const uint8_t *src, size_t srclen)
{
    int i, n;
    uint32_t initial, group;

    d->order = order;
    d->ring_size = 1u << (order + 2);
    d->ring_mask = d->ring_size - 1;

    uha_rc_init(&d->rc, src, srclen);
    model_init(&d->model);

    memset(d->ring, 0, (size_t)d->ring_size + 256);
    for (i = 0; i < UHA_HASH_SIZE; i++) {
        d->hash[i].position = UHA_NOPOS;
        d->hash[i].signature = UHA_NOPOS;
        d->hash_seen[i] = 0;
    }
    memset(d->pair_seen, 0, UHA_PAIR_SIZE);
    for (i = 0; i < UHA_PAIR_SIZE; i++)
        d->last_pos_by_pair[i] = UHA_NOPOS;

    for (i = 0; i < 50; i++)
        binprob_init(&d->decision_prob[i], seed_decision_probs[i].split,
                     seed_decision_probs[i].total);

    initial = 2560;
    for (group = 0; group < 10; group++) {
        for (n = 0; n < 512; n++)
            bittree_init(&d->rank_prob[group][n], (uint16_t)initial);
        if (initial > 64) initial -= 64;
    }

    d->out_pos = 0;
    d->match_run_count = 0;
    d->last_predicted_pos = UHA_NOPOS;
    d->previous_literal_ptr = -1;
    d->last_word = 0;
    d->ring_write_pos = 0;
    d->last_match_distance = UHA_NOPOS;
    d->last_adjustment = 0;
}

static uint32_t lzp_hash_of_history(const uha_lzp *d)
{
    return (d->last_word ^ (d->last_word >> 13)) & 0x3FFFF;
}

static uint16_t lzp_current_pair(const uha_lzp *d)
{
    return (uint16_t)(d->last_word & 0xFFFF);
}

static int lzp_literal_context(const uha_lzp *d)
{
    uint8_t lo = (uint8_t)(d->last_word & 0xFF);
    uint8_t hi = (uint8_t)((d->last_word >> 8) & 0xFF);
    uint16_t pair = lzp_current_pair(d);

    if (pair == 0xFFFF) return UHA_CTX_ALLFF;
    if (pair == 0xD1DF) return UHA_CTX_D1DF;
    if (pair == 0xD3DF) return UHA_CTX_D3DF;
    if (lo == 0xDF && text_class_map[hi] != 0) return UHA_CTX_HIGHDF;
    if (text_class_map[lo] == 0 && text_class_map[hi] != 0) return lo + 123;
    return lo;
}

static void lzp_put_byte(uha_lzp *d, uint8_t *out, uint8_t b)
{
    out[d->out_pos] = (uint8_t)~b;
    d->ring[d->ring_write_pos] = b;
    if (d->ring_write_pos < 256)
        d->ring[d->ring_size + d->ring_write_pos] = b;

    d->last_word = (d->last_word << 8) | b;
    d->out_pos++;
    d->ring_write_pos = (d->ring_write_pos + 1) & d->ring_mask;
}

static void lzp_copy_predicted(uha_lzp *d, uint8_t *out, uint32_t from,
                               uint32_t count, uint32_t usize)
{
    uint8_t b;

    while (count != 0 && d->out_pos < usize) {
        b = d->ring[from & d->ring_mask];
        lzp_put_byte(d, out, b);
        from = (from + 1) & d->ring_mask;
        count--;
    }
}

static uint8_t lzp_decode_one_literal(uha_lzp *d, uint8_t *out)
{
    int context = lzp_literal_context(d);
    int predicted = (d->previous_literal_ptr >= 0)
        ? d->ring[(uint32_t)d->previous_literal_ptr & d->ring_mask]
        : -1;
    int symbol = model_decode_symbol(&d->model, &d->rc, context, predicted);

    model_update_symbol(&d->model, context, symbol);

    d->previous_literal_ptr = -1;
    if (d->last_predicted_pos != UHA_NOPOS &&
        (uint8_t)symbol == d->ring[d->last_predicted_pos & d->ring_mask])
        d->previous_literal_ptr = (int)((d->last_predicted_pos + 1) & d->ring_mask);

    (void)out;
    return (uint8_t)symbol;
}

static uint8_t lzp_decode_rank_symbol(uha_lzp *d, int group, uint8_t seen)
{
    uint8_t state = 6;
    uint8_t result = 0xFF;
    int branch, node, bit;

    if (group < 0) group = 0;
    if (group > 9) group = 9;

    while (state != 0) {
        branch = (seen <= state) ? 1 : 0;
        node = state + branch * 256;
        bit = bittree_decode_bit(&d->rank_prob[group][node], &d->rc);
        if (bit == 0)
            result = state;
        state = rank_next_state[state * 2 + (result > state ? 1 : 0)];
    }
    return result;
}

static uint16_t lzp_candidate_pair(const uha_lzp *d, uint32_t pos)
{
    uint32_t next_pos;
    uint16_t result = (uint16_t)((uint32_t)d->ring[pos & d->ring_mask] << 8);

    next_pos = (pos + 1) & d->ring_mask;
    if (next_pos != d->ring_write_pos)
        result |= d->ring[next_pos];
    return result;
}

static int lzp_has_recent_evidence(const uha_lzp *d, uint32_t pos)
{
    uint8_t b0 = d->ring[(pos - 4) & d->ring_mask];
    uint8_t b1 = d->ring[(pos - 3) & d->ring_mask];
    uint8_t b2 = d->ring[(pos - 2) & d->ring_mask];
    uint8_t b3 = d->ring[(pos - 1) & d->ring_mask];
    uint32_t recent = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
                      ((uint32_t)b2 << 8) | (uint32_t)b3;

    if ((recent & 0x0000FFFF) == (d->last_word & 0x0000FFFF)) return 1;
    if ((recent & 0xFFFF00FF) == (d->last_word & 0xFFFF00FF)) return 1;
    if ((recent & 0xFFFFFF00) == (d->last_word & 0xFFFFFF00)) return 1;
    return 0;
}

static int lzp_try_lzp_or_match(uha_lzp *d, uint8_t *out, uint32_t usize)
{
    uint32_t h = lzp_hash_of_history(d);
    uha_hash_entry entry = d->hash[h];
    uint8_t was_seen = d->hash_seen[h];
    uint32_t pair_pos = d->last_pos_by_pair[lzp_current_pair(d)];
    uint32_t pred_pos, dist, available;
    int decision_index = 0;
    int has_hash_candidate = 0;
    int decision_bit;
    uint16_t pair;
    uint8_t pair_seen_count, rank_seen_count, length_symbol;
    int tree_group;

    d->last_predicted_pos = UHA_NOPOS;
    pred_pos = UHA_NOPOS;

    if (d->match_run_count != 0) {
        pred_pos = (d->ring_write_pos - d->last_match_distance) & d->ring_mask;
        decision_index = 48 + (d->match_run_count > 2 ? 1 : 0);
    } else if (entry.position != UHA_NOPOS && entry.signature == d->last_word) {
        pred_pos = entry.position & d->ring_mask;
        has_hash_candidate = 1;
        decision_index = 1;
    } else {
        pred_pos = (d->ring_write_pos - d->last_match_distance) & d->ring_mask;
        if (((pred_pos - d->ring_write_pos) & d->ring_mask) >= 0x104)
            if (lzp_has_recent_evidence(d, pred_pos))
                decision_index = 9;
        if (decision_index == 0 && pair_pos != UHA_NOPOS) {
            pred_pos = pair_pos & d->ring_mask;
            decision_index = 17;
        }
    }

    d->hash[h].position = d->ring_write_pos;
    d->hash[h].signature = d->last_word;
    d->last_pos_by_pair[lzp_current_pair(d)] = d->ring_write_pos;

    if (decision_index == 0 || pred_pos == UHA_NOPOS) {
        d->match_run_count = 0;
        return 0;
    }

    dist = (d->ring_write_pos - pred_pos) & d->ring_mask;

    if (((pred_pos - d->ring_write_pos) & d->ring_mask) < 256) {
        d->match_run_count = 0;
        return 0;
    }

    if (d->match_run_count == 0) {
        if (was_seen == 0)
            decision_index += 23;
        else
            decision_index -= 1;
        decision_index += d->last_adjustment;
    }
    if (decision_index < 0) decision_index = 0;
    if (decision_index > 49) decision_index = 49;

    if (d->previous_literal_ptr >= 0 &&
        d->ring[(uint32_t)d->previous_literal_ptr & d->ring_mask] ==
            d->ring[pred_pos & d->ring_mask]) {
        binprob_update_synthetic_one(&d->decision_prob[decision_index]);
        d->last_adjustment = last_adjustment_transition[(d->last_adjustment * 2 + 1) & 15];
        d->match_run_count = 0;
        return 0;
    }

    d->last_predicted_pos = pred_pos;
    decision_bit = binprob_decode_bit(&d->decision_prob[decision_index], &d->rc);
    d->last_adjustment =
        last_adjustment_transition[(d->last_adjustment * 2 + decision_bit) & 15];

    if (decision_bit != 0) {
        d->hash_seen[h] = 0;
        pair = lzp_candidate_pair(d, pred_pos);
        d->pair_seen[pair] = 0;
        d->match_run_count = 0;
        return 0;
    }

    pair = lzp_candidate_pair(d, pred_pos);
    pair_seen_count = d->pair_seen[pair];
    rank_seen_count = pair_seen_count;

    if (d->match_run_count != 0)
        tree_group = 8 + (d->match_run_count > 2 ? 1 : 0);
    else if (has_hash_candidate)
        tree_group = seen_to_tree_group[was_seen];
    else
        tree_group = seen_to_tree_group[pair_seen_count];

    length_symbol = lzp_decode_rank_symbol(d, tree_group, rank_seen_count);
    d->hash_seen[h] = length_symbol;
    d->pair_seen[pair] = length_symbol;

    d->last_match_distance = dist;
    d->last_predicted_pos = pred_pos;

    available = usize - d->out_pos;
    if (length_symbol == 0xFF) {
        if (available > 255) available = 255;
        d->previous_literal_ptr = -1;
        d->match_run_count++;
    } else {
        if ((uint32_t)length_symbol < available)
            available = (uint32_t)length_symbol;
        d->previous_literal_ptr = (int)((pred_pos + available) & d->ring_mask);
        d->match_run_count = 0;
    }

    if (available == 0)
        return 0;

    lzp_copy_predicted(d, out, pred_pos, available, usize);
    return 1;
}

static int lzp_decode_to(uha_lzp *d, uint8_t *out, uint32_t usize,
                         const uint32_t *member_ends, int nmembers)
{
    int member = 0;
    uint32_t next_boundary = 0;
    int i;

    /* AdvanceBoundary (initial) */
    {
        uint32_t target = (usize - next_boundary > 0x10000)
            ? next_boundary + 0x10000 : usize;
        while (member < nmembers && member_ends[member] < target)
            member++;
        if (member >= nmembers)
            next_boundary = usize;
        else {
            next_boundary = member_ends[member];
            if (member > 0 && member < nmembers - 1) {
                uint32_t cur = member_ends[member] - member_ends[member - 1];
                if (cur < 0x4000) {
                    while (member < nmembers - 1) {
                        uint32_t nxt = member_ends[member + 1] - member_ends[member];
                        if (nxt >= cur) break;
                        member++;
                        next_boundary = member_ends[member];
                        cur = nxt;
                    }
                }
            }
        }
    }

    while (d->out_pos < usize) {
        if (d->out_pos >= next_boundary) {
            model_init(&d->model);
            for (i = 0; i < 50; i++) {
                d->decision_prob[i].split = (uint16_t)((d->decision_prob[i].split + 7) >> 3);
                d->decision_prob[i].total = (uint16_t)((d->decision_prob[i].total + 15) >> 3);
            }
            /* AdvanceBoundary */
            {
                uint32_t target = (usize - next_boundary > 0x10000)
                    ? next_boundary + 0x10000 : usize;
                while (member < nmembers && member_ends[member] < target)
                    member++;
                if (member >= nmembers)
                    next_boundary = usize;
                else {
                    next_boundary = member_ends[member];
                    if (member > 0 && member < nmembers - 1) {
                        uint32_t cur = member_ends[member] - member_ends[member - 1];
                        if (cur < 0x4000) {
                            while (member < nmembers - 1) {
                                uint32_t nxt = member_ends[member + 1] - member_ends[member];
                                if (nxt >= cur) break;
                                member++;
                                next_boundary = member_ends[member];
                                cur = nxt;
                            }
                        }
                    }
                }
            }
        }
        if (d->rc.corrupt)
            return 3;

        if (lzp_try_lzp_or_match(d, out, usize))
            continue;

        if (d->rc.corrupt)
            return 3;

        {
            uint8_t b = lzp_decode_one_literal(d, out);
            if (d->rc.corrupt)
                return 3;
            lzp_put_byte(d, out, b);
        }
    }

    return d->rc.corrupt ? 3 : 0;
}

int uha_lzp_decode(const uint8_t *src, size_t srclen, int order, uint32_t usize,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t *out, size_t outlen)
{
    uha_lzp *d;
    int rc;

    if (order < 8 || order > 23)
        return 1;
    if (outlen < usize)
        return 2;

    d = calloc(1, sizeof(*d));
    if (!d)
        return 4;

    d->ring = malloc((size_t)(1u << (order + 2)) + 256);
    d->hash = malloc(sizeof(uha_hash_entry) * UHA_HASH_SIZE);
    d->hash_seen = malloc(UHA_HASH_SIZE);
    d->pair_seen = malloc(UHA_PAIR_SIZE);
    d->last_pos_by_pair = malloc(sizeof(uint32_t) * UHA_PAIR_SIZE);
    if (!d->ring || !d->hash || !d->hash_seen || !d->pair_seen || !d->last_pos_by_pair) {
        free(d->ring); free(d->hash); free(d->hash_seen);
        free(d->pair_seen); free(d->last_pos_by_pair); free(d);
        return 4;
    }

    lzp_reset(d, order, src, srclen);
    rc = lzp_decode_to(d, out, usize, member_ends, nmembers);

    free(d->ring); free(d->hash); free(d->hash_seen);
    free(d->pair_seen); free(d->last_pos_by_pair); free(d);
    return rc;
}

static uint32_t model_prefix_sum(uha_ctxmodel *m, int ctx, int sym)
{
    uint32_t sum = 0;
    uint8_t idx = (uint8_t)sym;

    while (idx != 0) {
        sum += m->tree[ctx][idx];
        idx = (uint8_t)(idx - (idx & -idx));
    }
    return sum;
}

static int model_encode_from_context(uha_ctxmodel *m, uha_rcw *w, int ctx,
                                     int prev, uint32_t total, int sym)
{
    uint32_t low, high, acc, step;
    int idx;

    if (total == 0)
        return -1;

    if (prev < 0) {
        low = model_prefix_sum(m, ctx, sym);
        high = low + m->freq[ctx][sym];
        if (high <= low)
            return -1;
        return uha_rcw_encode(w, low, high, total);
    }

    /*
     * Cumulative frequency below `sym`, skipping `prev`. Zero frequencies add
     * nothing, so this is a plain prefix sum (vectorizable) minus the
     * contribution of `prev` when it lies below `sym`. Same result as the
     * original symbol-by-symbol walk.
     */
    if (sym < 0 || sym >= UHA_BYTE_COUNT || sym == prev)
        return -1;
    step = m->freq[ctx][sym];
    if (step == 0)
        return -1;
    acc = 0;
    {
        const uint16_t *f = m->freq[ctx];
        for (idx = 0; idx < sym; idx++)
            acc += f[idx];
        if (prev < sym)
            acc -= f[prev];
    }
    (void)low;
    (void)high;
    return uha_rcw_encode(w, acc, acc + step, total);
}

static int model_encode_excluded_escape(uha_ctxmodel *m, uha_rcw *w,
                                        int ctx, int prev, int sym)
{
    int s;
    uint32_t total, acc, step;

    /*
     * Branch-free (vectorizable) form of the original walks: `total` sums the
     * escape weights of every symbol unseen in `ctx` except `prev`; `acc`
     * sums those strictly above `sym` (the original walk goes from 255 down).
     */
    {
        const uint16_t *f = m->freq[ctx];
        const uint16_t *e = m->freq[UHA_ESCAPE_CTX];
        uint32_t above = 0;
        int prev_unseen = (prev >= 0 && prev < UHA_BYTE_COUNT && f[prev] == 0);

        if (sym < 0 || sym >= UHA_BYTE_COUNT)
            return -1;
        total = 0;
        for (s = 0; s < UHA_BYTE_COUNT; s++)
            total += (f[s] == 0) ? (uint32_t)e[s] : 0u;
        for (s = sym + 1; s < UHA_BYTE_COUNT; s++)
            above += (f[s] == 0) ? (uint32_t)e[s] : 0u;
        if (prev_unseen) {
            total -= e[prev];
            if (prev > sym)
                above -= e[prev];
        }
        if (total == 0)
            return -1;
        if (sym == prev || f[sym] != 0)
            return -1;
        step = e[sym];
        acc = above;
        return uha_rcw_encode(w, acc, acc + step, total);
    }
}

static int model_encode_symbol(uha_ctxmodel *m, uha_rcw *w, int ctx,
                               int prev, int sym)
{
    uint32_t direct_total, combined;
    uint32_t low, high;
    int s;
    int can_direct;

    if (ctx < 0 || ctx >= UHA_SYMBOL_COUNT)
        ctx = UHA_ESCAPE_CTX;

    direct_total = model_total_of(m, ctx, prev);

    if (ctx == UHA_ESCAPE_CTX) {
        if (direct_total == 0)
            direct_total = m->tree[UHA_ESCAPE_CTX][0];
        return model_encode_from_context(m, w, UHA_ESCAPE_CTX, prev,
                                         direct_total, sym);
    }

    can_direct = (sym != prev) && (m->freq[ctx][sym] != 0) && (direct_total != 0);
    if (direct_total != 0) {
        combined = direct_total + m->escape_weight[ctx];
        if (can_direct) {
            /* Sum of the frequencies above `sym` (walk order is 255 down),
             * skipping `prev`: vectorizable suffix sum, identical result. */
            const uint16_t *f = m->freq[ctx];
            low = 0;
            for (s = sym + 1; s < UHA_BYTE_COUNT; s++)
                low += f[s];
            if (prev > sym && prev < UHA_BYTE_COUNT)
                low -= f[prev];
            high = low + f[sym];
            return uha_rcw_encode(w, low, high, combined);
        }
        if (uha_rcw_encode(w, direct_total, combined, combined) != 0)
            return -1;
    }
    return model_encode_excluded_escape(m, w, ctx, prev, sym);
}

static int binprob_encode_bit(uha_binprob *p, uha_rcw *w, int bit)
{
    int rc;

    if (bit == 0) {
        rc = uha_rcw_encode(w, 0, p->split, p->total);
        p->split = (uint16_t)(p->split + 64);
    } else {
        rc = uha_rcw_encode(w, p->split, p->total, p->total);
    }
    if (rc != 0)
        return rc;

    p->total = (uint16_t)(p->total + 64);
    if (p->total >= UHA_MODEL_LIMIT) {
        p->split = (uint16_t)(((uint32_t)p->split + 1) >> 1);
        p->total = (uint16_t)(((uint32_t)p->total + 2) >> 1);
        if (p->split == 0)
            p->split = 1;
        if (p->total <= p->split)
            p->total = (uint16_t)(p->split + 1);
    }
    return 0;
}

static void lzp_reset_encode(uha_lzp *d, int order)
{
    int i, n;
    uint32_t initial, group;

    d->order = order;
    d->ring_size = 1u << (order + 2);
    d->ring_mask = d->ring_size - 1;

    model_init(&d->model);

    memset(d->ring, 0, (size_t)d->ring_size + 256);
    for (i = 0; i < UHA_HASH_SIZE; i++) {
        d->hash[i].position = UHA_NOPOS;
        d->hash[i].signature = UHA_NOPOS;
        d->hash_seen[i] = 0;
    }
    memset(d->pair_seen, 0, UHA_PAIR_SIZE);
    for (i = 0; i < UHA_PAIR_SIZE; i++)
        d->last_pos_by_pair[i] = UHA_NOPOS;

    for (i = 0; i < 50; i++)
        binprob_init(&d->decision_prob[i], seed_decision_probs[i].split,
                     seed_decision_probs[i].total);

    initial = 2560;
    for (group = 0; group < 10; group++) {
        for (n = 0; n < 512; n++)
            bittree_init(&d->rank_prob[group][n], (uint16_t)initial);
        if (initial > 64)
            initial -= 64;
    }

    d->out_pos = 0;
    d->match_run_count = 0;
    d->last_predicted_pos = UHA_NOPOS;
    d->previous_literal_ptr = -1;
    d->last_word = 0;
    d->ring_write_pos = 0;
    d->last_match_distance = UHA_NOPOS;
    d->last_adjustment = 0;
}

static void lzp_put_enc(uha_lzp *d, uint8_t b)
{
    d->ring[d->ring_write_pos] = b;
    if (d->ring_write_pos < 256)
        d->ring[d->ring_size + d->ring_write_pos] = b;
    d->last_word = (d->last_word << 8) | b;
    d->out_pos++;
    d->ring_write_pos = (d->ring_write_pos + 1) & d->ring_mask;
}

static uint32_t lzp_match_len(const uha_lzp *d, const uint8_t *plain,
                              uint32_t usize, uint32_t pred_pos)
{
    uint32_t n = 0;
    uint32_t avail = usize - d->out_pos;
    uint32_t maxn = avail > 255 ? 255 : avail;
    uint32_t dist = (d->ring_write_pos - pred_pos) & d->ring_mask;

    if (dist == 0)
        return 0;
    while (n < maxn) {
        uint8_t b = d->ring[(pred_pos + (n % dist)) & d->ring_mask];
        uint8_t want = (uint8_t)(~plain[d->out_pos + n]);
        if (b != want)
            break;
        n++;
    }
    return n;
}

static int lzp_try_encode_match(uha_lzp *d, uha_rcw *w, const uint8_t *plain,
                                uint32_t usize)
{
    uint32_t h = lzp_hash_of_history(d);
    uha_hash_entry entry = d->hash[h];
    uint8_t was_seen = d->hash_seen[h];
    uint32_t pair_pos = d->last_pos_by_pair[lzp_current_pair(d)];
    uint32_t pred_pos, dist, match_len, available;
    int decision_index = 0;
    int has_hash_candidate = 0;
    uint16_t pair;
    uint8_t pair_seen_count, rank_seen_count, length_symbol;
    int tree_group;
    int take;

    d->last_predicted_pos = UHA_NOPOS;
    pred_pos = UHA_NOPOS;

    if (d->match_run_count != 0) {
        pred_pos = (d->ring_write_pos - d->last_match_distance) & d->ring_mask;
        decision_index = 48 + (d->match_run_count > 2 ? 1 : 0);
    } else if (entry.position != UHA_NOPOS && entry.signature == d->last_word) {
        pred_pos = entry.position & d->ring_mask;
        has_hash_candidate = 1;
        decision_index = 1;
    } else {
        pred_pos = (d->ring_write_pos - d->last_match_distance) & d->ring_mask;
        if (((pred_pos - d->ring_write_pos) & d->ring_mask) >= 0x104)
            if (lzp_has_recent_evidence(d, pred_pos))
                decision_index = 9;
        if (decision_index == 0 && pair_pos != UHA_NOPOS) {
            pred_pos = pair_pos & d->ring_mask;
            decision_index = 17;
        }
    }

    d->hash[h].position = d->ring_write_pos;
    d->hash[h].signature = d->last_word;
    d->last_pos_by_pair[lzp_current_pair(d)] = d->ring_write_pos;

    if (decision_index == 0 || pred_pos == UHA_NOPOS) {
        d->match_run_count = 0;
        return 0;
    }

    dist = (d->ring_write_pos - pred_pos) & d->ring_mask;

    if (((pred_pos - d->ring_write_pos) & d->ring_mask) < 256) {
        d->match_run_count = 0;
        return 0;
    }

    if (d->match_run_count == 0) {
        if (was_seen == 0)
            decision_index += 23;
        else
            decision_index -= 1;
        decision_index += d->last_adjustment;
    }
    if (decision_index < 0)
        decision_index = 0;
    if (decision_index > 49)
        decision_index = 49;

    if (d->previous_literal_ptr >= 0 &&
        d->ring[(uint32_t)d->previous_literal_ptr & d->ring_mask] ==
            d->ring[pred_pos & d->ring_mask]) {
        binprob_update_synthetic_one(&d->decision_prob[decision_index]);
        d->last_adjustment = last_adjustment_transition[(d->last_adjustment * 2 + 1) & 15];
        d->match_run_count = 0;
        return 0;
    }

    match_len = lzp_match_len(d, plain, usize, pred_pos);
    take = 0;
    length_symbol = 0;
    if (match_len >= 1) {
        int probe_bits[40];
        int probe_n;
        uint8_t seen_for_rank;
        int cand;

        pair = lzp_candidate_pair(d, pred_pos);
        seen_for_rank = d->pair_seen[pair];
        /* 0xFF = jeton of run full (255). The run final partial remainder encode
         * en length explicite (path emprunte by UHARC). */
        (void)seen_for_rank;
        (void)probe_bits;
        (void)probe_n;
        if (match_len >= 255) {
            if (s_rank_path_tab[0xFF].ok) {
                length_symbol = 0xFF;
                take = 1;
            }
        }
        if (!take) {
            for (cand = (int)match_len; cand >= 1; cand--) {
                if (s_rank_path_tab[(uint8_t)cand].ok) {
                    length_symbol = (uint8_t)cand;
                    take = 1;
                    break;
                }
            }
        }
    }

    d->last_predicted_pos = pred_pos;
    if (binprob_encode_bit(&d->decision_prob[decision_index], w, take ? 0 : 1) != 0)
        return -1;
    d->last_adjustment =
        last_adjustment_transition[(d->last_adjustment * 2 + (take ? 0 : 1)) & 15];

    if (!take) {
        d->hash_seen[h] = 0;
        pair = lzp_candidate_pair(d, pred_pos);
        d->pair_seen[pair] = 0;
        d->match_run_count = 0;
        return 0;
    }

    pair = lzp_candidate_pair(d, pred_pos);
    pair_seen_count = d->pair_seen[pair];
    rank_seen_count = pair_seen_count;

    if (d->match_run_count != 0)
        tree_group = 8 + (d->match_run_count > 2 ? 1 : 0);
    else if (has_hash_candidate)
        tree_group = seen_to_tree_group[was_seen];
    else
        tree_group = seen_to_tree_group[pair_seen_count];

    if (lzp_encode_rank_symbol(d, w, tree_group, rank_seen_count, length_symbol) != 0)
        return -1;
    d->hash_seen[h] = length_symbol;
    d->pair_seen[pair] = length_symbol;

    d->last_match_distance = dist;
    d->last_predicted_pos = pred_pos;

    available = usize - d->out_pos;
    if (length_symbol == 0xFF) {
        if (available > 255)
            available = 255;
        d->previous_literal_ptr = -1;
        d->match_run_count++;
    } else {
        if ((uint32_t)length_symbol < available)
            available = (uint32_t)length_symbol;
        d->previous_literal_ptr = (int)((pred_pos + available) & d->ring_mask);
        d->match_run_count = 0;
    }
    if (available == 0)
        return 0;

    {
        uint32_t i;
        for (i = 0; i < available; i++)
            lzp_put_enc(d, d->ring[(pred_pos + i) & d->ring_mask]);
    }
    return 1;
}

static uint32_t lzp_next_boundary(uint32_t usize, uint32_t next_boundary,
                                  const uint32_t *member_ends, int nmembers,
                                  int *member)
{
    uint32_t target = (usize - next_boundary > 0x10000)
        ? next_boundary + 0x10000 : usize;

    while (*member < nmembers && member_ends[*member] < target)
        (*member)++;
    if (*member >= nmembers)
        return usize;
    next_boundary = member_ends[*member];
    if (*member > 0 && *member < nmembers - 1) {
        uint32_t cur = member_ends[*member] - member_ends[*member - 1];
        if (cur < 0x4000) {
            while (*member < nmembers - 1) {
                uint32_t nxt = member_ends[*member + 1] - member_ends[*member];
                if (nxt >= cur)
                    break;
                (*member)++;
                next_boundary = member_ends[*member];
                cur = nxt;
            }
        }
    }
    return next_boundary;
}

int uha_lzp_encode(const uint8_t *plain, uint32_t usize,
                   int order,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t **out, size_t *outlen)
{
    uha_lzp *d;
    uha_rcw w;
    int rc, i, member;
    uint32_t next_boundary;

    if (!plain || !out || !outlen)
        return 2;
    if (order < 8 || order > 23)
        return 1;

    *out = NULL;
    *outlen = 0;
    rank_path_table_check();

    d = calloc(1, sizeof(*d));
    if (!d)
        return 4;

    d->ring = malloc((size_t)(1u << (order + 2)) + 256);
    d->hash = malloc(sizeof(uha_hash_entry) * UHA_HASH_SIZE);
    d->hash_seen = malloc(UHA_HASH_SIZE);
    d->pair_seen = malloc(UHA_PAIR_SIZE);
    d->last_pos_by_pair = malloc(sizeof(uint32_t) * UHA_PAIR_SIZE);
    if (!d->ring || !d->hash || !d->hash_seen || !d->pair_seen || !d->last_pos_by_pair) {
        free(d->ring); free(d->hash); free(d->hash_seen);
        free(d->pair_seen); free(d->last_pos_by_pair); free(d);
        return 4;
    }

    lzp_reset_encode(d, order);
    if (uha_rcw_init(&w) != 0) {
        free(d->ring); free(d->hash); free(d->hash_seen);
        free(d->pair_seen); free(d->last_pos_by_pair); free(d);
        return 4;
    }

    member = 0;
    next_boundary = lzp_next_boundary(usize, 0, member_ends, nmembers, &member);

    rc = 0;
    while (d->out_pos < usize) {
        if (d->out_pos >= next_boundary) {
            model_init(&d->model);
            for (i = 0; i < 50; i++) {
                d->decision_prob[i].split = (uint16_t)((d->decision_prob[i].split + 7) >> 3);
                d->decision_prob[i].total = (uint16_t)((d->decision_prob[i].total + 15) >> 3);
            }
            next_boundary = lzp_next_boundary(usize, next_boundary, member_ends,
                                              nmembers, &member);
        }
        {
            int mrc = lzp_try_encode_match(d, &w, plain, usize);
            if (mrc < 0) {
                rc = 3;
                break;
            }
            if (mrc > 0)
                continue;
        }
        {
            int context = lzp_literal_context(d);
            int predicted = (d->previous_literal_ptr >= 0)
                ? d->ring[(uint32_t)d->previous_literal_ptr & d->ring_mask]
                : -1;
            uint8_t b = (uint8_t)~plain[d->out_pos];
            if (model_encode_symbol(&d->model, &w, context, predicted, b) != 0) {
                rc = 3;
                break;
            }
            model_update_symbol(&d->model, context, b);
            d->previous_literal_ptr = -1;
            if (d->last_predicted_pos != UHA_NOPOS &&
                b == d->ring[d->last_predicted_pos & d->ring_mask])
                d->previous_literal_ptr =
                    (int)((d->last_predicted_pos + 1) & d->ring_mask);
            lzp_put_enc(d, b);
        }
    }

    if (rc == 0 && uha_rcw_flush(&w) != 0)
        rc = 3;

    free(d->ring); free(d->hash); free(d->hash_seen);
    free(d->pair_seen); free(d->last_pos_by_pair); free(d);

    if (rc != 0) {
        uha_rcw_free(&w);
        return rc;
    }
    *out = w.buf;
    *outlen = w.pos;
    w.buf = NULL;
    uha_rcw_free(&w);
    return 0;
}
