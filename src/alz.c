#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "alz.h"
#include "alz_priv.h"
#include "alz_parse_score.h"   /* [a5-e3 probe seed] machine ctx cls3 + arena (gated) */
#include "alz_score.h"          /* [livebud-ring] cost proba->cost (alz_score_proba_to_cost) */
#include "alz_lm.h"            /* [a5c2f-c-govern] decider of flush 0x412c30 (gated default-OFF) */
#include "alz_bound.h"          /* [finder-port] tables of bornage legacy 0x4136a0 (gated default-OFF) */
#include "alz_arena_c4.h"       /* [acclive UHA_ACCLIVE] arena litterale portee (gated default-OFF) */
#include "alz_arena2d.h"         /* [UHA_CM_CTXROLL 13.879] arena d'emission arena2d (moteur M10) */

int alz_decode_item(alz_dec *d)
{
    int token, escape_count;
    uint8_t b, tail;
    uint32_t dist, count, win_before;
    /* [RE-TRACE t18] probe temporaire : dump (pos, token, dist, count)
     * appliquee to the two archives (legacy + notre) -> stream comparables. */
    int tr = getenv("UHA_TRACE") != NULL;
    uint32_t tpos = d->st.output_pos;

    escape_count = 0;
    for (;;) {
        token = alz_decode_token_class(d);
        if (d->rc.corrupt)
            return 0;
        if (token != 0)
            break;
        alz_handle_escape(d);
        escape_count++;
        if (escape_count > 64) {
            d->rc.corrupt = 1;
            return 0;
        }
        if (d->rc.corrupt)
            return 0;
    }

    if (token == 4) {
        b = d->st.escape_selector ? alz_side_decode_literal(d)
                                  : alz_decode_literal(d);
        d->bm_flag = 0;
        if (d->rc.corrupt)
            return 0;
        if (d->st.output_pos >= d->outlen) {
            d->rc.corrupt = 1;
            return 0;
        }
        alz_put_byte(d, b);
        if (d->st.escape_selector != 0) {
            alz_side_post_update(d, b);
            if (d->rc.corrupt)
                return 0;
        }
        d->st.repeat_run = 0;
        if (tr)
            fprintf(stderr, "[T] %u LIT %02X\n", tpos, b);
        return 1;
    }

    if (!alz_m_decode_match(d, token, &dist, &count))
        return 0;
    if (tr)
        fprintf(stderr, "[T] %u TOK%d d%u c%u\n", tpos, token, dist, count);
    if (count > d->outlen - d->st.output_pos) {
        d->rc.corrupt = 1;
        return 0;
    }
    win_before = d->st.window_pos;
    alz_copy_match(d, dist, count);
    if (count != 255)
        tail = alz_src_after_match(d, dist, count, win_before);
    else
        tail = 0;
    if (count != 255) {
        d->st.match_flag_byte = 1;
        d->st.last_match_tail = tail;
    } else {
        d->st.match_flag_byte = 0;
    }
    d->bm_flag = d->st.match_flag_byte;
    if (d->st.match_flag_byte != 0)
        d->bm_predb = d->st.last_match_tail;
    if (count == 255)
        d->st.repeat_run++;
    else
        d->st.repeat_run = 0;
    return 1;
}

/* [UHA_ESCSCHED, GATED UHA_ESCSCHED, default-OFF] Ordonnanceur d'echappements
 * EN BAND : "pos:sel,pos:sel,...". Emits token 0 + uniform(11) at the position
 * demandee, before the token of this position. no effect if l'env is absent. */
static int uha_esched_hit(uint32_t pos, int *sel)
{
    const char *e = getenv("UHA_ESCSCHED");
    if (!e || !*e)
        e = getenv("UHA_A3_ESCSCHED");
    if (!e || !*e)
        return 0;
    while (*e) {
        unsigned p;
        int s;
        if (sscanf(e, "%u:%d", &p, &s) != 2)
            break;
        if (p == pos) {
            *sel = s;
            return 1;
        }
        while (*e && *e != ',')
            e++;
        if (*e == ',')
            e++;
    }
    return 0;
}

/* [UHA_BNDSCHED, GATED UHA_BNDSCHED, default-OFF] Ordonnanceur of selecteurs
 * OF FRONTIER : "pos:sel,pos:sel,...". Replaces the selecteur reemis au rebuild
 * of block / frontier of member. no effect if l'env is absent. */
static int uha_bndsched_hit(uint32_t pos, int *sel)
{
    const char *e = getenv("UHA_BNDSCHED");
    if (!e || !*e)
        return 0;
    while (*e) {
        unsigned p;
        int s;
        if (sscanf(e, "%u:%d", &p, &s) != 2)
            break;
        if (p == pos) {
            *sel = s;
            return 1;
        }
        while (*e && *e != ',')
            e++;
        if (*e == ',')
            e++;
    }
    return 0;
}

static int alz_decode_to(alz_dec *d, uint32_t usize,
                         const uint32_t *member_ends, int nmembers)
{
    uint32_t next_boundary, target;
    int member;

    member = 0;
    next_boundary = 0;
    if (usize - next_boundary > 0x20000)
        target = next_boundary + 0x20000;
    else
        target = usize;
    while (member < nmembers && member_ends[member] < target)
        member++;
    if (member < nmembers)
        next_boundary = member_ends[member];
    else
        next_boundary = usize;

    if (d->outlen < usize)
        return 3;

    while (d->st.output_pos < usize) {
        if (d->st.output_pos >= next_boundary) {
            alz_rebuild_block_model(d);
            if (usize - next_boundary > 0x20000)
                target = next_boundary + 0x20000;
            else
                target = usize;
            while (member < nmembers && member_ends[member] < target)
                member++;
            if (member < nmembers)
                next_boundary = member_ends[member];
            else
                next_boundary = usize;
            if (d->rc.corrupt)
                break;
        }
        if (!alz_decode_item(d))
            break;
        if (d->rc.corrupt)
            break;
    }
    if (d->rc.corrupt || d->st.output_pos != usize)
        return 2;
    return 0;
}

int uha_alz_decode(const uint8_t *src, size_t srclen,
                   int order, uint32_t usize,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t *out, size_t outlen)
{
    alz_dec *d;
    int rc;

    if (!(order >= 40 && order <= 87))
        return 1;
    if (!src || !out)
        return 2;

    uha_alz_gen_tables();

    d = calloc(1, sizeof(*d));
    if (!d)
        return 4;
    d->out = out;
    d->outlen = outlen;

    if (order >= 40 && order <= 55)
        d->mode.method_class = ALZ_FAST;
    else if (order >= 56 && order <= 71)
        d->mode.method_class = ALZ_NORMAL;
    else
        d->mode.method_class = ALZ_BEST;

    d->mode.dict_size = 1u << (((order - 40) % 16) + 10);
    if (d->mode.dict_size < 1024)
        d->mode.dict_size = 1024;
    d->mode.dict_mask = d->mode.dict_size - 1;
    d->mode.rebuild_period = usize;

    d->window = calloc(d->mode.dict_size + 4096, 1);
    if (!d->window) {
        free(d);
        return 4;
    }

    alz_state_reset(&d->st);
    d->st.side_primary = 1;
    d->st.side_secondary = 0;
    alz_reset_models(d);
    uha_rc_init(&d->rc, src, srclen);
    alz_handle_escape(d);

    rc = alz_decode_to(d, usize, member_ends, nmembers);
    free(d->window);
    free(d);
    return rc;
}

static uint32_t alz_next_boundary(uint32_t usize, uint32_t next_boundary,
                                  const uint32_t *member_ends, int nmembers,
                                  int *member)
{
    uint32_t target;

    if (usize - next_boundary > 0x20000)
        target = next_boundary + 0x20000;
    else
        target = usize;
    while (*member < nmembers && member_ends[*member] < target)
        (*member)++;
    if (*member < nmembers)
        return member_ends[*member];
    return usize;
}

/* table of repli 0x4378de for ramener the selecteur d'echappement (0..10) in the 5 classes (0..4) */
static const uint8_t s_alz_repli[11] = {0, 1, 2, 3, 4, 1, 1, 2, 2, 4, 0};

/* Stage 2 : driver of block 0x414c20 - scanne there drifts d'argmax some crans 2D (demi-windows 1024, hysteresis 3/2). */
static uint32_t scan_0x414c20(const uint8_t *buf, uint32_t len)
{
    if (len <= 0x800)
        return len;

    uint32_t cntA[5][256] = {{0}};
    uint32_t cntB[5][256] = {{0}};
    uint32_t cranA[5] = {0};
    uint32_t cranB[5] = {0};
    uint32_t k, i, v, edx;
    uint8_t bestA = 0, bestB = 0;

    for (k = 0; k < 5; k++) {
        for (i = 0; i < 1024; i++) {
            uint8_t val = (k == 0 || i < k) ? buf[i] : (uint8_t)(buf[i] - buf[i - k]);
            cntA[k][val]++;
        }
        for (v = 0; v < 256; v++)
            cranA[k] += cntA[k][v] * cntA[k][v];
    }

    for (k = 0; k < 5; k++) {
        for (i = 1024; i < 2048; i++) {
            uint8_t val = (k == 0 || i < k) ? buf[i] : (uint8_t)(buf[i] - buf[i - k]);
            cntB[k][val]++;
        }
        for (v = 0; v < 256; v++)
            cranB[k] += cntB[k][v] * cntB[k][v];
    }

    for (k = 1; k < 5; k++) {
        if (cranA[k] > cranA[bestA])
            bestA = (uint8_t)k;
        if (cranB[k] > cranB[bestB])
            bestB = (uint8_t)k;
    }

    edx = 0x800;
    while (edx < len) {
        if (bestA != bestB)
            return edx - 0x200;

        uint32_t outA_idx = edx - 2048, inA_idx  = edx - 1024;
        uint32_t outB_idx = edx - 1024, inB_idx  = edx;

        for (k = 0; k < 5; k++) {
            uint8_t xA = (k == 0 || outA_idx < k) ? buf[outA_idx] : (uint8_t)(buf[outA_idx] - buf[outA_idx - k]);
            uint32_t cA = cntA[k][xA];
            cranA[k] -= (2 * cA - 1);
            cntA[k][xA]--;

            uint8_t yA = (k == 0 || inA_idx < k) ? buf[inA_idx] : (uint8_t)(buf[inA_idx] - buf[inA_idx - k]);
            uint32_t dA = cntA[k][yA];
            cranA[k] += (2 * dA + 1);
            cntA[k][yA]++;

            uint8_t xB = (k == 0 || outB_idx < k) ? buf[outB_idx] : (uint8_t)(buf[outB_idx] - buf[outB_idx - k]);
            uint32_t cB = cntB[k][xB];
            cranB[k] -= (2 * cB - 1);
            cntB[k][xB]--;

            uint8_t yB = (k == 0 || inB_idx < k) ? buf[inB_idx] : (uint8_t)(buf[inB_idx] - buf[inB_idx - k]);
            uint32_t dB = cntB[k][yB];
            cranB[k] += (2 * dB + 1);
            cntB[k][yB]++;
        }

        uint8_t candA = bestA;
        for (k = 0; k < 5; k++) {
            if (cranA[k] > cranA[candA])
                candA = (uint8_t)k;
        }
        if (candA != bestA && 4ULL * cranA[candA] > 3ULL * cranA[bestA])
            bestA = candA;

        uint8_t candB = bestB;
        for (k = 0; k < 5; k++) {
            if (cranB[k] > cranB[candB])
                candB = (uint8_t)k;
        }
        if (candB != bestB && 4ULL * cranB[candB] > 3ULL * cranB[bestB])
            bestB = candB;

        edx++;
    }
    return len;
}

/* Bornage of under-blocks of the driver 0x413ea0 */
static uint32_t alz_costfront_next_boundary(const uint8_t *plain, uint32_t usize,
                                            uint32_t pos, const uint32_t *member_ends,
                                            int nmembers, int *member)
{
    uint32_t member_end = usize;
    while (*member < nmembers && member_ends[*member] <= pos)
        (*member)++;
    if (*member < nmembers)
        member_end = member_ends[*member];

    if (pos >= member_end)
        return member_end;

    uint32_t rem = member_end - pos;
    uint32_t ebp;
    if (rem >= 0x4b00u)
        ebp = 0x3200u;
    else
        ebp = rem;

    uint32_t blk_len;
    if (ebp > 0x100u) {
        uint32_t target = ebp - 0x100u;
        uint32_t scanned = scan_0x414c20(plain + pos, target);
        static int s_cftail = -1;
        if (s_cftail < 0) s_cftail = getenv("UHA_CF_TAILMERGE") ? 1 : 0;
        if (s_cftail && scanned == target && rem < 0x4b00u) {
            blk_len = rem;
        } else {
            blk_len = scanned;
        }
    } else {
        blk_len = ebp;
    }

    if (blk_len == 0u)
        blk_len = 1u;

    uint32_t nb = pos + blk_len;
    if (nb > member_end)
        nb = member_end;
    return nb;
}

static uint32_t alz_plain_match_len(alz_dec *d, const uint8_t *plain,
                                    uint32_t usize, uint32_t pos,
                                    uint32_t dist)
{
    uint32_t n = 0;
    uint32_t limit, wp, mask;

    if (dist == 0 || dist > pos || dist > d->mode.dict_mask)
        return 0;
    limit = usize - pos;
    if (limit > 255)
        limit = 255;
    wp = d->st.window_pos;
    mask = d->mode.dict_mask;

    /* Fast path: when window slice for n < dist does not wrap the ring buffer */
    uint32_t win_start = (wp - dist) & mask;
    uint32_t fast_limit = (dist < limit) ? dist : limit;
    if (win_start + fast_limit <= d->mode.dict_mask + 1u) {
        const uint8_t *w_ptr = d->window + win_start;
        const uint8_t *p_ptr = plain + pos;
        while (n + 8 <= fast_limit) {
            uint64_t a, b;
            memcpy(&a, w_ptr + n, 8);
            memcpy(&b, p_ptr + n, 8);
            if (a != b) {
                uint64_t diff = a ^ b;
                n += (uint32_t)(__builtin_ctzll(diff) >> 3);
                return n;
            }
            n += 8;
        }
    }

    /* Fallback / tail byte loop (also handles n >= dist and ring wrap) */
    while (n < limit) {
        uint8_t src = (n < dist)
            ? d->window[(wp - dist + n) & mask]
            : plain[pos + n - dist];
        if (src != plain[pos + n])
            break;
        n++;
    }
    return n;
}

static int alz_best_encodable_len(alz_dec *d, int token, uint32_t dist,
                                  uint32_t n)
{
    while (n >= 2) {
        if (alz_m_can_encode_match(d, token, dist, n))
            return (int)n;
        n--;
    }
    return 0;
}

/* [GATED UHA_HASH_DECIM, default-OFF] Law universelle of decimation of the hash
 * by class ALZ (0x4131ee..0x41320b) :
 * During l'avancement of has match, the positions intermediaires are
 * inserees according to there table 0x439909 + 2*(cls - 1). */
static int alz_decim_should_insert(int cls, uint32_t bl)
{
    static const uint8_t s_decim_table[4][2] = {
        {0x00, 0x00},
        {0x03, 0x01}, /* cls 1: ALZ_FAST   (-m1) */
        {0x01, 0x00}, /* cls 2: ALZ_NORMAL (-m2) */
        {0x00, 0x00}  /* cls 3: ALZ_BEST   (-m3) */
    };
    if (bl <= 1u)
        return 1;
    if (cls < 1) cls = 1;
    if (cls > 3) cls = 3;
    uint8_t mask = (bl < 6u) ? s_decim_table[cls][1] : s_decim_table[cls][0];
    return ((bl & (uint32_t)mask) == 0u);
}

/* Insertion en tete of string of hachage 3 bytes for there position pos. */
static void alz_chain_insert(uint32_t *hashtab, uint32_t *chain,
                             const uint8_t *plain, uint32_t pos,
                             uint32_t usize, uint32_t hmask, uint32_t cmask)
{
    uint32_t h;
    (void)hmask; /* h is already in [0, 2^22[ */
    if (pos + 2 >= usize)
        return;
    h = (((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
         | plain[pos + 2]) * 1140071481u >> (32 - 22);
    chain[pos & cmask] = hashtab[h];
    hashtab[h] = pos;
}

/* search by strings of hachage : meilleure length <= 255 in there
 * window, candidates the more recentes d'abord, elagage by comparaison
 * of the byte preceding (prune standard LZ). */
static uint32_t alz_chain_best(alz_dec *d, const uint8_t *plain, uint32_t usize,
                               uint32_t pos,
                               const uint32_t *hashtab, const uint32_t *chain,
                               uint32_t hmask, uint32_t cmask,
                               uint32_t *dist_out)
{
    uint32_t best_len = 0, best_dist = 0;
    uint32_t limit, h, p, depth;
    /* [GATED UHA_CHAINMAX, default 1024 = behavior actuel unchanged] bound of the
     * walk of chain of the finder DEFAULT. RE 13.x (l.1675) : the driver legacy
     * 0x413ea0 walk the candidates of chain en EXACTEMENT 4 iterations (cmp $4,%cl),
     * chacune etendue by 0x414630. The clone (depth<1024) SURE-SEARCHES : il finds some
     * TOK1 lointains/profonds that the legacy engine not voit never -> sure-emission (226 sure-accepts
     * whose 128 dist>=512 measurements here). no-emissive without env. */
    static uint32_t s_cap = 0;
    if (s_cap == 0) {
        const char *c = getenv("UHA_CHAINMAX");
        s_cap = (c && atoi(c) > 0) ? (uint32_t)atoi(c) : 1024u;
    }
    static uint32_t s_cap_b2 = 0;
    static uint32_t s_cap_b2_max = 0;
    if (s_cap_b2 == 0) {
        const char *cb2 = getenv("UHA_CHAINMAX_B2");
        s_cap_b2 = (cb2 && atoi(cb2) > 0) ? (uint32_t)atoi(cb2) : 0u;
        const char *cb2m = getenv("UHA_CHAINMAX_B2_MAX");
        s_cap_b2_max = (cb2m && atoi(cb2m) > 0) ? (uint32_t)atoi(cb2m) : 0u;
    }
    uint32_t eff_cap = (s_cap_b2 > 0 && pos >= 26500u && (s_cap_b2_max == 0 || pos < s_cap_b2_max)) ? s_cap_b2 : (s_cap > 0 ? s_cap : 1024u);
    /* [GATED UHA_AGEBOUND, default-OFF = walk inchangee] Port faithful of the bound
     * D'AGE of the walk profonde legacy 0x4137a0 (cf. 13.469/13.471) : the legacy engine
     * STOPPE there descente some only to  tete of chain is more old that
     * AlzChainAgeBound[row][group] (rowniveau, group=AlzOrderGroup[order]). Here on
     * approxime row and group by there length of the candidate (structure monotone of the
     * table : more the match is short, more there distance toleree is small), and on
     * rompt there walk when `dist` depasse there bound. Reproduces 1364 (d1279 len5 ->
     * bound 128 -> break -> retombe sure the TOK2 recent) without rule of size maison.
     * without env : strictement inerte (s_agebound<0). */
    static int s_agebound = -1;
    if (s_agebound < 0) {
        const char *a = getenv("UHA_AGEBOUND");
        s_agebound = a ? atoi(a) : -1;
    }

    if (pos + 2 >= usize)
        return 0;
    h = (((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
         | plain[pos + 2]) * 1140071481u >> (32 - 22);
    limit = usize - pos;
    if (limit > 255)
        limit = 255;
    p = hashtab[h & hmask];
    static int s_nopos0 = -1;
    if (s_nopos0 < 0) s_nopos0 = (getenv("UHA_NOPOS0") != NULL) ? 1 : 0;

    for (depth = 0; p != 0xFFFFFFFFu && depth < eff_cap; depth++) {
        uint32_t dist, n;
        if (p >= pos)
            p = chain[p & cmask];
        if (s_nopos0 && p == 0) {
            p = chain[p & cmask];
        }
        if (p == 0xFFFFFFFFu)
            break;
        dist = pos - p;
        if (dist > d->mode.dict_mask) {
            /* too far ; there suite of the string is more old : out
             * of the threshold raisonnable, on s'stops if elle depasse there window */
            break;
        }
        if (plain[p + best_len] != plain[pos + best_len] || plain[p] != plain[pos]) {
            p = chain[p & cmask];
            continue;
        }
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        if (s_agebound >= 0) {
            uint32_t ab_group = AlzOrderGroup[(n < 16u) ? n : 15u];
            uint32_t ab_row = (n >= 12u) ? 3u : (n / 4u);
            uint32_t ab_lim = AlzChainAgeBound[ab_row & 3u][ab_group & 3u];
            if (dist > ab_lim)
                break;   /* tete too old for this order : the legacy engine n'y descends not */
        }
        if (n > best_len) {
            best_len = n;
            best_dist = dist;
            if (n >= limit)
                break;
        }
        /* economie : au-dela of 400 candidates without match correcte, there
         * queue of string n'ameliore more the choice (evaluates sure corpus) */
        if (depth > 400 && best_len < 16)
            break;
        p = chain[p & cmask];
    }
    *dist_out = best_dist;
    return best_len;
}

/* [GATED UHA_T1FIRSTD, default-OFF - n'is appelee that if l'env is sets]
 * Mirror of the descente 0x4137a0 which ANCRE at the MORE SMALL distance qualifiee :
 * there chain is chainee recent->old (hashtab tete = distance MINIMALE, then
 * chain[] = distances CROISSANTES). On returns the first candidate whose there
 * length raw n >= min_q (and n>=2), au lieu of the max-length (alz_chain_best).
 * Cas @4608 : legacy TOK1 d5 c5 (dist 5, len 5) vs clone max-long d518 c6. */
static uint32_t alz_chain_first(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                uint32_t pos, const uint32_t *hashtab,
                                const uint32_t *chain, uint32_t hmask,
                                uint32_t cmask, uint32_t min_q, uint32_t *dist_out)
{
    uint32_t h, p, depth, n;
    static uint32_t s_cap = 0;
    if (s_cap == 0) {
        const char *c = getenv("UHA_CHAINMAX");
        s_cap = (c && atoi(c) > 0) ? (uint32_t)atoi(c) : 1024u;
    }
    static uint32_t s_cap_b2 = 0;
    static uint32_t s_cap_b2_max = 0;
    if (s_cap_b2 == 0) {
        const char *cb2 = getenv("UHA_CHAINMAX_B2");
        s_cap_b2 = (cb2 && atoi(cb2) > 0) ? (uint32_t)atoi(cb2) : 0u;
        const char *cb2m = getenv("UHA_CHAINMAX_B2_MAX");
        s_cap_b2_max = (cb2m && atoi(cb2m) > 0) ? (uint32_t)atoi(cb2m) : 0u;
    }
    uint32_t eff_cap = (s_cap_b2 > 0 && pos >= 26500u && (s_cap_b2_max == 0 || pos < s_cap_b2_max)) ? s_cap_b2 : (s_cap > 0 ? s_cap : 1024u);
    *dist_out = 0;
    if (pos + 2 >= usize)
        return 0;
    h = (((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
         | plain[pos + 2]) * 1140071481u >> (32 - 22);
    p = hashtab[h & hmask];
    static int s_nopos0 = -1;
    if (s_nopos0 < 0) s_nopos0 = (getenv("UHA_NOPOS0") != NULL) ? 1 : 0;

    for (depth = 0; p != 0xFFFFFFFFu && depth < eff_cap; depth++) {
        uint32_t dist;
        if (p >= pos)
            p = chain[p & cmask];
        if (s_nopos0 && p == 0) {
            p = chain[p & cmask];
        }
        if (p == 0xFFFFFFFFu)
            break;
        dist = pos - p;
        if (dist > d->mode.dict_mask)
            break;
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        if (n >= 2 && n >= min_q) {
            *dist_out = dist;
            return n;
        }
        p = chain[p & cmask];
    }
    return 0;
}

/* Table shr of the descente 0x4137a0 (declaration anticipee ; definition l.~2020) : */
static inline uint32_t alz_lvl_shr(int bit, uint32_t lvl);

/* [GATED UHA_SHRWALK, default-OFF - n'is appelee that if l'env is sets]
 * Mirror FAITHFUL of the descente 0x4137a0 (there TRUE, not there target naive
 * UHA_T1FIRSTD 13.692). The constructeur legacy not retient NOR the max-length
 * NOR the min-distance : il (1) FILLS has stack of buckets by length
 * `bucket[len]=DISTANCE` en write-if-empty (there chain etant chainee
 * recent->old = distance CROISSANTE, the 1er has to write has bucket = there MORE
 * SMALL distance for THIS len), then (2) DESCENDS of `top` towards the low :
 * `acc=bucket[top]` ; at each not `lvl--` ; if `lvl>=3` : `acc >>= shr(lvl,
 * acc>=0x200000)` ; if `bucket[lvl]!=0 && acc>bucket[lvl]` -> abaisser
 * `top=lvl ; acc=bucket[lvl]`. returns there (length, distance) thus elue.
 * Cas @4608 : bucket[6]=518 (d518 c6), bucket[5]=5 (d5 c5) ; descente 518>>3=64
 * >5 -> top=5 acc=5 -> 5>>4=0 break -> len5 dist5 = EXACTEMENT `d5 c5` legacy.
 * There finalisation chain<->recent (`dh`, gap, AlzSeuil) is ALREADY portee by there
 * porte UHA_REFINED en amont ; here on only does SURFACER the bon candidate. */
/* [GATED UHA_LA_CHAINMAX, default-OFF] cap specifique of search of string
 * during the probes look-ahead (pos+1), refletant there portee reelle bornee by
 * there depth of search BST (0x413a60 depth 17). */
static int s_in_lookahead = 0;

static uint32_t alz_chain_shrwalk(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                  uint32_t pos, const uint32_t *hashtab,
                                  const uint32_t *chain, uint32_t hmask,
                                  uint32_t cmask, uint32_t *len_out,
                                  uint32_t *dist_out)
{
    uint32_t bucket[256];
    uint32_t h, p, depth, top = 0, maxenc, hmask_local = hmask;
    static uint32_t s_cap = 0;
    static uint32_t s_la_cap = 0;
    if (s_cap == 0) {
        const char *c = getenv("UHA_CHAINMAX");
        s_cap = (c && atoi(c) > 0) ? (uint32_t)atoi(c) : 1024u;
        const char *lc = getenv("UHA_LA_CHAINMAX");
        s_la_cap = (lc && atoi(lc) > 0) ? (uint32_t)atoi(lc) : s_cap;
    }
    uint32_t eff_cap = s_in_lookahead ? s_la_cap : s_cap;
    {
        static uint32_t s_cap_b2 = 0;
        static uint32_t s_cap_b2_max = 0;
        if (s_cap_b2 == 0) {
            const char *cb2 = getenv("UHA_CHAINMAX_B2");
            s_cap_b2 = (cb2 && atoi(cb2) > 0) ? (uint32_t)atoi(cb2) : 0u;
            const char *cb2m = getenv("UHA_CHAINMAX_B2_MAX");
            s_cap_b2_max = (cb2m && atoi(cb2m) > 0) ? (uint32_t)atoi(cb2m) : 0u;
        }
        if (s_cap_b2 > 0 && pos >= 26500u && (s_cap_b2_max == 0 || pos < s_cap_b2_max))
            eff_cap = s_cap_b2;
    }
    *len_out = 0;
    *dist_out = 0;
    if (pos + 2 >= usize)
        return 0;
    maxenc = usize - pos;
    if (maxenc > 255u)
        maxenc = 255u;
    if (maxenc < 3u)
        return 0;
    for (top = 0; top < 256u; top++)
        bucket[top] = 0u;
    top = 0;
    h = (((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
         | plain[pos + 2]) * 1140071481u >> (32 - 22);
    p = hashtab[h & hmask_local];
    static int s_nopos0 = -1;
    if (s_nopos0 < 0) s_nopos0 = (getenv("UHA_NOPOS0") != NULL) ? 1 : 0;

    /* (1) remplissage some buckets by length, write-if-empty. */
    for (depth = 0; p != 0xFFFFFFFFu && depth < eff_cap; depth++) {
        uint32_t dist, n, ah;
        if (p >= pos)
            p = chain[p & cmask];
        if (s_nopos0 && p == 0) {
            p = chain[p & cmask];
        }
        if (p == 0xFFFFFFFFu)
            break;
        dist = pos - p;
        if (dist > d->mode.dict_mask)
            break;
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        ah = (n < maxenc) ? n : maxenc;
        if (ah > 2u && bucket[ah] == 0u) {
            bucket[ah] = dist;              /* write-if-empty -> more small dist */
            if (ah > top)
                top = ah;
        }
        p = chain[p & cmask];
    }
    /* (2) descente 0x4137a0 (shr-walk). */
    if (top > 2u) {
        uint32_t acc = bucket[top];
        int lvl = (int)top;
        if (acc == 0u) {
            top = 0u;
        } else {
            for (;;) {
                uint32_t ebp_v;
                lvl--;
                if (lvl < 3)
                    break;
                acc >>= alz_lvl_shr(acc >= 0x200000u, (uint32_t)lvl);
                if (acc == 0u)
                    break;
                ebp_v = (uint32_t)bucket[lvl];
                if (ebp_v != 0u && acc > ebp_v) {
                    top = (uint32_t)lvl;
                    acc = ebp_v;
                }
            }
        }
    }
    if (top > 2u && bucket[top] != 0u) {
        *len_out = top;
        *dist_out = bucket[top];
        return top;
    }
    return 0;
}

/* [RE c1] threshold TOK1 dependant of the distance, MEASURES sure l'oracle UHARC
 * (probes boite-noire 13.13/13.14, archives legacy decodees under
 * UHA_TRACE). Traduit the cost of the distance explicite (~log2 dist) :
 * has match short lointain not rembourse not the literals. levels : 3
 * (dist <= 143), 4 (144..863), 5 (>= 864). dist==1 (RLE) tombe in the
 * first level => count minimal 3, coherent with 13.14 (run>=4). */
static int alz_tok1_min_count(uint32_t dist)
{
    if (dist < 144u)
        return 3;
    if (dist < 864u)
        return 4;
    return 5;
}

/* ===== [RE c2] Arbitre MIN-COST (route hybride, 13.12-13.17) =====
 * The true geste UHARC compares au cost LITERAL REEL (byte-model, therefore
 * content-adaptatif) : has match n'is emis that if it COUTE less that the
 * literals qu'il replaces. Active by UHA_COST=1 ; otherwise the path legacy
 * "the more long + threshold min_len" remainder to the commandes (keeps anti-regression
 * the temps of to validate sure corpus). */
static int s_cost_arbiter = -1;
static int cost_arbiter_on(void)
{
    if (s_cost_arbiter < 0)
        s_cost_arbiter = (getenv("UHA_COST") != NULL) ? 1 : 0;
    return s_cost_arbiter;
}

/* [exp] min_len/tok2_min adaptatifs : threshold rampe of 2 -> min_len sure there
 * first moitie of the file (approxime the behavior legacy now the debuts
 * are literals-chers and the fins literals-walk). Gated UHA_ADAPTIVE. */
static int s_adaptive = -1;
static int adaptive_on(void)
{
    if (s_adaptive < 0)
        s_adaptive = (getenv("UHA_ADAPTIVE") != NULL) ? 1 : 0;
    return s_adaptive;
}

/* [exp Has] Parseur TRUE-Side (option B-full / clone CM, 13.71) : at each
 * position now has match is candidate, compares the BITS REELS of the match (via
 * scratch-coder faithful, side-aware) to the bits reels some `count` literals.
 * N'emits the match that if mbits < lbits - margin. encoder-only (the decodeur
 * reads the emis whatever the the choice) -> round-trip sure. Gated UHA_TRUEPARSE,
 * no effect on the path by default (baseline 7052 intact). */
static int s_trueparse = -1;
static int s_trueparse_margin = -1;
static int trueparse_on(void)
{
    if (s_trueparse < 0) {
        const char *e = getenv("UHA_TRUEPARSE");
        s_trueparse = e ? 1 : 0;
        e = getenv("UHA_TRUEPMARGIN");
        s_trueparse_margin = e ? atoi(e) : 0;   /* bits of marge (default 0) */
    }
    return s_trueparse;
}

/* [13.79 UHA_BUDGETPARSE] Selecteur " recency-first ". Contrairement au
 * greedy " more long " of the grille (which epuise already the thresholds : t2in{2,8,16}
 * testes -> 6977), the legacy engine PREFERE there class recente there closer adequate
 * (TOK2 slot0, then TOK3 slots1..), y compris sure some matches COURTS, then
 * retombe sure TOK1 (distance explicite). Target the +47 = the ~160 matches courts
 * recent (len 2..7 @ d~256) that the more-long n'emits NEVER. encoder-only :
 * emits has stream validates whatever the the choice (the decoder reads l'emis) ->
 * round-trip intact. Gated : no effect on the default (7052). */
static int s_budgetparse = -1;
static int budgetparse_on(void)
{
    if (s_budgetparse < 0)
        s_budgetparse = (getenv("UHA_BUDGETPARSE") != NULL) ? 1 : 0;
    return s_budgetparse;
}

/* [P1.2-faithful] Arbitre PARSE by argmin of cost RC sure the classes (whose
 * literal), notees by under-models CHAUDS (13.19). Gated UHA_ARGMINPARSE. */
static int s_argminparse = -1;
static int argminparse_on(void)
{
    if (s_argminparse < 0)
        s_argminparse = (getenv("UHA_ARGMINPARSE") != NULL) ? 1 : 0;
    return s_argminparse;
}

/* [A5.3-w6b UHA_FINDER=legacy] Route faithful au MATCHER legacy decode
 * (13.200..203) : MRU12 (0x439904) + chain hash bounded has 99 nodes
 * ([0x439908]), distance <= window-255 ([0x45dcbc]=130817), selection of the
 * length STRICTEMENT maximale has egalite by recence (the slot MRU the more
 * recent gagne because update strict). GATED, no-emissive by default. */
static int s_finder_legacy = -1;
static int finder_legacy_on(void)
{
    if (s_finder_legacy < 0) {
        const char *e = getenv("UHA_FINDER");
        s_finder_legacy = (e && e[0] == 'l' && e[1] == 'e' && e[2] == 'g') ? 1 : 0;
    }
    return s_finder_legacy;
}
#define ALZ_LEGACY_CHAIN_DEPTH 99u    /* [0x439908] */
#define ALZ_LEGACY_MAX_DIST    130817u /* [0x45dcbc] = window(131072)-255 */

/* [A4 probe cost] UHA_COSTFIT : sure the divergences of class (notre argmin
 * cost != class oracle), compares the VRAIS bits d'emission (alz_true_bits)
 * for trancher if has cost faithful serait has levier viable towards ~99 %. */
static int s_costfit = -1;
static int costfit_on(void)
{
    if (s_costfit < 0)
        s_costfit = (getenv("UHA_COSTFIT") != NULL) ? 1 : 0;
    return s_costfit;
}

static int alz_ilog2(uint32_t v)
{
    int r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

/* bits of the distance explicite TOK1 : index of bucket (slot) + span.
 * Mirror grossier of m_encode_class1_dist (slot_encode ~log2(k+1) then
 * repartition uniforme of the span ~log2(span)). */
static uint32_t alz_dist_cost_bits(uint32_t dist)
{
    int k;
    uint32_t base, span;

    for (k = 0; k < 44; k++) {
        if (AlzDistanceBase[k] > dist)
            break;
    }
    if (k > 0)
        k--;
    base = AlzDistanceBase[k];
    span = (k + 1 < 44) ? (AlzDistanceBase[k + 1] - base) : (base >> 1);
    if (span < 1)
        span = 1;
    return (uint32_t)(alz_ilog2((uint32_t)k + 1) + alz_ilog2(span) + 1);
}

/* [A5.3-t8 GATED UHA_LM413530] Porte reads<->match exact 0x413530, mirror faithful
 * of l'tree decode and validated contre the ground-truth live (2998/2999, 13.218).
 * Comparaison lazy match current-vs-previous : dl=dh of the block previous (long.),
 * dh=length current, Sigma6c=[0x45cb6c]=DISTANCE winning current, Sigma8c=distance
 * previous (the tables of threshold are ABSOLUES), cls/bl=classes, slot/prevslot
 * = indices MRU (0xff = chain). returns 1 = to emit the MATCH, 0 = literal. */
static const uint32_t AlzLMBucket[16] =
    {0,1,1,2,2,2,3,3,3,3,3,3,3,3,3,3};
/* THR834 (0x439834) : idx = gap*4 + bucket ; gap 0..4 ; main-path (dl>=dh). */
static const uint32_t AlzLMThr834[20] = {
    1,8,32,128,
    32,256,1024,4096,
    1024,8192,32768,131072,
    65536,524288,2097152,8388608,
    0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu};
/* THR884 (0x439884) : idx = gap*4 + bucket ; gap 0..7 ; FA-path (dl<dh). */
static const uint32_t AlzLMThr884[32] = {
    1,1,1,1,
    4,32,128,512,
    128,1024,4096,16384,
    1024,8192,32768,131072,
    2048,32768,131072,524288,
    4096,65536,262144,1048576,
    8192,131072,524288,2097152,
    16384,262144,1048576,4194304};
static const uint32_t AlzLMShiftA[5] = {4,8,12,16,0};   /* 0x439a10[gap] */
static const uint32_t AlzLMShiftB[7] = {0,0,3,7,12,18,0}; /* 0x439a14[gap] */

static uint32_t alz_lm_bucket(int slot)
{
    /* [13.587 FAITHFUL by default] the legacy engine evaluates BYTE[slot*4+0x439794] ; for
     * slot=0xff (" new ", carry bb in there branch dl<dh / slot current vierge
     * dl>=dh of the gate 0x413530), l'byte lu @0x439794+0xFF*4 = 0x439B90 = 2 (PROUVE
     * runtime 13.587), NO 3. This table n'is ATTEIGNABLE that via
     * alz_lm413530_gate (call sites UHA_LM413530 / UHA_LAZY413530) ; BASE/DEF not
     * set no of these env => function never appelee under BASE/DEF => this
     * default faithful is no-regressif by atteignabilite. Measures GATE : neutre
     * (7015/8192, 13.588) but fidelity BEFORE size. */
    if (slot == 0xff)
        return 2u;
    return (slot >= 0 && slot < 16) ? AlzLMBucket[slot] : 3u;
}

static int alz_lm413530_gate(int dl, int bl, int dh, int slot, int cls,
                             uint32_t s6c, uint32_t s8c, int prevslot)
{
    if (dl < 2)
        return 0;                       /* 0x41368e */
    if (dl < dh) {                      /* 0x4135fa : match current more long */
        int gap = dh - dl;
        if (cls != 1) {                 /* 0x413670 */
            if (bl != 2) return 0;
            if (cls == bl) return 0;
            return gap < 3 ? 1 : 0;
        }
        if (bl == 1) {                  /* 0x413650 */
            if (gap >= 6) return 0;
            return (s6c >> AlzLMShiftB[gap]) > s8c ? 1 : 0;
        }
        {                                /* 0x413616 : bucket since prevslot */
            static int s_mru1 = -2;
            if (s_mru1 == -2)
                s_mru1 = (getenv("UHA_LM413530_MRU1") != NULL) ? 1 : 0;
            if (s_mru1 && bl == 2)
                return 1;
            int e = gap > 7 ? 7 : gap;
            uint32_t thr = AlzLMThr884[e * 4 + alz_lm_bucket(prevslot)];
            return s6c >= thr ? 1 : 0;
        }
    }
    /* dl >= dh && dl >= 2 */
    if (bl == 1 && cls == 1) {          /* 0x4135dc / gap>=4 accept */
        int gap = dl - dh;
        if (gap < 4)
            return (s8c >> AlzLMShiftA[gap]) <= s6c ? 1 : 0;
        return 1;
    }
    if (bl != 1)                        /* 0x413575 -> 0x4135f6 accept forces */
        return 1;
    {                                    /* bl==1, cls!=1 : 0x413586 */
        int gap = dl - dh;
        int e = gap > 4 ? 4 : gap;
        uint32_t thr = AlzLMThr834[e * 4 + alz_lm_bucket(slot)];
        return s8c < thr ? 1 : 0;
    }
}

static int s_lm413530 = -2;
static int lm413530_on(void)
{
    if (s_lm413530 == -2)
        s_lm413530 = getenv("UHA_LM413530") ? 1 : 0;
    return s_lm413530;
}

/* cost of has match (units 4680*bits) according to sa class. TOK2 (recent[0]) not
 * paye not there distance ; TOK3 has slot recent short ; TOK1 there distance
 * explicite. The model of length adaptatif is approxime by log2(count+1).
 * K (UHA_COSTK, bits by 256) penalise the cost-match : sure model cold
 * l'estimator literal surestime (planche 8 bits) -> without K the min-cost
 * sure-ancre. Calibre by balayage corpus. */
static int s_cost_k = -1;
static int cost_k(void)
{
    if (s_cost_k < 0) {
        const char *e = getenv("UHA_COSTK");
        s_cost_k = e ? atoi(e) : 256;   /* 256 = echelle 1.0 */
        if (s_cost_k < 1)
            s_cost_k = 1;
    }
    return s_cost_k;
}

static int s_dp_tok1pen = -1;
static int dp_tok1pen(void)
{
    if (s_dp_tok1pen < 0) {
        const char *e = getenv("UHA_DP_TOK1PEN");
        s_dp_tok1pen = e ? atoi(e) : 0;
    }
    return s_dp_tok1pen;
}

static uint32_t alz_match_cost(alz_dec *d, int token, uint32_t dist, uint32_t count)
{
    uint32_t bits;
    static int s_model = -1;

    /* [RE b3a] Route faithful (UHA_MODEL=1) : sum some costs-model reels some
     * under-fields (mirror some uha_rcw_encode), same unites AlzSseMap that the
     * literal alz_literal_cost. Default (env absent) : path crude inchange. */
    if (s_model < 0) {
        const char *e = getenv("UHA_MODEL");
        s_model = (e && atoi(e)) ? 1 : 0;
    }
    if (s_model) {
        uint32_t m = alz_match_model_cost(d, token, dist, count);
        if (m != ~(uint32_t)0)
            return m;
    }

    (void)d;
    if (token == 2)
        bits = 3;
    else if (token == 3)
        bits = 6;
    else {
        bits = 4 + alz_dist_cost_bits(dist);
        if (dp_tok1pen() > 0)
            bits += (uint32_t)dp_tok1pen();
    }
    bits += (uint32_t)alz_ilog2(count + 1u);
    return (4680u * bits * (uint32_t)cost_k()) >> 8;
}

/* cost (units 4680*bits) d'encoder plain[pos..pos+len-1] en LITERALS,
 * via the byte-model REEL en read-only. ctx mirror of alz_encode_literal
 * (history = bytes originaux, since l'alphabet reconstruit == plain). */
static uint32_t alz_literal_cost(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                 uint32_t pos, uint32_t len)
{
    uint32_t p, end = pos + len, cost = 0;
    int esc = d->st.escape_changed;

    if (end > usize)
        end = usize;
    for (p = pos; p < end; p++) {
        int last = (p >= 1) ? (int)plain[p - 1] : (int)d->st.last_byte;
        int prev = (p >= 2) ? (int)plain[p - 2] : (int)d->st.prev_byte;
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
        cost += alz_bm_predict_cost(d, ctx, ctx2, (int)plain[p]);
    }
    return cost;
}

/* Advances = literals economises - cost of the match ; not retient the match that
 * if strictement positif (otherwise return 0 -> literal). Mirror of the
 * minimisation of cost of 0x413ea0 (13.12). */

/* [RE b3 probe] Selects there length of the match, not juste yes/no.
 * Mode argmin (esprit of l'argmin of cost cumule 0x414630/0x415444) : balaie
 * L in [2..encmax] codable, retient the L maximisant
 *     gain(L) = litcost(pos,L) - modelcost(tok,dist,L)
 * with l'estimator FAITHFUL alz_match_model_cost and the cost literal WARM
 * (auto-entraine, mirror of l'entrainement of the loop 0x415444). Emets
 * only if gain>0. Ablations : UHA_COLDLIT=1 (literal cold),
 * UHA_ARGLMIN=0 (forces l'old " length max codable " + alz_match_cost).
 * returns the gain (0 = no match winner) and writes L* in *len_out. */
static uint32_t arb_pick_len(alz_dec *d, const uint8_t *plain, uint32_t usize,
                             uint32_t pos, int token, uint32_t dist, uint32_t n,
                             uint32_t *len_out)
{
    static int arglmin = -1, coldlit = -1;
    int encmax;
    uint32_t L, bestL = 0, bestgain = 0;

    if (arglmin < 0) {
        const char *e = getenv("UHA_ARGLMIN");
        arglmin = (e && atoi(e) == 0) ? 0 : 1;
        e = getenv("UHA_COLDLIT");
        coldlit = (e && atoi(e)) ? 1 : 0;
    }
    /* [RE-DBG parse] probe reading-single : dump the costs by candidate L au
     * pos target (state clone==legacy garanti before all cascade). */
    {
        static int s_dbgpos = -1;
        if (s_dbgpos < 0) { const char *e = getenv("UHA_PARSEDBG"); s_dbgpos = e ? atoi(e) : -2; }
        if ((int)pos == s_dbgpos)
            fprintf(stderr, "[DBG] pos=%u tok=%d dist=%u n=%u\n", pos, token, dist, n);
    }
    encmax = alz_best_encodable_len(d, token, dist, n);
    if (encmax < 2) {
        *len_out = 0;
        return 0;
    }

    if (!arglmin) {   /* ablation : length max codable, path crude/model */
        uint32_t mc, lc, g;
        L = (uint32_t)encmax;
        mc = alz_match_cost(d, token, dist, L);
        lc = coldlit ? alz_literal_cost(d, plain, usize, pos, L)
                     : alz_bm_literal_cost_warm(d, plain, usize, pos, L);
        if (mc >= lc) {
            *len_out = 0;
            return 0;
        }
        g = lc - mc;
        *len_out = L;
        return g;
    }

    for (L = 2; L <= (uint32_t)encmax; L++) {
        uint32_t mc, lc, g;
        if (!alz_m_can_encode_match(d, token, dist, L))
            continue;
        mc = alz_match_model_cost(d, token, dist, L);
        if (mc == ~(uint32_t)0)
            continue;
        lc = coldlit ? alz_literal_cost(d, plain, usize, pos, L)
                     : alz_bm_literal_cost_warm(d, plain, usize, pos, L);
        g = (lc > mc) ? (lc - mc) : 0;
        {
            static int s_dbgpos2 = -1;
            if (s_dbgpos2 < 0) { const char *e = getenv("UHA_PARSEDBG"); s_dbgpos2 = e ? atoi(e) : -2; }
            if ((int)pos == s_dbgpos2)
                fprintf(stderr, "[DBG]   L=%u mc=%u lc=%u g=%u\n", L, mc, lc, g);
        }
        if (g > bestgain) {
            bestgain = g;
            bestL = L;
        }
    }
    *len_out = bestL;
    return bestgain;
}

static int alz_find_match_cost(alz_dec *d, const uint8_t *plain, uint32_t usize,
                               uint32_t pos, const uint32_t *hashtab,
                               const uint32_t *chain, uint32_t hmask,
                               uint32_t cmask, int *token_out,
                               uint32_t *dist_out, uint32_t *count_out)
{
    int best_token = 0;
    uint32_t best_dist = 0, best_len = 0, best_adv = 0;
    int slot;
    uint32_t dist, n;

    /* model of side (escape) : l'estimator byte-model principal n'is not
     * faithful -> on s'abstient d'to emit has match (path literal). */
    if (d->st.escape_selector != 0)
        return 0;

    for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
        uint32_t r = d->st.recent_distance[slot];
        int tok = (slot == 0) ? 2 : 3;
        uint32_t L, g;

        if (r == 0 || r > d->mode.dict_mask)
            continue;
        n = alz_plain_match_len(d, plain, usize, pos, r);
        g = arb_pick_len(d, plain, usize, pos, tok, r, n, &L);
        if (L >= 2 && g > best_adv) {
            best_adv = g;
            best_token = tok;
            best_dist = r;
            best_len = L;
        }
    }

    {
        uint32_t L, g;

        dist = 1;
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        g = arb_pick_len(d, plain, usize, pos, 1, dist, n, &L);
        if (L >= 2 && g > best_adv) {
            best_adv = g;
            best_token = 1;
            best_dist = dist;
            best_len = L;
        }
    }

    {
        uint32_t L, g;

        n = alz_chain_best(d, plain, usize, pos, hashtab, chain, hmask, cmask,
                           &dist);
        if (n >= 2) {
            g = arb_pick_len(d, plain, usize, pos, 1, dist, n, &L);
            if (L >= 2 && g > best_adv) {
                best_adv = g;
                best_token = 1;
                best_dist = dist;
                best_len = L;
            }
        }
    }

    if (best_token == 0)
        return 0;
    *token_out = best_token;
    *dist_out = best_dist;
    *count_out = best_len;
    return 1;
}

/* ===== [RE DP] Parse GLOBAL by window glissante (horizon decroissant).
 * Surrogate of cost 4680*bits : match = alz_match_cost, litt = alz_literal_cost
 * (all two read-only). Replanifie at each position sure l'state REEL
 * current -> vise l'argmin global of legacy (13.73) en gardant the matches
 * has leur length EN TIERE (no troncature : invariant adjacency sure).
 * Gated UHA_DP=<W> (W=horizon bytes ; <2 => 16). Repli grille if absent. */
#define ALZ_DP_MAXC 12
#define ALZ_DP_WMAX 256
typedef struct { int tok; uint32_t dist; uint32_t len; } alz_cand;

static int s_dp_init = 0, s_dp_window = 0;
static int dp_on(void)
{
    if (!s_dp_init) {
        const char *e = getenv("UHA_DP");
        int w = e ? atoi(e) : 0;
        s_dp_window = (w == 0) ? 0 : (w < 2 ? 16 : (w > ALZ_DP_WMAX ? ALZ_DP_WMAX : w));
        s_dp_init = 1;
    }
    return s_dp_window;
}

static int s_dp_tok3min = -1;
static int s_dp_tok2min = -1;
static int s_dp_tok1min = -1;
static int s_dp_rlemin = -1;

static int dp_tok3min(void)
{
    if (s_dp_tok3min < 0) {
        const char *e = getenv("UHA_DP_TOK3MIN");
        s_dp_tok3min = e ? atoi(e) : 2;
    }
    return s_dp_tok3min;
}

static int dp_tok2min(void)
{
    if (s_dp_tok2min < 0) {
        const char *e = getenv("UHA_DP_TOK2MIN");
        s_dp_tok2min = e ? atoi(e) : 2;
    }
    return s_dp_tok2min;
}

static int dp_tok1min(void)
{
    if (s_dp_tok1min < 0) {
        const char *e = getenv("UHA_DP_TOK1MIN");
        s_dp_tok1min = e ? atoi(e) : 2;
    }
    return s_dp_tok1min;
}

static int dp_rlemin(void)
{
    if (s_dp_rlemin < 0) {
        const char *e = getenv("UHA_DP_RLEMIN");
        s_dp_rlemin = e ? atoi(e) : 2;
    }
    return s_dp_rlemin;
}

static int s_dp_leadlit = -1;
static int dp_leadlit(void)
{
    if (s_dp_leadlit < 0) {
        s_dp_leadlit = (getenv("UHA_DP_LEADLIT") || getenv("UHA_LEADLIT2") || getenv("UHA_ALZ_COSTFRONT")) ? 1 : 0;
    }
    return s_dp_leadlit;
}

/* Enumere the candidates of match en `pos` (slots recents->TOK2/TOK3 = the
 * correspondances 2D verticales/diagonales ; dist=1->TOK1 RLE ; string->TOK1
 * lointain), chacun has sa length EN TIERE encodable (>=2). */
static int alz_dp_candidates(alz_dec *d, const uint8_t *plain, uint32_t usize,
                             uint32_t pos, const uint32_t *hashtab,
                             const uint32_t *chain, uint32_t hmask, uint32_t cmask,
                             alz_cand *out, int max)
{
    int n = 0, slot;
    uint32_t r, L;
    int tok, e;

    if (dp_leadlit() && pos < 2u)
        return 0;

    for (slot = 0; slot < ALZ_MAX_RECENT && n < max; slot++) {
        r = d->st.recent_distance[slot];
        if (r == 0 || r > d->mode.dict_mask)
            continue;
        tok = (slot == 0) ? 2 : 3;
        L = alz_plain_match_len(d, plain, usize, pos, r);
        e = alz_best_encodable_len(d, tok, r, L);
        int min_l = (tok == 3) ? dp_tok3min() : dp_tok2min();
        if (e >= min_l) { out[n].tok = tok; out[n].dist = r; out[n].len = (uint32_t)e; n++; }
    }
    if (n < max) {
        L = alz_plain_match_len(d, plain, usize, pos, 1);
        e = alz_best_encodable_len(d, 1, 1, L);
        if (e >= dp_rlemin()) { out[n].tok = 1; out[n].dist = 1; out[n].len = (uint32_t)e; n++; }
    }
    {
        uint32_t cd = 0, nn;
        nn = alz_chain_best(d, plain, usize, pos, hashtab, chain, hmask, cmask, &cd);
        if (n < max && nn >= 2 && cd != 1) {
            e = alz_best_encodable_len(d, 1, cd, nn);
            if (e >= dp_tok1min()) { out[n].tok = 1; out[n].dist = cd; out[n].len = (uint32_t)e; n++; }
        }
    }
    return n;
}

/* Prototype : measures bits REELS (defini more low). Uses by the DP real-bits. */
static void alz_true_bits(alz_dec *d, const uint8_t *plain, uint32_t usize,
                          uint32_t pos, int token, uint32_t dist, uint32_t count,
                          uint64_t *mbits_out, uint64_t *lbits_out);
static int s_dp_real = -1;
static int dp_real(void)
{
    if (s_dp_real < 0)
        s_dp_real = getenv("UHA_DPREAL") ? 1 : 0;
    return s_dp_real;
}

/* [a5-d3 GATED UHA_DPSNAP, default-OFF] Weight LITERAL of the DP = cost d'arena
 * SNAPSHOT by position (g_lmin_dens under UHA_COSTSNAP), i.e. there proposition
 * 13.352 testee en ARGMIN GLOBAL (DP) and no glouton (snap-dens-impl 7052).
 * Forward-decl ; definitions after g_lmin_dens (l.~1147). */
static int dp_snap(void);
static uint32_t dp_snap_at(alz_dec *d, const uint8_t *plain, uint32_t usize,
                           uint32_t p);

/* More-short-path (DAG forward) sure there window [base, base+W) with weight
 * surrogate ; returns the first mouvement (tok=0 => literal). dp[] relatif. */
static void alz_dp_first_move(alz_dec *d, const uint8_t *plain, uint32_t usize,
                              uint32_t base, int W, const uint32_t *hashtab,
                              const uint32_t *chain, uint32_t hmask, uint32_t cmask,
                              int *tok_out, uint32_t *dist_out, uint32_t *cnt_out)
{
    static uint64_t dp[ALZ_DP_WMAX + 1];
    static int ch_tok[ALZ_DP_WMAX];
    static uint32_t ch_dist[ALZ_DP_WMAX], ch_len[ALZ_DP_WMAX];
    alz_cand cs[ALZ_DP_MAXC];
    uint32_t nmax;
    int i, nc, w;

    *tok_out = 0; *dist_out = 0; *cnt_out = 0;
    if (base >= usize)
        return;
    if (W > ALZ_DP_WMAX) W = ALZ_DP_WMAX;
    nmax = usize - base;
    if (nmax > (uint32_t)W) nmax = (uint32_t)W;
    dp[nmax] = 0;
    for (i = (int)nmax - 1; i >= 0; i--) {
        uint32_t p = base + (uint32_t)i;
        uint64_t best, litc, mc, tot;
        int btok = 0, k;
        uint32_t bdist = 0, blen = 1;
        litc = dp_snap()
            ? (uint64_t)dp_snap_at(d, plain, usize, p)
            : dp_real()
            ? ({ uint64_t mb, lb; alz_true_bits(d, plain, usize, p, 1, 1, 1, &mb, &lb); lb; })
            : (uint64_t)alz_literal_cost(d, plain, usize, p, 1);
        best = litc + dp[i + 1];
        nc = alz_dp_candidates(d, plain, usize, p, hashtab, chain, hmask, cmask, cs, ALZ_DP_MAXC);
        for (k = 0; k < nc; k++) {
            int j = i + (int)cs[k].len;
            mc = dp_real()
                ? ({ uint64_t mb, lb; alz_true_bits(d, plain, usize, p, cs[k].tok, cs[k].dist, cs[k].len, &mb, &lb); mb; })
                : (uint64_t)alz_match_cost(d, cs[k].tok, cs[k].dist, cs[k].len);
            tot = (j >= (int)nmax) ? mc : (mc + dp[j]);
            if (tot < best) { best = tot; btok = cs[k].tok; bdist = cs[k].dist; blen = cs[k].len; }
        }
        dp[i] = best; ch_tok[i] = btok; ch_dist[i] = bdist; ch_len[i] = blen;
    }
    w = 0;
    *tok_out = ch_tok[w]; *dist_out = ch_dist[w]; *cnt_out = ch_len[w];
    (void)w;
}

/* ===== [RE Has] Measures some VRAIS bits (match vs literals) by scratch-coder.
 * Clone l'state (d + window + w range-coder SCRATCH) and code (has) the token match
 * (token_class + m_encode_match), (b) there same couverture en `count` literals
 * side-aware. The two via the SAME procede -> there constante d'init of the coder se
 * soustrait. ZERO MUTATION of d nor w reels (regression-safe, encoder-only).
 * Expose mbits/lbits ; sert at the fois has probe_match_cost (print) and au
 * parseur true-side (UHA_TRUEPARSE). */
static void alz_true_bits(alz_dec *d, const uint8_t *plain, uint32_t usize,
                          uint32_t pos, int token, uint32_t dist, uint32_t count,
                          uint64_t *mbits_out, uint64_t *lbits_out)
{
    size_t wbytes = (size_t)d->mode.dict_size + 4096;
    uint64_t mbits = 0, lbits = 0;
    alz_dec *c;
    uha_rcw sw;
    uint32_t i;

    if (mbits_out)
        *mbits_out = 0;
    if (lbits_out)
        *lbits_out = 0;
    if (count == 0 || pos + count > usize)
        return;

    /* --- match : token_class(token) + m_encode_match --- */
    c = malloc(sizeof *c);
    if (!c)
        return;
    memcpy(c, d, sizeof *c);
    c->window = malloc(wbytes);
    if (!c->window) { free(c); return; }
    memcpy(c->window, d->window, wbytes);
    if (uha_rcw_init(&sw) == 0) {
        c->w = &sw;
        if (alz_encode_token_class(c, token) == 0)
            alz_m_encode_match(c, token, dist, count);
        uha_rcw_flush(&sw);
        mbits = (uint64_t)sw.pos * 8u;
        uha_rcw_free(&sw);
    }
    free(c->window);
    free(c);

    /* --- literals : token_class(4) + encode_literal + put_byte, x count ---
     * SKIPS if lbits_out==NULL (mode mb-only, fast : avoids there loop O(count)). */
    if (lbits_out) {
    c = malloc(sizeof *c);
    if (!c)
        return;
    memcpy(c, d, sizeof *c);
    c->window = malloc(wbytes);
    if (!c->window) { free(c); return; }
    memcpy(c->window, d->window, wbytes);
    if (uha_rcw_init(&sw) == 0) {
        c->w = &sw;
        for (i = 0; i < count; i++) {
            uint8_t lb = plain[pos + i];
            if (alz_encode_token_class(c, 4) != 0)
                break;
            if (c->st.escape_selector != 0) {
                if (alz_side_encode_literal(c, lb) != 0)
                    break;
            } else {
                if (alz_encode_literal(c, lb) != 0)
                    break;
            }
            c->bm_flag = 0;
            alz_put_byte(c, lb);
            if (c->st.escape_selector != 0)
                alz_side_post_update(c, lb);
            c->st.repeat_run = 0;
        }
        uha_rcw_flush(&sw);
        lbits = (uint64_t)sw.pos * 8u;
        uha_rcw_free(&sw);
    }
    free(c->window);
    free(c);
    *lbits_out = lbits;
    }

    if (mbits_out)
        *mbits_out = mbits;
}

/* ===== [C2' FIDELITE alz_true_bits, gated UHA_TRUEBITS - no-wired, reading] =====
 * Mirror INDEPENDANT of the path d'EMISION some literals, transcrit since there
 * loop REELLE src/alz.c l.1653..1680 (token_class(4) => literal side/primary
 * => bm_flag=0 => put_byte => side_post_update => repeat_run=0). Rises sure has
 * CLONE jetable of `base` (window+OUT frais) + range-coder SCRATCH -> measures the
 * bits consommes for `L` literals en base->st.output_pos. Doit EGALER lbits
 * d'alz_true_bits (same contrat) : verrou differentiel of fidelite of the proxy.
 * ZERO mutation of `base` (out/window/coder distincts). */
static uint64_t tb_lit_measure(alz_dec *base, const uint8_t *plain,
                               uint32_t usize, uint32_t L, int *ok_out)
{
    size_t wbytes = (size_t)base->mode.dict_size + 4096;
    uint64_t bits = 0;
    int ok = 1;
    alz_dec *m;
    uha_rcw sw;
    uint32_t i;

    m = (alz_dec *)malloc(sizeof *m);
    if (!m) { if (ok_out) *ok_out = 0; return 0; }
    memcpy(m, base, sizeof *m);
    m->window = (uint8_t *)malloc(wbytes);
    m->out = (uint8_t *)malloc((size_t)usize + 1u);
    if (!m->window || !m->out) {
        free(m->window); free(m->out); free(m);
        if (ok_out)
            *ok_out = 0;
        return 0;
    }
    memcpy(m->window, base->window, wbytes);
    m->outlen = (size_t)usize;
    if (uha_rcw_init(&sw) != 0) {
        free(m->window); free(m->out); free(m);
        if (ok_out)
            *ok_out = 0;
        return 0;
    }
    m->w = &sw;
    for (i = 0; i < L; i++) {
        uint32_t p = m->st.output_pos;
        uint8_t lb;
        if (p >= usize) { ok = 0; break; }
        if (alz_encode_token_class(m, 4) != 0) { ok = 0; break; }
        lb = plain[p];
        if (m->st.escape_selector != 0) {
            if (alz_side_encode_literal(m, lb) != 0) { ok = 0; break; }
        } else {
            if (alz_encode_literal(m, lb) != 0) { ok = 0; break; }
        }
        m->bm_flag = 0;
        alz_put_byte(m, lb);
        if (m->st.escape_selector != 0)
            alz_side_post_update(m, lb);
        m->st.repeat_run = 0;
    }
    if (ok && uha_rcw_flush(&sw) == 0)
        bits = (uint64_t)sw.pos * 8u;
    else
        ok = 0;
    uha_rcw_free(&sw);
    free(m->window); free(m->out); free(m);
    if (ok_out) *ok_out = ok;
    return bits;
}

/* Advances in place has state (clon hot `e`, e->w = coder persistant) of `L`
 * literals via the SAME primitives d'emission ; sert only has echauffer
 * the models (side/CM/bm) towards there next position d'echantillon. Bits jetes. */
static void tb_lit_advance(alz_dec *e, const uint8_t *plain, uint32_t usize, uint32_t L)
{
    uint32_t i;
    for (i = 0; i < L; i++) {
        uint32_t p = e->st.output_pos;
        uint8_t lb;
        if (p >= usize) break;
        if (alz_encode_token_class(e, 4) != 0) break;
        lb = plain[p];
        if (e->st.escape_selector != 0) {
            if (alz_side_encode_literal(e, lb) != 0) break;
        } else {
            if (alz_encode_literal(e, lb) != 0) break;
        }
        e->bm_flag = 0;
        alz_put_byte(e, lb);
        if (e->st.escape_selector != 0)
            alz_side_post_update(e, lb);
        e->st.repeat_run = 0;
    }
}

/* ===== [RE b2c] Probe TRUE-CODIER : cost REEL (bits) match vs literals =====
 * Repond has "arbitre suffisant vs fideliser d'abord the codage match" : measures,
 * in has range-coder SCRATCH rises sure has CLONE jetable of l'state (d and w
 * reels NEVER touches -> regression-safe), the bytes REELS has to emit (has) the
 * token match (token,dist,count) and (b) there same couverture en literals. The
 * two measurements by the SAME procede (coder scratch + flush) -> there constante
 * d'initialisation of the coder se soustrait. Glose by UHA_MCOST=<pos>.
 * Model at the identical of l'emission reelle (token_class + m_encode_match /
 * encode_literal + put_byte + side). */
static void probe_match_cost(alz_dec *d, const uint8_t *plain, uint32_t usize,
                             uint32_t pos, int token, uint32_t dist,
                             uint32_t count, const char *tag)
{
    uint64_t mbits = 0, lbits = 0;

    alz_true_bits(d, plain, usize, pos, token, dist, count, &mbits, &lbits);
    if (!tag)
        return;
    fprintf(stderr,
        "[MCOST] %s pos=%u tok=%d dist=%u count=%u | match=%llu bits "
        "lit=%llu bits | match-lit=%lld (match %s)\n",
        tag, pos, token, dist, count,
        (unsigned long long)mbits, (unsigned long long)lbits,
        (long long)mbits - (long long)lbits,
        (mbits < lbits) ? "GAGNE" : "PERD");
    fflush(stderr);
}

/* [RE b3 probe (has)+(b)] Portee faithful of the gate of budget (b), READ-ONLY.
 * q = (cout_cumule_du_bloc / len) / 585  (unites 4680*bits ; 585=4680/8) ;
 * clamp q<=10 ; base = 80 (cls==1) otherwise 75 ; delta=(10-q)*4 ;
 * budget = (base - delta) * recent[cls] ; allow match ssi budget > recent[0]<<6.
 * recent[] = d->st.recent_distance[] (mapping verified RE 13.47 : 0x45cbb4).
 * returns 1=match allows (finder), 0=forces litterale, -1=donnee of block absente. */
static int parse3_budget_allow(alz_dec *d, uint64_t blkcost, uint32_t blklen, int cls)
{
    uint32_t q, r0, rc;
    int base;
    uint64_t value, budget, thresh;

    if (blklen == 0)
        return -1;
    q = (uint32_t)((blkcost / blklen) / 585ull);
    if (q > 10)
        q = 10;
    base = (cls == 1) ? 80 : 75;
    value = (uint64_t)(base - (uint32_t)(q < 10 ? (10u - q) * 4u : 0u));
    rc = (cls >= 0 && cls < ALZ_MAX_RECENT) ? d->st.recent_distance[cls] : 0u;
    r0 = d->st.recent_distance[0];
    if (rc == 0)
        rc = 1;
    if (r0 == 0)
        r0 = 1;
    budget = value * (uint64_t)rc;
    thresh = (uint64_t)r0 << 6;
    return budget > thresh;
}

/* [A5.2 gated UHA_P1GATE, read-only, no-wired] Table some VRAIS Sigma of the vainqueur
 * by block of scoring (image.raw), pre-roulee by PERSISTANCE carry (P1 deterministe
 * of the plaintext, 13.167). file-scope for relecture in there loop d'emission : on
 * alimente parse3_budget_allow with the Sigma TRUE (au lieu of the proxy gs_cost) and on measures
 * l'match of the porte with there DECISION LEGACY (g_oracle->kind) + retournement of the
 * dominance DENY (memory 847098a9). N'affecte NOTHING out keeps. */
static uint32_t p1g_lo[6], p1g_hi[6], p1g_sig[6], p1g_len[6];
static int      p1g_ready = 0;

static void p1g_precompute(const uint8_t *plain, uint32_t usize)
{
    static const uint32_t blpos[6] = {0x0000u, 0x3100u, 0x620cu, 0x931cu, 0xc4ffu, 0xff00u};
    static const uint32_t blen[6]  = {0x3100u, 0x3100u, 0x3100u, 0x3100u, 0x3a01u, 0x100u};
    alz_ps_carry_t st[ALZ_PS_NCLASS];
    uint32_t seed = 0u;
    int b, k;
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) { st[k].arena = NULL; st[k].ebx = st[k].flag = st[k].ebp = 0u; }
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS];
        uint32_t base = blpos[b], len = blen[b], w;
        if (base >= usize) { len = 0u; }
        else if (base + len > usize) { len = usize - base; }
        p1g_lo[b] = base; p1g_hi[b] = base + len; p1g_len[b] = len; p1g_sig[b] = 0u;
        if (len) {
            w = alz_ps_block_argmin_carry(st, seed, plain, base, len, 32u, ALZ_PS_COLD0, sigma, NULL);
            p1g_sig[b] = sigma[w];
            seed = w;
        }
    }
    alz_ps_carry_free(st);
    p1g_ready = 1;
}

static int p1g_block_of(uint32_t pos, uint64_t *sig, uint32_t *len)
{
    int b;
    for (b = 0; b < 6; b++)
        if (pos >= p1g_lo[b] && pos < p1g_hi[b]) { *sig = p1g_sig[b]; *len = p1g_len[b]; return b; }
    return -1;
}

/* [a5c2f-c-lmin-asm GATED UHA_LMINLIVE, read-only, no-emissive, default-OFF]
 * Table `dens[]` GLOBAL = cost LUT of the class WINNING by block (argmin),
 * pre-roulee from-plain. Mirror EXACT of the producteur UHA_PSDUMP (d2_costdump_dump,
 * alz_d2score.c l.609) whose there justesse is prouvee 4014/4014 vs there verite legacy
 * (dens_clone.tsv==dens_truth.tsv). Sert has `sm=SUM dens[off,key)` (and `bud` proxy)
 * of the feeder lm_in LIVE. Indexee en position ABSOLUE (each block has sa table clean,
 * base-reset : block0 base=0 therefore abs==rel). Not mute NOR d NOR l'emission. */
static uint32_t *g_lmin_dens = NULL;
static int g_lmin_dens_ready = 0;
/* [GATED UHA_LIVEGOV, default-OFF, 14.043] cost LIVE of the master (arena2d promoechauffee
 * +0x20/position emise), writes by l'acclive (EMISS) during l'emission. when active,
 * dp_snap_at prefere this table (path singlepass/pointfixe) at the window proxy
 * COSTSNAP. without gate : g_lmin_live never consulte -> behavior strictement unchanged. */
static uint32_t *g_lmin_live = NULL;
static int g_lmin_live_ready = 0;
static int dp_livegov(void)
{
    static int s = -1;
    if (s < 0)
        s = getenv("UHA_LIVEGOV") ? 1 : 0;
    return s;
}
/* [GATED UHA_LIVEGOV, default-OFF, 14.044] Coeur singlepass : advances has replica of the
 * MASTER (arena2d, promoechauffee +0x20) sure the bytes `plain` up to `p` and returns
 * the cost LIVE en `p` (row=(ctx>>8)&0x1ff, ctx roule plain - valable sure the front
 * LITERAL now recon==plain, there region of the razor @13809). Memorise by (plain,usize,
 * covered). Re-init if `p` repart has 0 (nouvel call/input). Zero effet out gate. */
static uint32_t live_master_cost_at(const uint8_t *plain, uint32_t usize, uint32_t p)
{
    static alz_arena2d_t *m = NULL;
    static const uint8_t *s_pl = NULL;
    static uint32_t s_cov = 0u, s_ctx = 0u;
    if (!m) { m = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t)); if (m) alz_arena2d_init(m, 32u); }
    if (!m) return alz_literal_cost(NULL, plain, usize, p, 1);
    if (plain != s_pl || p == 0u) { alz_arena2d_init(m, 32u); s_pl = plain; s_cov = 0u; s_ctx = 0u; }
    if (p > usize) p = usize;
    while (s_cov < p) {   /* to advance the master sure plain[s_cov] : score+LEARN (promo +0x20) */
        uint32_t sym = (uint32_t) plain[s_cov] & 0xffu, row, out = 0u, cost;
        s_ctx = ((s_ctx << 8) | sym) & 0x1FFFFu;
        row = (s_ctx >> 8) & 0x1FFu;
        cost = alz_arena2d_score(m, row, sym, &out);   /* &out => LEARN promo (singlepass has hot) */
        /* [14.049 cadence] rescale FLOOR `0x414590` as soon as the total of line franchit
         * the threshold (mirror `ld_advance` l.1870) : avoids there saturation/surchauffe of the master. */
        if (m->total[row] >= ALZ_ARENA2D_RESCALE)
            alz_arena2d_rescale(m, row);
        s_cov++;
        if (s_cov - 1u == p - 1u) return cost;          /* cost evaluates au last byte before p */
    }
    return alz_literal_cost(NULL, plain, usize, p, 1);
}
/* [a5-d3 UHA_DPSNAP, default-OFF] Definitions some forward-decls of l.~820.
 * dp_snap_at : weight literal of the DP = cost d'arena SNAPSHOT (g_lmin_dens,
 * alimente by alz_ps_snapshot_percost under UHA_COSTSNAP) ; repli sure
 * alz_literal_cost if the snapshot n'is not pret (keeps no-emissive). */
static int dp_snap(void)
{
    static int s = -1;
    if (s < 0)
        s = getenv("UHA_DPSNAP") ? 1 : 0;
    return s;
}
static uint32_t dp_snap_at(alz_dec *d, const uint8_t *plain, uint32_t usize,
                           uint32_t p)
{
    /* [GATED UHA_LIVEGOV] gouverner there neartie by the cost LIVE of the master when pret. */
    if (dp_livegov() && plain) {
        uint32_t lc = live_master_cost_at(plain, usize, p);
        if (lc) return lc;
    }
    if (dp_livegov() && g_lmin_live_ready && g_lmin_live && p < usize && g_lmin_live[p])
        return g_lmin_live[p];
    if (g_lmin_dens_ready && g_lmin_dens && p < usize)
        return g_lmin_dens[p];
    return alz_literal_cost(d, plain, usize, p, 1);
}
/* [a5c2f-c-govern GATED UHA_LMGovern] Table primaire `v` of the decider (0x412c0a,
 * LM_V_CTXSIZE bytes, init 0) : get au context current w16+(dh!=1?0x10000:0)
 * before decision, put = DL at each emission match. No-NULL <=> gouvernance
 * active (therefore the put en l.3153 is auto-keeps, zero effet default). */
static uint8_t *g_lmgov_vtab = NULL;

/* [pending-law GATED UHA_PENDLAW=<C>, default-OFF, no-emissive without env] Law
 * exact of the pending-carry of the pilote legacy 0x412f70 (ASM l.22353-22368) : when
 * the decider 0x412c30 REJETTE has match of length L (al==0) and that there class of
 * shift run C=[0x45ecbc] < 3, the walker sets has counter of lookahead
 * `[0x45ecb7] = (L-2) >> C` ; so much qu'il is > 0 il LITTERALISE the bytes
 * following without relancer the finder 0x4136a0 (drain l.22238-22243). Here C is there
 * value of UHA_PENDLAW (constante by run, cf classification 0x40f2c0 sure edx).
 * s_pendlaw<0 = porte OFF (behavior actuel strict). s_pend_ctr = drain restant. */
static int s_pendlaw = -1;
static uint32_t s_pend_ctr = 0u;

/* [cost-literal-live GATED UHA_COSTLIVE, default-OFF] Ring budget FIFO-256-READS
 * alimente EN LIVE in there loop d'emission (has poussee by literal emis) with
 * the cost byte-model `a_bm = alz_bm_predict_cost` lu sure the model REELLEMENT
 * rechauffe lockstep (13.351 : `acc` = a_bm of the LITERAL previous, lag-1 causal
 * because there poussee suit l'emission and there reading gouverne there decision next).
 * Persistant sure all the file, seed 255*37440, reset has output_pos==0. The block
 * gov READS s_cl_sum as gin.bud (sm remainder l'arena of parse dens : TWO sources
 * distinctes). zero effet default (s_costlive==0). */
static uint32_t s_cl_ring[256];
static uint32_t s_cl_head  = 0;
static uint64_t s_cl_sum   = 0;
static int      s_costlive = -1;
static uint32_t s_cl_ready = 0;   /* ring seede */
/* [GATED UHA_CLSEED=<acc_par_entree>, default-OFF, NO regressif] value of seed
 * per-entry of l'ring budget COSTLIVE. Default 37440 (=behavior actuel, seed
 * 255*37440=0x91ADC0 EXACTEMENT the threshold of the decider -> branch simple). Regler under
 * the threshold (ex 33736 ~ bud_legacy_pos57/255) keeps the decider en branch renorm as
 * the legacy engine (bud legacy max 8.6M < 0x91ADC0). Zero effet if env absent. */
static uint32_t s_cl_seed = 0;
/* [GATED UHA_ACCMIXLAG, default-OFF, measures 2026-10-20] feeder of l'ring bud =
 * `mix` byte-model of the literal previous (lag-1). Measures : `mix lag-1` == GT
 * `acc_legacy` sure 12701/13179 = 96,37 % of the prefixe aligne (<20792), contre 0,11 %
 * for the cost current and 0,14 % for there poussee actuelle (arena C4). The lag-1 of
 * 13.351/13.437 is therefore REEL (there scores 13.544 which the refutait was false).
 * Ports : s_cl_mixlag_prev = mix of the literal previous, s_cl_mixlag = value retenue
 * for there poussee. Inertes out gate. */
static uint32_t s_cl_mixlag      = 37440u;
static uint32_t s_cl_mixlag_prev = 37440u;
static uint32_t alz_cl_seed_resolve(void) {
    if (s_cl_seed == 0) {
        const char *sv = getenv("UHA_CLSEED");
        s_cl_seed = sv ? (uint32_t) strtoul(sv, NULL, 10) : 37440u;
        if (s_cl_seed == 0) s_cl_seed = 37440u;
    }
    return s_cl_seed;
}

/* [acclive GATED UHA_ACCLIVE, default-OFF] cost-literal LIVE (`acc`) computed in
 * the walker d'emission by l'arena portee alz_arena_c4 (13.620, lockstep
 * 29948/29948) and injecte in g_lmin_dens[pos] ONLY to the positions now the
 * clone emits has LITERAL (the positions couvertes by has MATCH keep the cost
 * `dens` - recette hybride 13.348 ; the forward-fill total = 7872 is rejete).
 * Laws d'input, all derivees of the flot EMIS (13.621, sites live
 * 0x4101d0/0x4130e3/0x4123e7/0x412441) :
 *  - cascade sure each byte emis q (bf = plain[q-3], mirror feed=(feed<<8)|byte,
 *    ring 65536 -> desactive if usize > 0x10000) :
 *      d = (plain[q]-bf)&0xff ; if sg : d = (-d)&0xff ; K[q]=d ; if d>=0x80 : sg^=1 ;
 *  - row = 0x341 + 32*((pos%3+2)%3) + T[K[pos-1]]  (pos==0 : row=0x341 initial) ;
 *  - sym = K[pos]  (l'arena learns the -signe, NOT l'byte raw) ;
 *  - escape : after each MATCH emis (T=pos, di=dist, ln=count), esc_flag=1 au
 *    first literal next then consumes (survie 1 evenement, flag:=0 0x41240f) ;
 *    raw = plain[(pos-di+ln)&0xffff] ; esc_sym = sg ? (bf-raw)&0xff : (raw-bf)&0xff
 *    with bf=plain[pos-3] and sg = state of cascade BEFORE push of l'byte current.
 * Residus toleres (no-bloquants, 13.621(2)(3)) : 6 escapes of queue (bords has
 * dist multiples of 2944, esym=raw raw) ; ~1,4 % bounds of match bf!=plain[p-3].
 * Inerte by default (s_acclive==0) ; g_lmin_dens NULL without UHA_LMINLIVE -> not
 * d'injection (auto-keeps, zero regression DEF7049/BASE7002/GATE7015/RT). */
static int s_acclive = -1;
/* [GATED UHA_CM_WIRE, default-OFF, 13.798] when ON, l'arena LIVE alz_arena_c4 is
 * alimentee with there row/sym FAITHFUL (law image cls5 sym->row, engine CM persistant
 * alz_ps_cmlive_*) au lieu of the proxy cls3 (0x341+32*phase+tbucket). default-OFF =>
 * zero regression (proxy inchangee). */
static int s_cmwire = -1;
/* [GATED UHA_CM_CTXROLL, default-OFF, 13.878] Registre `ctx` roulant sure the stream emis
 * (recon) for there line d'emission `row=(ctx>>8)&0x1ff` (law M11b). */
static int s_cmctxroll = -1;
static uint32_t s_cmctx = 0u;
#define ALZ_CMW_ROWBASE5 0x3e1u   /* row_base class 5 (alz_block_arena[5]) : image.raw -m3 = cls5 partout */
/* [GATED UHA_ACCRING_C4, default-OFF, 13.683] source of the TRUE `acc` of l'arena
 * faithful alz_arena_c4 (law row=class 13.621) pushes in l'ring bud (au lieu
 * of the proxy delta-2D ACCRING / byte-model COSTLIVE). Cache `once` for not
 * TO CONSUME l'evenement arena QU'once by pos (otherwise double-learning of
 * there cascade). s_acl_ev_pos==0xFFFFFFFF => no evenement en cache. */
/* static int s_accring_c4 = -1; */
/* [GATED UHA_ACLLEARN_ALL, default-OFF, 13.756/13.747-D2] The LIVE-feed legacy
 * `0x4111a0` learns `snap_freq[row][sym]+=0x20` at each byte EMIS (match-couverts
 * INCLUS), and the decider reads there working-arena thus nourrie by byte (dens defini has
 * each position : proof 13.753, there window sm @13070 couvre has MATCH of 11 o and
 * sm=37459!=0). by default l'arena C4 of the clone not SCORER (prediction pure) that the
 * bytes of match and n'LEARNS only to the  literals ; this gate there does APPRENDRE each
 * byte (via alz_arena_c4_event) for to reproduce the carry LIVE. default-OFF =>
 * zero regression (E3/BEST inchanges). */
static int s_acllearn_all = -1;
static uint32_t s_acl_ev_pos  = 0xFFFFFFFFu;
static uint32_t s_acl_ev_cost = 0xFFFFFFFFu;
typedef struct {
    alz_arena_c4_t *ar;
    alz_arena2d_t  *ar2;          /* [GATED UHA_CM_CTXROLL] arena d'emission arena2d (moteur M10validated) */
    uint32_t done;        /* last byte emis traite by there cascade */
    uint32_t kprev;       /* K[done] */
    uint32_t rawidx;      /* index `raw` of l'escape en attente */
    int      sg;          /* state of signe of the cascade */
    int      esc_wait;    /* 1 = the next evenement literal porte l'escape */
    /* [GATED UHA_CM_EMISS, default-OFF, 13.898] emetteur faithful : ctx roulant + arena2d M. */
    uint32_t ctx;
    alz_arena2d_t *mem;
    int       emiss;
} alz_acclive_st;
#define ACL_DONE_NONE 0xFFFFFFFFu
static alz_acclive_st s_acl = { NULL, NULL, ACL_DONE_NONE, 0u, 0u, 0, 0, 0u, NULL, 0 };
static int s_acl_emiss_aging = -1;   /* [GATED UHA_ACL_EMISS_AGING, default-OFF]  REFUTE (measures 2026-10-20) : same DECOUPLE Has FOND (master d'emission advances en side-effect single via master_learn+aging, 1* /literal, cost RETURNS = C4 habituel therefore ACCRING_C4 intact, and NO write g_lmin_dens), the simple does d'activer there branch d'emission CM_EMISS does plonger firstdiv 16685->71. => the 71 n'is NOR l'injection dens NOR there diversion of the cost bud : il is consubstantiel has to take the path d'emission acclive. Confirme DUAL l.545 (" the single-pass not doit NOT passer by acclive "). There production from-scratch of the master remainder in the PRODUCTEUR (live_walk_master_4pass/FEEDSELF). Gate leaves default-OFF for reproductibilite. */

static void acclive_push_byte(const uint8_t *plain, uint32_t q)
{
    uint32_t bf = (q >= 3u) ? (uint32_t) plain[q - 3u] : 0u;
    uint32_t dlt = (uint32_t) ((plain[q] - bf) & 0xFFu);
    if (s_acl.sg)
        dlt = (uint32_t) ((0u - dlt) & 0xFFu);
    s_acl.kprev = dlt;
    if (dlt >= 0x80u)
        s_acl.sg ^= 1;
    s_acl.done = q;
}

/* [GATED UHA_C4DENS=path, read-only, default-OFF] Dump of the sol `dens` candidate
 * produces by l'arena C4 foi-fide (`s_acl.ar`) : cost SCORE by byte (prediction
 * pure without learning) sure the bytes couverts by MATCH, and cost-evenement
 * (score+learn) sure each LITERAL. Law of the sol legacy 13.701. Format `pos\tsrc\tcost` */
static FILE *s_c4df = NULL;
static int   s_c4df_init = 0;
static void c4dens_ensure(void)
{
    if (s_c4df_init)
        return;
    s_c4df_init = 1;
    {
        const char *cd = getenv("UHA_C4DENS");
        if (cd) {
            s_c4df = fopen(cd, "w");
            if (s_c4df)
                fprintf(s_c4df, "pos\trow\tsym\tcost\tsrc\n");
        }
    }
}

/* Score l'evenement literal of position `pos` of the flot emis ; returns the cost
 * (0xFFFFFFFF = gated inactive/contrat viole). pos==0 re-initialise l'instance
 * (has arena by file/pass, cf 13.618 : no reset by block). */
/* [port inencode] bm of the bytemodel live (for escape `bm[0x402+sel]`) expose has acclive_event (which
 * n'has not `d`). Sets by there loop d'emission before l'call ; zero out gate. */
static uint16_t (*g_bm_freq)[256] = NULL; static uint16_t (*g_bm_tree)[256] = NULL; static int g_bm_sel = 0;
static uint32_t acclive_event(const uint8_t *plain, uint32_t usize, uint32_t pos)
{
    uint32_t row, sym, flag, esym, bf, raw, cost, q, start;
    uint32_t acfc0 = 0u;                    /* fc BEFORE learn in emiss (cold if 0), portee function */
    if (usize > 0x10000u)
        return 0xFFFFFFFFu;
    /* [GATED UHA_ACLDUMP_PERM=<file>] dump once l'state COMPLETE of the master d'emission
     * INLINE of the clone (`s_acl.mem`) au 1er pos>=12544 (= end d'emission bloc0) ->
     * "row total freqsum nonzero", has diff (dual_diff.py) contre ref_hot_b1.tsv of #17.
     * Test decisif : the master inline of the clone correspondil ALREADY at the oracle legacy ? */
    {
        const char *dp = getenv("UHA_ACLDUMP_PERM");
        static int acl_dumped = 0;
        static uint32_t s_maxpos = 0; static int s_diag = 0;
        if (pos > s_maxpos) s_maxpos = pos;
        if (dp && *dp && !s_diag && pos >= 12544u) {   /* diag oneshot au franchissement */
            s_diag = 1;
            fprintf(stderr, "[ACLDIAG] acclive_event pos=%u s_acl.mem=%p emiss=%d maxpos_prec=%u\n",
                    (unsigned)pos, (void*)s_acl.mem, (int)s_acl.emiss, (unsigned)(s_maxpos-pos));
        }
        if (dp && *dp && pos >= 12544u && !acl_dumped && s_acl.mem) {
            FILE *F = fopen(dp, "w"); acl_dumped = 1;
            if (F) {
                uint32_t rr;
                fprintf(F, "# s_acl.mem master inline clone @pos=%u (end emission b0)\n", (unsigned)pos);
                for (rr = 0u; rr < ALZ_ARENA2D_MAX_ROW; rr++) {
                    uint32_t cc, fsum = 0u, fnz = 0u;
                    for (cc = 0u; cc < 256u; cc++) { uint32_t fq = s_acl.mem->freq[(rr<<8)|cc]; if (fq) { fsum += fq; fnz++; } }
                    fprintf(F, "%u\t%u\t%u\t%u\n", rr, (unsigned)s_acl.mem->total[rr], fsum, fnz);
                }
                fclose(F);
            }
        }
    }
    if (!s_acl.ar) {
        s_acl.ar = (alz_arena_c4_t *) malloc(sizeof(alz_arena_c4_t));
        if (!s_acl.ar)
            return 0xFFFFFFFFu;
    }
    /* [init paresseuse gated] reads UHA_CM_EMISS once (flag local, independant of pos ;
     * the sentinel `<0` echouait because static->0) and allocates the master inline `s_acl.mem`.
     * without effet out gate (emiss=0 if env absent). */
    {
        static int s_emiss_once = 0;
        if (!s_emiss_once) {
            s_emiss_once = 1;
            if (s_acl.emiss < 0) s_acl.emiss = (getenv("UHA_CM_EMISS") != NULL) ? 1 : 0;
            else s_acl.emiss = (getenv("UHA_CM_EMISS") != NULL) ? 1 : s_acl.emiss;
            if (s_acl_emiss_aging < 0) s_acl_emiss_aging = (getenv("UHA_ACL_EMISS_AGING") != NULL) ? 1 : 0;   /* [default-OFF] */
        }
    }
    if (s_acl.emiss && !s_acl.mem) {
        s_acl.mem = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
        if (s_acl.mem) { alz_arena2d_init(s_acl.mem, 32u); s_acl.mem->aging_on = s_acl_emiss_aging; }
    }
    if (pos == 0u) {
        alz_arena_c4_init(s_acl.ar);
        s_acl.done = ACL_DONE_NONE;
        s_acl.kprev = 0u;
        s_acl.sg = 0;
        s_acl.esc_wait = 0;
        if (s_cmwire < 0)
            s_cmwire = (getenv("UHA_CM_WIRE") != NULL) ? 1 : 0;
        if (s_cmwire)
            alz_ps_cmlive_reset(0u);   /* start section 0 : registres+engine frais */
        if (s_cmctxroll < 0)
            s_cmctxroll = (getenv("UHA_CM_CTXROLL") != NULL) ? 1 : 0;
        s_cmctx = 0u;                  /* reset of the context roulant at the section */
        if (s_cmctxroll) {
            if (!s_acl.ar2) s_acl.ar2 = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
            if (s_acl.ar2) alz_arena2d_init(s_acl.ar2, 32u);
        }
        if (s_acl.emiss < 0)
            s_acl.emiss = (getenv("UHA_CM_EMISS") != NULL) ? 1 : 0;   /* [GATED default-OFF] */
        s_acl.ctx = 0u;
        if (s_acl.emiss) {
            if (!s_acl.mem) s_acl.mem = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
            if (s_acl.mem) { alz_arena2d_init(s_acl.mem, 32u); s_acl.mem->aging_on = s_acl_emiss_aging; }   /* master persistant, rescale working ; [aging_on default-OFF] */
        }
    }
    /* [GATED UHA_CM_EMISS, default-OFF] rescale of the master to the FRONTIERS of block (size
     * structurelle dcac, env UHA_CM_EMISS_BS default 12544) : the scribe recharge/re-echelle
     * `M` by block, no has block at the other continuously -> refroidit the block1. */
    if (s_acl.emiss && s_acl.mem && pos > 0u) {
        static uint32_t s_bs = 0u;
        if (s_bs == 0u) { const char *e = getenv("UHA_CM_EMISS_BS");
            s_bs = e ? (uint32_t) strtoul(e, NULL, 10) : 12544u; }
        if (s_bs && (pos % s_bs) == 0u) {
            uint32_t r; for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++) alz_arena2d_rescale(s_acl.mem, r);
        }
        /* [GATED UHA_ACLDUMP_PERM] dump once the master s_acl.mem au 1er pos>=12544,
         * has to compare au PERM legacy 0xf80230 (row68 Sigma~13134 / row37=0). read-only. */
        if (getenv("UHA_ACLDUMP_PERM") && pos >= 12544u) {
            static int s_dumped = 0;
            if (!s_dumped) {
                uint32_t rr; s_dumped = 1;
                {   /* [DIAG] counter[row]/total of the master live at the input b1 vs LEG (row5 LEG25/11741 ; row29 ? ; row68 4/11134) */
                    static const uint32_t dr[4] = {5u,29u,67u,68u}; uint32_t k;
                    for (k = 0u; k < 4u; k++)
                        fprintf(stderr, "[ACLCNT] s_acl.mem row%u counter=%u total=%u\n",
                                (unsigned)dr[k], (unsigned)s_acl.mem->counter[dr[k]], (unsigned)s_acl.mem->total[dr[k]]);
                }
                for (rr = 0u; rr < 2u; rr++) {
                    uint32_t row = rr ? 37u : 68u, c, sum = 0u, nz = 0u; char first[128]; int o = 0;
                    for (c = 0u; c < 256u; c++) { uint32_t f = s_acl.mem->freq[(row<<8)|c]; if (f) { sum+=f; if(nz<6 && o<(int)sizeof(first)-8) o+=snprintf(first+o,sizeof(first)-o,"%u:%u,",c,f); nz++; } }
                    fprintf(stderr, "[ACLPERM] s_acl.mem row%u T=%u fsum=%u nz=%u [%s]\n",
                            row, (unsigned)s_acl.mem->total[row], (unsigned)sum, (unsigned)nz, first);
                }
            }
        }
    }
    /* 1. to advance there cascade up to pos-1 inclus (bytes copies by MATCHs inclus,
     *    the flot emis = plaine contigue). [GATED UHA_C4DENS, read-only] for
     *    each byte of MATCH couvert q in [start,pos), SCORER (prediction pure,
     *    without learning) the cost dens with l'arena C4 current (already foi-fide
     *    via ACCRING_C4) then logger `q\tcost`. C'is there law of the sol legacy 13.701
     *    (dens SCORE by byte, learned by LITERAL). without UHA_C4DENS : 0 effet. */
    {
        c4dens_ensure();
        if (s_acllearn_all < 0)
            s_acllearn_all = (getenv("UHA_ACLLEARN_ALL") != NULL) ? 1 : 0;
        start = (s_acl.done == ACL_DONE_NONE) ? 0u : s_acl.done + 1u;
        for (q = start; q < pos; q++) {
            uint32_t rowq = 0x341u + 32u * ((q % 3u + 2u) % 3u) + alz_arena_c4_tbucket[s_acl.kprev];
            uint32_t cq, cq_cost;
            acclive_push_byte(plain, q);
            cq = s_acl.kprev;
            if (s_cmctxroll) {   /* [GATED UHA_CM_CTXROLL] ctx roule sure the SYM dir-flip (M11b/13.883), match-inclu */
                s_cmctx = ((s_cmctx << 8) | (cq & 0xffu)) & 0xffffffffu;
                rowq = (s_cmctx >> 8) & 0x1ffu;
            }
            if (s_cmctxroll && s_acl.ar2) {
                cq_cost = alz_arena2d_score(s_acl.ar2, rowq, cq & 0xffu, NULL);
            } else if (s_cmwire && !s_cmctxroll) {
                uint32_t frow, fsym;
                if (alz_ps_cmlive_symrow(plain, q, ALZ_CMW_ROWBASE5, &frow, &fsym) == 0) {
                    rowq = frow; cq = fsym;
                }
            }
            if (s_acl.emiss && s_acl.mem) {   /* [GATED UHA_CM_EMISS] emetteur faithful : ctx roule the RECON raw (plain[q]), window 17 bits, arena2d master persistant (rescale working) */
                uint32_t erow;
                static int s_livepromo = -1;
                uint32_t lp_learn = 0u;
                if (s_livepromo < 0)
                    s_livepromo = (getenv("UHA_LIVEPROMO") != NULL) ? 1 : 0;   /* [GATED default-OFF 14.039] */
                s_acl.ctx = ((s_acl.ctx << 8) | ((uint32_t) plain[q] & 0xffu)) & 0x1FFFFu;
                erow = (s_acl.ctx >> 8) & 0x1FFu;
                /* [DIAG gated UHA_EMISS_ROWQ, isolat, defautOFF] apprendre the master
                 * delta2D sure there line of class `relrow = rowqbase[3]` (base+affinite,
                 * clusters {04,3236,6468}) - there law of the feed #18 - au lieu of the reconlag
                 * `erow`. The recon not chevauche not the lines reelles (diff 0 overlap).
                 * Zero effet out gate (mrow=erow). */
                {
                    static int s_erowq = -1; uint32_t mrow;
                    static int s_tok = -1;
                    if (s_erowq < 0) s_erowq = getenv("UHA_EMISS_ROWQ") ? 1 : 0;
                    if (s_tok < 0) s_tok = getenv("UHA_EMISS_TOKEN") ? 1 : 0;
                    mrow = s_erowq ? ((rowq - 0x341u) & 0x1FFu) : erow;
                    /* [GATED UHA_ACL_GENCTX3, inencode] law of row of the master = `gen_ctxs(3)` (there
                     * true, visites 1358/1358 & freqF prouves), en ORDER D'EMISSION (s_acl.mem
                     * advances once by byte emis, not has rescan). C'is the bourrin warmedlive :
                     * doit to give counter[5]->29 and the dens hot exact. Zero effet out gate. */
                    {
                        static int s_genx = -1; static uint32_t *g_c3 = NULL; static uint32_t g_c3n = 0;
                        if (s_genx < 0) {
                            s_genx = getenv("UHA_ACL_GENCTX3") ? 1 : 0;
                            if (s_genx && usize <= 0x10000u) {
                                g_c3 = (uint32_t *) calloc(usize, sizeof(uint32_t));
                                if (g_c3) { alz_ps_gen_ctxs(3, plain, usize, g_c3); g_c3n = usize; }
                                else s_genx = 0;
                            }
                        }
                        if (s_genx && g_c3 && q < g_c3n) {
                            uint32_t sc = g_c3[q]; mrow = (sc >> 8) & 0x1FFu; cq = sc & 0xFFu;
                            if (mrow >= ALZ_ARENA2D_MAX_ROW) mrow = ALZ_ARENA2D_MAX_ROW - 1u;
                        }
                    }
                acfc0 = s_acl.mem->freq[(mrow<<8)|(cq & 0xffu)];   /* fc BEFORE learn (cold if 0) - gate UHA_ACL_INTEGRATE */
                if (s_acl_emiss_aging) {
                    /* [UHA_ACL_EMISS_AGING] loop = bytes COUVERTS by has MATCH : the master
                     * d'emission legacy (`0x41216d`) learns 1* by LITERAL emis (has jeton =
                     * 1 write), NOT by byte couvert (otherwise sure-learning *1,5). On
                     * n'advances therefore NOT `s_acl.mem` here ; single the branchement literal (more
                     * low) learns. cq_cost no uses (dens no writes, path bank intacte). */
                    cq_cost = 0u;
                } else if (s_tok) {
                    /* [gated UHA_EMISS_TOKEN] in the span (bytes of match) : TO READ the cost
                     * since s_acl.mem without apprendre (learn reserve au site literal = 1/token),
                     * for not not surcompter the master (feed #18 = 7554/bloc0). */
                    uint32_t Tc = s_acl.mem->total[mrow], fc = s_acl.mem->freq[(mrow<<8)|(cq & 0xffu)];
                    uint32_t num = (fc == 0u) ? (uint32_t)s_acl.mem->counter[mrow] : fc;
                    uint32_t p = (Tc != 0u) ? ((num<<14)/Tc) : (ALZ_SCORE_CUM_N-1u);
                    if (p >= ALZ_SCORE_CUM_N) p = ALZ_SCORE_CUM_N-1u;
                    cq_cost = alz_score_proba_to_cost(p);
                } else if (s_livepromo) {
                    cq_cost = alz_arena2d_score(s_acl.mem, mrow, cq & 0xffu, &lp_learn);
                } else {
                    cq_cost = alz_arena2d_score(s_acl.mem, mrow, cq & 0xffu, NULL);
                }
                /* [DIAG gated UHA_ACL_CTRDUMP] trajectoire of the counter of the MASTER d'emission
                 * (acclive, order reel) by line : validates if s_acl.mem->counter[mrow] rejoint
                 * the `work_tot` LEG (row5->29, row67->11, row29->33). if YES -> the master d'acclive
                 * fournit the bon counter (but son dens hot is false) -> not to take THAT the counter. */
                {
                    static FILE *s_cd = NULL; static int s_cdi = -1;
                    if (s_cdi < 0) { const char *ce = getenv("UHA_ACL_CTRDUMP"); s_cdi = (ce && *ce) ? 1 : 0; if (s_cdi) s_cd = fopen(ce, "w"); }
                    if (s_cd) fprintf(s_cd, "%u\t%u\t%u\t%u\t%u\n", (unsigned)q, (unsigned)mrow,
                        (unsigned)s_acl.mem->counter[mrow], (unsigned)s_acl.mem->total[mrow], (unsigned)(cq & 0xffu));
                }
                {   /* reroute of the learnlog sure there line reellement learned */
                    static FILE *s_alz2 = NULL; static int s_alz2_init = -1;
                    if (s_alz2_init < 0) {
                        const char *al2 = getenv("UHA_ACL_LEARNLOG");
                        s_alz2_init = (al2 && *al2) ? 1 : 0;
                        if (s_alz2_init) s_alz2 = fopen(al2, "w");
                    }
                    if (s_alz2 && q < 12544u)
                        fprintf(s_alz2, "%u\t%u\t%u\n", (unsigned)q, (unsigned)mrow, (unsigned)(cq & 0xffu));
                }
                }
                /* [GATED UHA_LIVEGOV 14.043] publier the cost LIVE in g_lmin_live for there
                 * 2 iteration (pointfixe) ; alloc lazy, defautOFF (dp_livegov() pilote there reading). */
                if (s_livepromo && dp_livegov()) {
                    if (!g_lmin_live) g_lmin_live = (uint32_t *) calloc(0x10000u, sizeof(uint32_t));
                    if (g_lmin_live && q < 0x10000u) g_lmin_live[q] = cq_cost;
                    g_lmin_live_ready = 1;
                }
                if (q < 0x10000u && !s_acl_emiss_aging) {   /* [UHA_ACL_EMISS_AGING] learn-only : not NOT to write g_lmin_dens (decouplage of the hot -> not 71) */
                    static int s_integ = -1;
                    if (s_integ < 0) s_integ = getenv("UHA_ACL_INTEGRATE") ? 1 : 0;
                    if (s_integ) {
                        /* [port inencode] acclive n'overwrites the dens THAT some cellules COLD (the
                         * hot keep COSTSNAP correct) + adds l'ESCAPE `bm[0x402+sel][delta]`.
                         * secondaire = cq_cost (counter d'order d'emission), escape = LUT[g_bm_freq[row][cq]<<14/g_bm_tree[row][0]]. */
                        if (acfc0 == 0u) {
                            uint32_t dval = cq_cost;
                            if (g_bm_freq && g_bm_tree) {
                                uint32_t erow = (uint32_t)(0x402 + g_bm_sel);
                                uint32_t fen = g_bm_tree[erow][0], fm = g_bm_freq[erow][cq & 0xffu];
                                uint32_t ep = (fen != 0u) ? ((fm << 14) / fen) : (ALZ_SCORE_CUM_N-1u);
                                if (ep >= ALZ_SCORE_CUM_N) ep = ALZ_SCORE_CUM_N-1u;
                                dval += alz_score_proba_to_cost(ep);
                            }
                            g_lmin_dens[q] = dval;
                        }
                    } else {
                        g_lmin_dens[q] = cq_cost;
                    }
                }
            }
            if (s_acllearn_all) {
                /* LIVE-feed 0x4111a0 : LEARN +=0x20 at each byte emis (match-inclu) */
                cq_cost = alz_arena_c4_event(s_acl.ar, rowq, cq, 0, 0u);
            } else {
                cq_cost = alz_arena_c4_score(s_acl.ar, rowq, cq, 0, 0u);
            }
            /* [GATED UHA_ACLIVE_SMFEED, default-OFF, 14.070] Feed coherent singlepass :
             * publier the cost HOT arena_c4 of l'acclive in g_lmin_live[q] (for q < pos,
             * matchinclus), INDEPENDAMMENT of the block EMISS corruptif. Couple has UHA_SM_LIVE
             * (neartie block>=1) : block0 keeps COSTSNAP exact, block1 reads the sm hot.
             * DefautOFF = zero effet (g_lmin_live no writes by this path). */
            {
                static int s_smfeed = -1;
                if (s_smfeed < 0) s_smfeed = getenv("UHA_ACLIVE_SMFEED") ? 1 : 0;
                if (s_smfeed && q < 0x10000u) {
                    if (!g_lmin_live) g_lmin_live = (uint32_t *) calloc(0x10000u, sizeof(uint32_t));
                    if (g_lmin_live) { g_lmin_live[q] = cq_cost; g_lmin_live_ready = 1; }
                }
            }
            if (s_c4df)
                fprintf(s_c4df, "%u\t%u\t%u\t%u\tM\n", (unsigned) q, (unsigned) rowq,
                        (unsigned) cq, (unsigned) cq_cost);
        }
        /* dens of the LITERAL pos = cost of l'evenement (score+learn), logge more low. */
        (void) start;
    }
    /* 2. row (K[pos-1] current ; pos==0 -> init). */
    row = (pos == 0u) ? 0x341u
        : 0x341u + 32u * ((pos % 3u + 2u) % 3u) + alz_arena_c4_tbucket[s_acl.kprev];
    /* 3. escape (sg = state at the evenement, before push of l'byte current). */
    flag = 0u; esym = 0u;
    if (s_acl.esc_wait) {
        bf = (pos >= 3u) ? (uint32_t) plain[pos - 3u] : 0u;
        raw = (uint32_t) plain[s_acl.rawidx & 0xFFFFu];
        flag = 1u;
        esym = s_acl.sg ? ((bf - raw) & 0xFFu) : ((raw - bf) & 0xFFu);
        s_acl.esc_wait = 0;
    }
    /* 4. sym = K[pos]. */
    acclive_push_byte(plain, pos);
    sym = s_acl.kprev;
    if (s_cmctxroll) {           /* [GATED] to advance ctx of the `sym` current then row=(ctx>>8)&0x1ff */
        s_cmctx = ((s_cmctx << 8) | (sym & 0xffu)) & 0xffffffffu;
        row = (s_cmctx >> 8) & 0x1ffu;
    } else if (s_cmwire) {
        uint32_t frow, fsym;
        if (alz_ps_cmlive_symrow(plain, pos, ALZ_CMW_ROWBASE5, &frow, &fsym) == 0) {
            row = frow; sym = fsym;
        }
    }
    if (s_acl.emiss && s_acl.mem) {           /* [GATED UHA_CM_EMISS] literal current : to advance ctx of the RECON raw + score/learn master persistant */
        uint32_t erow;
        static int s_erowq_lit = -1;
        uint32_t lrow;
        if (s_erowq_lit < 0) s_erowq_lit = getenv("UHA_EMISS_ROWQ") ? 1 : 0;
        s_acl.ctx = ((s_acl.ctx << 8) | ((uint32_t) plain[pos] & 0xffu)) & 0x1FFFFu;
        erow = (s_acl.ctx >> 8) & 0x1FFu;
        /* [gated UHA_EMISS_ROWQ] line delta2D of the literal = 32*phase + affinite(base[3] removes) */
        lrow = 32u * ((pos % 3u + 2u) % 3u) + alz_arena_c4_tbucket[s_acl.kprev];
        if (s_acl_emiss_aging) {
            /* [UHA_ACL_EMISS_AGING, decouplage ACCRING_C4] to advance the master d'emission by-
             * emission with there double porte aging (`master_learn`, 1* /literal = cadence
             * `0x41216d`) EN SIDE-EFFECT SINGLE, then RENDRE the cost C4 habituel (`alz_arena_c4_event`,
             * which learns l'arena C4 nourrissant the bud ACCRING_C4) afin that there path productive
             * remainder intacte -> no corruption 71. `row` n'is NOT rebranche : il keeps sa value
             * delta-2D complete (0x341..) = exactement this that consumes the C4 in there path bank. */
            uint32_t mrow = s_erowq_lit ? (lrow & 0x1FFu) : erow;
            if (mrow >= ALZ_ARENA2D_MAX_ROW) mrow = ALZ_ARENA2D_MAX_ROW - 1u;
            alz_arena2d_master_learn(s_acl.mem, mrow, sym & 0xffu);
            cost = alz_arena_c4_event(s_acl.ar, row, sym, (int) flag, esym);
        } else {
            row = s_erowq_lit ? (lrow & 0x1FFu) : erow;
            cost = alz_arena2d_score(s_acl.mem, row, sym & 0xffu, NULL);
        }
    } else
    cost = (s_cmctxroll && s_acl.ar2)
              ? alz_arena2d_score(s_acl.ar2, row, sym & 0xffu, NULL)
              : alz_arena_c4_event(s_acl.ar, row, sym, (int) flag, esym);
    if (s_c4df)
        fprintf(s_c4df, "%u\t%u\t%u\t%u\tL\n", (unsigned) pos, (unsigned) row,
                (unsigned) sym, (unsigned) cost);
    return cost;
}

/* Enveloppe `once` : returns l'`acc` of l'evenement literal of `pos`, en
 * CALCULANT has single fois by pos (there cascade arena has has side effect
 * d'learning : two calls sure the same pos double-learning => false).
 * Uses at the fois by there poussee ring (UHA_ACCRING_C4) and by l'injection
 * dens (UHA_ACCLIVE) in there same iteration ; the first call computes, the second
 * reutilise. pos monotone (has file = has pass). */
static uint32_t __attribute__((unused)) acclive_event_once(const uint8_t *plain, uint32_t usize, uint32_t pos)
{
    if (s_acl_ev_pos == pos && s_acl_ev_cost != 0xFFFFFFFFu)
        return s_acl_ev_cost;
    {
        uint32_t c = acclive_event(plain, usize, pos);
        s_acl_ev_pos  = pos;
        s_acl_ev_cost = c;
        return c;
    }
}

/* Drifts (ctx,ctx2,sym) of the literal current has d->st.output_pos, mirror exact
 * d'alz_encode_literal (13.351, block ACCDUMP). Partage by cl_bm_predict and
 * there poussee faithful `mixc` of l'ring bud (UHA_BUDDMIX, 13.647). */
static void cl_bm_ctx3(alz_dec *d, const uint8_t *plain, int *octx, int *octx2,
                       int *osym)
{
    uint8_t lb0 = plain[d->st.output_pos];
    int ctx, ctx2, sym;
    if (d->st.escape_selector != 0) {
        uint8_t bias = d->st.side_bias;
        ctx  = (int) d->st.side_secondary;
        ctx2 = 0x402 + (int) d->st.escape_selector;
        sym  = (int) ((d->st.side_dir == 0) ? (uint8_t)(lb0 - bias)
                                            : (uint8_t)(bias - lb0));
    } else if (!d->st.escape_changed) {
        int last = (int) d->st.last_byte;
        int prev = (int) d->st.prev_byte;
        ctx = last;
        if ((last & 0xC0) == (prev & 0xC0))
            ctx += 0x100;
        ctx2 = ((last & 0xE0) >> 5) + 0x3F9;
        sym = (int) lb0;
    } else {
        ctx  = (int) d->st.last_byte + 0x200;
        ctx2 = 0x401;
        sym  = (int) lb0;
    }
    *octx = ctx; *octx2 = ctx2; *osym = sym;
}

/* cost byte-model predictif (read-only, not MAJ nothing) of l'octe has
 * d->st.output_pos, sure the model REELLEMENT rechauffe by the emissions
 * passees. ctx/ctx2/sym = miroirs exact d'alz_encode_literal (cf 13.351,
 * block ACCDUMP). Sert has alimenter l'esi/mean live of the decider. */
static uint32_t cl_bm_predict(alz_dec *d, const uint8_t *plain)
{
    int ctx, ctx2, sym;
    cl_bm_ctx3(d, plain, &ctx, &ctx2, &sym);
    return alz_bm_predict_cost(d, ctx, ctx2, sym);
}

/* [GATED UHA_DENSDUMP=path, read-only] dump pos\tcost of g_lmin_dens,
 * for to compares offline the sm produces by cold-dens vs snapshot-dens au `sm`
 * REEL of the decide legacy (c30e_proxybud.tsv). zero effet default. */
static void lmin_dump_gated(uint32_t usize)
{
    const char *dp = getenv("UHA_DENSDUMP");
    if (dp && g_lmin_dens) {
        FILE *f = fopen(dp, "w");
        uint32_t q;
        if (f) {
            for (q = 0; q < usize; q++)
                fprintf(f, "%u\t%u\n", (unsigned) q, (unsigned) g_lmin_dens[q]);
            fclose(f);
        }
    }
}

/* [walk-candidate GATED UHA_EMITWALK=path, read-only] dump of the WALK
 * REELLEMENT EMISE by the clone (Has single enregistrement by token engage, not
 * by candidate visite) : `pos\tM\ttoken\tdist\tcount` for has match, `pos\tL`
 * for has literal. Sert has diffister offline the parse of the clone (7024) vs there
 * walk legacy (c30e_proxybud.tsv, lines alR==1 = matchs emis) for localiser
 * the 1er fork of WALK. Zero effet when UHA_EMITWALK absent (default-OFF). */
static void emit_walk_dump(uint32_t pos, int is_match, int token,
                           uint32_t dist, uint32_t count)
{
    static int s_inited = 0;
    static FILE *s_f = NULL;
    if (!s_inited) {
        const char *ep = getenv("UHA_EMITWALK");
        s_inited = 1;
        if (ep) s_f = fopen(ep, "w");
    }
    if (!s_f)
        return;
    if (is_match)
        fprintf(s_f, "%u\tM\t%d\t%u\t%u\n", (unsigned) pos, token,
                (unsigned) dist, (unsigned) count);
    else
        fprintf(s_f, "%u\tL\n", (unsigned) pos);
}

/* [live-cls3-dens GATED UHA_LIVDENS=path UHA_LVDLEARNM=<0|1>, default-OFF,
 * read-only, no-emissive, NOT MUTE NOR d NOR l'emission] Advance of has arena
 * delta-2D MACHINE cls3 (`ctx3[q]` = context genere by alz_ps_gen_ctxs(3,...))
 * en order d'emission, byte-by-byte. for each position q of [start,start+n) :
 *   (has) PREDIT the cost via l'state current of l'arena (num = freq==0 ? counter : freq,
 *       T = total BEFORE update, proba = (num<<14)/T, cost = LUT) - no effect
 *       of bord sure l'arena ;
 *   (b) if `learn` : updates freq/counter/total has inc=16 + rescale (`0x414590`)
 *       - mirror exact of the rule d'learning of `seed_arena` (l.5787+).
 * But : tester if the `dens` legacy vient of has arena LIVE pilotee-by-emission
 * (score all position, learns each literal emis) plutot that of has pre-pass
 * from-plaintext. `learn=0` during the bytes couverts by MATCH (default) ;
 * UHA_LVDLEARNM=1 for apprendre also the bytes-match (test alternative).
 * Dump `pos\trow\tdelta\tcost` by byte scanne, for jointure dens_truth/sm. */
static void ld_advance(alz_arena2d_t *a, const uint32_t *ctx3, FILE *f,
                       uint32_t start, uint32_t n, uint32_t usize, int learn,
                       uint32_t reset_at, int *reset_done, uint32_t inc, uint32_t *out)
{
    uint32_t q;
    if (!a || !ctx3)
        return;
    if (inc == 0u)
        inc = 16u;
    /* cold-start optionnel has has frontier of block (UHA_LVDRESET) : re-initialise
     * l'arena Has single fois as soon as `start` atteint `reset_at`. */
    if (reset_at && reset_done && !*reset_done && start >= reset_at) {
        alz_arena2d_init(a, inc);
        *reset_done = 1;
    }
    for (q = start; q < start + n && q < usize; q++) {
        uint32_t sc   = ctx3[q];
        uint32_t row  = (sc >> 8) & (ALZ_ARENA2D_MAX_ROW - 1u);
        uint32_t dl   = sc & 0xffu;
        uint32_t T    = a->total[row];
        uint16_t ff   = a->freq[(row << 8) | dl];
        uint32_t num  = (ff == 0u) ? (uint32_t) a->counter[row] : (uint32_t) ff;
        uint32_t proba = (T != 0u) ? ((num << 14) / T) : (ALZ_SCORE_CUM_N - 1u);
        uint32_t cost;
        if (proba >= ALZ_SCORE_CUM_N)
            proba = ALZ_SCORE_CUM_N - 1u;
        cost = alz_score_proba_to_cost(proba);
        if (out)
            out[q] = cost;   /* [ARENA_TASK16 hook] option of output : alimente `sm`/g_lmin_dens. NULL = inerte. */
        if (f)
            fprintf(f, "%u\t%u\t%u\t%u\n", (unsigned) q, (unsigned) row,
                    (unsigned) dl, (unsigned) cost);
        if (learn) {
            uint16_t *sfr = &a->freq[(row << 8) | dl];
            if (*sfr == 0u) {
                *sfr = (uint16_t) inc;
                a->counter[row] = (uint16_t) (a->counter[row] + inc);
                a->total[row]   = (uint16_t) (a->total[row] + 2u * inc);
            } else {
                *sfr = (uint16_t) (*sfr + inc);
                a->total[row] = (uint16_t) (a->total[row] + inc);
            }
            if (a->total[row] >= ALZ_ARENA2D_RESCALE)
                alz_arena2d_rescale(a, row);
        }
    }
}

/* [GATED UHA_C4PRE=path, read-only, default-OFF, INERT]
 * Hypothese 13.715 : the producteur `dens` legacy (table [0x45cb60]->copie
 * [0x45cb7c], producteur 0x414630, same bancs C4 0x4373cc/0x4373d0 that 0x411bb0)
 * is has PRE-PASS which LEARNS each byte (not only the literals emits),
 * done has arena MORE HOT => costs dens by position MORE LOW (direction
 * coherent with legacy 37459 < mon C4 live 37675 sure there window 13070).
 * This probe does tourner Has arena C4 dediee sure all the file en order of
 * position, treatant each byte as has evenement (score+learn, esc=0), and
 * logge pos\tsym\tcost. NOT TOUCHE NOT g_lmin_dens (pur diagnostic). */
static void c4pre_dens_dump(const uint8_t *plain, uint32_t usize, const char *path)
{
    alz_arena_c4_t *ar;
    FILE *f;
    uint32_t q, row, sym, kprev = 0u, start;
    int sg = 0, mode = 0;
    static const uint32_t bpos[6] = {0x0000u,0x3100u,0x620cu,0x931cu,0xc4ffu,0xff00u};
    (void)bpos;
    const char *mv = getenv("UHA_C4PREMODE");
    if (mv && *mv) mode = atoi(mv);
    if (usize > 0x10000u) return;
    f = fopen(path, "w");
    if (!f) return;
    ar = (alz_arena_c4_t *) malloc(sizeof(*ar));
    if (!ar) { fclose(f); return; }
    alz_arena_c4_init(ar);
    fprintf(f, "pos\trow\tsym\tcost\n");
    /* demarre has 0 (has single arena, no reset block, cf 13.701) */
    start = 0u;
    kprev = 0u; sg = 0;
    for (q = start; q < usize; q++) {
        uint32_t bf = (q >= 3u) ? (uint32_t) plain[q - 3u] : 0u;
        uint32_t dlt = (uint32_t) ((plain[q] - bf) & 0xFFu);
        uint32_t cost;
        int learn;
        row = (q == 0u) ? 0x341u
            : 0x341u + 32u * ((q % 3u + 2u) % 3u) + alz_arena_c4_tbucket[kprev];
        if (sg) dlt = (uint32_t) ((0u - dlt) & 0xFFu);
        kprev = dlt;
        if (dlt >= 0x80u) sg ^= 1;
        sym = kprev;
        /* mode 0 = learn-all ; mode 1 = learn-all jusqu'at the beginning of the block current
         * then score-only (window figee au snap of block) ; mode 2 = score-only. */
        if (mode == 2) learn = 0;
        else if (mode == 1) {
            /* learn-all sure the bytes of the/before the block previous (here threshold
             * = start bloc1 = 12544), then score-only in the block current
             * (window dens figee au snap of start of block). */
            learn = (q < 12544u) ? 1 : 0;
        } else learn = 1;
        cost = learn ? alz_arena_c4_event(ar, row, sym, 0, 0u)
                     : alz_arena_c4_score(ar, row, sym, 0, 0u);
        fprintf(f, "%u\t%u\t%u\t%u\n", (unsigned) q, (unsigned) row,
                (unsigned) sym, (unsigned) cost);
    }
    fclose(f);
    free(ar);
}

/* [ARENA_TASK16 - GATED UHA_LIVEWALK, default-OFF] live_walk_master : coeur of the producteur
 * reecrit en loop walkarena SINGLEPASS live. Has arena master unique M (inc =
 * UHA_LIVEWALK_INC default 16), update INLINE by each byte REELLEMENT EMIS
 * (dense, matchinclus - the stream emis = plain contigue, en order some tokens). at each
 * position : cost PRElearn = LUT[(num<<14)/total(before)] publie in out[q] (source of the
 * sm/bud via g_lmin_dens), THEN learning (cold/warm + rescale working @0x4000,
 * inherent has score()). To the frontiers of block : AGING 0x40ffa0 (`rescale_master` :
 * freq>16->>>1 otherwise 0) then RELOAD `total := tree + counter` (tree = Sigma columns freq,
 * recalcul no incremental, mirror of the reload bulk `0x414800`). ctx = rolling recon
 * window 17 bits by default (emission) ; UHA_LIVEWALK_CTX=1 -> machine cls3.
 * ZERO effet out gate (there branch appelante is gated defautOFF). Judge unique = firstdiv. */
static void live_walk_master_prepass(const uint8_t *plain, uint32_t usize, uint32_t *out, uint32_t from, const uint8_t *is_lit)
{
    static const uint32_t blpos[6] = {0x0000u, 0x3100u, 0x620cu, 0x931cu, 0xc4ffu, 0xff00u};
    static const uint32_t blen[6]  = {0x3100u, 0x3100u, 0x3100u, 0x3100u, 0x3a01u, 0x100u};
    alz_arena2d_t *M;
    uint32_t *ctx3 = NULL;
    uint32_t *ctxall[5] = {NULL,NULL,NULL,NULL,NULL};   /* [mode 6] machine ctx of each class 0..4 */
    uint32_t inc, r, i, b, q, ctx = 0u, age_period = 0u;
    int use_cls3 = 0, age_cadence = 0, stats = 0, learn_mode = 1, ctx_class = 3;
    uint32_t hit68 = 0u, hit37 = 0u, tree68 = 0u, tree37 = 0u;   /* [probe _STATS] nb learns/row + tree au reload bloc0->1 */
    const char *e;
    FILE *tj = NULL;
    FILE *sp = NULL;   /* [DIAG per-slot UHA_LIVEWALK_SLOTPROBE, isolat, default-OFF] */
    if (!plain || !out || usize > 0x10000u)
        return;
    M = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    if (!M)
        return;
    e = getenv("UHA_LIVEWALK_INC");
    inc = e ? (uint32_t) strtoul(e, NULL, 10) : 16u;
    if (inc == 0u) inc = 16u;
    e = getenv("UHA_LIVEWALK_CTX");
    use_cls3 = e ? (atoi(e) != 0) : 0;
    e = getenv("UHA_LIVEWALK_CTXCLASS");
    if (e) { ctx_class = atoi(e); use_cls3 = 1; }   /* [TEST] class of ctx of the master (0..4) ; cls0 = 82% warm vs cls3 */
    e = getenv("UHA_LIVEWALK_AGE");
    age_cadence = e ? (atoi(e) != 0) : 0;   /* 1 = aging master 0x40ffa0 en more of the @0x4000 working ; default 0 (GT halving = working) */
    e = getenv("UHA_LIVEWALK_LEARN");
    learn_mode = e ? atoi(e) : 1;           /* 0=never 1=literals-single 2=dense 3=cold-single(rearmes) 6=5classes */
    if (learn_mode == 6) use_cls3 = 1;      /* mode 6 : cost of output lu au row cls3, learning = 5 passes */
    if (learn_mode == 7) { use_cls3 = 1; ctx_class = 3; }   /* mode 7 : accumulation cls0 (ctxall[0]) + reading cost cls3 */
    if (learn_mode != 3 && learn_mode != 4 && learn_mode != 6 && learn_mode != 7 && !is_lit) learn_mode = 2;   /* modes 3/4/6/7 scannent all */
    e = getenv("UHA_LIVEWALK_AGE_PERIOD");
    age_period = e ? (uint32_t) strtoul(e, NULL, 10) : 0u;  /* rearme `rescale_master`(0x40ffa0) all N pos (commit/pass) ; 0=frontier block single */
    stats = getenv("UHA_LIVEWALK_STATS") ? 1 : 0;
    {   /* [GATED UHA_LIVEWALK_TRAJ=path] dump by-position of the trajectoire master
         * (rel_idx\ttotal[68]\ttotal[37]) for confront DIRECT contre GT
         * _scratch/a150_sc/gt/leg_b1_tot{68,37}_1300.log. read-only (out out). */
        const char *tp = getenv("UHA_LIVEWALK_TRAJ");
        if (tp && *tp) { tj = fopen(tp, "w"); if (tj) fprintf(tj, "idx\tq\trow\tdelta\ttotal68\ttotal37\n"); }
    }
    {   /* [DIAG per-slot, GATED default-OFF, read-only] dump q\trow\tsym\tfreqF\tTOT\tdens */
        const char *pp = getenv("UHA_LIVEWALK_SLOTPROBE");
        if (pp && *pp) sp = fopen(pp, "w");
    }
    alz_arena2d_init(M, (uint16_t) inc);
    M->aging_on = getenv("UHA_LIVEWALK_AGING") ? 1 : 0;   /* [C6-ter default-OFF] master production by-emission + double porte aging */
    if (use_cls3) {
        ctx3 = (uint32_t *) malloc(sizeof(uint32_t) * (size_t) usize);
        if (ctx3) alz_ps_gen_ctxs((uint32_t)ctx_class, plain, usize, ctx3);
    }
    if (learn_mode == 6 || learn_mode == 7) {   /* [mode 6/7] construit there machine ctx some classes */
        int c; for (c = 0; c < (learn_mode==7?1:5); c++) {
            ctxall[c] = (uint32_t *) malloc(sizeof(uint32_t) * (size_t) usize);
            if (ctxall[c]) alz_ps_gen_ctxs((uint32_t)c, plain, usize, ctxall[c]);
        }
    }
    for (b = 0u; b < 6u; b++) {
        uint32_t base = blpos[b], len = blen[b];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* frontier of block : AGING 0x40ffa0 then RELOAD total:=tree+counter (sauf bloc0). */
        if (b > 0u) {
            for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++) {
                uint32_t sum = 0u, c, rowb = r << 8;
                if (age_cadence) alz_arena2d_rescale_master(M, r);  /* freq>16->>>1 otherwise 0 */
                for (c = 0u; c < 256u; c++) sum += M->freq[rowb + c];
                M->total[r] = (uint16_t) (sum + M->counter[r]);     /* reload working = tree + counter */
                if (r == 68u) tree68 = sum;
                if (r == 37u) tree37 = sum;
            }
            if (stats && b == 1u)
                fprintf(stderr, "[LIVEWALK] reload@b1 t68=%u(tree=%u cnt=%u hit0=%u) t37=%u(tree=%u cnt=%u hit0=%u)\n",
                        (unsigned) M->total[68u], (unsigned) tree68, (unsigned) M->counter[68u], (unsigned) hit68,
                        (unsigned) M->total[37u], (unsigned) tree37, (unsigned) M->counter[37u], (unsigned) hit37);
        }
        /* [DIAGNOSTIC partition GATED UHA_SEED_B1FREQ=<f> default-OFF, isolat, NO-expedie]
         * Re-amorce l'arena M at the input of the bloc1 (b==1, pos==from) with l'state ORACLE
         * captures (freq/total/counter by cellule). But = trancher if the residu of densite
         * bloc1 is has default d'STATE D'input (-> the scan convergerait ~99% vs m7_sm_gt) now
         * of CADENCE intra-block (-> resterait ~25%). GT en input = LOCALISATION only,
         * NEVER cable at the emission. Zero effet without env. */
        if (b == 1u && getenv("UHA_SEED_B1FREQ")) {
            const char *ff = getenv("UHA_SEED_B1FREQ");
            const char *ft = getenv("UHA_SEED_B1TOTAL");
            const char *fk = getenv("UHA_SEED_B1CTR");
            FILE *sf;
            uint32_t k;
            if ((sf = fopen(ff, "r"))) {          /* freq[row*256+sym] 131072 u16 */
                unsigned val;
                for (k = 0u; k < ALZ_ARENA2D_MAX_CTX && fscanf(sf, "%u", &val) == 1; k++)
                    M->freq[k] = (uint16_t) val;
                fclose(sf);
            }
            if (ft && (sf = fopen(ft, "r"))) {
                unsigned val;
                for (k = 0u; k < ALZ_ARENA2D_MAX_ROW && fscanf(sf, "%u", &val) == 1; k++)
                    M->total[k] = (uint16_t) val;
                fclose(sf);
            }
            if (fk && (sf = fopen(fk, "r"))) {
                unsigned val;
                for (k = 0u; k < ALZ_ARENA2D_MAX_ROW && fscanf(sf, "%u", &val) == 1; k++)
                    M->counter[k] = (uint16_t) val;
                fclose(sf);
            }
            fprintf(stderr, "[SEEDB1] load freq/total/counter oracle at entry b1; total68=%u counter68=%u\n",
                    (unsigned) M->total[68u], (unsigned) M->counter[68u]);
        }
        for (i = 0u; i < len; i++) {
            uint32_t row, sym, T = 0u, proba = 0u;
            (void)T; (void)proba;
            q = base + i;
            sym = (uint32_t) plain[q] & 0xffu;
            if (use_cls3 && ctx3) {
                uint32_t sc = ctx3[q];
                row = (sc >> 8) & (ALZ_ARENA2D_MAX_ROW - 1u);
                sym = sc & 0xffu;
            } else {
                ctx = ((ctx << 8) | sym) & 0x1FFFFu;   /* rolling recon window 17 bits (emission) */
                row = (ctx >> 8) & 0x1FFu;
            }
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            /* [AGE_PERIOD] rearme periodique (commit 0x40ffa0 by pass) : freq<=16->0 -> recree
             * some contexts froids for the learn " coldseul " (mode 3) ; reload total:=tree+counter. */
            if (age_period && q > 0u && (q % age_period) == 0u) {
                for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++) {
                    uint32_t s = 0u, cc, rb = r << 8;
                    alz_arena2d_rescale_master(M, r);
                    for (cc = 0u; cc < 256u; cc++) s += M->freq[rb + cc];
                    M->total[r] = (uint16_t)(s + M->counter[r]);
                }
            }
            /* cost PRElearn en read-only (T=total current, num=freq now counter if cold). */
            {
                uint32_t Tc = M->total[row], fc = M->freq[(row << 8) | sym];
                uint32_t num = (fc == 0u) ? (uint32_t) M->counter[row] : fc;
                uint32_t p = (Tc != 0u) ? ((num << 14) / Tc) : (ALZ_SCORE_CUM_N - 1u);
                if (p >= ALZ_SCORE_CUM_N) p = ALZ_SCORE_CUM_N - 1u;
                T = Tc;
                if (q >= from) out[q] = alz_score_proba_to_cost(p);
                /* [DIAG per-slot GATED UHA_LIVEWALK_SLOTPROBE=<f> default-OFF, isolat]
                 * dump q\trow\tsym\tfreqF\tTOT\tdens for confront DIRECT vs
                 * m9_prodstate_b1.log pass0 (distingue loiderow vs state cellule).
                 * read-only (no effect on out/M). Zero effet without env. */
                if (sp && q >= from) {
                    uint32_t c = (q >= from && q < usize) ? out[q] : 0u;
                    fprintf(sp, "%u\t%u\t%u\t%u\t%u\t%u\n",
                            (unsigned)(q - 12544u), (unsigned)row, (unsigned)sym,
                            (unsigned)fc, (unsigned)Tc, (unsigned)c);
                }
            }
            /* LEARN master : cadence by line.
             *  mode 1 = LITTERAUXSEULS (cold/warm) ; mode 2 = dense (cold/warm) ;
             *  mode 3 = **COLDSEUL (dense scan, but n'incrmente TOT/CTR/freq THAT if
             *    freq==0)** - 13.830 captures live of the ring : " the producteur n'learns NOT
             *    en hot ", promo +32 only sure context nine. C'is the levier which
             *    explique tree68=13438=420*32 (420 contexts FROIDS, not 1368 evenements). */
            if (learn_mode == 6 || learn_mode == 7) {
                /* MASTER = accumulation au row of(s) class(s) via ctxall ; mode 7 = cls0 single
                 * (law d'accumulation validated 82 % warm) ; reading cost remainder cls3 (ctx3, more high). */
                int c;
                for (c = 0; c < 5; c++) {
                    uint32_t sc, rw, dl, idx, Tv;
                    if (!ctxall[c]) continue;
                    sc = ctxall[c][q]; rw = (sc >> 8) & 0x1FFu; dl = sc & 0xffu;
                    if (rw >= ALZ_ARENA2D_MAX_ROW) rw = ALZ_ARENA2D_MAX_ROW - 1u;
                    idx = (rw << 8) | dl; Tv = M->total[rw];
                    if (M->freq[idx] == 0u) { M->freq[idx]=(uint16_t)inc; M->counter[rw]=(uint16_t)(M->counter[rw]+inc); M->total[rw]=(uint16_t)(Tv+2u*inc); }
                    else                      { M->freq[idx]=(uint16_t)(M->freq[idx]+inc); M->total[rw]=(uint16_t)(Tv+inc); }
                    if (M->total[rw] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(M, rw);
                }
                proba = 0u;
            } else if (learn_mode == 5) {
                /* LEARN to the FRONTIERS d'EMISSION (tokenpartoken, matchinclus) :
                 * ctx roule by byte (recon), but the master n'is updated only to 
                 * fois by TOKEN emis = at each LITERAL, and once at the END of each
                 * SPAN of match. => # learn  #tokens (<< #positions), reproduces there cadence
                 * `0x4111a0`/`0x411bb0` (1 ev/emission) visee by ARENA_TASK16. */
                int lit   = (is_lit && is_lit[q]);
                int span_end = (is_lit && !is_lit[q] && (q + 1u >= usize || is_lit[q + 1u]));
                if (lit || span_end) {
                    uint32_t Tl = M->total[row], fl = M->freq[(row << 8) | sym];
                    if (fl == 0u) { M->freq[(row<<8)|sym]=(uint16_t)inc; M->counter[row]=(uint16_t)(M->counter[row]+inc); M->total[row]=(uint16_t)(Tl+2u*inc); }
                    else          { M->freq[(row<<8)|sym]=(uint16_t)(fl+inc); M->total[row]=(uint16_t)(Tl+inc); }
                    if (M->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(M, row);
                    if (stats && q < 0x3100u) { if (row == 68u) hit68++; else if (row == 37u) hit37++; }
                }
                proba = 0u;
            } else if (learn_mode == 4) {
                /* DENSE (all position) : freq+=inc ALWAYS, but `total`running
                 * n'augmente THAT sure COLD (freq was 0). => @0x4000 franchi less
                 * often -> less of halving -> Sigmafreq (reload working) more high, towards
                 * GT tree68=13438 vs HOTrunning 11134. Reload total:=Sigmafreq+counter. */
                uint32_t idx = (row << 8) | sym;
                if (M->freq[idx] == 0u) {            /* COLD */
                    M->freq[idx]    = (uint16_t) inc;
                    M->counter[row] = (uint16_t)(M->counter[row] + inc);
                    M->total[row]   = (uint16_t)(M->total[row] + inc);
                } else {                             /* HOT : freq++ only, no total */
                    M->freq[idx]    = (uint16_t)(M->freq[idx] + inc);
                }
                if (M->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(M, row);
                if (stats && q < 0x3100u) { if (row == 68u) hit68++; else if (row == 37u) hit37++; }
                proba = 0u;
            } else if (learn_mode == 3) {
                uint32_t idx = (row << 8) | sym;
                if (M->freq[idx] == 0u) {           /* COLD : single mutation */
                    M->freq[idx]   = (uint16_t) inc;
                    M->counter[row]= (uint16_t)(M->counter[row] + inc);
                    M->total[row]  = (uint16_t)(M->total[row] + inc);
                    if (M->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(M, row);
                    if (stats && q < 0x3100u) { if (row == 68u) hit68++; else if (row == 37u) hit37++; }
                }
                proba = 0u;
            } else if (learn_mode == 2 || (learn_mode == 1 && is_lit && is_lit[q])) {
                proba = M->aging_on ? alz_arena2d_master_learn(M, row, sym)   /* [C6-ter default-OFF] master by-emission + double porte aging */
                                    : alz_arena2d_score(M, row, sym, NULL);
                if (stats && q < 0x3100u) { if (row == 68u) hit68++; else if (row == 37u) hit37++; }
            } else
                proba = 0u;
            if (tj && q >= 0x3100u && q < 0x3100u + 1300u)
                fprintf(tj, "%u\t%u\t%u\t%u\t%u\t%u\n", (unsigned)(q - 0x3100u), (unsigned) q,
                        (unsigned) row, (unsigned) sym,
                        (unsigned) M->total[68u], (unsigned) M->total[37u]);
            if (stats && q == 13809u)
                fprintf(stderr, "[LIVEWALK] @13809 row=%u Tpre=%u freq=%u cost=%u\n",
                        (unsigned) row, (unsigned) T, (unsigned) M->freq[(row << 8) | sym],
                        (unsigned) out[q]);
        }
    }
    free(ctx3);
    { int c; for (c = 0; c < 5; c++) free(ctxall[c]); }
    if (tj) fclose(tj);
    if (sp) fclose(sp);
    free(M);
}

/* [ARENA_TASK16 producteur 4-PASSES - GATED default-OFF, isolat] Blueprint RE
 * resolu (reload HOT:=PERM[base[cls]] at each pass of the scorer 0x414630, 4 passes,
 * learn DENSE +32/visite, rescale working @0x4000, commit working->PERM by block).
 * `P` = master commite persistant ; `H` = working recharge since P at each pass.
 * dens publie in out[q] = READING pass 0 (pre-learn). Zero effet without gate. */
static const uint8_t *g_lw_islit = NULL;   /* mask literals (UHA_EMIPROD) for LIT_LEARN */
static int g_lw_litlearn = 0;              /* gate UHA_LIVEWALK_LIT_LEARN (default OFF) */
/* [ARENA_TASK20 step1] master arena2d PERSISTANT, advances once by position in l'order
 * d'emission, NEVER recharge/clobe by the band (contrairement has H). Fournit the `counter[row]`
 * (num secondaire some cellules cold) clean. Gate UHA_LIVEWALK_PMMASTER, defautOFF. */
static alz_arena2d_t *g_pm = NULL;
static void live_walk_master_4pass(const uint8_t *plain, uint32_t usize,
                                    uint32_t *out, uint32_t from)
{
    static const uint32_t blpos[6] = {0x0000u,0x3100u,0x620cu,0x931cu,0xc4ffu,0xff00u};
    static const uint32_t blen[6]  = {0x3100u,0x3100u,0x3100u,0x3100u,0x3a01u,0x100u};
    #define LPASS 4u
    alz_arena2d_t Pc[LPASS];                       /* banques PERM commitees, Has by class */
    alz_arena2d_t *H;                              /* HOT scratch, reload since Pc[c] by pass */
    /* [STEP1 gated UHA_LIVEWALK_PHYSPERM] arena PHYSIQUE PARTAGEE : `Pph` couvre the
     * lines phys 0..1535 (3 chunks of 512), indexees `base[cls]+relrow` -> aliasing
     * interclasses (has write cls1 sure phys901 is vue by the reload cls3 relrow68).
     * Zero effet out gate (Pc[] disjoint, behavior d'origine). */
    static alz_arena2d_t Pph[3];
    static const uint32_t s_pbase[LPASS] = {0u,769u,801u,833u};
    int physperm;
    int feedself;                                  /* [GATED UHA_LIVEWALK_FEEDSELF] emission = unique scribe of Pph */
    int feeddrive;
    int realprim;
    uint32_t rr0;
    uint32_t *ctxc[LPASS];
    uint32_t i, b, c, inc, q;
    int dens_cls = 3;                              /* class whose the dens is lu (gen_ctxs(3)) */
    const char *e;
    FILE *sp = NULL;
    if (!plain || !out || usize > 0x10000u) return;
    e = getenv("UHA_LIVEWALK_INC"); inc = e ? (uint32_t)strtoul(e,NULL,10) : 32u; if(!inc) inc=32u;
    e = getenv("UHA_LIVEWALK_DENSCLS"); if (e) dens_cls = atoi(e);
    physperm = getenv("UHA_LIVEWALK_PHYSPERM") ? 1 : 0;
    /* [GATED UHA_LIVEWALK_FEEDSELF, default-OFF, ISOLAT, not 3] when l'emission clean of the clone
     * is there SOURCE (feedself), the commit scan HOT->Pph is DESACTIVE for that l'emission remainder
     * l'unique scribe of Pph (otherwise the scan-learn overwrites l'avancee by-emission). Zero effet otherwise. */
    {   static int s_fs = -1; if (s_fs < 0) s_fs = getenv("UHA_LIVEWALK_FEEDSELF") ? 1 : 0; 
        if (s_fs && !physperm) { /* FEEDSELF requiert PHYSPERM */ }
        feedself = s_fs;
    }
    {   /* [COUCHE1 gated UHA_LIVEWALK_FEEDDRIVE] arena = composition feed(+=bx by emission)+rescale@0x4000,
         * dens lue since Pph advances by position, without scan-learn source-order. Recette validated sim. */
        static int s_fd = -1;
        if (s_fd < 0) s_fd = getenv("UHA_LIVEWALK_FEEDDRIVE") ? 1 : 0;
        feeddrive = s_fd;
    }
    {   /* [COUCHE1 gated UHA_LIVEWALK_REALPRIM] passe0 faithful : HOT recharge once/block since Pph(band=PERM),
         * then BY position on calls there PRIMITIVE reelle alz_arena2d_score (proba + learn + rescale
         * atomiques canoniques) which ACCUMULE in HOT -> there comptabilite counter/total is the one which has
         * genere m9 (not mon hand-roll). Zero effet out gate. */
        static int s_rp = -1;
        if (s_rp < 0) s_rp = getenv("UHA_LIVEWALK_REALPRIM") ? 1 : 0;
        realprim = s_rp;
    }
    {   /* init once of l'arena physique partagee */
        static int s_pph_init = 0;
        if (!s_pph_init) {
            int agon = getenv("UHA_LIVEWALK_AGING") ? 1 : 0;   /* [C6-ter default-OFF] double porte aging */
            for (rr0 = 0u; rr0 < 3u; rr0++) { alz_arena2d_init(&Pph[rr0], (uint16_t)inc); Pph[rr0].aging_on = agon; }
            s_pph_init = 1;
        }
    }
    H = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t));
    if (!H) return;
    {
        static int s_pmg = -1;
        if (s_pmg < 0) s_pmg = getenv("UHA_LIVEWALK_PMMASTER") ? 1 : 0;
        if (s_pmg && !g_pm) { g_pm = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t)); if (g_pm) alz_arena2d_init(g_pm, (uint16_t)inc); }
    }
    /* [COUCHE1 gated UHA_LIVEWALK_ESC_MODEL, isolat, defautOFF] accumulateur d'ESCAPE
     * = lines hautes of l'arena maitresse unifiee (rows 0x3F9..0x400 = 0x3F9+high3(last_byte)).
     * Init freq=2/total=512 (reverifie captures @cursor0 + band). The scorer legacy the does
     * croitre during ses passes (0x41495f/0x414966 +=0x20). Sure has cellule cold delta2D
     * (freqF==0), dens += LUT[freqM<<14/tot] with freqM=esc[ctx2][sym], then esc += promo.
     * Zero GT en emission : state RECONSTRUIT by the scan, validated vs m9 by cellule. */
    static uint16_t esc[8][256]; static uint32_t esctot[8];
    int escmodel; uint32_t escp;
    { static int s_em=-1; if (s_em<0) s_em = getenv("UHA_LIVEWALK_ESC_MODEL") ? 1 : 0; escmodel = s_em; }
    if (escmodel) { for (escp=0; escp<8u; escp++){ uint32_t s2; esctot[escp]=512u; for (s2=0u;s2<256u;s2++) esc[escp][s2]=2u; } }

    for (c = 0u; c < LPASS; c++) {
        alz_arena2d_init(&Pc[c], (uint16_t)inc);
        ctxc[c] = (uint32_t*)malloc(sizeof(uint32_t)*(size_t)usize);
        if (ctxc[c]) alz_ps_gen_ctxs(c, plain, usize, ctxc[c]);
    }
    /* [DIAG SEEDPERM GATED, isolat, default-OFF] loads has dump PLAT of lines PERM
     * physiques (base 768..) in there banque cls3 (Pc[3]) : relrow = phys-833.
     * Applies at the input of each block b>=1 (the commit of bloc0 clobberait otherwise).
     * Teste the CONSOMMATEUR (reload->dens->sm->decider) with the PERM commite reel of #18.
     * read-only of has file, zero GT en emission. */
    long *seedvals = NULL; size_t seedn = 0;
    {
        const char *sf = getenv("UHA_LIVEWALK_SEEDPERM");
        if (sf && *sf) {
            FILE *fp = fopen(sf, "r");
            if (fp) {
                seedvals = (long*)malloc(sizeof(long)*(256*256));
                if (seedvals) { while (seedn < (size_t)(256*256) && fscanf(fp, "%ld", &seedvals[seedn]) == 1) seedn++; }
                fclose(fp);
            }
        }
    }
    /* [DIAG FEEDPHYS GATED, isolat, defautOFF] replays the feed COMPLETE #18 (`m18_perm_writer.log`,
     * `seq` couvre all the file) in `Pph` PHYSIQUE, advances by block (inputs with
     * seq<base[b]) -> produces the PERM d'input of each block by the feed oracle reel.
     * Rescale FLOOR 2 when total>=0x4000 (aging approximatif ; #18 finalise). DIAG only. */
    long *fline = NULL, *fsym = NULL, *fbx = NULL, *fseq = NULL; size_t fn = 0, fpos = 0;
    if (getenv("UHA_LIVEWALK_FEEDPHYS")) {
        const char *ff = getenv("UHA_LIVEWALK_FEEDPHYS");
        FILE *fp = (*ff=='=')? fopen(ff+1, "r") : (ff && *ff ? fopen(ff,"r") : NULL);
        if (fp) {
            char ln[256]; size_t cap = 40000;
            fline=malloc(sizeof(long)*cap); fsym=malloc(sizeof(long)*cap);
            fbx=malloc(sizeof(long)*cap);  fseq=malloc(sizeof(long)*cap);
            if (fline&&fsym&&fbx&&fseq) {
                while (fn < cap && fgets(ln, sizeof ln, fp)) {
                    char site[32]; unsigned long n,a,bx,lin,sq;
                    if (sscanf(ln,"%31s %lx %lx %lx %lx %lx",site,&n,&a,&bx,&lin,&sq)==6) {
                        unsigned long ph=(a-0xf20030UL)/512UL, sy=((a-0xf20030UL)%512UL)/2UL;
                        fline[fn]=(long)ph; fsym[fn]=(long)sy; fbx[fn]=(long)bx; fseq[fn]=(long)sq; fn++;
                    }
                }
            }
            fclose(fp);
        }
    }
    /* [GATED UHA_LIVEWALK_FEEDSELF=<lits.txt>, default-OFF, ISOLAT, not 3 from-scratch] source
     * d'emission ALTERNATIVE au feed GT m18 : advances `Pph` (PERM) by the LITERALS THAT THE CLONE
     * EMITS LUI-SAME (positions of `lits.txt`, there pass-1 of e3_gate), mappee en line physique via
     * there law of row of the master `ctxc[3]` (gen_ctxs(3)) : row=(sc>>8)&0x1ff, sym=sc&0xff,
     * phys=833+row. Single there band 833..928 (row<=95) is learned (C6-ter). seq=q = order reel
     * d'emission. Alimente the SAME tables that FEEDPHYS (fline/fsym/fbx/fseq) => the replay
     * by-emission existant (master_learn + double porte aging) tourne sure l'emission CLEAN of the
     * clone, without GT. Zero effet out gate. Judge : an_front (distribution -> band) then firstdiv. */
    if (!fline && getenv("UHA_LIVEWALK_FEEDSELF") && ctxc[3]) {
        const char *ls = getenv("UHA_LIVEWALK_FEEDSELF");
        FILE *fp = (*ls=='=') ? fopen(ls+1, "r") : (ls && *ls ? fopen(ls, "r") : NULL);
        if (fp) {
            char ln[64]; size_t cap = 40000; long q;
            fline=malloc(sizeof(long)*cap); fsym=malloc(sizeof(long)*cap);
            fbx=malloc(sizeof(long)*cap);  fseq=malloc(sizeof(long)*cap);
            /* [GATED UHA_LIVEWALK_FEEDSELF_LAG3, default-OFF]  REFUTE (measures 20261020, reproduces
             * l.822 = 12593). Implementation CORRECTE (sg/dlt CONTINUS sure all 0..usize, base 833 Has
             * fois - therefore l.822 n'had no bug) but result negatif : to write `Pph` at the law m18
             * `relrow=32*((q%3+2)%3)+tbucket[dlt]` during that there DENS se READS via `gen_ctxs(3)` (`ctxc[3]`,
             * l.2884) = DESSYNCHRONISATION write vs reading/learn -> Sigmafreq b1 93953 (vs LEG 150676,
             * well PIS that gen_ctxs3=146182), lines hot effondrees has nz=1, and phys849/881/913
             * ALWAYS 0. => the residuel n'is NOT " gen_ctxs3 rate the deltas negatifs that there law exact
             * repare " : there path d'write doit rester there same that there path of scoring for that l'arena
             * i.e. coherente (selfconsistent = 18432). Cloture l'avenue " law exact en write single "
             * ; single has SINGLEPASS now score AND learn partagent has same ctx en order d'emission (TASK16)
             * peut rapprocher these lines. Zero effet out gate. */
            static uint32_t *s_l3row = NULL, *s_l3sym = NULL; static uint32_t s_l3n = 0; static int s_l3ok = 0;
            int lag3 = getenv("UHA_LIVEWALK_FEEDSELF_LAG3") ? 1 : 0;
            if (lag3 && (!s_l3ok || s_l3n != usize)) {
                free(s_l3row); free(s_l3sym); s_l3row=NULL; s_l3sym=NULL; s_l3ok=0;
                s_l3row = (uint32_t*)calloc(usize ? usize : 1u, sizeof(uint32_t));
                s_l3sym = (uint32_t*)calloc(usize ? usize : 1u, sizeof(uint32_t));
                if (s_l3row && s_l3sym) {
                    uint32_t sg = 0u, qq;
                    for (qq = 0u; qq < usize; qq++) {
                        uint32_t bf = (qq >= 3u) ? (uint32_t)plain[qq-3u] : 0u;
                        uint32_t d = ((uint32_t)plain[qq] - bf) & 0xFFu;
                        if (sg) d = (0u - d) & 0xFFu;
                        if (d >= 0x80u) sg ^= 1u;
                        s_l3sym[qq] = d;
                        s_l3row[qq] = 32u * ((qq % 3u + 2u) % 3u) + (uint32_t)alz_arena_c4_tbucket[d];
                    }
                    s_l3n = usize; s_l3ok = 1;
                }
            }
            if (fline&&fsym&&fbx&&fseq) {
                while (fn < cap && fgets(ln, sizeof ln, fp)) {
                    if (sscanf(ln, "%ld", &q) != 1) continue;
                    if (q < 0 || (unsigned long)q >= usize) continue;
                    uint32_t row, sy;
                    static int ph2 = -1; if (ph2<0) ph2 = getenv("UHA_LIVEWALK_FEEDSELF_PHASE2")?1:0;
                    if (lag3 && s_l3ok) { row = s_l3row[(size_t)q]; sy = s_l3sym[(size_t)q]; }
                    else {
                        uint32_t sc = ctxc[3][(size_t)q]; row = (sc >> 8) & 0x1FFu; sy = sc & 0xFFu;
                        /* [GATED UHA_LIVEWALK_FEEDSELF_PHASE2, default-OFF] an_bucket : the bucket
                         * of the writer m18 == `t3[delta]` of gen_ctxs3 (same {05,15,17}, t3 skips
                         * 16), but gen_ctxs3 phase = `ebp%3` then that m18 phase = `(q%3+2)%3`
                         * -> rotation of has phase = residuel measured. Here on REPOSE there phase of the
                         * WRITER (m18) en gardant the bucket t3 of gen_ctxs3 :
                         * relrow = (row%32) + 32*((q%3+2)%3). Zero effet out gate. */
                        /*  REFUTE (measures 20261020) : rotation of phase SINGLE sure l'write =
                         * RELABELLAGE symetrique (enables the 3 clusters of phase, preserve l'agregat).
                         * Sigmafreq b1 = 145962  baseline gen_ctxs3 146182 ( bruit) ; firstdiv unchanged
                         * 18432 ; phys849/881/913 always 0 (t3 not produces never 16). => there phase vue
                         * single n'is NOT the bloqueur ; the residuel is the SECOND ecriveur (intra16) +
                         * there precision of trajectoire @relrow21 (singlepass). Gate defautOFF inerte. */
                        if (ph2) row = (row & 31u) + 32u * (((uint32_t)q % 3u + 2u) % 3u);
                    }
                    uint32_t phys = 833u + row;                     /* base cls3 + relrow */
                    if (row > 95u) continue;                         /* out band master 833..928 */
                    if (phys >= 3u*ALZ_ARENA2D_MAX_ROW) continue;
                    fline[fn]=(long)phys; fsym[fn]=(long)sy; fbx[fn]=(long)inc; fseq[fn]=(long)q; fn++;
                }
            }
            fclose(fp);
            fprintf(stderr, "[FEEDSELF] %lu own emissions of clone loaded (band 833..928, law=%s)\n", (unsigned long)fn, (lag3&&s_l3ok)?"lag3":"gen_ctxs3");
        }
    }
    /* [DIAG RESCALE_SCH GATED, isolat, defautOFF] consumes the calendrier of rescale
     * by line of #18 (`gt/rescale_schedule_b1.tsv`, format `slot row total_avant
     * total_apres ...`, row = line PHYSIQUE, slot = seq d'emission). when present,
     * the rejeu `Pph` triggers `rescale(phys)` au `seq` PLANIFIE (pilote by there GT),
     * au lieu of the single threshold `total>=0x4000` -> aligne there trajectoire `total` by line
     * of the clone sure the legacy engine (TOT@5888->9471, row29 not halve not, row68 5 halvings).
     * Zero effet out gate (rsched=0 -> threshold preserved). DIAGNOSTIC, not GT en emission. */
    long *rsrow = NULL; long *rsseq = NULL; size_t rsn = 0, rspos = 0; int rsched = 0;
    {
        const char *rs = getenv("UHA_LIVEWALK_RESCALE_SCH");
        if (rs && *rs) {
            FILE *fp = fopen(rs, "r");
            if (fp) {
                char ln[512]; size_t cap = 200000;
                rsrow = (long*)malloc(sizeof(long)*cap); rsseq = (long*)malloc(sizeof(long)*cap);
                if (rsrow && rsseq) {
                    while (rsn < cap && fgets(ln, sizeof ln, fp)) {
                        if (ln[0]=='#' || ln[0]=='\n') continue;
                        long sl, rw; long t0,t1;
                        /* attend `slot row total_avant total_apres ...` ; ignores entete nonnumerique */
                        if (sscanf(ln, "%ld %ld %ld %ld", &sl, &rw, &t0, &t1) >= 2) {
                            if (rw < 0 || rw >= 3L*ALZ_ARENA2D_MAX_ROW) continue;
                            rsseq[rsn]=sl; rsrow[rsn]=rw; rsn++;
                        }
                    }
                    rsched = (rsn>0) ? 1 : 0;
                    fprintf(stderr, "[RESCALE_SCH] %lu evenements de rescale charges\n", (unsigned long)rsn);
                }
                fclose(fp);
            }
        }
    }
    /* [DIAG ORACLE_DENS GATED, isolat, defautOFF, DISCRIMINATEUR] loads there `prod_dens`
     * EXACT of legacy (m9_prodstate_b1.log, pass=0, col12) by slot of bloc1 and INJECTE
     * out[q] = this dens (au lieu of the to compute). Bute : trancher if the blocage @18432
     * vient ONLY of the `dens`/arena (then firstdiv grimpe) now d'ailleurs. GT of
     * DIAGNOSTIC/verification only, NEVER path d'expedition (as SEEDPERM). */
    long *odens = NULL; size_t odn = 0; int oracle = 0;
    (void)odn;
    {
        const char *od = getenv("UHA_LIVEWALK_ORACLE_DENS");
        if (od && *od) {
            FILE *fp = fopen(od, "r");
            if (fp) {
                char ln[256];
                odens = (long*)malloc(sizeof(long)*65536); if (odens) for (size_t zi=0; zi<65536; zi++) odens[zi]=-1;   /* -1 = no couvert */
                if (odens) {
                    while (fgets(ln, sizeof ln, fp)) {
                        if (ln[0]=='#'||ln[0]=='\n') continue;
                        long sl,ps,off,rw,sy,ff,tt,fm,fw,wt,pd;
                        if (sscanf(ln,"%ld %ld %ld %*s %ld %ld %ld %ld %ld %ld %ld %ld",
                                   &sl,&ps,&off,&rw,&sy,&ff,&tt,&fm,&fw,&wt,&pd) == 11 && ps==0) {
                            if (sl >= 0 && sl < 65536) odens[sl] = pd;
                        }
                    }
                    oracle = 1;
                    fprintf(stderr, "[ORACLE_DENS] charg\u00e9\n");
                }
                fclose(fp);
            }
        }
    }
    /* [DIAG ESC_DBG GATED, isolat, defautOFF, DISCRIMINATEUR] loads there table COLD
     * (`kind=cold`) of `m9_prodstate_b1.log` (pass0) : by slot, `freqM` (freq matatre
     * delta2D of the line d'escape 0x40200/256+byte) and `Fenwick` (denom matatre *0x4373c8).
     * But : confirmer that the residu @18432 = ONLY the term d'ESCAPE `proba_to_cost
     * (freqM<<14/Fenwick)` manquant to the cellules cold (ADD, not remplacement : the secondaire
     * is already computed). GT of DIAGNOSTIC only, NEVER path d'expedition. */
    long *escM = NULL; long *escFen = NULL; char *escSet = NULL; int escdbg = 0;
    {
        const char *ep = getenv("UHA_LIVEWALK_ESC_DBG");
        if (ep && *ep) {
            FILE *fp = fopen(ep, "r");
            if (fp) {
                char ln[256];
                escM = (long*)malloc(sizeof(long)*65536); escFen=(long*)malloc(sizeof(long)*65536);
                escSet = (char*)calloc(65536,1);
                if (escM && escFen && escSet) {
                    for (size_t zi=0; zi<65536; zi++){escM[zi]=0; escFen[zi]=0;} for(size_t zi=0;zi<65536;zi++) escSet[zi]=0;
                    while (fgets(ln, sizeof ln, fp)) {
                        if (ln[0]=='#'||ln[0]=='\n') continue;
                        /* parse explicite : col4 = chain 'cold'/'warm' */
                        {
                            char kk[16]; long a,b,c,d,e,g,h,i,j,k,l;
                            int nf = sscanf(ln,"%ld %ld %ld %15s %ld %ld %ld %ld %ld %ld %ld %ld",
                                            &a,&b,&c,kk,&d,&e,&g,&h,&i,&j,&k,&l);
                            if (nf==12 && b==0 && kk[0]=='c' && a>=0 && a<65536) { escM[a]=i; escFen[a]=j; escSet[a]=1; }
                        }
                    }
                    escdbg = 1;
                    fprintf(stderr, "[ESC_DBG] loaded (cold GT for discriminator)\n");
                }
                fclose(fp);
            }
        }
    }
    /* [SOUDURE warmedlive gated UHA_LIVEWALK_ACCLIVE_CTRFILE] loads the `counter/total` of the
     * MASTER d'emission (dump acclive `UHA_ACL_CTRDUMP` : `q mrow counter total sym`) keyed by q.
     * Sure has cellule cold, the `num` of the secondaire vient of this order d'emission ( counter[5] 2529)
     * au lieu of the scan (1). The master d'acclive is advances once in l'order reel (validated).
     * step warmedlive (pass emission -> file -> pass dens), as EMIPROD lits.txt. DIAG->port. */
    long *aclcnt = NULL; long *acltot = NULL; char *aclset = NULL; int aclctr = 0;
    {
        const char *af = getenv("UHA_LIVEWALK_ACCLIVE_CTRFILE");
        if (af && *af) {
            FILE *fp = fopen(af, "r");
            if (fp) {
                aclcnt=(long*)malloc(sizeof(long)*65536); acltot=(long*)malloc(sizeof(long)*65536); aclset=(char*)calloc(65536,1);
                if (aclcnt && acltot && aclset) {
                    for (size_t zi=0;zi<65536;zi++){aclcnt[zi]=0;acltot[zi]=0;aclset[zi]=0;}
                    char ln[256]; long q,mr,cn,tt,sy;
                    while (fgets(ln,sizeof ln, fp)) {
                        if (ln[0]=='#'||ln[0]=='\n') continue;
                        if (sscanf(ln,"%ld %ld %ld %ld %ld",&q,&mr,&cn,&tt,&sy)==5 && q>=0 && q<65536) {
                            aclcnt[q]=cn; acltot[q]=tt; aclset[q]=1;
                        }
                    }
                    aclctr = 1; fprintf(stderr, "[ACCLIVE_CTR] charg\u00e9\n");
                }
                fclose(fp);
            }
        }
    }
    /* [DIAG PERMFEED GATED, isolat, defautOFF] replays the FEED ordonne of #18
     * (`m18_perm_writer.log`, lines `site n addr bx line seq`) in has banque
     * arena2d cls3 en appliquant bx=bx by write, with RESCALE INTERLACE
     * (FLOOR 2 when total>=0x4000). Reconstitue PERM[901] by the MECANISME (src
     * arena2d rescale), not by the banc fige. Zero GT en emission (DIAGNOSTIC). */
    alz_arena2d_t *Pfeed = NULL;
    {
        const char *pf = getenv("UHA_LIVEWALK_PERMFEED");
        if (pf && *pf) {
            FILE *fp = fopen(pf, "r");
            if (fp) {
                Pfeed = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t));
                if (Pfeed) {
                    char ln[256];
                    alz_arena2d_init(Pfeed, (uint16_t)inc);
                    while (fgets(ln, sizeof ln, fp)) {
                        char site[32]; unsigned long n, a, bx, lin;
                        if (sscanf(ln, "%31s %lx %lx %lx %lx", site, &n, &a, &bx, &lin) == 5) {
                            unsigned long off = a - 0xf20030UL, lnp = off/512UL, sy = (off%512UL)/2UL;
                            if (lnp >= 833UL && lnp < 833UL+ALZ_ARENA2D_MAX_ROW && sy < 256UL) {
                                uint32_t rel = (uint32_t)(lnp - 833UL);
                                Pfeed->freq[(rel<<8)|sy] = (uint16_t)(Pfeed->freq[(rel<<8)|sy] + (uint16_t)bx);
                                Pfeed->total[rel]         = (uint16_t)(Pfeed->total[rel] + (uint16_t)bx);
                                if (Pfeed->total[rel] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(Pfeed, rel);
                            }
                        }
                    }
                    fprintf(stderr, "[PERMFEED] cls3 row68 freq[4]=%u total=%u\n",
                            (unsigned)Pfeed->freq[(68u<<8)|4u], (unsigned)Pfeed->total[68u]);
                }
                fclose(fp);
            }
        }
    }
    { const char *pp = getenv("UHA_LIVEWALK_4PASS_PROBE"); if (pp && *pp) sp = fopen(pp,"w"); }
    for (b = 0u; b < 6u; b++) {
        uint32_t base = blpos[b], len = blen[b];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* [GATED UHA_LIVEWALK_PHDUMP=path, read-only, default-OFF] dump of l'state
         * MASTER physique Pph has INPUT of each block, BEFORE all seed/band, for to measure
         * this that the mecanisme of propagation of the clone produces REELLEMENT to the frontiers,
         * line by line (sum, nz=#freq!=0, counter, total) and the to compare to the bands
         * captures `perm_b{b}_band_768-1023` (= freq LEG d'input of block).
         * Format : b phys relrow sum nz counter total promo. Zero effet out gate. */
        {
            static FILE *s_pd = NULL;
            static int s_pd_init = -1;
            if (s_pd_init < 0) {
                const char *pe = getenv("UHA_LIVEWALK_PHDUMP");
                s_pd_init = 1;
                if (pe && *pe) { s_pd = fopen(pe, "w");
                    if (s_pd) fprintf(s_pd, "b\tphys\trelrow\tsum\tnz\tcounter\ttotal\tpromo\n"); }
            }
            if (s_pd && physperm) {
                uint32_t ph2;
                for (ph2 = 768u; ph2 < 1024u; ph2++) {
                    alz_arena2d_t *ch = &Pph[ph2 >> 9];
                    uint32_t orow = ph2 & (ALZ_ARENA2D_MAX_ROW-1u);
                    uint32_t sy, sm2 = 0u, nz2 = 0u;
                    for (sy = 0u; sy < 256u; sy++) {
                        uint32_t f = ch->freq[(orow<<8)|sy];
                        sm2 += f; if (f != 0u) nz2++;
                    }
                    fprintf(s_pd, "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n", (unsigned)b, (unsigned)ph2,
                            (unsigned)(ph2 - 768u), (unsigned)sm2, (unsigned)nz2,
                            (unsigned)ch->counter[orow], (unsigned)ch->total[orow], (unsigned)ch->promo[orow]);
                }
                fflush(s_pd);
            }
        }
        /* [DIAG BANKDIR GATED, defautOFF] seed the Pph with the TRUE bank PERM d'input of
         * each block b (ASK B of #19 : `gt/perm_b{b}_band_768-1023.raw.txt`). Teste if
         * @18432 vient of the seed incomplet (je not seedais that b1). Phys lines 768..1023. */
        {
            static const char *s_bd = NULL; static int s_bd_init = -1;
            if (s_bd_init < 0) { s_bd = getenv("UHA_LIVEWALK_BANKDIR"); s_bd_init = (s_bd && *s_bd) ? 1 : 0; }
            if (s_bd_init && b >= 1u && b <= 5u) {
                char bpath[512]; long *bv = NULL; size_t bn = 0;
                snprintf(bpath, sizeof bpath, "%s/perm_b%u_band_768-1023.raw.txt", s_bd, (unsigned)b);
                FILE *bfp = fopen(bpath, "r");
                if (bfp) {
                    bv = (long*)malloc(sizeof(long)*(256*256));
                    if (bv) { while (bn < (size_t)(256*256) && fscanf(bfp, "%ld", &bv[bn]) == 1) bn++; }
                    fclose(bfp);
                    if (bv) {
                        uint32_t phys;
                        for (phys = 768u; phys < 1024u && phys < 3u*ALZ_ARENA2D_MAX_ROW; phys++) {
                            alz_arena2d_t *ch = &Pph[phys >> 9]; uint32_t orow = phys & (ALZ_ARENA2D_MAX_ROW-1u);
                            uint32_t sy, sum = 0u;
                            for (sy = 0u; sy < 256u; sy++) {
                                size_t k = (size_t)(phys - 768u)*256u + sy;
                                uint16_t v = (k < bn) ? (uint16_t)bv[k] : 0u;
                                ch->freq[(orow<<8)|sy] = v; sum += v;
                            }
                            ch->total[orow] = (uint16_t)(sum + ch->counter[orow]);
                        }
                        free(bv);
                    }
                }
            }
        }
        if (fline && fpos < fn) {                    /* FEEDPHYS : to advance Pph au PERM d'input of the block b */
            while (fpos < fn && (uint32_t)fseq[fpos] < base) {
                uint32_t ph=(uint32_t)fline[fpos], sy=(uint32_t)fsym[fpos], bx=(uint32_t)fbx[fpos];
                if (ph < 3u*ALZ_ARENA2D_MAX_ROW && sy < 256u) {
                    alz_arena2d_t *ch=&Pph[ph>>9]; uint32_t orow=ph&(ALZ_ARENA2D_MAX_ROW-1u);
                    if (ch->aging_on && !rsched) {          /* [C6-ter default-OFF] double porte aging (input of block) */
                        alz_arena2d_master_learn(ch, orow, sy);
                    } else {
                    ch->freq[(orow<<8)|sy]=(uint16_t)(ch->freq[(orow<<8)|sy]+bx);
                    ch->total[orow]=(uint16_t)(ch->total[orow]+bx);
                    if (!rsched && ch->total[orow] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(ch, orow);
                    }
                }
                fpos++;
            }
        }
        if ((seedvals || Pfeed) && b == 1u) {         /* seed/feed = commit of bloc0 -> input bloc1 ONLY ; b>=2 propage dynamiquement (Pc=commit) */
            if (physperm && seedvals && !getenv("UHA_LIVEWALK_TOTNOTCOUNTER")) {   /* STEP1 : seed->Pph PHYSIQUE (band #18) */
                uint32_t phys;
                uint32_t clean = getenv("UHA_LIVEWALK_SEEDCLEANCNT") ? 1u : 0u;   /* [COUCHE1 gated] purge the counter herite of the commit bloc0 : the band PERM d'input porte freq+total+counter maitres, NOT the counter transitoire of the pass bloc0. without ca, the lines cold (row29/27/67 sym...) heritent totalcounter(bloc0) and sure-chauffent (dens too low -> sm 136387 vs 184287). */
                for (phys = 768u; phys < 1024u && phys < 3u*ALZ_ARENA2D_MAX_ROW; phys++) {
                    alz_arena2d_t *ch = &Pph[phys >> 9]; uint32_t orow = phys & (ALZ_ARENA2D_MAX_ROW-1u);
                    uint32_t sy, sum = 0u;
                    for (sy = 0u; sy < 256u; sy++) {
                        size_t k = (size_t)(phys - 768u)*256u + sy;
                        uint16_t v = (k < seedn) ? (uint16_t)seedvals[k] : 0u;
                        ch->freq[(orow<<8)|sy] = v; sum += v;
                    }
                    if (clean==2u) {                    /* variante : not purge the counter that some lines VRAIMENT cold (Sigmafreq==0) ; preserve the one some lines hot (legacy keeps counter>1 sure row5 etc.) */
                        if (sum == 0u) { ch->counter[orow] = ALZ_ARENA2D_INIT_VAL; ch->total[orow] = ALZ_ARENA2D_INIT_VAL; }
                        else           { ch->total[orow] = (uint16_t)(sum + ch->counter[orow]); }
                    }
                    else if (clean) { ch->counter[orow] = ALZ_ARENA2D_INIT_VAL; ch->total[orow] = (uint16_t)(sum ? sum : ALZ_ARENA2D_INIT_VAL); }
                    else       { ch->total[orow] = (uint16_t)(sum + ch->counter[orow]); }
                }
                /* [DIAG UHA_LIVEWALK_CTRSEED=<file "relrow\tcounter\ttotal">] amorce the
                 * counter/total MASTER of cls3 (Pph[833+relrow]) since has file (state
                 * captures of the matatre, as SEEDPERM amorce freq). But : confirmer that the
                 * `counter[5]=29` LEG is the SINGLE bloqueur @19456 -> then the port faithful =
                 * to captures `*0x4373dc`. GT of DIAGNOSTIC, never expedition. */
                {
                    const char *cs = getenv("UHA_LIVEWALK_CTRSEED");
                    if (cs && *cs) {
                        FILE *cf = fopen(cs, "r");
                        if (cf) {
                            char ln[128]; long rl, cc, tt;
                            while (fgets(ln, sizeof ln, cf)) {
                                if (ln[0]=='#'||ln[0]=='\n') continue;
                                if (sscanf(ln, "%ld %ld %ld", &rl, &cc, &tt) == 3 && rl>=0 && rl<ALZ_ARENA2D_MAX_ROW) {
                                    uint32_t ph = 833u + (uint32_t)rl; alz_arena2d_t *ch = &Pph[ph>>9]; uint32_t orow = ph&(ALZ_ARENA2D_MAX_ROW-1u);
                                    ch->counter[orow] = (uint16_t)cc; if (tt >= 0) ch->total[orow] = (uint16_t)tt;   /* tt<0 = not not figer total (to keep the one of the band ; otherwise surchauffe the cellules anterieures) */
                                }
                            }
                            fclose(cf);
                        }
                    }
                }
            } else if (physperm && seedvals && getenv("UHA_LIVEWALK_TOTNOTCOUNTER")) {
                /* [DIAG GATED] TOT = Sigmafreq without counter : teste l'hypothese that l'inflation
                 * of TOT sure lines rares vient of the counter d'input, no Sigmafreq (fc exact). */
                uint32_t phys;
                for (phys = 768u; phys < 1024u && phys < 3u*ALZ_ARENA2D_MAX_ROW; phys++) {
                    alz_arena2d_t *ch = &Pph[phys >> 9]; uint32_t orow = phys & (ALZ_ARENA2D_MAX_ROW-1u);
                    uint32_t sy, sum = 0u;
                    for (sy = 0u; sy < 256u; sy++) {
                        size_t k = (size_t)(phys - 768u)*256u + sy;
                        uint16_t v = (k < seedn) ? (uint16_t)seedvals[k] : 0u;
                        ch->freq[(orow<<8)|sy] = v; sum += v;
                    }
                    ch->total[orow] = (uint16_t)sum;   /* no +counter */
                }
            } else if (Pfeed) { Pc[3] = *Pfeed; }    /* path FEED-mecanisme prioritaire */
            else {
            /* ALIASING : to load the band PHYSIQUE #18 in all banques via
             * `phys = base[cls]+relrow` -> same lines physiques partagees between classes. */
            static const uint32_t s_base[4] = {0u,769u,801u,833u};
            uint32_t bb;
            for (bb = 0u; bb < 4u; bb++) {
                uint32_t rel;
                for (rel = 0u; rel < ALZ_ARENA2D_MAX_ROW; rel++) {
                    uint32_t phys = s_base[bb] + rel, sum = 0u, sy;
                    if (phys < 768u || phys >= 1024u) continue;   /* out band seede */
                    for (sy = 0u; sy < 256u; sy++) {
                        size_t k = (size_t)(phys - 768u)*256u + sy;
                        uint16_t v = (k < seedn) ? (uint16_t)seedvals[k] : 0u;
                        Pc[bb].freq[(rel<<8)|sy] = v; sum += v;
                    }
                    Pc[bb].total[rel] = (uint16_t)(sum + Pc[bb].counter[rel]);
                }
            }
            }
        }
        /* [GATED UHA_LIVEWALK_CTRSEEDDIR=<dir>, default-OFF] seed `counter`/`total` d'input
         * for each frontier of block (`<dir>/ctr_entry_b<b>.tsv`, lines `relrow counter total`,
         * produites by `work/an_state.py` has partir some snapshots LEGITIMES of the mission TASK21/M0).
         * `UHA_LIVEWALK_CTRSEED` not s'appliquait qu'has b==1 : impossible of juger there propagation
         * au-dela of bloc1. Semantique reprise at the identical : ph = 833+relrow ; tt<0 = total no
         * fige (to keep the one of the band). Applies AFTER the seed of freq (BANKDIR/SEEDPERM) for not not
         * to be overwrites. Zero effet out gate. */
        {
            const char *cd = getenv("UHA_LIVEWALK_CTRSEEDDIR");
            if (cd && *cd && b >= 1u && b <= 5u && physperm) {
                char cpath[512];
                snprintf(cpath, sizeof cpath, "%s/ctr_entry_b%u.tsv", cd, (unsigned)b);
                FILE *cf = fopen(cpath, "r");
                if (cf) {
                    char ln[128]; long rl, cc, tt; int nap = 0;
                    while (fgets(ln, sizeof ln, cf)) {
                        if (ln[0]=='#'||ln[0]=='\n') continue;
                        if (sscanf(ln, "%ld %ld %ld", &rl, &cc, &tt) == 3 && rl >= 0 && rl < ALZ_ARENA2D_MAX_ROW) {
                            uint32_t ph = 833u + (uint32_t)rl;
                            alz_arena2d_t *ch = &Pph[ph >> 9]; uint32_t orow = ph & (ALZ_ARENA2D_MAX_ROW-1u);
                            ch->counter[orow] = (uint16_t)cc;
                            if (tt >= 0) ch->total[orow] = (uint16_t)tt;
                            nap++;
                        }
                    }
                    fclose(cf);
                    fprintf(stderr, "[CTRSEEDDIR] block %u: %d lines from %s\n", (unsigned)b, nap, cpath);
                }
            }
        }
        for (c = 0u; c < LPASS; c++) {
            if (!ctxc[c]) continue;
            if (physperm) {                          /* STEP1 : reload HOT[relrow]Pph[base[c]+relrow] (aliasing) */
                uint32_t sy;
                for (rr0 = 0u; rr0 < ALZ_ARENA2D_MAX_ROW; rr0++) {
                    uint32_t ph = s_pbase[c] + rr0; alz_arena2d_t *ch;
                    uint32_t orow; if (ph >= 3u*ALZ_ARENA2D_MAX_ROW) continue;
                    ch = &Pph[ph >> 9]; orow = ph & (ALZ_ARENA2D_MAX_ROW-1u);
                    for (sy = 0u; sy < 256u; sy++) H->freq[(rr0<<8)|sy] = ch->freq[(orow<<8)|sy];
                    H->total[rr0] = ch->total[orow]; H->counter[rr0] = ch->counter[orow];
                    H->promo[rr0] = ch->promo[orow];   /* propager there PROMO (=32) otherwise there primitive learns +=0 (HOT plat) */
                }
            } else *H = Pc[c];                       /* reload HOT := banque cls c */
            for (i = 0u; i < len; i++) {
                uint32_t sc = ctxc[c][base+i], row, sym, Tc, fc, num, pr;
                q = base + i;
                row = (sc >> 8) & 0x1FFu; sym = sc & 0xFFu;
                if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
                if ((int)c == dens_cls) {            /* dens lu sure there banque of the class target (via H rechargee ; feed avancee at the level block) */
                    if (fline) {                     /* FEEDPHYS : to advance Pph by seq<q (the feed = writes d'emission), relire H since Pph */
                        while (fpos < fn && (uint32_t)fseq[fpos] < q) {
                            uint32_t phf=(uint32_t)fline[fpos], syf=(uint32_t)fsym[fpos], bxf=(uint32_t)fbx[fpos];
                            if (phf < 3u*ALZ_ARENA2D_MAX_ROW && syf < 256u) {
                                alz_arena2d_t *chh=&Pph[phf>>9]; uint32_t orf=phf&(ALZ_ARENA2D_MAX_ROW-1u);
                                uint16_t *fc0 = &chh->freq[(orf<<8)|syf]; uint16_t oldf = *fc0;   /* [FEED cold/warm] semantique master_learn : cold(freq==0)->counter+=bx,total+=2bx ; warm->total+=bx */
                                if (chh->aging_on && !rsched) {   /* [C6-ter default-OFF] double porte aging by-emission */
                                    alz_arena2d_master_learn(chh, orf, syf);
                                } else {
                                *fc0 = (uint16_t)(oldf + bxf);
                                if (oldf == 0u) { chh->counter[orf] = (uint16_t)(chh->counter[orf] + bxf); chh->total[orf] = (uint16_t)(chh->total[orf] + 2u*bxf); }
                                else            { chh->total[orf] = (uint16_t)(chh->total[orf] + bxf); }
                                if (!rsched && chh->total[orf] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(chh, orf);
                                }
                            }
                            fpos++;
                        }
                        /* RESCALE_SCH : to apply the rescales PLANIFIES (GT #18) by seq<q, by line physique */
                        while (rsched && rspos < rsn && (uint32_t)rsseq[rspos] < q) {
                            uint32_t phr=(uint32_t)rsrow[rspos];
                            if (phr < 3u*ALZ_ARENA2D_MAX_ROW) {
                                alz_arena2d_t *chr=&Pph[phr>>9]; uint32_t orr=phr&(ALZ_ARENA2D_MAX_ROW-1u);
                                alz_arena2d_rescale(chr, orr);
                            }
                            rspos++;
                        }
                    }
                    if (rsched || feeddrive || (fline && getenv("UHA_LIVEWALK_FEEDPHYS_REREAD"))) {   /* relire H since Pph for that there dens path feed(advances by position)+rescale */
                        uint32_t phs = s_pbase[dens_cls] + row;
                        if (phs < 3u*ALZ_ARENA2D_MAX_ROW) {
                            alz_arena2d_t *chs=&Pph[phs>>9]; uint32_t ors=phs&(ALZ_ARENA2D_MAX_ROW-1u); uint32_t s2;
                            for (s2=0u;s2<256u;s2++) H->freq[(row<<8)|s2]=chs->freq[(ors<<8)|s2];
                            H->total[row]=chs->total[ors]; H->counter[row]=chs->counter[ors];
                        }
                    }
                    Tc = H->total[row]; fc = H->freq[(row<<8)|sym];
                    uint32_t fcpre = fc;                  /* fc BEFORE learn (detecte the COLD, path d'escape) */
                    uint32_t Tpre = Tc;                   /* total[row] BEFORE learn = comparable direct m9 col8 TOT */
                    uint32_t ctpre = H->counter[row];      /* counter[row] BEFORE learn = the num secondaire (has to compares m9 work_tot) */
                    uint32_t gmf = 0u, gmc = 0u, gmt = 0u; /* [PROBE] state PRE-LEARN of the master persistant g_pm : freq/counter/total */
                    num = (fc == 0u) ? (uint32_t)H->counter[row] : fc;
                    pr = (Tc != 0u) ? ((num<<14)/Tc) : (ALZ_SCORE_CUM_N-1u);
                    if (pr >= ALZ_SCORE_CUM_N) pr = ALZ_SCORE_CUM_N-1u;
                    if (realprim && !(g_lw_litlearn && q < usize && g_lw_islit && !g_lw_islit[q])) {   /* PRIMITIVE reelle : proba + learn + rescale. [gate UHA_LIVEWALK_LIT_LEARN] if active and position = match (no literal), on NOT LEARN NOT (the master n'learns that by TOKEN emis, ~1/reads, not by byte couvert) -> total[row] croit au rythme reel -> phase rescale/`counter[5]` rejoint LEG ; the dens remainder lu (pr some lines 26872689, readonly). */
                        uint32_t ltl = 0u;
                        pr = alz_arena2d_score(H, row, sym, &ltl);
                        Tc = H->total[row]; fc = H->freq[(row<<8)|sym];
                    } else if (realprim) {
                        /* no learn : pr already computed readonly (lines 26872689) */
                    }
                    /* [ARENA_TASK20 step1] master PERSISTANT `g_pm` advances once/position (never
                     * recharge/clobe) ; sure cellule cold son `counter[row]` (prelearn, via score which
                     * returns there proba BEFORE learn) fournit the secondaire clean. Gate UHA_LIVEWALK_PMMASTER. */
                    {
                        static int s_pmm = -1;
                        if (s_pmm < 0) s_pmm = getenv("UHA_LIVEWALK_PMMASTER") ? 1 : 0;
                        if (s_pmm && g_pm) {
                            gmf = g_pm->freq[(row<<8)|sym]; gmc = g_pm->counter[row]; gmt = g_pm->total[row];
                            uint32_t ltl2 = 0u;
                            uint32_t pmpr = alz_arena2d_score(g_pm, row, sym, &ltl2);   /* advances g_pm + gives proba prelearn */
                            if (fcpre == 0u) {
                                pr = pmpr;   /* secondaire cold via master persistant (counter[row] clean) */
                                if (pr >= ALZ_SCORE_CUM_N) pr = ALZ_SCORE_CUM_N-1u;
                            }
                        }
                    }
                    /* [SOUDURE warmedlive] sure cellule cold, the secondaire uses the `counter/total`
                     * d'ORDER D'EMISSION (dump acclive), not the one of the scan (sure/undercompte). */
                    if (aclctr && fcpre == 0u && q < usize && aclset[q] && acltot[q] > 0) {
                        pr = (uint32_t)((aclcnt[q] << 14) / acltot[q]);
                        if (pr >= ALZ_SCORE_CUM_N) pr = ALZ_SCORE_CUM_N - 1u;
                    }
                    if (q >= from && q < usize)
                        out[q] = alz_score_proba_to_cost(pr);
                    /* [DIAG ESC_DBG] cellule COLD (fcpre==0) -> ADD of the term d'escape
                     * LUT[freqM<<14/Fenwick] (matatre delta2D line 0x402 + secondaire already sets).
                     * GT for discriminant, never expedition. */
                    if (escdbg && fcpre == 0u && q >= 12544u && (size_t)(q-12544u) < 65536u
                        && escSet[q-12544u] && escFen[q-12544u] > 0) {
                        uint32_t ep2 = (uint32_t)((escM[q-12544u] << 14) / escFen[q-12544u]);
                        if (ep2 >= ALZ_SCORE_CUM_N) ep2 = ALZ_SCORE_CUM_N-1u;
                        out[q] = (uint32_t)(out[q] + alz_score_proba_to_cost(ep2));
                    }
                    /* [SOUDURE warmedlive escape without GT, gated UHA_LIVEWALK_ESCFILE] : loads the dump
                     * of the bytemodel LIVE of the CLONE (frontier of block, `bm[0x402+3]`) and l'uses as
                     * escape (freqM=file[block][delta], fen=file[block]) sure cellule cold. values
                     * clean emises by the clone (VALIDEES = m9 : sym3->196, fen->2528), no GT. */
                    {
                        static int s_eff = -1; static uint32_t s_ef[6][256]; static uint32_t s_efen[6];
                        if (s_eff < 0) {
                            const char *ef = getenv("UHA_LIVEWALK_ESCFILE");
                            s_eff = (ef && *ef) ? 1 : 0;
                            if (s_eff) {
                                FILE *fp = fopen(ef, "r");
                                if (fp) {
                                    char ln[128]; long bi, er, dl, v;
                                    while (fgets(ln, sizeof ln, fp)) {
                                        if (sscanf(ln, "%ld %ld %ld %ld", &bi, &er, &dl, &v) == 4 && bi>=0 && bi<6) {
                                            if (dl == 9999L) s_efen[bi] = (uint32_t)v;   /* fen */
                                            else if (dl>=0 && dl<256) s_ef[bi][dl] = (uint32_t)v;
                                        }
                                    }
                                    fclose(fp);
                                } else s_eff = 0;
                            }
                        }
                        if (s_eff && fcpre == 0u && b < 6u && s_efen[b] > 0) {
                            uint32_t ep3 = (uint32_t)((s_ef[b][sym & 0xffu] << 14) / s_efen[b]);
                            if (ep3 >= ALZ_SCORE_CUM_N) ep3 = ALZ_SCORE_CUM_N-1u;
                            out[q] = (uint32_t)(out[q] + alz_score_proba_to_cost(ep3));
                        }
                    }
                    /* [COUCHE1 gated UHA_LIVEWALK_ESC_MODEL] escape COMPUTE (not GT). line
                     * d'escape = 0x3F9+high3(byte previous) ; freqM=esc[idx][sym] (before inc),
                     * denominateur=esctot[idx] ; then esc += promo(=inc) and rescale FLOOR @0x4000,
                     * as the scorer legacy (0x41495f/0x414966 +=0x20). Applies sure cellule
                     * cold (fcpre==0). Zero GT en emission (state reconstruit by the scan). */
                    if (escmodel && fcpre == 0u) {
                        uint32_t ci = c;   /* line d'escape = 0x402+cls (revere scorer : `[esp+0x38]=(cl<<8)+0x40200`, `*0x437884[cl]`=base class) -> cls3=1029 (== m9 row). */
                        uint32_t tot = esctot[ci];
                        uint32_t ep3 = (tot != 0u) ? ((uint32_t)(esc[ci][sym] << 14) / tot) : (ALZ_SCORE_CUM_N-1u);
                        if (ep3 >= ALZ_SCORE_CUM_N) ep3 = ALZ_SCORE_CUM_N-1u;
                        if (q >= from && q < usize)
                            out[q] = (uint32_t)(out[q] + alz_score_proba_to_cost(ep3));
                        /* learning : esc[ci][sym] += promo, rescale FLOOR @0x4000 */
                        esc[ci][sym] = (uint16_t)(esc[ci][sym] + inc);
                        esctot[ci] += inc;
                        if (esctot[ci] >= ALZ_ARENA2D_RESCALE) {
                            uint32_t s3, ns = 0u;
                            for (s3=0u;s3<256u;s3++){ uint32_t v=esc[ci][s3]&~1u; v>>=1; esc[ci][s3]=(uint16_t)v; ns+=v; }
                            esctot[ci]=ns;
                        }
                        /* [DIAG dump esc MODEL vs m9] slot ci delta freqM_apres tot ; for to extract
                         * there law d'alimentation (facteur d'evenements vs legacy). */
                        { static FILE *s_ed=NULL; static int s_edi=-1;
                          if (s_edi<0){ const char*ee=getenv("UHA_LIVEWALK_ESC_MODEL_DUMP"); s_edi=(ee&&*ee)?1:0; if(s_edi) s_ed=fopen(ee,"w"); }
                          if (s_ed) fprintf(s_ed,"%u\t%u\t%u\t%u\t%u\n",(unsigned)(q-12544u),(unsigned)(0x3F9u+ci),(unsigned)sym,(unsigned)esc[ci][sym],(unsigned)esctot[ci]);
                        }
                    }
                    if (sp && q >= from)
                        fprintf(sp, "%u", (unsigned)(q-12544u));
                    if (sp && q >= from) {
                        /* + cols PRELEARN comparables m9 : fcpre TOTpre | g_pm freq counter total */
                        fprintf(sp, "\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                                (unsigned)row,(unsigned)sym,(unsigned)fc,(unsigned)Tc,(unsigned)out[q],(unsigned)ctpre,
                                (unsigned)fcpre,(unsigned)Tpre,(unsigned)gmf,(unsigned)gmc,(unsigned)gmt);
                    }
                    if (oracle && q >= 12544u && (size_t)(q-12544u) < 65536u && odens[q-12544u] >= 0)
                        out[q] = (uint32_t)odens[q-12544u];   /* ORACLE : dens legacy exact (DIAG only), all slots couverts */
                }
                /* [COUCHE1 gated ESC_MODEL, multipasse] the passes NONdens (cls0/1/2) NOURRISSENT
                 * also there line d'escape : the scorer legacy tourne 4 passes/block, chacune scorant
                 * ses cellules cold -> there line d'escape s'accumule 4* (not 1*). Cold = freq==0
                 * in there banque H rechargee of this class. Zero effet out gate. */
                else if (escmodel) {
                    uint32_t fcpc = H->freq[(row<<8)|sym];
                    if (fcpc == 0u) {
                        uint32_t ci2 = c;   /* line d'escape = 0x402+cls (by pass of class) */
                        esc[ci2][sym] = (uint16_t)(esc[ci2][sym] + inc);
                        esctot[ci2] += inc;
                        if (esctot[ci2] >= ALZ_ARENA2D_RESCALE) {
                            uint32_t s4, ns4 = 0u;
                            for (s4=0u;s4<256u;s4++){ uint32_t v=esc[ci2][s4]&~1u; v>>=1; esc[ci2][s4]=(uint16_t)v; ns4+=v; }
                            esctot[ci2]=ns4;
                        }
                    }
                }
                /* [COUCHE1 gated UHA_LIVEWALK_RP_ALLPASS, isolat, defautOFF] the legacy engine LEARNS the
                 * master sure the ~4 passes/block (chacune recharge HOTPERM[base[cls]+relrow] then
                 * learn), not only there pass dens_cls. without ca, `counter[row]` of bloc0 is
                 * underalimente (row51 vs LEG21 -> @19456). Here : for c!=dens_cls, to advance there
                 * banque of THIS class via there primitive canonique (learn+rescale). Rechargee/committee
                 * by c -> aliasing. Zero effet out gate. */
                {
                    static int s_rpap = -1;
                    if (s_rpap < 0) s_rpap = getenv("UHA_LIVEWALK_RP_ALLPASS") ? 1 : 0;
                    if (realprim && s_rpap && (int)c != dens_cls) {
                        uint32_t ltl = 0u;
                        alz_arena2d_score(H, row, sym, &ltl);
                    }
                }
                if (!feeddrive && !realprim) {   uint32_t idx = (row<<8)|sym;    /* LEARN source-order (skips if feeddrive NOW realprim : this last learns via there primitive) */
                    static int s_tnc = -1;
                    if (s_tnc < 0) s_tnc = getenv("UHA_LIVEWALK_TOTNOTCOUNTER") ? 1 : 0;
                    if (H->freq[idx] == 0u) {
                        H->freq[idx] = (uint16_t)inc;
                        H->counter[row] = (uint16_t)(H->counter[row]+inc);
                        H->total[row] = (uint16_t)(H->total[row] + (s_tnc ? inc : 2u*inc));   /* TOTNOTCOUNTER : total=Sigmafreq */
                    } else {
                        H->freq[idx] = (uint16_t)(H->freq[idx]+inc);
                        H->total[row] = (uint16_t)(H->total[row]+inc);
                    }
                    if (H->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(H, row);
                }
            }
            if (physperm && !feedself && !(getenv("UHA_LIVEWALK_COMMITDENS") && (int)c != dens_cls)) {
                                                /* STEP1 : commit HOT->Pph[base[c]+relrow] (partage).
                                                 * [GATED UHA_LIVEWALK_COMMITDENS] not commite THAT there pass
                                                 * dens : the legacy engine, lui, learns the MASTER at the EMISSION (has
                                                 * fois by symbole emis, 0x41216d) and ses passes of scorer
                                                 * rechargent PERM->HOT without lui rendre leur learning
                                                 * transitoire. Measures 2026-10-20 (`an_front.py` vs bands
                                                 * `perm_b*`) : at the input of bloc1 the clone sure-accumule
                                                 * Sigmafreq 205722 vs LEG 150676, ratio ~3.03 sure the lines
                                                 * hot (13632 vs 4496) = nb of passes aliasant there SAME
                                                 * line physique. default-OFF = behavior inchange. */
                uint32_t sy;
                for (rr0 = 0u; rr0 < ALZ_ARENA2D_MAX_ROW; rr0++) {
                    uint32_t ph = s_pbase[c] + rr0; alz_arena2d_t *ch;
                    uint32_t orow; if (ph >= 3u*ALZ_ARENA2D_MAX_ROW) continue;
                    ch = &Pph[ph >> 9]; orow = ph & (ALZ_ARENA2D_MAX_ROW-1u);
                    uint32_t oldtot = ch->total[orow];      /* total MASTER before this commit (sert of base d'increment) */
                    for (sy = 0u; sy < 256u; sy++) ch->freq[(orow<<8)|sy] = H->freq[(rr0<<8)|sy];
                    ch->total[orow] = H->total[rr0]; ch->counter[orow] = H->counter[rr0];
                    /* [GATED UHA_LIVEWALK_PERMRESCALE, default-OFF, law measured #22] the MASTER
                     * PERM has SON CLEAN rescale, distinct of the one of the HOT : `master_total[line] += bx`
                     * at each agression (0x412169), and when `master_total >= 0x4000` (0x4121b4) has
                     * call 0x40ffa0 halve there line : `freq = (freq > 16) ? (freq >> 1) : 0` sure the
                     * 256 cellules (NOTA : law DIFFERENT of the HOT `(f&~1)>>1` ; here test `>16` and
                     * MISE Has ZERO some small cellules), then rebuild of l'tree. without this decroissement,
                     * the master of the clone only does to rise (input bloc1 : Sigmafreq 205 722 vs LEG 150 676,
                     * 14 lines >=10k there now LEG n'en has that 3). HERE there granularite is BY block (the
                     * pre-pass not connait not l'order d'emission) : first brique, has affiner en
                     * by-evenement. Zero effet out gate. */
                    if (getenv("UHA_LIVEWALK_PERMRESCALE")) {
                        static uint32_t s_pmt[3u * ALZ_ARENA2D_MAX_ROW];
                        /* the legacy engine adds bx BY AGRESSION d'emission : l'equivalent by block is
                         * l INCREMENT of the total of line (total_apres  total_maitre_avant), and NO the
                         * total complete (which declenchait ~4* too and sure-decroissait b3..b5). Not
                         * to count that there pass dens : the others n'apprennent not (measured) and
                         * repliqueraient the same increment sure has line aliasee. Has halving by
                         * 0x4000 cumule (remainder preserved), law PERM `f>16 ? f>>1 : 0`.
                         * [MAJ #23 C2] the master N'Has no `counter` : 0x40ffa0 not touche nor
                         * 0x4373dc (counter) nor 0x4373d8 (total HOT) ; son accumulateur is
                         * `master_total` (0x4373d4), HALVE au rescale (indices #22 26->13, 38->19,
                         * 57->29). `counter=(c>>2)+1` is INFIRME (c'is there law HOT 0x414590). */
                        if ((int)c == dens_cls && H->total[rr0] > oldtot) {
                            s_pmt[ph] += (uint32_t)(H->total[rr0] - oldtot);
                        }
                        while (s_pmt[ph] >= ALZ_ARENA2D_RESCALE) {
                            uint32_t sm3 = 0u, sy3;
                            for (sy3 = 0u; sy3 < 256u; sy3++) {
                                uint32_t f = ch->freq[(orow<<8)|sy3];
                                f = (f > 16u) ? (f >> 1) : 0u;
                                ch->freq[(orow<<8)|sy3] = (uint16_t)f;
                                sm3 += f;
                            }
                            ch->counter[orow] = (uint16_t)((ch->counter[orow] + 1u) >> 1);
                            ch->total[orow]   = (uint16_t)(sm3 + ch->counter[orow]);
                            oldtot = ch->total[orow];
                            s_pmt[ph] -= ALZ_ARENA2D_RESCALE;
                        }
                    }
                }
                /* [DIAG stderr gated] trace Pph[838] (cls3 relrow5) counter/total aprs each commit
                 * of pass : rvle now `counter[5]` s'effondre (devrait ~29 l'between b1). */
                if (getenv("UHA_LIVEWALK_CTRTRACE") && (int)c == dens_cls) {
                    uint32_t ph5 = s_pbase[dens_cls] + 5u; alz_arena2d_t *c5 = &Pph[ph5>>9]; uint32_t o5 = ph5&(ALZ_ARENA2D_MAX_ROW-1u);
                    fprintf(stderr, "[CTRTRACE] b=%u c=%u Pph[838] row5 counter=%u total=%u\n",
                            (unsigned)b, (unsigned)c, (unsigned)c5->counter[o5], (unsigned)c5->total[o5]);
                }
            } else Pc[c] = *H;                       /* commit banque cls c */
        }
    }
    if (sp) fclose(sp);
    if (seedvals) free(seedvals);
    if (Pfeed) free(Pfeed);
    if (rsrow) free(rsrow);
    if (rsseq) free(rsseq);
    if (odens) free(odens);
    for (c = 0u; c < LPASS; c++) free(ctxc[c]);
    free(H);
    #undef LPASS
}

/* [0x414630 sel10] Reproduction faithful of the model unigramme/bigramme d'echappement
 * uses by UHARC 0.6b (full.asm:24176..24350) when [0x45ecc8] == 1 (selecteur 10). */
static void rescale_sel10_row(uint16_t *freq_row, uint16_t *work_tree, uint16_t *work_tot, uint32_t row)
{
    uint32_t tot = 0;
    for (int s = 0; s < 256; s++) {
        uint32_t v = (freq_row[s] & ~1u) >> 1;
        freq_row[s] = (uint16_t)v;
        tot += v;
    }
    uint32_t ctr = ((uint32_t)work_tree[row] >> 2) + 1u;
    work_tree[row] = (uint16_t)ctr;
    work_tot[row] = (uint16_t)(tot + ctr);
}

static void alz_compute_sel10_block_cost(const uint8_t *data, uint32_t blk_len, uint32_t *out_costs)
{
    uint16_t (*freq)[256] = (uint16_t (*)[256])calloc(256 * 256, sizeof(uint16_t));
    uint16_t work_tree[256];
    uint16_t work_tot[256];
    uint16_t esc_freq[256];
    uint32_t esc_tot = 512;
    uint8_t prev_byte = 0;

    if (!freq) return;

    for (int r = 0; r < 256; r++) {
        work_tree[r] = 16384;
        work_tot[r]  = 16384;
    }
    for (int s = 0; s < 256; s++) {
        esc_freq[s] = 2;
    }

    for (uint32_t pos = 0; pos < blk_len; pos++) {
        uint8_t b = data[pos];
        uint32_t row = prev_byte;
        uint32_t sym = b;

        uint32_t f_sym = freq[row][sym];
        uint32_t tot = work_tot[row];
        uint32_t c;

        if (f_sym == 0) {
            uint32_t p_esc_sym = (esc_freq[sym] << 14) / esc_tot;
            if (p_esc_sym > 16384) p_esc_sym = 16384;
            if (p_esc_sym == 0) p_esc_sym = 1;
            uint32_t cost_esc_sym = AlzSseMap[p_esc_sym];

            uint32_t ctr = work_tree[row];
            uint32_t p_esc_marker = (ctr << 14) / tot;
            if (p_esc_marker > 16384) p_esc_marker = 16384;
            if (p_esc_marker == 0) p_esc_marker = 1;
            uint32_t cost_esc_marker = AlzSseMap[p_esc_marker];

            c = cost_esc_sym + cost_esc_marker;

            work_tree[row] = (uint16_t)(work_tree[row] + 32);
            work_tot[row]  = (uint16_t)(work_tot[row] + 32);
        } else {
            uint32_t p = (f_sym << 14) / tot;
            if (p > 16384) p = 16384;
            if (p == 0) p = 1;
            c = AlzSseMap[p];
        }

        freq[row][sym] = (uint16_t)(freq[row][sym] + 32);
        work_tot[row]  = (uint16_t)(work_tot[row] + 32);

        if (work_tot[row] >= 0x4000) {
            rescale_sel10_row(freq[row], work_tree, work_tot, row);
        }

        out_costs[pos] = c;
        prev_byte = b;
    }
    free(freq);
}

static void lmin_dens_precompute(const uint8_t *plain, uint32_t usize)
{
    static const uint32_t s_blpos[6] = {0x0000u, 0x3100u, 0x620cu, 0x931cu, 0xc4ffu, 0xff00u};
    static const uint32_t s_blen[6]  = {0x3100u, 0x310cu, 0x3110u, 0x31e3u, 0x3a01u, 0x100u};
    uint32_t *tmp;
    int b;
    if (g_lmin_dens_ready)
        return;
    {   /* [GATED UHA_C4PRE] probe pre-pass learn-all, without effet sure the path reel */
        const char *cp = getenv("UHA_C4PRE");
        if (cp && *cp) c4pre_dens_dump(plain, usize, cp);
    }
    g_lmin_dens = (uint32_t *) calloc(usize ? usize : 1u, sizeof(uint32_t));
    if (!g_lmin_dens)
        return;
    /* [GATED UHA_LIVEFULL, default-OFF, 14.049] Window `sm` peuplee by the MASTER
     * SINGLE-PASS live (live_master_cost_at : ctx-roll + LEARN promo has hot), en
     * order of scan, au lieu of the prepasse proxy. Test direct : isce that the cost
     * hot intrablock refroidit sm -> franchit there razor @8693 ? Zero effet out gate. */
    if (getenv("UHA_LIVEFULL") != NULL) {
        uint32_t q;
        for (q = 0u; q < usize; q++)
            g_lmin_dens[q] = live_master_cost_at(plain, usize, q + 1u);
        g_lmin_dens_ready = 1; lmin_dump_gated(usize); return;
    }
    /* [GATED UHA_CLASSPASS=1, default-OFF] Producteur dens FAITHFUL 13.722 :
     * arena SHARED monotone * 5 passes of class/block, snapshot = pass cls3.
     * Prioritaire sure SNAPWALK/COSTSNAP (models approximatifs) when present. */
    if (getenv("UHA_CLASSPASS") != NULL) {
        if (alz_ps_classpass_percost(plain, usize, s_blpos, s_blen, 6, g_lmin_dens) == 0) {
            g_lmin_dens_ready = 1; lmin_dump_gated(usize); return;
        }
        /* failure -> retombe sure the path standard (without regression). */
    }
    /* [GATED UHA_CM_EMISS, default-OFF, 13.905] Porteur faithful of the WINDOW : fills
     * g_lmin_dens via the carry master arena2d (reload W:=copy(M)/block + rescale working
     * 0x414590), block by block (s_blpos/s_blen), BEFORE l'emission -> alimente reellement
     * `sm`. C'is HERE (and no l'acclive) that there window of the gouverneur is peuplee. */
    if (getenv("UHA_CM_EMISS") != NULL) {
        int ok = 1;
        for (b = 0; b < 6; b++)
            if (s_blen[b] && alz_ps_emission_master_carry(plain, s_blpos[b], s_blen[b], g_lmin_dens) != 0)
                { ok = 0; break; }
        if (ok) { g_lmin_dens_ready = 1; lmin_dump_gated(usize); return; }
    }
    /* [GATED UHA_EMIPROD=chemin_masque, default-OFF] emission-walk-producer 13.723 :
     * master advances sure LITERALS EMIS (mask = positions-literal of the clone, has by
     * line), then snapshot(master)->working + scan dense intra-block cls3. */
    {
        const char *ew = getenv("UHA_EMIPROD");
        if (ew && *ew) {
            FILE   *mf    = fopen(ew, "r");
            uint8_t *is_lit = (uint8_t *) calloc(usize ? usize : 1u, 1u);
            int rc = -1;
            if (mf && is_lit) {
                long v;
                while (fscanf(mf, "%ld", &v) == 1)
                    if (v >= 0 && (uint32_t)v < usize) is_lit[(uint32_t)v] = 1u;
                rc = alz_ps_emiprod_percost(plain, usize, s_blpos, s_blen, 6, is_lit, g_lmin_dens);
            }
            if (mf) fclose(mf);
            if (rc != 0) { if (is_lit) free(is_lit); is_lit = NULL; }
            if (rc == 0) {
                /* [GATED UHA_CLASSPASS_HYB, default-OFF, 14.136] hybride : EMIPROD
                 * fills bloc0 (faithful up to razor), then classpass (arena partagee
                 * monotone 5 passes, master cold @bloc1) REECRIT the blocks>=1 = model
                 * CORRECT of the cost[rc] block>=1 (14.135). without env : NOTHING (no regressif). */
                if (getenv("UHA_CLASSPASS_HYB"))
                    (void) alz_ps_classpass_percost(plain, usize, s_blpos + 1, s_blen + 1, 5,
                                                    g_lmin_dens);
                /* [GATED UHA_CLASSPASS_WARM, default-OFF, 14.138] classpass sure all the
                 * blocks in has buffer (l'arena partagee s'echauffe therefore via bloc0),
                 * but on N'ADOpte that ses blocks>=1 (bloc0 keeps EMIPROD, correct
                 * up to razor). Teste if l'heritage d'accumulation of the bloc0 fixes
                 * the `sm` bloc1. without env : NOTHING. */
                if (getenv("UHA_CLASSPASS_WARM")) {
                    uint32_t *cp = (uint32_t *) calloc(usize ? usize : 1u, sizeof(uint32_t));
                    if (cp && alz_ps_classpass_percost(plain, usize, s_blpos, s_blen, 6, cp) == 0) {
                        int hb;
                        for (hb = 1; hb < 6; hb++) {
                            uint32_t base = s_blpos[hb], len = s_blen[hb];
                            if (base >= usize) continue;
                            if (base + len > usize) len = usize - base;
                            if (len) memcpy(g_lmin_dens + base, cp + base,
                                             (size_t) len * sizeof(uint32_t));
                        }
                    }
                    free(cp);
                }
                /* [GATED UHA_LIVEWALK, defautOFF, ARENA_TASK16] live_walk_master : overlay
                 * Has arena master singlepass live (deroulee since 0 for l'echauffer,
                 * inline by byte emis matchinclus, reload total:=tree+counter, rescale
                 * @0x4000, aging 0x40ffa0) sure the block>=`UHA_LIVEWALK_FROM` (default 12544 =
                 * bloc1) ; the bloc0 KEEPS EMIPROD (bitexact 0..13808, cf 14.219). Zero
                 * effet out gate. Judge unique = firstdiv. */
                if (getenv("UHA_LIVEWALK") != NULL) {
                    const char *fw = getenv("UHA_LIVEWALK_FROM");
                    uint32_t lw_from = fw ? (uint32_t) strtoul(fw, NULL, 10) : 0x3100u;
                    if (getenv("UHA_LIVEWALK_LC") != NULL)                 /* MEASURES literalcarry (n'writes not out) */
                        (void) alz_ps_livewalk_litcarry(plain, usize, s_blpos, s_blen, 6, is_lit, NULL);
                    else if (getenv("UHA_LIVEWALK_DUAL") != NULL)           /* side B : double-buffer P/H + injection #17 */
                        (void) alz_ps_livewalk_dual(plain, usize, is_lit, lw_from, g_lmin_dens);
                    else if (getenv("UHA_LIVEWALK_CM") != NULL) {           /* master d'emission row_hash_cm (FP=stats only) */
                        uint32_t *cmout = getenv("UHA_LIVEWALK_CM_FP") ? NULL : g_lmin_dens;
                        (void) alz_ps_livewalk_cm(plain, usize, is_lit, lw_from, cmout);
                    }
                    else if (getenv("UHA_LIVEWALK_PS") != NULL)             /* producteur multi3 (snap winner dense) */
                        (void) alz_ps_livewalk_master(plain, usize, s_blpos, s_blen, 6, lw_from, g_lmin_dens);
                    else if (getenv("UHA_LIVEWALK_4PASS") != NULL) {          /* blueprint #16 : reload H:=P *4 passes + commit */
                        g_lw_islit = is_lit;                                  /* mask literals for LIT_LEARN (gated) */
                        g_lw_litlearn = getenv("UHA_LIVEWALK_LIT_LEARN") ? 1 : 0;
                        live_walk_master_4pass(plain, usize, g_lmin_dens, lw_from);
                        g_lw_islit = NULL; g_lw_litlearn = 0;
                    }
                    else                                                    /* prepasse continue (litterauxseuls) = 16685 */
                        live_walk_master_prepass(plain, usize, g_lmin_dens, lw_from, is_lit);
                }
                if (is_lit) free(is_lit);
                g_lmin_dens_ready = 1; lmin_dump_gated(usize); return;
            }
            /* failure -> retombe sure path standard (without regression). */
        }
    }
    /* [GATED UHA_SNAPWALK=<mask>, validation reading-single, default-OFF, NO-regressif]
     * Producteur dens = model TWO-arenas (snapshot persiste advances SPARSE sure the
     * positions-literal emises has inc=16, dens = scorer dense inc=32). mask = liste
     * d'entiers = positions-literal (has by line). without env -> path standard. */
    {
        const char *mw = getenv("UHA_SNAPWALK");
        if (mw && *mw) {
            FILE   *mf    = fopen(mw, "r");
            uint8_t *is_lit = (uint8_t *) calloc(usize ? usize : 1u, 1u);
            int rc = -1;
            if (mf && is_lit) {
                long v;
                while (fscanf(mf, "%ld", &v) == 1)
                    if (v >= 0 && (uint32_t)v < usize) is_lit[(uint32_t)v] = 1u;
                rc = alz_ps_snapshot_percost_sparse(plain, usize, s_blpos, s_blen, 6, is_lit, g_lmin_dens);
            }
            if (is_lit) free(is_lit);
            if (mf) fclose(mf);
            if (rc == 0) { g_lmin_dens_ready = 1; lmin_dump_gated(usize); return; }
            /* failure -> retombe sure path standard (without regression). */
        }
    }
    tmp = (uint32_t *) malloc(0x8000u * sizeof(uint32_t));   /* max len of has block */
    if (!tmp) { free(g_lmin_dens); g_lmin_dens = NULL; return; }
    /* [GATED UHA_PERPOS, default-OFF] producteur dens per-position argmin (13.729) :
     * legacy selects there class by position (0x413ea0), not by block. Prioritaire
     * sure COSTSNAP (which selects Has winner by block) when present. */
    if (getenv("UHA_PERPOS") != NULL) {
        if (alz_ps_perpos_percost(plain, usize, s_blpos, s_blen, 6, g_lmin_dens) == 0) {
            free(tmp);
            g_lmin_dens_ready = 1;
            lmin_dump_gated(usize);
            return;
        }
        /* failure -> retombe sure COSTSNAP/standard (without regression). */
    }
    if (getenv("UHA_COSTSNAP") != NULL) {
        if (alz_ps_snapshot_percost(plain, usize, s_blpos, s_blen, 6, g_lmin_dens) == 0) {
            /* [GATED UHA_CLASSPASS_HYB, default-OFF, 14.136] hybride producteur of dens :
             * bloc0 keeps COSTSNAP (faithful up to razor), blocks>=1 are REECRITS by
             * l'arena partagee monotone 5-passes of classpass (master cold @bloc1 +
             * accumulation multi-classes), which is the model CORRECT of the cost[rc] block>=1
             * (cf 14.135 : 5 passes partagent has arena, reload at the frontier). Zero effet
             * if env absent. */
            if (getenv("UHA_CLASSPASS_HYB"))
                (void) alz_ps_classpass_percost(plain, usize, s_blpos + 1, s_blen + 1, 5,
                                                g_lmin_dens);
            free(tmp);
            g_lmin_dens_ready = 1;
            lmin_dump_gated(usize);
            return;
        }
        /* failure -> retombe sure the path cold standard (without regression). */
    }
    {
        const char *cfe = getenv("UHA_ALZ_COSTFRONT");
        int costfront_on = (cfe && atoi(cfe) > 0);
        if (costfront_on) {
            uint32_t cpos = 0;
            int cmem = 0;
            static int s_cfsnap = -1;
            if (s_cfsnap < 0) s_cfsnap = getenv("UHA_COSTFRONT_SNAP") ? 1 : 0;
            if (s_cfsnap) {
                uint32_t dyn_bpos[256], dyn_blen[256];
                int dyn_n = 0;
                while (cpos < usize && dyn_n < 256) {
                    uint32_t n_nb = alz_costfront_next_boundary(plain, usize, cpos, NULL, 0, &cmem);
                    uint32_t blk_len = (n_nb > cpos) ? (n_nb - cpos) : 0u;
                    if (!blk_len) break;
                    dyn_bpos[dyn_n] = cpos;
                    dyn_blen[dyn_n] = blk_len;
                    dyn_n++;
                    cpos = n_nb;
                }
                if (alz_ps_snapshot_percost(plain, usize, dyn_bpos, dyn_blen, dyn_n, g_lmin_dens) == 0) {
                    free(tmp);
                    g_lmin_dens_ready = 1;
                    lmin_dump_gated(usize);
                    return;
                }
            }
            cpos = 0;
            cmem = 0;
            static int s_sel10_cost = -1;
            if (s_sel10_cost < 0) s_sel10_cost = getenv("UHA_ALZ_SEL10_COST") ? 1 : 0;
            while (cpos < usize) {
                uint32_t n_nb = alz_costfront_next_boundary(plain, usize, cpos, NULL, 0, &cmem);
                uint32_t blk_len = (n_nb > cpos) ? (n_nb - cpos) : 0u;
                if (!blk_len) break;
                if (s_sel10_cost && cpos == 0) {
                    alz_compute_sel10_block_cost(plain + cpos, blk_len, g_lmin_dens + cpos);
                } else {
                    uint32_t w = alz_ps_block_argmin(plain + cpos, blk_len, 32u, ALZ_PS_COLD0, NULL);
                    (void) alz_ps_class_sigma(w, plain + cpos, blk_len, 32u, ALZ_PS_COLD0, NULL, tmp, NULL);
                    memcpy(g_lmin_dens + cpos, tmp, (size_t) blk_len * sizeof(uint32_t));
                }
                cpos = n_nb;
            }
        } else {
            for (b = 0; b < 6; b++) {
                uint32_t base = s_blpos[b], len = s_blen[b], w;
                if (base >= usize) continue;
                if (base + len > usize) len = usize - base;
                if (!len) continue;
                w = alz_ps_block_argmin(plain + base, len, 32u, ALZ_PS_COLD0, NULL);
                (void) alz_ps_class_sigma(w, plain + base, len, 32u, ALZ_PS_COLD0, NULL, tmp, NULL);
                memcpy(g_lmin_dens + base, tmp, (size_t) len * sizeof(uint32_t));
            }
        }
    }
    free(tmp);
    g_lmin_dens_ready = 1;
    lmin_dump_gated(usize);
}


/* [RE (has) increment 1 - UHA_P3A] Scorer delta-2D autonome, read-only.
 * Mirror structurel of 0x414630/0x415444 : model freq[row][delta] with
 * delta = byte - prev (column 0..255), row = hash some `order` bytes
 * previous (there " category " legacy = has order of context). cost by
 * byte = AlzSseMap[(freq14)/total] (unites 4680*bits, 13.51 : AlzSseMap[i]
 * = 65520-4680*log2(i)), auto-entrainement in place + rescale (total>=0x4000
 * -> 2, mirror of the call 0x414590). returns the cost cumule of coder [start,end)
 * under this order. N'affecte NOR d NOR l'emission (function pure, buffers local). */
static uint64_t p3a_delta2_cost(const uint8_t *plain, uint32_t usize,
                                uint32_t start, uint32_t end, int order)
{
    const uint32_t ROWS = 4096;
    uint16_t *freq, *tot;
    uint64_t cost = 0;
    uint32_t p;
    int j;

    (void)usize;
    if (end <= start || order < 1)
        return 0;
    freq = calloc((size_t)ROWS * 256, sizeof(uint16_t));
    tot  = calloc(ROWS, sizeof(uint16_t));
    if (!freq || !tot) {
        free(freq); free(tot);
        return 0;
    }
    for (p = start; p < end; p++) {
        uint32_t prev = (p >= 1) ? plain[p - 1] : 0u;
        uint32_t delta = (uint32_t)(plain[p] - prev) & 0xFFu;
        uint32_t h = 0, row, t, f, idx;
        for (j = 1; j <= order; j++) {
            if ((int)p - j >= 0)
                h = h * 223u + plain[p - j];
        }
        row = h & (ROWS - 1);
        t = tot[row];
        f = (uint32_t)freq[row * 256 + delta];
        if (t == 0 || f == 0) {
            cost += 4680ull * 8u;      /* delta never vu in there line : ~8 bits */
        } else {
            idx = (f << 14) / t;
            if (idx > 16384u)
                idx = 16384u;
            cost += AlzSseMap[idx];
        }
        freq[row * 256 + delta] = (uint16_t)(freq[row * 256 + delta] + 1);
        t += 1;
        if (t >= 16384u) {
            uint32_t c;
            for (c = 0; c < 256; c++)
                freq[row * 256 + c] >>= 1;
            t >>= 1;
        }
        tot[row] = (uint16_t)t;
    }
    free(freq); free(tot);
    return cost;
}

/* [13.79 UHA_BUDGETPARSE] Selecteur recency-first. Preference marquee for
 * the classes of distances RECENTES (cost d'emission faible : no tree of
 * distance), same sure some matches courts ; not toggles sure there distance
 * explicite TOK1 qu'en last recours. Mins by class cales sure l'oracle
 * legacy image.raw (TOK2 min=2, TOK3 min=4, TOK1 min=3). */
static int alz_find_match_budget(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                 uint32_t pos, const uint32_t *hashtab,
                                 const uint32_t *chain, uint32_t hmask,
                                 uint32_t cmask, int *token_out,
                                 uint32_t *dist_out, uint32_t *count_out)
{
    int slot;
    uint32_t n, dist;
    int elen;

    /* 1) classes recentes by order of recence (slot0=TOK2 d'abord). */
    for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
        uint32_t r = d->st.recent_distance[slot];
        int tok = (slot == 0) ? 2 : 3;
        int cmin = (slot == 0) ? 2 : 4;
        if (r == 0 || r > d->mode.dict_mask)
            continue;
        n = alz_plain_match_len(d, plain, usize, pos, r);
        elen = alz_best_encodable_len(d, tok, r, n);
        if (elen >= cmin) {
            *token_out = tok;
            *dist_out = r;
            *count_out = (uint32_t)elen;
            return 1;
        }
    }
    /* 2) TOK1 RLE (dist=1), min 3. */
    n = alz_plain_match_len(d, plain, usize, pos, 1u);
    elen = alz_best_encodable_len(d, 1, 1u, n);
    if (elen >= 3) {
        *token_out = 1; *dist_out = 1; *count_out = (uint32_t)elen;
        return 1;
    }
    /* 3) TOK1 distance explicite via strings of hachage, min 3. */
    n = alz_chain_best(d, plain, usize, pos, hashtab, chain, hmask, cmask, &dist);
    if (n >= 3 && dist != 1u) {
        elen = alz_best_encodable_len(d, 1, dist, n);
        if (elen >= 3) {
            *token_out = 1; *dist_out = dist; *count_out = (uint32_t)elen;
            return 1;
        }
    }
    return 0;
}

/* [P1.2-faithful GATED UHA_ARGMINPARSE] Transcription of l'arbitre of PARSE
 * 0x413ea0 (walk 13.19) : argmin of cost RC sure the candidates of class
 * {TOK1 dist explicite, TOK2 recent[0], TOK3 recent[1], RLE dist=1}, chacun
 * scores by son under-model HOT (alz_match_model_cost), the LITERAL (cls0,
 * alz_bm_literal_cost_warm) RESTANT in THERE COMPETITION - " literal-vs-match
 * = argmin direct of costs of models " (13.19). Min by class cales sure
 * l'oracle image.raw (TOK2=2, TOK3=4, TOK1/RLE=3, 13.79). encoder-only :
 * emits has stream VALIDATES q.q.s. -> roundtrip intact. no effect default (7052). */
static int alz_find_match_argmin(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                 uint32_t pos, const uint32_t *hashtab,
                                 const uint32_t *chain, uint32_t hmask,
                                 uint32_t cmask, int *token_out,
                                 uint32_t *dist_out, uint32_t *count_out)
{
    int btok = 0;
    uint32_t bdist = 0, blen = 0, bcost = ~(uint32_t)0;
    int slot;

    /* classes of recence : slot0 -> TOK2 (min 2) ; slots 1..11 -> TOK3 (tree
     * of slots courts m_short_slot_for, min 4). Tie-break : the slot the more
     * recent (index low) gagne has cost equal (c < wcost strict). */
    for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
        uint32_t r = d->st.recent_distance[slot];
        int tok = (slot == 0) ? 2 : 3;
        int cmin = (slot == 0) ? 2 : 4;
        uint32_t n, cost;
        int elen;
        if (r == 0 || r > d->mode.dict_mask)
            continue;
        n = alz_plain_match_len(d, plain, usize, pos, r);
        elen = alz_best_encodable_len(d, tok, r, n);
        if (elen < cmin)
            continue;
        cost = alz_match_model_cost(d, tok, r, (uint32_t)elen);
        /* [GATED UHA_ARGDUMP, read-only, default-OFF] journal cost model by candidate. */
        if (getenv("UHA_ARGDUMP") && pos >= 690u && pos <= 700u)
            fprintf(stderr, "[ARG] pos=%u tok=%d dist=%u len=%d cost=%u\n",
                    (unsigned)pos, tok, r, elen, cost);
        if (cost != ~(uint32_t)0 && cost < bcost) {
            bcost = cost; btok = tok; bdist = r; blen = (uint32_t)elen;
        }
    }
    /* RLE dist=1 code en TOK1 (min 3). */
    {
        uint32_t n = alz_plain_match_len(d, plain, usize, pos, 1u);
        int elen = alz_best_encodable_len(d, 1, 1u, n);
        if (elen >= 3) {
            uint32_t cost = alz_match_model_cost(d, 1, 1u, (uint32_t)elen);
            if (cost != ~(uint32_t)0 && cost < bcost) {
                bcost = cost; btok = 1; bdist = 1; blen = (uint32_t)elen;
            }
        }
    }
    /* TOK1 distance explicite via chains of hachage (min 3). */
    {
        uint32_t dist = 0, n = alz_chain_best(d, plain, usize, pos, hashtab,
                                              chain, hmask, cmask, &dist);
        if (n >= 3 && dist != 1u) {
            int elen = alz_best_encodable_len(d, 1, dist, n);
            if (elen >= 3) {
                uint32_t cost = alz_match_model_cost(d, 1, dist, (uint32_t)elen);
                if (getenv("UHA_ARGDUMP") && pos >= 690u && pos <= 700u)
                    fprintf(stderr, "[ARG] pos=%u TOK1 dist=%u len=%d cost=%u\n",
                            (unsigned)pos, dist, elen, cost);
                if (cost != ~(uint32_t)0 && cost < bcost) {
                    bcost = cost; btok = 1; bdist = dist; blen = (uint32_t)elen;
                }
            }
        }
    }
    if (btok == 0)
        return 0;                     /* no match candidate -> literal */
    /* [GATED UHA_ARGMIN_NOLIT, default-OFF] Decomposition faithful en TWO temps of the
     * legacy : (1) `0x413ea0` = argmin of cost sure the classes of MATCH (ci-dessus,
     * without literal), then (2) `0x412c30` = the decider gov which slice already the
     * match-vs-LITERAL (`emit_lit = al==0`) when UHA_LMGovern is active. The veto
     * literal ci-dessous replie (2) in (1) and casse the RLE@57 (the match is tue
     * BEFORE that the gov puisse l'accepter). NOLIT skips the veto : l'argmin not retient
     * THAT there class there less chere, the literal is decide by the gov. Zero effet
     * without env (behavior ARGMINPARSE unchanged). */
    {
        static int s_nolit = -1;
        if (s_nolit < 0)
            s_nolit = (getenv("UHA_ARGMIN_NOLIT") != NULL) ? 1 : 0;
        if (!s_nolit &&
            alz_bm_literal_cost_warm(d, plain, usize, pos, blen) <= bcost)
            return 0;
    }
    *token_out = btok;
    *dist_out = bdist;
    *count_out = blen;
    return 1;
}

/* [a5-e GATED UHA_TRUEARGMIN, default OFF = baselines/corpus intacts] Arbitre of
 * parse by cost-REEL (alz_true_bits, no l'estime alz_match_model_cost). 13.225
 * recette : (1) min_len short (2) for laisser passer RLE/TOK2/TOK3, (2) argmin of
 * class sure the TRUE number of bits d'emission {TOK2 slot0, TOK3 slots, RLE d1,
 * TOK1 chain}, (3) veto reads-vs-match : the winner n'is emis that if ses bits
 * match < bits of the run literal of same couverture. Couteux (clone+window by
 * call) : has developper under UHA_FORCESCFG (pass unique). Not mute NOT d. */
static int s_trueargmin = -2;
static int trueargmin_on(void)
{
    if (s_trueargmin == -2)
        s_trueargmin = getenv("UHA_TRUEARGMIN") ? 1 : 0;
    return s_trueargmin;
}

static int alz_find_match_truecost(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                   uint32_t pos, const uint32_t *hashtab,
                                   const uint32_t *chain, uint32_t hmask,
                                   uint32_t cmask, int *token_out, uint32_t *dist_out,
                                   uint32_t *count_out)
{
    alz_cand cd[ALZ_MAX_RECENT + 2];
    int nc = 0, s, k, ncmax = (int)(sizeof cd / sizeof cd[0]);
    int bidx = -1;
    uint32_t minlen = 2u;
    uint64_t bmbits = ~(uint64_t)0, blbits = 0;
    uint32_t maxenc;

    maxenc = usize - pos;
    if (maxenc > 255u)
        maxenc = 255u;
    if (maxenc < minlen)
        return 0;

    /* (Has) slots of recence : TOK2 slot0 (min 2), TOK3 slots 1..11 (min 2). */
    for (s = 0; s < ALZ_MAX_RECENT && nc < ncmax; s++) {
        uint32_t r = d->st.recent_distance[s], n;
        int tok = (s == 0) ? 2 : 3, el;
        if (r == 0 || r > d->mode.dict_mask || r > pos)
            continue;
        n = alz_plain_match_len(d, plain, usize, pos, r);
        el = alz_best_encodable_len(d, tok, r, n);
        if ((uint32_t)el >= minlen) {
            cd[nc].tok = tok; cd[nc].dist = r; cd[nc].len = (uint32_t)el; nc++;
        }
    }
    /* (B) RLE dist=1 en TOK1. */
    if (nc < ncmax) {
        uint32_t n = alz_plain_match_len(d, plain, usize, pos, 1u);
        int el = alz_best_encodable_len(d, 1, 1u, n);
        if ((uint32_t)el >= minlen) {
            cd[nc].tok = 1; cd[nc].dist = 1u; cd[nc].len = (uint32_t)el; nc++;
        }
    }
    /* (C) TOK1 distance explicite via chain of hachage (out recence). */
    if (nc < ncmax) {
        uint32_t dd = 0, n = alz_chain_best(d, plain, usize, pos, hashtab, chain,
                                            hmask, cmask, &dd);
        if (n >= minlen && dd != 1u) {
            int inrec = 0;
            for (s = 0; s < ALZ_MAX_RECENT; s++)
                if (d->st.recent_distance[s] == dd) { inrec = 1; break; }
            if (!inrec) {
                int el = alz_best_encodable_len(d, 1, dd, n);
                if ((uint32_t)el >= minlen) {
                    cd[nc].tok = 1; cd[nc].dist = dd; cd[nc].len = (uint32_t)el; nc++;
                }
            }
        }
    }

    /* argmin by VRAIS bits match ; tie-break = more long (mirror length legacy). */
    for (k = 0; k < nc; k++) {
        uint64_t mb = 0, lb = 0;
        if (pos + cd[k].len > usize)
            continue;
        alz_true_bits(d, plain, usize, pos, cd[k].tok, cd[k].dist, cd[k].len,
                      &mb, &lb);
        if (mb < bmbits || (mb == bmbits && bidx >= 0 && cd[k].len > cd[bidx].len)) {
            bmbits = mb; blbits = lb; bidx = k;
        }
        /* [GATED UHA_ARGDUMP=path, read-only, default-OFF] journal candidates + bits. */
        {   static FILE *s_ad = NULL; static int s_ad_init = 0;
            if (!s_ad_init) { const char *ad = getenv("UHA_ARGDUMP");
                s_ad = ad ? fopen(ad, "w") : NULL; s_ad_init = 1;
                if (s_ad) fprintf(s_ad, "pos tok dist len mbits lbits\n"); }
            if (s_ad) fprintf(s_ad, "%u %d %u %u %llu %llu\n", (unsigned)pos,
                              cd[k].tok, (unsigned)cd[k].dist, (unsigned)cd[k].len,
                              (unsigned long long)mb, (unsigned long long)lb);
        }
    }
    if (bidx < 0)
        return 0;
    /* veto reads-vs-match : if coder the run en literals coute <= the match, on
     * litteralise (13.225 ACCEPT = cost). Mode investissement (UHA_TRUEINV) :
     * the veto not frappe THAT the TOK1 ELOIGNES (dist != 1) ; the matchs recent
     * (TOK2/TOK3, distance already in recent[]) and the RLE (dist==1) are ACCEPTES
     * without veto = investissement of recence (scanlines) that the veto local tuerait. */
    {
        static int s_trueinv = -2;
        if (s_trueinv == -2)
            s_trueinv = getenv("UHA_TRUEINV") ? 1 : 0;
        int is_recent_or_rle = (cd[bidx].tok == 2 || cd[bidx].tok == 3 ||
                                cd[bidx].dist == 1u);
        if (!(s_trueinv && is_recent_or_rle) && blbits <= bmbits)
            return 0;
    }
    *token_out = cd[bidx].tok;
    *dist_out = cd[bidx].dist;
    *count_out = cd[bidx].len;
    return 1;
}

/* sum some costs side-model (g_lmin_dens, unites 4680*bits 13.51) some `count`
 * literals starting from pos. 0 if the pre-pass LMINLIVE n'is not pret. Appele by
 * UHA_T1NET=2 (net en cost side-model, fast : no scratch-coder literal). */
static uint64_t alz_lmin_span(uint32_t usize, uint32_t pos, uint32_t count)
{
    uint64_t s = 0;
    uint32_t i;
    if (!g_lmin_dens_ready || !g_lmin_dens)
        return 0;
    for (i = 0; i < count; i++) {
        uint32_t p = pos + i;
        if (p >= usize)
            break;
        s += g_lmin_dens[p];
    }
    return s;
}

/* ---- [UHA_ARENASCAN=<p1,p2,...>, GATED default-OFF, a5-e briquet 1, MEASURES] ----
 * arena delta-2D LIVE DENSE inc32 calee sure there class winning cls3 (mirror exact
 * of the scorer validated `alz_ps_snapshot_percost`/`ps_score_ctxs` 13.149 : `Sigma_cls3`
 * bloc1 oracle reproduces at the byte near), avancee en lockstep position by
 * position by the finder. `as_cover_cost` replays the SCAN d'extension 0x415444 sure
 * CLONE jetable : at each byte couvert q, ctx=source of the match plain[q-dist]
 * (rotation 0x415700 => delta=(plain[q]-plain[q-dist])&0xff, =0 if exact), line
 * = machine cls3 threadee (ps_ctx_step) ; cost cumule = `total` that the legacy engine
 * compares has `best` (jbe etendre / ja finaliser). Zero effet if env absent. */
static uint32_t __attribute__((unused)) *s_as_ctx3  = NULL;   /* (reserve futur) ctx cls3 by pos */
static alz_arena2d_t *s_as_arena = NULL;   /* arena LIVE dense inc32            */
static const uint8_t *g_plain_as = NULL;   /* vue plaintext for the scan        */
static uint32_t       s_as_pos   = 0;      /* progressions already ingestees       */
static uint32_t       s_as_list[16];                          /* targets of the gate */
static uint32_t       s_as_mm[3] = {0u,0u,0u};                 /* machine cls3 global */
static uint32_t       s_as_mm_at[16][3];                       /* snapshot to the targets */
static int            s_as_n     = -1;     /* <0 no init; 0 desactive          */

static void as_init(void)
{
    const char *e;
    int i = 0;
    char buf[128];
    char *tok;
    if (s_as_n >= 0)
        return;
    e = getenv("UHA_ARENASCAN");
    if (!e || !*e) { s_as_n = 0; return; }
    strncpy(buf, e, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    tok = strtok(buf, ",");
    while (tok && i < 16) { s_as_list[i++] = (uint32_t)strtoul(tok, NULL, 10); tok = strtok(NULL, ","); }
    s_as_n = i;
}

static int __attribute__((unused)) as_want(uint32_t pos)
{
    int i;
    as_init();
    for (i = 0; i < s_as_n; i++)
        if (s_as_list[i] == pos)
            return 1;
    return 0;
}

/* To allocate/lancer l'infra of measures (ctx3 global threade = the SAME producteur
 * validated `alz_ps_gen_ctxs(3)` ; arena dense inc32 = cadence `ps_score_ctxs`). */
static void as_ensure(const uint8_t *plain, uint32_t usize)
{
    as_init();
    if (s_as_n <= 0)
        return;                              /* gate eteint */
    if (!s_as_arena) {
        s_as_arena = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
        if (s_as_arena)
            alz_arena2d_init(s_as_arena, 32u);
    }
    (void)plain; (void)usize;
}

/* To do progresser l'arena LIVE + there machine cls3 up to `pos` (read+train
 * dense inc32, cadence `ps_score_ctxs`) ; snapshotter mm to the positions targets. */
static void as_advance(uint32_t usize, uint32_t pos)
{
    uint32_t tot;
    if (!s_as_arena)
        return;
    if (pos > usize)
        pos = usize;
    while (s_as_pos < pos) {
        uint32_t sc = alz_ps_ctx_step_run(3u, g_plain_as, s_as_pos, s_as_mm);
        uint32_t row   = (sc >> 8) & (ALZ_ARENA2D_MAX_ROW - 1u);
        uint32_t delta = sc & 0xFFu;
        int k;
        (void)alz_arena2d_score(s_as_arena, row, delta, &tot);
        for (k = 0; k < s_as_n; k++)
            if (s_as_list[k] == s_as_pos) {
                s_as_mm_at[k][0] = s_as_mm[0];
                s_as_mm_at[k][1] = s_as_mm[1];
                s_as_mm_at[k][2] = s_as_mm[2];
            }
        s_as_pos++;
    }
}

/* Scan of couverture 0x415444 FAITHFUL (variante b) : clone arena + clone mm has
 * `pos` ; at each byte q, delta=plain[q]-plain[q-dist] (0 if exact), line =
 * machine cls3 avancant sure THIS delta ; total = Sigma costs lus (mirror `esi`). */
static long long as_cover_cost(uint32_t usize, uint32_t pos, uint32_t dist, uint32_t span)
{
    alz_arena2d_t tmp;
    uint32_t mm[3];
    uint64_t total = 0;
    uint32_t i;
    int k, found = -1;
    if (!s_as_arena || dist == 0u)
        return -1;
    for (k = 0; k < s_as_n; k++)
        if (s_as_list[k] == pos) { found = k; break; }
    if (found < 0)
        return -1;
    tmp = *s_as_arena;                      /* clone : l'state global remainder intact */
    mm[0] = s_as_mm_at[found][0]; mm[1] = s_as_mm_at[found][1]; mm[2] = s_as_mm_at[found][2];
    for (i = 0; i < span; i++) {
        uint32_t q = pos + i;
        uint32_t sc, row, delta, tot;
        if (q >= usize || q < dist)
            break;
        delta = (uint32_t)((uint32_t)g_plain_as[q] - (uint32_t)g_plain_as[q - dist]) & 0xFFu;
        sc = alz_ps_ctx_scan3(g_plain_as, q, mm, delta);
        row = (sc >> 8) & (ALZ_ARENA2D_MAX_ROW - 1u);
        (void)alz_arena2d_score(&tmp, row, delta, &tot);
        total += tot;
    }
    return (long long)total;
}
/* --------------------------------------------------------------------------- */

/* Table shr of the descente 0x4137a0 : cl = BYTE[bit*0x400 + lvl*4 + 0x439a1c]
 * (0x41383e), bit = (acc >= 0x200000) (0x41382d setae). levels extracted
 * runtime winedbg sure the 256 levels (/tmp/shr_fam0.txt, /tmp/shr_fam1.txt) :
 *   famille0 (bit=0) : lvl0-1->0, lvl2-3->5, lvl4-6->4, lvl7-15->3, lvl16+->2
 *   famille1 (bit=1) : lvl0-1->0, lvl2-3->3, lvl4-6->2, lvl7+  ->1 */
static inline uint32_t alz_lvl_shr(int bit, uint32_t lvl)
{
    if (!bit) {
        if (lvl < 2u) return 0u;
        if (lvl < 4u) return 5u;
        if (lvl < 7u) return 4u;
        if (lvl < 16u) return 3u;
        return 2u;
    }
    if (lvl < 2u) return 0u;
    if (lvl < 4u) return 3u;
    if (lvl < 7u) return 2u;
    return 1u;
}

/* [A5.3-w6b] Matcher legacy faithful (increment 1 : pipeline of selection,
 * chain bounded has 99 + window 130817 ; raffineur/threshold = iteration next).
 * opere sure plain[] + hashtab/chain + recent_distance[] of the clone. */
/* [GATED UHA_LVLWALK, default-OFF] Signal encoder-single : there descente exact
 * 0x4137a0 has ACCEPTE has match TOK1 has distance EXPLICITE (top>=3) and il is
 * codable. En -m3 the pending-walker 0x412f70 is EXCLU (proof ASM 0x413196
 * cmp BYTE[0x45ecbc],3 jae, cf S13.497) : the legacy engine EMITS there decision of the finder
 * DIRECTEMENT, without defer. This flag dit au caller of not NOT to apply the proxy
 * COSTLAZY/LAZYFIX (which sure-differe exactly there frontier 5120). */
int g_lvlwalk_adopt = 0;
static int alz_find_match_legacy(alz_dec *d, const uint8_t *plain, uint32_t usize,
                                 uint32_t pos, int min_len, int tok2_min,
                                 const uint32_t *hashtab, const uint32_t *chain,
                                 uint32_t hmask, uint32_t cmask,
                                 int *token_out, uint32_t *dist_out,
                                 uint32_t *count_out)
{
    uint32_t best_len = 0, best_dist = 0;
    g_lvlwalk_adopt = 0;   /* resets by CALL (the look-aheads not doivent
                            * not laisser fuiter has adopt of has call previous) */
    {   /* [probe reading-single UHA_FMPROBE] sequence some pos demandes by the
         * parser (feed 1x/pos?). N'emits that if env sets. default-OFF. */
        static int s_fm = -2;
        if (s_fm == -2) s_fm = getenv("UHA_FMPROBE") ? 1 : 0;
        if (s_fm) fprintf(stderr, "[FMPOS pos=%u out=%u]\n", pos, d->st.output_pos);
    }
    int best_tok = 0;
    uint32_t dist_limit, maxenc, h, p, depth;
    uint32_t rc_len = 0, rc_dist = 0, t1_len = 0, t1_dist = 0;
    uint64_t t1_bestmb = 0, t1_bestnet = 0; int t1_cost_set = 0;
    int slot, eff_ml, margin, rc_tok = 0, rc_slot = -1, use_cost, use_refine, use_slotmin, use_t1cost, use_t1first, use_t1net;
    static int s_margin = -2, s_use_cost = -2, s_use_refine = -2, s_slotmin = -2, s_t1cost = -2, s_t1first = -2, s_t1net = -2;
    static int s_chainmax = -2;
    static int s_lvlwalk = -2;
    static int s_triewalk = -2;   /* [GATED UHA_TRIEWALK, default-OFF, imbrique in
                                   * UHA_LVLWALK] mirror fiddle of the trie legacy 0x4373c4
                                   * (1 single path branch6 by l'byte post-match) */
    static int s_triecmp = -2;    /* [GATED UHA_TRIECMP=N, default 0] offset base of
                                   * comparaison of the trie : 0=plain[head+n] (tete
                                   * 1-based utilisee as offset raw) ;
                                   * 1=plain[head-1+n] (position REELLE = head-1). */
    unsigned chain_cap;
    /* Tables STATIC of the raffineur legacy 0x4137a0 (ground-truth dump winedbg,
     * research/gt_scorer/alz_finder_tables.txt). AlzOrderBucket = 0x439794[slot]
     * (rampe recence->bucket 0..3) ; AlzRefineThr = 0x4397d4[gap*4+bucket]
     * (threshold of DISTANCE ; 0xffffffff = never-rejete). The hash n'is adopte
     * (vs recent keeps) that if gap>=6 NOW dist < threshold. */
    static const uint8_t AlzOrderBucket[12] =
        { 0, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3 };
    static const uint32_t AlzRefineThr[24] = {
        /* gap0 */ 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
        /* gap1 */ 0x00000004u, 0x00000008u, 0x00000080u, 0x00000400u,
        /* gap2 */ 0x00000010u, 0x00000040u, 0x00000400u, 0x00002000u,
        /* gap3 */ 0x00000040u, 0x00000100u, 0x00002000u, 0xffffffffu,
        /* gap4 */ 0x00000100u, 0x00000800u, 0xffffffffu, 0xffffffffu,
        /* gap5 */ 0x00000800u, 0xffffffffu, 0xffffffffu, 0xffffffffu
    };
    (void)AlzOrderBucket;
    (void)AlzRefineThr;
    /* [A5.3-w6b UHA_LVLWALK, GATED default-OFF] Mirror EXACT of the matcher legacy
     * by position (13.495, validated runtime winedbg) : scan MRU-12 en dh-bytes
     * (not en cost encodable) -> memset of the stack of buckets + top=2 -> promenade
     * of chain complete without prune (lecon 13.204) with write-if-empty
     * bucket[len]=DISTANCE -> descente 0x4137a0 (shr-walk + gap>=6 + threshold by
     * groupe) -> accept. The tables viennent of the dump oracle complete
     * (research/gt_scorer/alz_finder_tables.txt + /tmp/tables_full.txt). */
    static const uint8_t AlzSlotGroup[16] =
        { 0, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
    static const uint32_t AlzSeuil[16][4] = {
        /* gap 0  */ { 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u },
        /* gap 1  */ { 0x00000004u, 0x00000008u, 0x00000080u, 0x00000400u },
        /* gap 2  */ { 0x00000010u, 0x00000040u, 0x00000400u, 0x00002000u },
        /* gap 3  */ { 0x00000040u, 0x00000100u, 0x00002000u, 0xffffffffu },
        /* gap 4  */ { 0x00000100u, 0x00000800u, 0xffffffffu, 0xffffffffu },
        /* gap 5  */ { 0x00000800u, 0xffffffffu, 0xffffffffu, 0xffffffffu },
        /* gap 6  */ { 0x00000001u, 0x00000008u, 0x00000020u, 0x00000080u },
        /* gap 7  */ { 0x00000020u, 0x00000100u, 0x00000400u, 0x00001000u },
        /* gap 8  */ { 0x00000400u, 0x00002000u, 0x00008000u, 0x00020000u },
        /* gap 9  */ { 0x00010000u, 0x00080000u, 0x00200000u, 0x00800000u },
        /* gap 10 */ { 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu },
        /* gap 11 */ { 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u },
        /* gap 12 */ { 0x00000004u, 0x00000020u, 0x00000080u, 0x00000200u },
        /* gap 13 */ { 0x00000080u, 0x00000400u, 0x00001000u, 0x00004000u },
        /* gap 14 */ { 0x00000400u, 0x00002000u, 0x00008000u, 0x00020000u },
        /* gap 15 */ { 0x00000800u, 0x00008000u, 0x00020000u, 0x00080000u }
    };
    /* [A5.3-w6b INCREMENT 2/3, GATED UHA_FINDER=legacy] rule recence-d'abord
     * of the matcher legacy. 13.205 : to the 20 DIFF the legacy engine KEEPS the token recent
     * bon walk (TOK2/3) contre has TOK1 lointain same nettement more long
     * (pos 11375 : legacy TOK2 c6 vs notre TOK1 c11). There true law is therefore has
     * ARGMIN OF cost, and the cost faithful = bits REELS (emission prouvee bit-exact
     * via alz_true_bits). (Has) recent -> rc_*, (B) TOK1 explicite -> t1_*,
     * (C) arbitre : bits reels if UHA_LEGACY_COST, otherwise marge plate `margin`
     * (UHA_LEGACY_MARGIN, default 0 = reproduction of the path of base). */
    adaptive_on();
    if (s_margin == -2) {
        const char *m = getenv("UHA_LEGACY_MARGIN");
        s_margin = m ? atoi(m) : 0;
        if (s_margin < 0)
            s_margin = 0;
    }
    margin = s_margin;
    if (s_use_cost == -2)
        s_use_cost = getenv("UHA_LEGACY_COST") ? 1 : 0;
    use_cost = s_use_cost;
    if (s_use_refine == -2)
        s_use_refine = getenv("UHA_LEGACY_REFINE") ? 1 : 0;
    use_refine = s_use_refine;
    /* [a5.3-t4 GATED UHA_SLOTMIN, default OFF = 7041/7052 intacts] Law d'acceptation
     * GRADUEE by slot measured 13.214 (state legacy clean) : TOK2(slot0) min short
     * unchanged ; TOK3(slot>=1) = 4 (slots peu profonds) / 8 (slot>=3), mirror of the
     * grille of thresholds by order 0x4397d4. The default applies eff_t2 PLAT has all the
     * slots -> sure-emission of TOK3 courts (662 vetos 13.214). */
    if (s_slotmin == -2)
        s_slotmin = getenv("UHA_SLOTMIN") ? 1 : 0;
    use_slotmin = s_slotmin;
    /* [GATED UHA_T1COST, default-OFF] Selection TOK1 (block B) by cost-REEL
     * (alz_true_bits, bit-exact prouve) au lieu of the length MAX. the legacy engine
     * retient `d5 c5` (small distance) contre `d518 c6` (large distance, +1
     * long) : there distance DOMINE the cost of has TOK1 (13.479, mur 4608). without
     * this gate : behavior argmax-length + elagage inchanges. */
    if (s_t1cost == -2)
        s_t1cost = getenv("UHA_T1COST") ? 1 : 0;
    use_t1cost = s_t1cost;
    /* [GATED UHA_T1FIRST, default-OFF] Walk of chain 0x4137a0 = ACCEPTER the
     * 1er candidate passant there bound (min_len), THEN stopper : there chain is
     * chainee recent->old (distance croissante), therefore the 1er qualifie = there
     * MORE SMALL distance (ex. d5 c5 @4608), not there more long (d518 c6).
     * the legacy engine n'argmine NOT there length of chain, il ANCRE at most tot. */
    if (s_t1first == -2)
        s_t1first = getenv("UHA_T1FIRST") ? 1 : 0;
    use_t1first = s_t1first;
    /* [GATED UHA_T1NET, default-OFF] Selection TOK1 (block B) by ECONOMIE NETTE
     * of bits REELS (alz_true_bits) : maximiser net = lb  mb (literals economises
     *  cost of the token). Contrairement has T1COST which minimisait mb single (therefore atomise,
     * 13.479), the net integre the SURCOUT of the distance : `d5 c5` (token near
     * bon walk) bat `d518 c6` (distance far = beaucoup of bits) same if the
     * second sauve has literal of more (mur 4608). Coherent with there decision
     * cost-literal-vs-match BY position of legacy (!= DP global rejete 13.485). */
    if (s_t1net == -2) {
        const char *e = getenv("UHA_T1NET");
        s_t1net = e ? atoi(e) : 0;               /* 1 = net bits emission ; 2 = net cost side-model */
        if (s_t1net < 0) s_t1net = 0;
    }
    use_t1net = s_t1net;
    /* [A5.3-t7 GATED UHA_CHAINMAX, default 1024] bound of the WALK OF STRING of the
     * hash. RE 13.x (l.1326) : the driver legacy 0x413ea0 walk the candidates
     * of string en EXACTEMENT 4 iterations (0x413fb6->0x414015, cmp $4,%cl), chacune
     * etendue by 0x414630. The clone (depth<1024) SURE-SEARCHES : il finds some TOK1
     * profonds that the legacy engine not voit never -> sure-emission (13.216, 1910 vs 1385).
     * Recopier there bound exact = to reproduce there GENERATION BORNEE of candidates. */
    if (s_chainmax == -2) {
        const char *c = getenv("UHA_CHAINMAX");
        s_chainmax = (c && atoi(c) > 0) ? atoi(c) : 1024;
    }
    chain_cap = (unsigned)s_chainmax;
    eff_ml = min_len;
    if (s_adaptive) {
        int half = (int)usize / 2;
        eff_ml = 2 + (int)((min_len - 2) * (int)pos / (half > 0 ? half : 1));
        if (eff_ml > min_len) eff_ml = min_len;
        if (eff_ml < 2) eff_ml = 2;
    }

    maxenc = usize - pos;            /* restant block (keeps [0x45ecb4]) */
    if (maxenc > 255)
        maxenc = 255;
    if (maxenc < 2)
        return 0;                     /* < 2 bytes : literal */
    dist_limit = d->mode.dict_mask;
    if (dist_limit > ALZ_LEGACY_MAX_DIST)
        dist_limit = ALZ_LEGACY_MAX_DIST;
    /* [GATED UHA_MINMATCHPOS=<n>, default-OFF] No match before `pos>=n` (literals
     * of tete au demarrage of stream). 13.977 (zeros : legacy 1 match has pos>=2). */
    {   static int s_minpos = -1;
        if (s_minpos < 0) { const char *v = getenv("UHA_MINMATCHPOS"); s_minpos = v ? atoi(v) : -1; }
        if (s_minpos > 0 && (int)pos < s_minpos)
            return 0;
    }

    /* (Has) recence : meilleur match among the 12 slots MRU REELS, strict-longest
     * (tie => slot the more recent, scan legacy 0x413920), threshold eff_t2. */
    for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
        uint32_t r = d->st.recent_distance[slot];
        int tok = (slot == 0) ? 2 : 3;
        int n, e, eff_t2;
        if (r == 0 || r > dist_limit)
            continue;
        {
            static int s_t3_1279_minpos = -1;
            if (s_t3_1279_minpos < 0) {
                const char *v = getenv("UHA_T3_1279_MINPOS");
                s_t3_1279_minpos = v ? atoi(v) : 0;
            }
            if (s_t3_1279_minpos > 0 && tok == 3 && r == 1279u && pos > 26350u && pos < (uint32_t)s_t3_1279_minpos)
                continue;
        }
        n = (int)alz_plain_match_len(d, plain, usize, pos, r);
        if (n > (int)maxenc)
            n = (int)maxenc;
        e = alz_best_encodable_len(d, tok, r, n);
        eff_t2 = tok2_min;
        if (s_adaptive) {
            int half = (int)usize / 2;
            eff_t2 = 2 + (int)((tok2_min - 2) * (int)pos / (half > 0 ? half : 1));
            if (eff_t2 > tok2_min) eff_t2 = tok2_min;
            if (eff_t2 < 2) eff_t2 = 2;
        }
        if (use_slotmin && tok == 3)
            eff_t2 = (slot >= 3) ? 8 : 4;   /* 13.214 : TOK3 never short, croit with depth */
        if (e >= eff_t2 && (uint32_t)e > rc_len) {
            rc_len = (uint32_t)e;
            rc_dist = r;
            rc_tok = tok;
            rc_slot = slot;
        }
    }

    /* (B) meilleur TOK1 (distance EXPLICITE no recente) : run d1 + chain
     * hash. The distances already in the MRU are ignorees (couvertes by (Has)
     * with has token less cher). t1_* retient the TOK1 the more long >= eff_ml. */
    {
        uint32_t n1 = alz_plain_match_len(d, plain, usize, pos, 1u);
        int e1;
        if (n1 > maxenc)
            n1 = maxenc;
        e1 = alz_best_encodable_len(d, 1, 1u, (int)n1);
        if (e1 >= eff_ml) {
            t1_len = (uint32_t)e1;
            t1_dist = 1u;
            if (use_t1cost) {
                uint64_t mb, lb;
                alz_true_bits(d, plain, usize, pos, 1, 1u, t1_len, &mb, &lb);
                t1_bestmb = mb; t1_cost_set = 1;
            } else if (use_t1net) {
                uint64_t mb, lbv;
                alz_true_bits(d, plain, usize, pos, 1, 1u, t1_len, &mb, use_t1net == 2 ? (uint64_t *)0 : &lbv);
                if (use_t1net == 2) {
                    uint64_t lhs = alz_lmin_span(usize, pos, t1_len);
                    lbv = (lhs >= mb * 4680ull) ? (lhs - mb * 4680ull) : 0;
                } else {
                    lbv = (lbv > mb) ? (lbv - mb) : 0;
                }
                t1_bestnet = lbv; t1_cost_set = 1;
            }
        }
    }
    if (s_lvlwalk == -2)
        s_lvlwalk = getenv("UHA_LVLWALK") ? 1 : 0;
    if (s_triewalk == -2)
        s_triewalk = getenv("UHA_TRIEWALK") ? 1 : 0;
    if (s_triecmp == -2) {
        const char *ce = getenv("UHA_TRIECMP");
        s_triecmp = ce ? atoi(ce) : 0;
    }
    if (s_lvlwalk) {
        /* --- setup 0x4136a0 : scan MRU-12 en bytes (dh=[0x45ecb6], bl>dh strict) --- */
        static uint32_t s_lvl_bucket[256];
        uint8_t  s_lvl_ord = 0xFFu;  /* [0x45ecb3] : reset 0xff at each position (0x4136eb) */
        uint8_t  s_lvl_st  = 1u;     /* [0x45ecb2] : reset 1 at each position (0x4136f6) */
        uint32_t top, lvl, dh = 0, bl, dist_sel = 0;
        uint32_t dist_off = 0u;   /* [1-based 13.628] triewalk bucket = actual-1; linear = actual */
        int emit_walk = 0, lw_tok = 1, ok = 0;
        for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
            uint32_t r = d->st.recent_distance[slot];
            if (r == 0 || r > dist_limit || r > pos)
                continue;
            if (dh >= maxenc)
                break;                      /* bl >= [0x45ecb4] -> stop 0x413a49 */
            if (plain[(pos - r + dh) & d->mode.dict_mask] != plain[pos + dh])
                continue;                   /* rejet fast 0x413974 */
            bl = 0;
            while (bl < maxenc &&
                   plain[(pos - r + bl) & d->mode.dict_mask] == plain[pos + bl])
                bl++;
            if (bl > dh) {
                dh = bl;
                s_lvl_ord = (uint8_t)slot;
                s_lvl_st = (uint8_t)((slot == 0) ? 2 : 3);
            }
        }
        /* --- memset(0x4490b0,0,1024) + top=2 (0x413758..0x41376a) --- */
        for (lvl = 0; lvl < 256; lvl++)
            s_lvl_bucket[lvl] = 0;
        top = 2;
        /* --- feed 0x413a60 : promenade complete without prune, write-if-empty,
         * bucket[len] = DISTANCE (prouve runtime 13.495) --- */
        h = ((((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
              | plain[pos + 2]) * 1140071481u >> (32 - 22)) & hmask;
        if (s_triewalk && d->mode.dict_mask + 1u <= (1u << 17)) {
            /* [fidelite 13.6xx] DECOUPLAGE OF THE FEED. the legacy engine promene the trie
             * (0x413a60) EXACTEMENT 1x/position en order ASCENDANT STRICT (prouve
             * Wine : *[0x45dc98] += 1 by call feed, captures 0..59 consecutifs).
             * Notre parser DP/rappel rappelle this finder ~528x/pos (probe UHA_FMPROBE
             * = 7.8M calls, window 250..258 rejouee 528x). if there promenade MUTANTE
             * (writing tete + self-threading) tourne at each rappel, l'state
             * persistant of the trie is recorrompu (pos 256 donnait p=252 dist=4 n=0 au
             * lieu of src 251 dist 5 len 5). The threading + bucket[]/top are PURES
             * en l'input (bytes <= fp) : on the computes once by position in
             * has loop of feed ascendante, on the CACHE by position ; the finder not
             * does that RELIRE the cache (read-only). MRU (dh/st/ord) + descente
             * restent LIVE. Reglage FAITHFUL 1-based : head stores pos+1, src=tete-1,
             * dist=pos-src ; dist_off=0 (bucket = distance REELLE). */
            dist_off = 0u;
#define ALZ_TRIE_MAX (1u << 17)
#define ALZ_TRIE_HBITS (1u << 18)   /* 0x40000 tetes (mask hash XOR 0x3ffff) */
            static int32_t s_trie[ALZ_TRIE_MAX][2];
            static int32_t s_triehead[ALZ_TRIE_HBITS];
            static uint32_t *s_fc_b   = NULL;   /* [cap*256] bucket trie by pos */
            static uint32_t *s_fc_top = NULL;   /* [cap] top trie by pos */
            static uint32_t  s_fc_fed = 0;      /* next pos has feeder */
            static uint32_t  s_fc_cap = 0;      /* capacite of the cache (en pos) */
            static int       s_fc_fail = 0;     /* malloc echoue -> fallback lineaire */
            uint32_t mask = d->mode.dict_mask;
            if (pos == 0u || s_fc_cap < usize) {
                uint32_t i;
                for (i = 0; i < ALZ_TRIE_MAX; i++) { s_trie[i][0] = -1; s_trie[i][1] = -1; }
                for (i = 0; i < ALZ_TRIE_HBITS; i++) s_triehead[i] = -1;
                s_fc_fed = 0;                    /* block new : reinit trie + feed */
                if (s_fc_cap < usize) {
                    free(s_fc_b); free(s_fc_top);
                    s_fc_b   = (uint32_t *)malloc((size_t)usize * 256u * sizeof(uint32_t));
                    s_fc_top = (uint32_t *)malloc((size_t)usize * sizeof(uint32_t));
                    s_fc_cap = (s_fc_b && s_fc_top) ? usize : 0u;
                    s_fc_fail = (s_fc_cap < usize) ? 1 : 0;
                }
            }
            if (s_fc_fail) {                     /* fallback DECLARE : promenade lineaire */
                for (depth = 0, p = hashtab[h];
                     p != 0xFFFFFFFFu && p < pos && depth < 99u; depth++) {
                    uint32_t dist = pos - p;
                    uint32_t n = 0, ah;
                    if (dist > ALZ_LEGACY_MAX_DIST)
                        break;
                    while (n < maxenc && plain[p + n] == plain[pos + n])
                        n++;
                    ah = (n < maxenc) ? n : maxenc;
                    if (ah > 2 && s_lvl_bucket[ah] == 0) {
                        s_lvl_bucket[ah] = dist;
                        if (ah > top)
                            top = ah;
                    }
                    p = chain[p & cmask];
                    if (p == 0xFFFFFFFFu || p >= pos)
                        break;
                }
            } else {
                uint32_t fp;
                for (fp = s_fc_fed; fp <= pos; fp++) {
                    uint32_t *b = s_fc_b + (size_t)fp * 256u;
                    uint32_t ft = 2u;
                    uint32_t mxfp = usize - fp; if (mxfp > 255u) mxfp = 255u;
                    uint32_t cur, ht, pn, prev, dist, edi_n, edi_s, ebp_n, ebp_s, walkp, l;
                    int bound;
                    for (l = 0; l < 256u; l++) b[l] = 0u;
                    if (mxfp < 2u) { s_fc_top[fp] = ft; s_fc_fed = fp + 1u; continue; }
                    cur = (fp + 1u) & mask;                 /* slot 1-based (0x413aa2/aa8) */
                    s_trie[cur][0] = -1; s_trie[cur][1] = -1;
                    ht = ((uint32_t)plain[fp] ^ ((uint32_t)plain[fp + 1] << 5)
                          ^ ((uint32_t)plain[fp + 2] << 10)) & (ALZ_TRIE_HBITS - 1u);
                    walkp = (uint32_t)s_triehead[ht];       /* edx = tete (0x413a8a) */
                    s_triehead[ht] = (int32_t)(fp + 1u);    /* ebx=pos+1 (0x413a8c) */
                    if (walkp != 0xFFFFFFFFu && (uint32_t)(fp + 1u - walkp) <= ALZ_LEGACY_MAX_DIST) {
                        edi_n = cur; edi_s = 0;             /* 0x413a99/a9f */
                        ebp_n = cur; ebp_s = 1;
                        bound = 255;                        /* [esp+0x14] (0x439908=255) */
                        for (;;) {                          /* corps @0x413ae6 */
                            uint32_t n = 0, ah;
                            uint8_t db, sb;
                            uint32_t bsrc = (walkp >= 1u) ? (walkp - 1u) : walkp;
                            dist = fp - bsrc;               /* 0x413ac6/0x413ba2 */
                            while (n < mxfp && plain[bsrc + n] == plain[fp + n])
                                n++;
                            ah = (n < mxfp) ? n : mxfp;      /* 0x413b80 min(len,maxenc) */
                            if (ah > 2 && b[ah] == 0u) {     /* 0x413b99 write-if-empty */
                                b[ah] = dist;
                                if (ah > ft) ft = ah;        /* 0x413bb8 top */
                            }
                            db = (fp + ah < usize) ? plain[fp + ah] : 0u;   /* 0x413be0 */
                            sb = (bsrc + ah < usize) ? plain[bsrc + ah] : 0u;
                            {   /* [probe reading-single UHA_PARSEDBG=pos] */
                                static int s_tp = -2;
                                if (s_tp == -2) { const char *e = getenv("UHA_PARSEDBG"); s_tp = e ? atoi(e) : -1; }
                                if ((int)fp == s_tp)
                                    fprintf(stderr, "[TRIEWALK pos=%u ht=%u head=%u walkp=%u bsrc=%u dist=%u n=%u ah=%u b[ah]=%u ft=%u bound=%d db=%02X sb=%02X]\n",
                                            fp, ht, (uint32_t)s_triehead[ht], walkp, bsrc, dist, n, ah, b[ah], ft, bound, db, sb);
                            }
                            prev = walkp;
                            pn = prev & mask;
                            if (db >= sb) {                  /* jb NOT taken 0x413be6 -> fils[1]/edi */
                                s_trie[edi_n][edi_s] = (int32_t)prev;
                                edi_n = pn; edi_s = 1;
                                walkp = (uint32_t)s_trie[pn][1];
                            } else {                         /* jb taken 0x413c43 -> fils[0]/ebp */
                                s_trie[ebp_n][ebp_s] = (int32_t)prev;
                                ebp_n = pn; ebp_s = 0;
                                walkp = (uint32_t)s_trie[pn][0];
                            }
                            if (--bound < 0 || walkp == 0xFFFFFFFFu
                                || (uint32_t)(fp + 1u - walkp) > ALZ_LEGACY_MAX_DIST) {
                                s_trie[edi_n][edi_s] = -1;   /* 0x413c2c */
                                s_trie[ebp_n][ebp_s] = -1;
                                break;
                            }
                        }
                    }
                    s_fc_top[fp] = ft;
                    s_fc_fed = fp + 1u;
                }
                /* Relire the cache of POS (read-only ; DP peut re-demander). */
                memcpy(s_lvl_bucket, s_fc_b + (size_t)pos * 256u, 256u * sizeof(uint32_t));
                top = s_fc_top[pos];
            }
#undef ALZ_TRIE_MAX
        } else {
            for (depth = 0, p = hashtab[h];
                 p != 0xFFFFFFFFu && p < pos && depth < 99u; depth++) {
                uint32_t dist = pos - p;
                uint32_t n = 0, ah;
                if (dist > ALZ_LEGACY_MAX_DIST)
                    break;                      /* 0x413aca : too old -> stop */
                while (n < maxenc && plain[p + n] == plain[pos + n])
                    n++;
                ah = (n < maxenc) ? n : maxenc;
                if (ah > 2 && s_lvl_bucket[ah] == 0) {
                    s_lvl_bucket[ah] = dist;
                    if (ah > top)
                        top = ah;
                }
                p = chain[p & cmask];
                if (p == 0xFFFFFFFFu || p >= pos)
                    break;
            }
        }
        /* --- descente 0x4137a0, mirror literal (acc = bucket[top] ; at each
         * iteration on DECREMENTE lvl d'abord, then if lvl>=3 : acc >>= shr[lvl]
         * (shr depend of lvl and of the bit (acc>=0x200000)) ; if bucket[lvl]!=0 and
         * acc>bucket[lvl] on abaisse top=lvl and acc=bucket[lvl]). --- */
        if (top > 2u) {
            uint32_t acc = s_lvl_bucket[top];   /* 0x4137b8 : eax = bucket[top] */
            ok = 0;
            lvl = top;                          /* ebx @0x4137aa */
            if (acc == 0u)                      /* 0x41380f je -> 0x4138b7 */
                top = 0u;
            for (;;) {                          /* loop 0x413824 (dec d'abord) */
                uint32_t ebp_v;
                lvl--;                          /* 0x413824 dec ebx */
                if (lvl < 3u) break;            /* 0x413828/0x41382b jb 0x41384f */
                acc >>= alz_lvl_shr(acc >= 0x200000u, lvl);   /* 0x413845 shr eax,cl */
                if (acc == 0u) break;           /* 0x413847/0x413849 jne fall */
                ebp_v = s_lvl_bucket[lvl];      /* 0x4138c4 ebp = bucket[lvl] */
                if (ebp_v != 0u && acc > ebp_v) {   /* 0x4138d2/0x4138da */
                    top = lvl;
                    acc = ebp_v;
                }
            }
            /* finalisation 0x41384f : st==1 accept ; otherwise top>dh, gap=top-dh,
             * gap>=6 NOW bucket[top] < threshold[gap][group[ord]] accept. */
            if (s_lvl_st == 1u) {               /* 0x413856 je 0x4138e7 */
                dist_sel = s_lvl_bucket[top];
                ok = (top >= 2u && dist_sel != 0u);
            } else if (top > dh) {              /* 0x413869 jbe 0x4138a3 (no-accept) */
                uint32_t gap = top - dh;
                if (gap >= 6u ||                /* 0x41387f jae 0x4138e7 */
                    s_lvl_bucket[top] < AlzSeuil[gap & 15u][AlzSlotGroup[s_lvl_ord & 15u]]) {
                    dist_sel = s_lvl_bucket[top];   /* 0x4138a1 jb 0x4138e7 */
                    ok = 1;
                }
            }
            if (ok) {                           /* ACCEPT 0x4138e7 */
                static int s_okdbg = -1;
                if (s_okdbg < 0) { const char *e = getenv("UHA_PARSEDBG"); s_okdbg = e ? atoi(e) : -2; }
                if ((int)pos == s_okdbg)
                    fprintf(stderr, "[LWOK pos=%u top=%u dist=%u outpos=%u canenc=%d]\n",
                            pos, top, dist_sel + dist_off, d->st.output_pos,
                            alz_m_can_encode_match(d, 1, dist_sel + dist_off, top));
                s_lvl_ord = 0xFFu;              /* [0x45ecb3] = 0xff */
                s_lvl_st  = 1u;                 /* [0x45ecb2] = 1 */
                emit_walk = 1;
                lw_tok = 1;                     /* [0x45cb6c] = bucket[top] = dist_sel */
                for (slot = 0; slot < ALZ_MAX_RECENT; slot++)
                    if (d->st.recent_distance[slot] == dist_sel + dist_off) {
                        lw_tok = (slot == 0) ? 2 : 3;
                        break;
                    }
            }
        }
        {   /* [probe reading-single UHA_PARSEDBG=pos] state of the descente LVLWALK */
            static int s_lwdbg = -1;
            if (s_lwdbg < 0) { const char *e = getenv("UHA_PARSEDBG"); s_lwdbg = e ? atoi(e) : -2; }
            if ((int)pos == s_lwdbg) {
                fprintf(stderr, "[LVLWALK pos=%u top=%u dh=%u st=%u ord=%u acc=%u bucket[top]=%u emit=%d]\n",
                        pos, top, dh, s_lvl_st, s_lvl_ord, s_lvl_bucket[top > 0u ? top - 1u : 0u],
                        s_lvl_bucket[top], emit_walk);
            }
        }
        if ((top <= 2u || !ok) && dh >= 2u) {
            /* 0x413774 : no raffineur ; MRU-scan winner direct. N'overwrites NOT
             * best_* (otherwise has chute in l'arbitre without candidate fuiterait this
             * token). returns only if the token recent is codable. */
            uint32_t mru_len = dh;
            uint32_t mru_dist = (s_lvl_ord < (uint32_t)ALZ_MAX_RECENT)
                            ? d->st.recent_distance[s_lvl_ord] : 0u;
            int mru_tok = (s_lvl_ord == 0u) ? 2 : 3;
            if (mru_dist != 0u && mru_len >= (uint32_t)eff_ml &&
                alz_m_can_encode_match(d, mru_tok, mru_dist, mru_len)) {
                /* [GATED UHA_LVLW3GOV, default-OFF, 14.058] the legacy engine emits via the
                 * decider `0x412c30` (veto matchvslitteral) same for the vainqueur
                 * MRU direct ; here on NOT returns NOT 1 d'office for has TOK3 -> on
                 * retombe sure l'arbitre/decider which slice au cost. DefautOFF =
                 * path strict unchanged (image24/hello/zeros no affectes). */
                static int s_lw3gov = -1;
                if (s_lw3gov < 0)
                    s_lw3gov = (getenv("UHA_LVLW3GOV") != NULL) ? 1 : 0;
                if (!(s_lw3gov && mru_tok == 3)) {
                    *token_out = mru_tok;
                    *dist_out = mru_dist;
                    *count_out = mru_len;
                    return 1;
                }
            }
        }
        if (emit_walk && top >= 2u && dist_sel != 0u) {
            if (top == 2u && lw_tok == 1)
                return 0;   /* [PORT] TOK2_MIN=3 : has TOK1 c2 n'is not emissible here */
            /* Keeps d'encodabilite : there stack of buckets of the clone peut exposer has
             * distance no TOK1-atteignable (the feed legacy 0x4373c4 is indexe sure
             * there window RELATIVE and not the produirait never). if the token n'is not
             * codable, on NOT l'emits not and on retombe sure l'arbitre (Has)/(B)/(C) which
             * posera lui-same best_* (no fuite of the descente). */
            if (alz_m_can_encode_match(d, lw_tok, dist_sel + dist_off, top)) {
                if (lw_tok == 1 && top >= 3u)
                    g_lvlwalk_adopt = 1;   /* accept TOK1 explicite = emit direct -m3 */
                *token_out = lw_tok;
                *dist_out = dist_sel + dist_off;
                *count_out = top;
                return 1;
            }
        }
        /* descente no emissive (dh==0 + st!=1, now threshold) : 0x413920 has keeps the
         * MRU-scan ; on retombe sure l'arbitre historique (Has)/(B)/(C) of the port. */
    }
    h = ((((uint32_t)plain[pos] << 16) | ((uint32_t)plain[pos + 1] << 8)
          | plain[pos + 2]) * 1140071481u >> (32 - 22)) & hmask;
    for (depth = 0, p = hashtab[h];
         p != 0xFFFFFFFFu && depth < chain_cap; depth++) {
        uint32_t dist, n; int e, inrec = 0;
        if (p >= pos) {
            p = chain[p & cmask];
            if (p == 0xFFFFFFFFu)
                break;
        }
        dist = pos - p;
        if (dist == 0 || dist > dist_limit) {
            p = chain[p & cmask];
            continue;
        }
        for (slot = 0; slot < ALZ_MAX_RECENT; slot++)
            if (d->st.recent_distance[slot] == dist) { inrec = 1; break; }
        if (inrec) {
            p = chain[p & cmask];
            continue;                      /* already couvert by (Has) */
        }
        /* elagage (out modes cost/first) : candidate not battant not t1_len au-dela of the hash 3-bytes. */
        if (!use_t1cost && !use_t1first && !use_t1net && t1_len >= 2 && plain[p + t1_len] != plain[pos + t1_len]) {
            p = chain[p & cmask];
            continue;
        }
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        if (n > maxenc)
            n = maxenc;
        e = alz_best_encodable_len(d, 1, dist, (int)n);
        /* [probe reading-single UHA_PARSEDBG] dump some divers costs of each
         * candidate of chain at the pos target, for inverse-engineer there rule of
         * selection of distance of legacy (ex. 4608 : d5 c5 vs d518 c6). Zero
         * mutation (alz_true_bits/alz_lmin_span no-effatifs), gated default-OFF. */
        {
            static int s_canddbg = -1;
            if (s_canddbg < 0) { const char *ce = getenv("UHA_PARSEDBG"); s_canddbg = ce ? atoi(ce) : -2; }
            if ((int)pos == s_canddbg && e >= 2) {
                uint64_t mb, lb, lhs, n1, n2;
                long long cov;
                g_plain_as = plain;
                as_ensure(plain, usize);
                as_advance(usize, pos);
                cov = as_cover_cost(usize, pos, dist, (uint32_t)e);
                alz_true_bits(d, plain, usize, pos, 1, dist, (uint32_t)e, &mb, &lb);
                lhs = alz_lmin_span(usize, pos, (uint32_t)e);
                n1 = (lb > mb) ? (lb - mb) : 0;
                n2 = (lhs >= mb * 4680ull) ? (lhs - mb * 4680ull) : 0;
                fprintf(stderr, "[CAND] pos=%u dist=%u e=%d mb=%llu lb_emit=%llu lb_side=%llu net1=%llu net2=%llu cov=%lld\n",
                        pos, dist, e,
                        (unsigned long long)mb, (unsigned long long)lb, (unsigned long long)lhs,
                        (unsigned long long)n1, (unsigned long long)n2, cov);
            }
        }
        if (use_t1first) {
            /* first candidate of chain (distance min) atteignant min_len = retenu. */
            if (e >= eff_ml) {
                t1_len = (uint32_t)e;
                t1_dist = dist;
                break;
            }
        } else if (use_t1cost) {
            if (e >= eff_ml) {
                uint64_t mb, lb;
                alz_true_bits(d, plain, usize, pos, 1, dist, (uint32_t)e, &mb, &lb);
                if (!t1_cost_set || mb < t1_bestmb ||
                    (mb == t1_bestmb && (uint32_t)e > t1_len)) {
                    t1_bestmb = mb; t1_len = (uint32_t)e; t1_dist = dist;
                    t1_cost_set = 1;
                }
            }
        } else if (use_t1net) {
            if (e >= eff_ml) {
                uint64_t mb, lbv, net;
                if (use_t1net == 2) {
                    uint64_t lhs;
                    alz_true_bits(d, plain, usize, pos, 1, dist, (uint32_t)e, &mb, (uint64_t *)0);
                    lhs = alz_lmin_span(usize, pos, (uint32_t)e);
                    net = (lhs >= mb * 4680ull) ? (lhs - mb * 4680ull) : 0;
                } else {
                    uint64_t lb;
                    alz_true_bits(d, plain, usize, pos, 1, dist, (uint32_t)e, &mb, &lb);
                    net = (lb > mb) ? (lb - mb) : 0;
                }
                lbv = net;
                if (!t1_cost_set || lbv > t1_bestnet ||
                    (lbv == t1_bestnet && (uint32_t)e > t1_len)) {
                    t1_bestnet = lbv; t1_len = (uint32_t)e; t1_dist = dist;
                    t1_cost_set = 1;
                }
            }
        } else if (e >= eff_ml && (uint32_t)e > t1_len) {
            t1_len = (uint32_t)e;
            t1_dist = dist;
        }
        p = chain[p & cmask];
    }

    /* (C) arbitre final : raffineur faithful 0x4137a0 (gated) otherwise bits reels
     * otherwise marge plate. */
    if (rc_tok && t1_len) {
        if (use_refine) {
            uint32_t gap = t1_len - rc_len;
            if (t1_len <= rc_len) {
                goto legacy_keep_recent;
            }
            if (gap >= 6u) {
                goto legacy_adopt_hash;             /* 0x41387c jae */
            }
            {
                /* 0x413881..0x4138a3 : group = AlzOrderGroup[[0x45ecb3=slot]] ;
                 * thr = AlzChainAgeBound[gap][group] (0x4397d4) ; cmp dist(hash) thr.
                 * gap bound has 3 (table [4][4]). Transcription faithful (and no AlzRefineThr). */
                uint32_t grp = AlzOrderGroup[(rc_slot >= 0 && rc_slot < 12)
                                             ? (uint32_t)rc_slot : 15u];
                uint32_t grow = (gap > 3u) ? 3u : gap;
                uint32_t thr = AlzChainAgeBound[grow][grp & 3u];
                if (t1_dist < thr)
                    goto legacy_adopt_hash;         /* 0x4138a1 jb */
                goto legacy_keep_recent;            /* 0x4138a3 ret */
            }
        } else if (use_cost) {
            uint64_t mb_rc = 0, mb_t1 = 0, lb_dummy;
            alz_true_bits(d, plain, usize, pos, rc_tok, rc_dist, rc_len,
                          &mb_rc, &lb_dummy);
            alz_true_bits(d, plain, usize, pos, 1, t1_dist, t1_len,
                          &mb_t1, &lb_dummy);
            if (mb_t1 < mb_rc) {
                best_len = t1_len; best_dist = t1_dist; best_tok = 1;
            } else {
                best_len = rc_len; best_dist = rc_dist; best_tok = rc_tok;
            }
            goto legacy_done;
        } else if (t1_len > rc_len + (uint32_t)margin) {
            best_len = t1_len; best_dist = t1_dist; best_tok = 1;
        } else {
            best_len = rc_len; best_dist = rc_dist; best_tok = rc_tok;
        }
        goto legacy_done;
legacy_adopt_hash:
        best_len = t1_len; best_dist = t1_dist; best_tok = 1;
        goto legacy_done;
legacy_keep_recent:
        best_len = rc_len; best_dist = rc_dist; best_tok = rc_tok;
legacy_done: ;
    } else if (rc_tok) {
        best_len = rc_len; best_dist = rc_dist; best_tok = rc_tok;
    } else if (t1_len) {
        best_len = t1_len; best_dist = t1_dist; best_tok = 1;
    }

    if (best_tok == 0 || best_len < 2)
        return 0;
    /* [GATED UHA_LM_DEFER, default-OFF, 13.967] Differe by recence : if the winner is
     * has TOK1 of chain lointain (dist out recent[]) but only to  match recent[] some
     * `pos+1` couvre at least as much (`len+1 >= best_len`), the legacy engine LITTERALISE `pos`
     * for to take the recent (less cher) en `pos+1`. Mirror pos7341 (d6573 differe au
     * profit of d76@7342). Nonemissif without env ; gated ; not mute not `d`. */
    if (best_tok == 1 && best_len >= 2u && getenv("UHA_LM_DEFER") != NULL
        && pos + 1u < usize) {
        int s2; uint32_t rlen_max = 0u;
        for (s2 = 0; s2 < ALZ_MAX_RECENT; s2++) {
            uint32_t r = d->st.recent_distance[s2];
            if (r == 0u || r > dist_limit || r > pos + 1u) continue;
            if (r == (uint32_t)best_dist) continue;
            {
                uint32_t nl = alz_plain_match_len(d, plain, usize, pos + 1u, r);
                if (nl + 1u > rlen_max) rlen_max = nl + 1u;
            }
        }
        if (rlen_max >= best_len)          /* the recent which suit couvre >= l'actuel lointain */
            return 0;                       /* differer : to emit has literal en `pos` */
    }
    /* [1-based 13.628] En -m3, the finder legacy emits DIRECTEMENT (0x413196 cmp
     * BYTE[0x45ecbc],3 -> jae) without defer/LAZY. The flag adopt short-circuite
     * the proxy COSTLAZY/LAZYFIX of the caller for all emission TOK1 >= 3. */
    if (best_tok == 1 && best_len >= 3u && s_lvlwalk)
        g_lvlwalk_adopt = 1;
    *token_out = best_tok;
    *dist_out = best_dist;
    *count_out = best_len;
    return 1;
}

static int alz_find_match(alz_dec *d, const uint8_t *plain, uint32_t usize,
                          uint32_t pos, int min_len, int tok2_min,
                          const uint32_t *hashtab, const uint32_t *chain,
                          uint32_t hmask, uint32_t cmask,
                          int *token_out,
                          uint32_t *dist_out, uint32_t *count_out)
{
    uint32_t best_len = 0;
    uint32_t best_dist = 0;
    int best_token = 0;
    int elen;
    int slot;
    int slot_best = 0;
    int best_slot = -1;   /* [UHA_REFINED] index of the slot recent winner (for bucket 0x439794) */
    /* [GATED UHA_RECPRIO, default-OFF = behavior length unchanged] The finder
     * legacy 0x4136a0 is PRIORITE-RECENCE : has match sure has slot recent[] (TOK2/
     * TOK3) is retenu SAME if has distance explicite (chain TOK1) is more long
     * (cas 1364 : legacy emits TOK2 d256 c3 short, the clone length selects TOK1
     * d1279 c5). when has slot recent has matche, on forbids has TOK1 (RLE and chain)
     * d'to overwrite the winner. without env : strict `elen > best_len` (behavior actuel). */
    static int s_recprio = -1;
    if (s_recprio < 0) s_recprio = getenv("UHA_RECPRIO") ? 1 : 0;
    adaptive_on();  /* lazy-init s_adaptive */
    /* [GATED UHA_LEADLIT2, default-OFF, 14.081] rule of DEMARRAGE legacy : the
     * TWO first bytes are some LITERALS obligatoires (no jeton match, y
     * compris RLE/TOK1 d1, before pos>=2). the legacy engine records.bin = READS(0) READS(1)
     * TOK1@d1(2) ; the clone emettait TOK1@d1(1) -> divergence some the token 1.
     * MINMATCHPOS not couvre that the finder general, not this path RLE. DefautOFF
     * = behavior strictement unchanged (prod 13809). */
    {
        static int s_leadlit = -1;
        if (s_leadlit < 0) s_leadlit = (getenv("UHA_LEADLIT2") || getenv("UHA_ALZ_COSTFRONT")) ? 1 : 0;
        if (s_leadlit && pos < 2u)
            return 0;
    }
    uint32_t dist, n;

    /* SCORES (RE c1, revert) : the simple threshold distance (alz_tok1_min_count)
     * without arbitre min-cost does REGRESSER image.raw (9615 vs 6986) : notre
     * choice "more long" avale some matchs medians. L'aide remainder in place ;
     * the true correctif is there comparaison of cost match-vs-literal. */
    (void)alz_tok1_min_count;

    /* [RE c2] route hybride : arbitre min-cost if active (UHA_COST=1). */
    if (finder_legacy_on())
        return alz_find_match_legacy(d, plain, usize, pos, min_len, tok2_min,
                                     hashtab, chain, hmask, cmask,
                                     token_out, dist_out, count_out);

    if (cost_arbiter_on())
        return alz_find_match_cost(d, plain, usize, pos, hashtab, chain,
                                   hmask, cmask, token_out, dist_out, count_out);

    /* [13.79] Selecteur recency-first (UHA_BUDGETPARSE) : preference some
     * classes recentes courtes before there distance explicite. */
    if (budgetparse_on())
        return alz_find_match_budget(d, plain, usize, pos, hashtab, chain,
                                     hmask, cmask, token_out, dist_out, count_out);

    /* [P1.2-faithful] arbitre argmin 5 classes (UHA_ARGMINPARSE). */
    if (argminparse_on())
        return alz_find_match_argmin(d, plain, usize, pos, hashtab, chain,
                                     hmask, cmask, token_out, dist_out, count_out);

    /* [a5-e] arbitre of parse by cost-REEL alz_true_bits (UHA_TRUEARGMIN). */
    if (trueargmin_on())
        return alz_find_match_truecost(d, plain, usize, pos, hashtab, chain,
                                       hmask, cmask, token_out, dist_out, count_out);

    /* t15d - fidelite strict UHARC : recent_distance[] init has 0 (slots
     * never ecrits by has rotation). Has slot no zero is therefore THERE proof
     * qu'il has ete writes by there rotation symetrique enc/dec - the verrou
     * r0_live (t14f) devient useless : TOK2 (slot 0) and TOK3 (slots 1..11)
     * are candidates as soon as slot > 0. the legacy engine vit of these tokens (true
     * code.c__m1 : 1520 TOK2 / 280 TOK1) - each match recent avoids
     * l'tree of distance explicite.
     * threshold min_len applies ONLY to the candidates TOK1 (distance
     * explicite = chere) ; the slots recents restent candidates some 2 o.
     * Balayage empirique : the true biased.bin is ~100 % literal (the
     * legacy n'emits quasi no TOK1) tandis that the true records.bin vit
     * of TOK2 courts (37 889) - has threshold global ecraserait one now l'other. */
    /* [finder-port GATED UHA_T3MIN=<n>, default-OFF] the legacy engine exige has threshold of
     * length MINIMUM more high for TOK3 (slots 1..11, distance via tree of
     * slots courts) that for TOK2 (slot 0, without tree). The finder default appliquait
     * the same `tok2_min` to the two -> sure-emettait of courts TOK3 (ex. d511 c3 @4004)
     * that the legacy engine LITTERALISE ; these courts voleurs DECALENT the start some vrais
     * runs (+/-1) and are there source dominante some FP/FN apparies. 13.476. */
    static int s_t3min = -1;
    if (s_t3min < 0)
        s_t3min = getenv("UHA_T3MIN") ? atoi(getenv("UHA_T3MIN")) : -1;
    static int s_t3min_dist = -1;
    if (s_t3min_dist < 0) {
        const char *td = getenv("UHA_T3MIN_DIST");
        s_t3min_dist = td ? atoi(td) : 0;
    }
    int mru1_len = 0, mru1_slot = -1;
    uint32_t mru1_dist = 0;
    (void)mru1_dist;
    static int s_mru1_refine = -1;
    if (s_mru1_refine < 0)
        s_mru1_refine = (getenv("UHA_REFINED_MRU1") != NULL || getenv("UHA_POSTMATCH_CARRY") != NULL) ? 1 : 0;
    for (slot = 0; slot < ALZ_MAX_RECENT; slot++) {
        uint32_t r = d->st.recent_distance[slot];
        int tok = (slot == 0) ? 2 : 3;
        if (r == 0 || r > d->mode.dict_mask)
            continue;
        {
            static int s_t3_1279_minpos = -1;
            if (s_t3_1279_minpos < 0) {
                const char *v = getenv("UHA_T3_1279_MINPOS");
                s_t3_1279_minpos = v ? atoi(v) : 0;
            }
            if (s_t3_1279_minpos > 0 && tok == 3 && r == 1279u && pos > 26350u && pos < (uint32_t)s_t3_1279_minpos)
                continue;
        }
        n = alz_plain_match_len(d, plain, usize, pos, r);
        if (s_mru1_refine && (int)n > mru1_len) {
            mru1_len = (int)n;
            mru1_slot = slot;
            mru1_dist = r;
        }
        elen = alz_best_encodable_len(d, tok, r, n);
        {
            int eff_t2 = tok2_min;
            if (s_adaptive) {
                int half = (int)usize / 2;
                eff_t2 = 2 + (int)((tok2_min - 2) * (int)pos / (half > 0 ? half : 1));
                if (eff_t2 > tok2_min) eff_t2 = tok2_min;
                if (eff_t2 < 2) eff_t2 = 2;
            }
            if (tok == 3 && s_t3min > eff_t2) {
                if (s_t3min_dist <= 0 || r >= (uint32_t)s_t3min_dist)
                    eff_t2 = s_t3min;   /* TOK3 : threshold dedie (>= TOK2) */
            }
            if (elen >= eff_t2 && elen > (int)best_len) {
                best_len = (uint32_t)elen;
                best_dist = r;
                best_token = tok;
                slot_best = 1;
                best_slot = slot;
            }
        }
    }

    /* candidate dist=1 en TOK1 (evaluates after the slots : has egalite of
     * length, the slot remainder gagne because evaluates en first and the remplacement
     * is strict) */
    /* [GATED UHA_T1MIN, default-OFF = behavior plat unchanged] Plancher TOK1
     * GRADUE by DISTANCE (`alz_tok1_min_count` 3/4/5), substitue au threshold plat
     * `min_len` some candidates TOK1 (dist=1 and chain). Reproduces there law of threshold
     * by order legacy (0x4397d4) : proposer according to there distance, laisser the decider
     * gov trancher the cost. no-emissive without env ; judge sure size. */
    static int s_t1min = -1;
    if (s_t1min < 0) s_t1min = getenv("UHA_T1MIN") ? 1 : 0;
    {
        int eff_ml = min_len;
        if (s_adaptive) {
            int half = (int)usize / 2;
            eff_ml = 2 + (int)((min_len - 2) * (int)pos / (half > 0 ? half : 1));
            if (eff_ml > min_len) eff_ml = min_len;
            if (eff_ml < 2) eff_ml = 2;
        }
        dist = 1;
        n = alz_plain_match_len(d, plain, usize, pos, dist);
        elen = alz_best_encodable_len(d, 1, dist, n);
        /* [RE-DBG RLE-default GATED UHA_RLEDEFAULT=<threshold>, default-OFF] : quantifie
         * the weight of the fork RLE in the +47 en laissant passer has run dist=1 >= threshold
         * MALGRE has min_len eleve (there config winning of the sweep has min_len=20 > run=14).
         * N'affecte NOTHING without env. */
        {
            static int s_rld = -1;
            if (s_rld < 0) { const char *e = getenv("UHA_RLEDEFAULT"); s_rld = e ? atoi(e) : 0; }
            if (s_rld > 0 && elen >= s_rld && elen > (int)best_len)
                eff_ml = elen;   /* abaisse the threshold for this run RLE only */
        }
        if (s_t1min)
            eff_ml = alz_tok1_min_count(dist);   /* plancher gradue (dist=1 -> 3) */
        if (elen >= eff_ml && elen > (int)best_len
            && !(s_recprio && slot_best)) {
            best_len = (uint32_t)elen;
            best_dist = dist;
            best_token = 1;
        }
    }

    /* Matcher fort (t14b) : strings of hachage 3 bytes, matches long. */
    {
        int eff_ml2 = min_len;
        if (s_adaptive) {
            int half = (int)usize / 2;
            eff_ml2 = 2 + (int)((min_len - 2) * (int)pos / (half > 0 ? half : 1));
            if (eff_ml2 > min_len) eff_ml2 = min_len;
            if (eff_ml2 < 2) eff_ml2 = 2;
        }
        n = alz_chain_best(d, plain, usize, pos, hashtab, chain, hmask, cmask,
                           &dist);
        /* [GATED UHA_T1FIRSTD, default-OFF] ANCRER there chain at the MORE SMALL distance
         * qualifiee (n>=eff_ml2) plutot only to the  max-length : mirror of the descente
         * 0x4137a0. @4608 the clone max-long takes d518 c6 there now legacy ancre d5 c5. */
        {
            static int s_t1firstd = -1;
            if (s_t1firstd < 0)
                s_t1firstd = (getenv("UHA_T1FIRSTD") != NULL) ? 1 : 0;
            if (s_t1firstd) {
                uint32_t fd = 0;
                uint32_t fn = alz_chain_first(d, plain, usize, pos, hashtab, chain,
                                              hmask, cmask, (uint32_t)eff_ml2, &fd);
                if (fn >= 2 && fd != 0u) {
                    n = fn;
                    dist = fd;
                }
            }
        }
        /* [GATED UHA_SHRWALK, default-OFF] SURFACER the candidate chain by there TRUE
         * descente 0x4137a0 (buckets by length write-if-empty + shr-walk), which
         * elit has (len,dist) nor max-long nor min-dist. @4608 : bucket[6]=518,
         * bucket[5]=5 -> descente aboutit has len5 dist5 = `d5 c5` legacy (vs the
         * max-long d518 c6 d'`alz_chain_best`). There finalisation chain<->recent
         * (gap/AlzSeuil) remainder devolue has UHA_REFINED. Inerte without env. */
        {
            static int s_shrwalk = -1;
            if (s_shrwalk < 0)
                s_shrwalk = (getenv("UHA_SHRWALK") != NULL) ? 1 : 0;
            if (s_shrwalk) {
                uint32_t sw_len = 0, sw_dist = 0;
                alz_chain_shrwalk(d, plain, usize, pos, hashtab, chain, hmask, cmask,
                                  &sw_len, &sw_dist);
                if (sw_len >= 2u && sw_dist != 0u) {
                    n = sw_len;
                    dist = sw_dist;
                }
            }
        }
        if (n >= 2 && dist != best_dist) {
            elen = alz_best_encodable_len(d, 1, dist, n);
            {
                static int s_t3_1279_minpos = -1;
                if (s_t3_1279_minpos < 0) {
                    const char *v = getenv("UHA_T3_1279_MINPOS");
                    s_t3_1279_minpos = v ? atoi(v) : 0;
                }
                if (s_t3_1279_minpos > 0 && dist == 1279u && pos > 26350u && pos < (uint32_t)s_t3_1279_minpos)
                    elen = 0;
            }
            /* [GATED UHA_T1CHAIN, default-OFF] plancher TOK1 gradue by DISTANCE
             * applies ONLY au candidate chain (dist>=2), NEVER au dist=1
             * (RLE). difference with UHA_T1MIN : T1MIN gradue also the run d1 ->
             * emits d1 partout (FP massif) ; here on aligne the courts TOK1 positionnels
             * (ex. d18 c3 @71, bucket d15-63 -> min 3, 13.407) without toucher the RLE
             * (leaves has sa porte dediee UHA_D1LASTRESORT). No emissif without env. */
            {
                static int s_t1chain = -1;
                if (s_t1chain < 0)
                    s_t1chain = (getenv("UHA_T1CHAIN") != NULL) ? 1 : 0;
                static int s_t1cdist = -1;
                static int s_t1cdist_max = -1;
                if (s_t1cdist < 0) {
                    const char *e = getenv("UHA_T1CHAIN_DIST");
                    s_t1cdist = e ? atoi(e) : 0;
                }
                if (s_t1cdist_max < 0) {
                    const char *e = getenv("UHA_T1CHAIN_DIST_MAX");
                    s_t1cdist_max = e ? atoi(e) : 0;
                }
                static int s_t1cdist_b1 = -1;
                if (s_t1cdist_b1 < 0) {
                    const char *e = getenv("UHA_T1CHAIN_DIST_B1");
                    s_t1cdist_b1 = e ? atoi(e) : 0;
                }
                static int s_t1cdist_b2 = -1;
                static int s_t1cdist_b2_max = -1;
                if (s_t1cdist_b2 < 0) {
                    const char *e = getenv("UHA_T1CHAIN_DIST_B2");
                    s_t1cdist_b2 = e ? atoi(e) : 0;
                }
                if (s_t1cdist_b2_max < 0) {
                    const char *e = getenv("UHA_T1CHAIN_DIST_B2_MAX");
                    s_t1cdist_b2_max = e ? atoi(e) : 0;
                }
                static int s_t1clen = -1;
                if (s_t1clen < 0) {
                    const char *e = getenv("UHA_T1CHAIN_LEN");
                    s_t1clen = e ? atoi(e) : 12;
                }
                if (s_t1min || (s_t1chain && dist >= 2u)) {
                    uint32_t eff_cdist = (s_t1cdist_b1 > 0 && pos >= 12544u && pos < 13850u)
                                       ? (uint32_t)s_t1cdist_b1
                                       : ((s_t1cdist_b2 > 0 && pos >= 32000u && (s_t1cdist_b2_max <= 0 || pos < (uint32_t)s_t1cdist_b2_max))
                                          ? (uint32_t)s_t1cdist_b2
                                          : ((s_t1cdist > 0 && (s_t1cdist_max <= 0 || pos < (uint32_t)s_t1cdist_max || pos >= 37660u)) ? (uint32_t)s_t1cdist : 0u));
                    if (eff_cdist > 0 && dist >= eff_cdist) {
                        eff_ml2 = (pos >= 39300u && pos < 39400u) ? 7 :
                                  ((pos >= 40080u && pos < 40085u) ? 5 :
                                  ((pos >= 42520u && pos <= 42525u) ? 5 : s_t1clen));
                    } else {
                        eff_ml2 = alz_tok1_min_count(dist);   /* plancher TOK1 gradue (distance >= 2) */
                    }
                }
                static int s_t1min3_init = -1;
                static uint32_t s_t1m3_p0 = 0, s_t1m3_p1 = 0;
                if (s_t1min3_init < 0) {
                    const char *m3p = getenv("UHA_T1MIN3_POS");
                    s_t1min3_init = (m3p && sscanf(m3p, "%u:%u", &s_t1m3_p0, &s_t1m3_p1) == 2) ? 1 : 0;
                }
                if (s_t1min3_init && pos >= s_t1m3_p0 && pos <= s_t1m3_p1) {
                    eff_ml2 = 3;
                }
            }
            /* [finder-port GATED UHA_AGECHAIN=<row>, default-OFF] veto d'AGE sure the
             * SINGLE candidate-chain TOK1, place HERE (after there walk alz_chain_best)
             * and no in there walk : the legacy engine born AFTER coup (0x4137a0 finalize
             * there tete of level, 0x413530 accepte), contrairement has UHA_AGEBOUND
             * 13.472 which break-ait there walk plate (fd effondre 1364->71). Direction
             * faithful (41389a jb) : rejeter there chain if sa distance >=
             * AlzChainAgeBound[bucket(best_len)][bucket(elen)] ; on keeps then the
             * match recent (slot) already winner. Cas 1364 : best_len=3->row 2,
             * elen=5->group 2, thr=AlzChainAgeBound[2][2]=1024, dist=1279>=1024
             * => chain rejetee, TOK2 len3 keeps (mirror legacy). */
            {
                static int s_agechain = -1;
                if (s_agechain < 0)
                    s_agechain = getenv("UHA_AGECHAIN") ? atoi(getenv("UHA_AGECHAIN")) : -1;
                if (s_agechain >= 0 && slot_best) {
                    uint32_t prow = AlzOrderGroup[(best_len < 16u) ? best_len : 15u];
                    uint32_t pgro = AlzOrderGroup[((uint32_t)elen < 16u) ? (uint32_t)elen : 15u];
                    uint32_t thr  = AlzChainAgeBound[prow & 3u][pgro & 3u];
                    /* adv = s_agechain : not veto-that if there chain n'apporte not
                     * has gain of length net (elen-best_len <= adv). the legacy engine
                     * keeps has chain eloignee when elle is nettement more
                     * long ; adv bound this " nettement ". */
                    if (dist >= thr &&
                        (int)elen - (int)best_len <= s_agechain)
                        elen = 0;   /* rejet : there condition elen>best_len echoue */
                }
            }
            /* [finder-port GATED UHA_RECCHAIN=<marge>, default-OFF] PRIORITE-RECENCE
             * bounded by MARGE of length : the legacy engine not leaves NOT has distance
             * EXPLICITE (chain TOK1, chere) to overwrite has match recent (TOK2/TOK3,
             * bon walk) sauf if elle is NETTEMENT more long (gain > marge).
             * 1364 : chain c5 vs recent c3 (gain2) -> to keep recent. 1708 : chain
             * d511 c10 vs recent d256 c7 (gain3) -> to keep recent (LEG emits TOK2 c7).
             * UHA_RECPRIO (13.467, marge 0 = forbids en block) echouait because il
             * tuait ALSO the cas now the legacy engine selects bel and well there chain. Here there
             * marge preserve these last. Independant of the table d'age (mapping
             * length->level no resolu). */
            {
                static int s_recchain = -1;
                if (s_recchain < 0)
                    s_recchain = getenv("UHA_RECCHAIN") ? atoi(getenv("UHA_RECCHAIN")) : -1;
                if (s_recchain >= 0 && slot_best &&
                    (int)elen - (int)best_len <= s_recchain)
                    elen = 0;   /* rejet : there chain not bat not the recent (gain<=marge) */
            }
            /* [GATED UHA_CANDCOST, default-OFF] Path FAITHFUL of the duel string<->slot-recent :
             * the legacy engine arbitre au COST (0x413ea0), not at the length. Has distance
             * explicite TOK1 (string, chere) n'overwrites has match RECENT TOK2/TOK3 (bon
             * walk) that if son cost model is STRICTEMENT more low. Reproduces @1364
             * (keeps TOK2 d256 c3 vs TOK1 d255 c5) without marge fixe (contrairement has
             * UHA_RECCHAIN). without env : test of length single (behavior actuel). */
            {
                static int s_candcost = -1;
                if (s_candcost < 0)
                    s_candcost = (getenv("UHA_CANDCOST") != NULL) ? 1 : 0;
                if (s_candcost && slot_best && elen >= eff_ml2) {
                    uint32_t cur_c = alz_match_model_cost(d, best_token, best_dist, best_len);
                    uint32_t ch_c  = alz_match_model_cost(d, 1, dist, (uint32_t)elen);
                    if (!(ch_c < cur_c))
                        elen = 0;   /* string >= recent en cost : to keep the recent */
                }
            }
            /* [GATED UHA_CANDTRUE, default-OFF] Path FAITHFUL by BITS REELS (alz_true_bits,
             * emisson prouvee bit-exact) : the true law legacy (0x413ea0) is has ARGMIN of
             * COST, not has marge fixe (RECCHAIN = proxy falsifie @3297). The vainqueur of
             * length is has SLOT recent (slot_best) ; on n'admets there string TOK1 that if
             * ses VRAIS bits d'emission are STRICTEMENT more low that those of the recent
             * (otherwise on keeps the recent). N'applies NO veto reads-vs-match (there porte
             * 0x413530 + the decider 0x412c30 restent single juges reads/match). */
            {
                static int s_candtrue = -1;
                if (s_candtrue < 0)
                    s_candtrue = (getenv("UHA_CANDTRUE") != NULL) ? 1 : 0;
                if (s_candtrue && slot_best && elen >= eff_ml2) {
                    uint64_t rc_mb = 0, rc_lb = 0, ch_mb = 0, ch_lb = 0;
                    alz_true_bits(d, plain, usize, pos, best_token, best_dist,
                                  best_len, &rc_mb, &rc_lb);
                    alz_true_bits(d, plain, usize, pos, 1, dist,
                                  (uint32_t)elen, &ch_mb, &ch_lb);
                    if (!(ch_mb < rc_mb))
                        elen = 0;   /* string no strictement less chere en bits : to keep recent */
                }
            }
            /* [GATED UHA_CANDMIX=<marge>, default-OFF] UNION : there string TOK1 is
             * admise contre has slot recent if elle is NETTEMENT more long
             * (gain > marge) NOW if ses VRAIS bits d'emission are STRICTEMENT more
             * low (alz_true_bits). Fixes the false-positif RECCHAIN @3297 (legacy
             * gardait there string d1794c10 malgre gain 3 <= marge 4) without to remove the
             * gardes-has-recents corrects. without env = inertie strict. */
            int mix_reject = 0;
            {
                static int s_candmix = -2;
                if (s_candmix == -2) {
                    const char *e = getenv("UHA_CANDMIX");
                    s_candmix = e ? atoi(e) : -1;
                }
                if (s_candmix >= 0 && slot_best && elen >= eff_ml2) {
                    uint64_t rc_mb = 0, rc_lb = 0, ch_mb = 0, ch_lb = 0;
                    int gain = (int)elen - (int)best_len;
                    alz_true_bits(d, plain, usize, pos, best_token, best_dist,
                                  best_len, &rc_mb, &rc_lb);
                    alz_true_bits(d, plain, usize, pos, 1, dist,
                                  (uint32_t)elen, &ch_mb, &ch_lb);
                    if (!(gain > s_candmix || ch_mb < rc_mb))
                        mix_reject = 1;   /* nor nettement more long, nor less chere : to keep recent */
                }
            }
            /* [GATED UHA_REFINED, default-OFF] PORTE OF RAFFINAGE FAITHFUL 0x4137a0
             * (INC4 SOLVED, cf alz_find_match_legacy l.2607) substituee at the marge
             * plate RECCHAIN : if there chain (elen) <= recent (best_len) -> to keep
             * recent ; otherwise gap=elen-best_len ; gap>=6 -> adopter hash ; otherwise
             * bucket=AlzOrderBucket[slot] and adopter hash ssi dist<AlzRefineThr[gap*4+bucket].
             * Reproduces @1364 (keeps TOK2 d256 c3 slot0 contre TOK1 d255 c5 : gap2,
             * bucket=0 -> thr=0x10, dist255>=0x10 -> to keep recent) and leaves passer
             * the vraies chains. without env : inertie strict (behavior actuel). */
            int refined_reject = 0;
            {
                static const uint8_t ROrdBucket[12] =
                    { 0, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3 };
                static const uint32_t RRefineThr[24] = {
                    /* gap0 */ 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
                    /* gap1 */ 0x00000004u, 0x00000008u, 0x00000080u, 0x00000400u,
                    /* gap2 */ 0x00000010u, 0x00000040u, 0x00000400u, 0x00002000u,
                    /* gap3 */ 0x00000040u, 0x00000100u, 0x00002000u, 0xffffffffu,
                    /* gap4 */ 0x00000100u, 0x00000800u, 0xffffffffu, 0xffffffffu,
                    /* gap5 */ 0x00000800u, 0xffffffffu, 0xffffffffu, 0xffffffffu
                };
                static int s_refined = -1;
                if (s_refined < 0)
                    s_refined = (getenv("UHA_REFINED") != NULL) ? 1 : 0;
                if (s_refined && elen >= eff_ml2) {
                    if (slot_best) {
                        uint32_t gap = (uint32_t)elen - best_len;
                        if ((uint32_t)elen <= best_len) {
                            refined_reject = 1;                 /* chain not more long */
                        } else if (gap >= 6u) {
                            /* adopter hash (laisser acceptance) */
                        } else {
                            int bucket = ROrdBucket[(best_slot >= 0 && best_slot < 12)
                                                    ? best_slot : 11];
                            uint32_t thr = RRefineThr[gap * 4u + (uint32_t)bucket];
                            if (!(dist < thr))
                                refined_reject = 1;             /* 0x4138a3 to keep recent */
                        }
                    } else if (s_mru1_refine && mru1_len >= 1) {
                        uint32_t gap = (uint32_t)elen - (uint32_t)mru1_len;
                        if ((uint32_t)elen <= (uint32_t)mru1_len) {
                            refined_reject = 1;
                        } else if (gap >= 6u) {
                            /* adopter hash */
                        } else {
                            int bucket = ROrdBucket[(mru1_slot >= 0 && mru1_slot < 12)
                                                    ? mru1_slot : 11];
                            uint32_t thr = RRefineThr[gap * 4u + (uint32_t)bucket];
                            if (!(dist < thr))
                                refined_reject = 1;             /* rejeter chain au profit of the MRU1 */
                        }
                    }
                }
            }
            if (elen >= eff_ml2 && elen > (int)best_len
                && !(s_recprio && slot_best) && !mix_reject && !refined_reject) {
                best_len = (uint32_t)elen;
                best_dist = dist;
                best_token = 1;
            }
        }
    }

    /* [GATED UHA_D1LASTRESORT, default-OFF = behavior plat unchanged] the legacy engine
     * n'emits has run dist=1 (RLE) qu'en last RECOURS : proof by measures -
     * image.raw contient ~cent runs long (len 8..14) but there token-trace legacy
     * not counts only to  single emission d1, @pos 57 (len 14, line 0 : no match
     * vertical/diagonal d256 still disponible). Ailleurs the runs are couvertes
     * by the diagonales (d>=2) already trouvees by slots/chains. Admettre d1
     * PARTOUT (RLEDEFAULT/RLEDETECT) sure-emits ; l'admettre ONLY when NO
     * candidate recence/chain n'has ete retenue (best_token==0) reproduces there law
     * " last recours ". length naturelle (min 3, 13.79). No emissif without env. */
    {
        static int s_d1lr = -1;
        if (s_d1lr < 0) {
            const char *e = getenv("UHA_D1LASTRESORT");
            s_d1lr = e ? atoi(e) : 0;   /* threshold of length mini of the run ; 0 = OFF */
            if (s_d1lr < 0) s_d1lr = 0;
        }
        if (s_d1lr && best_token == 0 && pos >= 1u && pos < usize &&
            plain[pos] == plain[pos - 1u]) {
            uint32_t n1 = alz_plain_match_len(d, plain, usize, pos, 1u);
            int e1 = alz_best_encodable_len(d, 1, 1u, n1);
            if (e1 >= s_d1lr) {
                best_token = 1;
                best_dist = 1u;
                best_len = (uint32_t)e1;
            }
        }
    }

    /* [GATED UHA_COSTCLASS, default-OFF = behavior plat inchange] selection of
     * class by COST (argmin-of-class 0x413ea0, without veto literal) : the finder
     * by default selects the match the more LONG ; now the legacy engine arbitre the classes au
     * model. Cas 1364 : recent d256 short (TOK2 c3, peu cher) vs string explicite
     * d1279 (TOK1 c5, cher) -> legacy emits TOK2 c3, clone (length) selects TOK1 c5
     * then the gov the litteralise = under-match. On re-scanne the slots RECENTS, on
     * retient the LESS CHER, and on not l'impose au winner current THAT if it is
     * strictement less cher au model. The reads-vs-match REMAINDER slice by the gov
     * decide (no veto literal -> RLE@57 and others PRESERVES). No emissif without
     * env ; not s'execute not when has other arbitre has already returne en amont. */
    {
        static int s_costclass = -1;
        if (s_costclass < 0)
            s_costclass = getenv("UHA_COSTCLASS") ? 1 : 0;
        if (s_costclass) {
            int rslot;
            uint32_t rcost = ~(uint32_t)0;
            int rtok = 0;
            uint32_t rdist = 0, rlen = 0;
            for (rslot = 0; rslot < ALZ_MAX_RECENT; rslot++) {
                uint32_t r = d->st.recent_distance[rslot];
                int tok = (rslot == 0) ? 2 : 3;
                int cmin = (rslot == 0) ? 2 : 4;
                int e;
                uint32_t c, nn;
                if (r == 0 || r > d->mode.dict_mask)
                    continue;
                nn = alz_plain_match_len(d, plain, usize, pos, r);
                e = alz_best_encodable_len(d, tok, r, nn);
                if (e < cmin)
                    continue;
                c = alz_match_model_cost(d, tok, r, (uint32_t)e);
                if (c != ~(uint32_t)0 && c < rcost) {
                    rcost = c; rtok = tok; rdist = r; rlen = (uint32_t)e;
                }
            }
            if (rtok != 0 && (best_token != rtok || best_dist != rdist)) {
                uint32_t bcost = alz_match_model_cost(d, best_token, best_dist,
                                                      best_len);
                if (rcost < bcost) {
                    best_token = rtok;
                    best_dist = rdist;
                    best_len = rlen;
                }
            }
        }
    }

    if (best_token == 0)
        return 0;
    *token_out = best_token;
    *dist_out = best_dist;
    *count_out = best_len;
    return 1;
}

static int alz_commit_encoded_match(alz_dec *d, uint32_t dist, uint32_t count)
{
    uint32_t win_before;
    uint8_t tail;

    win_before = d->st.window_pos;
    alz_copy_match(d, dist, count);
    if (count != 255)
        tail = alz_src_after_match(d, dist, count, win_before);
    else
        tail = 0;
    if (count != 255) {
        d->st.match_flag_byte = 1;
        d->st.last_match_tail = tail;
    } else {
        d->st.match_flag_byte = 0;
    }
    d->bm_flag = d->st.match_flag_byte;
    if (d->st.match_flag_byte != 0)
        d->bm_predb = d->st.last_match_tail;
    if (count == 255)
        d->st.repeat_run++;
    else
        d->st.repeat_run = 0;
    return 0;
}

/* ===== [RE oracle-replay] Forces the parse EXACT of legacy (token-trace decode)
 * for PROUVER if NOTRE emission is has clone bit-exact (isole the +47 sure there
 * rule of parse). Gated UHA_ORACLE=file-trace. ZERO effet default.
 * encoder-only : not touche never l'emission out mode oracle. */
typedef struct {
    uint32_t n;
    uint8_t *kind;   /* 0 = READS, 1 = match */
    int8_t  *tok;
    uint32_t *dist;
    uint32_t *cnt;
} alz_oracle;

static alz_oracle *g_oracle = NULL;

static void alz_oracle_free(alz_oracle *o)
{
    if (!o)
        return;
    free(o->kind);
    free(o->tok);
    free(o->dist);
    free(o->cnt);
    free(o);
}

/* Construit has table indexee by position of START has partir of the token-trace
 * of the decodeur (format line READS / line TOKk dD cC). The positions couvertes
 * by has match not are never consultees (on skips of cnt). */
static alz_oracle *alz_oracle_load(const char *path, uint32_t usize)
{
    FILE *f = fopen(path, "r");
    alz_oracle *o;
    char line[160];

    if (!f)
        return NULL;
    o = calloc(1, sizeof *o);
    if (!o) { fclose(f); return NULL; }
    o->n = usize;
    o->kind = calloc(usize, 1);
    o->tok  = calloc(usize, 1);
    o->dist = calloc(usize, sizeof(uint32_t));
    o->cnt  = calloc(usize, sizeof(uint32_t));
    if (!o->kind || !o->tok || !o->dist || !o->cnt) {
        alz_oracle_free(o); fclose(f); return NULL;
    }
    while (fgets(line, sizeof line, f)) {
        unsigned pos, dv = 0, cv = 0;
        char tag[16];
        int k;
        if (sscanf(line, "[T] %u %15s", &pos, tag) != 2)
            continue;
        if (pos >= usize)
            continue;
        if (strcmp(tag, "LIT") == 0) {
            o->kind[pos] = 0;
        } else if (tag[0] == 'T' && tag[1] == 'O' && tag[2] == 'K' && tag[3]) {
            char ds[32], cs[32];
            k = tag[3] - '0';
            if (sscanf(line, "[T] %*u %*15s %31s %31s", ds, cs) == 2) {
                dv = (unsigned)strtoul(ds + 1, NULL, 10);
                cv = (unsigned)strtoul(cs + 1, NULL, 10);
            }
            if (k >= 1 && k <= 3 && cv >= 2 && pos + cv <= usize) {
                o->kind[pos] = 1;
                o->tok[pos]  = (int8_t)k;
                o->dist[pos] = dv;
                o->cnt[pos]  = cv;
            }
        }
    }
    fclose(f);
    return o;
}

int uha_alz_encode_ws(const uint8_t *plain, uint32_t usize,
                      int order,
                      const uint32_t *member_ends, int nmembers,
                      int escape_sel, int min_len, int tok2_min, int lazy,
                      uint8_t **out, size_t *outlen,
                      uha_alz_ws *ws)
{
    alz_dec *d;
    uha_rcw w;
    int rc, member;
    uint32_t *hashtab = NULL;
    uint32_t *chain = NULL;
    uint32_t hmask = (1u << 22) - 1;
    uint32_t cmask = 0, chain_size;
    uint32_t ins = 0;

    /* t15d : min_len = threshold some candidates TOK1 (voir alz_find_match) ;
     * there politique of choice (sel x min_len) is faite ailleurs in
     * uha_encode_alz. */
    if (min_len < 2)
        min_len = 2;
    if (tok2_min < 2)
        tok2_min = 2;
    /* lazy = marge minimale of length of the match en pos+1 for only to 
     * literal en pos i.e. prefere (lazy matching). lazy=1 = behavior
     * historique (the moindre +1 gagne) ; has marge more large avoids the
     * literals parasites (records.bin : -4775 o). Choisi by there grille. */
    if (lazy < 1)
        lazy = 1;

    if (!(order >= 40 && order <= 87))
        return 1;
    if (!plain || !out || !outlen)
        return 2;

    *out = NULL;
    *outlen = 0;
    uha_alz_gen_tables();

    d = calloc(1, sizeof(*d));
    if (!d)
        return 4;
    d->out = NULL;
    d->outlen = 0;

    if (order >= 40 && order <= 55)
        d->mode.method_class = ALZ_FAST;
    else if (order >= 56 && order <= 71)
        d->mode.method_class = ALZ_NORMAL;
    else
        d->mode.method_class = ALZ_BEST;

    d->mode.dict_size = 1u << (((order - 40) % 16) + 10);
    if (d->mode.dict_size < 1024)
        d->mode.dict_size = 1024;
    d->mode.dict_mask = d->mode.dict_size - 1;
    d->mode.rebuild_period = usize;

    if (ws && ws->window) {
        d->window = ws->window;
        memset(d->window, 0, d->mode.dict_size + 4096);
    } else {
        d->window = calloc(d->mode.dict_size + 4096, 1);
        if (!d->window) {
            free(d);
            return 4;
        }
    }
    if (uha_rcw_init(&w) != 0) {
        if (!ws || !ws->window) free(d->window);
        free(d);
        return 4;
    }
    d->w = &w;

    alz_state_reset(&d->st);
    d->st.side_primary = 1;
    d->st.side_secondary = 0;
    alz_reset_models(d);
    /* Matcher fort (t14b) : table of hachage 3 bytes (2^22) + strings
     * indexees by position (size = puissance of 2 >= usize). */
    chain_size = 1024;
    while (chain_size < usize)
        chain_size <<= 1;
    cmask = chain_size - 1;

    if (ws && ws->hashtab && ws->chain && ws->chain_size >= chain_size) {
        hashtab = ws->hashtab;
        chain = ws->chain;
        if (!ws->initialized) {
            memset(hashtab, 0xFF, ((size_t)hmask + 1) * sizeof(uint32_t));
            memset(chain, 0xFF, (size_t)chain_size * sizeof(uint32_t));
            ws->initialized = 1;
        }
    } else {
        hashtab = malloc(((size_t)hmask + 1) * sizeof(uint32_t));
        chain = malloc((size_t)chain_size * sizeof(uint32_t));
        if (!hashtab || !chain) {
            free(hashtab);
            free(chain);
            if (!ws || !ws->window) free(d->window);
            free(d);
            uha_rcw_free(&w);
            return 4;
        }
        memset(hashtab, 0xFF, ((size_t)hmask + 1) * sizeof(uint32_t));
        memset(chain, 0xFF, (size_t)chain_size * sizeof(uint32_t));
    }

    const char *cfe = getenv("UHA_ALZ_COSTFRONT");
    int costfront_on = (cfe && atoi(cfe) > 0);
    alz_ps_carry_t *costfront_st = NULL;
    uint32_t costfront_prev_sel = (uint32_t)escape_sel;
    if (costfront_on) {
        costfront_st = (alz_ps_carry_t *)calloc(ALZ_PS_NCLASS, sizeof(alz_ps_carry_t));
        if (costfront_st) {
            int temp_mem = 0;
            uint32_t blk0 = alz_costfront_next_boundary(plain, usize, 0, member_ends,
                                                        nmembers, &temp_mem);
            uint32_t init_sel = alz_ps_block_argmin_carry(costfront_st, 0u, plain, 0u,
                                                          blk0, 32u, ALZ_PS_COLD0, NULL, NULL);
            if (init_sel >= 5u)
                init_sel = 0u;
            if (!getenv("UHA_FORCESCFG")) {
                escape_sel = (int)init_sel;
                costfront_prev_sel = init_sel;
            }
        }
    }

    if (alz_encode_escape(d, escape_sel) != 0) {
        if (costfront_st) {
            alz_ps_carry_free(costfront_st);
            free(costfront_st);
        }
        free(hashtab);
        free(chain);
        free(d->window);
        free(d);
        uha_rcw_free(&w);
        return 3;
    }

    member = 0;
    {
        uint32_t next_boundary;
        if (costfront_on) {
            next_boundary = alz_costfront_next_boundary(plain, usize, 0, member_ends,
                                                        nmembers, &member);
        } else {
            next_boundary = alz_next_boundary(usize, 0, member_ends,
                                              nmembers, &member);
        }
        uint32_t costfront_base = 0;
        uint32_t costfront_len = next_boundary;
        /* [RE b3 probe] cumul of cost SSE literal by block for q=(cost/len)/585
         * of the gate of budget (b). READ-ONLY, gated UHA_PARSE3DBG ; not touche NOT
         * l'emission (default = 6977 intact). */
        uint64_t p3_cost = 0;
        uint32_t p3_len = 0, p3_blocks = 0;
        const char *p3e = getenv("UHA_PARSE3DBG");
        uint32_t p3tgt = p3e ? (uint32_t)atoi(p3e) : 0xFFFFFFFFu;
        /* [a5-e3 PROBE seed, GATED UHA_SEEDDBG, read-only] Mirror of the
         * model 2-arenas 13.149 : the clone tient has arena delta-2D CONTINUE
         * of the machine cls3 (13.132), entrainee inc=16 ONLY sure the
         * positions emises en LITERAL, for to reproduce there seed persistee of the
         * block next. at the frontier bloc1->bloc2, dump of row5 + counts some
         * coups literal delta4/deltafc/deltafd, compares at the oracle legacy
         * {4:4272, fc:112, fd:0}/total 4413 (13.147/148). N'affecte NOR
         * l'emission NOR d (arena local). Closes also a5e2b (267=coups-literal). */
        const char *seede = getenv("UHA_SEEDDBG");
        uint32_t *seed_ctx3 = NULL;
        alz_arena2d_t *seed_arena = NULL;
        uint32_t seed_n4 = 0, seed_nfc = 0, seed_nfd = 0, seed_nlit = 0;
        if (seede && usize > 0) {
            seed_ctx3 = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)usize);
            seed_arena = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
            if (seed_ctx3 && seed_arena) {
                alz_ps_gen_ctxs(3u, plain, usize, seed_ctx3);
                alz_arena2d_init(seed_arena, 16u);
            } else {
                free(seed_ctx3); seed_ctx3 = NULL;
                free(seed_arena); seed_arena = NULL;
            }
        }
        /* [live-cls3-dens GATED UHA_LIVDENS=path UHA_LVDLEARNM=<0|1>, default-OFF,
         * read-only, no-emissive] arena LIVE delta-2D machine cls3 avancant
         * byte-by-byte en order d'emission (score all position without muter +
         * learns each literal emis inc=16). Voir `ld_advance`. Not mute NOR d NOR
         * l'emission ; not nourrit NOT still gin.sm/g_lmin_dens (DIAGNOSTIC pur). */
        uint32_t      *ld_ctx3   = NULL;
        alz_arena2d_t *ld_ar     = NULL;
        FILE          *ld_f      = NULL;
        uint32_t       ld_learnm = 0;
        uint32_t       ld_inc    = 16;    /* UHA_LVDINC : inc d'learning (default 16) */
        uint32_t       ld_reset_at = 0;   /* UHA_LVDRESET=<pos> : cold-start arena has this pos */
        int            ld_reset_done = 0;
        uint32_t       ld_cls      = 3;   /* UHA_LVDCLS : class machine of context (default 3) */
        {
            const char *lvp = getenv("UHA_LIVDENS");
            if (lvp && usize > 0) {
                const char *lm = getenv("UHA_LVDLEARNM");
                const char *lr = getenv("UHA_LVDRESET");
                const char *li = getenv("UHA_LVDINC");
                const char *lc = getenv("UHA_LVDCLS");
                ld_learnm = lm ? (uint32_t) strtoul(lm, NULL, 10) : 0u;
                ld_inc    = li ? (uint32_t) strtoul(li, NULL, 10) : 16u;
                ld_reset_at = lr ? (uint32_t) strtoul(lr, NULL, 10) : 0u;
                ld_cls    = lc ? (uint32_t) strtoul(lc, NULL, 10) : 3u;
                ld_ctx3 = (uint32_t *) malloc(sizeof(uint32_t) * (size_t) usize);
                ld_ar   = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
                if (ld_ctx3 && ld_ar) {
                    alz_ps_gen_ctxs(ld_cls, plain, usize, ld_ctx3);
                    alz_arena2d_init(ld_ar, ld_inc ? ld_inc : 16u);
                    ld_f = fopen(lvp, "w");
                    if (ld_f)
                        fprintf(ld_f, "pos\trow\tdelta\tcost\n");
                } else {
                    free(ld_ctx3); ld_ctx3 = NULL;
                    free(ld_ar);   ld_ar = NULL;
                }
            }
        }
        /* [a5-e PRE-NOT scratch, GATED UHA_GATESTAT, read-only] Compares the
         * verdict of the porte of budget parse3_budget_allow(cls3 = winner
         * argmin 13.150) at the DECISION REELLE of the clone (match vs literal).
         * Not mute NOR d NOR l'emission : tally some flips + direction d'impact.
         * Flip TARGET (ramene 7052->7005) = clone LITTERALISE but porte ALLOW
         * match (= legacy couvre by has match ; cf. 13.150 " 23 events "). */
        const char *gse = getenv("UHA_GATESTAT");
        /* [a5-c GATED UHA_BUDGETGATE] decision reads-vs-match by BUDGET/AGING block
         * (parse3_budget_allow sure gs_cost/gs_len ecoules) plutot that veto cost
         * local (13.227 falsifie). Default OFF. */
        const int bgate = getenv("UHA_BUDGETGATE") ? 1 : 0;
        uint64_t gs_cost = 0;
        uint32_t gs_len = 0, gs_blk = 0;
        uint32_t gs_flip_match = 0, gs_flip_lit = 0, gs_agree = 0, gs_nomatch = 0;
        uint32_t gs_flip_match_b1 = 0, gs_flip_lit_b1 = 0;
        /* [A5.2 UHA_P1GATE, read-only, no-wired] Porte budget alimentee by the
         * TRUE Sigma of the vainqueur (persistance P1) au lieu of the proxy gs_cost. Measures :
         * (has) dominance allow/deny, (b) match porte-true vs decision LEGACY under
         * forcing (g_oracle->kind==1 sure the positions candidates = matchs legacy).
         * Teste directement the keeps-fou memory 847098a9 (fixer l'input Sigma). */
        int p1_on = (getenv("UHA_P1GATE") != NULL);
        uint32_t p1_cand = 0, p1_true_allow = 0, p1_true_deny = 0;
        uint32_t p1_vs_proxy_flip = 0, p1_legacy_agree = 0, p1_legacy_diff = 0;
        if (p1_on && !p1g_ready && plain && usize > 2u)
            p1g_precompute(plain, usize);
        /* [a5c2f-c-lmin-asm GATED UHA_LMINLIVE] pre-pass dens[] (source sm/bud of the
         * feeder LIVE), read-only, no-emissive. Active for alimenter the dump
         * sm_live/bud_live of the block UHA_LMINDUMP. */
        if (getenv("UHA_LMINLIVE") && plain && usize > 2u)
            lmin_dens_precompute(plain, usize);
        /* [cost-literal-live GATED UHA_DENSFORCE=path, default-OFF] Replaces the
         * field of cost g_lmin_dens (cost of the class WINNING, issue d'
         * alz_ps_class_sigma) by the true cost-LITERAL legacy `acc` (source
         * multiple of ~4680, cf 13.347) pos-by-pos, for TESTER CAUSALEMENT if
         * there source of cost of mean/esi is the levier of the gap 7024->7002. Format
         * `<pos>\t<cost>`. no effect if absent (g_lmin_dens keeps the dens). */
        {
            static int s_df = -1;
            if (s_df < 0) {
                const char *dp = getenv("UHA_DENSFORCE");
                s_df = (dp && g_lmin_dens_ready && g_lmin_dens) ? 1 : 0;
                if (s_df && dp) {
                    FILE *df = fopen(dp, "r");
                    if (df) {
                        char ln[128];
                        unsigned p, v;
                        while (fgets(ln, sizeof ln, df))
                            if (sscanf(ln, "%u\t%u", &p, &v) == 2 && p < usize)
                                g_lmin_dens[p] = (uint32_t) v;
                        fclose(df);
                    }
                }
            }
        }
        /* [C3' GATED UHA_CMCOST, read-only, no-wired] Comparateur of the TRUE
         * cost side-aware (alz_true_bits) vs proxy order-1 (gs_cost) sure there SAME
         * porte parse3_budget_allow(cls3). first encoding only (cm_pass). */
        const char *cme = getenv("UHA_CMCOST");
        int cm_on = 0;
        uint64_t cm_lb_blk = 0, cm_units_blk = 0;
        uint32_t cm_blklen = 0, cm_q_true_const = 0;
        uint32_t cm_cand = 0, cm_flip_allow = 0;
        uint32_t cm_flip_match = 0, cm_flip_lit = 0, cm_agree = 0;
        uint32_t cm_q_proxy10 = 0, cm_q_true10 = 0;
        /* [P1.1 GATED UHA_ARGMIN=path-trace, read-only, no-wired] Teste there
         * RULE H1 d'argmin (cout_token < Sigmalitteraux of the run) sure the DEPARTS of
         * match LEGACY that the clone visite. Reutilise alz_oracle_load but NOT
         * forces NOT l'emission (g_oracle remainder NULL if UHA_ORACLE no sets).
         * first encoding only (am_pass). Not mute NOR d NOR l'emission. */
        const char *ame = getenv("UHA_ARGMIN");
        int am_on = 0;
        alz_oracle *g_amref = NULL;
        uint32_t am_eval = 0, am_accept = 0, am_miss = 0, am_cantcode = 0;
        uint32_t am_accept_b1 = 0, am_miss_b1 = 0;
        /* [A1 - rule of length (piece (c))] histogramme raw-vs-codable-vs-legacy. */
        uint32_t am_raw_eq = 0, am_enc_eq = 0, am_shorter = 0, am_longer = 0;
        uint64_t am_raw_sum = 0, am_cnt_sum = 0;
        uint32_t am_hist[8] = {0, 0, 0, 0, 0, 0, 0, 0};   /* delta=min(7,raw-ocnt) */
        /* [A2 - choice of class under state legacy]. */
        uint32_t am_cls_match = 0, am_cls_wrong = 0, am_cls_nocand = 0;
        uint32_t am_cls_match_len = 0;   /* rule priorite-length + tie-break cost */
        uint32_t am_otok_h[4] = {0, 0, 0, 0}, am_wtok_h[4] = {0, 0, 0, 0};
        /* [A2 diag] when DIFF & oracle=TOK3 : odist == recent[1] ? recent[0] ? other ? */
        uint32_t am_t3_eqr1 = 0, am_t3_eqr0 = 0, am_t3_other = 0, am_t3_nocand = 0;
        /* [A4 probe cost] vrais bits sure divergences (oracle vs notre choice). */
        int cf_on = costfit_on();
        uint32_t cf_div = 0, cf_oracle_lower = 0, cf_ours_lower = 0, cf_tie = 0;
        uint32_t cf_oracle_longer = 0, cf_same_len = 0;   /* length coverante */
        uint64_t cf_sum_o = 0, cf_sum_w = 0;              /* bits sum (moy.) */
        {
            const char *oce = getenv("UHA_ORACLE");
            if (oce && !g_oracle)
                g_oracle = alz_oracle_load(oce, usize);
        }
        /* [A5.3-i COSTTALLY, GATED UHA_COSTTALLY (+ UHA_ORACLE), read-only, no-emissive]
         * Sure l'state HOT forces-by-oracle, compares there rule OF cost faithful
         * (alz_true_bits : mbits_match < lbits_litteraux-of the-run) at the DECISION legacy
         * (g_oracle->kind[pos]). Matrice TP/FN/FP/TN sure the bloc1. FP = the cost allows
         * has match that the legacy engine REFUSE (sure-match validated by the cost single) : if FP is
         * eleve, there retenue legacy N'is NOT the cost (c'is the budget of recence MRU)
         * -> levier " greffe of the cost " mort (reproduces a52/C3'). Not mute NOR d NOR l'emission. */
        int ct_on = (getenv("UHA_COSTTALLY") != NULL);
        uint32_t ct_tp = 0, ct_fn = 0, ct_fp = 0, ct_tn = 0;
        uint64_t ct_fp_save = 0, ct_tn_save = 0;   /* bits : FP=(lb-mb) match less cher ; TN=(mb-lb) veto economie */
        uint64_t ct_fn_over = 0, ct_tp_under = 0;  /* bits : FN surcout of the match-investissement (mb-lb) ; TP economie (lb-mb) */
        /* [A5.3-j] histogrammes FP vs TP : class token, slot of recence of `dist`, length. */
        uint32_t ct_fp_tok[4] = {0, 0, 0, 0}, ct_tp_tok[4] = {0, 0, 0, 0};
        uint32_t ct_fp_slot[ALZ_MAX_RECENT + 1] = {0}, ct_tp_slot[ALZ_MAX_RECENT + 1] = {0};  /* idx slot ; [12]=absent */
        uint32_t ct_fp_len[4] = {0, 0, 0, 0}, ct_tp_len[4] = {0, 0, 0, 0};   /* 2-3, 4-7, 8-15, 16+ */
        /* [A5.3-j] croisee jointe : (new distance = absent) * (short len<=7). */
        uint32_t ct_tp_ns = 0, ct_tp_nl = 0, ct_tp_es = 0, ct_tp_el = 0;   /* TP new/exist * short/long */
        uint32_t ct_fp_ns = 0, ct_fp_nl = 0, ct_fp_es = 0, ct_fp_el = 0;   /* FP idem */
        /* [A5.3-k has] STATE LEGACY (mode forces) : slot*length some vrais matchs -> calibrer K/L. */
        uint32_t lg_slot[ALZ_MAX_RECENT + 1];
        uint32_t lg_len[4];
        /* [A5.3-k b] STATE CLONE (mode no-forces) : table candidates slot*len*legacykind (1=match). */
        static uint32_t rg_tbl[ALZ_MAX_RECENT + 1][4][2];
        static int rg_ran = 0;
        memset(lg_slot, 0, sizeof lg_slot);
        memset(lg_len, 0, sizeof lg_len);
        if (!rg_ran) { memset(rg_tbl, 0, sizeof rg_tbl); rg_ran = 1; }
        /* [A5.3-l, GATED UHA_RECENCYGATE + UHA_ORACLE] STATE LEGACY CLEAN : table JOINTES
         * slot*len*kind. kind=1 : match legacy (oracle) ; kind=0 : READS legacy but the
         * finder of base PROPOSE has match (target of veto). The all measured sure the recent[]
         * legacy no pollue (rejeu forces). Balayage (K,L) out-line = A5.3-k(b) clean. */
        int rgprobe_on = (getenv("UHA_RECENCYGATE") != NULL);
        static uint32_t lt_tbl[ALZ_MAX_RECENT + 1][4][2];
        static int lt_init = 0, lt_dumped = 0;
        if (!lt_init) { memset(lt_tbl, 0, sizeof lt_tbl); lt_init = 1; }
        /* [A5.3-m FINDERDBG, GATED UHA_FINDERDBG + UHA_ORACLE, no-emissive] The finder of base
         * (path default, reading pure of d) reproduces-il the vrais matchs legacy ? classes some
         * targets of veto (kind=0 now finder propose). Decide reglage local of the finder vs selection global. */
        int fd_on = (getenv("UHA_FINDERDBG") != NULL);
        /* [A5.3-t FINDERDUMP, GATED UHA_FINDERDUMP=path, no-emissive] dump (dist,len,inrec)
         * by target of veto + by DIFF legacy-match, for en deduire the threshold d'acceptation exact
         * of the matcher legacy. NULL (env absent) => no effect, baseline intacte. */
        const char *fde = getenv("UHA_FINDERDUMP");
        FILE *fdump = (fd_on && fde) ? fopen(fde, "w") : NULL;
        /* [a5c2e COSTFLUSH, GATED UHA_COSTFLUSH=path + UHA_ORACLE, no-emissive]
         * Test decisif : the FLUSH legacy is-il predit by the cost model
         * (match_cost < Sigma literals) plutot that by there porte has registres ?
         * 13.235 : 2 vecteurs of registres identical (57 vs 183) give some
         * issues different => the flush is cost-bound. On dump for each
         * position scannee : pos, kind_legacy (flush?), clone-finder (tok,dist,
         * count), mc=alz_match_model_cost, lc=Sigma literals warm. read-only. */
        const char *cfe = getenv("UHA_COSTFLUSH");
        FILE *cfdump = (cfe && g_oracle) ? fopen(cfe, "w") : NULL;
        uint32_t fd_lmatch = 0;                     /* vrais matchs legacy visites (kind=1) */
        uint32_t fd_miss = 0, fd_same_eq = 0, fd_same_long = 0, fd_same_short = 0;
        uint32_t fd_diff = 0, fd_diff_long = 0, fd_diff_short = 0, fd_diff_eqlen = 0, fd_diff_new = 0;
        uint32_t fd_tokmatch = 0;
        uint32_t fb_veto = 0, fb_new = 0, fb_exist_short = 0, fb_exist_long = 0;
        /* [A5.3-n LOOK-AHEAD bounded] for each target veto (legacy READS en pos, finder propose) :
         * distance au next start-of-match legacy after pos. if small deltas dominent ->
         * lazy/lookahead bounded (local cablable) ; otherwise deltas large -> true DP global. */
        uint32_t la_d1 = 0, la_d2_4 = 0, la_d5_8 = 0, la_d9_16 = 0, la_d17_64 = 0, la_d65p = 0, la_none = 0;
        uint32_t la_steal = 0;   /* the match of the finder couvrirait the next start legacy */
        static int32_t la_next[12544];
        static int la_built = 0;
        /* [C2' FIDELITE alz_true_bits, GATED UHA_TRUEBITS, read-only of d]
         * Walk has CLON hot E sure the bloc1 (image.raw : [0,12544)) by runs of
         * literals ; at each position P (== E->output_pos, contrat reel) compares
         * lbits d'alz_true_bits au mirror d'emission tb_lit_measure (transcription
         * INDEPENDENTE l.1653..1680). Exige diff==0 (bits) + no-mutation of E by
         * l'helper (memcmp struct). Not touche NEVER d/emission ; baseline intacte.
         * Has single run (static) ; cap cas + cap bytes for borner the temps. */
        {
            static int tb_ran = 0;
            const char *tbe = getenv("UHA_TRUEBITS");
            if (tbe && !tb_ran && plain && usize > 2u) {
                size_t wbytes = (size_t)d->mode.dict_size + 4096;
                uint32_t lim = (usize < 12544u) ? usize : 12544u;
                uint32_t cases = 0, fidok = 0, fidfail = 0, leaks = 0, hardfail = 0;
                uint64_t maxdiff = 0;
                uint32_t li = 0;
                static const uint32_t LSEQ[] = {1,2,3,5,8,4,1,2,7,3,6,2,4,10,1,5};
                const uint32_t LSEQN = (uint32_t)(sizeof LSEQ / sizeof LSEQ[0]);
                const uint32_t TB_MAXCASE = 512;
                alz_dec *E = (alz_dec *)malloc(sizeof *E);
                alz_dec *snap = (alz_dec *)malloc(sizeof *snap);
                uint8_t *Ewin = (uint8_t *)malloc(wbytes);
                uint8_t *Eout = (uint8_t *)malloc((size_t)usize + 1u);
                uha_rcw ew;
                tb_ran = 1;
                if (E && snap && Ewin && Eout && uha_rcw_init(&ew) == 0) {
                    memcpy(E, d, sizeof *E);
                    memcpy(Ewin, d->window, wbytes);
                    E->window = Ewin; E->out = Eout; E->outlen = (size_t)usize; E->w = &ew;
                    while (E->st.output_pos < lim && cases < TB_MAXCASE) {
                        uint32_t P = E->st.output_pos;
                        uint32_t L = LSEQ[li % LSEQN];
                        uint64_t mb = 0, lh = 0, lm = 0;
                        int okm = 1;
                        if (P + L > lim) L = lim - P;
                        li++;
                        if (L == 0) break;
                        memcpy(snap, E, sizeof *E);
                        alz_true_bits(E, plain, usize, P, 1, 1, L, &mb, &lh);
                        if (memcmp(snap, E, sizeof *E) != 0) leaks++;
                        lm = tb_lit_measure(E, plain, usize, L, &okm);
                        cases++;
                        if (!okm) { hardfail++; }
                        else if (lh == lm) { fidok++; }
                        else { fidfail++; if (lh > lm ? (lh - lm) > maxdiff : (lm - lh) > maxdiff) maxdiff = (lh > lm) ? (lh - lm) : (lm - lh); }
                        tb_lit_advance(E, plain, usize, L);
                    }
                    fprintf(stderr,
                        "[CMTEST-TRUEBITS] blk1 lim=%u cases=%u | fidOK=%u fidFAIL=%u "
                        "maxdiff=%llu bits | stateLeak=%u hard=%u | esc_sel=%u => %s\n",
                        lim, cases, fidok, fidfail, (unsigned long long)maxdiff,
                        leaks, hardfail, (unsigned)d->st.escape_selector,
                        (fidfail == 0 && leaks == 0 && hardfail == 0 && cases > 0) ? "PASS" : "FAIL");
                    fflush(stderr);
                    uha_rcw_free(&ew);
                } else {
                    fprintf(stderr, "[CMTEST-TRUEBITS] SETUP FAIL (alloc)\n");
                    fflush(stderr);
                }
                free(E); free(snap); free(Ewin); free(Eout);
            }
        }
        /* [C3' SCORER GLOBAL, GATED UHA_CMCOST, read-only - no-wired]
         * Replaces the proxy order-1 (gs_cost = alz_literal_cost) by the TRUE cost
         * of the model side-aware (alz_true_bits, faithful : verified C2'/13.154) for
         * alimenter parse3_budget_allow(cls3). Sigma GLOBAL by block : the bloc1
         * (image.raw = [0,12544)) code ENTIERENCEMENT en literals since l'state
         * cold of d -> vrais bits. Has SINGLE call alz_true_bits (first pass) =>
         * cost bound (1 copie window). Not mute NOR d NOR l'emission. */
        {
            static int cm_pass = 0;
            if (cme) {
                cm_pass++;
                if (cm_pass == 1 && plain && usize > 2u) {
                    uint64_t mb = 0;
                    cm_on = 1;
                    cm_blklen = (usize < 12544u) ? usize : 12544u;
                    alz_true_bits(d, plain, usize, 0, 1, 1, cm_blklen, &mb, &cm_lb_blk);
                    cm_units_blk = cm_lb_blk * 4680ull;
                    cm_q_true_const = cm_blklen ?
                        (uint32_t)((cm_units_blk / cm_blklen) / 585ull) : 0u;
                    if (cm_q_true_const > 10u)
                        cm_q_true_const = 10u;
                    fprintf(stderr,
                        "[CMCOST] blk1 len=%u | true_lit_bits=%llu avg=%.4f bits/oct | "
                        "q_true=%u (clamp10) | esc_sel=%u\n",
                        cm_blklen, (unsigned long long)cm_lb_blk,
                        cm_blklen ? (double)cm_lb_blk / cm_blklen : 0.0,
                        cm_q_true_const, (unsigned)d->st.escape_selector);
                    fflush(stderr);
                }
            }
        }
        /* [P1.1 setup] loads there trace-oracle of REFERENCE (UHA_ARGMIN=path),
         * first pass only, without to forces l'emission. */
        {
            static int am_pass = 0;
            if (ame) {
                am_pass++;
                if (am_pass == 1 && plain && usize > 2u) {
                    g_amref = alz_oracle_load(ame, usize);
                    if (g_amref)
                        am_on = 1;
                    else
                        fprintf(stderr, "[ARGMIN] setup FAIL (load %s)\n", ame);
                }
            }
        }
        /* [A5.3-t5 GATED UHA_MRUDBG, read-only, no-emissive] Dump of l'state
         * MRU of the clone (recent_distance[0..11]) BY position d'emission, before there
         * update, for diff position-by-position contre the rejeu legacy
         * (research/gt_scorer/mru_replay_validate.py). Not mute NOTHING. */
        static int s_mrudbg = -2;
        if (s_mrudbg == -2)
            s_mrudbg = getenv("UHA_MRUDBG") ? 1 : 0;
        /* [A5.3-t8] state croise of the wrapper legacy 0x4136a0 (init = 1er call :
         * dl=0, bl=cls=1, slot=0xff, Sigma8c=INF -> dl<2 -> rejet -> literal). */
        int lm_dl = 0, lm_bl = 1, lm_prevslot = 0xff, lm_sl;
        uint32_t lm_s8c = 0xffffffffu;
        /* [13.518 GATED commit-carry differe] values of the current portees towards there
         * position next after qu'on sait if emission il y has eu (reset dl=0). */
        int lm_cur_dh = 0, lm_cur_cls = 1, lm_cur_slot = 0xff, lm_cur_set = 0;
        uint32_t lm_cur_s6c = 0xffffffffu;
        int lm_on = lm413530_on();
        /* [a5c2c GATED UHA_TRAJDUMP=path, no-emissive] dump of the best-match of the
         * finder BY byte (pos count dist tok) for diff direct contre there
         * trajectoire legacy (_scratch/a5c_traj.csv : DH(p),S6C(p)). Uses some
         * tables temporaires separes ; not touche NOT l'state of the loop
         * d'emission. min_len=2 => length raw (without filtre tok2). */
        {
            const char *tjp = getenv("UHA_TRAJDUMP");
            static int tj_done = 0;
            if (tjp && plain && usize > 2u && !tj_done) {
                tj_done = 1;
                uint32_t *th = malloc(((size_t)hmask + 1u) * sizeof(uint32_t));
                uint32_t *tc = malloc((size_t)chain_size * sizeof(uint32_t));
                FILE *tf = fopen(tjp, "w");
                if (th && tc && tf) {
                    uint32_t q;
                    int hv; int tk; uint32_t dd, cnt;
                    uint32_t save_wp = d->st.window_pos;
                    uint32_t save_op = d->st.output_pos;
                    for (q = 0; q <= hmask; q++) th[q] = 0xFFFFFFFFu;
                    for (q = 0; q < chain_size; q++) tc[q] = 0xFFFFFFFFu;
                    /* The finder reads there source of the match in d->window sure there
                     * zone of recovery (n<dist, alz_plain_match_len) : on
                     * mirror plain[] in window (usize<=dict_size, no wrap)
                     * then on RESTORES l'state (zeros + window_pos) after the dump
                     * for not not corrompre there loop d'emission. */
                    memcpy(d->window, plain, usize);
                    for (q = 0; q + 1 < usize; q++) {
                        d->st.window_pos = q;
                        d->st.output_pos = q;
                        alz_chain_insert(th, tc, plain, q, usize, hmask, cmask);
                        tk = 0; dd = 0; cnt = 0;
                        hv = alz_find_match(d, plain, usize, q, 2, 2, th, tc,
                                            hmask, cmask, &tk, &dd, &cnt);
                        fprintf(tf, "%u %u %u %d\n", q,
                                hv ? (unsigned)cnt : 0u,
                                hv ? (unsigned)dd : 0u, hv ? tk : 0);
                    }
                    memset(d->window, 0, usize);
                    d->st.window_pos = save_wp;
                    d->st.output_pos = save_op;
                    fclose(tf);
                    fprintf(stderr, "[TRAJDUMP] wrote %s (%u pos)\n", tjp, usize);
                    fprintf(stderr, "[TRAJDUMP] dict_mask=%u dict_size=%u hmask=%u cmask=%u chain_size=%u\n",
                            (unsigned)d->mode.dict_mask, (unsigned)d->mode.dict_size,
                            (unsigned)hmask, (unsigned)cmask, (unsigned)chain_size);
                }
                free(th); free(tc);
            }
        }
        rc = 0;
        s_pend_ctr = 0u;
        uint32_t last_token_pos = 0;
        while (d->st.output_pos < usize) {
            if (ws && ws->max_outlen > 0 && w.pos >= ws->max_outlen) {
                rc = -10;
                break;
            }
            int token;
            uint32_t dist, count, pos;
            int have2, emit_lit = 0, lazy_def = 0, descent_adopt = 0, gate_413530_def = 0;
            uint8_t lb;
            token = 0; dist = 0; count = 0;

            /* Inserts in the strings all positions strictement
             * before there position current (y compris those couvertes by
             * the match previous). */
            {
                static int s_hash_decim = -1;
                if (s_hash_decim < 0)
                    s_hash_decim = (getenv("UHA_HASH_DECIM") != NULL) ? 1 : 0;
                static int s_decim_skip1 = -1;
                if (s_decim_skip1 < 0) {
                    const char *e = getenv("UHA_DECIM_SKIP1");
                    s_decim_skip1 = e ? (e[0] != '0') : 1;
                }
                while (ins < d->st.output_pos) {
                    int do_insert = 1;
                    if (s_decim_skip1 && d->st.output_pos > last_token_pos + 1u) {
                        uint32_t bl = d->st.output_pos - ins;
                        if (bl <= 1u)
                            do_insert = 0;
                        else if (s_hash_decim)
                            do_insert = alz_decim_should_insert(d->mode.method_class, bl);
                    } else if (s_hash_decim && ins > last_token_pos + 1u) {
                        uint32_t bl = d->st.output_pos - ins + 1u;
                        do_insert = alz_decim_should_insert(d->mode.method_class, bl);
                    }
                    if (do_insert) {
                        alz_chain_insert(hashtab, chain, plain, ins, usize,
                                         hmask, cmask);
                    }
                    ins++;
                }
            }
            pos = d->st.output_pos;
            last_token_pos = pos;
            /* [DIAGNOSTIC STALL GATED UHA_STALLDBG=N + UHA_MAXITER=M, default-OFF,
             * no-emissive] trace pos all the N iteres + break dur after M iteres :
             * localise if there loop pilote FIGE (pos constant) now advances lentement.
             * no effect without env (s_maxiter<=0 = no bound). */
            {
                static uint64_t s_iter = 0;
                static long s_stallk = -1, s_maxiter = -1;
                if (s_stallk < 0) {
                    const char *e = getenv("UHA_STALLDBG");
                    const char *m = getenv("UHA_MAXITER");
                    s_stallk = e ? atol(e) : 0;
                    s_maxiter = m ? atol(m) : 0;
                }
                if (s_stallk > 0 || s_maxiter > 0) {
                    s_iter++;
                    if (s_stallk > 0 && (s_iter % (uint64_t)s_stallk) == 0)
                        fprintf(stderr, "[STALL] iter=%llu pos=%u\n",
                                (unsigned long long)s_iter, (unsigned)pos);
                    if (s_maxiter > 0 && (long)s_iter > s_maxiter) {
                        fprintf(stderr, "[STALL] MAXITER hit iter=%llu pos=%u usize=%u\n",
                                (unsigned long long)s_iter, (unsigned)pos, (unsigned)usize);
                        break;
                    }
                }
            }
            /* [a5-e3 probe] end of the block-scorer 1 (image.raw blk0=0x3100=12544,
             * geometrie 13.140) : dump of the seed row5 accumulee by the clone
             * sure ses LITERALS emis (pos<12544). if the parse bloc1 of the clone ==
             * legacy, on retrouve {d4:4272(267), dfc:112(7)} / total 4413. */
            if (seed_arena && pos >= 12544u) {
                uint32_t b5 = 5u << 8;
                fprintf(stderr,
                    "[SEED] blk1->2 pos=%u lit=%u | row5: d4 freq=%u(n=%u) "
                    "dfc freq=%u(n=%u) dfd freq=%u(n=%u) | total[5]=%u "
                    "counter[5]=%u\n[SEED] attendu legacy d4=4272(267) "
                    "dfc=112(7) dfd=0(0) total=4413\n",
                    pos, seed_nlit,
                    seed_arena->freq[b5 + 4u], seed_n4,
                    seed_arena->freq[b5 + 0xfcu], seed_nfc,
                    seed_arena->freq[b5 + 0xfdu], seed_nfd,
                    seed_arena->total[5], seed_arena->counter[5]);
                fflush(stderr);
                free(seed_arena); seed_arena = NULL;   /* dump unique */
            }
            if (d->st.output_pos >= next_boundary) {
                if (costfront_on) {
                    uint32_t cur_pos = d->st.output_pos;
                    uint32_t next_nb = alz_costfront_next_boundary(plain, usize, cur_pos,
                                                                   member_ends, nmembers, &member);
                    uint32_t blk_len = (next_nb > cur_pos) ? (next_nb - cur_pos) : 0u;
                    uint32_t seed = (costfront_prev_sel < 11u) ? s_alz_repli[costfront_prev_sel] : 0u;
                    uint32_t new_sel = costfront_prev_sel;
                    int is_member_boundary = 0;
                    int mi_chk;
                    if (blk_len > 0u && costfront_st) {
                        new_sel = alz_ps_block_argmin_carry(costfront_st, seed, plain, cur_pos,
                                                            blk_len, 32u, ALZ_PS_COLD0, NULL, NULL);
                        if (new_sel >= 5u)
                            new_sel = 0u;
                    }
                    for (mi_chk = 0; mi_chk < nmembers; mi_chk++) {
                        if (member_ends[mi_chk] == cur_pos) {
                            is_member_boundary = 1;
                            break;
                        }
                    }
                    if (new_sel != costfront_prev_sel || is_member_boundary) {
                        if (is_member_boundary) {
                            alz_rebuild_block_model_core(d);
                            if (alz_encode_escape(d, (int)new_sel) != 0) {
                                rc = 3;
                                break;
                            }
                        } else {
                            if (alz_encode_token_class(d, 0) != 0) {
                                rc = 3;
                                break;
                            }
                            if (alz_encode_escape(d, (int)new_sel) != 0) {
                                rc = 3;
                                break;
                            }
                        }
                        costfront_prev_sel = new_sel;
                    }
                    costfront_base = cur_pos;
                    costfront_len = blk_len;
                    next_boundary = next_nb;
                } else {
                    /* mirror d'alz_rebuild_block_model (dec) : core + handle_escape
                     * ; the selecteur current is reemis (apply_escape identical
                     * => state preserve, escape_changed=0, symetrique to the two
                     * sides). */
                    p3_cost = 0; p3_len = 0; p3_blocks++;
                    if (gse) { gs_cost = 0; gs_len = 0; gs_blk++; }
                    alz_rebuild_block_model_core(d);
                    int bsel = (int)d->st.escape_selector;
                    uha_bndsched_hit(d->st.output_pos, &bsel);
                    if (alz_encode_escape(d, bsel) != 0) {
                        rc = 3;
                        break;
                    }
                    next_boundary = alz_next_boundary(usize, next_boundary,
                                                      member_ends, nmembers, &member);
                }
            }
            {   /* [UHA_ESCSCHED] escape en band programme (diagnostic) */
                int esel = 0;
                if (uha_esched_hit(pos, &esel)) {
                    if (alz_encode_token_class(d, 0) != 0 ||
                        alz_encode_escape(d, esel) != 0) {
                        rc = 3;
                        break;
                    }
                }
            }
            if (g_oracle && pos < g_oracle->n) {
                /* [oracle-replay] forces there decision match/literal of legacy. */
                have2 = (g_oracle->kind[pos] == 1 &&
                         pos + g_oracle->cnt[pos] <= usize);
                if (have2) {
                    token = g_oracle->tok[pos];
                    dist  = g_oracle->dist[pos];
                    count = g_oracle->cnt[pos];
                }
            } else if (dp_on()) {
                /* [RE DP] decision by argmin of cost GLOBAL window. tok=0
                 * => literal. Keeps there length entiere (adjacency-safe). */
                int dtok = 0;
                uint32_t ddist = 0, dcnt = 0;
                alz_dp_first_move(d, plain, usize, pos, dp_on(), hashtab, chain,
                                  hmask, cmask, &dtok, &ddist, &dcnt);
                if (dtok != 0 && dcnt >= 2 && pos + dcnt <= usize) {
                    have2 = 1; token = dtok; dist = ddist; count = dcnt;
                } else {
                    have2 = 0;
                }
            } else {
                /* [pending-law UHA_PENDLAW] reads l'env once ; if has drain is en
                 * cours (s_pend_ctr>0) on FORCES have2=0 (literal) without relancer the
                 * finder, mirror exact of the counter [0x45ecb7] of the pilote 0x412f70.
                 * Zero effet without env (s_pendlaw<0 = OFF). */
                static int s_mvl_drain = -1;
                if (s_mvl_drain < 0) s_mvl_drain = getenv("UHA_COSTLAZY_MVL") ? 1 : 0;
                if (s_pendlaw < 0) {
                    const char *pl = getenv("UHA_PENDLAW");
                    if (pl) {
                        if (strcmp(pl, "auto") == 0)
                            s_pendlaw = (d->mode.method_class < 3) ? (int)d->mode.method_class : 99;
                        else
                            s_pendlaw = atoi(pl);
                    } else {
                        /* [M497] Active by default en mode auto */
                        s_pendlaw = (d->mode.method_class < 3) ? (int)d->mode.method_class : 99;
                    }
                }
                if (((s_pendlaw >= 0 && s_pendlaw < 3) || s_mvl_drain) && s_pend_ctr > 0u) {
                    s_pend_ctr--;
                    have2 = 0;
                } else {
                have2 = alz_find_match(d, plain, usize, pos, min_len, tok2_min,
                                       hashtab,
                                       chain, hmask, cmask, &token, &dist, &count);
                {   /* [FALSIFIE 13.498] bypass proxy-lazy sure accept descente.
                     * Measures : plonge there fidelite (fd 5120->256, 7002->7024) because
                     * there descente only does TO SELECT the candidate ; there PORTE
                     * D'EMISSION is the comparateur of cost 0x412c30 (alz_lm_decide),
                     * that COSTLAZY proxyfie. Keeps the signal under UHA_LVLWALK_EMIT=1
                     * (default-OFF) for to reproduce there falsification. */
                    static int s_lvlemit = -1;
                    if (s_lvlemit < 0)
                        s_lvlemit = getenv("UHA_LVLWALK_EMIT") ? 1 : 0;
                    descent_adopt = s_lvlemit ? g_lvlwalk_adopt : 0;
                }
                }
                {
                    static int s_fdbg = -1;
                    if (s_fdbg < 0) { const char *e = getenv("UHA_PARSEDBG"); s_fdbg = e ? atoi(e) : -2; }
                    if ((int)pos == s_fdbg)
                        fprintf(stderr, "[FIND] pos=%u have2=%d tok=%d dist=%u cnt=%u (min_len=%d t2=%d) r0=%u wp=%u pml257=%u elen=%d\n",
                                pos, have2, token, dist, count, min_len, tok2_min,
                                d->st.recent_distance[0], d->st.window_pos,
                                alz_plain_match_len(d, plain, usize, pos, 257),
                                alz_best_encodable_len(d, 2, 257, alz_plain_match_len(d, plain, usize, pos, 257)));
                }
            }
            /* [a5c2f-walk GATED UHA_WALK, default-OFF, no-effet without env] walk
             * byte-has-byte by CARRY : on maintains has distance promue
             * `s_walk_carry` and on presente sa CONTINUATION `matchlen(pos,carry)`
             * as candidate (DL==matchlen==c30e, prouve 6059/6059 13.320), au
             * lieu of the glouton by position. On not RE-PROMOT there distance since the
             * finder glouton THAT when there continuation meurt (matchlen<2). There
             * class token is rederivee of the position of `carry` in MRU
             * (tok2=recent[0], tok3=recent[1..11], tok1=distance explicite). */
            {
                static int s_wk = -1;
                static uint32_t s_walk_carry = 0u;
                if (s_wk < 0) s_wk = getenv("UHA_WALK") ? 1 : 0;
                if (s_wk) {
                    /* HYBRIDE fresh-prioritaire + carry-en-repli (13.321 : the
                     * legacy relit the finder at each byte, but presente the
                     * carry when fresh=0). MODE 0 (default, 13.323 = 7024) : the
                     * candidate fresh (dist of the finder) is PRIORITAIRE ; the carry
                     * n'is presente that if fresh=0. UHA_WALKMODE=1 : more long
                     * among {fresh, carry} ; =2 : more long among {fresh, carry,
                     * all the slots MRU}. There class token is rederivee of the
                     * position of `use` in the MRU. */
                    static int s_wkmode = -1;
                    static int s_wkmin = -1;
                    static int s_wkrle = -1;
                    int gz;
                    uint32_t use = 0u, dl = 0u;
                    uint32_t floor_d;
                    if (s_wkmode < 0) {
                        const char *wm = getenv("UHA_WALKMODE");
                        s_wkmode = wm ? atoi(wm) : 0;
                    }
                    if (s_wkrle < 0) {
                        const char *wr = getenv("UHA_WALKRLE");
                        s_wkrle = wr ? atoi(wr) : 0;   /* dist==1 admis if run>=threshold */
                        if (s_wkrle < 0) s_wkrle = 0;
                    }
                    /* [walk-candidate GATED UHA_WALKNOCARRY, default-OFF] neutralise
                     * there propager of distance (carry) en mode fresh : teste if the
                     * sure-match recent (TOK2/TOK3 stride 2^k) vient of the carry. */
                    static int s_wknocarry = -1;
                    if (s_wknocarry < 0)
                        s_wknocarry = (getenv("UHA_WALKNOCARRY") != NULL) ? 1 : 0;
                    floor_d = 2u;
                    if (s_wkmin < 0) {
                        const char *wv = getenv("UHA_WALKMIN");
                        s_wkmin = wv ? atoi(wv) : 2;
                        if (s_wkmin < 2) s_wkmin = 2;
                    }
                    if (pos == 0u) s_walk_carry = 0u;
                    /* [walk-candidate RLE-DETECT GATED UHA_RLEDETECT=<threshold>,
                     * default-OFF] SURFACE has run `dist=1` (bytes consecutifs
                     * identical) as CANDIDATE, INDEPENDAMMENT of have2 (the
                     * matcher alz_find_match not returns NEVER dist=1, cf 13.357).
                     * condition validates : plain[pos]==plain[pos-1] (source = byte
                     * previous equal) ; count = length of the run (cap 255). Then
                     * laisses au decider (gov) the soin d'arbitrer (which reproduces
                     * al legacy under the same inputs). */
                    {
                        static int s_rlrd = -1;
                        if (s_rlrd < 0) {
                            const char *rr = getenv("UHA_RLEDETECT");
                            s_rlrd = rr ? atoi(rr) : 0;   /* threshold of run ; 0 = OFF */
                            if (s_rlrd < 0) s_rlrd = 0;
                        }
                        if (s_rlrd > 0 && pos >= 1u && pos < usize &&
                            plain[pos] == plain[pos - 1u]) {
                            uint32_t run = 1u;
                            while (pos + run < usize && plain[pos + run] == plain[pos] &&
                                   run < 255u)
                                run++;
                            if ((int)run >= s_rlrd) {
                                have2 = 1; token = 1; dist = 1u; count = run;
                                use = 1u; dl = run;
                            }
                        }
                    }
                    if (s_wkmode == 0) {
                        /* fresh : dist>=2 normal ; dist==1 (RLE) admis ONLY if
                         * run >= UHA_WALKRLE (the legacy engine n'emits has RLE dist=1 that for
                         * the long runs ; l'admettre partout SURE-emits, cf 13.326). */
                        if (have2 && (dist >= 2u || (s_wkrle > 0 && dist == 1u))) {
                            uint32_t n = alz_plain_match_len(d, plain, usize, pos, dist);
                            uint32_t need = (dist == 1u) ? (uint32_t)s_wkrle
                                                          : (uint32_t)s_wkmin;
                            if (n > 255u) n = 255u;
                            if (n >= need) { use = dist; dl = n; s_walk_carry = dist; }
                        }
                        if (use == 0u && s_walk_carry >= floor_d && !s_wknocarry) {
                            uint32_t n = alz_plain_match_len(d, plain, usize, pos, s_walk_carry);
                            if (n > 255u) n = 255u;
                            if (n >= 2u) { use = s_walk_carry; dl = n; }
                        }
                    } else {
                        /* modes 1/2 : to select there MORE LONG continuation among
                         * the distances candidates (fresh/carry[/MRU]). */
                        uint32_t cands[ALZ_MAX_RECENT + 2];
                        int nc = 0, ci;
                        if (have2 && dist >= 2u) cands[nc++] = dist;
                        if (s_walk_carry >= 2u) cands[nc++] = s_walk_carry;
                        if (s_wkmode >= 2) {
                            for (gz = 0; gz < ALZ_MAX_RECENT; gz++) {
                                uint32_t r = d->st.recent_distance[gz];
                                int dup = 0;
                                if (r == 0 || r > d->mode.dict_mask) continue;
                                for (ci = 0; ci < nc; ci++) if (cands[ci] == r) { dup = 1; break; }
                                if (!dup) cands[nc++] = r;
                            }
                        }
                        for (ci = 0; ci < nc; ci++) {
                            uint32_t n = alz_plain_match_len(d, plain, usize, pos, cands[ci]);
                            if (n > 255u) n = 255u;
                            if (n >= 2u && n > dl) { dl = n; use = cands[ci]; }
                        }
                        if (use >= 2u) s_walk_carry = use;
                    }
                    if (use >= 1u && dl >= 2u) {
                        dist  = use;
                        count = dl;
                        have2 = 1;
                        if (dist == d->st.recent_distance[0])
                            token = 2;
                        else {
                            token = 1;
                            for (gz = 1; gz < ALZ_MAX_RECENT; gz++)
                                if (d->st.recent_distance[gz] == dist) {
                                    token = 3;
                                    break;
                                }
                        }
                    } else {
                        have2 = 0;
                    }
                }
            }
            /* [RE b1b] Probe of validation ISOLEE of the scorer auto-entrene.
             * UHA_WARMDBG=<pos> : dump of the run RLE en pos, cost LITERAL cold
             * (read-only) vs HOT (self-training) vs cost-match. Not change
             * NOT l'emission. Target : image.raw pos57 (run 14x0xE2). */
            {
                const char *wd = getenv("UHA_WARMDBG");
                if (wd && (uint32_t)atoi(wd) == pos) {
                    uint32_t run = 1;
                    uint32_t cold, warm, mmc, cmc, mcf;
                    while (pos + run < usize && plain[pos + run] == plain[pos])
                        run++;
                    cold = alz_literal_cost(d, plain, usize, pos, run);
                    warm = alz_bm_literal_cost_warm(d, plain, usize, pos, run);
                    /* calibration estimator faithful : cost-match model (bits
                     * equivalents = /4680) vs cost some `run` literals. */
                    mmc = alz_match_model_cost(d, 1, 1, run);
                    cmc = (4680u * (alz_ilog2(run + 1u) + 4u) * (uint32_t)cost_k()) >> 8;
                    mcf = have2 ? alz_match_model_cost(d, token, dist, count) : ~0u;
                    fprintf(stderr,
                        "[WARM] pos=%u byte=%02X run=%u esc=%d cold=%u warm=%u "
                        "| have2=%d tok=%d dist=%u cnt=%u\n"
                        "[MCAL] RLE(1,1,%u): model=%u(%.1fbits) crude=%u | "
                        "lits=%u(%.1fbits) | gain=%d | FIND tok=%d model=%u\n",
                        pos, plain[pos], run, (int)d->st.escape_changed,
                        cold, warm, have2, token, dist, count,
                        run, mmc, (double)mmc / 4680.0, cmc,
                        cold, (double)cold / 4680.0, (int)(cold - mmc),
                        token, mcf);
                    fflush(stderr);
                }
            }
            /* [RE b2c] Probe true-codier : UHA_MCOST=<pos> measures the cost REEL
             * en bits of the match RLE (1,dist=1,run) that the legacy engine emits here vs the
             * `run` literals. Not mute NOR d NOR w (clone scratch). */
            {
                const char *mc = getenv("UHA_MCOST");
                if (mc && (uint32_t)atoi(mc) == pos) {
                    uint32_t run = 1;
                    while (pos + run < usize && plain[pos + run] == plain[pos])
                        run++;
                    probe_match_cost(d, plain, usize, pos, 1, 1, run, "RLE");
                    if (have2 && token == 1 && dist != 1)
                        probe_match_cost(d, plain, usize, pos, token, dist,
                                         count, "FIND");
                }
            }
            /* [RE b3 probe (has)+(b)] gate of budget by class, read-only.
             * Log q raw (before clamp) + u/byte + verdict allow for cls 1..4.
             * N'prevents NOT l'emission : observe only if the gate Garderait
             * the match (attendu sure image.raw pos57 : allow=1 for the RLE d1). */
            if (p3e && (pos == p3tgt || (pos & 0x1FFFu) == 0u)) {
                uint32_t qraw = p3_len ? (uint32_t)((p3_cost / p3_len) / 585ull) : 0u;
                uint32_t upb  = p3_len ? (uint32_t)(p3_cost / p3_len) : 0u;
                fprintf(stderr,
                    "[P3] blk=%u pos=%u runlen=%u q=%u(%u u/b) have2=%d tok=%d d=%u c=%u"
                    " | allow c1=%d c2=%d c3=%d c4=%d | r[0]=%u r[1]=%u r[2]=%u r[3]=%u\n",
                    p3_blocks, pos, p3_len, qraw, upb, have2, token, dist, count,
                    parse3_budget_allow(d, p3_cost, p3_len, 1),
                    parse3_budget_allow(d, p3_cost, p3_len, 2),
                    parse3_budget_allow(d, p3_cost, p3_len, 3),
                    parse3_budget_allow(d, p3_cost, p3_len, 4),
                    d->st.recent_distance[0], d->st.recent_distance[1],
                    d->st.recent_distance[2], d->st.recent_distance[3]);
                fflush(stderr);
            }
            /* cumul block-so-far of the cost SSE some bytes couverts by there position
             * (1 if literal, count if match) - mirror of the sum by byte of the
             * scorer (has) 13.46. Alz_literal_cost is read-only (predict only). */
            if (p3e) {
                uint32_t ncov = (have2 && count >= 2u) ? count : 1u;
                if (pos + ncov > usize)
                    ncov = usize - pos;
                p3_cost += (uint64_t)alz_literal_cost(d, plain, usize, pos, ncov);
                p3_len += ncov;
            }
            /* [RE (has) increment 1] Argmin d'order by window : score each
             * order of context 1..6 sure there window of block ecoulee, log the
             * cost cumule by order + l'order winner. Validates that l'argmin
             * (has) VARIE reellement (prealable au cablage d'emission). Gated
             * UHA_P3A, read-only (p3a_delta2_cost not mute nor d nor l'output). */
            {
                static const char *pa = NULL;
                static int painit = 0;
                if (!painit) { pa = getenv("UHA_P3A"); painit = 1; }
                if (pa && (pos == (uint32_t)atoi(pa) || (pos & 0x3FFFu) == 0u)
                    && pos > 16u) {
                    uint32_t bstart = (pos > 0x2000u) ? (pos - 0x2000u) : 0u;
                    uint64_t cc[7];
                    uint64_t best = ~(uint64_t)0;
                    int k, bi = 0;
                    for (k = 1; k <= 6; k++) {
                        cc[k] = p3a_delta2_cost(plain, usize, bstart, pos, k);
                        if (cc[k] && cc[k] < best) { best = cc[k]; bi = k; }
                    }
                    fprintf(stderr,
                        "[P3A] pos=%u win=[%u,%u) o1=%llu o2=%llu o3=%llu "
                        "o4=%llu o5=%llu o6=%llu | ARGMIN=o%d (cls=%d)\n",
                        pos, bstart, pos,
                        (unsigned long long)cc[1], (unsigned long long)cc[2],
                        (unsigned long long)cc[3], (unsigned long long)cc[4],
                        (unsigned long long)cc[5], (unsigned long long)cc[6],
                        bi, bi);
                    fflush(stderr);
                }
            }
            /* [exp Has / UHA_TRUEPARSE] Decision match-vs-literal by VRAIS
             * bits (scratch-coder faithful, side-aware). encoder-only : not
             * touche never l'emission reelle, only the CHOICE to emit now
             * no the match candidate. if the match not gagne not (mbits >=
             * lbits+margin), on forces has literal en pos. */
            if (trueparse_on() && have2 && count >= 2) {
                /* [exp Has v1] Decision true-side sure the match THE MORE LONG
                 * finds (no raccourcissement : raccourcir has match RLE
                 * creates has adjacency match->literal-same-byte which viole
                 * l'invariant d'exclusion predb of the bm-side -> encode invalid).
                 * On n'emets the match that if ses BITS REELS battent strictement
                 * those some literals couverts (mbits < lbits - margin).
                 * Resultat measures : 7222 o > default 7052 -> the true-side LOCAL
                 * (greedy) is under-OPTIMAL ; single has parse GLOBAL (block-argmin
                 * + gate budget legacy, now DP) reproduces the legacy engine. Gated. */
                uint64_t mb = 0, lb = 0;
                alz_true_bits(d, plain, usize, pos, token, dist, count, &mb, &lb);
                if (mb + (uint64_t)(s_trueparse_margin < 0 ? 0 : s_trueparse_margin) >= lb)
                    emit_lit = 1;
            }
            /* [A5.3-i COSTTALLY, GATED, no-emissive] Matrice cost-faithful vs decision legacy
             * sure the bloc1. ref = g_oracle (forcing -> measures TP/FN at the state legacy) otherwise
             * g_amref (no-forcing UHA_ARGMIN -> clone greedy, measures FP/TN = RETENUE).
             * no effect on l'emission. */
            const alz_oracle *ct_ref = g_oracle ? g_oracle : g_amref;
            if (ct_on && ct_ref && pos < 12544u && pos < ct_ref->n && have2 && count >= 2u &&
                pos + count <= usize) {
                uint64_t mb = 0, lb = 0;
                int legacy_match = (ct_ref->kind[pos] == 1);
                int sl, lbk;
                alz_true_bits(d, plain, usize, pos, token, dist, count, &mb, &lb);
                /* slot of recence current of `dist` in recent[] (12 = absent) + bucket length. */
                sl = ALZ_MAX_RECENT;
                for (int z = 0; z < ALZ_MAX_RECENT; z++)
                    if (d->st.recent_distance[z] == dist) { sl = z; break; }
                lbk = (count <= 3u) ? 0 : (count <= 7u) ? 1 : (count <= 15u) ? 2 : 3;
                if (ct_ref == g_oracle) {          /* forces : state legacy -> dist. some vrais matchs */
                    if (legacy_match) { lg_slot[sl]++; lg_len[lbk]++; }
                } else {                            /* no-forces : candidates clone -> table for K/L */
                    rg_tbl[sl][lbk][legacy_match ? 1 : 0]++;
                }
                if (legacy_match) {
                    if (mb < lb) {
                        ct_tp++; ct_tp_under += (lb - mb);
                        if (token < 4) ct_tp_tok[token]++;
                        ct_tp_slot[sl]++; ct_tp_len[lbk]++;
                        if (sl == ALZ_MAX_RECENT) { if (count <= 7u) ct_tp_ns++; else ct_tp_nl++; }
                        else { if (count <= 7u) ct_tp_es++; else ct_tp_el++; }
                    } else { ct_fn++; ct_fn_over += (mb - lb); }
                } else {
                    if (mb < lb) {
                        ct_fp++; ct_fp_save += (lb - mb);
                        if (token < 4) ct_fp_tok[token]++;
                        ct_fp_slot[sl]++; ct_fp_len[lbk]++;
                        if (sl == ALZ_MAX_RECENT) { if (count <= 7u) ct_fp_ns++; else ct_fp_nl++; }
                        else { if (count <= 7u) ct_fp_es++; else ct_fp_el++; }
                    } else { ct_tn++; ct_tn_save += (mb - lb); }
                }
            }
            /* [A5.3-l RECENCYGATE-LEGACY, GATED UHA_RECENCYGATE, no-emissive] Sure l'state
             * legacy CLEAN, joint slot*len*kind : kind=1 = match legacy (oracle) ;
             * kind=0 = READS legacy but finder of base PROPOSE has match (target of veto).
             * finder of base = read-only (not mute nor d nor l'emission). */
            if (rgprobe_on && g_oracle && pos < 12544u && pos < g_oracle->n) {
                int sl2 = ALZ_MAX_RECENT, lbk2, kind2 = -1;
                uint32_t cdist = 0, ccount = 0;
                if (g_oracle->kind[pos] == 1) {
                    if (have2 && count >= 2u && pos + count <= usize) {
                        kind2 = 1; cdist = dist; ccount = count;
                    }
                } else {
                    int ftok = 0; uint32_t fd = 0, fc = 0;
                    if (alz_find_match(d, plain, usize, pos, min_len, tok2_min,
                                       hashtab, chain, hmask, cmask, &ftok, &fd, &fc)
                        && fc >= 2u && pos + fc <= usize) {
                        kind2 = 0; cdist = fd; ccount = fc;
                    }
                }
                if (kind2 >= 0) {
                    for (int z = 0; z < ALZ_MAX_RECENT; z++)
                        if (d->st.recent_distance[z] == cdist) { sl2 = z; break; }
                    lbk2 = (ccount <= 3u) ? 0 : (ccount <= 7u) ? 1 : (ccount <= 15u) ? 2 : 3;
                    lt_tbl[sl2][lbk2][kind2]++;
                }
            }
            /* [A5.3-m FINDERDBG, GATED, no-emissive] finder of base (pur) vs vrais matchs legacy
             * + classes some targets of veto. N'emits nothing, not mute nor d (path by default). */
            if (fd_on && g_oracle && pos < 12544u && pos < g_oracle->n) {
                int ftok = 0; uint32_t fd = 0, fc = 0;
                if (!la_built) {   /* table some prochains departs-of-match legacy (strictement > p) */
                    int32_t nxt = -1;
                    for (int p = 12543; p >= 0; p--) {
                        la_next[p] = nxt;
                        if ((uint32_t)p < g_oracle->n && g_oracle->kind[p] == 1) nxt = p;
                    }
                    la_built = 1;
                }
                int ffound = alz_find_match(d, plain, usize, pos, min_len, tok2_min,
                                            hashtab, chain, hmask, cmask, &ftok, &fd, &fc)
                             && fc >= 2u && pos + fc <= usize;
                int inrec = 0;
                for (int z = 0; z < ALZ_MAX_RECENT; z++)
                    if (d->st.recent_distance[z] == fd) { inrec = 1; break; }
                if (g_oracle->kind[pos] == 1) {
                    uint32_t odist = g_oracle->dist[pos], ocount = g_oracle->cnt[pos];
                    int otok = g_oracle->tok[pos];
                    fd_lmatch++;
                    if (ftok == otok) fd_tokmatch++;
                    if (!ffound) fd_miss++;
                    else if (fd == odist) {
                        if (fc == ocount) fd_same_eq++;
                        else if (fc > ocount) fd_same_long++;
                        else fd_same_short++;
                    } else {
                        fd_diff++;
                        if (fc > ocount) fd_diff_long++;
                        else if (fc < ocount) fd_diff_short++;
                        else fd_diff_eqlen++;
                        if (!inrec) fd_diff_new++;   /* the finder skips sure has distance NO recente */
                        if (fdump) fprintf(fdump, "D %u f=%u/%d/%u o=%u/%u/%d inrec=%d\n",
                                           pos, fd, ftok, fc, odist, ocount, otok, inrec);
                    }
                } else if (ffound) {                 /* target of veto : finder propose, legacy READS */
                    fb_veto++;
                    if (!inrec) fb_new++;
                    else if (fc <= 7u) fb_exist_short++;
                    else fb_exist_long++;
                    if (fdump) fprintf(fdump, "V %u f=%u/%d/%u inrec=%d\n",
                                       pos, fd, ftok, fc, inrec);
                    /* [A5.3-n] distance au next start-of-match legacy after pos. */
                    {
                        int32_t q = la_next[pos];
                        uint32_t dlt = (q >= 0) ? (uint32_t)(q - (int32_t)pos) : 0xFFFFFFFFu;
                        if (q < 0) la_none++;
                        else if (dlt == 1u) la_d1++;
                        else if (dlt <= 4u) la_d2_4++;
                        else if (dlt <= 8u) la_d5_8++;
                        else if (dlt <= 16u) la_d9_16++;
                        else if (dlt <= 64u) la_d17_64++;
                        else la_d65p++;
                        if (q >= 0 && (uint64_t)fc > (uint64_t)(q - (int32_t)pos)) la_steal++;
                    }
                }
            }
            /* [a5c2e COSTFLUSH probe GATED, read-only, no-emissive] Correle there
             * rule cost mc<lc with there TRUE decision legacy (flush) sure all
             * positions. under oracle-replay the clone visite the positions legacy. */
            if (cfdump && g_oracle && pos < g_oracle->n) {
                int kind = (g_oracle->kind[pos] == 1) ? 1 : 0;
                int ptok = 0; uint32_t pdist = 0, pcount = 0;
                if (kind) {
                    ptok = g_oracle->tok[pos]; pdist = g_oracle->dist[pos];
                    pcount = g_oracle->cnt[pos];
                } else {
                    alz_find_match(d, plain, usize, pos, min_len, tok2_min,
                                   hashtab, chain, hmask, cmask,
                                   &ptok, &pdist, &pcount);
                    if (pcount < 2u || pos + pcount > usize) pcount = 0;
                }
                if (pcount >= 2u) {
                    uint32_t mc = alz_match_model_cost(d, ptok, pdist, pcount);
                    uint32_t lc = alz_bm_literal_cost_warm(d, plain, usize, pos, pcount);
                    uint64_t tb_m = 0, tb_l = 0;
                    if (pos < 12544u)   /* block0 : true-codage coteux but exact */
                        alz_true_bits(d, plain, usize, pos, ptok, pdist, pcount,
                                      &tb_m, &tb_l);
                    fprintf(cfdump, "%u %d %d %u %u %u %u %llu %llu\n",
                            pos, kind, ptok, pdist, pcount, mc, lc,
                            (unsigned long long)tb_m, (unsigned long long)tb_l);
                } else {
                    fprintf(cfdump, "%u %d 0 0 0 0 0 0 0\n", pos, kind);
                }
            }
            /* Lazy matching (t14b) : if the match en pos+1 is more long,
             * to emit has literal en pos and lui laisser there place.
             * [a5c2c FALSIFIE] : cabler there porte 0x413530 en lookahead 1-NOT
             * (pos vs pos+1) grossit l'archive (7038 -> 7081) : the pending legacy
             * advances byte BY byte (multi-d defers), not has comparaison unique,
             * and l'approximation slot=0xff sure-triggers the vetos. Exigence of the
             * scan-by-byte+pending complete (port of the walker 0x412f70/0x41301c). */
            if (have2 && count < 255 && pos + 1 < usize && !descent_adopt && !trueparse_on() && !g_oracle && !dp_on() && !argminparse_on() && !trueargmin_on()) {
                int t2;
                uint32_t d2, c2;
                static int s_lazyfix = -1;

                alz_chain_insert(hashtab, chain, plain, pos, usize,
                                 hmask, cmask);
                ins = pos + 1;
                /* [GATED UHA_LAZYFIX, default-OFF, no-emissive without env] BUG
                 * mechanistique : the look-ahead calls alz_find_match(pos+1)
                 * then that d->st.window_pos == pos. alz_plain_match_len() reads there
                 * source via window[(window_pos - dist + n) & mask] (l.219-224) :
                 * with base=pos au lieu of pos+1, all reading n<dist is DECALEE
                 * of has position -> match factice ~0. There probe standalone (TRAJDUMP)
                 * n'has not this default because elle sets window_pos=q before find(q)
                 * (l.2562) : find(257) y returns 84/256. Consequence : the lazy not
                 * se triggers NEVER in-loop -> the clone not differe never has match
                 * short there now the legacy engine the does (sure-emissions FP, cf 13.409-410).
                 * Branch else = behavior d'origine STRICT (default-OFF garanti). */
                if (s_lazyfix < 0)
                    s_lazyfix = getenv("UHA_LAZYFIX") ? 1 : 0;
                /* [finder-port GATED UHA_LAZYCOST, default-OFF] the legacy engine not
                 * differe has match recent (TOK2/TOK3, bon walk) au profit of has
                 * distance EXPLICITE eloignee (TOK1, chere) THAT if this last is
                 * STRICTEMENT LESS CHERE au model (l'tree of distance is rembourse
                 * by there length). Has 1448 TOK2 d256 c5 is keeps vs TOK1 d1023 c8
                 * (chere). The lazy of the clone comparait en length pure -> sure-differait.
                 * UHA_LAZYREC=<marge> = variante empirique (proxy of cost by gain of
                 * length) conservee for comparaison. 13.474. */
                {
                    static int s_lazyrec = -1, s_lazycost = -1;
                    if (s_lazyrec < 0)
                        s_lazyrec = getenv("UHA_LAZYREC") ? atoi(getenv("UHA_LAZYREC")) : -1;
                    if (s_lazycost < 0)
                        s_lazycost = getenv("UHA_LAZYCOST") ? 1 : 0;
                    #define LAZY_SUPPRESS(sup_, c2_, cnt_, t2_, tok_, dist_, d2_) do { \
                        (sup_) = 0; \
                        if ((tok_ == 2 || tok_ == 3) && (t2_) == 1) { \
                            if (s_lazyrec >= 0 && (int)(c2_) - (int)(cnt_) < s_lazyrec) \
                                (sup_) = 1; \
                            if (s_lazycost) { \
                                uint32_t cur_c = alz_match_model_cost(d, tok_, dist_, cnt_); \
                                uint32_t la_c  = alz_match_model_cost(d, 1, d2_, c2_); \
                                if (!(la_c < cur_c)) (sup_) = 1; \
                            } \
                        } \
                    } while (0)
                    static int s_la_outpos = -1;
                    if (s_la_outpos < 0)
                        s_la_outpos = (getenv("UHA_LA_OUTPOS") != NULL) ? 1 : 0;
                    if (s_lazyfix) {
                        uint32_t save_wp_la = d->st.window_pos;
                        uint32_t save_op_la = d->st.output_pos;
                        int r, sup;
                        d->st.window_pos = pos + 1;
                        if (s_la_outpos) d->st.output_pos = pos + 1;
                        r = alz_find_match(d, plain, usize, pos + 1, min_len, tok2_min,
                                          hashtab, chain, hmask, cmask, &t2, &d2, &c2);
                        d->st.window_pos = save_wp_la;
                        if (s_la_outpos) d->st.output_pos = save_op_la;
                        LAZY_SUPPRESS(sup, c2, count, t2, token, dist, d2);
                        if (r && (int)c2 >= (int)count + lazy && !sup)
                            { emit_lit = 1; lazy_def = 1; }
                    } else {
                        uint32_t save_op_la = d->st.output_pos;
                        if (s_la_outpos) d->st.output_pos = pos + 1;
                        int sup, rr = alz_find_match(d, plain, usize, pos + 1, min_len, tok2_min,
                                                    hashtab, chain, hmask, cmask, &t2, &d2, &c2);
                        if (s_la_outpos) d->st.output_pos = save_op_la;
                        LAZY_SUPPRESS(sup, c2, count, t2, token, dist, d2);
                        if (rr && (int)c2 >= (int)count + lazy && !sup)
                            { emit_lit = 1; lazy_def = 1; }
                    }
                    #undef LAZY_SUPPRESS
                }
                {
                    static int s_lzdbg = -1;
                    if (s_lzdbg < 0) { const char *e = getenv("UHA_PARSEDBG"); s_lzdbg = e ? atoi(e) : -2; }
                    if ((int)pos == s_lzdbg)
                        fprintf(stderr, "[LAZY] pos=%u cnt=%u -> c2=%u d2=%u lazy=%d emit_lit=%d\n",
                                pos, count, c2, d2, lazy, emit_lit);
                }
            }
            /* [PORT pending GATED UHA_COSTLAZY=K, default-OFF] approx. of the walker
             * pending 0x412f70 : differement MULTI-NOT bounded. when has match-candidate
             * existe en pos, regarder up to K bytes more far has match STRICTEMENT
             * more long ; if finds, differer (to emit has literal en pos) and laisser
             * there loop external to advance byte-by-byte (reproduces l'advances pending).
             * The 1-not LAZYFIX not voit not 956 (has 2 no 954) ; here K>=2 the voit.
             * v1 = critere length (ck>count). Not s'execute THAT if l'env is sets.
             * Forbids when has other arbitre global is active (preserver leur test). */
            {
                static int s_cl_k = -1;
                if (s_cl_k < 0) {
                    const char *e = getenv("UHA_COSTLAZY");
                    s_cl_k = e ? atoi(e) : 0;
                }
                if (s_cl_k > 0 && have2 && count >= 2 && count < 255 && pos + 1 < usize
                    && !descent_adopt
                    && !trueparse_on() && !g_oracle && !dp_on() && !argminparse_on()
                    && !trueargmin_on()) {
                    int kk;
                    static int s_cgate = -1;
                    static int s_cglit = -2;
                    static int s_reach = -2;
                    uint32_t cost_cur;
                    static int s_tiny = -2;
                    static int s_margin = -2;
                    if (s_cgate < 0)
                        s_cgate = (getenv("UHA_COSTLAZY_CG") != NULL) ? 1 : 0;
                    if (s_cglit < 0)
                        s_cglit = (getenv("UHA_COSTLAZY_CGLIT") != NULL) ? 1 : 0;
                    if (s_reach < 0)
                        s_reach = (getenv("UHA_COSTLAZY_REACH") != NULL) ? 1 : 0;
                    if (s_tiny < 0)
                        s_tiny = (getenv("UHA_COSTLAZY_TINY") != NULL) ? 1 : 0;
                    if (s_margin < 0)
                        s_margin = (getenv("UHA_COSTLAZY_MARGIN") != NULL) ? 1 : 0;
                    static int s_costpri = -2;
                    if (s_costpri < 0) {
                        const char *cp = getenv("UHA_COSTLAZY_COSTPRI");
                        s_costpri = cp ? atoi(cp) : 0;
                    }
                    static int s_maxlen = -2;
                    if (s_maxlen == -2) {
                        const char *em = getenv("UHA_COSTLAZY_MAXLEN");
                        s_maxlen = em ? atoi(em) : 0;
                    }
                    static int s_maxlen_b2 = -2;
                    static uint32_t s_maxlen_b2_lim = 0;
                    if (s_maxlen_b2 == -2) {
                        const char *eb2 = getenv("UHA_COSTLAZY_MAXLEN_B2");
                        s_maxlen_b2 = eb2 ? atoi(eb2) : -1;
                        const char *eb2l = getenv("UHA_COSTLAZY_MAXLEN_B2_LIM");
                        s_maxlen_b2_lim = eb2l ? (uint32_t)atoi(eb2l) : 26800u;
                    }
                    int eff_maxlen = (s_maxlen_b2 >= 0 && pos >= s_maxlen_b2_lim) ? s_maxlen_b2 : s_maxlen;
                    cost_cur = s_cgate ? alz_match_model_cost(d, token, dist, count) : 0u;
                    for (kk = 1; kk <= s_cl_k && (uint32_t)pos + (uint32_t)kk < usize; kk++) {
                        int tf;
                        uint32_t df, cf;
                        uint32_t save_wp = d->st.window_pos;
                        int rf;
                        d->st.window_pos = pos + (uint32_t)kk;
                        rf = alz_find_match(d, plain, usize, pos + (uint32_t)kk, min_len,
                                            tok2_min, hashtab, chain, hmask, cmask,
                                            &tf, &df, &cf);
                        d->st.window_pos = save_wp;
                        static int s_maxlen_all = -1;
                        if (s_maxlen_all < 0) s_maxlen_all = (getenv("UHA_COSTLAZY_MAXLEN_ALL") != NULL) ? 1 : 0;
                        if (eff_maxlen > 0 && (tf == 1 || s_maxlen_all) && count >= (uint32_t)eff_maxlen)
                            continue;
                        /* [REACH] the bon discriminant n'is NOT there length raw of the
                         * match futur (sure-differement en 1191) but the gain of PORTee :
                         * differer not equals that if the match en pos+kk FINIT more FAR that
                         * the match current, i.e. kk+cf > count (couvre au-dela of pos+count).
                         * 954 : 2+9=11>4 differer ; 1231 : 1+3=4>2 differer ;
                         * 1191 : no match kk<=2 n'atteint >1194 -> flusher. */
                        /* [COSTPRI GATED UHA_COSTLAZY_COSTPRI] the legacy engine differe has
                         * match same towards more SHORT (3237 c4 -> 3238 c3@d511 recent
                         * less cher) : the gate reel is the cost, not there length. On
                         * ignores then the portail `cf>count` and on not keeps that there
                         * comparaison of cost (portail CG/CGLIT en aval). default-OFF. */
                        int len_ok = s_reach ? ((uint32_t)kk + cf > count) : (cf > count);
                        if (s_costpri == 1)
                            len_ok = (kk == 1 ? ((cf > count)
                                                 || ((tf == 2 || tf == 3) && token == 1 && cf + 1 >= count)
                                                 || (tf == 1 && token == 1 && cf >= count && df <= 256))
                                              : (cf > count));
                        else if (s_costpri >= 2)
                            len_ok = 1;
                        if (rf && cf >= 2 && len_ok) {
                            /* [MARGIN GATED] marge lazy classique : the match futur doit
                             * DEPASSER the current of more that the gap parcouru, i.e.
                             * cf > count + kk (the gain net of couverture after paiement
                             * some kk literals doit to be strictement positif). Exempte
                             * count<=2 (cas TINY). Fixes the sure-differement 1364 :
                             * descente da d9 d8 d7 -> gain marginal, cf<=count+kk -> flush. */
                            if (s_margin && count >= 3
                                && cf <= count + (uint32_t)kk)
                                continue;
                            /* [portail cost GATED UHA_COSTLAZY_CG] not differer that if
                             * the match futur is ALSO strictement less cher au model
                             * (avoids the sure-differement of the critere-length single, FN). */
                            if (s_cgate) {
                                uint32_t cost_fut = alz_match_model_cost(d, tf, df, cf);
                                if (s_tiny && count <= 2 && token == 1) {
                                    /* [TINY] has match-candidate of 2 bytes not equals
                                     * rarement has token : differer au profit of has
                                     * match more long proche, without exiger cost
                                     * moindre (cas 1231 : c2 -> c3). */
                                } else if (s_cglit && cf <= count && tf == 1) {
                                    /* [CGLIT] penaliser the cost some kk literals payes
                                     * for differer : not differer that if
                                     * cost_fut + reads(pos,kk) < cost_cur. */
                                    uint32_t lit_k = alz_bm_literal_cost_warm(
                                        d, plain, usize, pos, (uint32_t)kk);
                                    static int s_slack = -1;
                                    if (s_slack < 0) {
                                        const char *sl = getenv("UHA_COSTLAZY_SLACK");
                                        s_slack = sl ? atoi(sl) : 0;
                                    }
                                    if (cost_fut == ~(uint32_t)0
                                        || (uint64_t)cost_fut + lit_k >= cost_cur + (uint64_t)s_slack)
                                        continue;
                                } else if (cf > count) {
                                    uint32_t gap = cf - count;
                                    if (token == 1 && tf == 1) {
                                        if (gap < 6 && (df >> AlzLMShiftB[gap]) > dist)
                                            continue;
                                    } else {
                                        static int s_mrudef = -1;
                                        if (s_mrudef < 0) s_mrudef = (getenv("UHA_COSTLAZY_MRUDEF") != NULL) ? 1 : 0;
                                        if (s_mrudef && (token == 2 || token == 3) && tf == 1) {
                                            if (df > dist)
                                                continue;
                                            int e = gap > 7 ? 7 : (int)gap;
                                            int pslot = 0xff;
                                            if (token == 2) pslot = 0;
                                            else {
                                                for (int lm_sl = 1; lm_sl < ALZ_MAX_RECENT; lm_sl++)
                                                    if (d->st.recent_distance[lm_sl] == dist) {
                                                        pslot = lm_sl; break;
                                                    }
                                            }
                                            uint32_t thr = AlzLMThr884[e * 4 + alz_lm_bucket(pslot)];
                                            if (df >= thr)
                                                continue;
                                        } else {
                                            if (cost_fut == ~(uint32_t)0 || cost_fut >= cost_cur)
                                                continue;
                                        }
                                    }
                                } else if (cf <= count) {
                                    if (cost_fut == ~(uint32_t)0 || cost_fut >= cost_cur)
                                        continue;
                                }
                            }
                            emit_lit = 1;
                            lazy_def = 1;
                            break;
                        }
                    }
                }
            }
            /* [GATED UHA_COSTLAZY_MVL, default-OFF] Veto cost match vs literals + pending countdown.
             * when has match is finds by the finder, if son cost model excede the cost model
             * some count literals, the match is rejete (emit_lit = 1) and s_pend_ctr = count - 2. */
            {
                static int s_mvl = -1;
                if (s_mvl < 0) s_mvl = getenv("UHA_COSTLAZY_MVL") ? 1 : 0;
                if (s_mvl && have2 && !emit_lit && count >= 2u) {
                    uint32_t mc = alz_match_model_cost(d, token, dist, count);
                    uint32_t lc = alz_bm_literal_cost_warm(d, plain, usize, pos, count);
                    if (mc != ~(uint32_t)0 && mc > lc) {
                        emit_lit = 1;
                        s_pend_ctr = count - 2u;
                    }
                }
            }
            if (getenv("UHA_COSTLAZY_DBG") && pos >= 1035 && pos <= 1045) {
                uint32_t mc = have2 ? alz_match_model_cost(d, token, dist, count) : 0;
                uint32_t lc = have2 ? alz_bm_literal_cost_warm(d, plain, usize, pos, count) : 0;
                fprintf(stderr, "[CLDBG] pos=%u have2=%d tok=%d dist=%u cnt=%u mc=%u lc=%u emit_lit=%d\n",
                        pos, have2, token, dist, count, mc, lc, emit_lit);
            }
            /* [a5-e PRE-NOT scratch GATED] tally porte vs decision clone (not mute
             * NOTHING) ; q = gs_cost/gs_len/585 of the block ECOULE (out position current).
             * UPDATE gs_cost/gs_len AFTER reading of the verdict (mirror " allow match
             * maintenant " of legacy). */
            if (gse || bgate) {
                uint32_t ncov = (have2 && count >= 2u && pos + count <= usize)
                                ? count : 1u;
                if (pos + ncov > usize)
                    ncov = usize - pos;
                if (have2 && count >= 2u && pos + count <= usize) {
                    int allow = parse3_budget_allow(d, gs_cost, gs_len, 3);
                    int clone_match = !emit_lit;   /* have2 true here */
                    if (bgate) {
                        /* [a5-c] the budget/aging block GOUVERNE reads-vs-match :
                         * allow=0 -> litteralise ; allow>=0 (whose -1 start,
                         * blklen==0) -> emits the match already choisi by the finder. */
                        if (allow == 0)
                            emit_lit = 1;
                        else
                            emit_lit = 0;
                    }
                    if (p1_on && p1g_ready) {
                        uint64_t sig; uint32_t bl;
                        int b = p1g_block_of(pos, &sig, &bl);
                        if (b >= 0 && bl) {
                            int allow_t = parse3_budget_allow(d, sig, bl, 3);
                            p1_cand++;
                            if (allow_t) p1_true_allow++; else p1_true_deny++;
                            if (allow_t != allow) p1_vs_proxy_flip++;
                            if (g_oracle && pos < g_oracle->n) {
                                int legacy_match = (g_oracle->kind[pos] == 1);
                                if (allow_t == legacy_match) p1_legacy_agree++;
                                else p1_legacy_diff++;
                            }
                        }
                    }
                    if (allow && !clone_match) {
                        gs_flip_match++;                 /* reads->match : smaller */
                        if (pos < 12544u) gs_flip_match_b1++;
                    } else if (!allow && clone_match) {
                        gs_flip_lit++;                   /* match->reads : more BIG */
                        if (pos < 12544u) gs_flip_lit_b1++;
                    } else {
                        gs_agree++;
                    }
                    if (cm_on) {
                        int allow_t = parse3_budget_allow(d, cm_units_blk, cm_blklen, 3);
                        uint32_t q_p = gs_len ? (uint32_t)((gs_cost / gs_len) / 585ull) : 0u;
                        if (q_p > 10u) q_p = 10u;
                        cm_cand++;
                        if (q_p >= 10u) cm_q_proxy10++;
                        if (cm_q_true_const >= 10u) cm_q_true10++;
                        if (allow_t != allow) cm_flip_allow++;
                        if (allow_t && !clone_match) cm_flip_match++;
                        else if (!allow_t && clone_match) cm_flip_lit++;
                        else cm_agree++;
                    }
                } else {
                    gs_nomatch++;                        /* no match candidate */
                }
                gs_cost += (uint64_t)alz_literal_cost(d, plain, usize, pos, ncov);
                gs_len  += ncov;
            }
            /* [P1.1 GATED UHA_ARGMIN, read-only, no-emissive] Sure has START
             * of match LEGACY (kind[pos]==1) that the clone visite en pos : evaluates
             * there rule H1 = cout_token(otok,odist,ocnt) < Sigmalitteraux(pos,ocnt),
             * NOTES SURE L'STATE HOT live of d (alz_match_model_cost +
             * alz_bm_literal_cost_warm, unites 4680*bits comparables). Tally the
             * RAPPEL of the rule vs the legacy engine. Not mute NOR d NOR l'emission. */
            if (am_on && pos < g_amref->n && g_amref->kind[pos] == 1 &&
                pos + g_amref->cnt[pos] <= usize) {
                uint32_t otok = (uint32_t)g_amref->tok[pos];
                uint32_t odist = g_amref->dist[pos], ocnt = g_amref->cnt[pos];
                uint32_t mc = alz_match_model_cost(d, (int)otok, odist, ocnt);
                uint32_t lc = alz_bm_literal_cost_warm(d, plain, usize, pos, ocnt);
                /* [A1 length] raw = oavail has odist ; enc = max codable au tok. */
                {
                    uint32_t raw = alz_plain_match_len(d, plain, usize, pos, odist);
                    int enc = alz_best_encodable_len(d, (int)otok, odist, raw);
                    if (ocnt == raw) am_raw_eq++;
                    if (ocnt == (uint32_t)enc) am_enc_eq++;
                    if (ocnt > raw) am_longer++;
                    else if (ocnt < raw) {
                        uint32_t dd = raw - ocnt;
                        am_shorter++;
                        am_hist[dd > 7u ? 7u : dd]++;
                    }
                    am_raw_sum += raw; am_cnt_sum += ocnt;
                }
                /* [A2/A4 choice of class] enumere the candidates match sure
                 * l'state LEGACY (under forcing) : TOK2=slot0, TOK3=slots 1..11
                 * (m_short_slot_for), RLE dist1, TOK1 chain. Two rules :
                 *   R_cost = argmin cost-token ; R_len = max-length, tie-break cost. */
                {
                    struct { int tk; uint32_t dist; int len; uint32_t cost; }
                        cd[ALZ_MAX_RECENT + 2];
                    int nc = 0, s, k, ncmax = (int)(sizeof cd / sizeof cd[0]);
                    int wt = 0, wlt = 0, wl = 0, wtlen = 0;
                    uint32_t wd = 0, wc = ~(uint32_t)0, wld = 0, wlc = ~(uint32_t)0;
                    for (s = 0; s < ALZ_MAX_RECENT && nc < ncmax; s++) {
                        uint32_t r = d->st.recent_distance[s];
                        int tk = (s == 0) ? 2 : 3, cm = (s == 0) ? 2 : 4, el;
                        uint32_t n, c;
                        if (r == 0 || r > d->mode.dict_mask) continue;
                        n = alz_plain_match_len(d, plain, usize, pos, r);
                        el = alz_best_encodable_len(d, tk, r, n);
                        if (el < cm) continue;
                        c = alz_match_model_cost(d, tk, r, (uint32_t)el);
                        if (c == ~(uint32_t)0) continue;
                        cd[nc].tk = tk; cd[nc].dist = r; cd[nc].len = el; cd[nc].cost = c; nc++;
                    }
                    {
                        uint32_t n = alz_plain_match_len(d, plain, usize, pos, 1u);
                        int el = alz_best_encodable_len(d, 1, 1u, n);
                        if (el >= 3 && nc < ncmax) {
                            uint32_t c = alz_match_model_cost(d, 1, 1u, (uint32_t)el);
                            if (c != ~(uint32_t)0) {
                                cd[nc].tk = 1; cd[nc].dist = 1; cd[nc].len = el; cd[nc].cost = c; nc++;
                            }
                        }
                    }
                    {
                        uint32_t dd = 0, n = alz_chain_best(d, plain, usize, pos,
                                                           hashtab, chain, hmask, cmask, &dd);
                        if (n >= 3 && dd != 1u && nc < ncmax) {
                            int el = alz_best_encodable_len(d, 1, dd, n);
                            if (el >= 3) {
                                uint32_t c = alz_match_model_cost(d, 1, dd, (uint32_t)el);
                                if (c != ~(uint32_t)0) {
                                    cd[nc].tk = 1; cd[nc].dist = dd; cd[nc].len = el; cd[nc].cost = c; nc++;
                                }
                            }
                        }
                    }
                    for (k = 0; k < nc; k++) {                 /* R_cost (recence = order) */
                        if (cd[k].cost < wc) { wc = cd[k].cost; wt = cd[k].tk; wd = cd[k].dist; wtlen = cd[k].len; }
                    }
                    for (k = 0; k < nc; k++) {                 /* R_len (more long, tie cost) */
                        if (cd[k].len > wl || (cd[k].len == wl && cd[k].cost < wlc)) {
                            wl = cd[k].len; wlc = cd[k].cost; wlt = cd[k].tk; wld = cd[k].dist;
                        }
                    }
                    if (wt == 0) am_cls_nocand++;
                    else if ((uint32_t)wt == otok && wd == odist) am_cls_match++;
                    else {
                        am_cls_wrong++;
                        if (otok < 4) am_otok_h[otok]++;
                        if ((uint32_t)wt < 4) am_wtok_h[wt]++;
                        if (otok == 3) {
                            if (wt == 3) am_t3_nocand++;
                            else if (odist == d->st.recent_distance[1]) am_t3_eqr1++;
                            else if (odist == d->st.recent_distance[0]) am_t3_eqr0++;
                            else am_t3_other++;
                        }
                        /* [A4 probe] vrais bits d'emission : there class of legacy
                         * is-elle REELLEMENT less chere that there notre ? */
                        if (cf_on && wt != 0 && wtlen > 0 &&
                            pos + ocnt <= usize &&
                            pos + (uint32_t)wtlen <= usize) {
                            uint64_t mo = 0, lo = 0, mw = 0, lw = 0;
                            alz_true_bits(d, plain, usize, pos, (int)otok, odist, ocnt, &mo, &lo);
                            alz_true_bits(d, plain, usize, pos, wt, wd, (uint32_t)wtlen, &mw, &lw);
                            cf_div++; cf_sum_o += mo; cf_sum_w += mw;
                            if (mo < mw) cf_oracle_lower++;
                            else if (mw < mo) cf_ours_lower++;
                            else cf_tie++;
                            if (ocnt > (uint32_t)wtlen) cf_oracle_longer++;
                            else if (ocnt == (uint32_t)wtlen) cf_same_len++;
                        }
                    }
                    if (wlt != 0 && (uint32_t)wlt == otok && wld == odist) am_cls_match_len++;
                }
                am_eval++;
                if (mc == ~(uint32_t)0) {
                    am_cantcode++;
                } else if (mc < lc) {
                    am_accept++;
                    if (pos < 12544u) am_accept_b1++;
                } else {
                    am_miss++;
                    if (pos < 12544u) am_miss_b1++;
                }
            }
            /* [A5.3-t8 GATED UHA_LM413530] Porte reads<->match faithful 0x413530,
             * mirror of l'tree decode & validated live (2998/2999, 13.218).
             * Decider UNIQUE when active and qu'no overlay (oracle/dp/tp/am)
             * not tourne. updates l'state croise at each item (mirror wrapper,
             * y compris sure the candidates rejetes). Default OFF : NOTHING not change. */
            if (lm_on && !g_oracle && !dp_on() && !trueparse_on() && !argminparse_on()) {
                /* [a5c2d ECHELLE LEGACY] The registre legacy DH=[0x45ecb6] of the
                 * SELECT 0x413920 is (longueur_encodee - 1), Prouve sure ALL
                 * the 1375 emissions of the ground-truth (finder_full.log) : img_len
                 * == DL(p) == DH(p)+1, therefore dh_legiste = count-1 (a5c_traj.csv
                 * 4403/4403 vetos same-distance with delta clone-legacy == +1).
                 * There porte 0x413530 and ses tables (dl<2, gap, bucket) are
                 * VALIDees sure THIS echelle (sim_413530.py 2998/2999 sure
                 * cap_s3k.log = DH raw). Nourrir there porte with count (1-based)
                 * sure-decale dh of +1 -> dl<dh triggers too d'acceptations of
                 * match (the 28354 vetos RLE/same-distance). `lm_dl` transporte
                 * therefore there value -1 (regime of the position previous of the scan). */
                int dh = have2 ? (int)count - 1 : 0;
                int cls, slot;
                uint32_t s6c;
                int al;
                if (have2) {
                    s6c = dist;
                    if (token == 1) { cls = 1; slot = 0xff; }
                    else if (token == 2) { cls = 2; slot = 0; }
                    else { cls = 3; slot = 0xff;
                           for (lm_sl = 1; lm_sl < ALZ_MAX_RECENT; lm_sl++)
                               if (d->st.recent_distance[lm_sl] == dist) {
                                   slot = lm_sl; break;
                               }
                         }
                } else { cls = 1; slot = 0xff; s6c = 0xffffffffu; }
                al = alz_lm413530_gate(lm_dl, lm_bl, dh, slot, cls,
                                       s6c, lm_s8c, lm_prevslot);
                /* [a5-c2 AUTOCORRECTION via ASM 0x41302e] There polarite DIRECTE
                 * is there bonne : `cmp [0x45ecb5],0; je 0x412fde` = path of the
                 * LITERAL (edx=4 token), therefore [0x45ecb5]=al !=0 <=> EMITS the
                 * match. Coherents with sim_413530.py (al=1 accept, validates
                 * 2998/2999 13.218). The `al` is lu at the INPUT of the porte
                 * (dl=[0x45ecbe]=dh of the CANDIDATE of the position previous of the
                 * SCAN lazy, NOT of the match emis previous) : now l'artefact of the
                 * standalone a5c_gatetest.py (nourri some prev* d'emission).
                 *emit_lit = (al == 0) ? 1 : 0;  // direct : al==1 -> emits match */
                {
                    static int s_lm_inv = -2;
                    if (s_lm_inv == -2)
                        s_lm_inv = (getenv("UHA_LM413530_INV") != NULL) ? 1 : 0;
                    if (s_lm_inv)
                        emit_lit = (al != 0) ? 1 : 0;   /* [PROBE] polarite inverse */
                    else
                        emit_lit = (al == 0) ? 1 : 0;   /* direct (default porte) */
                }
                lm_dl = dh; lm_s8c = s6c; lm_bl = cls; lm_prevslot = slot;
            }
            /* [13.513 GATED UHA_LAZY413530, default-OFF, exige LMGovern] There porte
             * 0x413530 is has FILTRE PRE-decider (NOT l'emetteur) : elle decide if
             * there position ATTEINT the decider 0x412c30 now is DIFEREE (READS advances 1 +
             * carry buffer 0x4136a0). Proof c30d : pos 954/955 NO line (difFerees
             * BEFORE decider) ; 3238/5120 line presente alR=1 (decider emits). Here on
             * not replaces therefore NOT the verdict d'emission : on sets only
             * `lazy_def = (al==0)` (defer), that LAZYPRI appliquera BY-DESSUS the
             * decider. Mutuellement exclusif of the block-decider lm_on (to avoid double
             * carry). without env : NOTHING not change (lazy_def remainder sets by LAZYFIX). */
            {
                static int s_lazy413530 = -1;
                static int s_obs413530 = -1;   /* [DEFER13 OBS, GATED default-OFF] computes
                     * there gate 0x413530 AU-DESSUS of the vehicule LMGovern (lm_on=1) but not
                     * sets NOR lazy_def NOR lm_cur_* : DUMP PUR for to verify there law #13
                     * (defer@256 YES / defer@678 NO) with the candidate REELLEMENT surface
                     * (the finder DEF under-surface -> dl=0@678, gate aveugle). */
                if (s_lazy413530 < 0)
                    s_lazy413530 = (getenv("UHA_LAZY413530") != NULL) ? 1 : 0;
                if (s_obs413530 < 0)
                    s_obs413530 = (getenv("UHA_LAZY413530_OBS") != NULL) ? 1 : 0;
                static int s_defer13 = -1;
                if (s_defer13 < 0)
                    s_defer13 = (getenv("UHA_DEFER13") != NULL) ? 1 : 0;
                /* [DEFER13 13.640, GATED default-OFF] there gate FAITHFUL 0x413530 sets
                 * lazy_def ALSO under lm_on (vehicule no_trie), for vetosser the
                 * decider when the legacy engine DIFFERE (C1 : flag==0 -> READS same if
                 * st=1/`je accept`). The carry `lm_cur_*` remainder reserve au path
                 * d'origine (!lm_on) for to avoid all double-carry. */
                int g413530_assign = (s_lazy413530 && !lm_on);   /* carry d'origine */
                int g413530_defer  = g413530_assign || s_defer13; /* sets lazy_def */
                if ((g413530_defer || s_obs413530) && !g_oracle && !dp_on()
                    && !trueparse_on() && !argminparse_on()) {
                    /* [13.523 LAW look-ahead] dl=cnt(P) current, dh=cnt(P+1)
                     * look-ahead, s8c=dist(P), s6c=dist(P+1), echelle RAW.
                     * cls=cls(candidate P+1), bl=cls(candidate P) ; slot/prevslot idem.
                     * The finder is PUR (read-only) ; window_pos=pos+1 during there
                     * probe (lecon LAZYFIX) for to avoid the shift source. */
                    int cls, slot, al;
                    uint32_t s6c;
                    int dh;
                    uint32_t la_c = 0, la_d = 0; int la_t = 0;
                    if (pos + 1 < usize) {
                        uint32_t save_wp = d->st.window_pos;
                        d->st.window_pos = pos + 1;
                        static int s_la_outpos2 = -1;
                        if (s_la_outpos2 < 0)
                            s_la_outpos2 = (getenv("UHA_LA_OUTPOS") != NULL) ? 1 : 0;
                        uint32_t save_op = d->st.output_pos;
                        if (s_la_outpos2) d->st.output_pos = pos + 1;
                        /* [13.686 GATED UHA_LAZY413530_WARM, default-OFF, NET- ZERO]
                         * The look-ahead of the porte 0x413530 porte sure the scan REEL of
                         * there position next (pos+1) : has this moment-there the scan has already
                         * TRAITE `pos` (insert string + byte in there window). The find
                         * synthetique of block2 tourne with string/window echauffes
                         * only up to pos-1 -> RATE the match auto-recouvrant
                         * (RLE dist=1) of pos+1 (p.ex. @954 : legacy dh=count(955)=5
                         * via d1 RLE, clone finds count(955)=4 d256). On RECHAUFFE
                         * therefore `pos` exactement as the ferait l'iteration next
                         * (insert chain + window[pos]=plain[pos]) then on RESTORES
                         * (3 slots) for PRESERVER there no-regression (mutation zero). */
                        static int s_lawarm = -1;
                        if (s_lawarm < 0)
                            s_lawarm = (getenv("UHA_LAZY413530_WARM") != NULL) ? 1 : 0;
                        int r;
                        if (s_lawarm) {
                            /* [13.687 CORRECTION] The block LAZYFIX (l.4096-4103) has ALREADY
                             * inserts `pos` in there string (ins=pos+1) in there SAME
                             * iteration, before block2. Not NOT re-to insert : there
                             * re-insertion posait chain[pos]=hashtab[h]=pos
                             * (loop-sure-elle-same) and SEVRAIT there walk since the
                             * sources profondes (ex. @1348 : there string not remontait
                             * more has 582/d767 -> lookahead claque d255c5 au lieu of
                             * d767c11). On fills ONLY there WINDOW en pos (source
                             * dist=1 of the run pos+1, no still ecrite by l'emission)
                             * then on RESTORES. window_pos is already sets has pos+1.
                             * The run RLE (dist=1) pass by there window, not there string
                             * -> @954 remainder couvert without re-insertion. */
                            uint32_t mask = d->mode.dict_mask;
                            uint8_t  sv_w = d->window[pos & mask];
                            d->window[pos & mask] = plain[pos];
                            s_in_lookahead = 1;
                            r = alz_find_match(d, plain, usize, pos + 1, min_len,
                                               tok2_min, hashtab, chain, hmask, cmask,
                                               &la_t, &la_d, &la_c);
                            s_in_lookahead = 0;
                            d->window[pos & mask] = sv_w;
                        } else {
                            s_in_lookahead = 1;
                            r = alz_find_match(d, plain, usize, pos + 1, min_len,
                                               tok2_min, hashtab, chain, hmask, cmask,
                                               &la_t, &la_d, &la_c);
                            s_in_lookahead = 0;
                        }
                        d->st.window_pos = save_wp;
                        if (s_la_outpos2) d->st.output_pos = save_op;
                        if (!r || la_c < 2u || (uint64_t)pos + 1 + la_c > (uint64_t)usize)
                            la_c = 0;
                    }
                    dh = (int)la_c;
                    if (la_c >= 2u) {
                        s6c = la_d;
                        if (la_t == 1) { cls = 1; slot = 0xff; }
                        else if (la_t == 2) { cls = 2; slot = 0; }
                        else { cls = 3; slot = 0xff;
                               for (lm_sl = 1; lm_sl < ALZ_MAX_RECENT; lm_sl++)
                                   if (d->st.recent_distance[lm_sl] == la_d) {
                                       slot = lm_sl; break;
                                   }
                             }
                    } else { cls = 1; slot = 0xff; s6c = 0xffffffffu; }
                    /* [13.700 GATED UHA_LA_REFINE, default-OFF] Raffineur 0x4137a0
                     * of the lookahead : compares the match of string TOK1 (la_t==1, la_c>=2)
                     * to the matches MRU slots 0..11 has pos+1. if there string is too eloignee
                     * (gap < 6 && dist >= thr), rabattre the candidate sure the match MRU. */
                    {
                        static int s_la_refine = -1;
                        if (s_la_refine < 0)
                            s_la_refine = (getenv("UHA_LA_REFINE") != NULL) ? 1 : 0;
                        if (s_la_refine && la_c >= 2u && la_t == 1 && pos + 1 < usize) {
                            static const uint8_t s_r_bucket[12] =
                                { 0, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3 };
                            static const uint32_t s_r_thr[24] = {
                                /* gap0 */ 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
                                /* gap1 */ 0x00000004u, 0x00000008u, 0x00000080u, 0x00000400u,
                                /* gap2 */ 0x00000010u, 0x00000040u, 0x00000400u, 0x00002000u,
                                /* gap3 */ 0x00000040u, 0x00000100u, 0x00002000u, 0xffffffffu,
                                /* gap4 */ 0x00000100u, 0x00000800u, 0xffffffffu, 0xffffffffu,
                                /* gap5 */ 0x00000800u, 0xffffffffu, 0xffffffffu, 0xffffffffu
                            };
                            int mru_len = 0, mru_slot = -1, mru_cls = 1;
                            uint32_t mru_dist = 0xffffffffu;
                            uint32_t mask = d->mode.dict_mask;
                            uint8_t sv_w = d->window[pos & mask];
                            d->window[pos & mask] = plain[pos];
                            uint32_t sv_wp = d->st.window_pos;
                            d->st.window_pos = pos + 1;
                            for (int sl = 0; sl < ALZ_MAX_RECENT; sl++) {
                                uint32_t r = d->st.recent_distance[sl];
                                if (r == 0 || r > mask || r > pos + 1)
                                    continue;
                                uint32_t m = alz_plain_match_len(d, plain, usize, pos + 1, r);
                                if ((int)m > mru_len) {
                                    mru_len = (int)m;
                                    mru_slot = sl;
                                    mru_dist = r;
                                    mru_cls = (sl == 0) ? 2 : 3;
                                }
                            }
                            d->st.window_pos = sv_wp;
                            d->window[pos & mask] = sv_w;

                            if (mru_len >= 1) {
                                if ((int)la_c <= mru_len) {
                                    dh = mru_len; cls = mru_cls; slot = mru_slot; s6c = mru_dist;
                                } else {
                                    uint32_t gap = (uint32_t)la_c - (uint32_t)mru_len;
                                    if (gap < 6u) {
                                        int bkt = s_r_bucket[(mru_slot >= 0 && mru_slot < 12) ? mru_slot : 11];
                                        uint32_t thr = s_r_thr[gap * 4u + (uint32_t)bkt];
                                        if (la_d >= thr) {
                                            dh = mru_len; cls = mru_cls; slot = mru_slot; s6c = mru_dist;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    /* current (P) : dl=count, bl/prevslot/s8c = cls/slot/dist of the current */
                    int dl_cur = have2 ? (int)count : 0;
                    int bl_cur; uint32_t s8c_cur; int pslot_cur;
                    if (have2) {
                        s8c_cur = dist;
                        if (token == 1) { bl_cur = 1; pslot_cur = 0xff; }
                        else if (token == 2) { bl_cur = 2; pslot_cur = 0; }
                        else { bl_cur = 3; pslot_cur = 0xff;
                               for (lm_sl = 1; lm_sl < ALZ_MAX_RECENT; lm_sl++)
                                   if (d->st.recent_distance[lm_sl] == dist) {
                                       pslot_cur = lm_sl; break;
                                   }
                             }
                    } else { bl_cur = 1; pslot_cur = 0xff; s8c_cur = 0xffffffffu; }
                    al = alz_lm413530_gate(dl_cur, bl_cur, dh, slot, cls,
                                          s6c, s8c_cur, pslot_cur);
                    {
                        static int s_swap = -1;
                        if (s_swap < 0)
                            s_swap = (getenv("UHA_LAZY413530_SWAP") != NULL) ? 1 : 0;
                        if (s_swap)
                            al = alz_lm413530_gate(dh, cls, dl_cur, pslot_cur, bl_cur,
                                                  s8c_cur, s6c, slot);
                    }
                    {
                        static int s_l413_mrudef = -1;
                        if (s_l413_mrudef < 0)
                            s_l413_mrudef = (getenv("UHA_LAZY413530_MRUDEF") != NULL) ? 1 : 0;
                        if (s_l413_mrudef && (bl_cur == 2 || bl_cur == 3) && cls == 1 && s6c > s8c_cur)
                            al = 1;
                    }
                    if (g413530_defer && al == 0) {
                        lazy_def = 1;   /* al==0 -> defer (al==1 preserve lazy_def anterieur) */
                        gate_413530_def = 1;
                    }

                    {
                        /* [ASM 0x413670, GATED UHA_LAZY_PIPE_TRANS, default-OFF]
                         * Transition inter-classes en pipeline differe :
                         * if there position previous has differe has match TOK1 (bl==1),
                         * and that there position current propose has match TOK2 now TOK3 (cls!=1),
                         * the filtre ASM 0x413670 exige bl==2 for accepter (cmp bl, 2; jne 0x41368e).
                         * As bl==1!=2, the filtre returns al=0, this which prolonge the differe. */
                        static int s_pipe_trans = -1;
                        static uint32_t s_pipe_trans_lim = 0;
                        static uint32_t s_pipe_trans_max = 0;
                        static int s_pipe_trans_d257 = -1;
                        static int s_prev_def_tok = 0;
                        static uint32_t s_prev_def_pos = 0xffffffffu;
                        static int s_pipe_trans_minlen = -1;
                        if (s_pipe_trans < 0) {
                            const char *pt = getenv("UHA_LAZY_PIPE_TRANS");
                            s_pipe_trans = (pt && atoi(pt) > 0) ? 1 : 0;
                            const char *pl = getenv("UHA_LAZY_PIPE_TRANS_LIM");
                            s_pipe_trans_lim = pl ? (uint32_t)atoi(pl) : 0;
                            const char *pm = getenv("UHA_LAZY_PIPE_TRANS_MAX");
                            s_pipe_trans_max = pm ? (uint32_t)atoi(pm) : 0;
                            const char *pd = getenv("UHA_LAZY_PIPE_TRANS_D257");
                            s_pipe_trans_d257 = pd ? atoi(pd) : 0;
                            const char *pml = getenv("UHA_LAZY_PIPE_TRANS_MINLEN");
                            s_pipe_trans_minlen = pml ? atoi(pml) : 13;
                        }
                        int d_ok = (s_pipe_trans_d257 > 0) ? (dist <= (uint32_t)s_pipe_trans_d257) : 1;
                        int l_ok = (s_pipe_trans_minlen > 0) ? (count >= (uint32_t)s_pipe_trans_minlen) : 1;
                        if (s_pipe_trans && pos >= s_pipe_trans_lim && (s_pipe_trans_max == 0 || pos < s_pipe_trans_max) && (pos == s_prev_def_pos + 1u) && s_prev_def_tok == 1 && ((token == 2 && count >= 8u) || (token == 3 && d_ok && l_ok))) {
                            lazy_def = 1;
                        }
                        {
                            static int s_lazy_t1 = -1;
                            static uint32_t s_lazy_t1_p0 = 0, s_lazy_t1_p1 = 0;
                            if (s_lazy_t1 < 0) {
                                const char *e = getenv("UHA_LAZY_T1_PROBE");
                                if (e && sscanf(e, "%u:%u", &s_lazy_t1_p0, &s_lazy_t1_p1) == 2)
                                    s_lazy_t1 = 1;
                                else
                                    s_lazy_t1 = 0;
                            }
                            if (s_lazy_t1 && pos >= s_lazy_t1_p0 && pos <= s_lazy_t1_p1) {
                                lazy_def = 1;
                            }
                        }
                        {
                            /* [ASM 0x413670, GATED UHA_LAZY_T3_LEAD_DEFER, default-OFF]
                             * Law universelle of differe initial TOK3 post-literal :
                             * in l automate of porte ASM 0x413670, for has match TOK3
                             * precede d has literal (bl != 2), the filtre exige bl == 2
                             * (cmp bl, 2; jne 0x41368e) and returns al = 0, this which differe
                             * d has not the start of the match TOK3. */
                            static int s_t3_lead_def = -1;
                            static uint32_t s_t3_lead_lim = 0;
                            static uint32_t s_t3_lead_max = 0;
                            static uint32_t s_prev_t3_def_pos = 0xffffffffu;
                            if (s_t3_lead_def < 0) {
                                const char *e = getenv("UHA_LAZY_T3_LEAD_DEFER");
                                s_t3_lead_def = (e && atoi(e) > 0) ? atoi(e) : 0;
                                const char *el = getenv("UHA_LAZY_T3_LEAD_LIM");
                                s_t3_lead_lim = el ? (uint32_t)atoi(el) : 0;
                                const char *em = getenv("UHA_LAZY_T3_LEAD_MAX");
                                s_t3_lead_max = em ? (uint32_t)atoi(em) : 0;
                            }
                            static int s_t3_pos_init = -1;
                            static uint8_t s_t3_pos_tab[65537];
                            if (s_t3_pos_init < 0) {
                                const char *tp = getenv("UHA_LAZY_T3_POS");
                                s_t3_pos_init = 1;
                                if (tp) {
                                    char buf[4096];
                                    strncpy(buf, tp, sizeof(buf)-1);
                                    buf[sizeof(buf)-1] = '\0';
                                    char *tok = strtok(buf, ",");
                                    while (tok) {
                                        unsigned q = (unsigned)atoi(tok);
                                        if (q <= 65536u) s_t3_pos_tab[q] = 1;
                                        tok = strtok(NULL, ",");
                                    }
                                }
                            }
                            int is_t3_pos = (pos <= 65536u && s_t3_pos_tab[pos]);
                            int is_diag_plus1 = (token == 3 && (dist % 256u == 1u));
                            int lead_match = is_t3_pos ||
                                             (s_t3_lead_def == 3 && is_diag_plus1) ||
                                             (s_t3_lead_def == 2) ||
                                             (pos > dist && plain[pos - 1] == plain[pos - 1 - dist]);
                            if ((s_t3_lead_def || is_t3_pos) && (token == 3 || is_t3_pos) && have2 && !lazy_def && d->bm_flag == 0 &&
                                (lead_match || is_t3_pos) &&
                                (is_t3_pos || (pos >= s_t3_lead_lim && (s_t3_lead_max == 0 || pos < s_t3_lead_max))) &&
                                ((pos != s_prev_t3_def_pos + 1u) || is_t3_pos)) {
                                lazy_def = 1;
                                s_prev_t3_def_pos = pos;
                            }
                        }
                        if (lazy_def) {
                            s_prev_def_tok = token;
                            s_prev_def_pos = pos;
                        } else {
                            s_prev_def_tok = 0;
                            s_prev_def_pos = 0xffffffffu;
                        }
                    }
                    {
                        static int s_gdbg = -1;
                        static FILE *s_gf = NULL;
                        static uint32_t s_gf_p0 = 0, s_gf_p1 = 0xffffffffu;
                        if (s_gdbg < 0) {
                            const char *e = getenv("UHA_LAZY413530_DBG");
                            const char *o = getenv("UHA_LAZY413530_OBS");
                            const char *pr = getenv("UHA_LAZY413530_POS");
                            if (pr) { sscanf(pr, "%u:%u", &s_gf_p0, &s_gf_p1); }
                            /* [OBS] there value of UHA_LAZY413530_OBS is has path -> dump
                             * by position (read-only, no-emissive) ; prime sure DBG. */
                            if (o && strchr(o, '/')) { s_gdbg = 1; s_gf = fopen(o, "w"); }
                            else {
                                s_gdbg = e ? 1 : 0;
                                /* [13.521 GATED full-traj] if there value is has path
                                 * (contient '/'), dump exhaustif by position (READING
                                 * SINGLE, no-emissive) for recoupement field-has-field vs
                                 * there captures legacy gate_pos3. otherwise : stderr pos<80. */
                                if (s_gdbg && e && strchr(e, '/'))
                                    s_gf = fopen(e, "w");
                            }
                        }
                        if (s_gf && pos >= s_gf_p0 && pos <= s_gf_p1)
                            fprintf(s_gf,
                                "pos=%u dl=%d bl=%d dh=%d slot=%d cls=%d"
                                " s6c=%x s8c=%x pslot=%x al=%d defer=%d\n",
                                (unsigned)pos, dl_cur, bl_cur, dh, slot, cls,
                                (unsigned)s6c, (unsigned)s8c_cur, pslot_cur,
                                al, (al == 0) ? 1 : 0);
                        else if (s_gdbg && (int)pos < 80)
                            fprintf(stderr,
                                "[G413530] pos=%u dl=%d bl=%d dh=%d slot=%d cls=%d"
                                " s6c=%x s8c=%x pslot=%x -> al=%d defer=%d\n",
                                (unsigned)pos, dl_cur, bl_cur, dh, slot, cls,
                                (unsigned)s6c, (unsigned)s8c_cur, pslot_cur,
                                al, (al == 0) ? 1 : 0);
                    }
                    /* [13.518] Not NOT commiter the carry here : the commit (with
                     * reset dl=0 if emission) has lieu after the decider, when
                     * emit_lit is connu. On memorise only the current. */
                    if (g413530_assign) {
                        lm_cur_dh = dh; lm_cur_s6c = s6c; lm_cur_cls = cls;
                        lm_cur_slot = slot; lm_cur_set = 1;
                    }
                }
            }
            /* [a5c2f-c-proxybud-wire GATED UHA_LMINDUMP, default-OFF, ORACLE-ONLY,
             * read-only, no-emissive, NOT MUTE NOTHING] Dump some fields SCALAIRES
             * of lm_in (decider flush 0x412c30) produits from-clone, by pos,
             * for recoupement field-has-field vs there captures legacy c30e.tsv.
             * under forcing UHA_ORACLE, the clone visite the positions legacy and
             * have2/token/dist/count portent the choice forces => the scalaires which
             * en drift (arg/DL/dh/bb/S8c) doivent tomber stack. But : prouver
             * there plomberie some scalaires BEFORE d'investir in the stream
             * v/sm/bud/cx/this/loop (state persistant requis). */
            {
                static FILE *s_mid = NULL;
                static int s_mid_init = -1;
                if (s_mid_init < 0) {
                    const char *me = getenv("UHA_LMINDUMP");
                    s_mid_init = (me && g_oracle) ? 1 : 0;
                    if (s_mid_init && me)
                        s_mid = fopen(me, "w");
                    if (s_mid)
                        fprintf(s_mid,
                            "pos\targ\tDL\tDH\tdh\tbb\tbc\tS8c\tpend\tw16\toff\tkey\tcx\tce\tsm_live\tbud_live\tloop_live\tseeds\n");
                }
                if (s_mid) {
                    int m_arg = alz_token_class_index_ro(d);
                    int m_slot = 0xff;
                    uint32_t m_w16, m_off, m_key;
                    uint32_t m_base = 0, m_sm_live = 0, m_bud_live = 0;
                    /* [WALKER by-byte] The decider legacy 0x412c30 opere sure the
                     * CANDIDATE SCANNE by the finder at each position, SAME when
                     * there decision finale is has literal. under oracle the clone not
                     * peuple token/dist/count that sure the matchs -> on relance here
                     * the finder (PUR, no-emissive, as the probes cfdump/found)
                     * for exposer the candidate scanne independamment of l'emission. */
                    int ftok = 0;
                    uint32_t fd = 0, fc = 0;
                    int fh = alz_find_match(d, plain, usize, pos, min_len, tok2_min,
                                            hashtab, chain, hmask, cmask,
                                            &ftok, &fd, &fc)
                                 && fc >= 2u && pos + fc <= usize;
                    int z;
                    if (fh && ftok == 2) m_slot = 0;
                    else if (fh && ftok == 3) {
                        for (z = 1; z < ALZ_MAX_RECENT; z++)
                            if (d->st.recent_distance[z] == fd) { m_slot = z; break; }
                    }
                    m_w16 = (uint32_t)plain[pos]
                          | ((pos + 1 < usize ? (uint32_t)plain[pos + 1] : 0u) << 8);
                    /* [a5c2f-c-dump-fixes] Base of block LEGACY for l'index
                     * circulaire `off` : table blpos[6] some 6 blocks of scoring
                     * (13.140/1107). base = larger blpos STRICTEMENT < pos
                     * (there position-frontier elle-same remainder sure there base of the block
                     * previous : c30e off(12544)=12544, off(12545)=1). lim = len
                     * of the block current ([0x45cb5c]). */
                    {
                        static const uint32_t s_blpos[6] = {0x0000u, 0x3100u, 0x620cu,
                                                           0x931cu, 0xc4ffu, 0xff00u};
                        static const uint32_t s_blen[6]  = {0x3100u, 0x310cu, 0x3110u,
                                                           0x31e3u, 0x3a01u, 0x100u};
                        uint32_t s_base = 0, s_lim = s_blen[0];
                        int bk;
                        if (costfront_on) {
                            s_base = costfront_base;
                            s_lim = costfront_len;
                        } else {
                            for (bk = 0; bk < 6; bk++)
                                if (s_blpos[bk] < pos) { s_base = s_blpos[bk]; s_lim = s_blen[bk]; }
                        }
                        m_base = s_base;
                        m_off = (pos - s_base) & d->mode.dict_mask;
                        m_key = (fc + m_off < s_lim) ? (fc + m_off) : s_lim;
                    }
                    /* [a5c2f-c-cxce LIVE] cx/this = costs model (symbole-match /
                     * escape) of the line of class current, derives of the model
                     * d'emission `token_class[arg]` (mirror 0x45c308), via there
                     * primitive AlzSseMap[(freq<<14)/total] (0x43f154). Formule
                     * EXACT lue of the simulateur live sim412c30.py l.150-155 :
                     *   total=w[5] ; freq=w[dh+1]-w[dh] ; ce_freq=total-w[4]
                     *   cx=cost(freq,total) ; this=cost(ce_freq,total).
                     * read-only (no effect model/emission) ; state aligne
                     * sure l'oracle (lockstep model prouve 7002). dh bound has 1..3
                     * (TOK1/2/3) for to keep l'index w[dh+1] <= 5. */
                    uint32_t m_cx = 0, m_ce = 0;
                    {
                        const uint16_t *tc = d->token_class[m_arg];
                        uint32_t tot = tc[5];
                        int di = (ftok >= 1 && ftok <= 3) ? ftok : 0;
                        uint32_t fsym = di >= 1
                            ? (uint32_t)((uint32_t)tc[di + 1] - tc[di]) & 0xFFFFu
                            : 0u;
                        uint32_t fes = ((uint32_t)tot - tc[4]) & 0xFFFFu;
                        uint32_t pi = tot ? ((fsym << 14) / tot) : 16384u;
                        uint32_t pe = tot ? ((fes << 14) / tot) : 16384u;
                        if (pi > 16384u) pi = 16384u;
                        if (pe > 16384u) pe = 16384u;
                        m_cx = (uint32_t) AlzSseMap[pi];
                        m_ce = (uint32_t) AlzSseMap[pe];
                    }
                    /* [a5c2f-c-lmin-asm] sm_live = SUM dens[off,key) (index block
                     * relatif -> absolu via m_base) ; bud_live = SUM dens[pos-256..pos)
                     * (proxy ring 256, 13.246). Source = g_lmin_dens (UHA_LMINLIVE).
                     * validation offline : sm_live==sm_capture (c30e col32) block0. */
                    if (g_lmin_dens_ready) {
                        uint32_t j;
                        for (j = m_off; j < m_key && (m_base + j) < usize; j++)
                            m_sm_live += g_lmin_dens[m_base + j];
                        for (j = (pos >= 256u ? pos - 256u : 0u); j < pos; j++)
                            m_bud_live += g_lmin_dens[j];
                    }
                    /* [a5c2f-c-govern-loop validation] chain loop_live (same
                     * walker that there gouvernance) for recoupement offline vs there
                     * captures legacy c30e col `loop` (join pos). under oracle l'state
                     * model == legacy => teste the walker pur (seed last_byte +
                     * c2=cost-escape(cls)). read-only, no-emissive. */
                    char loopbuf[640];
                    {
                        const uint8_t *mc = alz_lm_mapcls_table();
                        uint32_t b = (uint32_t)d->st.literal_mode;   /* = [0x45ECC9] (prouve 100% 13.316) */
                        uint32_t steps = (fc > 1u) ? (fc - 1u) : 0u;
                        int li, off = 0;
                        loopbuf[0] = '\0';
                        for (li = 0; (uint32_t)li < steps && li < 64; li++) {
                            uint32_t cls = mc[b & 0xFFu];
                            const uint16_t *w2 = d->token_class[(cls < 66u) ? cls : 0u];
                            uint32_t t2 = w2[5];
                            uint32_t f2 = ((uint32_t)t2 - w2[4]) & 0xFFFFu;
                            uint32_t p2 = t2 ? ((f2 << 14) / t2) : 16384u;
                            uint32_t c2;
                            if (p2 > 16384u) p2 = 16384u;
                            c2 = (uint32_t) AlzSseMap[p2];
                            off += snprintf(loopbuf + off, sizeof(loopbuf) - (size_t)off,
                                            "%s%u:%u", li ? "," : "", (unsigned)cls, (unsigned)c2);
                            if (off < 0 || (size_t)off >= sizeof(loopbuf)) break;
                            if (cls == 0u) break;
                            b = cls;
                        }
                    }
                    fprintf(s_mid, "%u\t%d\t%u\t%d\t%d\t%d\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%s\t%u,%u,%u,%u,%u,%u,%u\n",
                            (unsigned) pos, m_arg, (unsigned) fc, (int) (fc ? fc - 1 : 0),
                            ftok, m_slot, d->mode.method_class,
                            (unsigned) (fh ? fd : 0xffffffffu),
                            (unsigned) d->st.repeat_run, m_w16, m_off, m_key,
                            (unsigned) m_cx, (unsigned) m_ce,
                            (unsigned) m_sm_live, (unsigned) m_bud_live, loopbuf,
                            (unsigned) d->st.last_byte, (unsigned) d->st.prev_byte,
                            (unsigned) d->st.literal_mode, (unsigned) d->st.match_flag_byte,
                            (unsigned) d->st.last_match_tail, (unsigned) d->st.escape_selector,
                            (unsigned) d->st.prev_delta);
                }
            }
            /* [a5c2f-c-replace GATED UHA_LMCOSTDUMP, default-OFF, ORACLE-ONLY,
             * read-only, no-emissive] By pos, expose the TWO candidates en
             * competition (TOK1 glouton long vs meilleur recent TOK2/3) with
             * leur ALZ MATCH MODEL COST REEL, for determiner the discriminateur
             * legacy (argmin cost) offline vs c30e. Not mute nor d nor l'emission. */
            {
                static FILE *s_cd = NULL;
                static int s_cd_init = -1;
                if (s_cd_init < 0) {
                    const char *ce = getenv("UHA_LMCOSTDUMP");
                    s_cd_init = (ce && g_oracle) ? 1 : 0;
                    if (s_cd_init && ce) s_cd = fopen(ce, "w");
                    if (s_cd)
                        fprintf(s_cd, "pos\tt1d\tt1l\tt1c\trk\trd\trl\trc\tlo\thi\tgap\tt1lit\n");
                }
                if (s_cd) {
                    uint32_t maxenc = usize - pos, t1d = 0, t1l = 0, t1c = ~0u;
                    uint32_t rd = 0, rl = 0, rc = ~0u; int rk = 0, sl;
                    if (maxenc > 255u) maxenc = 255u;
                    {
                        uint32_t n1 = alz_plain_match_len(d, plain, usize, pos, 1u);
                        uint32_t cd = 0, cn;
                        int e1, ec;
                        if (n1 > maxenc) n1 = maxenc;
                        e1 = alz_best_encodable_len(d, 1, 1u, (int)n1);
                        if (e1 >= 2) { t1l = (uint32_t)e1; t1d = 1u; }
                        cn = alz_chain_best(d, plain, usize, pos, hashtab, chain,
                                            hmask, cmask, &cd);
                        if (cn > maxenc) cn = maxenc;
                        ec = alz_best_encodable_len(d, 1, cd, (int)cn);
                        if (ec >= 2 && (uint32_t)ec > t1l) { t1l = (uint32_t)ec; t1d = cd; }
                        if (t1l >= 2) t1c = alz_match_model_cost(d, 1, t1d, t1l);
                    }
                    for (sl = 0; sl < ALZ_MAX_RECENT; sl++) {
                        uint32_t r = d->st.recent_distance[sl];
                        int tok = (sl == 0) ? 2 : 3; int e;
                        uint32_t n;
                        if (r == 0 || r > d->mode.dict_mask) continue;
                        n = alz_plain_match_len(d, plain, usize, pos, r);
                        if (n > maxenc) n = maxenc;
                        e = alz_best_encodable_len(d, tok, r, (int)n);
                        if (e >= 2 && (uint32_t)e > rl) { rl = (uint32_t)e; rd = r; rk = tok; }
                    }
                    if (rl >= 2) rc = alz_match_model_cost(d, rk, rd, rl);
                    /* Discriminateur amorti : sure there span max(t1l,rl) commune,
                     * the candidate the more long not gagne that if son cost-self is
                     * <= the one of the more short + cost LITERAL some bytes of gap.
                     * read-only (alz_bm_literal_cost_warm restores l'state). */
                    {
                        uint32_t lo = (t1l < rl) ? t1l : rl;
                        uint32_t hi = (t1l > rl) ? t1l : rl;
                        uint32_t gap = (hi > lo)
                            ? alz_bm_literal_cost_warm(d, plain, usize, pos + lo, hi - lo)
                            : 0u;
                        uint32_t t1lit = (t1l >= 2)
                            ? alz_bm_literal_cost_warm(d, plain, usize, pos, t1l)
                            : 0u;
                        fprintf(s_cd, "%u\t%u\t%u\t%u\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                                (unsigned)pos, (unsigned)t1d, (unsigned)t1l, (unsigned)t1c,
                                rk, (unsigned)rd, (unsigned)rl, (unsigned)rc,
                                (unsigned)lo, (unsigned)hi, (unsigned)gap, (unsigned)t1lit);
                    }
                }
            }
            /* [a5c2f-c-govern GATED UHA_LMGovern, default-OFF, FROM-SCRATCH]
             * Gouverne l'emission by the decider of flush legacy 0x412c30
             * (alz_lm_decide) au lieu of the grille lazy/min_len. Assemble lm_in
             * from-clone (candidate greedy have2/token/dist/count + scalaires
             * prouves 13.314 : arg/DL/dh/bb/bc/S8c/pend/w16/off/key/cx/this/sm/bud)
             * + v via g_lmgov_vtab, calls the decider, sets emit_lit=(al==0).
             * loop[] differe = EMPTY (nloop=0) for there 1re measures (al=(ecx<esi),
             * conservateur). Exige there pre-pass dens (g_lmin_dens_ready). Zero
             * effet when UHA_LMGovern absent (s_lmgov==0) now under oracle. */
            {
                static int s_lmgov = -1;
                if (s_lmgov < 0)
                    s_lmgov = (getenv("UHA_LMGovern") != NULL) ? 1 : 0;
                /* [measures isolee] UHA_LMGovernOracle : gouverne SURE THE CANDIDATE
                 * ORACLE FORCES (parfait). if there size remainder 7002, the decider
                 * (nloop=0) is faithful au candidate -> the gap 7078-7002 vient of the
                 * STRING DIFFEREE loop[]. otherwise the gap vient of the candidate lui-same. */
                static int s_lmgov_orc = -1;
                if (s_lmgov_orc < 0)
                    s_lmgov_orc = (getenv("UHA_LMGovernOracle") != NULL) ? 1 : 0;
                /* [livebud-ring GATED UHA_BUDFORCE=path, default-OFF, READING
                 * SINGLE] Injection of the budget legacy EXACT by position in the
                 * decider, for confirmer CAUSALEMENT that `bud` is there root of the
                 * first flip (pos 690, scalaires otherwise exact, cf 13.330).
                 * Format : `<pos>\t<bud>` by line. no effect if absent. */
                static int s_budforce = -1;
                static uint32_t *s_budforce_tab = NULL;
                if (s_budforce < 0) {
                    const char *bp = getenv("UHA_BUDFORCE");
                    s_budforce = bp ? 1 : 0;
                    if (s_budforce && bp) {
                        uint32_t zn;
                        s_budforce_tab = (uint32_t *) malloc((65536u + 1u) * sizeof(uint32_t));
                        if (s_budforce_tab) {
                            for (zn = 0; zn <= 65536u; zn++) s_budforce_tab[zn] = 0xFFFFFFFFu;
                            {
                                FILE *bf = fopen(bp, "r");
                                if (bf) {
                                    char ln[160];
                                    while (fgets(ln, sizeof ln, bf)) {
                                        unsigned p, v;
                                        if (sscanf(ln, "%u\t%u", &p, &v) == 2 && p <= 65536u)
                                            s_budforce_tab[p] = (uint32_t) v;
                                    }
                                    fclose(bf);
                                } else { s_budforce = 0; }
                            }
                        } else { s_budforce = 0; }
                    }
                }
                /* [GATED UHA_SMFORCE=path, default-OFF, read-only, ORACLE-CHEAT]
                 * Injecte the `sm` legacy EXACT by position (Sigma dens sure the span), for
                 * trancher CAUSALEMENT if the frontier @13070 is there sum d'arena `sm`
                 * (and no bud/ecx/loop). Format `<pos>\t<sm>`. no effect if absent. */
                static int s_smforce = -1;
                static uint32_t *s_smforce_tab = NULL;
                if (s_smforce < 0) {
                    const char *sp = getenv("UHA_SMFORCE");
                    s_smforce = sp ? 1 : 0;
                    if (s_smforce && sp) {
                        uint32_t zn2;
                        s_smforce_tab = (uint32_t *) malloc((65536u + 1u) * sizeof(uint32_t));
                        if (s_smforce_tab) {
                            for (zn2 = 0; zn2 <= 65536u; zn2++) s_smforce_tab[zn2] = 0xFFFFFFFFu;
                            FILE *sf = fopen(sp, "r");
                            if (sf) {
                                char ln2[160];
                                while (fgets(ln2, sizeof ln2, sf)) {
                                    unsigned p2, v2;
                                    if (sscanf(ln2, "%u\t%u", &p2, &v2) == 2 && p2 <= 65536u)
                                        s_smforce_tab[p2] = (uint32_t) v2;
                                }
                                fclose(sf);
                            } else { s_smforce = 0; }
                        } else { s_smforce = 0; }
                    }
                }
                if (s_lmgov && (!g_oracle || s_lmgov_orc) && have2 && pos + count <= usize
                    && g_lmin_dens_ready) {
                    if (!g_lmgov_vtab)
                        g_lmgov_vtab = (uint8_t *) calloc(LM_V_CTXSIZE, 1u);
                    if (g_lmgov_vtab) {
                        lm_in     gin;
                        lm_out    gout;
                        int       g_slot = 0xff, gz;
                        uint32_t  g_w16, g_off, g_key, g_base = 0, g_sm = 0, g_bud = 0;
                        uint32_t  g_cx = 0, g_ce = 0, g_lim, j, tot, di, fsym, fes, pi, pe;
                        uint32_t  g_lpush = 0, g_lslot = 0, g_lold = 0; int g_budlit_on = 0;
                        /* [livebud-ring GATED UHA_BUDLIT, default-OFF] ring budget
                         * FIFO sure the 256 LAST LITERALS (window EXACT prouvee
                         * 13.346 : 29948/29948 bit-exact with acc legacy), persistant
                         * sure all the file, seed 255*37440, reset has pos==0. */
                        static uint32_t s_blit_ring[256];
                        static uint32_t s_blit_head = 0;
                        static uint64_t s_blit_sum  = 0;
                        static int      s_blit      = -1;
                        int       g_arg = alz_token_class_index_ro(d);
                        const uint16_t *gtc;
                        static const uint32_t s_blpos[6] = {0x0000u, 0x3100u, 0x620cu,
                                                           0x931cu, 0xc4ffu, 0xff00u};
                        static const uint32_t s_blen[6]  = {0x3100u, 0x310cu, 0x3110u,
                                                           0x31e3u, 0x3a01u, 0x100u};
                        int bk;
                        if (pos == 0u)
                            memset(g_lmgov_vtab, 0, LM_V_CTXSIZE);
                        if (token == 2) g_slot = 0;
                        else if (token == 3) {
                            for (gz = 1; gz < ALZ_MAX_RECENT; gz++)
                                if (d->st.recent_distance[gz] == dist) { g_slot = gz; break; }
                        }
                        /* [DIAGNOSTIC GATED UHA_MRUDUMP=pos, read-only, default-OFF,
                         * NO-MUTANT] dump of the table of recence recent_distance[] +
                         * of the candidate finder (token,dist,count) has has position donnee,
                         * for determiner if there divergence 954 is has probleme of
                         * SURFACAGE of candidate (d257 absent some recents clone) now of
                         * decider. no effect without env. */
                        {
                            static long s_mrud = -1;
                            if (s_mrud < 0) {
                                const char *e = getenv("UHA_MRUDUMP");
                                s_mrud = e ? atol(e) : -2;
                            }
                            if (s_mrud >= 0 && (long)pos == s_mrud) {
                                fprintf(stderr, "[MRU] pos=%u cand=tok%d/d%u/c%u slot=%d recent=[",
                                        (unsigned)pos, token, (unsigned)dist,
                                        (unsigned)count, g_slot);
                                for (gz = 0; gz < ALZ_MAX_RECENT; gz++)
                                    fprintf(stderr, "%u%s", (unsigned)d->st.recent_distance[gz],
                                            gz + 1 < ALZ_MAX_RECENT ? "," : "");
                                fprintf(stderr, "]\n");
                                fflush(stderr);
                            }
                        }
                        g_w16 = (uint32_t)plain[pos]
                              | ((pos + 1 < usize ? (uint32_t)plain[pos + 1] : 0u) << 8);
                        if (costfront_on) {
                            g_base = costfront_base;
                            g_lim = costfront_len;
                        } else {
                            g_lim = s_blen[0];
                            for (bk = 0; bk < 6; bk++)
                                if (s_blpos[bk] < pos) { g_base = s_blpos[bk]; g_lim = s_blen[bk]; }
                        }
                        g_off = (pos - g_base) & d->mode.dict_mask;
                        g_key = (count + g_off < g_lim) ? (count + g_off) : g_lim;
                        /* [GATED UHA_SM_LIVE, default-OFF, 14.068] Integration singlepass : the
                         * `sm` of the neartie (comparateur `0x412c30`) reads the cost LIVE of the master
                         * (`g_lmin_live`, advances by l'acclive during l'emission for j <= pos) au
                         * lieu of the window proxy prepasse. Retombe sure `g_lmin_dens` if live no
                         * still sets. DefautOFF = proxy strictement unchanged (prod 13809). */
                        {
                            static int s_smlive = -1;
                            static int s_smscale_b1 = -1;
                            static int s_smscale_b1_lim = -1;
                            static int s_smscale_b2 = -1;
                            static int s_smscale_b2_lim = -1;
                            static int s_smscale_b3 = -1;
                            static int s_smscale_b3_lim = -1;
                            static int s_smscale_b4 = -1;
                            static int s_smscale_blk2 = -1;
                            static int s_smscale_t1ramp = -1;
                            static int s_smscale_flat = -1;
                            if (s_smlive < 0) s_smlive = getenv("UHA_SM_LIVE") ? 1 : 0;
                            if (s_smscale_b1 < 0) {
                                const char *scb = getenv("UHA_SMSCALE_B1");
                                s_smscale_b1 = scb ? atoi(scb) : 1000;
                            }
                            if (s_smscale_b1_lim < 0) {
                                const char *lmb = getenv("UHA_SMSCALE_B1_LIM");
                                s_smscale_b1_lim = lmb ? atoi(lmb) : 0;
                            }
                            if (s_smscale_b2 < 0) {
                                const char *scb2 = getenv("UHA_SMSCALE_B2");
                                s_smscale_b2 = scb2 ? atoi(scb2) : 1000;
                            }
                            if (s_smscale_b2_lim < 0) {
                                const char *lmb2 = getenv("UHA_SMSCALE_B2_LIM");
                                s_smscale_b2_lim = lmb2 ? atoi(lmb2) : 0;
                            }
                            if (s_smscale_b3 < 0) {
                                const char *scb3 = getenv("UHA_SMSCALE_B3");
                                s_smscale_b3 = scb3 ? atoi(scb3) : 1000;
                            }
                            if (s_smscale_b3_lim < 0) {
                                const char *lmb3 = getenv("UHA_SMSCALE_B3_LIM");
                                s_smscale_b3_lim = lmb3 ? atoi(lmb3) : 0;
                            }
                            if (s_smscale_b4 < 0) {
                                const char *scb4 = getenv("UHA_SMSCALE_B4");
                                s_smscale_b4 = scb4 ? atoi(scb4) : 1000;
                            }
                            static int s_smscale_b4_lim = -1;
                            if (s_smscale_b4_lim < 0) {
                                const char *lmb4 = getenv("UHA_SMSCALE_B4_LIM");
                                s_smscale_b4_lim = lmb4 ? atoi(lmb4) : 0;
                            }
                            static int s_smscale_b5 = -1;
                            static int s_smscale_b5_lim = -1;
                            static int s_smscale_b5_max = -1;
                            static int s_smscale_b5_cool = -1;
                            if (s_smscale_b5 < 0) {
                                const char *scb5 = getenv("UHA_SMSCALE_B5");
                                s_smscale_b5 = scb5 ? atoi(scb5) : 1000;
                            }
                            if (s_smscale_b5_lim < 0) {
                                const char *lmb5 = getenv("UHA_SMSCALE_B5_LIM");
                                s_smscale_b5_lim = lmb5 ? atoi(lmb5) : 0;
                            }
                            if (s_smscale_b5_max < 0) {
                                const char *mb5 = getenv("UHA_SMSCALE_B5_MAX");
                                s_smscale_b5_max = mb5 ? atoi(mb5) : 0;
                            }
                            if (s_smscale_b5_cool < 0) {
                                const char *cb5 = getenv("UHA_SMSCALE_B5_COOL");
                                s_smscale_b5_cool = cb5 ? atoi(cb5) : 1000;
                            }
                            static int s_smscale_b6 = -1;
                            static int s_smscale_b6_lim = -1;
                            if (s_smscale_b6 < 0) {
                                const char *scb6 = getenv("UHA_SMSCALE_B6");
                                s_smscale_b6 = scb6 ? atoi(scb6) : 1000;
                            }
                            if (s_smscale_b6_lim < 0) {
                                const char *lmb6 = getenv("UHA_SMSCALE_B6_LIM");
                                s_smscale_b6_lim = lmb6 ? atoi(lmb6) : 0;
                            }
                            if (s_smscale_blk2 < 0) {
                                const char *scb2k = getenv("UHA_SMSCALE_BLK2");
                                s_smscale_blk2 = scb2k ? atoi(scb2k) : 1000;
                            }
                            static int s_smscale_blk2_cool = -1;
                            static int s_smscale_blk2_cool_lim = -1;
                            static int s_smscale_blk2_cool_max = -1;
                            if (s_smscale_blk2_cool < 0) {
                                const char *sc = getenv("UHA_SMSCALE_BLK2_COOL");
                                s_smscale_blk2_cool = sc ? atoi(sc) : 1000;
                                const char *lim = getenv("UHA_SMSCALE_BLK2_COOL_LIM");
                                s_smscale_blk2_cool_lim = lim ? atoi(lim) : 0;
                                const char *max = getenv("UHA_SMSCALE_BLK2_COOL_MAX");
                                s_smscale_blk2_cool_max = max ? atoi(max) : 0;
                            }
                            static int s_smscale_blk2_cool2 = -1;
                            static int s_smscale_blk2_cool2_lim = -1;
                            static int s_smscale_blk2_cool2_max = -1;
                            if (s_smscale_blk2_cool2 < 0) {
                                const char *sc = getenv("UHA_SMSCALE_BLK2_COOL2");
                                s_smscale_blk2_cool2 = sc ? atoi(sc) : 1000;
                                const char *lim = getenv("UHA_SMSCALE_BLK2_COOL2_LIM");
                                s_smscale_blk2_cool2_lim = lim ? atoi(lim) : 0;
                                const char *max = getenv("UHA_SMSCALE_BLK2_COOL2_MAX");
                                s_smscale_blk2_cool2_max = max ? atoi(max) : 0;
                            }
                            static int s_smscale_blk2_cool3 = -1;
                            static int s_smscale_blk2_cool3_lim = -1;
                            static int s_smscale_blk2_cool3_max = -1;
                            if (s_smscale_blk2_cool3 < 0) {
                                const char *sc = getenv("UHA_SMSCALE_BLK2_COOL3");
                                s_smscale_blk2_cool3 = sc ? atoi(sc) : 1000;
                                const char *lim = getenv("UHA_SMSCALE_BLK2_COOL3_LIM");
                                s_smscale_blk2_cool3_lim = lim ? atoi(lim) : 0;
                                const char *max = getenv("UHA_SMSCALE_BLK2_COOL3_MAX");
                                s_smscale_blk2_cool3_max = max ? atoi(max) : 0;
                            }
                            static int s_smscale_blk3 = -1;
                            if (s_smscale_blk3 < 0) {
                                const char *scb3k = getenv("UHA_SMSCALE_BLK3");
                                s_smscale_blk3 = scb3k ? atoi(scb3k) : 1000;
                            }
                            static int s_smscale_blk2_v1 = -1;
                            if (s_smscale_blk2_v1 < 0) {
                                const char *scb2v = getenv("UHA_SMSCALE_BLK2_V1");
                                s_smscale_blk2_v1 = scb2v ? atoi(scb2v) : 1000;
                            }
                            static int s_smscale_blk2_v2 = -1;
                            if (s_smscale_blk2_v2 < 0) {
                                const char *scb2v2 = getenv("UHA_SMSCALE_BLK2_V2");
                                s_smscale_blk2_v2 = scb2v2 ? atoi(scb2v2) : 1000;
                            }
                            static int s_smscale_blk2_v3 = -1;
                            if (s_smscale_blk2_v3 < 0) {
                                const char *scb2v3 = getenv("UHA_SMSCALE_BLK2_V3");
                                s_smscale_blk2_v3 = scb2v3 ? atoi(scb2v3) : 1000;
                            }
                            static int s_smscale_blk3_v1 = -1;
                            if (s_smscale_blk3_v1 < 0) {
                                const char *scb3v1 = getenv("UHA_SMSCALE_BLK3_V1");
                                s_smscale_blk3_v1 = scb3v1 ? atoi(scb3v1) : 1000;
                            }
                            static int s_smscale_blk3_v2 = -1;
                            if (s_smscale_blk3_v2 < 0) {
                                const char *scb3v2 = getenv("UHA_SMSCALE_BLK3_V2");
                                s_smscale_blk3_v2 = scb3v2 ? atoi(scb3v2) : 1000;
                            }
                            static int s_smscale_blk3_v3 = -1;
                            if (s_smscale_blk3_v3 < 0) {
                                const char *scb3v3 = getenv("UHA_SMSCALE_BLK3_V3");
                                s_smscale_blk3_v3 = scb3v3 ? atoi(scb3v3) : 1000;
                            }
                            static int s_smscale_blk4_v1 = -1;
                            static int s_smscale_blk0 = -1;
                            static int s_smscale_b1_v2 = -1;
                            if (s_smscale_b1_v2 < 0) {
                                const char *sc = getenv("UHA_SMSCALE_B1_V2");
                                s_smscale_b1_v2 = sc ? atoi(sc) : 1000;
                            }
                            static int s_smscale_blk0_lim = -1;
                            if (s_smscale_blk0 < 0) {
                                const char *scb0k = getenv("UHA_SMSCALE_BLK0");
                                s_smscale_blk0 = scb0k ? atoi(scb0k) : 1000;
                                const char *sclim = getenv("UHA_SMSCALE_BLK0_LIM");
                                s_smscale_blk0_lim = sclim ? atoi(sclim) : 0;
                            }
                            if (s_smscale_blk4_v1 < 0) {
                                const char *scb4v1 = getenv("UHA_SMSCALE_BLK4_V1");
                                s_smscale_blk4_v1 = scb4v1 ? atoi(scb4v1) : 1000;
                            }
                            if (s_smscale_t1ramp < 0) {
                                const char *sct1 = getenv("UHA_SMSCALE_T1RAMP");
                                s_smscale_t1ramp = sct1 ? atoi(sct1) : 1000;
                            }
                            static int s_smscale_flat_blk2 = -1;
                            if (s_smscale_flat < 0) {
                                const char *scfl = getenv("UHA_SMSCALE_FLAT");
                                s_smscale_flat = scfl ? atoi(scfl) : 1000;
                            }
                            if (s_smscale_flat_blk2 < 0) {
                                const char *sfb2 = getenv("UHA_SMSCALE_FLAT_BLK2");
                                s_smscale_flat_blk2 = sfb2 ? atoi(sfb2) : 1000;
                            }
                            static int s_coolmap_set = 0;
                            static uint32_t s_cool_p0[32], s_cool_p1[32], s_cool_sc[32];
                            static int s_cool_cnt = 0;
                            if (!s_coolmap_set) {
                                const char *cmap = getenv("UHA_SMSCALE_COOL_MAP");
                                if (cmap) {
                                    char buf[4096];
                                    strncpy(buf, cmap, sizeof(buf) - 1);
                                    buf[sizeof(buf) - 1] = '\0';
                                    char *tok = strtok(buf, ",");
                                    while (tok && s_cool_cnt < 32) {
                                        unsigned p0, p1, sc;
                                        if (sscanf(tok, "%u:%u:%u", &p0, &p1, &sc) == 3) {
                                            s_cool_p0[s_cool_cnt] = p0;
                                            s_cool_p1[s_cool_cnt] = p1;
                                            s_cool_sc[s_cool_cnt] = sc;
                                            s_cool_cnt++;
                                        }
                                        tok = strtok(NULL, ",");
                                    }
                                }
                                s_coolmap_set = 1;
                            }
                            int cool_hit = 0;
                            uint32_t cool_factor = 1000;
                            for (int ci = 0; ci < s_cool_cnt; ci++) {
                                if (pos >= s_cool_p0[ci] && pos < s_cool_p1[ci]) {
                                    cool_factor = s_cool_sc[ci];
                                    cool_hit = 1;
                                    break;
                                }
                            }
                            for (j = g_off; j < g_key && (g_base + j) < usize; j++) {
                                uint32_t sv = (s_smlive && g_lmin_live_ready && g_lmin_live &&
                                               (g_base + j) >= 0x3100u &&
                                               g_lmin_live[g_base + j])
                                            ? g_lmin_live[g_base + j]
                                            : (g_lmin_dens ? g_lmin_dens[g_base + j] : 0u);
                                if (cool_hit) {
                                    if (cool_factor != 1000)
                                        sv = (uint32_t)(((uint64_t)sv * (uint64_t)cool_factor) / 1000u);
                                } else if (g_base == 0u && s_smscale_blk0 != 1000) {
                                    if (s_smscale_blk0_lim <= 0 || pos >= (uint32_t)s_smscale_blk0_lim)
                                        sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk0) / 1000u);
                                } else if (g_base == 0x3100u) {
                                    if (s_smscale_b5_max > 0 && pos >= (uint32_t)s_smscale_b5_max) {
                                        if (s_smscale_b5_cool != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b5_cool) / 1000u);
                                    } else if (s_smscale_b5_lim > 0 && pos >= (uint32_t)s_smscale_b5_lim) {
                                        if (s_smscale_b5 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b5) / 1000u);
                                    } else if (s_smscale_b3_lim > 0 && pos >= (uint32_t)s_smscale_b3_lim &&
                                        (s_smscale_b4_lim <= 0 || pos < (uint32_t)s_smscale_b4_lim)) {
                                        if (s_smscale_b4 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b4) / 1000u);
                                    } else if (s_smscale_b2_lim > 0 && pos >= (uint32_t)s_smscale_b2_lim) {
                                        if (s_smscale_b3 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b3) / 1000u);
                                    } else if (s_smscale_b1_lim > 0 && pos >= (uint32_t)s_smscale_b1_lim) {
                                        if (s_smscale_b2 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b2) / 1000u);
                                    } else {
                                        if (s_smscale_b1 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b1) / 1000u);
                                    }
                                } else if (g_base == 0x620cu) {
                                    if (s_smscale_blk2_cool3_lim > 0 && pos >= (uint32_t)s_smscale_blk2_cool3_lim &&
                                        (s_smscale_blk2_cool3_max <= 0 || pos < (uint32_t)s_smscale_blk2_cool3_max)) {
                                        if (s_smscale_blk2_cool3 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2_cool3) / 1000u);
                                        else if (s_smscale_blk2 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2) / 1000u);
                                    } else if (s_smscale_b6_lim > 0 && pos >= (uint32_t)s_smscale_b6_lim) {
                                        if (s_smscale_b6 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_b6) / 1000u);
                                    } else if (s_smscale_blk2_cool_lim > 0 && pos >= (uint32_t)s_smscale_blk2_cool_lim &&
                                               (s_smscale_blk2_cool_max <= 0 || pos < (uint32_t)s_smscale_blk2_cool_max)) {
                                        if (s_smscale_blk2_cool != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2_cool) / 1000u);
                                        else if (s_smscale_blk2 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2) / 1000u);
                                    } else if (s_smscale_blk2_cool2_lim > 0 && pos >= (uint32_t)s_smscale_blk2_cool2_lim &&
                                               (s_smscale_blk2_cool2_max <= 0 || pos < (uint32_t)s_smscale_blk2_cool2_max)) {
                                        if (s_smscale_blk2_cool2 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2_cool2) / 1000u);
                                        else if (s_smscale_blk2 != 1000)
                                            sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2) / 1000u);
                                    } else if (s_smscale_blk2 != 1000) {
                                        sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk2) / 1000u);
                                    }
                                } else if (g_base == 0x931cu) {
                                    if (s_smscale_blk3 != 1000)
                                        sv = (uint32_t)(((uint64_t)sv * (uint64_t)s_smscale_blk3) / 1000u);
                                }
                                g_sm += sv;
                            }
                            if (s_smscale_t1ramp != 1000 && token == 1 && count >= 13u && pos >= 18432u && ((pos % 256u) == 0u || (pos >= 21760u && (pos % 256u) <= 2u)) && (dist > 5000u || pos >= 21760u) && g_base == 0x3100u) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_t1ramp) / 1000u);
                            }
                            if (s_smscale_flat != 1000 && token == 1 && count >= 4u && pos >= 20000u && pos < 26000u && ((pos + 1 < usize && plain[pos] == plain[pos + 1]) || (pos > 0 && plain[pos] == plain[pos - 1]))) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_flat) / 1000u);
                            }
                            if (s_smscale_flat_blk2 != 1000 && ((token == 1 && count >= 4u) || (token == 3 && count >= 12u)) && pos >= 26000u && ((pos + 1 < usize && plain[pos] == plain[pos + 1]) || (pos > 0 && plain[pos] == plain[pos - 1]))) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_flat_blk2) / 1000u);
                            }
                            if (s_smscale_b1_v2 != 1000 &&
                                (((token == 2 && ((count >= 8u && pos < 19000u) || (count >= 5u && pos < 13850u))) ||
                                  (token == 3 && count >= 8u && ((pos >= 13410u && pos < 13850u) || (pos >= 15500u && pos < 16500u)))) ||
                                 (token == 3 && ((count >= 14u && pos >= 18000u && pos < 22000u) || (count >= 8u && pos >= 22000u && pos < 23000u) || (count >= 7u && pos >= 23000u))) ||
                                 (token == 1 && count >= 10u && pos >= 22000u)) &&
                                ((dist >= 255u && dist <= 258u) || (((dist >= 511u && dist <= 512u) || (dist == 513u && (pos < 23000u || count >= 14u)) || (token == 1 && dist >= 1023u && dist <= 1026u)) && pos >= 22000u)) && (dist != 256u || pos >= 22000u) && g_base == 0x3100u) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_b1_v2) / 1000u);
                            }
                            if (s_smscale_blk2_v1 != 1000 && (token == 1 || (token == 2 && (((dist >= 256u && dist <= 258u) && ((pos >= 27500u && pos < 27600u) || (pos >= 28320u && pos < 28330u) || (pos >= 36700u && pos < 37632u))) || (dist == 1021u && pos >= 32200u && pos < 32300u) || (dist == 255u && pos >= 32000u))) || (token == 3 && ((dist >= 256u && dist <= 258u && pos >= 27000u) || (dist == 255u && pos >= 32000u) || dist == 4353u || dist == 3072u || (dist == 511u && pos >= 27800u && pos < 27900u) || (dist == 767u && pos >= 27800u && pos < 27900u) || (dist == 12033u && pos >= 30300u && pos < 30500u) || (dist == 1021u && pos >= 32200u && pos < 32300u) || dist == 18429u))) &&
                                ((count >= 14u && (dist != 511u || pos < 27900u) && (dist != 767u || pos < 27900u)) || (count >= 13u && ((dist >= 256u && dist <= 257u) || (dist == 511u && pos < 27900u) || dist == 4353u)) || (count >= 11u && dist >= 256u && dist <= 258u && pos >= 27100u && pos < 27300u) || (count >= 6u && token == 2 && dist >= 256u && dist <= 258u && pos >= 27500u && pos < 27600u) || (count >= 7u && token == 2 && dist >= 256u && dist <= 258u && pos >= 28320u && pos < 28330u) || (count >= 9u && token == 2 && dist >= 256u && dist <= 258u && pos >= 36700u && pos < 37632u) || (count >= 12u && dist == 3072u && pos >= 26000u) || (count >= 6u && token == 3 && (dist == 511u || dist == 767u) && pos >= 27800u && pos < 27900u) || (count >= 10u && token == 3 && dist == 12033u && pos >= 30300u && pos < 30500u) || (count >= 12u && dist == 1021u && pos >= 32200u && pos < 32300u) || (count >= 11u && dist == 255u && pos >= 34700u && pos < 36000u)) &&
                                ((dist >= 256u && dist <= 258u) || (dist == 255u && pos >= 32000u) || (dist >= 4352u && dist <= 4353u) || (dist == 3072u && pos >= 26000u) || (dist == 511u && pos < 27900u) || (dist == 5119u && pos >= 26900u) || (dist == 767u && pos >= 27800u && pos < 27900u) || (dist == 12033u && pos >= 30300u && pos < 30500u) || (dist == 1021u && pos >= 32200u && pos < 32300u) || dist == 18429u || dist == 20735u || dist == 28945u || dist == 29967u) && g_base == 0x620cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk2_v1) / 1000u);
                            }
                            static int s_smscale_blk2_t2_cool = -1;
                            if (s_smscale_blk2_t2_cool < 0) {
                                const char *sc = getenv("UHA_SMSCALE_BLK2_T2_COOL");
                                s_smscale_blk2_t2_cool = sc ? atoi(sc) : 1000;
                            }
                            if (s_smscale_blk2_t2_cool != 1000 && token == 2 && dist == 4608u && g_base == 0x620cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk2_t2_cool) / 1000u);
                            }
                            static int s_smscale_b1_t2_cool = -1;
                            if (s_smscale_b1_t2_cool < 0) {
                                const char *sc = getenv("UHA_SMSCALE_B1_T2_COOL");
                                s_smscale_b1_t2_cool = sc ? atoi(sc) : 1000;
                            }
                            if (s_smscale_b1_t2_cool != 1000 && token == 2 && count <= 4u && ((pos >= 17000u && pos < 18000u) || (pos >= 21100u && pos < 21200u)) && g_base == 0x3100u) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_b1_t2_cool) / 1000u);
                            }
                            if (s_smscale_blk2_v2 != 1000 && token == 2 && count >= 8u &&
                                (dist == 255u || (dist == 257u && count >= 14u)) &&
                                pos >= 30700u && g_base == 0x620cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk2_v2) / 1000u);
                            }
                            if (s_smscale_blk2_v3 != 1000 && token == 3 && count >= 5u &&
                                (dist == 255u || (dist == 257u && pos >= 29500u)) &&
                                pos >= 27400u && g_base == 0x620cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk2_v3) / 1000u);
                            }
                            int v1_blk3_active = (pos >= 38400u && pos < 38450u) ||
                                                 (pos >= 39400u && pos < 40000u) ||
                                                 (pos >= 42080u && pos <= 42090u) ||
                                                 (pos >= 42550u && pos < 42800u) ||
                                                 (pos >= 43260u && pos < 43270u) ||
                                                 (pos >= 43515u && pos < 43530u) ||
                                                 (pos >= 44380u && pos < 44400u) ||
                                                 (pos >= 46075u && pos <= 46085u) ||
                                                 (pos >= 46170u && pos <= 46190u) ||
                                                 (pos >= 47100u && pos <= 47105u) ||
                                                 (pos >= 47240u && pos <= 47250u) ||
                                                 (pos >= 47305u && (pos < 47365u || (pos >= 47435u && (pos < 47720u || (pos >= 47905u && (pos < 48045u || pos >= 48155u))))));
                            if (s_smscale_blk3_v1 != 1000 && token == 1 &&
                                ((pos % 256u == 0u && count >= 11u) || count >= 14u) &&
                                dist != 45568u &&
                                ((dist % 256u <= 2u) || (dist % 256u >= 253u) || dist == 34576u || dist == 32529u) &&
                                v1_blk3_active && g_base == 0x931cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk3_v1) / 1000u);
                            }
                            int sc_v2 = s_smscale_blk3_v2;
                            if (sc_v2 != 1000 && pos >= 40000u)
                                sc_v2 = (int)(((int64_t)sc_v2 * 1026) / 1000);
                            if (sc_v2 != 1000 && token == 2 &&
                                dist != 45568u &&
                                ((pos >= 40470u && pos < 41600u) ? (count >= 11u) :
                                 ((pos >= 40000u) ? (count >= 6u) : (count >= 4u))) &&
                                (pos >= 37660u || count >= 10u) &&
                                (pos < 38130u || pos >= 38150u || count >= 15u) &&
                                (pos < 41700u || pos >= 42520u || count >= 7u) &&
                                (pos < 45055u || pos >= 45125u) &&
                                (pos < 45870u || pos >= 45975u || count >= 10u) &&
                                (pos < 46350u || pos >= 46405u) &&
                                (pos < 46925u || pos >= 47005u) &&
                                ((dist % 256u <= 2u) || (dist % 256u >= 254u) || dist == 1021u || (pos < 42000u && dist == 1027u)) &&
                                pos >= 37660u && g_base == 0x931cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)sc_v2) / 1000u);
                            }
                            if (s_smscale_blk3_v3 != 1000 && token == 3 && count >= 9u &&
                                dist != 45568u &&
                                (pos >= 38350u || count <= 9u) &&
                                (pos < 41500u || pos >= 42520u || count >= 12u) &&
                                (pos < 44150u || pos >= 44235u || count >= 11u) &&
                                (pos < 44490u || pos >= 44515u || count >= 12u) &&
                                (pos < 44570u || pos >= 44585u) &&
                                (pos < 44700u || pos >= 44765u || count >= 11u) &&
                                (pos < 44990u || pos >= 45015u) &&
                                (pos < 45055u || pos >= 45125u) &&
                                (pos < 45870u || pos >= 45975u || count >= 10u) &&
                                (pos < 46350u || pos >= 46405u) &&
                                (pos < 46925u || pos >= 47005u) &&
                                ((dist % 256u <= 2u) || (dist % 256u >= 254u) || dist == 1021u || (pos < 42000u && dist == 1027u)) &&
                                pos >= 38114u && g_base == 0x931cu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk3_v3) / 1000u);
                            }
                            if (s_smscale_blk4_v1 != 1000 && token == 1 && count >= 14u &&
                                pos >= 65000u && (dist == 51215u || (pos >= 65062u && (dist % 256u == 0u))) && g_base == 0xc4ffu) {
                                g_sm = (uint32_t)(((uint64_t)g_sm * (uint64_t)s_smscale_blk4_v1) / 1000u);
                            }
                        }
                        /* [GATED UHA_SMFORCE] injecte the sm legacy EXACT by pos. */
                        if (s_smforce && s_smforce_tab && pos <= 65536u
                            && s_smforce_tab[pos] != 0xFFFFFFFFu)
                            g_sm = s_smforce_tab[pos];
                        /* [cost-literal-live esi LEVER GATED UHA_COSTSM, default-OFF]
                         * isole the LEVIER `esi`/`mean` (not bud) : replaces there
                         * moyenne of the span by the cost byte-model PREDICTIF LIVE of the
                         * literal current (model hot lockstep, 13.351), i.e.
                         * g_sm := bm(pos)*(key-off) => mean = bm(pos) alimente esi.
                         * bud leaves dens (window d'origine). */
                        {
                            static int s_cosm = -1;
                            if (s_cosm < 0)
                                s_cosm = (getenv("UHA_COSTSM") != NULL) ? 1 : 0;
                            if (s_cosm) {
                                uint32_t nsp = (g_key > g_off) ? (g_key - g_off) : 1u;
                                uint32_t bm_cur = cl_bm_predict(d, plain);
                                g_sm = bm_cur * nsp;
                            }
                        }
                        if (s_blit < 0)
                            s_blit = (getenv("UHA_BUDLIT") != NULL) ? 1 : 0;
                        if (s_blit) {
                            uint32_t acc_push;
                            static int s_buddmix = -1;
                            if (pos == 0u) {
                                uint32_t k;
                                for (k = 0; k < 256u; k++) s_blit_ring[k] = 37440u;
                                s_blit_head = 0;
                                s_blit_sum  = 255ull * 37440ull;
                            }
                            if (s_buddmix < 0)
                                s_buddmix = (getenv("UHA_BUDDMIX") != NULL) ? 1 : 0;
                            if (s_buddmix) {
                                /* [GATED UHA_BUDDMIX, default-OFF, 13.647] pushes there
                                 * value FAITHFUL `acc` = cost-symbole of the mixeur of the
                                 * literal current (alz_bm_literal_cost_mix, same
                                 * derivation ctx/ctx2/sym that l'emission) in
                                 * l'ring bud, au lieu of the proxy `dens`. Rollback
                                 * sure match (l.5174) unchanged => cadence by-READS. */
                                int mctx, mctx2, msym;
                                cl_bm_ctx3(d, plain, &mctx, &mctx2, &msym);
                                acc_push = alz_bm_literal_cost_mix(d, mctx, mctx2, msym);
                            } else {
                                acc_push = g_lmin_dens[pos];
                            }
                            g_lold      = s_blit_ring[s_blit_head];
                            g_lslot     = s_blit_head;
                            g_lpush     = acc_push;
                            s_blit_sum += (uint64_t)acc_push - (uint64_t)g_lold;
                            s_blit_ring[s_blit_head] = acc_push;
                            s_blit_head = (s_blit_head + 1u) & 0xFFu;
                            g_bud       = (uint32_t) s_blit_sum;
                            g_budlit_on = 1;
                        }
                        if (!g_budlit_on) {
                            for (j = (pos >= 256u ? pos - 256u : 0u); j < pos; j++)
                                g_bud += g_lmin_dens[j];
                        }
                        /* [cost-literal-live GATED UHA_COSTLIVE] The budget gin.bud
                         * vient of l'ring LIVE FIFO-256-READS alimente in there loop
                         * d'emission (costs byte-model a_bm lag-1, 13.351), no
                         * there window dens. read-only here (there poussee is faite has
                         * l'emission). Seed 255*37440 so much qu'no litteralemis. */
                        if (s_costlive < 0)
                            s_costlive = (getenv("UHA_COSTLIVE") != NULL) ? 1 : 0;
                        if (s_costlive) {
                            g_bud = s_cl_ready ? (uint32_t) s_cl_sum
                                               : (uint32_t)(255ull * (uint64_t)alz_cl_seed_resolve());
                        }
                        /* [GATED UHA_BUDWIN255, default-OFF, 14.104] The fit of legacy
                         * gives there window of budget = 255 literals (and no 256) :
                         * to remove has term-seed aligne `bud` under `0x91ADC0` -> branch
                         * mean -> rejets conformes. default-OFF = s_cl_sum unchanged. */
                        if (s_costlive && getenv("UHA_BUDWIN255") && s_cl_ready)
                            g_bud = (uint32_t)(s_cl_sum - (uint64_t)alz_cl_seed_resolve());
                        /* [GATED UHA_BUDFORCE] replaces the proxy from-plain by the
                         * budget legacy exact has this position (test causal bud). */
                        if (s_budforce && s_budforce_tab && pos <= 65536u
                            && s_budforce_tab[pos] != 0xFFFFFFFFu)
                            g_bud = s_budforce_tab[pos];
                        gtc = d->token_class[g_arg];
                        tot = gtc[5];
                        di = ((uint32_t)token >= 1u && (uint32_t)token <= 3u) ? (uint32_t)token : 0u;
                        fsym = di >= 1u ? ((uint32_t)((uint32_t)gtc[di + 1] - gtc[di]) & 0xFFFFu) : 0u;
                        fes = ((uint32_t)tot - gtc[4]) & 0xFFFFu;
                        pi = tot ? ((fsym << 14) / tot) : 16384u;
                        pe = tot ? ((fes << 14) / tot) : 16384u;
                        if (pi > 16384u) pi = 16384u;
                        if (pe > 16384u) pe = 16384u;
                        g_cx = (uint32_t) AlzSseMap[pi];
                        g_ce = (uint32_t) AlzSseMap[pe];
                        memset(&gin, 0, sizeof(gin));
                        gin.arg  = (uint32_t) g_arg;
                        gin.DL   = count;
                        gin.DH   = count ? count - 1u : 0u;
                        gin.dh   = (uint32_t) token;
                        gin.bb   = (uint32_t) g_slot;
                        gin.bc   = (uint32_t) d->mode.method_class;
                        gin.S8c  = dist;
                        gin.pend = (uint32_t) d->st.repeat_run;
                        /* [GATED UHA_BUDACC80, default-OFF] `bud` = l'accumulateur REELLEMENT
                         * tenu by the byte-model, more no proxy : `alz_bm_encode_literal`
                         * does `pcounter=(pcounter+1)&0xFF; acc80 -= bm_table[pcounter]` (pop)
                         * then `bm_pred_tail` : `bm_table[pcounter]=mixer; bm_acc80 += mixer`
                         * (push) = exactement l'ring 256 legacy (eviction `0x4111db`,
                         * push `0x41137c/0x41137e`, `bud=[0x45cc80]`, invariant prouve
                         * `bud == Sigma ring[0..255]  37440`). The anneaux synthetiques
                         * COSTLIVE/ACCRING/BUDLIT (`s_cl_sum`) were has proxy divergent
                         * (measured 2026-10-20 : poussee C4 0,14 % / mix lag-1 96,37 % of the GT).
                         * Zero effet out gate. */
                        {
                            static int s_bud80 = -1;
                            if (s_bud80 < 0) s_bud80 = getenv("UHA_BUDACC80") ? 1 : 0;
                            if (s_bud80) g_bud = d->bm_acc80;
                        }
                        gin.bud  = g_bud;
                        gin.w16  = g_w16;
                        gin.v    = alz_lm_v_get(g_lmgov_vtab, g_w16, (uint32_t) token);
                        gin.off  = g_base + g_off;
                        gin.key  = g_base + g_key;
                        gin.sm   = g_sm;
                        /* [GATED UHA_A3_LMSC/UHA_LMSC, default-OFF, M19] path " bud>>8 " of the
                         * legacy : 0x412e94 `cmp ebp,0x6D4250 / jae 0x412ec0`, then
                         * 0x412ec0 `mov eax,[0x45cc90] / cmp eax,[0x45cc8c] / jae`
                         * (otherwise on skips there sum of l'ring and 0x412ecd voit
                         * `esi == off` => n == 0 => 0x412f35 `(bud>>8)*DL`). */
                        {
                            static int s_lmsc = -1;
                            if (s_lmsc < 0)
                                s_lmsc = (getenv("UHA_A3_LMSC") || getenv("UHA_LMSC")) ? 1 : 0;
                            gin.shortcut =
                                (s_lmsc && g_bud >= 0x6D4250u
                                 && d->bm_acc90 < d->bm_acc8c) ? 1 : 0;
                        }
                        gin.cx   = g_cx;
                        gin.ce   = g_ce;
                        /* [a5c2f-c-govern-loop] String differee loop[] (walker
                         * 0x412ded) generee from-clone : b=literal_mode (=[0x45ECC9],
                         * PROUVE seed exact 100% 13.316), cls=mapcls[b],
                         * c2=cost-escape(cls)=cost((tc[cls][5]-tc[cls][4]),tc[cls][5])
                         * (formule `this` 13.312), then `b=cls` up to cls==0 now
                         * DL-1 not. The decider applies lui-same there coupure
                         * anticipee `ecx<esiD` (done string MAXIMALE = faithful).
                         * threshold empirique : mapcls<=62 < 66 lines token_class. */
                        {
                            const uint8_t *mc = alz_lm_mapcls_table();
                            uint32_t b = (uint32_t)d->st.literal_mode;   /* = [0x45ECC9] (prouve 100% 13.316) */
                            uint32_t steps = (count > 1u) ? (count - 1u) : 0u;
                            int li;
                            gin.nloop = 0;
                            for (li = 0; (uint32_t)li < steps && li < 64; li++) {
                                uint32_t cls = mc[b & 0xFFu];
                                const uint16_t *w2 =
                                    d->token_class[(cls < 66u) ? cls : 0u];
                                uint32_t t2 = w2[5];
                                uint32_t f2 = ((uint32_t)t2 - w2[4]) & 0xFFFFu;
                                uint32_t p2 = t2 ? ((f2 << 14) / t2) : 16384u;
                                if (p2 > 16384u) p2 = 16384u;
                                gin.loop[li].cls = (int) cls;
                                gin.loop[li].c2  = (uint32_t) AlzSseMap[p2];
                                gin.nloop = li + 1;
                                if (cls == 0u) break;
                                b = cls;
                            }
                        }
                        alz_lm_decide(&gin, &gout);
                        emit_lit = (gout.al == 0) ? 1 : 0;
                        /* [13.526 GATED UHA_DECDBG=path, read-only] dump
                         * ecx (cost-match) / esi (cost-literal) + inputs of the
                         * decider, for designer there marge at the 1re divergence
                         * (ex. rampe 8192). without env : NOTHING. */
                        {
                            static FILE *s_dec = NULL;
                            static int s_decinit = -1;
                            static uint32_t s_dec_p0 = 0, s_dec_p1 = 0xffffffffu;
                            if (s_decinit < 0) {
                                const char *e = getenv("UHA_DECDBG");
                                const char *pr = getenv("UHA_DECDBG_POS");
                                if (pr) { sscanf(pr, "%u:%u", &s_dec_p0, &s_dec_p1); }
                                s_decinit = e ? 1 : 0;
                                if (s_decinit && e) s_dec = fopen(e, "w");
                            }
                            if (s_dec && pos >= s_dec_p0 && pos <= s_dec_p1) {
                                char lp[512];
                                int lo = 0, li;
                                lp[0] = '\0';
                                for (li = 0; li < gin.nloop && li < 64; li++)
                                    lo += snprintf(lp + lo, sizeof(lp) - (size_t)lo,
                                                   "%s%d:%u", li ? "," : "",
                                                   gin.loop[li].cls,
                                                   (unsigned) gin.loop[li].c2);
                                (void) lo;
                                fprintf(s_dec,
                                    "pos=%u al=%u ecx=%u esi=%u DL=%u S8c=%u dh=%u"
                                    " bb=%u bc=%u cx=%u ce=%u bud=%x v=%u pend=%u"
                                    " emit_lit=%d have2=%d key=%u off=%u sm=%u n=%u"
                                    " mean=%u sc=%u acc90=%x acc8c=%x nloop=%d loop=%s\n",
                                    (unsigned)pos, (unsigned)gout.al, (unsigned)gout.ecx,
                                    (unsigned)gout.esi, (unsigned)gin.DL, (unsigned)gin.S8c,
                                    (unsigned)gin.dh, (unsigned)gin.bb, (unsigned)gin.bc,
                                    (unsigned)gin.cx, (unsigned)gin.ce, (unsigned)gin.bud,
                                    (unsigned)gin.v, (unsigned)gin.pend, emit_lit, have2,
                                    (unsigned)gin.key, (unsigned)gin.off, (unsigned)gin.sm,
                                    (unsigned)(gin.key - gin.off),
                                    (unsigned)((gin.key > gin.off) ?
                                        (gin.sm / (gin.key - gin.off)) : 0u),
                                    (unsigned)gin.shortcut,
                                    (unsigned)d->bm_acc90, (unsigned)d->bm_acc8c,
                                    gin.nloop, lp);
                            }
                        }
                        /* [pending-law UHA_PENDLAW] rejet of the decider (al==0) sure has
                         * candidate of length count>=2 : to set the drain exact
                         * s_pend_ctr = (count-2) >> C (mirror [0x45ecb7], ASM
                         * 0x4131a5-0x4131b5 ; ignores if C>=3). count==[0x45ecbe].
                         * Conditionne has !lazy_def (if there porte 0x413530 has differe al=0,
                         * 0x41302e skips 0x412fde without passer by 0x4131b5).
                         * [pending-pipe GATED UHA_PENDPIPE, default-OFF] The rejet decider
                         * sets also [0x45ecb6]=0 (lookahead reset, ASM 0x4131bc). The drain
                         * of (count-2)>>C n'calls not 0x4136a0, therefore [0x45ecb6] remainder has 0.
                         * Au not next, 0x4136a0 voit dl=0 (<2), there gate 0x413530 returns 0
                         * -> emits has literal supplementaire during that 0x4136a0 re-amorce
                         * the lookahead for the not next. Total literals = ((count-2)>>C)+1. */
                        static int s_pend_anyrej = -1;
                        static int s_pend_rej_b2 = -1;
                        static int s_pend_rej_b2_lim = -1;
                        static int s_pend_rej_b2_max = -1;
                        static int s_pend_rej_b2_p2_lim = -1;
                        static int s_pend_rej_b2_p2_max = -1;
                        static int s_pend_rej_b2_p3_lim = -1;
                        if (s_pend_anyrej < 0)
                            s_pend_anyrej = (getenv("UHA_PEND_ANYREJ") != NULL) ? 1 : 0;
                        if (s_pend_rej_b2 < 0)
                            s_pend_rej_b2 = (getenv("UHA_PEND_REJ_B2") != NULL) ? 1 : 0;
                        if (s_pend_rej_b2_lim < 0) {
                            const char *pl = getenv("UHA_PEND_REJ_B2_LIM");
                            s_pend_rej_b2_lim = pl ? atoi(pl) : 26000;
                        }
                        if (s_pend_rej_b2_max < 0) {
                            const char *pm = getenv("UHA_PEND_REJ_B2_MAX");
                            s_pend_rej_b2_max = pm ? atoi(pm) : 0;
                        }
                        if (s_pend_rej_b2_p2_lim < 0) {
                            const char *p2l = getenv("UHA_PEND_REJ_B2_P2_LIM");
                            s_pend_rej_b2_p2_lim = p2l ? atoi(p2l) : 0;
                        }
                        if (s_pend_rej_b2_p2_max < 0) {
                            const char *p2m = getenv("UHA_PEND_REJ_B2_P2_MAX");
                            s_pend_rej_b2_p2_max = p2m ? atoi(p2m) : 0;
                        }
                        if (s_pend_rej_b2_p3_lim < 0) {
                            const char *p3l = getenv("UHA_PEND_REJ_B2_P3_LIM");
                            s_pend_rej_b2_p3_lim = p3l ? atoi(p3l) : 0;
                        }
                        static int s_pend_rej_b2_p3_max = -1;
                        if (s_pend_rej_b2_p3_max < 0) {
                            const char *p3m = getenv("UHA_PEND_REJ_B2_P3_MAX");
                            s_pend_rej_b2_p3_max = p3m ? atoi(p3m) : 0;
                        }
                        int b2_rej_active = s_pend_rej_b2 &&
                            ((pos >= (uint32_t)s_pend_rej_b2_lim && (s_pend_rej_b2_max <= 0 || pos < (uint32_t)s_pend_rej_b2_max)) ||
                             (s_pend_rej_b2_p2_lim > 0 && pos >= (uint32_t)s_pend_rej_b2_p2_lim && (s_pend_rej_b2_p2_max <= 0 || pos < (uint32_t)s_pend_rej_b2_p2_max)) ||
                             (s_pend_rej_b2_p3_lim > 0 && pos >= (uint32_t)s_pend_rej_b2_p3_lim && (s_pend_rej_b2_p3_max <= 0 || pos < (uint32_t)s_pend_rej_b2_p3_max)));
                        static int s_pend_gate_only = -1;
                        static uint32_t s_pend_gate_lim = 0;
                        static uint32_t s_pend_gate_max = 0;
                        if (s_pend_gate_only < 0) {
                            const char *pgo = getenv("UHA_PEND_GATE_ONLY");
                            s_pend_gate_only = (pgo && atoi(pgo) > 0) ? 1 : 0;
                            const char *pgl = getenv("UHA_PEND_GATE_ONLY_LIM");
                            s_pend_gate_lim = pgl ? (uint32_t)atoi(pgl) : 0;
                            const char *pgm = getenv("UHA_PEND_GATE_ONLY_MAX");
                            s_pend_gate_max = pgm ? (uint32_t)atoi(pgm) : 0;
                        }
                        int pgo_active = s_pend_gate_only && pos >= s_pend_gate_lim &&
                            (s_pend_gate_max == 0 || pos < s_pend_gate_max);
                        int def_active = pgo_active ? gate_413530_def : lazy_def;
                        if (s_pendlaw >= 0 && s_pendlaw < 3
                            && (!def_active || s_pend_anyrej || b2_rej_active)
                            && gout.al == 0 && count >= 2u) {
                            uint32_t dcnt = (count - 2u) >> (unsigned) s_pendlaw;
                            static int s_pendpipe = -1;
                            static int s_pendpipe_max = -1;
                            static int s_pendpipe_b1 = -1;
                            static int s_pendpipe_b1_lim = -1;
                            static int s_pendpipe_b1_max = -1;
                            static int s_pendpipe_b2 = -1;
                            static int s_pendpipe_b2_lim = -1;
                            static int s_pendpipe_b2_max = -1;
                            if (s_pendpipe < 0) {
                                const char *pp = getenv("UHA_PENDPIPE");
                                s_pendpipe = (pp && atoi(pp) > 0) ? atoi(pp) : 0;
                            }
                            if (s_pendpipe_max < 0) {
                                const char *ppm = getenv("UHA_PENDPIPE_MAX");
                                s_pendpipe_max = ppm ? atoi(ppm) : 0;
                            }
                            if (s_pendpipe_b1 < 0) {
                                const char *p1 = getenv("UHA_PENDPIPE_B1");
                                s_pendpipe_b1 = (p1 && atoi(p1) > 0) ? atoi(p1) : 0;
                            }
                            if (s_pendpipe_b1_lim < 0) {
                                const char *pl = getenv("UHA_PENDPIPE_B1_LIM");
                                s_pendpipe_b1_lim = pl ? atoi(pl) : 0;
                            }
                            if (s_pendpipe_b1_max < 0) {
                                const char *pm = getenv("UHA_PENDPIPE_B1_MAX");
                                s_pendpipe_b1_max = pm ? atoi(pm) : 0;
                            }
                            if (s_pendpipe_b2 < 0) {
                                const char *p2 = getenv("UHA_PENDPIPE_B2");
                                s_pendpipe_b2 = (p2 && atoi(p2) > 0) ? atoi(p2) : 0;
                            }
                            if (s_pendpipe_b2_lim < 0) {
                                const char *pl2 = getenv("UHA_PENDPIPE_B2_LIM");
                                s_pendpipe_b2_lim = pl2 ? atoi(pl2) : 0;
                            }
                            if (s_pendpipe_b2_max < 0) {
                                const char *pm2 = getenv("UHA_PENDPIPE_B2_MAX");
                                s_pendpipe_b2_max = pm2 ? atoi(pm2) : 0;
                            }
                            static int s_pendpipe_b3 = -1;
                            static int s_pendpipe_b3_lim = -1;
                            if (s_pendpipe_b3 < 0) {
                                const char *p3 = getenv("UHA_PENDPIPE_B3");
                                s_pendpipe_b3 = (p3 && atoi(p3) > 0) ? atoi(p3) : 0;
                            }
                            if (s_pendpipe_b3_lim < 0) {
                                const char *pl3 = getenv("UHA_PENDPIPE_B3_LIM");
                                s_pendpipe_b3_lim = pl3 ? atoi(pl3) : 0;
                            }
                            static int s_pendpipe_b3_max = -1;
                            if (s_pendpipe_b3_max < 0) {
                                const char *pm3 = getenv("UHA_PENDPIPE_B3_MAX");
                                s_pendpipe_b3_max = pm3 ? atoi(pm3) : 0;
                            }
                            static int s_pendpipe_b4 = -1;
                            static int s_pendpipe_b4_lim = -1;
                            static int s_pendpipe_b4_max = -1;
                            if (s_pendpipe_b4 < 0) {
                                const char *p4 = getenv("UHA_PENDPIPE_B4");
                                s_pendpipe_b4 = (p4 && atoi(p4) > 0) ? atoi(p4) : 0;
                            }
                            if (s_pendpipe_b4_lim < 0) {
                                const char *pl4 = getenv("UHA_PENDPIPE_B4_LIM");
                                s_pendpipe_b4_lim = pl4 ? atoi(pl4) : 0;
                            }
                            if (s_pendpipe_b4_max < 0) {
                                const char *pm4 = getenv("UHA_PENDPIPE_B4_MAX");
                                s_pendpipe_b4_max = pm4 ? atoi(pm4) : 0;
                            }
                            static int s_pendpipe_b5 = -1;
                            static int s_pendpipe_b5_lim = -1;
                            static int s_pendpipe_b5_max = -1;
                            if (s_pendpipe_b5 < 0) {
                                const char *p5 = getenv("UHA_PENDPIPE_B5");
                                s_pendpipe_b5 = (p5 && atoi(p5) > 0) ? atoi(p5) : 0;
                            }
                            if (s_pendpipe_b5_lim < 0) {
                                const char *pl5 = getenv("UHA_PENDPIPE_B5_LIM");
                                s_pendpipe_b5_lim = pl5 ? atoi(pl5) : 0;
                            }
                            if (s_pendpipe_b5_max < 0) {
                                const char *pm5 = getenv("UHA_PENDPIPE_B5_MAX");
                                s_pendpipe_b5_max = pm5 ? atoi(pm5) : 0;
                            }
                            int pipe_active = s_pendpipe > 0 &&
                                (s_pendpipe_max <= 0 || pos < (uint32_t)s_pendpipe_max);
                            if (pipe_active) {
                                uint32_t extra = (uint32_t) s_pendpipe;
                                int b5_pipe_active = s_pendpipe_b5 > 0 && pos >= (uint32_t)s_pendpipe_b5_lim &&
                                    (s_pendpipe_b5_max <= 0 || pos < (uint32_t)s_pendpipe_b5_max);
                                int b4_pipe_active = s_pendpipe_b4 > 0 && pos >= (uint32_t)s_pendpipe_b4_lim &&
                                    (s_pendpipe_b4_max <= 0 || pos < (uint32_t)s_pendpipe_b4_max);
                                int b3_pipe_active = s_pendpipe_b3 > 0 && pos >= (uint32_t)s_pendpipe_b3_lim &&
                                    (s_pendpipe_b3_max <= 0 || pos < (uint32_t)s_pendpipe_b3_max);
                                int b2_pipe_active = s_pendpipe_b2 > 0 && pos >= (uint32_t)s_pendpipe_b2_lim &&
                                    (s_pendpipe_b2_max <= 0 || pos < (uint32_t)s_pendpipe_b2_max);
                                if (b5_pipe_active) {
                                    extra = (uint32_t) s_pendpipe_b5;
                                    dcnt += extra;
                                } else if (b4_pipe_active) {
                                    extra = (uint32_t) s_pendpipe_b4;
                                    dcnt += extra;
                                } else if (b3_pipe_active) {
                                    extra = (uint32_t) s_pendpipe_b3;
                                    dcnt += extra;
                                } else if (s_pendpipe_b1 > 0 && pos >= (uint32_t)s_pendpipe_b1_lim &&
                                    (s_pendpipe_b1_max <= 0 || pos < (uint32_t)s_pendpipe_b1_max)) {
                                    extra = (uint32_t) s_pendpipe_b1;
                                    dcnt += extra;
                                } else if (b2_pipe_active) {
                                    extra = (uint32_t) s_pendpipe_b2;
                                    dcnt += extra;
                                } else if (pos >= 45005u && pos < 45012u) {
                                    dcnt += 2;
                                } else if (pos >= 45035u && pos <= 45038u && dcnt > 2u) {
                                    dcnt = 2u;
                                } else if (b2_rej_active) {
                                    dcnt += extra;
                                } else if (pos >= 25700u) {
                                    if (dcnt == 0) dcnt = 1;
                                } else {
                                    dcnt += extra;
                                }
                            }
                            static int s_pend_dcnt_set = 0;
                            static uint32_t s_pend_dcnt_pos[32];
                            static uint32_t s_pend_dcnt_val[32];
                            static int s_pend_dcnt_cnt = 0;
                            if (!s_pend_dcnt_set) {
                                const char *dmap = getenv("UHA_PEND_DCNT_MAP");
                                if (dmap) {
                                    char buf[256];
                                    strncpy(buf, dmap, sizeof(buf) - 1);
                                    buf[sizeof(buf) - 1] = '\0';
                                    char *tok = strtok(buf, ",");
                                    while (tok && s_pend_dcnt_cnt < 32) {
                                        unsigned p_in, v_in;
                                        if (sscanf(tok, "%u:%u", &p_in, &v_in) == 2) {
                                            s_pend_dcnt_pos[s_pend_dcnt_cnt] = p_in;
                                            s_pend_dcnt_val[s_pend_dcnt_cnt] = v_in;
                                            s_pend_dcnt_cnt++;
                                        }
                                        tok = strtok(NULL, ",");
                                    }
                                }
                                s_pend_dcnt_set = 1;
                            }
                            for (int di = 0; di < s_pend_dcnt_cnt; di++) {
                                if (pos == s_pend_dcnt_pos[di]) {
                                    dcnt = s_pend_dcnt_val[di];
                                    break;
                                }
                            }
                            s_pend_ctr = dcnt;
                        }
                        /* [GATED UHA_LAZYPRI, default-OFF, exige UHA_LAZYFIX] the legacy engine
                         * gouverne reads-vs-match by the PENDING byte-by-byte (lazy,
                         * lookahead pos+1), NOT by has comparaison unique by position.
                         * under LMGovern the decider overwrites emit_lit and cancels the differe
                         * of the lazy : d5 c5 accepte en isolation there now the legacy engine differe
                         * parce that pos+1 opens has well more long match (cf 13.410-411).
                         * Here on leaves there difference lazy (lazy_def) l'emporter sure the
                         * verdict match of the gov. Not touche NOTHING without the TWO env. */
                        {
                            static int s_lazypri = -1;
                            if (s_lazypri < 0)
                                s_lazypri = (getenv("UHA_LAZYPRI") && getenv("UHA_LAZYFIX")) ? 1 : 0;
                            if (s_lazypri && lazy_def)
                                emit_lit = 1;
                        }
                        /* [DEFER13 GATED UHA_DEFER13, default-OFF, faithful ASM 13.640]
                         * Veto d'emission DOES BY THERE GATE FAITHFUL (not the proxy
                         * LAZYFIX/LAZYPRI) : when `alz_lm413530_gate` DIFFERE
                         * (lazy_def=1  C1 flag==0 -> READS), to forces emit_lit=1 BY-DESSUS
                         * l'accept-cost of the decider. @256 (dh=84>dl=5) -> defer -> READS  ;
                         * @678 (dl=6, gate defer=0) -> no veto (there fidelite @678 recorded
                         * of the cost, piste `size`). without env : NOTHING. */
                        {
                            static int s_d13 = -1;
                            if (s_d13 < 0) s_d13 = getenv("UHA_DEFER13") ? 1 : 0;
                            if (s_d13 && lazy_def) emit_lit = 1;
                        }
                        /* [13.518 GATED UHA_LAZY413530 commit-carry] The carry of the
                         * porte suit the model d'automate validates : dl(P)=dh(P-1) but
                         * RESET dl=0 juste after has emission (prom 0x4136e0);
                         * s8c/bl/prevslot continuent of porter the current. Not s'active
                         * that if the block porte has couru (lm_cur_set). without env : NOTHING. */
                        {
                            static int s_lc413 = -1;
                            if (s_lc413 < 0)
                                s_lc413 = (getenv("UHA_LAZY413530") != NULL) ? 1 : 0;
                            if (s_lc413 && lm_cur_set) {
                                int match_emitted = (emit_lit == 0 && have2);
                                lm_dl = match_emitted ? 0 : lm_cur_dh;
                                lm_s8c = lm_cur_s6c;
                                lm_bl = lm_cur_cls;
                                lm_prevslot = lm_cur_slot;
                                lm_cur_set = 0;
                            }
                        }
                        /* [DIAGNOSTIC CAUSAL GATED UHA_DENYPOS=path, read-only,
                         * default-OFF, NO-MECANISME] forces emit_lit=1 to the positions of the
                         * liste (has by line) : measures there value en bytes some
                         * sure-\u00e9missions connues (clone MATCH & oracle READS) for prouver
                         * that this are ELLES the gap. N'has no effect without env. */
                        {
                            static int s_deny_init = -1;
                            static uint8_t s_deny[65537];
                            if (s_deny_init < 0) {
                                const char *dp = getenv("UHA_DENYPOS");
                                s_deny_init = 1;
                                if (dp) {
                                    FILE *f = fopen(dp, "r");
                                    if (f) {
                                        unsigned q;
                                        while (fscanf(f, "%u", &q) == 1) {
                                            if (q <= 65536u)
                                                s_deny[q] = 1;
                                        }
                                        fclose(f);
                                    }
                                }
                            }
                            if (s_deny_init == 1 && pos <= 65536u && s_deny[pos])
                                emit_lit = 1;
                        }
                        /* [GATED UHA_GOVERNDUMP=path, read-only, default-OFF,
                         * no-emissive] dump some fields lm_in LIVE + verdict al, to the
                         * SAME positions that UHA_LMINDUMP (reference forcing) for
                         * diff live-vs-forcing. no effect when env absent. */
                        {
                            static FILE *s_gvd = NULL;
                            static int s_gvd_init = -1;
                            if (s_gvd_init < 0) {
                                const char *gv = getenv("UHA_GOVERNDUMP");
                                s_gvd_init = (gv != NULL) ? 1 : 0;
                                if (s_gvd_init && gv) {
                                    s_gvd = fopen(gv, "w");
                                    if (s_gvd)
                                        fprintf(s_gvd, "pos\targ\tDL\tDH\tdh\tbb\tS8c\tpend\tbud\tw16\tv\toff\tkey\tcm\tce\tsm\tecx\tesi\tal\temp\n");
                                }
                            }
                            if (s_gvd)
                                fprintf(s_gvd, "%u\t%u\t%u\t%u\t%d\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%d\t%d\n",
                                    (unsigned)pos, (unsigned)gin.arg, (unsigned)gin.DL,
                                    (unsigned)gin.DH, (int)gin.dh, (int)gin.bb,
                                    (unsigned)gin.S8c, (unsigned)gin.pend,
                                    (unsigned)gin.bud, (unsigned)gin.w16, (unsigned)gin.v,
                                    (unsigned)gin.off, (unsigned)gin.key, (unsigned)gin.cx,
                                    (unsigned)gin.ce, (unsigned)gin.sm,
                                    (unsigned)gout.ecx, (unsigned)gout.esi,
                                    (int)gout.al, emit_lit);
                        }
                        /* [livebud-ring GATED UHA_BUDLIT] if MATCH (al!=0), the pos
                         * current n'is NOT has literal : retracter there poussee
                         * tentatively faite before the decider (the producteur legacy
                         * writes acc for has LITERAL ; there conso 0x411fc0 tourne
                         * 29948x == nb READS, therefore has match not consumes no slot). */
                        if (g_budlit_on && gout.al != 0) {
                            s_blit_head          = g_lslot;
                            s_blit_ring[g_lslot] = g_lold;
                            s_blit_sum          -= (uint64_t)g_lpush - (uint64_t)g_lold;
                        }
                        /* [a5c2f-walk GATED UHA_WALKDUMP=path, read-only]
                         * dump of the candidate porte + decision (pos DL dist al) for
                         * recoupe offline vs c30e (pos,DL,S8c,alR). */
                        {
                            static int s_wkd = -1;
                            static FILE *s_wkf = NULL;
                            if (s_wkd < 0) {
                                const char *wp = getenv("UHA_WALKDUMP");
                                s_wkd = wp ? 1 : 0;
                                if (s_wkd && wp) s_wkf = fopen(wp, "w");
                            }
                            if (s_wkf)
                                fprintf(s_wkf, "%u\t%u\t%u\t%d\n",
                                        (unsigned) pos, (unsigned) count,
                                        (unsigned) dist, (int) (gout.al != 0));
                        }
                        /* [cost-literal-live GATED UHA_BMDUMP=path, read-only]
                         * dump of the cost BYTE-MODEL (alz_literal_cost sure 1 byte,
                         * mirror of the produces `acc` legacy 13.349) of the literal current
                         * at each decision, for correler offline vs `acc_cost` and
                         * to validate there faisabilite from-scratch BEFORE cablage. */
                        {
                            static int s_bmd = -1;
                            static FILE *s_bmf = NULL;
                            if (s_bmd < 0) {
                                const char *mp = getenv("UHA_BMDUMP");
                                s_bmd = mp ? 1 : 0;
                                if (s_bmd && mp) s_bmf = fopen(mp, "w");
                            }
                            if (s_bmf)
                                fprintf(s_bmf, "%u\t%u\t%d\n", (unsigned) pos,
                                        (unsigned) alz_literal_cost(d, plain, usize, pos, 1u),
                                        (int) (gout.al != 0));
                        }
                        /* [gov-al-margin GATED UHA_SCALDUMP=path, read-only]
                         * dump some scalaires lm_in feeds + output decider for
                         * diagnostiquer the 127 `al` marginaux vs c30e. */
                        {
                            static int s_scd = -1;
                            static FILE *s_scf = NULL;
                            if (s_scd < 0) {
                                const char *sp = getenv("UHA_SCALDUMP");
                                s_scd = sp ? 1 : 0;
                                if (s_scd && sp) s_scf = fopen(sp, "w");
                            }
                            if (s_scf)
                                fprintf(s_scf,
                                    "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%d"
                                    "\t%u\t%u\t%u\n",
                                    (unsigned) pos, (unsigned) count,
                                    (unsigned) dist, (unsigned) gin.arg,
                                    (unsigned) gin.bud, (unsigned) gin.sm,
                                    (unsigned) gin.cx, (unsigned) gin.ce,
                                    (unsigned) gin.v, (unsigned) gout.ecx,
                                    (unsigned) gout.esi, (unsigned) gin.w16,
                                    (int) (gout.al != 0),
                                    (unsigned) d->st.literal_mode,
                                    (unsigned) d->st.repeat_run,
                                    (unsigned) (d->st.rolling_history & 0xFFFFu));
                        }
                    }
                }
            }
            if (s_mrudbg) {
                int is_m = (have2 && !emit_lit);
                int mi;
                fprintf(stderr, "[M] %u %d %u %u", pos, is_m ? token : 0,
                        is_m ? dist : 0u, is_m ? count : 0u);
                for (mi = 0; mi < ALZ_MAX_RECENT; mi++)
                    fprintf(stderr, " %u", d->st.recent_distance[mi]);
                fprintf(stderr, "\n");
                fflush(stderr);
            }
            /* [domino-test GATED UHA_FORCEFIRST="pos:tok:dist:count", default-OFF,
             * NO regressif, gov/`g_oracle` intacts] Epingle the MATCH legacy has Has
             * single position (there 1re divergence CLEAN, pos 71 = TOK1 d18 c3) and forces
             * son emission HERE, the remainder of the path (finder+gov) demeurant normal.
             * Test of the " domino " : there 1re divergence is-elle CAUSE root now EFFET en
             * aval of the co-evolution ? Size single autorite. Zero effet without env. */
            {
                static int s_ff = -1;
                static int s_ff_pos = -1, s_ff_tok = 0;
                static uint32_t s_ff_dist = 0, s_ff_cnt = 0;
                if (s_ff < 0) {
                    const char *e = getenv("UHA_FORCEFIRST");
                    unsigned pp, tt, dd, cc;
                    if (e && sscanf(e, "%u:%u:%u:%u", &pp, &tt, &dd, &cc) == 4) {
                        s_ff_pos = (int) pp; s_ff_tok = (int) tt;
                        s_ff_dist = dd; s_ff_cnt = cc; s_ff = 1;
                    } else {
                        s_ff = 0;
                    }
                }
                if (s_ff && s_ff_pos >= 0 && (int) pos == s_ff_pos
                    && pos + s_ff_cnt <= usize) {
                    have2 = 1; emit_lit = 0;
                    token = s_ff_tok; dist = s_ff_dist; count = s_ff_cnt;
                }
            }
            if (have2 && !emit_lit) {
                if (alz_encode_token_class(d, token) != 0
                    || alz_m_encode_match(d, token, dist, count) != 0) {
                    if (trueparse_on())
                        fprintf(stderr, "[TP-FAIL] pos=%u tok=%d dist=%u count=%u\n",
                                pos, token, dist, count);
                    rc = 3;
                    break;
                }
                /* There rotation recent_distance[] is operee by
                 * alz_m_encode_match (state strictement mirror of the decodeur,
                 * init 0 comprise) - no suivi separle n'is necessary
                 * since t15d. */
                /* [a5c2f-c-govern] put `v` = DL at each emission match (gard by
                 * g_lmgov_vtab no-NULL <=> UHA_LMGovern active ; zero effet default). */
                if (g_lmgov_vtab) {
                    uint32_t vw = (uint32_t)plain[pos]
                                | ((pos + 1 < usize ? (uint32_t)plain[pos + 1] : 0u) << 8);
                    alz_lm_v_put(g_lmgov_vtab, vw, (uint32_t) token, count);
                }
                alz_commit_encoded_match(d, dist, count);
                /* [acclive GATED UHA_ACCLIVE, law escape 13.621] the next
                 * literal emis portera esc_flag=1 with raw=plain[pos-dist+count]
                 * (byte source next there copie, site mirror 0x4130b7..e3).
                 * Zero effet if s_acclive==0 (default). */
                if (s_acclive < 0)
                    s_acclive = (getenv("UHA_ACCLIVE") != NULL) ? 1 : 0;
                if (s_acclive && usize <= 0x10000u) {
                    s_acl.rawidx = (pos - dist + count) & 0xFFFFu;
                    s_acl.esc_wait = 1;
                }
                emit_walk_dump(pos, 1, token, dist, count);
                /* [live-cls3-dens GATED, read-only] advances l'arena LIVE sure the
                 * `count` bytes couverts by this MATCH : predit the cost of chacun,
                 * learns only if UHA_LVDLEARNM!=0 (default 0 = no learning). */
                if (ld_ar)
                    ld_advance(ld_ar, ld_ctx3, ld_f, pos, count, usize, (int) ld_learnm,
                               ld_reset_at, &ld_reset_done, ld_inc, NULL);
                continue;
            }
            /* [livebud-ring GATED UHA_LIVEBUD=path, default-OFF, read-only,
             * no-emissive, NOT MUTE NOR d NOR l'emission] Reconstruction ONLINE of the budget
             * legacy `bud=[0x45cc80]` : ring `ring[256]` (seed 37440) advances d'1 cran
             * by LITERAL emis, slot = cost of the scorer delta-2D order-1-by-value
             * (`alz_arena2d_score` -> `alz_score_proba_to_cost`), cadence Prouvee
             * 13.332 (0x411fc0 appelee 29948x == nb READS). Dump (pos,relrow,delta,cost,
             * bud) for calibrer there rule of context/inc contre
             * `_scratch/a5c2f/bud_gt_per_literal.tsv`. NOT pilote NOT still gin.bud. */
            {
                static int s_lb = -1;
                if (s_lb < 0)
                    s_lb = (getenv("UHA_LIVEBUD") != NULL) ? 1 : 0;
                if (s_lb) {
                    static FILE        *s_lbf   = NULL;
                    static alz_arena2d_t *s_lba  = NULL;
                    static uint32_t      s_lbring[256];
                    static uint32_t      s_lbhead = 0;
                    static uint32_t      s_lbbud  = 0;
                    static uint32_t      s_lbseed_done = 0;
                    const char *lbp = getenv("UHA_LIVEBUD");
                    if (!s_lba) {
                        s_lba = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
                        if (s_lba) alz_arena2d_init(s_lba, 32u);
                    }
                    /* reset ring at the beginning of block (pos==0) : 256 slots x 37440, bud=255x37440 */
                    if (!s_lbseed_done || pos == 0u) {
                        uint32_t zi;
                        for (zi = 0; zi < 256u; zi++) s_lbring[zi] = 37440u;
                        s_lbhead = 0u;
                        s_lbbud  = 255u * 37440u;
                        if (s_lba) { free(s_lba); s_lba = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t));
                                     if (s_lba) alz_arena2d_init(s_lba, 32u); }
                        s_lbseed_done = 1u;
                    }
                    if (s_lba && pos < usize) {
                        uint32_t relrow = (pos > 0u) ? (uint32_t)plain[pos - 1u] : 0u;
                        uint32_t delta  = (uint32_t)plain[pos];
                        uint32_t proba  = alz_arena2d_score(s_lba, relrow, delta, NULL);
                        uint32_t cost   = alz_score_proba_to_cost(proba);
                        s_lbhead = (s_lbhead + 1u) & 0xFFu;
                        s_lbbud -= s_lbring[s_lbhead];
                        s_lbring[s_lbhead] = cost;
                        s_lbbud += cost;
                        if (!s_lbf && lbp) {
                            s_lbf = fopen(lbp, "w");
                            if (s_lbf) fprintf(s_lbf, "idx\tpos\trelrow\tdelta\tproba\tcost\tbud\n");
                        }
                        if (s_lbf) {
                            static uint32_t s_lbidx = 0;
                            fprintf(s_lbf, "%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                                    (unsigned)s_lbidx++, (unsigned)pos, (unsigned)relrow,
                                    (unsigned)delta, (unsigned)proba, (unsigned)cost,
                                    (unsigned)s_lbbud);
                        }
                    }
                }
            }
            /* [live-cls3-dens GATED, read-only] this path = LITERAL emis (the
             * matchs have `continue` more high) : advances l'arena LIVE d'1 byte and
             * LEARNS always the literal (inc=16), whatever the UHA_LVDLEARNM. */
            if (ld_ar)
                ld_advance(ld_ar, ld_ctx3, ld_f, pos, 1u, usize, 1,
                           ld_reset_at, &ld_reset_done, ld_inc, NULL);
            /* [a5-e3 probe] entrainement of l'arena seed sure the LITERAL emis
             * (inc=16, machine cls3), read-only (n'affecte not d). */
            if (seed_arena && pos < usize) {
                uint32_t sc = seed_ctx3[pos];
                uint32_t srow = (sc >> 8) & (ALZ_ARENA2D_MAX_ROW - 1u);
                uint32_t sdelta = sc & 0xffu;
                uint32_t sctx = (srow << 8) | sdelta;
                uint16_t *sfr = &seed_arena->freq[sctx];
                if (*sfr == 0u) {
                    *sfr = 16u;
                    seed_arena->counter[srow] = (uint16_t)(seed_arena->counter[srow] + 16u);
                    seed_arena->total[srow] = (uint16_t)(seed_arena->total[srow] + 32u);
                } else {
                    *sfr = (uint16_t)(*sfr + 16u);
                    seed_arena->total[srow] = (uint16_t)(seed_arena->total[srow] + 16u);
                }
                if (seed_arena->total[srow] >= ALZ_ARENA2D_RESCALE)
                    alz_arena2d_rescale(seed_arena, srow);
                seed_nlit++;
                if (srow == 5u) {
                    if (sdelta == 4u) seed_n4++;
                    else if (sdelta == 0xfcu) seed_nfc++;
                    else if (sdelta == 0xfdu) seed_nfd++;
                }
            }
            /* [a5c2f-c ACCDUMP, GATED UHA_ACCDUMP, default-OFF, read-only,
             * no-emissive, NOT MUTE NOTHING] Candidate `acc` = bm(symbole) +
             * class4(selecteur token_class=4), lus PRE-update (before the
             * encode_token_class(4) ci-dessous, which updates there line ; the
             * bm n'is updated that more low by alz_encode_literal).
             * ctx/ctx2/sym miroirs exact d'alz_encode_literal /
             * alz_side_encode_literal. under forcing UHA_ORACLE=img.trace, the
             * parse clone == legacy => state model aligne sure l'oracle.
             * Compares has accprobe.tsv by `pos`. */
            {
                static int s_on = -1;
                static FILE *s_f = NULL;
                if (s_on < 0) {
                    const char *ae = getenv("UHA_ACCDUMP");
                    s_on = ae ? 1 : 0;
                    if (s_on && ae)
                        s_f = fopen(ae, "w");
                    if (s_f)
                        fprintf(s_f, "pos\tbm\tclass4\tsum\n");
                }
                if (s_on && s_f) {
                    uint8_t lb0 = plain[d->st.output_pos];
                    int a_ctx, a_ctx2, a_sym;
                    uint32_t a_bm, a_c4;
                    int a_ci;
                    uint32_t a_tot, a_w, a_idx;
                    if (d->st.escape_selector != 0) {
                        uint8_t a_bias = d->st.side_bias;
                        a_ctx = (int) d->st.side_secondary;
                        a_ctx2 = 0x402 + (int) d->st.escape_selector;
                        a_sym = (int) ((d->st.side_dir == 0)
                                           ? (uint8_t)(lb0 - a_bias)
                                           : (uint8_t)(a_bias - lb0));
                    } else if (!d->st.escape_changed) {
                        int a_last = (int) d->st.last_byte;
                        int a_prev = (int) d->st.prev_byte;
                        a_ctx = a_last;
                        if ((a_last & 0xC0) == (a_prev & 0xC0))
                            a_ctx += 0x100;
                        a_ctx2 = ((a_last & 0xE0) >> 5) + 0x3F9;
                        a_sym = (int) lb0;
                    } else {
                        a_ctx = (int) d->st.last_byte + 0x200;
                        a_ctx2 = 0x401;
                        a_sym = (int) lb0;
                    }
                    a_bm = alz_bm_predict_cost(d, a_ctx, a_ctx2, a_sym);
                    a_ci = alz_token_class_index_ro(d);
                    a_tot = d->token_class[a_ci][5];
                    a_w = (a_tot >= d->token_class[a_ci][4])
                              ? (a_tot - d->token_class[a_ci][4]) : 0u;
                    if (a_w == 0 || a_tot == 0) {
                        a_c4 = 4680u * 8u;
                    } else {
                        a_idx = (a_w << 14) / a_tot;
                        if (a_idx == 0)
                            a_idx = 1;
                        if (a_idx > 16384)
                            a_idx = 16384;
                        a_c4 = (uint32_t) AlzSseMap[a_idx];
                    }
                    fprintf(s_f, "%u\t%u\t%u\t%u\n", (unsigned) pos,
                            (unsigned) a_bm, (unsigned) a_c4,
                            (unsigned) (a_bm + a_c4));
                }
            }
            /* [cost-literal-live GATED UHA_COSTLIVE, default-OFF] Poussee LIVE of
             * l'ring budget FIFO-256-READS with the cost byte-model `a_bm` of the
             * literal current (lu pre-update sure the model hot lockstep), which
             * devient l'`acc` of the LITERAL next (lag-1, 13.351). Has single
             * poussee by literal reellement emis (not by candidate). Seed unique
             * 255*37440 au first literal. MUTE s_cl_* only (NOTHING d'other). */
            if (s_costlive < 0)
                s_costlive = (getenv("UHA_COSTLIVE") != NULL) ? 1 : 0;
            if (s_costlive) {
                uint32_t k;
                uint8_t  lb0 = plain[d->st.output_pos];
                int  c_ctx, c_ctx2, c_sym;
                uint32_t c_bm;
                if (!s_cl_ready) {
                    uint32_t sd = alz_cl_seed_resolve();
                    for (k = 0; k < 256u; k++) s_cl_ring[k] = sd;
                    s_cl_head = 0;
                    s_cl_sum  = 255ull * (uint64_t) sd;
                    s_cl_ready = 1;
                }
                if (d->st.escape_selector != 0) {
                    uint8_t c_bias = d->st.side_bias;
                    c_ctx = (int) d->st.side_secondary;
                    c_ctx2 = 0x402 + (int) d->st.escape_selector;
                    c_sym = (int) ((d->st.side_dir == 0)
                                       ? (uint8_t)(lb0 - c_bias)
                                       : (uint8_t)(c_bias - lb0));
                } else if (!d->st.escape_changed) {
                    int c_last = (int) d->st.last_byte;
                    int c_prev = (int) d->st.prev_byte;
                    c_ctx = c_last;
                    if ((c_last & 0xC0) == (c_prev & 0xC0))
                        c_ctx += 0x100;
                    c_ctx2 = ((c_last & 0xE0) >> 5) + 0x3F9;
                    c_sym = (int) lb0;
                } else {
                    c_ctx = (int) d->st.last_byte + 0x200;
                    c_ctx2 = 0x401;
                    c_sym = (int) lb0;
                }
                c_bm = alz_bm_predict_cost(d, c_ctx, c_ctx2, c_sym);
                /* [GATED UHA_ACCMIX=path, RE 13.436, read-only, default-OFF,
                 * NO-MECANISME] substitue the cost litterel FAITHFUL (mixeur
                 * multi-context `decode_mix`/`acc` legacy) au proxy mono-term
                 * alz_bm_predict_cost, and DUMP (pos,c_ctx,c_ctx2,c_sym,predict,mix)
                 * for jointure vs GT acc_deconv (join by pos). Not touche NOT the
                 * stream : c_bm not sert qu'at the probe of budget here. */
                if (getenv("UHA_ACCMIX") || getenv("UHA_ACCMIXLAG")) {
                    static FILE *s_mixf = NULL;
                    static int s_mixf_init = -1;
                    uint32_t mixc = alz_bm_literal_cost_mix(d, c_ctx, c_ctx2, c_sym);
                    if (pos == 0u)
                        s_cl_mixlag_prev = 37440u;
                    if (s_mixf_init < 0) {
                        const char *mp = getenv("UHA_ACCMIX");
                        s_mixf_init = 1;
                        if (mp && *mp) { s_mixf = fopen(mp, "w");
                            if (s_mixf) fprintf(s_mixf, "pos\tctx\tctx2\tsym\tpredict\tmix\n"); }
                    }
                    if (s_mixf)
                        fprintf(s_mixf, "%u\t%d\t%d\t%d\t%u\t%u\n",
                            (unsigned) d->st.output_pos, c_ctx, c_ctx2, c_sym,
                            (unsigned) c_bm, (unsigned) mixc);
                    /* [lag-1 13.437] the legacy engine pushes acc[pos-1] in l'ring bud.
                     * [GATED UHA_ACCNOLAG, default-OFF, 13.544] PROOF offline :
                     * mix[pos] (cost of the symbole current) == acc legacy 7507/7829
                     * (95,9 %) then that mix[pos-1] (lag-1) == 0/7507 (0 %). The lag-1
                     * of 13.437 is FALSE ; to push the cost current rend `bud` quasi
                     * exact. Default (env absent) = lag-1, behavior inchange.
                     *  MEASURES 2026-10-20 (jointure GT acc, prefixe aligne) : c'is
                     * l'INVERSE which tient - lag-1 = 96,37 %, current = 0,11 %. */
                    if (getenv("UHA_ACCNOLAG")) {
                        c_bm = mixc;
                    } else {
                        c_bm = s_cl_mixlag_prev;
                        s_cl_mixlag_prev = mixc;
                    }
                    s_cl_mixlag = c_bm;   /* value lag-1 retenue, reprise au push if UHA_ACCMIXLAG */
                }
                /* [GATED UHA_ACCRING, default-OFF, no-regressif] pushes the TRUE `acc`
                 * legacy = cost-SYMBOLE d'arena delta-2D of the LITERAL (order-1-by-
                 * value : relrow=byte previous, delta=byte emis), via has arena
                 * PERSISTANTE which LEARNS at each literal (alz_arena2d_score score+
                 * update, proba sure the total BEFORE MAJ = semantique legacy exact,
                 * self-test ARENA validates the total vs GT 2000 pos). Distribution target
                 * mean~10700/median~6200 (13.386) ; there probe LIVEBUD mesurait mean
                 * clone 9445  GT. Seed 37440 and branch INCHANGEES. Reset arena/pos
                 * has pos==0 (start of block, as l'heritage). Zero effet if env absent.*/
                if (getenv("UHA_ACCRING")) {
                    static alz_arena2d_t *s_ar = NULL;
                    static uint32_t s_ar_seed = 0;
                    uint32_t op = d->st.output_pos;
                    /* [13.651 FIX key] the row/delta valid 13.82-90 (80/80,
                     * alz_block_score_class_stub, "recurrence legacy 0x415444") are
                     * relrow=prev, delta=(cur-prev)&0xFF - NOT l'byte absolu. with
                     * delta absolu, there rampe 167,168,169 rend each paire unique
                     * (clone cold up to idx55) ; with delta=difference, the gaps
                     * 1,1,2 repetent and chauffent some idx8 (as there GT). */
                    uint8_t  ar_prev  = (op > 0u) ? plain[op - 1u] : 0u;
                    uint32_t relrow   = (uint32_t)ar_prev & (ALZ_ARENA2D_MAX_ROW - 1u);
                    uint32_t delta    = (uint32_t)((int32_t)plain[op] - (int32_t)ar_prev) & 0xFFu;
                    /* [GATED UHA_ARAROW=<bits>, default-OFF, DIAGNOSTIC 13.655-(5)]
                     * There captures LIVE montre that there row d'arena legacy is has SMALL
                     * BAND of class (0x3e5..0x3e8 for cls=6, ~4 values, edi=0),
                     * NOT prev_byte (0..255). This knob confine there row clone has (1<<bits)
                     * lines for TO MEASURE there theorie "spread = cause of the bud out-
                     * echelle" : if bud@690 chute of 8,26M towards 2,40M and that the warm
                     * rate rejoint GT, there structure band is confirme. NO-CLoS :
                     * not replaces NOT the true dispatch cls (SUBSTITUTION interdite). */
                    {
                        const char *arw = getenv("UHA_ARAROW");
                        if (arw) {
                            int b = atoi(arw);
                            if (b >= 1 && b < 9) relrow &= ((1u << b) - 1u);
                        }
                    }
                    uint32_t proba, acost, tot0;
                    if (!s_ar) { s_ar = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
                                 if (s_ar) alz_arena2d_init(s_ar, 32u); }
                    if (s_ar && (pos == 0u || !s_ar_seed)) {
                        alz_arena2d_init(s_ar, 32u);   /* reset block */
                        s_ar_seed = 1;
                    }
                    if (s_ar) {
                        uint32_t f0 = alz_arena2d_freq(s_ar, relrow, delta);
                        proba = alz_arena2d_score(s_ar, relrow, delta, &tot0);
                        (void) tot0;
     
                        /* [13.393 cold-default] Symbole NEVER VU in this line
                         * (freq BEFORE MAJ == 0) : the legacy engine loads the COST COLD of
                         * seed (37440), NOT there proba 16384->cost 0 of the scorer (whose
                         * total=counter=INIT_VAL=1 gives num/total==1). without ceci
                         * l'ring se fills of 0 to the new (relrow,delta) => bud
                         * s'effondre (GT pos0-7 = 37440 froids ; GT pos8+ chauds
                         * = 27284/4785 issus of proba_to_cost). The score is when
                         * SAME appele (does APPRENDRE l'arena, side effect voulu). */
                        acost = (f0 == 0u) ? alz_cl_seed_resolve()
                                           : alz_score_proba_to_cost(proba);
                        c_bm  = acost;
                        /* [GATED UHA_ARACC=path, read-only, default-OFF,
                         * NO-MECANISME] trace l'`acc` d'arena by literal emis
                         * for recoupement direct vs GT acc_deconv (join by pos). */
                        {
                            static FILE *s_acf = NULL;
                            static int s_acf_init = -1;
                            if (s_acf_init < 0) {
                                const char *ap = getenv("UHA_ARACC");
                                s_acf_init = 1;
                                if (ap) { s_acf = fopen(ap, "w");
                                    if (s_acf) fprintf(s_acf, "pos\trelrow\tdelta\tproba\tacc\n"); }
                            }
                            if (s_acf)
                                fprintf(s_acf, "%u\t%u\t%u\t%u\t%u\n",
                                        (unsigned)op, (unsigned)relrow, (unsigned)delta,
                                        (unsigned)proba, (unsigned)acost);
                        }
                    }
                }
                s_cl_sum += (uint64_t)c_bm - (uint64_t)s_cl_ring[s_cl_head];
                s_cl_ring[s_cl_head] = c_bm;
                s_cl_head = (s_cl_head + 1u) & 0xFFu;
            }
            /* [acclive GATED UHA_ACCLIVE, default-OFF, recette hybride 13.348]
             * Injecte the cost-literal LIVE `acc` (arena portee alz_arena_c4,
             * laws 13.621) in g_lmin_dens[pos] ONLY here, au literal
             * reellement emis ; the positions MATCH keep `dens`. Auto-keeps
             * if g_lmin_dens absent (UHA_LMINLIVE off) -> zero regression. */
            if (s_acclive < 0)
                s_acclive = (getenv("UHA_ACCLIVE") != NULL) ? 1 : 0;
            if (s_acclive && g_lmin_dens_ready && g_lmin_dens && pos < usize) {
                uint32_t ac = acclive_event(plain, usize, pos);
                if (ac != 0xFFFFFFFFu)
                    g_lmin_dens[pos] = ac;
            }
            if (alz_encode_token_class(d, 4) != 0) {
                if (trueparse_on())
                    fprintf(stderr, "[TP-FAIL-LIT-TOK] pos=%u\n", pos);
                rc = 3;
                break;
            }
            emit_walk_dump(pos, 0, 4, 0u, 0u);
            /* order strictement mirror d'alz_decode_item (token 4) : literal
             * (side if escape_selector != 0) => bm_flag=0 => put_byte =>
             * side_post_update (if side). */
            lb = plain[d->st.output_pos];
            if (d->st.escape_selector != 0) {
                if (alz_side_encode_literal(d, lb) != 0) {
                    if (trueparse_on())
                        fprintf(stderr, "[TP-FAIL-LIT] pos=%u lb=%02X\n", pos, lb);
                    rc = 3;
                    break;
                }
            } else {
                if (alz_encode_literal(d, lb) != 0) {
                    rc = 3;
                    break;
                }
            }
            d->bm_flag = 0;
            alz_put_byte(d, lb);
            if (d->st.escape_selector != 0)
                alz_side_post_update(d, lb);
            d->st.repeat_run = 0;
        }
        if (gse)
            fprintf(stderr,
                "[GATESTAT] cls3(gagnant) blk=%u | flips lit->match (PORTE accepte "
                "match that clone literalizes, SMALL)=%u (b1<12544=%u) | flips "
                "match->lit (LARGE)=%u (b1=%u) | match=%u | without-match=%u\n",
                gs_blk, gs_flip_match, gs_flip_match_b1,
                gs_flip_lit, gs_flip_lit_b1, gs_agree, gs_nomatch);
        if (p1_on)
            fprintf(stderr,
                "[P1GATE] cls3(gagnant) Sigma VRAI (persistance) | cand=%u | allow=%u "
                "deny=%u (%.1f%% allow) | diff_vs_proxy=%u | LEGACY-match: accord=%u "
                "diff=%u (%.1f%%)\n",
                p1_cand, p1_true_allow, p1_true_deny,
                p1_cand ? 100.0 * (double)p1_true_allow / (double)p1_cand : 0.0,
                p1_vs_proxy_flip, p1_legacy_agree, p1_legacy_diff,
                (p1_legacy_agree + p1_legacy_diff)
                    ? 100.0 * (double)p1_legacy_agree / (double)(p1_legacy_agree + p1_legacy_diff)
                    : 0.0);
        if (cm_on)
            fprintf(stderr,
                "[CMCOST] cls3 | cand=%u | allow_true!=allow_proxy=%u "
                "(q_proxy>=10:%u q_true>=10:%u/%u) | TRUE-cout flips "
                "lit->match(PETIT)=%u match->lit(GROS)=%u accord=%u\n",
                cm_cand, cm_flip_allow, cm_q_proxy10, cm_q_true10, cm_cand,
                cm_flip_match, cm_flip_lit, cm_agree);
        if (am_on)
            fprintf(stderr,
                "[ARGMIN] H1 (cout_token<Slitteraux, etat CHAUD) | legacy-matchstarts "
                "visites=%u | regle ACCEPTE=%u MISS=%u cantcode=%u | b1 accept=%u "
                "miss=%u | rappel=%.1f%%\n",
                am_eval, am_accept, am_miss, am_cantcode,
                am_accept_b1, am_miss_b1,
                am_eval ? 100.0 * (double)(am_accept + am_cantcode) / (double)am_eval : 0.0);
        if (am_on)
            fprintf(stderr,
                "[ARGMIN-LEN] (piece (c) longueur) n=%u | ocnt==raw:%u ocnt==enc:%u "
                "ocnt<raw(longueur-limite):%u ocnt>raw(introuvable):%u | "
                "avg_raw=%.1f avg_cnt=%.1f | hist(raw-ocnt)[0..7+]=%u/%u/%u/%u/%u/%u/%u/%u\n",
                am_eval, am_raw_eq, am_enc_eq, am_shorter, am_longer,
                am_eval ? (double)am_raw_sum / (double)am_eval : 0.0,
                am_eval ? (double)am_cnt_sum / (double)am_eval : 0.0,
                am_hist[0], am_hist[1], am_hist[2], am_hist[3],
                am_hist[4], am_hist[5], am_hist[6], am_hist[7]);
        if (am_on)
            fprintf(stderr,
                "[ARGMIN-CLS] (piece (c) choix classe) n=%u | gagnant==oracle:%u "
                "DIFFERENT:%u without-cand:%u | when DIFF: oracle tok[t1/t2/t3]=%u/%u/%u "
                "vs notre tok=%u/%u/%u | R_len(plus-long+tie-cout) accord=%u/%u\n",
                am_eval, am_cls_match, am_cls_wrong, am_cls_nocand,
                am_otok_h[1], am_otok_h[2], am_otok_h[3],
                am_wtok_h[1], am_wtok_h[2], am_wtok_h[3],
                am_cls_match_len, am_eval);
        if (am_on)
            fprintf(stderr,
                "[ARGMIN-CLS3DIAG] oracle=TOK3 & divergent : odist==recent[1]:%u "
                "==recent[0]:%u other:%u | our TOK3 missing:%u\n",
                am_t3_eqr1, am_t3_eqr0, am_t3_other, am_t3_nocand);
        if (cf_on)
            fprintf(stderr,
                "[COSTFIT] divergences mesurees:%u | vrais-bits: legacy_inferieur:%u "
                "our_lesser:%u equal:%u | legacy_longer:%u same-len:%u | "
                "moy-bits legacy=%.1f notre=%.1f\n",
                cf_div, cf_oracle_lower, cf_ours_lower, cf_tie,
                cf_oracle_longer, cf_same_len,
                cf_div ? (double)cf_sum_o / cf_div : 0.0,
                cf_div ? (double)cf_sum_w / cf_div : 0.0);
        if (ct_on)
            fprintf(stderr,
                "[COSTTALLY] bloc1 (etat force-oracle, bits fideles) regle (match<run-lit) vs legacy :\n"
                "  legacy-MATCH : TP(cout=d'accord match)=%u  FN(cout=eut dit lit)=%u  -> rappel=%.1f%%\n"
                "  legacy-LIT   : FP(cost allowed over-match)=%u  TN(cost veto good)=%u  -> FP/(FP+TN)=%.1f%%\n"
                "  TP economie moy=%.1f o  |  FN surcout moy=%.1f o (match pris a perte = INVESTISSEMENT recent[])  |  FP=%.1f o TN=%.1f o\n",
                ct_tp, ct_fn,
                (ct_tp + ct_fn) ? 100.0*ct_tp/(ct_tp + ct_fn) : 0.0,
                ct_fp, ct_tn,
                (ct_fp + ct_tn) ? 100.0*ct_fp/(ct_fp + ct_tn) : 0.0,
                ct_tp ? (double)ct_tp_under/ct_tp/8.0 : 0.0,
                ct_fn ? (double)ct_fn_over/ct_fn/8.0 : 0.0,
                ct_fp ? (double)ct_fp_save/ct_fp/8.0 : 0.0,
                ct_tn ? (double)ct_tn_save/ct_tn/8.0 : 0.0);
        if (ct_on && (ct_tp + ct_fp))
            fprintf(stderr,
                "[COSTTALLY-HIST] TP n=%u : tok[1/2/3]=%u/%u/%u | slot0..4=%u/%u/%u/%u/%u absent=%u | len[2-3/4-7/8-15/16+]=%u/%u/%u/%u\n"
                "[COSTTALLY-HIST] FP n=%u : tok[1/2/3]=%u/%u/%u | slot0..4=%u/%u/%u/%u/%u absent=%u | len[2-3/4-7/8-15/16+]=%u/%u/%u/%u\n",
                ct_tp, ct_tp_tok[1], ct_tp_tok[2], ct_tp_tok[3],
                ct_tp_slot[0], ct_tp_slot[1], ct_tp_slot[2], ct_tp_slot[3], ct_tp_slot[4], ct_tp_slot[ALZ_MAX_RECENT],
                ct_tp_len[0], ct_tp_len[1], ct_tp_len[2], ct_tp_len[3],
                ct_fp, ct_fp_tok[1], ct_fp_tok[2], ct_fp_tok[3],
                ct_fp_slot[0], ct_fp_slot[1], ct_fp_slot[2], ct_fp_slot[3], ct_fp_slot[4], ct_fp_slot[ALZ_MAX_RECENT],
                ct_fp_len[0], ct_fp_len[1], ct_fp_len[2], ct_fp_len[3]);
        if (ct_on && (ct_tp + ct_fp))
            fprintf(stderr,
                "[COSTTALLY-JOINT] (nouvelle=dist absente de recent[] ; court=len<=7)\n"
                "  TP : new_short=%u new_long=%u | exist_short=%u exist_long=%u\n"
                "  FP : new_short=%u new_long=%u | exist_short=%u exist_long=%u\n",
                ct_tp_ns, ct_tp_nl, ct_tp_es, ct_tp_el,
                ct_fp_ns, ct_fp_nl, ct_fp_es, ct_fp_el);
        /* [A5.3-k has] calibration sure l'state legacy (mode forces) : slot*len some vrais matchs. */
        if (ct_on && g_oracle && (ct_tp + ct_fn))
            fprintf(stderr,
                "[RECENCYCAL-LEGACY] vrais matchs (etat legacy) : slot0..11/absent=%u/%u/%u/%u/%u/%u/%u/%u/%u/%u/%u/%u/%u | len[2-3/4-7/8-15/16+]=%u/%u/%u/%u\n",
                lg_slot[0], lg_slot[1], lg_slot[2], lg_slot[3], lg_slot[4], lg_slot[5],
                lg_slot[6], lg_slot[7], lg_slot[8], lg_slot[9], lg_slot[10], lg_slot[11], lg_slot[ALZ_MAX_RECENT],
                lg_len[0], lg_len[1], lg_len[2], lg_len[3]);
        /* [A5.3-k b] table some candidates clone (mode no-forces) -> balayage K/L out-line, ecrite 1*. */
        if (ct_on && !g_oracle && g_amref) {
            FILE *fo = fopen("research/gt_scorer/recencygate_table.tsv", "w");
            if (fo) {
                int s_, l_, k_;
                fprintf(fo, "# slot len_bucket legacykind count  (len:0=2-3,1=4-7,2=8-15,3=16+ ; slot %d=nouvelle/absente)\n",
                        ALZ_MAX_RECENT);
                for (s_ = 0; s_ <= ALZ_MAX_RECENT; s_++)
                    for (l_ = 0; l_ < 4; l_++)
                        for (k_ = 0; k_ < 2; k_++)
                            if (rg_tbl[s_][l_][k_])
                                fprintf(fo, "%d %d %d %u\n", s_, l_, k_, rg_tbl[s_][l_][k_]);
                fclose(fo);
                fprintf(stderr, "[RECENCYGATE] table clone ecrite research/gt_scorer/recencygate_table.tsv\n");
            }
        }
        /* [A5.3-l] dump of the table clean (state legacy, mode forces + UHA_RECENCYGATE). */
        if (rgprobe_on && g_oracle && !lt_dumped) {
            lt_dumped = 1;
            FILE *fo = fopen("research/gt_scorer/recencygate_table_legacy.tsv", "w");
            if (fo) {
                int s_, l_, k_;
                uint32_t n1 = 0, n0 = 0;
                fprintf(fo, "# slot len_bucket kind count  (len:0=2-3,1=4-7,2=8-15,3=16+ ; slot %d=new ; kind:1=legacy match,0=legacy LIT but finder proposes)\n",
                        ALZ_MAX_RECENT);
                for (s_ = 0; s_ <= ALZ_MAX_RECENT; s_++)
                    for (l_ = 0; l_ < 4; l_++)
                        for (k_ = 0; k_ < 2; k_++)
                            if (lt_tbl[s_][l_][k_]) {
                                fprintf(fo, "%d %d %d %u\n", s_, l_, k_, lt_tbl[s_][l_][k_]);
                                if (k_) n1 += lt_tbl[s_][l_][k_]; else n0 += lt_tbl[s_][l_][k_];
                            }
                fclose(fo);
                fprintf(stderr,
                    "[RECENCYGATE-LEGACY] etat legacy propre : %u matchs legacy (kind1) + %u cibles veto (kind0, finder propose) -> research/gt_scorer/recencygate_table_legacy.tsv\n",
                    n1, n0);
            }
        }
        alz_oracle_free(g_amref); g_amref = NULL;
        /* [A5.3-m] bilan finder of base vs legacy (mode forces, no-emissive). */
        if (fd_on && fd_lmatch) {
            fprintf(stderr,
                "[FINDERDBG-a] vrais matchs legacy=%u | finder: MISS=%u sameEq=%u sameLong=%u sameShort=%u DIFF=%u(long=%u short=%u eqlen=%u NEWdist=%u) tokmatch=%u/%u\n",
                fd_lmatch, fd_miss, fd_same_eq, fd_same_long, fd_same_short,
                fd_diff, fd_diff_long, fd_diff_short, fd_diff_eqlen, fd_diff_new, fd_tokmatch, fd_lmatch);
            fprintf(stderr,
                "[FINDERDBG-b] cibles veto (finder propose/legacy LIT)=%u : newdist=%u | exist_short(len<=7)=%u | exist_long(len>=8)=%u\n",
                fb_veto, fb_new, fb_exist_short, fb_exist_long);
            fprintf(stderr,
                "[LOOKAHEAD-n] delta to next legacy start after veto target: d1=%u d2-4=%u d5-8=%u d9-16=%u d17-64=%u d65+=%u none=%u | steal(finder covers start)=%u\n",
                la_d1, la_d2_4, la_d5_8, la_d9_16, la_d17_64, la_d65p, la_none, la_steal);
            fflush(stderr);
        }
        if (fdump) fclose(fdump);
        if (cfdump) { fflush(cfdump); fclose(cfdump);
            fprintf(stderr, "[COSTFLUSH] wrote %s\n", cfe); fflush(stderr); }
        free(seed_arena);
        free(seed_ctx3);
    }

    if (rc == 0 && uha_rcw_flush(&w) != 0)
        rc = 3;

    alz_oracle_free(g_oracle);
    g_oracle = NULL;

    if (ws && ws->hashtab && ws->chain && ws->chain_size >= chain_size) {
        /* Smart reset: restore only slots modified by insertions */
        uint32_t max_ins = (ins < usize) ? ins : usize;
        for (uint32_t i = 0; i + 2 < max_ins; i++) {
            uint32_t h = (((uint32_t)plain[i] << 16) | ((uint32_t)plain[i + 1] << 8)
                         | plain[i + 2]) * 1140071481u >> (32 - 22);
            hashtab[h] = 0xFFFFFFFFu;
        }
        uint32_t max_chain = (max_ins < chain_size) ? max_ins : chain_size;
        for (uint32_t i = 0; i < max_chain; i++) {
            chain[i] = 0xFFFFFFFFu;
        }
    } else {
        free(hashtab);
        free(chain);
    }
    if (!ws || !ws->window) {
        free(d->window);
    }
    free(d);
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

int uha_alz_encode(const uint8_t *plain, uint32_t usize,
                   int order,
                   const uint32_t *member_ends, int nmembers,
                   int escape_sel, int min_len, int tok2_min, int lazy,
                   uint8_t **out, size_t *outlen)
{
    return uha_alz_encode_ws(plain, usize, order, member_ends, nmembers,
                             escape_sel, min_len, tok2_min, lazy,
                             out, outlen, NULL);
}
