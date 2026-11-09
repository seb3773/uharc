#include "rangecoder.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef UHA_ENABLE_TRACING
extern uint32_t alz_score_cost(uint32_t freq, uint32_t total);
static uint64_t g_uha_cost_acc = 0;
static uint64_t g_uha_cost_cap = 0;
static uint64_t g_uha_cost_cnt = 0;
static int g_uha_cost_mode = -1;

int g_rct = -1;
static uint32_t g_last_total = 0;
static unsigned long g_rc_enc_n = 0, g_rc_dec_n = 0;
unsigned long g_rc_enc_seq = 0;

unsigned long uha_rc_dec_count(void) { return g_rc_dec_n; }

static int rct_on(void)
{
    if (g_rct < 0) { const char *e = getenv("UHA_PPMTRACE"); g_rct = (e && e[0] == '2') ? 2 : 0; }
    return g_rct;
}

static int uha_cost_mode(void)
{
    if (g_uha_cost_mode < 0) {
        const char *e = getenv("UHA_PPM_COST");
        g_uha_cost_mode = e ? atoi(e) : 0;
    }
    return g_uha_cost_mode;
}

void uha_cost_reset(void) { if (uha_cost_mode()) { g_uha_cost_acc = 0; g_uha_cost_cnt = 0; } }
uint64_t uha_cost_get(void) { return g_uha_cost_acc; }
void uha_cost_setcap(uint64_t n) { g_uha_cost_cap = n; }

static inline void uha_cost_add(uint32_t low, uint32_t high, uint32_t total)
{
    int m = uha_cost_mode();
    if (!m) return;
    if (g_uha_cost_cap && g_uha_cost_cnt >= g_uha_cost_cap) return;
    g_uha_cost_cnt++;
    if (m == 1)      g_uha_cost_acc += (uint64_t)alz_score_cost(low, total);
    else if (m == 2) g_uha_cost_acc += (uint64_t)alz_score_cost(high - low, total);
    else             g_uha_cost_acc += (uint64_t)alz_score_cost(total - high, total);
}

static uint64_t g_tr_lo = 0, g_tr_hi = ~(uint64_t)0;
static unsigned long g_tr_turn = 0;

static int termrenorm_on(void)
{
    static int v = -1;
    if (v < 0) {
        const char *f = getenv("UHA_PPM_FAMADV");
        const char *e = getenv("UHA_PPM_TERMRENORM");
        v = (f && f[0] != '0' && e && e[0]) ? 1 : 0;
        if (v) {
            char *end = NULL;
            unsigned long lo = strtoul(e, &end, 10);
            if (end && *end == ':') {
                g_tr_lo = lo;
                g_tr_hi = strtoul(end + 1, NULL, 10);
            } else if (lo > 1UL) {
                g_tr_lo = lo;
                g_tr_hi = lo + 64UL;
            }
        }
    }
    return v;
}
#else
/* Non-tracing stubs */
unsigned long uha_rc_dec_count(void) { return 0; }
void uha_cost_reset(void) {}
uint64_t uha_cost_get(void) { return 0; }
void uha_cost_setcap(uint64_t n) { (void)n; }
#endif

void uha_reader_init(uha_reader *r, const uint8_t *data, size_t size)
{
    r->data = data;
    r->size = size;
    r->pos = 0;
    r->exhausted = 0;
}

uint8_t uha_reader_byte(uha_reader *r)
{
    if (r->pos < r->size)
        return r->data[r->pos++];
    r->exhausted = 1;
    return 0;
}

void uha_rc_init(uha_rc *rc, const uint8_t *data, size_t size)
{
    int i;

    uha_reader_init(&rc->rd, data, size);
    rc->code = 0;
    rc->range = UHA_RC_INIT;
    rc->corrupt = 0;
    for (i = 0; i < 5; i++)
        rc->code = (rc->code << 8) | uha_reader_byte(&rc->rd);
    if (rc->rd.exhausted)
        rc->corrupt = 1;
}

void uha_rc_normalize(uha_rc *rc)
{
    while (rc->range < UHA_RC_TOP) {
        rc->code = (rc->code << 8) | uha_reader_byte(&rc->rd);
        rc->range <<= 8;
    }
}

uint32_t uha_rc_threshold(uha_rc *rc, uint32_t total)
{
    uint32_t r;

#ifdef UHA_ENABLE_TRACING
    g_last_total = total;
#endif
    if (total == 0) {
        rc->corrupt = 1;
        return 0;
    }
    rc->range /= total;
    if (rc->range == 0) {
        rc->corrupt = 1;
        return 0;
    }
    r = rc->code / rc->range;
    if (r >= total) {
        rc->corrupt = 1;
        r = total - 1;
    }
    return r;
}

uint32_t uha_rc_fixed12(uha_rc *rc)
{
    uint32_t r;

    rc->range >>= 12;
    if (rc->range == 0) {
        rc->corrupt = 1;
        return 0;
    }
    r = rc->code / rc->range;
    if (r >= 4096) {
        rc->corrupt = 1;
        r = 4095;
    }
    return r;
}

void uha_rc_remove(uha_rc *rc, uint32_t low, uint32_t high)
{
#ifdef UHA_ENABLE_TRACING
    {
        static int p255 = -1;
        if (p255 < 0) { const char *e = getenv("UHA_M255RC"); p255 = (e && e[0] != '0') ? 1 : 0; }
        if (p255 && rct_on() == 2) {
            size_t q = rc->rd.pos;
            fprintf(stderr, "[M255ST] n=%lu code=%u range=%u pos=%lu size=%lu b=%02x%02x%02x%02x\n",
                    (unsigned long)g_rc_dec_n, rc->code, rc->range, (unsigned long)q,
                    (unsigned long)rc->rd.size,
                    q + 0 < rc->rd.size ? rc->rd.data[q] : 0u,
                    q + 1 < rc->rd.size ? rc->rd.data[q + 1] : 0u,
                    q + 2 < rc->rd.size ? rc->rd.data[q + 2] : 0u,
                    q + 3 < rc->rd.size ? rc->rd.data[q + 3] : 0u);
        }
    }
#endif
    if (high <= low) {
        rc->corrupt = 1;
        return;
    }
    rc->code -= rc->range * low;
    rc->range *= (high - low);
#ifdef UHA_ENABLE_TRACING
    if (rct_on() == 2)
        fprintf(stderr, "[RCDEC] n=%lu low=%u high=%u total=%u pos=%lu site=%p\n",
                g_rc_dec_n++, low, high, g_last_total, (unsigned long)rc->rd.pos,
                __builtin_return_address(0));
#endif
    uha_rc_normalize(rc);
}

uint32_t uha_rc_uniform(uha_rc *rc, uint32_t total)
{
    uint32_t t;

    if (total == 0) {
        rc->corrupt = 1;
        return 0;
    }
    t = uha_rc_threshold(rc, total);
    uha_rc_remove(rc, t, t + 1);
    return t;
}

int uha_rc_bit12_shift(uha_rc *rc, uint16_t *prob, int shift)
{
    uint32_t t;

    if (rc->corrupt)
        return 0;
    if (shift < 1)
        shift = 1;
    else if (shift > 12)
        shift = 12;

    rc->range >>= 12;
    if (rc->range == 0) {
        rc->corrupt = 1;
        return 0;
    }
    t = rc->code / rc->range;
    if (t >= 4096) {
        rc->corrupt = 1;
        t = 4095;
    }
    if (t < *prob) {
        rc->range *= *prob;
        *prob = (uint16_t)(*prob + ((4096u - *prob) >> shift));
        uha_rc_normalize(rc);
        return 0;
    }
    rc->code -= rc->range * *prob;
    rc->range *= (4096u - *prob);
    *prob = (uint16_t)(*prob - (*prob >> shift));
    uha_rc_normalize(rc);
    return 1;
}

int uha_rc_bit12(uha_rc *rc, uint16_t *prob)
{
    return uha_rc_bit12_shift(rc, prob, 6);
}

static int rcw_grow(uha_rcw *w, size_t extra)
{
    size_t ncap;
    uint8_t *nbuf;

    if (w->pos + extra <= w->cap)
        return 0;
    ncap = w->cap ? w->cap : 64;
    while (ncap < w->pos + extra) {
        if (ncap > (size_t)-1 / 2)
            return -1;
        ncap *= 2;
    }
    nbuf = realloc(w->buf, ncap);
    if (!nbuf)
        return -1;
    w->buf = nbuf;
    w->cap = ncap;
    return 0;
}

static inline int rcw_shift_low(uha_rcw *w)
{
    uint32_t carry = (uint32_t)(w->low >> 32);
#ifdef UHA_ENABLE_TRACING
    int      tr       = termrenorm_on();
    size_t   tr_pos0  = w->pos;
    uint32_t tr_range = w->range;
    uint32_t tr_low   = (uint32_t)w->low;
    uint32_t tr_carry = carry;
    uint32_t tr_ff    = w->ffnum;
    uint8_t  tr_cache = w->cache;
    int      tr_emit  = ((uint32_t)w->low < 0xFF000000u || carry != 0) ? 1 : 0;
#endif

    if ((uint32_t)w->low < 0xFF000000u || carry != 0) {
        uint8_t temp = w->cache;
        uint32_t n = w->ffnum;
        if (rcw_grow(w, (size_t)n + 1) != 0) {
            w->error = 1;
            return -1;
        }
        for (;;) {
            w->buf[w->pos++] = (uint8_t)(temp + (uint8_t)carry);
#ifdef UHA_ENABLE_TRACING
            { static int ob = -1; if (ob < 0) { const char *e = getenv("UHA_C550DBG"); ob = (e && e[0] != '0') ? 1 : 0; }
              if (ob) fprintf(stderr, "[OUTB] w=%p pos=%zu byte=%02x encseq=%lu\n",
                              (void*)w, w->pos - 1, w->buf[w->pos - 1], g_rc_enc_seq); }
#endif
            temp = 0xFF;
            if (n == 0)
                break;
            n--;
        }
        w->ffnum = 0;
        w->cache = (uint8_t)((uint32_t)w->low >> 24);
    } else {
        w->ffnum++;
    }
    w->low = (uint64_t)(uint32_t)(w->low << 8);
#ifdef UHA_ENABLE_TRACING
    if (tr && (uint64_t)tr_pos0 >= g_tr_lo && (uint64_t)tr_pos0 <= g_tr_hi) {
        size_t nby = w->pos - tr_pos0;
        fprintf(stderr,
            "[TERMRENORM] w=%p turn=%lu pos_avant=%zu pos_apres=%zu range=%08X low=%08X "
            "carry=%u cache=%02X cacheSize=%u emissif=%d n_octets=%zu octet0=%02X "
            "octetN=%02X encseq=%lu\n",
            (void *)w, ++g_tr_turn, tr_pos0, w->pos, tr_range, tr_low, tr_carry,
            tr_cache, tr_ff, tr_emit, nby,
            (unsigned)(nby ? w->buf[tr_pos0] : 0u),
            (unsigned)(nby ? w->buf[w->pos - 1] : 0u), g_rc_enc_seq);
    }
#endif
    return 0;
}

static inline int rcw_normalize(uha_rcw *w)
{
    while (w->range < UHA_RC_TOP) {
        if (rcw_shift_low(w) != 0)
            return -1;
        w->range <<= 8;
    }
    return 0;
}

int uha_rcw_init(uha_rcw *w)
{
    if (!w)
        return -1;
    w->low = 0;
    w->range = UHA_RC_INIT;
    w->buf = NULL;
    w->cap = 0;
    w->pos = 0;
    w->ffnum = 0;
    w->cache = 0;
    w->error = 0;
    return 0;
}

int uha_rcw_encode(uha_rcw *w, uint32_t low, uint32_t high, uint32_t total)
{
    if (!w || w->error)
        return -1;
    if (total == 0 || high <= low) {
        w->error = 1;
        return -1;
    }
    w->range /= total;
    if (w->range == 0) {
        w->error = 1;
        return -1;
    }
    w->low += (uint64_t)w->range * low;
    w->range *= (high - low);
#ifdef UHA_ENABLE_TRACING
    g_rc_enc_seq++;
    uha_cost_add(low, high, total);
    if (rct_on() == 2)
        fprintf(stderr, "[RCENC] n=%lu low=%u high=%u total=%u pos=%lu\n",
                g_rc_enc_n++, low, high, total, (unsigned long)w->pos);
#endif
    return rcw_normalize(w);
}

int uha_rcw_encode_fixed12(uha_rcw *w, uint32_t low, uint32_t high)
{
    if (!w || w->error)
        return -1;
    if (high <= low || high > 4096) {
        w->error = 1;
        return -1;
    }
    w->range >>= 12;
    if (w->range == 0) {
        w->error = 1;
        return -1;
    }
    w->low += (uint64_t)w->range * low;
    w->range *= (high - low);
#ifdef UHA_ENABLE_TRACING
    uha_cost_add(low, high, 4096u);
#endif
    return rcw_normalize(w);
}

int uha_rcw_flush(uha_rcw *w)
{
    int i, n = 5;
#ifdef UHA_ENABLE_TRACING
    size_t pre;
    static int s_n = -2;
    if (!w || w->error)
        return -1;
    if (s_n == -2) { const char *e = getenv("UHA_RCFINAL"); s_n = e ? atoi(e) : 5; }
    n = s_n;
    pre = w->pos;
    uint64_t pre_low = w->low;
    uint32_t pre_range = w->range, pre_cache = w->cache, pre_ff = w->ffnum;
#else
    if (!w || w->error)
        return -1;
#endif
    for (i = 0; i < n; i++) {
        if (rcw_shift_low(w) != 0)
            return -1;
    }
#ifdef UHA_ENABLE_TRACING
    if (getenv("UHA_RCFLUSHDBG")) {
        fprintf(stderr, "[rcflush] n=%d pre_pos=%zu -> pos=%zu ENTRY low=%016llx range=%08x cache=%02x ffnum=%u tail:",
                n, pre, w->pos,
                (unsigned long long)pre_low, pre_range, pre_cache, pre_ff);
        for (i = 0; i < (int)w->pos && i < 8; i++)
            fprintf(stderr, " %02x", w->buf[w->pos - ((int)w->pos - i)]);
        fprintf(stderr, " | last8:");
        for (i = (int)w->pos - 8; i < (int)w->pos; i++)
            if (i >= 0) fprintf(stderr, " %02x", w->buf[i]);
        fprintf(stderr, "\n");
    }
    if (getenv("UHA_RCDUMP") && pre < 64) {
        fprintf(stderr, "[rcdump] pre_pos=%zu pos=%zu buf:", pre, w->pos);
        for (i = 0; i < (int)w->pos; i++)
            fprintf(stderr, " %02x", w->buf[i]);
        fprintf(stderr, "\n");
    }
#endif
    return 0;
}

void uha_rcw_free(uha_rcw *w)
{
    if (!w)
        return;
    free(w->buf);
    w->buf = NULL;
    w->cap = 0;
    w->pos = 0;
}
