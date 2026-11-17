#include "rangecoder.h"

#include <stdlib.h>
#include <stdio.h>

void uha_cost_reset(void) {}
uint64_t uha_cost_get(void) { return 0; }
void uha_cost_setcap(uint64_t n) { (void)n; }

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

/* The other range decoder primitives are inline in rangecoder.h. */

#if defined(__GNUC__) || defined(__clang__)
#define UHA_LIKELY(x)   __builtin_expect(!!(x), 1)
#define UHA_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define UHA_LIKELY(x)   (x)
#define UHA_UNLIKELY(x) (x)
#endif

int uha_rcw_reserve(uha_rcw *w, size_t cap)
{
    if (!w)
        return -1;
    if (cap <= w->cap)
        return 0;
    uint8_t *nbuf = realloc(w->buf, cap);
    if (!nbuf)
        return -1;
    w->buf = nbuf;
    w->cap = cap;
    return 0;
}

static inline int rcw_grow(uha_rcw *w, size_t extra)
{
    size_t ncap;
    uint8_t *nbuf;

    if (UHA_LIKELY(w->pos + extra <= w->cap))
        return 0;
    ncap = w->cap ? w->cap : 65536;
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

    if (UHA_LIKELY((uint32_t)w->low < 0xFF000000u || carry != 0)) {
        uint8_t temp = w->cache;
        uint32_t n = w->ffnum;
        if (UHA_UNLIKELY(rcw_grow(w, (size_t)n + 1) != 0)) {
            w->error = 1;
            return -1;
        }
        for (;;) {
            w->buf[w->pos++] = (uint8_t)(temp + (uint8_t)carry);
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
    return rcw_normalize(w);
}

int uha_rcw_flush(uha_rcw *w)
{
    int i, n = 5;
    if (!w || w->error)
        return -1;
    for (i = 0; i < n; i++) {
        if (rcw_shift_low(w) != 0)
            return -1;
    }
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
