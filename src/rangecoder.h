#ifndef UHA_RANGECODER_H
#define UHA_RANGECODER_H

#include <stdint.h>
#include <stddef.h>

#define UHA_RC_TOP   0x01000000u
#define UHA_RC_INIT  0xFFFFFFFFu

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
    int            exhausted;
} uha_reader;

typedef struct {
    uha_reader rd;
    uint32_t   code;
    uint32_t   range;
    int        corrupt;
} uha_rc;

#if defined(__GNUC__) || defined(__clang__)
#define UHA_RC_LIKELY(x)   __builtin_expect(!!(x), 1)
#define UHA_RC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define UHA_RC_INLINE      static inline __attribute__((always_inline))
#else
#define UHA_RC_LIKELY(x)   (x)
#define UHA_RC_UNLIKELY(x) (x)
#define UHA_RC_INLINE      static inline
#endif

/*
 * Range decoder primitives.
 *
 * They are defined inline here (instead of out-of-line in rangecoder.c) so
 * that every codec gets them inlined into its inner loops. The semantics are
 * exactly those of the historical out-of-line versions, including the
 * `corrupt` flag and the clamping of out-of-range thresholds.
 *
 * Binary decisions avoid the second division of the generic path:
 *     floor(code / r) < p   <=>   code < r * p        (r, p > 0)
 * and the "threshold out of range" condition floor(code / r) >= total is
 * code >= r * total. All products are bounded by the 32-bit range, so the
 * decoded bits and the coder state are identical to the division form.
 */

UHA_RC_INLINE void uha_reader_init(uha_reader *r, const uint8_t *data, size_t size)
{
    r->data = data;
    r->size = size;
    r->pos = 0;
    r->exhausted = 0;
}

UHA_RC_INLINE uint8_t uha_reader_byte(uha_reader *r)
{
    if (UHA_RC_LIKELY(r->pos < r->size))
        return r->data[r->pos++];
    r->exhausted = 1;
    return 0;
}

void     uha_rc_init(uha_rc *rc, const uint8_t *data, size_t size);

UHA_RC_INLINE void uha_rc_normalize(uha_rc *rc)
{
    while (rc->range < UHA_RC_TOP) {
        rc->code = (rc->code << 8) | uha_reader_byte(&rc->rd);
        rc->range <<= 8;
    }
}

UHA_RC_INLINE uint32_t uha_rc_threshold(uha_rc *rc, uint32_t total)
{
    uint32_t r;

    if (UHA_RC_UNLIKELY(total == 0)) {
        rc->corrupt = 1;
        return 0;
    }
    rc->range /= total;
    if (UHA_RC_UNLIKELY(rc->range == 0)) {
        rc->corrupt = 1;
        return 0;
    }
    r = rc->code / rc->range;
    if (UHA_RC_UNLIKELY(r >= total)) {
        rc->corrupt = 1;
        r = total - 1;
    }
    return r;
}

UHA_RC_INLINE uint32_t uha_rc_fixed12(uha_rc *rc)
{
    uint32_t r;

    rc->range >>= 12;
    if (UHA_RC_UNLIKELY(rc->range == 0)) {
        rc->corrupt = 1;
        return 0;
    }
    r = rc->code / rc->range;
    if (UHA_RC_UNLIKELY(r >= 4096)) {
        rc->corrupt = 1;
        r = 4095;
    }
    return r;
}

UHA_RC_INLINE void uha_rc_remove(uha_rc *rc, uint32_t low, uint32_t high)
{
    if (UHA_RC_UNLIKELY(high <= low)) {
        rc->corrupt = 1;
        return;
    }
    rc->code -= rc->range * low;
    rc->range *= (high - low);
    uha_rc_normalize(rc);
}

UHA_RC_INLINE uint32_t uha_rc_uniform(uha_rc *rc, uint32_t total)
{
    uint32_t t;

    if (UHA_RC_UNLIKELY(total == 0)) {
        rc->corrupt = 1;
        return 0;
    }
    t = uha_rc_threshold(rc, total);
    uha_rc_remove(rc, t, t + 1);
    return t;
}

/*
 * Division-free equivalent of
 *     t = uha_rc_fixed12(rc); bit = !(t < split);
 *     bit ? uha_rc_remove(rc, split, 4096) : uha_rc_remove(rc, 0, split);
 * Returns the decoded bit. Requires 0 < split < 4096 for the fast path; any
 * other case (and every corrupt-stream case) takes the reference path.
 */
UHA_RC_INLINE int uha_rc_decode_bit12(uha_rc *rc, uint32_t split)
{
    uint32_t r = rc->range >> 12;
    uint32_t bound;

    if (UHA_RC_UNLIKELY(r == 0 || split == 0 || split >= 4096 || rc->code >= (r << 12))) {
        uint32_t t = uha_rc_fixed12(rc);
        if (t < split) {
            uha_rc_remove(rc, 0, split);
            return 0;
        }
        uha_rc_remove(rc, split, 4096);
        return 1;
    }
    bound = r * split;
    if (rc->code < bound) {
        rc->range = bound;
        uha_rc_normalize(rc);
        return 0;
    }
    rc->code -= bound;
    rc->range = r * (4096u - split);
    uha_rc_normalize(rc);
    return 1;
}

/*
 * Division-free equivalent of
 *     t = uha_rc_threshold(rc, total); bit = !(t < split);
 *     bit ? uha_rc_remove(rc, split, total) : uha_rc_remove(rc, 0, split);
 * for 0 < split < total. Other cases take the reference path.
 */
UHA_RC_INLINE int uha_rc_decode_binary(uha_rc *rc, uint32_t split, uint32_t total)
{
    uint32_t r, bound;

    if (UHA_RC_UNLIKELY(total == 0 || split == 0 || split >= total))
        goto slow;
    r = rc->range / total;
    if (UHA_RC_UNLIKELY(r == 0 || (uint64_t)rc->code >= (uint64_t)r * total))
        goto slow;
    rc->range = r;
    bound = r * split;
    if (rc->code < bound) {
        rc->range = bound;
        uha_rc_normalize(rc);
        return 0;
    }
    rc->code -= bound;
    rc->range = r * (total - split);
    uha_rc_normalize(rc);
    return 1;
slow:
    {
        uint32_t t = uha_rc_threshold(rc, total);
        if (t < split) {
            uha_rc_remove(rc, 0, split);
            return 0;
        }
        uha_rc_remove(rc, split, total);
        return 1;
    }
}

UHA_RC_INLINE int uha_rc_bit12_shift(uha_rc *rc, uint16_t *prob, int shift)
{
    uint32_t r, t, p, bound;

    if (rc->corrupt)
        return 0;
    if (shift < 1)
        shift = 1;
    else if (shift > 12)
        shift = 12;

    r = rc->range >> 12;
    p = *prob;
    if (UHA_RC_UNLIKELY(r == 0)) {
        rc->range = 0;
        rc->corrupt = 1;
        return 0;
    }
    if (UHA_RC_UNLIKELY(rc->code >= (r << 12))) {
        /* Threshold out of range: reference behaviour (clamp to 4095). */
        rc->range = r;
        rc->corrupt = 1;
        t = 4095;
        if (t < p) {
            rc->range *= p;
            *prob = (uint16_t)(p + ((4096u - p) >> shift));
            uha_rc_normalize(rc);
            return 0;
        }
        rc->code -= rc->range * p;
        rc->range *= (4096u - p);
        *prob = (uint16_t)(p - (p >> shift));
        uha_rc_normalize(rc);
        return 1;
    }
    /* Here floor(code / r) <= 4095, so (t < p) <=> (code < r * p). */
    bound = r * p;
    if (rc->code < bound) {
        rc->range = bound;
        *prob = (uint16_t)(p + ((4096u - p) >> shift));
        uha_rc_normalize(rc);
        return 0;
    }
    rc->code -= bound;
    rc->range = r * (4096u - p);
    *prob = (uint16_t)(p - (p >> shift));
    uha_rc_normalize(rc);
    return 1;
}

UHA_RC_INLINE int uha_rc_bit12(uha_rc *rc, uint16_t *prob)
{
    return uha_rc_bit12_shift(rc, prob, 6);
}

typedef struct {
    uint64_t  low;
    uint32_t  range;
    uint8_t  *buf;
    size_t    cap;
    size_t    pos;
    uint32_t  ffnum;
    uint8_t   cache;
    int       error;
} uha_rcw;

int  uha_rcw_init(uha_rcw *w);
int  uha_rcw_reserve(uha_rcw *w, size_t cap);
int  uha_rcw_encode(uha_rcw *w, uint32_t low, uint32_t high, uint32_t total);
int  uha_rcw_encode_fixed12(uha_rcw *w, uint32_t low, uint32_t high);
int  uha_rcw_flush(uha_rcw *w);
void uha_rcw_free(uha_rcw *w);

#endif /* UHA_RANGECODER_H */
