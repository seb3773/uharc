#ifndef UHA_SIMD_KERNELS_H
#define UHA_SIMD_KERNELS_H

/*
 * Small 256-entry integer kernels shared by the decoders. SSE2 is part of
 * the x86-64 base ISA, so no runtime dispatch is needed; other targets use
 * the portable C loops, which produce the same integer results.
 */

#include <stdint.h>

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

/* Sum of w[s] over the 16 symbols s in [base, base + 16) with m[s] == 0
 * (exact, no modular wrap: at most 16 * 65535). */
static inline uint32_t uha_sum16_block_where_zero(const uint16_t *m, const uint16_t *w)
{
#if defined(__SSE2__)
    const __m128i zero = _mm_setzero_si128();
    __m128i m0 = _mm_loadu_si128((const __m128i *)m);
    __m128i m1 = _mm_loadu_si128((const __m128i *)(m + 8));
    __m128i w0 = _mm_and_si128(_mm_cmpeq_epi16(m0, zero), _mm_loadu_si128((const __m128i *)w));
    __m128i w1 = _mm_and_si128(_mm_cmpeq_epi16(m1, zero), _mm_loadu_si128((const __m128i *)(w + 8)));
    /* widen to 32-bit lanes before adding so the result is exact */
    __m128i a = _mm_add_epi32(_mm_unpacklo_epi16(w0, zero), _mm_unpackhi_epi16(w0, zero));
    __m128i b = _mm_add_epi32(_mm_unpacklo_epi16(w1, zero), _mm_unpackhi_epi16(w1, zero));
    a = _mm_add_epi32(a, b);
    a = _mm_add_epi32(a, _mm_shuffle_epi32(a, 0x4E));
    a = _mm_add_epi32(a, _mm_shuffle_epi32(a, 0xB1));
    return (uint32_t)_mm_cvtsi128_si32(a);
#else
    uint32_t t = 0;
    int i;

    for (i = 0; i < 16; i++)
        t += m[i] == 0 ? w[i] : 0u;
    return t;
#endif
}

/* (sum of w[s] over the 256 symbols s with m[s] != 0) modulo 2^16. */
static inline uint32_t uha_sum16_where_nonzero(const uint16_t *m, const uint16_t *w)
{
#if defined(__SSE2__)
    const __m128i zero = _mm_setzero_si128();
    __m128i acc0 = zero, acc1 = zero;
    int i;

    for (i = 0; i < 256; i += 16) {
        __m128i m0 = _mm_loadu_si128((const __m128i *)(m + i));
        __m128i m1 = _mm_loadu_si128((const __m128i *)(m + i + 8));
        __m128i w0 = _mm_loadu_si128((const __m128i *)(w + i));
        __m128i w1 = _mm_loadu_si128((const __m128i *)(w + i + 8));
        acc0 = _mm_add_epi16(acc0, _mm_andnot_si128(_mm_cmpeq_epi16(m0, zero), w0));
        acc1 = _mm_add_epi16(acc1, _mm_andnot_si128(_mm_cmpeq_epi16(m1, zero), w1));
    }
    acc0 = _mm_add_epi16(acc0, acc1);
    acc0 = _mm_add_epi16(acc0, _mm_shuffle_epi32(acc0, 0x4E));
    acc0 = _mm_add_epi16(acc0, _mm_shuffle_epi32(acc0, 0xB1));
    acc0 = _mm_add_epi16(acc0, _mm_srli_epi32(acc0, 16));
    return (uint32_t)_mm_cvtsi128_si32(acc0) & 0xFFFFu;
#else
    uint32_t t = 0;
    int i;

    for (i = 0; i < 256; i++)
        t += m[i] != 0 ? w[i] : 0u;
    return t & 0xFFFFu;
#endif
}

/*
 * Descending escape search shared by several decoders. Reference walk:
 *
 *   acc = 0;
 *   for (s = 255; s >= 0; s--) {
 *       if (s == excl || m[s] != 0) continue;
 *       acc = (acc + w[s]) & 0xFFFF;
 *       if (acc > point) return s;           (*acc_out = acc)
 *   }
 *   return -1;                               (no symbol: corrupt stream)
 *
 * excl < 0 disables the exclusion, point < 2^16. Whole 16-symbol blocks
 * are skipped when their exact sum keeps the accumulator <= point: no
 * modular wrap can happen inside such a block and the walk would not stop
 * in it, so the result (symbol and accumulator) is identical.
 */
static inline int uha_desc_search_zero(const uint16_t *m, const uint16_t *w, int excl,
                                       uint32_t point, uint32_t *acc_out)
{
    uint32_t acc = 0;
    int b, s;

    for (b = 15; b >= 0; b--) {
        const int lo = b * 16;
        uint32_t bs = uha_sum16_block_where_zero(m + lo, w + lo);
        if (excl >= lo && excl < lo + 16 && m[excl] == 0)
            bs -= w[excl];
        if (acc + bs <= point) {
            acc += bs;
            continue;
        }
        for (s = lo + 15; s >= lo; s--) {
            if (s == excl || m[s] != 0)
                continue;
            acc = (acc + w[s]) & 0xFFFFu;
            if (acc > point) {
                *acc_out = acc;
                return s;
            }
        }
    }
    *acc_out = acc;
    return -1;
}

/* Sum of the 16 values w[0..15] (exact). */
static inline uint32_t uha_sum16_block(const uint16_t *w)
{
#if defined(__SSE2__)
    const __m128i zero = _mm_setzero_si128();
    __m128i w0 = _mm_loadu_si128((const __m128i *)w);
    __m128i w1 = _mm_loadu_si128((const __m128i *)(w + 8));
    __m128i a = _mm_add_epi32(_mm_unpacklo_epi16(w0, zero), _mm_unpackhi_epi16(w0, zero));
    __m128i b = _mm_add_epi32(_mm_unpacklo_epi16(w1, zero), _mm_unpackhi_epi16(w1, zero));
    a = _mm_add_epi32(a, b);
    a = _mm_add_epi32(a, _mm_shuffle_epi32(a, 0x4E));
    a = _mm_add_epi32(a, _mm_shuffle_epi32(a, 0xB1));
    return (uint32_t)_mm_cvtsi128_si32(a);
#else
    uint32_t t = 0;
    int i;

    for (i = 0; i < 16; i++)
        t += w[i];
    return t;
#endif
}

/*
 * One descending pass over g[255..0]: acc = (acc + g[s]) & 0xFFFF and stop
 * at the first s where acc > point (returns s), else returns -1 with the
 * accumulator of the full pass. Symbols with g[s] == 0 never change acc and
 * can never stop the walk, so callers zero the ineligible symbols. Block
 * skipping as in uha_desc_search_zero (point < 2^16, *acc_io < 2^16).
 */
static inline int uha_desc_search_g(const uint16_t *g, uint32_t point, uint32_t *acc_io)
{
    uint32_t acc = *acc_io;
    int b, s;

    for (b = 15; b >= 0; b--) {
        const int lo = b * 16;
        uint32_t bs = uha_sum16_block(g + lo);
        if (acc + bs <= point) {
            acc += bs;
            continue;
        }
        for (s = lo + 15; s >= lo; s--) {
            acc = (acc + g[s]) & 0xFFFFu;
            if (acc > point) {
                *acc_io = acc;
                return s;
            }
        }
    }
    *acc_io = acc;
    return -1;
}

/* g[s] = (m[s] == 0) ? w[s] : 0 for the 256 symbols; returns the exact sums
 * of g (*gsum) and of w (*wsum). */
static inline void uha_mask_where_zero(const uint16_t *m, const uint16_t *w, uint16_t *g,
                                       uint32_t *gsum, uint32_t *wsum)
{
#if defined(__SSE2__)
    const __m128i zero = _mm_setzero_si128();
    __m128i ga = zero, wa = zero;
    int i;

    for (i = 0; i < 256; i += 8) {
        __m128i mv = _mm_loadu_si128((const __m128i *)(m + i));
        __m128i wv = _mm_loadu_si128((const __m128i *)(w + i));
        __m128i gv = _mm_and_si128(_mm_cmpeq_epi16(mv, zero), wv);
        _mm_storeu_si128((__m128i *)(g + i), gv);
        ga = _mm_add_epi32(ga, _mm_add_epi32(_mm_unpacklo_epi16(gv, zero), _mm_unpackhi_epi16(gv, zero)));
        wa = _mm_add_epi32(wa, _mm_add_epi32(_mm_unpacklo_epi16(wv, zero), _mm_unpackhi_epi16(wv, zero)));
    }
    ga = _mm_add_epi32(ga, _mm_shuffle_epi32(ga, 0x4E));
    ga = _mm_add_epi32(ga, _mm_shuffle_epi32(ga, 0xB1));
    wa = _mm_add_epi32(wa, _mm_shuffle_epi32(wa, 0x4E));
    wa = _mm_add_epi32(wa, _mm_shuffle_epi32(wa, 0xB1));
    *gsum = (uint32_t)_mm_cvtsi128_si32(ga);
    *wsum = (uint32_t)_mm_cvtsi128_si32(wa);
#else
    uint32_t gs = 0, ws = 0;
    int i;

    for (i = 0; i < 256; i++) {
        g[i] = m[i] == 0 ? w[i] : 0;
        gs += g[i];
        ws += w[i];
    }
    *gsum = gs;
    *wsum = ws;
#endif
}

#endif
