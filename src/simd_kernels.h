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

#endif
