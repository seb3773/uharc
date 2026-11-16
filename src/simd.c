#include "simd.h"
#include <string.h>

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#define UHA_UNUSED __attribute__((unused))
#else
#define UHA_UNUSED
#endif

/* Implémentation scalaire portable C99 (fallback universel) */
UHA_UNUSED static size_t uha_lcp_scalar(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
    size_t n = 0;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && (defined(__GNUC__) || defined(__clang__))
    while (n + 8u <= max_len) {
        uint64_t a, b, diff;
        memcpy(&a, s1 + n, 8);
        memcpy(&b, s2 + n, 8);
        diff = a ^ b;
        if (diff)
            return n + (size_t)(__builtin_ctzll(diff) >> 3);
        n += 8u;
    }
#endif
    while (n < max_len && s1[n] == s2[n])
        n++;
    return n;
}

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))

__attribute__((target("sse2")))
static size_t uha_lcp_sse2(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
    size_t n = 0;
    while (n + 16u <= max_len) {
        __m128i v1 = _mm_loadu_si128((const __m128i*)(const void*)(s1 + n));
        __m128i v2 = _mm_loadu_si128((const __m128i*)(const void*)(s2 + n));
        __m128i cmp = _mm_cmpeq_epi8(v1, v2);
        uint32_t mask = (uint32_t)_mm_movemask_epi8(cmp);
        if (mask != 0xFFFFu)
            return n + (size_t)__builtin_ctz(~mask & 0xFFFFu);
        n += 16u;
    }
    while (n + 8u <= max_len) {
        uint64_t a, b, diff;
        memcpy(&a, s1 + n, 8);
        memcpy(&b, s2 + n, 8);
        diff = a ^ b;
        if (diff)
            return n + (size_t)(__builtin_ctzll(diff) >> 3);
        n += 8u;
    }
    while (n < max_len && s1[n] == s2[n])
        n++;
    return n;
}

__attribute__((target("avx2")))
static size_t uha_lcp_avx2(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
    size_t n = 0;
    while (n + 32u <= max_len) {
        __m256i v1 = _mm256_loadu_si256((const __m256i*)(const void*)(s1 + n));
        __m256i v2 = _mm256_loadu_si256((const __m256i*)(const void*)(s2 + n));
        __m256i cmp = _mm256_cmpeq_epi8(v1, v2);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
        if (mask != 0xFFFFFFFFu)
            return n + (size_t)__builtin_ctz(~mask);
        n += 32u;
    }
    while (n + 8u <= max_len) {
        uint64_t a, b, diff;
        memcpy(&a, s1 + n, 8);
        memcpy(&b, s2 + n, 8);
        diff = a ^ b;
        if (diff)
            return n + (size_t)(__builtin_ctzll(diff) >> 3);
        n += 8u;
    }
    while (n < max_len && s1[n] == s2[n])
        n++;
    return n;
}

#if defined(__GNUC__) && __GNUC__ >= 7
__attribute__((target("avx512f,avx512bw")))
static size_t uha_lcp_avx512(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
    size_t n = 0;
    while (n + 64u <= max_len) {
        __m512i v1 = _mm512_loadu_si512((const void*)(s1 + n));
        __m512i v2 = _mm512_loadu_si512((const void*)(s2 + n));
        uint64_t mask = _mm512_cmpeq_epi8_mask(v1, v2);
        if (mask != ~0ULL)
            return n + (size_t)__builtin_ctzll(~mask);
        n += 64u;
    }
    while (n + 32u <= max_len) {
        __m256i v1 = _mm256_loadu_si256((const __m256i*)(const void*)(s1 + n));
        __m256i v2 = _mm256_loadu_si256((const __m256i*)(const void*)(s2 + n));
        __m256i cmp = _mm256_cmpeq_epi8(v1, v2);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
        if (mask != 0xFFFFFFFFu)
            return n + (size_t)__builtin_ctz(~mask);
        n += 32u;
    }
    while (n + 8u <= max_len) {
        uint64_t a, b, diff;
        memcpy(&a, s1 + n, 8);
        memcpy(&b, s2 + n, 8);
        diff = a ^ b;
        if (diff)
            return n + (size_t)(__builtin_ctzll(diff) >> 3);
        n += 8u;
    }
    while (n < max_len && s1[n] == s2[n])
        n++;
    return n;
}
#endif

#endif

uha_lcp_fn g_uha_lcp = NULL;

void uha_simd_init(void)
{
    if (g_uha_lcp)
        return;

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#if defined(__GNUC__) && __GNUC__ >= 7
    if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw")) {
        g_uha_lcp = uha_lcp_avx512;
        return;
    }
#endif
    if (__builtin_cpu_supports("avx2")) {
        g_uha_lcp = uha_lcp_avx2;
        return;
    }
    g_uha_lcp = uha_lcp_sse2;
#else
    g_uha_lcp = uha_lcp_scalar;
#endif
}
