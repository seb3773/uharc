#ifndef UHA_SIMD_H
#define UHA_SIMD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Type de fonction pour le calcul du plus long préfixe commun (LCP).
 * Calcule le nombre d'octets consécutifs identiques entre s1 et s2 (jusqu'à max_len).
 */
typedef size_t (*uha_lcp_fn)(const uint8_t *s1, const uint8_t *s2, size_t max_len);

extern uha_lcp_fn g_uha_lcp;

void uha_simd_init(void);

static inline size_t uha_lcp(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && (defined(__GNUC__) || defined(__clang__))
    /*
     * Inline fast path: most comparisons in the match finders end within the
     * first 8 bytes. Compare one 64-bit word here and only call the
     * dispatched SIMD routine when it matches entirely. Reads stay within
     * [0, max_len) exactly like the out-of-line implementations.
     */
    if (max_len >= 8u) {
        uint64_t a, b, x;
        memcpy(&a, s1, 8);
        memcpy(&b, s2, 8);
        x = a ^ b;
        if (x)
            return (size_t)(__builtin_ctzll(x) >> 3);
        if (!g_uha_lcp)
            uha_simd_init();
        return 8u + g_uha_lcp(s1 + 8, s2 + 8, max_len - 8u);
    }
#endif
    if (!g_uha_lcp)
        uha_simd_init();
    return g_uha_lcp(s1, s2, max_len);
}

#endif /* UHA_SIMD_H */

