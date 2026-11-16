#ifndef UHA_SIMD_H
#define UHA_SIMD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Type de fonction pour le calcul du plus long préfixe commun (LCP).
 * Calcule le nombre d'octets consécutifs identiques entre s1 et s2 (jusqu'à max_len).
 */
typedef size_t (*uha_lcp_fn)(const uint8_t *s1, const uint8_t *s2, size_t max_len);

extern uha_lcp_fn g_uha_lcp;

void uha_simd_init(void);

static inline size_t uha_lcp(const uint8_t *s1, const uint8_t *s2, size_t max_len)
{
    if (!g_uha_lcp)
        uha_simd_init();
    return g_uha_lcp(s1, s2, max_len);
}

#endif /* UHA_SIMD_H */

