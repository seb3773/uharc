#ifndef UHA_ALZ_H
#define UHA_ALZ_H

#include <stdint.h>
#include <stddef.h>

int uha_alz_decode(const uint8_t *src, size_t srclen,
                   int order, uint32_t usize,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t *out, size_t outlen);

typedef struct {
    uint32_t *hashtab;
    uint32_t *chain;
    uint32_t  chain_size;
    uint8_t  *window;
    size_t    dict_size;
    size_t    max_outlen;
    int       initialized;
} uha_alz_ws;

int uha_alz_encode_ws(const uint8_t *plain, uint32_t usize,
                      int order,
                      const uint32_t *member_ends, int nmembers,
                      int escape_sel, int min_len, int tok2_min, int lazy,
                      uint8_t **out, size_t *outlen,
                      uha_alz_ws *ws);

int uha_alz_encode(const uint8_t *plain, uint32_t usize,
                   int order,
                   const uint32_t *member_ends, int nmembers,
                   int escape_sel, int min_len, int tok2_min, int lazy,
                   uint8_t **out, size_t *outlen);

#endif
