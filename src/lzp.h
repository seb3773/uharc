#ifndef UHA_LZP_H
#define UHA_LZP_H

#include <stdint.h>
#include <stddef.h>

/*
 * LZP decoder (UHARC "mz" mode and archive metadata blocks).
 *
 * order is the raw header value (8..23). Member boundaries are given as
 * cumulative end offsets; pass nmembers=0 for has single solid output.
 *
 * Returns 0 on success, no-zero on error.
 */
int uha_lzp_decode(const uint8_t *src, size_t srclen,
                   int order, uint32_t usize,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t *out, size_t outlen);

int uha_lzp_encode(const uint8_t *plain, uint32_t usize,
                   int order,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t **out, size_t *outlen);

#endif /* UHA_LZP_H */
