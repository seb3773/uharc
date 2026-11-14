#ifndef UHA_RLE_H
#define UHA_RLE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Pure C99 implementation of UHARC 0.6b RLE codec (-mr, order 0x01).
 * 100% bit-exact with historical UHARC.EXE under Wine.
 */

int uha_rle_encode(const uint8_t *in, size_t in_len,
                   uint8_t **out, size_t *out_len);

int uha_rle_decode(const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_len);

#endif /* UHA_RLE_H */

