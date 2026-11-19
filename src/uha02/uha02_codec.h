#ifndef UHA02_CODEC_H
#define UHA02_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include "uha.h"

int  uha02_parse_header(const uint8_t *raw, size_t rawlen, size_t sfx_ofs, uha_header *h);
int  uha02_read_entries(const uint8_t *raw, size_t rawlen, const uha_header *h, uha_entrylist *out);
int  uha02_decode_stream(uint8_t method, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_len);
void uha02_unfilter(uint8_t *b, size_t len);

#endif /* UHA02_CODEC_H */

