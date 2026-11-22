#ifndef UHA03_CODEC_H
#define UHA03_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "uha.h"

/*
 * Decode one UHARC 0.3 compressed stream (methods 0..80) from `in` into `out`.
 * `ends` (if non-NULL and nfiles > 0) holds cumulative member end offsets for
 * solid model restarts. `flags_filt` is header byte +9 (needed by filters).
 * Returns 0 on success, negative error code on failure.
 */
int uha03_decode_stream(uint8_t method, uint8_t flags_filt,
                        const uint8_t *in, size_t in_len,
                        const uint32_t *ends, int nfiles,
                        uint8_t *out, size_t out_len);

int uha03_parse_header(const uint8_t *raw, size_t rawlen, size_t sfx_ofs, uha_header *h);
int uha03_read_entries(const uint8_t *raw, size_t rawlen, const uha_header *h, uha_entrylist *out);

#endif /* UHA03_CODEC_H */

