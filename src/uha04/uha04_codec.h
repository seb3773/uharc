#ifndef UHA04_CODEC_H
#define UHA04_CODEC_H

#include <stddef.h>
#include <stdint.h>

/*
 * Decode one UHARC 0.4 compressed stream (methods 0..87) from `in` into `out`.
 * `ends` (if non-NULL and nfiles > 0) holds cumulative member end offsets for
 * solid model restarts. `flags_filt` is header byte +9 (needed by PPM 0.4).
 * Returns 0 on success, negative error code on failure.
 */
int uha04_decode_stream(uint8_t method, uint8_t flags_filt,
                        const uint8_t *in, size_t in_len,
                        const uint32_t *ends, int nfiles,
                        uint8_t *out, size_t out_len);

#endif /* UHA04_CODEC_H */

