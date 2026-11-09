#ifndef UHA_PPM_H
#define UHA_PPM_H

#include <stdint.h>
#include <stddef.h>

int uha_ppm_decode(const uint8_t *src, size_t srclen,
                    int order, uint32_t usize,
                    const uint32_t *member_ends, int nmembers,
                    uint8_t *out, size_t outlen);

int uha_ppm_encode(const uint8_t *plain, uint32_t usize,
                    int order, int bc_mode,
                    const uint32_t *member_ends, int nmembers,
                    uint8_t **out, size_t *outlen);

/* [M185, GATED UHA_PPM_E0LAW, default-OFF] Arm there law B side encoder : `mode` 0 = gate OFF
 * (behavior historique, e0_blk_len = usize), otherwise `e0` = end of the prefixe of members bc=0
 * (law B, OUT/m184_e0_lawB_port.md). Pilote (b) l'emission of the field and (c) there promotion
 * mid-stream bc0->bc1. Appele by encode.c::uha_encode_ppm ; reset implicite at each call. */
void uha_ppm_set_e0law(int mode, uint32_t e0);

int uha_ppm_encode_syms(const uint8_t *syms, uint32_t nsyms, uint32_t usize,
                        int order,
                        const uint32_t *member_ends, int nmembers,
                        uint8_t **out, size_t *outlen);

#endif
