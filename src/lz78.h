#ifndef UHA_LZ78_H
#define UHA_LZ78_H

#include <stddef.h>
#include <stdint.h>

#include "uha.h"

/*
 * LZ78 (-mw), UHARC 0.6b. Order header = 2..7 (-md1 .. -md32).
 *
 * Flux solide : un seul dictionnaire pour tout le payload. ends[] / nfiles
 * ne réinitialisent pas le dico (UHARC ne le fait pas). Le conteneur
 * redécoupe les membres après décompression, dans decode.c.
 *
 * *out de uha_lz78_encode est alloué par malloc ; l'appelant libère.
 * Retour 0 si OK, <0 sinon.
 */

#ifndef LZ78_CODE_FC0_USE_REPLAY
#define LZ78_CODE_FC0_USE_REPLAY 0
#endif

/* -md<KiB> (puissance de 2, plafond 32) + taille décompressée -> order 2..7. */
uint8_t uha_lz78_select_order(uint32_t md_kb_cap, size_t usize);

int uha_lz78_encode(const uint8_t *in, size_t in_len, uint8_t order,
                    const uint32_t *ends, int nfiles,
                    uint8_t **out, size_t *out_len);

int uha_lz78_decode(const uint8_t *in, size_t in_len, uint8_t order,
                    uint32_t usize, const uint32_t *ends, int nfiles,
                    uint8_t *out, size_t out_cap);

#endif /* UHA_LZ78_H */
