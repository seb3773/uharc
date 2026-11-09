#ifndef UHA_SELCLK_H
#define UHA_SELCLK_H
#include <stdint.h>

/* Pompe FAITHFUL of the classifieur 0x420C20..0x42114A (lane #4, static) : SELCLK = delta(...) = Sigma(W-1)
 * sure the stream CONCATENE en order stores, with armement = Sigma sizes(P) and charniere = [0x4826C8] = -1.
 * Transcription byte-exact of re_asm/OUT/m343_pompe_walk.py + sa correction m346_pompe_fidele.py
 * (_record_walk_fidele indexee by byte, via _mt_byte). Verified by #1 : delta(ALL,45337)=7216,
 * delta(random,0)=0. tables lues of l'image via selclk_data.h (constante d'image, no corpus).
 * no effect out gate (appelee only under UHA_FRONTIER for to compute SELCLK). */

uint32_t uha_selclk_delta(const uint8_t *flux, uint32_t len, uint32_t armement);

/* Override gated-ON : there value calculee replaces there reading env UHA_PPM_SELCLK of selclk_shift().
 * default OFF (active=0) => selclk_shift() = behavior herite (env now 0). No input out gate. */
void     uha_selclk_set(uint32_t v);
int      uha_selclk_active(void);
uint32_t uha_selclk_get(void);

#endif
