#ifndef UHA_FILTER_H
#define UHA_FILTER_H

#include <stdint.h>
#include <stddef.h>

int  uha_apply_forward_filter(uint8_t *buf, uint32_t usize, int ppm_byte_swap);
int  uha_restore_filter(uint8_t *buf, uint32_t usize, int ppm_byte_swap);
void uha_apply_forward_multimedia(uint8_t *buf, uint32_t usize);
void uha_restore_multimedia(uint8_t *buf, uint32_t usize);

#endif
