#ifndef UHA_FILTER_H
#define UHA_FILTER_H

#include <stdint.h>
#include <stddef.h>

void uha_restore_filter(uint8_t *buf, uint32_t usize, int ppm_byte_swap);
void uha_restore_multimedia(uint8_t *buf, uint32_t usize);

#endif
