#ifndef UHA_CRC32_H
#define UHA_CRC32_H

#include <stdint.h>
#include <stddef.h>

uint32_t uha_crc32(const uint8_t *buf, size_t len);

/* UHARC 0.6b native CRC-32 (reflected, poly 0xEDB88320, init 0xFFFFFFFF,
 * output XOR 0x46BE298E). Used for the per-member CRC field in the archive. */
uint32_t uha_crc32_uharc(const uint8_t *buf, size_t len);

#endif
