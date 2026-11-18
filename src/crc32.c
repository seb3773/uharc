#include "crc32.h"
#include <string.h>

/*
 * Slicing-by-16 CRC-32 tables using standard reflected IEEE 802.3 polynomial (0xEDB88320u).
 * 16 tables of 256 uint32_t (16 KB in .bss, generated once on first use instead of .rodata).
 * Processes 16 bytes per iteration, yielding 4-6x speedup over single-byte lookup.
 */
static uint32_t s_crc32_tables[16][256];
static int s_crc32_ready = 0;

static void crc32_init_tables(void)
{
    uint32_t i, t;
    for (i = 0; i < 256u; i++) {
        uint32_t c = i;
        int b;
        for (b = 0; b < 8; b++)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc32_tables[0][i] = c;
    }
    for (t = 1; t < 16u; t++) {
        for (i = 0; i < 256u; i++) {
            uint32_t prev = s_crc32_tables[t - 1][i];
            s_crc32_tables[t][i] = (prev >> 8) ^ s_crc32_tables[0][prev & 0xFFu];
        }
    }
    s_crc32_ready = 1;
}

static inline uint32_t crc32_core_init(uint32_t c, const uint8_t *buf, size_t len)
{
    if (!buf || len == 0)
        return c;
    if (!s_crc32_ready)
        crc32_init_tables();

    while (len >= 16) {
        uint32_t w0, w1, w2, w3;
        memcpy(&w0, buf, 4);
        memcpy(&w1, buf + 4, 4);
        memcpy(&w2, buf + 8, 4);
        memcpy(&w3, buf + 12, 4);
        w0 ^= c;
        c = s_crc32_tables[15][w0 & 0xFFu]
          ^ s_crc32_tables[14][(w0 >> 8) & 0xFFu]
          ^ s_crc32_tables[13][(w0 >> 16) & 0xFFu]
          ^ s_crc32_tables[12][(w0 >> 24) & 0xFFu]
          ^ s_crc32_tables[11][w1 & 0xFFu]
          ^ s_crc32_tables[10][(w1 >> 8) & 0xFFu]
          ^ s_crc32_tables[9][(w1 >> 16) & 0xFFu]
          ^ s_crc32_tables[8][(w1 >> 24) & 0xFFu]
          ^ s_crc32_tables[7][w2 & 0xFFu]
          ^ s_crc32_tables[6][(w2 >> 8) & 0xFFu]
          ^ s_crc32_tables[5][(w2 >> 16) & 0xFFu]
          ^ s_crc32_tables[4][(w2 >> 24) & 0xFFu]
          ^ s_crc32_tables[3][w3 & 0xFFu]
          ^ s_crc32_tables[2][(w3 >> 8) & 0xFFu]
          ^ s_crc32_tables[1][(w3 >> 16) & 0xFFu]
          ^ s_crc32_tables[0][(w3 >> 24) & 0xFFu];
        buf += 16;
        len -= 16;
    }
    while (len > 0) {
        c = (c >> 8) ^ s_crc32_tables[0][(c ^ *buf) & 0xFFu];
        buf++;
        len--;
    }
    return c;
}

uint32_t uha_crc32_update(uint32_t state, const uint8_t *buf, size_t len)
{
    return crc32_core_init(state, buf, len);
}

uint32_t uha_crc32(const uint8_t *buf, size_t len)
{
    return crc32_core_init(0xFFFFFFFFu, buf, len) ^ 0xFFFFFFFFu;
}

/*
 * UHARC's own CRC-32: reflected, polynomial 0xEDB88320, init 0xFFFFFFFF,
 * but with output XOR 0x46BE298E (NOT the IEEE 0xFFFFFFFF). Cracked against
 * the per-member CRC field of real UHARC 0.6b archives (12/12 corpus match).
 */
uint32_t uha_crc32_uharc(const uint8_t *buf, size_t len)
{
    return crc32_core_init(0xFFFFFFFFu, buf, len) ^ 0x46BE298Eu;
}
