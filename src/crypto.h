#ifndef UHA_CRYPTO_H
#define UHA_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#include "uha.h"

#define UHA_FLAG_PW_DATA  0x02u
#define UHA_FLAG_PW_HDR   0x04u

int uha_needs_password(const uha_header *h);
int uha_decrypt(uint8_t *raw, size_t rawlen, const uha_header *h, const char *password);

#endif
