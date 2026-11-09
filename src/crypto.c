#include "crypto.h"

#include <string.h>

#include "crc32.h"

#define UHA_DEFAULT_PASSWORD "UHARC Default Password"

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void derive_table(uint8_t T[256], const char *pw)
{
    size_t n;
    size_t i;
    int k;
    int ebx;
    uint32_t c;

    memset(T, 0, 256);
    if (!pw)
        return;
    n = strlen(pw);
    if (n == 0)
        return;
    T[0] = (uint8_t)(n & 0xFFu);
    for (i = 0; i < 255; i++)
        T[i + 1] = (uint8_t)pw[i % n];

    ebx = 0;
    for (k = 0; k < 32; k++) {
        c = uha_crc32(T, 256) ^ 0xFFFFFFFFu;
        store_le32(T + ebx, load_le32(T + ebx) ^ c);
        store_le32(T + ebx + 4, load_le32(T + ebx + 4) ^ ~c);
        ebx += 8;
    }
}

static void stream_xor(uint8_t *buf, size_t n, const uint8_t T0[256])
{
    uint8_t S[256];
    int i, j, k;
    uint8_t b, t;

    if (!buf || n == 0)
        return;
    memcpy(S, T0, 256);
    i = 0;
    j = (0 - 2) & 0xFF;
    for (k = 0; k < (int)n; k++) {
        j = (j + 1) & 0xFF;
        i = (i + 1) & 0xFF;
        b = S[i];
        t = (uint8_t)(S[(i - 1) & 0xFF] + b);
        S[i] = t;
        buf[k] ^= t;
        S[j] = (uint8_t)(S[j] - b);
    }
}

int uha_needs_password(const uha_header *h)
{
    return h && (h->flags & (UHA_FLAG_PW_DATA | UHA_FLAG_PW_HDR)) != 0;
}

int uha_decrypt(uint8_t *raw, size_t rawlen, const uha_header *h, const char *password)
{
    uint8_t user[256];
    uint8_t def[256];
    size_t crc_len;
    size_t end;

    if (!raw || !h)
        return -2;
    if (!uha_needs_password(h))
        return 0;
    if (!password || !password[0])
        return -5;

    crc_len = (size_t)h->file_count * 4;
    end = h->attrs_ofs + h->attrs_packed;
    if (end > rawlen)
        return -2;

    derive_table(user, password);

    if ((h->flags & UHA_FLAG_PW_DATA) && h->psize > 0) {
        if (h->data_ofs + h->psize > rawlen)
            return -2;
        stream_xor(raw + h->data_ofs, h->psize, user);
    }

    if (h->flags & UHA_FLAG_PW_HDR) {
        derive_table(def, UHA_DEFAULT_PASSWORD);
        if (crc_len > 0) {
            stream_xor(raw + h->crc_ofs, crc_len, user);
            stream_xor(raw + h->crc_ofs, crc_len, def);
        }
        if (h->names_packed > 0) {
            stream_xor(raw + h->names_ofs, h->names_packed, user);
            stream_xor(raw + h->names_ofs, h->names_packed, def);
        }
        if (h->attrs_packed > 0) {
            stream_xor(raw + h->attrs_ofs, h->attrs_packed, user);
            stream_xor(raw + h->attrs_ofs, h->attrs_packed, def);
        }
    }
    return 0;
}
