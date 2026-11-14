#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uha.h"
#include "lzp.h"
#include "crc32.h"

static const uint8_t uha_init_sbox[256] = {
    0xc3,0xae,0x65,0x6b,0x78,0x47,0xf2,0x91,0xd6,0x50,0xcb,0x65,0x20,0xbd,0x75,0xbf,
    0x45,0xa1,0xcd,0x6b,0xb4,0x5f,0x25,0xb6,0x39,0xbf,0xff,0x37,0xae,0x45,0x37,0xed,
    0xa5,0xfa,0x5c,0xf3,0x1b,0x20,0xae,0x0b,0xf3,0xe6,0xc6,0x8d,0x1b,0x3b,0x1e,0x41,
    0x65,0x18,0x9a,0xe1,0xad,0xc2,0x24,0x2f,0xa0,0xd4,0x7a,0x2c,0x52,0x2c,0xd6,0xf4,
    0x55,0xa7,0x84,0x6c,0x8d,0x6b,0x4d,0x85,0x32,0x12,0xdc,0x0a,0x8c,0xdc,0x2a,0xe7,
    0xcd,0xbd,0xf9,0x79,0x61,0x65,0x08,0x87,0x5e,0xdc,0x28,0x48,0x97,0x35,0xbf,0xb2,
    0xd6,0xa1,0x4b,0x68,0x20,0x4c,0xf5,0xb2,0x7b,0x5f,0xf7,0x9a,0x8a,0xa1,0x1f,0x47,
    0x84,0xd5,0x64,0x22,0x13,0x2f,0xac,0xf8,0x25,0x0f,0x09,0xc3,0x9b,0xd5,0xfb,0x3b,
    0xd5,0x40,0xdf,0x1e,0x3d,0x9d,0x07,0xd2,0xe9,0x23,0xcc,0xd5,0x21,0xf9,0x72,0x1b,
    0x94,0x34,0x26,0xa3,0x66,0xcc,0x8a,0x7b,0xe6,0xea,0x15,0xa4,0x3e,0x26,0xdc,0x4d,
    0xe0,0xdd,0x06,0x85,0x5e,0x13,0xf0,0x68,0x7b,0x27,0x59,0x10,0xd7,0xff,0xa8,0xee,
    0x0b,0xb1,0xcc,0x2f,0xc2,0x58,0x5b,0xd5,0xa3,0x54,0x6e,0x27,0x55,0xb9,0xd0,0xfd,
    0x3d,0xc5,0xd1,0xb6,0xcc,0x3b,0x39,0x6b,0x75,0x42,0x9f,0xf1,0xe2,0xb8,0x57,0x2b,
    0xf7,0x3f,0xe7,0x72,0x49,0xe5,0x15,0x8a,0x3c,0x33,0x79,0x2a,0xd4,0xee,0xa1,0xe6,
    0xc1,0xf5,0x16,0x69,0x09,0x2f,0xa8,0xa7,0x0c,0x3c,0x62,0x62,0xfe,0xc4,0xce,0xba,
    0xb9,0xfd,0xb9,0xaf,0x61,0x31,0x70,0x46,0x0d,0xfa,0x44,0x08,0xb3,0x34,0xb2,0xe5
};

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le24(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void descramble(uint8_t *buf, size_t n)
{
    uint8_t S[256];
    int i, j;
    size_t k;
    uint8_t b, t;

    memcpy(S, uha_init_sbox, 256);
    i = 0;
    j = (0 - 2) & 0xFF;
    for (k = 0; k < n; k++) {
        j = (j + 1) & 0xFF;
        i = (i + 1) & 0xFF;
        b = S[i];
        t = (uint8_t)(S[(i - 1) & 0xFF] + b);
        S[i] = t;
        buf[k] ^= t;
        S[j] = (uint8_t)(S[j] - b);
    }
}

int uha_parse_header(const uint8_t *raw, size_t rawlen, uha_header *h)
{
    uint8_t dec[UHA_HDR_LEN];
    uint8_t seed;
    uint16_t check16;
    uint64_t crc_ofs64, names_ofs64, attrs_ofs64, end64;
    size_t sfx_ofs = 0;
    const uint8_t *hdr = raw;
    int i;

    if (!raw || !h || rawlen < UHA_HDR_LEN)
        return -2;

    if (raw[0] == 'M' && raw[1] == 'Z') {
        size_t off;
        int found = 0;
        for (off = 0; off + UHA_HDR_LEN <= rawlen; off++) {
            if (raw[off] == 'U' && raw[off + 1] == 'H' && raw[off + 2] == 'A' && raw[off + 3] == 6) {
                uint8_t test_dec[UHA_HDR_LEN];
                uint8_t test_seed = raw[off + 0x25];
                uint16_t test_chk = le16(raw + off + 37);
                int k;
                for (k = 0; k < 31; k++)
                    test_dec[4 + k] = (uint8_t)(raw[off + 4 + k] ^ ((test_seed + (uint32_t)k * (uint32_t)k) & 0xFF));
                if (test_chk == (uint16_t)(uha_crc32(test_dec + 4, 31) & 0xFFFFu)) {
                    sfx_ofs = off;
                    hdr = raw + off;
                    found = 1;
                    break;
                }
            }
        }
        if (!found)
            return -1;
    } else {
        if (raw[0] != 'U' || raw[1] != 'H' || raw[2] != 'A')
            return -1;
        if (raw[3] != 6)
            return -1;
    }

    memcpy(dec, hdr, UHA_HDR_LEN);
    seed = hdr[0x25];
    for (i = 0; i < 31; i++)
        dec[4 + i] = (uint8_t)(hdr[4 + i] ^ ((seed + (uint32_t)i * (uint32_t)i) & 0xFF));

    check16 = le16(hdr + 37);
    if (check16 != (uint16_t)(uha_crc32(dec + 4, 31) & 0xFFFFu))
        return -2;

    memset(h, 0, sizeof(*h));
    h->version        = hdr[3];
    h->family         = dec[9];
    h->order          = dec[10];
    h->flags          = dec[8];
    h->ndirs          = le16(dec + 11);
    h->usize          = le32(dec + 13);
    h->psize          = le32(dec + 17);
    h->file_count     = le24(dec + 21);
    h->names_unpacked = le24(dec + 24);
    h->names_packed   = le24(dec + 27);
    h->attrs_packed   = le24(dec + 30);
    h->w33            = le16(dec + 33);
    h->w35            = le16(dec + 35);
    h->check16        = check16;

    crc_ofs64   = (uint64_t)sfx_ofs + (uint64_t)UHA_HDR_LEN + h->psize;
    names_ofs64 = crc_ofs64 + (uint64_t)h->file_count * 4ULL;
    attrs_ofs64 = names_ofs64 + h->names_packed;
    end64       = attrs_ofs64 + h->attrs_packed;
    if (end64 > (uint64_t)SIZE_MAX)
        return -2;

    h->header_ofs     = sfx_ofs;
    h->data_ofs       = sfx_ofs + UHA_HDR_LEN;
    h->crc_ofs        = (size_t)crc_ofs64;
    h->names_ofs      = (size_t)names_ofs64;
    h->attrs_ofs      = (size_t)attrs_ofs64;
    return 0;
}

const char *uha_codec_name(const uha_header *h)
{
    if (!h)
        return "?";
    if (h->order == UHA_ORDER_STORE)
        return "STORE";
    if (h->order == UHA_ORDER_RLE)
        return "RLE";
    if (h->order >= UHA_ORDER_LZ78_MIN && h->order <= UHA_ORDER_LZ78_MAX)
        return "LZ78";
    if (h->order >= UHA_ORDER_LZP_MIN && h->order <= UHA_ORDER_LZP_MAX)
        return "LZP";
    if (h->order >= UHA_ORDER_PPM_MIN && h->order <= UHA_ORDER_PPM_MAX)
        return "PPM";
    if (h->order >= UHA_ORDER_ALZ_MIN && h->order <= UHA_ORDER_ALZ_MAX)
        return "ALZ";
    return "UNKNOWN";
}

static int decode_meta_block(const uint8_t *raw, size_t rawlen,
                             size_t ofs, uint32_t pklen, uint32_t unpacked,
                             uint8_t **out)
{
    uint8_t *blk;
    uint8_t *plain;
    int rc;

    if ((uint64_t)ofs + pklen > rawlen)
        return -2;
    if (unpacked == 0) {
        *out = NULL;
        return 0;
    }
    if (pklen == 0)
        return -2;

    blk = malloc(pklen);
    plain = malloc(unpacked);
    if (!blk || !plain) {
        free(blk);
        free(plain);
        return -4;
    }
    memcpy(blk, raw + ofs, pklen);
    descramble(blk, pklen);

    rc = uha_lzp_decode(blk, pklen, 0x11, unpacked, NULL, 0, plain, unpacked);
    free(blk);
    if (rc != 0) {
        free(plain);
        return -4;
    }
    *out = plain;
    return 0;
}

void uha_entrylist_free(uha_entrylist *l)
{
    int i;

    if (!l)
        return;
    if (l->items) {
        for (i = 0; i < l->count; i++)
            free(l->items[i].name);
        free(l->items);
    }
    l->items = NULL;
    l->count = 0;
}

int uha_read_entries(const uint8_t *raw, size_t rawlen, uha_entrylist *out)
{
    uha_header h;
    uint8_t *names = NULL;
    uint8_t *attrs = NULL;
    uint8_t *aux = NULL;
    char **dirs = NULL;
    char *dir_pool = NULL;
    uint32_t alen, fc, ndirs, f, i, p;
    uint32_t prev, v, sz;
    uint32_t base, w33_state;
    int rc;

    if (!out)
        return -2;
    out->items = NULL;
    out->count = 0;

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0)
        return rc;
    if ((uint64_t)h.names_ofs + h.names_packed + h.attrs_packed > rawlen)
        return -2;
    if (h.file_count == 0)
        return 0;
    if (h.names_packed == 0 || h.attrs_packed == 0 || h.names_unpacked == 0)
        return -2;

    fc = h.file_count;
    ndirs = h.ndirs;
    if (ndirs == 0 || (uint64_t)ndirs + fc > h.names_unpacked)
        return -2;
    if ((uint64_t)fc * 11ULL > SIZE_MAX)
        return -2;
    if (h.crc_ofs + (uint64_t)fc * 4ULL > rawlen)
        return -2;

    rc = decode_meta_block(raw, rawlen, h.names_ofs, h.names_packed,
                           h.names_unpacked, &names);
    if (rc != 0)
        return rc;

    alen = 11u * fc;
    rc = decode_meta_block(raw, rawlen, h.attrs_ofs, h.attrs_packed, alen, &attrs);
    if (rc != 0) {
        free(names);
        return rc;
    }

    if ((uint16_t)(uha_crc32(attrs, alen) & 0xFFFFu) != h.w35) {
        free(names);
        free(attrs);
        return -2;
    }

    aux = malloc((size_t)fc * 4u);
    if (!aux) {
        free(names);
        free(attrs);
        return -4;
    }
    memcpy(aux, raw + h.crc_ofs, (size_t)fc * 4u);
    descramble(aux, (size_t)fc * 4u);

    w33_state = uha_crc32_update(0xFFFFFFFFu, aux, (size_t)fc * 4u);
    w33_state = uha_crc32_update(w33_state, names, h.names_unpacked);
    if ((uint16_t)((w33_state ^ 0xFFFFFFFFu) & 0xFFFFu) != h.w33) {
        free(aux);
        free(names);
        free(attrs);
        return -2;
    }

    dirs = malloc((size_t)ndirs * sizeof(char *));
    dir_pool = malloc((size_t)h.names_unpacked + ndirs + 1u);
    out->items = calloc(fc, sizeof(uha_entry));
    if (!dirs || !dir_pool || !out->items) {
        free(dirs);
        free(dir_pool);
        free(aux);
        free(names);
        free(attrs);
        uha_entrylist_free(out);
        return -4;
    }
    out->count = (int)fc;

    p = 0;
    {
        size_t pool_ofs = 0;
        for (i = 0; i < ndirs; i++) {
            uint32_t ln = 0, j;
            dirs[i] = dir_pool + pool_ofs;
            if (p >= h.names_unpacked) {
                free(dirs);
                free(dir_pool);
                free(aux);
                free(names);
                free(attrs);
                uha_entrylist_free(out);
                return -2;
            }
            ln = names[p++];
            if (p + ln > h.names_unpacked) {
                free(dirs);
                free(dir_pool);
                free(aux);
                free(names);
                free(attrs);
                uha_entrylist_free(out);
                return -2;
            }
            for (j = 0; j < ln; j++) {
                char c = (char)names[p++];
                if (c == '\\')
                    c = '/';
                dir_pool[pool_ofs++] = c;
            }
            dir_pool[pool_ofs++] = '\0';
        }
    }

    for (f = 0; f < fc; f++) {
        uint32_t ln, j, d;
        size_t dlen;
        char *full;

        if (p >= h.names_unpacked) {
            free(dirs);
            free(dir_pool);
            free(aux);
            free(names);
            free(attrs);
            uha_entrylist_free(out);
            return -2;
        }
        ln = names[p++];
        if (p + ln > h.names_unpacked) {
            free(dirs);
            free(dir_pool);
            free(aux);
            free(names);
            free(attrs);
            uha_entrylist_free(out);
            return -2;
        }
        d = (uint32_t)attrs[4u * fc + f] | ((uint32_t)attrs[5u * fc + f] << 8);
        if (d >= ndirs) {
            free(dirs);
            free(dir_pool);
            free(aux);
            free(names);
            free(attrs);
            uha_entrylist_free(out);
            return -2;
        }
        dlen = strlen(dirs[d]);
        full = malloc(dlen + ln + 1u);
        if (!full) {
            free(dirs);
            free(dir_pool);
            free(aux);
            free(names);
            free(attrs);
            uha_entrylist_free(out);
            return -4;
        }
        if (dlen > 0)
            memcpy(full, dirs[d], dlen);
        for (j = 0; j < ln; j++) {
            char c = (char)names[p++];
            if (c == '\\')
                c = '/';
            full[dlen + j] = c;
        }
        full[dlen + ln] = '\0';
        out->items[f].name = full;
    }

    base = 6u * fc;
    prev = 0;
    for (f = 0; f < fc; f++) {
        v = (uint32_t)attrs[base + f]
          | ((uint32_t)attrs[base + fc + f] << 8)
          | ((uint32_t)attrs[base + 2u * fc + f] << 16)
          | ((uint32_t)attrs[base + 3u * fc + f] << 24);
        sz = (prev - v) & 0xFFFFFFFFu;
        out->items[f].size = sz;
        prev = sz;

        out->items[f].dos_date = le16(attrs + 2u * f);
        out->items[f].dos_time = le16(attrs + 2u * fc + 2u * f);
        out->items[f].dos_attr = attrs[10u * fc + f];
        out->items[f].psize    = 0;
        out->items[f].crc      = le32(aux + 4u * f);
        out->items[f].has_crc  = 1;
    }

    free(dirs);
    free(dir_pool);
    free(aux);
    free(names);
    free(attrs);
    return out->count;
}
