#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uha.h"
#include "lzp.h"

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
    int i, j, k;
    uint8_t b, t;

    memcpy(S, uha_init_sbox, 256);
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

int uha_parse_header(const uint8_t *raw, size_t rawlen, uha_header *h)
{
    uint8_t dec[UHA_HDR_LEN];
    uint8_t seed;
    int i;

    if (!raw || !h || rawlen < UHA_HDR_LEN)
        return -2;
    if (raw[0] != 'U' || raw[1] != 'H' || raw[2] != 'A')
        return -1;

    memcpy(dec, raw, UHA_HDR_LEN);
    seed = raw[0x25];
    for (i = 0; i < 31; i++)
        dec[4 + i] = (uint8_t)(raw[4 + i] ^ ((seed + (uint32_t)i * (uint32_t)i) & 0xFF));

    memset(h, 0, sizeof(*h));
    h->version        = raw[3];
    h->family         = dec[9];
    h->order          = dec[10];
    h->flags          = dec[8];
    h->usize          = le32(dec + 13);
    h->psize          = le32(dec + 17);
    h->file_count     = le24(dec + 21);
    h->names_unpacked = le24(dec + 24);
    h->names_packed   = le24(dec + 27);
    h->attrs_packed   = le24(dec + 30);
    h->data_ofs       = UHA_HDR_LEN;
    h->crc_ofs        = h->data_ofs + h->psize;
    h->names_ofs      = h->crc_ofs + (size_t)h->file_count * 4;
    h->attrs_ofs      = h->names_ofs + h->names_packed;
    return 0;
}

const char *uha_codec_name(const uha_header *h)
{
    if (!h)
        return "?";
    if (h->family == 0 || (h->usize == 0 && h->order == 0))
        return "STORE";
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

    if (ofs + pklen > rawlen)
        return -2;
    if (unpacked == 0) {
        *out = NULL;
        return 0;
    }

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
    uint32_t alen;
    int rc, f, p, i, j, ln, ndirs;
    uint32_t prev, v, sz;
    uint32_t base;
    const uint8_t *didx;
    char dirs[256][512];

    if (!out)
        return -2;
    out->items = NULL;
    out->count = 0;

    rc = uha_parse_header(raw, rawlen, &h);
    if (rc != 0)
        return rc;
    if (h.file_count == 0 || h.names_packed == 0)
        return 0;
    if (h.names_ofs + h.names_packed + h.attrs_packed > rawlen)
        return -2;

    rc = decode_meta_block(raw, rawlen, h.names_ofs, h.names_packed,
                           h.names_unpacked, &names);
    if (rc != 0)
        return rc;

    alen = 14 * h.file_count + 16;
    rc = decode_meta_block(raw, rawlen, h.attrs_ofs, h.attrs_packed, alen, &attrs);
    if (rc != 0) {
        free(names);
        return rc;
    }
    if (getenv("UHA_DUMP_META")) {
        uint32_t q;
        fprintf(stderr, "[attrs fc=%u alen=%u]\n", h.file_count, alen);
        for (q = 0; q < alen; q++)
            fprintf(stderr, "%02x%s", attrs[q], (q % 16 == 15) ? "\n" : " ");
        fprintf(stderr, "\n[names upk=%u]\n", h.names_unpacked);
        for (q = 0; q < h.names_unpacked; q++)
            fprintf(stderr, "%02x%s", names[q], (q % 16 == 15) ? "\n" : " ");
        fprintf(stderr, "\n");
    }

    out->items = calloc(h.file_count, sizeof(uha_entry));
    if (!out->items) {
        free(names);
        free(attrs);
        return -4;
    }
    out->count = (int)h.file_count;

    didx = attrs + 4 * h.file_count;
    ndirs = 0;
    for (f = 0; f < (int)h.file_count; f++) {
        int d = didx[f];
        if (d + 1 > ndirs)
            ndirs = d + 1;
    }
    if (ndirs > 256)
        ndirs = 256;

    p = 0;
    for (i = 0; i < ndirs; i++) {
        ln = 0;
        j = 0;
        if (p < (int)h.names_unpacked)
            ln = names[p++];
        for (; j < ln && p < (int)h.names_unpacked && j < 511; j++) {
            char c = (char)names[p++];
            if (c == '\\')
                c = '/';
            dirs[i][j] = c;
        }
        dirs[i][j] = 0;
    }

    for (f = 0; f < (int)h.file_count; f++) {
        char nm[512];
        char full[1024];
        int nmlen = 0;
        int d;

        nm[0] = 0;
        if (p < (int)h.names_unpacked) {
            ln = names[p++];
            for (i = 0; i < ln && p < (int)h.names_unpacked && nmlen < 511; i++) {
                char c = (char)names[p++];
                if (c == '\\')
                    c = '/';
                nm[nmlen++] = c;
            }
            nm[nmlen] = 0;
        }
        d = didx[f];
        if (d >= 0 && d < ndirs && dirs[d][0])
            snprintf(full, sizeof(full), "%s%s", dirs[d], nm);
        else
            snprintf(full, sizeof(full), "%s", nm);
        out->items[f].name = strdup(full);
    }

    base = 6 * h.file_count;
    prev = 0;
    for (f = 0; f < (int)h.file_count; f++) {
        v = (uint32_t)attrs[base + f]
          | ((uint32_t)attrs[base + h.file_count + f] << 8)
          | ((uint32_t)attrs[base + 2 * h.file_count + f] << 16)
          | ((uint32_t)attrs[base + 3 * h.file_count + f] << 24);
        sz = (prev - v) & 0xFFFFFFFFu;
        out->items[f].size = sz;
        prev = sz;
    }

    /* [M194 UHA_XLIST] read-only of columns already dechiffrees (attrs/crc) for affichage.
     * ENTIEREMENT under there gate : out gate, no byte n'is lu nor writes -> decodage
     * byte-identical (difftest 88 OK preserve).
     * [M195 CORRECTION Portee sure the rendu of M194] There table of CRC n'is NOT in plaintext sure
     * disque : `encode.c` l.351-354 there construit in plaintext (`uha_crc32(member.data, size)`) then
     * l'writes **brouillee** (`scramble(aux_disk, fc*4)`, same S-box/cameleon that names/attrs).
     * There reading raw of M194 rendait therefore has key of stream, not some CRC : mesurablement false
     * (0/34 members correspondant au crc32 of the contenu, sure the 17 archives legacy AS sure nos
     * clean archives - `OUT/m195_order_data_m194.md` S2). The rendu is fixes here : copier,
     * `descramble()` (involution), to read. The gate remainder read-only. */
    if (getenv("UHA_XLIST") && getenv("UHA_XLIST")[0] == '1') {
        uint32_t fc = h.file_count;
        uint8_t *aux = NULL;
        /* NEGATIF measures (ALL__mx) : no some 4-columns transposees of attrs not cumule
         * towards h.psize ; single there column [6*fc..10*fc) cumule towards usize (table size). therefore
         * the packed-size BY MEMBER n'is NOT stores in has archive solide UHA. psize=0. */
        for (f = 0; f < (int)fc; f++)
            out->items[f].psize = 0;
        if (fc && h.crc_ofs + (size_t)4 * fc <= rawlen)
            aux = malloc((size_t)4 * fc);
        if (aux) {
            memcpy(aux, raw + h.crc_ofs, (size_t)4 * fc);
            descramble(aux, (size_t)4 * fc);
            for (f = 0; f < (int)fc; f++)
                out->items[f].crc = le32(aux + 4 * f);
            free(aux);
        } else {
            for (f = 0; f < (int)fc; f++)
                out->items[f].crc = 0;
        }
    }

    free(names);
    free(attrs);
    return out->count;
}
