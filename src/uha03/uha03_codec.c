#include "uha03_codec.h"
#include "uharc_dec.h"
#include "rle.h"
#include "crc32.h"

#include <stdlib.h>
#include <string.h>

/* ---------- Stream memory helpers ---------- */
typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} uha03_mr;

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
} uha03_mw;

static int uha03_mem_read(void *ctx, unsigned char *buf, unsigned want)
{
    uha03_mr *m = (uha03_mr *)ctx;
    size_t avail = m->len - m->pos;
    size_t n;

    if (avail == 0)
        return 0;
    n = ((size_t)want < avail) ? (size_t)want : avail;
    memcpy(buf, m->buf + m->pos, n);
    m->pos += n;
    return (int)n;
}

static int uha03_mem_write(void *ctx, const unsigned char *buf, unsigned len)
{
    uha03_mw *m = (uha03_mw *)ctx;

    if (m->pos + (size_t)len > m->cap)
        return 1;
    memcpy(m->buf + m->pos, buf, len);
    m->pos += (size_t)len;
    return 0;
}

int uha03_decode_stream(uint8_t method, uint8_t flags_filt,
                        const uint8_t *in, size_t in_len,
                        const uint32_t *ends, int nfiles,
                        uint8_t *out, size_t out_len)
{
    uha03_mr mr;
    uha03_mw mw;
    unsigned long *cum = NULL;
    unsigned long ncum = 0;
    void *ctx = NULL;
    int rc = -3;
    int i;

    if (!out && out_len > 0)
        return -2;
    if (out_len == 0)
        return 0;
    if (!in)
        return -2;

    if (method == 0 || method == 80) {
        if (in_len < out_len)
            return -2;
        memcpy(out, in, out_len);
        return 0;
    }

    if (method == 1)
        return uha_rle_decode(in, in_len, out, out_len);

    if (ends && nfiles > 0) {
        cum = (unsigned long *)malloc((size_t)nfiles * sizeof(unsigned long));
        if (!cum)
            return -4;
        for (i = 0; i < nfiles; i++)
            cum[i] = (unsigned long)ends[i];
        ncum = (unsigned long)nfiles;
    }

    mr.buf = in;
    mr.len = in_len;
    mr.pos = 0;
    mw.buf = out;
    mw.cap = out_len;
    mw.pos = 0;

    if (method >= 2 && method <= 7) {
        rc = uharc_dec2l_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec2l_decode(ctx, uha03_mem_read, &mr,
                                    uha03_mem_write, &mw,
                                    (unsigned long)out_len);
            uharc_dec2l_free(ctx);
        }
    } else if (method >= 8 && method <= 21) {
        rc = uharc_dec3u_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec3u_decode_b(ctx, cum, ncum,
                                      uha03_mem_read, &mr,
                                      uha03_mem_write, &mw,
                                      (unsigned long)out_len);
            uharc_dec3u_free(ctx);
        }
    } else if (method >= 22 && method <= 35) {
        rc = uharc_dec4uc_init(&ctx, (int)method);
        if (rc == 0) {
            uharc_dec4uc_set_flags2(ctx, (unsigned char)flags_filt);
            rc = uharc_dec4uc_decode_b(ctx, cum, ncum,
                                       uha03_mem_read, &mr,
                                       uha03_mem_write, &mw,
                                       (unsigned long)out_len);
            uharc_dec4uc_free(ctx);
        }
    } else if (method >= 36 && method <= 79) {
        rc = uharc_dec5u_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec5u_decode(ctx,
                                    uha03_mem_read, &mr,
                                    uha03_mem_write, &mw,
                                    (unsigned long)out_len);
            uharc_dec5u_free(ctx);
        }
    } else {
        free(cum);
        return -3;
    }

    free(cum);

    if (rc != 0)
        return (rc == 2) ? -4 : -1;
    if (mw.pos != out_len)
        return -1;
    return 0;
}

int uha03_parse_header(const uint8_t *raw, size_t rawlen, size_t sfx_ofs, uha_header *h)
{
    const uint8_t *hdr;
    uint8_t dec[44];
    uint8_t seed;
    uint16_t check16, expected_crc;
    uint64_t crc_ofs64, names_ofs64, attrs_ofs64, attrs2_ofs64, end64;
    int i;

    if (!raw || !h || rawlen < sfx_ofs + 44)
        return -2;

    hdr = raw + sfx_ofs;
    if (hdr[0] != 'U' || hdr[1] != 'H' || hdr[2] != 'A' || hdr[3] != 3)
        return -1;

    memcpy(dec, hdr, 44);
    seed = hdr[42];
    for (i = 0; i < 36; i++)
        dec[4 + i] ^= (uint8_t)((seed + (uint32_t)i * (uint32_t)i) & 0xFF);

    expected_crc = (uint16_t)hdr[42] | ((uint16_t)hdr[43] << 8);
    check16 = (uint16_t)(uha_crc32(dec + 4, 36) & 0xFFFFu);
    if (check16 != expected_crc)
        return -2;

    memset(h, 0, sizeof(*h));
    h->version        = 3;
    h->flags          = dec[8];
    h->family         = dec[9];
    h->order          = dec[10];
    h->ndirs          = (uint16_t)dec[11] | ((uint16_t)dec[12] << 8);
    h->usize          = (uint32_t)dec[13] | ((uint32_t)dec[14] << 8) |
                        ((uint32_t)dec[15] << 16) | ((uint32_t)dec[16] << 24);
    h->psize          = (uint32_t)dec[17] | ((uint32_t)dec[18] << 8) |
                        ((uint32_t)dec[19] << 16) | ((uint32_t)dec[20] << 24);
    h->file_count     = (uint32_t)dec[21] | ((uint32_t)dec[22] << 8) |
                        ((uint32_t)dec[23] << 16);
    h->names_unpacked = (uint32_t)dec[24] | ((uint32_t)dec[25] << 8) |
                        ((uint32_t)dec[26] << 16);
    h->names_packed   = (uint32_t)dec[27] | ((uint32_t)dec[28] << 8) |
                        ((uint32_t)dec[29] << 16);
    h->attrs_packed   = (uint32_t)dec[30] | ((uint32_t)dec[31] << 8) |
                        ((uint32_t)dec[32] << 16);
    h->attrs2_packed  = (uint32_t)dec[33] | ((uint32_t)dec[34] << 8) |
                        ((uint32_t)dec[35] << 16);
    h->w33            = (uint16_t)dec[36] | ((uint16_t)dec[37] << 8);
    h->w35            = (uint16_t)dec[38] | ((uint16_t)dec[39] << 8);
    h->w40            = (uint16_t)dec[40] | ((uint16_t)dec[41] << 8);
    h->check16        = expected_crc;

    crc_ofs64    = (uint64_t)sfx_ofs + 44ULL + (uint64_t)h->psize;
    names_ofs64  = crc_ofs64 + (uint64_t)h->file_count * 4ULL;
    attrs_ofs64  = names_ofs64 + (uint64_t)h->names_packed;
    attrs2_ofs64 = attrs_ofs64 + (uint64_t)h->attrs_packed;
    end64        = attrs2_ofs64 + (uint64_t)h->attrs2_packed;
    if (end64 > (uint64_t)rawlen)
        return -2;

    h->header_ofs = sfx_ofs;
    h->data_ofs   = sfx_ofs + 44;
    h->crc_ofs    = (size_t)crc_ofs64;
    h->names_ofs  = (size_t)names_ofs64;
    h->attrs_ofs  = (size_t)attrs_ofs64;
    h->attrs2_ofs = (size_t)attrs2_ofs64;
    return 0;
}

int uha03_read_entries(const uint8_t *raw, size_t rawlen, const uha_header *h, uha_entrylist *out)
{
    uint8_t *tab0 = NULL, *tab1 = NULL, *tab2 = NULL, *tab3 = NULL;
    uint8_t *cmp = NULL;
    char **dirs = NULL;
    char *dir_pool = NULL;
    uint32_t fc, ndirs, f, i, p;
    uint32_t crc_calc;
    int rc;

    if (!raw || !h || !out)
        return -2;
    out->items = NULL;
    out->count = 0;

    if (h->file_count == 0)
        return 0;
    if (h->file_count > 1000000u)
        return -2;

    if ((uint64_t)h->attrs2_ofs + h->attrs2_packed > rawlen)
        return -2;

    fc = h->file_count;
    ndirs = h->ndirs;

    tab0 = malloc(4u * fc);
    tab1 = malloc(h->names_unpacked ? h->names_unpacked : 1u);
    tab2 = malloc(4u * fc);
    tab3 = malloc(7u * fc);
    if (!tab0 || !tab1 || !tab2 || !tab3) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -4;
    }

    /* Tab 0: file CRCs (STORE) */
    memcpy(tab0, raw + h->crc_ofs, 4u * fc);
    uha_descramble(tab0, 4u * fc);

    /* Tab 1: names (method 17) */
    cmp = malloc(h->names_packed ? h->names_packed : 1u);
    if (!cmp) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -4;
    }
    memcpy(cmp, raw + h->names_ofs, h->names_packed);
    uha_descramble(cmp, h->names_packed);
    rc = uha03_decode_stream(17, 0, cmp, h->names_packed, NULL, 0, tab1, h->names_unpacked);
    free(cmp);
    if (rc != 0) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return rc;
    }
    /* crc1 is cumulative over tab0 + tab1 */
    crc_calc = uha_crc32_update(0xFFFFFFFFu, tab0, 4u * fc);
    crc_calc = uha_crc32_update(crc_calc, tab1, h->names_unpacked);
    if ((uint16_t)((~crc_calc) & 0xFFFFu) != h->w33) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -2;
    }

    /* Tab 2: dates and times (method 2) */
    cmp = malloc(h->attrs_packed ? h->attrs_packed : 1u);
    if (!cmp) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -4;
    }
    memcpy(cmp, raw + h->attrs_ofs, h->attrs_packed);
    uha_descramble(cmp, h->attrs_packed);
    rc = uha03_decode_stream(2, 0, cmp, h->attrs_packed, NULL, 0, tab2, 4u * fc);
    free(cmp);
    if (rc != 0) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return rc;
    }
    crc_calc = uha_crc32_update(0xFFFFFFFFu, tab2, 4u * fc);
    if ((uint16_t)((~crc_calc) & 0xFFFFu) != h->w35) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -2;
    }

    /* Tab 3: dir indices, sizes, methods (method 7) */
    cmp = malloc(h->attrs2_packed ? h->attrs2_packed : 1u);
    if (!cmp) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -4;
    }
    memcpy(cmp, raw + h->attrs2_ofs, h->attrs2_packed);
    uha_descramble(cmp, h->attrs2_packed);
    rc = uha03_decode_stream(7, 0, cmp, h->attrs2_packed, NULL, 0, tab3, 7u * fc);
    free(cmp);
    if (rc != 0) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return rc;
    }
    crc_calc = uha_crc32_update(0xFFFFFFFFu, tab3, 7u * fc);
    if ((uint16_t)((~crc_calc) & 0xFFFFu) != h->w40) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -2;
    }

    /* Rebuild entries */
    dirs = malloc((size_t)(ndirs ? ndirs : 1u) * sizeof(char *));
    dir_pool = malloc((size_t)h->names_unpacked + ndirs + 1u);
    out->items = calloc(fc, sizeof(uha_entry));
    if (!dirs || !dir_pool || !out->items) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        free(dirs); free(dir_pool);
        uha_entrylist_free(out);
        return -4;
    }
    out->count = (int)fc;

    p = 0;
    {
        size_t pool_ofs = 0;
        for (i = 0; i < ndirs; i++) {
            uint32_t ln, j;
            dirs[i] = dir_pool + pool_ofs;
            if (p >= h->names_unpacked) goto parse_err;
            ln = tab1[p++];
            if (p + ln > h->names_unpacked) goto parse_err;
            for (j = 0; j < ln; j++) {
                char c = (char)tab1[p++];
                if (c == '\\') c = '/';
                dir_pool[pool_ofs++] = c;
            }
            dir_pool[pool_ofs++] = '\0';
        }
    }

    /* Compute actual member sizes from delta differences in tab3 */
    {
        uint32_t prev_sz = 0;
        for (f = 0; f < fc; f++) {
            uint32_t var = (uint32_t)tab3[2u * fc + f] |
                           ((uint32_t)tab3[3u * fc + f] << 8) |
                           ((uint32_t)tab3[4u * fc + f] << 16) |
                           ((uint32_t)tab3[5u * fc + f] << 24);
            uint32_t sz;
            if (f == 0) sz = 0U - var;
            else sz = prev_sz - var;
            out->items[f].size = sz;
            prev_sz = sz;
        }
    }

    for (f = 0; f < fc; f++) {
        uint32_t ln, j, d;
        size_t dlen;
        char *full;
        char name_buf[256];

        if (p >= h->names_unpacked) goto parse_err;
        ln = tab1[p++];
        if (p + ln > h->names_unpacked) goto parse_err;
        if (ln >= sizeof(name_buf)) ln = sizeof(name_buf) - 1;
        for (j = 0; j < ln; j++) {
            char c = (char)tab1[p++];
            if (c == '\\') c = '/';
            name_buf[j] = c;
        }
        name_buf[ln] = '\0';

        d = (uint32_t)tab3[f] | ((uint32_t)tab3[fc + f] << 8);
        if (ndirs > 0 && d < ndirs && dirs[d][0] != '\0') {
            dlen = strlen(dirs[d]);
            while (dlen > 0 && dirs[d][dlen - 1] == '/') dlen--;
            full = malloc(dlen + 1 + ln + 1);
            if (!full) goto mem_err;
            memcpy(full, dirs[d], dlen);
            full[dlen] = '/';
            memcpy(full + dlen + 1, name_buf, ln + 1);
        } else {
            full = malloc(ln + 1);
            if (!full) goto mem_err;
            memcpy(full, name_buf, ln + 1);
        }

        out->items[f].name = full;
        out->items[f].dos_date = (uint16_t)tab2[2u * f] | ((uint16_t)tab2[2u * f + 1] << 8);
        out->items[f].dos_time = (uint16_t)tab2[2u * fc + 2u * f] | ((uint16_t)tab2[2u * fc + 2u * f + 1] << 8);
        out->items[f].crc = (uint32_t)tab0[4u * f] |
                            ((uint32_t)tab0[4u * f + 1] << 8) |
                            ((uint32_t)tab0[4u * f + 2] << 16) |
                            ((uint32_t)tab0[4u * f + 3] << 24);
        out->items[f].has_crc = 1;
        out->items[f].dos_attr = 0x20;
    }

    free(tab0); free(tab1); free(tab2); free(tab3);
    free(dirs); free(dir_pool);
    return 0;

parse_err:
    free(tab0); free(tab1); free(tab2); free(tab3);
    free(dirs); free(dir_pool);
    uha_entrylist_free(out);
    return -2;

mem_err:
    free(tab0); free(tab1); free(tab2); free(tab3);
    free(dirs); free(dir_pool);
    uha_entrylist_free(out);
    return -4;
}

