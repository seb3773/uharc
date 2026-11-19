#include "uha02_codec.h"
#include "uha04/uharc_dec.h"
#include "rle.h"
#include "crc32.h"

#include <stdlib.h>
#include <string.h>

int uha02_parse_header(const uint8_t *raw, size_t rawlen, size_t sfx_ofs, uha_header *h)
{
    const uint8_t *hdr = raw + sfx_ofs;
    uint8_t dec[UHA_HDR_LEN_V2];
    uint8_t key;
    uint32_t crc;
    uint32_t hdr_crc_expected;
    uint64_t crc_ofs64, names_ofs64, attrs_ofs64, attrs2_ofs64, end64;
    int i;

    if (!raw || !h || rawlen < sfx_ofs + UHA_HDR_LEN_V2)
        return -2;

    memcpy(dec, hdr, UHA_HDR_LEN_V2);
    key = hdr[44];
    for (i = 0; i < 40; i++)
        dec[4 + i] ^= (uint8_t)((key + (uint32_t)i * (uint32_t)i) & 0xFF);

    crc = uha_crc32_update(0xFFFFFFFFu, dec + 4, 40);
    hdr_crc_expected = (uint32_t)hdr[44] | ((uint32_t)hdr[45] << 8) |
                       ((uint32_t)hdr[46] << 16) | ((uint32_t)hdr[47] << 24);
    if ((~crc & 0xFFFFFFFFu) != hdr_crc_expected)
        return -2;

    memset(h, 0, sizeof(*h));
    h->version        = 2;
    h->family         = 0;
    h->order          = dec[9];
    h->flags          = 0;
    h->ndirs          = (uint16_t)((uint16_t)dec[10] | ((uint16_t)dec[11] << 8));
    h->file_count     = (uint32_t)dec[12] | ((uint32_t)dec[13] << 8) |
                        ((uint32_t)dec[14] << 16) | ((uint32_t)dec[15] << 24);
    h->usize          = (uint32_t)dec[16] | ((uint32_t)dec[17] << 8) |
                        ((uint32_t)dec[18] << 16) | ((uint32_t)dec[19] << 24);
    h->psize          = (uint32_t)dec[20] | ((uint32_t)dec[21] << 8) |
                        ((uint32_t)dec[22] << 16) | ((uint32_t)dec[23] << 24);
    h->names_unpacked = (uint32_t)dec[24] | ((uint32_t)dec[25] << 8) |
                        ((uint32_t)dec[26] << 16) | ((uint32_t)dec[27] << 24);
    h->names_packed   = (uint32_t)dec[28] | ((uint32_t)dec[29] << 8) |
                        ((uint32_t)dec[30] << 16) | ((uint32_t)dec[31] << 24);
    h->attrs_packed   = (uint32_t)dec[32] | ((uint32_t)dec[33] << 8) |
                        ((uint32_t)dec[34] << 16) | ((uint32_t)dec[35] << 24);
    h->attrs2_packed  = (uint32_t)dec[36] | ((uint32_t)dec[37] << 8) |
                        ((uint32_t)dec[38] << 16) | ((uint32_t)dec[39] << 24);
    h->contents_crc   = (uint32_t)dec[40] | ((uint32_t)dec[41] << 8) |
                        ((uint32_t)dec[42] << 16) | ((uint32_t)dec[43] << 24);
    h->check16        = (uint16_t)(hdr_crc_expected & 0xFFFFu);

    crc_ofs64    = (uint64_t)sfx_ofs + (uint64_t)UHA_HDR_LEN_V2 + h->psize;
    names_ofs64  = crc_ofs64 + (uint64_t)h->file_count * 4ULL;
    attrs_ofs64  = names_ofs64 + h->names_packed;
    attrs2_ofs64 = attrs_ofs64 + h->attrs_packed;
    end64        = attrs2_ofs64 + h->attrs2_packed;
    if (end64 > (uint64_t)rawlen)
        return -2;

    h->header_ofs = sfx_ofs;
    h->data_ofs   = sfx_ofs + UHA_HDR_LEN_V2;
    h->crc_ofs    = (size_t)crc_ofs64;
    h->names_ofs  = (size_t)names_ofs64;
    h->attrs_ofs  = (size_t)attrs_ofs64;
    h->attrs2_ofs = (size_t)attrs2_ofs64;
    return 0;
}

/* ---------- 0.2 default-password table cipher ---------- */
typedef struct {
    uint8_t s[256];
    uint8_t pos;
} uha02_crypt;

static void uha02_crypt_init(uha02_crypt *c)
{
    static const char pwd[] = "UHARC Default Password";
    uint8_t sb[256];
    unsigned i, off, k;
    uint32_t crc;

    for (i = 0; i < 256; i++)
        sb[i] = (uint8_t)pwd[i % 22];

    for (off = 0; off < 256; off += 8) {
        crc = uha_crc32_update(0xFFFFFFFFu, sb, 256);
        for (k = 0; k < 4; k++) {
            sb[off + k]     ^= (uint8_t)((crc >> (8 * k)) & 0xFF);
            sb[off + 4 + k] ^= (uint8_t)(((~crc) >> (8 * k)) & 0xFF);
        }
    }
    memcpy(c->s, sb, 256);
    c->pos = 0;
}

static void uha02_crypt_update(uha02_crypt *c, uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        uint8_t a = c->s[c->pos];
        c->pos = (uint8_t)(c->pos + 1);
        c->s[c->pos] = (uint8_t)(c->s[c->pos] + a);
        data[i] ^= c->s[c->pos];
    }
}

/* ---------- Stream memory helpers ---------- */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} uha02_mr;

static int uha02_mem_read(void *ctx, unsigned char *buf, unsigned want)
{
    uha02_mr *m = (uha02_mr *)ctx;
    size_t avail = m->len - m->pos;
    size_t n;
    if (avail == 0) return 0;
    n = ((size_t)want < avail) ? (size_t)want : avail;
    memcpy(buf, m->buf + m->pos, n);
    m->pos += n;
    return (int)n;
}

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
} uha02_mw;

static int uha02_mem_write(void *ctx, const unsigned char *buf, unsigned len)
{
    uha02_mw *m = (uha02_mw *)ctx;
    if (m->pos + (size_t)len > m->cap) return 1;
    memcpy(m->buf + m->pos, buf, len);
    m->pos += (size_t)len;
    return 0;
}

static int decode_table(const uint8_t *raw, size_t ofs, uint32_t cmp_len,
                        int method, uint8_t *out, uint32_t dec_len,
                        uint32_t crc_in, uint32_t *crc_out)
{
    uint8_t *cmp;
    uha02_crypt cr;
    uha02_mr mr;
    uha02_mw mw;
    void *ctx = NULL;
    int rc;

    if (cmp_len == 0 && dec_len == 0) {
        if (crc_out) *crc_out = crc_in;
        return 0;
    }
    cmp = (uint8_t *)malloc(cmp_len ? cmp_len : 1);
    if (!cmp) return -4;
    memcpy(cmp, raw + ofs, cmp_len);

    uha02_crypt_init(&cr);
    uha02_crypt_update(&cr, cmp, cmp_len);

    if (method == 0) {
        if (cmp_len != dec_len) { free(cmp); return -2; }
        memcpy(out, cmp, dec_len);
        free(cmp);
        if (crc_out) *crc_out = uha_crc32_update(crc_in, out, dec_len);
        return 0;
    }

    mr.buf = cmp;
    mr.len = cmp_len;
    mr.pos = 0;
    mw.buf = out;
    mw.cap = dec_len;
    mw.pos = 0;

    rc = uharc_dec2l_init(&ctx, method);
    if (rc != 0) { free(cmp); return -4; }
    rc = uharc_dec2l_decode(ctx, uha02_mem_read, &mr, uha02_mem_write, &mw, (unsigned long)dec_len);
    uharc_dec2l_free(ctx);
    free(cmp);

    if (rc != 0 || mw.pos != dec_len)
        return -2;
    if (crc_out)
        *crc_out = uha_crc32_update(crc_in, out, dec_len);
    return 0;
}

int uha02_read_entries(const uint8_t *raw, size_t rawlen, const uha_header *h, uha_entrylist *out)
{
    uint32_t fc, ndirs, crc;
    uint8_t *tab0 = NULL, *tab1 = NULL, *tab2 = NULL, *tab3 = NULL;
    char **dirs = NULL;
    char *dir_pool = NULL;
    int rc;
    uint32_t k, p;
    size_t pool_ofs;

    (void)rawlen;
    if (!raw || !h || !out) return -2;
    out->items = NULL;
    out->count = 0;

    fc = h->file_count;
    ndirs = h->ndirs;
    if (fc == 0) return 0;
    if (fc > 1000000u || ndirs > 100000u) return -2;

    tab0 = (uint8_t *)malloc(4u * fc);
    tab1 = (uint8_t *)malloc(h->names_unpacked ? h->names_unpacked : 1);
    tab2 = (uint8_t *)malloc(4u * fc);
    tab3 = (uint8_t *)malloc(7u * fc);
    if (!tab0 || !tab1 || !tab2 || !tab3) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -4;
    }

    /* Chain CRC across tab0, tab1, tab2, tab3 */
    crc = 0xFFFFFFFFu;
    rc = decode_table(raw, h->crc_ofs, 4u * fc, 0, tab0, 4u * fc, crc, &crc);
    if (rc == 0)
        rc = decode_table(raw, h->names_ofs, h->names_packed, 7, tab1, h->names_unpacked, crc, &crc);
    if (rc == 0)
        rc = decode_table(raw, h->attrs_ofs, h->attrs_packed, 2, tab2, 4u * fc, crc, &crc);
    if (rc == 0)
        rc = decode_table(raw, h->attrs2_ofs, h->attrs2_packed, 7, tab3, 7u * fc, crc, &crc);

    if (rc != 0) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return rc;
    }

    if ((~crc & 0xFFFFFFFFu) != (h->contents_crc & 0xFFFFFFFFu)) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        return -2;
    }

    dirs = (char **)calloc(ndirs ? ndirs : 1, sizeof(char *));
    dir_pool = (char *)malloc(h->names_unpacked + ndirs + 1);
    out->items = (uha_entry *)calloc(fc, sizeof(uha_entry));
    if (!dirs || !dir_pool || !out->items) {
        free(tab0); free(tab1); free(tab2); free(tab3);
        free(dirs); free(dir_pool);
        uha_entrylist_free(out);
        return -4;
    }
    out->count = (int)fc;

    /* Parse directories from tab1 */
    p = 0;
    pool_ofs = 0;
    for (k = 0; k < ndirs; k++) {
        uint32_t ln, j;
        dirs[k] = dir_pool + pool_ofs;
        if (p >= h->names_unpacked) goto fail;
        ln = tab1[p++];
        if (p + ln > h->names_unpacked) goto fail;
        for (j = 0; j < ln; j++) {
            char c = (char)tab1[p++];
            if (c == '\\') c = '/';
            dir_pool[pool_ofs++] = c;
        }
        dir_pool[pool_ofs++] = '\0';
    }

    /* Size deltas from tab3 */
    {
        uint32_t prev_sz = 0;
        for (k = 0; k < fc; k++) {
            uint32_t var = (uint32_t)tab3[4 * k] | ((uint32_t)tab3[4 * k + 1] << 8) |
                           ((uint32_t)tab3[4 * k + 2] << 16) | ((uint32_t)tab3[4 * k + 3] << 24);
            uint32_t sz;
            if (k == 0) sz = 0u - var;
            else sz = prev_sz - var;
            out->items[k].size = sz;
            prev_sz = sz;
        }
    }

    /* Parse files */
    for (k = 0; k < fc; k++) {
        uha_entry *e = &out->items[k];
        uint32_t ln, j, dir_idx;
        char fname[1024];
        const char *d;
        size_t dlen, nlen;
        char *full;

        if (p >= h->names_unpacked) goto fail;
        ln = tab1[p++];
        if (p + ln > h->names_unpacked || ln >= sizeof(fname)) goto fail;
        for (j = 0; j < ln; j++) {
            char c = (char)tab1[p++];
            if (c == '\\') c = '/';
            fname[j] = c;
        }
        fname[ln] = '\0';

        dir_idx = (uint32_t)tab3[4 * fc + k] | ((uint32_t)tab3[5 * fc + k] << 8);
        e->dos_attr = tab3[6 * fc + k];
        e->dos_time = (uint16_t)((uint16_t)tab2[2 * k] | ((uint16_t)tab2[2 * k + 1] << 8));
        e->dos_date = (uint16_t)((uint16_t)tab2[2 * fc + 2 * k] | ((uint16_t)tab2[2 * fc + 2 * k + 1] << 8));
        e->crc = (uint32_t)tab0[4 * k] | ((uint32_t)tab0[4 * k + 1] << 8) |
                 ((uint32_t)tab0[4 * k + 2] << 16) | ((uint32_t)tab0[4 * k + 3] << 24);
        e->has_crc = 1;

        d = (dir_idx < ndirs) ? dirs[dir_idx] : "";
        while (*d == '/' || *d == '\\') d++;
        dlen = strlen(d);
        while (dlen > 0 && (d[dlen - 1] == '/' || d[dlen - 1] == '\\')) dlen--;

        nlen = strlen(fname);
        if (dlen > 0) {
            full = (char *)malloc(dlen + 1 + nlen + 1);
            if (!full) goto fail;
            memcpy(full, d, dlen);
            full[dlen] = '/';
            memcpy(full + dlen + 1, fname, nlen + 1);
        } else {
            full = (char *)malloc(nlen + 1);
            if (!full) goto fail;
            memcpy(full, fname, nlen + 1);
        }
        e->name = full;
    }

    free(dirs);
    free(dir_pool);
    free(tab0); free(tab1); free(tab2); free(tab3);
    return 0;

fail:
    free(dirs);
    free(dir_pool);
    free(tab0); free(tab1); free(tab2); free(tab3);
    uha_entrylist_free(out);
    return -2;
}

int uha02_decode_stream(uint8_t method, const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t out_len)
{
    uha02_mr mr;
    uha02_mw mw;
    void *ctx = NULL;
    int rc = -3;

    if (!out && out_len > 0) return -2;
    if (out_len == 0) return 0;
    if (!in) return -2;

    if (method == 0) {
        if (in_len < out_len) return -2;
        memcpy(out, in, out_len);
        return 0;
    }

    if (method == 1)
        return uha_rle_decode(in, in_len, out, out_len);

    mr.buf = in;
    mr.len = in_len;
    mr.pos = 0;
    mw.buf = out;
    mw.cap = out_len;
    mw.pos = 0;

    if (method >= 2 && method <= 7) {
        rc = uharc_dec2l_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec2l_decode(ctx, uha02_mem_read, &mr,
                                    uha02_mem_write, &mw,
                                    (unsigned long)out_len);
            uharc_dec2l_free(ctx);
        }
    } else if (method >= 8 && method <= 43) {
        rc = uharc_dec3t_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec3t_decode(ctx, uha02_mem_read, &mr,
                                    uha02_mem_write, &mw,
                                    (unsigned long)out_len);
            uharc_dec3t_free(ctx);
        }
    } else {
        return -3;
    }

    if (rc != 0)
        return (rc == 2) ? -4 : -1;
    if (mw.pos != out_len)
        return -1;
    return 0;
}

void uha02_unfilter(uint8_t *b, size_t len)
{
    int64_t v2, i, end;
    if (len <= 15) return;
    if (!((b[0] == 0x4D && b[1] == 0x5A) || (b[0] == 0x5A && b[1] == 0x4D)))
        return;
    v2 = (int64_t)len;
    end = (int64_t)len - 15;
    i = 0;
    while (i < end) {
        int64_t v7, v9;
        int adv;
        if (b[i] != 0xE8 && b[i] != 0xE9) { i++; continue; }
        v7 = (int64_t)((uint32_t)b[i + 1] | ((uint32_t)b[i + 2] << 8) |
                       ((uint32_t)b[i + 3] << 16) | ((uint32_t)b[i + 4] << 24));
        if (v7 >= 0x80000000LL) v7 -= 0x100000000LL;
        adv = 4;
        if (v7 != 0) {
            int done = 0;
            if (v7 > 0 && v7 <= v2 - 1) {
                int64_t t = v7;
                if (t == i) t ^= i;
                v9 = t - i;
                done = 1;
            } else if (v7 < 0 && v7 >= -i) {
                v9 = v2 + v7;
                done = 1;
            }
            if (done) {
                uint32_t u = (uint32_t)v9;
                b[i + 1] = (uint8_t)(u & 0xFFu);
                b[i + 2] = (uint8_t)((u >> 8) & 0xFFu);
                b[i + 3] = (uint8_t)((u >> 16) & 0xFFu);
                b[i + 4] = (uint8_t)((u >> 24) & 0xFFu);
                adv = 5;
            }
        }
        i += adv;
    }
}
