#include "uha04_codec.h"
#include "uharc_dec.h"
#include "rle.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} uha04_mr;

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
} uha04_mw;

static int uha04_mem_read(void *ctx, unsigned char *buf, unsigned want)
{
    uha04_mr *m = (uha04_mr *)ctx;
    size_t avail = m->len - m->pos;
    size_t n;

    if (avail == 0)
        return 0;
    n = ((size_t)want < avail) ? (size_t)want : avail;
    memcpy(buf, m->buf + m->pos, n);
    m->pos += n;
    return (int)n;
}

static int uha04_mem_write(void *ctx, const unsigned char *buf, unsigned len)
{
    uha04_mw *m = (uha04_mw *)ctx;

    if (m->pos + (size_t)len > m->cap)
        return 1;
    memcpy(m->buf + m->pos, buf, len);
    m->pos += (size_t)len;
    return 0;
}

int uha04_decode_stream(uint8_t method, uint8_t flags_filt,
                        const uint8_t *in, size_t in_len,
                        const uint32_t *ends, int nfiles,
                        uint8_t *out, size_t out_len)
{
    uha04_mr mr;
    uha04_mw mw;
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

    if (method == 0) {
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
            rc = uharc_dec2l_decode(ctx, uha04_mem_read, &mr,
                                    uha04_mem_write, &mw,
                                    (unsigned long)out_len);
            uharc_dec2l_free(ctx);
        }
    } else if (method >= 8 && method <= 23) {
        rc = uharc_dec3v_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec3v_decode_mem(ctx, cum, ncum, in, in_len, out, out_len);
            mw.pos = out_len;
            uharc_dec3v_free(ctx);
        }
    } else if (method >= 24 && method <= 39) {
        rc = uharc_dec4vc_init(&ctx, (int)method);
        if (rc == 0) {
            uharc_dec4vc_set_flags2(ctx, (unsigned char)flags_filt);
            rc = uharc_dec4vc_decode_b(ctx, cum, ncum,
                                       uha04_mem_read, &mr,
                                       uha04_mem_write, &mw,
                                       (unsigned long)out_len);
            uharc_dec4vc_free(ctx);
        }
    } else if (method >= 40 && method <= 87) {
        rc = uharc_dec5v_init(&ctx, (int)method);
        if (rc == 0) {
            rc = uharc_dec5v_decode_b(ctx, cum, ncum,
                                      uha04_mem_read, &mr,
                                      uha04_mem_write, &mw,
                                      (unsigned long)out_len);
            uharc_dec5v_free(ctx);
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

