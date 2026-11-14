#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ppm.h"
#include "ppm_priv.h"

int uha_ppm_decode(const uint8_t *src, size_t srclen,
                   int order, uint32_t usize,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t *out, size_t outlen)
{
    ppm_model m;
    uha_rc r;
    uint8_t *work;
    uint8_t raw_syms[256];
    ppm_match mr;
    int out_pos, i, n, route, sym, member, rc, dl;
    uint32_t next_boundary, target, period;

    if (order < 0x18 || order > 0x27)
        return PPM_ERR_ORDER;
    if (!src || !out)
        return PPM_ERR_CORRUPT;
    if (outlen < usize)
        return PPM_ERR_OUTSPACE;
    if (usize == 0)
        return PPM_OK;
    if (srclen == 0)
        return PPM_ERR_CORRUPT;

    memset(&m, 0, sizeof(m));
    if (!ppm_model_alloc(&m, order))
        return PPM_ERR_NOMEM;

    rc = PPM_ERR_CORRUPT;
    m.blk_len4 = usize;

    uha_reader_init(&r.rd, src, srclen);
    r.code = 0;
    r.range = PPM_M32;
    r.corrupt = 0;
    ppm_read_block_header(&m, &r);
    if (r.corrupt)
        goto done;

    next_boundary = 0;
    member = 0;
    period = 0x40000u >> (m.byte_class * 2);
    if (usize - next_boundary > period)
        target = next_boundary + period;
    else
        target = usize;
    if (target > m.e0_blk_len)
        target = m.e0_blk_len;
    if (target > m.detr_thr1)
        target = m.detr_thr1;
    while (member < nmembers && member_ends && member_ends[member] < target)
        member++;
    if (member < nmembers && member_ends)
        next_boundary = member_ends[member];
    else
        next_boundary = usize;

    if (!ppm_block_reset(&m, &r))
        goto done;
    if (m.byte_class != 0)
        ppm_bc1_reset();

    work = malloc((size_t)usize + 0x1000);
    if (!work) {
        rc = PPM_ERR_NOMEM;
        goto done;
    }

    out_pos = 0;
    while ((uint32_t)out_pos < usize) {
        if ((uint32_t)out_pos >= m.e0_blk_len) {
            ppm_promote_to_bc1(&m);
            ppm_bc1_reset();
            next_boundary = (uint32_t)out_pos;
        }
        if ((uint32_t)out_pos >= next_boundary) {
            period = 0x40000u >> (m.byte_class * 2);
            if (usize - next_boundary > period)
                target = next_boundary + period;
            else
                target = usize;
            if (target > m.e0_blk_len)
                target = m.e0_blk_len;
            if (target > m.detr_thr1)
                target = m.detr_thr1;
            while (member < nmembers && member_ends && member_ends[member] < target)
                member++;
            if (member < nmembers && member_ends)
                next_boundary = member_ends[member];
            else
                next_boundary = usize;
            if (!ppm_block_reset(&m, &r)) {
                free(work);
                goto done;
            }
            if (m.byte_class != 0)
                ppm_bc1_block_reset();
            m.out_count = (uint32_t)out_pos;
        }

        ppm_matchfinder_decode(&m, &r, raw_syms, &mr);
        if (mr.lzp_ctx >= 0 && mr.lzp_cls < 0) {
            free(work);
            goto done;
        }
        if (mr.lzp_ctx >= 0) {
            ppm_lzp_apply_update(&m, mr.lzp_ctx, mr.lzp_cls);
            if (mr.lzp_cls != 1)
                ppm_lzp_nomatch_tail(&m);
        }

        if (mr.is_match) {
            n = mr.raw_len;
            for (i = 0; i < n; i++) {
                if ((uint32_t)out_pos >= usize)
                    break;
                dl = (n - i) <= 8;
                ppm_match_maintain(&m, raw_syms[i], dl, work, &out_pos);
            }
        } else {
            ppm_matchfinder_literal_tail(&m);
            if (!ppm_decode_literal_cascade(&m, &r, work, &out_pos, &route, &sym)) {
                free(work);
                goto done;
            }
        }
        if (r.corrupt) {
            free(work);
            goto done;
        }
    }

    if ((uint32_t)out_pos != usize) {
        free(work);
        goto done;
    }
    memcpy(out, work, usize);
    free(work);
    rc = PPM_OK;

done:
    ppm_model_free(&m);
    return rc;
}
