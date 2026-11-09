#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ppm.h"
#include "ppm_priv.h"

/* UHA_PPMTRACE (diagnostic t12g/t14c, has to remove) */
static int ptrace_on = -1;
static int ptr_route[8], ptr_match, ptr_esc, ptr_bcr[4];

static void ppm_trace_dump(const char *who)
{
    if (ptrace_on != 1)
        return;
    fprintf(stderr, "[PPMTRC %s] blk<bc0=%d bc1=%d bc>1=%d> lit[r0o1=%d pred=%d rec2=%d entry=%d c550=%d] match=%d esc=%d\n",
            who, ptr_bcr[0], ptr_bcr[1], ptr_bcr[2],
            ptr_route[CR_ORDER1_HIT], ptr_route[CR_PREDICTED_HIT],
            ptr_route[CR_REC2_HIT], ptr_route[CR_ENTRY_HIT], ptr_route[CR_C550],
            ptr_match, ptr_esc);
}

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
    int xp_m = 0;   /* [M205 UHA_XPSIZE] rank of member publie */
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
    { const char *pe = getenv("UHA_PPMTRACE"); ptrace_on = pe ? (pe[0]=='2' ? 2 : 1) : 0; }
    if (ptrace_on >= 1)
        fprintf(stderr, "[PPMTRC dec hdr] bc=%d e0_blk_len=%u detr_thr1=%u usize=%u\n",
                m.byte_class, m.e0_blk_len, m.detr_thr1, usize);

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
        /* [M205 UHA_XPSIZE, default-OFF, no emissif] SIZE COMPRESSED BY MEMBER OF THE MASTER :
         * position of the lecteur of the range-coder at the output of each member. `psize` by member
         * n'is not stores ; c'is therefore THERE measures directe of the bound compressed of legacy.
         * same grandeur side encoder (`ppm_encode.c`, `[XPSIZE] enc`) : the deltas se compares. */
        { static int xp = -1;
          if (xp < 0) { const char *e = getenv("UHA_XPSIZE"); xp = (e && e[0] != '0') ? 1 : 0; }
          if (xp) {
              while (xp_m < nmembers && member_ends && (uint32_t)out_pos >= member_ends[xp_m]) {
                  fprintf(stderr, "[XPSIZE] dec rang=%d outpos=%u inpos=%lu\n",
                          xp_m, (unsigned)member_ends[xp_m], (unsigned long)r.rd.pos);
                  xp_m++;
              }
          } }
        if ((uint32_t)out_pos >= m.e0_blk_len) {
            if (ptrace_on == 1)
                fprintf(stderr, "[PPMTRC dec promote] @%u\n", (unsigned)out_pos);
            ptr_bcr[1]++;
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
            /* [M178, GATED UHA_PPMTRACE=2, defautOFF] position of the reset of block (frontier
             * of member) : without elle there trace [BLKCLS] n'affiche that `outpos=0` (counter
             * remis has jour juste AFTER the reset). */
            { static int ba = -1;
              if (ba < 0) { const char *e = getenv("UHA_PPMTRACE"); ba = (e && e[0]=='2') ? 1 : 0; }
              if (ba) fprintf(stderr, "[BLKAT] outpos=%u member=%d bc=%d\n",
                              (unsigned)out_pos, member, m.byte_class); }
            if (m.byte_class != 0)
                ppm_bc1_block_reset();
            m.out_count = (uint32_t)out_pos;
        }

        ppm_matchfinder_decode(&m, &r, raw_syms, &mr);
        { static int lzd = -1;
          if (lzd < 0) { const char *e = getenv("UHA_LZPDBG"); lzd = (e && e[0] != '0') ? 1 : 0; }
          if (lzd) fprintf(stderr, "[LZPD] pos=%u ctx=%d cls=%d match=%d rc=%lu\n",
                           (unsigned)out_pos, mr.lzp_ctx, mr.lzp_cls, mr.is_match,
                           uha_rc_dec_count()); }
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
            ptr_match++;
            n = mr.raw_len;
            /* [M208 GATED UHA_PARSE] decision of parse symbole by symbole (decode) : judge of the
             * first divergence of parse (the 1er byte d'archive n'is only to  symptome of the range coder). */
            { static int ps = -1;
              if (ps < 0) { const char *e = getenv("UHA_PARSE"); ps = (e && e[0] != '0') ? (e[0] == '2' ? 2 : 1) : 0; }
              if (ps && (ps == 2 || out_pos < 45337))
                  fprintf(stderr, "[PARSED] pos=%u M len=%d cls=%d\n",
                          (unsigned)out_pos, n, mr.lzp_cls); }
            /* [M208 GATED UHA_LASTSYM=2] the legacy engine allows-t-il has match has ATTEINDRE/DEPASSER there
             * frontier of member ? Measures sure the stream decode (oracle) : distance of the end of match
             * at the frontier there closer. */
            { static int lsm2 = -1;
              if (lsm2 < 0) { const char *e = getenv("UHA_LASTSYM"); lsm2 = (e && e[0] == '2') ? 1 : 0; }
              if (lsm2) {
                  int kk;
                  for (kk = 0; kk < nmembers; kk++) {
                      uint32_t b = member_ends[kk];
                      if (b > (uint32_t)out_pos && b <= (uint32_t)(out_pos + n))
                          fprintf(stderr, "[MFX] pos=%u len=%d end=%u bound=%u d=%d cls=%d inprog=%u\n",
                                  (unsigned)out_pos, n, (unsigned)(out_pos + n), (unsigned)b,
                                  (int)(b - (uint32_t)(out_pos + n)), mr.lzp_cls, (unsigned)m.b8);
                      else if (b > (uint32_t)(out_pos + n) && b - (uint32_t)(out_pos + n) <= 4)
                          fprintf(stderr, "[MFN] pos=%u len=%d end=%u bound=%u d=%d inprog=%u\n",
                                  (unsigned)out_pos, n, (unsigned)(out_pos + n), (unsigned)b,
                                  (int)(b - (uint32_t)(out_pos + n)), (unsigned)m.b8);
                  }
              } }
            { static int lsm = -1;
              if (lsm < 0) { const char *e = getenv("UHA_LASTSYM"); lsm = (e && e[0] != '0') ? 1 : 0; }
              if (lsm && out_pos >= 45325 && out_pos <= 45340)
                  fprintf(stderr, "[MFDEC] pos=%u len=%d cls=%d syms=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                          (unsigned)out_pos, n, mr.lzp_cls,
                          raw_syms[0], raw_syms[1], raw_syms[2], raw_syms[3],
                          raw_syms[4], raw_syms[5], raw_syms[6], raw_syms[7]); }
            if (ptrace_on == 2)
                fprintf(stderr, "[TR2 dec MATCH] pos=%u len=%d cls=%d\n",
                        (unsigned)out_pos, n, mr.lzp_cls);
            for (i = 0; i < n; i++) {
                if ((uint32_t)out_pos >= usize)
                    break;
                dl = (n - i) <= 8;
                ppm_match_maintain(&m, raw_syms[i], dl, work, &out_pos);
            }
        } else {
            unsigned long rc_n0 = uha_rc_dec_count();
            int lit0 = out_pos;
            ppm_matchfinder_literal_tail(&m);
            if (!ppm_decode_literal_cascade(&m, &r, work, &out_pos, &route, &sym)) {
                free(work);
                goto done;
            }
            { static int ps = -1;
              if (ps < 0) { const char *e = getenv("UHA_PARSE"); ps = (e && e[0] != '0') ? (e[0] == '2' ? 2 : 1) : 0; }
              if (ps && (ps == 2 || (uint32_t)lit0 < 45337))
                  fprintf(stderr, "[PARSED] pos=%d L sym=%u route=%d\n", lit0, (unsigned)sym, route); }
            ptr_route[route]++;
            if (ptrace_on == 2) {
                int k;
                fprintf(stderr, "[TR2 dec] pos=%u route=%d sym=%u rcn0=%lu depth=%lu bytes=",
                        (unsigned)out_pos, route, (unsigned)sym, rc_n0,
                        uha_rc_dec_count() - rc_n0);
                for (k = lit0; k < out_pos && k < lit0 + 8; k++)
                    fprintf(stderr, "%02x", work[k]);
                if (out_pos - lit0 > 8)
                    fprintf(stderr, "..(%d)", out_pos - lit0);
                fprintf(stderr, "\n");
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
    ppm_trace_dump("dec");
    ppm_model_free(&m);
    return rc;
}
