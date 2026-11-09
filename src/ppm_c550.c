#include "ppm_priv.h"
#include <stdio.h>
#include <stdlib.h>

int ppm_c550_decode(ppm_model *m, uha_rc *r, int ctx, int next_ctx, ppm_c550 *res)
{
    uint32_t idx, age, freq;
    int flag, kctx, workctx;
    ppm_kstate ks;

    res->sse2_idx = -1;
    res->sse2_up_idx = -1;
    res->kernel_excl = -1;
    res->weight = 0;
    res->path_a = 0;

    idx = (m->age_ctr + 1) & 0xFF;
    age = (m->age - m->age_ring[idx]) & PPM_M32;
    /* [GATED UHA_AGEDBG, default-OFF, M162] state of l'ring d'age au site c550 :
     * date there divergence of the path Has (age >= 0x91ADC0 -> literal uniforme 256). */
    { static int agd = -1;
      if (agd < 0) { const char *e = getenv("UHA_AGEDBG"); agd = (e && e[0] != '0') ? 1 : 0; }
      if (agd) fprintf(stderr, "[AGED] pos=%u ctr=%u idx=%u age=%u ring=%u\n",
                       m->out_count, m->age_ctr, idx, age, m->age_ring[idx]); }
    flag = (next_ctx == 0x301) ? 1 : 0;

    if (age < 0x6D4250 || age >= 0xFEFF01) {
        kctx = ctx;
        workctx = next_ctx;
    } else if (age < 0x91ADC0) {
        if (m->rec_a[flag] > m->rec_b[flag]) {
            kctx = 0x200;
            workctx = 0x302 + flag;
        } else {
            kctx = ctx;
            workctx = next_ctx;
        }
    } else {
        freq = uha_rc_threshold(r, 0x100);
        if (freq > 0xFF)
            freq = 0xFF;
        uha_rc_remove(r, freq, freq + 1);
        res->sym = (int)freq;
        res->supported = 1;
        res->path_a = 1;
        res->kctx = ctx;
        res->work_ctx = next_ctx;
        res->weight = 0;
        return 1;
    }

    m->work_ctx = workctx;
    res->sym = ppm_kernel_decode(m, r, kctx, &ks);
    res->supported = ks.supported;
    res->kctx = kctx;
    res->work_ctx = workctx;
    res->weight = ks.weight;
    res->sse2_idx = ks.sse2_idx;
    res->sse2_up_idx = ks.sse2_up_idx;
    res->kernel_excl = ks.kernel_excl;
    return ks.supported;
}

int ppm_c550_encode(ppm_model *m, int ctx, int next_ctx, int target, ppm_c550 *res)
{
    uint32_t idx, age;
    int flag, kctx, workctx;
    ppm_kstate ks;

    res->sse2_idx = -1;
    res->sse2_up_idx = -1;
    res->kernel_excl = -1;
    res->weight = 0;
    res->path_a = 0;

    idx = (m->age_ctr + 1) & 0xFF;
    age = (m->age - m->age_ring[idx]) & PPM_M32;
    flag = (next_ctx == 0x301) ? 1 : 0;

    if (age < 0x6D4250 || age >= 0xFEFF01) {
        kctx = ctx;
        workctx = next_ctx;
    } else if (age < 0x91ADC0) {
        if (m->rec_a[flag] > m->rec_b[flag]) {
            kctx = 0x200;
            workctx = 0x302 + flag;
        } else {
            kctx = ctx;
            workctx = next_ctx;
        }
    } else {
        if (!m->w)
            return 0;
        if (uha_rcw_encode(m->w, (uint32_t)(target & 0xFF),
                           (uint32_t)(target & 0xFF) + 1, 0x100) != 0)
            return 0;
        res->sym = target & 0xFF;
        res->supported = 1;
        res->path_a = 1;
        res->kctx = ctx;
        res->work_ctx = next_ctx;
        res->weight = 0;
        return 1;
    }

    m->work_ctx = workctx;
    res->sym = ppm_kernel_encode(m, kctx, target, &ks);
    res->supported = ks.supported;
    res->kctx = kctx;
    res->work_ctx = workctx;
    res->weight = ks.weight;
    res->sse2_idx = ks.sse2_idx;
    res->sse2_up_idx = ks.sse2_up_idx;
    res->kernel_excl = ks.kernel_excl;
    return ks.supported && res->sym == (target & 0xFF);
}
