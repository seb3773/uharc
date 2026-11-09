#include <string.h>
#include "ppm_priv.h"

void ppm_detr_init(ppm_detr *d)
{
    d->flag = 0;
    d->arg = 0;
}

static void detr_put(uint8_t b, uint8_t *outp, int *outlen)
{
    outp[*outlen] = b;
    (*outlen)++;
}

void ppm_detr_emit(ppm_detr *d, uint8_t sym, uint32_t count,
                   uint32_t thr1, uint32_t thr2, uint8_t *outp, int *outlen)
{
    uint32_t dl, flag, cls, strlen, i, off, term;

    dl = (~sym) & 0xFFu;
    flag = d->flag;

    if (flag == 1) {
        d->flag = 0;
        if (count < thr1) {
            term = (d->arg - 0xA6u) & PPM_M32;
            detr_put(DetrEsc[(term * 11 + dl) & PPM_M32], outp, outlen);
        } else if (dl == 0xFE) {
            detr_put(0xFE, outp, outlen);
        } else {
            detr_put(0, outp, outlen);
            detr_put(0, outp, outlen);
            detr_put(3, outp, outlen);
            detr_put(3, outp, outlen);
            detr_put((uint8_t)dl, outp, outlen);
        }
        return;
    }

    if (count >= thr1 && dl == 0xFE) {
        d->flag = 1;
        return;
    }
    if (count >= thr2) {
        detr_put((uint8_t)dl, outp, outlen);
        return;
    }
    if (dl < 0x80 && flag == 0) {
        detr_put((uint8_t)dl, outp, outlen);
        return;
    }

    cls = DetrClass[dl];
    if (cls >= 0xC8) {
        detr_put((uint8_t)((dl - flag) & 0xFFu), outp, outlen);
        d->flag = 0;
        return;
    }
    if (cls == 0x64) {
        d->arg = (uint8_t)dl;
        d->flag = 1;
        return;
    }
    if (cls == 0x63) {
        d->flag = 0x20;
        return;
    }

    strlen = DetrStrLen[cls];
    off = DetrStrOff[cls];
    if (flag != 0) {
        detr_put((uint8_t)((((~DetrStrData[off]) & 0xFFu) - 0x20u) & 0xFFu), outp, outlen);
        off++;
        strlen--;
        d->flag = 0;
    }
    for (i = 1; i <= strlen; i++) {
        detr_put((uint8_t)((~DetrStrData[off]) & 0xFFu), outp, outlen);
        off++;
    }
}

int ppm_fenwick_bsearch(const uint16_t *row, uint32_t total, uint32_t freq, uint32_t *rem)
{
    uint32_t budget, node;
    int base, s;

    budget = total - freq;
    base = 0;
    s = 0x80;
    while (s != 0) {
        node = row[base + s];
        if (node < budget) {
            base = base + s;
            budget = budget - node;
        }
        s >>= 1;
    }
    *rem = budget;
    return base;
}

int ppm_fenwick_mixsearch(const uint16_t *row, const uint16_t *freq_row,
                          uint32_t total, uint32_t freq,
                          const uint8_t *excl, int nexcl, uint32_t *rem)
{
    int base_node, step, esi_node, i;
    uint32_t budget, s, cumat;
    int alive[32];

    budget = (total - freq) & 0xFFFFu;
    base_node = 0;
    step = 0x80;
    for (i = 0; i < nexcl; i++)
        alive[i] = 1;
    while (step != 0) {
        esi_node = base_node + step;
        s = 0;
        for (i = 0; i < nexcl; i++)
            if (alive[i] && esi_node > excl[i])
                s = (s + freq_row[excl[i]]) & 0xFFFFu;
        cumat = row[esi_node];
        if (cumat < ((s + budget) & PPM_M32)) {
            for (i = 0; i < nexcl; i++)
                if (alive[i] && esi_node > excl[i])
                    alive[i] = 0;
            budget = (budget - ((cumat - s) & PPM_M32)) & 0xFFFFu;
            base_node = esi_node;
        }
        step >>= 1;
    }
    *rem = budget;
    return base_node;
}
