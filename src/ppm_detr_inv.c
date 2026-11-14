#include <stdint.h>
#include <stddef.h>
#include "ppm_priv.h"

int ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                     uint8_t *out, uint32_t *nout);

int ppm_detr_inverse(const uint8_t *in, uint32_t len,
                     uint8_t *out, uint32_t *nout)
{
    return ppm_detr_forward(in, len, len, out, nout);
}
