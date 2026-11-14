#include <stdlib.h>
#include <string.h>

#include "uha.h"
#include "lzp.h"
#include "alz.h"
#include "ppm.h"
#include "filter.h"
#include "rle.h"

int uha_decode_payload(const uint8_t *raw, size_t rawlen,
                       const uha_header *h,
                       const uha_entrylist *entries,
                       uint8_t *out)
{
    uint32_t *ends = NULL;
    uint64_t total = 0;
    int i, n, rc;

    if (!raw || !h || !out)
        return -2;
    if (h->usize == 0)
        return 0;

    if (h->order == UHA_ORDER_STORE) {
        if ((uint64_t)h->data_ofs + h->usize > rawlen)
            return -2;
        memcpy(out, raw + h->data_ofs, h->usize);
        return 0;
    }

    if ((uint64_t)h->data_ofs + h->psize > rawlen)
        return -2;

    n = entries ? entries->count : 0;
    if (n > 0) {
        ends = malloc((size_t)n * sizeof(uint32_t));
        if (!ends)
            return -4;
        for (i = 0; i < n; i++) {
            total += entries->items[i].size;
            if (total > h->usize) {
                free(ends);
                return -2;
            }
            ends[i] = (uint32_t)total;
        }
        if (total != h->usize) {
            free(ends);
            ends = NULL;
            n = 0;
        }
    }

    rc = -3;
    if (h->order == UHA_ORDER_RLE)
        rc = uha_rle_decode(raw + h->data_ofs, h->psize, out, h->usize);
    else if (h->order >= UHA_ORDER_LZP_MIN && h->order <= UHA_ORDER_LZP_MAX)
        rc = uha_lzp_decode(raw + h->data_ofs, h->psize, h->order, h->usize,
                            ends, n, out, h->usize);
    else if (h->order >= UHA_ORDER_PPM_MIN && h->order <= UHA_ORDER_PPM_MAX)
        rc = uha_ppm_decode(raw + h->data_ofs, h->psize, h->order, h->usize,
                            ends, n, out, h->usize);
    else if (h->order >= UHA_ORDER_ALZ_MIN && h->order <= UHA_ORDER_ALZ_MAX)
        rc = uha_alz_decode(raw + h->data_ofs, h->psize, h->order, h->usize,
                            ends, n, out, h->usize);

    if (rc == 0 && h->family != 0) {
        uint64_t ofs = 0;
        int ppm_swap = (h->order >= UHA_ORDER_PPM_MIN
                        && h->order <= UHA_ORDER_PPM_MAX);
        if (n > 0) {
            for (i = 0; i < n; i++) {
                uint32_t sz = entries->items[i].size;
                if (sz >= 1024) {
                    int exe_matched = 0;
                    if (h->family & 0x01u)
                        exe_matched = uha_restore_filter(out + ofs, sz, ppm_swap);
                    if ((h->family & 0x02u) && !exe_matched)
                        uha_restore_multimedia(out + ofs, sz);
                }
                ofs += sz;
            }
        } else if (h->usize >= 1024) {
            int exe_matched = 0;
            if (h->family & 0x01u)
                exe_matched = uha_restore_filter(out, h->usize, ppm_swap);
            if ((h->family & 0x02u) && !exe_matched)
                uha_restore_multimedia(out, h->usize);
        }
    }

    free(ends);
    return rc;
}
