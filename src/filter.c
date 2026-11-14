#include <stdlib.h>
#include <string.h>
#include "filter.h"

static int32_t sext16(uint16_t w)
{
    if (w & 0x8000u)
        return (int32_t)w - 0x10000;
    return (int32_t)w;
}

static uint32_t rd32(const uint8_t *buf, size_t p)
{
    return (uint32_t)buf[p]
         | ((uint32_t)buf[p + 1] << 8)
         | ((uint32_t)buf[p + 2] << 16)
         | ((uint32_t)buf[p + 3] << 24);
}

static uint16_t rd16(const uint8_t *buf, size_t p)
{
    return (uint16_t)((uint16_t)buf[p] | ((uint16_t)buf[p + 1] << 8));
}

static void wr32(uint8_t *buf, size_t p, uint32_t v)
{
    buf[p]     = (uint8_t)v;
    buf[p + 1] = (uint8_t)(v >> 8);
    buf[p + 2] = (uint8_t)(v >> 16);
    buf[p + 3] = (uint8_t)(v >> 24);
}

static void wr16(uint8_t *buf, size_t p, uint16_t v)
{
    buf[p]     = (uint8_t)v;
    buf[p + 1] = (uint8_t)(v >> 8);
}

static void apply_exe_filter(uint8_t *buf, uint32_t size, uint32_t limit,
                             uint32_t start, int ppm_byte_swap)
{
    int64_t i, n, lim = (int64_t)limit;
    size_t ecx;
    int32_t idx, k, al, found, skip, steps;
    uint32_t eax, swapped;
    int32_t se;
    uint16_t hi, lo, key, tv;
    uint16_t tbl[128];

    if (size <= 15)
        return;
    memset(tbl, 0, sizeof(tbl));
    n = (int64_t)size - 15;
    i = (int64_t)start;
    while (i < n) {
        if (buf[i] != 0xE8 && buf[i] != 0xE9) {
            i++;
            continue;
        }
        ecx = (size_t)(i + 1);
        eax = rd32(buf, ecx);
        if (eax == 0) {
            i += 4;
            continue;
        }
        skip = 4;
        if (ppm_byte_swap) {
            swapped = (eax & 0xFF00FF00u)
                    | ((eax >> 16) & 0xFFu)
                    | ((eax << 16) & 0xFF0000u);
            if (((int64_t)(int32_t)eax >= -i && (int64_t)(int32_t)eax < lim)
             || ((int64_t)(int32_t)swapped >= -i && (int64_t)(int32_t)swapped < lim)) {
                eax = swapped;
                wr32(buf, ecx, eax);
                skip = 5;
            }
        }
        se = (int32_t)eax;
        if (se > 0 && (int64_t)eax < lim) {
            if ((int64_t)eax == i)
                eax = 0;
            eax = (uint32_t)((int64_t)eax - i);
            wr32(buf, ecx, eax);
            i += 5;
            continue;
        }
        if (se < 0) {
            if ((int64_t)se >= -i) {
                wr32(buf, ecx, (uint32_t)((int64_t)eax + lim));
                i += 5;
                continue;
            }
        }
        hi = rd16(buf, ecx + 2);
        if (hi == 0) {
            i += skip;
            continue;
        }
        if (hi == (uint16_t)((limit - 1u) >> 16)) {
            i += skip;
            continue;
        }
        if (hi == (uint16_t)((uint64_t)(-i) >> 16)) {
            i += skip;
            continue;
        }
        lo = rd16(buf, ecx);
        if (((uint32_t)lo + 0xFFFF8000u) < 0x80u) {
            idx = (int32_t)lo - 0x8000;
            tv = tbl[idx];
            wr16(buf, ecx, (uint16_t)(((int64_t)sext16(tv) - i) & 0xFFFF));
            if (idx != 0) {
                for (k = idx; k >= 1; k--)
                    tbl[k] = tbl[k - 1];
                tbl[0] = tv;
            }
            i += skip;
            continue;
        }
        key = (uint16_t)(((int64_t)lo + i) & 0xFFFF);
        steps = 0;
        for (; steps < 256; steps++) {
            found = -1;
            al = 0;
            while (al < 0x80) {
                if (tbl[al] == key) {
                    found = al;
                    break;
                }
                al++;
            }
            if (found >= 0) {
                wr16(buf, ecx, (uint16_t)(0x8000 | found));
                key = (uint16_t)(((int64_t)(0x8000 | found) + i) & 0xFFFF);
                continue;
            }
            if (sext16(key) < sext16(0x8080))
                break;
            for (k = 0x7F; k >= 1; k--)
                tbl[k] = tbl[k - 1];
            tbl[0] = key;
            break;
        }
        i += skip;
    }
}

static void apply_forward_exe_filter(uint8_t *buf, uint32_t size, uint32_t limit,
                                     uint32_t start, int ppm_byte_swap)
{
    int64_t i, n, lim = (int64_t)limit;
    size_t ecx;
    int32_t k, al, found, skip, steps;
    uint32_t eax, swapped;
    int64_t target;
    uint16_t hi, lo, key;
    uint16_t tbl[128];

    if (size <= 15)
        return;
    memset(tbl, 0, sizeof(tbl));
    n = (int64_t)size - 15;
    i = (int64_t)start;
    while (i < n) {
        if (buf[i] != 0xE8 && buf[i] != 0xE9) {
            i++;
            continue;
        }
        ecx = (size_t)(i + 1);
        eax = rd32(buf, ecx);
        if (eax == 0) {
            i += 4;
            continue;
        }
        skip = 4;
        target = (int64_t)(int32_t)eax + i;
        if (target >= 0 && target < lim) {
            uint32_t outv = (target == 0) ? (uint32_t)i : (uint32_t)target;
            wr32(buf, ecx, outv);
            skip = 5;
        } else if ((int32_t)eax > 0 && (int64_t)eax < lim) {
            wr32(buf, ecx, (uint32_t)((int64_t)eax - lim));
            skip = 5;
        } else {
            hi = rd16(buf, ecx + 2);
            if (hi != 0 &&
                hi != (uint16_t)((limit - 1u) >> 16) &&
                hi != (uint16_t)((uint64_t)(-i) >> 16)) {
                lo = rd16(buf, ecx);
                key = (uint16_t)(((int64_t)lo + i) & 0xFFFF);
                found = -1;
                for (al = 0; al < 0x80; al++) {
                    if (tbl[al] == key) {
                        found = al;
                        break;
                    }
                }
                if (found >= 0) {
                    wr16(buf, ecx, (uint16_t)(0x8000 | found));
                    if (found != 0) {
                        for (k = found; k >= 1; k--)
                            tbl[k] = tbl[k - 1];
                        tbl[0] = key;
                    }
                } else {
                    for (steps = 0; steps < 256; steps++) {
                        uint16_t cur = rd16(buf, ecx);
                        if (((uint32_t)cur + 0xFFFF8000u) >= 0x80u)
                            break;
                        int idx = (int)cur - 0x8000;
                        wr16(buf, ecx, (uint16_t)(((int64_t)tbl[idx] - i) & 0xFFFF));
                    }
                    if (sext16(key) >= sext16(0x8080)) {
                        for (k = 0x7F; k >= 1; k--)
                            tbl[k] = tbl[k - 1];
                        tbl[0] = key;
                    }
                }
            }
        }
        if (ppm_byte_swap) {
            eax = rd32(buf, ecx);
            swapped = (eax & 0xFF00FF00u)
                    | ((eax >> 16) & 0xFFu)
                    | ((eax << 16) & 0xFF0000u);
            if (((int64_t)(int32_t)eax >= -i && (int64_t)(int32_t)eax < lim)
             || ((int64_t)(int32_t)swapped >= -i && (int64_t)(int32_t)swapped < lim)) {
                wr32(buf, ecx, swapped);
                skip = 5;
            }
        }
        i += skip;
    }
}

static int classify_exe(const uint8_t *buf, uint32_t usize,
                        int *mode, uint32_t *start_ofs)
{
    uint32_t w0, d0, word67, word18;

    *mode = 0;
    *start_ofs = 0;
    if (usize < 2)
        return 0;
    w0 = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8);
    d0 = 0;
    if (usize >= 4)
        d0 = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8)
           | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);

    if (w0 == 0x5A4D || w0 == 0x4D5A || w0 == 0x514D) {
        if (usize < 8) {
            *mode = 0;
            *start_ofs = 0;
            return 1;
        }
        word67 = (uint32_t)buf[6] | ((uint32_t)buf[7] << 8);
        if (word67 < 0x10 || word67 > 0x2000) {
            *mode = 0;
            *start_ofs = 8;
            return 1;
        }
        word18 = 0;
        if (usize >= 0x1A)
            word18 = (uint32_t)buf[0x18] | ((uint32_t)buf[0x19] << 8);
        if (word18 >= 0x1C && (uint64_t)word18 + (uint64_t)word67 * 4u < usize)
            *mode = 1;
        else
            *mode = 0;
        *start_ofs = 0x1A;
        return 1;
    }
    if (d0 == 0x464C457F) {
        if (usize > 0x13 && buf[0x12] == 3 && buf[0x13] == 0) {
            *mode = 0;
            *start_ofs = 0x14;
            return 1;
        }
        return 0;
    }
    if (d0 == 0x564F4246) {
        *mode = 0;
        *start_ofs = 0;
        return 1;
    }
    return 0;
}

int uha_apply_forward_filter(uint8_t *buf, uint32_t usize, int ppm_byte_swap)
{
    int mode;
    uint32_t start_ofs, reloc_ofs, reloc_size, plane, i, j;
    uint8_t *relocations;

    if (!buf || usize < 1024)
        return 0;
    if (!classify_exe(buf, usize, &mode, &start_ofs))
        return 0;
    if (mode == 1) {
        reloc_ofs = (uint32_t)buf[0x18] | ((uint32_t)buf[0x19] << 8);
        reloc_size = ((uint32_t)buf[6] | ((uint32_t)buf[7] << 8)) * 4u;
        if ((uint64_t)reloc_ofs + reloc_size <= (uint64_t)usize - 15u) {
            relocations = (uint8_t *)malloc(reloc_size);
            if (!relocations)
                return 1;
            memcpy(relocations, buf + reloc_ofs, reloc_size);
            for (i = reloc_size; i > 4u; i -= 2u) {
                uint32_t idx = i - 2u;
                uint32_t cur = (uint32_t)relocations[idx] | ((uint32_t)relocations[idx + 1u] << 8);
                uint32_t prev = (uint32_t)relocations[idx - 4u] | ((uint32_t)relocations[idx - 3u] << 8);
                uint32_t diff = (cur - prev) & 0xFFFFu;
                relocations[idx] = (uint8_t)diff;
                relocations[idx + 1u] = (uint8_t)(diff >> 8);
            }
            j = reloc_ofs;
            for (plane = 0; plane < 4u; plane++) {
                for (i = plane; i < reloc_size; i += 4u)
                    buf[j++] = relocations[i];
            }
            free(relocations);
            start_ofs = reloc_ofs + reloc_size;
        }
    }
    apply_forward_exe_filter(buf, usize, usize, start_ofs, ppm_byte_swap);
    return 1;
}

int uha_restore_filter(uint8_t *buf, uint32_t usize, int ppm_byte_swap)
{
    int mode;
    uint32_t start_ofs, reloc_ofs, reloc_size, plane, i, j, v;
    uint8_t *relocations;

    if (!buf || usize < 1024)
        return 0;
    if (!classify_exe(buf, usize, &mode, &start_ofs))
        return 0;
    if (mode == 1) {
        reloc_ofs = (uint32_t)buf[0x18] | ((uint32_t)buf[0x19] << 8);
        reloc_size = ((uint32_t)buf[6] | ((uint32_t)buf[7] << 8)) * 4u;
        if ((uint64_t)reloc_ofs + reloc_size > (uint64_t)usize - 15u)
            return 1;
        relocations = (uint8_t *)malloc(reloc_size);
        if (!relocations)
            return 1;
        j = reloc_ofs;
        for (plane = 0; plane < 4; plane++) {
            i = plane;
            while (i < reloc_size) {
                relocations[i] = buf[j];
                j++;
                i += 4;
            }
        }
        i = 4;
        while (i < reloc_size) {
            v = (uint32_t)relocations[i] | ((uint32_t)relocations[i + 1] << 8);
            v += (uint32_t)relocations[i - 4] | ((uint32_t)relocations[i - 3] << 8);
            relocations[i] = (uint8_t)v;
            relocations[i + 1] = (uint8_t)(v >> 8);
            i += 2;
        }
        memcpy(buf + reloc_ofs, relocations, reloc_size);
        free(relocations);
        start_ofs = reloc_ofs + reloc_size;
    }
    apply_exe_filter(buf, usize, usize, start_ofs, ppm_byte_swap);
    return 1;
}

static int detect_mm_stride(const uint8_t *buf, uint32_t usize)
{
    static const uint8_t headers[3][36] = {
        {0x42,0x4D,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
         0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x01,0x00,0x18,0x00,0x00,0x00,
         0x00,0x00,0x3F,0x3F},
        {0x52,0x49,0x46,0x46,0x3F,0x3F,0x3F,0x3F,0x57,0x41,0x56,0x45,0x66,0x6D,0x74,0x20,
         0x3F,0x3F,0x3F,0x3F,0x01,0x00,0x3F,0x00,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,0x3F,
         0x3F,0x3F,0x3F,0x00},
        {0x43,0x72,0x65,0x61,0x74,0x69,0x76,0x65,0x20,0x56,0x6F,0x69,0x63,0x65,0x20,0x46,
         0x69,0x6C,0x65,0x1A,0x1A,0x00,0x0A,0x01,0x29,0x11,0x01,0x3F,0x3F,0x3F,0x3F,0x00,
         0x3F,0x3F,0x3F,0x3F}
    };
    int kind, i, j, stride, matches;

    if (!buf || usize < 1024)
        return 0;
    kind = -1;
    for (j = 0; j < 3; j++) {
        matches = 1;
        for (i = 0; i < 36; i++)
            if (headers[j][i] != 0x3F && headers[j][i] != buf[i])
                matches = 0;
        if (matches)
            kind = j;
    }
    switch (kind) {
    case 0:
        return 3;
    case 1:
        stride = buf[22];
        if (stride != 1 && stride != 2)
            return 0;
        if (buf[34] == 16)
            stride *= 2;
        else if (buf[34] != 8)
            return 0;
        return stride;
    case 2:
        return 1;
    default:
        return 0;
    }
}

void uha_apply_forward_multimedia(uint8_t *buf, uint32_t usize)
{
    int stride, phase, shift;
    int direction[4];
    uint32_t history, i;
    uint8_t cur, delta, outb;

    stride = detect_mm_stride(buf, usize);
    if (stride <= 0)
        return;
    memset(direction, 0, sizeof(direction));
    history = 0;
    shift = stride * 8 - 8;
    for (i = 36; i < usize; i++) {
        phase = (int)(i % (uint32_t)stride);
        cur = buf[i];
        delta = (uint8_t)(cur - ((history >> shift) & 0xFFu));
        outb = direction[phase] ? (uint8_t)(-(int)delta) : delta;
        buf[i] = outb;
        if (outb >= 0x80)
            direction[phase] = !direction[phase];
        history = (history << 8) | cur;
    }
}

void uha_restore_multimedia(uint8_t *buf, uint32_t usize)
{
    int stride, phase, shift;
    int direction[4];
    uint32_t history, i;
    uint8_t raw, delta;

    stride = detect_mm_stride(buf, usize);
    if (stride <= 0)
        return;
    memset(direction, 0, sizeof(direction));
    history = 0;
    shift = stride * 8 - 8;
    for (i = 36; i < usize; i++) {
        phase = (int)(i % (uint32_t)stride);
        raw = buf[i];
        delta = raw;
        if (direction[phase])
            delta = (uint8_t)(-(int)raw);
        if (raw >= 0x80)
            direction[phase] = !direction[phase];
        buf[i] = (uint8_t)(delta + ((history >> shift) & 0xFF));
        history = (history << 8) | buf[i];
    }
}
