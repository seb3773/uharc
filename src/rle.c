#include "rle.h"

#include <stdlib.h>
#include <string.h>

static int rle_buf_reserve(uint8_t **buf, size_t *cap, size_t needed)
{
    if (*cap < needed) {
        size_t nc = *cap ? *cap * 2 : 256;
        while (nc < needed)
            nc *= 2;
        uint8_t *p = (uint8_t *)realloc(*buf, nc);
        if (!p)
            return -1;
        *buf = p;
        *cap = nc;
    }
    return 0;
}

int uha_rle_encode(const uint8_t *in, size_t in_len,
                   uint8_t **out, size_t *out_len)
{
    if (!out || !out_len)
        return -2;
    *out = NULL;
    *out_len = 0;
    if (in_len == 0) {
        *out = (uint8_t *)malloc(1);
        if (!*out)
            return -4;
        (*out)[0] = 0;
        *out_len = 0;
        return 0;
    }
    if (!in)
        return -2;

    size_t cap = in_len + 64;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf)
        return -4;

    size_t len = 0;
    uint8_t bl = 0xED;
    size_t i = 0;

    while (i < in_len) {
        size_t j = i + 1;
        while (j < in_len && in[j] == in[i])
            j++;
        size_t count = j - i;
        uint8_t b = in[i];

        while (count > 65535) {
            uint8_t esc_tag = (uint8_t)((bl + 1) & 0xFF);
            if (rle_buf_reserve(&buf, &cap, len + 5) != 0) {
                free(buf);
                return -4;
            }
            buf[len++] = esc_tag;
            buf[len++] = 0xFF;
            buf[len++] = 0xFF;
            buf[len++] = 0xFF;
            buf[len++] = b;
            count -= 65535;
        }

        uint8_t esc_b = bl;
        uint8_t esc_tag = (uint8_t)((bl + 1) & 0xFF);

        if (b == esc_b) {
            if (count == 1) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0x00;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (count == 2) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0x02;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (count == 3) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_b;
                buf[len++] = esc_b;
            } else if (count <= 254) {
                if (rle_buf_reserve(&buf, &cap, len + 3) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = (uint8_t)count;
                buf[len++] = esc_b;
            } else {
                if (rle_buf_reserve(&buf, &cap, len + 5) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0xFF;
                buf[len++] = (uint8_t)(count & 0xFF);
                buf[len++] = (uint8_t)((count >> 8) & 0xFF);
                buf[len++] = esc_b;
            }
        } else if (b == esc_tag) {
            if (count == 1) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0x01;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (count == 2) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0x03;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (count == 3) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_b;
                buf[len++] = esc_tag;
            } else if (count <= 254) {
                if (rle_buf_reserve(&buf, &cap, len + 3) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = (uint8_t)count;
                buf[len++] = esc_tag;
            } else {
                if (rle_buf_reserve(&buf, &cap, len + 5) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0xFF;
                buf[len++] = (uint8_t)(count & 0xFF);
                buf[len++] = (uint8_t)((count >> 8) & 0xFF);
                buf[len++] = esc_tag;
            }
        } else {
            if (count == 1) {
                if (rle_buf_reserve(&buf, &cap, len + 1) != 0) { free(buf); return -4; }
                buf[len++] = b;
            } else if (count == 2) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = b;
                buf[len++] = b;
            } else if (count == 3) {
                if (rle_buf_reserve(&buf, &cap, len + 2) != 0) { free(buf); return -4; }
                buf[len++] = esc_b;
                buf[len++] = b;
            } else if (count <= 254) {
                if (rle_buf_reserve(&buf, &cap, len + 3) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = (uint8_t)count;
                buf[len++] = b;
            } else {
                if (rle_buf_reserve(&buf, &cap, len + 5) != 0) { free(buf); return -4; }
                buf[len++] = esc_tag;
                buf[len++] = 0xFF;
                buf[len++] = (uint8_t)(count & 0xFF);
                buf[len++] = (uint8_t)((count >> 8) & 0xFF);
                buf[len++] = b;
            }
        }
        i = j;
    }

    *out = buf;
    *out_len = len;
    return 0;
}

int uha_rle_decode(const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_len)
{
    if (out_len == 0)
        return 0;
    if (!in || !out)
        return -2;

    uint8_t bl = 0xED;
    size_t ip = 0;
    size_t op = 0;

    while (ip < in_len && op < out_len) {
        uint8_t b = in[ip++];
        uint8_t esc_b = bl;
        uint8_t esc_tag = (uint8_t)((bl + 1) & 0xFF);

        if (b == esc_tag) {
            if (ip >= in_len)
                return -1;
            uint8_t c = in[ip++];
            if (c == 0x00) {
                out[op++] = esc_b;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (c == 0x01) {
                out[op++] = esc_tag;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (c == 0x02) {
                if (op + 2 > out_len) return -1;
                out[op++] = esc_b;
                out[op++] = esc_b;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (c == 0x03) {
                if (op + 2 > out_len) return -1;
                out[op++] = esc_tag;
                out[op++] = esc_tag;
                bl = (uint8_t)((bl - 0x40) & 0xFF);
            } else if (c == 0xFF) {
                if (ip + 3 > in_len) return -1;
                size_t cnt = (size_t)in[ip] | ((size_t)in[ip + 1] << 8);
                uint8_t val = in[ip + 2];
                ip += 3;
                if (op + cnt > out_len) return -1;
                memset(out + op, val, cnt);
                op += cnt;
            } else {
                if (ip >= in_len) return -1;
                uint8_t val = in[ip++];
                if (op + c > out_len) return -1;
                memset(out + op, val, c);
                op += c;
            }
        } else if (b == esc_b) {
            if (ip >= in_len) return -1;
            uint8_t val = in[ip++];
            if (op + 3 > out_len) return -1;
            out[op++] = val;
            out[op++] = val;
            out[op++] = val;
        } else {
            out[op++] = b;
        }
    }

    if (op != out_len)
        return -1;
    return 0;
}

