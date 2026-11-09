#ifndef UHA_RANGECODER_H
#define UHA_RANGECODER_H

#include <stdint.h>
#include <stddef.h>

#define UHA_RC_TOP   0x01000000u
#define UHA_RC_INIT  0xFFFFFFFFu

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
    int            exhausted;
} uha_reader;

typedef struct {
    uha_reader rd;
    uint32_t   code;
    uint32_t   range;
    int        corrupt;
} uha_rc;

void     uha_reader_init(uha_reader *r, const uint8_t *data, size_t size);
uint8_t  uha_reader_byte(uha_reader *r);

void     uha_rc_init(uha_rc *rc, const uint8_t *data, size_t size);
void     uha_rc_normalize(uha_rc *rc);
uint32_t uha_rc_threshold(uha_rc *rc, uint32_t total);
uint32_t uha_rc_fixed12(uha_rc *rc);
void     uha_rc_remove(uha_rc *rc, uint32_t low, uint32_t high);
/* [M122h] diagnostic : number of decisions rc (remove) consommees jusqu'here. */
unsigned long uha_rc_dec_count(void);
uint32_t uha_rc_uniform(uha_rc *rc, uint32_t total);
int      uha_rc_bit12_shift(uha_rc *rc, uint16_t *prob, int shift);
int      uha_rc_bit12(uha_rc *rc, uint16_t *prob);

typedef struct {
    uint64_t  low;
    uint32_t  range;
    uint8_t  *buf;
    size_t    cap;
    size_t    pos;
    uint32_t  ffnum;
    uint8_t   cache;
    int       error;
} uha_rcw;

int  uha_rcw_init(uha_rcw *w);
int  uha_rcw_encode(uha_rcw *w, uint32_t low, uint32_t high, uint32_t total);
int  uha_rcw_encode_fixed12(uha_rcw *w, uint32_t low, uint32_t high);
int  uha_rcw_flush(uha_rcw *w);
void uha_rcw_free(uha_rcw *w);

#endif /* UHA_RANGECODER_H */
