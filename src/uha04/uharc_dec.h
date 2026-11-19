#ifndef UHARC_DEC_H
#define UHARC_DEC_H

#ifdef _MSC_VER
#define UHI64 __int64
#define U64LL(x) x##UI64
#define I64LL(x) x##I64
#else
#define UHI64 long long
#define U64LL(x) x##ULL
#define I64LL(x) x##LL
#endif

typedef int (*uharc_dec_read_cb)(void *ctx, unsigned char *buf,
                                 unsigned want_len);
typedef int (*uharc_dec_write_cb)(void *ctx, const unsigned char *buf,
                                  unsigned len);

/* Core 2 (LZ78 LSB-first, methods 2..7) */
int  uharc_dec2l_init(void **pctx, int method);
int  uharc_dec2l_decode(void *ctx,
                        uharc_dec_read_cb rcb, void *rctx,
                        uharc_dec_write_cb wcb, void *wctx,
                        unsigned long out_len);
void uharc_dec2l_free(void *ctx);

/* Core 3 (0.2, methods 8..43) */
int  uharc_dec3t_init(void **pctx, int method);
int  uharc_dec3t_decode(void *ctx,
                        uharc_dec_read_cb rcb, void *rctx,
                        uharc_dec_write_cb wcb, void *wctx,
                        unsigned long out_len);
void uharc_dec3t_free(void *ctx);

/* Core 3 (LZP 0.4, methods 8..23) */
int  uharc_dec3v_init(void **pctx, int method);
int  uharc_dec3v_decode_b(void *ctx,
                          const unsigned long *cum, unsigned long ncum,
                          uharc_dec_read_cb rcb, void *rctx,
                          uharc_dec_write_cb wcb, void *wctx,
                          unsigned long out_len);
void uharc_dec3v_free(void *ctx);

/* Core 4 (PPM 0.4, methods 24..39) */
int  uharc_dec4vc_init(void **pctx, int method);
void uharc_dec4vc_set_flags2(void *ctx, unsigned char flags2);
int  uharc_dec4vc_decode_b(void *ctx,
                           const unsigned long *cum, unsigned long ncum,
                           uharc_dec_read_cb rcb, void *rctx,
                           uharc_dec_write_cb wcb, void *wctx,
                           unsigned long out_len);
void uharc_dec4vc_free(void *ctx);

/* Core 5 (ALZ 0.4, methods 40..87) */
int  uharc_dec5v_init(void **pctx, int method);
int  uharc_dec5v_decode_b(void *ctx,
                          const unsigned long *cum, unsigned long ncum,
                          uharc_dec_read_cb rcb, void *rctx,
                          uharc_dec_write_cb wcb, void *wctx,
                          unsigned long out_len);
void uharc_dec5v_free(void *ctx);

#endif /* UHARC_DEC_H */

