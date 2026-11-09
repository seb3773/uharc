/* ppm_blocklen.h - M169 : length of block of class (mx), transcription of 0x422890
 *
 * NO BRANCH by default : no file of the build not l'inclut still (compilation
 * manuelle / harnais t169_blocklen). Voir OUT/m169_blocklen.md.
 *
 * State = the one of legacy :
 *   t  (5 x u32) = 0x480390   Sigma f^2, window 2048 positions
 *   t5 (5 x u32) = 0x4803a4   Sigma g^2, window 1024 positions
 *   D  (5 x 0x800 u8) = 0x464b10   ring some residus (has by class, stride 0x800)
 *   cur (u8) = 0x48392c       class current
 * f (0x467310) and g (0x468728) = 5 x 256 u32 chacun, remis has zero at each call
 * if len > 0x800 (memset 0x1400 = 5 x 0x400 bytes).
 */
#ifndef PPM_BLOCKLEN_H
#define PPM_BLOCKLEN_H

#include <stdint.h>

#define PBL_NCLS   5
#define PBL_RING   0x800u
#define PBL_MINLEN 0x800u

typedef struct {
    uint32_t f[PBL_NCLS][256];      /* 0x467310 */
    uint32_t g[PBL_NCLS][256];      /* 0x468728 */
    uint8_t  d[PBL_NCLS][PBL_RING]; /* 0x464b10 */
    uint32_t t[PBL_NCLS];           /* 0x480390 */
    uint32_t t5[PBL_NCLS];          /* 0x4803a4 */
    uint8_t  cur;                   /* 0x48392c */
} ppm_blocklen_ctx;

/* remise has zero of l'state (equivalent .bss : t, t5, cur, t as au demarrage) */
void ppm_blocklen_init(ppm_blocklen_ctx *c);

/* roulage 0x421c85 (rep movs of 20 o) : t[0..4] <- t5[0..4].
 * Has to call BEFORE ppm_blocklen, at each frontier of block. */
void ppm_blocklen_roll(ppm_blocklen_ctx *c);

/* 0x422890(window, len) : updates t/t5/cur and returns there length of block :
 *   len <= 0x800            -> len (no scan)
 *   no changement        -> len
 *   changement at the position pos -> pos - 0x200
 * `window` pointe sure the DATA RAW of the file (not the symboles detr),
 * and doit to be lisible up to window[len] inclus. */
uint32_t ppm_blocklen(ppm_blocklen_ctx *c, const uint8_t *window, uint32_t len);

/* [M170b] HARNAIS only (default OFF) : desactive there output sure changement for
 * observer the t5 of end of scan (comparaison at the GT legacy). no effect if no appele. */
void ppm_blocklen_set_nocut(int on);

/* bound of the scan : the legacy engine traite pos = 0x800 .. len INCLUS (cf. OUT/m169_blocklen.md
 * section 5bis, slice by there GT t5 5/5 sure mixed block 1). */
#endif /* PPM_BLOCKLEN_H */
