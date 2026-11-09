/*
 * alz_lm.h - Decider of flush legacy 0x412c30 (reads<->match) of UHARC 0.6b.
 *
 * Transcription C FAITHFUL validated by rejeu 6059/6059 (ecx/esi/al) sure there captures
 * live `_scratch/a5t8cap/c30e.tsv` (13.237) and by the harnais standalone
 * `_scratch/a5c2f/lm412c30_replay.c`. Spec complete : `_scratch/a5c2f/0x412c30_port.md`.
 *
 * STATUT : module PUREMENT ADDITIF. So much qu'no site d'call n'is branch in
 * l'encoder (gated UHA_LMCOST, default-OFF), this code n'has no effect on l'emission
 * standard (baselines 7049 / 7038 / 7002 garanties).
 */
#ifndef UHA_ALZ_LM_H
#define UHA_ALZ_LM_H

#include <stdint.h>

/*
 * Inputs of the decider. Chacune has has derivation from-scratch FERMEE side clone
 * (voir _scratch/a5c2f/state_map.md) :
 *   arg = alz_token_class_index_ro ; DL/DH/dh/bb/bc/S8c = scalaires of the candidate
 *   (finder + recent[] + mode) ; pend = st.repeat_run (0 sure block0) ; bud/off/key/sm
 *   = flot by byte (ring 256 + table densite) ; w16 = LE16(plain[pos..]) ;
 *   v = table primaire " length of the last match emis sure the context order-2 " ;
 *   cx/this = costs model sym/escape via token_class + alz_score_cost ;
 *   loop[] = chain differee (cls,c2) of the remainder of run (0x412ded).
 */
typedef struct {
    uint32_t arg, DL, DH, dh, bb, bc, S8c, pend, bud;
    uint32_t w16, v;
    uint32_t off, key, sm;
    int      shortcut;      /* sc : path (bud>>8)*DL pris before there loop densite */
    uint32_t cx, ce;        /* costs model fournis (symbole, escape) */
    int      nloop;
    struct { int cls; uint32_t c2; } loop[64];
} lm_in;

typedef struct { uint32_t ecx, esi; int al; } lm_out;

/*
 * Decider pur (without side effect) : ecx=cost-match, esi=cost-literal,
 * al = (ecx<esi) after prise en counts of the loop differee. Reproduces
 * byte-for-byte there logique of 0x412c30 (wraps 32-bit, divisions tronquees,
 * tables static). al!=0 => emets the MATCH ; al==0 => literal.
 */
void alz_lm_decide(const lm_in *in, lm_out *o);

/*
 * Table `v` primaire au context current w16 - mirror strict of legacy 0x412c0a
 * (validated 6059/6059 from-scratch, 13.240 / val_v.py) :
 *   lookup(during of has decision)      = tab[w16 + (dh!=1 ? 0x10000 : 0)]
 *   at each EMISSION of has match     : tab[w16_emit + (dh_emit!=1 ? 0x10000 : 0)] = DL_emit
 * Initialisee has 0. DISTINCTE of m_len_pred (the one-ci is au context SOURCE posdist,
 * sert the model of length ; `v` sert there DECISION of flush au context current).
 * Size 0x20000 (w16<0x10000, +0x10000 if dh!=1).
 */
#define LM_V_CTXSIZE 0x20000u
static inline uint32_t alz_lm_v_ctx(uint32_t w16, uint32_t dh)
{
    return w16 + (dh != 1 ? 0x10000u : 0u);
}
static inline uint32_t alz_lm_v_get(const uint8_t *vtab, uint32_t w16, uint32_t dh)
{
    return vtab[alz_lm_v_ctx(w16, dh)];
}
static inline void alz_lm_v_put(uint8_t *vtab, uint32_t w16, uint32_t dh, uint32_t DL)
{
    vtab[alz_lm_v_ctx(w16, dh)] = (uint8_t)DL;
}

/*
 * [a5c2f-c-govern-loop] Table `mapcls` (byte->class, 256 u8, legacy 0x437464)
 * servant has generer there string differee loop[] (walker 0x412ded) from-clone :
 * at each `pos`, there class of the byte previous `b` is `cls = mapcls[b]`, there
 * next `b = cls`, up to `cls==0` (terminaison) now epuisement of `DL-1`.
 * L'accesseur avoids of dupliquer there table ; without effet sure the decider pur.
 */
const uint8_t *alz_lm_mapcls_table(void);

#endif /* UHA_ALZ_LM_H */
