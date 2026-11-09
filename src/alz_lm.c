/*
 * alz_lm.c - Transcription C faithful of the decider of flush legacy 0x412c30.
 *
 * Copie EXACT (arithmetique entiere, wraps 32-bit, divisions tronquees, tables)
 * of the noyau validated by rejeu 6059/6059 in `_scratch/a5c2f/lm412c30_replay.c`
 * (function `lm_decide`). The knobs of diagnostic of the harnais (LMDBG_POS, LMVFORCE)
 * are retires : ils n'appartiennent only to the  banc of test, not au port.
 *
 * Module PUREMENT ADDITIF (voir alz_lm.h) : no effect on l'emission as long as
 * no branch (gated UHA_LMCOST default-OFF).
 */
#include <stdint.h>
#include <stdlib.h>
#include "alz_lm.h"

#define M32 0xFFFFFFFFu

/* Tables static DGROUP of the decider (dumpees au runtime ; 13.237-240).
 * The primitif of cost symbole (alz_score_cost) intervient in the computation amont
 * some fields cx/this (stream by byte), fournis already resolus au decider pur. */
#include "alz_lm_tables.inc"

/* [a5c2f-c-govern-loop] Accesseur additif : expose there table mapcls (byte->class,
 * 0x437464) for that l'encoder genere there string differee loop[] from-clone
 * (walker 0x412ded) BEFORE d'to call alz_lm_decide. without effet sure the decider. */
const uint8_t *alz_lm_mapcls_table(void)
{
    return lm_mapcls;
}

/*
 * ecx : cost-match ; esi : cost-literal ; al : decision.
 * Paths and constantes transcrits of 0x412c30..0x412f65 (spec 0x412c30_port.md).
 */
void alz_lm_decide(const lm_in *in, lm_out *o)
{
    uint32_t ecx, esi, accum = 0, q, d, e, mean, v, k, fac;
    int edi;

    /* ---- ecx : cost-match (0x412c3f..0x412d40) ---- */
    ecx = 4;
    if ((in->pend == 0 || in->dh == 1) && in->S8c > 1) {
        /* Index legacy ebx = w16 + (dh!=1 ? 0x10000 : 0) in *[0x4373e8] ; the
         * byte lu (`v`) is fourni already resolu by the walker (table primaire). */
        if (in->v == in->DL)             /* BYTE[*[0x4373e8]+ebx] == length current */
            ecx = (ecx - 1) & M32;
    }
    if (in->dh == 1) {
        accum = (in->DL * in->S8c) & M32;
        ecx = (ecx + in->bc) & M32;
        if (in->S8c >= 0x100) {
            ecx = (ecx + 1) & M32;
            if (in->S8c >= 0x10000)
                ecx = (ecx + lm_t9910[in->S8c >> 19] + 1) & M32;
        }
    } else if (in->bb != 0) {
        if (in->DL < 4) {
            ecx = (ecx - 1) & M32;
            accum = ((in->DL - 1) * in->bb) & M32;
        } else {
            accum = (in->DL * in->bb) & M32;
        }
    } else {
        ecx = (ecx - (in->DL < 5 ? 2u : 1u)) & M32;
    }
    if (accum) {
        d = 7 - in->bc;
        q = d > 0 ? (((accum << 2) & M32) / d) : 0;
        for (;;) {
            q >>= 1;
            if (q == 0)
                break;
            ecx = (ecx + 1) & M32;
        }
    }
    ecx = (ecx * 4680u) & M32;

    /* ---- esi : cost-literal (0x412d56 / 0x412e5e) ---- */
    if (in->bud >= 0x91ADC0u) {          /* budget full (never sure block0) */
        e = (in->DL * 8u) & M32;
        e = (e + in->DL) & M32;
        e = (e << 6) & M32;
        esi = ((e << 6) + e) & M32;      /* 37440 * DL */
    } else if (in->shortcut) {
        esi = (((in->bud >> 8) * in->DL) & M32);
    } else {
        uint32_t n = in->key - in->off;
        if (n == 0) {
            esi = (((in->bud >> 8) * in->DL) & M32);
        } else {
            mean = in->sm / n;
            if (mean < 0x1248) {
                esi = (mean * in->DL) & M32;
            } else {
                v = ((mean + (in->bud >> 8)) & M32) / 0x1248u;
                k = (in->bud >> 5) / (mean + 1);
                fac = (lm_t9714[v & 63u] + k + 0x3Bu) & M32;
                esi = ((((mean * fac) & M32) >> 6) * in->DL) & M32;
            }
        }
    }

    /* ---- costs model fournis + decision (0x412d70..0x412dd9) ---- */
    ecx = (ecx + in->cx) & M32;
    esi = (esi + in->ce) & M32;
    {
        static int s_lmbias = -1;
        static int s_bias_val = 0;
        static int s_bias_lim = -1;
        static int s_bias_dl = 0;
        if (s_lmbias < 0) {
            const char *b = getenv("UHA_LM_BIAS");
            s_lmbias = b ? 1 : 0;
            if (s_lmbias) s_bias_val = atoi(b);
            const char *bl = getenv("UHA_LM_BIAS_LIM");
            s_bias_lim = bl ? atoi(bl) : -1;
            const char *bdl = getenv("UHA_LM_BIAS_DL");
            s_bias_dl = bdl ? atoi(bdl) : 0;
        }
        if (s_lmbias) {
            if (s_bias_lim < 0 || (int)in->off < s_bias_lim) {
                uint32_t bval = (uint32_t)s_bias_val;
                if (s_bias_dl) bval = (uint32_t)(s_bias_val * (int)in->DL);
                esi = (esi + bval) & M32;
            }
        }
    }
    o->ecx = ecx;
    o->esi = esi;
    if (ecx < esi) {
        o->al = 1;
        return;
    }
    /* ---- loop differee sure the remainder of the run (0x412ded) ---- */
    edi = (int)in->DL - 1;
    {
        int i;
        uint32_t esiD = esi;
        for (i = 0; i < in->nloop; i++) {
            uint32_t c2 = in->loop[i].c2;
            if (in->loop[i].cls == 0) {  /* 0x412f46 : al = ecx < esi + m*edi */
                o->al = (ecx < ((esiD + c2 * (uint32_t)edi) & M32)) ? 1 : 0;
                return;
            }
            esiD = (esiD + c2) & M32;
            if (ecx < esiD) {            /* 0x412f5a : mov al,1 ; ret */
                o->al = 1;
                return;
            }
            if (--edi == 0)
                break;
        }
        o->al = (ecx < esiD) ? 1 : 0;    /* 0x412e4f : setb */
    }
}
