/*
 * alz_lm.c — Transcription C fidèle du décideur de flush legacy 0x412c30.
 *
 * Copie EXACTE (arithmétique entière, wraps 32-bit, divisions tronquées, tables)
 * du noyau validé par rejeu 6059/6059 dans `_scratch/a5c2f/lm412c30_replay.c`
 * (fonction `lm_decide`). Les knobs de diagnostic du harnais (LMDBG_POS, LMVFORCE)
 * sont retirés : ils n'appartiennent qu'au banc de test, pas au port.
 *
 * Module PUREMENT ADDITIF (voir alz_lm.h) : aucun effet sur l'émission tant que
 * non branché (gated UHA_LMCOST défaut-OFF).
 */
#include <stdint.h>
#include <stdio.h>
#include "alz_lm.h"

#define M32 0xFFFFFFFFu

/* Tables statiques DGROUP du decideur (dumpées au runtime ; §13.237-240).
 * Le primitif de coût symbole (alz_score_cost) intervient dans le calcul amont
 * des champs cx/ce (flux par octet), fournis déjà résolus au décideur pur. */
#include "alz_lm_tables.inc"

/* [a5c2f-c-govern-loop] Accesseur additif : expose la table mapcls (byte->classe,
 * 0x437464) pour que l'encodeur genere la chaine differee loop[] from-clone
 * (walker 0x412ded) AVANT d'appeler alz_lm_decide. Sans effet sur le decideur. */
const uint8_t *alz_lm_mapcls_table(void)
{
    return lm_mapcls;
}

/*
 * ecx : coût-match ; esi : coût-littéral ; al : décision.
 * Chemins et constantes transcrits de 0x412c30..0x412f65 (spec 0x412c30_port.md).
 */
void alz_lm_decide(const lm_in *in, lm_out *o)
{
    uint32_t ecx, esi, accum = 0, q, d, e, mean, v, k, fac;
    int edi;

    /* ---- ecx : coût-match (0x412c3f..0x412d40) ---- */
    ecx = 4;
    if ((in->pend == 0 || in->dh == 1) && in->S8c > 1) {
        /* Index legacy ebx = w16 + (dh!=1 ? 0x10000 : 0) dans *[0x4373e8] ; le
         * byte lu (`v`) est fourni déjà résolu par le walker (table primaire). */
        if (in->v == in->DL)             /* BYTE[*[0x4373e8]+ebx] == longueur courante */
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

    /* ---- esi : coût-littéral (0x412d56 / 0x412e5e) ---- */
    if (in->bud >= 0x91ADC0u) {          /* budget plein (jamais sur block0) */
        e = (in->DL * 8u) & M32;
        e = (e + in->DL) & M32;
        e = (e << 6) & M32;
        esi = ((e << 6) + e) & M32;      /* 37440 * DL */
    } else if (in->shortcut) {
        esi = (((in->bud >> 8) * in->DL) & M32);
    } else {
        uint32_t n = (in->key > in->off) ? (in->key - in->off) : 0u;
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

    /* ---- coûts modèle fournis + décision (0x412d70..0x412dd9) ---- */
    ecx = (ecx + in->cx) & M32;
    esi = (esi + in->ce) & M32;
    o->ecx = ecx;
    o->esi = esi;
    if (ecx < esi) {
        o->al = 1;
        return;
    }
    /* ---- boucle différée sur le reste du run (0x412ded) ---- */
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
            edi--;
            if (edi <= 0) break;
        }
        o->al = (ecx < esiD) ? 1 : 0;    /* 0x412e4f : setb */
    }
}
