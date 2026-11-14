#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ppm_priv.h"
#include "ppm_tables.h"

#include "ppm_detr_fwd_tables.inc"

/* M162 - TRANSFORMEE `detr` ALLER of legacy (bytes -> symboles), transcription
 * strict of the site encoder 0x420c20..0x421146 of UHARC.EXE (reference DGROUP,
 * journal DUAL_INTEGRATION M122n for the VA).
 *
 * the legacy engine n'uses NOT DetrClass here : for each first byte il parcourt
 * `g_detr_cand[(b-97)*16 .. +g_detr_nb[b]]`, liste ORDONNEE of classes, and takes
 * the first candidate whose there string (stockee NIEE in the PE) correspond -
 * therefore " first match ", NOT " more long match ".
 *
 * Three codes without byte clean :
 *   0x63  capitalisation : sets flag=0x20 and arg = b+0x20 ; the tour next not
 *         reads no byte, il searches the candidates for `arg` (minuscule) and
 *         consumes len(string)-1 bytes ;
 *   0x60  "\n"   if l'byte next is of class 2 (minuscule) ;
 *   0x61/0x62 "\r\n" / "\r\n " (same tables that the fins of line Windows).
 *
 * Measures (judge `an_m162_forward_gt.py`, GT = symboles reels of legacy lus en
 * decodant ses archives -mx) : 618873/618873 nodes sure the corpus complete.
 *
 * `thr2` = end of transformee (= size of the member side encoder, as
 * m->detr_thr2) : au-dela, l'byte is emis raw (uses surtout by bc=1).
 */
int ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                     uint8_t *out, uint32_t *nout)
{
    uint32_t pos = 0, n = 0;
    int pending = -1;

    if (!in || !out || !nout)
        return 0;
    *nout = 0;

    while (pos < len || pending >= 0) {
        int reuse = (pending >= 0);
        uint32_t b = reuse ? (uint32_t)pending : (uint32_t)in[pos];
        /* `count` = bytes already LUS legacy side (0x483fd4) : incremente some there
         * reading (0x420dec), therefore pos+1 ; en mode `reuse` nothing n'is lu. */
        uint32_t count = reuse ? pos : pos + 1;
        int cls = -1;

        if (reuse)
            pending = -1;

        if (count >= thr2) {
            out[n++] = (uint8_t)~b;
            pos += 1;
            continue;
        }

        if (b == 0x20) {
            uint32_t nsp = 1;
            while (nsp < 32 && pos + nsp < len && in[pos + nsp] == 0x20)
                nsp++;
            if (nsp == 1)
                cls = -1;               /* has single espace : literal */
            else if (nsp >= 32)
                cls = 0;                /* class 32 espaces */
            else
                cls = (int)(17 - nsp);
        } else if (g_detr_nb[b] != 0 && thr2 - count >= 4) {
            uint32_t off = reuse ? pos : pos + 1;
            const uint8_t *cands = g_detr_cand + (uint32_t)(b - 97) * 16;
            uint32_t i, nb = g_detr_nb[b];
            for (i = 0; i < nb; i++) {
                uint32_t c = cands[i];
                uint32_t sl = DetrStrLen[c], j, ok = 1;
                for (j = 1; j < sl; j++) {
                    uint32_t k = off + (j - 1);
                    if (k >= len ||
                        (uint8_t)~DetrStrData[DetrStrOff[c] + j] != in[k]) {
                        ok = 0;
                        break;
                    }
                }
                if (ok && sl >= 1) {
                    cls = (int)c;
                    break;
                }
            }
        } else if (b == 0x0A && pos + 1 < len) {
            if (g_detr_case[in[pos + 1]] == 2)
                cls = 0x60;
        } else if (b == 0x0D && pos + 2 < len && in[pos + 1] == 0x0A) {
            if (g_detr_case[in[pos + 2]] == 2)
                cls = 0x61;
            else if (in[pos + 2] == 0x20 && pos + 3 < len && in[pos + 3] != 0x20)
                cls = 0x62;
        } else if (g_detr_case[b] == 1 && pos + 1 < len &&
                   g_detr_case[in[pos + 1]] == 2) {
            cls = 0x63;
        }

        if (cls < 0) {
            out[n++] = (uint8_t)~b;
            /* En mode `reuse` l'byte has ALREADY ete consumes by the 0x63 : the
             * curseur d'input not moves not, single there output advances d'1. */
            pos += reuse ? 0u : 1u;
        } else if (cls == 0x63) {
            out[n++] = (uint8_t)~g_detr_dl[0x63];
            pos += 1;
            pending = (int)((b + 0x20) & 0xFFu);
        } else {
            uint32_t sl = DetrStrLen[cls];
            out[n++] = (uint8_t)~g_detr_dl[cls];
            if (reuse) {
                if (sl == 0)
                    sl = 1;
                pos += sl - 1;
            } else {
                pos += sl ? sl : 1;
            }
        }
    }

    *nout = n;
    return 1;
}
