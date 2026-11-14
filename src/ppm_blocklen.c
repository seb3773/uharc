/* ppm_blocklen.c - M169 : transcription faithful of 0x422890 (length of block of class, -mx)
 *
 * Source : agent_capture/full.asm l. 39860..40261. Detail : OUT/m169_blocklen.md.
 *
 * Structure (3 subtilites has not NOT "simplifier") :
 *   S1  l'index of retrait of g is GLISSANT : (pos + 0x400) & 0x7ff. L'ASM keeps this pointer
 *       in [esp+0xc] (init 0xc00, `and 0x7ff` -> 0x400) and l'incremente of 1 at each position
 *       (0x422ccd / 0x422cd3). The to read fixe produces has false positif sure 6/6 files towards pos~2500.
 *   S2  loop 1 (window [0,0x400)) not soustrait the residu that if k >= cls (0x422958) ;
 *       loop 2 (window [0x400,0x800)) soustrait as soon as cls != 0, without tester k >= cls (0x422a2f).
 *   S3  ring d of 0x800 by class (stride 0x800) : loop 1 fills d[0..0x3ff],
 *       loop 2 fills d[0x400..0x7ff], the scan reecrit d[pos & 0x7ff].
 *
 * Arithmetique : uint32 (module 2^32), comparaisons NO signees, argmax has strict superiorite.
 * bound of the scan : pos = 0x800 .. len INCLUS (slice by there GT t5 5/5 sure mixed block 1).
 */
#include "ppm_blocklen.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* [M170b] Mode HARNAIS (default OFF, no effect on the build) : when il is active, the
 * scan not s'stops NEVER sure has changement and va up to len, en tenant `cur` has jour
 * as the does the path "no changement" of l'ASM (0x422cdb : cur = bestA, on
 * continue). But : obtenir notre t5 of END of scan for the to compare at the GT legacy
 * ([0x4803a4] relu au hit next) when there decision of cut, elle, diverge. */
static int pbl_nocut;

/* [M170b] Restore of the version M169 (before corrections mesurees) for l'Has/B. */
static int pbl_v1;

void ppm_blocklen_set_nocut(int on)
{
    pbl_nocut = on ? 1 : 0;
}

void ppm_blocklen_set_v1(int on)
{
    pbl_v1 = on ? 1 : 0;
}

void ppm_blocklen_init(ppm_blocklen_ctx *c)
{
    if (!c)
        return;
    memset(c, 0, sizeof(*c));
}

void ppm_blocklen_roll(ppm_blocklen_ctx *c)
{
    int i;

    if (!c)
        return;
    /* 0x421c85 : rep movs 20 bytes 0x4803a4 -> 0x480390.
     * [M170b] Measures M170 : `[0x480390..] = [10882 255380 153928 111602]` au hit next
     * sure image.raw = nos values of LOOP 2 (t5), therefore **0x480390 = loop 2** and
     * **0x4803a4 = loop 1**. The roulage va therefore of notre `t` (loop 1) towards notre `t5`
     * (loop 2), at the inverse of the version M169. */
    /* [M274/M278, UHA_PBLROLL, PROMU default 1 = direction ASM] DIRECTION OF THE ROULAGE.
     * ASM `0x421c5b..0x421c93` : `esi = 0x4803a4` (source), `edi = 0x480390` (destination),
     * `rep movs` 20 bytes => **t (0x480390) <- t5 (0x4803a4)** at each cut. The default of the
     * port does l'INVERSE (`t5 = t`), this which overwrites the resultat of the scan `0x422890` by has
     * table perime : at the cut `start = 937 440` (1re divergence of the corps, `firstdiv =
     * 178 540`) the port affiche `t == t5 == [6662 7020 7570 6844 7428]` then that there value
     * issue of the scan previous was `[4978 5066 4970 5046 5172]`. `=1` applies the direction ASM. */
    for (i = 0; i < PBL_NCLS; i++)
        c->t[i] = c->t5[i];
}

uint32_t ppm_blocklen(ppm_blocklen_ctx *c, const uint8_t *window, uint32_t len)
{
    uint32_t pos, k, i, ia_ = 0, ib_ = 0;
    int cls, bestA, bestB, j;
    const uint32_t *ta, *tb;
    uint8_t cur, newv, old, v, addv = 0;
    uint32_t fo, fn, gv, gn;

    if (!c || !window)
        return len;

    /* 0x4228a8 : cmp edx,0x800 ; ja ... otherwise returns len */
    if (len <= PBL_MINLEN)
        return len;

    /* memset t, t5, f, g (0x4228c5..0x42290f). d (0x464b10) n'is NOT remis has zero
     * by the legacy engine, but the two loops the reecrivent entierement. */
    memset(c->t, 0, sizeof(c->t));
    memset(c->t5, 0, sizeof(c->t5));
    memset(c->f, 0, sizeof(c->f));
    memset(c->g, 0, sizeof(c->g));

    /* --- loop 1 : window [0, 0x400) -> f and t (test k >= cls) --- */
    for (cls = 0; cls < PBL_NCLS; cls++) {
        uint32_t *fc = c->f[cls];
        uint8_t *dc = c->d[cls];
        uint32_t acc = 0;

        for (k = 0; k < 0x400u; k++) {
            uint8_t dv = window[k];
            /* [M170b] EXPERIENCE : no soustraction for cls = 0 (otherwise t[0] = 1024^2
             * overwrites l'argmax and forbids all "no changement"). */
            if (cls && k >= (uint32_t)cls)
                dv = (uint8_t)(dv - window[k - cls]);
            dc[k] = dv;
            fc[dv]++;
        }
        for (j = 0; j < 256; j++)
            acc += fc[j] * fc[j];
        c->t[cls] = acc;
    }

    /* --- loop 2 : window [0x400, 0x800) -> g and t5 (no test k >= cls : S2) --- */
    for (cls = 0; cls < PBL_NCLS; cls++) {
        uint32_t *gc = c->g[cls];
        uint8_t *dc = c->d[cls];
        uint32_t acc = 0;

        for (k = 0; k < 0x400u; k++) {
            uint8_t dv = window[0x400u + k];
            if (cls)
                dv = (uint8_t)(dv - window[0x400u + k - (uint32_t)cls]);
            dc[0x400u + k] = dv;
            gc[dv]++;
        }
        for (j = 0; j < 256; j++)
            acc += gc[j] * gc[j];
        c->t5[cls] = acc;
    }

    cur = c->cur;

    /* [M274e, GATED UHA_PBL_F2048, default-OFF] L'INIT OF `f` COUVRE-T-ELLE 2048 POSITIONS ?
     * `t` (0x480390) is has window **2048**, `t5` (0x4803a4) has window **1024** ; but there
     * pass 1 not fills `f` that sure [0, 0x400) (1024). if the master counts `f` sure all l'ring
     * `d` [0, 0x800), the first retraits of the loop glissante portent at nous sure some
     * cellules NEVER incrementees : `fo = 0` -> `fc = 0-1 = 0xFFFFFFFF` -> `t` explose.
     * Signature mesuree (`work/t171_blk_gt`) : `t` = +1606 has +2458 (+35 %) then that `t5` is
     * presque juste. `=1` recalcule `f` (and `t`) sure `d[0..0x800)` after there pass 2. */
    for (pos = 0x800u; pbl_v1 ? (pos <= len) : (pos < len); pos++) {
        uint8_t w0 = window[pos];
        i = pos & (PBL_RING - 1u);
        ia_ = i;
        ib_ = (uint32_t)((i + 0x400u) & (PBL_RING - 1u));

        for (cls = 0; cls < PBL_NCLS; cls++) {
            uint32_t *fc = c->f[cls];
            uint32_t *gc = c->g[cls];
            uint8_t *dc = c->d[cls];

            old = dc[ia_];
            fo = fc[old];
            c->t[cls] -= (2u * fo - 1u);
            fc[old] = fo - 1u;

            newv = w0;
            if (cls)
                newv = (uint8_t)(w0 - window[pos - (uint32_t)cls]);
            addv = dc[ib_];
            fn = fc[addv];
            c->t[cls] += (2u * fn + 1u);
            fc[addv] = fn + 1u;

            v = dc[ib_];
            gv = gc[v];
            c->t5[cls] -= (2u * gv - 1u);
            gc[v] = gv - 1u;

            dc[i] = newv;

            gn = gc[newv];
            c->t5[cls] += (2u * gn + 1u);
            gc[newv] = gn + 1u;
        }

        /* [M170b] Mapper MEASURES some two tables : l'argmax `bestA` reads 0x480390 (= notre
         * loop 2, t5) and `bestB` reads 0x4803a4 (= notre loop 1, t). L'old mapper
         * (M169 : bestA sure t, bestB sure t5) is disponible via ppm_blocklen_set_v1(1). */
        ta = pbl_v1 ? c->t5 : c->t;
        tb = pbl_v1 ? c->t : c->t5;

        /* argmax no signe sure 0..4, init 0, strict superiorite */
        bestA = 0;
        bestB = 0;
        for (j = 1; j < PBL_NCLS; j++) {
            if (ta[j] > ta[bestA])
                bestA = j;
            if (tb[j] > tb[bestB])
                bestB = j;
        }

        /* keeps-fou of confiance 4/3 : 0x422c53..0x422ca7 */
        if (bestA != (int)cur && 3u * ta[bestA] < 4u * ta[cur])
            bestA = (int)cur;
        if (bestB != (int)cur && 3u * tb[bestB] < 4u * tb[cur])
            bestB = (int)cur;

#ifdef PBL_TRACE
        if (pos <= 0x803u)
            fprintf(stderr, "[PBL] AP  pos=%u cur=%d bestA=%d bestB=%d a1=[%u %u %u %u %u] a2=[%u %u %u %u %u]\n",
                    pos, (int)cur, bestA, bestB,
                    ta[0], ta[1], ta[2], ta[3], ta[4],
                    tb[0], tb[1], tb[2], tb[3], tb[4]);
#endif
        if (bestA != bestB && !pbl_nocut) {
#ifdef PBL_TRACE
            fprintf(stderr, "[PBL] pos=%u cur=%d bestA=%d bestB=%d ta=[%u %u %u %u %u] tb=[%u %u %u %u %u]\n",
                    pos, (int)cur, bestA, bestB,
                    ta[0], ta[1], ta[2], ta[3], ta[4],
                    tb[0], tb[1], tb[2], tb[3], tb[4]);
#endif
            c->cur = (uint8_t)bestA;
            return pos - 0x200u;
        }
        cur = (uint8_t)bestA;
        c->cur = cur;
    }

    return len;
}
