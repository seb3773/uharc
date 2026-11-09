/*
 * ppm_blk_cost.c - [M170g, ISOLAT, NO-WIRE] scan of cost cumule `ebp` (`0x422d00..0x423245`).
 *
 * Transcription line has line ; each term porte son address legacy.
 * Law amont : OUT/m170g_arenafeed.md (arena live + feed) ; geometrie : OUT/m170e_costscan.md.
 *
 * THIS WHICH is PORTE HERE (and nothing d'other) :
 *   0x42302d..0x423061  extraction of the symbole (historique d'arena for it < 0x100, block ensuite)
 *   0x423063..0x42306e  toggles of the flag of signe when |delta| >= 0x80
 *   0x423073..0x4230c7  cellule freq / total / extra (extra indexe by ctx ABSOLU)
 *   0x4230c7..0x42312b  branch COLD (term prior + term escape)
 *   0x42312e..0x423156  term principal + output anticipee if ebp > budget
 *   0x4231bd..0x4231dd  writing freq/total + rescale `0x422100` if total >= 0x4000
 *   0x423199            verdict : ebp >= budget -> al = 0 (cancels)
 * THIS WHICH N'is NOT PORTE (declare, not devine) :
 *   0x4231e2 call 0x423650  and  0x42321a call 0x4232a0  (machine of context + last byte)
 *   -> fournis by the callback `in->step` ; without lui there sequence is FIGEE (tests structurels).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "selclk.h"
#include <stdlib.h>
#include <string.h>

#include "ppm_blk_cost.h"

/* [M314, GATED UHA_PPM_FAMADV, default-OFF, no emissif] Machine d'avancement of the walk of
 * family : 0x4231ea call 0x423650 (maj some three registres of descente of context) then
 * 0x42321a call 0x4232a0 (new ctx_abs = base(class) + depth). Law and constantes
 * EXTRACTED and assertees sure the binary (OUT/m308b_hash_loi.md, OUT/m308b_tab_hash.tsv) :
 *   h70 = (h70<<8)+delta ; h74/h78 = (h<<8)+|int8(delta)>>n ; cls 8/9 not maj THAT h70 ;
 *   selection cls<7 : off = h70==0?1:h74==0?2:h78==0?3:0, base 745(cls5)/749 ;
 *   cls7 : off{0,2,4,6} sure phase+753 ; cls8 : h70==0?763:phase+761 ; cls>=9 : h70==0?768:phase+764 ;
 *   phase = (pos+1) % CTXSZ[cls] ; 0x4232a0 resets [0x483932](flag)=0 ; cls5 and cls7 do [0x48392F]+=0x80.
 * The judge is t204_front_judge.py sure the TWO walks + t205 vs M307, without regresser l'in-stream.
 *state LOCAL at the walk (the hashs of the master are global .bss ; this milestone the initialise has 0 and
 * measures l'gap) ; =0 => behavior inchange (controler). */
static int famadv_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_FAMADV"); v = e ? (e[0] != '0') : 1; }
    return v;
}
/* [M417/M423, GATED UHA_M417DBG, default-OFF, NO EMISSIF] see ppm_encode.c. */
static int m417dbg_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_M417DBG"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
/* [M432 V-1a, GATED UHA_PPM_HASHINIT, default-OFF, no emissif] value D'INIT some three hashes of
 * context. MEASURES #1 (OUT/m430_integrite_validation_m399.md Has.2/Has.7) : the master re-initialise
 * l'enregistrement in 0x423250 (appelee at the ARMEMENT, 0x417d17 sure class > 4 lue of the stream, and au
 * DESACCORD of class, 0x42300b) : raz 0 via 0x423264 call 0x40e3f0 sure [0x462cd0 .. +0x1e40]
 * (the callee diffuse dl = 0 ; the ecx = 0xffffffff of the site n'is only to  registre saves), then
 * 0x423270 mov [0x462cd8],2 and 0x423276..0x423290 which sets 0xffffffff sure S[0x70], S[0x74],
 * S[0x78] some FOUR enregistrements (0x464910 + 0x7c*k, k = 1..4).
 * Now the test of " hash empty " is == 0 (0x423549 test ebp,ebp ; 0x423569/0x423574 cmp ...,0) :
 * with -1 au start, there branch " empty " n'is NEVER prise au first symbole (elle exige 4
 * symboles zero consecutifs in the rouleau (h<<8)+sym), then that l'init has 0 of the port there takes some
 * l'input.  Has SINGLE VARIABLE : there value d'init. There PERSISTANCE sure the member (the h70/h74/
 * h78 of the port are local au scan) is V-1b, DISTINCTE, and not tourne not here. =0 => inchange. */
static int hashinit_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_HASHINIT"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
/* [M434 V-1b, GATED UHA_PPM_HAPERSIST, default-OFF, no emissif has gate OFF] PERSISTANCE of the
 * machine d'avancement. AT THE MASTER the three hashes of context S[0x70]/S[0x74]/S[0x78] (there
 * cellule 0x46491c + 124*x) are some GLOBAL .bss : elles survivent of has scan at the other of the same
 * member and not are re-semees (0x423250 : raz 0 by 0x40e3f0 then -1 sure the hashes some 4
 * cellules, 0x423276..0x423290) qu'at the ARMEMENT (0x417d17, class > 4 lue of the stream) and au
 * DESACCORD of class (0x42300b, path 0x422FE3). The port, lui, the declare Local au scan
 * (h70/h74/h78 at the input of ppm_blk_cost_scan) : there descente of context is therefore calculee sure
 * has historique tronque at the window, then that the rouleau (h<<8)+sym porte the 4 last
 * bytes of the MEMBER.  previous in the port for this class of default : UHA_MM6CARRY (M278).
 *  MEASURES M433 : there value d'init single is INERTE (0 byte of difference) parce that `off` is
 * computes AFTER there update of h70 ; c'is therefore there PERSISTANCE which porte l'gap.
 * DETECTION DUN NEW MEMBER : there position of cut `win_idx` equals 0 sure the first scan of has
 * member (measures M170g : cuts 0 / 12 558 / 34 747).  Probe, not has law.
 *  PRESUPPOSITION CONSIGNOREE : there walk of VETO (ppm_encode.c l.701) advances ALSO l'state,
 * as at the master whose the path of rejet (0x42315c..0x42317e) not restores that
 * [0x4803c0]/[0x4803d0]/[0x4803c4]/[0x483934] and NOT lenregistrement (M307B Q3). There position and
 * there phase restent fournies by l'appelant (no persistees), conformement has this restore.
 * =0 => behavior inchange (controler). */
static int hapersit_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_HAPERSIST"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
static struct {
    uint32_t h70, h74, h78;
    int      armed;
} haper;

/* =====================================================================================
 * [M435 V-3/V-4, GATED UHA_PPM_CORPSB (+ UHA_PPM_CBUSE for there consommation), default-OFF]
 * Machine of context of the CORPS B (classes >= 7), rendue en #1 :
 *   - transition 0x423b93..0x423e2a (M399 validates + corrections M430 : balayage au MIN,
 *     [0x462ce4] = delta signe no mis at the echelle, line of base all the 256)
 *   - tables : T = [0x45ecd0] = tente circulaire min(i,4096-i) (0x416b22..56, M430 3.6) ;
 *     U0 = [0x43d0f4] = quantificateur of Fibonacci of |int8| (M431 Has.1) ;
 *     U1 = [0x43c4f4] = |int8|>>3 ; U2 = [0x43ccf4] = |int8|>>6.
 *   - prediction 0x423497..0x423510 (filtre 6 taps -> [0x4630ec]) and ARBITRAGE
 *     0x423515 cmp S[0x5c],S[0x60] / jbe -> [0x48392f] = symbole reel if S[0x5c] > S[0x60]
 *     otherwise there prediction ; then, class 7 SINGLE, +0x80 BY NCEUD (0x423531/37/3d -- relul
 *     #1 : the " bump at the input unique " of M309 is l'other site, 0x4233f2..fa, branch Has).
 *  THE PROXY EXISTANT OF THE PORT (`st.last = raw`) REPRODUCES PRECISEMENT THERE BRANCH " symbole
 *   reel " : there gate not peut therefore dister THAT when the master takes there PREDICTION, this which
 *   explique has divergence ponctuelle then en cascade (measures M434 6bis).
 * Domain MEASURES : `raw` of the port = bh of the master - 0x80 (l.181-184, M315) ; symb (cls 7) =
 *   bh - 0x80 = `raw` (0x423e2b mov al,cl / sub eax,0x80) ; symb (cls >= 8) = movsx(bh)
 *   (0x423bc7) ; [esp+0x2c] = `bl` of the port (0x42365a mov [esp+0x2c],dl).
 *  L'state is LOCAL au scan : sure `mixed.bin` has single scan tourne en famadv (M434), therefore
 *   local and global are INDISTINGUABLES sure there target (measures, not hypothese).
 * =0 => behavior inchange (controler au harnais). */
typedef struct {
    int32_t  C[4];          /* S[0x00],S[0x04],S[0x08],S[0x0c] : contexts        */
    int32_t  tap[5];        /* S[0x14],S[0x18],S[0x1c],S[0x20],S[0x24]            */
    int32_t  S28, S2c;      /* symbole declare (biaise), delta signe              */
    int32_t  w[11];         /* S[0x30..0x58] : the 11 scoreurs                     */
    int32_t  w8[2], b8[2];  /* S[0x5c],S[0x60] ; bases S[0x64],S[0x68]            */
    uint32_t cnt;           /* S[0x6c]                                            */
    uint32_t h[3];          /* S[0x70],S[0x74],S[0x78]                            */
    int32_t  carry, carry2; /* [0x462ce4], [0x462ce8] : delta porte (+ swap cls 9) */
    int32_t  pred;          /* [0x4630ec]                                         */
} cb_state;

static int corpsb_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_CORPSB"); v = e ? (e[0] != '0') : 1; }
    return v;
}
static int corpsb_use(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_CBUSE"); v = e ? (e[0] != '0') : 1; }
    return v;
}
/* T[i0] : tente circulaire (0x416b22..0x416b56 : T[i]=i for i<=2047, 4096-i au-dela). */
static uint32_t cb_tent(int32_t x)
{
    uint32_t i = (uint32_t)x & 0xfffu;
    return i <= 2048u ? i : 4096u - i;
}
static int cb_abs8(uint32_t j)                  /* |int8(j)|, j = index byte 0..255 */
{
    int d = (int)(int8_t)(uint8_t)j;
    return d < 0 ? -d : d;
}
/* U0 = [0x43d0f4] : value v = smaller index tel that |int8| < bound[v] (Fibonacci). */
static uint32_t cb_u0(uint32_t j)
{
    static const int lo[13] = { 0,1,2,3,4,5,7,10,15,23,36,57,91 };
    int d = cb_abs8(j), v = 0;
    while (v < 12 && d >= lo[v + 1]) v++;
    return (uint32_t)v;
}
static void cb_init(cb_state *s)
{
    memset(s, 0, sizeof *s);
    s->h[0] = s->h[1] = s->h[2] = 0xffffffffu;   /* 0x423276..0x423290 : -1 sure the hashes */
}
/* Has nceud of the walk, class >= 7. bh = byte reel of the master, bl = symbole code. */
static void cb_node(cb_state *s, uint32_t bh, uint32_t bl, int cls, uint8_t *ctxbyte)
{
    int32_t symb = (cls == 7) ? ((int32_t)bh - 0x80)        /* 0x423e2b sub eax,0x80      */
                              : ((int32_t)(int8_t)(uint8_t)bh); /* 0x423bc7 movsx          */
    uint8_t ctx  = (uint8_t)s->pred;                        /* 0x423bd2 mov al,[0x4630ec]  */
    int32_t i0r  = (int32_t)(int8_t)(uint8_t)(ctx - (uint8_t)symb) << 4; /* movsx then shl4 */
    uint32_t acc;
    int k;

    /* --- the 11 scoreurs : i0, then i0 -/+ C_k (k=0..3), then i0 -/+ carry --- */
    s->w[0] += (int32_t)cb_tent(i0r);
    for (k = 0; k < 4; k++) {
        s->w[1 + 2*k] += (int32_t)cb_tent(i0r - s->C[k]);
        s->w[2 + 2*k] += (int32_t)cb_tent(i0r + s->C[k]);
    }
    s->w[9]  += (int32_t)cb_tent(i0r - s->carry);
    s->w[10] += (int32_t)cb_tent(i0r + s->carry);

    /* --- the 2 weight 8 bits sure U0 (0x423d02..0x423d33) --- */
    s->w8[0] += (int32_t)cb_u0((uint32_t)(ctx - (uint8_t)symb));
    s->w8[1] += (int32_t)cb_u0((uint32_t)((uint8_t)s->S28 - (uint8_t)symb));

    /* --- delta signe porte + symbole archive (0x423d28..0x423d49) --- */
    s->S2c   = (int32_t)(int8_t)(uint8_t)((uint8_t)symb - (uint8_t)s->S28);
    s->carry = s->S2c;
    s->cnt++;
    s->S28   = symb;

    /* --- vieillissement : 16, then line of base some weight 8 bits : 256 --- */
    if ((s->cnt & 0xfu) == 0u) {
        int32_t best = s->w[0];
        int idx = 0;
        s->w[0] = 0;
        for (k = 1; k <= 10; k++) {
            uint32_t cur = (uint32_t)s->w[k];
            if ((uint32_t)best > cur) { best = s->w[k]; idx = k; }   /* MIN, cmp NO SIGNEe */
            s->w[k] = 0;
        }
        if (idx >= 1 && idx <= 10) {                                  /* dec esi / cmp 9 / ja */
            switch (idx - 1) {                                        /* table [0x423624]      */
            case 0: if (s->tap[0] > -0x20) s->tap[0]--; break;         /* 0x423d89             */
            case 1: if (s->tap[0] <  0x20) s->tap[0]++; break;         /* 0x423e39             */
            case 2: if (s->tap[1] > -0x20) s->tap[1]--; break;         /* 0x423e50             */
            case 3: if (s->tap[1] <  0x20) s->tap[1]++; break;         /* 0x423e67             */
            case 4: if (s->tap[2] > -0x20) s->tap[2]--; break;         /* 0x423e7e             */
            case 5: if (s->tap[2] <  0x20) s->tap[2]++; break;         /* 0x423e95             */
            case 6: if (s->tap[3] > -0x20) s->tap[3]--; break;         /* 0x423eac             */
            case 7: if (s->tap[3] <  0x20) s->tap[3]++; break;         /* 0x423ec3             */
            case 8: if (s->tap[3] > -0x20) s->tap[4]--; break;         /* 0x423eda (keeps S20) */
            case 9: if (s->tap[3] <  0x20) s->tap[4]++; break;         /* 0x423eec (keeps S20) */
            default: break;
            }
        }
        if ((s->cnt & 0xffu) == 0u) {                                 /* 0x423d9d..0x423db6   */
            s->w8[0] -= s->b8[0]; s->b8[0] = s->w8[0];
            s->w8[1] -= s->b8[1]; s->b8[1] = s->w8[1];
        }
    }

    /* --- special class 9 : swaps some cellules portees (0x423db9..0x423dd2) --- */
    if (cls == 9) { int32_t t = s->carry; s->carry = s->carry2; s->carry2 = t; }

    /* --- rouleaux of hash ; S[0x74]/S[0x78] en class 7 SINGLE --- */
    s->h[0] = (s->h[0] << 8) + bl;                                    /* 0x423de1..ec       */
    if (cls == 7) {
        s->h[1] = (s->h[1] << 8) + (uint32_t)(cb_abs8(bl) >> 3);      /* U1 [0x43c4f4]      */
        s->h[2] = (s->h[2] << 8) + (uint32_t)(cb_abs8(bl) >> 6);      /* U2 [0x43ccf4]      */
    }

    /* --- 0x4232a0, branch cls >= 7 : roulement B, prediction, arbitrage --- */
    {
        int32_t c0 = s->C[0], c1 = s->C[1], c2 = s->C[2], d = s->S2c;
        s->C[2] = c1;                    /* S[0x08] <- S[0x04]        (0x4234b1) */
        s->C[3] = c2;                    /* S[0x0c] <- S[0x08] old (0x4234b9) */
        s->C[1] = d - c0;                /* S[0x04] <- S[0x2c]-S[0x00](0x4234be) */
        s->C[0] = d;                     /* S[0x00] <- S[0x2c]        (0x4234ca) */
        acc = (uint32_t)(s->S28 << 4) + (uint32_t)(s->tap[0] * d)
            + (uint32_t)(s->tap[1] * s->C[1]) + (uint32_t)(s->tap[2] * s->C[2])
            + (uint32_t)(s->tap[3] * s->C[3]) + (uint32_t)(s->tap[4] * s->carry);
        acc -= (uint32_t)((int32_t)acc >> 31) << 4;                   /* sbb edx (=0 now -16) */
        s->pred = (int32_t)acc >> 4;                                  /* sar eax,4           */
    }
    /* arbitrage 0x423515 : S[0x5c] > S[0x60] -> symbole reel, otherwise prediction */
    *ctxbyte = ((uint32_t)s->w8[0] > (uint32_t)s->w8[1])
             ? (uint8_t)s->S28 : (uint8_t)s->pred;
}
/* [M344, GATED UHA_PPM_SELCLK, DEFAULT-0, no emissif] Shift d'HORLOGE of the machine `sel`.
 * MEASURES (OUT/m344_front_cd_cadence.md) : the master teste there cadence of the corps some accumulateurs
 * sure `[0x4803C0]` = in_pos ABSOLU (points of changement of CD4 : 1259/1259 has residu 0 for m=4,
 * 310/310 for m=8, 4/4 for m=128 ; origine " relative at the tete " REFUTEE : residus 1/5/21),
 * then that the port l'evaluates sure `win_idx` = in_pos + 7216. Now 7216 = 0 (mod 4) and 0 (mod 8) but
 * 48 (mod 128) : the dephasage is INVISIBLE en regime sel=4/5 (all there window M316) and devient
 * has error of phase of 48 nceuds under the mask 127 (sel<=3) -> 1re divergence CD4/CD8 mesuree
 * has in_pos 1064912 (= 1072128 = 128*8376 in l'horloge of the port, which n'is not has tir of the master).
 *  EXPERIMENTATION : there value is MESUREE, not has law ; no promotable en dur. 0 => behavior
 * STRICTEMENT inchange (controler =0 after each rebuild ; the shift is has relabeling of the
 * SINGLE machine internal, l'emission of probe remainder sure win_idx, therefore the judge not moves not). */
static uint32_t selclk_shift(void)
{
    static long v = -1;
    /* [M400 GATED default-OFF] if l'appelant (uha_c, UHA_FRONTIER) has COMPUTES the plateau, l'to use.
     * otherwise (gate OFF) : behavior herite (env UHA_PPM_SELCLK now 0) = strictement inchange. */
    if (uha_selclk_active()) return uha_selclk_get();
    if (v < 0) { const char *e = getenv("UHA_PPM_SELCLK"); v = e ? strtol(e, NULL, 0) : 0; }
    return (uint32_t)v;
}
static const uint32_t FAM_CB[10]    = { 513, 521, 553, 585, 681, 745, 749, 753, 761, 764 };
static const uint32_t FAM_CTXSZ[10] = {   1,   1,   2,   3,   4,   1,   1,   2,   2,   4 };

/*
 * [M337-D, GATED UHA_PPM_FAMADV, default-OFF, no emissif] MACHINE `sel` of 0x423650/0x4232A0
 * (path cls<7). under-systeme predictif : 6 totaux (slot/nceud, LUT sqrt) -> argmin -> sel ->
 * cell[sel] -> last. Replaces the proxy `st.last=raw`. State LOCAL au scan (gel), init all-0
 * (memset 0x1E40 @0x423264) SAUF CD8=2 (0x423270) ; CD4 remainder 0 (0x423270 not sets THAT CD8).
 * Law : OUT/m312b_sel_statique.md (argmin Q1.2, LUT Q2.3, ring/acc Q3, sym Q1.5/Q4) and
 *       OUT/m314b_predicteur_vtot.md (predicteur Q1.3, v_k Q2.4, CD Q3). Formules confrontees
 *       to the captures M312/M314/M315 (t206 selfcheck 31/31,160/160,31/31 ; biaises/H 170/170).
 * all values 32 bits are EXPLICITES (int32_t/uint32_t) - never of promotion C.
 */
static const uint32_t SEL_MASKS[6] = { 127, 127, 127, 127, 7, 3 };   /* 0x43B8DC (mask, extracts .data) */

/* LUT512[v] = ceil(sqrt(min(i,512-i))), i = v & 0x1ff (0x423a0b..0x423a11 ; m312b Q2.3, 0 gap/512). */
static uint32_t sel_lut(int32_t v)
{
    uint32_t i = ((uint32_t)v) & 0x1FFu;
    uint32_t d = (i <= 256u) ? i : (512u - i);
    uint32_t k = 0;
    while (k * k < d) k++;                    /* smaller k : k*k >= d (root carree by exces) */
    return k;
}
/* F[j] = min(j, 4096-j), j = idx & 0xfff (0x45ECD0 ; table construite at the exec, m314b Q3.4, prouvee). */
static uint32_t sel_F(uint32_t idx)
{
    uint32_t j = idx & 0xFFFu;
    return (j <= 2048u) ? j : (4096u - j);
}
/* Division by 16 with TRONCATURE TOWARDS ZERO (0x423399 sar31 / 0x42339c shl4 / 0x42339f sbb / 0x4233a1 sar4).
 * x>=0 -> x>>4 ; x<0 -> (x+15)>>4 (arith). PIEGE : this n'is NOT `sar4` single (-1 -> 0, -16 -> -1). */
static int32_t sel_div16(int32_t x)
{
    return (x < 0) ? ((x + 15) >> 4) : (x >> 4);
}

typedef struct {
    uint32_t slot[6][256];    /* 0x463104 + 0x404k + 4p : cellule of the block k au slot p */
    uint32_t tot[6];          /* 0x463504 + 0x404k : total of the block k (alias +0x400)    */
    uint32_t ring[128];       /* 0x462EEC : journal some differences d(n)=sym(n)-sym(n-1) */
    uint32_t acc[124];        /* 0x462CEC : accumulateurs (i=2..123 parcourus)          */
    int32_t  cells[6];        /* 0x4630EC : the 6 cellules, ecrites by 0x4232A0 (consommees au nceud next) */
    int32_t  CD4, CD8;        /* 0x462CD4 / 0x462CD8 : argmins d'index (CD4 init 0, CD8 init 2) */
    int32_t  CDC, CE0;        /* 0x462CDC (sym nceud current) / 0x462CE0 (sym nceud previous) */
    int32_t  sel;             /* 0x462CD0 : issue of l'argmin */
    /* jeu predictif 0x46491C (cls<7 : registre global unique, no indexe by there phase) */
    int32_t  A, B, C, D, E;   /* historique Has..E (+0x00..0x10) ; E = 5e tap */
    int32_t  W[5];            /* W1..W5 (+0x14..0x24) */
    int32_t  S, H;            /* biais S (+0x28) = sym ; input H (+0x2C) = diff */
    int32_t  cnt[11];         /* 11 counters c0..c10 (+0x30..0x58) */
    uint32_t garde;           /* counter +0x6C (keeps of periodicite) */
    int      started;         /* 0 before the first 0x423650 */
} sel_state;

/* Has tour of the machine au nceud `pos` (= [0x4803C0], BEFORE increment ; 0x4232A0 uses pos+1).
 * `raw` = byte raw of the nceud (bh). Rend `last` (byte of output, [0x48392F]) for the nceud next. */
static uint8_t sel_step(sel_state *s, uint32_t pos, uint8_t raw, int cls)
{
    /* [M344 GATED UHA_PPM_SELCLK] horloge of the machine : the master cadence/indexe ses structures
     * sure l'horloge symbole absolue, not sure l'index d'writing of the port. 0 = inchange. */
    pos -= selclk_shift();
    /* ---- 0x423650 (pos = n) ---- */
    /* The `buf` that reads the port (`raw`) is there forme BIAISEE -0x80 of l'byte of the master (0x423046
     * bh). L'byte reel bh = raw + 0x80, and [esp+0x24] = movsbl(bh) (M315 : biais/esp24/cell3 =
     * -40 at the tete when raw=88 -> bh=216 ; -41 has n+1 when raw=87 -> bh=215). Compares 2 nceuds. */
    int32_t sym  = (int32_t)(int8_t)(uint8_t)(raw + 0x80u);   /* [esp+0x24] = movsbl(byte master) */
    int32_t diff = sym - s->CDC;                  /* [esp+0x20] = sym - [0x462CDC] (unique ecrivain 0x42369b) */
    /* error e = movsbl(byte[0x4630F8] - byte[esp+0x24]) ; [0x4630F8] = cell3 of the nceud previous */
    int32_t e    = (int32_t)(int8_t)((uint8_t)s->cells[3] - (uint8_t)sym);
    int32_t E16  = e << 4;                         /* eax = 16*e (0x4236ab) */
    int32_t A0 = s->A, B0 = s->B, C0 = s->C, D0 = s->D, E0 = s->E;
    /* biais S = sym, input H = diff (0x4237e3 / 0x4237d9 ; compares M315 : biais=sym, H=diff 170/170) */
    s->S = sym; s->H = diff;
    /* 11 counters : c_k += F[(E16 +/- hist) & 0xfff] (0x4236b9..0x4237c6) */
    s->cnt[0]  += (int32_t)sel_F((uint32_t)E16);
    s->cnt[1]  += (int32_t)sel_F((uint32_t)(E16 - A0));
    s->cnt[2]  += (int32_t)sel_F((uint32_t)(E16 + A0));
    s->cnt[3]  += (int32_t)sel_F((uint32_t)(E16 - B0));
    s->cnt[4]  += (int32_t)sel_F((uint32_t)(E16 + B0));
    s->cnt[5]  += (int32_t)sel_F((uint32_t)(E16 - C0));
    s->cnt[6]  += (int32_t)sel_F((uint32_t)(E16 + C0));
    s->cnt[7]  += (int32_t)sel_F((uint32_t)(E16 - D0));
    s->cnt[8]  += (int32_t)sel_F((uint32_t)(E16 + D0));
    s->cnt[9]  += (int32_t)sel_F((uint32_t)(E16 - E0));
    s->cnt[10] += (int32_t)sel_F((uint32_t)(E16 + E0));
    /* keeps ++ (0x4237d0/0x4237e0) ; adaptation if (keeps & 0x0f)==0. M317 fixes M314B E2 :
     * 8a 73 6c = mov 0x6c(%ebx),%dh loads L'byte at the address ebx+0x6c (0x464988), NOT l'byte
     * high of the dword ; test $0xf,%dh porte therefore sure there NIBBLE LOW of l'byte lu (v&0xf==0), value
     * AFTER l'inc. Periode 16 ; 1re adaptation au nceud tete+15 (garde_abs 15, maetre W1!=0 has
     * 1063802, M316). Keeps LOCAL resets by walk (M316 : garde_abs=0 at each tete) : the
     * selst by scan is correct (there value " keeps global " was has inference of too). */
    s->garde++;
    if ((s->garde & 0xFu) == 0u) {
        /* M317 : there loop tient the MINIMUM unsigned (0x4237fe `cmp %edi,%edx` computes best -
         * candidate ; 0x423800 `jbe` skips when best <= candidate => on NOT replaces that if
         * best > candidate => minimum). best init = c0 ; inegalite STRICT => en cas d'egalite the
         * MORE LOW index gagne. (M314B E1 disait " max " => mapping no injectif, the constat
         * M316 ; under argmin the mapping redevient fonctionnel.) */
        uint32_t best = (uint32_t)s->cnt[0];
        int idx = 0;
        for (int i = 1; i < 11; i++)                 /* c1..c10 examines (c0 traite by the prologue) */
            if ((uint32_t)s->cnt[i] < best) { best = (uint32_t)s->cnt[i]; idx = i; }
        for (int i = 0; i < 11; i++) s->cnt[i] = 0;  /* the 11 zeres in there same pass (c0 0x4237f8, c1..c10 0x42380a) */
        if (idx != 0) {                              /* c0 winner (term without tap) => no write */
            int w    = (idx - 1) / 2;                /* c1,c2->W1 ; c3,c4->W2 ; c5,c6->W3 ; c7,c8->W4 ; c9,c10->W5 */
            int sign = (idx % 2 == 0) ? 1 : -1;      /* idx pair (term -h) -> +1 ; impair (term +h) -> -1 */
            /* Keeps-fou +/-32 SIGNEE sure the weight WRITES, SAUF idx 9/10 (W5) which testent W4 (anomalie
             * re-confirmee en bytes M317 Q3 : 83 7b 20 e0 / 83 7b 20 20 + ff 4b 24 / ff 43 24 ;
             * never exercee by there window [Win-2..13], reproduite when same for the bit-exact). */
            int guard_w = (idx == 9 || idx == 10) ? 3 : w;
            int cur = s->W[guard_w];
            if (!((sign < 0 && cur <= -32) || (sign > 0 && cur >= 32)))
                s->W[w] += sign;
        }
    }
    /* ring : ring[pos & 0x7f] = diff (0x423831..0x42383d ; index = pos pre-increment) */
    s->ring[pos & 0x7Fu] = (uint32_t)diff;
    /* corps accumulateurs ONLY if (pos & masks[sel_entree]) == 0 (0x423844..0x423856 ; sel d'INPUT = previous) */
    if ((pos & SEL_MASKS[(uint32_t)s->sel & 5u]) == 0u) {
        uint32_t min_score = 0xFFFFu;                /* 0x42385c */
        s->CD4 = 2; s->CD8 = 2;                       /* 0x42386b / 0x423871 (remise has 2 by scan) */
        for (uint32_t i = 2; i < 124; i++) {          /* 122 tours, i=2..123 (0x423974 cmp 0x7c) */
            uint32_t a = s->ring[(pos      - i) & 0x7Fu];
            uint32_t b = s->ring[(pos  - 1 - i) & 0x7Fu];
            uint32_t c = s->ring[(pos  - 2 - i) & 0x7Fu];
            uint32_t Ssc =
                  sel_F((s->ring[pos & 0x7Fu]        - a) & 0xFFFu)
                + sel_F((s->ring[(pos - 1) & 0x7Fu]  - b) & 0xFFFu)
                + sel_F((s->ring[(pos - 2) & 0x7Fu]  - c) & 0xFFFu);
            uint32_t acc13 = (uint32_t)((uint32_t)(13 * (int32_t)s->acc[i]) >> 4);  /* imul signe then SHR no signe (0x423939/40) */
            s->acc[i] = acc13 + Ssc;                                                 /* add (0x423943), no bound */
            if (s->acc[i] < s->acc[(uint32_t)s->CD4 & 127u]) s->CD4 = (int32_t)i;   /* 0x42394b..0x423960 jae no signe -> smaller i gagne */
            if (Ssc < min_score) { min_score = Ssc; s->CD8 = (int32_t)i; }          /* 0x423965..0x42396b */
        }
    }
    /* candidates v_k (0x42397d..0x4239e0) : sym - cell[0..3] ; diff - cell[4..5] (cellules of the nceud previous) */
    int32_t v[6];
    v[0] = sym  - s->cells[0];
    v[1] = sym  - s->cells[1];
    v[2] = sym  - s->cells[2];
    v[3] = sym  - s->cells[3];
    v[4] = diff - s->cells[4];
    v[5] = diff - s->cells[5];
    /* argmin 0x4239d6..0x423a4d : reset sel=0, then 6 tours (slot unique p=pos&0xff, LUT, total += new-old) */
    {
        uint32_t p = pos & 0xFFu;
        int32_t sel = 0;                              /* 0x4239d6 */
        for (int k = 0; k < 6; k++) {
            uint32_t c = sel_lut(v[k]);
            s->tot[k] -= s->slot[k][p];               /* 0x4239f7..0x423a02 : T -= old */
            s->slot[k][p] = c;                        /* 0x423a18 : cell[p] = c */
            s->tot[k] += c;                           /* 0x423a1d : total += c */
            if ((int32_t)s->tot[k] < (int32_t)s->tot[sel]) sel = k;   /* 0x423a33 jge -> strict, more low index */
        }
        s->sel = sel;
    }
    /* 0x423a4f..0x423a60 : [0x462CE0] <- old [0x462CDC] ; [0x462CDC] <- new sym */
    s->CE0 = s->CDC;
    s->CDC = sym;

    /* ---- 0x4232A0 (pos = n+1) : 6 cellules + last ---- */
    {
        uint32_t p1 = pos + 1u;
        int32_t R = (int32_t)s->ring[(p1 - (uint32_t)s->CD4) & 0x7Fu];   /* 0x423301 (5e tap = cellule 4, same index) */
        int32_t acc3 = s->W[0]*s->H + 16*s->S
                     + s->W[1]*(s->H - A0) + s->W[2]*B0 + s->W[3]*C0 + s->W[4]*R;  /* 5 imul SIGNES, sum without mask */
        s->cells[0] = 0;                              /* 0x4232d2/da (path cls<7 : c0=0) */
        s->cells[1] = s->CDC;                         /* 0x4232e0 = [0x462CDC] */
        s->cells[2] = 2*s->CDC - s->CE0;             /* 0x4232f7 = 2.[CDC] - [CE0] */
        s->cells[3] = sel_div16(acc3);                /* 0x4233a4 = [0x4630F8] (predicteur) */
        s->cells[4] = R;                             /* 0x4233b6 = ring[(p1 - CD4)&0x7f] */
        s->cells[5] = (int32_t)s->ring[(p1 - (uint32_t)s->CD8) & 0x7Fu];  /* 0x4233cc = ring[(p1 - CD8)&0x7f] */
        /* shift historique Has..E (0x42330d..0x423342) */
        s->E = R; s->D = C0; s->C = B0; s->B = s->H - A0; s->A = s->H;
        /* last = (cell[sel]&0xFF + (sel>=4 ? CDC&0xFF : 0) + (cls in {5,7} ? 0x80 : 0)) & 0xFF  (0x4233e8..0x423416) */
        uint32_t last = ((uint32_t)s->cells[s->sel] & 0xFFu)
                      + (((uint32_t)s->sel >= 4u) ? ((uint32_t)s->CDC & 0xFFu) : 0u)
                      + ((cls == 5 || cls == 7) ? 0x80u : 0u);
        return (uint8_t)(last & 0xFFu);
    }
}

/* [M170m, UHA_BLKCOLD, default-OFF] Probe of the NODE COLD : imprime, for each node now
 * `freq[rel][sym] == 0`, l'state VU by there branch cold (`0x4230cc..0x42312b`) :
 *   pf/pt = row of prior of the master (freq[772+cl][sym], cum[772+cl][0])
 *   esc/tot = buffers of travail of the line `rel` BEFORE update
 *   ebp     = cumul BEFORE the node (enables of recuperer the cost of the node by difference).
 * No writing, no value modifiee. */
static int blkcold_on(void)
{
    static int v = -1;
    if (v < 0) {
        const char *e = getenv("UHA_BLKCOLD");
        v = (e && e[0]) ? atoi(e) : 0;   /* 1 = nodes froids ; 2 = sequence complete */
    }
    return v;
}

/* [M278, GATED UHA_FAMNODES=<n>, default 0 = OFF, no emissif] DISTRIBUTION BY NODE of the
 * family `0x422d00`. Imprime the `n` first nodes of has call whose `start == UHA_FAMSTART`
 * (default 937440) : `rel sym f t esc cost`. The denominateur of the term hot is etabli by
 * l'ASM (`0x423137` : `di = WORD[esp+0x48]` = `total[rel]` lu BEFORE, `0x4230b1`) ; this probe
 * dit if l'gap `f/t` 0,51 (port) vs 0,187 (GT) vient of `f`, of `t` now of the number of froids. */
static long famnodes_n(void)
{
    static long v = -1;
    if (v < 0) { const char *e = getenv("UHA_FAMNODES"); v = (e && e[0]) ? atol(e) : 0; }
    return v;
}
static unsigned long famnodes_start(void)
{
    static long v = -1;
    if (v < 0) { const char *e = getenv("UHA_FAMSTART"); v = (e && e[0]) ? atol(e) : 937440; }
    return (unsigned long)v;
}

/* [M278, GATED UHA_FAMCTXM=<m>, default 0 = OFF] SENSIBILITE (NOT has law) : forces
 * `ctx_abs = base + (it % m)` for to measure if there VARIATION of `rel` peut porter l'gap of cost
 * (port 4 334 512 vs master 10 133 783). Sert only has to validate now refuter there direction
 * " rel constant = cause " before there captures by node (`MISSION_M278`). */
static long famctx_m(void)
{
    static long v = -1;
    if (v < 0) { const char *e = getenv("UHA_FAMCTXM"); v = (e && e[0]) ? atol(e) : 0; }
    return v;
}

/* [M278, GATED UHA_FAMT0=<v>, default 0 = OFF] SENSIBILITE (NOT has law) : adds `v` au TOTAL
 * of each row of the class before there loop, for representer has arena ALREADY NOURRIE by
 * l'estimator `0x4221c0` (the master has only Has buffer `0x43a264`, already rempli some 5 evaluations).
 * Measures of the port : `t` part of 1..353 and plafonne has 8 513 then that there bound ASM is `0x4000`. */
static long famt0_v(void)
{
    static long v = -1;
    if (v < 0) { const char *e = getenv("UHA_FAMT0"); v = (e && e[0]) ? atol(e) : 0; }
    return v;
}

int ppm_blk_cost_scan(ppm_cost_arena *a, const ppm_blk_scan_in *in, uint32_t budget,
                      ppm_blk_scan_out *out)
{
    ppm_blk_state st;
    uint64_t ebp = 0;
    uint32_t it, ncold = 0, niter = 0;
    uint32_t wstart;                 /* [M243] start of the scan (bound of the window) */
    int overflow = 0;

    if (!out)
        return 0;
    memset(out, 0, sizeof *out);
    if (!a || !in || !in->win || !in->step2)
        return 0;

    st = in->st;
    wstart = in->st.win_idx;         /* [M243] identifie l'call in the traces */

    /* [M314 GATED UHA_PPM_FAMADV] state local of the machine d'avancement. */
    int      famadv = famadv_on();
    int      famcl  = -1;
    uint32_t clsz   = 1, phase = 0, posc = st.win_idx;
    uint32_t h70 = 0, h74 = 0, h78 = 0;
    if (famadv && hashinit_on())
        h70 = h74 = h78 = 0xffffffffu;   /* [M432 V-1a] 0x423279/7f/85 mov [S+0x70|74|78], -1 */
    int      halive = 0;                 /* [M434 V-1b] there machine has-t-elle tourne (writing return) */
    if (famadv) {
        int z;
        for (z = 0; z < 10; z++) if (FAM_CB[z] == in->base) { famcl = z; break; }
        /* there machine 0x4232a0 n'is definie that for the classes marchees 5..9 (M308B Q5 :
         * `749+off` out domaine for cls 0..4 -> [NO SLICE]). outside of this domaine on remainder
         * sure the not existant, for not never indexer out arena. */
        if (famcl < 5) { famadv = 0; }
        else { clsz = FAM_CTXSZ[famcl]; st.ctx_abs = in->base; }  /* forces 0x422feb : rel(noeud0)=0 */
    }
    if (m417dbg_on())
        fprintf(stderr, "[M417DBG][famadv] wstart=%u in_base=%u famcl=%d famadv=%d\n",
                (unsigned)wstart, (unsigned)in->base, famcl, famadv);
    /* [M434 V-1b] rouleau persistant sure the member (0x46491c+0x70/0x74/0x78 en .bss). */
    if (famadv && hapersit_on()) {
        if (!haper.armed || wstart == 0u) {
            haper.h70 = haper.h74 = haper.h78 = 0xffffffffu;   /* 0x423276..0x423290 at the armement */
            haper.armed = 1;
        }
        h70 = haper.h70; h74 = haper.h74; h78 = haper.h78;
        halive = 1;
        if (m417dbg_on())
            fprintf(stderr, "[M434][hapersit] wstart=%u famcl=%d h70=%08x h74=%08x h78=%08x\n",
                    (unsigned)wstart, famcl, h70, h74, h78);
    }
    /* [M435 V-3] machine of context of the corps B : tourne by nceud when famadv && class >= 7. */
    cb_state cb;
    int      cbon = (famadv && famcl >= 7 && corpsb_on());
    if (cbon) cb_init(&cb);

    /* [M337-D] state of the machine `sel` : LOCAL au scan, gel as l'arena. Init all-0 (memset
     * 0x1E40 @0x423264) SAUF CD8=2 (0x423270). Tourne only en famadv && famcl<7. */
    sel_state selst;
    memset(&selst, 0, sizeof selst);
    selst.CD8 = 2;   /* 0x423270 puts [0x462CD8]=2 ; CD4 remainder 0 */
    { long famn_ = famnodes_n(); unsigned long famstart = famnodes_start();
    long famctxm = famctx_m();
    { long t0 = famt0_v(); uint32_t rr;
      if (t0 > 0 && a)
          for (rr = 0; rr < in->nctx; rr++)
              a->total[rr] = (uint16_t)(a->total[rr] + t0); }

    for (it = 0; it < in->len; it++) {
        uint8_t raw, bl, sym;
        uint32_t rel, step, f, tt0, esc0;
        uint64_t ebp0;
        uint8_t fl0;

        if (famctxm > 0)
            st.ctx_abs = in->base + (it % (uint32_t)famctxm);

        /* 0x423035 : it < 0x100 -> window d'arena [0x43a21c] ; otherwise block (0x4231ac). */
        if (it < 0x100u)
            raw = in->hist[st.win_idx];
        else
            raw = (uint8_t)(~in->win[it - 0x100u]);
        /* [M278, UHA_FAMHISTNEG, PROMU default 1] There branch `it < 0x100` (0x423046) reads
         * `[0x43a21c][win_idx]` without negation, then that there branch block (0x4231b0) does `not bh`.
         * Measures M278 (master, pos = 937440) : `sym(it=0) = 161` = `~94` = `~raw[937440]` ; the port
         * rendait 141 (via `g_blk_sym`). => l'arena d'historique of legacy contient already l'byte
         * NEGATE. `=0` restores l'historique. */
        { static int hn = -1;
          if (hn < 0) { const char *e = getenv("UHA_FAMHISTNEG"); hn = (e && e[0] == '0') ? 0 : 1; }
          if (hn && it < 0x100u)
              raw = (uint8_t)(~raw); }

        /* 0x423048..0x42305e : bl = raw - last ; negation if flag. */
        fl0 = st.flag;                    /* [M279] flag d'INPUT of the node (before toggles) */
        bl = (uint8_t)(raw - st.last);
        if (st.flag)
            bl = (uint8_t)(-(int8_t)bl);

        /* 0x423061..0x42306e : |bl| >= 0x80 -> toggles of the flag. */
        if (bl >= 0x80u)
            st.flag = (uint8_t)(st.flag ? 0u : 1u);
        sym = bl;

        /* 0x423077 : ctx RELATIF = [0x4803c4] - CLS_CTXBASE[class]. */
        if (famadv) {
            /* machine portee : ctx_abs is already in [base, base+nctx-1] by construction ;
             * on NOT clampe NOT has 0 (it was the vehicule false) and on not bound not has nctx. */
            rel = st.ctx_abs - in->base;
        } else {
            rel = (st.ctx_abs >= in->base) ? (st.ctx_abs - in->base) : 0u;
            if (rel >= in->nctx)
                rel = in->nctx ? in->nctx - 1u : 0u;
        }

        /* 0x4230bf : extra = WORD[0x482d0c + 2*ctx_ABSOLU]. */
        step = in->step2[st.ctx_abs];
        f = a->freq[(size_t)rel * 256u + sym];
        { /* [M278] values VUES by the node, before all update (ASM : t lu en
           * `0x423137` since `[esp+0x48]`, rempli en `0x4230b1`). */
          tt0 = a->total[rel];
          esc0 = a->escape[rel];
          ebp0 = ebp;
        }

        if (f == 0u && blkcold_on()) {
            uint32_t pf = a->prior ? a->prior[sym] : 0xFFFFu;
            fprintf(stderr, "[BLKCOLD] it=%u rel=%u sym=%u step=%u pf=%u pt=%u esc=%u tot=%u ebp=%llu\n",
                    (unsigned)it, (unsigned)rel, (unsigned)sym, (unsigned)step,
                    (unsigned)pf, (unsigned)a->prior_total, (unsigned)a->escape[rel],
                    (unsigned)a->total[rel], (unsigned long long)ebp);
        }
        /* [M170m] UHA_BLKCOLD=2 : SEQUENCE COMPLETE some nodes (state vu BEFORE the node),
         * for alignement direct sure the GT per-node `OUT/m170g_A_*.tsv`
         * (columns : call it win_idx wpos ctx_abs last flag sym_bl sym_bh). */
        if (blkcold_on() >= 2)
            fprintf(stderr, "[BLKSEQ] start=%u it=%u ctx=%u sym=%u flag=%u last=%u rel=%u f=%u tot=%u\n",
                    (unsigned)wstart, (unsigned)it, (unsigned)(in->base + rel), (unsigned)sym,
                    (unsigned)st.flag, (unsigned)st.last, (unsigned)rel, (unsigned)f,
                    (unsigned)a->total[rel]);

        /* Cost + updates : identical au node of l'estimator (0x4230c7..0x4231dd),
         * y compris there branch cold : term 1 = LUT[prior/cum_prior] with there line of prior
         * (freq = 8 by construction, cum[0] = ROWSEED[0]<<3 = 2048 - ppm_model.c:372 and
         * ppm_tables.c:517), term 2 = LUT[escape/total]. Increment = `extra` (and no 32). */
        ebp += ppm_cost_node_step(a, rel, sym, 0, step);
        if (f == 0u)
            ncold++;
        if (famn_ > 0 && (long)it < famn_ && (unsigned long)wstart == famstart)
            fprintf(stderr, "[FAMN] start=%u i=%u ctx=%u rel=%u sym=%u f=%u t=%u esc=%u cost=%u ebp=%llu last=%u flag=%u\n",
                    (unsigned)wstart, (unsigned)it, (unsigned)st.ctx_abs, (unsigned)rel, (unsigned)sym,
                    (unsigned)f, (unsigned)tt0, (unsigned)esc0,
                    (unsigned)(ebp - ebp0), (unsigned long long)ebp,
                    (unsigned)st.last, (unsigned)st.flag);
        if (famn_ > 0 && (long)it < famn_ && (unsigned long)wstart == famstart)
            fprintf(stderr, "[FAMRAW] i=%u raw=%u win_idx=%u fl0=%u bl=%u\n",
                    (unsigned)it, (unsigned)raw, (unsigned)st.win_idx,
                    (unsigned)fl0, (unsigned)bl);

        /* 0x423154 : ebp > budget -> output immediate (no writing ulterieure). */
        if (ebp > (uint64_t)budget) {
            overflow = 1;
            niter = it + 1u;
            break;
        }

        /* 0x4231ea call 0x423650 / 0x42321a call 0x4232a0 : machine d'avancement. */
        if (famadv) {
            int      iv  = (sym >= 0x80u) ? (int)sym - 256 : (int)sym;
            uint32_t ad  = (uint32_t)(iv < 0 ? -iv : iv);          /* |int8 delta| */
            h70 = (h70 << 8) + (uint32_t)sym;                      /* 0x423a75 / 0x423dec */
            if (famcl < 7)       { h74 = (h74 << 8) + (ad >> 2); h78 = (h78 << 8) + (ad >> 4); }
            else if (famcl == 7) { h74 = (h74 << 8) + (ad >> 3); h78 = (h78 << 8) + (ad >> 6); }
            /* cls 8/9 : h74/h78 NO maintenus (0x423df2) */
            posc++;                                                /* [0x4803c0] = pos+1 (0x42320e) */
            phase = clsz ? (posc % clsz) : 0u;                     /* [0x4803d0] (0x423214) */
            if (famcl < 7) {
                uint32_t b2  = (famcl == 5) ? 745u : 749u;
                uint32_t off = (h70 == 0) ? 1u : (h74 == 0) ? 2u : (h78 == 0) ? 3u : 0u;
                st.ctx_abs = b2 + off;
            } else if (famcl == 7) {
                uint32_t off = (h70 == 0) ? 2u : (h74 == 0) ? 4u : (h78 == 0) ? 6u : 0u;
                st.ctx_abs = phase + 753u + off;
            } else if (famcl == 8) {
                st.ctx_abs = (h70 == 0) ? 763u : (phase + 761u);
            } else {
                st.ctx_abs = (h70 == 0) ? 768u : (phase + 764u);
            }
            /* [M337-D] machine `sel` (path cls<7) : replaces the proxy st.last=raw.
             * Appelee with pos = win_idx (= [0x4803C0] = n, BEFORE l'increment of the pilote ;
             * the 0x4232A0 internal uses n+1). The path ctx_abs/rel/cost remainder there law
             * FAMADV existante (m331 &4 step 5 : "rel/ctx_abs/cost = law FAMADV").
             * famcl>=7 (cls9 walk) : other path (m312b &0.3), sel/argmin/ring not tournent
             * not -> on keeps the proxy (st.last bump +0x80 at the input, otherwise raw). */
            if (famcl < 7) {
                uint8_t mlast = sel_step(&selst, st.win_idx, raw, famcl);
                if (famn_ > 0 && (long)it < famn_ && (unsigned long)wstart == famstart)
                    fprintf(stderr,
                        "[FAMSEL] node=%u pos=%u sym=%d tot0=%u tot1=%u tot2=%u tot3=%u tot4=%u tot5=%u "
                        "sel=%d c0=%d c1=%d c2=%d c3=%d c4=%d c5=%d cell=%d last=%u bl=%u "
                        "CD4=%d CD8=%d idx5=%u c5=%d cell3=%d W1=%d W2=%d W3=%d W4=%d W5=%d\n",
                        (unsigned)st.win_idx, (unsigned)st.win_idx, (int)sym,
                        selst.tot[0], selst.tot[1], selst.tot[2], selst.tot[3], selst.tot[4], selst.tot[5],
                        (int)selst.sel,
                        selst.cells[0], selst.cells[1], selst.cells[2], selst.cells[3], selst.cells[4], selst.cells[5],
                        selst.cells[selst.sel], (unsigned)mlast, (unsigned)bl,
                        (int)selst.CD4, (int)selst.CD8,
                        (unsigned)((st.win_idx + 1u - (uint32_t)selst.CD8) & 0x7Fu),
                        selst.cells[5], selst.cells[3],
                        selst.W[0], selst.W[1], selst.W[2], selst.W[3], selst.W[4]);
                st.last = mlast;
            } else {
                /* [0x48392F] = last : law MESUREE M309 (column `last`) -- the bump +0x80 of
                 * 0x4232A0 (cls5/7) not s'applies qu'at the INPUT (unique) ; ensuite
                 * last(n+1) = buf(n) = `raw` current. On not touche NOT st.flag : there loop
                 * (0x423058/6e) the does to toggle sure |bl|>=0x80, conforme au master. */
                if (it == 0u && famcl == 7)
                    st.last = (uint8_t)(st.last + 0x80u);
                else
                    st.last = raw;
                /* [M435 V-3/V-4] there machine of the corps B, then (UHA_PPM_CBUSE) son arbitrage
                 * replaces the proxy. Domaine : [0x48392f] of the master = ctxbyte + (cls==7 ? 0x80
                 * : 0) (0x423537, BY NCEUD), and `st.last` of the port is en domaine `master - 0x80`
                 * (l.181-184, M315) ==> last_port = ctxbyte + (cls==7 ? 0 : 0x80). */
                if (cbon) {
                    uint8_t ctxb;
                    cb_node(&cb, (uint8_t)(raw + 0x80u), bl, famcl, &ctxb);
                    if (corpsb_use())
                        st.last = (uint8_t)(ctxb + (uint8_t)((famcl == 7) ? 0u : 0x80u));
                    if (m417dbg_on())
                        fprintf(stderr, "[M435][corpsb] it=%u raw=%u bl=%u ctxb=%u last=%u proxy=%u "
                                "w8=%d/%d pred=%d tap=%d,%d,%d,%d,%d cnt=%u\n",
                                (unsigned)it, (unsigned)raw, (unsigned)bl, (unsigned)ctxb,
                                (unsigned)st.last, (unsigned)raw,
                                cb.w8[0], cb.w8[1], cb.pred,
                                cb.tap[0], cb.tap[1], cb.tap[2], cb.tap[3], cb.tap[4],
                                (unsigned)cb.cnt);
                }
            }
        } else if (in->step) {
            in->step(in->ud, &st, raw, sym);
        }

        st.win_idx++;
        niter = it + 1u;
    }

    out->ebp = ebp;
    out->niter = niter;
    out->ncold = ncold;
    out->overflow = overflow;
    }
    if (halive) {                          /* [M434 V-1b] restitution of the rouleau au member */
        haper.h70 = h70; haper.h74 = h74; haper.h78 = h78;
    }
    return 1;
}
