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
#include "ppm_priv.h"

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
static uint32_t selclk_shift(void)
{
    if (uha_selclk_active()) return uha_selclk_get();
    return 0;
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
    /* [M170g / Fix cls==6] 0x42367f..0x42368b vs 0x423ac0..0x423ac9:
     * Only cls != 6 (i.e. cls == 5) subtracts 0x80; cls == 6 uses movsx(bh) directly! */
    int32_t sym  = (cls == 6) ? (int32_t)(int8_t)raw
                              : (int32_t)(int8_t)(uint8_t)(raw + 0x80u);
    int32_t diff = sym - s->CDC;                  /* [esp+0x20] = sym - [0x462CDC] (unique ecrivain 0x42369b) */
    /* error e = movsbl(byte[0x4630F8] - byte[esp+0x24]) ; [0x4630F8] = cell3 of the nceud previous */
    int32_t e    = (int32_t)(int8_t)((uint8_t)s->cells[3] - (uint8_t)sym);
    int32_t E16  = e * 16;                         /* eax = 16*e (0x4236ab) */
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

int ppm_blk_cost_scan(ppm_cost_arena *a, const ppm_blk_scan_in *in, uint32_t budget,
                      ppm_blk_scan_out *out)
{
    ppm_blk_state st;
    uint64_t ebp = 0;
    uint32_t it, ncold = 0, niter = 0;
    int overflow = 0;

    if (!out)
        return 0;
    memset(out, 0, sizeof *out);
    if (!a || !in || !in->win || !in->step2)
        return 0;

    st = in->st;

    int famadv = 1;
    int famcl = -1;
    uint32_t clsz = 1, phase = 0, posc = st.win_idx;
    uint32_t h70 = 0, h74 = 0, h78 = 0;
    int z;
    for (z = 0; z < 10; z++) {
        if (FAM_CB[z] == in->base) {
            famcl = z;
            break;
        }
    }
    if (famcl < 5) {
        famadv = 0;
    } else {
        clsz = FAM_CTXSZ[famcl];
        st.ctx_abs = in->base;
    }

    ppm_mm7 mm7;
    int cbon = (famadv && famcl >= 7);
    if (cbon)
        ppm_mm7_reset(&mm7, (uint8_t)famcl);

    sel_state selst;
    memset(&selst, 0, sizeof selst);
    selst.CD8 = 2;

    for (it = 0; it < in->len; it++) {
        uint8_t raw, bl, sym;
        uint32_t rel, step, f;

        if (it < 0x100u)
            raw = (uint8_t)(~in->hist[st.win_idx]);
        else
            raw = (uint8_t)(~in->win[it - 0x100u]);

        bl = (uint8_t)(raw - st.last);
        if (st.flag)
            bl = (uint8_t)(-(int8_t)bl);

        if (bl >= 0x80u)
            st.flag = (uint8_t)(st.flag ? 0u : 1u);
        sym = bl;

        if (famadv) {
            rel = st.ctx_abs - in->base;
        } else {
            rel = (st.ctx_abs >= in->base) ? (st.ctx_abs - in->base) : 0u;
            if (rel >= in->nctx)
                rel = in->nctx ? in->nctx - 1u : 0u;
        }

        step = in->step2[st.ctx_abs];
        f = a->freq[(size_t)rel * 256u + sym];

        ebp += ppm_cost_node_step(a, rel, sym, 0, step);
        if (f == 0u)
            ncold++;

        if (ebp > (uint64_t)budget) {
            overflow = 1;
            niter = it + 1u;
            break;
        }

        if (famadv && cbon) {
            uint32_t cur_phase = phase;
            ppm_mm7_update(&mm7, cur_phase, raw, bl, st.flag);
            posc++;
            phase = clsz ? (posc % clsz) : 0u;
            ppm_mm7_predict(&mm7, phase, &st.last, &st.flag, &st.ctx_abs);
        } else if (famadv) {
            int iv = (sym >= 0x80u) ? (int)sym - 256 : (int)sym;
            uint32_t ad = (uint32_t)(iv < 0 ? -iv : iv);
            h70 = (h70 << 8) + (uint32_t)sym;
            if (famcl < 7) {
                h74 = (h74 << 8) + (ad >> 2);
                h78 = (h78 << 8) + (ad >> 4);
            } else if (famcl == 7) {
                h74 = (h74 << 8) + (ad >> 3);
                h78 = (h78 << 8) + (ad >> 6);
            }
            posc++;
            phase = clsz ? (posc % clsz) : 0u;
            if (famcl < 7) {
                uint32_t b2 = (famcl == 5) ? 745u : 749u;
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
            if (famcl < 7) {
                st.last = sel_step(&selst, st.win_idx, raw, famcl);
            } else {
                if (it == 0u && famcl == 7)
                    st.last = (uint8_t)(st.last + 0x80u);
                else
                    st.last = raw;
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
    return 1;
}
