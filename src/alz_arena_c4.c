/*
 * alz_arena_c4.c - implementation of the port faithful of l'arena litterale of the scorer
 * 0x411bb0 (UHARC 0.6b). Traduction 1:1 of the model offline validated 29943/29943
 * (_scratch/acccap13/acc_full.py, 13.618 trajectoire + 13.619 costs/acc).
 *
 * Laws encodees (references gravees) :
 *  - HOT   : total = BIT0[row] + d4  (without mask u16, C3) ; if escape : total = freq[row][esym] ;
 *            cost  = LUT[(freq[row][sym]<<14)/total]                       (13.609/617)
 *  - COLD  : dx = M16(BIT0[row]  flag*freq[row][esym])   (0x811bdd..bf7)
 *            cost1 = dx ? LUT[(d4<<14)/(dx+d4)] : 0        (store 0x811c64 ; absent if dx==0)
 *            cost2 = LUT[(freq405[sym]<<14)/t2] with
 *                    t2 = BIT0[405]  Sigma_{i:freq[row][i]!=0} freq405[i]  esc405   (re-ancre 0x811d08..)
 *                    esc405 = freq405[esym] ssi flag && freq[row][esym]==0   (0x811f4e ; dx==0 single not suffit not,
 *                    cf rembobinage NULL by escape 13.620 : BIT0==freq[esym]!=0 -> NULL without soustraction bench)
 *            cost  = cost1 + cost2 ; acc au rank n = cost of l'evenement n1 (phase 13.619(1))
 *  - C4    : cc94 = (d4+cell) ; if cell==0 : seed banc 0x405 (+16, Fenwick, bit0+=16) and d4+=0x20 ;
 *            freq[sym]+=0x20 ; Fenwick bit ; bit0+=0x20 (wrap u16) ;
 *            gate (bit0+d4 >= 0x4000) NOW cc94<0 -> commit 0x80ffa0              (13.618(3))
 *  - commit: decay b==0->nothing / b<=0x10->0 no cumul / otherwise b>>1 with Sigma ; bit[1..255]:=freq[0..254] ;
 *            bit[0]=Sigma ; rebuild Fenwick c=1,2,4..64 ; d4=(d4+1)>>1 ; cc94=(Sigma+d4)<<8  (#11)
 *  - Init  : d4=1, cc94=256 (fixpoint PRIME commit, C1) ; bancs freq[i]=4, bit[0]=1024 (13.615(2)).
 */
#include <stdio.h>
#include <string.h>

#include "alz_arena_c4.h"

/* LUT of cost capturee au runtime @0x43f154 (13.133/134). alz_score_cum[16385],
 * liaison internal (static) - no collision with alz_score.c which l'inclut also. */
#include "alz_score_table.inc"

#define M16(v) ((uint16_t)((v) & 0xFFFFu))
#define M32(v) ((uint32_t)((v) & 0xFFFFFFFFu))

/* Index LUT bounded has 16384 - CONVENTION OF THE SCORER validated (13.65 port faithful
 * 0x414630, alz_score_proba : p >= ALZ_SCORE_CUM_N-1 -> clamp). En HOT with
 * escape, total peut passer under cell (freq[esym] > 0 soustrait, site 0x811bb0) ;
 * without clamp, reading OOB. Sure there chain GT lockstep, the clamp not se triggers
 * never (29948/29948 preserved) ; il not s active that sure there chain of the clone. */
#define C4_LUT(p) (alz_score_cum[(p) > 16384u ? 16384u : (p)])
/* Division bounded facon alz_score_proba : total==0 -> index 16384 (13.65). */
#define C4_DIVLUT(num, den) ((den) == 0u ? alz_score_cum[16384u] : C4_LUT((num) / (den)))

/* table of bucketing class-3 T @VA 0x4379f8 (law row 13.621), capturee au runtime
 * (`_scratch/acccap13/rowtab.log`, dump 64*M() au BP 0x4103fa) - identical at the
 * table deduite some 29948 evenements (0 divergence). Index : d post-signe K[q]. */
const uint8_t alz_arena_c4_tbucket[256] = {
    0,1,2,3,4,5,6,7,7,8,8,9,9,10,10,10,
    11,11,11,11,11,12,12,12,12,12,12,12,12,13,13,13,
    13,13,13,13,13,13,13,13,13,13,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,
    17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,
    17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,
    17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,
    17,17,18,18,18,18,18,18,18,18,18,18,18,18,18,18,
    18,18,18,18,18,18,18,19,19,19,19,19,19,19,19,19,
    19,19,19,19,20,20,20,20,20,20,20,20,21,21,21,21,
    21,22,22,22,23,23,24,24,25,25,26,27,28,29,30,31
};

/* --- primitives Fenwick (13.618(3), mirror exact of the model Python) --- */
static void c4_fenwick_up(uint16_t *w, uint32_t sym, uint32_t inc)
{
    uint32_t i = sym + 1;
    while (i <= 0xFFu) {
        w[i] = M16((uint32_t)w[i] + inc);
        i += (i & ((uint32_t)0u - i));      /* i += lowbit(i) */
    }
}

static void c4_bit_rebuild(uint16_t *w)
{
    uint32_t c = 1;
    while (c <= 0x40u) {
        uint32_t p = 0x100u - 2u * c;
        while (p > 0u) {
            w[p] = M16((uint32_t)w[p] + w[p - c]);
            p -= 2u * c;
        }
        c <<= 1;
    }
}

static void c4_row_commit(alz_arena_c4_row *R)
{
    uint32_t tot = 0, k;
    for (k = 0; k < 256u; k++) {
        uint16_t b = R->freq[k];
        uint16_t d;
        if (b == 0u) continue;
        if (b <= 0x10u) { R->freq[k] = 0u; continue; }   /* 0, no cumulatif */
        d = (uint16_t)(b >> 1);
        R->freq[k] = d;
        tot += d;
    }
    for (k = 0; k < 255u; k++) R->bit[k + 1] = R->freq[k];
    R->bit[0] = M16(tot);
    c4_bit_rebuild(R->bit);
    R->d4 = M16(M16((uint32_t)R->d4 + 1u) >> 1);
    R->cc94 = M32(M32((tot & 0xFFFFu) + R->d4) << 8);
}

/* --- API publique --- */
void alz_arena_c4_init(alz_arena_c4_t *a)
{
    uint32_t r, i;
    memset(a, 0, sizeof(*a));
    for (r = 0; r < ALZ_ARENA_C4_ROWMAX; r++) {
        a->rows[r].d4 = 1u;        /* C1 : fixpoint of the PRIME commit */
        a->rows[r].cc94 = 256u;
    }
    for (i = 0; i < 256u; i++) {
        a->b405.freq[i] = 4u;      /* 13.615(2) : pre-armage d'init */
        a->b402.freq[i] = 4u;
    }
    a->b405.bit[0] = 1024u;        /* copie init 0x80f728 : BIT[x][0]=0x400 */
    a->b402.bit[0] = 1024u;
    a->b405.d4 = 0u;               /* bancs never scores hot : d4/cc94 inertes */
    a->b402.d4 = 0u;
}

void alz_arena_c4_mark_special(alz_arena_c4_t *a)
{
    a->special_pending = 1u;
}

/* Predit the cost sure l'state current, without NO mutation (13.701). Partage by
 * _event (before learn) and _score (reading pure by byte for `dens`). */
static uint32_t c4_pred_cost(const alz_arena_c4_t *a, const alz_arena_c4_row *R,
                             uint32_t sym, int esc_flag, uint32_t esc_sym,
                             uint16_t cell)
{
    if (cell != 0u) {
        /* ---- HOT (0x811bb0..) ---- */
        uint32_t total = (uint32_t)R->bit[0] + (uint32_t)R->d4;   /* C3 : no mask u16 */
        if (esc_flag) total -= R->freq[esc_sym];
        return C4_DIVLUT(((uint32_t)cell << 14), total);
    } else {
        /* ---- COLD (0x811bdd.. + re-ancre 0x811d08.. + scan 0x811eac..) ---- */
        uint32_t dx, c1, c2, present, escb, t2, i, s;
        dx = M16((uint32_t)R->bit[0] - (esc_flag ? R->freq[esc_sym] : 0u));
        c1 = dx ? C4_DIVLUT(((uint32_t)R->d4 << 14), dx + (uint32_t)R->d4) : 0u;

        present = a->b405.bit[0];
        if (R->bit[0] != 0u) {
            s = 0u;
            for (i = 0u; i < 256u; i++)
                if (R->freq[i] != 0u) s += a->b405.freq[i];
            present -= s;
        }
        escb = 0u;
        if (esc_flag && R->freq[esc_sym] == 0u) {
            escb = a->b405.freq[esc_sym];        /* 0x811f4e : test sure freq[line][esym], NOT dx */
        }
        t2 = M16(present - escb);
        c2 = C4_DIVLUT(((uint32_t)a->b405.freq[sym] << 14), t2);
        return c1 + c2;
    }
}

/* Learn C4 (0x81129d..) + path speciale 0x8122bf + gate, single MUTATIONS (13.701). */
static void c4_learn(alz_arena_c4_t *a, alz_arena_c4_row *R, uint32_t sym, uint16_t cell)
{
    if (cell == 0u && a->special_pending) {
        /* path 0x8122bf : re-seed of the banc 0x402 (weight 6) ; inerte for the cost (13.619). */
        a->special_pending = 0u;
        a->b402.freq[sym] = M16(a->b402.freq[sym] + ALZ_ARENA_C4_SEED402);
        c4_fenwick_up(a->b402.bit, sym, ALZ_ARENA_C4_SEED402);
        a->b402.bit[0] = M16(a->b402.bit[0] + ALZ_ARENA_C4_SEED402);
        a->n_seed402++;
    }
    {
        const uint32_t inc = ALZ_ARENA_C4_INC;
        uint16_t after;
        uint32_t gate;
        R->cc94 = M32(R->cc94 - (uint32_t)(R->d4 + cell));
        if (cell == 0u) {
            a->b405.freq[sym] = M16(a->b405.freq[sym] + ALZ_ARENA_C4_BENCH_W);
            c4_fenwick_up(a->b405.bit, sym, ALZ_ARENA_C4_BENCH_W);
            a->b405.bit[0] = M16(a->b405.bit[0] + ALZ_ARENA_C4_BENCH_W);
            a->n_seed405++;
            R->d4 = M16((uint32_t)R->d4 + inc);
        }
        R->freq[sym] = M16((uint32_t)R->freq[sym] + inc);
        c4_fenwick_up(R->bit, sym, inc);
        after = M16((uint32_t)R->bit[0] + inc);
        gate = (uint32_t)after + (uint32_t)R->d4;
        R->bit[0] = after;
        if (gate >= ALZ_ARENA_C4_GATE || R->cc94 > 0x7FFFFFFFu) {
            c4_row_commit(R);
            a->n_commit++;
        }
    }
}

/* [13.701 additif NO-BRANCH] Score pur (no mutation) for there law dens
 * score-by-byte ; not consumes NOT special_pending, not counts NOT. */
uint32_t alz_arena_c4_score(const alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym)
{
    const alz_arena_c4_row *R;
    if (row >= ALZ_ARENA_C4_ROWMAX || sym > 0xFFu || esc_sym > 0xFFu)
        return 0xFFFFFFFFu;
    R = &a->rows[row];
    return c4_pred_cost(a, R, sym, esc_flag, esc_sym, R->freq[sym]);
}

uint32_t alz_arena_c4_event(alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym)
{
    alz_arena_c4_row *R;
    uint32_t cost_pred;
    uint16_t cell;

    if (row >= ALZ_ARENA_C4_ROWMAX || sym > 0xFFu || esc_sym > 0xFFu) {
        return 0xFFFFFFFFu;                     /* contrat appelant viole */
    }
    R = &a->rows[row];
    cell = R->freq[sym];
    R->used = 1u;

    cost_pred = c4_pred_cost(a, R, sym, esc_flag, esc_sym, cell);
    if (cell != 0u) a->n_hot++; else a->n_cold++;
    c4_learn(a, R, sym, cell);
    return cost_pred;
}

void alz_arena_c4_commit(alz_arena_c4_t *a, uint32_t row)
{
    if (row < ALZ_ARENA_C4_ROWMAX) c4_row_commit(&a->rows[row]);
}

/*
 * Self-test lockstep : replays has stream TSV " rank ctx sym esc_flag esc_sym expected cmp special"
 * (decimal, whitespace ; produces by _scratch/acccap13/export_events.py) and compares the cost
 * renvoye by the module au cost of the model Python validated (13.619). cmp=1  rank whose the cost
 * Python is confirme contre `acc` live ; cmp=0 = ranks no couples au live (evenement special
 * and successeur, cf skip 13.618 C2). returns the number of divergences cmp=1 (objectif 0 ;
 * the gaps cmp=0 are affiches but toleres : the C applies there law, the GT live the exclut).
 */
int alz_arena_c4_replay(alz_arena_c4_t *a, const char *tsv_path)
{
    FILE *f;
    int rank, cmp, special;
    unsigned ctx, sym, eflag, esym;
    long expected;
    unsigned n = 0, ndiv = 0, nskipdiv = 0, ncmt = 0;
    uint32_t got;

    f = fopen(tsv_path, "r");
    if (!f) { fprintf(stderr, "alz_arena_c4_replay: ouverture %s impossible\n", tsv_path); return -1; }
    while (fscanf(f, "%d %u %u %u %u %ld %d %d",
                  &rank, &ctx, &sym, &eflag, &esym, &expected, &cmp, &special) == 8) {
        if (special) alz_arena_c4_mark_special(a);
        got = alz_arena_c4_event(a, ctx, sym, (int)eflag, esym);
        n++;
        if (got != (uint32_t)expected) {
            if (cmp) { ndiv++; printf("DIV1 rank=%d exp=%ld got=%u\n", rank, expected, got); }
            else     { nskipdiv++; printf("div0 rank=%d exp=%ld got=%u\n", rank, expected, got); }
        }
        ncmt += (got != 0xFFFFFFFFu);
    }
    fclose(f);
    printf("replay: %u events | hot=%u cold=%u commit=%u seed405=%u seed402=%u | BIT0[405]=%u\n",
           n, a->n_hot, a->n_cold, a->n_commit, a->n_seed405, a->n_seed402, a->b405.bit[0]);
    printf("replay: divergences cmp=1 : %u | cmp=0 (non couplees live) : %u\n", ndiv, nskipdiv);
    (void)ncmt;
    return (int)ndiv;
}
