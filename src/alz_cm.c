/*
 * alz_cm.c - primitives faithful of the CM delta-2D of legacy UHARC ALZ.
 * Voir alz_cm.h for the context RE (13.55/56/57/61/62). Module NO-WIRED.
 */
#include <stdint.h>
#include <stdio.h>
#include "alz_cm.h"

/* 13.55 - table of deltas en ring, deterministe.
 * TABLE[i] = (i < 2048) ? i : (4096 - i). */
void alz_cm_init_table(uint16_t table[ALZ_CM_RING])
{
    uint32_t i;
    for (i = 0; i < ALZ_CM_RING; i++)
        table[i] = (uint16_t)((i < ALZ_CM_RING_HALF) ? i : (ALZ_CM_RING - i));
}

/* 13.61 - rotation d'history (chain of differences) + sets of the delta.
 * Order exact lu in 0x415700 (captures BEFORE ecrasement) :
 *   h2 = h1_old ; h1 = delta - h0_old ; h3 = h2_old ; h0 = delta. */
void alz_cm_advance(alz_cm_record *rec, uint32_t base_octet, int32_t delta)
{
    uint32_t h0 = rec->h[0];
    uint32_t h1 = rec->h[1];
    uint32_t h2 = rec->h[2];

    rec->h[2] = h1;
    rec->h[1] = (uint32_t)delta - h0;
    rec->h[3] = h2;
    rec->h[0] = (uint32_t)delta;
    rec->base  = base_octet;
    rec->delta = delta;
}

/* 13.61 - hash context->line.
 * dot = (base<<4) + w0*delta + w1*h1 + w2*h2 + w3*h3 + w4*w4glob   (arith 32-bit wrap)
 * row = dot / 16  with troncature towards zero (l'idiome sar0x1f/shl4/sbb/sar4 of legacy).
 * Accumulation en uint32_t (wrap 2-complement), then division signee. */
uint32_t alz_cm_hash(const alz_cm_record *rec, uint32_t w4glob)
{
    uint32_t dot = 0;

    dot += rec->base << 4;
    dot += (uint32_t)(rec->w[0] * rec->delta);
    dot += (uint32_t)(rec->w[1] * (int32_t)rec->h[1]);
    dot += (uint32_t)(rec->w[2] * (int32_t)rec->h[2]);
    dot += (uint32_t)(rec->w[3] * (int32_t)rec->h[3]);
    dot += (uint32_t)(rec->w[4] * (int32_t)w4glob);

    return (uint32_t)((int32_t)dot / 16);
}

/* 13.56 - clamp of has weight in [-32, +32]. */
int32_t alz_cm_clamp_w(int32_t w)
{
    if (w > ALZ_CM_WMAX)
        return ALZ_CM_WMAX;
    if (w < ALZ_CM_WMIN)
        return ALZ_CM_WMIN;
    return w;
}

/* 13.100 - min-scan some 11 accumulateurs + nudge of weight via there table of SAUTS
 * reelle 0x415a5c (validated by desassembly + croisee with there trajectoire 13.99).
 * The winner is l'accu of value MIN (comparaison SIGNEE, `jbe`) ; all the 11
 * accu are remis has 0 (not only the winner) ; then dispatch :
 *   winner==0  (accu central `ring[err]`, rec+0x30)  -> NO nudge (table[>9] skips)
 *   winner 1..10 (pos k-1)                            -> weight w=(k-1)/2, direction=(k-1)%2
 *     direction pair -> -1 (side err - h),  direction impair -> +1 (side err + h) ; clamp +/-32.
 * Autrement dit there table 0x415a5c[0..9] =
 *   [ w0-1, w0+1, w1-1, w1+1, w2-1, w2+1, w3-1, w3+1, w4-1, w4+1 ].
 *  subtilite no still reproduite : the two nudges of w4 (idx8/9) are gardes by
 *   there bound of w3 (rec[0x20]) in the legacy engine, no of w4 ; without effet sure l'amorce
 *   image.raw (w3=0). Has reviser during of the rejeu complete (d8b). */
static int cm_minscan_core(uint32_t acc[ALZ_CM_NACC], int32_t w[ALZ_CM_NWEIGHT])
{
    int mini = -1, i;
    uint32_t mv = 0;

    for (i = 0; i < ALZ_CM_NACC; i++) {
        if (mini < 0 || (int32_t)acc[i] < (int32_t)mv) {
            mv = acc[i];
            mini = i;
        }
    }
    if (mini < 0)
        return -1;

    /* Reset some 11 accumulateurs (the legacy engine resets has 0 the 11, not the single winner). */
    for (i = 0; i < ALZ_CM_NACC; i++)
        acc[i] = 0;

    /* winner 0 = accu central -> no nudge. winner 1..10 -> table of sauts. */
    if (mini == 0)
        return mini;
    {
        int k = mini - 1;                 /* index table 0x415a5c : 0..9 */
        int widx = k / 2;                 /* w0..w4 */
        int dir  = (k & 1) ? +1 : -1;     /* pair: err-h (1) ; impair: err+h (+1) */
        if (widx < ALZ_CM_NWEIGHT)
            w[widx] = alz_cm_clamp_w(w[widx] + dir);
    }
    return mini;
}

int alz_cm_minscan_nudge(alz_cm_record *rec)
{
    return cm_minscan_core(rec->acc, rec->w);
}

/* MaJ some 11 accumulateurs via l'ring triangulaire, sure err and the 5 histoires.
 * validated 165/165 (window) then 583/616 sure 60 pos (out artefacts of reset) - 13.100/101. */
static void cm_ring_update(uint32_t acc[ALZ_CM_NACC], int32_t err, const uint32_t h[ALZ_CM_LHIST])
{
    acc[0]  += alz_cm_ring_value((uint32_t)(err));
    acc[1]  += alz_cm_ring_value((uint32_t)(err - (int32_t)h[0]));
    acc[2]  += alz_cm_ring_value((uint32_t)(err + (int32_t)h[0]));
    acc[3]  += alz_cm_ring_value((uint32_t)(err - (int32_t)h[1]));
    acc[4]  += alz_cm_ring_value((uint32_t)(err + (int32_t)h[1]));
    acc[5]  += alz_cm_ring_value((uint32_t)(err - (int32_t)h[2]));
    acc[6]  += alz_cm_ring_value((uint32_t)(err + (int32_t)h[2]));
    acc[7]  += alz_cm_ring_value((uint32_t)(err - (int32_t)h[3]));
    acc[8]  += alz_cm_ring_value((uint32_t)(err + (int32_t)h[3]));
    acc[9]  += alz_cm_ring_value((uint32_t)(err - (int32_t)h[4]));
    acc[10] += alz_cm_ring_value((uint32_t)(err + (int32_t)h[4]));
}

/* 16 signe towards zero, idiom x86 (sar0x1f/shl4/sbb/sar4) ; validated 38/38 13.102. */
static uint32_t cm_div16_signed(int32_t v)
{
    return (uint32_t)((v >= 0) ? (v / 16) : (-((-v) / 16)));
}

/*
 * alz_cm_learn_step - no learning of the finder legacy (0x415ab0), FAITHFUL
 * 13.100. Formule validated bit-exact contre there captures GT `learnstate` :
 *   - increments d'ring some 11 accu : 165/165 (window pos1..15)
 *   - declenchement + winner + nudge at the frontier counter=16 : w0 0->1
 * Conventions exact lues in the desassemblage :
 *   err = movsbl( (row_hash_byte - (v_cur & 0xff)) ) << 4      (arith 8-bit then <<4)
 *   acc[0]     += ring[ (err)          & 0xfff ]               ; term central
 *   acc[1+2k]  += ring[ (err - hist[k])& 0xfff ] ; acc[2+2k] += ring[(err + hist[k])&0xfff]
 *   delta = v_cur - v ; v = v_cur ; counter++ ; if (counter & 0xf)==0 : min-scan.
 *  L'appelant (selecteur/cablage d8c) doit to set L->hist[0..4] = rec[0x00..0x10]
 *   legacy BEFORE this call (chain d'histoires). Here no-wired, therefore no effet.
 */
void alz_cm_learn_step(alz_cm_learner *L, uint32_t row_hash_byte, uint32_t v_cur)
{
    uint8_t sub8 = (uint8_t)(row_hash_byte - (v_cur & 0xffu));
    int32_t err  = (int32_t)(int8_t)sub8 * 16;   /* movsbl of the result 8-bit, then shl 4 */

    cm_ring_update(L->acc, err, L->hist);

    L->delta = (int32_t)(v_cur - L->v);
    L->v = v_cur;
    L->counter++;
    if ((L->counter & 0xfu) == 0u)
        (void)cm_minscan_core(L->acc, L->w);
}

/*
 * alz_cm_rotate_hist - rotation EXACT some 5 operandes of the dot legacy (13.113).
 * To read the old values before write (FIFO of differences 2d + lookup arena).
 *   hist[4] = dr_ref = DR[(line-ref)&127]  (operande w4 ; COUPLAGE arena->CM).
 */
void alz_cm_rotate_hist(alz_cm_learner *L, int32_t d_cur, int32_t dr_ref)
{
    uint32_t o0 = L->hist[0], o1 = L->hist[1], o2 = L->hist[2];
    L->hist[0] = (uint32_t)d_cur;
    L->hist[1] = (uint32_t)(d_cur - (int32_t)o0);
    L->hist[2] = o1;
    L->hist[3] = o2;
    L->hist[4] = (uint32_t)dr_ref;
}

/*
 * alz_cm_learn_byte - composite validated GT 13.115 (rejeu cold 0..83 : row_hash
 * 83/83 + weight 84/84 contre captures BP 0x415804). PHASE SPLIT intra-line epinglee :
 * the path d'learning reads l'hist has phase RETARDEE, the dot has phase current.
 *   - err = movsbl(prev_dot - v_cur) ; prev_dot = row_hash@{i-1} = dot NOT previous ;
 *   - MaJ ring (acc->minscan) sure hist entrante (delta_{i-1}) ;
 *   - minscan (counter&0xf==0) : nudge some weight ;
 *   - rotate hist towards delta current D = byte_i - byte_{i-1} ;
 *   - dot = (v<<4) + Sigma w_postnudge * hist_courant -> prev_dot_full = row_hash@i.
 * 13.103/13.113 had modelise the dot by DELTA RETARDE and WEIGHT PRE-SCAN : there
 * captures au moment of sets of the dot revele there correction of phase (13.115).
 * L'initialisation (acc/w/hist/prev_dot to the bounds of reset) and dr_ref (arena) are
 * there loads of l'appelant ; here no-wired, therefore no effect d'encoding.
 */
void alz_cm_learn_byte(alz_cm_learner *L, uint8_t byte_cur, uint8_t byte_prev1, uint8_t byte_prev2, int32_t dr_ref)
{
    int32_t  d = (int32_t)byte_cur - (int32_t)byte_prev1;     /* delta current (rotation->dot, 13.115) */
    int32_t  v = (int32_t)byte_cur - 0x80;                    /* base current */
    uint8_t  sub8 = (uint8_t)((uint8_t)L->prev_dot - (uint8_t)v);
    int32_t  err  = (int32_t)(int8_t)sub8 * 16;
    int32_t  dot;
    int      k;

    (void)byte_prev2;  /* no requis : there string d'histoires porte the crans passes */

    /* ORDER LEGACY intra-line, epingle by captures BP 0x415804 (13.115) :
     *   (has) finder maj some 11 accu sure l'hist ENTRANTE (delta_{i-1}, phase RETARDEE)
     *       via err = movsbl(row_hash@{i-1} - v_cur) ;
     *   (b) minscan (all the 16) sure these accu -> nudge some weight + reset accu :
     *       the SELECTEUR reads the weight POST-nudge (verified : w change @15/31/47/79) ;
     *   (c) rotation of l'hist towards the delta current (hist0<-d_i, hist1<-d_i-d_{i-1}) ;
     *   (d) dot = (v<<4) + sum(w_postnudge * hist_courant) -> 0x44d8d8 (row_hash@i).
     * The path acc->minscan remainder therefore has phase RETARDEE (pos31/pos47) tandis that the
     * dot/row_hash is has phase current : fixes the +/-1 some there 1ere transition of
     * delta no-zero (i=71). */
    cm_ring_update(L->acc, err, L->hist);
    L->counter++;
    if ((L->counter & 0xfu) == 0u)
        (void)cm_minscan_core(L->acc, L->w);

    alz_cm_rotate_hist(L, d, dr_ref);

    /* prev_dot for the NOT next : weight AFTER scan of this not (13.115).
     * prev_dot_full = dot/16 SIGNE complete (= 0x44d8d8 legacy ; requis by the
     * predicteur p3 of l'arbitre, which peut to be <0 now >255 out window cold).
     * prev_dot = low-byte ( full when |dot/16|<256) : sert at the err 8-bit 13.100. */
    dot = (v << 4);
    for (k = 0; k < ALZ_CM_NWEIGHT; k++)
        dot += L->w[k] * (int32_t)L->hist[k];
    L->prev_dot_full = cm_div16_signed(dot);
    L->prev_dot = (uint32_t)L->prev_dot_full & 0xffu;

    L->delta = (int32_t)(v - (int32_t)L->v);
    L->v = (uint32_t)v;
}

/* 13.57 - rescale by halving of counters 16-bit packes.
 * v &= 0xfffefffe ; v >>= 1  (moitiene each demi-counter without deborder sure l'other). */
void alz_cm_rescale_halving(uint32_t *arena, uint32_t ndwords)
{
    uint32_t i;
    for (i = 0; i < ndwords; i++) {
        uint32_t v = arena[i] & 0xfffefffeu;
        arena[i] = v >> 1;
    }
}

/* ---- Self-test deterministe (validation some primitives ; n'affecte not l'encoding) ---- */
/* ===== arena of score multi-candidates (13.108, validated bit-exact, no-wired) ===== */
void alz_arena_init(alz_arena *A)
{
    uint32_t i;
    for (i = 0; i < ALZ_ARENA_DRING; i++) A->dr[i]   = 0u;
    for (i = 0; i < ALZ_ARENA_NCOST; i++) A->cost[i] = 0u;
    A->ref  = 2u;
    A->b8   = 2u;
    A->line = 0u;
}

void alz_arena_step(alz_arena *A, uint8_t byte_cur, uint8_t byte_prev, int entered)
{
    uint32_t line   = A->line;
    int32_t  delta  = (int32_t)byte_cur - (int32_t)byte_prev;
    A->dr[line & 0x7fu] = (uint32_t)delta;      /* sets of the delta in l'ring */
    if (entered) {
        uint32_t ref = 2u, b8 = 2u, edi = 0xffffu;
        uint32_t eax;
        for (eax = ALZ_ARENA_EAX0; eax < ALZ_ARENA_EAXN; eax++) {
            int32_t  d0 = (int32_t)A->dr[(line - 1u) & 0x7fu] - (int32_t)A->dr[(line - 1u - eax) & 0x7fu];
            int32_t  d1 = (int32_t)A->dr[(line      ) & 0x7fu] - (int32_t)A->dr[(line      - eax) & 0x7fu];
            int32_t  d2 = (int32_t)A->dr[(line - 2u) & 0x7fu] - (int32_t)A->dr[(line - 2u - eax) & 0x7fu];
            uint32_t cn = alz_cm_ring_value((uint32_t)d0)
                        + alz_cm_ring_value((uint32_t)d1)
                        + alz_cm_ring_value((uint32_t)d2);
            uint32_t nc = ((13u * A->cost[eax]) >> 4) + cn;   /* cn adds AFTER shift */
            A->cost[eax] = nc;
            if (nc < A->cost[ref]) ref = eax;                 /* argmin cost (strict) */
            if (cn < edi)         { edi = cn; b8 = eax; }     /* argmin cn raw (strict) */
        }
        A->ref = ref;
        A->b8  = b8;
    }
    A->line++;
}

/* ===== Arbitre of classes (13.109, validated, no-wired) ===== */
/* Table bucket 0x437b10[0..0x1ff] : magnitude circulaire (tente symetrique).
 * Extract bit-exact of legacy ; 0/420 conflit vs paires empiriques (13.109). */
static const uint16_t alz_arb_bucket[512] = {
    0,1,2,2,2,3,3,3,3,3,4,4,4,4,4,4,
    4,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,
    6,6,6,6,6,7,7,7,7,7,7,7,7,7,7,7,
    7,7,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    9,9,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,11,11,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,
    12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,
    12,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,
    13,13,13,13,13,13,13,13,13,13,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
    16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
    16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
    16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,15,
    15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,
    15,15,15,15,15,15,15,15,15,15,15,15,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,13,13,13,13,13,13,13,13,13,
    13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,
    12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,
    12,12,12,12,12,12,12,11,11,11,11,11,11,11,11,11,
    11,11,11,11,11,11,11,11,11,11,11,11,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,9,
    9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,7,
    7,7,7,7,7,7,7,7,7,7,7,7,6,6,6,6,
    6,6,6,6,6,6,6,5,5,5,5,5,5,5,5,5,
    4,4,4,4,4,4,4,3,3,3,3,3,2,2,2,1,
};

void alz_arb_init(alz_arb *R)
{
    uint32_t c, i;
    for (c = 0; c < ALZ_ARB_NCLASS; c++) {
        for (i = 0; i < ALZ_ARB_RING; i++) R->ring[c][i] = 0u;
        R->total[c] = 0u;
    }
    R->idx  = 0u;
    R->line = 0u;
}

void alz_arb_step(alz_arb *R, const int32_t diff[ALZ_ARB_NCLASS])
{
    uint32_t slot = R->line & 0xffu;
    uint32_t c, idx = 0u;
    for (c = 0; c < ALZ_ARB_NCLASS; c++) {
        uint32_t b = alz_arb_bucket[(uint32_t)diff[c] & 0x1ffu];
        R->total[c] = R->total[c] - R->ring[c][slot] + b;   /* window 256 */
        R->ring[c][slot] = b;
    }
    for (c = 1; c < ALZ_ARB_NCLASS; c++)                    /* argmin strict, first-min */
        if (R->total[c] < R->total[idx]) idx = c;
    R->idx = idx;
    R->line++;
}

void alz_arb_predict(alz_arb *R, int32_t base_i, int32_t base_prev, int32_t base_prev2,
                     int32_t delta_i, int32_t dr_ref, int32_t dr_b8, int32_t row_hash)
{
    int32_t d[ALZ_ARB_NCLASS];
    d[0] = base_i;                                  /* p0 = 0            */
    d[1] = base_i - base_prev;                       /* p1 = base_{i-1}   */
    d[2] = base_i - (2 * base_prev - base_prev2);    /* p2 = extrapolation*/
    d[3] = base_i - row_hash;                        /* p3 = row_hash CM  */
    d[4] = delta_i - dr_ref;                         /* p4 = DR[(line-ref_prev)] */
    d[5] = delta_i - dr_b8;                          /* p5 = DR[(line-b8_prev)]  */
    alz_arb_step(R, d);
}

static int st_check(int cond, const char *name)
{
    if (!cond)
        fprintf(stderr, "[CM-TEST] FAIL: %s\n", name);
    return cond ? 0 : 1;
}

int alz_cm_selftest(void)
{
    int bad = 0;
    uint16_t table[ALZ_CM_RING];
    uint32_t arena[4];
    alz_cm_record rec;
    int i;

    /* TABLE ring (13.55) */
    alz_cm_init_table(table);
    bad += st_check(table[0] == 0, "TABLE[0]==0");
    bad += st_check(table[2047] == 2047, "TABLE[2047]==2047");
    bad += st_check(table[2048] == 2048, "TABLE[2048]==2048");
    bad += st_check(table[4095] == 1, "TABLE[4095]==1");
    bad += st_check(alz_cm_ring_index(1) == 16u, "ring_index(1)==16");
    bad += st_check(alz_cm_ring_index(255) == (uint32_t)((255 << 4) & 0xfff), "ring_index(255)");

    /* clamp +/-32 (13.56) */
    bad += st_check(alz_cm_clamp_w(100) == ALZ_CM_WMAX, "clamp(100)==32");
    bad += st_check(alz_cm_clamp_w(-100) == ALZ_CM_WMIN, "clamp(-100)==-32");
    bad += st_check(alz_cm_clamp_w(-5) == -5, "clamp(-5)==-5");

    /* halving (13.57) : 0x00020004 -> two demi (0x0002,0x0004) moities (0x0001,0x0002) */
    arena[0] = 0x00020004u;
    arena[1] = 0x00010003u;   /* demi-high 0x0001 perd son LSB -> 0 ; demi-low 0x0003 -> 0x0002 */
    arena[2] = 0x00000000u;
    arena[3] = 0xFFFFFFFFu;   /* after &0xfffefffe (0xfffefffe) then >>1 = 0x7fff7fff */
    alz_cm_rescale_halving(arena, 4);
    bad += st_check(arena[0] == 0x00010002u, "halving 0x00020004");
    bad += st_check(arena[1] == 0x00000001u, "halving 0x00010003");
    bad += st_check(arena[2] == 0x00000000u, "halving 0");
    bad += st_check(arena[3] == 0x7fff7fffu, "halving 0xffffffff");

    /* rotation d'history + hash (13.61), cas simple deterministic */
    for (i = 0; i < ALZ_CM_NHIST; i++) rec.h[i] = 0;
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 0;
    rec.base = 0; rec.delta = 0; rec.counter = 0;

    /* weight zero -> dot = base<<4 ; row = base<<4 /16 = base (troncat). Test base=5. */
    alz_cm_advance(&rec, 5u, 0);
    bad += st_check(alz_cm_hash(&rec, 0) == 5u, "hash(w=0,base=5)==5");

    /* advances : h0=delta=3, h1=3-0=3 (delta - h0_old=0). w0=16 -> dot += 16*3=48 ; base<<4=0. */
    rec.w[0] = 16;
    alz_cm_advance(&rec, 0u, 3);       /* h0=3, h1=3-3(prev h0? prev h0=0 from above? rec.h0 was 0) */
    /* to score : h0_old was 0 (initial), delta=3 -> h1=3, h0=3, delta field=3 */
    /* dot = 0<<4 + 16*3(delta) + 0 + 0 + 0 + 0 = 48 -> 48/16 = 3 */
    bad += st_check(alz_cm_hash(&rec, 0) == 3u, "hash(w0=16,delta=3)==3");

    /* min-scan + nudge via table of SAUTS (13.100). Scenarios deterministes. */
    /* (i) winner = accu central (index 0) -> NO nudge, all the accu has 0. */
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 100 + (uint32_t)i;
    {
        int m = alz_cm_minscan_nudge(&rec);
        bad += st_check(m == 0, "minscan winner==0 (acc[0]=100 min)");
        bad += st_check(rec.acc[0] == 0, "minscan reset acc[0]");
        bad += st_check(rec.acc[5] == 0, "minscan reset ALL accu[5]");
        bad += st_check(rec.w[0] == 0 && rec.w[4] == 0, "winner0 => aucun nudge");
    }
    /* (ii) winner = acc[1] (k=0) -> w0 -1. */
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 100;
    rec.acc[0] = 50; rec.acc[1] = 1;      /* min = acc[1] (ignores acc[0] no min) */
    rec.acc[0] = 999;                     /* central no winner */
    { int m = alz_cm_minscan_nudge(&rec);
      bad += st_check(m == 1, "minscan winner==1");
      bad += st_check(rec.w[0] == -1, "winner1 (k0 pair) => w0-1"); }
    /* (iii) winner = acc[2] (k=1) -> w0 +1. */
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 100;
    rec.acc[0] = 999; rec.acc[2] = 1;
    { int m = alz_cm_minscan_nudge(&rec);
      bad += st_check(m == 2, "minscan winner==2");
      bad += st_check(rec.w[0] == 1, "winner2 (k1 impair) => w0+1"); }
    /* (iv) winner = acc[9] (k=8) -> w4-1 ; (v) acc[10] (k=9) -> w4+1. */
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 100;
    rec.acc[0] = 999; rec.acc[9] = 1;
    { int m = alz_cm_minscan_nudge(&rec);
      bad += st_check(m == 9, "minscan winner==9");
      bad += st_check(rec.w[4] == -1, "winner9 (k8) => w4-1"); }
    for (i = 0; i < ALZ_CM_NWEIGHT; i++) rec.w[i] = 0;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 100;
    rec.acc[0] = 999; rec.acc[10] = 1;
    { int m = alz_cm_minscan_nudge(&rec);
      bad += st_check(m == 10, "minscan winner==10");
      bad += st_check(rec.w[4] == 1, "winner10 (k9) => w4+1"); }

    /* nudge bound : w already has -32, winner-> w0-1 doit rester -32 (clamp). */
    rec.w[0] = ALZ_CM_WMIN;
    for (i = 0; i < ALZ_CM_NACC; i++) rec.acc[i] = 500;
    rec.acc[0] = 999; rec.acc[1] = 1;   /* winner=acc[1] (k0 pair) => w0-1 clamp */
    (void)alz_cm_minscan_nudge(&rec);
    bad += st_check(rec.w[0] == ALZ_CM_WMIN, "nudge clamp bas ==-32");

    /* --- alz_cm_learn_step : rejeu contre GT `learnstate` (13.100) ---
     *  (has) increments d'ring pos1 (165/165 validated out-line)
     *  (b) frontier counter=16 : rejeu pos15 since state pos14 -> minscan w0 0->1 */
    {
        static const uint32_t GT_HIST1[ALZ_CM_LHIST]  = { 39u, 39u, 0u, 0u, 0u };
        static const uint32_t GT_ACC14[ALZ_CM_NACC]   = { 944u,1002u,932u,990u,988u,957u,989u,990u,956u,1000u,934u };
        static const uint32_t GT_HIST15[ALZ_CM_LHIST] = { 1u, 0xffffffffu, 1u, 0xffffffffu, 2u };
        static const uint32_t EXP_INCR1[ALZ_CM_NACC]  = { 16u,55u,23u,55u,23u,16u,16u,16u,16u,16u,16u };
        alz_cm_learner L;
        int k, ok;

        /* (has) not isolement-ring : acc=0, counter=0 (->1, no scan). */
        for (k = 0; k < ALZ_CM_NACC; k++) L.acc[k] = 0;
        for (k = 0; k < ALZ_CM_NWEIGHT; k++) L.w[k] = 0;
        for (k = 0; k < ALZ_CM_LHIST; k++) L.hist[k] = GT_HIST1[k];
        L.v = 39u; L.delta = 0; L.counter = 0;
        alz_cm_learn_step(&L, 39u, 40u);
        ok = 1;
        for (k = 0; k < ALZ_CM_NACC; k++) if (L.acc[k] != EXP_INCR1[k]) ok = 0;
        bad += st_check(ok, "learn_step ring-increment pos1 == GT");

        /* (b) frontier : pre-loads acc=state pos14, counter=15, replays pos15. */
        for (k = 0; k < ALZ_CM_NACC; k++) L.acc[k] = GT_ACC14[k];
        for (k = 0; k < ALZ_CM_NWEIGHT; k++) L.w[k] = 0;
        for (k = 0; k < ALZ_CM_LHIST; k++) L.hist[k] = GT_HIST15[k];
        L.v = 59u; L.counter = 15u;
        alz_cm_learn_step(&L, 59u, 60u);
        bad += st_check(L.counter == 16u, "learn_step counter->16");
        bad += st_check(L.w[0] == 1, "learn_step minscan w0 0->1 (GT pos15->16)");
        ok = 1;
        for (k = 0; k < ALZ_CM_NACC; k++) if (L.acc[k] != 0) ok = 0;
        bad += st_check(ok, "learn_step minscan reset 11 accu");

        /* (c) rotation : amorce pos1 [39,39,0,0,0], D pos2..4 = 1,1,2. dr_ref =
         *   rec3 = DR[(line-ref)&127] ; sure this front cold ref=2 const ->
         *   DR[0]=base_0=39, DR[1]=1, DR[2]=1 (== old D_prev asserts). 13.113 */
        for (k = 0; k < ALZ_CM_LHIST; k++) L.hist[k] = (uint32_t)(int32_t)GT_HIST1[k]; /* [39,39,0,0,0] */
        alz_cm_rotate_hist(&L, 1, 39);
        bad += st_check(L.hist[0]==1u && (int32_t)L.hist[1]==-38 && L.hist[2]==39u
                        && L.hist[3]==0u && L.hist[4]==39u, "rotate_hist pos2 == GT");
        alz_cm_rotate_hist(&L, 1, 1);
        bad += st_check(L.hist[0]==1u && L.hist[1]==0u && (int32_t)L.hist[2]==-38
                        && L.hist[3]==39u && L.hist[4]==1u, "rotate_hist pos3 == GT");
        alz_cm_rotate_hist(&L, 2, 1);
        bad += st_check(L.hist[0]==2u && L.hist[1]==1u && L.hist[2]==0u
                        && (int32_t)L.hist[3]==-38 && L.hist[4]==1u, "rotate_hist pos4 == GT");

        /* (d) supersession : the verrou composite hand-seeded (approx. dr_ref=D_prev,
         *     old order rotate->ring->dot->minscan) is REPLACES by the rejeu GT
         *     cold complete 13.115 ci-dessous (dr_ref = arena reelle, order correle). */
    }

    /* --- 13.115 verrou GT " phase split " : rejeu COLD complete image.raw[0..83]
    *     via alz_cm_learn_byte, dr_ref = trajectoire d'arena capturee (hist4 au dot,
    *     BP 0x415804). Epingle l'order intra-line legacy correle :
    *       (has) ring sure hist entrant (retarde) -> (b) minscan/nudge weight
    *       -> (c) rotate towards delta current -> (d) dot with weight POST-nudge.
    *   - prev_dot_full(step i) == 0x44d8d8@(i+1)  (row_hash CM, predicteur p3) ;
    *   - w0/w4@(i) == trajectoire legacy post-minscan (nudges pos15/31/47/79, whose
    *     the tie pos47 idx10->w4+1). validated 83/83 row_hash + 84/84 weight (harnais GT). */
    {
        static const uint8_t GT_BYTES[84] = {   /* image.raw[0..83] */
            167, 168, 169, 171, 172, 174, 175, 177, 178, 180, 181, 183, 184, 186, 187,
            188, 190, 191, 193, 194, 195, 197, 198, 199, 200, 202, 203, 204, 205, 206,
            207, 208, 210, 211, 212, 213, 213, 214, 215, 216, 217, 218, 219, 219, 220,
            221, 221, 222, 222, 223, 223, 224, 224, 225, 225, 225, 226, 226, 226, 226,
            226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 225, 225, 225, 224,
            224, 223, 223, 222, 222, 221, 220, 220, 219 };
        static const int32_t GT_DRREF[84] = {   /* hist4 au dot = DR[(line-ref)&127] */
            0, 39, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 1, 2, 1, 2, 1, 1, 2, 1,
            1, 1, 2, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
            0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, -1, 0, 0, -1, 0, 0, -1, -1, 0 };
        static const int32_t GT_RH[84] = {      /* 0x44d8d8@i = dot@{i-1} (p3=row_hash CM) */
            0, 39, 40, 41, 43, 44, 46, 47, 49, 50, 52, 53, 55, 56,
            58, 59, 60, 62, 63, 65, 66, 67, 69, 70, 71, 72, 74, 75,
            76, 77, 78, 79, 80, 82, 83, 84, 85, 85, 86, 87, 88, 89,
            90, 91, 91, 92, 93, 93, 94, 94, 95, 95, 96, 96, 97, 97,
            97, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98,
            98, 98, 96, 97, 97, 95, 95, 94, 95, 93, 94, 92, 91, 91 };
        static const int32_t GT_W0[84] = {      /* weight w0 post-minscan */
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 1, 1, 1, 1, 1 };
        static const int32_t GT_W4[84] = {      /* weight w4 post-minscan (tie pos47) */
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1 };
        alz_cm_learner L;
        int k, i, okrh = 1, okw = 1;
        for (k = 0; k < ALZ_CM_NACC; k++)    L.acc[k] = 0;
        for (k = 0; k < ALZ_CM_NWEIGHT; k++) L.w[k] = 0;
        for (k = 0; k < ALZ_CM_LHIST; k++)   L.hist[k] = 0;
        L.v = 0; L.delta = 0; L.counter = 0; L.prev_dot = 0; L.prev_dot_full = 0;
        for (i = 0; i < 84; i++) {
            uint8_t b1 = (i >= 1) ? GT_BYTES[i - 1] : 0x80u;
            uint8_t b2 = (i >= 2) ? GT_BYTES[i - 2] : 0x80u;
            alz_cm_learn_byte(&L, GT_BYTES[i], b1, b2, GT_DRREF[i]);
            if (L.w[0] != GT_W0[i] || L.w[4] != GT_W4[i]) okw = 0;   /* post-minscan(i) */
            if (i + 1 < 84 && (int32_t)L.prev_dot_full != GT_RH[i + 1]) okrh = 0;
        }
        bad += st_check(okrh, "cm 13.115 row_hash prev_dot_full == GT 0x44d8d8 (83/83)");
        bad += st_check(okw,  "cm 13.115 poids w0/w4 == GT post-minscan (84/84, tie pos47)");
    }

    /* --- 13.108 arena of score : rejeu bit-exact vs GT (ref/b8 70/70, cost checkpoints).
     *     Verrou of regression of the scorer d'arena (no-wired). Schedule d'input observe
     *     sure the 1er block image.raw : line=0 (idx0/masque127) then idx4/masque7 -> (line&7)==0. */
    {
        static const uint8_t AB[70] = {   /* image.raw[0..69] */
            167,168,169,171,172,174,175,177,178,180,181,183,184,186,187,188,190,191,193,194,
            195,197,198,199,200,202,203,204,205,206,207,208,210,211,212,213,213,214,215,216,
            217,218,219,219,220,221,221,222,222,223,223,224,224,225,225,225,226,226,226,226,
            226,226,226,226,226,226,226,226,226,226 };
        static const int32_t GT_REF[70] = {
            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,5,5,5,5,5,5,5,5,5,5,5,5,5,5 };
        static const int32_t GT_B8[70] = {
            2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,13,13,13,13,13,13,13,13,2,2,2,2,2,2,2,2,7,7,7,7,7,7,7,7,
            5,5,5,5,5,5,5,5,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,2,2,2,2,2,2 };
        static const uint32_t GT_C0[6]  = {39,39,39,39,39,39};
        static const uint32_t GT_C8[6]  = {31,34,31,33,70,69};
        static const uint32_t GT_C16[6] = {27,28,27,27,58,57};
        static const uint32_t GT_C24[6] = {22,23,22,22,49,47};
        alz_arena A;
        int i, k, okr = 0, okb = 0, okc = 0;
        const uint32_t *gc;
        alz_arena_init(&A);
        for (i = 0; i < 70; i++) {
            int entered = (i == 0) || (i >= 8 && (i & 7) == 0);
            uint8_t prev = (i > 0) ? AB[i - 1] : 0x80u;
            alz_arena_step(&A, AB[i], prev, entered);
            if ((int32_t)A.ref != GT_REF[i]) okr++;
            if ((int32_t)A.b8  != GT_B8[i])  okb++;
            if (entered) {
                gc = (i == 0) ? GT_C0 : (i == 8) ? GT_C8 : (i == 16) ? GT_C16 : (i == 24) ? GT_C24 : 0;
                if (gc) for (k = 0; k < 6; k++) if (A.cost[2 + k] != gc[k]) okc++;
            }
        }
        bad += st_check(okr == 0, "arena ref 70/70 == GT (13.108)");
        bad += st_check(okb == 0, "arena b8  70/70 == GT (13.108)");
        bad += st_check(okc == 0, "arena cost[2..7] checkpoints pos0/8/16/24 == GT (13.108)");

        /* --- 13.110 chain byte-only : bytes + refs arena (line prev) +
         *     row_hash (CM) -> assemble the 6 diff -> arbitre -> idx. Verrouille
         *     there reformulation byte-only some predicteurs (no-wired). */
        static const int32_t PROWH[70] = {   /* p3 = row_hash legacy (injecte ; single between model) */
            0,39,40,41,43,44,46,47,49,50,52,53,55,56,
            58,59,60,62,63,65,66,67,69,70,71,72,74,75,
            76,77,78,79,80,82,83,84,85,85,86,87,88,89,
            90,91,91,92,93,93,94,94,95,95,96,96,97,97,
            97,98,98,98,98,98,98,98,98,98,98,98,98,98 };
        static const uint32_t GIDX[70] = {   /* GT idx (arbitre) */
            0,1,1,1,1,1,1,4,4,4,4,4,4,4,
            4,4,4,4,4,4,4,4,4,4,4,4,4,4,
            4,4,4,4,4,4,4,4,4,4,5,4,4,4,
            4,4,4,4,4,4,4,4,4,4,4,4,4,4,
            4,4,5,4,4,5,5,5,5,5,5,5,5,5 };
        alz_arb R2;
        int okp = 0;
        alz_arb_init(&R2);
        for (i = 0; i < 70; i++) {
            int32_t b_i  = (int32_t)AB[i] - 0x80;
            int32_t b_p1 = (i >= 1) ? (int32_t)AB[i-1] - 0x80 : 0;
            int32_t b_p2 = (i >= 2) ? (int32_t)AB[i-2] - 0x80 : 0;
            int32_t dl   = (i >= 1) ? (int32_t)AB[i] - (int32_t)AB[i-1] : (int32_t)AB[0] - 0x80;
            int32_t refp = (i >= 1) ? GT_REF[i-1] : 2;
            int32_t b8p  = (i >= 1) ? GT_B8[i-1]  : 2;
            int32_t jr = i - refp, jb = i - b8p;
            int32_t dr_ref = (jr >= 1) ? (int32_t)AB[jr] - (int32_t)AB[jr-1]
                       : (jr == 0) ? (int32_t)AB[0] - 0x80 : 0;
            int32_t dr_b8  = (jb >= 1) ? (int32_t)AB[jb] - (int32_t)AB[jb-1]
                       : (jb == 0) ? (int32_t)AB[0] - 0x80 : 0;
            alz_arb_predict(&R2, b_i, b_p1, b_p2, dl, dr_ref, dr_b8, PROWH[i]);
            if (R2.idx != GIDX[i]) okp++;
        }
        bad += st_check(okp == 0, "arb byte-only predict idx 70/70 == GT (13.110)");
    }

    /* --- 13.109 arbitre of classes : rejeu idx vs GT (6 diff captures -> argmin).
     *     Verrou of regression of l'arbitre (no-wired). The 6 diff are fournis
     *     (predicteurs out module) ; on validates window-256 + bucket + argmin. */
    {
        static const int32_t GT_DIFF[70][6] = {
            {39,39,39,39,39,39},{40,1,-38,1,1,1},{41,1,0,1,-38,-38},{43,2,1,2,1,1},
            {44,1,-1,1,0,0},{46,2,1,2,0,0},{47,1,-1,1,0,0},{49,2,1,2,0,0},
            {50,1,-1,1,0,0},{52,2,1,2,0,0},{53,1,-1,1,0,0},{55,2,1,2,0,0},
            {56,1,-1,1,0,0},{58,2,1,2,0,0},{59,1,-1,1,0,0},{60,1,0,1,-1,-1},
            {62,2,1,2,1,1},{63,1,-1,1,0,0},{65,2,1,2,0,0},{66,1,-1,1,0,0},
            {67,1,0,1,-1,-1},{69,2,1,2,1,1},{70,1,-1,1,0,-1},{71,1,0,1,-1,0},
            {72,1,0,1,0,-1},{74,2,1,2,1,1},{75,1,-1,1,0,0},{76,1,0,1,-1,-1},
            {77,1,0,1,0,0},{78,1,0,1,0,0},{79,1,0,1,0,0},{80,1,0,1,0,0},
            {82,2,1,2,1,1},{83,1,-1,1,0,0},{84,1,0,1,-1,0},{85,1,0,1,0,0},
            {85,0,-1,0,-1,-1},{86,1,1,1,0,0},{87,1,0,1,1,0},{88,1,0,1,0,-1},
            {89,1,0,1,0,0},{90,1,0,1,0,1},{91,1,0,1,0,0},{91,0,-1,0,-1,-1},
            {92,1,1,1,0,0},{93,1,0,1,1,0},{93,0,-1,0,-1,-1},{94,1,1,1,0,0},
            {94,0,-1,0,0,0},{95,1,1,1,0,0},{95,0,-1,0,0,0},{96,1,1,1,0,0},
            {96,0,-1,0,0,0},{97,1,1,1,0,0},{97,0,-1,0,0,0},{97,0,0,0,-1,-1},
            {98,1,1,1,1,1},{98,0,-1,0,0,0},{98,0,0,0,-1,0},{98,0,0,0,0,-1},
            {98,0,0,0,0,0},{98,0,0,0,-1,0},{98,0,0,0,0,0},{98,0,0,0,0,0},
            {98,0,0,0,0,0},{98,0,0,0,0,0},{98,0,0,0,0,0},{98,0,0,0,0,0},
        };
        static const uint32_t GT_IDX[70] = {
            0,1,1,1,1,1,1,4,4,4,4,4,4,4,
            4,4,4,4,4,4,4,4,4,4,4,4,4,4,
            4,4,4,4,4,4,4,4,4,4,5,4,4,4,
            4,4,4,4,4,4,4,4,4,4,4,4,4,4,
            4,4,5,4,4,5,5,5,5,5,5,5,5,5,
        };
        alz_arb R;
        int i, oki = 0;
        alz_arb_init(&R);
        for (i = 0; i < 70; i++) {
            alz_arb_step(&R, GT_DIFF[i]);
            if (R.idx != GT_IDX[i]) oki++;
        }
        bad += st_check(oki == 0, "arb idx 70/70 == GT (13.109)");
    }

    if (bad == 0)
        fprintf(stderr, "[CM-TEST] all primitive invariants OK\n");
    else
        fprintf(stderr, "[CM-TEST] %d failure(s)\n", bad);
    return bad;
}
