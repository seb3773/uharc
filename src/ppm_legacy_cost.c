/*
 * ppm_legacy_cost.c - [ISOLAT, GATED UHA_PPM_COST2 default-OFF, NO-wired]
 * Port C of the moteur of cost PPM legacy `0x4221c0` (selection of class by argmin-cost).
 *
 * MOTEUR NUMERIQUE validated OUT-line 100 % (freq/total) + 99,94 % (cost/symbole)
 *   contre the captures #2 (OUT/m41, OUT/m42) - cf. _scratch/ppm_cost_sim.py (spec ref.).
 *
 * arena of cost "mini" CLEAN (distincte of the model PPM d'encoding), REINITIALISEE PLATE
 * at each call of cost (reload priors `rep movs` 0x422262). Index : freq[(ctx<<8)+err],
 * total[ctx], escape[ctx] (0x43a264/0x43a26c/0x43a270). err = symbole of l'arena.
 *
 * THIS module contient there PART BOUCLEE (arena + cost by node). There GENERATION of the
 * sequence (ctx,err) by there descente d'order adaptative remainder has cabler (TODO descente) :
 *   ctx=(ctx<<8)|model_byte ; ctx_pred=ctx>>BASE_CLS[c] ; err=(ctx_pred-model_byte)&0xff ;
 *   ebp re-indexe via 0x43b2cc/0x43b6cc/0x43b6dc/0x43b7dc (OUT/tab_0x43b*, tables disk) ;
 *   `shr` as long as >=6 ; override 0x800 for nodes d'order ; MRU/escape 0x46af50/0x469f48.
 *
 * Nothing n'is adjusts : each constante provient of has measures. The judge final remainder `cmp`.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ppm_cost_tables.h"   /* PPM_T2CC[256] = table legacy 0x43b2cc */
#include "ppm_legacy_cost.h"   /* ppm_cost_arena + feed of l'arena live (M170g) */

/* primitive LUT of legacy (0x43f154) - definie in alz_score.c, already validated 100 % */
extern uint32_t alz_score_cost(uint32_t freq, uint32_t total);

#define PPM_COST_STEP      32u      /* +32 by occurrence (0x4224d9/0x4224e0)      */
#define PPM_COST_HALF      0x4000u  /* threshold of rescale total (0x4224e7)           */
#define PPM_COST_PRIOR     8u       /* repli freq==0 (prior plat 0x43a260)         */
#define PPM_COST_OVERRIDE  0x800u   /* cost fixe of has node d'ORDER (0x42266f)      */
#define PPM_COST_MAXCTX    256u     /* nb of lines ctx observees <=34 ; bound sure */

/* [M170k] ctx_bits initial of l'estimator = the 4 bytes REELS which previous there window
 * (the legacy engine reads the global 0x48269c has 0x422392). Declare here : uses by ppm_ctx_bits(). */
static uint32_t g_prectx;
/* [M170k] Two states d'input MEASUREMENTS in the legacy engine (captures OUT/m170l_state.log, BP 0x4221c0)
 * at the decision 2 d'`image` :
 *   [0x4803c0] = 12558 = there position OF CUT : c'is the counter of band [esp+0x3c]
 *                (0x422239 `mov eax,ds:0x4803c0` -> [esp+0x3c], `inc` has 0x42253c), therefore there
 *                band of the candidate equals `(pos + i) % n` and NO `i % n`. Has `pos = 0` the two
 *                coincident : c'is why all nos GT (pos = 0) validaient `i % n`.
 *   [0x4803c4] = 0x28d = 653 = `m->cls_ctx` : the ctx RELATIF of the node 0 equals
 *                `cls_ctx - CTXBASE[cand]` = 68 (and no 0), but only for the candidate
 *                equal at the class current (0x422224 `cmp al,ah` / 0x42230e `xor ebp,ebp`). */
static uint32_t g_bandbase;   /* [0x4803c0] : position of cut of the block */
static uint32_t g_ctxband;    /* [M266] BAND OF CONTEXT `[esp+0x3c]` = `[0x4803c0]`, NOT `pos` */
static const char *s_lowpfx;  /* [M269] prefixe of the dump binary some rows 0..512 */
uint32_t g_m265_ctxmax, g_m265_ctxarm;  /* [M265] ctx max lu by there walk + armement */
uint32_t g_m265_out, g_m265_outarm;     /* [M267] position of output au moment of the cut */

static int m265out_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_M265OUT"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

void ppm_cost_set_outpos(uint32_t v)
{
    g_m265_out = v;
    g_m265_outarm = (m265out_on() && v != 0xffffffffu) ? 1u : 0u;
    if (v == 0xffffffffu) g_m265_out = 0u;
}

void ppm_cost_set_outarm(void)
{
    if (m265out_on()) g_m265_outarm = 1u;
}

void ppm_cost_set_ctxband(uint32_t v)
{
    g_ctxband = v;
}

static int ctxband_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_CTXBAND"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
static uint32_t g_initctx;    /* [0x4803c4] - CTXBASE[cand] : ctx relatif of the node 0 */
/* [M170k] FLAG OF DIRECTION initial of the candidate. L'ASM not l'initialise THAT sure the path
 * `cand == [0x483934]` (0x42223d `mov al,ds:0x483932` -> `[esp+0x50]`, 0x422242) ; sure l'other
 * path (0x42230e) the slot `[esp+0x50]` n'is NOT writes : il keeps there value laissee by
 * l'call previous (same cadre of stack) = the flag FINAL of the candidate simule before lui.
 * `[0x483932]` = `m->cls_neg` (ppm_post.c). value finale exportee for l'call next. */
static uint32_t g_flag_in;        /* flag d'input of the next call (GT : 0 au start) */
static uint32_t g_flag_out;        /* flag leaves in [esp+0x50] at the output */
static int      g_flag_set;        /* 1 = g_flag_in vient of l'appelant (the setter gagne) */

/* [M170g] `ppm_cost_arena` / `ppm_live_arena` viennent of ppm_legacy_cost.h (l'old
 * typedef local has ete removes for rendre the feed of l'arena live visible here). */

/* reinitialisation PLATE (reload some priors at each call of cost)
 * [M126] State initial measured au first contact of has ctx : `freq = 0`, **`total = 33`**
 * (0x21), then `+0x20` by visite. This n'is nor 1 nor 8 : c'is there value transcrite here.
 * [M122l] The node COLD (freq==0) has sa clean branch (LUT[(prior<<14)/diviseur] with
 * two tables pointees by 0x43a260/0x43a25c) - **no portee** ; this module not couvre
 * therefore that the regime HOT as long as M128 n'has not livre the tables.
 * `UHA_PPM_COST_TOT0` remainder has probe for balayer l'state initial. */
void ppm_cost_arena_reset(ppm_cost_arena *a)
{
    size_t i;
    /* [M130] `total` initial = **1** (arena plate). Proof : there formule cold
     * `LUT[((escape+1)<<14)/total]` not gives 4576 sure zeros qu'with total = 65 (= 1+64),
     * and 0 (LUT[16384]) au all first node, this which exige total = 1 with escape = 0.
     * L'old value 33 of M126/M122m was has ARTEFACT some columns `t_before_derive`
     * (= t_after  0x20), which not suivent not the `t_after` reels. Gate TOT0 conservee
     * for balayage.
     */
    static int tot0_init = 0;
    static uint32_t s_t0 = 1u;
    uint32_t t0;
    if (!tot0_init) {
        const char *e = getenv("UHA_PPM_COST_TOT0");
        if (e && e[0])
            s_t0 = (uint32_t)strtoul(e, NULL, 0);
        tot0_init = 1;
    }
    t0 = s_t0;
    memset(a->freq, 0, sizeof a->freq);
    /* [M141] `escape` initial = **1**, NOT 0 (measured : `escape_avant` in {1, 33, 65, ...} = 1+32k).
     * with the 2e term without `+1`, the all first node tombe sure `(1<<14)/1 = 16384` => `LUT = 0`
     * => cost 37 440 without no cas particulier. (M140 had scores escape=0 : c'was false.) */
    memset(a->escape, 0, sizeof a->escape);
    a->prior = NULL;                 /* [M170k] no model live => repli 37440 */
    a->prior_total = 0u;
    for (i = 0; i < PPM_COST_MAXCTX; i++)
        a->escape[i] = 1u;
    for (i = 0; i < PPM_COST_MAXCTX; i++)
        a->total[i] = (uint16_t)t0;
    ppm_cost_rowsel_reset(a);          /* [M220] model of distance of the node 0x4221c0 */
}

/* [M170g/M170i] FEED OF L'ARENA LIVE - mirror of 0x422262..0x42229e (estimator) and of
 * 0x422e22..0x422e5c (family d'escape). Law : OUT/m170g_arenafeed.md 3.
 *   freq[rel][sym] = m->freq[base+rel][sym]     (memcpy of 0x200 o by context)
 *   escape[rel]    = m->ent_wt[base+rel]        (0x4222e0 / 0x422e9d)
 *   total[rel]     = escape + m->cum[base+rel][0]  (0x4222fe : total = esc + cum[0])
 * Invariant verified sure the two loops of update of the scan : total = sum(freq) + escape.
 *
 * [M170i] ECRASEMENT PARTIAL, no ZERO GLOBAL : the legacy engine recopie `n` lines (memcpy of
 * `line*0x200` bytes) and n'initialise `tot`/`esc` that for these `n` contexts ; the lines
 * `n..95` KEEP l'state leaves by there decision previous (buffer persistant). Zeroer all
 * l'arena (version previous) rendait the costs some candidates following degeneres as soon as
 * leur `ctx` depassait `n` (measures : 94,5 M au lieu of 74,0 M with `n = 8`).
 * returns 0 if l'input is invalid (keeps of bound, never atteinte : n <= 96). */
int ppm_cost_arena_load_live(ppm_cost_arena *a, const ppm_live_arena *L)
{
    uint32_t rel, i;
    if (!a || !L || !L->freq || !L->cum || !L->ent)
        return 0;
    if (L->n > PPM_COST_MAXCTX)
        return 0;
    for (rel = 0; rel < L->n; rel++) {
        const uint16_t *row = L->freq + (size_t)(L->base + rel) * 256u;
        uint32_t esc = L->ent[L->base + rel];
        uint32_t c0 = L->cum[(size_t)(L->base + rel) * 256u];
        uint16_t *dst = a->freq + (size_t)rel * 256u;
        for (i = 0; i < 256u; i++)
            dst[i] = row[i];
        a->escape[rel] = (uint16_t)esc;
        a->total[rel] = (uint16_t)(esc + c0);
    }
    /* [M170k] row of prior of the candidate : lue au 1er term of the node COLD (0x42242b).
     * `prior_freq == NULL` (path from-scratch, without model) => l'old constante. */
    a->prior = L->prior_freq;
    a->prior_total = L->prior_total;
    return 1;
}

/* rescale 0x422100 (halving Fenwick of has line ctx) :
 *   each freq[cell] -> (f+1)>>1 ; escape -> (escape>>2)+1 ; total -> Sigma(cells halved)+escape */
static void ppm_cost_rescale(ppm_cost_arena *a, uint32_t ctx)
{
    uint32_t base = ctx << 8;
    uint32_t i;
    uint32_t sum = 0;
    for (i = 0; i < 256; i++) {
        uint32_t v = a->freq[base + i];
        v = (v + 1u) >> 1;
        a->freq[base + i] = (uint16_t)v;
        sum += v;
    }
    a->escape[ctx] = (uint16_t)((a->escape[ctx] >> 2) + 1);
    a->total[ctx] = (uint16_t)(sum + a->escape[ctx]);
}

/* Has node of the walk : reads (freq,total), returns the cost of the node, updates l'arena.
 *   override != 0  -> cost = 0x800 (node d'order) ; otherwise cost = LUT[(freq<<14)/total].
 *   maj : freq[cell]+=32 ; total[ctx]+=32 (+32 suppl. and escape+=32 if freq_lu==0) ;
 *   rescale if total>=0x4000.  (validated 100 % freq/total, 99,94 % cost vs m42 cand0) */
/* [M170g] Variante parametree by l'increment `extra`. The scan d'escape 0x422d00 uses
 * `extra = tstep2[ctx_absolu]` (0x20 partout, 0x0A for ctx >= 0x2F9) and no 32 fixe
 * (OUT/m170g_arenafeed.md 5). The corps is the one of ppm_cost_node, inchange.
 *   LUT = alz_score_cost (0x43f154) ; cold = LUT[prior 8 / 2048] + LUT[escape/total]. */
/* [M252, PROMUE the 2026-10-29] There walk of l'estimator CUT sure the node which franchit
 * l'incumbent, and THIS NUD N'is NOT NOURRI (demi-feed `escape` if the node is COLD). Double
 * proof : (1) ASM `0x4224c6 cmp eax,edx ; 0x4224c8 ja 0x422578` place the test of cut BETWEEN the
 * incrementements froids (`0x422481 escape += 0x20`, `0x422488 total += 0x20`) and l'incrementement
 * of frequency (`0x4224ce..0x4224d9 freq += 0x20`, second `total += 0x20`, rescale `0x4224f0`) -
 * voir `OUT/m251_feededge.md` 2 ; (2) measures sure the 80 vecteurs `OUT/m250_arena_calls.tsv` :
 * l'exces was Has row `ctx` of the last node BY walk tronquee (16/16 predites) and il
 * tombe has ZERO to the five cuts saines, `escape` 0/96, without changer no cost.
 * `UHA_PPM_CUTNOFEED=0` restores the behavior historique (node cut nourri integralement). */
static int cutnofeed_on(void)
{
    static int cn = -1;
    if (cn < 0) {
        const char *e = getenv("UHA_PPM_CUTNOFEED");
        cn = (e && e[0] == '0') ? 0 : 1;
    }
    return cn;
}

/* [M254, GATED UHA_M252TIE, default-OFF] PREDICAT OF PROMOTION OF THE MRU OF DISTANCE.
 * L'ASM some TWO copies of the machine (LIVE `0x4190d1..0x4190ed` and ESTIMATOR
 * `0x4227c4..0x4227e0`) is structurellement identical : `cmp cnt[c04],cnt[c08]` then `jb` ->
 * there promotion se does therefore has l'**egalite** (`>=`), this that the port code. Measures M254
 * (`OUT/m254_live_head.tsv`, 80 tetes) : the `c04` of the port equal the one of the master sure **15 cuts
 * sure 16** (the values "sauvages" 249, 214, 190, 177... are those of the master - notre rejeu by
 * byte is therefore faithful, Hypothese " call by symbole emis " REFUTEE), but the `c08` of the master
 * equals **12 has all cuts** then that the notre decroche has 8 some there transition d'egalite of
 * `i=65 661` (`cnt[8]=5`, `cnt[12]=5`) and not revient more.
 *  **HYPOTHESE REFUTEE BY MEASURES** (2026-10-29, same cycle) : majorite strict `=1` -> tetes
 * identical **5/16** (pis that the default 7/16) and `76 806` always has 8 ; `=2` (pass live
 * single) : same failure. There cause was l'**ring** (`UHA_PPM_C08RING`, promu) and no the predicat.
 * There gate is LAISSEE EN L'STATE (default OFF) as trace of the variante testee - not not there
 * remacher. `=1` strict to the two passes ; `=2` strict sure there pass LIVE only. */
/* [M265, GATED UHA_PPM_NOFEEDHEAD, default-OFF] RESTREINT there law CUTNOFEED (the node which
 * franchit l'incumbent n'is not nourri) to the walks whose there bound d'incumbant is FINIE.
 * Motivation MESUREE (m261_exploitation.md 10) : with `UHA_PPM_CUTNOFEED=0`, has single some
 * 30 values confrontees moves - `57 883 c1`, has TETE (bound `0xffffffff`) - and elle pass
 * has EXACT. Hypothese testee has has variable : sure has walk has bound infinie, there cut
 * " not not nourrir " n'has not lieu d'to be (the legacy engine not peut not couper) ; the node doit to be
 * nourri as en `CUTNOFEED=0`. No other behavior n'is modifie.
 * Judge d'order : mono `an_m246_costscore` 16/16 and `an_m155` 12/12 (contrainte dure) BEFORE
 * d'esperer has mouvement of `an_m259_costall` (0/54). */
static int nofeedhead_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_NOFEEDHEAD"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

static int c08tie_strict(void)
{
    static int tv = -1;
    if (tv < 0) {
        const char *e = getenv("UHA_M252TIE");
        tv = (e && e[0]) ? atoi(e) : 0;
    }
    return tv;
}

/* [M254, PROMUE the 2026-10-29] Not NOT boucler the regard en arriere of the pass LIVE sure there
 * size of l'ring of 64 Ko when the buffer indexe is the MEMBER entier : voir the block of
 * commentaires in `c08_phase`. validation : 48 tetes of walk (`c00`,`c04`,`c08` * 16 cuts)
 * identical at the GT `OUT/m254_live_head.tsv` (contre 5/16 triples before), rows d'arena exact
 * 44,64 % -> 94,32 % sure the 80 vecteurs, `argmin` 8/11 -> **11/11**, and zero byte change
 * (mono 19 083, container 260 239 / 191 350, firstdiv 2 913 / 1 319, parse 1 073 409 / 1 019 550).
 * `UHA_PPM_C08RING=0` = behavior historique (mask applies au member). */
static int c08_no_livemask(void)
{
    static int rv = -1;
    if (rv < 0) {
        const char *e = getenv("UHA_PPM_C08RING");
        /* DEFAULT = 1 (path promue : of-bouclage some regards en arriere). `=0` = historique ;
         * `=2` adds there law of bord of the seed by stream absolu - TESTEE AND REFUTEE (costs
         * 15/16 au lieu of 16/16 and `an_costcmp` casse sure `zeros.bin`), laissee as level
         * explicite of diagnostic. */
        rv = (e && e[0] == '0') ? 0 : (e && e[0] == '2') ? 2 : 1;
    }
    return rv;
}

/* [M254] LEVEL 2 of `UHA_PPM_C08RING` : traiter the BORD of the seed (`i < k*c08`) by the STREAM
 * ABSOLU same when there geometrie payload n'is not armee (otherwise sentinelle historique). */
static int c08_border_flux(void)
{
    return c08_no_livemask() >= 2;
}

/* [M252, GATED UHA_M252CUT, default-OFF, read-only] PROBE OF L'INSTANT OF CUT of the walk.
 * Has line by Walk (call of l'estimator), at the endroit same now the sort of the walk se joue :
 *   tag 'c' = cut with `UHA_PPM_CUTNOFEED` ON (node no nourri) ;
 *   tag 'e' = cut with the behavior historique (node ALREADY nourri by `ppm_cost_node`) ;
 *   tag 'n' = walk ALLEE AU BOUT OF `len` (no cut) - nourrit therefore son last node.
 * Rend `f`/`t` LUS BEFORE the feed (same registres that the BP legacy `0x422426`), the cost of the node,
 * the cumul AFTER ajout and l'incumbent : c'is there donnee which departage " the master nourrit the node
 * cut " of " il not the nourrit not ", cut by cut, without captures. no effect on l'arithmetique. */
static int g_m252cut = -1;
/* [M252] armement of the probe d'image rechargee (voir `ppm_legacy_cost_live`). */
static int g_m252reload = -1;
#define M252CUT_ARM() \
    do { if (g_m252cut < 0) { const char *e_ = getenv("UHA_M252CUT"); \
           g_m252cut = (e_ && e_[0] != '0') ? 1 : 0; } } while (0)
#define M252CUT(cand_, ctx_, err_, f_, t_, node_, cum_, inc_, i_, tag_) \
    do { M252CUT_ARM(); \
        if (g_m252cut) \
            fprintf(stderr, "[M252CUT] pos=%u cand=%u %c i=%zu ctx=%u err=%u f=%u t=%u "\
                    "node=%u cumul=%llu inc=%llu len=%zu\n", \
                    (unsigned)g_bandbase, (unsigned)(cand_), (tag_), (size_t)(i_), \
                    (unsigned)((ctx_) & 0xffu), (unsigned)((err_) & 0xffu), (unsigned)(f_), \
                    (unsigned)(t_), (unsigned)(node_), (unsigned long long)(cum_), \
                    (unsigned long long)(inc_), len); \
    } while (0)
#define M252CUT_END(cand_, cum_, inc_) \
    do { M252CUT_ARM(); \
        if (g_m252cut) \
            fprintf(stderr, "[M252CUT] pos=%u cand=%u n i=END ctx=0 err=0 f=0 t=0 "\
                    "node=0 cumul=%llu inc=%llu len=%zu\n", \
                    (unsigned)g_bandbase, (unsigned)(cand_), \
                    (unsigned long long)(cum_), (unsigned long long)(inc_), len); \
    } while (0)

uint32_t ppm_cost_node_cost(const ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override)
{
    uint32_t cell;
    uint32_t f, t, cost;
    /* [M265, gate UHA_M265CTX] ctx MAX lu by there walk : dit if there walk touche the lines
     * `>= n` of l'arena, i.e. if l'state HERITE (no recopie) peut influencer the costs. */
    extern uint32_t g_m265_ctxmax, g_m265_ctxarm;
    if (g_m265_ctxarm && ctx > g_m265_ctxmax)
        g_m265_ctxmax = ctx;
    if (ctx >= PPM_COST_MAXCTX)      /* keeps : ctx observe small ; not not to write out bound */
        ctx = PPM_COST_MAXCTX - 1;
    err &= 0xff;
    cell = (ctx << 8) + err;
    f = a->freq[cell];
    t = a->total[ctx];
    /* [M274k, GATED UHA_PPM_TOTESC, default 0 = historique] DENOMINATEUR OF THE COST HOT.
     * Measures `m274i`/`m274j` : has `start = 937 440` the cost of family equals `4 334 512` at nous
     * and `10 133 783` at the master ; has 11 froids identical near, the cost hot by node is
     * `16 011` contre `39 681`, i.e. `f/t = 0,51` contre `0,187` -> the DENOMINATEUR is ~2,7x
     * too small. `=1` adds `escape[ctx]` au total of the node. */
    { static int te = -1;
      if (te < 0) { const char *e = getenv("UHA_PPM_TOTESC"); te = (e && e[0] != '0') ? 1 : 0; }
      if (te)
          t = (uint32_t)(t + a->escape[ctx]); }
    /* [GATED UHA_COSTDBG4, defautOFF, M130] state VU by the node (autocontrole vs peek). */
    { static int c4 = -1; static unsigned long n4 = 0;
      if (c4 < 0) { const char *e = getenv("UHA_COSTDBG4"); c4 = (e && e[0] != '0') ? 1 : 0; }
      if (c4 && n4 < 12) { fprintf(stderr, "[CN] n=%lu ctx=%u err=%u f=%u t=%u tot0=%u tot7=%u ov=%d\n",
                                  n4, ctx, err, f, t, a->total[0], a->total[7], override); n4++; } }

    if (override)
        cost = PPM_COST_OVERRIDE;
    else if (f == 0) {
        /* [M170k] NUD COLD - LAW EXACT lue in l'ASM of l'estimator 0x4221c0 :
         *   1 term (0x42242b..0x422465) : `proba = (freq_prior[err] << 14) / cum_prior[0]`
         *     with `freq_prior = master[(0x30400/0x200) + cand]` = row 772+cand and
         *     `cum_prior[0] = master_cum[772+cand][0]` (0x42244d, div by cum[0]).
         *     => this n'is NOT there constante `LUT[(8<<14)/2048] = 37440` : the one-ci n'is that there
         *     value some rows of prior when elles are still PLATES (pos = 0).
         *   2 term (0x422479..0x4224a7) : `proba = (escape_avant << 14) / total_avant`
         *     (`eax` = esc_work[ctx] sure the path cold ; total lu BEFORE the updates).
         * Preuves : 42 626 nodes GT `m41` (cold 1 term = 37440 constant has pos 0) ;
         * `image` decision 2 : row 775 = cum0 4144, f0 232, f1 376, f88 24, f255 136. */
        if (a->prior && a->prior_total)
            cost = alz_score_cost((uint32_t)a->prior[err], a->prior_total)
                 + alz_score_cost((uint32_t)a->escape[ctx], t);
        else {
            static int cold_leg = -1;
            if (cold_leg < 0)
                cold_leg = getenv("UHA_PPM_COLD_LEGACY") ? 1 : 0;
            if (cold_leg)
                cost = alz_score_cost(PPM_COST_PRIOR, t);
            else
                cost = alz_score_cost(PPM_COST_PRIOR, 2048u)
                     + alz_score_cost((uint32_t)a->escape[ctx], t);   /* [M141] ESCAPE_AVANT, without +1 */
        }
    } else
        cost = alz_score_cost(f, t);

    /* [M222, GATED UHA_PPM_ROWNOESC, default OFF] PROBE : the denominateur of the cost HOT serait
     * `Sigma freq` (= `total  escape`) and no `total` (which inclut l'echappement). Measures which motive
     * there probe : has `937 696` (cand 0, arena neuve, `d=1`) the number of nodes FROIDS is **20**
     * contre **22,66** en GT (848 447 / 37 440) => the term cold is juste, but there QUEUE coute
     * 123/node at nous and 8/node en GT. There queue not depend that of `f/t` : if `t = Sigma freq`, then
     * `f/t -> 1` some there 2 visite and there queue disparait. Never promotable. */
    if (!override && f != 0) {
        static int ne = -1;
        if (ne < 0) { const char *e = getenv("UHA_PPM_ROWNOESC"); ne = (e && e[0] != '0') ? 1 : 0; }
        if (ne && t > (uint32_t)a->escape[ctx] && t > (uint32_t)a->escape[ctx] + f)
            cost = alz_score_cost(f, t - (uint32_t)a->escape[ctx]);
    }

    return cost;
}

/* [M252] NOURRISSAGE SINGLE of the node (law M130 prouvee 57 201/57 201 sure `freq`/`total`/`escape`
 * + rescale). Relit `f`/`t` : values identical has those vues by `ppm_cost_node_cost` so much
 * qu'no write n'is intervenue between the two - and precisement this which interesse there
 * gate `UHA_PPM_CUTNOFEED`, which CALLS the cost and NEAPPELLE NOT this function sure the node
 * which franchit l'incumbent (law measured : the master cut without nourrir).
 *  Not NOT to use single in has path now the cost n'has not ete computed : `f`/`t` are relus
 * here, not transmis, for to keep the signature historique of `ppm_cost_node_step`. */
void ppm_cost_node_feed(ppm_cost_arena *a, uint32_t ctx, uint32_t err, uint32_t step)
{
    uint32_t cell;
    uint32_t f, t, nt;
    if (ctx >= PPM_COST_MAXCTX)      /* keeps identical has the one of the cost */
        ctx = PPM_COST_MAXCTX - 1;
    err &= 0xff;
    cell = (ctx << 8) + err;
    f = a->freq[cell];
    t = a->total[ctx];

    /* update of l'arena
     * [M130 - LAW PROUVEE sure 62 720 nodes GT (`OUT/m41_pattern_ctxerr_freq_total_delta.tsv`,
     * 5 candidates * 12 544) : rejeu horsline **57 201/57 201 = 100 %** of `freq`/`total`]
     *   total[ctx] init = 1 (arena plate ; sure `zeros` l'state is HERITE : 33)
     *   by node    : freq[cell] += 32 ; total[ctx] += 32
     *   if cold    : total[ctx] += 32 of MORE (l'escape 0x422488) and escape[ctx] += 32
     *   rescale     : total >= 0x4000 -> freq->(f+1)>>1 ; escape->(escape>>2)+1 ;
     *                 total = Sigma(cellules halvees) + escape   (NOT has >>1 of total)
     * Histogramme measured some total sure `pattern` : hot = +32 (12 488 cas), cold = +64 (5 cas),
     * rescale = return has ~8192. There variante " +32 only au 1er cold " (gate previous,
     * `escape==0`) not tient that **19 774/57 201** : elle is RETRACTEE. Elle had ete deduite some
     * columns `t_before_derive` of `m126_cand0_nodes.tsv`, which are incoherentes (the drifts
     * `t_after  0x20` not suit not the `t_after` reels) - lecon : not never to drift has law of has
     * column recalculee.
     */
    a->freq[cell] = (uint16_t)(f + step);
    nt = t + step;
    if (f == 0) {
        nt += step;                              /* escape 0x422488 (measured : =+64 sure cold) */
        a->escape[ctx] = (uint16_t)(a->escape[ctx] + step);
    }
    if (nt >= PPM_COST_HALF) {
        /* [GATED UHA_PPM_SEEDLAW, defautOFF, M153] rescale = law measured sure the banc 16353/16385/8177 :
         *   freq'   = (f+1)>>1 by WORD sure there single row of the ctx   (16288 -> 8144 ; 32 -> 16)
         *   escape' = ceil(ceil(e/2)/2) = (e>>2)+1   for e  1 (mod 4)   (65 -> 33 -> 17)
         *   total'  = Sigma freq' + escape'  = 8160 + 17 = 8177   (NOT (t+1)>>1 - refute M153)
         * L'invariant total == Sigma freq + escape is verified to the 3 instants (M153). */
        { static int sl2 = -1; if (sl2 < 0) { const char *e = getenv("UHA_PPM_SEEDLAW"); sl2 = (e && e[0] != '0') ? 1 : 0; }
          if (sl2) {
              uint32_t k, sum = 0u, e2;
              for (k = 0; k < 256u; k++) {
                  uint16_t *p = &a->freq[(ctx << 8) + k];
                  uint32_t h = ((uint32_t)*p + 1u) >> 1;
                  *p = (uint16_t)h;
                  sum += h;
              }
              e2 = ((uint32_t)a->escape[ctx] >> 2) + 1u;
              a->escape[ctx] = (uint16_t)e2;
              a->total[ctx] = (uint16_t)(sum + e2);
          } else {
              a->total[ctx] = (uint16_t)nt;
              ppm_cost_rescale(a, ctx);
          } }
    } else {
        a->total[ctx] = (uint16_t)nt;
    }
}

/* [M252, law measured `UHA_M252CUT`] DEMI-FEED OF THE NUD COLD CUT - there part " escape " of the
 * update (terms 0x422488 : `escape[ctx] += 32` and the `+32` of `total` which there porte) s'execute
 * BEFORE the test of cut ; there part " frequency " (`freq[cell] += 32`, son `+32` sure `total`,
 * rescale eventuel) s'execute AFTER, therefore sure the node cut : SAUTEE.
 * Judge direct (`OUT/m250_arena_calls.tsv`, row `ctx` of the node cut cold) : `skip-all` donnait
 * 32 sure `total` AND 32 sure `escape` ; feed cold complete gives +32 sure `total` ; the demi-feed
 * rendu by this function tombe has 0 sure the two columns. Invariant `total = Sigmafreq + escape`
 * respecte (there row gagne exactement son increment d'escape).
 *  No test of rescale here : il n'existe qu'en end of feed complete (the threshold `0x4000` n'has ete
 * atteint by no node cut measured ; if has cas apparaissait, there GT the dirait). */
void ppm_cost_feed_esc(ppm_cost_arena *a, uint32_t ctx, uint32_t step)
{
    if (ctx >= PPM_COST_MAXCTX)
        ctx = PPM_COST_MAXCTX - 1;
    a->escape[ctx] = (uint16_t)(a->escape[ctx] + step);
    a->total[ctx] = (uint16_t)(a->total[ctx] + step);
}

/* [M252] Node COMPLETE = cost THEN nourrissage : behavior historique unchanged for all the
 * appelants which not deferent nothing (scan d'escape 0x422d00, selecteur, harnais of validation). */
uint32_t ppm_cost_node_step(ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override,
                            uint32_t step)
{
    uint32_t cost = ppm_cost_node_cost(a, ctx, err, override);
    ppm_cost_node_feed(a, ctx, err, step);
    return cost;
}

/* enveloppe historique : increment fixe 32 (estimator 0x4221c0 / descente d'order). */
uint32_t ppm_cost_node(ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override)
{
    return ppm_cost_node_step(a, ctx, err, override, PPM_COST_STEP);
}

/* reading some values BEFORE node (for harnais of validation contre m41) */
void ppm_cost_peek(const ppm_cost_arena *a, uint32_t ctx, uint32_t err,
                   uint32_t *freq, uint32_t *total)
{
    uint32_t cell;
    if (ctx >= PPM_COST_MAXCTX)
        ctx = PPM_COST_MAXCTX - 1;
    cell = (ctx << 8) + (err & 0xff);
    *freq = a->freq[cell];
    *total = a->total[ctx];
}

/*
 * ppm_legacy_cost(window, len, cls, incumbent) - cost of has candidate sure has window.
 *   returns Sigma some costs by node (the cost `eax` of 0x4221c0) ; cut some cumul>incumbent.
 *   incumbent = 0xffffffff for the seed (never elague), otherwise the meilleur cost current.
 *
 * TODO (generation restante) : the corps ci-dessous deroule l'arena has partir some paires
 * (ctx,err) PRODUITES BY THERE DESCENTE d'order sure there window. as long as there descente
 * adaptative n'is not cablee, this parcours attend that `ppm_cost_emit` lui fournisse
 * each (ctx,err) ; there loop of generation (ctx roulant + tables 0x43b2cc/6cc/6dc/7dc,
 * shr<6, override order) is there single brique no validated has this jour.
 */
static uint64_t ppm_legacy_cost_gen(const uint8_t *win, size_t len, uint32_t cand, uint64_t incumbent);

/* [M172b] Geometrie of the member vu by the path block live (voir there description complete more low).
 * Declaree here because `ppm_legacy_cost` (the SELECTEUR) doit there desarmer : the selecteur not travaille not
 * sure the member entier and n'has therefore nothing has voir with there law `input`/payload. */
static const uint8_t *g_pay;
static size_t g_payn, g_payusize;

uint64_t ppm_legacy_cost(const uint8_t *win, size_t len, uint32_t cls, uint64_t incumbent)
{
    /* [GATED UHA_COSTENTRY, defautOFF, M130] probe d'input (auto-controle of the path). */
    { static int ce = -1; if (ce < 0) { const char *e = getenv("UHA_COSTENTRY"); ce = (e && e[0] != '0') ? 1 : 0; }
      if (ce) fprintf(stderr, "[CE] cls=%u len=%zu inc=0x%llx\n", cls, len, (unsigned long long)incumbent); }
    g_pay = NULL; g_payusize = 0;      /* selecteur : behavior historique */
    /* generateur of cost frombytes some 5 candidates (laws closes M45/M45B..G, validated
     * boutenbout : argmin cand0..4 -> class ; gap = leaf7, no bloquant). */
    if (cls <= 4u)
        return ppm_legacy_cost_gen(win, len, cls, incumbent);
    return 0;
}

/* ---------------------------------------------------------------------------
 * GENERATEUR class0 (seed cand0) - laws CLOSES 100 % frombytes (M45/M45B,
 * #2 + main ; mirror faithful of OUT/m45b_gen.py). Mask 0x7fff ; ring
 * ring(p) = data[256+p] (rebord p<0 now horsbound -> 0xff). Machine MRU recence
 * -> c08 ; ctx = T2CC[(ring[i-2c08]-ring[i-c08])&0xff] ; err = (ring[i-c08]-data[i])&0xff ;
 * acc/override clos (override = 98,96 % : clause order reevalue en attente, voir TODO).
 * --------------------------------------------------------------------------- */
/* [M170o] MASK of window measured (BP 0x4221c0, `OUT/m170o_winstate.log`, mixed mx) :
 * `[0x4826b0] = 0x10000` (size) and `[0x4826bc] = 0xffff` (mask) - there value 0x7fff
 * n'was only to  hypothese ; elle deplace the fausses acceptations of `d` of 32768 has
 * 65536 and fabrique some distances fantomes. There constante is therefore CORRIGEE. */
#define PPM_MASK 0xffffu

/* Acces au stream for there machine MRU / the predicteur : p = distance before i.
 * Law measured (M45e) : `err_froid = (b[i1]  b[i]) & 0xff` and `model_byte = ~input`
 * => the stream relu at the distance p is simplement `data[ip]` ; p < 0 (before there window)
 * equals 0xff (bord measured).
 * [M130] BUG corrected : there version previous lisait `d[256+p]` with there keeps `k < n`,
 * this which basculait en 0xff sure the **256 LAST symboles** of each window
 * (err=255 => +2,44 M d'unites sure `zeros`, measured ; the legacy engine remainder sure err=0).
 */
static uint32_t ring_byte(const uint8_t *d, size_t n, long p)
{
    if (p < 0 || (size_t)p >= n) return 0xffu;
    return d[p];
}

/* [M135] Acces au BUFFER model of the seed : measured = `input` DECALEE of +256
 * (OUT/m135_buf_1.txt + OUT/m135_a600_eng.log : `buf[j] == input[j+256]`
 * 600/600, `eax == sext8(b2-b1)` 600/600, and `eax == sext8(input[p+256-2c] -
 * input[p+256-c])` sure 7 124/7 132 = 99,89 % some nodes with p = position
 * GLOBAL (`[esp+0x44]`), 83,5 % only with p local of window).
 * Gate UHA_PPM_SEEDOFF256 (default OFF) : `off` = 256 ; otherwise behavior
 * historique (`off` = 0, reading in there window). Au-dela of the window on
 * reads the stream complete so much qu'on remainder in there marge `off` (the legacy engine reads son
 * buffer, which couvre all the file). */
static uint32_t seed_byte(const uint8_t *d, size_t n, long p, long off)
{
    if (p < 0) return 0xffu;
    if ((size_t)p >= n) {
        if (off <= 0 || (size_t)p >= n + (size_t)off) return 0xffu;
        return d[p];
    }
    return d[p];
}

/* [M154] Level of the gate `UHA_PPM_LAW256` :
 *   0 = behavior historique (reference of reproduction) ;
 *   1 = `ctx` and l'accumulateur `acc`/`order` read the TRUE `err_seed` au same node ;
 *   2 = en more, l'index d'arena devient `err_cost` (with the buffer +256) au same node.
 * Law measured contre `OUT/m133_eng.log` (site 0x422418) :
 *   ctx = T2CC[data[i2c+256]  data[ic+256]]      12 542/12 544 (99,984 %)
 *   err = data[ic+256]  data[i]                   12 543/12 544 (99,992 %)
 * The 2 nodes en failure are i = 0 and i = 1 (the buffer model reads then there zone
 * of prefixe no initialisee).
 * PROMUE (default 2) the 20261023 : `an_costcmp` pass of 14/22 (gap max 3,5682 %)
 * has 18/22 (gap max 0,0028 %) and the cost ARGMIN devient exact sure the 5 files
 * (`biased` 0x992ef05, `eng` 0xa62272e, `image` 0x46a185c, `random` 0x1d7f98c4,
 * `zeros` 0x3d39d) - `random` was the single false (0x1d80c3eb). measured meilleure
 * PARTOUT, no regression some 4 juges (16685/7036, 13809/6988, 88 OK).
 * `UHA_PPM_LAW256=0` restores the behavior historique, at the identical. */
static int law256(void)
{
    static int lv = -1;
    if (lv < 0) {
        const char *e = getenv("UHA_PPM_LAW256");
        /* [M177, PROMUE the 2026-10-25] Default = 3 : the bord of the seed relit the STREAM ABSOLU
         * (`nb = ~data[(wpos - c08) & 0xffff]`), measured sure 102 nodes of bord (block 3 of `mixed`).
         * N'agit that if there geometrie of the member is armee (`pay_active()`). 0 = historique (Has/B). */
        lv = (e && e[0]) ? atoi(e) : 3;
    }
    return lv;
}

/* [M154] bytes reellement lisibles au-dela of `win` (the legacy engine reads son buffer, which
 * couvre all the file ; there window of selection n'en is only to  prefixe of 0x3100).
 * 0 = inconnu -> on se bound at the window. Rule by l'appelant (encode.c). */
static size_t g_cost_avail = 0;

void ppm_cost_set_avail(size_t n)
{
    g_cost_avail = n;
}

/* [M154] byte of the buffer model : `buf[j] == input[j+256]` (M135, 600/600).
 * bounded has this which is reellement allocates for not never to read out buffer. */
static uint32_t law_byte(const uint8_t *d, size_t n, long p)
{
    size_t lim = (g_cost_avail > n) ? g_cost_avail : n;
    if (p < 0) return 0xffu;
    return ((size_t)p < lim) ? (uint32_t)d[p] : 0xffu;
}

/* [M170r] STREAM ABSOLU complemente : `stream[(wpos  back) & mask]` (0x42262c/0x42263a :
 * `sub eax,c08 ; and eax,[0x4826bc] ; mov cl,[0x43a21c+eax]`). The buffer `0x43a21c` contient
 * the stream COMPLEMENTE, now the `~`. Sert au cas of BORD of the seed cand 0 (`i < c` / `i < 2c`). */
static uint32_t flux_byte(const uint8_t *d, size_t n, uint32_t wpos, long back)
{
    /* [M254] same geometrie that `c08_phase` : at the master, `[0x43a21c]` is has RING of
     * 64 Ko of the stream (therefore `(wpos - back) & 0xffff` y designe `stream[wpos - back]`), then that `d`
     * here is there BASE OF THE MEMBER, which peut depasser 64 Ko (`records.bin` = 240 000 o). Boucler
     * retombait ailleurs some `wpos >= 0x10000` (cut `76 806`, `back = c08 = 12` :
     * `76 794 & 0xffff = 11 258`). under `UHA_PPM_C08RING` (default promu), reading directe. */
    long p = c08_no_livemask() ? ((long)wpos - back)
                               : (((long)wpos - back) & (long)PPM_MASK);
    if (p < 0 || (size_t)p >= n) return 0xffu;
    return (~d[p]) & 0xffu;
}

/* [M172b, GATED UHA_PPM_PAYLOAD, defautOFF]  THIS THAT the legacy engine READS VRAIMENT EN `input[p]`.
 * Measures M172 (dump of the buffer has `0x421c95`, `OUT/m172_entree_wide.txt`) : there base fournie has
 * l'estimator equals `input = base_entree + start + 256` (3 hits : 0+256, 30004+256, 34747+256,
 * same `base_entree = 0x02210030`), therefore l'index ABSOLU of has reading is `start + i  k*c08 + 256`.
 * as long as l'index remainder in the member on reads the file ; some qu'il atteint `usize`, the legacy engine
 * reads there zone MEMORY ADJACENTE, which is son clean buffer of output : the dump matches has
 * `payload[abs  usize  shift]` sure **1019 bytes consecutifs** (`shift = (16  usize%16)%16 = 5`
 * for usize = 35003, i.e. l'alignement 16 of the block next). Before emission there zone is fraiche
 * => some zeros (observe : `00 00 00 00 00` then the payload). */
static int payload_law(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_PAYLOAD"); v = (e && e[0]) ? atoi(e) : 1; }
    return v;
}

static size_t ppm_cost_payload_shift(void)
{
    return (16u - (uint32_t)(g_payusize % 16u)) % 16u;
}

void ppm_cost_set_payload(const uint8_t *pay, size_t paylen, size_t usize)
{
    g_pay = pay; g_payn = paylen; g_payusize = usize;
}

/* path block LIVE only : there geometrie of the member (base, usize, payload emis) n'is connue
 * that if l'appelant of `ppm_encode.c` l'has armee. The selecteur (`ppm_legacy_cost`, window pos 0 sure
 * all the file) not l'arme never and keeps therefore son behavior historique. */
static int pay_active(void)
{
    return g_pay != NULL && g_payusize > 0;
}

/* byte `input` for has index ABSOLU in the member (`d` = buffer of the member entier). */
static uint32_t entree_byte(const uint8_t *d, size_t n, long abs)
{
    size_t lim = (g_cost_avail > n) ? g_cost_avail : n;
    if (abs < 0) return 0xffu;
    if (payload_law() && g_pay && g_payusize && (size_t)abs >= g_payusize) {
        long j = abs - (long)g_payusize - (long)ppm_cost_payload_shift();
        return (j >= 0 && (size_t)j < g_payn) ? (uint32_t)g_pay[j] : 0u;
    }
    return ((size_t)abs < lim) ? (uint32_t)d[abs] : 0xffu;
}

/* [M135] Offset of the buffer model of the seed : 0 = behavior historique,
 * 256 = value measured (`buf[j] == input[j+256]`, 600/600 + 99,89 % sure 7 132
 * nodes). Gate `UHA_PPM_SEEDOFF256`, default OFF. */
static long seed_off(void)
{
    static long off = -1;
    if (off < 0) {
        const char *e = getenv("UHA_PPM_SEEDOFF256");
        off = (e && e[0] != '0') ? 256 : 0;
    }
    return off;
}

/* [M170o, GATED UHA_PPM_C08ABS, defautOFF] Base of position of the machine MRU.
 * the legacy engine travaille en positions ABSOLUES (`[esp+0x44]` = `[0x4826b4]` = wpos, incremente
 * by node) and sa seed of `lastpos[]` n'is NOT 0 but **0x80000000** :
 *   `0x422315` recopie `0x400` o of `0x46ab50` (memset 0x80000000 sure 256 dwords, `0x417934`)
 *   towards `0x46af50`, then `0x469b48` (zeros) towards `0x469f48`, and `[0x481c00/04/08] = 0/0/1`.
 * Consequence measured : `d = (wpos  lastpos) & MASK` (MASK = `0x4826bc` = size window  1)
 * equals `wpos & MASK` (>= 0x100, therefore REJETE) for has byte never vu. The port, en positions
 * RELATIVES with `lastpos = 0`, acceptait `d = i` for all `i < 0x100` => c08 false in the
 * 256 first nodes of has block situe ailleurs qu'has `pos = 0` (now there validation 100 % of
 * M139, prise has `pos = 0`, now relatif and absolu coincident : lecon " has law validated has
 * pos = 0 not teste not the states d'input "). */
static int c08abs(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_C08ABS"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M170o, GATED UHA_PPM_C08LIVE, defautOFF] STATE PERSISTANT of the machine MRU.
 * measured (BP `0x4221c0`, `OUT/m170o_c08entry.log`) : `[0x481c08]` (l'ORDER c08 entrant of has
 * call estimator) equals **0** at the decision 1, **1** at the decision 2, **0x66 = 102** at the
 * decision 3 (and `0x6e` after elle). The `0x422315` n'is therefore NOT has seed vierge : il
 * recopie `0x46af50  0x46ab50`, `0x469f48  0x469b48` and `[0x481c00/04/08]  [0x481c10/14/18]`,
 * c'isadire has SNAPSHOT of l'state live (these three global are ecrits by `0x4190xx`).
 * Proof independante : there GT pernoeud of the block 3 (`0x87bb`, 256 nodes, class 0) n'is
 * coherente qu'with **c08 = 102** (= there value measured at the input), not with 1.
 * => there machine is has state of STREAM which TRAVERSES the blocks (elle n'advances that during the
 * parcours of l'estimator ; the matchs between blocks not there touchent not). */
static int c08live(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_C08LIVE"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M170o, GATED UHA_PPM_C08NB, defautOFF] OFFSET of the reading `nb` (byte of controle of the
 * counter of justesse `cnt[c08]`) : l'ASM reads `byte[[esp+0x18] + (i  c08)]` **without** shift
 * (0x422785 / 0x422799 / 0x42279d) ; the port lisait `input[i  c08 + 256]` (convention M135),
 * this which compares the model au stream 256 bytes more far => `nb == bl` presque never true
 * => `cnt[c08]` not rises not => **c08 remainder fige has 1** au lieu of 102 (measured `OUT/m170o_c08entry.log`).
 * Gate SEPAREE of `UHA_PPM_SEEDOFF256` (which pilote also l'error of seed, 0x422628/0x422644). */
static int c08nb0(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_C08NB"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M170o, GATED UHA_PPM_C08FLOW, defautOFF]  model EXACT (static `0x418fc0` vs `0x4226f3`) :
 * there machine existe en **TWO** exemplaires. `0x418fc0` is there machine **LIVE**, appelee for
 * **each byte emis** (literals AND matchs) : `lastpos = 0x46ab50`, `cnt = 0x469b48`,
 * `c00/c04/c08 = 0x481c10/14/18`. `0x422315` recopie this state LIVE in the buffers of travail
 * (`0x46af50/0x469f48/0x481c00/04/08`) and the parcours of the block the does to advance. Consequence : au
 * first node of has block, `c08` = l'state of the stream **has this byte**, not 15/102 " by magie ".
 * Proof chiffree (M170p) : block 2 => `c08 = 15`, `cnt[15] = 49`, `c00 = 9`, `c04 = 2`,
 * `lastpos[bl] = 0` ; block 3 => `102`. => rejeu DETERMINISTE since l'byte 0 sure the stream
 * complete, positions absolues, output only for `[start, start+len)`. */
static int c08flow(void)
{
    static int v = -1;
    /* [M170r] LEVEL (and no booleen) : 1 = old model STREAM monoloi (`nb` always +256),
     * 2 = TWO PHASES (live offset 0 then estimator +256 with frontier). */
    /* [M177, PROMUE the 2026-10-25] Default = 2 (TWO PHASES). validation : state d'input exact has two
     * frontiers (30004 -> c08 15, 34747 -> c08 102), 85/85 nodes of bord, 23 393 nodes `(freq,total)`
     * and 20 480 nodes of cost identical to legacy. 0 = old behavior (Has/B). */
    if (v < 0) { const char *e = getenv("UHA_PPM_C08FLOW"); v = (e && e[0]) ? atoi(e) : 2; }
    return v;
}

typedef struct {
    uint32_t lastpos[256];
    uint32_t cnt[0x100];
    uint32_t c00, c04, c08;
    int init;
} c08_state;
static c08_state s_c08;

/* [M170r]  TWO LAWS OF `nb`, mesurees and CLOSES (GT `OUT/m170q_c08_internals.log`) :
 *  * `NB_LAW_LIVE` = machine LIVE `0x418fc0` / `0x4190a9` : `nb = stream[(wpos - c08) & mask]`,
 *    the stream etant the stream COMPLEMENTE (the `cmp bl,...` compares two bytes of the same stream) ;
 *    en terms of file : `nb = ~data[pos - c08]` (offset 0, NO decoupe).
 *  * `NB_LAW_EST` = estimator `0x4226f3` : `0x422799 add edx,[esp+0x18]` then `0x42279d mov dl,[edx]`
 *    + `0x42279f not dl` => `nb = ~input[i - c08]` with `input` = window **+ 256** ; but
 *    `0x422793 jl 0x42285a` returns the cas `i - c08 < 0` sure the STREAM absolu (offset 0).
 * GT 85 nodes (block 2 of `mixed`) : offset 0 single = 3/85 ; +256 single = 83/85 ;
 * **law composite (+256 sauf `i < c08` -> 0) = 85/85**. The 2 nodes of frontier are
 * `i = 9` and `i = 13` (c08 = 15), exactement the " 2 exceptions " inexpliquees of M170q. */
#define NB_LAW_LIVE 0
#define NB_LAW_EST  1

/* Seed some two exemplaires (0x417934 / 0x417943 / 0x417959..67) : `lastpos = 0x80000000`,
 * `cnt[*] = 0`, `c00 = c04 = 0`, `c08 = 1`. */
static void c08_seed(c08_state *s)
{
    int b;
    unsigned k;
    for (b = 0; b < 256; b++) s->lastpos[b] = 0x80000000u;
    for (k = 0; k < 0x100; k++) s->cnt[k] = 0;
    s->c00 = 0; s->c04 = 0; s->c08 = 1; s->init = 1;
}

/* [M170r] Has PHASE of the machine, positions ABSOLUES (`pos = i`, as `[esp+0x44]` = `wpos`),
 * state porte by `s`. `blk0` = start of the block (single `NB_LAW_EST` en depend, for there frontier
 * `i - c08 < 0`). `c08_out` recoit `c08` BEFORE there update of the node (0x4225b5 reads the c08 of the
 * node). `d`/`n` couvrent all the stream disponible (the legacy engine reads son buffer entier). */
static void c08_phase(const uint8_t *d, size_t n, size_t i0, size_t i1,
                      uint32_t *c08_out, size_t off_out, size_t blk0, int law, c08_state *s)
{
    size_t i;
    /* [M252, GATED UHA_M252C08=<band>, default-OFF, read-only] Transitions of `c08` of the
     * machine sure there pass demandee : has line each fois that `s->c08` change
     * (`pos old new law bl dd cnt[old] cnt[new] c00 c04`). Sert has dater there transition
     * `12 -> 8` observee at the tete some walks `init` has partir of the cut `76 806` : if elle tombe
     * near of `0x10000` (mask of positions) there cause is l'arithmetique of bouclage, otherwise elle
     * is in the data. no effect on there machine. */
    static long m252c08 = -2;
    static int c08tail_cfg = 0;
    int c08trk = 0, c08tail;
    const int no_mask = c08_no_livemask();
    const int tie = c08tie_strict();
    if (m252c08 == -2) {
        const char *e = getenv("UHA_M252C08");
        m252c08 = (e && e[0]) ? atol(e) : -1;
        /* `UHA_M252C08` recu as chain NO numerique (ex. `tail`) : rend only l'STATE FINAL of
         * each pass, for all cuts. */
        c08tail_cfg = (e && e[0] && !((e[0] >= '0' && e[0] <= '9') || e[0] == '-')) ? 1 : 0;
    }
    if (m252c08 >= 0 && (long)g_bandbase == m252c08) c08trk = 1;
    c08tail = c08tail_cfg;
    for (i = i0; i < i1; i++) {
        const uint32_t pos = (uint32_t)i;
        uint32_t bl = (~d[i]) & 0xffu;
        uint32_t cand[3];
        long dd = 0;
        int found = 0, j;
        unsigned k;
        if (c08_out) c08_out[i - off_out] = s->c08;
        if (bl == 0u || bl == 0xffu) continue;      /* 0x4226f3 / 0x4226fb : nor MRU nor lastpos */
        cand[0] = bl; cand[1] = (bl - 1u) & 0xffu; cand[2] = (bl + 1u) & 0xffu;
        for (j = 0; j < 3; j++) {
            uint32_t x = (pos - s->lastpos[cand[j]]) & PPM_MASK;
            if (x > 0u && x < 0x100u) { dd = (long)x; found = 1; break; }
        }
        if (found) {
            s->cnt[dd & 0xff] += 1;                 /* 0x41907a / 0x42276c */
            if ((uint32_t)dd != s->c08) {
                long q;
                /* `NB_LAW_EST` : `0x422793 jl 0x42285a` => frontier if `i - c08 < 0` (index RELATIF). */
                if (law == NB_LAW_EST && ((long)i - (long)blk0 - (long)s->c08) >= 0)
                    q = (long)i - (long)s->c08 + 256;      /* 0x422799 : no mask */
                else if (no_mask)
                    /* [M254] same rule au **bord of start of block** : reading directe. */
                    q = (long)i - (long)s->c08;
                else
                    q = ((long)i - (long)s->c08) & (long)PPM_MASK;   /* stream absolu */
                uint32_t nb = (~entree_byte(d, n, q)) & 0xffu;   /* [M172b] out member = payload */
                if (nb == bl) s->cnt[s->c08] += 1;         /* 0x4190b2 / 0x4227af */
                else s->c00 += 2;                          /* 0x419434 / 0x422874 */
                if ((uint32_t)dd != s->c04) s->c04 = (uint32_t)dd;   /* 0x419440 / 0x422880 */
                else {
                    /* `UHA_M252TIE` : 0 = rule ASM lue (`>=`, promotion at the egalite) ;
                     * 1 = majorite strict (`>`) to the two passes ; 2 = majorite strict sure there
                     * single pass LIVE (`law == NB_LAW_LIVE`). */
                    int strict = (tie == 2) ? (law == NB_LAW_LIVE) : (tie != 0);
                    if (strict ? (s->cnt[s->c04] >  s->cnt[s->c08])
                               : (s->cnt[s->c04] >= s->cnt[s->c08])) {
                    if (c08trk)
                        fprintf(stderr, "[M252C08] i=%zu loi=%d %u->%u bl=%u dd=%d "
                                "cnt_old=%u cnt_new=%u c00=%u c04=%u\n", i, law,
                                (unsigned)s->c08, (unsigned)dd, (unsigned)bl, (int)dd,
                                (unsigned)s->cnt[s->c08], (unsigned)s->cnt[dd & 0xff],
                                (unsigned)s->c00, (unsigned)s->c04);
                    s->c04 = s->c08; s->c08 = (uint32_t)dd;          /* 0x4190e7 / 0x4227da */
                    }
                }
            }
        }
        s->c00 += 1;                                 /* 0x4190fc / 0x4227e5 */
        if (s->c00 >= 0x28) {                        /* 0x419109 / 0x4227f2 */
            for (k = 0; k < 0x100; k++) s->cnt[k] >>= 1;
            s->cnt[s->c08] += 1;
            if (s->c08 == 1 && s->cnt[1] < 4) s->cnt[1] += 1;
            s->c00 = 0;
        }
        s->lastpos[bl] = pos;                        /* 0x41916b / 0x42284e */
    }
    if (c08tail)   /* `c08_phase` n'is appele that by there walk `cand == 0` (block `if (cand == 0u)`) */
        fprintf(stderr, "[M252C08TAIL] pos=%u loi=%d i0=%zu i1=%zu c00=%u c04=%u c08=%u\n",
                (unsigned)g_bandbase, law, i0, i1, (unsigned)s->c00, (unsigned)s->c04,
                (unsigned)s->c08);
}

/* machine MRU recence -> table c08[i] (validated 100 % vs m45_ctr_eng) */
static void c08_machine(const uint8_t *d, size_t n, uint32_t *c08_out,
                        uint32_t pos0, size_t off, int flow)
{
    uint32_t lastpos[256]; uint32_t cnt[0x100];
    uint32_t c00 = 0, c04 = 0, c08 = 1;
    const int abs_mode = flow ? 1 : c08abs();
    const int live_mode = flow ? 0 : c08live();
    size_t i; int b; unsigned k;
    /* [GATED UHA_PPM_C08DBG, defautOFF, M139] trace internal of the machine MRU
     * (`i c08 c04 c00 d bl nb cnt_c08 cnt_d found`) - diagnostic node has node only. */
    static int dbg_init = 0;
    static const char *dbg_path = NULL;
    FILE *dbg = NULL;
    if (!dbg_init) {
        const char *p = getenv("UHA_PPM_C08DBG");
        dbg_path = (p && p[0]) ? p : NULL;
        dbg_init = 1;
    }
    if (dbg_path) dbg = fopen(dbg_path, "a");
    if (live_mode && s_c08.init) {
        memcpy(lastpos, s_c08.lastpos, sizeof lastpos);
        memcpy(cnt, s_c08.cnt, sizeof cnt);
        c00 = s_c08.c00; c04 = s_c08.c04; c08 = s_c08.c08;
    } else {
        for (b = 0; b < 256; b++) lastpos[b] = abs_mode ? 0x80000000u : 0u;
        for (k = 0; k < 0x100; k++) cnt[k] = 0;
    }
    for (i = 0; i < n; i++) {
        long t_dd = -1, t_nb = -1;
        if (i >= off) c08_out[i - off] = c08;
        /* [M170o] trace COMPLETE some nodes of the block (gate C08DBG) : `N i c08 c04 c00` */
        if (dbg && i >= off) fprintf(dbg, "N %zu %u %u %u\n", i - off, c08, c04, c00);
        /* [M137] `bl` = COMPLEMENT of the stream at the index **GLOBAL** `pos44` :
         * `bl == ~eng[pos44]` measured **16 296/16 296 = 100 %** (the variantes `eng[pos]`
         * and `+256` plafonnent has 7,69 % / 0 %). for there window 0, `pos44 == i`. */
        uint32_t bl = (~d[i]) & 0xffu;
        /* [M136] gardes ASM : `0x4226f3 test bl,bl ; je end` and `0x4226fb cmp bl,0xff ; je end`
         * => for bl in {0, 0xff} nor MRU nor update of `lastpos[bl]`. */
        if (bl == 0u || bl == 0xffu) { continue; }
        long dd;
        int found = 0;
        uint32_t cand[3]; int j;
        const uint32_t pos = abs_mode ? (pos0 + (uint32_t)i) : (uint32_t)i;
        cand[0] = bl; cand[1] = (bl - 1u) & 0xffu; cand[2] = (bl + 1u) & 0xffu;
        dd = 0;
        for (j = 0; j < 3; j++) {
            long x;
            /* [M139] BASE 0 : `pos44` measured demarre has **0** (`hit 1 -> pos44 = 0`) and `lastpos[bl]`
             * equals there **position 0-based** of the last byte (dump `0x46af50` hit 512 : `lastpos[133]=294`
             * = index of the last `'z'`). Has byte never vu (`lastpos = 0`) gives therefore `d = i`,
             * rejete only if `i == 0`. There base `i+1` utilisee before faussait `d` of +1
             * (c08 98,80 %) ; en base 0 the rejeu gives **12 544/12 544 = 100 %** vs GT `m133` col `c08`. */
            x = (long)pos - (long)lastpos[cand[j]];
            x &= PPM_MASK;
            if (x > 0 && x < 0x100) { dd = x; found = 1; break; }
        }
        if (found) {
            cnt[dd & 0xff] += 1;
            if ((uint32_t)dd != c08) {
                long p = (long)i - (long)c08;
                /* [M137/M135] `nb` reads the same buffer model that `err` : `buf = input + 256`
                 * (`0x422799 add edx,[esp+0x18]` then `0x42279d mov dl,[edx]`), now l'acces
                 * `input[pos20 + 256  c08]` - l'old `i  c08` ignorait l'offset. */
                /* [M170o] `UHA_PPM_C08NB=1` : reading **without** shift (law ASM 0x422799) ;
                 * default = old acces `+256` (behavior historique unchanged). */
                uint32_t nb = c08nb0()
                            ? ((~seed_byte(d, n, p, 0)) & 0xffu)
                            : ((~seed_byte(d, n, p + 256L, 256L)) & 0xffu);
                t_dd = dd; t_nb = (long)nb;
                if (dbg) fprintf(dbg, "%zu %u %u %u %ld %u %u %u %u %u 1\n", i, c08, c04, c00, dd, bl, nb,
                                 cnt[c08], cnt[dd & 0xffu], (nb == bl) ? 1u : 0u);
                if (nb == bl) cnt[c08] += 1; else c00 += 2;
                if ((uint32_t)dd != c04) c04 = (uint32_t)dd;
                else if (cnt[c04] >= cnt[c08]) { c04 = c08; c08 = (uint32_t)dd; }
            } else if (dbg)
                fprintf(dbg, "%zu %u %u %u %ld %u 0 %u %u 2\n", i, c08, c04, c00, dd, bl, cnt[c08], cnt[dd & 0xffu]);
            c00 += 1;
            if (c00 >= 0x28) {
                for (k = 0; k < 0x100; k++) cnt[k] >>= 1;
                cnt[c08] += 1;                       /* fix main 0x42281f/0x422826 */
                if (c08 == 1 && cnt[1] < 4) cnt[1] += 1;
                c00 = 0;
            }
        } else {
            c00 += 1;
            if (c00 >= 0x28) {
                for (k = 0; k < 0x100; k++) cnt[k] >>= 1;
                cnt[c08] += 1;
                if (c08 == 1 && cnt[1] < 4) cnt[1] += 1;
                c00 = 0;
            }
        }
        if (dbg && i >= off)
            fprintf(dbg, "D %zu %u %u %u %ld %ld %u %u\n", i - off, c08, c04, c00, t_dd, t_nb, bl,
                    (unsigned)cnt[(uint32_t)(c08 & 0xffu)]);
        lastpos[bl] = pos;   /* [M139] position of the last byte (as `0x46af50`) ; [M170o] absolue if C08ABS */
    }
    if (live_mode) {
        memcpy(s_c08.lastpos, lastpos, sizeof lastpos);
        memcpy(s_c08.cnt, cnt, sizeof cnt);
        s_c08.c00 = c00; s_c08.c04 = c04; s_c08.c08 = c08; s_c08.init = 1;
    }
    if (dbg) fclose(dbg);
}

void ppm_cost_set_prectx(uint32_t v)
{
    g_prectx = v;
}

void ppm_cost_set_window(uint32_t bandbase, uint32_t initctx)
{
    g_bandbase = bandbase;
    g_initctx = initctx;
}

void ppm_cost_set_flag(uint32_t f)
{
    g_flag_in = f & 1u;
    g_flag_set = 1;
}

uint32_t ppm_cost_get_flag(void)
{
    return g_flag_out;
}

/* ---------------------------------------------------------------------------
 * [M220, GATED UHA_PPM_ROWSEL, default-OFF] THE SELECTEUR OF line OF THE NUD 0x4221c0
 * ---------------------------------------------------------------------------
 * The node not computes not has cost sure `rel` : il computes d'abord has INDEX OF line
 * `ebp` (0x42261a `mov ebp,[eax*4+0x43b2cc]`) has partir of has delta 2D, then Has SINGLE
 * cost sure this line (0x4223f1). The delta is there difference between there prediction
 * by distance `d = [0x481c08]` and the one by distance `2d` (0x4225a1..0x4225e0) :
 *     cl  = ~win[i-d]     b2 = ~win[i-2d]     delta = cl - b2
 *     line = PPMS_43B2CC[delta]                err = sym - cl
 * `d` is maintenu by the model OF DISTANCE (0x422704..0x42284e), execute en END
 * of node `cand == 0` : `last[256]` (0x46af50), `dhist[256]` (0x469f48), registres
 * 0x481c00/04/08, halving has 0x28. The all persiste of has candidate au next (l'arena
 * n'is never remise has plat) ; l'snapshot n'is RAFRAICHI since the live that if
 * `cand == class current == 0` (0x422315, cf. ppm_cost_rowsel_feed_live).
 */
#define RS_MASK 0xffffu

static int rowsel_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ROWSEL"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

int ppm_cost_rowsel_on(void)
{
    return rowsel_on();
}

/* 0x417929..0x41794a + 0x41795f : `last` = 0x80000000, `dhist` = 0, regs 0/0/1. */
void ppm_cost_rowsel_reset(ppm_cost_arena *a)
{
    uint32_t k;
    if (!a) return;
    for (k = 0; k < 256u; k++) { a->last[k] = 0x80000000u; a->dhist[k] = 0u; }
    a->reg00 = 0u; a->reg04 = 0u; a->reg08 = 1u;
    a->dctr = 0u; a->dma = 0u; a->bias = 0u;
    a->rowsel_armed = 1;
}

/* 0x42270c..0x422757 (node) / 0x41900f..0x419065 (machine live) : distance retenue =
 * the one of the symbole, repli sure sym-1 then sym+1 so much qu'elle depasse 0x100 (no
 * re-test after sym+1, 0x42274c/0x422755 retombe sure 0x422759). */
static uint32_t rs_dist(const uint32_t *last, uint32_t pos, uint32_t sym)
{
    uint32_t d = (pos - last[sym & 0xffu]) & RS_MASK;
    if (d >= 0x100u) {
        d = (pos - last[(sym - 1u) & 0xffu]) & RS_MASK;
        if (d >= 0x100u)
            d = (pos - last[(sym + 1u) & 0xffu]) & RS_MASK;
    }
    return d;
}

/* 0x4227e5..0x422846 (node) / 0x4190fc..0x41915b (live) : counter + halving has 0x28.
 * The halving porte sure the 256 counters THEN re-incremente `dhist[reg08]` ; if
 * `reg08 == 1` and `dhist[1] < 4`, `dhist[1]` is still incremente (0x422832..0x422840). */
static void rs_tail(uint32_t *dhist, uint32_t *reg00, uint32_t reg08)
{
    uint32_t k, r8;
    (*reg00)++;
    if (*reg00 < 0x28u)
        return;
    for (k = 0; k < 256u; k++)
        dhist[k] >>= 1;
    r8 = reg08 & 0xffu;
    dhist[r8]++;
    *reg00 = 0u;
    if (r8 == 1u && dhist[1] < 4u)
        dhist[1]++;
}

/* 0x42276c..0x4227e5 (node) / 0x41907a..0x4190fc (live) : model of distance of has
 * node. `pred_ok` = there prediction by `reg08` retombe sure the symbole (the two bytes
 * are complementes, therefore there comparaison raw is equivalente). */
static void rs_body(uint32_t *dhist, uint32_t *reg00, uint32_t *reg04, uint32_t *reg08,
                    uint32_t d, int pred_ok)
{
    dhist[d]++;
    if (d != *reg08) {
        if (!pred_ok)
            *reg00 += 2u;                   /* 0x422874 / 0x419434 */
        else
            dhist[*reg08]++;                /* 0x4227af / 0x4190bc */
        if (d != *reg04) {
            *reg04 = d;                     /* 0x422880 / 0x419440 */
        } else if (dhist[*reg04] >= dhist[*reg08]) {
            *reg04 = *reg08;                /* 0x4227da / 0x4190e7 */
            *reg08 = d;
        }
    }
    rs_tail(dhist, reg00, *reg08);
}

/* [M230] AMORCAGE " FREQUENCIES NEUVES + ESCAPES OF THE model ". The feed reel does
 * `arene_esc[rel] = esc_abs[base+rel]` (0x4222e0) and `esc_abs` = `m->ent_wt` : l'`escape` of
 * l'arena **is** the one of the model ; the `+0x20` (0x422488) is there update *during there walk*.
 * Measures (M222, `win_pos = 1 109 444` = frontier `1 071 003`) : `ent_wt[0] = 49` with
 * `Sigma freq(row 0) = 0`, and `1` for the lines 1..3. Has reset plat (`escape = 1`) is therefore false sure
 * l'escape ; this function keeps the frequencies has zero and sets `escape = total = ent_wt`.
 * Rend 0 if l'input is invalid. */
/* [M235] Variante " PRIOR SINGLE " : frequencies neuves, escapes plats (`1`), but on keeps there
 * ROW OF PRIOR of the candidate (0x42242b). if there row is empty, the 1er term cold equals
 * `LUT[0 / cum0]` = cost MAXIMAL, this which RENCHERIT each node cold - piste of the +4,77 % of
 * 1 071 003. */
int ppm_cost_arena_seed_prior(ppm_cost_arena *a, const ppm_live_arena *L)
{
    if (!a || !L)
        return 0;
    a->prior = L->prior_freq;
    a->prior_total = L->prior_total;
    return 1;
}

int ppm_cost_arena_seed_esc(ppm_cost_arena *a, const ppm_live_arena *L)
{
    uint32_t rel;
    if (!a || !L || !L->ent)
        return 0;
    if (L->n > PPM_COST_MAXCTX)
        return 0;
    for (rel = 0; rel < L->n; rel++) {
        uint32_t esc = L->ent[L->base + rel];
        a->escape[rel] = (uint16_t)esc;
        a->total[rel]  = (uint16_t)esc;      /* Sigmafreq = 0 */
    }
    a->prior = L->prior_freq;
    a->prior_total = L->prior_total;
    return 1;
}

/* [M220] Election of the line for `cand == 0` (0x42259d..0x422623) : rend there line,
 * l'index d'arena and the biais eventuel. `win` = start of the block, `bandbase` = start. */
int ppm_cost_rowsel(ppm_cost_arena *a, const uint8_t *win, const uint8_t *flux,
                    size_t fn, uint32_t i, uint32_t bandbase,
                    uint32_t *row, uint32_t *err, uint32_t *bias)
{
    uint32_t d, cl, b2, delta, sym, pos;
    if (!a || !row || !err || !bias)
        return 0;
    *bias = 0u;
    pos   = bandbase + i;
    d     = a->reg08;
    sym   = (~win[i]) & 0xffu;              /* bl = stream[pos] (0x4223cb) */
    /* 0x4225a1..0x4225d4 : predictions to the distances `d` and `2d` ; index RELATIF negatif
     * -> STREAM ABSOLU (0x422628 / 0x422644), law measured M170r. */
    cl = ((long)i - (long)d < 0)
       ? flux_byte(flux, fn, pos, (long)d)
       : ((~entree_byte(flux, fn, (long)bandbase + (long)i - (long)d + 256L)) & 0xffu);
    b2 = ((long)i - 2L * (long)d < 0)
       ? flux_byte(flux, fn, pos, 2L * (long)d)
       : ((~entree_byte(flux, fn, (long)bandbase + (long)i - 2L * (long)d + 256L)) & 0xffu);
    delta = (cl - b2) & 0xffu;
    /* 0x4225e2 : `[esp+0x40] = 0` at each node, then 0x4225e8 decoupe sure `reg08`. */
    if (d == 4u) {
        int32_t s = (int32_t)(int8_t)delta;
        uint32_t m = ((uint32_t)(s < 0 ? -s : s) + a->dma) >> 1;   /* 0x4225fd */
        a->dma = m;                                                /* 0x4225ff */
        if (m <= 3u)
            *bias = (m << 10) + 0x800u;                            /* 0x422608 */
    } else if (d > 4u) {
        if (delta == 0u)
            a->dctr += 3u;                                         /* 0x42268b */
        else
            a->dctr >>= 1;                                         /* 0x422664 */
        if (a->dctr >= 6u)
            *bias = 0x800u;                                        /* 0x42266f */
    }
    *row = PPM_T2CC[delta];                 /* 0x42261a */
    *err = (sym - cl) & 0xffu;              /* 0x422621 : bh = bl - cl */
    return 1;
}

/* [M220] End of node `cand == 0` : update of the model of distance (0x422704..0x42284e). */
void ppm_cost_rowsel_step(ppm_cost_arena *a, const uint8_t *win, const uint8_t *flux,
                          size_t fn, uint32_t i, uint32_t bandbase)
{
    uint32_t sym, pos, d, pred;
    if (!a)
        return;
    pos = bandbase + i;
    sym = (~win[i]) & 0xffu;
    /* 0x4226f3 : `test bl,bl` then `cmp bl,0xff` - the symboles 0 and 0xFF are EXCLUS
     * (nor model of distance, nor `last[]`). */
    if (sym == 0u || sym == 0xffu)
        return;
    d = rs_dist(a->last, pos, sym);
    if (d == 0u || d >= 0x100u) {           /* 0x422759 -> 0x4227e5 */
        rs_tail(a->dhist, &a->reg00, a->reg08);
    } else {
        /* 0x422785..0x4227a1 : there prediction by `reg08` retombe-t-elle sure the symbole ? */
        pred = ((long)i - (long)a->reg08 < 0)
             ? flux_byte(flux, fn, pos, (long)a->reg08)
             : ((~entree_byte(flux, fn, (long)bandbase + (long)i - (long)a->reg08 + 256L)) & 0xffu);
        rs_body(a->dhist, &a->reg00, &a->reg04, &a->reg08, d, pred == sym);
    }
    a->last[sym] = pos;                     /* 0x42284e : at each node */
}

/* [M220] Machine has distance LIVE (0x418fc0..0x41918d), rejouee sure `mem[0..upto)`.
 * same law that the node, but all lectures passent by the stream absolu
 * (`stream[(pos-k)&mask]`, 0x4190a9) and l'state is the one some tables LIVE. Has call by
 * byte EMIS (0x419bc5/0x41c4e2) => l'state at the position P is has function deterministe
 * of the prefixe. Recopie ensuite in l'snapshot (0x422315). */
void ppm_cost_rowsel_feed_live(ppm_cost_arena *a, const uint8_t *mem, size_t upto)
{
    uint32_t l_last[256], l_hist[256];
    uint32_t r00 = 0u, r04 = 0u, r08 = 1u, pos, k;
    if (!a || !mem)
        return;
    for (k = 0; k < 256u; k++) { l_last[k] = 0x80000000u; l_hist[k] = 0u; }
    for (pos = 0; pos < (uint32_t)upto; pos++) {
        uint32_t sym = (~mem[pos]) & 0xffu;
        uint32_t d, pred;
        if (sym == 0u || sym == 0xffu)      /* 0x418ff0 / 0x418ff9 -> 0x419171 */
            continue;
        d = rs_dist(l_last, pos, sym);
        if (d == 0u || d >= 0x100u) {
            rs_tail(l_hist, &r00, r08);
        } else {
            pred = (~mem[(pos - r08) & RS_MASK]) & 0xffu;   /* 0x4190a9 */
            rs_body(l_hist, &r00, &r04, &r08, d, pred == sym);
        }
        l_last[sym] = pos;                  /* 0x41916b */
    }
    memcpy(a->last, l_last, sizeof a->last);
    memcpy(a->dhist, l_hist, sizeof a->dhist);
    a->reg00 = r00;
    a->reg04 = r04;
    a->reg08 = r08;
    /* [M220] probe of causalite : `UHA_PPM_RSD=<n>` forces there distance of start
     * (`[0x481c08]`) that the master had has this frontier. Never promotable. */
    { static long fdr = -2;
      if (fdr == -2) { const char *e = getenv("UHA_PPM_RSD"); fdr = (e && e[0]) ? atol(e) : -1; }
      if (fdr >= 0) a->reg08 = (uint32_t)fdr; }
    a->rowsel_armed = 1;
}

/* cost of has candidate (cls 0..4) sure there window : stream (ctx,err,override) -> CostArena -> Sigma.
 * class0 (cand0) : ring + override (acc/order) ; cand>=1 : rouleau, ctx recurrence lag 1,
 * no override (echappement porte by l'arena). Pruning if cumul>incumbent. */
static uint64_t ppm_cost_gen_a(ppm_cost_arena *ap, const uint8_t *win, size_t len,
                               uint32_t cand, uint64_t incumbent, int reset)
{
    static uint32_t *s_errs = NULL, *s_c08 = NULL, *s_ess = NULL;
    static size_t s_errs_cap = 0, s_c08_cap = 0, s_ess_cap = 0;
    ppm_cost_arena *const arena = ap;
    { static int mc = -1;
      if (mc < 0) { const char *e = getenv("UHA_M265CTX"); mc = (e && e[0] != '0') ? 1 : 0; }
      g_m265_ctxarm = (uint32_t)mc; g_m265_ctxmax = 0u; }
    uint64_t cumul = 0;
    unsigned long cold_n = 0;
    size_t i;
    const size_t need = len ? len : 1u;
    uint32_t *c08 = NULL;
    uint32_t *errs;
    uint32_t *ess = NULL;               /* [M154] err_seed by node (gate LAW256) */
    const int law = law256();
    if (need > s_errs_cap) {
        uint32_t *p = (uint32_t *)realloc(s_errs, need * sizeof *p);
        if (!p) return 0;
        s_errs = p;
        s_errs_cap = need;
    }
    errs = s_errs;
    if (cand == 0u) {
        if (need > s_c08_cap) {
            uint32_t *p = (uint32_t *)realloc(s_c08, need * sizeof *p);
            if (!p) return 0;
            s_c08 = p;
            s_c08_cap = need;
        }
        c08 = s_c08;
        if (c08flow() >= 2) {
            /* [M170r]  TWO PHASES - there single law measured which rende at the fois l'state d'input of the
             * block AND the nodes (`m170q` 85/85) :
             *   Has. machine LIVE sure `[0, start)` (law stream, offset 0) => state `c00/c04/c08/cnt`
             *      AND `lastpos` at the input of the block (c'is this that `0x422315` recopie live -> travail) ;
             *   B. estimator sure `[start, start+len)` (law `input` +256, frontier `i < c08` -> 0)
             *      => there sequence `c08[]` of the block. */
            size_t st = (size_t)g_bandbase;
            c08_state s;
            c08_seed(&s);
            if (st) c08_phase(win - st, st + len, 0, st, NULL, 0, st, NB_LAW_LIVE, &s);
            c08_phase(win - st, st + len, st, st + len, c08, st, st, NB_LAW_EST, &s);
        } else if (c08flow()) {
            /* [M170o] STREAM : rejeu deterministe sure `d[0 .. start+len)` (positions absolues),
             * output only for `[start, start+len)`. `win = base + start`. */
            size_t st = (size_t)g_bandbase;
            c08_machine(win - st, st + len, c08, 0u, st, 1);
        } else {
            c08_machine(win, len, c08, g_bandbase, 0, 0);
        }
        if (law) {
            if (need > s_ess_cap) {
                uint32_t *p = (uint32_t *)realloc(s_ess, need * sizeof *p);
                if (!p) return 0;
                s_ess = p;
                s_ess_cap = need;
            }
            ess = s_ess;
        }
    }
    /* 1 pass : err by symbole */
    /* [M130c->M170k] flag of direction : `[esp+0x50]` = `g_flag_in` (voir ppm_cost_set_flag).
     * Source legacy : `BYTE[0x483932]` = m->cls_neg for the candidate equal at the class current,
     * heritage of the cadre of stack (flag final of the candidate previous) otherwise. */
    if (!g_flag_set) {
        static int env_done;
        if (!env_done) { const char *e = getenv("UHA_PPM_PRED_FLAG");
                         env_done = 1; if (e && e[0]) g_flag_in = (e[0] != '0') ? 1u : 0u; }
    }
    int flag = g_flag_in ? 1 : 0;
    if (cand == 0u) {
        const long soff = seed_off();
        const int p_act = pay_active();
        const int c08_flux = (law >= 3 && (p_act || c08_border_flux()));
        const uint8_t *const flux = win - g_bandbase;
        const size_t fn = (size_t)g_bandbase + len;
        for (i = 0; i < len; i++) {
            /* [M130c] SEED (cand0), path 0x42259d..0x4225e6 :
             *   cl = ~data[posc08] (0x4225b5/0x4225b7) ; bh = ~data[pos2*c08] (0x4225d2/0x4225d4)
             *   `al = cl ; sub al,bh` (0x4225dc/0x4225e0) => err = model(posc)  model(pos2c)
             *   = (data[pos2c]  data[posc]) & 0xff - without flag of direction. */
            uint32_t c = c08[i] ? c08[i] : 1u;
            long p1 = (long)i + soff - (long)c;
            long p2 = (long)i + soff - 2L * (long)c;
            if (law) {
                /* [M154] LAW COMPLETE (cf law256) : two variables DISTINCTES au same node. */
                uint32_t cl, b2;
                const uint32_t wpos = g_bandbase + (uint32_t)i;
                if (c08_flux) {
                    cl = ((long)i - (long)c < 0)
                       ? flux_byte(flux, fn, wpos, (long)c)
                       : ((p_act
                          ? entree_byte(flux, fn, (long)g_bandbase + (long)i - (long)c + 256L)
                          : law_byte(win, len, (long)i - (long)c + 256L)) ^ 0xffu);
                    b2 = ((long)i - 2L * (long)c < 0)
                       ? flux_byte(flux, fn, wpos, 2L * (long)c)
                       : ((p_act
                          ? entree_byte(flux, fn, (long)g_bandbase + (long)i - 2L * (long)c + 256L)
                          : law_byte(win, len, (long)i - 2L * (long)c + 256L)) ^ 0xffu);
                } else {
                    cl = (i >= (size_t)c)
                        ? ((~law_byte(win, len, (long)i - (long)c + 256L)) & 0xffu) : 0u;
                    b2 = (i >= 2u * c)
                        ? ((~law_byte(win, len, (long)i - 2L * (long)c + 256L)) & 0xffu) : 0u;
                }
                ess[i] = (cl - b2) & 0xffu;
                if (law >= 2)
                    errs[i] = ((((~win[i]) & 0xffu) - cl)) & 0xffu;
                else if ((long)i - (long)c < 0)
                    errs[i] = (~win[i]) & 0xffu;
                else
                    errs[i] = (ring_byte(win, len, (long)i - (long)c) - win[i]) & 0xffu;
            } else if (c < 4u) {
                if ((long)i - (long)c < 0)
                    errs[i] = (~win[i]) & 0xffu;
                else
                    errs[i] = (ring_byte(win, len, (long)i - (long)c) - win[i]) & 0xffu;
            } else if (p2 < 0)
                errs[i] = 0u;
            else if (soff > 0)
                errs[i] = (seed_byte(win, len, p2, soff)
                         - seed_byte(win, len, p1, soff)) & 0xffu;
            else
                errs[i] = (ring_byte(win, len, p1)
                         - ring_byte(win, len, p2)) & 0xffu;
        }
    } else {
        /* err cand>=1 - LAW DECODEE in L'ASM + VERIFIED GT (M130c) : rolling 4-byte
         * complement register initialized with g_prectx, toggling flag whenever err >= 0x80. */
        static const uint32_t SH[5] = {0, 0, 8, 16, 24};
        const uint32_t sh = SH[cand];
        uint32_t ctx_bits = g_prectx;
        for (i = 0; i < len; i++) {
            uint32_t bl = (~(uint32_t)win[i]) & 0xffu;
            uint32_t pred = (ctx_bits >> sh) & 0xffu;
            uint32_t err = flag ? ((pred - bl) & 0xffu) : ((bl - pred) & 0xffu);
            if (err >= 0x80u)
                flag = !flag;
            errs[i] = err;
            ctx_bits = (ctx_bits << 8) | bl;
        }
    }
    /* [M125] l'arena n'is NOT remise has plat between candidates legacy side :
     * `reset` n'is true that for the first candidate evaluates (heritage measured). */
    if (reset)
        ppm_cost_arena_reset(arena);
    /* [M220, UHA_PPM_ROWSEL] `dctr`/`dma`/`bias` are some slots of STACK remis has 0 at each
     * call of l'estimator (0x4221e6..0x4221ee) : this n'is no l'state persistant. */
    const int rs = rowsel_on();
    if (rs) { arena->dctr = 0u; arena->dma = 0u; arena->bias = 0u; }
    {
        static int ec = -1;
        static long cs = -2;
        static int ni = -1;
        static long mn = -2;
        static int mnc = -1;
        static unsigned long mnn = 0;
        static int cs_seq = -1;
        static FILE *csf = NULL;
        static unsigned long csn = 0;
        static long only = -2;
        static long rb = -2;
        static unsigned char *bm = NULL, *be = NULL;
        static int c5 = -1;
        static int nc = -1;
        static FILE *nf = NULL;
        static int c2 = -1;
        static int c2lim = 8;
        static FILE *fd = NULL;
        static int fd_ini = 0;
        static int c6 = -1;
        static int c3 = -1;

        if (ec < 0) { const char *e = getenv("UHA_PPM_ERRCOST"); ec = (e && e[0] != '0') ? 1 : 0; }
        if (cs == -2) {
            const char *e = getenv("UHA_PPM_CTXSAVE");
            const char *n2 = getenv("UHA_PPM_CTXNOINC");
            cs = (e && e[0]) ? atol(e) : 0;
            ni = (n2 && n2[0] != '0') ? 1 : 0;
        }
        if (mn == -2) {
            const char *e = getenv("UHA_M252NODES");
            const char *c2e = getenv("UHA_M252NODES_CAND");
            mn = (e && e[0]) ? atol(e) : -1;
            mnc = (c2e && c2e[0]) ? (int)atol(c2e) : 0;
        }
        if (cs_seq < 0) {
            const char *e = getenv("UHA_COSTSEQ");
            cs_seq = (e && e[0]) ? 1 : 0;
            if (cs_seq) csf = fopen(e, "w");
            if (cs_seq && !csf) cs_seq = 0;
        }
        if (cs_seq && only == -2) {
            const char *e2 = getenv("UHA_COSTSEQ_POS");
            only = (e2 && e2[0]) ? atol(e2) : -1;
        }
        if (rb == -2) { const char *e = getenv("UHA_PPM_RSDBG"); rb = (e && e[0]) ? atol(e) : -1; }
        if (c5 < 0) { const char *e = getenv("UHA_COSTDBG5"); c5 = (e && e[0] != '0') ? 1 : 0; }
        if (nc < 0) { const char *p = getenv("UHA_PPM_NODECOST"); nc = (p && p[0]) ? 1 : 0; if (nc) nf = fopen(p, "w"); }
        if (c2 < 0) {
            const char *e = getenv("UHA_COSTDBG2");
            const char *L = getenv("UHA_COSTDBG2_N");
            c2 = (e && e[0] != '0') ? 1 : 0;
            if (L && atoi(L) > 0) c2lim = atoi(L);
        }
        if (!fd_ini) {
            const char *p = getenv("UHA_PPM_NODEDUMP");
            fd_ini = 1;
            fd = (p && p[0]) ? fopen(p, "a") : NULL;
        }
        if (c6 < 0) { const char *e = getenv("UHA_COSTDBG6"); c6 = (e && e[0] != '0') ? 1 : 0; }
        if (c3 < 0) { const char *e = getenv("UHA_COSTDBG3"); c3 = (e && e[0] != '0') ? 1 : 0; }
        M252CUT_ARM();

        const int cb_on = ctxband_on();
        const int cnf = cutnofeed_on();
        const int cnf_cut = cnf && !(nofeedhead_on() && incumbent == 0xffffffffu);
        const int rb_hit = (rb >= 0 && (long)g_bandbase == rb);
        const int mn_hit = (mn >= 0 && (long)g_bandbase == mn && (int)cand == mnc);
        const int any_probe = (mn_hit || (cs_seq && csf) || rb_hit || c5 || (nc && nf)
                               || c2 || (fd != NULL) || c6 || c3 || g_m252cut);
        const uint32_t bi0 = cb_on ? g_ctxband : (uint32_t)((long)g_bandbase - cs);
        const int fast_bi3 = (cand == 3u && !ni && ((uint64_t)bi0 + (uint64_t)len <= 0xffffffffULL));
        uint32_t bi3 = fast_bi3 ? (bi0 % 3u) : 0u;
        uint32_t acc = 0, order = 0, ctx = g_initctx;

        for (i = 0; i < len; i++) {
            uint32_t c = (cand == 0u) ? (c08[i] ? c08[i] : 1u) : 0u;
            uint32_t bh, ctx_here = 0, err = errs[i], ov = 0u, f = 0u, t = 0u, node;
            uint32_t rs_bias = 0u;
            int      rs_use = 0;
            if (cand == 0u && rs) {
                /* [M220, UHA_PPM_ROWSEL] path 2D EXACT (0x42259d..0x422623). */
                ppm_cost_rowsel(arena, win, win - g_bandbase, (size_t)g_bandbase + len,
                                (uint32_t)i, g_bandbase, &ctx_here, &err, &rs_bias);
                bh = errs[i];
                ov = 0u;
                rs_use = 1;
            } else if (cand == 0u) {
                bh = errs[i];                                   /* = (e1  e2) & 0xff  = err_seed */
                ctx_here = ctx;                                 /* == T2CC[err_seed(i)] (errs decale) */
                ctx = PPM_T2CC[bh];
                if (law && ess) {
                    /* [M154] `ctx` and `acc`/`order` read `err_seed` au same node. */
                    bh = ess[i];
                    ctx_here = PPM_T2CC[bh];
                    ctx = ctx_here;
                }
                if (__builtin_expect(ec, 0)) {
                    uint32_t e1 = ring_byte(win, len, (long)i - (long)c);
                    err = (i < (size_t)c) ? ((255u - (uint32_t)win[i]) & 0xffu)
                                          : ((e1 - (uint32_t)win[i]) & 0xffu);
                }
                if (c == 4u) { int32_t es = (int32_t)bh; if (es >= 128) es -= 256;
                    acc = ((uint32_t)((es < 0 ? -es : es) + acc) >> 1);
                    ov = (acc <= 3u) ? ((acc << 10) + 0x800u) : 0u; }
                else if (c > 4u) { order = (bh == 0u) ? (order + 3u) : (order >> 1);
                    ov = (order >= 6u) ? 0x800u : 0u; }
            } else {
                uint32_t bi = cb_on ? (g_ctxband + (uint32_t)i)
                                    : (uint32_t)((long)g_bandbase + (ni ? 0L : (long)i) - cs);
                ctx_here = ctx;                                /* cand>=1 : lag 1 (ctx sets au sym. i1) */
                bh = errs[i] & 0xffu;
                if (cand == 1u) ctx = PPM_T6DC[bh] + ((PPM_T6CC[ctx & 0xfu] & 0xffu) << 4);
                else if (cand == 2u) ctx = PPM_T6DC[bh] + ((bi & 1u) << 4);
                else if (cand == 3u) ctx = PPM_T7DC[bh] + ((fast_bi3 ? bi3 : (bi % 3u)) << 5);
                else /*cand==4*/ ctx = PPM_T6DC[bh] + ((bi & 3u) << 4);
                if (fast_bi3) {
                    bi3++;
                    if (bi3 == 3u) bi3 = 0u;
                }
            }
            if (__builtin_expect(any_probe, 0)) {
                ppm_cost_peek(arena, ctx_here & 0xffu, err, &f, &t);
                if (mn_hit && mnn < 20000ul) {
                    fprintf(stderr, "[M252NODES] i=%zu row=%u err=%u f=%u\n",
                            i + 1u, (unsigned)(ctx_here & 0xffu), (unsigned)(err & 0xffu),
                            (unsigned)f);
                    mnn++;
                }
                if (cs_seq && csf && csn < 4000000ul && (only < 0 || (long)g_bandbase == only)) {
                    fprintf(csf, "%u %u %zu %u %u %u\n", (unsigned)g_bandbase, cand, i,
                            ctx_here & 0xffu, err & 0xffu, ov);
                    csn++;
                }
                if (rb_hit) {
                    if (!bm) bm = (unsigned char *)calloc(8192u, 1u);
                    if (!be) be = (unsigned char *)calloc(256u, 1u);
                    if (bm && be) {
                        uint32_t kk = ((ctx_here & 0xffu) << 8) | (err & 0xffu);
                        bm[kk >> 3] |= (unsigned char)(1u << (kk & 7u));
                        be[err & 0xffu] = 1u;
                        if (i + 1u == len) {
                            uint32_t nb = 0, nbd = 0, n2;
                            for (n2 = 0; n2 < 8192u; n2++)
                                nb += (uint32_t)__builtin_popcount(bm[n2]);
                            for (n2 = 0; n2 < 256u; n2++)
                                nbd += (uint32_t)be[n2];
                            fprintf(stderr, "[RSDIST] pos=%u cand=%u pairs=%u flag_in=%u nerr=%u\n",
                                    (unsigned)g_bandbase, (unsigned)cand, (unsigned)nb,
                                    (unsigned)g_flag_in, (unsigned)nbd);
                            memset(bm, 0, 8192u);
                            memset(be, 0, 256u);
                        }
                    }
                }
            }
            node = cnf
                ? ppm_cost_node_cost(arena, ctx_here & 0xffu, err, ov != 0u)
                : ppm_cost_node(arena, ctx_here & 0xffu, err, ov != 0u);
            if (rs_use && rs_bias != 0u)
                node = rs_bias;
            if (__builtin_expect(any_probe, 0)) {
                if (rb_hit &&
                    (i < 6u || i == 100u || i == 1000u || i == 6000u || i + 1u == len))
                    fprintf(stderr, "[RSDBG] rs=%d use=%d i=%u cand=%u d=%u ctx=%u err=%u f=%u t=%u bias=%u node=%u w=%u,%u,%u,%u\n",
                            rs, rs_use,
                            (unsigned)i, (unsigned)cand, (unsigned)arena->reg08,
                            (unsigned)(ctx_here & 0xffu), (unsigned)(err & 0xffu),
                            (unsigned)f, (unsigned)t, (unsigned)rs_bias, (unsigned)node,
                            (unsigned)win[0], (unsigned)win[1], (unsigned)win[2], (unsigned)win[3]);
            }
            if (cand == 0u && rs)
                ppm_cost_rowsel_step(arena, win, win - g_bandbase, (size_t)g_bandbase + len,
                                     (uint32_t)i, g_bandbase);
            if (__builtin_expect(any_probe, 0)) {
                if (c5 && ((i % 1024u) == 0u || i + 24u >= len))
                    fprintf(stderr, "[C5] cand=%u i=%zu ctx=%u err=%u f=%u t=%u node=%u cum=%llu"
                                    " tot0=%u esc0=%u\n",
                            cand, i, ctx_here & 0xffu, err, f, t, node,
                            (unsigned long long)cumul, arena->total[0], arena->escape[0]);
            }
            if (ov != 0u) node = ov;                           /* cost node = override otherwise LUT */
            if (__builtin_expect(any_probe, 0)) {
                if (nc && nf)
                    fprintf(nf, "%zu\t%u\t%u\t%u\t%u\t%llu\t%u\t%u\t%u\n", i,
                            ctx_here & 0xffu, err, ov, node,
                            (unsigned long long)cumul, cand, f, t);
                if (c2 && i < (size_t)c2lim)
                    fprintf(stderr, "[C2] cand=%u i=%zu ctx=%u err=%u ov=%u f=%u t=%u node=%u"
                                    " win=%u bh=%u c=%u nz=%u\n",
                            cand, i, ctx_here & 0xffu, err, ov, f, t, node,
                            win[i], bh, (cand == 0u) ? (c08 && c08[i] ? c08[i] : 1u) : 0u,
                            (unsigned)(win[0] | win[1] | win[2] | win[3]));
            }
            cumul += node;
            if (cnf_cut) {
                if (cumul > incumbent) {
                    if (!any_probe)
                        ppm_cost_peek(arena, ctx_here & 0xffu, err, &f, &t);
                    if (f == 0u)
                        ppm_cost_feed_esc(arena, ctx_here & 0xffu, PPM_COST_STEP);
                    M252CUT(cand, ctx_here, err, f, t, node, cumul, incumbent, i, 'c');
                    g_flag_out = (uint32_t)flag;
                    return cumul;
                }
                ppm_cost_node_feed(arena, ctx_here & 0xffu, err, PPM_COST_STEP);
            }
            if (__builtin_expect(any_probe, 0)) {
                if (fd) fprintf(fd, "%zu\t%u\t%u\n", i, ctx_here & 0xffu, err);
                if (f == 0u) {
                    cold_n++;
                    if (c6)
                        fprintf(stderr, "[C6] cand=%u i=%zu ctx=%u err=%u f=%u t=%u esc=%u node=%u\n",
                                cand, i, ctx_here & 0xffu, err, f, t,
                                arena->escape[ctx_here & 0xffu], node);
                }
            }
            if (cumul > incumbent) {
                M252CUT(cand, ctx_here, err, f, t, node, cumul, incumbent, i, 'e');
                g_flag_out = (uint32_t)flag;
                return cumul;
            }
        }
    }
    g_flag_out = (uint32_t)flag;
    M252CUT_END(cand, cumul, incumbent);
    /* [GATED UHA_COSTDBG3, defautOFF, M122p] number of visites COLD of the candidate. */
    { static int c3 = -1; if (c3 < 0) { const char *e = getenv("UHA_COSTDBG3"); c3 = (e && e[0] != '0') ? 1 : 0; }
      if (c3) fprintf(stderr, "[C3] cand=%u len=%zu cold=%lu cumul=%llu\n",
                      cand, len, cold_n, (unsigned long long)cumul); }
    {
        static long rdbg2 = -2;
        if (rdbg2 == -2) { const char *e = getenv("UHA_PPM_RSDBG"); rdbg2 = (e && e[0]) ? atol(e) : -1; }
        if (rdbg2 >= 0 && (long)g_bandbase == rdbg2)
            fprintf(stderr, "[RSCOLD] pos=%u cand=%u len=%zu cold=%lu cumul=%llu pernode=%.1f\n",
                    (unsigned)g_bandbase, (unsigned)cand, len, cold_n, (unsigned long long)cumul,
                    len ? (double)cumul / (double)len : 0.0);
    }
    if (g_m265_ctxarm)
        fprintf(stderr, "[M265CTX] pos=%u cand=%u len=%zu ctxmax=%u ctxband=%u\n", (unsigned)g_bandbase,
                (unsigned)cand, len, (unsigned)g_m265_ctxmax, (unsigned)g_ctxband);
    if (g_m265_outarm)
        fprintf(stderr, "[M265OUT] pos=%u cand=%u len=%zu out=%u\n", (unsigned)g_bandbase,
                (unsigned)cand, len, (unsigned)g_m265_out);
    return cumul;
}

static uint64_t ppm_legacy_cost_gen(const uint8_t *win, size_t len, uint32_t cand, uint64_t incumbent)
{
    ppm_cost_arena a;
    return ppm_cost_gen_a(&a, win, len, cand, incumbent, 1);
}

/* [M265, GATED UHA_M265COPY, default-OFF, read-only] Instant EXACT of the copie legacy
 * `0x422282` (juste BEFORE the `rep movs`) : the 96 first words of the SRC (`[0x43a260] +
 * base*0x200`, i.e. the priors `L->freq` line 0) and the 96 first words of the DEST (arena,
 * line 0, BEFORE ecrasement). GT : OUT/m264b_copy_real.tsv (w0..95 / y0..95, 30 lines
 * `0x422282`). no effect on l'arithmetique : two `fprintf` bounds by l'environnement. */
static int m265copy_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_M265COPY"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

static void m265copy_dump(ppm_cost_arena *a, const ppm_live_arena *L, uint32_t cand)
{
    uint32_t i;
    fprintf(stderr, "[M265COPY] pos=%u cand=%u base=%u n=%u w=", (unsigned)g_bandbase,
            (unsigned)cand, (unsigned)L->base, (unsigned)L->n);
    for (i = 0; i < 96u; i++)
        fprintf(stderr, " %u", (unsigned)L->freq[(size_t)L->base * 256u + i]);
    fprintf(stderr, " y=");
    for (i = 0; i < 96u; i++)
        fprintf(stderr, " %u", (unsigned)a->freq[i]);
    fprintf(stderr, " pt=%u p=", (unsigned)L->prior_total);
    if (L->prior_freq)
        for (i = 0; i < 32u; i++)
            fprintf(stderr, " %u", (unsigned)L->prior_freq[i]);
    fprintf(stderr, "\n");
    /* [M265] mode FULL (`UHA_M265FULL=1`) : the `n` lines entieres (256 words chacune) of the SRC,
     * in l'order memory = `freq[rel][sym]` - pair direct of `m265_freq_gt.tsv`. */
    { static int fu = -1;
      if (fu < 0) { const char *e = getenv("UHA_M265FULL"); fu = (e && e[0] != '0') ? 1 : 0; }
      if (fu) {
          uint32_t r;
          fprintf(stderr, "[M265FULL] pos=%u cand=%u n=%u", (unsigned)g_bandbase,
                  (unsigned)cand, (unsigned)L->n);
          for (r = 0; r < L->n; r++)
              for (i = 0; i < 256u; i++)
                  fprintf(stderr, " %u", (unsigned)L->freq[(size_t)(L->base + r) * 256u + i]);
          fprintf(stderr, "\n"); } }
    /* [M269] dump BINARY some rows 0..512 (model d'EMISSION) at the instant of the copie :
     * `UHA_M265LOW=<prefixe>` writes `<prefixe>_freq.bin` (513x256 u16), `_t25c.bin` (idem) and
     * `_t268.bin` (513 u16) - pairs directs of `m269_*_p937440.bin`. Has single writing. */
    { static int lo = -1; static unsigned long ln = 0; static long lp = -2;
      if (lo < 0) { const char *e = getenv("UHA_M265LOW"); lo = (e && e[0]) ? 1 : 0;
                    if (lo) s_lowpfx = e;
                    const char *p2 = getenv("UHA_M265LOW_POS"); lp = (p2 && p2[0]) ? atol(p2) : -1; }
      if (lo && ln == 0 && L->cum && L->ent && (lp < 0 || (long)g_bandbase == lp)) {
          char p[512];
          FILE *f;
          snprintf(p, sizeof p, "%s_freq.bin", s_lowpfx);
          if ((f = fopen(p, "wb")) != NULL) { fwrite(L->freq, 2, 513u * 256u, f); fclose(f); }
          snprintf(p, sizeof p, "%s_t25c.bin", s_lowpfx);
          if ((f = fopen(p, "wb")) != NULL) { fwrite(L->cum, 2, 513u * 256u, f); fclose(f); }
          snprintf(p, sizeof p, "%s_t268.bin", s_lowpfx);
          if ((f = fopen(p, "wb")) != NULL) { fwrite(L->ent, 2, 513u, f); fclose(f); }
          ln++; } }
}

/* [M170g] Variante " arena live " : no reset (0x42230e reutilise l'state in place) ;
 * the feed, when il has lieu, is does by ppm_cost_arena_load_live() (law : OUT/m170g_arenafeed.md). */
uint64_t ppm_legacy_cost_live(ppm_cost_arena *a, const uint8_t *win, size_t len,
                              uint32_t cand, uint64_t incumbent,
                              const ppm_live_arena *L, int feed)
{
    if (!a)
        return 0;
    if (!a->rowsel_armed)
        ppm_cost_rowsel_reset(a);      /* [M220] arena persistante : init paresseuse */
    if (feed && L && m265copy_on())
        m265copy_dump(a, L, cand);     /* [M265] state BEFORE there copie (site 0x422282) */
    if (feed && L && !ppm_cost_arena_load_live(a, L))
        return 0;
    /* [M252, GATED UHA_M252RELOAD, default-OFF, read-only] 96 `total[]` AFTER there recharge and
     * BEFORE there walk = l'instant EXACT of the BP legacy `0x422392` (GT
     * `OUT/m252_recharge_calls.tsv`, 80 hits). C'is there single facon of juger l'IMAGE rechargee
     * separement some feeds of the walk : the probes d'input d'call (`BLKARENA`/`M250B`) voient
     * l'state LEAVES by the candidate previous, not the one of the candidate which va tourner.
     * `n` = number of rows of the domaine recharge. no effect on l'arithmetique. */
    if (feed && L && (g_m252reload < 0
            ? (g_m252reload = (getenv("UHA_M252RELOAD") &&
                               getenv("UHA_M252RELOAD")[0] != '0') ? 1 : 0)
            : g_m252reload)) {
        uint32_t kr;
        fprintf(stderr, "[M252RELOAD] pos=%u cand=%u n=%u", (unsigned)g_bandbase,
                (unsigned)cand, (unsigned)L->n);
        for (kr = 0; kr < 96u; kr++)
            fprintf(stderr, " %u", (unsigned)a->total[kr]);
        fprintf(stderr, "\n");
    }
    return ppm_cost_gen_a(a, win, len, cand, incumbent, 0);
}

/* ---------------------------------------------------------------------------
 * COUTURE OF SELECTION (path consommatrice, independante of the generateur #2).
 * Reprend there law validated 10/10 (PPM_CLASS_LAW) : cls_bloc = argmin sure
 * {seed = 0x43b2c2[cls_courant]}  {1,2,3,4} of the cost legacy ; bc = archive[40]>>7 ;
 * " 0 call if pos < threshold(=pos+window) " (hello/code.c : keeps by l'appelant).
 * L'oracle of cost is injecte via `cost_fn` : the main y branchera `ppm_legacy_cost`
 * as soon as there generation `(ctx,err,override)` (#2, MISSION_M45) is validated > 90 %.
 * --------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * bc by there partition `restant = usize  Has  B  C  S`.
 *  RETRACTE (M124, 20261022) : `bc=(restant==0)` N'is NOT there law. The bancs
 * M122 montrent bc=1 with restant up to 15 799 ; there validation " 4/4 " sure some
 * files reels was has COINCIDENCE. There partition is necessary but no
 * suffisante (il manque the detecteur of langue `0x404510`). preserved only
 * as accesseur of test (injection UHA_PPM_*), never as predicat of prod.
 * --------------------------------------------------------------------------- */
uint32_t ppm_bc_from_restant(uint32_t usize)
{
    long A = 0, B = 0, C = 0, S = 0, restant;
    const char *e;
    if ((e = getenv("UHA_PPM_RESTANT"))) {           /* injection directe (test of cable) */
        restant = strtol(e, NULL, 0);
    } else {
        if ((e = getenv("UHA_PPM_A"))) A = strtol(e, NULL, 0);
        if ((e = getenv("UHA_PPM_B"))) B = strtol(e, NULL, 0);
        if ((e = getenv("UHA_PPM_C"))) C = strtol(e, NULL, 0);
        if ((e = getenv("UHA_PPM_S"))) S = strtol(e, NULL, 0);
        /* TODO(M80) : S = Sigma(buckets T1/T2) calcules since `usize`/input ; Has/B/C idem. */
        restant = (long)usize - A - B - C - S;
    }
    return (restant == 0) ? 1u : 0u;
}

/* ---------------------------------------------------------------------------
 * [M122] Partition of the frame legacy `0x4047c7..0x404833` computed SINCE THE bytes.
 * Law etablie and validated 4/4 sure the values legacy (`OUT/m70_restant_*.log`) AND
 * recoupee by has grandeur internal independante of legacy - the `ratio`
 * `(S<<6)/restant` compares en `0x404871` : code.c 107 and hello.txt 1696, values
 * reproduites exactement by this computation (`OUT/m63_bc_*.log`).
 *   Has = #(byte == 0x20)  espaces
 *   B = #(byte == 0x0a)  sauts of line
 *   C = 0                 (never observe no zero : 11 inputs corpus + 35 fabriquees)
 *   S = Sigma frequency some 26 lettres Has-Z / has-z (casse repliee) = table T1[0..25]
 *   restant = usize  Has  B  C  S ;   bc = (restant == 0)
 * LIMIT ASSUMEE : there partition n'is NOT there law `bc` (retractee M124) ; the predicat
 * " texte " of the detecteur `0x404510` n'is not transcrit here, and the legacy engine emits `bc=1`
 * for the BINARY same when restant>0. measured sure the corpus : 5/11 `bc` exact
 * only. Not not promouvoir out experimentation.
 * ------------------------------------------------------------------------- */
uint32_t ppm_bc_from_bytes(const uint8_t *d, uint32_t usize)
{
    uint32_t i, A = 0, B = 0, S = 0;
    long restant;
    if (!d)
        return 0;
    for (i = 0; i < usize; i++) {
        uint8_t b = d[i];
        if (b == 0x20)
            A++;
        if (b == 0x0a)
            B++;
        if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'))
            S++;
    }
    restant = (long)usize - (long)A - (long)B - (long)S;   /* C = 0 */
    return (restant == 0) ? 1u : 0u;
}

/* ===========================================================================
 * [GATED UHA_PPM_BCLAW, defautOFF, M159] Predicat `bc` = transcription of `0x404510`.
 *
 * Etabli by there measures :
 *  - M156 : `bc=1` is the DEFAULT, `bc=0` l'exception of has detection positive.
 *  - M157 : `bc = 0` ssi `0x404510` modifie the field class (bits 2431) of the `mode` (11/11).
 *  - M158 : predicat LOCAL measured 7/7 au site `0x4048c2` : `bc=0` ssi candidate != mode entrant.
 *
 * Corps transcrit (full.asm `0x40475c..0x404c34`) :
 *   histogramme sure min(n, 0x10000) (`0x40478f`), but `restant` sure n ENTIER (`0x404778`).
 *   `Has=h[0x20] B=h[0x0a] C=h[0x0d] S=Sigma[Has-Z]+Sigma[has-z]` ; `restant = nABCS` ;
 *   `ratio=(S<<6)/restant` (0 if restant==0) ; `ratio2=(sp2sp<<6)/(nA)` ;
 *   `textcount=#{c : BCLASS1[c]!=0}` (table `0x436d74`).
 *   DECISION = " engagement " (=> bc=0) ssi has soustraction of class has eu lieu AND all the
 *   tests passent : soustraction if `ratio>=40` (echelle 400/200/40) now `ratio2>=16` with Has!=0 ;
 *   rejet if `aa>a_na`, voyelle doublee (`ee/ii/oo/uu`), `2*esi <= edi` (`edi=#'e'`,
 *   `esi=#'e'` whose `BCLASS2[prev]>=1`, table `0x436e74`), now `rare(j,q,z,J,Q,Z) > (T+has+e+t+Has+E)>>2`.
 *
 * RESERVE measured : ~~`mixed.bin` (legacy bc=1) n'execute not the detecteur - reading short of
 * son stream has `0x4047bf`~~ -> **REFUTE M160** (run 5 : `eax == ebp` 3/3, reading FULL). There
 * true porte is l'arret of the scan has `32*textcount > n` (cf. there loop).
 * ========================================================================= */
static const uint8_t BCLASS1[256] = {
      0,   1,   1,   1,   1,   1,   1,   1,   0,   0,   0,   1,   1,   0,   1,   1,
      1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   1,   1,   1,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      1,   0,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
      1,   1,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
      1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
      0,   0,   1,   0,   1,   1,   1,   1,   1,   1,   0,   1,   1,   1,   1,   1,
      1,   1,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   0,   1,   1,
      1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,   0,   1,   1,   0,
      1,   0,   1,   1,   0,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,
      1,   1,   1,   1,   1,   1,   0,   1,   1,   1,   1,   1,   0,   1,   0,   1
};
static const uint8_t BCLASS2[256] = {
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   2,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   2,   0,
      2,   2,   2,   2,   2,   2,   2,   2,   2,   2,   0,   0,   0,   0,   0,   0,
      0,   0,   2,   0,   2,   2,   0,   2,   2,   2,   0,   0,   2,   2,   2,   0,
      0,   0,   2,   2,   2,   0,   2,   2,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   1,   0,   1,   1,   0,   1,   1,   1,   0,   0,   1,   1,   1,   0,
      0,   0,   1,   1,   1,   0,   1,   1,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0
};

/* `bc` predit by there transcription (0 = detection positive, 1 = default). */
uint32_t ppm_bc_law(const uint8_t *d, uint32_t usize)
{
    uint32_t h[256];
    uint32_t i, n = usize, scan, prev = 0;
    uint32_t A, B, Cr, S = 0, textcount = 0, edi = 0, esi = 0, sp2sp = 0;
    uint32_t a_eq = 0, a_ne = 0, i_eq = 0, i_ne = 0, e_eq = 0, e_ne = 0;
    uint32_t o_eq = 0, o_ne = 0, u_eq = 0, u_ne = 0;
    uint32_t rare, commun, ratio, ratio2, restant, sub;
    if (!d)
        return 1u;
    for (i = 0; i < 256u; i++)
        h[i] = 0;
    scan = (n > 0x10000u) ? 0x10000u : n;          /* 0x40478f : scan bounded has 64 Kio */
    for (i = 0; i < scan; i++) {
        uint32_t c = d[i];
        h[c]++;
        if (BCLASS1[c]) {
            textcount++;
            /* [M160] PORTE measured (run 5, 0x404993) : `ecx = textcount<<5` ; `cmp ecx,ebx(n)`
             * `jbe` otherwise output of the scan. The scan avorte some `32*textcount > n` ; `[esp+0x734]`
             * (remainder) n'is then never decremente -> `0x4047c7 jne 0x4048c2` = commit without
             * echelle = `bc` 1. C'is there porte which manquait : `mixed.bin` counts 1 094 bytes
             * of class no zero for n = 35 003 (1 094 > 1 093,84) -> bc=1 ; `hello.txt` en
             * counts 0 -> echelle -> bc=0. rule of CONTENU, not state of stream. */
            if (32u * textcount > n)
                return 1u;
        }
        if (c == 0x65u) {                          /* 'e' : single voyelle which alimente esi/edi */
            edi++;
            if (BCLASS2[prev] >= 1u)
                esi++;
            if (prev == 0x65u) e_eq++; else e_ne++;
        } else if (c == 0x61u) { if (prev == 0x61u) a_eq++; else a_ne++; }
        else if (c == 0x69u) { if (prev == 0x69u) i_eq++; else i_ne++; }
        else if (c == 0x6fu) { if (prev == 0x6fu) o_eq++; else o_ne++; }
        else if (c == 0x75u) { if (prev == 0x75u) u_eq++; else u_ne++; }
        if (i != 0u && c == 0x20u && prev == 0x20u)
            sp2sp++;
        prev = c;
    }
    A = h[0x20]; B = h[0x0a]; Cr = h[0x0d];
    for (i = 'A'; i <= 'Z'; i++) S += h[i];
    for (i = 'a'; i <= 'z'; i++) S += h[i];
    restant = n - A - B - Cr - S;                  /* n ENTIER less counters bounds */
    ratio = restant ? ((S << 6) / restant) : 0u;
    ratio2 = (n - A) ? ((sp2sp << 6) / (n - A)) : 0u;
    if (ratio <= 300u && !((n >> 6) > textcount))
        return 1u;                                 /* 0x404ad3 -> 0x4048c2 : commit unchanged */
    if (ratio >= 400u)
        sub = 4u;
    else if (ratio >= 200u)
        sub = 3u;
    else if (ratio >= 40u)
        sub = 2u;
    else if (ratio2 >= 16u)
        sub = A ? 1u : 0u;
    else
        sub = 0u;                                  /* no soustraction -> bc remainder 1 */
    if (sub == 0u)
        return 1u;
    if (a_eq > a_ne)
        return 1u;
    if (e_eq > e_ne || i_eq > i_ne || o_eq > o_ne || u_eq > u_ne)
        return 1u;
    if (!(2u * esi > edi))
        return 1u;
    rare = h['j'] + h['q'] + h['z'] + h['J'] + h['Q'] + h['Z'];
    commun = h['T'] + h['a'] + h['e'] + h['t'] + h['A'] + h['E'];
    if (rare > (commun >> 2))
        return 1u;
    return 0u;                                     /* engagement : bc = 0 */
}

/* table seed some candidates 0x43b2c2 (extracted UHARC.EXE, DISK : cf DUAL M45) */
static const uint8_t PPM_SEED[16] = {
    0, 1, 2, 3, 4, 1, 1, 2, 2, 4, 0, 0, 0, 0, 1, 0
};

/* signature of l'oracle : cost of has candidate (cls) sure there window, cut if > incumbent */
typedef uint64_t (*ppm_cost_fn)(const uint8_t *win, size_t len, uint32_t cls, uint64_t incumbent);

/* selects there class of the block by argmin-cost sure {seed}{1,2,3,4}. cls_courant = class of the
 * block previous (0 au start). returns there class selectionnee ; *out_cost = cost winner. */
uint32_t ppm_legacy_cost_select_class(const uint8_t *win, size_t len, uint32_t cls_courant,
                                      ppm_cost_fn cost_fn, uint64_t *out_cost)
{
    uint32_t cands[5];
    uint64_t costs[5];
    uint32_t seed, n, k, best;
    if (!cost_fn || len == 0) { if (out_cost) *out_cost = 0; return 0; }
    seed = PPM_SEED[cls_courant & 15];
    /* enumeration exact of legacy : {seed} then 0,1,2,3,4 (without doublon).
     * [M198 CORRECTION mesuree by M197] L'old forme n'enumerait that {seed} U {1..4} :
     * with seed != 0, the candidate 0 was ABSENT of the loop, then that there captures of the master has
     * there frontier 1 071 003 montre l'order d'writing some costs `esi = 3, 0, 1, 2, 4` (GT
     * `OUT/m197_frontier_costs.tsv`, sites 0x421cbe/0x421ce7) : 0 is well evaluates. The cas seed = 0
     * (all nos GT closes : 22/22, 15/15, 12/12 mono) is strictement inchange : [0,1,2,3,4]. */
    n = 0;
    cands[n++] = seed;
    for (k = 0; k <= 4; k++) {
        uint32_t j, dup = 0;
        for (j = 0; j < n; j++) if (cands[j] == k) { dup = 1; break; }
        if (!dup) cands[n++] = k;
    }
    best = 0;
    /* seed evaluates without elagage (incumbent 0xffffffff), then candidates vs meilleur current */
    {
        uint64_t inc = 0xffffffffull;
        /* [GATED UHA_PPM_NOPRUNE, defautOFF, M130] desactive l'elagage : indispensable for
         * dumper there suite COMPLETE (ctx,err) some 5 candidates and there to compare at the GT
         * `OUT/m41_pattern_ctxerr_freq_total_delta.tsv`. Out dump, l'elagage is faithful. */
        static int noprune = -1;
        if (noprune < 0) { const char *e = getenv("UHA_PPM_NOPRUNE"); noprune = (e && e[0] != '0') ? 1 : 0; }
        static int sh_on = -1;
        if (sh_on < 0) { const char *sh = getenv("UHA_PPM_COST_SHARED"); sh_on = (sh && sh[0] != '0') ? 1 : 0; }
        if (sh_on) {
            /* [GATED UHA_PPM_COST_SHARED, defautOFF, M125] Has SINGLE arena for the 5
             * candidates (reset au first only) : the legacy engine HERITE l'state of has
             * candidate at the other (no reset intermediaire observe). */
            ppm_cost_arena a;
            for (k = 0; k < n; k++) {
                uint64_t c = ppm_cost_gen_a(&a, win, len, cands[k], inc, k == 0);
                costs[k] = c;
                if (c < inc) { inc = c; best = k; }
            }
        } else {
            for (k = 0; k < n; k++) {
                uint64_t c = cost_fn(win, len, cands[k], noprune ? 0xffffffffull : inc);
                costs[k] = c;
                if (c < inc) { inc = c; best = k; }
            }
        }
    }
    /* [GATED UHA_PPM_COSTDBG, default-OFF, M122] marge by candidate (diagnostic). */
    { static int cd = -1; if (cd < 0) { const char *e = getenv("UHA_PPM_COSTDBG"); cd = (e && e[0] != '0') ? 1 : 0; }
      if (cd) { fprintf(stderr, "[COSTDBG] len=%zu cands=", len);
               for (k = 0; k < n; k++) fprintf(stderr, "%u:0x%llx ", cands[k], (unsigned long long)costs[k]);
               fprintf(stderr, "-> cls=%u\n", cands[best]); } }
    if (out_cost) *out_cost = costs[best];
    return cands[best];
}

/* bc emis = MSB(byte of payload of the range-coder) = archive[40]>>7 - CONFIRME by
 * M124(B) : il n'y has no emission " uniforme/2 " separee, `bc` is the first
 * symbole ordinaire of the stream (writes au curseur 1 by `0x41dba9`). The MSB n'is therefore
 * only to  OBSERVABLE : il not dit nothing of the facon whose the legacy engine SELECTS `bc`. */
int ppm_legacy_bc_from_payload(const uint8_t *payload /* = archive+40 */)
{
    return (payload[0] >> 7) & 1;
}

