#ifndef ALZ_CM_H
#define ALZ_CM_H

#include <stdint.h>

/*
 * alz_cm - model of context (CM) delta-2D adaptatif of legacy UHARC ALZ.
 *
 * faithful port some primitives entierement reconstituees by RE :
 *   - table of deltas en ring (13.55)          : deterministe, static
 *   - rotation d'history + hash of context (13.61): produces scalaire 16
 *   - clamp some weight +/-32 (13.56)                 : descente of gradient
 *   - min-scan some accumulateurs (13.56)          : structure connue
 *   - rescale by halving 16-bit packes (13.57)   : normalisation d'arena
 *
 *  State : module AUTONOME, NO BRANCH sure the path d'emission (B3).
 *   There chain exact " row -> line d'arena -> freq -> proba -> bits " remainder has RE
 *   (13.62). This file sets the primitives verifiables contre the desassemblage.
 *   The self-test (alz_cm_selftest) validates the invariants deterministes.
 */

#define ALZ_CM_RING       4096u   /* ring some deltas : TABLE[i], index (delta<<4)&0xfff */
#define ALZ_CM_RING_HALF  2048u   /* mi-periode : distance circulaire */
#define ALZ_CM_WMIN       (-32)   /* bound low weight (13.56) */
#define ALZ_CM_WMAX       32      /* bound high weight (13.56) */
#define ALZ_CM_NHIST      4       /* slots d'history (R[0x00,04,08,0c]) */
#define ALZ_CM_NWEIGHT    5       /* weight w0..w4 (R[0x14..0x24]) */
#define ALZ_CM_NACC        11      /* accumulateurs of the min-scan (R+0x30..0x58) */
#define ALZ_CM_ADAPT_PERIOD 16    /* periodicite min-scan (counter & 0xf == 0) */
#define ALZ_CM_NCLASS      5       /* classes of context (argmin 0..4, 13.52) */
#define ALZ_CM_ARENA_BLOCK 0x200u  /* size block d'arena by class (bytes) */
#define ALZ_CM_LHIST       5       /* lengths of the chain d'histoires of the finder (13.100 : rec[0x00..0x10]) */

/* Record of context by-class - reflete the offsets of the record legacy (0x7c). */
typedef struct {
    uint32_t h[ALZ_CM_NHIST];        /* R[0x00,04,08,0c] : history (chain of differences) */
    int32_t  w[ALZ_CM_NWEIGHT];      /* R[0x14,18,1c,20,24] : weight w0..w4 bounds +/-32 */
    uint32_t base;                   /* R[0x28] : base-byte (decale <<4 in the hash) */
    int32_t  delta;                  /* R[0x2c] : delta signe current (input) */
    uint32_t acc[ALZ_CM_NACC];       /* R+0x30..0x58 : accumulateurs of TABLE */
    uint32_t counter;                /* R+0x6c : counter d'inserts (pilote /16) */
} alz_cm_record;

/*
 * Context d'learning of the finder legacy (0x415ab0, 13.100). Autonome vis-
 * has-vis d'`alz_cm_record` (which porte the hash/rotation) for not not destabiliser
 * the primitives already validees. Reflete the record global 0x44f0fc-ancre :
 *   w[0..4]   = weight rec[0x14..0x24] (clamp +/-32)
 *   acc[0..10]= 11 accumulateurs rec[0x30..0x58]
 *   hist[0..4]= chain rec[0x00..0x10] (maintenue by the selecteur/callant)
 *   v         = rec[0x28] (base = byte-0x80, order-dependant)
 *   delta     = rec[0x2c] (v - v_prev)
 *   counter   = rec[0x6c]
 */
typedef struct {
    int32_t  w[ALZ_CM_NWEIGHT];      /* w0..w4 */
    uint32_t acc[ALZ_CM_NACC];       /* 11 accumulateurs */
    uint32_t hist[ALZ_CM_LHIST];     /* chain d'histoires of the finder */
    uint32_t v;                       /* base = byte-0x80 */
    int32_t  delta;                   /* v - v_prev */
    uint32_t counter;                /* rec[0x6c] */
    uint32_t prev_dot;               /* (dot/16)&0xff : low-byte for l'err d'learning (13.100) */
    int32_t  prev_dot_full;          /* dot/16 SIGNE complete = 0x44d8d8 ; operande predicteur p3 (13.113) */
} alz_cm_learner;

/*
 * alz_cm_learn_step - has no learning of the finder, FAITHFUL 13.100 (validated
 * ring 165/165 + min-scan sure frontier). Appele AFTER that the selecteur has sets
 * the histoires (hist[]) and computes row_hash. no effect d'encoding (no-wired).
 *
 *   L->w, L->acc, L->hist, L->v, L->counter : state persistant.
 *   row_hash_byte : byte low of the dot/16 (0x44d8d8) = PREDICTION of the not.
 *   v_cur : value of context of l'byte current (order5 : byte-0x80).
 * Enchaine : err = movsbl(row_hash_byte - v_cur)<<4 ; MaJ 11 accu via ring[err  h_k] ;
 *   delta = v_cur - v ; v = v_cur ; counter++ ; if (counter & 0xf)==0 : min-scan.
 */
void alz_cm_learn_step(alz_cm_learner *L, uint32_t row_hash_byte, uint32_t v_cur);

/*
 * alz_cm_rotate_hist - rotation of the chain of 5 operandes of the dot CM legacy
 * (recent 0x44f100..0x44f10c + delta 0x44f128), validated 13.102/13.113.
 * The dot legacy (objdump 0x415778..0x4157f2) =
 *   (base<<4) + w0*delta + w1*rec0 + w2*rec1 + w3*rec2 + w4*rec3
 * with (0x415761..0x415793) there rotation EXACT :
 *   hist[0] = D                       (delta current 0x44f128 ; operand w0)
 *   hist[1] = D - hist[0]_prev        (rec0 = 2e difference 0x44f100)
 *   hist[2] = hist[1]_prev            (rec1 = shift 0x44f104)
 *   hist[3] = hist[2]_prev            (rec2 = shift 0x44f108)
 *   hist[4] = dr_ref                  (rec3 = DR[(line-ref)&127] 0x44f10c)  COUPLAGE arena
 * dr_ref is the delta of l'ring d'arena at the distance ref (lu by the selecteur
 * BEFORE the re-score current). 13.102 had modelise hist[4] by D_prev (approx.
 * valable en window cold : DR[slot]==D_prev for ref=2, pos2/3/4) ; there rule
 * EXACT is the lookup arena (source of the drifts +/-1 of the row_hash au-dela of ~72,
 * cf. 13.113). Has to call BEFORE learn_step. no effect enc.
 */
void alz_cm_rotate_hist(alz_cm_learner *L, int32_t d_cur, int32_t dr_ref);

/*
 * alz_cm_learn_byte - pass COMPOSITE of has byte, verrou GT 13.115 (rejeu cold
 * image.raw[0..83] : row_hash 83/83 + weight 84/84 contre captures BP 0x415804).
 * ORDER INTRA-line legacy epingle by there captures au moment of sets of the dot : PHASE
 * SPLIT between the path d'learning (retarde) and the path of the dot (current) :
 *   1. base current v = byte_i - 0x80 ; err = movsbl(prev_dot - v)<<4  [prev_dot =
 *      row_hash@{i-1} = dot of the NOT previous] ;
 *   2. MaJ 11 accu (ring) sure l'hist ENTRANTE (delta_{i-1}, phase RETARDEE) ;
 *   3. counter++ ; if (counter & 0xf)==0 : min-scan (argmin signe, reset 11, nudge
 *      some weight)  -> the SELECTEUR reads the weight POST-nudge (verified w change@15/31/47/79) ;
 *   4. rotation of l'hist towards the delta current  D = byte_i - byte_{i-1}  (hist[0]<-D,
 *      hist[1]<-D-D_prev) ;
 *   5. prev_dot_full = (16 signe)( (v<<4) + Sigma w_postnudge * hist_courant )  -> will be
 *      the row_hash@i lu by l'arbitre (predicteur p3) au NOT next.
 * byte_prev2 n'is more requis (there chain d'histoires porte the crans passes).
 * dr_ref = operande external of hist[4] (= DR[(line-ref)&127], couplage arena 13.113).
 * no effect encoding (no-wired).
 */
void alz_cm_learn_byte(alz_cm_learner *L, uint8_t byte_cur, uint8_t byte_prev1, uint8_t byte_prev2, int32_t dr_ref);

/* Init of the table of deltas en ring (13.55) :
 *   TABLE[i] = (i < 2048) ? i : (4096 - i)  - distance circulaire sure ring 4096. */
void alz_cm_init_table(uint16_t table[ALZ_CM_RING]);

/* Index d'ring for has delta (13.55) : (delta<<4) & 0xfff. */
static inline uint32_t alz_cm_ring_index(int32_t delta)
{
    return ((uint32_t)delta << 4) & 0xfffu;
}

/* value of l'ring (13.55/13.100, CONFIRMEE live) : vague triangulaire
 *   ring[i] = (i < 2048) ? i : (4096 - i)   - no signee (0..2048).
 * The finder indexe by (err  h_k) & 0xfff (err/h already <<4). */
static inline uint32_t alz_cm_ring_value(uint32_t idx)
{
    idx &= 0xfffu;
    return (idx < ALZ_CM_RING_HALF) ? idx : (ALZ_CM_RING - idx);
}

/* Rotation d'history + sets of the delta current, PRECEDANT the hash (13.61) :
 *   h2=h1 ; h1=delta - h0 ; h3=h2_old ; h0=delta ; rec->base=base_octet ; rec->delta=delta. */
void alz_cm_advance(alz_cm_record *rec, uint32_t base_octet, int32_t delta);

/* Hash context->line faithful (13.61). returns there line = (dot-product)  16
 * (division signee arrondie : edx=eax>>0x1f ; edx<<=4 ; sbb ; sar 4).
 *   row = ((base<<4) + w0*delta + w1*h1 + w2*h2 + w3*h3 + w4*w4glob) / 16.
 * w4glob = operande of the 5e term (global legacy [0x44d4c4] ; role 13.62 en attente). */
uint32_t alz_cm_hash(const alz_cm_record *rec, uint32_t w4glob);

/* Clamp of has weight in [ALZ_CM_WMIN, ALZ_CM_WMAX] (13.56). */
int32_t alz_cm_clamp_w(int32_t w);

/* Min-scan some accumulateurs (13.56) : returns l'index of the smaller, the resets has
 * zero, and applies the nudge +/-1 clampe au weight correspondant (descente of gradient ;
 * pair -> -1, impair -> +1).  There correspondance exact index-accumulateur -> weight is
 * micro-restante (13.62) : here mapping provisoire w[idx % NWEIGHT], has to validate.
 * returns l'index of the minimum (0..NACC-1) now -1 if no. */
int alz_cm_minscan_nudge(alz_cm_record *rec);

/* Rescale by halving of counters 16-bit packes (13.57) : for each DWORD,
 *   v &= 0xfffefffe ; v >>= 1   (moitiene the two demi-counters without debordement).
 * Opere sure n DWORDs (has arena / has block of class). */
void alz_cm_rescale_halving(uint32_t *arena, uint32_t ndwords);

/* Self-test deterministe some primitives. returns 0 = OK, otherwise nb d'failures.
 * N'has no effect on l'encoding ; but sert of porte d'input of validation B1. */
int alz_cm_selftest(void);

/* ===================================================================
 * arena of score multi-candidates (finder 0x415cbc..0x415dd7) - validated
 * bit-exact 13.108 (ref 70/70, b8 70/70, cost[2..7] 32/32). No-wired.
 *
 * model (100% delta-based ; there table of frequencies d'arena 0x4373d0
 * n'between NOT in ref/b8/cost) :
 *   - dr[line&127] = delta_line (delta_i = byte_i - byte_{i-1}, byte_{-1}=0x80) ;
 *   - there loop n'is executee that when there PORTE is ouverte (cascade of
 *     classes : mask = tbl[0x437af8][idx] with idx=[0x44d4b0] ; idx=4 -> mask 7
 *     -> input when (line & 7)==0). The pilotage of idx is outside of this module
 *     (d8d_arbitre) : here l'appelant fournit `entered`.
 *   - at each input : ref=b8=2, edi=0xffff, then for eax in [2,124) :
 *       cn = ring(dr[line-r] - dr[line-r-eax])  for r=0,1,2   (index &0xfff NU)
 *       cost[eax] = (13*cost[eax] >> 4) + cn                    (cn NO divise)
 *       ref = argmin cost (strict <) ; b8 = argmin cn (strict <).
 *   - gele between inputs (ref/b8/cost preserve there last execution).
 * ref nourrit hist[4] = dr[(line-ref)&127] ; b8 sert of relrow (ctx arena).
 */
#define ALZ_ARENA_DRING 128u   /* ring deltas (0x44d6cc), index &127 */
#define ALZ_ARENA_NCOST 125u   /* table costs (0x44d4cc), creneaux 2..123 */
#define ALZ_ARENA_EAX0    2u   /* first candidate (0x415cc1 esi=2) */
#define ALZ_ARENA_EAXN  124u   /* bound exclusive (0x415dd4 cmp eax,0x7c) */

typedef struct {
    uint32_t dr[ALZ_ARENA_DRING];   /* dr[line&127] = delta signe (dword) */
    uint32_t cost[ALZ_ARENA_NCOST]; /* costs EMA by offset candidate */
    uint32_t ref;                    /* argmin cost  (0x44d4b4) */
    uint32_t b8;                     /* argmin cn raw (0x44d4b8) = relrow */
    uint32_t line;                   /* index absolu   (0x45dc9c) */
} alz_arena;

void alz_arena_init(alz_arena *A);

/* Has byte : sets the delta current in l'ring, and if `entered` execute there
 * loop of score (EMA + double argmin). byte_prev = byte previous (0x80 virtuel
 * for i=0). no effect encoding (no-wired). */
void alz_arena_step(alz_arena *A, uint8_t byte_cur, uint8_t byte_prev, int entered);

/* ===================================================================
 * Arbitre of classes (finder 0x415ddd..0x415ead) - validated 13.109.
 * No-wired. 6 classes en competition ; each class c tient has window
 * glissante (256) some buckets d'error of son predicteur ; idx = argmin
 * some totaux. This idx (=[0x44d4b0]) pilote the mask d'input d'arena
 * (tbl 0x437af8[idx]) and there class of the model of frequencies.
 *   at each position : for c in [0,6) :
 *     slot  = line & 0xff
 *     tot[c] -= ring[c][slot]              (eviction ; 0 en 1re visite)
 *     b      = bucket[ diff[c] & 0x1ff ]   (table 0x437b10, 512, tente symetrique)
 *     ring[c][slot] = b ;  tot[c] += b
 *   idx = argmin_c tot[c]  (strict <, first-min gagne ; init idx=0).
 * The 6 stream `diff` viennent some predicteurs of context (0x44d8cc..0x44d8e0) :
 * outside of this module (l'appelant the fournit). validation : sure the 6 diff
 * captures image.raw[0..69], idx == GT 70/70 ; 0/420 conflit sure bucket.
 */
#define ALZ_ARB_NCLASS 6u
#define ALZ_ARB_RING   256u
typedef struct {
    uint32_t ring[ALZ_ARB_NCLASS][ALZ_ARB_RING]; /* buckets by class (window 256) */
    uint32_t total[ALZ_ARB_NCLASS];              /* sum glissante (0x44dce4 + c*0x404) */
    uint32_t idx;                                /* class winning (0x44d4b0) */
    uint32_t line;
} alz_arb;

void alz_arb_init(alz_arb *R);

/* Has position : maj some 6 totaux (window 256) then choice idx=argmin.
 * `diff[c]` = error of the predicteur of class c (reel - pred_c). */
void alz_arb_step(alz_arb *R, const int32_t diff[ALZ_ARB_NCLASS]);

/* Assemble the 6 `diff` en byte-only then calls alz_arb_step.
 * Predicteurs decodes and valid 13.110 (diffs 70/70, idx 70/70) :
 *   p0=0 ; p1=base_{i-1} ; p2=2*base_{i-1}-base_{i-2} (extrapolation) ;
 *   p3=row_hash CM (dot/16, between external) ; p4=dr_ref=DR[(line-ref_prev)&127] ;
 *   p5=dr_b8=DR[(line-b8_prev)&127].
 * reel = base for cin{0..3}, delta for cin{4,5}. base=byte-0x80.
 * `dr_ref`/`dr_b8` viennent of l'ring deltas of l'arena (Has->dr) with the
 * ref/b8 of the line previous (phase 1-en-retard, cf. 13.105). */
void alz_arb_predict(alz_arb *R, int32_t base_i, int32_t base_prev, int32_t base_prev2,
                     int32_t delta_i, int32_t dr_ref, int32_t dr_b8, int32_t row_hash);

#endif /* ALZ_CM_H */
