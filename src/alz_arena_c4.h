/*
 * alz_arena_c4.h - faithful port of l'arena litterale of the scorer 0x411bb0 (UHARC 0.6b,
 * cost-literal `acc` pilotant esi au decider 0x412c30). Specifications validees :
 *   13.609/610 (identite HOT cost=LUT[(freq<<14)/total], 29948/29948) ;
 *   13.615 (banc LU 0x405 : freq=4+16*k, BIT0=1024+16*n, pre-armage init ; weight 0x10/0x300=6) ;
 *   13.617 (geometrie hot = 39 lines CONTEXT <0x3f9, total=BIT0+d4 ; cold = re-ancre
 *             0x405 + scan-liste = mask of presence freq[line argument] ; liste NULL  dx==0) ;
 *   13.618 (trajectoire C4 from-scratch validated 100 % : ok_freq 29944/29944, total resolu
 *             28840+1102 esc_hot+2 esc_cold, unsolved=0 ; d4 init=1, cc94 init=256 = fixpoint
 *             of the PRIME commit ; commit 0x80ffa0 = pseudoC_arena_commit.c #11) ;
 *   13.619 (costs+acc VALID 29943/29943 : cost1 cold = LUT[(d4<<14)/(dx+d4)] store 0x811c64
 *             before re-ancre, absent if dx==0 ; echappement 405 of the scan soustrait
 *             bench.freq[esym] only if freq[line][esym]==0 (0x811f4e) ; LUT =
 *             src/alz_score_table.inc, 16385 words, figee after init).
 *
 * STATUT : module PUREMENT ADDITIF, NO BRANCH. no effect on l'emission standard
 * (baselines DEF7049/BASE7002/GATE7015/RT garanties) so much qu'no site d'call gated
 * UHA_ACCLIVE (default-OFF) n'is cable in the walker.
 *
 * DIFFERENCES ASSUMEES vs legacy (has verrouiller by verrouillage lockstep of the port) :
 *  - the 4 evenements of the path 0x8122bf by file (rescore (0x300, byte table) + re-seed
 *    0x402 weight 6) : l'appelant doit lever `special_pending` au not next (cf .c) ;
 *  - the ~12 re-chauffages live now BIT[cold][0]/freq divergent of the from-scratch (cf 10 re-tirs
 *    13.615(4), [runtime-requis]) : the module applies there LAW, not there value live.
 */
#ifndef ALZ_ARENA_C4_H
#define ALZ_ARENA_C4_H

#include <stdint.h>

#define ALZ_ARENA_C4_ROWMAX   0x401u   /* lines context 0x000..0x400 (class-3 : 0x341..0x3a0) */
#define ALZ_ARENA_C4_INC      0x20u    /* increment C4 by evenement_learn (13.609)            */
#define ALZ_ARENA_C4_BENCH_W  16u      /* weight of re-seed of the banc LU 0x405 (13.615)           */
#define ALZ_ARENA_C4_SEED402  6u       /* weight of re-seed of the banc 0x402 (input 0x300)         */
#define ALZ_ARENA_C4_GATE     0x4000u  /* threshold of commit (BIT0+d4) (13.609/#11)               */

/* Has line d'arena : freq (PERM, u16*256), bit (Fenwick/BIT, u16*256),
 * d4 (*0x4373d4 TOTAL, u16), cc94 (*0x45cc94 CREDIT, u32). Init : d4=1, cc94=256
 * (fixpoint of the PRIME commit, correction C1 13.618). */
typedef struct {
    uint16_t freq[256];
    uint16_t bit[256];
    uint16_t d4;
    uint32_t cc94;
    uint8_t  used;                 /* 0 = line never touchee (counters of stats) */
} alz_arena_c4_row;

typedef struct {
    alz_arena_c4_row rows[ALZ_ARENA_C4_ROWMAX];
    /* Bancs LU pre-armorques (13.615(2)) : freq[i]=4, bit[0]=1024. */
    alz_arena_c4_row b405;         /* banc lu 0x405 (weight 16)                     */
    alz_arena_c4_row b402;         /* banc of re-seed 0x402 (weight 6)              */
    uint8_t  special_pending;      /* 1 = the next learn skips the re-seed (C2)  */
    uint32_t n_cold, n_hot, n_commit, n_seed405, n_seed402;
} alz_arena_c4_t;

/* Init : lines zeros, d4=1/cc94=256 partout ; bancs 0x402/0x405 freq=4, bit[0]=1024. */
void alz_arena_c4_init(alz_arena_c4_t *a);

/* table of bucketing `T` of the context class-3 (VA live 0x4379f8, lue en 0x4103ff
 * `mov al,[eax+0x4379f8]` ; law row 13.621 : row = 0x341 + 32*((pos%3+2)%3) +
 * T[K[pos-1]]). Quantification monotone 0..31 CAPTUREE au runtime (dump 64*M()
 * `_scratch/acccap13/rowtab.log`, identical at the deduction by events, 0 divergence).
 * previous d'embed : LUT costs `alz_score_table.inc` (13.133/134). */
extern const uint8_t alz_arena_c4_tbucket[256];

/* marquer there path 0x8122bf : the next evenement is COLD but leve the re-seed
 * (the warm-up of the line vient of the C4, the cost cold sort of the banc 0x402). */
void alz_arena_c4_mark_special(alz_arena_c4_t *a);

/* Score + learn of has evenement of the flot EMIS (pilote = drv.clone). returns the cost
 * accumule in acc(*0x45cc88) for THIS evenement (cost2 single, now cost1+cost2 if
 * dx!=0 ; cf 13.619(2)). esc_flag/esc_sym = echappement current of the lecteur (#12 Q3) :
 * the port the connait because c'is LUI which emits l'escape. `row` = line context
 * (< 0x3f9, law row class-3 13.604/605 computed by l'appelant). */
uint32_t alz_arena_c4_event(alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym);

/* [13.701, additif NO-BRANCH] Score SINGLE (reading pure of l'state current, NO
 * mutation : nor freq/bit/d4/cc94, nor bancs, nor special_pending, nor counters). returns
 * the same cost that calculerait `alz_arena_c4_event` sure THIS state, without apprendre.
 * Sert there law `dens` = scorer the cost au model current at each position (by byte)
 * all en n'APPRENNANT only to the  literals (via _event). Zero effet sure l'emission. */
uint32_t alz_arena_c4_score(const alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym);

/* commit 0x80ffa0 of has line (expose for the self-test). */
void alz_arena_c4_commit(alz_arena_c4_t *a, uint32_t row);

/* Self-test : replays has stream TSV (rank, ctx, sym, esc_flag, esc_sym, cout_attendu)
 * and compares. returns 0 if all d'match, otherwise the number of divergences. */
int alz_arena_c4_replay(alz_arena_c4_t *a, const char *tsv_path);

#endif /* ALZ_ARENA_C4_H */
