/*
 * alz_parse_score.h - faithful port of the scorer of PARSE ALZ legacy (conductor
 * of block 0x413ea0/0x413f7f + category 0x414630). Brique a5-d3, GATED, NO-WIRED.
 *
 * Reproduces from-scratch, for has class of context `cls` (0..4) and has range
 * d'bytes, there sum cumulative `Sigma_cls` some costs of the model delta-2D auto-entraine
 * (machine ctx 13.132 + arena 2D alz_arena2d + double term COLD 13.139/140),
 * l'argmin some 5 classes (winning = cls3 sure image.raw bloc1), and there porte budget
 * consommee by the selecteur of parse legacy `0x414017`.
 *
 * Contrat validated (UHARC_RE_REPORT.md 13.137..13.141 a5-d CLOSED, 13.210 ;
 * reference Python _scratch/a5d3_scorer.py) :
 *   image.raw -m3, bloc1 (n=12544) : Sigma_cls0=0x086c23ec, Sigma_cls1=0x04a50d90,
 *   Sigma_cls2=0x04a521c4, Sigma_cls3=0x046a185c (WINNING), Sigma_cls4=0x046a4476 (delta=0).
 *   cls2/cls4 abort tot (running > meilleur-in) ; argmin => cls3.
 *   running[pos] = Sigma costs[0..pos-1] (BEFORE add) reproduces
 *   research/gt_scorer/0x414910_allpos_block1.log sure 12544/12544 positions.
 *
 * Auto-tests gated in uha_c : UHA_PARSETEST (selftest from-plain bloc1),
 * UHA_PARSEMULTI (6 blocks, init COLD), UHA_PARSEMULTI2 (6 blocks, persistance
 * arena+machine). There greffe in there decision READS-vs-match is a5-e.
 */
#ifndef ALZ_PARSE_SCORE_H
#define ALZ_PARSE_SCORE_H

#include <stdint.h>
#include "alz_arena2d.h"

#define ALZ_PS_NCLASS   5u          /* classes of context scorees (0..4)          */
#define ALZ_PS_COLD0    64u         /* 1er term of the double term COLD (LUT[64])   */

/* Machine ctx : fills out[0..n) with ctx=(row<<8)|delta for there class `cls`
 * sure data[0..n) (path order-2 for cls0, delta-2D with ebx/flag/ebp otherwise). */
void alz_ps_gen_ctxs(uint32_t cls, const uint8_t *data, uint32_t n, uint32_t *out);

/* [a5-e briquet 1] Not unique of machine, STATE mm[3]={ebx,flag,ebp} threade at the
 * main (mirror ps_ctx_step ; cls0 ignores mm). returns (ligne_avant<<8)|delta. */
uint32_t alz_ps_ctx_step_run(uint32_t cls, const uint8_t *g, uint32_t abs, uint32_t *mm);

/* [GATED UHA_CM_WIRE, 13.798] Moteur CM persistant incremental for l'arena LIVE
 * (acclive->alz_arena_c4). reset(sec) sets the start of section (registres+engine);
 * symrow(g,pos,row_base,&row_abs,&sym) advances rc-dense up to pos and rend there row
 * absolue (row_base+aff) and the sym dir-flippe faithful. Return 0 OK, <0 if no init. */
void alz_ps_cmlive_reset(uint32_t sec_start);
int  alz_ps_cmlive_symrow(const uint8_t *g, uint32_t pos, uint32_t row_base,
                          uint32_t *row_abs, uint32_t *sym_out);
int  alz_ps_cmlive_ctxrow(const uint8_t *g, uint32_t pos, uint32_t *row_out,
                          uint32_t *sym_out);

/* [GATED UHA_CM_EMCARRY, default-OFF, 13.896] Crochet of the carry MASTER d'emission
 * `M[block+1] = f(emission block)` (law has fournir by M13). Inerte as long as there law
 * (line ctx live + commit/rescale `0x40ffa0`) n'is not branchee -> zero effet. */
int alz_ps_emission_master_carry(const uint8_t *g, uint32_t base, uint32_t len,
                                 uint32_t *out_dens);

/* [a5-e briquet 1] Scan of couverture 0x415444 : as ps_ctx_step cls3 but with
 * delta FOURNI by l'appelant (delta=plain[q]-plain[q-dist] of the match), there machine
 * (line/flag/ebp) avancant sure THIS delta-there (mirror exact of the scan legacy). */
uint32_t alz_ps_ctx_scan3(const uint8_t *g, uint32_t abs, uint32_t *mm, uint32_t delta);

/* Sigma_cls from-scratch (arena initialisee has cold) sure data[0..n).
 *   default_inc : inc of promotion by line (32 en pratique) ;
 *   cold_first  : 1er term of the cost COLD (ALZ_PS_COLD0) ;
 *   best_in     : if != NULL, abandon precoce as soon as acc > *best_in (mirror 0x4149c2) ;
 *   percost     : if != NULL, y writes the cost of each position ;
 *   pnpos       : if != NULL, nb of positions effectivement scorees (abandon inclus).
 * returns the Sigma final (accumulation 32 bits). */
uint32_t alz_ps_class_sigma(uint32_t cls, const uint8_t *data, uint32_t n,
                            uint32_t default_inc, uint32_t cold_first,
                            const uint32_t *best_in,
                            uint32_t *percost, uint32_t *pnpos);

/* Argmin some 5 classes from-scratch sure data[0..n). if sigma_out != NULL (size
 * ALZ_PS_NCLASS), y writes the Sigma of each class. returns there class winning. */
uint32_t alz_ps_block_argmin(const uint8_t *data, uint32_t n,
                             uint32_t default_inc, uint32_t cold_first,
                             uint32_t *sigma_out);

/* --- path PERSISTANT (a5.1 it2) : machine ctx + arena threadees cross-blocks. --- */
typedef struct {
    alz_arena2d_t *arena;   /* arena allouee at the 1re input, reutilisee ensuite  */
    uint32_t       ebx;     /* state machine ctx (row current)                    */
    uint32_t       flag;    /* signe of the delta                                     */
    uint32_t       ebp;     /* counter of position absolu                        */
} alz_ps_carry_t;

/* As alz_ps_class_sigma but reads/writes l'state threade `st`, sure g[base..base+n). */
uint32_t alz_ps_class_sigma_carry(alz_ps_carry_t *st, uint32_t cls,
                                  const uint8_t *g, uint32_t base, uint32_t n,
                                  uint32_t default_inc, uint32_t cold_first,
                                  const uint32_t *best_in,
                                  uint32_t *percost, uint32_t *pnpos);

/* Argmin persistant : there class `seed_cls` is scoree en first (never abandonnee),
 * the others en order croissant with abandon precoce contre the meilleur current.
 * sigma_out/npos_out optionnels (size ALZ_PS_NCLASS). returns there winning. */
uint32_t alz_ps_block_argmin_carry(alz_ps_carry_t *st, uint32_t seed_cls,
                                   const uint8_t *g, uint32_t base, uint32_t n,
                                   uint32_t default_inc, uint32_t cold_first,
                                   uint32_t *sigma_out, uint32_t *npos_out);

/* Frees the arenas allouees of has table of ALZ_PS_NCLASS states carry. */
void alz_ps_carry_free(alz_ps_carry_t *st);

/* [cost-literal-live SNAPSHOT dens] Reproduces there granularity SNAPSHOT (MULTI3/it3) :
 * machine ctx threadee by class + snapshot advances sure the stream of there class
 * WINNING (argmin) by block, and writes in out[base..base+len) the cost BY
 * position of this winning (cost d'arena of PARSE position-indexe passif faithful
 * to legacy, +/-0,4 % under oracle). Pur (buffers local). returns 0 OK, <0 error. */
int alz_ps_snapshot_percost(const uint8_t *g, uint32_t usize,
                            const uint32_t *blkpos, const uint32_t *blklen,
                            int nblk, uint32_t *out);

/* [13.729 GATED UHA_PERPOS] Producteur dens per-position argmin (legacy selects
 * there class by position, argmin 5 classes 0x413ea0, not by block). Has arena global
 * continue + machines ctx threadees ; at each position, argmin some 5 costs of class
 * in l'arena, dens=min, then learning of the ctx of the winner. learning DENSE
 * (all positions) en 1 variante. Pur (buffers local). 0 OK, <0 error. */
int alz_ps_perpos_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, uint32_t *out);

/* [13.722 GATED UHA_CLASSPASS] Producteur dens FAITHFUL : Has arena SHARED
 * monotone, 5 passes of class/block (order 0,1,2,3,4 then 3,0,1,2,4), each
 * pass score+learns (promo 32, rescale 0x4000) ; `out` = output of the pass
 * cls3 (snapshot lu by the decider). Machine ctx re-amorcee by pass.
 * Pur, buffers local. returns 0 OK, <0 error. */
int alz_ps_classpass_percost(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, uint32_t *out);

/* [GATED UHA_SNAPWALK, validation reading-single] Producteur dens faithful au model
 * TWO-ARENAS (snapshot persiste advances SPARSE sure the positions-literal emises has
 * inc=16 ; dens = scorer dense inc=32 sure copie live of the snapshot, stream cls3).
 * is_lit[abs]=1 if there position is has literal emis. returns 0 OK, <0 error. */
int alz_ps_snapshot_percost_sparse(const uint8_t *g, uint32_t usize,
                                   const uint32_t *blkpos, const uint32_t *blklen,
                                   int nblk, const uint8_t *is_lit, uint32_t *out);

/* [13.723 GATED UHA_EMIPROD] emission-walk-producer : master advances by LITERALS
 * EMIS (sparse, chain cls3 relative-block), then by block snapshot(master)->working
 * + scan dense intra-block for to emit the `dens` fige. is_lit[abs]=1 if literal
 * emis. Pur, buffers local. 0 OK, <0 error. */
int alz_ps_emiprod_percost(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, const uint8_t *is_lit, uint32_t *out);

/* [ARENA_TASK16, GATED default-OFF] producteur master faithful multi3 (snap persistant
 * advances by the stream dense of the class WINNING, reload live:=snap/block, ps_score_ctxs
 * promo=32 + rescale @0x4000). Writes `out` that for base>=from (overlay block>=1).
 * returns 0 OK, <0 error. */
int alz_ps_livewalk_master(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, uint32_t from, uint32_t *out);

/* [ARENA_TASK16 - MEASURES] master " literalcarry " : carry ps_ctx_step(3) + learn ONLY
 * to the emissions of literals (gele during the matchs). Digite tree/counter/hit rows 68/37
 * by block sure stderr (vs GT). N'writes NOT out. 0 OK. */
int alz_ps_livewalk_litcarry(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, uint32_t *out_stats);

/* [ARENA_TASK16, GATED default-OFF] master d'emission indexe by row_hash_cm (0x44d8d8).
 * arena P separee learned to the literals of the bloc0 via the moteur CM ; fingerprint rows 37/68
 * if UHA_LIVEWALK_STATS ; if out!=NULL, reload W:=P + score dense gen_ctxs(3) sure block>=from. */
int alz_ps_livewalk_cm(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                       uint32_t from, uint32_t *out);

/* [ARENA_TASK16/17, GATED default-OFF] producteur double-buffer P(PERM persist)/H(HOT reload/block) ;
 * SCORAGE dense gen_ctxs(3)->cost overlay block>=from ; EMISSION-LEARN of P = not d'injection #17
 * (stub baseline = literals). returns 0. */
int alz_ps_livewalk_dual(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                         uint32_t from, uint32_t *out);

/* Self-test from-plain image.raw bloc1 : Sigma_cls == oracles + argmin cls3. 0 if OK. */
int alz_parse_score_selftest(void);

/* Multitest 6 blocks, init COLD (hyp. zero no-persistance). 0 if OK. */
int alz_parse_score_multitest(const char *path);

/* Multitest 6 blocks, persistance arena+machine. 0 if OK. */
int alz_parse_score_multitest2(const char *path);

/* Multitest 6 blocks, modelisation SNAPSHOT (copie by class, snap advances by winner). 0 if OK. */
int alz_parse_score_multitest3(const char *path);

/* [TEST hook] active/desactive there correction of phase cls3 of the harness offline. */
void alz_ps_set_phasefix(int v);

#endif /* ALZ_PARSE_SCORE_H */
