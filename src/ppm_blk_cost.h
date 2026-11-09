/*
 * ppm_blk_cost.h - [M170g, ISOLAT, NO-WIRE] the scan of cost cumule `ebp` of `0x422d00`.
 *
 * Law : OUT/m170g_arenafeed.md 6 (transcription complete of `0x422d00..0x423245`)
 *       + OUT/m170e_costscan.md (geometrie of the scan, two terms LUT, arret sure depassement).
 *
 * The scan measures the cost d'encoder has block with l'arena LIVE of the class `class`, and the
 * compares has `budget` (= cost[cl] of l'stage 1). `ebp >= budget`  ->  no escape (al = 0).
 *
 * This module NOT BRANCH NOTHING : il takes has arena already nourrie (`ppm_cost_arena_load_live`)
 * and has machine d'state fournie by l'appelant (calls legacy `0x423650` / `0x4232a0`).
 */
#ifndef PPM_BLK_COST_H
#define PPM_BLK_COST_H

#include <stdint.h>
#include "ppm_legacy_cost.h"   /* ppm_cost_arena */

/* State of the scan (the 4 global that `0x422d00` sauve/restores).
 * MEASURES M170g : `last(0) = 0` and `flag(0) = 0` at each call (restore `0x423158`) ;
 * `win_idx(0)` = there position OF CUT of the block (0 / 12 558 / 34 747) and advances of 1 by iteration ;
 * `ctx_abs(0)` = `m->cls_ctx` current. */
typedef struct {
    uint32_t ctx_abs;   /* [0x4803c4] : context ABSOLU current  <-> m->cls_ctx        */
    uint8_t  last;      /* [0x48392f] : byte PREDIT (not l'byte previous) <-> m->cls_base */
    uint8_t  flag;      /* [0x483932] : flag of signe, toggles has |d|>=0x80 <-> m->cls_neg */
    uint32_t win_idx;   /* [0x4803c0] : index absolu in the stream (base = start of the block) */
} ppm_blk_state;

/* Machine d'state appelee AFTER each node (legacy `0x423650` then `0x4232a0`).
 * MAPPING MEASURES (OUT/m170g_result_port.md 2) : these two calls are already in the port, under
 * there forme `ppm_post_symbol_maintenance()` -> `cls_delta_update()` + `cls_phase_update()`
 * (`work/src/ppm_post.c`), which write `m->cls_base` (= last), `m->cls_neg` (= flag) and
 * `m->cls_ctx` (= ctx_abs). The callback doit therefore to do tourner THIS machine sure has COPIE
 * of l'state (without emission). `raw` = byte raw lu (bh), `sym` = delta consumes (bl). */
typedef void (*ppm_blk_step_fn)(void *ud, ppm_blk_state *st, uint8_t raw, uint8_t sym);

typedef struct {
    const uint8_t  *hist;        /* [0x43a21c] stream : hist[win_idx] = byte ABSOLU of the stream      */
    const uint8_t  *win;         /* block (len bytes)                                  */
    uint32_t        len;         /* edx d'input                                       */
    uint32_t        base;        /* CLS_CTXBASE[class] = 0x43b268[class]             */
    uint32_t        nctx;        /* 0x43b290[class] (nb of ctx of the class)          */
    const uint16_t *step2;       /* extra by ctx ABSOLU (m->tstep2)                    */
    /* [M170k - FIXES] The term of PRIOR of the branch cold n'is NOT constant : il equals
     * `LUT[(freq[772+class][err]<<14) / cum[772+class][0]]` (0x42242b..0x422465), and these
     * rows EVOLUENT (measured : row 775 at the decision 2 d'`image` = cum0 4144, f0 232).
     * Il n'y has therefore nothing has passer here : `ppm_cost_arena_load_live()` recopie `prior_freq` and
     * `prior_total` in l'arena and `ppm_cost_node_step()` the reads. L'affirmation previous
     * (" equals 8/2048 by construction ") n'was true qu'has `pos = 0`. */
    ppm_blk_state   st;          /* state d'input                                       */
    ppm_blk_step_fn step;        /* machine 0x423650/0x4232a0, now NULL                  */
    void           *ud;
} ppm_blk_scan_in;

typedef struct {
    uint64_t ebp;        /* cost cumule                                        */
    uint32_t niter;      /* iterations effectuees (arret anticipe possible)    */
    uint32_t ncold;      /* nodes froids (freq lue == 0)                      */
    int      overflow;   /* 1 = output by ebp > budget                        */
} ppm_blk_scan_out;

/* returns 1 always ; `out->ebp` and `out->overflow` portent the verdict.
 * L'arena `has` doit to have ete nourrie by ppm_cost_arena_load_live() BEFORE l'call
 * (0x422e1a : the feed precede the scan) and is MUTEE by there simulation (jetable). */
int ppm_blk_cost_scan(ppm_cost_arena *a, const ppm_blk_scan_in *in, uint32_t budget,
                      ppm_blk_scan_out *out);

#endif
