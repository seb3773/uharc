#ifndef ALZ_BLOCK_H
#define ALZ_BLOCK_H

#include <stdint.h>
#include "alz_arena2d.h"

/*
 * alz_block - layer (has) BLOCK of the scorer ALZ legacy UHARC 0.6b : containers MULTI-
 * categories + geometrie static + transaction load/score/restore + argmin of cost
 * cumule by class. faithful port some functions RE :
 *   - driver argmin by block 0x413ea0 (loop classes 0x413fb6..0x414015) ;
 *   - scorer of category 0x414630 (keeps category active 0x41469e/0x4146a6,
 *     fallback category 0 0x4147b7, commit 0x41437d, restore 0x4147be) ;
 *   - geometrie by category : tables static DGROUP [0x437884]/[0x4378ac]/
 *     [0x43785c]/[0x4378d4] (off file = VA - 0x402000) - extracted byte-for-
 *     byte of the binary (13.47, 13.120).
 *
 * The true gap of the +47 (cf. 13.49) = the model is multi-category (~10 arenas)
 * evaluated at the block level, whereas our byte-model previously had only one category. This module
 * puts in place the verified containers and geometry; exact cost recurrence
 * remains for future refinement - the class score here is a non-emissive probe.
 *
 * STATUS: Gated, non-wired (no effect on standard encoding). Self-test structure
 * via env UHA_BLOCKTEST.
 */

#define ALZ_BLOCK_NCAT   10u   /* categories idx 0..9 (arenas 0x000,0x301..0x3f4)      */
#define ALZ_BLOCK_NCLASS  5u   /* scored classes at block input 0..4 (13.119)          */

/* --- Static category geometry (extracted from binary, off = VA-0x402000) ----------- */
/* [0x437884] arena base by category (idx0=0 -> fallback category 0). */
extern const uint16_t alz_block_arena[ALZ_BLOCK_NCAT];
/* [0x4378ac] tableA : line/size parameter (shift <<9 for 2D slice offset). */
extern const uint16_t alz_block_tblA[ALZ_BLOCK_NCAT];
/* [0x43785c] tableC : relative counts/lines by category. */
extern const uint8_t  alz_block_tblC[ALZ_BLOCK_NCAT];
/* [0x4378d4] escape byte by class (index = class/category, 0..19 useful). */
extern const uint8_t  alz_block_escape[20];

/*
 * Block state container. Allocated on heap (each alz_arena2d_t ~264 KB; NCAT models
 * live + NCAT snapshots => dynamic allocation required).
 */
typedef struct {
    alz_arena2d_t *model;      /* [NCAT] 2D live models (self-trained in place)     */
    alz_arena2d_t *snapshot;   /* [NCAT] snapshots for transactional restore         */
    uint32_t       active_cat; /* [0x45ecc0] active category (held by scorer)        */
    uint8_t        flag_snap;  /* [0x45ecc8] snapshot flag (1 = complete restore)    */
} alz_block_t;

/* Creates/destroys (calloc arena tables, zero-fill). Returns NULL if OOM. */
alz_block_t *alz_block_create(uint16_t default_inc);
void         alz_block_destroy(alz_block_t *b);

/* --- Transaction load/score/restore (13.120 item 5) -------------------------------- */
/* snapshot[cat] <- model[cat]  (saves state before self-training scoring). */
void alz_block_save(alz_block_t *b, uint32_t cat);
/* model[cat] <- snapshot[cat]  (restores: each category is scored independently). */
void alz_block_restore(alz_block_t *b, uint32_t cat);

/* Commit of active category (0x41437d) : sets active_cat + flag according to the path. */
void alz_block_commit_cat(alz_block_t *b, uint32_t cat, uint8_t snap_flag);

/*
 * Probe of cumulative cost of a category on window [win, win+len): accumulation
 * of delta-2D cost by position via live arena (in-place self-training).
 *  STUB - exact correspondence (relrow, delta) <-> legacy (0x415444) and population
 * of positional cost table 0x45cb60[]. Writes to *out_cost if non-NULL. Non-emissive.
 */
uint64_t alz_block_score_class_stub(alz_block_t *b, uint32_t cat,
                                    const uint8_t *win, uint32_t len,
                                    uint64_t *out_cost);

/*
 * Argmin of cost cumule sure the classes [0, nclass) (13.119 item 2) : for each
 * class, restore -> score (stub) -> cost ; keeps the minimum ; commit some costs
 * positionnels of the winner. returns l'index of class winning (<nclass) now -1 if
 * len==0. Fills costs[] (nclass inputs) if no NULL.
 */
int alz_block_argmin(alz_block_t *b, const uint8_t *win, uint32_t len,
                     uint32_t nclass, uint64_t *costs);

/* Self-test : geometrie == constantes extracted ; save/restore idempotent ; argmin
 * returns there class of cost minimal. returns 0 if OK, otherwise nb d'failures. */
int alz_block_selftest(void);

#endif /* ALZ_BLOCK_H */
