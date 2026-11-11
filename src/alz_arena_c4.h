/*
 * alz_arena_c4.h — Portage FIDÈLE de l'arène littérale du scoreur 0x411bb0 (UHARC 0.6b,
 * coût-littéral `acc` pilotant esi au décideur 0x412c30). Spécifications validées :
 *   §13.609/610 (identité HOT cost=LUT[(freq<<14)/total], 29948/29948) ;
 *   §13.615 (banc LU 0x405 : freq=4+16·k, BIT0=1024+16·n, pré-armage init ; poids 0x10/0x300=6) ;
 *   §13.617 (géométrie chaude = 39 lignes CONTEXTE <0x3f9, total=BIT0+d4 ; froid = ré-ancre
 *             0x405 + scan-liste = mask de présence freq[ligne argument] ; liste NULL ⟺ dx==0) ;
 *   §13.618 (trajectoire C4 from-scratch VALIDÉE 100 % : ok_freq 29944/29944, total résolu
 *             28840+1102 esc_hot+2 esc_cold, unsolved=0 ; d4 init=1, cc94 init=256 = fixpoint
 *             du PRIME commit ; commit 0x80ffa0 = pseudoC_arena_commit.c #11) ;
 *   §13.619 (coûts+acc VALIDÉS 29943/29943 : cost1 froid = LUT[(d4<<14)/(dx+d4)] store 0x811c64
 *             avant ré-ancre, absent si dx==0 ; échappement 405 du scan soustrait
 *             bench.freq[esym] seulement si freq[ligne][esym]==0 (0x811f4e) ; LUT =
 *             src/alz_score_table.inc, 16385 mots, figée après init).
 *
 * STATUT : module PUREMENT ADDITIF, NON BRANCHÉ. Aucun effet sur l'émission standard
 * (baselines DEF7049/BASE7002/GATE7015/RT garanties) tant qu'aucun site d'appel gated
 * UHA_ACCLIVE (défaut-OFF) n'est câblé dans le walker.
 *
 * DIFFÉRENCES ASSUMÉES vs legacy (à verrouiller par verrouillage lockstep du port) :
 *  - les 4 événements de la voie 0x8122bf par fichier (rescore (0x300, byte table) + re-seed
 *    0x402 poids 6) : l'appelant doit lever `special_pending` au pas suivant (cf .c) ;
 *  - les ~12 ré-chauffages live où BIT[froid][0]/freq divergent du from-scratch (cf 10 re-tirs
 *    §13.615(4), [runtime-requis]) : le module applique la LOI, pas la valeur live.
 */
#ifndef ALZ_ARENA_C4_H
#define ALZ_ARENA_C4_H

#include <stdint.h>

#define ALZ_ARENA_C4_ROWMAX   0x401u   /* lignes contexte 0x000..0x400 (classe-3 : 0x341..0x3a0) */
#define ALZ_ARENA_C4_INC      0x20u    /* incrément C4 par événement_learn (§13.609)            */
#define ALZ_ARENA_C4_BENCH_W  16u      /* poids de re-seed du banc LU 0x405 (§13.615)           */
#define ALZ_ARENA_C4_SEED402  6u       /* poids de re-seed du banc 0x402 (entrée 0x300)         */
#define ALZ_ARENA_C4_GATE     0x4000u  /* seuil de commit (BIT0+d4) (§13.609/#11)               */

/* Une ligne d'arène : freq (PERM, u16×256), bit (Fenwick/BIT, u16×256),
 * d4 (*0x4373d4 TOTAL, u16), cc94 (*0x45cc94 CREDIT, u32). Init : d4=1, cc94=256
 * (fixpoint du PRIME commit, correction C1 §13.618). */
typedef struct {
    uint16_t freq[256];
    uint16_t bit[256];
    uint16_t d4;
    uint32_t cc94;
    uint8_t  used;                 /* 0 = ligne jamais touchée (compteurs de stats) */
} alz_arena_c4_row;

typedef struct {
    alz_arena_c4_row rows[ALZ_ARENA_C4_ROWMAX];
    /* Bancs LU pré-armorqués (§13.615(2)) : freq[i]=4, bit[0]=1024. */
    alz_arena_c4_row b405;         /* banc lu 0x405 (poids 16)                     */
    alz_arena_c4_row b402;         /* banc de re-seed 0x402 (poids 6)              */
    uint8_t  special_pending;      /* 1 = le prochain learn saute le re-seed (C2)  */
    uint32_t n_cold, n_hot, n_commit, n_seed405, n_seed402;
} alz_arena_c4_t;

/* Init : lignes zéros, d4=1/cc94=256 partout ; bancs 0x402/0x405 freq=4, bit[0]=1024. */
void alz_arena_c4_init(alz_arena_c4_t *a);

/* Table de bucketing `T` du contexte classe-3 (VA live 0x4379f8, lue en 0x4103ff
 * `mov al,[eax+0x4379f8]` ; loi row §13.621 : row = 0x341 + 32·((pos%3+2)%3) +
 * T[K[pos-1]]). Quantification monotone 0..31 CAPTURÉE au runtime (dump 64×M()
 * `_scratch/acccap13/rowtab.log`, identique à la déduction par events, 0 divergence).
 * Précédent d'embed : LUT coûts `alz_score_table.inc` (§13.133/134). */
extern const uint8_t alz_arena_c4_tbucket[256];

/* marquer la voie 0x8122bf : le prochain événement est FROID mais lève le re-seed
 * (le warm-up de la ligne vient du C4, le coût froid sort du banc 0x402). */
void alz_arena_c4_mark_special(alz_arena_c4_t *a);

/* Score + learn d'un événement du flot ÉMIS (pilote = drv.clone). Renvoie le coût
 * accumulé dans acc(*0x45cc88) pour CET événement (cost2 seul, ou cost1+cost2 si
 * dx!=0 ; cf §13.619(2)). esc_flag/esc_sym = échappement courant du lecteur (#12 Q3) :
 * le port les connaît car c'est LUI qui émet l'escape. `row` = ligne contexte
 * (< 0x3f9, loi row classe-3 §13.604/605 calculée par l'appelant). */
uint32_t alz_arena_c4_event(alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym);

/* [§13.701, additif NON-BRANCHÉ] Score SEUL (lecture pure de l'état courant, AUCUNE
 * mutation : ni freq/bit/d4/cc94, ni bancs, ni special_pending, ni compteurs). Renvoie
 * le même coût que calculerait `alz_arena_c4_event` sur CET état, sans apprendre.
 * Sert la loi `dens` = scorer le coût au modèle courant à CHAQUE position (par octet)
 * tout en n'APPRENNANT qu'aux littéraux (via _event). Zéro effet sur l'émission. */
uint32_t alz_arena_c4_score(const alz_arena_c4_t *a, uint32_t row, uint32_t sym,
                            int esc_flag, uint32_t esc_sym);

/* commit 0x80ffa0 d'une ligne (exposé pour le self-test). */
void alz_arena_c4_commit(alz_arena_c4_t *a, uint32_t row);

/* Self-test : rejoue un flux TSV (rang, ctx, sym, esc_flag, esc_sym, coût_attendu)
 * et compare. Renvoie 0 si tout d'accord, sinon le nombre de divergences. */
int alz_arena_c4_replay(alz_arena_c4_t *a, const char *tsv_path);

#endif /* ALZ_ARENA_C4_H */
