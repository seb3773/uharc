/*
 * alz_parse_score.h — portage fidèle du scoreur de PARSE ALZ legacy (conductor
 * de bloc 0x413ea0/0x413f7f + catégorie 0x414630). Brique a5-d3, GATED, NON-WIRED.
 *
 * Reproduit from-scratch, pour une classe de contexte `cls` (0..4) et une plage
 * d'octets, la somme cumulative `Σ_cls` des coûts du modèle delta-2D auto-entraîné
 * (machine ctx §13.132 + arène 2D alz_arena2d + double terme FROID §13.139/140),
 * l'argmin des 5 classes (gagnante = cls3 sur image.raw bloc1), et la porte budget
 * consommée par le sélecteur de parse legacy `0x414017`.
 *
 * Contrat validé (UHARC_RE_REPORT.md §13.137..§13.141 a5-d CLOSED, §13.210 ;
 * référence Python _scratch/a5d3_scorer.py) :
 *   image.raw -m3, bloc1 (n=12544) : Σ_cls0=0x086c23ec, Σ_cls1=0x04a50d90,
 *   Σ_cls2=0x04a521c4, Σ_cls3=0x046a185c (GAGNANTE), Σ_cls4=0x046a4476 (delta=0).
 *   cls2/cls4 abandonnent tôt (running > meilleur-in) ; argmin ⟹ cls3.
 *   running[pos] = Σ coûts[0..pos-1] (AVANT add) reproduit
 *   research/gt_scorer/0x414910_allpos_block1.log sur 12544/12544 positions.
 *
 * Auto-tests gated dans uha_c : UHA_PARSETEST (selftest from-plain bloc1),
 * UHA_PARSEMULTI (6 blocs, init COLD), UHA_PARSEMULTI2 (6 blocs, persistance
 * arène+machine). La greffe dans la décision LIT-vs-match est a5-e.
 */
#ifndef ALZ_PARSE_SCORE_H
#define ALZ_PARSE_SCORE_H

#include <stdint.h>
#include "alz_arena2d.h"

#define ALZ_PS_NCLASS   5u          /* classes de contexte scorées (0..4)          */
#define ALZ_PS_COLD0    64u         /* 1er terme du double terme FROID (LUT[64])   */

/* Machine ctx : remplit out[0..n) avec ctx=(row<<8)|delta pour la classe `cls`
 * sur data[0..n) (voie ordre-2 pour cls0, delta-2D avec ebx/flag/ebp sinon). */
void alz_ps_gen_ctxs(uint32_t cls, const uint8_t *data, uint32_t n, uint32_t *out);

/* [GATED UHA_A3_ESCFEED, lane ALZ -m3] Modèle d'escape cls3 (ligne 0x402+cls, registre
 * m9 ligne 1029) : freq init 4, total init 1024, +16 par événement froid du scan, appliqué
 * aux frontières de bloc (table FIGÉE dans le bloc : m9, 29/29 Fenwick = 2528).
 * Renvoie le PREMIER terme du coût froid LUT[FLOOR(f<<14/tot)] et compte l'événement ;
 * renvoie 0 si la gate est absente (comportement historique = terme unique). */
uint32_t alz_ps_esc_coldcost(uint32_t sym);
void     alz_ps_esc_boundary_pub(void);

/* [GATED UHA_A3_ESCBRANCH, défaut-OFF, lane ALZ -m3] canal d'ÉCRITURE du maître :
 * si non-NULL avant un appel gen_ctxs(3), reçoit `(ligne << 8) | cellule` que le maître
 * écrit au journal `m18` (ligne d'ESCAPE 16+32·phase quand la branche 0x41031f tire).
 * `out[]` reste la paire ordinaire du scan/dens (m9). NULL = aucun effet. */
extern uint32_t *alz_ps_escwr;

/* [GATED UHA_A3_CTXCLASS_AUTO, défaut-OFF, lane ALZ -m3, tour 120] classe GAGNANTE par
 * bloc exportée par `alz_ps_snapshot_percost` (argmin de Σ sur les classes 0..4 avec copie
 * d'état snapshot→live, 0x413fce‑0x414008). Permet au producteur chaud de dérouler la
 * machine de la gagnante sans que l'opérateur la fournisse (`UHA_LIVEWALK_CTXCLASS`).
 * Réécrit à CHAQUE appel (cache de processus remis à zéro) ; `_n` = nombre de blocs. */
#define ALZ_PS_SNAPWIN_MAX 64
extern int alz_ps_snapwin_blk[ALZ_PS_SNAPWIN_MAX];
extern int alz_ps_snapwin_n;

/* [a5-e briquet 1] Pas unique de machine, ETAT mm[3]={ebx,flag,ebp} threadé à la
 * main (miroir ps_ctx_step ; cls0 ignore mm). Retourne (ligne_avant<<8)|delta. */
uint32_t alz_ps_ctx_step_run(uint32_t cls, const uint8_t *g, uint32_t abs, uint32_t *mm);

/* [GATED UHA_CM_WIRE, §13.798] Moteur CM persistant incrémental pour l'arène LIVE
 * (acclive→alz_arena_c4). reset(sec) pose le début de section (registres+engine);
 * symrow(g,pos,row_base,&row_abs,&sym) avance rc-dense jusqu'à pos et rend la row
 * absolue (row_base+aff) et le sym dir-flippé fidèles. Retour 0 OK, <0 si non init. */
void alz_ps_cmlive_reset(uint32_t sec_start);
int  alz_ps_cmlive_symrow(const uint8_t *g, uint32_t pos, uint32_t row_base,
                          uint32_t *row_abs, uint32_t *sym_out);
int  alz_ps_cmlive_ctxrow(const uint8_t *g, uint32_t pos, uint32_t *row_out,
                          uint32_t *sym_out);

/* [GATED UHA_CM_EMCARRY, défaut-OFF, §13.896] Crochet du carry MAÎTRE d'émission
 * `M[bloc+1] = f(émission bloc)` (loi à fournir par M13). Inerte tant que la loi
 * (ligne ctx live + commit/rescale `0x40ffa0`) n'est pas branchée → zéro effet. */
int alz_ps_emission_master_carry(const uint8_t *g, uint32_t base, uint32_t len,
                                 uint32_t *out_dens);

/* [a5-e briquet 1] Scan de couverture 0x415444 : comme ps_ctx_step cls3 mais avec
 * delta FOURNI par l'appelant (delta=plain[q]-plain[q-dist] du match), la machine
 * (ligne/flag/ebp) avançant sur CE delta-là (miroir exact du scan legacy). */
uint32_t alz_ps_ctx_scan3(const uint8_t *g, uint32_t abs, uint32_t *mm, uint32_t delta);

/* Σ_cls from-scratch (arène initialisée à froid) sur data[0..n).
 *   default_inc : inc de promotion par ligne (32 en pratique) ;
 *   cold_first  : 1er terme du coût FROID (ALZ_PS_COLD0) ;
 *   best_in     : si != NULL, abandon précoce dès que acc > *best_in (miroir 0x4149c2) ;
 *   percost     : si != NULL, y écrit le coût de chaque position ;
 *   pnpos       : si != NULL, nb de positions effectivement scorées (abandon inclus).
 * Retourne le Σ final (accumulation 32 bits). */
uint32_t alz_ps_class_sigma(uint32_t cls, const uint8_t *data, uint32_t n,
                            uint32_t default_inc, uint32_t cold_first,
                            const uint32_t *best_in,
                            uint32_t *percost, uint32_t *pnpos);

/* Argmin des 5 classes from-scratch sur data[0..n). Si sigma_out != NULL (taille
 * ALZ_PS_NCLASS), y écrit le Σ de chaque classe. Retourne la classe gagnante. */
uint32_t alz_ps_block_argmin(const uint8_t *data, uint32_t n,
                             uint32_t default_inc, uint32_t cold_first,
                             uint32_t *sigma_out);

/* --- Chemin PERSISTANT (a5.1 it2) : machine ctx + arène threadées cross-blocs. --- */
typedef struct {
    alz_arena2d_t *arena;   /* arène allouée à la 1re entrée, réutilisée ensuite  */
    uint32_t       ebx;     /* état machine ctx (row courante)                    */
    uint32_t       flag;    /* signe du delta                                     */
    uint32_t       ebp;     /* compteur de position absolu                        */
} alz_ps_carry_t;

/* Comme alz_ps_class_sigma mais lit/écrit l'état threadé `st`, sur g[base..base+n). */
uint32_t alz_ps_class_sigma_carry(alz_ps_carry_t *st, uint32_t cls,
                                  const uint8_t *g, uint32_t base, uint32_t n,
                                  uint32_t default_inc, uint32_t cold_first,
                                  const uint32_t *best_in,
                                  uint32_t *percost, uint32_t *pnpos);

/* Argmin persistant : la classe `seed_cls` est scorée en premier (jamais abandonnée),
 * les autres en ordre croissant avec abandon précoce contre le meilleur courant.
 * sigma_out/npos_out optionnels (taille ALZ_PS_NCLASS). Retourne la gagnante. */
uint32_t alz_ps_block_argmin_carry(alz_ps_carry_t *st, uint32_t seed_cls,
                                   const uint8_t *g, uint32_t base, uint32_t n,
                                   uint32_t default_inc, uint32_t cold_first,
                                   uint32_t *sigma_out, uint32_t *npos_out);

/* Libère les arènes allouées d'un tableau de ALZ_PS_NCLASS états carry. */
void alz_ps_carry_free(alz_ps_carry_t *st);

/* [cost-literal-live SNAPSHOT dens] Reproduit la granularity SNAPSHOT (MULTI3/it3) :
 * machine ctx threadée par classe + snapshot avancé sur le flux de la classe
 * GAGNANTE (argmin) par bloc, et écrit dans out[base..base+len) le COÛT PAR
 * POSITION de cette gagnante (coût d'arène de PARSE position-indexé passif fidèle
 * au legacy, ±0,4 % sous oracle). Pur (buffers locaux). Retourne 0 OK, <0 erreur. */
int alz_ps_snapshot_percost(const uint8_t *g, uint32_t usize,
                            const uint32_t *blkpos, const uint32_t *blklen,
                            int nblk, uint32_t *out);

/* [§13.729 GATED UHA_PERPOS] Producteur dens per-POSITION argmin (legacy sélectionne
 * la classe par POSITION, argmin 5 classes 0x413ea0, pas par bloc). UNE arène globale
 * continue + machines ctx threadées ; à chaque position, argmin des 5 coûts de classe
 * dans l'arène, dens=min, puis apprentissage du ctx du gagnant. Apprentissage DENSE
 * (toutes positions) en 1ʳᵉ variante. Pur (buffers locaux). 0 OK, <0 erreur. */
int alz_ps_perpos_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, uint32_t *out);

/* [§13.722 GATED UHA_CLASSPASS] Producteur dens FIDÈLE : UNE arène SHARED
 * monotone, 5 passes de classe/bloc (ordre 0,1,2,3,4 puis 3,0,1,2,4), chaque
 * passe score+apprend (promo 32, rescale 0x4000) ; `out` = sortie de la passe
 * cls3 (snapshot lu par le décideur). Machine ctx re-amorcée par passe.
 * Pur, buffers locaux. Retourne 0 OK, <0 erreur. */
int alz_ps_classpass_percost(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, uint32_t *out);

/* [GATED UHA_SNAPWALK, VALIDATION lecture-seule] Producteur dens fidele au modele
 * DEUX-ARENES (snapshot persiste avance SPARSE sur les positions-litteral emises a
 * inc=16 ; dens = scoreur dense inc=32 sur copie live du snapshot, flux cls3).
 * is_lit[abs]=1 si la position est un litteral emis. Retourne 0 OK, <0 erreur. */
int alz_ps_snapshot_percost_sparse(const uint8_t *g, uint32_t usize,
                                   const uint32_t *blkpos, const uint32_t *blklen,
                                   int nblk, const uint8_t *is_lit, uint32_t *out);

/* [§13.723 GATED UHA_EMIPROD] emission-walk-producer : master avancé par LITTÉRAUX
 * ÉMIS (sparse, chaîne cls3 relative-bloc), puis par bloc snapshot(master)→working
 * + scan dense intra-bloc pour émettre le `dens` figé. is_lit[abs]=1 si littéral
 * émis. Pur, buffers locaux. 0 OK, <0 erreur. */
int alz_ps_emiprod_percost(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, const uint8_t *is_lit, uint32_t *out);

/* [GATED UHA_A3_CLASS0, défaut-OFF] Producteur densité FIDÈLE classe-0 (-m1) :
 * maître persistant (HOT 0..511 + seed + 8 lignes escape) appris par littéral émis
 * (learn 0x4120fd, rescale maître 0x40ffa0 double porte, escape 0x40fe90) ; par bloc
 * snapshot(master)→working + scan dense cls0 (a3_est_cost / 0x414630). Maître froid
 * au bloc 1 (bloc 0 émet via lignes>=512). N'écrit `out` que pour blocs>=1 ; bloc 0
 * intact. Loi validée offline 100 % (replay_master.c / verify_taildens.c). 0 OK, <0 err. */
int alz_ps_class0_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, const uint8_t *is_lit, uint32_t *out);
int alz_ps_class0_percost_ex(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, int b0_learn,
                             uint32_t *out);

/* [ARENA_TASK16, GATED défaut-OFF] producteur maître fidèle multi3 (snap persistant
 * avancé par le flux dense de la classe GAGNANTE, reload live:=snap/bloc, ps_score_ctxs
 * promo=32 + rescale @0x4000). Écrit `out` que pour base>=from (overlay bloc≥1).
 * Retourne 0 OK, <0 erreur. */
int alz_ps_livewalk_master(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, uint32_t from, uint32_t *out);

/* [ARENA_TASK16 — MESURE] maître « literal‑carry » : carry ps_ctx_step(3) + learn UNIQUEMENT
 * aux émissions de littéraux (gelé pendant les matchs). Digite tree/counter/hit rows 68/37
 * par bloc sur stderr (vs GT). N'écrit PAS out. 0 OK. */
int alz_ps_livewalk_litcarry(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, uint32_t *out_stats);

/* [ARENA_TASK16, GATED défaut-OFF] maître d'émission indexé par row_hash_cm (0x44d8d8).
 * Arène P séparée apprise aux littéraux du bloc0 via le moteur CM ; fingerprint rows 37/68
 * si UHA_LIVEWALK_STATS ; si out!=NULL, reload W:=P + score dense gen_ctxs(3) sur bloc≥from. */
int alz_ps_livewalk_cm(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                       uint32_t from, uint32_t *out);

/* [ARENA_TASK16/17, GATED défaut-OFF] producteur double-buffer P(PERM persist)/H(HOT reload/bloc) ;
 * SCORAGE dense gen_ctxs(3)→coût overlay bloc≥from ; EMISSION-LEARN de P = point d'injection #17
 * (stub baseline = littéraux). Retourne 0. */
int alz_ps_livewalk_dual(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                         uint32_t from, uint32_t *out);

/* Self-test from-plain image.raw bloc1 : Σ_cls == oracles + argmin cls3. 0 si OK. */
int alz_parse_score_selftest(void);

/* Multitest 6 blocs, init COLD (hyp. nulle non-persistance). 0 si OK. */
int alz_parse_score_multitest(const char *path);

/* Multitest 6 blocs, persistance arène+machine. 0 si OK. */
int alz_parse_score_multitest2(const char *path);

/* Multitest 6 blocs, modélisation SNAPSHOT (copie par classe, snap avancé par gagnant). 0 si OK. */
int alz_parse_score_multitest3(const char *path);

/* [TEST hook] active/désactive la correction de phase cls3 du harness offline. */
void alz_ps_set_phasefix(int v);

#endif /* ALZ_PARSE_SCORE_H */
