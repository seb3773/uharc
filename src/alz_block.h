#ifndef ALZ_BLOCK_H
#define ALZ_BLOCK_H

#include <stdint.h>
#include "alz_arena2d.h"

/*
 * alz_block — couche (a) BLOCK du scoreur ALZ legacy UHARC 0.6b : conteneurs MULTI-
 * CATÉGORIES + géométrie statique + transaction load/score/restore + argmin de coût
 * cumulé par classe. Portage fidèle des fonctions RE :
 *   - conducteur argmin par bloc 0x413ea0 (boucle classes 0x413fb6..0x414015) ;
 *   - scoreur de catégorie 0x414630 (garde catégorie active 0x41469e/0x4146a6,
 *     fallback catégorie 0 0x4147b7, commit 0x41437d, restore 0x4147be) ;
 *   - géométrie par catégorie : tables statiques DGROUP [0x437884]/[0x4378ac]/
 *     [0x43785c]/[0x4378d4] (off fichier = VA - 0x402000) — extraites octet-pour-
 *     octet du binaire (§13.47, §13.120).
 *
 * Le VRAI gouffre du +47 (cf. §13.49) = le modèle est MULTI-CATÉGORIES (~10 arènes)
 * argminées au niveau BLOC, là où notre byte-model n'a qu'UNE catégorie. Ce module
 * met en place les CONTENEURS et la GÉOMÉTRIE vérifiés ; la récurrence de coût exacte
 * (récurrence SSE §13.39) reste un incrément ultérieur — le score par classe est ici
 * une SONDE (stub) clairement identifiée, NON émissive.
 *
 * STATUT : Gated, NON-WIRED (aucun effet sur l'encodage standard). Self-test structuré
 * via env UHA_BLOCKTEST dans uha_c.
 */

#define ALZ_BLOCK_NCAT   10u   /* catégories idx 0..9 (arènes 0x000,0x301..0x3f4)      */
#define ALZ_BLOCK_NCLASS  5u   /* classes scorées à l'entrée de bloc 0..4 (§13.119)    */

/* --- Géométrie de catégorie STATIQUE (extraite du binaire, off = VA-0x402000) ------- */
/* [0x437884] base d'arène par catégorie (idx0=0 → fallback catégorie 0). */
extern const uint16_t alz_block_arena[ALZ_BLOCK_NCAT];
/* [0x4378ac] tableA : param de ligne/taille (shift <<9 pour offset du slice 2D). */
extern const uint16_t alz_block_tblA[ALZ_BLOCK_NCAT];
/* [0x43785c] tableC : compte/lignes relatif par catégorie. */
extern const uint8_t  alz_block_tblC[ALZ_BLOCK_NCAT];
/* [0x4378d4] octet escape par classe (index = classe/catégorie, 0..19 utile). */
extern const uint8_t  alz_block_escape[20];

/*
 * Conteneur d'état de bloc. Alloué sur tas (chaque alz_arena2d_t ~264 Ko ; NCAT modèles
 * vivants + NCAT instantanés ⇒ plusieurs Mo → allocation dynamique obligatoire).
 */
typedef struct {
    alz_arena2d_t *model;      /* [NCAT] modèles 2D VIVANTS (auto-entraînés en place)  */
    alz_arena2d_t *snapshot;   /* [NCAT] instantanés pour restore transactionnel        */
    uint32_t       active_cat; /* [0x45ecc0] catégorie active (garde du scoreur)       */
    uint8_t        flag_snap;  /* [0x45ecc8] drapeau snapshot (1 = restore complet)    */
} alz_block_t;

/* Fabrique/détruit (calloc des tableaux d'arènes, zero-fill). Renvoie NULL si OOM. */
alz_block_t *alz_block_create(uint16_t default_inc);
void         alz_block_destroy(alz_block_t *b);

/* --- Transaction load/score/restore (§13.120 item 5) -------------------------------- */
/* snapshot[cat] <- model[cat]  (mémorise l'état avant un score auto-entraînant). */
void alz_block_save(alz_block_t *b, uint32_t cat);
/* model[cat] <- snapshot[cat]  (restaure : chaque catégorie est scorée indépendamment). */
void alz_block_restore(alz_block_t *b, uint32_t cat);

/* Commit de catégorie active (0x41437d) : pose active_cat + flag selon le chemin. */
void alz_block_commit_cat(alz_block_t *b, uint32_t cat, uint8_t snap_flag);

/*
 * SONDE de coût cumulé d'une catégorie sur une fenêtre [win, win+len) : accumulation
 * du coût delta-2D par position via l'arène vivante (auto-entraînement en place).
 * ⚠️ STUB — la correspondance exacte (relrow, delta) <-> legacy (0x415444) et le
 * remplissage du tableau de coûts positionnels 0x45cb60[] sont l'incrément SUIVANT.
 * Écrit éventuellement dans *out_cost si non NULL. NON émissif.
 */
uint64_t alz_block_score_class_stub(alz_block_t *b, uint32_t cat,
                                    const uint8_t *win, uint32_t len,
                                    uint64_t *out_cost);

/*
 * Argmin de coût cumulé sur les classes [0, nclass) (§13.119 item 2) : pour chaque
 * classe, restore -> score (stub) -> coût ; garde le minimum ; commit des coûts
 * positionnels du gagnant. Renvoie l'index de classe gagnante (<nclass) ou -1 si
 * len==0. Remplit costs[] (nclass entrées) si non NULL.
 */
int alz_block_argmin(alz_block_t *b, const uint8_t *win, uint32_t len,
                     uint32_t nclass, uint64_t *costs);

/* Self-test : géométrie == constantes extraites ; save/restore idempotent ; argmin
 * retourne la classe de coût minimal. Renvoie 0 si OK, sinon nb d'échecs. */
int alz_block_selftest(void);

#endif /* ALZ_BLOCK_H */
