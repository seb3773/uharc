/*
 * alz_esc_line.h — ligne d'échappement (PERM ligne 0x402+cl + son arbre Fenwick), port fidèle
 *                 du learn 0x4100E0 et du rescale 0x40FE90.
 *
 * État mesuré (capture n°9 + OUT/A3_escmod_b1_5.tsv) :
 *   - 256 cellules, valeur initiale 4 ; racine Fenwick initiale 1024 = 4*256 ;
 *   - un événement d'échappement ajoute `inc` (16 pour cls 3) à la cellule indexée par le
 *     **delta** (post-signe), met à jour l'arbre (Fenwick 8 bits, index delta+1, wrap sur 0)
 *     et la racine, puis rescale si racine >= 0x4000 (0x40FE90 : ceil-halving, sans seuil).
 *   - bancs DISTINCTS : les cellules (freq) sont dans *0x4373CC, l'arbre dans *0x4373C8 ;
 *     l'estimateur lit freq[delta] et WORD[fen + 2*line] = racine (slot 0).
 *
 * STATUT : module de LANE, NON WIRÉ. Le déclencheur exact (quel chemin d'émission appelle le
 * learn, et quelle valeur de `inc`) reste à confirmer par capture — cf. OUT/A3_loi_escape_line.md.
 */
#ifndef A3_ESC_LINE_H
#define A3_ESC_LINE_H

#include <stdint.h>

#define A3_ESC_INIT_CELL 4u
#define A3_ESC_RESCALE   0x4000u

typedef struct a3_esc_line {
    uint16_t freq[256];   /* PERM ligne 0x402+cl : cellules, init 4 */
    uint16_t fen[256];    /* arbre Fenwick de la ligne ; fen[0] = RACINE = Σ freq */
} a3_esc_line_t;

/* Initialise la ligne : toutes les cellules à `cell`, racine à 256*cell, arbre construit. */
void a3_esc_line_init(a3_esc_line_t *p, uint16_t cell);

/* Un événement d'échappement sur `delta` : cellule += inc, arbre += inc, racine += inc,
 * rescale si racine >= 0x4000. Rend 1 si un rescale a eu lieu. */
int a3_esc_line_learn(a3_esc_line_t *p, uint32_t delta, uint16_t inc);

/* p_esc 14 bits = (freq[delta] << 14) / racine (division entière, comme 0x41493F).
 * Racine nulle = état invalide (le legacy diviserait par zéro) : rend 0. */
uint32_t a3_esc_line_proba(const a3_esc_line_t *p, uint32_t delta);

/* Rescale de la ligne (0x40FE90) : v' = ((v + 1) & 0xFFFE) >> 1 pour chaque cellule, puis
 * reconstruction de l'arbre. Racine après = Σ v'. */
void a3_esc_line_rescale(a3_esc_line_t *p);

#endif /* A3_ESC_LINE_H */
