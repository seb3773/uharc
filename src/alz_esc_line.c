/*
 * a3_esc_line.c — ligne d'échappement 0x402+cl : cellules (PERM *0x4373CC) + arbre Fenwick
 *                 (*0x4373C8), learn 0x4100E0 et rescale 0x40FE90. Voir .h.
 */
#include "alz_esc_line.h"
#include <string.h>

static uint32_t lowbit(uint32_t x)
{
    return x & (0u - x);
}

/* Reconstruit l'arbre depuis les cellules. Convention du legacy : l'index d'arbre est
 * sym+1 (0x410118 `inc al`), donc fen[i] agrège les cellules [i-lowbit(i), i-1].
 * L'estimateur ne LIT que la racine (fen[0]) ; l'arbre n'est là que pour l'invariant. */
static void rebuild_tree(a3_esc_line_t *p)
{
    uint32_t i, j, sum = 0u;
    memset(p->fen, 0, sizeof p->fen);
    for (i = 1u; i < 256u; i++) {
        uint32_t lo = i - lowbit(i), s = 0u;
        for (j = lo; j < i; j++)
            s += p->freq[j];
        p->fen[i] = (uint16_t)s;
    }
    for (i = 0u; i < 256u; i++)
        sum += p->freq[i];
    p->fen[0] = (uint16_t)sum;
}

void a3_esc_line_init(a3_esc_line_t *p, uint16_t cell)
{
    uint32_t i;
    for (i = 0u; i < 256u; i++)
        p->freq[i] = cell;
    rebuild_tree(p);
}

int a3_esc_line_learn(a3_esc_line_t *p, uint32_t delta, uint16_t inc)
{
    uint32_t i;

    delta &= 0xffu;
    p->freq[delta] = (uint16_t)(p->freq[delta] + inc);

    /* 0x410118..0x41012A : i = sym+1, +lowbit, arithmétique 8 bits (wrap sur 0 = sortie) */
    i = delta + 1u;
    while (i != 0u) {
        p->fen[i] = (uint16_t)(p->fen[i] + inc);
        i = (i + lowbit(i)) & 0xffu;
    }

    /* 0x41012C..0x410131 : racine += inc */
    p->fen[0] = (uint16_t)(p->fen[0] + inc);

    if (p->fen[0] >= A3_ESC_RESCALE) {
        a3_esc_line_rescale(p);
        return 1;
    }
    return 0;
}

uint32_t a3_esc_line_proba(const a3_esc_line_t *p, uint32_t delta)
{
    uint32_t root = p->fen[0];                 /* WORD[0x4373C8 + 2*line] */
    if (root == 0u)
        return 0u;                             /* état invalide : le legacy diviserait par zéro */
    return (((uint32_t)p->freq[delta & 0xffu] << 14) / root);
}

void a3_esc_line_rescale(a3_esc_line_t *p)
{
    uint32_t i;
    /* 0x40FEAE..0x40FF08 : v' = ((v + 1) & 0xFFFE) >> 1  (pair -> v/2 ; impair -> (v+1)/2) */
    for (i = 0u; i < 256u; i++) {
        uint32_t v = p->freq[i];
        v = ((v + 1u) & 0xFFFEu) >> 1;
        p->freq[i] = (uint16_t)v;
    }
    rebuild_tree(p);
}
