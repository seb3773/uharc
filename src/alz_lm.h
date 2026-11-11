/*
 * alz_lm.h — Décideur de flush legacy 0x412c30 (lit<->match) de UHARC 0.6b.
 *
 * Transcription C FIDÈLE validée par rejeu 6059/6059 (ecx/esi/al) sur la capture
 * live `_scratch/a5t8cap/c30e.tsv` (§13.237) et par le harnais standalone
 * `_scratch/a5c2f/lm412c30_replay.c`. Spec complète : `_scratch/a5c2f/0x412c30_port.md`.
 *
 * STATUT : module PUREMENT ADDITIF. Tant qu'aucun site d'appel n'est branché dans
 * l'encodeur (gated UHA_LMCOST, défaut-OFF), ce code n'a AUCUN effet sur l'émission
 * standard (baselines 7049 / 7038 / 7002 garanties).
 */
#ifndef UHA_ALZ_LM_H
#define UHA_ALZ_LM_H

#include <stdint.h>

/*
 * Entrées du décideur. Chacune a une dérivation from-scratch FERMÉE côté clone
 * (voir _scratch/a5c2f/state_map.md) :
 *   arg = alz_token_class_index_ro ; DL/DH/dh/bb/bc/S8c = scalaires du candidat
 *   (finder + recent[] + mode) ; pend = st.repeat_run (0 sur block0) ; bud/off/key/sm
 *   = flot par octet (anneau 256 + table densité) ; w16 = LE16(plain[pos..]) ;
 *   v = table primaire « longueur du dernier match émis sur le contexte order-2 » ;
 *   cx/ce = coûts modèle sym/escape via token_class + alz_score_cost ;
 *   loop[] = chaîne différée (cls,c2) du reste de run (0x412ded).
 */
typedef struct {
    uint32_t arg, DL, DH, dh, bb, bc, S8c, pend, bud;
    uint32_t w16, v;
    uint32_t off, key, sm;
    int      shortcut;      /* sc : chemin (bud>>8)*DL pris avant la boucle densité */
    uint32_t cx, ce;        /* coûts modèle fournis (symbole, escape) */
    int      nloop;
    struct { int cls; uint32_t c2; } loop[64];
} lm_in;

typedef struct { uint32_t ecx, esi; int al; } lm_out;

/*
 * Décideur pur (sans effet de bord) : ecx=coût-match, esi=coût-littéral,
 * al = (ecx<esi) après prise en compte de la boucle différée. Reproduit
 * octet-pour-octet la logique de 0x412c30 (wraps 32-bit, divisions tronquées,
 * tables statiques). al!=0 => émets le MATCH ; al==0 => littéral.
 */
void alz_lm_decide(const lm_in *in, lm_out *o);

/*
 * Table `v` primaire au contexte COURANT w16 — miroir strict du legacy 0x412c0a
 * (validé 6059/6059 from-scratch, §13.240 / val_v.py) :
 *   lookup(lors d'une décision)      = tab[w16 + (dh!=1 ? 0x10000 : 0)]
 *   à chaque ÉMISSION d'un match     : tab[w16_emit + (dh_emit!=1 ? 0x10000 : 0)] = DL_emit
 * Initialisée à 0. DISTINCTE de m_len_pred (celle-ci est au contexte SOURCE pos−dist,
 * sert le MODÈLE de longueur ; `v` sert la DÉCISION de flush au contexte courant).
 * Taille 0x20000 (w16<0x10000, +0x10000 si dh!=1).
 */
#define LM_V_CTXSIZE 0x20000u
static inline uint32_t alz_lm_v_ctx(uint32_t w16, uint32_t dh)
{
    return w16 + (dh != 1 ? 0x10000u : 0u);
}
static inline uint32_t alz_lm_v_get(const uint8_t *vtab, uint32_t w16, uint32_t dh)
{
    return vtab[alz_lm_v_ctx(w16, dh)];
}
static inline void alz_lm_v_put(uint8_t *vtab, uint32_t w16, uint32_t dh, uint32_t DL)
{
    vtab[alz_lm_v_ctx(w16, dh)] = (uint8_t)DL;
}

/*
 * [a5c2f-c-govern-loop] Table `mapcls` (byte->classe, 256 u8, legacy 0x437464)
 * servant a generer la chaine differee loop[] (walker 0x412ded) from-clone :
 * a chaque `pos`, la classe du byte precedent `b` est `cls = mapcls[b]`, la
 * suivante `b = cls`, jusqu'a `cls==0` (terminaison) ou epuisement de `DL-1`.
 * L'accesseur evite de dupliquer la table ; sans effet sur le decideur pur.
 */
const uint8_t *alz_lm_mapcls_table(void);

#endif /* UHA_ALZ_LM_H */
