#ifndef ALZ_BOUND_H
#define ALZ_BOUND_H

#include <stdint.h>
/* ---------------------------------------------------------------------------
 * TABLES DE BORNAGE DU FINDER LEGACY (UHARC 0.6b 0x4136a0) — extraites du
 * .data DGROUP, GÉNÉRÉES mécaniquement (dd skip=(VMA-0x434000+0x32000) |
 * od -An -tu4, décimal LE direct), puis croisées avec `objdump -s -j DGROUP`
 * (concordant) ; cf. UHARC_RE_REPORT.md §13.469/§13.470/§13.471.
 * Index = diff_len*4 + group, avec group = AlzOrderGroup[ordre].
 * Sémantique : borne de DISTANCE (âge) tolérée selon l'écart de longueur
 * (diff) et le groupe d'ordre (group) du match. Utilisées pour le port fidèle
 * de la marche bornée (0x4137a0) + finaliseur d'acceptation (0x413530).
 * En-tête unique pour éviter la duplication/dérive entre TU.
 * ------------------------------------------------------------------------- */

/* 0x439794 : level/ordre -> groupe (0..3). */
static const uint32_t AlzOrderGroup[16] = {
    0, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
};

/* 0x4397d4 : borne d'ÂGE de la marche profonde 0x4137a0 [diff][group]. */
static const uint32_t AlzChainAgeBound[4][4] = {
    {          0u,           0u,           0u,           0u },
    {          4u,           8u,         128u,        1024u },
    {         16u,          64u,        1024u,        8192u },
    {         64u,         256u,        8192u, 0xFFFFFFFFu },
};

/* 0x439834 : seuil d'ACCEPTATION 0x413530 (branche principale, diff cap 4). */
static const uint32_t AlzAcceptThreshold[5][4] = {
    {          1u,           8u,          32u,         128u },
    {         32u,         256u,        1024u,        4096u },
    {       1024u,        8192u,       32768u,      131072u },
    {      65536u,      524288u,     2097152u,     8388608u },
    { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu },
};

/* 0x439884 : seuil d'ACCEPTATION (branche d'extension 0x413625, diff cap 7).
 * Valeurs GÉNÉRÉES directement depuis le binaire (od -t u4), authoritative. */
static const uint32_t AlzAcceptThresholdExt[8][4] = {
    {          1u,           1u,           1u,           1u },
    {          4u,          32u,         128u,         512u },
    {        128u,        1024u,        4096u,       16384u },
    {       1024u,        8192u,       32768u,      131072u },
    {       2048u,       32768u,      131072u,      524288u },
    {       4096u,       65536u,      262144u,     1048576u },
    {       8192u,      131072u,      524288u,     2097152u },
    {      16384u,      262144u,     1048576u,     4194304u },
};

#endif /* ALZ_BOUND_H */
