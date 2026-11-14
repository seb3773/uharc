#ifndef UHA_FRONTIER_H
#define UHA_FRONTIER_H
#include <stdint.h>

/* Frontier `P` : predicat `adds` of has member (cascade complete).
 * Transcription byte-exact of the string validee M366/M368/M369 (arena #4) :
 *   m369_diviseur.verdict_m369  .  m368_transform_stade1.{walk,verdict,ratio_et_palier}
 *   bins = byte raw (histogramme identite, no remap) ; capacite = edi = m['e']+m['E'] ;
 *   Sigma = esi = subset 'e'/'E' filtre by [0x436e74+octet_precedent] ;
 *   rule d'arret M369 (32*string > size -> without level -> no adds) ;
 *   diviseur ratio = size - m[' '] - m[LF] - m[CR] - somme_lettres (cas 0 -> skips there division).
 * no effect out gate : appele ONLY under UHA_FRONTIER / UHA_FRONTIER_DEBUG. */

/* returns 1 if the member is adds (in P), 0 otherwise (repos / without level / arret). */
int uha_frontier_addoue(const uint8_t *octets, uint32_t n);

/* returns frontier level (PAL_H/PAL_M/PAL_L/PAL_B) if uha_frontier_addoue != 0, else 0. */
uint32_t uha_frontier_pal(const uint8_t *octets, uint32_t n);

/* m370 : tete of l'arrangement = adds (cumul) UNION chemin_court (count=0 / annulus size-0). */
int uha_frontier_promu(const uint8_t *octets, uint32_t n);

/* Debug (no emissif) : grandeurs calculees by the member, chacune peut to be NULL. */
void uha_frontier_debug(const uint8_t *octets, uint32_t n,
                        uint32_t *out_eax, uint32_t *out_edx, uint32_t *out_capa,
                        uint32_t *out_sigma, uint32_t *out_chaine, int *out_arret,
                        int *out_addoue);

#endif
