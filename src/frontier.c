/* frontier.c - predicat `adds` of the frontier P (transcription byte-exact M369/M368/M366).
 * Voir frontier.h. no effect out gate (calls only under UHA_FRONTIER now UHA_FRONTIER_DEBUG).
 * Autorite : re_asm/OUT/m369_diviseur.py (verdict_m369) compose m368_transform_stade1.py
 *   (walk / verdict / ratio_et_palier) then m366_producteurs.py (bins, EAX_K / EDX_K). */
#include "frontier.h"
#include "frontier_tables.h"
#include <string.h>

/* bins of decision (m366 EAX_K / EDX_K) ; lettres = Has..Z has..z (m368 K_LETTRES). */
static const uint32_t EAX_K[6] = { 74, 81, 90, 106, 113, 122 };
static const uint32_t EDX_K[6] = { 65, 69, 84, 97, 101, 116 };

/* thresholds / levels (m368 thresholds, levels ; constantes d'image). */
#define SEUIL_300   0x12cu    /* r1 <= 300 : test pre-bands (0x404871) */
#define SEUIL_400   0x190u    /* level 0xc000000 (0x404889) */
#define SEUIL_200   0xc8u     /* level 0x9000000 (0x404af1) */
#define SEUIL_40    0x28u     /* level 0x6000000 (0x404b09) */
#define SEUIL_16    0x10u     /* level 0x3000000 via r2 (0x404b1e) */
#define PAL_H       0x0c000000u
#define PAL_M       0x09000000u
#define PAL_L       0x06000000u
#define PAL_B       0x03000000u

typedef struct {
    uint32_t m[256];
    uint32_t paires[10];
    uint32_t sigma, capacite, chaine, esp_red;
    uint32_t n;
} marche_t;

/* m368_transform_stade1.walk - promenade lineaire sure the bytes raw, bins = byte. */
static void marche(const uint8_t *o, uint32_t n, marche_t *mm)
{
    uint32_t i, precedent = 0;
    memset(mm, 0, sizeof *mm);
    mm->n = n;
    for (i = 0; i < n; i++) {
        uint32_t x = o[i];
        mm->m[x]++;                                   /* 0x404969.. m[byte]++, BEFORE the flag */
        if (FRONTIER_ROUTAGE[x]) {                    /* 0x40496d/76/78 : routage -> string */
            mm->chaine++;
            precedent = x;
            continue;
        }
        if (x == 0x20u) {                             /* 0x4049c1 espace redouble -> [esp+0x758] */
            if (x == precedent) mm->esp_red++;
        } else if (x == 0x61u) {                      /* 0x4049ee 'has' -> paires 6/7 (0x718) */
            mm->paires[(x == precedent) ? 7 : 6]++;
        } else if (x == 0x69u) {                      /* 0x404a09 'i' -> paires 8/9 (0x720) */
            mm->paires[(x == precedent) ? 9 : 8]++;
        } else if (x == 0x6fu) {                      /* 0x404a24 'o' -> paires 2/3 (0x708) */
            mm->paires[(x == precedent) ? 3 : 2]++;
        } else if (x == 0x75u) {                      /* 0x404a3f 'u' -> paires 4/5 (0x710) */
            mm->paires[(x == precedent) ? 5 : 4]++;
        } else if (x == 0x65u) {                      /* 0x404a60 'e' : capa + sigma(filtre>=1) + paire 0/1 */
            mm->capacite++;
            if (FRONTIER_FILTRE[precedent] >= 1) mm->sigma++;
            mm->paires[(x == precedent) ? 1 : 0]++;
        } else if (x == 0x45u) {                      /* 0x404aac 'E' : capa + sigma(filtre>=2), no paire */
            mm->capacite++;
            if (FRONTIER_FILTRE[precedent] >= 2) mm->sigma++;
        }
        precedent = x;                                /* 0x4049dd [esp+0x764]=al */
    }
}

/* m369_diviseur.arret_anticipe : 32 * string > size. */
static int arret_anticipe(const marche_t *mm)
{
    return (uint64_t)32 * mm->chaine > (uint64_t)mm->n;
}

/* m368.ratio_et_palier + repos + egalite, diviseur REEL (bins m[' '],m[LF],m[CR]). returns adds ; *r1_out = [esp+0x740] (ratio). */
static int verdict(const marche_t *mm, uint32_t eax, uint32_t edx, uint32_t lettres, int *pal_out, uint32_t *r1_out)
{
    uint32_t n = mm->n;
    uint32_t h80 = mm->m[0x20], h28 = mm->m[0x0a], h34 = mm->m[0x0d];
    uint32_t den2 = n - h80;
    uint32_t r2 = den2 ? (uint32_t)(((uint64_t)64 * mm->esp_red) / den2) : 0u;
    uint32_t den = n - h80 - h28 - h34 - lettres;      /* no signe, wrap 32b (== & M32) */
    uint32_t r1 = den ? (uint32_t)(((uint64_t)64 * lettres) / den) : 0u;
    uint32_t pal;
    int repos;
    if (r1 <= SEUIL_300 && !((n >> 6) > mm->chaine)) {  /* 0x404871 then keeps string */
        pal = 0;
    } else {
        if (r1 >= SEUIL_400)      pal = PAL_H;          /* 0x404889/0x404895 */
        else if (r1 >= SEUIL_200) pal = PAL_M;          /* 0x404af1/0x404af9 */
        else if (r1 >= SEUIL_40)  pal = PAL_L;          /* 0x404b09/0x404b0e */
        else if (r2 >= SEUIL_16)  pal = PAL_B;          /* 0x404b1e/0x404b2c */
        else pal = 0;
        if (pal == PAL_B && h80 == 0) pal = 0;          /* 0x404b47 test ecx,ecx / reset */
    }
    if (pal_out) *pal_out = (int)pal;
    if (r1_out) *r1_out = r1;
    /* repos : 5 paires (0x4048a0/62/76/8a/9e) then 2*sigma<=capa (0x404bb2) then eax>edx (0x404c27) */
    repos = (mm->paires[7] > mm->paires[6] ||
             mm->paires[1] > mm->paires[0] ||
             mm->paires[9] > mm->paires[8] ||
             mm->paires[3] > mm->paires[2] ||
             mm->paires[5] > mm->paires[4] ||
             2u * mm->sigma <= mm->capacite ||
             eax > edx);
    /* egalite = (repos now without level) ; adds = no-egalite */
    return (repos || pal == 0) ? 0 : 1;
}

static int cascade(const uint8_t *octets, uint32_t n,
                   uint32_t *eax_o, uint32_t *edx_o, uint32_t *capa_o,
                   uint32_t *sig_o, uint32_t *chai_o, int *arret_o, int *ajoute_o, int *promu_o)
{
    marche_t mm;
    uint32_t eax = 0, edxsum = 0, lettres = 0, k, i;
    int ajoute;
    marche(octets, n, &mm);
    for (k = 0; k < 6; k++) eax += mm.m[EAX_K[k]];
    for (k = 0; k < 6; k++) edxsum += mm.m[EDX_K[k]];
    for (i = 65; i <= 90; i++)  lettres += mm.m[i];
    for (i = 97; i <= 122; i++) lettres += mm.m[i];
    if (eax_o) *eax_o = eax;
    if (edx_o) *edx_o = edxsum >> 2;                   /* 0x404c22 shr edx,2 */
    if (capa_o) *capa_o = mm.capacite;
    if (sig_o) *sig_o = mm.sigma;
    if (chai_o) *chai_o = mm.chaine;
    if (arret_o) *arret_o = arret_anticipe(&mm);
    uint32_t r1 = 0;
    int casse = arret_anticipe(&mm), court, promu;
    if (casse)
        ajoute = 0;                                      /* output without level -> no adds */
    else
        ajoute = verdict(&mm, eax, edxsum >> 2, lettres, 0, &r1);
    /* m370 chemin_court : remainder==0 (i.e. NOT casse) AND r1<=0x12c AND (size>>6)<=string */
    court = (!casse) && (r1 <= SEUIL_300) && (((n >> 6) <= mm.chaine) ? 1 : 0);
    promu = ajoute || court;
    if (promu_o) *promu_o = promu;
    if (ajoute_o) *ajoute_o = ajoute;
    return ajoute;
}

int uha_frontier_addoue(const uint8_t *octets, uint32_t n)
{
    return cascade(octets, n, 0, 0, 0, 0, 0, 0, 0, 0);
}

/* m370 : promu = cumul (adds) UNION chemin_court (count=0 / annulus) - tete of l'arrangement. */
int uha_frontier_promu(const uint8_t *octets, uint32_t n)
{
    int promu = 0;
    cascade(octets, n, 0, 0, 0, 0, 0, 0, 0, &promu);
    return promu;
}

void uha_frontier_debug(const uint8_t *octets, uint32_t n,
                        uint32_t *out_eax, uint32_t *out_edx, uint32_t *out_capa,
                        uint32_t *out_sigma, uint32_t *out_chaine, int *out_arret,
                        int *out_addoue)
{
    cascade(octets, n, out_eax, out_edx, out_capa, out_sigma, out_chaine, out_arret, out_addoue, 0);
}
