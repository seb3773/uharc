/*
 * alz_parse_score.c — scoreur de PARSE ALZ (conducteur de bloc 0x413f7f/0x413ea0 + catégorie
 * 0x414630). Reproduction bit-exact du pipeline validé from-scratch §13.132/§13.137..§13.141.
 * GATED, NON-WIRED. Voir alz_parse_score.h pour la spécification.
 */
#include "alz_parse_score.h"
#include "alz_score.h"
#include "alz_cm.h"
#include "alz_est414630.h"
#include "alz_esc_line.h"
#include "encode.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Tables statiques de la machine ctx (générées, §13.132). */
#include "alz_parse_score_tables.inc"

/* [GATED UHA_AADUMP, sonde LECTURE SEULE §13.722(4)/§13.724] Pointeur de dump
 * (row,freq,total) pos-à-pos de la passe cls3, ouvert UNIQUEMENT par
 * alz_ps_emiprod_percost quand UHA_AADUMP=chemin. NULL sinon ⟹ aucun effet. */
static FILE *g_adump = NULL;
/* [GATED UHA_WLEARNLIT, défaut-OFF, §14.126] masque de learn par position globale
 * (index base+i). NULL => learn PARTOUT (comportement actuel, non régressif).
 * Quand posé : la passe ne MUT l'arène (freq/total/rescale) que là où mask!=0
 * (ex. littéraux émis), tout en SCORANT chaque position (percost intact).
 * Teste l'hypothèse « le legacy n'apprend que sur le flux d'émission ». */
static const uint8_t *g_ps_learn_mask = NULL;
/* [GATED UHA_LIVEWALK_BOUNDRESCALE] si ≠0, ps_learn NE rescale PAS inline ; le rescale
 * est appliqué à la FRONTIÈRE de bloc (cadence commit legacy `0x414590`, boucle colonnes
 * `0x414806–0x414871`), pas dès que total≥0x4000 pendant l'apprentissage. */
static int g_ps_no_inline_rescale = 0;
/* [GATED UHA_PHASEFIX, défaut-OFF, §13.739] Phase cls3 corrigée = (abs+2)%3
 * (mesurée 29943/29944 = 100 % vs flux learn réel 0x411bb8) au lieu du compteur
 * ebp threadé par bloc. Affecte UNIQUEMENT cls3, et seulement quand la porte est ON. */
static int g_ps_phasefix = 0;

int a3_promo_on(const char *name);   /* [PROMO_ALZ-1] défini dans alz.c — pas de .h touché */

/* [GATED UHA_A3_ESCBRANCH=1, défaut-OFF, lane ALZ -m3, 2026-10-28, single-pass]
 * Port fidèle de la branche d'échappement de la CLASSE 3 (capture n°2 : machine d'état
 * exacte 65 536/65 536, prédicat f6[v]>8 && cap<5, ligne 16+32·phase, cellule = delta
 * d'entrée de l'appel — cf. OUT/A3_predicat_escape.md). Dans alz_ps_gen_ctxs(cls==3)
 * uniquement. Défaut-OFF = comportement strictement inchangé (banque 16685
 * reproductible au mot près). */
static int g_ps_escbranch = -1;
static inline int ps_escbranch_on(void)
{
    if (g_ps_escbranch < 0) g_ps_escbranch = a3_promo_on("UHA_A3_ESCBRANCH");
    return g_ps_escbranch;
}

/* [GATED UHA_A3_ESCBRANCH] CANAL D'ÉCRITURE du maître (défaut NULL = pas de split) :
 * quand un consommateur le demande, gen_ctxs(3) y dépose la paire (ligne, cellule) que
 * le MAÎTRE écrit au journal `m18` — ligne d'ESCAPE (`16+32·phase`) et sa cellule propre —
 * tandis que `out[]` garde la paire ORDINAIRE pré-escape que lit le SCAN/dens (registre `m9`,
 * 12 544/12 544 en bloc 1). Mesure 2026-10-28 : confondre les deux canaux casse le candidat
 * aux 167 slots famille du bloc 1 (row 80 au lieu de 69). */
uint32_t *alz_ps_escwr = NULL;
/* [GATED UHA_A3_ESCWR_CLS, PROMUE tour 138 — DÉFAUT‑ON, échappatoire `=0`, lane ALZ -m3, tour 120]
 * canal d'ÉCRITURE pour les classes ≠ 3. Mesure (tour 118) : gen_ctxs ne remplissait le canal que
 * dans sa branche cls 3 ; pour cls 0/1/2/4 le consommateur lisait un `calloc` vierge (13 crédits
 * dérivés contre 13 300 legacy sur `records`, 16 contre 116 sur `biased`). Loi uniforme : dans la
 * voie ordre‑2 (cls 0) et la boucle générique (cls ≥ 4), la paire écrite par le maître EST la
 * paire publiée (`row`,`b`) / (`ebx`,`delta`) — contrairement à cls 3 où l'escape sépare ligne
 * d'écriture et ligne ordinaire. On recopie donc `out[]`, sans jamais le modifier.
 * `UHA_A3_ESCWR_CLS=0` : canal intact, aucun effet (chemin d'avant la promotion). */
static int g_ps_escwr_cls = -1;
static inline int ps_escwr_cls_on(void)
{
    if (g_ps_escwr_cls < 0) g_ps_escwr_cls = a3_promo_on("UHA_A3_ESCWR_CLS");
    return g_ps_escwr_cls;
}

/* [GATED UHA_A3_CTXCLASS_AUTO, défaut-OFF, lane ALZ -m3, tour 120] gagnante par bloc
 * exportée par `alz_ps_snapshot_percost` (voir header). Écriture systématique (pas de
 * getenv dans la boucle) ; le consommateur décide. `_n` remis à 0 à chaque appel. */
int alz_ps_snapwin_blk[ALZ_PS_SNAPWIN_MAX];
int alz_ps_snapwin_n = 0;

/* [GATED UHA_PFILE, défaut-OFF, ISOLAT, M33→razor -m3] Pré-substrat `P[pos]` du
 * cm-engine (lois M33 closes par #2, psim.py 159/159, produit depuis image.raw SEUL),
 * chargé en une passe depuis le fichier (1 octet/prédiction). Quand posé, gen_ctxs(cls==3)
 * utilise `ctx = P[i]` (la VRAIE prédiction) au lieu de `ctx=(rolling>>esc)&0xff`
 * (approx lag‑3), donc le `delta = zigzag(value − P)` devient fidèle ⟹ intra16
 * peuplé (M31 : base 0x351) et la PAIRE (row,sym) est cohérente EN ÉCRITURE ET EN LECTURE
 * (tous les consommateurs lisent `ctxc[3]`), contrairement aux gates réfutées
 * FEEDSELF_LAG3/PHASE2 qui écrivaient hors‑ctxc. Défaut‑OFF = comportement strictement
 * inchangé (banque 16685). */
/* ✖ MESURÉ NÉGATIF (2026‑10‑21, main) pour CETTE intégration en pré‑passe : FEEDSELF+AGING
 * (razor ref 18432) + UHA_PFILE → **firstdiv 18432 → 12679** (régresse). Cause double :
 * (a) le scoreur 0x412c30/0x414630, DÉJÀ clos/fidèle, CONSOMME ctxc[3] avec le ctx lag‑3 ;
 *     substituer P partout le perturbe → near‑ties renversées plus tôt ; (b) le ROW law M31
 *     (base 0x351 / ctx_roulant=[0x45cbc8]) est non clos → la paire (row,sym) reste incohérente.
 *  ⟹ P fidèle est NÉCESSAIRE mais NON SUFFISANT en pré‑passe ; le levier réel = SINGLE‑PASS
 *  (TASK16) où score+learn+row partagent un même ctx en ordre d'émission RÉEL. Gate laissée
 *  défaut‑OFF (brique P réutilisable pour TASK16), non câblée au défaut. */
static const uint8_t *alz_ps_pfile_try(uint32_t n)
{
    (void)n;
    return NULL;
}

/* [GATED UHA_CM_WIRE, défaut-OFF, §13.787/789] Tables de la machine-registre d'affinite
 * image (extraite du binaire UHARC.EXE, off = VA-0x402000) :
 *   f74 = (f74<<8) + T1[sym]   (T1 @ 0x438310)
 *   f78 = (f78<<8) + T2[sym]   (T2 @ 0x438b10)
 * Meme categorie de provenance que alz_ps_t1/t3 et alz_block_arena (tables STATIQUES
 * du mecanisme, PAS des captures runtime). Utilisees UNIQUEMENT quand UHA_CM_WIRE est ON. */
static const uint32_t ALZ_REG_T1[256]={0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,6,6,6,6,7,7,7,7,8,8,8,8,9,9,9,9,10,10,10,10,11,11,11,11,12,12,12,12,13,13,13,13,14,14,14,14,15,15,15,15,16,16,16,16,17,17,17,17,18,18,18,18,19,19,19,19,20,20,20,20,21,21,21,21,22,22,22,22,23,23,23,23,24,24,24,24,25,25,25,25,26,26,26,26,27,27,27,27,28,28,28,28,29,29,29,29,30,30,30,30,31,31,31,31,32,31,31,31,31,30,30,30,30,29,29,29,29,28,28,28,28,27,27,27,27,26,26,26,26,25,25,25,25,24,24,24,24,23,23,23,23,22,22,22,22,21,21,21,21,20,20,20,20,19,19,19,19,18,18,18,18,17,17,17,17,16,16,16,16,15,15,15,15,14,14,14,14,13,13,13,13,12,12,12,12,11,11,11,11,10,10,10,10,9,9,9,9,8,8,8,8,7,7,7,7,6,6,6,6,5,5,5,5,4,4,4,4,3,3,3,3,2,2,2,2,1,1,1,1,0,0,0};
static const uint32_t ALZ_REG_T2[256]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static inline uint32_t rb(const uint8_t *d, uint32_t i, uint32_t k)
{
    return (i >= k) ? (uint32_t)d[i - k] : 0u;
}

void alz_ps_gen_ctxs(uint32_t cls, const uint8_t *data, uint32_t n, uint32_t *out)
{
    uint32_t i;
    if (cls == 0u) {
        /* Voie ordre-2 (0x414b2e) : row = prev1 + (0x100 si même classe des 2 MSB). */
        for (i = 0; i < n; i++) {
            uint32_t b  = data[i];
            uint32_t p1 = rb(data, i, 1);
            uint32_t p2 = rb(data, i, 2);
            uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
            out[i] = (row << 8) | b;
            /* [GATED UHA_A3_ESCWR_CLS] écriture du maître = (row, octet brut) : la même paire. */
            if (alz_ps_escwr && ps_escwr_cls_on()) alz_ps_escwr[i] = out[i];
        }
        return;
    }
    {
        uint32_t ebx = 0u, flag = 0u, ebp = 0u;
        uint32_t esc = alz_ps_escape[cls];
        /* [GATED UHA_PFILE, M33] pour cls3, la prédiction cm-engine remplace le ctx lag‑3. */
        const uint8_t *pc = (cls == 3u) ? alz_ps_pfile_try(n) : NULL;
        /* [GATED UHA_A3_ESCBRANCH, défaut-OFF] boucle fidèle classe 3 : état d'échappement
         * (f6/rem par slot mod 6, cap, ecc2/5/6, fenêtre 32 bits, référence ecbf).
         * Sortie = (ligne bande-relative de l'appel précédent — lag du maître — << 8) |
         * delta d'ENTRÉE de l'appel courant = la cellule écrite par le maître. */
        if (cls == 3u && !pc && ps_escbranch_on()) {
            uint32_t f6[6] = {0u,0u,0u,0u,0u,0u}, rem[6] = {0u,0u,0u,0u,0u,0u};
            uint32_t cap = 0u, ecc2 = 0u, ecc5 = 0u, ecc6 = 0u, ecbf = 0u, win = 0u;
            uint32_t row = 0u;      /* ligne d'ÉCRITURE de l'appel précédent (escape ou ordinaire) */
            uint32_t row_ord = 0u;  /* ligne ORDINAIRE de l'appel précédent (candidat scan/dens) */
            uint32_t m6 = 0u, m6p1 = 1u, m3 = 0u;
            for (i = 0; i < n; i++) {
                uint32_t b = data[i];
                uint32_t win_pre = rb(data, i, 1) | (rb(data, i, 2) << 8) |
                                   (rb(data, i, 3) << 16) | (rb(data, i, 4) << 24);
                uint32_t de = (b + 0x100u - ecbf) & 0xffu;          /* delta d'entrée (0x4101e6) */
                uint32_t dl;
                if (ecc6) de = (0u - de) & 0xffu;
                if (de >= 0x80u) ecc6 ^= 1u;                        /* flip 0x4101fd */
                dl = de;
                if (ecc2) {                                         /* réarmement 0x41039b+ */
                    uint32_t ref2 = (win_pre >> 16) & 0xffu;
                    dl = (b + 0x100u - ref2) & 0xffu;
                    ecc6 = ecc5;
                    if (ecc6) dl = (0u - dl) & 0xffu;
                    if (dl >= 0x80u) ecc6 = (ecc6 == 0u) ? 1u : 0u;
                }
                /* CANDIDAT (scan/dens, confront m9) = ligne ORDINAIRE + cellule `dl` ;
                 * ÉCRITURE du maître (journal m18) = ligne escape/ordinaire + cellule `de`,
                 * exposée par `alz_ps_escwr` si le consommateur l'a demandée. */
                out[i] = (row_ord << 8) | dl;
                if (alz_ps_escwr) alz_ps_escwr[i] = (row << 8) | de;
                {
                    uint32_t u = m6;                                /* cmp octet vs rem[u] */
                    if (b == rem[u]) f6[u] += 1u; else f6[u] >>= 1u;
                }
                win = ((win << 8) | b) & 0xffffffffu;
                {
                    uint32_t v = m6p1;
                    uint32_t ph = m3 << 5;
                    uint32_t ecbf_new = (win >> 16) & 0xffu;
                    rem[v] = (ecbf_new + b - ((win >> 24) & 0xffu)) & 0xffu;
                    uint32_t t3r = alz_ps_t3[dl] + ph;   /* ligne ORDINAIRE (candidat) */
                    if (f6[v] > 8u && cap < 5u) {                   /* ÉCHAPPEMENT 0x41031f */
                        ecc5 = ecc6;
                        row  = 16u + ph;                            /* ligne d'ÉCRITURE seulement */
                        ecc6 = 0u; ecbf = rem[v]; cap += 1u; ecc2 = 1u;
                    } else {
                        uint32_t fl = (f6[v] > 8u) ? 1u : 0u;
                        ecc2 = 0u; ecbf = ecbf_new;
                        row  = t3r;
                        cap  = fl ? cap + 1u : 0u;
                    }
                    row_ord = t3r;
                }
                m6 = m6p1;
                m6p1 = (m6p1 == 5u) ? 0u : (m6p1 + 1u);
                m3 = (m3 == 2u) ? 0u : (m3 + 1u);
            }
            return;
        }
        {
        uint32_t ebp_m3 = 0u;
        for (i = 0; i < n; i++) {
            uint32_t b = data[i];
            uint32_t ctx;
            if (pc) {
                ctx = pc[i];
            } else {
                uint32_t rolling = rb(data, i, 1) | (rb(data, i, 2) << 8) |
                                   (rb(data, i, 3) << 16) | (rb(data, i, 4) << 24);
                ctx = (rolling >> esc) & 0xffu;
            }
            uint32_t delta = flag ? ((ctx + 0x100u - b) & 0xffu) : ((b + 0x100u - ctx) & 0xffu);
            out[i] = (ebx << 8) | delta;
            /* [GATED UHA_A3_ESCWR_CLS] boucle générique : écriture du maître = (ebx, delta),
             * soit exactement `out[i]` ; n'expose le canal que pour cls ≥ 4 (cls 1/2 non
             * requises par le corpus, `random` est déjà exact sans ligne dérivée). */
            if (alz_ps_escwr && cls >= 4u && ps_escwr_cls_on()) alz_ps_escwr[i] = out[i];
            if (delta >= 0x80u) flag ^= 1u;
            switch (cls) {
                case 1: ebx = alz_ps_t1[delta] + ((uint32_t)alz_ps_tnib[ebx & 0xfu] << 4); break;
                case 2: ebx = alz_ps_t1[delta] + ((ebp & 1u) << 4); break;
                case 3: ebx = alz_ps_t3[delta] + (ebp_m3 << 5); break;
                default: ebx = alz_ps_t1[delta] + ((ebp & 3u) << 4); break; /* cls>=4 */
            }
            ebp++;
            ebp_m3 = (ebp_m3 == 2u) ? 0u : (ebp_m3 + 1u);
        }
        }
    }
}

uint32_t alz_ps_class_sigma(uint32_t cls, const uint8_t *data, uint32_t n,
                            uint32_t default_inc, uint32_t cold_first,
                            const uint32_t *best_in,
                            uint32_t *percost, uint32_t *pnpos)
{
    uint32_t *ctxs;
    alz_arena2d_t *a;
    uint32_t i, acc = 0u;

    ctxs = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)n);
    a    = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!ctxs || !a) { free(ctxs); free(a); if (pnpos) *pnpos = 0; return 0u; }

    alz_ps_gen_ctxs(cls, data, n, ctxs);
    alz_arena2d_init(a, (uint16_t)default_inc);

    for (i = 0; i < n; i++) {
        uint32_t ctx = ctxs[i];
        uint32_t row = ctx >> 8;
        uint32_t delta = ctx & 0xffu;
        uint32_t T, f, c, inc, cs;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u; /* garde */
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];

        if (f != 0u) {                                   /* --- WARM : 1 terme --- */
            cs = alz_score_proba_to_cost((f << 14) / T);
        } else {                                         /* --- COLD : 2 termes --- */
            cs = alz_score_proba_to_cost(cold_first)
               + alz_score_proba_to_cost((c << 14) / T);
        }
        acc += cs;
        if (percost) percost[i] = cs;

        if (best_in && acc > *best_in) {                 /* abandon précoce (0x4149c2) */
            if (pnpos) *pnpos = i + 1u;
            free(ctxs); free(a);
            return acc;
        }

        /* mise à jour d'arène (identique à alz_arena2d_score) */
        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE)
            alz_arena2d_rescale(a, row);
        (void)delta;
    }
    if (pnpos) *pnpos = n;
    free(ctxs); free(a);
    return acc;
}

uint32_t alz_ps_block_argmin(const uint8_t *data, uint32_t n,
                             uint32_t default_inc, uint32_t cold_first,
                             uint32_t *sigma_out)
{
    uint32_t cls, best = 0xffffffffu, winner = 0u;
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++) {
        uint32_t bi = best, s;
        s = alz_ps_class_sigma(cls, data, n, default_inc, cold_first,
                               (cls == 0u) ? NULL : &bi, NULL, NULL);
        if (sigma_out) sigma_out[cls] = s;
        if (s < best) { best = s; winner = cls; }
    }
    return winner;
}

/* ============================================================================
 * [A5.1 it2] Chemin PERSISTANT : machine ctx + arène threadées cross-blocs.
 * Voir alz_parse_score.h pour la spécification (gated, lecture seule).
 * ========================================================================== */

/* Un pas de la machine ctx : renvoie ctx=(row<<8)|delta pour la position ABSOLUE
 * abs dans le buffer global g, et avance st-état (ebx/flag/ebp). cls0 = ordre-2 direct. */
static inline uint32_t ps_ctx_step(uint32_t cls, const uint8_t *g, uint32_t abs,
                                   uint32_t *ebx, uint32_t *flag, uint32_t *ebp)
{
    if (cls == 0u) {
        uint32_t b  = g[abs];
        uint32_t p1 = rb(g, abs, 1);
        uint32_t p2 = rb(g, abs, 2);
        uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
        (*ebp)++;
        return (row << 8) | b;
    } else {
        uint32_t b = g[abs];
        uint32_t rolling = rb(g, abs, 1) | (rb(g, abs, 2) << 8) |
                           (rb(g, abs, 3) << 16) | (rb(g, abs, 4) << 24);
        uint32_t esc = alz_ps_escape[cls];
        uint32_t ctx   = (rolling >> esc) & 0xffu;
        uint32_t e = *ebx, f = *flag, p = *ebp;
        uint32_t delta = f ? ((ctx + 0x100u - b) & 0xffu) : ((b + 0x100u - ctx) & 0xffu);
        uint32_t out = (e << 8) | delta;
        if (delta >= 0x80u) f ^= 1u;
        switch (cls) {
            case 1: e = alz_ps_t1[delta] + ((uint32_t)alz_ps_tnib[e & 0xfu] << 4); break;
            case 2: e = alz_ps_t1[delta] + ((p & 1u) << 4); break;
            case 3: e = alz_ps_t3[delta] + ((p % 3u) << 5); break;
            default: e = alz_ps_t1[delta] + ((p & 3u) << 4); break; /* cls>=4 */
        }
        p++;
        *ebx = e; *flag = f; *ebp = p;
        return out;
    }
}

/* [a5-e briquet 1] wrappers d'état machine pour le scan de couverture legacy. */
uint32_t alz_ps_ctx_step_run(uint32_t cls, const uint8_t *g, uint32_t abs, uint32_t *mm)
{
    return ps_ctx_step(cls, g, abs, &mm[0], &mm[1], &mm[2]);
}

uint32_t alz_ps_ctx_scan3(const uint8_t *g, uint32_t abs, uint32_t *mm, uint32_t delta)
{
    uint32_t b     = g[abs];                    /* roule ctx machine (comme cls3) */
    uint32_t roll  = rb(g, abs, 1) | (rb(g, abs, 2) << 8) |
                     (rb(g, abs, 3) << 16) | (rb(g, abs, 4) << 24);
    uint32_t ctx   = (roll >> alz_ps_escape[3]) & 0xffu;
    uint32_t e = mm[0], f = mm[1], p = mm[2];
    uint32_t d;
    uint32_t out;
    (void)b; (void)ctx;                          /* le scan fournit son propre delta */
    d   = delta & 0xffu;
    out = (e << 8) | d;                          /* ligne AVANT lecture (miroir) */
    if (d >= 0x80u) f ^= 1u;
    e = alz_ps_t3[d] + ((p % 3u) << 5);          /* machine avance sur delta-scan */
    p++;
    mm[0] = e; mm[1] = f; mm[2] = p;
    return out;
}

/* [GATED UHA_A3_ESCFEED, DEFAUT-OFF, lane ALZ -m3] MODELE D'ESCAPE cls3 (ligne
 * 0x402+cls, registre m9 ligne 1029) : 256 symboles, freq init 4, total init 1024,
 * +16 par ÉVÉNEMENT FROID du scan, appliqué AUX FRONTIÈRES de bloc (la table est
 * FIGÉE dans le bloc : m9, 29/29 Fenwick = 2528). Premier terme du coût froid =
 * LUT[FLOOR(f<<14/tot)] (le second, LUT[(counter<<14)/T], est déjà posé).
 * État bloc1 attendu = 4+16*n, total 1024+16*94 (n = compte froid du bloc 0). */
static uint16_t g_escf[256];
static uint32_t g_esct = 1024u;
static uint32_t g_esccnt[256];
static int      g_esc_on = 0;
static int      g_esc_count = 0;   /* comptage armé UNIQUEMENT sur la passe de SORTIE */
static void ps_esc_lazy(void)
{
}
static uint32_t ps_esc_term(uint32_t sym)
{
    uint32_t p;
    sym &= 0xffu;
    p = g_esct ? (uint32_t)((((uint64_t) g_escf[sym]) << 14) / g_esct) : (ALZ_SCORE_CUM_N - 1u);
    if (p >= ALZ_SCORE_CUM_N) p = ALZ_SCORE_CUM_N - 1u;
    if (g_esc_count) g_esccnt[sym]++;
    return alz_score_proba_to_cost(p);
}
/* Accesseurs exportés (lane ALZ -m3) : terme froid d'escape + frontière de bloc,
 * pour le canal LIVE-WALK de alz.c (qui remplit g_lmin_dens en mode banque). */
static void ps_esc_boundary(void);
uint32_t alz_ps_esc_coldcost(uint32_t sym)
{
    uint32_t cv;
    int save;
    ps_esc_lazy();
    if (!g_esc_on) return 0u;
    save = g_esc_count; g_esc_count = 1;
    cv = ps_esc_term(sym);
    g_esc_count = save;
    return cv;
}
void alz_ps_esc_boundary_pub(void) { ps_esc_boundary(); }

static void ps_esc_boundary(void)
{
    uint32_t na = 0u;
    int s;
    ps_esc_lazy();
    if (!g_esc_on) return;
    for (s = 0; s < 256; s++) na += g_esccnt[s];
    for (s = 0; s < 256; s++) { g_escf[s] = (uint16_t)(g_escf[s] + 16u * g_esccnt[s]); g_esccnt[s] = 0u; }
    g_esct += 16u * na;
}

uint32_t alz_ps_class_sigma_carry(alz_ps_carry_t *st, uint32_t cls,
                                  const uint8_t *g, uint32_t base, uint32_t n,
                                  uint32_t default_inc, uint32_t cold_first,
                                  const uint32_t *best_in,
                                  uint32_t *percost, uint32_t *pnpos)
{
    alz_arena2d_t *a;
    uint32_t i, acc = 0u;

    if (!st->arena) {
        st->arena = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
        if (!st->arena) { if (pnpos) *pnpos = 0; return 0u; }
        alz_arena2d_init(st->arena, (uint16_t)default_inc);
    }
    a = st->arena;

    for (i = 0; i < n; i++) {
        uint32_t ctx = ps_ctx_step(cls, g, base + i, &st->ebx, &st->flag, &st->ebp);
        uint32_t row, delta, T, f, c, inc, cs;
        /* [GATED UHA_PHASEFIX] corrige le terme de phase du row cls3 = (abs+2)%3. */
        if (g_ps_phasefix && cls == 3u) {
            uint32_t e = ctx >> 8;
            uint32_t pbase = base + i;
            e = (e & 0x1fu) + (((pbase + 2u) % 3u) << 5);
            ctx = (e << 8) | (ctx & 0xffu);
        }
        row = ctx >> 8;
        delta = ctx & 0xffu;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];

        if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / T);
        else {
            ps_esc_lazy();
            cs = (g_esc_on ? ps_esc_term(delta) : alz_score_proba_to_cost(cold_first))
                   + alz_score_proba_to_cost((c << 14) / T);
        }
        if (g_adump && cls == 3u)
            fprintf(g_adump, "%u\t%u\t%u\t%u\t%u\t%u\n",
                    (unsigned)(base + i), (unsigned)row, (unsigned)f,
                    (unsigned)T, (unsigned)c, (unsigned)cs);
        acc += cs;
        if (percost) percost[i] = cs;

        if (best_in && acc > *best_in) {          /* abandon : machine avancée, arène NON entraînée */
            if (pnpos) *pnpos = i + 1u;
            return acc;
        }
        /* [GATED UHA_WLEARNLIT] skip la MUTATION d'arène hors des positions masquées
         * (le coût/percost ci-dessus reste calculé pour TOUTES les positions). */
        if (g_ps_learn_mask && !g_ps_learn_mask[base + i]) continue;

        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE)
            alz_arena2d_rescale(a, row);
        (void)delta;
    }
    if (pnpos) *pnpos = n;
    return acc;
}

uint32_t alz_ps_block_argmin_carry(alz_ps_carry_t *st, uint32_t seed_cls,
                                   const uint8_t *g, uint32_t base, uint32_t n,
                                   uint32_t default_inc, uint32_t cold_first,
                                   uint32_t *sigma_out, uint32_t *npos_out)
{
    uint32_t order[ALZ_PS_NCLASS];
    uint32_t k, cls, best = 0xffffffffu, winner = 0u, cnt = 0u;

    /* seed_cls en premier (best_in=NULL, jamais abandonné), puis les autres en ordre croissant. */
    order[cnt++] = seed_cls;
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++)
        if (cls != seed_cls) order[cnt++] = cls;

    for (k = 0; k < cnt; k++) {
        uint32_t c = order[k];
        uint32_t bi = best, s, np = 0;
        s = alz_ps_class_sigma_carry(&st[c], c, g, base, n, default_inc, cold_first,
                                     (k == 0u) ? NULL : &bi, NULL, &np);
        if (sigma_out) sigma_out[c] = s;
        if (npos_out)  npos_out[c]  = np;
        if (s < best) { best = s; winner = c; }
    }
    return winner;
}

void alz_ps_carry_free(alz_ps_carry_t *st)
{
    uint32_t c;
    for (c = 0; c < ALZ_PS_NCLASS; c++) {
        free(st[c].arena);
        st[c].arena = NULL;
    }
}

/* ---- Self-test : image.raw bloc1, Σ_cls from-scratch == oracles + argmin cls3 (§13.141). ---- */
int alz_parse_score_selftest(void)
{
#include "alz_parse_score_vecs.inc"   /* alz_ps_testdata[12544] */
    static const uint32_t oracle[ALZ_PS_NCLASS] = {
        0x086c23ecu, 0x04a50d90u, 0x04a521c4u, 0x046a185cu, 0x046a4476u
    };
    uint32_t sigma[ALZ_PS_NCLASS];
    uint32_t n = (uint32_t)(sizeof(alz_ps_testdata) / sizeof(alz_ps_testdata[0]));
    uint32_t winner, cls;
    int fails = 0;

    winner = alz_ps_block_argmin(alz_ps_testdata, n, 32u, ALZ_PS_COLD0, sigma);
    for (cls = 0; cls < ALZ_PS_NCLASS; cls++) {
        if (sigma[cls] != oracle[cls]) {
            printf("[PARSE-TEST] FAIL cls%u: got 0x%08x exp 0x%08x\n",
                   cls, sigma[cls], oracle[cls]);
            fails++;
        }
    }
    if (winner != 3u) { printf("[PARSE-TEST] FAIL argmin: winner cls%u exp cls3\n", winner); fails++; }

    if (fails == 0)
        printf("[PARSE-TEST] scoreur 0x414630 from-plain OK (%u/%u classes == oracle ; argmin=cls3)\n",
               (unsigned)ALZ_PS_NCLASS, (unsigned)ALZ_PS_NCLASS);
    else
        printf("[PARSE-TEST] %d divergence(s)\n", fails);
    return fails ? 1 : 0;
}

/* ---- [A5.1 it1] Multitest par blocs (gated UHA_PARSEMULTI=<image.raw>) : rolle P1
 * (alz_ps_block_argmin, INIT COLD = hypothèse nulle « pas de persistance ») sur les
 * 6 blocs de scoring d'image.raw et compare aux Σ_cls ORACLE (blockcost_perclass.log,
 * §13.118/§13.165). Objectif : (a) confirmer gagnant cls3 robuste, (b) quantifier
 * l'impact de la graine inter-blocs. Lecture seule, n'affecte PAS l'encodage. ---- */
static const uint32_t am_blk_pos[6] = {0x0000u, 0x3100u, 0x620cu, 0x931cu, 0xc4ffu, 0xff00u};
static const uint32_t am_blk_len[6] = {0x3100u, 0x3100u, 0x3100u, 0x3100u, 0x3a01u, 0x100u};
static const uint32_t am_blk_oracle[6][ALZ_PS_NCLASS] = {
    { 0x086c23ecu, 0x04a50d90u, 0x04a521c4u, 0x046a185cu, 0x046a4476u },
    { 0x0433d5bbu, 0x0433c900u, 0x0433cbb1u, 0x0433c605u, 0x0433ce95u },
    { 0x042d808bu, 0x042d7932u, 0x042d8158u, 0x042d7095u, 0x042d93aau },
    { 0x042d3e19u, 0x042d3708u, 0x042eb482u, 0x042d2ac8u, 0x042d32f3u },
    { 0x04f184d0u, 0x04f1aac0u, 0x04f1a865u, 0x04f17ab6u, 0x04f1a7f0u },
    { 0x001647c0u, 0x0015d3a5u, 0x0015eb5bu, 0x0015d16cu, 0x0015f426u },
};
int alz_parse_score_multitest(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    if (!fp) { printf("[PARSE-MULTI] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI] read fail\n"); return 1; }
    fclose(fp);
    printf("[PARSE-MULTI] %s sz=%ld, 6 blocs, init COLD (hyp. nulle non-persistance)\n", path, sz);
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS];
        uint32_t pos = am_blk_pos[b], len = am_blk_len[b], w;
        int exact = 1, wsmatch;
        if ((long)(pos + len) > sz) { printf("  blk%d HORS-FICHIER\n", b); free(buf); return 1; }
        w = alz_ps_block_argmin(buf + pos, len, 32u, ALZ_PS_COLD0, sigma);
        wsmatch = (w == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d pos=0x%05x len=0x%05x : gagnant=cls%u (%s cls3) | "
               "gotallo=%s | Σ[0..4]=",
               b, pos, len, w, wsmatch ? "==" : "!=", exact ? "==ORACLE" : ">=1 écart");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            printf(" %s0x%08x%s", k ? "" : "", sigma[k], k < 4 ? "" : "");
        printf(" vs oracle:");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++)
            printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI] gagnant==cls3 : %d/6 blocs | Σ 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    free(buf);
    return 0;
}

/* ---- [A5.1 it2] Multitest PERSISTANCE (gated UHA_PARSEMULTI2=<image.raw>) : même découpage
 * que it1 MAIS arènes + machine ctx threadées d'un bloc à l'autre (vainqueur scoré en premier,
 * contexte global, ebp absolu). Objectif : vérifier convergence Σ_cls -> oracle (cible exact).
 * Lecture seule, n'affecte PAS l'encodage. ---- */
static int s_pm2_machine_reset = 0;
int alz_parse_score_multitest2(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    alz_ps_carry_t st[ALZ_PS_NCLASS];
    uint32_t seed_cls = 0u;
    if (!fp) { printf("[PARSE-MULTI2] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI2] read fail\n"); return 1; }
    fclose(fp);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        st[k].arena = NULL; st[k].ebx = 0; st[k].flag = 0; st[k].ebp = 0;
    }
    printf("[PARSE-MULTI2] %s sz=%ld, 6 blocs, PERSISTANCE arène+machine (vainqueur d'abord)\n", path, sz);
    s_pm2_machine_reset = 0;
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS], npos[ALZ_PS_NCLASS];
        uint32_t base = am_blk_pos[b], len = am_blk_len[b], w;
        int exact = 1, wsmatch;
        double dev = 0.0;
        if ((long)(base + len) > sz) { printf("  blk%d HORS-FICHIER\n", b); free(buf); return 1; }
        if (s_pm2_machine_reset && b > 0) {
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) { st[k].ebx = 0; st[k].flag = 0; st[k].ebp = 0; }
        }
        w = alz_ps_block_argmin_carry(st, seed_cls, buf, base, len, 32u, ALZ_PS_COLD0, sigma, npos);
        seed_cls = w;
        wsmatch = (w == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
            if (am_blk_oracle[b][k])
                dev += (double)sigma[k] / (double)am_blk_oracle[b][k] - 1.0;
        }
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d base=0x%05x len=0x%05x seed=cls%u : gagnant=cls%u (%s cls3) | %s | "
               "dévΣ moy=%+.2f%% | npos=", b, base, len, w, w,
               wsmatch ? "==" : "!=", exact ? "==ORACLE" : ">=1 écart", dev * 20.0);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" %u", npos[k]);
        printf("\n      Σ   =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", sigma[k]);
        printf("\n      orc =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI2] gagnant==cls3 : %d/6 blocs | \u03a3 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    alz_ps_carry_free(st);
    free(buf);
    return 0;
}

/* ============================================================================
 * [A5.1 it3] Modelisation SNAPSHOT : a chaque appel de scoring 0x414630, la classe
 * copie l'arène-SNAPSHOT courante dans une arène LIVE jetable (§13.13/14 « copie
 * snapshot->live a chaque appel, rep movsb ») ; l'entrainement d'une classe ne pollue
 * DONC PAS les autres classes du bloc. Le snapshot n'avance QU'UNE SEULE FOIS par bloc,
 * entraine sur le flux de la classe GAGNANTE (argmin). La machine ctx (ebx/flag/ebp)
 * reste GLOBALE par classe et avance de tout le bloc, abandon ou pas (from-plain).
 * C'est la granularity de persistance correcte attendue de a5-d3b. Lecture seule, gated.
 * ========================================================================== */

/* Score une classe sur un flux ctxs deja genere, dans l'arène a (m.a.j + rescale),
 * abandon optionnel contre *best_in. Retourne l'accunulateur 32 bits.
 * percost (optionnel, taille n) : y écrit le coût de CHAQUE position (cs). */
/* [GATED UHA_A3_CELLDUMP=<f>, LECTURE SEULE] base absolue du dump cellule (posn ée
 * par le producteur snapshot avant sa passe de re-score gagnante). */
static uint32_t g_ps_dumpbase = 0u;
static uint32_t g_ps_dumpn    = 0u;

static uint32_t ps_score_ctxs(alz_arena2d_t *a, const uint32_t *ctxs, uint32_t n,
                              uint32_t default_inc, uint32_t cold_first,
                              const uint32_t *best_in, uint32_t *pnpos,
                              uint32_t *percost)
{
    uint32_t i, acc = 0u;
    (void)default_inc;
    for (i = 0u; i < n; i++) {
        uint32_t ctx = ctxs[i];
        uint32_t row = ctx >> 8;
        uint32_t T, f, c, inc, cs;
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        T   = a->total[row];
        f   = a->freq[ctx];
        c   = a->counter[row];
        inc = a->promo[row];
        if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / (T ? T : 1u));
        else {
            ps_esc_lazy();
            cs = (g_esc_on ? ps_esc_term(ctx & 0xffu) : alz_score_proba_to_cost(cold_first))
                   + alz_score_proba_to_cost((c << 14) / (T ? T : 1u));
        }
        acc += cs;
        if (percost) percost[i] = cs;
        if (best_in && acc > *best_in) { if (pnpos) *pnpos = i + 1u; return acc; }
        if (f == 0u) {
            a->freq[ctx]    = (uint16_t)inc;
            a->counter[row] = (uint16_t)(c + inc);
            a->total[row]   = (uint16_t)(T + 2u * inc);
        } else {
            a->freq[ctx]    = (uint16_t)(f + inc);
            a->total[row]   = (uint16_t)(T + inc);
        }
        if (a->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, row);
    }
    if (pnpos) *pnpos = n;
    return acc;
}

/* --- briques du producteur per-position argmin (§13.729, UHA_PERPOS) ------------
 * coût READ-ONLY d'un ctx dans l'arène (miroir exact de la branche coût de
 * ps_score_ctxs, SANS mutation) ; et ps_learn = MAJ d'arène (mutation) miroir de
 * ps_score_ctxs. Indexation f=a->freq[ctx] (ctx non clampé) / total=row clampé,
 * identique à ps_score_ctxs pour rester conforme au modèle validé. */
static uint32_t ps_cost_of(const alz_arena2d_t *a, uint32_t ctx, uint32_t cold_first)
{
    uint32_t row = ctx >> 8, T, f, c, cs;
    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
    T = a->total[row]; f = a->freq[ctx]; c = a->counter[row];
    if (f != 0u) cs = alz_score_proba_to_cost((f << 14) / T);
    else         cs = alz_score_proba_to_cost(cold_first)
                        + alz_score_proba_to_cost((c << 14) / T);
    return cs;
}
static void ps_learn(alz_arena2d_t *a, uint32_t ctx)
{
    uint32_t row = ctx >> 8, T, f, c, inc;
    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
    T = a->total[row]; f = a->freq[ctx]; c = a->counter[row]; inc = a->promo[row];
    if (f == 0u) {
        a->freq[ctx]    = (uint16_t)inc;
        a->counter[row] = (uint16_t)(c + inc);
        a->total[row]   = (uint16_t)(T + 2u * inc);
    } else {
        a->freq[ctx]    = (uint16_t)(f + inc);
        a->total[row]   = (uint16_t)(T + inc);
    }
    if (!g_ps_no_inline_rescale && a->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, row);
}


int alz_parse_score_multitest3(const char *path)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int b, k, winok = 0, sigma_ok = 0;
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];   /* ebx, flag, ebp par classe */
    uint32_t seed_cls = 0u;
    uint32_t maxlen;
    if (!fp) { printf("[PARSE-MULTI3] open fail %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); sz = ftell(fp); rewind(fp);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); printf("[PARSE-MULTI3] read fail\n"); return 1; }
    fclose(fp);
    snap = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!snap || !live) { free(buf); free(snap); free(live); printf("[PARSE-MULTI3] oom\n"); return 1; }
    alz_arena2d_init(snap, (uint16_t)32u);
    maxlen = 0u;
    for (b = 0; b < 6; b++) if (am_blk_len[b] > maxlen) maxlen = am_blk_len[b];
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        ctxs[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)maxlen);
    }
    printf("[PARSE-MULTI3] %s sz=%ld, 6 blocs, SNAPSHOT (copie per-classe, snap avance par gagnant)\n", path, sz);
    for (b = 0; b < 6; b++) {
        uint32_t sigma[ALZ_PS_NCLASS], npos[ALZ_PS_NCLASS];
        uint32_t base = am_blk_pos[b], len = am_blk_len[b], order[ALZ_PS_NCLASS];
        uint32_t best = 0xffffffffu, winner = 0u, cnt = 0u, c;
        int exact = 1, wsmatch;
        double dev = 0.0;
        if ((long)(base + len) > sz) { printf("  blk%d HORS-FICHIER\n", b); break; }
        /* (1) generer les flux ctxs par classe sur TOUT le bloc (machine avance pleine). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++) {
            uint32_t i;
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, buf, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        }
        /* (2) ordre : seed (= gagnant bloc precedent) d'abord, puis ascending. */
        order[cnt++] = seed_cls;
        for (c = 0u; c < ALZ_PS_NCLASS; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) chaque classe copie le snapshot dans live, score, jette live. */
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cc = order[(uint32_t)k], s, np = 0;
            *live = *snap;
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, &np, NULL);
            sigma[cc] = s; npos[cc] = np;
            if (s < best) { best = s; winner = cc; }
        }
        /* (4) avancer le snapshot en entrainant le flux de la gagnante (plein).
         * Override env UHA_PM3ADV=<0..4> pour tester quelle classe alimente le snapshot. */
        {
            ps_score_ctxs(snap, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        }
        seed_cls = winner;
        wsmatch = (winner == 3u);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            if (sigma[k] != am_blk_oracle[b][k]) exact = 0;
            if (am_blk_oracle[b][k]) dev += (double)sigma[k] / (double)am_blk_oracle[b][k] - 1.0;
        }
        if (wsmatch) winok++;
        if (exact) sigma_ok++;
        printf("  blk%d base=0x%05x len=0x%05x seed=cls%u : gagnant=cls%u (%s cls3) | %s | dev\u03a3 moy=%+.3f%% | npos=",
               b, base, len, winner, winner, wsmatch ? "==" : "!=",
               exact ? "==ORACLE" : ">=1 ecart", dev * 20.0);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" %u", npos[k]);
        printf("\n      \u03a3   =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", sigma[k]);
        printf("\n      orc =");
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) printf(" 0x%08x", am_blk_oracle[b][k]);
        printf("\n");
    }
    printf("[PARSE-MULTI3] gagnant==cls3 : %d/6 blocs | \u03a3 5/5 exacts : %d/6 blocs\n", winok, sigma_ok);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(snap); free(live); free(buf);
    return (sigma_ok == 6) ? 0 : 2;
}

/* ==========================================================================
 * [cost-literal-live SNAPSHOT dens — GATED par l'appelant alz.c UHA_COSTSNAP]
 * Reproduit la granularity SNAPSHOT de MULTI3 (it3) mais remplit `out[base+i]`
 * du COÛT PAR POSITION de la classe GAGNANTE (argmin) du bloc, pour alimenter
 * g_lmin_dens d'un coût d'arène de PARSE position-indexé PASSIF fidèle au legacy
 * (validé ±0,4 % sous oracle §t9-sim-arena), au lieu du cold0-par-bloc (24 %).
 * Machine ctx (ebx/flag/ebp) threadée GLOBALEMENT par classe via ps_ctx_step.
 * Pur : n'affecte aucune arène globale, buffers locaux. Retourne 0 OK, <0 erreur. */
/* [GATED UHA_SNAPINC=<n>, DEFAUT-OFF] Fixe le inc (promo) des LIGNES d'une arène.
 * 0 = ne touche pas (comportement actuel, promo issu d'alz_arena2d_init). Non-régressif. */
static void ps_set_promo_all(alz_arena2d_t *a, uint32_t inc)
{
    uint32_t r;
    if (!a || inc == 0u) return;
    for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++) a->promo[r] = (uint16_t)inc;
}

int alz_ps_snapshot_percost(const uint8_t *g, uint32_t usize,
                            const uint32_t *blkpos, const uint32_t *blklen,
                            int nblk, uint32_t *out)
{
    static alz_arena2d_t *s_snap_ar = NULL, *s_live_ar = NULL;
    static uint32_t *s_snap_ctxs[ALZ_PS_NCLASS] = {NULL, NULL, NULL, NULL, NULL};
    static uint32_t  s_snap_ctx_cap[ALZ_PS_NCLASS] = {0u, 0u, 0u, 0u, 0u};
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t seed_cls = 0u, maxlen = 0u, need;
    uint32_t nclass = (uha_get_nomm() == 1) ? 1u : ALZ_PS_NCLASS;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    alz_ps_snapwin_n = 0;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    if (!s_snap_ar) s_snap_ar = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!s_live_ar) s_live_ar = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    snap = s_snap_ar;
    live = s_live_ar;
    if (!snap || !live) return -1;
    alz_arena2d_init(snap, (uint16_t)32u);
    ps_set_promo_all(snap, 0u);
    need = maxlen ? maxlen : 1u;
    for (k = 0; k < (int)nclass; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        if (!s_snap_ctxs[k] || s_snap_ctx_cap[k] < need) {
            uint32_t *nb = (uint32_t *)realloc(s_snap_ctxs[k], sizeof(uint32_t) * (size_t)need);
            if (!nb) return -1;
            s_snap_ctxs[k] = nb;
            s_snap_ctx_cap[k] = need;
        }
        ctxs[k] = s_snap_ctxs[k];
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], order[ALZ_PS_NCLASS];
        uint32_t best = 0xffffffffu, winner = 0u, cnt = 0u, c, np = 0;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        for (c = 0u; c < nclass; c++) {
            uint32_t i;
            for (i = 0u; i < len; i++) {
                uint32_t cx = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
                ctxs[c][i] = cx;
            }
        }
        if (seed_cls >= nclass) seed_cls = 0u;
        order[cnt++] = seed_cls;
        for (c = 0u; c < nclass; c++) if (c != seed_cls) order[cnt++] = c;
        for (k = 0; k < (int)nclass; k++) {
            uint32_t cc = order[(uint32_t)k], s;
            *live = *snap;
            ps_set_promo_all(live, 32u);
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, &np, NULL);
            if (s < best) { best = s; winner = cc; }
        }
        if (alz_ps_snapwin_n < ALZ_PS_SNAPWIN_MAX)
            alz_ps_snapwin_blk[alz_ps_snapwin_n++] = (int) winner;
        *live = *snap;
        ps_set_promo_all(live, 32u);
        g_ps_dumpbase = base; g_ps_dumpn = len;
        ps_score_ctxs(live, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
        ps_score_ctxs(snap, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        seed_cls = winner;
    }
    return 0;
}

/* ==========================================================================
 * [§13.729 GATED UHA_PERPOS, DEFAUT-OFF] Producteur dens per-POSITION argmin.
 * Le legacy sélectionne LA classe par POSITION (argmin 5 classes 0x413ea0), pas
 * par bloc. Modèle : UNE arène globale continue + machines ctx threadées par classe
 * ; à chaque position i, coût READ-ONLY des 5 ctx (par classe) dans l'arène,
 * gagnant = argmin, dens[i] = min, PUIS apprentissage (ps_learn) du ctx du gagnant
 * SEULEMENT. Apprentissage DENSE (toutes positions) dans cette 1ʳᵉ variante (la
 * sparse par-littéral-émis reste à coupler au parse). Pur, buffers locaux. 0 OK <0 err. */
int alz_ps_perpos_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, uint32_t *out)
{
    alz_arena2d_t *a;
    uint32_t *ctxs[ALZ_PS_NCLASS];
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t maxlen = 0u;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    a = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!a) return -1;
    alz_arena2d_init(a, (uint16_t)32u);
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        mm[k][0] = mm[k][1] = mm[k][2] = 0u;
        ctxs[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
        if (!ctxs[k]) { int j; for (j = 0; j < k; j++) free(ctxs[j]); free(a); return -1; }
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i, c;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) générer le flux ctx de CHAQUE classe sur tout le bloc (machines avancent pleine). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++)
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        /* (2) par position : argmin des 5 coûts de classe dans l'arène courante ;
         *     dens = min ; puis apprendre le ctx du gagnant (mutates arène). */
        for (i = 0u; i < len; i++) {
            uint32_t best = 0xffffffffu, win = 0u, cs;
            for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                cs = ps_cost_of(a, ctxs[c][i], ALZ_PS_COLD0);
                if (cs < best) { best = cs; win = c; }
            }
            out[base + i] = best;
            ps_learn(a, ctxs[win][i]);
        }
    }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(a);
    return 0;
}

/* [GATED UHA_SNAPWALK, VALIDATION lecture-seule] Producteur `dens` fidele au modele
 * DEUX-ARENES (memoire d2229f89, §13.270/271) : le snapshot PERSISTE n'avance qu'aux
 * positions LITTERAL EMISES (is_lit[abs]==1) a inc=16 (pass EMISSION sparse), PAS dense ;
 * dens[pos] = scoreur DENSE (copie live du snapshot, inc=32) au flux cls3 (gagnant
 * universel §13.593). Machine ctx cls3 GLOBALE threadee cross-blocs. is_lit taille
 * usize (0/1). Retourne 0 OK, <0 erreur. NUL effet sur l'encodage (chemin gated). */
int alz_ps_snapshot_percost_sparse(const uint8_t *g, uint32_t usize,
                                   const uint32_t *blkpos, const uint32_t *blklen,
                                   int nblk, const uint8_t *is_lit, uint32_t *out)
{
    alz_arena2d_t *snap, *live;
    uint32_t *ctx;
    uint32_t mm[3] = {0u, 0u, 0u};
    uint32_t maxlen = 0u;
    int b;

    if (!g || !blkpos || !blklen || !is_lit || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    snap = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    ctx  = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!snap || !live || !ctx) { free(snap); free(live); free(ctx); return -1; }
    alz_arena2d_init(snap, (uint16_t)16u);   /* SNAPSHOT apprend a inc=16 (§13.271) */
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) flux ctx cls3 sur TOUT le bloc (machine GLOBALE avance pleine). */
        for (i = 0u; i < len; i++)
            ctx[i] = ps_ctx_step(3u, g, base + i, &mm[0], &mm[1], &mm[2]);
        /* (2) dens[pos] = scoreur dense (live copie snap, inc=32) ecrit dans out. */
        *live = *snap;
        ps_set_promo_all(live, 32u);
        ps_score_ctxs(live, ctx, len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
        /* (3) avancer le SNAPSHOT sur les seules positions LITTERAL émes, inc=16. */
        for (i = 0u; i < len; i++) {
            uint32_t c = ctx[i], row = c >> 8;
            if (!is_lit[base + i]) continue;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            (void) alz_arena2d_score(snap, row, c & 0xffu, NULL);
        }
    }
    free(snap); free(live); free(ctx);
    return 0;
}

/* ==========================================================================
 * [§13.723 GATED UHA_EMIPROD, DEFAUT-OFF, FRONTIÈRE emission-walk-producer]
 * Modèle FIDÈLE décodé : la pré-passe `0x414630` est READ-ONLY vs master (restore
 * `rep movs` master→working par appel, aucun store vers master) ; le master est
 * avancé UNIQUEMENT par le LIVE `0x415ab0` qui APPREND par LITTÉRAL ÉMIS (sparse).
 * Producteur : par bloc, W = copie(master M) puis scan DENSE intra-bloc cls3
 * (score+learn dans W) ⟹ `out[i]` = coût figé lu par le décideur ; PUIS avancer M
 * en n'apprenant qu'aux positions `is_lit` du bloc (rien sur les matchs). Machine
 * cls3 relative-bloc (graine ebp=1) ALIGNÉE entre W (lecture) et M (écriture) pour
 * que le carry tombe dans les MÊMES cellules. Pur, buffers locaux. 0 OK, <0 erreur. */

/* [GATED UHA_CM_WIRE, §13.796] delta/base section-relatifs (sentinelle 0x80 avant `base`). */
static int32_t ps_q(const uint8_t *g, long base, long k)
{
    if (k < base) return 0;
    return (int32_t)g[k] - ((k >= base + 1) ? (int32_t)g[k - 1] : 0x80);
}
static int32_t ps_b(const uint8_t *g, long base, long k)
{
    if (k < base) return 0;
    return (int32_t)g[k] - 0x80;
}

int alz_ps_livewalk_cm(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                       uint32_t from, uint32_t *out)
{
    (void)g; (void)usize; (void)is_lit; (void)from; (void)out;
    return 0;
}

int alz_ps_livewalk_dual(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                         uint32_t from, uint32_t *out)
{
    (void)g; (void)usize; (void)is_lit; (void)from; (void)out;
    return 0;
}

/* [GATED UHA_CM_WIRE, §13.798] Moteur CM persistant INCREMENTAL pour l'arène LIVE
 * (acclive_event_once → alz_arena_c4). Reproduit la loi validée cm_closed (sym 100 %)
 * position par position (rc dense), pour une section donnée (sec_start). Le caller
 * (acclive) appelle reset à chaque frontière de section et symrow pour chaque pos.
 * Retourne row_abs = row_base + aff et sym = dirflip(value−P). État module-static. */
typedef struct {
    int      started;
    uint32_t done;        /* dernier rc avancé (inclus) */
    long     sec;         /* début de section courant */
    alz_cm_learner L; alz_arena A; alz_arb R;
    uint32_t rf70, rf74, rf78; int rflag, last_prev_idx; int32_t prev_rh;
    uint32_t last_sym, last_aff;
    /* [GATED UHA_A3_CPRED, défaut-OFF, §A3 tour 37] prédiction du pas PRÉCÉDENT : c'est elle
     * que le sélecteur de classe retranche (`*0x45ecbf`, écrite au pas i-1), alors que le proxy
     * historique réutilise `Pcur` du pas courant. N'a d'effet que si la porte est ON. */
    uint32_t prev_pred;
} ps_cmlive_t;
static ps_cmlive_t s_cml = {0};
static const uint32_t PS_MASKW[6] = {127u,127u,127u,127u,7u,3u}; /* tbl 0x437af8/idx */

void alz_ps_cmlive_reset(uint32_t sec_start)
{
    memset(&s_cml, 0, sizeof s_cml);
    alz_arena_init(&s_cml.A);
    alz_arb_init(&s_cml.R);
    s_cml.rf70 = s_cml.rf74 = s_cml.rf78 = 0xffffffffu;
    s_cml.prev_pred = 0u;
    s_cml.sec = (long)sec_start;
    if (sec_start == 0u)
        s_cml.done = 0xFFFFFFFFu;          /* done+1 == 0 : premier pas = g[0] */
    else
        s_cml.done = sec_start > 0u ? sec_start - 1u : 0u;
    s_cml.started = 1;
}

static void ps_cmlive_step(const uint8_t *g, uint32_t k)
{
    long base = s_cml.sec;
    uint32_t i = k - (uint32_t)base;
    uint8_t b_cur   = g[k];
    uint8_t b_prev  = (i >= 1u) ? g[k - 1u] : 0x80u;
    uint8_t b_prev2 = (i >= 2u) ? g[k - 2u] : 0x80u;
    int32_t base_i  = (int32_t)b_cur - 0x80;
    int32_t base_p1 = ps_b(g, base, (long)k - 1);
    int32_t base_p2 = ps_b(g, base, (long)k - 2);
    int32_t dl      = ps_q(g, base, (long)k);
    int32_t ref_prev = (int32_t)s_cml.A.ref, b8_prev = (int32_t)s_cml.A.b8;
    int32_t dr_ref = ps_q(g, base, (long)k - ref_prev);
    int32_t dr_b8  = ps_q(g, base, (long)k - b8_prev);
    int32_t rh = s_cml.prev_rh;
    uint32_t idx_gate = s_cml.R.idx;
    int entered = ((PS_MASKW[idx_gate % 6u] & k) == 0u);
    s_cml.A.line = k; alz_arena_step(&s_cml.A, b_cur, b_prev, entered);
    s_cml.R.line = k;
    alz_arb_predict(&s_cml.R, base_i, base_p1, base_p2, dl, dr_ref, dr_b8, rh);
    uint32_t idx_i = s_cml.R.idx;
    int32_t dr_learn = ps_q(g, base, (long)(k + 1) - (int32_t)s_cml.A.ref);
    alz_cm_learn_byte(&s_cml.L, b_cur, b_prev, b_prev2, dr_learn);
    uint32_t taps6[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
    taps6[0]=0; taps6[1]=vp1;
    taps6[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
    taps6[3]=(uint8_t)rh;
    taps6[4]=(uint8_t)s_cml.A.dr[(k-(uint32_t)ref_prev)&0x7fu];
    taps6[5]=(uint8_t)s_cml.A.dr[(k-(uint32_t)b8_prev )&0x7fu];
    /* [GATED UHA_A3_CPRED, défaut-OFF] niveaux :
     *   1 = w du pas précédent (sémantique `*0x45ecbf`)
     *   2 = 1 + sélection de tap par l'idx COURANT (`[0x44d4b0]` lu en 0x415831)
     *   3 = 2 + trace (pos, idx, taps, Pcur, Pprev, sym) sur stderr
     * ⚠ Les variantes 4 (`w` courant, 0 sur 2 pas) et 5 (tap3 = dot frais) ont été RETIRÉES au
     * tour 39 : elles ne compensaient qu'un défaut d'indexation (`UHA_A3_CPRED0`, g[0] sauté).
     * Une fois la marche calée sur `g[0]` (legacy `ebp=0`), le niveau 0 rend 32/32 deltas GT
     * (`m13_cand_image.log`) et la 1ʳᵉ ligne de `mixed`@30003 — voir OUT/A3_port_selecteur_plan.md
     * §3quater. La variante 5 était de plus une FUITE (le dot avait déjà vu l'octet). */
    int ip = s_cml.last_prev_idx;
    uint32_t Pcur = ((taps6[ip % 6u] & 0xffu) + ((ip >= 4) ? (uint32_t)vp1 : 0u) + 0x80u) & 0xffu;
    uint32_t Pprev = (i == 0u) ? 0u : Pcur;
    uint8_t d = (uint8_t)(b_cur - Pprev);
    uint8_t sym = s_cml.rflag ? (uint8_t)(0u-(uint32_t)d) : d;
    s_cml.rf70 = (s_cml.rf70<<8)|sym;
    s_cml.rf74 = (s_cml.rf74<<8) + ALZ_REG_T1[sym];
    s_cml.rf78 = (s_cml.rf78<<8) + ALZ_REG_T2[sym];
    if (sym >= 0x80u) s_cml.rflag ^= 1;
    s_cml.last_sym = sym;
    s_cml.last_aff = (s_cml.rf70==0u)?1u:(s_cml.rf74==0u)?2u:(s_cml.rf78==0u)?3u:0u;
    s_cml.last_prev_idx = (int)idx_i;
    s_cml.prev_rh = s_cml.L.prev_dot_full;
    s_cml.prev_pred = Pcur;
    s_cml.done = k;
}

int alz_ps_cmlive_symrow(const uint8_t *g, uint32_t pos, uint32_t row_base,
                         uint32_t *row_abs, uint32_t *sym_out)
{
    uint32_t k;
    if (!s_cml.started)
        return -1;
    if ((long)pos < s_cml.sec)
        return -1;                        /* hors section courante sans reset */
    for (k = s_cml.done + 1u; k <= pos; k++)
        ps_cmlive_step(g, k);
    *row_abs = row_base + s_cml.last_aff;
    *sym_out = s_cml.last_sym;
    return 0;
}

/* [GATED UHA_CM_EMISS, défaut-OFF, §13.909] Renvoie la ligne d'émission = fenêtre
 * glissante du registre `rf70` (roulé par `ps_cmlive_step`, `rf70=(rf70<<8|sym)`),
 * analogue structurel du `ctx` `[0x45dca8]` du legacy : `row=(rf70>>8)&0x1ff`. */
int alz_ps_cmlive_ctxrow(const uint8_t *g, uint32_t pos, uint32_t *row_out, uint32_t *sym_out)
{
    uint32_t k;
    if (!s_cml.started || (long)pos < s_cml.sec)
        return -1;
    for (k = s_cml.done + 1u; k <= pos; k++)
        ps_cmlive_step(g, k);
    *row_out = (s_cml.rf70 >> 8) & 0x1FFu;
    *sym_out = s_cml.last_sym;
    return 0;
}

/* [GATED UHA_CM_EMCARRY, défaut-OFF, §13.896/897] Carry MAÎTRE d'émission (mécanisme
 * validé m13 91,5 %) : un `arena2d` M persistant (par fichier), rechargé en working
 * `W:=copy(M)` au début de chaque bloc, puis scan DENSE (score+learn, rescale **working
 * 0x414590**) écrivant `out[]=prod_dens` (la fenetre passe#0 du `sm`). `M` est ensuite
 * avancé par le carry d'émission du bloc. Les `(row,sym)` viennent de la loi ctx→row
 * (M14) ; ici on branch `ps_ctx_step` (delta‑2D) comme SOURCE EN ATTENTE de M14.
 * Défaut‑OFF : jamais appelé si non requis → zéro effet / zéro régression. */
int alz_ps_emission_master_carry(const uint8_t *g, uint32_t base, uint32_t len,
                                 uint32_t *out_dens)
{
    static alz_arena2d_t *M = NULL, *W = NULL;
    static int m_init = 0;
    static uint32_t s_ctx_seed = 0u;
    uint32_t i, ctx_run;
    if (!g || !out_dens || len == 0u)
        return -1;
    if (!M) M = (alz_arena2d_t *)malloc(sizeof *M);
    if (!W) W = (alz_arena2d_t *)malloc(sizeof *W);
    if (!M || !W) return -1;
    if (!m_init) { alz_arena2d_init(M, 32u); alz_arena2d_init(W, 32u); m_init = 1; }
    if (base == 0u) { alz_arena2d_init(M, 32u); alz_arena2d_init(W, 32u); s_ctx_seed = 0u;
        alz_ps_cmlive_reset(0u); }   /* relance le moteur CM live (source row/sym) */
    /* (1) reload W:=copy(M) ; (2) scan dense : lignes = `ctx` du moteur CM (`rf70`) si
     * dispo, sinon roulage position du recon ; arena2d rescale working. */
    *W = *M;
    ctx_run = s_ctx_seed;
    for (i = 0u; i < len; i++) {
        uint32_t row, sym;
        if (alz_ps_cmlive_ctxrow(g, base + i, &row, &sym) != 0) {
            ctx_run = ((ctx_run << 8) | ((uint32_t) g[base + i] & 0xffu)) & 0x1FFFFu;
            row = (ctx_run >> 8) & 0x1FFu;
            sym = (uint32_t) g[base + i] & 0xffu;
        }
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        out_dens[base + i] = alz_arena2d_score(W, row, sym & 0xffu, NULL);
    }
    /* (3) avancer le MAÎTRE par les mêmes lignes (carry d'émission).
     * [GATED UHA_CMCARRY_LEARN, défaut-OFF, §14.061] le producteur LEGACY APPREND dans
     * le maître (`add WORD[edx],0x20` @0x414966) : sans LEARN, `M` reste froid et le
     * reload block1 recharge un maître static → EMISS médiocre. Gate ON ⇒ M s'accumule
     * (promo +0x20), miroir du carry réel. Défaut‑OFF = NULL (inchangé, non régressif). */
    for (i = 0u; i < len; i++) {
        uint32_t row, sym;
        if (alz_ps_cmlive_symrow(g, base + i, 0u, &row, &sym) != 0) { row = 0u; sym = (uint32_t) g[base + i] & 0xffu; }
        if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
        (void) alz_arena2d_score(M, row, sym & 0xffu, NULL);
    }
    s_ctx_seed = ctx_run;
    return 0;
}

int alz_ps_livewalk_master(const uint8_t *g, uint32_t usize,
                           const uint32_t *blpos, const uint32_t *blen, int num_blocks,
                           uint32_t from, uint32_t *out)
{
    (void)g; (void)usize; (void)blpos; (void)blen; (void)num_blocks; (void)from; (void)out;
    return 0;
}

int alz_ps_livewalk_litcarry(const uint8_t *g, uint32_t usize,
                             const uint32_t *blpos, const uint32_t *blen, int num_blocks,
                             const uint8_t *is_lit, uint32_t *out)
{
    (void)g; (void)usize; (void)blpos; (void)blen; (void)num_blocks; (void)is_lit; (void)out;
    return 0;
}

/* ==========================================================================
 * [GATED UHA_A3_CLASS0, défaut-OFF] Producteur densité FIDÈLE classe-0 (-m1).
 *
 * Maître persistant (HOT lignes 0..511, seed, 8 lignes d'échappement) appris PAR
 * LITTÉRAL ÉMIS via le bloc learn 0x4120fd..0x4121c1 ; par bloc, working = snapshot
 * du maître puis scan DENSE cls0 (a3_est_cost / 0x414630). Rescale maître 0x40ffa0
 * (double porte seed+root>=0x4000 OU budget<0, ré-arme <<6 car ligne<0x300), escape
 * 0x40fe90. Loi VALIDÉE offline 100 % (replay_master.c : hotfreq/seed/wtotal/escape
 * 0 mismatch ; verify_taildens.c : 256/256 cellules queue).
 *
 * Le maître densité est FROID à l'entrée du bloc 1 : le bloc 0 émet via les lignes
 * d'émission >=512 (mesuré : 0 événement row<512 avant pos 12544). On n'écrit `out`
 * que pour les blocs >=1 ; le bloc 0 est laissé intact (l'appelant garde son snapshot
 * froid). Géométrie legacy 0x413ed9 : block=rest>=0x4b00?0x3200:rest, len=block-0x100.
 * ========================================================================== */
#define A3_C0_NROW 512u
typedef struct a3_c0_master {
    uint16_t hot[A3_C0_NROW * 256];   /* HOT[row][sym] (PERM *0x4373cc) */
    uint16_t seed[A3_C0_NROW];        /* compteur secondaire (*0x4373d4) */
    uint32_t root[A3_C0_NROW];        /* racine Fenwick = Σ freq (invariant) */
    int32_t  budget[A3_C0_NROW];      /* [0x45cc94 + row*4] aging budget signé */
    uint16_t esc[8 * 256];            /* lignes escape 1017..1024, cellules */
    uint32_t escroot[8];              /* racine Fenwick de chaque ligne escape */
} a3_c0_master_t;

/* Rescale maître 0x40ffa0 : f>16 → f>>1 sinon 0 ; root=Σ ; seed=(seed+1)>>1 ;
 * budget=(seed_new+root_new)<<6 (ligne densité <0x300 → 0x4100a8 shl 6). */
static void a3_c0_rescale_master(a3_c0_master_t *m, uint32_t row)
{
    uint32_t j, s = 0u;
    for (j = 0u; j < 256u; j++) {
        uint32_t v = m->hot[row * 256u + j];
        v = (v > 16u) ? (v >> 1) : 0u;
        m->hot[row * 256u + j] = (uint16_t)v;
        s += v;
    }
    m->root[row]   = s;
    m->seed[row]   = (uint16_t)((m->seed[row] + 1u) >> 1);
    m->budget[row] = (int32_t)((m->seed[row] + s) << 6);
}

/* Rescale escape 0x40fe90 : v'=((v+1)&~1)>>1 ; racine=Σ. */
static void a3_c0_rescale_esc(a3_c0_master_t *m, uint32_t k)
{
    uint32_t j, s = 0u;
    for (j = 0u; j < 256u; j++) {
        uint32_t v = m->esc[k * 256u + j];
        v = ((v + 1u) & ~1u) >> 1;
        m->esc[k * 256u + j] = (uint16_t)v;
        s += v;
    }
    m->escroot[k] = s;
}

/* Learn d'un littéral émis (0x4120fd..0x4121c1). row cls0 = p1 + (0x100 si
 * (p1&0xc0)==(p2&0xc0)) ; escape k=(p1&0xe0)>>5 ; sym=g[pos] BRUT. promo=32,
 * escape_inc=8 (lignes densité). budget -= (seed+freq_avant) ; froid → escape+8
 * et seed+=32 ; HOT+=32, root+=32 ; rescale si seed+root>=0x4000 OU budget<0. */
static void a3_c0_learn(a3_c0_master_t *m, const uint8_t *g, uint32_t pos)
{
    uint32_t p1 = (pos >= 1u) ? g[pos - 1u] : 0u;
    uint32_t p2 = (pos >= 2u) ? g[pos - 2u] : 0u;
    uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
    uint32_t k   = (p1 & 0xe0u) >> 5;
    uint32_t sym = g[pos];
    uint32_t f0  = m->hot[row * 256u + sym];
    m->budget[row] -= (int32_t)(m->seed[row] + f0);   /* 0x412144 (avant update) */
    if (f0 == 0u) {                                    /* COLD */
        m->esc[k * 256u + sym] = (uint16_t)(m->esc[k * 256u + sym] + 8u);
        m->escroot[k] += 8u;
        if (m->escroot[k] >= 0x4000u) a3_c0_rescale_esc(m, k);
        m->seed[row] = (uint16_t)(m->seed[row] + 32u); /* 0x412169 */
    }
    m->hot[row * 256u + sym] = (uint16_t)(f0 + 32u);    /* 0x41216d */
    m->root[row] += 32u;
    if (m->seed[row] + m->root[row] >= 0x4000u || m->budget[row] < 0)
        a3_c0_rescale_master(m, row);
}

int alz_ps_class0_percost_ex(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, int b0_learn,
                             uint32_t *out)
{
    static a3_c0_master_t *s_c0_m = NULL;
    static alz_arena2d_t  *s_c0_w = NULL;
    a3_c0_master_t *m;
    alz_arena2d_t *W;
    a3_esc_line_t E[8];
    int b;
    uint32_t i;

    if (!g || !blkpos || !blklen || !is_lit || !out || nblk <= 0)
        return -1;
    if (!s_c0_m)
        s_c0_m = (a3_c0_master_t *) calloc(1, sizeof(a3_c0_master_t));
    else
        memset(s_c0_m, 0, sizeof(a3_c0_master_t));
    if (!s_c0_w)
        s_c0_w = (alz_arena2d_t *) calloc(1, sizeof(alz_arena2d_t));
    m = s_c0_m;
    W = s_c0_w;
    if (!m || !W) return -1;
    W->aging_on = 0;

    /* init froid : HOT=0, seed=1, root=0, budget=0x4000 ; escape cellules=2 racine=512. */
    for (i = 0u; i < A3_C0_NROW; i++) { m->seed[i] = 1u; m->budget[i] = 0x4000; }
    for (i = 0u; i < 8u * 256u; i++) m->esc[i] = 2u;
    for (i = 0u; i < 8u; i++) m->escroot[i] = 512u;

    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        if (b == 0) {
            /* bloc 0 : maître froid à l'entrée ; si b0_learn != 0 (sel 0,
             * escape_changed == 0), bloc 0 émet via lignes 0..511 et apprend
             * ses littéraux dans le maître ; sinon (sel 10) lignes >= 512.
             * `out` du bloc 0 reste intact (snapshot froid de l'appelant). */
            if (b0_learn) {
                for (i = 0u; i < len; i++) {
                    uint32_t abs = base + i;
                    if (is_lit[abs]) a3_c0_learn(m, g, abs);
                }
            }
            continue;
        }

        /* (1) snapshot working W = maître (freq=HOT, counter=seed, total=seed+root). */
        memcpy(W->freq, m->hot, sizeof W->freq);
        for (i = 0u; i < ALZ_ARENA2D_MAX_ROW; i++) {
            W->counter[i] = m->seed[i];
            W->total[i]   = (uint16_t)(m->seed[i] + m->root[i]);
            W->promo[i]   = 32u;
        }
        for (i = 0u; i < 8u; i++) {
            memcpy(E[i].freq, m->esc + i * 256u, 256u * sizeof(uint16_t));
            memset(E[i].fen, 0, sizeof E[i].fen);
            E[i].fen[0] = (uint16_t)m->escroot[i];
        }
        /* (2) scan DENSE cls0 intra-bloc → coût figé par position (0x414630). */
        for (i = 0u; i < len; i++) {
            uint32_t abs = base + i;
            uint32_t p1 = (abs >= 1u) ? g[abs - 1u] : 0u;
            uint32_t p2 = (abs >= 2u) ? g[abs - 2u] : 0u;
            uint32_t row = p1 + (((p1 & 0xc0u) == (p2 & 0xc0u)) ? 0x100u : 0u);
            uint32_t k   = (p1 & 0xe0u) >> 5;
            out[abs] = a3_est_cost(W, &E[k], row, g[abs], NULL);
        }
        /* (3) avancer le MAÎTRE : learn sparse aux seuls littéraux émis, en ordre pos. */
        for (i = 0u; i < len; i++) {
            uint32_t abs = base + i;
            if (is_lit[abs]) a3_c0_learn(m, g, abs);
        }
    }
    return 0;
}

int alz_ps_class0_percost(const uint8_t *g, uint32_t usize,
                          const uint32_t *blkpos, const uint32_t *blklen,
                          int nblk, const uint8_t *is_lit, uint32_t *out)
{
    return alz_ps_class0_percost_ex(g, usize, blkpos, blklen, nblk, is_lit, 0, out);
}

int alz_ps_emiprod_percost(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, const uint8_t *is_lit, uint32_t *out)
{
    static alz_arena2d_t *s_ep_m = NULL, *s_ep_w = NULL;
    static uint32_t *s_ep_tmp = NULL;
    static uint32_t  s_ep_tmp_cap = 0u;
    alz_arena2d_t *M, *W;
    uint32_t *tmp, maxlen = 0u, need;
    int b;

    if (!g || !blkpos || !blklen || !is_lit || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    if (!s_ep_m) s_ep_m = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!s_ep_w) s_ep_w = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    need = maxlen ? maxlen : 1u;
    if (!s_ep_tmp || s_ep_tmp_cap < need) {
        uint32_t *nt = (uint32_t *)realloc(s_ep_tmp, sizeof(uint32_t) * (size_t)need);
        if (!nt) return -1;
        s_ep_tmp = nt;
        s_ep_tmp_cap = need;
    }
    M   = s_ep_m;
    W   = s_ep_w;
    tmp = s_ep_tmp;
    if (!M || !W || !tmp) return -1;
    alz_arena2d_init(M, 32u);

    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i;
        alz_ps_carry_t stW;
        uint32_t mm[3];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;

        if (b > 0) ps_esc_boundary();
        *W = *M;
        memset(&stW, 0, sizeof stW);
        stW.ebp = 1u;
        stW.arena = W;
        g_esc_count = 1;
        (void) alz_ps_class_sigma_carry(&stW, 3u, g, base, len, 32u, ALZ_PS_COLD0,
                                        NULL, tmp, NULL);
        g_esc_count = 0;
        memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));

        mm[0] = 0u; mm[1] = 0u; mm[2] = 1u;
        for (i = 0u; i < len; i++) {
            uint32_t c;
            if (!is_lit[base + i]) continue;
            c = ps_ctx_step(3u, g, base + i, &mm[0], &mm[1], &mm[2]);
            if (g_ps_phasefix) {
                uint32_t e = (c >> 8) & 0x1fu;
                e += (((base + i + 2u) % 3u) << 5);
                c = (e << 8) | (c & 0xffu);
            }
            uint32_t row = c >> 8;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            (void) alz_arena2d_score(M, row, c & 0xffu, NULL);
        }
    }
    return 0;
}

int alz_ps_classpass_percost(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, uint32_t *out)
{
    static const uint32_t ord0[ALZ_PS_NCLASS] = { 0u, 1u, 2u, 3u, 4u };
    static const uint32_t ord1[ALZ_PS_NCLASS] = { 3u, 0u, 1u, 2u, 4u };
    alz_arena2d_t *ar;
    uint32_t *tmp, maxlen = 0u;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    ar  = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    tmp = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!ar || !tmp) { free(ar); free(tmp); return -1; }
    alz_arena2d_init(ar, 32u);

    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b];
        const uint32_t *ord = (b == 0) ? ord0 : ord1;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cls = ord[k];
            alz_ps_carry_t st;
            memset(&st, 0, sizeof st);
            st.ebp = 1u;
            st.arena = ar;
            (void) alz_ps_class_sigma_carry(&st, cls, g, base, len, 32u, ALZ_PS_COLD0,
                                            NULL, (cls == 3u) ? tmp : NULL, NULL);
            if (cls == 3u)
                memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        }
    }
    free(ar); free(tmp);
    return 0;
}

void alz_ps_set_phasefix(int v) { g_ps_phasefix = v; }

