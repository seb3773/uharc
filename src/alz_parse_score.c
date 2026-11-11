/*
 * alz_parse_score.c — scoreur de PARSE ALZ (conducteur de bloc 0x413f7f/0x413ea0 + catégorie
 * 0x414630). Reproduction bit-exact du pipeline validé from-scratch §13.132/§13.137..§13.141.
 * GATED, NON-WIRED. Voir alz_parse_score.h pour la spécification.
 */
#include "alz_parse_score.h"
#include "alz_score.h"
#include "alz_cm.h"   /* [GATED UHA_CM_WIRE] engine CM dense (alz_arb/alz_arena/alz_cm) pour la loi sym→row (§13.796) */
#include "alz_est414630.h"   /* [GATED UHA_A3_CLASS0] estimateur densité fidèle 0x414630 (2D + escape) */
#include "alz_esc_line.h"    /* [GATED UHA_A3_CLASS0] lignes d'échappement 0x402+cl (learn 0x4100e0 / rescale 0x40fe90) */
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
static uint8_t *g_pfile = NULL;
static uint32_t g_pfile_n = 0;
static int g_pfile_tried = 0;
static const uint8_t *alz_ps_pfile_try(uint32_t n)
{
    if (!g_pfile_tried) {
        const char *e = getenv("UHA_PFILE");
        g_pfile_tried = 1;
        if (e) {
            FILE *f = fopen(e, "rb");
            if (f) {
                uint8_t *b = (uint8_t *)malloc(n ? n : 1u);
                if (b && fread(b, 1u, n, f) == n) { g_pfile = b; g_pfile_n = n; }
                else free(b);
                fclose(f);
                if (g_pfile)
                    fprintf(stderr, "[UHA_PFILE] cm-engine P chargé: %u positions\n", (unsigned)n);
            }
        }
    }
    return (g_pfile && n == g_pfile_n) ? g_pfile : NULL;
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
static int      g_esc_on = -1;
static int      g_esc_count = 0;   /* comptage armé UNIQUEMENT sur la passe de SORTIE */
static void ps_esc_lazy(void)
{
    if (g_esc_on < 0) {
        int s;
        g_esc_on = getenv("UHA_A3_ESCFEED") ? 1 : 0;
        if (g_esc_on) for (s = 0; s < 256; s++) g_escf[s] = 4u;
    }
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
            static int s_phrel = -1;   /* [GATED UHA_PHASEFIX_REL, défaut-OFF, §14.147] */
            uint32_t e = ctx >> 8;
            uint32_t pbase;
            if (s_phrel < 0) s_phrel = getenv("UHA_PHASEFIX_REL") ? 1 : 0;
            pbase = s_phrel ? i : (base + i);   /* relatif-au-bloc vs absolu */
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
    {
        const char *mm = getenv("UHA_PM2");   /* "m" = machine réinit/par-bloc (arène seule carry) */
        s_pm2_machine_reset = (mm && mm[0] == 'm') ? 1 : 0;
        printf("[PARSE-MULTI2] mode carry = %s\n", s_pm2_machine_reset ? "ARÈNE seule (machine reset/bloc)" : "arène+machine");
    }
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
    static FILE *cd = NULL;
    static int cdi = -1;
    (void)default_inc;
    if (cdi < 0) {
        const char *ce = getenv("UHA_A3_CELLDUMP");
        cdi = 0;
        if (ce && *ce) { cd = fopen(ce, "w"); cdi = cd ? 1 : 0; }
    }
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
        if (cd && percost)   /* cellule intime de la position publiée */
            fprintf(cd, "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
                    (unsigned)(g_ps_dumpbase + i), (unsigned) row, (unsigned)(ctx & 0xffu),
                    (unsigned) f, (unsigned) T, (unsigned) c,
                    (unsigned)(((f << 14) | 0u) / (T ? T : 1u)), (unsigned) cs);
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

/* rescale par ligne à la frontière (total≥0x4000), miroir du reload/commit legacy. */
static void ps_rescale_all(alz_arena2d_t *a)
{
    uint32_t r; for (r = 0u; r < ALZ_ARENA2D_MAX_ROW; r++)
        if (a->total[r] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(a, r);
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
            uint32_t adv = winner;
            const char *ae = getenv("UHA_PM3ADV");
            if (ae && ae[0] >= '0' && ae[0] <= '4') adv = (uint32_t)(ae[0] - '0');
            ps_score_ctxs(snap, ctxs[adv], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
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
    uint32_t snap_inc = 0u;   /* [GATED UHA_SNAPINC] inc d'apprentissage du SNAPSHOT persisté */
    uint32_t snap_adv = 0xffffffffu;  /* [GATED UHA_SNAPADV=<0..4>] classe qui alimente l'avancement du carry; sentinel=winner (défaut) */
    const char *nomm_env = getenv("UHA_NOMM");
    uint32_t nclass = (nomm_env && nomm_env[0] == '1') ? 1u : ALZ_PS_NCLASS;
    int b, k;

    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    alz_ps_snapwin_n = 0;   /* [UHA_A3_CTXCLASS_AUTO] cache de processus remis a zero */
    {
        const char *se = getenv("UHA_SNAPINC");
        if (se && *se) snap_inc = (uint32_t)strtoul(se, NULL, 10);
    }
    {
        const char *ae = getenv("UHA_SNAPADV");
        if (ae && ae[0] >= '0' && ae[0] <= '4') snap_adv = (uint32_t)(ae[0] - '0');
    }
    /* [GATED UHA_PHASEFIX, défaut-OFF, §13.739] phase cls3 corrigée (abs+2)%3. */
    if (getenv("UHA_PHASEFIX")) g_ps_phasefix = 1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    if (!s_snap_ar) s_snap_ar = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    if (!s_live_ar) s_live_ar = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
    snap = s_snap_ar;
    live = s_live_ar;
    if (!snap || !live) return -1;
    alz_arena2d_init(snap, (uint16_t)32u);
    ps_set_promo_all(snap, snap_inc);   /* snapshot apprend à inc=N si sondé (sinon 32) */
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
        /* [GATED UHA_A3_BLKAGE=<1|2>, défaut-OFF, lane ALZ -m3] TRANSFORMATION DE
         * FRONTIÈRE du scoreur : aging maître 0x40ffa0 (`freq>16 → >>1, sinon 0`) sur
         * TOUTES les lignes, puis `total := Σfreq + counter` (1) ou counter >>1 (2).
         * Mesuré contre la table legacy du bloc 1 (capture n°16, 12 544 valeurs). */
        {
            static int s_blkage = -1;
            if (s_blkage < 0) {
                const char *ba = getenv("UHA_A3_BLKAGE");
                s_blkage = (ba && *ba) ? atoi(ba) : 0;
            }
            if (s_blkage && b > 0) {
                uint32_t r2, c2;
                for (r2 = 0u; r2 < ALZ_ARENA2D_MAX_ROW; r2++) {
                    uint32_t s2 = 0u;
                    alz_arena2d_rescale_master(snap, r2);
                    if (s_blkage >= 2)
                        snap->counter[r2] = (uint16_t)(snap->counter[r2] >> 1);
                    for (c2 = 0u; c2 < 256u; c2++) s2 += snap->freq[(r2 << 8) | c2];
                    snap->total[r2] = (uint16_t)(s2 + snap->counter[r2]);
                }
            }
        }
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* (1) générer flux ctxs par classe sur TOUT le bloc (machine avance pleine). */
        /* [GATED UHA_SNAPCTXROW, défaut-OFF, §14.066] Seed : avancer le moteur CM live
         * UNE fois par position (cmlive_symrow avance+renvoie la ligne vécue) et memoriser
         * les lignes, puis les injecter dans ctxs[] (au lieu du delta‑2D). Reset si base==0. */
        static uint32_t *s_sx_buf = NULL;
        static int s_sx_on = -1, s_sx_ready = 0;
        if (s_sx_on < 0) s_sx_on = getenv("UHA_SNAPCTXROW") ? 1 : 0;
        if (s_sx_on && !s_sx_buf) {
            s_sx_buf = (uint32_t *)calloc((size_t)(ALZ_ARENA2D_MAX_ROW * 64u), sizeof(uint32_t));
        }
        if (base == 0u && s_sx_on) { alz_ps_cmlive_reset(0u); s_sx_ready = 0; }
        if (s_sx_on && s_sx_buf) {
            uint32_t j;
            for (j = 0u; j < len && (base + j) < (uint32_t)(ALZ_ARENA2D_MAX_ROW * 64u); j++) {
                uint32_t fr, fs;
                if (alz_ps_cmlive_symrow(g, base + j, 0u, &fr, &fs) == 0) {
                    if (fr >= ALZ_ARENA2D_MAX_ROW) fr = ALZ_ARENA2D_MAX_ROW - 1u;
                    s_sx_buf[base + j] = fr; s_sx_ready = 1;
                }
            }
        }
        for (c = 0u; c < nclass; c++) {
            uint32_t i;
            for (i = 0u; i < len; i++) {
                uint32_t cx = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
                /* [GATED UHA_PHASEFIX] row cls3 : phase = (abs+2)%3 (au lieu de ebp%3). */
                if (g_ps_phasefix && c == 3u) {
                    uint32_t e = (cx >> 8) & 0x1fu;
                    e += (((base + i + 2u) % 3u) << 5);
                    cx = (e << 8) | (cx & 0xffu);
                }
                /* [GATED UHA_SNAPCTXROW, défaut-OFF, §14.064] Remplacer la ligne
                 * delta‑2D par la LIGNE `ctx` VÉCUE (moteur CM live), miroir du scan
                 * legacy (row=(ctx>>8)&0x1ff sur le recon). Défaut‑OFF = delta‑2D inchangé. */
                if (s_sx_on && s_sx_ready && (base + i) < (ALZ_ARENA2D_MAX_ROW * 64u)) {
                    cx = (s_sx_buf[base + i] << 8) | (cx & 0xffu);
                }
                ctxs[c][i] = cx;
            }
        }
        /* (2) ordre : seed (gagnant bloc précédent) d'abord, puis ascending. */
        if (seed_cls >= nclass) seed_cls = 0u;
        order[cnt++] = seed_cls;
        for (c = 0u; c < nclass; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) argmin : chaque classe copie snap->live, score (abandon précoce). */
        for (k = 0; k < (int)nclass; k++) {
            uint32_t cc = order[(uint32_t)k], s;
            *live = *snap;
            ps_set_promo_all(live, 32u);   /* scoreur LIVE toujours inc=32 (§13.270) */
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, &np, NULL);
            if (s < best) { best = s; winner = cc; }
        }
        /* [GATED UHA_A3_SNAPWIN, LECTURE SEULE, DEFAUT-OFF, lane ALZ -m3] la classe GAGNANTE
         * de chaque bloc, telle que la calcule le modèle froid à deux arènes (argmin de Σ sur
         * les classes 0..4, copie d'état snapshot->live à chaque classe). Sert à juger si le
         * producteur chaud — qui déroule cls 3 partout, sauf surcharge
         * `UHA_LIVEWALK_CTXCLASS` — doit dérouler la gagnante **PAR BLOC** : mesure sur
         * `biased` (sel 0) et `records` (sel 4), rendus byte‑exactes par le modèle froid et
         * régressés par le chaud. Zéro effet sinon. */
        if (getenv("UHA_A3_SNAPWIN") != NULL)
            fprintf(stderr, "[SNAPWIN] b=%d base=0x%05x len=0x%05x winner=cls%u sigma=0x%08x\n",
                    b, base, len, winner, best);
        /* [GATED UHA_A3_CTXCLASS_AUTO] export de la gagnante par bloc (ordre des blocs). */
        if (alz_ps_snapwin_n < ALZ_PS_SNAPWIN_MAX)
            alz_ps_snapwin_blk[alz_ps_snapwin_n++] = (int) winner;
        /* (4) RE-score la gagnante sur copie fraîche de snap (sans abandon) en
         * écrivant le coût PAR POSITION dans out[base..base+len). */
        *live = *snap;
        ps_set_promo_all(live, 32u);   /* scoreur LIVE toujours inc=32 (out dens) */
        g_ps_dumpbase = base; g_ps_dumpn = len;
        ps_score_ctxs(live, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
        /* (5) avancer le snapshot en entrainant le flux du gagnant (plein).
         * [GATED UHA_SNAPADV] : surcharge quelle classe alimente le carry cross-bloc,
         * SANS toucher au dens par bloc (out[] reste sur `winner`). Défaut = winner. */
        /* [GATED UHA_SNAPLITMASK=<maskfile>, défaut-OFF, §14.017] Porter le MAÎTRE sur le
         * FLUX ÉMIS (littéraux seuls) au lieu du rescan full-ctx : miroir de la mise à jour
         * du maître par l'émission réelle (block0 émis == legacy car firstdiv>12544). */
        {
            static uint8_t *s_slm = NULL; static int s_slm_load = 0; static uint32_t s_slm_n = 0u;
            if (!s_slm_load) {
                const char *mk = getenv("UHA_SNAPLITMASK");
                if (mk && *mk) {
                    FILE *mf = fopen(mk, "r");
                    s_slm_n = usize;
                    if (mf) { s_slm = (uint8_t *) calloc(usize ? usize : 1u, 1u); s_slm_load = 1;
                        if (s_slm) { long v; while (fscanf(mf, "%ld", &v) == 1)
                            if (v >= 0 && (uint32_t)v < usize) s_slm[(uint32_t)v] = 1u; }
                        fclose(mf);
                    }
                }
                s_slm_load = 1;
            }
            if (s_slm && s_slm_n == usize) {
                uint32_t i;
                for (i = 0u; i < len; i++)
                    if (s_slm[base + i])
                        (void) ps_score_ctxs(snap, ctxs[(snap_adv < nclass) ? snap_adv : winner] + i,
                                             1u, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
            } else
                ps_score_ctxs(snap, ctxs[(snap_adv < nclass) ? snap_adv : winner],
                              len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        }
        seed_cls = winner;
        /* [GATED UHA_A3_SNAPK2, LECTURE SEULE, DEFAUT-OFF, lane ALZ -m3, tour 124] Σ des carrés
         * des fréquences de l'arène carry après avancement du bloc. La porte du sélecteur
         * (0x414089/0x414090, décodée à la capture n°48) compare `T * K[best]` à `64 * K[0]`, où K
         * est un accumulateur de `Σ f²` (0x414d2e : `imul ecx,ecx` sur `[0x452f08+...]`, entretenu
         * à ± en 0x414ee4-0x414f33 à chaque apprentissage). CIBLES mesurées n°48 (division exacte
         * par 64 et par T=80/75, zéro fraction sur les 23 passages) : K[0] = 5214 5152 5010 5006
         * 5074 5228 5118 5080 5172 5056 (random, 10 blocs) et 75968 74606 76154 67290 62378 66274
         * 78716 76136 75658 76494 75840 76514 104206 74954 75122 66348 61862 (records, 17 blocs) ;
         * K[best] = 5004..5022 (random, best 1) et 36962..35822 (records, best 4). Sert à dire si
         * l'arène du clone rend cette grandeur, et à quelle plage de lignes. Zéro effet sinon. */
        {
            static int s_k2 = -1;
            if (s_k2 < 0) s_k2 = getenv("UHA_A3_SNAPK2") ? 1 : 0;
            if (s_k2) {
                uint32_t rk, ck;
                unsigned long long sq = 0ull, warm = 0ull;
                for (rk = 0u; rk < ALZ_ARENA2D_MAX_ROW; rk++)
                    for (ck = 0u; ck < 256u; ck++) {
                        unsigned long long v = snap->freq[(rk << 8) + ck];
                        sq += v * v;
                        if (v) warm++;
                    }
                fprintf(stderr, "[A3K2] b=%d winner=%u sumsq=%llu cellules=%llu\n",
                        b, winner, sq, warm);
            }
        }
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

/* [GATED UHA_CM_WIRE, §13.796] Avance fidèle du maître sur la loi image sym→row.
 * Déroule l'engine CM (alz_arena+alz_arb+alz_cm) DENSEMENT par rc sur la section
 * [base,base+len) et reproduit EXACTEMENT le harnais validé _scratch/cm_closed.c
 * (sym 12700/12700, idx/ref/b8 15000/15000). master_learn(M, relrow=aff, sym)
 * UNIQUEMENT aux littéraux. Reset engine+registres+flag à la frontière de section. */
static void ps_cmwire_advance_master(alz_arena2d_t *M, const uint8_t *g,
                                     uint32_t base, uint32_t len,
                                     const uint8_t *is_lit, uint32_t usize)
{
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u}; /* tbl 0x437af8/idx */
    alz_cm_learner L; memset(&L, 0, sizeof L);
    alz_arena A; alz_arena_init(&A);
    alz_arb   R; alz_arb_init(&R);
    uint32_t rf70 = 0xffffffffu, rf74 = 0xffffffffu, rf78 = 0xffffffffu; /* §13.796 reset section */
    int rflag = 0, last_prev_idx_for_P = 0;
    int32_t prev_rh_sim = 0;
    uint32_t i;
    for (i = 0; i < len; i++) {
        uint32_t abs = base + i;
        uint8_t b_cur   = g[abs];
        uint8_t b_prev  = (i >= 1u) ? g[abs - 1u] : 0x80u;
        uint8_t b_prev2 = (i >= 2u) ? g[abs - 2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur  - 0x80;
        int32_t base_p1 = ps_b(g, (long)base, (long)abs - 1);
        int32_t base_p2 = ps_b(g, (long)base, (long)abs - 2);
        int32_t dl      = ps_q(g, (long)base, (long)abs);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref_arb = ps_q(g, (long)base, (long)abs - ref_prev);
        int32_t dr_b8_arb  = ps_q(g, (long)base, (long)abs - b8_prev);
        int32_t row_hash_model = prev_rh_sim;
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & abs) == 0u);
        A.line = abs;
        alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = abs;
        alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref_arb, dr_b8_arb, row_hash_model);
        uint32_t idx_i = R.idx;
        int32_t dr_ref_learn = ps_q(g, (long)base, (long)(abs + 1) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_ref_learn);
        int32_t rh_sim = L.prev_dot_full;
        /* loi sym→row (§13.796) : taps en domaine base, ref/b8 AVANT update, idx lag. */
        {
            uint32_t taps6[6];
            uint8_t vp1 = (uint8_t)(base_p1);
            uint8_t vp2 = (uint8_t)(base_p2);
            taps6[0] = 0;
            taps6[1] = vp1;
            taps6[2] = (uint8_t)(2 * (int32_t)vp1 - (int32_t)vp2);
            taps6[3] = (uint8_t)row_hash_model;
            taps6[4] = (uint8_t)A.dr[(abs - (uint32_t)ref_prev) & 0x7fu];
            taps6[5] = (uint8_t)A.dr[(abs - (uint32_t)b8_prev)  & 0x7fu];
            int ip = last_prev_idx_for_P;
            uint32_t Pcur = ((taps6[ip % 6u] & 0xffu) + ((ip >= 4) ? (uint32_t)vp1 : 0u) + 0x80u) & 0xffu;
            uint32_t Pprev = (i == 0u) ? 0u : Pcur;   /* 1ere ligne section : [0x45ecbf]=reset 0 */
            uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
            uint8_t sym = rflag ? (uint8_t)(0u - (uint32_t)d) : d;
            rf70 = (rf70 << 8) | sym;
            rf74 = (rf74 << 8) + ALZ_REG_T1[sym];
            rf78 = (rf78 << 8) + ALZ_REG_T2[sym];
            if (sym >= 0x80u) rflag ^= 1;
            uint32_t aff = (rf70 == 0u) ? 1u : (rf74 == 0u) ? 2u : (rf78 == 0u) ? 3u : 0u;
            if (is_lit[abs]) {
                /* [GATED UHA_CMROWHASH, défaut-OFF, ARENA_TASK16] index du maître = row_hash_cm
                 * (0x44d8d8 = L->prev_dot_full, & 0x1ff) — la LOI VALIDÉE M11, au lieu de
                 * `aff` (bande 4‑lignes). Défault‑OFF = comportement cmwire inchangé (aff). */
                if (getenv("UHA_CMROWHASH") != NULL)
                    alz_arena2d_master_learn(M, ((uint32_t)rh_sim) & 0x1FFu, sym);
                else
                    alz_arena2d_master_learn(M, aff, sym);   /* relrow=aff (bande 4-lignes cls5), sym dir-flippé */
            }
            last_prev_idx_for_P = (int)idx_i;
        }
        prev_rh_sim = rh_sim;
    }
    (void)usize;
}

/* ==========================================================================
 * [ARENA_TASK16 — GATED défaut-OFF] alz_ps_livewalk_cm : le MAÎTRE D'ÉMISSION indexé
 * par `row_hash_cm` (0x44d8d8 = alz_cm prev_dot_full, validé 83/83 §13.115). Arène P
 * SÉPARÉE (ne touche PAS le chemin EMIPROD/bloc0). Déroule le moteur CM densement sur
 * [0,usize) ; aux LITTÉRAUX du bloc0 (q<0x3100) apprend P[row_hash_cm&0x1ff][sym]
 * (cold/warm +32, rescale @0x4000) = le PERM d'émission legacy. Then, si `out` non NULL,
 * recharge W:=P et score DENSE gen_ctxs(3) sur [0x3100,usize) → coût pré-learn publié.
 * Digeste un fingerprint P (rows 37/68) sur stderr si UHA_LIVEWALK_STATS (validation vs
 * dumps GT : freq[68]=7 cell. Σ~11130 ±2..±5 ; freq[37]=0). Retourne 0. */
int alz_ps_livewalk_cm(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                       uint32_t from, uint32_t *out)
{
    static const uint32_t s_bp[6] = {0x0000u,0x3100u,0x620cu,0x931cu,0xc4ffu,0xff00u};
    static const uint32_t s_bl[6] = {0x3100u,0x3100u,0x3100u,0x3100u,0x3a01u,0x100u};
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u};
    (void)s_bp; (void)s_bl;
    alz_cm_learner L; alz_arena A; alz_arb R;
    alz_arena2d_t *P;
    uint32_t rf70=0xffffffffu, rf74=0xffffffffu, rf78=0xffffffffu;
    int rflag=0, last_prev_idx=0; int32_t prev_rh=0;
    uint32_t i, stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    if (!g || !is_lit || usize > 0x10000u) return -1;
    memset(&L,0,sizeof L); alz_arena_init(&A); alz_arb_init(&R);
    P = (alz_arena2d_t*)malloc(sizeof(alz_arena2d_t));
    if (!P) return -1;
    alz_arena2d_init(P, 32u);
    /* (1)+(2) moteur CM (conduiteur EXACT cmwire, section base=0) ; learn P aux
     * littéraux du bloc0 (i<0x3100), row = row_hash_cm(prev_dot_full)&0x1ff. */
    for (i = 0; i < usize; i++) {
        uint8_t b_cur = g[i];
        uint8_t b_prev  = (i>=1u)? g[i-1u] : 0x80u;
        uint8_t b_prev2 = (i>=2u)? g[i-2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur - 0x80;
        int32_t base_p1 = ps_b(g, 0L, (long)i - 1);
        int32_t base_p2 = ps_b(g, 0L, (long)i - 2);
        int32_t dl      = ps_q(g, 0L, (long)i);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref_arb = ps_q(g, 0L, (long)i - ref_prev);
        int32_t dr_b8_arb  = ps_q(g, 0L, (long)i - b8_prev);
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & i) == 0u);
        A.line = i; alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = i; alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref_arb, dr_b8_arb, prev_rh);
        uint32_t idx_i = R.idx;
        int32_t dr_ref_learn = ps_q(g, 0L, (long)(i + 1u) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_ref_learn);
        int32_t rh = L.prev_dot_full;
        /* sym = dir-flip(b_cur - P) via taps (idem cmwire). */
        {
            uint32_t taps6[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
            taps6[0]=0; taps6[1]=vp1; taps6[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
            taps6[3]=(uint8_t)prev_rh;
            taps6[4]=(uint8_t)A.dr[(i-(uint32_t)ref_prev)&0x7fu];
            taps6[5]=(uint8_t)A.dr[(i-(uint32_t)b8_prev)&0x7fu];
            int ip = last_prev_idx;
            uint32_t Pcur = ((taps6[ip%6u]&0xffu) + ((ip>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
            uint32_t Pprev = (i==0u)?0u:Pcur;
            uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
            uint8_t sym = rflag ? (uint8_t)(0u-(uint32_t)d) : d;
            rf70=(rf70<<8)|sym; rf74=(rf74<<8)+ALZ_REG_T1[sym]; rf78=(rf78<<8)+ALZ_REG_T2[sym];
            if (sym>=0x80u) rflag^=1;
            if (i < 0x3100u && is_lit[i])              /* PERM d'émission = littéraux bloc0 */
                alz_arena2d_master_learn(P, ((uint32_t)rh)&0x1FFu, sym);
            last_prev_idx = (int)idx_i;
        }
        prev_rh = rh;
    }
    if (stats) {
        uint32_t c, s68=0,s37=0,n68=0,n37=0;
        for (c=0;c<256u;c++){ if(P->freq[(68u<<8)+c]){s68+=P->freq[(68u<<8)+c];n68++;} if(P->freq[(37u<<8)+c]){s37+=P->freq[(37u<<8)+c];n37++;} }
        fprintf(stderr, "[LWC] P-perm@b1 freq68 SUM=%u nz=%u | freq37 SUM=%u nz=%u\n",
                (unsigned)s68,(unsigned)n68,(unsigned)s37,(unsigned)n37);
    }
    /* (4) reload W:=P, scan dense gen_ctxs(3) sur bloc≥from → coût pré-learn. */
    if (out) {
        uint32_t *ctx3 = (uint32_t*)malloc(sizeof(uint32_t)*(size_t)usize);
        alz_arena2d_t W;
        if (ctx3) {
            alz_ps_gen_ctxs(3u, g, usize, ctx3);
            W = *P;
            for (i = from; i < usize; i++) {
                uint32_t sc = ctx3[i], row = (sc>>8)&0x1FFu, sym = sc&0xffu, T=0u, proba;
                if (row>=ALZ_ARENA2D_MAX_ROW) row=ALZ_ARENA2D_MAX_ROW-1u;
                proba = alz_arena2d_score(&W, row, sym, &T);
                out[i] = alz_score_proba_to_cost(proba);
            }
            free(ctx3);
        }
    }
    free(P);
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16/17 — GATED défaut‑OFF, côté B] alz_ps_livewalk_dual : producteur
 * DOUBLE‑BUFFER `P`(PERM/maître, persiste) / `H`(HOT/working, rechargé par bloc),
 * contrat `DUAL_INTEGRATION.md`. §1 RELOAD `H:=copy(P)` par bloc ; SCORAGE DENSE
 * `gen_ctxs(3)` dans H (score+learn, rescale @0x4000) → coût PRÉ‑learn écrit dans
 * `out` si `base>=from` (bloc0 garde EMIPROD). §2 EMISSION‑LEARN du P = **POINT
 * D'INJECTION** (#17 fournit row/subset/incrément/cold‑vs‑warm) ; STUB baseline =
 * learn aux LITTÉRAUX sur row `gen_ctxs(3)` (≈ EMIPROD/16685). Sonde _STATS :
 * fingerprint freq[68]/[37] de P (cible 11130/0). Retourne 0 ; zéro effet hors gate. */
int alz_ps_livewalk_dual(const uint8_t *g, uint32_t usize, const uint8_t *is_lit,
                         uint32_t from, uint32_t *out)
{
    static const uint32_t bp[6] = {0x0000u,0x3100u,0x620cu,0x931cu,0xc4ffu,0xff00u};
    static const uint32_t bl[6] = {0x3100u,0x3100u,0x3100u,0x3100u,0x3a01u,0x100u};
    alz_arena2d_t *P, *H;
    uint32_t *ctx3, *tmp;
    uint32_t i, b, c, stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    int feed_used = 0;
    int brscale = getenv("UHA_LIVEWALK_BOUNDRESCALE") ? 1 : 0;
    g_ps_no_inline_rescale = brscale;   /* décroche le rescale du learn si boundary‑rescale ON */
    /* feed par‑bloc (contrat #17) : événements stockés avec leur bloc (marqueur `#B <n>`,
     * invisible pour dual_sim qui ignore les lignes '#'). */
    int fcap = 0, fn = 0; int *fblk = NULL, *frow = NULL, *fsym = NULL, *flrn = NULL;
    uint32_t rctx = 0u;   /* [RECON] ctx roulant 17 bits continu sur tout le fichier */
    if (!g || !is_lit || !out || usize > 0x10000u) return -1;
    P = (alz_arena2d_t*) malloc(sizeof(alz_arena2d_t));
    H = (alz_arena2d_t*) malloc(sizeof(alz_arena2d_t));
    ctx3 = (uint32_t*) malloc(sizeof(uint32_t)*(size_t)usize);
    tmp  = (uint32_t*) malloc(sizeof(uint32_t)*(size_t)0x3a01u);
    if (!P||!H||!ctx3||!tmp){ free(P);free(H);free(ctx3);free(tmp); return -1; }
    alz_arena2d_init(P, 32u);
    alz_ps_gen_ctxs(3u, g, usize, ctx3);
    /* [CONTRAT #17] UHA_LIVEWALK_FEED=<fichier> : feed d'évènements d'émission par bloc.
     * Lignes : `#B <n>` = courant‑bloc ; `<row> <sym> [learn]` = évènement (2 ou 3 champs).
     * Rétro‑compatible dual_sim (qui ignore `#`). P reçoit les évènements du bloc b APRÈS le
     * traitement de b → à l'entrée cls3 de b+1, P = émission des blocs 0..b (oracle exact). */
    {
        const char *ff = getenv("UHA_LIVEWALK_FEED");
        if (ff && *ff) {
            FILE *fp = fopen(ff, "r");
            if (fp) {
                char ln[128]; int curblk = 0;
                fcap = 65536; fblk=malloc(sizeof(int)*fcap); frow=malloc(sizeof(int)*fcap);
                fsym=malloc(sizeof(int)*fcap); flrn=malloc(sizeof(int)*fcap);
                feed_used = 1;
                while (fn < fcap && fgets(ln, sizeof ln, fp)) {
                    if (ln[0]=='\n') continue;
                    if (ln[0]=='#') { int nb; if (sscanf(ln, "#B %d", &nb)==1) curblk=nb; continue; }
                    int row, sym, lrn = 1, k;
                    k = sscanf(ln, "%d %d %d", &row, &sym, &lrn);
                    if (k < 2) continue;
                    if (row < 0 || row >= (int)ALZ_ARENA2D_MAX_ROW || sym < 0 || sym > 255) continue;
                    fblk[fn]=curblk; frow[fn]=row; fsym[fn]=sym; flrn[fn]=lrn?1:0; fn++;
                }
                fclose(fp);
            }
        }
    }
    for (b = 0; b < 6; b++) {
        uint32_t base = bp[b], len = bl[b];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        if (stats && base >= from) {
            uint32_t s68=0,n68=0,s37=0,n37=0;
            for(c=0;c<256u;c++){ if(P->freq[(68u<<8)+c]){s68+=P->freq[(68u<<8)+c];n68++;} if(P->freq[(37u<<8)+c]){s37+=P->freq[(37u<<8)+c];n37++;} }
            fprintf(stderr, "[DUAL] reload@0x%05x P freq68 SUM=%u nz=%u | freq37 SUM=%u nz=%u\n",
                    (unsigned)base,(unsigned)s68,(unsigned)n68,(unsigned)s37,(unsigned)n37);
        }
        /* [B↔#17 DIFF] dump l'état COMPLET de P (maître) à l'ENTRÉE du 1er bloc≥from (=cls3 b1)
         * → "row total freqsum nonzero" par ligne, pour diff automatique contre le bitmap de
         * référence dumpé par #17 à 0x413ea0. Gated UHA_LIVEWALK_DUMPOUT=<fichier>, 1 seule fois. */
        {
            const char *dop = getenv("UHA_LIVEWALK_DUMPOUT");
            static int dumped_once = 0;
            if (dop && *dop && base >= from && !dumped_once) {
                FILE *dp = fopen(dop, "w");
                dumped_once = 1;
                if (dp) {
                    uint32_t rr;
                    fprintf(dp, "# row total freqsum nonzero (P maître @entrée 0x%05x)\n", (unsigned)base);
                    for (rr = 0u; rr < ALZ_ARENA2D_MAX_ROW; rr++) {
                        uint32_t cc, fsum = 0u, fnz = 0u;
                        for (cc = 0u; cc < 256u; cc++) { uint32_t fq = P->freq[(rr<<8)|cc]; if (fq) { fsum += fq; fnz++; } }
                        fprintf(dp, "%u\t%u\t%u\t%u\n", (unsigned)rr, (unsigned)P->total[rr], (unsigned)fsum, (unsigned)fnz);
                    }
                    fclose(dp);
                }
            }
        }
        /* §1 RELOAD HOT := PERM(P) ; SCORAGE dense gen_ctxs(3) dans H → coût pré-learn */
        if (brscale && b > 0u) ps_rescale_all(P);   /* [BOUNDRESCALE] rescale par colonne à la frontière (cadence commit legacy) */
        *H = *P;
        (void) ps_score_ctxs(H, ctx3 + base, len, 32u, ALZ_PS_COLD0, NULL, NULL, tmp);
        if (base >= from) memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        /* [VALIDATION B, gated UHA_LIVEWALK_TRAJ, hors `out`] rejoue le scan bloc1 sur une copie
         * de P et trace H->total[68]/[37] par position → confront `leg_b1_tot68` (test de bout
         * en bout du consommateur, n'affecte PAS la sortie). */
        if (getenv("UHA_LIVEWALK_TRAJ") && base == from && ctx3) {
            alz_arena2d_t H2 = *P; uint32_t jj;
            for (jj = 0u; jj < len && jj < 1300u; jj++) {
                uint32_t sc = ctx3[base + jj], rw = (sc >> 8) & 0x1FFu, dl = sc & 0xffu, T0;
                if (rw >= ALZ_ARENA2D_MAX_ROW) rw = ALZ_ARENA2D_MAX_ROW - 1u;
                T0 = H2.total[68u];
                (void) alz_arena2d_score(&H2, rw, dl, NULL);          /* score+learn+rescale */
                fprintf(stderr, "[DUALTRAJ] %u\t%u\t%u\t%u\t%u\n", (unsigned)jj,
                        (unsigned)(base + jj), (unsigned)T0, (unsigned)H2.total[68u], (unsigned)H2.total[37u]);
            }
        }
        /* §2 EMISSION‑LEARN du P  >>> DUAL_LAW (#17) <<<  appliqué APRÈS le scan du bloc b,
         * donc P reflète l'émission des blocs 0..b à l'entrée cls3 de b+1. SOURCE = feed #17
         * (par bloc) si fourni ; sinon STUB baseline = littéraux sur row gen_ctxs(3). */
        if (feed_used) {
            int e;
            for (e = 0; e < fn; e++)
                if (fblk[e] == (int)b && flrn[e]) ps_learn(P, (frow[e] << 8) | fsym[e]);
        } else if (getenv("UHA_LIVEWALK_RECON") != NULL) {
            /* [TEST B] loi recon‑lag (comme s_acl.mem du clone) mais DENSE (toutes positions).
             * erow = (rctx>>8)&0x1ff, rctx=((rctx<<8)|g[q])&0x1FFFF ; sym = g[q].
             * Test : dense recon‑lag chauffe‑t‑il row68 vers 11130 en épargnant row37 ? */
            for (i = 0u; i < len; i++) {
                uint32_t q = base + i, erow;
                rctx = ((rctx << 8) | (g[q] & 0xffu)) & 0x1FFFFu;
                erow = (rctx >> 8) & 0x1FFu;
                ps_learn(P, (erow << 8) | (g[q] & 0xffu));
            }
        } else if (getenv("UHA_LIVEWALK_CMROW") != NULL) {
            /* [TEST B] prime P via le moteur CM (row_hash_cm&0x1ff si UHA_CMROWHASH, sinon aff) ;
             * teste si la loi de row CM reproduit le bitmap oracle. */
            ps_cmwire_advance_master(P, g, base, len, is_lit, usize);
        } else if (getenv("UHA_LIVEWALK_ALLCLASS") != NULL) {
            /* [TEST B] hypothèse : le maître accumule les 5 PASSES de classe (chaque position
             * contribue au row de CHAQUE classe), pas seulement cls3. Recharge carry mm par classe. */
            static uint32_t mm5[ALZ_PS_NCLASS][3] = {{0,0,1},{0,0,1},{0,0,1},{0,0,1},{0,0,1}};
            uint32_t cc;
            int only_lit = getenv("UHA_LIVEWALK_ALLCLASS_LIT") ? 1 : 0;
            const char *cl_env = getenv("UHA_LIVEWALK_CLASS");
            int single_class = cl_env ? atoi(cl_env) : -1;   /* -1 = les 5 classes ; sinon UNE seule */
            for (cc = 0u; cc < ALZ_PS_NCLASS; cc++) {
                if (single_class >= 0 && (int)cc != single_class) continue;
                for (i = 0u; i < len; i++) {
                    uint32_t sc = ps_ctx_step(cc, g, base + i, &mm5[cc][0], &mm5[cc][1], &mm5[cc][2]);
                    uint32_t row = (sc >> 8) & 0x1FFu;
                    if (only_lit && !is_lit[base + i]) continue;   /* ctx avance, n'apprend qu'aux littéraux émis */
                    if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
                    ps_learn(P, (row << 8) | (sc & 0xffu));
                }
            }
        } else { int dense_stub = getenv("UHA_LIVEWALK_DENSESTUB") ? 1 : 0; for (i = 0u; i < len; i++) {
            uint32_t q = base + i, sc = ctx3[q], row = (sc >> 8) & 0x1FFu;
            if (!dense_stub && !is_lit[q]) continue;   /* défaut: littéraux; DENSESTUB: toutes positions */
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            ps_learn(P, (row << 8) | (sc & 0xffu));
        } }
    }
    free(fblk); free(frow); free(fsym); free(flrn);
    free(P); free(H); free(ctx3); free(tmp);
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
    s_cml.rf70 = s_cml.rf74 = s_cml.rf78 = 0xffffffffu;   /* §13.796 reset registres section */
    s_cml.prev_pred = 0u;
    s_cml.sec = (long)sec_start;
    /* [GATED UHA_A3_CPRED0, défaut-OFF] indexation 0-base : le premier pas traite `g[0]`
     * (le legacy 0x415444 démarre à `ebp = 0`). Sans la porte, `done = 0` fait démarrer
     * la marche à `k = 1` et saute donc `g[0]`. */
    {
        /* PROMU défaut-ON au tour 39 : c'est la sémantique du legacy (`ebp = 0`), validée 32/32
         * deltas + 31/31 lignes sur `image.raw` pos 0 et 171 = GT sur `mixed`@30003 ; l'ancien
         * démarrage à `k = 1` sautait `g[0]` et rendait 17/31. `UHA_A3_CPRED0=0` rétablit l'ancien
         * comportement pour l'A/B. */
        static int s_cp0 = -1;
        if (s_cp0 < 0) {
            const char *e = getenv("UHA_A3_CPRED0");
            s_cp0 = (e && e[0] == '0') ? 0 : 1;
        }
        if (s_cp0 && sec_start == 0u)
            s_cml.done = 0xFFFFFFFFu;          /* done+1 == 0 : premier pas = g[0] */
        else
            s_cml.done = sec_start > 0u ? sec_start - 1u : 0u;
    }
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
    static int s_cpred = -1;
    if (s_cpred < 0) {
        const char *cp = getenv("UHA_A3_CPRED");
        s_cpred = cp ? atoi(cp) : 0;
        if (s_cpred < 0) s_cpred = 1;
    }
    int ip = (s_cpred >= 2) ? (int)idx_i : s_cml.last_prev_idx;
    uint32_t Pcur = ((taps6[ip%6u]&0xffu) + ((ip>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
    uint32_t Pprev = (i == 0u) ? 0u : (s_cpred ? s_cml.prev_pred : Pcur);
    uint8_t d = (uint8_t)(b_cur - Pprev);
    if (s_cpred >= 3) {
        fprintf(stderr, "[CPRED] k=%u i=%u b=%u idx_prev=%d idx=%u taps=%u,%u,%u,%u,%u,%u ip=%d Pcur=%u Pprev=%u sym=%u\n",
                (unsigned)k, (unsigned)i, (unsigned)b_cur, s_cml.last_prev_idx,
                (unsigned)idx_i, (unsigned)taps6[0], (unsigned)taps6[1], (unsigned)taps6[2],
                (unsigned)taps6[3], (unsigned)taps6[4], (unsigned)taps6[5], ip,
                (unsigned)Pcur, (unsigned)Pprev, (unsigned)((s_cml.rflag ? (uint8_t)(0u-(uint32_t)d) : d)));
    }
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
    {
        static int s_ccl = -1;
        int cl;
        if (s_ccl < 0) s_ccl = (getenv("UHA_CMCARRY_LEARN") != NULL) ? 1 : 0;
        cl = s_ccl;
        for (i = 0u; i < len; i++) {
            uint32_t row, sym, lo = 0u;
            if (alz_ps_cmlive_symrow(g, base + i, 0u, &row, &sym) != 0) { row = 0u; sym = (uint32_t) g[base + i] & 0xffu; }
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            (void) alz_arena2d_score(M, row, sym & 0xffu, cl ? &lo : NULL);
        }
    }
    s_ctx_seed = ctx_run;
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16 — GATED défaut-OFF, voie fidèle data‑driven] alz_ps_livewalk_master.
 * Recette validée `Σ==ORACLE` par `alz_ps_multi3` (l.605‑611) : un SNAPSHOT maître
 * `snap` PERSISTANT, RECHARGÉ `live:=snap` par bloc, chaque classe copiant snap→live
 * et SCORANT son flux (argmin 5 classes → gagnant). Le `snap` n'est avancé QUE par le
 * flux DENSE de la CLASSE GAGNANTE (cls3 pour image.raw) — pas par tous les littéraux,
 * pas par `gen_ctxs` — via `ps_score_ctxs` (cold/warm promo=32 + `rescale @0x4000`).
 * L'avance machine ctx (`ps_ctx_step(c,…)`) est un CARRY qui roule sur tout le fichier.
 * Sortie = coût PRÉ‑learn par position du `live` gagnant (miroir du `sm`). N'ÉCRIT
 * `out` que pour les blocs dont `base >= from` (overlay ; le bloc0 garde EMIPROD).
 * Retourne 0 OK, <0 erreur. Zéro effet hors gate (appelé sous `UHA_LIVEWALK`). */
int alz_ps_livewalk_master(const uint8_t *g, uint32_t usize,
                           const uint32_t *blkpos, const uint32_t *blklen,
                           int nblk, uint32_t from, uint32_t *out)
{
    alz_arena2d_t *snap, *live;
    uint32_t *ctxs[ALZ_PS_NCLASS], *tmp;
    uint32_t mm[ALZ_PS_NCLASS][3];
    uint32_t maxlen = 0u, seed_cls = 0u, stats = 0u;
    int b, k;
    if (!g || !blkpos || !blklen || !out || nblk <= 0)
        return -1;
    for (b = 0; b < nblk; b++)
        if (blklen[b] > maxlen) maxlen = blklen[b];
    snap = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    live = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    tmp  = (uint32_t *) malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
    if (!snap || !live || !tmp) { free(snap); free(live); free(tmp); return -1; }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
        ctxs[k] = (uint32_t *) malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
        mm[k][0] = mm[k][1] = 0u; mm[k][2] = 1u;   /* init carry (idem alz.c avance M) */
        if (!ctxs[k]) { while (--k >= 0) free(ctxs[k]); free(snap); free(live); free(tmp); return -1; }
    }
    alz_arena2d_init(snap, 32u);
    stats = getenv("UHA_LIVEWALK_STATS") ? 1u : 0u;
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i, c, order[ALZ_PS_NCLASS], cnt = 0u;
        uint32_t best = 0xffffffffu, winner = 0u;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* [sonde] reload du maître à l'entrée de CE bloc (= total après blocs précédents). */
        if (stats && base >= from)
            fprintf(stderr, "[LWM] reload@0x%05x t68=%u(tree68 cnt68=%u) t37=%u(tree37 cnt37=%u)\n",
                    (unsigned) base, (unsigned) snap->total[68u], (unsigned) snap->counter[68u],
                    (unsigned) snap->total[37u], (unsigned) snap->counter[37u]);
        /* (1) générer les flux ctx par classe sur TOUT le bloc (carry machine). */
        for (c = 0u; c < ALZ_PS_NCLASS; c++)
            for (i = 0u; i < len; i++)
                ctxs[c][i] = ps_ctx_step(c, g, base + i, &mm[c][0], &mm[c][1], &mm[c][2]);
        /* (2) ordre : seed (gagnant bloc précédent) d'abord, puis ascendant. */
        order[cnt++] = seed_cls;
        for (c = 0u; c < ALZ_PS_NCLASS; c++) if (c != seed_cls) order[cnt++] = c;
        /* (3) argmin : chaque classe copie snap→live et score (abandon précoce). */
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cc = order[(uint32_t)k], s;
            *live = *snap;
            s = ps_score_ctxs(live, ctxs[cc], len, 32u, ALZ_PS_COLD0,
                              (k == 0) ? NULL : &best, NULL, NULL);
            if (s < best) { best = s; winner = cc; }
        }
        /* (4) SORTIE : coût par position du `live` gagnant (rechargé depuis snap). */
        *live = *snap;
        (void) ps_score_ctxs(live, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, tmp);
        if (base >= from) memcpy(out + base, tmp, (size_t) len * sizeof(uint32_t));
        /* (5) avancer le SNAP maître par le flux DENSE du gagnant (persiste inter‑blocs). */
        (void) ps_score_ctxs(snap, ctxs[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
        seed_cls = winner;
    }
    for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxs[k]);
    free(snap); free(live); free(tmp);
    return 0;
}

/* ==========================================================================
 * [ARENA_TASK16 — MESURE, gated UHA_LIVEWALK_LC, N'ÉCRIT PAS `out`] maître « literal‑carry ».
 * Hypothèse data‑driven (hit68 729 vs GT 420) : le legacy fait avancer la machine ctx
 * (`ps_ctx_step(3)` carry ebx/flag/ebp) UNIQUEMENT aux ÉMISSIONS de LITTÉRAL (carry gelé
 * pendant les runs de match), et n'APPREND le maître (0x4111a0) qu'à ces mêmes émissions.
 * Ici : `snap` maître persistant (init 32), mm[3] carry pas‑à‑pas ; pour q croissant, si
 * is_lit[q] → ctx=ps_ctx_step(3,…,&mm) puis learn snap (cold/warm + rescale @0x4000).
 * Digite tree/counter/hit de rows 68/37 à l'entrée de chaque bloc (via _STATS) pour
 * confront à GT (tree68=13438 tree37=4496, hit≈420/140). Retourne 0. */
int alz_ps_livewalk_litcarry(const uint8_t *g, uint32_t usize,
                             const uint32_t *blkpos, const uint32_t *blklen,
                             int nblk, const uint8_t *is_lit, uint32_t *out_stats)
{
    alz_arena2d_t *snap;
    uint32_t mm[3] = {0u, 0u, 1u};
    uint32_t hit68 = 0u, hit37 = 0u;
    int b; uint32_t i, q, c;
    (void)out_stats;
    if (!g || !is_lit || nblk <= 0) return -1;
    snap = (alz_arena2d_t *) malloc(sizeof(alz_arena2d_t));
    if (!snap) return -1;
    alz_arena2d_init(snap, 32u);
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], r, sum68 = 0u, sum37 = 0u, col;
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        /* entrée de bloc : snapshot du maître (reload total:=tree+counter est la loi de
         * rescale(); ici on lit l'état cumulé). */
        for (col = 0u; col < 256u; col++) { sum68 += snap->freq[(68u<<8)+col]; sum37 += snap->freq[(37u<<8)+col]; }
        (void)r;
        fprintf(stderr, "[LC] blk%d base=0x%05x t68=%u(tree68=%u cnt68=%u hit68=%u) t37=%u(tree37=%u cnt37=%u hit37=%u)\n",
                b, (unsigned)base, (unsigned)snap->total[68u], (unsigned)sum68, (unsigned)snap->counter[68u], (unsigned)hit68,
                (unsigned)snap->total[37u], (unsigned)sum37, (unsigned)snap->counter[37u], (unsigned)hit37);
        for (i = 0u; i < len; i++) {
            uint32_t ctx, row, delta;
            q = base + i;
            if (!is_lit[q]) continue;                 /* carry GELÉ pendant les matchs */
            ctx = ps_ctx_step(3u, g, q, &mm[0], &mm[1], &mm[2]);
            row = ctx >> 8; delta = ctx & 0xffu;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            if (q >= 0x3100u) { }                      /* (learn bloc0 uniquement pour la mesure du reload b1) */
            /* learn maître = cold/warm + rescale @0x4000 (réutilisé via un mini‑inline) */
            {
                uint32_t T = snap->total[row], f = snap->freq[(row<<8)|delta], inc = snap->promo[row];
                if (f == 0u) { snap->freq[(row<<8)|delta]=(uint16_t)inc; snap->counter[row]=(uint16_t)(snap->counter[row]+inc); snap->total[row]=(uint16_t)(T+2u*inc); }
                else         { snap->freq[(row<<8)|delta]=(uint16_t)(f+inc); snap->total[row]=(uint16_t)(T+inc); }
                if (snap->total[row] >= ALZ_ARENA2D_RESCALE) alz_arena2d_rescale(snap, row);
            }
            if (row == 68u) hit68++;
            else if (row == 37u) hit37++;
        }
    }
    (void)c;
    free(snap);
    return 0;
}

/* [GATED UHA_CM_WIRE, §13.803 M5] Produit g_lmin = cost[rc] BIT-EXACT sur la section
 * [base,base+len). Recette validée 100 % par ISOL_M5/m5_harness.c : CM engine dense sur
 * les litteraux (is_lit) -> sym/aff (row d'affinite R1), avec LAG de ligne (relrow=aff[i-1]),
 * arena2d WORKING (score+learn, rescale 0x414590), WARM=1 LUT / COLD=LUT[64]+LUT[(cnt<<14)/total]
 * (maitre fenwick a sa seed freqM=4/fenwick=1024). Ne TOUCHE PAS le maitre M. */
static void ps_cmwire_dens(const uint8_t *g, uint32_t base, uint32_t len,
                           const uint8_t *is_lit, uint32_t *out)
{
    static const uint32_t MASKW[6] = {127u,127u,127u,127u,7u,3u};
    alz_cm_learner L; memset(&L, 0, sizeof L);
    alz_arena A; alz_arena_init(&A);
    alz_arb   R; alz_arb_init(&R);
    alz_arena2d_t S; alz_arena2d_init(&S, 32u);   /* arène de SCORAGE working (section) */
    uint32_t rf70 = 0xffffffffu, rf74 = 0xffffffffu, rf78 = 0xffffffffu; int rflag = 0;
    int lpi = 0; int32_t prev_rh = 0;
    uint32_t aff_cost = 0, idx_cost = 0;          /* LAG ligne i-1 */
    uint32_t i;
    (void)is_lit;
    for (i = 0; i < len; i++) {
        uint32_t abs = base + i;
        /* M5 : le scoreur avance à TOUT rc (dense) ; is_lit-avance sous-avance l'arène
         * et fait dériver cost[rc] dès ~rc544. (m5_harness avance à gt_have_engine ≈ dense.) */
        uint8_t b_cur   = g[abs];
        uint8_t b_prev  = (i >= 1u) ? g[abs - 1u] : 0x80u;
        uint8_t b_prev2 = (i >= 2u) ? g[abs - 2u] : 0x80u;
        int32_t base_i  = (int32_t)b_cur - 0x80;
        int32_t base_p1 = ps_b(g, (long)base, (long)abs - 1);
        int32_t base_p2 = ps_b(g, (long)base, (long)abs - 2);
        int32_t dl      = ps_q(g, (long)base, (long)abs);
        int32_t ref_prev = (int32_t)A.ref, b8_prev = (int32_t)A.b8;
        int32_t dr_ref = ps_q(g, (long)base, (long)abs - ref_prev);
        int32_t dr_b8  = ps_q(g, (long)base, (long)abs - b8_prev);
        int32_t row_hash_model = prev_rh;
        uint32_t idx_gate = R.idx;
        int entered = ((MASKW[idx_gate % 6u] & abs) == 0u);
        A.line = abs; alz_arena_step(&A, b_cur, b_prev, entered);
        R.line = abs;
        alz_arb_predict(&R, base_i, base_p1, base_p2, dl, dr_ref, dr_b8, row_hash_model);
        uint32_t idx_i = R.idx;
        int32_t dr_learn = ps_q(g, (long)base, (long)(abs + 1) - (int32_t)A.ref);
        alz_cm_learn_byte(&L, b_cur, b_prev, b_prev2, dr_learn);
        /* machine registre -> sym, aff (R1) */
        uint32_t tap[6]; uint8_t vp1 = (uint8_t)base_p1, vp2 = (uint8_t)base_p2;
        tap[0]=0; tap[1]=vp1; tap[2]=(uint8_t)(2*(int32_t)vp1-(int32_t)vp2);
        tap[3]=(uint8_t)row_hash_model;
        tap[4]=(uint8_t)A.dr[(abs-(uint32_t)ref_prev)&0x7fu];
        tap[5]=(uint8_t)A.dr[(abs-(uint32_t)b8_prev )&0x7fu];
        uint32_t Pcur = ((tap[lpi%6]&0xffu) + ((lpi>=4)?(uint32_t)vp1:0u) + 0x80u) & 0xffu;
        uint32_t Pprev = (i == 0u) ? 0u : Pcur;
        uint8_t d = (uint8_t)((uint32_t)b_cur - Pprev);
        uint8_t sym = rflag ? (uint8_t)(0u-(uint32_t)d) : d;
        rf70 = (rf70<<8)|sym; rf74 = (rf74<<8)+ALZ_REG_T1[sym]; rf78 = (rf78<<8)+ALZ_REG_T2[sym];
        if (sym >= 0x80u) rflag ^= 1;
        uint32_t aff = (rf70==0u)?1u:(rf74==0u)?2u:(rf78==0u)?3u:0u;
        lpi = (int)idx_i; prev_rh = L.prev_dot_full;
        /* coût = cost[rc] avec LAG (relrow = aff de la LIGNE PRÉCÉDENTE), sym courant */
        uint32_t rel = aff_cost;                 /* LAG */
        uint32_t freqF = alz_arena2d_freq(&S, rel, sym);
        uint32_t cnt   = S.counter[rel];
        uint32_t T_before = S.total[rel];
        uint32_t cost;
        if (freqF != 0u) {                        /* WARM 1 terme */
            uint32_t p2 = (T_before!=0u)?((freqF<<14)/T_before):(ALZ_SCORE_CUM_N-1u);
            if (p2 >= ALZ_SCORE_CUM_N) p2 = ALZ_SCORE_CUM_N-1u;
            cost = alz_score_proba_to_cost(p2);
        } else {                                  /* COLD 2 termes (maitre à sa seed) */
            uint32_t p1 = (1024u!=0u)?((4u<<14)/1024u):(ALZ_SCORE_CUM_N-1u);   /* freqM=4,fenwick=1024 -> 64 */
            if (p1 >= ALZ_SCORE_CUM_N) p1 = ALZ_SCORE_CUM_N-1u;
            uint32_t p2 = (T_before!=0u)?((cnt<<14)/T_before):(ALZ_SCORE_CUM_N-1u);
            if (p2 >= ALZ_SCORE_CUM_N) p2 = ALZ_SCORE_CUM_N-1u;
            cost = alz_score_proba_to_cost(p1) + alz_score_proba_to_cost(p2);
        }
        (void)alz_arena2d_score(&S, rel, sym, NULL);   /* avance (learn+rescale working) */
        aff_cost = aff; idx_cost = idx_i;
        out[abs] = cost;
    }
    (void)idx_cost;
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
    int b, dense = 0, masterlaw = 0, cmwire = 0, cmwire_prod = 0, emcarry = 0, mbound = 0, mcold = 0, litcarry = 0;
    FILE *cd = NULL;   /* [GATED UHA_CTXDUMP, défaut-OFF] journal pos/relrow/delta/octet. */

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
    {   /* [GATED UHA_AADUMP, LECTURE SEULE] ouvre la sonde (row,freq,total) cls3. */
        const char *ad = getenv("UHA_AADUMP");
        if (ad && *ad) g_adump = fopen(ad, "w");
        /* [GATED UHA_EMIPROD_DENSE] master apprend à TOUTES les positions (sinon lits seuls). */
        if (getenv("UHA_EMIPROD_DENSE")) dense = 1;
        /* [GATED UHA_EMIPROD_LITCARRY, défaut‑OFF, ARENA_TASK16] le maître avance sa machine
         * ctx (carry mm) ET apprend UNIQUEMENT aux émissions de LITTÉRAL (carry gelé pendant
         * les runs de match) — miroir du learn d'émission `0x4111a0`. Réduit `reload[68]` de
         * 15248 (source‑order) vers ~14257 (GT 13501, écart +5,6 % vs +13 %). */
        if (getenv("UHA_EMIPROD_LITCARRY")) litcarry = 1;
        /* [GATED UHA_EMIPROD_MASTERLAW] rescale du maître = loi 0x40ffa0 (≠ working). */
        if (getenv("UHA_EMIPROD_MASTERLAW")) masterlaw = 1;
        /* [GATED UHA_MCOLD, défaut-OFF, §14.127] ne PAS avancer le maître (M reste
         * froid) : teste l'hypothèse « la legacy garde M cold, seul W accumule ».
         * Combiné à UHA_WLEARNLIT pour la passe de sortie. */
        if (getenv("UHA_MCOLD")) mcold = 1;
        /* [GATED UHA_CM_WIRE, défaut-OFF] bande registre (aff∈{0..3}) vs proxy cls3. */
        if (getenv("UHA_CM_WIRE")) cmwire = 1;
        /* [GATED UHA_CMWIRE_PROD, défaut‑OFF] Surcharge producteur g_lmin=cost[rc] (M5/argmin).
         * Désactivable pour tester la feed CM acclive SEULE (§13.859). */
        if (getenv("UHA_CMWIRE_PROD")) cmwire_prod = 1;
        /* [GATED UHA_CM_EMCARRY, défaut‑OFF] carry maître d'émission arena2d (§13.897). */
        if (getenv("UHA_CM_EMCARRY")) emcarry = 1;
        /* [GATED UHA_CM_MBOUND, défaut‑OFF] rescale maître aux frontières de bloc (§13.911) ;
         * valeur = NB de rescales à chaque frontière (cadence du scribe). */
        { const char *mb = getenv("UHA_CM_MBOUND"); if (mb) mbound = atoi(mb); }
        /* [GATED UHA_CTXDUMP=chemin, défaut-OFF] journal (pos,relrow=e,delta,octet) par
         * position de la machine cls3, pour diff vs flux réel learn 0x411bb8 (§13.738). */
        {   const char *cx = getenv("UHA_CTXDUMP");
            if (cx && *cx) cd = fopen(cx, "w");
        }
        /* [GATED UHA_PHASEFIX, défaut-OFF] phase cls3 = (abs+2)%3 (scan OUT + avance M). */
        if (getenv("UHA_PHASEFIX")) g_ps_phasefix = 1;
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b], i;
        alz_ps_carry_t stW;
        uint32_t mm[3];
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        /* [GATED UHA_CM_MBOUND, défaut-OFF, §13.911] rescale du MAÎTRE à la frontière de
         * bloc (le scribe ré-échelle `M` entre blocs) : refroidit le working reloadé au
         * block1 → cible `esi` front ↓ vers 58364. Mécanisme, pas réglage. */
        if (mbound && b > 0) {
            uint32_t rr, nb; for (nb = 0u; nb < (uint32_t)mbound; nb++)
                for (rr = 0u; rr < ALZ_ARENA2D_MAX_ROW; rr++) alz_arena2d_rescale(M, rr);
        }
        /* [GATED UHA_A3_ESCFEED] frontière de bloc : le modèle d'escape encaisse les
         * événements froids du bloc précédent (+16 chacun). */
        if (b > 0) ps_esc_boundary();
        /* (1) snapshot working = copie du master, puis scan DENSE intra-bloc cls3
         *     (score + learn) ⟹ coût figé par position dans `tmp`. */
        *W = *M;
        memset(&stW, 0, sizeof stW);
        stW.ebp = 1u;
        stW.arena = W;
        /* [GATED UHA_WLEARNLIT, défaut-OFF] la passe de sortie (cls3) n'apprend que
         * sur les LITTÉRAUX émis (is_lit), tout en scorant chaque position. */
        if (getenv("UHA_WLEARNLIT") && base >= 0x3100u) g_ps_learn_mask = is_lit;
        g_esc_count = 1;   /* [GATED UHA_A3_ESCFEED] compte les froids de la passe de SORTIE */
        (void) alz_ps_class_sigma_carry(&stW, 3u, g, base, len, 32u, ALZ_PS_COLD0,
                                       NULL, tmp, NULL);
        g_esc_count = 0;
        g_ps_learn_mask = NULL;
        memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        /* [GATED UHA_CM_EMCARRY, §13.897] surcharge par la dens du carry maître d'émission. */
        if (emcarry) (void) alz_ps_emission_master_carry(g, base, len, out);
        /* [GATED UHA_CM_WIRE, §13.803] APRÈS le memcpy du proxy : SURCHARGE g_lmin[pos]
         * = cost[rc] BIT-EXACT (M5) aux seuls littéraux (non-littéraux gardent le proxy). */
        if (cmwire && cmwire_prod) ps_cmwire_dens(g, base, len, is_lit, out);
        /* (2) avancer le MASTER : machine cls3 relative-bloc (ebp=1, alignée), mais
         *     n'APPRENDRE qu'aux LITTÉRAUX ÉMIS (rien sur les matchs).
         *     [GATED UHA_CM_WIRE] : voie fidèle sym→row (engine CM dense) à la place du proxy. */
        if (cmwire) {
            ps_cmwire_advance_master(M, g, base, len, is_lit, usize);
        } else {
        mm[0] = 0u; mm[1] = 0u; mm[2] = 1u;
        for (i = 0u; !mcold && i < len; i++) {
            uint32_t c;
            /* [LITCARRY] carry GELÉ + aucun learn pendant les octets couverts par MATCH. */
            if (litcarry && !is_lit[base + i]) continue;
            c = ps_ctx_step(3u, g, base + i, &mm[0], &mm[1], &mm[2]);
            uint32_t row;
            /* [GATED UHA_PHASEFIX] même correction de phase que le scan OUT. */
            if (g_ps_phasefix) {
                uint32_t e = (c >> 8) & 0x1fu;
                e += (((base + i + 2u) % 3u) << 5);
                c = (e << 8) | (c & 0xffu);
            }
            row = c >> 8;
            if (cd && is_lit[base + i])
                fprintf(cd, "%u 0x%x 0x%x 0x%x\n", base + i, row, c & 0xffu, g[base + i]);
            if (!dense && !is_lit[base + i]) continue;
            if (row >= ALZ_ARENA2D_MAX_ROW) row = ALZ_ARENA2D_MAX_ROW - 1u;
            if (masterlaw) (void) alz_arena2d_master_learn(M, row, c & 0xffu);
            else           (void) alz_arena2d_score(M, row, c & 0xffu, NULL);
        }
        }
    }
    if (cd) { fclose(cd); cd = NULL; }
    g_ps_phasefix = 0;
    if (g_adump) { fclose(g_adump); g_adump = NULL; }
    return 0;
}

/* ==========================================================================
 * [§13.722 classpass producteur dens — GATED par l'appelant alz.c UHA_CLASSPASS,
 * DEFAUT-OFF] Producteur FIDELE au legacy `0x414630` : UNE seule arène SHARED
 * monotone (§13.717 « 1 buffer monotone ») traversée par 5 PASSES de classe par
 * bloc, chaque passe SCORANT + APPRENNANT (promo=32, rescale 0x4000 — miroir des
 * apprentissages `0x4149d0..0x4149f2` de `0x414630`). Ordre des passes :
 * `0,1,2,3,4` (bloc0) puis `3,0,1,2,4` (blocs ≥ 1) (§13.717(2)/§13.721).
 * La machine ctx (ebx/flag/ebp) est RE-AMORCÉE à chaque passe (setup `0x414645`
 * par appel), l'arène N'EST JAMAIS réinitialisée. Le snapshot consommé par le
 * décidez = sortie de la passe `cls3` (1ʳᵉ copie figée, §13.719(2)/§13.721(1))
 * ⟹ `out[base+i]` n'est écrit que durant la passe cls3. Formule de coût validée
 * EXACT 11/11 sur la fenêtre @13070 (§13.722(2)). Pur : n'affecte aucune arène
 * globale, buffers locaux. Retourne 0 OK, <0 erreur. */
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
    /* [GATED UHA_CLASSPASS_COLD, défaut-OFF, diagnostic §13.723] Hypothèse :
     * master@bloc1 quasi-VIDE pour les cellules cls3 (le LIVE de block0 apprend
     * surtout d'autres rows) ⟹ producteur fidèle = arène FROIDE par bloc + scan
     * DENSE intra-bloc cls3 (rien de cross-bloc, aucune des 5 autres passes).
     * Test : à chaque bloc, RE-INIT `ar` (master cold) et ne courir QUE cls3. */
    if (getenv("UHA_CLASSPASS_COLD") != NULL) {
        for (b = 0; b < nblk; b++) {
            uint32_t base = blkpos[b], len = blklen[b];
            alz_ps_carry_t st;
            if (base >= usize) continue;
            if (base + len > usize) len = usize - base;
            if (!len) continue;
            alz_arena2d_init(ar, 32u);          /* master cold par bloc (restore=∅) */
            memset(&st, 0, sizeof st);
            st.ebp = 1u;
            st.arena = ar;
            (void) alz_ps_class_sigma_carry(&st, 3u, g, base, len, 32u, ALZ_PS_COLD0,
                                            NULL, tmp, NULL);
            memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        }
        free(ar); free(tmp);
        return 0;
    }
    /* [GATED UHA_CPADV=<0..3>, défaut-OFF, §13.733 fix-classpass-model]
     * MODÈLE RESTORÉ fidèle à l'ASM (`full.asm` l.24140-25010) : MASTER `M`
     * persistant ; par bloc × par classe, WORKING `W := copie fraîche de M` puis
     * scan DENSE de la classe dans W (jeté). `out` = passe gagnante (argmin,≡cls3).
     * Le MASTER est avancé entre blocs par la loi d'émission UHA_CPADV (balayage) :
     *   0 = froid (aucune avance ⟹ restore-only, master vide) ;
     *   1 = dense-cls3 (1 év/pos sur le row cls3) ≡ avancement COSTSNAP ;
     *   2 = dense TOUTES classes (5 év/pos, file des 5 flux) ;
     *   3 = dense par-position argmin-classe (1 év/pos, row de la CLASSE GAGNANTE
     *       de CE position, argmin read-only dans M) — même DENSITÉ que 1 mais
     *       ROWS hétérogènes (§13.726 « densité par-row », le levier non réfuté).
     * Machine ctx threadée GLOBALEMENT par classe (comme COSTSNAP). Non-régressif :
     * UHA_CLASSPASS seul garde le chemin partagé. SUBSTITUTION interdite. */
    {
        const char *advs = getenv("UHA_CPADV");
        if (advs && advs[0] >= '0' && advs[0] <= '3') {
            int law = advs[0] - '0';
            alz_arena2d_t *M = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
            alz_arena2d_t *W = (alz_arena2d_t *)malloc(sizeof(alz_arena2d_t));
            uint32_t *ctxp[ALZ_PS_NCLASS];
            uint32_t cmm[ALZ_PS_NCLASS][3];
            int ok = (M != NULL && W != NULL);
            if (!ok) { free(M); free(W); free(ar); free(tmp); return -1; }
            alz_arena2d_init(M, 32u);
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
                cmm[k][0] = cmm[k][1] = cmm[k][2] = 0u;
                ctxp[k] = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)(maxlen ? maxlen : 1u));
                if (!ctxp[k]) ok = 0;
            }
            if (!ok) { for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxp[k]); free(M); free(W); free(ar); free(tmp); return -1; }
            for (b = 0; b < nblk; b++) {
                uint32_t base = blkpos[b], len = blklen[b], i, c;
                uint32_t best = 0xffffffffu, winner = 3u;
                if (base >= usize) continue;
                if (base + len > usize) len = usize - base;
                if (!len) continue;
                /* (1) générer les 5 flux ctx sur TOUT le bloc (machines globales). */
                /* [GATED UHA_CPCTX, défaut-OFF, §13.881] lignes d'émission par `ctx` roulant
                 * (M11b : ctx=(ctx<<8)|octet ; row=(ctx>>8)&0x1ff ; sym=octet), réinitialisé
                 * par passe de classe (reload M10). Remplace le delta‑2D `ps_ctx_step`. */
                if (getenv("UHA_CPCTX") != NULL) {
                    for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                        uint32_t ctxr = 0u;
                        for (i = 0u; i < len; i++) {
                            uint32_t bytev = g[base + i];
                            ctxr = ((ctxr << 8) | bytev) & 0xffffffffu;
                            ctxp[c][i] = (((ctxr >> 8) & 0x1ffu) << 8) | (bytev & 0xffu);
                        }
                    }
                } else
                for (c = 0u; c < ALZ_PS_NCLASS; c++)
                    for (i = 0u; i < len; i++)
                        ctxp[c][i] = ps_ctx_step(c, g, base + i, &cmm[c][0], &cmm[c][1], &cmm[c][2]);
                /* (2) argmin par RESTORE : W := copie(M), scan dense classe, jeter. */
                for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                    uint32_t s, np = 0;
                    *W = *M;
                    ps_set_promo_all(W, 32u);
                    s = ps_score_ctxs(W, ctxp[c], len, 32u, ALZ_PS_COLD0,
                                      (c == 0u) ? NULL : &best, &np, NULL);
                    if (s < best) { best = s; winner = c; }
                }
                /* (3) out = passe gagnante sur copie fraîche de M (sans abandon). */
                if (base >= 0x3100u && base < 0x3101u && getenv("UHA_CPADV_STATS"))
                    fprintf(stderr, "[CPADV] reload@0x%05x M t68=%u t37=%u\n",
                            (unsigned) base, (unsigned) M->total[68u], (unsigned) M->total[37u]);
                *W = *M;
                ps_set_promo_all(W, 32u);
                ps_score_ctxs(W, ctxp[winner], len, 32u, ALZ_PS_COLD0, NULL, NULL, out + base);
                /* (4) avancer le MASTER selon la loi UHA_CPADV. */
                if (law == 1) {
                    ps_score_ctxs(M, ctxp[3u], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
                } else if (law == 2) {
                    for (c = 0u; c < ALZ_PS_NCLASS; c++)
                        ps_score_ctxs(M, ctxp[c], len, 32u, ALZ_PS_COLD0, NULL, NULL, NULL);
                } else if (law == 3) {
                    for (i = 0u; i < len; i++) {
                        uint32_t bb = 0xffffffffu, wc = 0u, cs;
                        for (c = 0u; c < ALZ_PS_NCLASS; c++) {
                            cs = ps_cost_of(M, ctxp[c][i], ALZ_PS_COLD0);
                            if (cs < bb) { bb = cs; wc = c; }
                        }
                        ps_learn(M, ctxp[wc][i]);
                    }
                }
                /* law == 0 : master jamais avancé (restore-only). */
            }
            for (k = 0; k < (int)ALZ_PS_NCLASS; k++) free(ctxp[k]);
            free(M); free(W);
            free(ar); free(tmp);
            return 0;
        }
    }
    for (b = 0; b < nblk; b++) {
        uint32_t base = blkpos[b], len = blklen[b];
        /* [GATED UHA_CP3LAST, défaut-OFF, §14.138] ordre cls3 EN DERNIER pour blocs>=1
         * (l'arène SHARED est d'abord réchauffée par les 4 autres classes, puis cls3
         * écrit out) → teste si le warm multi‑classes intra‑bloc atteint cost[rc] legacy. */
        static const uint32_t ordL[ALZ_PS_NCLASS] = { 0u, 1u, 2u, 4u, 3u };
        const uint32_t *ord = (b == 0) ? ord0
                            : (getenv("UHA_CP3LAST") ? ordL : ord1);
        if (base >= usize) continue;
        if (base + len > usize) len = usize - base;
        if (!len) continue;
        if (base >= 0x3100u && base < 0x3101u && getenv("UHA_CPSTATS"))
            fprintf(stderr, "[CP] shared ar@b1 t68=%u t37=%u\n",
                    (unsigned) ar->total[68u], (unsigned) ar->total[37u]);
        for (k = 0; k < (int)ALZ_PS_NCLASS; k++) {
            uint32_t cls = ord[k];
            alz_ps_carry_t st;
            memset(&st, 0, sizeof st);      /* machine ctx re-amorcée par passe */
            /* Legacy : `0x414a51 inc ebp` AVANT le calcul machine (`0x414bde`),
             * ebp re-semé au compteur RELATIF bloc ⟹ row(i) = table[δ(i-1)] +
             * phase(i%3). Graine 1 (et non 0 du ps_ctx_step défaut) prouvée par
             * la fenêtre §13.722 : row(526)=t3[5]+32*(526%3)=37 ✓ 11/11. */
            st.ebp = 1u;
            st.arena = ar;                  /* arène SHARED monotone */
            (void) alz_ps_class_sigma_carry(&st, cls, g, base, len, 32u, ALZ_PS_COLD0,
                                            NULL, (cls == 3u) ? tmp : NULL, NULL);
            if (cls == 3u)
                memcpy(out + base, tmp, (size_t)len * sizeof(uint32_t));
        }
    }
    free(ar); free(tmp);
    return 0;
}

/* [TEST hook] Permet au harness offline d'aligner la correction de phase cls3
 * (g_ps_phasefix) sans passer par getenv ; sans effet sur l'encodage standard. */
void alz_ps_set_phasefix(int v) { g_ps_phasefix = v; }

