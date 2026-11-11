#ifndef ALZ_CM_H
#define ALZ_CM_H

#include <stdint.h>

/*
 * alz_cm — Modèle de contexte (CM) delta-2D adaptatif du legacy UHARC ALZ.
 *
 * Portage FIDÈLE des primitives entièrement reconstituées par RE :
 *   - table de deltas en anneau (§13.55)          : déterministe, statique
 *   - rotation d'history + hash de contexte (§13.61): produit scalaire ÷16
 *   - clamp des poids ±32 (§13.56)                 : descente de gradient
 *   - min-scan des accumulateurs (§13.56)          : structure connue
 *   - rescale par halving 16-bit packés (§13.57)   : normalisation d'arène
 *
 * ⚠ État : module AUTONOME, NON BRANCHÉ sur le chemin d'émission (B3).
 *   La chaîne exacte « row → ligne d'arène → freq → proba → bits » reste à RE
 *   (§13.62). Ce fichier pose les primitives vérifiables contre le désassemblage.
 *   Le self-test (alz_cm_selftest) valide les invariants déterministes.
 */

#define ALZ_CM_RING       4096u   /* anneau des deltas : TABLE[i], index (delta<<4)&0xfff */
#define ALZ_CM_RING_HALF  2048u   /* mi-période : distance circulaire */
#define ALZ_CM_WMIN       (-32)   /* borne basse poids (§13.56) */
#define ALZ_CM_WMAX       32      /* borne haute poids (§13.56) */
#define ALZ_CM_NHIST      4       /* slots d'history (R[0x00,04,08,0c]) */
#define ALZ_CM_NWEIGHT    5       /* poids w0..w4 (R[0x14..0x24]) */
#define ALZ_CM_NACC        11      /* accumulateurs du min-scan (R+0x30..0x58) */
#define ALZ_CM_ADAPT_PERIOD 16    /* périodicité min-scan (compteur & 0xf == 0) */
#define ALZ_CM_NCLASS      5       /* classes de contexte (argmin 0..4, §13.52) */
#define ALZ_CM_ARENA_BLOCK 0x200u  /* taille bloc d'arène par classe (octets) */
#define ALZ_CM_LHIST       5       /* longueurs de la chaîne d'histoires du finder (§13.100 : rec[0x00..0x10]) */

/* Record de contexte par-classe — reflète les offsets du record legacy (0x7c). */
typedef struct {
    uint32_t h[ALZ_CM_NHIST];        /* R[0x00,04,08,0c] : history (chaîne de différences) */
    int32_t  w[ALZ_CM_NWEIGHT];      /* R[0x14,18,1c,20,24] : poids w0..w4 bornés ±32 */
    uint32_t base;                   /* R[0x28] : base-octet (décalé <<4 dans le hash) */
    int32_t  delta;                  /* R[0x2c] : delta signé courant (entrée) */
    uint32_t acc[ALZ_CM_NACC];       /* R+0x30..0x58 : accumulateurs de TABLE */
    uint32_t counter;                /* R+0x6c : compteur d'inserts (pilote /16) */
} alz_cm_record;

/*
 * Contexte d'APPRENTISSAGE du finder legacy (0x415ab0, §13.100). Autonome vis-
 * à-vis d'`alz_cm_record` (qui porte le hash/rotation) pour ne pas destabiliser
 * les primitives déjà validées. Reflète le record global 0x44f0fc-ancré :
 *   w[0..4]   = poids rec[0x14..0x24] (clamp ±32)
 *   acc[0..10]= 11 accumulateurs rec[0x30..0x58]
 *   hist[0..4]= chaîne rec[0x00..0x10] (maintenue par le selecteur/callant)
 *   v         = rec[0x28] (base = byte-0x80, ordre-dependant)
 *   delta     = rec[0x2c] (v - v_prev)
 *   counter   = rec[0x6c]
 */
typedef struct {
    int32_t  w[ALZ_CM_NWEIGHT];      /* w0..w4 */
    uint32_t acc[ALZ_CM_NACC];       /* 11 accumulateurs */
    uint32_t hist[ALZ_CM_LHIST];     /* chaîne d'histoires du finder */
    uint32_t v;                       /* base = byte-0x80 */
    int32_t  delta;                   /* v - v_prev */
    uint32_t counter;                /* rec[0x6c] */
    uint32_t prev_dot;               /* (dot/16)&0xff : bas-octet pour l'err d'apprentissage (§13.100) */
    int32_t  prev_dot_full;          /* dot/16 SIGNÉ complet = 0x44d8d8 ; opérande prédicteur p3 (§13.113) */
} alz_cm_learner;

/*
 * alz_cm_learn_step — un pas d'apprentissage du finder, FIDÈLE §13.100 (validé
 * anneau 165/165 + min-scan sur frontière). Appelé APRÈS que le selecteur a posé
 * les histoires (hist[]) et calcule row_hash. Aucun effet d'encodage (non-wired).
 *
 *   L->w, L->acc, L->hist, L->v, L->counter : état persistant.
 *   row_hash_byte : octet bas du dot/16 (0x44d8d8) = PREDICTION du pas.
 *   v_cur : valeur de contexte de l'octet courant (order5 : byte-0x80).
 * Enchaîne : err = movsbl(row_hash_byte - v_cur)<<4 ; MàJ 11 accu via ring[err ∓ h_k] ;
 *   delta = v_cur - v ; v = v_cur ; counter++ ; si (counter & 0xf)==0 : min-scan.
 */
void alz_cm_learn_step(alz_cm_learner *L, uint32_t row_hash_byte, uint32_t v_cur);

/*
 * alz_cm_rotate_hist — rotation de la chaîne de 5 opérandes du dot CM legacy
 * (récents 0x44f100..0x44f10c + delta 0x44f128), VALIDÉE §13.102/§13.113.
 * Le dot legacy (objdump 0x415778..0x4157f2) =
 *   (base<<4) + w0*delta + w1*rec0 + w2*rec1 + w3*rec2 + w4*rec3
 * avec (0x415761..0x415793) la rotation EXACTE :
 *   hist[0] = D                       (delta courant 0x44f128 ; operand w0)
 *   hist[1] = D - hist[0]_prev        (rec0 = 2e différence 0x44f100)
 *   hist[2] = hist[1]_prev            (rec1 = shift 0x44f104)
 *   hist[3] = hist[2]_prev            (rec2 = shift 0x44f108)
 *   hist[4] = dr_ref                  (rec3 = DR[(line-ref)&127] 0x44f10c) ← COUPLAGE ARÈNE
 * dr_ref est le delta de l'anneau d'arène à la distance ref (lu par le sélecteur
 * AVANT le re-score courant). §13.102 avait modélisé hist[4] par D_prev (approx.
 * valable en fenêtre froide : DR[slot]==D_prev pour ref=2, pos2/3/4) ; la règle
 * EXACTE est le lookup arène (source de la dérive ±1 du row_hash au-delà de ~72,
 * cf. §13.113). À appeler AVANT learn_step. Aucun effet enc.
 */
void alz_cm_rotate_hist(alz_cm_learner *L, int32_t d_cur, int32_t dr_ref);

/*
 * alz_cm_learn_byte — passe COMPOSITE d'un octet, verrou GT §13.115 (rejeu froid
 * image.raw[0..83] : row_hash 83/83 + poids 84/84 contre capture BP 0x415804).
 * ORDRE INTRA-LIGNE legacy épinglé par la capture au moment de pose du dot : PHASE
 * SPLIT entre le chemin d'apprentissage (retardé) et le chemin du dot (courant) :
 *   1. base courante v = byte_i - 0x80 ; err = movsbl(prev_dot - v)<<4  [prev_dot =
 *      row_hash@{i-1} = dot du PAS PRÉCÉDENT] ;
 *   2. MàJ 11 accu (anneau) sur l'hist ENTRANTE (delta_{i-1}, phase RETARDÉE) ;
 *   3. counter++ ; si (counter & 0xf)==0 : min-scan (argmin signé, reset 11, nudge
 *      des poids)  -> le SELECTEUR lit les poids POST-nudge (vérifié w change@15/31/47/79) ;
 *   4. rotation de l'hist vers le delta COURANT  D = byte_i - byte_{i-1}  (hist[0]<-D,
 *      hist[1]<-D-D_prev) ;
 *   5. prev_dot_full = (÷16 signé)( (v<<4) + Σ w_postnudge · hist_courant )  -> sera
 *      le row_hash@i lu par l'arbitre (prédicteur p3) au PAS SUIVANT.
 * byte_prev2 n'est plus requis (la chaîne d'histoires porte les crans passés).
 * dr_ref = opérande externe de hist[4] (= DR[(line-ref)&127], couplage arène §13.113).
 * Aucun effet encodage (non-wired).
 */
void alz_cm_learn_byte(alz_cm_learner *L, uint8_t byte_cur, uint8_t byte_prev1, uint8_t byte_prev2, int32_t dr_ref);

/* Init de la table de deltas en anneau (§13.55) :
 *   TABLE[i] = (i < 2048) ? i : (4096 - i)  — distance circulaire sur anneau 4096. */
void alz_cm_init_table(uint16_t table[ALZ_CM_RING]);

/* Index d'anneau pour un delta (§13.55) : (delta<<4) & 0xfff. */
static inline uint32_t alz_cm_ring_index(int32_t delta)
{
    return ((uint32_t)delta << 4) & 0xfffu;
}

/* Valeur de l'anneau (§13.55/13.100, CONFIRMÉE live) : vague triangulaire
 *   ring[i] = (i < 2048) ? i : (4096 - i)   — non signée (0..2048).
 * Le finder indexe par (err ∓ h_k) & 0xfff (err/h déjà <<4). */
static inline uint32_t alz_cm_ring_value(uint32_t idx)
{
    idx &= 0xfffu;
    return (idx < ALZ_CM_RING_HALF) ? idx : (ALZ_CM_RING - idx);
}

/* Rotation d'history + pose du delta courant, PRÉCÉDANT le hash (§13.61) :
 *   h2=h1 ; h1=delta - h0 ; h3=h2_old ; h0=delta ; rec->base=base_octet ; rec->delta=delta. */
void alz_cm_advance(alz_cm_record *rec, uint32_t base_octet, int32_t delta);

/* Hash contexte→ligne fidèle (§13.61). Retourne la ligne = (dot-product) ÷ 16
 * (division signée arrondie : edx=eax>>0x1f ; edx<<=4 ; sbb ; sar 4).
 *   row = ((base<<4) + w0*delta + w1*h1 + w2*h2 + w3*h3 + w4*w4glob) / 16.
 * w4glob = opérande du 5e terme (global legacy [0x44d4c4] ; rôle §13.62 en attente). */
uint32_t alz_cm_hash(const alz_cm_record *rec, uint32_t w4glob);

/* Clamp d'un poids dans [ALZ_CM_WMIN, ALZ_CM_WMAX] (§13.56). */
int32_t alz_cm_clamp_w(int32_t w);

/* Min-scan des accumulateurs (§13.56) : renvoie l'index du plus petit, le remet à
 * zéro, et applique le nudge ±1 clampé au poids correspondant (descente de gradient ;
 * pair → -1, impair → +1). ⚠ La correspondance exacte index-accumulateur → poids est
 * micro-restante (§13.62) : ici mapping provisoire w[idx % NWEIGHT], à valider.
 * Retourne l'index du minimum (0..NACC-1) ou -1 si aucun. */
int alz_cm_minscan_nudge(alz_cm_record *rec);

/* Rescale par halving de compteurs 16-bit packés (§13.57) : pour chaque DWORD,
 *   v &= 0xfffefffe ; v >>= 1   (moitiéne les deux demi-compteurs sans débordement).
 * Opère sur n DWORDs (une arène / un bloc de classe). */
void alz_cm_rescale_halving(uint32_t *arena, uint32_t ndwords);

/* Self-test déterministe des primitives. Retourne 0 = OK, sinon nb d'échecs.
 * N'a AUCUN effet sur l'encodage ; mais sert de porte d'entrée de validation B1. */
int alz_cm_selftest(void);

/* ===================================================================
 * Arène de score multi-candidats (finder 0x415cbc..0x415dd7) — VALIDÉE
 * bit-exact §13.108 (ref 70/70, b8 70/70, cost[2..7] 32/32). Non-wired.
 *
 * Modèle (100% delta-based ; la table de fréquences d'arène 0x4373d0
 * n'entre PAS dans ref/b8/cost) :
 *   - dr[line&127] = delta_line (delta_i = byte_i - byte_{i-1}, byte_{-1}=0x80) ;
 *   - la boucle n'est exécutée que lorsque la PORTE est ouverte (cascade de
 *     classes : masque = tbl[0x437af8][idx] avec idx=[0x44d4b0] ; idx=4 -> masque 7
 *     -> entrée quand (line & 7)==0). Le pilotage de idx est HORS de ce module
 *     (d8d_arbitre) : ici l'appelant fournit `entered`.
 *   - à chaque entrée : ref=b8=2, edi=0xffff, puis pour eax in [2,124) :
 *       cn = ring(dr[line-r] - dr[line-r-eax])  pour r=0,1,2   (index &0xfff NU)
 *       cost[eax] = (13*cost[eax] >> 4) + cn                    (cn NON divisé)
 *       ref = argmin cost (strict <) ; b8 = argmin cn (strict <).
 *   - gelé entre entrées (ref/b8/cost conservent la dernière exécution).
 * ref nourrit hist[4] = dr[(line-ref)&127] ; b8 sert de relrow (ctx arène).
 */
#define ALZ_ARENA_DRING 128u   /* anneau deltas (0x44d6cc), index &127 */
#define ALZ_ARENA_NCOST 125u   /* tableau coûts (0x44d4cc), créneaux 2..123 */
#define ALZ_ARENA_EAX0    2u   /* premier candidat (0x415cc1 esi=2) */
#define ALZ_ARENA_EAXN  124u   /* borne exclusive (0x415dd4 cmp eax,0x7c) */

typedef struct {
    uint32_t dr[ALZ_ARENA_DRING];   /* dr[line&127] = delta signé (dword) */
    uint32_t cost[ALZ_ARENA_NCOST]; /* coûts EMA par offset candidat */
    uint32_t ref;                    /* argmin cost  (0x44d4b4) */
    uint32_t b8;                     /* argmin cn brut (0x44d4b8) = relrow */
    uint32_t line;                   /* index absolu   (0x45dc9c) */
} alz_arena;

void alz_arena_init(alz_arena *A);

/* Un octet : pose le delta courant dans l'anneau, et SI `entered` exécute la
 * boucle de score (EMA + double argmin). byte_prev = octet précédent (0x80 virtuel
 * pour i=0). Aucun effet encodage (non-wired). */
void alz_arena_step(alz_arena *A, uint8_t byte_cur, uint8_t byte_prev, int entered);

/* ===================================================================
 * Arbitre de classes (finder 0x415ddd..0x415ead) — VALIDÉ §13.109.
 * Non-wired. 6 classes en compétition ; chaque classe c tient une fenêtre
 * glissante (256) des buckets d'erreur de son prédicteur ; idx = argmin
 * des totaux. Cet idx (=[0x44d4b0]) pilote le masque d'entrée d'arène
 * (tbl 0x437af8[idx]) et la classe du modèle de fréquences.
 *   à chaque position : pour c in [0,6) :
 *     slot  = line & 0xff
 *     tot[c] -= ring[c][slot]              (éviction ; 0 en 1re visite)
 *     b      = bucket[ diff[c] & 0x1ff ]   (table 0x437b10, 512, tente symétrique)
 *     ring[c][slot] = b ;  tot[c] += b
 *   idx = argmin_c tot[c]  (strict <, premier-min gagne ; init idx=0).
 * Les 6 flux `diff` viennent des prédicteurs de contexte (0x44d8cc..0x44d8e0) :
 * HORS de ce module (l'appelant les fournit). VALIDATION : sur les 6 diff
 * capturés image.raw[0..69], idx == GT 70/70 ; 0/420 conflit sur bucket.
 */
#define ALZ_ARB_NCLASS 6u
#define ALZ_ARB_RING   256u
typedef struct {
    uint32_t ring[ALZ_ARB_NCLASS][ALZ_ARB_RING]; /* buckets par classe (fenêtre 256) */
    uint32_t total[ALZ_ARB_NCLASS];              /* somme glissante (0x44dce4 + c*0x404) */
    uint32_t idx;                                /* classe gagnante (0x44d4b0) */
    uint32_t line;
} alz_arb;

void alz_arb_init(alz_arb *R);

/* Une position : maj des 6 totaux (fenêtre 256) puis choix idx=argmin.
 * `diff[c]` = erreur du prédicteur de classe c (réel - pred_c). */
void alz_arb_step(alz_arb *R, const int32_t diff[ALZ_ARB_NCLASS]);

/* Assemble les 6 `diff` en byte-only puis appelle alz_arb_step.
 * Prédicteurs décodés et validés §13.110 (diffs 70/70, idx 70/70) :
 *   p0=0 ; p1=base_{i-1} ; p2=2*base_{i-1}-base_{i-2} (extrapolation) ;
 *   p3=row_hash CM (dot/16, entré externe) ; p4=dr_ref=DR[(line-ref_prev)&127] ;
 *   p5=dr_b8=DR[(line-b8_prev)&127].
 * réel = base pour c∈{0..3}, delta pour c∈{4,5}. base=byte-0x80.
 * `dr_ref`/`dr_b8` viennent de l'anneau deltas de l'arène (A->dr) avec les
 * ref/b8 de la LIGNE PRÉCÉDENTE (phase 1-en-retard, cf. §13.105). */
void alz_arb_predict(alz_arb *R, int32_t base_i, int32_t base_prev, int32_t base_prev2,
                     int32_t delta_i, int32_t dr_ref, int32_t dr_b8, int32_t row_hash);

#endif /* ALZ_CM_H */
