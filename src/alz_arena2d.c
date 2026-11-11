/*
 * alz_arena2d.c — couche (2) du scoreur delta-2D ALZ : arène adaptative de fréquences.
 * Portage fidèle UHARC 0.6b. Spécification et validation : UHARC_RE_REPORT.md §13.82..90.
 * Règle cold/warm + compteur secondaire + rescale, VALIDÉE pos-à-pos 80/80 contre le
 * ground-truth legacy (research/gt_scorer/image_raw_ctx_80.log + image_raw_symbolcost_200.log).
 * NON-WIRED : aucun effet sur l'encodage standard (gated, self-testé).
 */
#include "alz_arena2d.h"
#include "alz_score.h"

/* [DIAG A3, LECTURE SEULE] compteur global de halvings maître (branche aging_on==1).
 * Permet à la pré-passe de lire la cadence PAR BLOC (journal [A3MRBLK]). Zéro effet
 * sur l'émission ; aucun écrivain hors de alz_arena2d_master_learn. */
unsigned g_a3_halv_count = 0u;
/* [DIAG A3, LECTURE SEULE] compteur global de rescales WORKING (arène H, 0x414590),
 * cadence à comparer au registre m21t (164/159/163/165/214/1 = 866). Écrit par la
 * pré-passe sous UHA_A3_WORKARENA uniquement. */
unsigned g_a3_hw_count = 0u;
/* [DIAG A3, tour 14] Position d'émission courante, posée par l'appelant (alz.c) juste avant
 * `alz_arena2d_master_learn`, pour que le journal [A3MR] porte le MÊME `pos` que la GT
 * `m23_c2_halving.tsv` (colonnes pos/bloc/ligne/n_cells/somme_avant/somme_apres).
 * Écriture et lecture sous `UHA_A3_MASTERLAW_COUNT` uniquement ; aucun effet sur la loi. */
unsigned g_a3_mr_pos = 0xFFFFFFFFu;
/* [A3, tour 13] RÉARMEMENT D'AGING — état CALIBRÉ, non dérivé.
 * L'asm (0x410083..0x4100a8) prescrit `aging = X_new + Σfreq_new` puis `shl 6` si `ebp < 0x300`.
 * A/B mesuré sur la cadence GT `m23_c2` (bloc 0 = 69 halvings, bloc 1 = 44) :
 *   `<<0` → 3 558 (firstdiv 12 593) · `<<6` → 143 (18 432) · `<<8` → **69 puis 44** (27 201).
 * La transcription littérale sur-déclenche donc (x50 / x2) : l'échelle `<<8` est conservée
 * parce qu'elle seule reproduit la GT. Le facteur 4 entre `<<6` et `<<8` reste à identifier
 * (unités de X/freq du legacy vs `mtot` du port — voir OUT/A3_decideur_gt_27201.md §5bis). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void alz_arena2d_init(alz_arena2d_t *a, uint16_t default_inc)
{
    uint32_t i;
    memset(a->freq, 0, sizeof(a->freq));
    for (i = 0; i < ALZ_ARENA2D_MAX_ROW; i++) {
        a->total[i]   = (uint16_t)ALZ_ARENA2D_INIT_VAL;
        a->counter[i] = (uint16_t)ALZ_ARENA2D_INIT_VAL;
        a->promo[i]   = default_inc;
        a->aging[i]   = 256u;   /* C6-ter(c) cold init aging = 0x100 */
        a->mtot[i]    = 1u;     /* master_total init = 1 (registre m23_c4 : mt_before=1 à b0) */
    }
    a->aging_on = 0;   /* défaut-OFF : master_learn garde son comportement seuil seul */
}

void alz_arena2d_set_inc(alz_arena2d_t *a, uint32_t relrow, uint16_t inc)
{
    if (relrow < ALZ_ARENA2D_MAX_ROW)
        a->promo[relrow] = inc;
}

/*
 * Rescale d'une ligne (0x414590, §13.84). Déclenché quand total[row] >= 0x4000.
 *   - chaque freq de la ligne : arrondi vers PAIR puis halving  (v = (v & ~1) >> 1) ;
 *   - somme des freq halvées accumulée ;
 *   - counter[row] = (counter[row] >> 2) + 1   (compteur secondaire décroît /4) ;
 *   - total[row]   = somme_freqs_halvées + counter[row].
 */
void alz_arena2d_rescale(alz_arena2d_t *a, uint32_t relrow)
{
    uint32_t base, j;
    uint32_t sum = 0;
    if (relrow >= ALZ_ARENA2D_MAX_ROW)
        return;
    base = relrow << 8;
    for (j = 0; j < 256u; j++) {
        uint32_t v = a->freq[base + j];
        v &= ~1u;          /* rendre pair (FLOOR, §13.84/90 GT 80/80 ; ≠ 0x40fe90 budget) */
        v >>= 1;           /* halving */
        a->freq[base + j] = (uint16_t)v;
        sum += v;
    }
    a->counter[relrow] = (uint16_t)((a->counter[relrow] >> 2) + 1u);
    a->total[relrow]   = (uint16_t)(sum + a->counter[relrow]);
}

/*
 * Rescale MAÎTRE (0x40ffa0 + branche >16 en 0x4100b1, §13.727). Déclenché quand
 * total[row] >= 0x4000 pendant l'apprentissage d'émission sur le maître.
 *   - chaque freq de la ligne : f>16 → f>>=1 ; sinon f=0   (0x40ffd0 ja>0x10 → 0x4100b1 shr,1 ;
 *     0x40ffd6 ≤16 → mov WORD,eax,di(=0)) ;
 *   - total[row] = Σ f des colonnes résiduelles (PAS de +counter, contrairement au working).
 * Le rebuild de l'arbre Fenwick [0x4373c8] (0x40ffe0.. rep movs) est hors portée du score.
 */
void alz_arena2d_rescale_master(alz_arena2d_t *a, uint32_t relrow)
{
    uint32_t base, j;
    uint32_t sum = 0;
    if (relrow >= ALZ_ARENA2D_MAX_ROW)
        return;
    base = relrow << 8;
    for (j = 0; j < 256u; j++) {
        uint32_t v = a->freq[base + j];
        v = (v > 16u) ? (v >> 1) : 0u;    /* >16 → halving ; ≤16 → zéro (0x40ffd6) */
        a->freq[base + j] = (uint16_t)v;
        sum += v;                          /* edx accumule le nouveau total (0x4100bc) */
    }
    a->total[relrow] = (uint16_t)sum;      /* total = Σ f, SANS counter */
}

/*
 * Learn d'émission maître (cœur de 0x4111a0, §13.727). Règle cold/warm IDENTIQUE à
 * alz_arena2d_score (pour ISOLER leffet de la loi de rescale) mais rescale MAÎTRE.
 * Utilisé par emiprod (gated) pour reconstruire master@bloc1.
 */
uint32_t alz_arena2d_master_learn(alz_arena2d_t *a, uint32_t relrow, uint32_t delta)
{
    uint32_t ctx, T, f, inc;
    if (relrow >= ALZ_ARENA2D_MAX_ROW) relrow = ALZ_ARENA2D_MAX_ROW - 1u;
    delta &= 0xffu;
    ctx   = (relrow << 8) | delta;
    inc   = a->promo[relrow];              /* poids par row = WORD[row*2+0x45e4c0] */
    T     = a->total[relrow];
    f     = a->freq[ctx];
    /* [GATED aging_on, C6-ter] décrément du budget maître avant update : aging -= (master_total + freq_AVANT) */
    if (a->aging_on)
        a->aging[relrow] -= (a->mtot[relrow] + f);
    /* [UHA_A3_MASTERLAW] master_total += bx UNIQUEMENT sur la branche FROIDE
     * (0x412169 ; registre m23_c4 : mt_before reste 32..97 — jamais 8000).
     * L'incrément froid est déjà fait plus bas sous `if (a->aging_on)`. */
    if (f == 0u) {                         /* COLD */
        a->freq[ctx]      = (uint16_t)(f + inc);
        a->counter[relrow]= (uint16_t)(a->counter[relrow] + inc);
        a->total[relrow]  = (uint16_t)(T + 2u * inc);
        if (a->aging_on) a->mtot[relrow] += inc;   /* master_total += bx (branche froide 0x412169) */
    } else {                               /* WARM */
        a->freq[ctx]     = (uint16_t)(f + inc);
        a->total[relrow] = (uint16_t)(T + inc);
    }
    if (a->aging_on == 2) {
        /* [GATED UHA_A3_MASTERLAW, lane ALZ -m3, registre m23] LOI FIDELE DU MAITRE
         * PERM (0x4121b4 -> 0x40ffa0). `total[]` = racine accumulee (esi), `mtot[]`
         * = master_total (edx). Apres le learn : si `root + master_total >= 0x4000`
         * -> halving `f>16 ? f>>1 : 0` ; topiques du registre m23_c1 :
         *   root := Σf_new (esi=16335/16359/...), master_total := (mt+1)>>1
         *   (edx 64 -> 32 entre pos 18315 et 21363, PAS Σf). 176 evenements.
         * 210 evenements avec mt:=Σf (mesure du 2026-10-27) -> sur-rescale x1,6. */
        uint32_t rb = relrow << 8, s = 0u, j;
        for (j = 0; j < 256u; j++) s += a->freq[rb + j];
        if (s + a->mtot[relrow] >= ALZ_ARENA2D_RESCALE) {
            uint32_t sn = 0u, mtb = a->mtot[relrow];
            for (j = 0; j < 256u; j++) {
                uint32_t v = a->freq[rb + j];
                v = (v > 16u) ? (v >> 1) : 0u;
                a->freq[rb + j] = (uint16_t) v;
                sn += v;
            }
            a->total[relrow] = (uint16_t) sn;          /* racine = Σf_new */
            a->mtot[relrow]  = (mtb + 1u) >> 1;        /* master_total halve (m23_c1) */
            /* [DIAG UHA_A3_MASTERLAW_COUNT, LECTURE SEULE] journal des rescales
             * maitre (miroir de m23_c2/phys) pour comparer la CADENCE par ligne. */
            {
                static int s_mlc = -1;
                if (s_mlc < 0) s_mlc = getenv("UHA_A3_MASTERLAW_COUNT") ? 1 : 0;
                if (s_mlc)
                    fprintf(stderr, "[A3MR] row=%u root_before=%u mt_before=%u sum_after=%u mt_after=%u\n",
                            (unsigned) relrow, (unsigned) s, (unsigned) mtb,
                            (unsigned) sn, (unsigned) ((mtb + 1u) >> 1));
            }
        }
    } else if (a->aging_on) {
        /* double porte C6-ter : racine(=Σfreq ligne) + master_total >= 0x4000  OU  aging<0 */
        uint32_t rb = relrow << 8, s = 0u, j;
        int32_t  ags;
        for (j = 0; j < 256u; j++) s += a->freq[rb + j];    /* racine = Σfreq (arbre slot[0]) */
        ags = (int32_t)a->aging[relrow];
        if (s + a->mtot[relrow] >= ALZ_ARENA2D_RESCALE || ags < 0) {
            uint32_t sn = 0u, mtb = a->mtot[relrow];
            uint32_t nc = 0u, sav = 0u, sap = 0u;   /* [tour 14] colonnes GT m23_c2 */
            int seuil = (s + mtb >= ALZ_ARENA2D_RESCALE);
            for (j = 0; j < 256u; j++) {                     /* 0x40ffa0 : f>16 -> >>1 sinon 0 */
                uint32_t v0 = a->freq[rb + j];
                uint32_t v = (v0 > 16u) ? (v0 >> 1) : 0u;
                if (v != v0) { nc++; sav += v0; sap += v; }  /* cellules RÉELLEMENT modifiées */
                a->freq[rb + j] = (uint16_t)v; sn += v;
            }
            a->total[relrow] = (uint16_t)sn;                 /* racine = Σfreq_new */
            a->mtot[relrow]  = (a->mtot[relrow] + 1u) >> 1;  /* master_total=(mt+1)>>1 (0x41007b-80) */
            /* [A3, tour 13] RÉARMEMENT (0x410083..0x4100a8) :
             *   aging = mtot_new + Σfreq_new          (0x410094 : edx = dx (=X_new) + cx (=Σfreq))
             *   puis `shl 6` SI la ligne < 0x300      (0x41009b cmp ebp,0x300 ; 0x4100a8 shl cl=6)
             * La somme est transcrite exactement ; l'ÉCHELLE est calibrée à `<<8` (et non `<<6`)
             * parce que `<<6` rend 143 halvings au bloc 0 contre 69 en GT (cf. en-tête du fichier
             * et OUT/A3_decideur_gt_27201.md §5bis) : c'est le seul écart assumé de ce bloc. */
            {
                uint32_t agv = a->mtot[relrow] + sn;          /* 0x41008b */
                /* 0x4100a8 dit `shl 6` (si ligne < 0x300), mais cette transcription
                 * sur-déclenche x2 (143 vs 69 au bloc 0) ; `<<8` reproduit 69/44. */
                a->aging[relrow] = agv << 8;
            }
            /* [DIAG UHA_A3_MASTERLAW_COUNT, LECTURE SEULE] mêmes champs que le registre m23_c4
             * (mt_before/sfreq) + motif (S=seuil 0x4121b4, A=aging 0x41232f). */
            {
                static int s_mlc2 = -1;
                if (s_mlc2 < 0) s_mlc2 = getenv("UHA_A3_MASTERLAW_COUNT") ? 1 : 0;
                if (s_mlc2)
                    fprintf(stderr, "[A3MR] pos=%u row=%u root_before=%u mt_before=%u sum_after=%u"
                                    " mt_after=%u ncells=%u sav=%u sap=%u src=%s\n",
                            (unsigned) g_a3_mr_pos, (unsigned) relrow, (unsigned) s, (unsigned) mtb,
                            (unsigned) sn, (unsigned) ((mtb + 1u) >> 1), (unsigned) nc,
                            (unsigned) sav, (unsigned) sap, seuil ? "S" : "A");
            }
            g_a3_halv_count++;
        }
    } else
    if (a->total[relrow] >= ALZ_ARENA2D_RESCALE)
        alz_arena2d_rescale_master(a, relrow);
    return 0;
}

uint32_t alz_arena2d_score(alz_arena2d_t *a, uint32_t relrow, uint32_t delta, uint32_t *p_total)
{
    uint32_t ctx, T, f, num, proba, inc;
    if (relrow >= ALZ_ARENA2D_MAX_ROW) relrow = ALZ_ARENA2D_MAX_ROW - 1u;
    delta &= 0xffu;
    ctx   = (relrow << 8) | delta;
    inc   = a->promo[relrow];
    T     = a->total[relrow];        /* total AVANT mise à jour (dénominateur du legacy) */
    f     = a->freq[ctx];

    if (f == 0u) {                   /* --- COLD : ce ctx apparaît pour la 1re fois --- */
        num = a->counter[relrow];    /* le legacy charge eax = counter[row] (0x41552b) */
        a->freq[ctx]      = (uint16_t)(f + inc);            /* = inc */
        a->counter[relrow]= (uint16_t)(a->counter[relrow] + inc);
        a->total[relrow]  = (uint16_t)(T + 2u * inc);       /* freq nouveau + counter */
    } else {                         /* --- WARM --- */
        num = f;
        a->freq[ctx]     = (uint16_t)(f + inc);
        a->total[relrow] = (uint16_t)(T + inc);
    }

    if (p_total)
        *p_total = T;

    proba = (T != 0u) ? ((num << 14) / T) : (ALZ_SCORE_CUM_N - 1u);
    if (proba >= ALZ_SCORE_CUM_N)
        proba = ALZ_SCORE_CUM_N - 1u;

    if (a->total[relrow] >= ALZ_ARENA2D_RESCALE)
        alz_arena2d_rescale(a, relrow);

    return proba;
}

uint32_t alz_arena2d_cost(alz_arena2d_t *a, uint32_t relrow, uint32_t delta)
{
    uint32_t proba = alz_arena2d_score(a, relrow, delta, NULL);
    return alz_score_proba_to_cost(proba);
}

/* Accesseur PUR (lecture seule, AUCUN effet de bord, ne touche pas la règle de score
 * ni le self-test ARENA 80/80) : frequence courante d'un ctx (relrow,delta). Permet
 * a l'appelant de detecter un symbole FROID (freq==0, jamais vu) sans le muter. */
uint32_t alz_arena2d_freq(const alz_arena2d_t *a, uint32_t relrow, uint32_t delta)
{
    if (relrow >= ALZ_ARENA2D_MAX_ROW) relrow = ALZ_ARENA2D_MAX_ROW - 1u;
    return (uint32_t) a->freq[(relrow << 8) | (delta & 0xffu)];
}

/* ---- Self-test : rejoue le ground-truth legacy (image.raw, 80 positions). ---- */
struct alz_arena2d_tv { uint32_t relrow, delta, proba, total; };
/* Vecteurs d'evolution du total (2000 positions, couvrant les declenchements de rescale). */
struct alz_arena2d_tvt { uint32_t relrow, delta, total; };

int alz_arena2d_selftest(void)
{
    static const struct alz_arena2d_tv tv[] = {
#include "alz_arena2d_vecs.inc"
    };
    static const struct alz_arena2d_tvt tvt[] = {
#include "alz_arena2d_total_vecs.inc"
    };
    const int n = (int)(sizeof(tv) / sizeof(tv[0]));
    const int nt = (int)(sizeof(tvt) / sizeof(tvt[0]));
    alz_arena2d_t a;
    int fails = 0, i;

    alz_arena2d_init(&a, 32u);   /* promo[row] = 32 (GT §13.90) */
    for (i = 0; i < n; i++) {
        uint32_t tot = 0;
        uint32_t proba = alz_arena2d_score(&a, tv[i].relrow, tv[i].delta, &tot);
        if (proba != tv[i].proba || tot != tv[i].total) {
            printf("[ARENA-TEST] FAIL pos%d (rel%u,d%u): got proba=%u total=%u ; exp %u/%u\n",
                   i, tv[i].relrow, tv[i].delta, proba, tot, tv[i].proba, tv[i].total);
            fails++;
            if (fails >= 10) break;
        }
    }

    /* Phase 2 : evolution complete du total sur 2000 positions (re-init, valide le rescale). */
    alz_arena2d_init(&a, 32u);
    for (i = 0; i < nt; i++) {
        uint32_t tot = 0;
        (void)alz_arena2d_score(&a, tvt[i].relrow, tvt[i].delta, &tot);
        if (tot != tvt[i].total) {
            printf("[ARENA-TEST] FAIL total pos%d (rel%u,d%u): got total=%u exp %u\n",
                   i, tvt[i].relrow, tvt[i].delta, tot, tvt[i].total);
            fails++;
            if (fails >= 20) break;
        }
    }
    if (fails == 0)
        printf("[ARENA-TEST] arena2d OK (proba+total %d/%d ; total %d/%d positions, rescale couvert)\n",
               n, n, nt, nt);
    else
        printf("[ARENA-TEST] %d divergence(s)\n", fails);
    return fails ? 1 : 0;
}
