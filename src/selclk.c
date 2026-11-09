/* selclk.c - pompe FAITHFUL of the classifieur (transcription byte-exact of m343_pompe_walk.py + m346).
 * Voir selclk.h. No value of corpus en dur : tables = constantes d'image (selclk_data.h) ;
 * stream/armement = INPUT (passes by l'appelant under gate). charniere = [0x4826C8] = -1 (constante #2). */
#include "selclk.h"
#include "selclk_data.h"
#include <string.h>

/* tables indexees by offset-VA in there window .data (constantes d'image) */
#define SEL_T858(i)   SELCLK_DATA[(0x43D858u - SELCLK_DBASE) + (i)]   /* weight by symbole */
#define SEL_T8BC(i)   SELCLK_DATA[(0x43D8BCu - SELCLK_DBASE) + (i)]   /* class of walk */
#define SEL_TB40(i)   SELCLK_DATA[(0x43DB40u - SELCLK_DBASE) + (i)]   /* shift of run (28) */
#define SEL_TB40_LEN  0x1Cu
#define SEL_TB5C(i)   SELCLK_DATA[(0x43DB5Cu - SELCLK_DBASE) + (i)]
#define SEL_TBC0(i)   SELCLK_DATA[(0x43DBC0u - SELCLK_DBASE) + (i)]   /* value of run */
#define SEL_TE2E(i)   SELCLK_DATA[(0x43DE2Eu - SELCLK_DBASE) + (i)]   /* 1=Has..Z 2=has..z */
#define SEL_TC64(i)   rd_le32(0x43D664u + 4u*(i))                     /* 256 pointers d'enregistrements */

#define CHARNIERE     0xFFFFFFFFu      /* [0x4826C8] = -1, porte always ouverte (measures #2) */

static uint32_t rd_le32(uint32_t va)
{
    const uint8_t *p = &SELCLK_DATA[va - SELCLK_DBASE];
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* -1 = out window (== None of the .py) ; otherwise byte 0..255. */
static int sel_va_byte(uint32_t va)
{
    if (va >= SELCLK_DBASE && va < SELCLK_DBASE + SELCLK_DLEN)
        return SELCLK_DATA[va - SELCLK_DBASE];
    return -1;
}

typedef struct {
    uint32_t pos, edi, gfd, fin, c0;
    uint32_t relais, att42;
    uint32_t charniere, armement;
    uint32_t n, ecr;
    int w_out;
    const uint8_t *buf;
    uint32_t len;
} pk_t;

static void emets(pk_t *e, uint32_t *W, int esp_c)
{
    (void)esp_c;                       /* context (0x420c85 ~esp_c) no consumes by delta ; W/cellules suffisent */
    e->w_out = (int)*W;
    e->ecr = (e->ecr + 1) & 0xFFFFFFu;
    e->n++;
}

static void recharge(pk_t *e, uint32_t n)        /* INFERE : effet = advances-keeps-fou (gfd += n) */
{
    e->gfd += n;
}

/* forward decls */
static void ed0(pk_t *e, uint32_t *W, int esp_c, uint32_t classe, uint32_t marche);
static void accum(pk_t *e, uint32_t *W, int esp_c);

static void accum(pk_t *e, uint32_t *W, int esp_c)   /* 0x42110c..0x421146 */
{
    uint32_t al = SEL_T858(esp_c & 0xFF);
    *W = *W + al;
    e->edi += al; e->pos += al; e->c0 -= al;
    esp_c = SEL_TB5C(esp_c & 0xFF);
    emets(e, W, esp_c);
}

static void ed0(pk_t *e, uint32_t *W, int esp_c, uint32_t classe, uint32_t marche)  /* 0x420ed0 */
{
    if (classe != marche) { accum(e, W, esp_c); return; }
    if (esp_c < 0x80) { emets(e, W, esp_c); return; }
    {
        uint32_t ch = SEL_TBC0(esp_c & 0xFF);
        int al;
        if (ch == 0) { emets(e, W, esp_c); return; }
        e->att42 = ch;
        al = ((uint32_t)esp_c < SEL_TB40_LEN) ? (int)SEL_TB40(esp_c) : 0;
        e->relais = 1;
        esp_c = al;
        e->c0 += 1;
        *W = 0;
        emets(e, W, esp_c);
    }
}

/* m346._record_walk_fidele : 0x420f55..0x42100a, MT indexee by byte (corr. M346). */
static void record_walk_fidele(pk_t *e, uint32_t *W, int esp_c, uint32_t classe, uint32_t rest)
{
    uint32_t marche;
    if (rest < 4) { ed0(e, W, esp_c, classe, classe); return; }
    if ((int64_t)e->gfd - (int64_t)e->edi < 4) recharge(e, 4);
    marche = 0;
    while (marche < classe) {
        uint32_t va = 0x43D9BCu + ((uint32_t)esp_c << 4) - 0x610u + marche;   /* _mt_byte(byte,walk) */
        int w = sel_va_byte(va);
        uint32_t poids, recptr, edx;
        int32_t al;
        uint32_t ptr;
        int rupture = 0;
        if (w < 0) break;
        poids = SEL_T858(w & 0xFF);
        recptr = SEL_TC64(w & 0xFF);
        edx = recptr + 1;
        ptr = e->edi;
        al = (int32_t)poids;
        for (;;) {
            int rb = sel_va_byte(edx);
            int expected, cur;
            if (rb < 0) { rupture = 1; break; }
            expected = rb ^ 0xFF;
            cur = (ptr < e->len) ? (int)e->buf[ptr] : -1;
            if (cur == expected) {
                al -= 1; edx += 1; ptr += 1;
                if (al != 0) continue;
                ed0(e, W, w, classe, marche); return;     /* weight epuise -> 0x420fe7 */
            }
            rupture = 1; break;
        }
        if (!rupture) break;
        if (poids != 0) { marche += 1; continue; }
        ed0(e, W, w, classe, marche); return;             /* weight==0 rupture */
    }
    ed0(e, W, esp_c, classe, marche);
}

/* m343._space_walk : 0x420e79..0x420ed0, byte == 0x20. */
static void space_walk(pk_t *e, uint32_t *W, int esp_c, uint32_t classe, uint32_t rest)
{
    uint32_t marche;
    if (rest < 0x20) { ed0(e, W, esp_c, classe, classe); return; }
    if ((int64_t)e->gfd - (int64_t)e->edi < 0x20) recharge(e, 0x20);
    marche = 1;
    while (marche <= 0x20) {
        int64_t q = (int64_t)e->edi - 1 + (int64_t)marche;
        if (!(q >= 0 && q < (int64_t)e->len) || e->buf[q] != 0x20) break;
        marche += 1;
    }
    if (marche <= 1) { ed0(e, W, esp_c, classe, marche); return; }
    if (marche != 0x20) {
        int esp_c2;
        if (marche > 0x10) marche = 0x10;
        esp_c2 = (0x11 - (int)marche) & 0xFF;
        ed0(e, W, esp_c2, classe, marche); return;
    }
    ed0(e, W, 0, classe, marche);
}

/* m343._attente0 : class == 0, 0x42100f..0x421107. */
static void attente0(pk_t *e, uint32_t *W, int esp_c, uint32_t classe, uint32_t rest)
{
    uint32_t p; int nxt;
    if (rest < 4) { ed0(e, W, esp_c, classe, classe); return; }
    if ((int64_t)e->gfd - (int64_t)e->edi < 4) recharge(e, 4);
    p = e->edi;
    nxt = (p < e->len) ? (int)e->buf[p] : 0;
    if ((esp_c & 0xFF) == 0x0A) {
        if (SEL_TE2E(nxt & 0xFF) == 2) { ed0(e, W, 0x60, classe, 0x60); return; }
        ed0(e, W, esp_c, classe, classe); return;
    }
    if ((esp_c & 0xFF) == 0x0D) {
        if (nxt == 0x0A && p + 1 < e->len) {
            int nxt2 = (int)e->buf[p + 1];
            if (SEL_TE2E(nxt2 & 0xFF) == 2) { ed0(e, W, 0x61, classe, 0x61); return; }
            if (nxt2 == 0x20 && nxt2 != ((p + 2 < e->len) ? (int)e->buf[p + 2] : 0))
                { ed0(e, W, 0x62, classe, 0x62); return; }
        }
        ed0(e, W, esp_c, classe, classe); return;
    }
    if (SEL_TE2E(esp_c & 0xFF) == 1) {
        if (SEL_TE2E(nxt & 0xFF) == 2) {
            e->relais = 0x20;
            e->att42 = (uint32_t)((esp_c + 0x20) & 0xFF);
            e->c0 += 1;
            { uint32_t z = 0; ed0(e, &z, 0x63, classe, 0x63); *W = z; }   /* 0x421104 [esp]=0 */
            return;
        }
    }
    ed0(e, W, esp_c, classe, classe);
}

/* m343._motif : 00 03 03 != FE, pos >= charniere. */
static void motif(pk_t *e, uint32_t *W, int esp_c, uint32_t garde)
{
    uint32_t p;
    if (esp_c != 0) {
        if (esp_c == 0xFE) { e->att42 = 0xFE; e->relais = 1; e->c0 += 1; *W = 0; emets(e, W, 0xFE); return; }
        emets(e, W, esp_c); return;
    }
    if ((int64_t)e->fin - (int64_t)e->pos < 5) { emets(e, W, esp_c); return; }
    if (garde < 5) recharge(e, 5);
    p = e->edi;
    if (p + 4 <= e->len && e->buf[p] == 0 && e->buf[p + 1] == 3 &&
        e->buf[p + 1] == e->buf[p + 2] && e->buf[p + 3] != 0xFE) {
        e->edi += 3; e->pos += 3; e->c0 -= 3;
        *W = 4; emets(e, W, 0xFE); return;
    }
    emets(e, W, esp_c);
}

/* m343.pompe_cellule. returns 1 if has cellule is produite, 0 if pos>=end (arret). */
static int pompe_cellule(pk_t *e, uint32_t *Wout)
{
    uint32_t W = 1;
    uint32_t dl = e->relais & 0xFF;
    int esp_c;
    uint32_t garde, classe, rest;
    if (e->pos >= e->fin) return 0;
    if (dl == 1) { e->relais = 0; *Wout = W; emets(e, &W, (int)(e->att42 & 0xFF)); return 1; }
    if (dl == 0) {
        uint32_t old = e->edi;
        if (e->edi == e->gfd) recharge(e, 1);
        esp_c = (old < e->len) ? (int)(e->buf[old] & 0xFF) : 0;
        e->edi = old + 1; e->pos += 1;
    } else {
        e->relais = 0;
        esp_c = (int)(e->att42 & 0xFF);
    }
    garde = e->gfd - e->edi;
    if (e->pos >= e->charniere) { motif(e, &W, esp_c, garde); *Wout = (uint32_t)e->w_out; return 1; }
    if (e->pos > e->armement) { emets(e, &W, esp_c); *Wout = W; return 1; }
    classe = SEL_T8BC(esp_c & 0xFF) & 0xFF;
    rest = e->armement - e->pos;
    if (classe == 0) { attente0(e, &W, esp_c, classe, rest); *Wout = (uint32_t)e->w_out; return 1; }
    if (esp_c != 0x20) { record_walk_fidele(e, &W, esp_c, classe, rest); *Wout = (uint32_t)e->w_out; return 1; }
    space_walk(e, &W, esp_c, classe, rest); *Wout = (uint32_t)e->w_out; return 1;
}

uint32_t uha_selclk_delta(const uint8_t *flux, uint32_t len, uint32_t armement)
{
    pk_t e;
    uint32_t cap = 8u * len + 8192u, total = 0;
    memset(&e, 0, sizeof e);
    e.fin = len; e.gfd = len; e.charniere = CHARNIERE; e.armement = armement;
    e.buf = flux; e.len = len;
    while (e.n < cap) {
        uint32_t W;
        if (!pompe_cellule(&e, &W)) break;
        total += (W - 1u);
    }
    return total;
}

/* Override gated-ON (lu by ppm_blk_cost.selclk_shift()). default OFF : active=0, behavior herite. */
static uint32_t g_selclk_val;
static int      g_selclk_on;

void uha_selclk_set(uint32_t v) { g_selclk_val = v; g_selclk_on = 1; }
int  uha_selclk_active(void)    { return g_selclk_on; }
uint32_t uha_selclk_get(void)   { return g_selclk_val; }
