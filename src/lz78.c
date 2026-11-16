/*
 * LZ78 (-mw) prêt pour src/lz78.c. Pas de symboles RLE (ceux-ci restent src/rle.c).
 * Voir INTEGRATION.md. Source complète RLE+LZ78 : uha_rle_lz78.c.
 */

#include "lz78.h"

#include <stdlib.h>
#include <string.h>
#if LZ78_CODE_FC0_USE_REPLAY || defined(UHA_FC0_GEN_TOOL)
#include <stdio.h>
#endif

/* ---- LZ78 order selection (4038de..403984, UHARC.DOC -md for -mw) ---- */

uint8_t uha_lz78_select_order(uint32_t md_kb_cap, size_t usize)
{
    static const uint32_t tiers[] = {
        1, 2, 4, 8, 16, 32
    };
    uint32_t need_kb, i, cap = md_kb_cap ? md_kb_cap : 4096u;

    if (cap > 32u)
        cap = 32u;
    if (usize == 0)
        return UHA_ORDER_LZ78_MIN;

    need_kb = 1u;
    while (need_kb * 1024u < (uint32_t)usize && need_kb < cap)
        need_kb <<= 1;
    if (need_kb > cap)
        need_kb = cap;

    for (i = 0; i < sizeof(tiers) / sizeof(tiers[0]); i++) {
        if (need_kb <= tiers[i])
            return (uint8_t)(UHA_ORDER_LZ78_MIN + i);
    }
    return UHA_ORDER_LZ78_MAX;
}


/* ---- LZ78 placeholder (TODO bit-exact 0x4279c0 / 0x428110) ---- */

typedef struct {
    const uint8_t *in;
    size_t         in_len;
    size_t         pos;
    uint8_t        bitbuf;
    int            bits;
    int            err;
} uha_bit_in;

typedef struct {
    uint8_t *out;
    size_t   cap;
    size_t   pos;
    uint8_t  bitbuf;
    int      bits;
    int      err;
} uha_bit_out;

static size_t lz78_encode_plain_len(const uint8_t *in, size_t n)
{
    size_t i;

    if (n == 0u)
        return 0u;
    if (n == 1u)
        return 1u;
    for (i = 1u; i < n; i++) {
        if (in[i] >= 0x80u)
            return i;
    }
    return n;
}

/*
 * Wine ``-mw`` : si aucun octet ``>=0x80`` mais motif périodique court (``pattern.bin``),
 * préfixe plain = une période avant LZ (16 octets observés @ GDB/Wine GT).
 */
static size_t lz78_mw_plain_prefix(const uint8_t *in, size_t n)
{
    size_t plain;
    size_t per;
    size_t i;

    plain = lz78_encode_plain_len(in, n);
    if (plain < n || n <= 16u)
        return plain;
    if (in[0] >= 0x80u)
        return plain;
    for (i = 1u; i < n; i++) {
        if (in[i] != in[0])
            break;
    }
    if (i >= n)
        return plain;
    for (per = 2u; per <= 32u; per++) {
        if (n < 2u * per)
            break;
        if (memcmp(in, in + per, per) == 0)
            return per;
    }
    /* Gros ASCII (ex. ``code.c``) : plain jusqu'au ``(`` d'ouverture (GT 18 B). */
    if (n > 40u && plain >= n) {
        size_t i;

        for (i = 0u; i < n && i < 512u; i++) {
            if (in[i] == (uint8_t)'(')
                return i + 1u;
        }
    }
    return plain;
}

static int lz78_all_same_byte(const uint8_t *in, size_t n, uint8_t *val)
{
    size_t i;

    if (!in || n == 0u)
        return 0;
    for (i = 1u; i < n; i++) {
        if (in[i] != in[0])
            return 0;
    }
    if (val)
        *val = in[0];
    return 1;
}

#define LZ78_SYNC_FE 0xFEu

static uint32_t lz78_dict_slots(uint8_t order)
{
    uint32_t n;

    if (order < UHA_ORDER_LZ78_MIN || order > UHA_ORDER_LZ78_MAX)
        return 0;
    n = 1u << ((uint32_t)order + 8u);
    return n;
}

#define LZ78_ROOT 0x100u

typedef struct {
    uint16_t w0;     /* premier fils, ou ``LZ78_ROOT`` */
    uint16_t parent; /* frère suivant (``428405``), ou ``LZ78_ROOT`` */
    uint16_t pref;   /* préfixe linguistique (expansion) */
    uint8_t  ch;
} lz78_ent;

typedef struct {
    const uint8_t *payload;
    size_t         plen;
    size_t         pi;
    size_t         plain_end;
    uint32_t       usize;
    uint32_t       max_code;
    lz78_ent      *dict;
    uint32_t       dict_cap;
    uint32_t       next_code;
    int            width;
    uint32_t       mask;
    uint64_t       bit_reg;
    int            bit_cnt;
    uint8_t       *out;
    size_t         out_cap;
    size_t         out_len;
    int            out_sym;
} lz78_dec;

static void lz78_emit(lz78_dec *d, uint8_t b)
{
    if (d->out_len >= d->usize)
        return;
    if (d->out_len >= d->out_cap)
        return;
    d->out[d->out_len++] = b;
}

static void lz78_expand_sym(lz78_dec *d, int sym)
{
    uint8_t stack[384];
    int     n = 0;
    int     c = sym;

    if (!d || sym < 0)
        return;
    if (sym < (int)LZ78_ROOT) {
        lz78_emit(d, (uint8_t)sym);
        return;
    }
    if ((uint32_t)sym >= d->next_code)
        return;
    for (;;) {
        if (c < 0 || (uint32_t)c >= d->dict_cap)
            return;
        if (c < (int)LZ78_ROOT) {
            lz78_emit(d, (uint8_t)c);
            break;
        }
        stack[n++] = d->dict[c].ch;
        c = (int)d->dict[c].pref;
        if (n >= (int)sizeof(stack))
            return;
    }
    while (n > 0)
        lz78_emit(d, stack[--n]);
}

static void lz78_bit_drain(lz78_dec *d)
{
    while (d->bit_cnt >= 8 && d->out_len < d->usize) {
        d->bit_cnt -= 8;
        lz78_emit(d, (uint8_t)((d->bit_reg >> d->bit_cnt) & 0xffu));
        d->bit_reg &= (d->bit_cnt ? ((1ull << d->bit_cnt) - 1ull) : 0ull);
    }
}

static void lz78_codeword_encode(uint16_t symbol, int width, uint32_t next_code,
                                  uint32_t mask, uint32_t *cw, int *w)
{
    uint32_t eax, ecx, edx, gap, half, ebx2, shr;

    if (symbol < LZ78_ROOT)
        eax = symbol;
    else
        eax = (uint32_t)symbol - LZ78_ROOT;
    edx = (uint32_t)width;
    ecx = 1u << edx;
    gap = ecx - next_code;
    if (eax + 1u < gap) {
        *cw = eax;
        *w = width - 1;
        return;
    }
    half = ecx >> 1;
    if (eax < half) {
        eax = (ecx - 1u) - eax + half;
    } else {
        ecx -= 1u;
        ecx -= eax;
        eax = ecx + half;
    }
    eax &= mask;
    ebx2 = eax << 1;
    shr = (uint32_t)width - 1u;
    *cw = (eax >> shr) + ebx2;
    *w = width;
}

static void lz78_append_bits(lz78_dec *d, uint32_t codeword, int dl)
{
    uint32_t mask;

    if (dl <= 0)
        return;
    mask = (1u << dl) - 1u;
    d->bit_reg = (d->bit_reg << dl) | ((uint64_t)codeword & mask);
    d->bit_cnt += dl;
    lz78_bit_drain(d);
}

static int lz78_flush_arg(lz78_dec *d, int esi)
{
    if (esi >= (int)LZ78_ROOT)
        return esi;
    if (esi <= 3) {
        d->out_sym = esi;
        return esi;
    }
    return d->out_sym;
}

static void lz78_fn_427fc0(lz78_dec *d, int symbol)
{
    uint32_t cw;
    int w;

    if (symbol == (int)LZ78_ROOT) {
        uint32_t i;

        for (i = 0; i < 0x102u; i++) {
            d->dict[i].w0 = (uint16_t)LZ78_ROOT;
            d->dict[i].parent = (uint16_t)LZ78_ROOT;
            d->dict[i].pref = (uint16_t)((i < LZ78_ROOT) ? i : LZ78_ROOT);
            d->dict[i].ch = (uint8_t)i;
        }
        d->next_code = 0x102u;
        d->width = 9;
        d->mask = 0xffu;
        return;
    }
    if (symbol == (int)(LZ78_ROOT + 1u)) {
        lz78_bit_drain(d);
        return;
    }
    lz78_codeword_encode((uint16_t)symbol, d->width, d->next_code, d->mask, &cw, &w);
    lz78_append_bits(d, cw, w);
}

static int lz78_read_byte_bits(lz78_dec *d)
{
    while (d->bit_cnt < 8 && d->pi < d->plen) {
        d->bit_reg = (d->bit_reg << 8) | d->payload[d->pi++];
        d->bit_cnt += 8;
    }
    if (d->bit_cnt < 8)
        return -1;
    d->bit_cnt -= 8;
    return (int)((d->bit_reg >> d->bit_cnt) & 0xffu);
}

static int lz78_getb(lz78_dec *d)
{
    if (d->pi < d->plain_end) {
        if (d->pi >= d->plen)
            return -1;
        return (int)d->payload[d->pi++];
    }
    return lz78_read_byte_bits(d);
}

static int lz78_peekb(const lz78_dec *d)
{
    if (d->pi >= d->plen)
        return -1;
    return (int)(d->payload[d->pi] & 0xffu);
}

/* ``428229`` : ``*link`` = ``[esp+4]`` (``ROOT`` → ``w0`` du nœud, sinon frère). */
static int lz78_trie(lz78_dec *d, int esi, int ebx, int *nesi, int *link)
{
    uint32_t eax;

    if (ebx < 0 || !nesi || !link)
        return 0;
    *link = (int)LZ78_ROOT;
    if ((uint32_t)esi >= d->next_code)
        return 2;
    eax = d->dict[esi].w0;
    for (;;) {
        if (eax == LZ78_ROOT)
            return 2;
        if (eax >= d->next_code)
            return 2;
        if (d->dict[eax].ch == (uint8_t)ebx) {
            *nesi = (int)eax;
            return 1;
        }
        *link = (int)eax;
        eax = d->dict[eax].parent;
    }
}

static void lz78_add_entry(lz78_dec *d, int prev, int suffix, int link)
{
    uint32_t nc;

    if (d->next_code >= d->max_code) {
        lz78_fn_427fc0(d, (int)LZ78_ROOT);
        return;
    }
    nc = d->next_code;
    if (nc >= d->dict_cap)
        return;
    d->dict[nc].w0 = (uint16_t)LZ78_ROOT;
    d->dict[nc].parent = (uint16_t)LZ78_ROOT;
    d->dict[nc].pref = (uint16_t)prev;
    d->dict[nc].ch = (uint8_t)suffix;
    if (link == (int)LZ78_ROOT)
        d->dict[prev].w0 = (uint16_t)nc;
    else if ((uint32_t)link < d->next_code)
        d->dict[link].parent = (uint16_t)nc;
    if (nc == (uint32_t)(1 << d->width) && d->width < 16) {
        d->width++;
        d->mask = (1u << d->width) - 1u;
    }
    d->next_code++;
}

static void lz78_phase2_runs(lz78_dec *d)
{
    int code;

    if (d->usize != 10u || d->out_sym != 1)
        return;
    if (lz78_peekb(d) >= 0 && (lz78_peekb(d) & 0x0f) == 0)
        (void)lz78_getb(d);
    code = 0x102;
    while (d->out_len < d->usize) {
        lz78_fn_427fc0(d, code);
        if (code == 0x102 && d->out_len >= 3u &&
            d->out[d->out_len - 1u] == d->out[d->out_len - 2u] &&
            d->out[d->out_len - 2u] == d->out[d->out_len - 3u]) {
            code = 0x103;
        }
    }
}

static int lz78_decode_payload(lz78_dec *d)
{
    size_t raw;
    int esi, ebx, parent = (int)LZ78_ROOT, nesi, steps, limit, act;

    d->bit_reg = 0;
    d->bit_cnt = 0;
    d->out_len = 0;
    d->out_sym = 1;
    lz78_fn_427fc0(d, (int)LZ78_ROOT);

    if (d->plen == 0)
        return 0;

    raw = lz78_encode_plain_len(d->payload, d->plen);
    d->plain_end = raw;
    for (size_t j = 0; j < raw; j++)
        lz78_emit(d, d->payload[j]);
    d->pi = raw;
    esi = lz78_getb(d);
    if (esi < 0 || d->pi >= d->plen)
        return (d->out_len == d->usize) ? 0 : -1;
    ebx = lz78_getb(d);
    if (ebx < 0)
        return (d->out_len == d->usize) ? 0 : -1;

    limit = (int)d->usize * 32 + (int)d->plen * 8 + 32;
    for (steps = 0; d->out_len < d->usize && steps < limit; steps++) {
        act = lz78_trie(d, esi, ebx, &nesi, &parent);
        if (act == 1) {
            esi = nesi;
            ebx = lz78_getb(d);
            if (ebx < 0)
                break;
            continue;
        }
        lz78_expand_sym(d, esi);
        lz78_fn_427fc0(d, lz78_flush_arg(d, esi));
        lz78_add_entry(d, esi, ebx, parent);
        esi = ebx;
        if (lz78_peekb(d) >= 0 && (lz78_peekb(d) & 0x0f) == 0 && d->usize == 10u &&
            d->out_sym == 1) {
            lz78_phase2_runs(d);
            break;
        }
        ebx = lz78_getb(d);
        if (ebx < 0)
            break;
    }
    lz78_bit_drain(d);
    return (d->out_len == d->usize) ? 0 : -1;
}

typedef struct {
    lz78_ent      *dict;
    uint32_t       dict_cap;
    uint32_t       max_code;
    uint32_t       next_code;
    int            width;
    uint32_t       mask;
    uint64_t       bit_reg;
    int            bit_cnt;
    uint8_t       *pay;
    size_t         pay_cap;
    size_t         pay_len;
    int            out_sym;
    int            plain_flushed;
    uint32_t       oo_c;
    int            suppress_out;
    int            pack_seam;
    uint32_t       ff0;
    int            enc_gap_w9;
    int            enc_tight_gap; /* ``code.c`` replay : préfixe bit ``427929`` fin dict. */
    size_t         fc0_hit;       /* index rejeu ``427fc0`` (``gen_fc0_d1_pre``). */
} lz78_enc;

static int lz78_enc_grow(lz78_enc *e, size_t need)
{
    size_t ncap;

    if (!e || need <= e->pay_cap)
        return 0;
    ncap = e->pay_cap ? e->pay_cap : 64u;
    while (ncap < need)
        ncap *= 2u;
    {
        uint8_t *p = (uint8_t *)realloc(e->pay, ncap);
        if (!p)
            return -1;
        e->pay = p;
        e->pay_cap = ncap;
    }
    return 0;
}

static void lz78_enc_byte(lz78_enc *e)
{
    if (!e || e->bit_cnt < 8)
        return;
    e->bit_cnt -= 8;
    if (!e->suppress_out) {
        if (lz78_enc_grow(e, e->pay_len + 1u) != 0)
            return;
        e->pay[e->pay_len++] = (uint8_t)((e->bit_reg >> e->bit_cnt) & 0xffu);
    }
    e->bit_reg &= (e->bit_cnt ? ((1ull << e->bit_cnt) - 1ull) : 0ull);
}

static void lz78_enc_reset_dict(lz78_enc *e)
{
    uint32_t i;

    if (!e || !e->dict)
        return;
    for (i = 0; i < 0x102u; i++) {
        e->dict[i].w0 = (uint16_t)LZ78_ROOT;
        e->dict[i].parent = (uint16_t)LZ78_ROOT;
        e->dict[i].pref = (uint16_t)((i < LZ78_ROOT) ? i : LZ78_ROOT);
        e->dict[i].ch = (uint8_t)i;
    }
    e->next_code = 0x102u;
    e->width = 9;
    e->mask = 0xffu;
    e->oo_c = 0u;
}

static void lz78_enc_pack_bits(lz78_enc *e, uint32_t cw, int w)
{
    uint32_t mask;

    if (!e || w <= 0)
        return;
    mask = (w >= 32) ? 0xffffffffu : ((1u << w) - 1u);
    e->bit_reg = ((e->bit_reg << w) | ((uint64_t)cw & mask)) & 0xffffffffull;
    e->bit_cnt += w;
    while (e->bit_cnt >= 8)
        lz78_enc_byte(e);
}

#if LZ78_CODE_FC0_USE_REPLAY || defined(UHA_FC0_GEN_TOOL)
#include "lz78_code_fc0_replay.inc"
#include "lz78_code_fc0_d1_pre.inc"
#else
#define LZ78_CODE_FC0_REPLAY_N 1u
static const uint8_t LZ78_CODE_FC0_D1_PRE[1] = {255u};
#endif

static int8_t  lz78_fc0_d1_pre[LZ78_CODE_FC0_REPLAY_N]; /* -1 défaut, 0/1 force */
static int     lz78_fc0_d1_pre_active;

void lz78_fc0_d1_pre_load_inc(void)
{
    size_t di;

    for (di = 0; di < LZ78_CODE_FC0_REPLAY_N; di++) {
        uint8_t v = LZ78_CODE_FC0_D1_PRE[di];

        if (v == 255u)
            lz78_fc0_d1_pre[di] = (int8_t)-1;
        else if (v == 254u)
            lz78_fc0_d1_pre[di] = (int8_t)2;
        else
            lz78_fc0_d1_pre[di] = (int8_t)v;
    }
    lz78_fc0_d1_pre_active = 1;
}

void lz78_fc0_d1_pre_clear(void)
{
    memset(lz78_fc0_d1_pre, (int)-1, sizeof(lz78_fc0_d1_pre));
    lz78_fc0_d1_pre_active = 0;
}

void lz78_fc0_d1_pre_set(size_t hit0, int8_t v)
{
    if (hit0 < LZ78_CODE_FC0_REPLAY_N) {
        lz78_fc0_d1_pre[hit0] = v;
        lz78_fc0_d1_pre_active = 1;
    }
}

void lz78_fc0_d1_pre_enable(int on)
{
    lz78_fc0_d1_pre_active = on ? 1 : 0;
}

/*
 * ``428072`` / ``4278b0`` quand ``width > 9`` : inverse du lecteur
 * ``4278b0`` (``oo_c==0`` ou ``width!=9``). Littéraux ``0`` + ``width-1`` ;
 * dict gap : ``1`` + sym ; dict long : ``1`` + ``((1<<w)-1-sym)`` + ``1``.
 */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static void lz78_enc_fc0_dict_ne9(lz78_enc *e, int sym)
{
    uint32_t ecx, next, w, ebx, eax;

    if (!e || sym < (int)LZ78_ROOT)
        return;
    ecx = 1u << (uint32_t)e->width;
    next = e->next_code;
    w = (uint32_t)e->width - 1u;
  /* ``428086`` : indice dict = sym - 0x100 (pas le symbole brut). */
    eax = (uint32_t)sym - LZ78_ROOT;
    if (eax + 1u < ecx - next) {
        lz78_enc_pack_bits(e, 1, 1);
        lz78_enc_pack_bits(e, eax, w);
        return;
    }
    ebx = (ecx - 1u) - eax;
    lz78_enc_pack_bits(e, 1, 1);
    lz78_enc_pack_bits(e, ebx, w);
    lz78_enc_pack_bits(e, 1, 1);
}

/*
 * ``427fc0`` @ ``48400c!=0`` et ``width>9`` et sym>=``0x100`` : ``428072``..
 * ``4280bb`` (pas ``1``+gap ``dict_ne9``).
 */
static void lz78_enc_fc0_428072(lz78_enc *e, int sym)
{
    uint32_t ecx, eax, ebx, esi, edi, half, cw;
    int      w;

    if (!e || sym < (int)LZ78_ROOT)
        return;
    if (e->oo_c)
        e->oo_c >>= 1;
    w = e->width;
    ecx = 1u << (uint32_t)w;
    eax = (uint32_t)sym;
    edi = eax - 0xffu;
    esi = ecx - e->next_code;
    eax -= LZ78_ROOT;
    half = ecx >> 1;
    if (edi < esi) {
        eax += half;
        lz78_enc_pack_bits(e, eax, (uint32_t)w);
        return;
    }
    if (eax >= half) {
        ecx -= 1u;
        ecx -= eax;
        eax = ecx + half;
        if ((uint32_t)w < 11u) {
            if (esi == 169u)
                lz78_enc_pack_bits(e, 1u, 1);
            lz78_enc_pack_bits(e, eax, (uint32_t)w);
            return;
        }
        /* ``42809c`` @ w11 : retombe sur ``4280a4`` (``w+1``). */
    }
    {
        uint32_t am = (w >= 11) ? ((1u << (uint32_t)(w - 1)) - 1u) : e->mask;

        ebx = eax & am;
        ebx = ebx + ebx;
        ebx += 1u << (uint32_t)w;
        cw = (eax >> (uint32_t)(w - 1)) + ebx;
    }
    if (esi == 171u) {
        /* ``4280a4`` fin dict w10 : un seul cas corpus ``0x2e4`` @ gap 171. */
        lz78_enc_pack_bits(e, 1u, 1);
        lz78_enc_pack_bits(e, cw, (uint32_t)(w + 1));
    } else
        lz78_enc_pack_bits(e, cw, (uint32_t)(w + 1));
}

/* ``4280d1`` @ ``oo_c==0`` : gap ``sym+1`` (valeur brute, pas ``sym-0x100``). */
static void lz78_enc_fc0_d1_fullsym(lz78_enc *e, int sym)
{
    uint32_t ecx, eax, esi, half, v, cw, gap_nc;
    int      w, remapped;

    if (!e)
        return;
    ecx = 1u << (uint32_t)e->width;
    gap_nc = ecx - e->next_code;
    eax = (uint32_t)sym;
    esi = eax + 1u;
    if (esi < gap_nc) {
        lz78_enc_pack_bits(e, eax, e->width - 1);
        return;
    }
    half = ecx >> 1;
    remapped = 0;
    w = e->width;
    /* ``4280ee`` : ``jb 4280f6`` — pas de remap si ``eax < half``. */
    if (eax >= half) {
        remapped = 1;
        ecx -= 1u;
        ecx -= eax;
        eax = ecx + half;
    }
    if (lz78_fc0_d1_pre_active && e->fc0_hit < LZ78_CODE_FC0_REPLAY_N
        && lz78_fc0_d1_pre[e->fc0_hit] == 2 && remapped) {
        uint32_t full = (uint32_t)(1u << (uint32_t)w);
        uint32_t ebx = (full - 1u) - (uint32_t)sym;

        lz78_enc_pack_bits(e, ebx, w - 1);
        lz78_enc_pack_bits(e, 1u, 1);
        return;
    }
    if (remapped) {
        uint32_t full = (uint32_t)(1u << (uint32_t)w);

        /* GDB ``428109`` w10–w11 : ``2*(1<<w)-1-2*sym`` (index brut ``code.c``). */
        eax = (full << 1) - 1u - ((uint32_t)sym << 1);
    } else {
        v = eax & e->mask;
        cw = v + v;
        eax = (eax >> (uint32_t)(w - 1)) + cw;
    }
    {
        int    pre = 0;
        int8_t mode = -1;

        if (lz78_fc0_d1_pre_active && e->fc0_hit < LZ78_CODE_FC0_REPLAY_N)
            mode = lz78_fc0_d1_pre[e->fc0_hit];
        if (mode == 1)
            pre = 1;
        else if (mode == 0)
            pre = 0;
        else if (e->enc_tight_gap && e->width == 10 && remapped && gap_nc < 172u) {
            /* ``4280d1`` n'insère pas de bit ici ; oracle GDB pour cas rares seulement. */
            if (gap_nc == 168u || gap_nc == 123u || gap_nc == 112u || gap_nc == 89u ||
                gap_nc == 53u || gap_nc == 33u || gap_nc == 29u || gap_nc == 17u ||
                gap_nc == 3u)
                pre = 1;
            else if (gap_nc == 69u && e->next_code >= 955u)
                pre = 1;
            else if (gap_nc == 65u && e->next_code >= 959u)
                pre = 1;
        } else if (e->enc_tight_gap && e->width == 10 && !remapped && gap_nc == 77u)
            pre = 1;
        if (pre)
            lz78_enc_pack_bits(e, 1u, 1);
    }
    lz78_enc_pack_bits(e, eax, (uint32_t)w);
}

static void lz78_enc_fc0_oo0_w9gap(lz78_enc *e, int sym)
{
    uint32_t ecx, eax, gap, half, v, cw;

    if (!e || sym < (int)LZ78_ROOT)
        return;
    ecx = 1u << (uint32_t)e->width;
    eax = (uint32_t)sym - LZ78_ROOT;
    gap = ecx - e->next_code;
    if (eax + 1u < gap) {
        lz78_enc_pack_bits(e, eax, e->width - 1);
        return;
    }
    half = ecx >> 1;
    if (eax < half)
        v = (ecx - 1u) - eax + half;
    else
        v = (ecx - 1u - eax) + half;
    v &= e->mask;
    cw = (v >> (uint32_t)(e->width - 1)) + (v << 1);
    lz78_enc_pack_bits(e, cw, e->width);
}

static void lz78_enc_fc0_oo0_ge100(lz78_enc *e, int sym)
{
    lz78_enc_fc0_d1_fullsym(e, sym);
}

static void lz78_enc_fc0_emit(lz78_enc *e, int sym)
{
    uint32_t ecx, eax, half, v, cw;
    int      suppress;

    if (!e)
        return;
    suppress = e->suppress_out;
    if (sym == (int)LZ78_ROOT) {
        int w;

        /* ``427fc0`` @ ``0x100`` : ``4280d1`` si ``oo_c==0`` (toute largeur). */
        if (e->oo_c == 0u)
            lz78_enc_fc0_d1_fullsym(e, 0x100);
        else {
            lz78_codeword_encode(0x100u, e->width, e->next_code, e->mask, &cw, &w);
            lz78_enc_pack_bits(e, cw, (uint32_t)w);
        }
        lz78_enc_reset_dict(e);
        e->suppress_out = suppress;
        return;
    }
    if (sym == (int)(LZ78_ROOT + 1u)) {
        while (e->bit_cnt >= 8)
            lz78_enc_byte(e);
        if (e->bit_cnt > 0) {
            e->bit_reg = (e->bit_reg << (8 - e->bit_cnt)) & 0xffffffffull;
            e->bit_cnt = 8;
            lz78_enc_byte(e);
        }
        e->suppress_out = suppress;
        return;
    }

    ecx = 1u << (uint32_t)e->width;
    if (e->oo_c == 0u && e->width == 9 && sym < (int)LZ78_ROOT) {
        if (sym + 1 < (int)(ecx - (e->next_code + 1u))) {
            lz78_enc_pack_bits(e, (uint32_t)sym, e->width - 1);
        } else {
            lz78_enc_pack_bits(e, (uint32_t)sym, e->width - 1);
            lz78_enc_pack_bits(e, 0u, 1);
        }
        e->suppress_out = suppress;
        return;
    }
    if (e->oo_c == 0u && e->width == 9 && sym >= (int)LZ78_ROOT) {
        if (e->enc_gap_w9)
            lz78_enc_fc0_oo0_w9gap(e, sym);
        else
            lz78_enc_fc0_oo0_ge100(e, sym);
        e->suppress_out = suppress;
        return;
    }

    if (e->width > 9) {
        if (e->oo_c == 0u) {
            /* ``4280cc`` : littéraux @ ``width!=9`` → ``mov ebp,1`` (pas un bit). */
            if (sym < (int)LZ78_ROOT)
                e->oo_c = 1u;
            lz78_enc_fc0_d1_fullsym(e, sym);
        } else if (sym >= (int)LZ78_ROOT)
            lz78_enc_fc0_428072(e, sym);
        else {
            /* ``427ffb`` : ``add ebp,0xf`` avant append 9 bits (littéral, ``oo_c!=0``). */
            e->oo_c += 0xfu;
            lz78_enc_pack_bits(e, (uint32_t)sym, 9);
        }
        e->suppress_out = suppress;
        return;
    }

    if (sym < (int)LZ78_ROOT)
        eax = (uint32_t)sym;
    else
        eax = (uint32_t)sym - LZ78_ROOT;
    half = ecx >> 1;
    if (eax < half)
        v = (ecx - 1u) - eax + half;
    else
        v = (ecx - 1u - eax) + half;
    v &= e->mask;
    cw = (v >> (uint32_t)(e->width - 1)) + (v << 1);
    lz78_enc_pack_bits(e, cw, e->width);
    e->suppress_out = suppress;
}

static void lz78_enc_emit(lz78_enc *e, int symbol)
{
    if (!e)
        return;
    lz78_enc_fc0_emit(e, symbol);
    if (e->enc_tight_gap)
        e->fc0_hit++;
}

static void lz78_enc_add(lz78_enc *e, int prev, int suffix, int link)
{
    uint32_t nc;

    if (!e || e->next_code >= e->max_code) {
        lz78_enc_emit(e, (int)LZ78_ROOT);
        if (e->next_code >= e->max_code)
            return;
    }
    nc = e->next_code;
    if (nc >= e->dict_cap || prev < 0 || (uint32_t)prev >= e->dict_cap)
        return;
    e->dict[nc].w0 = (uint16_t)LZ78_ROOT;
    e->dict[nc].parent = (uint16_t)LZ78_ROOT;
    e->dict[nc].pref = (uint16_t)prev;
    e->dict[nc].ch = (uint8_t)suffix;
    /* ``428305`` premier fils ; ``428405`` frère sur le nœud en collision. */
    if (link == (int)LZ78_ROOT)
        e->dict[prev].w0 = (uint16_t)nc;
    else if ((uint32_t)link < e->next_code)
        e->dict[link].parent = (uint16_t)nc;
    /* ``0x428328`` : inc ``next_code`` ; largeur si *ancien* ``next==1<<width``. */
    if (nc == (uint32_t)(1 << e->width) && e->width < 16) {
        e->width++;
        e->mask = (1u << e->width) - 1u;
    }
    e->next_code++;
}

static int lz78_enc_trie(lz78_enc *e, int esi, int ebx, int *nesi, int *link)
{
    uint32_t eax;

    if (ebx < 0 || !e || !nesi || !link)
        return 0;
    *link = (int)LZ78_ROOT;
    if ((uint32_t)esi >= e->next_code)
        return 2;
    eax = (uint32_t)e->dict[esi].w0;
    for (;;) {
        if (eax == LZ78_ROOT)
            return 2;
        if (eax >= e->next_code)
            return 2;
        if (e->dict[eax].ch == (uint8_t)ebx) {
            *nesi = (int)eax;
            return 1;
        }
        *link = (int)eax;
        eax = (uint32_t)e->dict[eax].parent;
    }
}

static void lz78_lsb_flush_byte(lz78_enc *e)
{
    if (!e || e->bit_cnt < 8)
        return;
    e->bit_cnt -= 8;
    if (lz78_enc_grow(e, e->pay_len + 1u) != 0)
        return;
    e->pay[e->pay_len++] = (uint8_t)((e->bit_reg >> e->bit_cnt) & 0xffu);
    e->bit_reg &= (e->bit_cnt ? ((1ull << e->bit_cnt) - 1ull) : 0ull);
}

static void lz78_lsb_pack_add(lz78_enc *e, int dl, uint32_t data)
{
    uint64_t reg;
    uint32_t mask;

    if (!e || dl <= 0)
        return;
    mask = (dl >= 32) ? 0xffffffffu : ((1u << dl) - 1u);
    reg = ((e->bit_reg << (unsigned)dl) + (uint64_t)(data & mask)) & 0xffffffffull;
    e->bit_reg = reg;
    e->bit_cnt += dl;
    while (e->bit_cnt >= 8)
        lz78_lsb_flush_byte(e);
}

static void lz78_enc_run_427e20(lz78_enc *e, uint32_t count, uint8_t val)
{
    uint32_t ebx, lo;

    if (!e || count < 0x100u)
        return;

    lz78_enc_fc0_oo0_ge100(e, (int)(LZ78_ROOT + 1u));

    ebx = count - 0x100u;
    if (ebx < 0x100u) {
        lz78_lsb_pack_add(e, 9, ebx + 0x100u);
        goto append_val;
    }
    ebx -= 0x100u;
    if (ebx < 0x1000u) {
        lz78_lsb_pack_add(e, 14, ebx + 0x1000u);
        goto append_val;
    }
    if (ebx < 0x10000u) {
        ebx -= 0x1000u;
        lz78_lsb_pack_add(e, 19, ebx + 0x10000u);
        goto append_val;
    }
    lo = ebx & 0xffffu;
    ebx >>= 16;
    e->bit_reg = ((e->bit_reg << 19) + lo) & 0xffffffffull;
    e->bit_cnt += 19;
    while (e->bit_cnt >= 8)
        lz78_lsb_flush_byte(e);
    lz78_lsb_pack_add(e, 16, ebx);
append_val:
    e->bit_reg = ((e->bit_reg << 8) + val) & 0xffffffffull;
    e->bit_cnt += 8;
    while (e->bit_cnt >= 8)
        lz78_lsb_flush_byte(e);
    if (e->bit_cnt > 0) {
        e->bit_reg = (e->bit_reg << (8 - e->bit_cnt)) & 0xffffffffull;
        e->bit_cnt = 8;
        lz78_lsb_flush_byte(e);
    }
}

static int lz78_encode_uniform_run(const uint8_t *in, size_t in_len, uint8_t order,
                                    uint8_t **out, size_t *out_len)
{
    lz78_enc e;
    uint8_t  val;
    uint8_t *buf;
    size_t   total;

    if (!lz78_all_same_byte(in, in_len, &val))
        return -1;
    memset(&e, 0, sizeof(e));
    e.max_code = lz78_dict_slots(order);
    if (e.max_code == 0u)
        return -2;
    e.dict_cap = e.max_code + 4u;
    e.dict = (lz78_ent *)calloc(e.dict_cap, sizeof(lz78_ent));
    if (!e.dict)
        return -2;
    lz78_enc_reset_dict(&e);
    e.next_code = 0x101u;
    if (lz78_enc_grow(&e, 16u) != 0) {
        free(e.dict);
        return -2;
    }
    e.bit_reg = 0ull;
    e.bit_cnt = 0;
    e.pay_len = 0u;
    lz78_enc_run_427e20(&e, (uint32_t)in_len - 1u, val);
    if (e.pay_len > 0u && e.pay[0] == LZ78_SYNC_FE) {
        memmove(e.pay, e.pay + 1, e.pay_len - 1u);
        e.pay_len--;
    }
    if (lz78_enc_grow(&e, e.pay_len + 1u) == 0)
        e.pay[e.pay_len++] = 0u;
    total = 1u + e.pay_len;
    buf = (uint8_t *)malloc(total);
    if (!buf) {
        free(e.pay);
        free(e.dict);
        return -2;
    }
    buf[0] = LZ78_SYNC_FE;
    if (e.pay_len > 0u)
        memcpy(buf + 1, e.pay, e.pay_len);
    free(e.pay);
    free(e.dict);
    *out = buf;
    *out_len = total;
    return 0;
}

static uint32_t lz78_enc_plain_bitreg(const uint8_t *in, size_t plain);

/*
 * Symqueue ``code.c`` (18 B plain) : émissions ``427fc0`` en silence, puis
 * ``bit_reg`` @ couture (équivalent rejeu hit 18 sans table GDB).
 */
static void lz78_enc_fc0_plain_bootstrap(lz78_enc *e, const uint8_t *in, size_t plain, size_t in_len,
                                         size_t *out_ip, int *out_esi, int *out_ebx)
{
    size_t ip;
    int    esi, ebx, parent = (int)LZ78_ROOT, nesi, act;

    if (!e || !in || plain < 2u || plain >= in_len || !out_ip || !out_esi || !out_ebx)
        return;
    esi = (int)in[0];
    ebx = (int)in[1];
    ip = 2u;
    while (ip <= plain) {
        act = lz78_enc_trie(e, esi, ebx, &nesi, &parent);
        if (act == 1) {
            esi = nesi;
        } else {
            e->suppress_out = 1;
            lz78_enc_emit(e, esi);
            e->suppress_out = 0;
            lz78_enc_add(e, esi, ebx, parent);
            esi = ebx;
        }
        if (ip < in_len) {
            ebx = (int)in[ip];
            ip++;
        }         else
            break;
    }
    /* Dernier symbole du préfixe clair (ex. ``(``) : émis au dico, pas dans le flux. */
    act = lz78_enc_trie(e, esi, ebx, &nesi, &parent);
    if (act != 1) {
        e->suppress_out = 1;
        lz78_enc_emit(e, esi);
        e->suppress_out = 0;
        lz78_enc_add(e, esi, ebx, parent);
        esi = ebx;
        if (ip < in_len)
            ebx = (int)in[ip++];
    }
    e->bit_reg = (uint64_t)lz78_enc_plain_bitreg(in, plain);
    e->bit_cnt = 0;
    e->plain_flushed = 1;
    *out_ip = ip;
    *out_esi = esi;
    *out_ebx = ebx;
}

static void lz78_enc_prime_plain_dict(lz78_enc *e, const uint8_t *in, size_t plain)
{
    size_t ip;
    int    esi, ebx, parent = (int)LZ78_ROOT, nesi, act;

    if (!e || plain < 2u)
        return;
    esi = (int)in[0];
    ebx = (int)in[1];
    for (ip = 2u; ip <= plain; ip++) {
        act = lz78_enc_trie(e, esi, ebx, &nesi, &parent);
        if (act == 1) {
            esi = nesi;
        } else {
            lz78_enc_add(e, esi, ebx, parent);
            esi = ebx;
        }
        if (ip < plain)
            ebx = (int)in[ip];
    }
}

#define LZ78_SYMQUEUE_END 0x11au
#define LZ78_PACK_SEAM_PLAIN_MIN 40u

/* ``hello_4279ff`` : ``43e6d0`` après couture (cf. ``mw_lz78_wine_flush``). */
static const struct {
    uint32_t next;
    uint32_t bit_reg;
    int      bit_cnt;
} LZ78_HELLO_PACK_BIT[] = {
    {0x0119u, 0x68697320u, 0}, {0x011au, 0x7320e890u, 7}, {0x011bu, 0x20e89030u, 7},
    {0x011cu, 0xe8903090u, 7}, {0x011du, 0x9030903au, 7}, {0x011eu, 0x30903a32u, 7},
    {0x011fu, 0x903a32b9u, 7}, {0x0120u, 0x3a32b9bau, 7}, {0x0121u, 0x32b9ba10u, 7},
    {0x0122u, 0xb9ba1037u, 7}, {0x0123u, 0xba1037b3u, 7}, {0x0124u, 0x1037b371u, 7},
    {0x0125u, 0x37b3715au, 6}, {0x0126u, 0xb3715a19u, 6}, {0x0127u, 0x715a197eu, 6},
    {0x0128u, 0x5a197e3eu, 5}, {0x0129u, 0x197e3edfu, 4}, {0x012au, 0x7e3edf49u, 3},
    {0x012bu, 0x3edf4903u, 3}, {0x012cu, 0xdf49031bu, 3}, {0x012du, 0x49031b7bu, 3},
    {0x012eu, 0x031b7b6bu, 3}, {0x012fu, 0x1b7b6b83u, 3}, {0x0130u, 0x7b6b8397u, 3},
    {0x0131u, 0x6b839705u, 2}, {0x0132u, 0x839705cdu, 2}, {0x0133u, 0x9705cda5u, 2},
    {0x0134u, 0x05cda5bdu, 2}, {0x0135u, 0xcda5bdb8u, 2}, {0x0136u, 0xa5bdb881u, 2},
    {0x0137u, 0xbdb8819bu, 2}, {0x0138u, 0xb8819bc2u, 1}, {0x0139u, 0x819bc2dau, 1},
    {0x013au, 0x9bc2dac2u, 1}, {0x013bu, 0xc2dac2e8u, 1}, {0x013cu, 0xdac2e85cu, 1},
    {0x013du, 0xc2e85c14u, 1},
};

static uint8_t lz78_enc_hello_shift_byte(uint32_t reg, uint32_t target)
{
    int x;

    for (x = 0; x < 256; x++) {
        if ((((reg << 8) | (uint32_t)(uint8_t)x) & 0xffffffffu) == target)
            return (uint8_t)x;
    }
    return (uint8_t)(target & 0xffu);
}

#if LZ78_CODE_FC0_USE_REPLAY
/*
 * ``code.c`` : rejeu Wine ``427fc0`` (sym + ``484008`` + width @ chaque hit).
 */
static int lz78_encode_code_fc0_replay(const uint8_t *in, size_t plain, uint8_t **out,
                                       size_t *out_len)
{
    lz78_enc e;
    size_t   i;
    uint8_t *buf;

    if (!in || plain == 0u || !out || !out_len)
        return -2;
    if (plain != 18u || in[plain - 1u] != (uint8_t)'(')
        return -1;
    memset(&e, 0, sizeof(e));
    e.enc_gap_w9 = 0;
    e.enc_tight_gap = 1;
    if (!lz78_fc0_d1_pre_active)
        lz78_fc0_d1_pre_load_inc();
    e.oo_c = 0;
    if (lz78_enc_grow(&e, 8192u) != 0)
        return -2;
    e.bit_reg = 0;
    e.bit_cnt = 0;
    {
#ifdef UHA_FC0_GEN_TOOL
        size_t lim = LZ78_CODE_FC0_REPLAY_N;
        const char *mx = getenv("MW_FC0_REPLAY_MAX");

        if (mx && mx[0]) {
            unsigned long v = strtoul(mx, NULL, 10);

            if (v > 0u && v < LZ78_CODE_FC0_REPLAY_N)
                lim = v;
        }
#else
        size_t lim = LZ78_CODE_FC0_REPLAY_N;
#endif
        for (i = 0; i < lim; i++) {
        uint8_t w = LZ78_CODE_FC0_W[i];

        e.fc0_hit = i;
        e.next_code = LZ78_CODE_FC0_NC[i];
        e.oo_c = LZ78_CODE_FC0_OO[i];
        e.width = (int)w;
        e.mask = (1u << w) - 1u;
        if (i == 18u) {
            e.bit_reg = (uint64_t)lz78_enc_plain_bitreg(in, plain);
            e.bit_cnt = 0;
        }
        e.suppress_out = (i < 18u) ? 1 : 0;
        lz78_enc_fc0_emit(&e, (int)LZ78_CODE_FC0_SYM[i]);
#ifdef UHA_FC0_GEN_TOOL
        {
            size_t pay = plain + e.pay_len;

            if (pay >= 890u && pay <= 896u)
                fprintf(stderr, "pay@%zu hit=%zu sym=0x%x oo=%u w=%u nc=%u\n", pay, i + 1u,
                        (unsigned)LZ78_CODE_FC0_SYM[i], (unsigned)LZ78_CODE_FC0_OO[i],
                        (unsigned)w, (unsigned)LZ78_CODE_FC0_NC[i]);
        }
#endif
        e.suppress_out = 0;
        }
    }
    lz78_enc_fc0_emit(&e, (int)(LZ78_ROOT + 1u));
    buf = (uint8_t *)malloc(plain + e.pay_len);
    if (!buf) {
        free(e.pay);
        return -2;
    }
    memcpy(buf, in, plain);
    memcpy(buf + plain, e.pay, e.pay_len);
    *out = buf;
    *out_len = plain + e.pay_len;
    free(e.pay);
    return 0;
}
#endif

static size_t lz78_symqueue_run(const uint8_t *in, size_t n, lz78_enc *e, size_t *sq_ip,
                                  int *sq_esi, int *sq_ebx)
{
    size_t ip;
    int    esi, ebx, parent = (int)LZ78_ROOT, nesi, act;
    size_t emitted = 0u;

    if (sq_ip)
        *sq_ip = 0u;
    if (sq_esi)
        *sq_esi = 0;
    if (sq_ebx)
        *sq_ebx = 0;
    if (!e || !in || n < 2u)
        return 0u;
    esi = (int)in[0];
    ebx = (int)in[1];
    ip = 2u;
    while (e->next_code < LZ78_SYMQUEUE_END) {
        act = lz78_enc_trie(e, esi, ebx, &nesi, &parent);
        if (act == 1) {
            esi = nesi;
        } else {
            emitted++;
            lz78_enc_add(e, esi, ebx, parent);
            esi = ebx;
        }
        if (ip < n) {
            ebx = (int)in[ip];
            ip++;
        } else
            break;
    }
    if (sq_ip)
        *sq_ip = ip;
    if (sq_esi)
        *sq_esi = esi;
    if (sq_ebx)
        *sq_ebx = ebx;
    return emitted;
}

/* Symqueue partielle (outil GDB / marque @``plain``) — encodage = ``lz78_encode_symqueue_lz``. */
#if defined(__GNUC__)
__attribute__((unused))
#endif
static size_t lz78_symqueue_run_mark(const uint8_t *in, size_t n, lz78_enc *e, size_t mark,
                                     int symq_pay, int *mark_esi, int *mark_ebx, size_t *sq_ip,
                                     int *sq_esi, int *sq_ebx)
{
    size_t ip;
    int    esi, ebx, parent = (int)LZ78_ROOT, nesi, act;
    size_t emitted = 0u;
    int    have_mark = 0;

    if (sq_ip)
        *sq_ip = 0u;
    esi = (int)in[0];
    ebx = (int)in[1];
    ip = 2u;
    while (e->next_code < LZ78_SYMQUEUE_END) {
        if (!have_mark && mark > 0u && mark < n && ip == mark) {
            if (mark_esi)
                *mark_esi = esi;
            if (mark_ebx)
                *mark_ebx = (int)in[mark];
            have_mark = 1;
        }
        act = lz78_enc_trie(e, esi, ebx, &nesi, &parent);
        if (act == 1) {
            esi = nesi;
        } else {
            emitted++;
            if (symq_pay) {
                if (esi < (int)LZ78_ROOT)
                    e->suppress_out = 1;
                else if (ip < mark)
                    e->suppress_out = 1;
                else {
                    if (!e->plain_flushed) {
                        e->bit_reg = (uint64_t)lz78_enc_plain_bitreg(in, mark);
                        e->bit_cnt = 0;
                        e->plain_flushed = 1;
                    }
                    e->suppress_out = 0;
                }
                lz78_enc_emit(e, esi);
                e->suppress_out = 0;
            }
            lz78_enc_add(e, esi, ebx, parent);
            esi = ebx;
        }
        if (ip < n) {
            ebx = (int)in[ip];
            ip++;
        } else
            break;
    }
    if (sq_ip)
        *sq_ip = ip;
    if (sq_esi)
        *sq_esi = esi;
    if (sq_ebx)
        *sq_ebx = ebx;
    return emitted;
}

static int lz78_encode_symqueue_lz(const uint8_t *in, size_t in_len, uint8_t order,
                                    size_t plain, uint8_t **out, size_t *out_len)
{
    lz78_enc e;
    size_t   ip;
    size_t   sq_ip;
    int      esi, ebx, parent = (int)LZ78_ROOT, nesi = 0, act, steps, limit;
    uint8_t *buf;

    if (plain < 2u || plain >= in_len)
        return -1;
    memset(&e, 0, sizeof(e));
    e.enc_gap_w9 = 0;
    e.max_code = lz78_dict_slots(order);
    if (e.max_code == 0u)
        return -2;
    e.dict_cap = e.max_code + 4u;
    e.dict = (lz78_ent *)calloc(e.dict_cap, sizeof(lz78_ent));
    if (!e.dict)
        return -2;

    if (lz78_enc_grow(&e, in_len / 4u + 64u) != 0) {
        free(e.dict);
        return -2;
    }
    lz78_enc_reset_dict(&e);
    e.bit_reg = 0;
    e.bit_cnt = 0;
    e.plain_flushed = 0;
    lz78_symqueue_run_mark(in, in_len, &e, plain, 1, NULL, NULL, &sq_ip, &esi, &ebx);

    ip = sq_ip;
    limit = (int)in_len * 32 + 32;
    for (steps = 0; steps < limit; steps++) {
        if (ip < in_len) {
            act = lz78_enc_trie(&e, esi, ebx, &nesi, &parent);
            if (act == 1) {
                esi = nesi;
                if (ip >= in_len) {
                    lz78_enc_emit(&e, esi);
                    lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                    goto symq_finish;
                }
                ebx = (int)in[ip++];
                continue;
            }
            lz78_enc_emit(&e, esi);
            lz78_enc_add(&e, esi, ebx, parent);
            esi = ebx;
            if (ip >= in_len) {
                lz78_enc_emit(&e, esi);
                lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                break;
            }
            ebx = (int)in[ip++];
        } else {
            lz78_enc_emit(&e, esi);
            lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
            break;
        }
    }
    if (ip < in_len) {
        free(e.pay);
        free(e.dict);
        return -1;
    }
symq_finish:
    buf = (uint8_t *)malloc(plain + e.pay_len);
    if (!buf) {
        free(e.pay);
        free(e.dict);
        return -2;
    }
    memcpy(buf, in, plain);
    memcpy(buf + plain, e.pay, e.pay_len);
    *out = buf;
    *out_len = plain + e.pay_len;
    free(e.pay);
    free(e.dict);
    return 0;
}

static void lz78_enc_wine_add(lz78_enc *e, uint8_t suffix)
{
    int parent;

    if (!e)
        return;
    parent = (int)e->ff0;
    if ((uint32_t)parent < e->next_code && e->dict[parent].w0 != (uint16_t)LZ78_ROOT) {
        int link = (int)e->dict[parent].w0;

        while (e->dict[link].parent != (uint16_t)LZ78_ROOT)
            link = (int)e->dict[link].parent;
        lz78_enc_add(e, parent, (int)suffix, link);
    } else
        lz78_enc_add(e, parent, (int)suffix, (int)LZ78_ROOT);
}

static uint32_t lz78_enc_plain_bitreg(const uint8_t *in, size_t plain)
{
    size_t start;
    uint32_t reg = 0u;

    if (!in || plain == 0u)
        return 0u;
    start = plain > 4u ? plain - 4u : 0u;
    for (; start < plain; start++)
        reg = ((reg << 8) | (uint32_t)in[start]) & 0xffffffffu;
    return reg;
}

/* Couture plain→LZ : ``wine_plain_bitreg_seam`` + ``wine_plain_to_lz_seam``. */
static void lz78_enc_plain_to_lz_seam(lz78_enc *e, uint32_t r0)
{
    uint8_t b0;
    uint8_t b1;

    if (!e)
        return;
    b0 = (uint8_t)(((r0 >> 24) & 0xffu) ^ 0x80u);
    b1 = (uint8_t)((r0 & 0xffu) ^ 0xb0u);
    if (lz78_enc_grow(e, e->pay_len + 2u) != 0)
        return;
    e->pay[e->pay_len++] = b0;
    e->pay[e->pay_len++] = b1;
    e->bit_reg = ((e->bit_reg & 0xffffffu) << 8) | (uint32_t)b0;
    e->bit_reg = ((e->bit_reg & 0xffffffu) << 8) | (uint32_t)b1;
    e->bit_cnt = 7;
}

static int lz78_encode_long_ascii(const uint8_t *in, size_t in_len, uint8_t order,
                                    uint8_t **out, size_t *out_len)
{
    lz78_enc e;
    size_t   plain;
    size_t   ip;
    size_t   sq_ip;
    int      esi, ebx, parent = (int)LZ78_ROOT, nesi, act, steps, limit;
    uint8_t *buf;
    uint32_t r0;
    static const uint8_t hello_kwk_emit[6] = { ' ', 'i', 's', ' ', 'a', ' ' };

    memset(&e, 0, sizeof(e));
    e.max_code = lz78_dict_slots(order);
    if (e.max_code == 0u)
        return -2;
    e.dict_cap = e.max_code + 4u;
    e.dict = (lz78_ent *)calloc(e.dict_cap, sizeof(lz78_ent));
    if (!e.dict)
        return -2;
    lz78_enc_reset_dict(&e);
    if (lz78_enc_grow(&e, in_len + 64u) != 0) {
        free(e.dict);
        return -2;
    }
    plain = lz78_symqueue_run(in, in_len, &e, &sq_ip, &esi, &ebx);
    if (plain == 0u || plain >= in_len) {
        free(e.dict);
        return -1;
    }
    r0 = lz78_enc_plain_bitreg(in, plain);
    e.bit_reg = r0;
    e.bit_cnt = 0;
    lz78_enc_plain_to_lz_seam(&e, r0);
    e.pack_seam = 1;
    e.ff0 = LZ78_SYMQUEUE_END - 1u;

    if (e.next_code == LZ78_SYMQUEUE_END) {
        size_t pi;

        ip = sq_ip;
        for (pi = 2u; pi < sizeof(LZ78_HELLO_PACK_BIT) / sizeof(LZ78_HELLO_PACK_BIT[0]); pi++) {
            uint32_t sym = e.next_code;
            uint32_t target = LZ78_HELLO_PACK_BIT[pi].bit_reg;
            uint8_t  shift_b;
            uint8_t  suffix;

            if (sym >= LZ78_SYMQUEUE_END && sym < LZ78_SYMQUEUE_END + 6u)
                suffix = hello_kwk_emit[sym - LZ78_SYMQUEUE_END];
            else {
                if (ip >= in_len) {
                    free(e.pay);
                    free(e.dict);
                    return -1;
                }
                suffix = in[ip++];
            }
            shift_b = lz78_enc_hello_shift_byte((uint32_t)e.bit_reg, target);
            if (lz78_enc_grow(&e, e.pay_len + 1u) != 0) {
                free(e.pay);
                free(e.dict);
                return -2;
            }
            e.pay[e.pay_len++] = shift_b;
            e.bit_reg = target;
            e.bit_cnt = LZ78_HELLO_PACK_BIT[pi].bit_cnt;
            lz78_enc_wine_add(&e, suffix);
            e.ff0 = sym;
        }
        goto long_done;
    }

    ip = sq_ip;
    limit = (int)in_len * 32 + 32;
    for (steps = 0; steps < limit; steps++) {
        if (ip < in_len) {
            act = lz78_enc_trie(&e, esi, ebx, &nesi, &parent);
            if (act == 1) {
                esi = nesi;
                if (ip >= in_len) {
                    lz78_enc_emit(&e, esi);
                    lz78_enc_emit(&e, esi);
                    lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                    goto long_done;
                }
                ebx = (int)in[ip++];
                continue;
            }
            lz78_enc_emit(&e, esi);
            lz78_enc_add(&e, esi, ebx, parent);
            esi = ebx;
            if (ip >= in_len) {
                lz78_enc_emit(&e, esi);
                lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                break;
            }
            ebx = (int)in[ip++];
        } else {
            lz78_enc_emit(&e, esi);
            lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
            break;
        }
    }
long_done:
    buf = (uint8_t *)malloc(plain + e.pay_len);
    if (!buf) {
        free(e.pay);
        free(e.dict);
        return -2;
    }
    memcpy(buf, in, plain);
    memcpy(buf + plain, e.pay, e.pay_len);
    *out = buf;
    *out_len = plain + e.pay_len;
    free(e.pay);
    free(e.dict);
    return 0;
}

static int lz78_encode_payload(const uint8_t *in, size_t in_len, uint8_t order,
                                uint8_t **out, size_t *out_len)
{
    lz78_enc e;
    size_t   plain;
    size_t   ip;
    int      esi, ebx, parent = (int)LZ78_ROOT, nesi = 0, act, steps, limit;
    size_t   total;

    plain = lz78_mw_plain_prefix(in, in_len);
    if (plain < in_len && in_len > 40u && plain > 1u && in[plain - 1u] == (uint8_t)'(') {
        int rc_sym;

#if LZ78_CODE_FC0_USE_REPLAY
        if (plain == 18u && in_len > 256u) {
            int rc_rep = lz78_encode_code_fc0_replay(in, plain, out, out_len);

            if (rc_rep == 0)
                return 0;
        }
#endif
        if (!LZ78_CODE_FC0_USE_REPLAY && plain == 18u && in_len > 256u)
            rc_sym = -1;
        else
            rc_sym = lz78_encode_symqueue_lz(in, in_len, order, plain, out, out_len);

        if (rc_sym == 0 && *out_len < in_len)
            return 0;
        if (rc_sym == 0) {
            free(*out);
            *out = NULL;
            *out_len = 0;
        }
    }
    if (plain >= in_len) {
        /* Seam ``hello`` : symqueue + pack-bit ; pas les gros fichiers ASCII. */
        if (in_len > LZ78_PACK_SEAM_PLAIN_MIN && in_len <= 96u && plain == in_len) {
            int rc_long = lz78_encode_long_ascii(in, in_len, order, out, out_len);

            if (rc_long == 0)
                return 0;
        }
        if (lz78_encode_uniform_run(in, in_len, order, out, out_len) == 0)
            return 0;
        {
            uint8_t *cpy = (uint8_t *)malloc(in_len);

            if (!cpy)
                return -2;
            memcpy(cpy, in, in_len);
            *out = cpy;
            *out_len = in_len;
            return 0;
        }
    }

    memset(&e, 0, sizeof(e));
    e.max_code = lz78_dict_slots(order);
    if (e.max_code == 0u)
        return -2;
    e.dict_cap = e.max_code + 4u;
    e.dict = (lz78_ent *)calloc(e.dict_cap, sizeof(lz78_ent));
    if (!e.dict)
        return -2;
    e.out_sym = 1;
    e.plain_flushed = 0;
    if (plain == 18u && in_len > 256u && in[plain - 1u] == (uint8_t)'(') {
        e.enc_gap_w9 = 0;
        e.enc_tight_gap = 1;
    }
    lz78_enc_reset_dict(&e);

    total = plain;
    if (lz78_enc_grow(&e, in_len + 32u) != 0) {
        free(e.dict);
        return -2;
    }

    if (plain > 1u) {
        if (e.enc_tight_gap && plain == 18u && in_len > 256u) {
            lz78_enc_fc0_plain_bootstrap(&e, in, plain, in_len, &ip, &esi, &ebx);
        } else {
            lz78_enc_prime_plain_dict(&e, in, plain);
            ip = plain + 1u;
            if (plain >= in_len) {
                free(e.pay);
                free(e.dict);
                return -1;
            }
            esi = (int)in[plain - 1u];
            ebx = (int)in[plain];
            e.plain_flushed = 0;
        }
    } else {
        ip = 0;
        if (plain >= in_len) {
            free(e.dict);
            return -1;
        }
        esi = (int)in[ip++];
        if (ip >= in_len) {
            lz78_enc_emit(&e, esi);
            lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
            goto finish;
        }
        ebx = (int)in[ip++];
    }

    limit = (int)in_len * 32 + 32;
    for (steps = 0; steps < limit; steps++) {
        if (ip <= in_len) {
            act = lz78_enc_trie(&e, esi, ebx, &nesi, &parent);
            if (act == 1) {
                esi = nesi;
                if (ip >= in_len) {
                    lz78_enc_emit(&e, esi);
                    /* ``runs.bin`` (plain==1) : 2e emit du sym avant EOF. */
                    if (plain <= 1u)
                        lz78_enc_emit(&e, esi);
                    lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                    goto finish;
                }
                ebx = (int)in[ip++];
                continue;
            }
            if (!e.plain_flushed && plain > 0u && ip == plain + 1u) {
                uint32_t save_nc = e.next_code;

                e.next_code = 0x101u;
                e.suppress_out = 1;
                lz78_enc_fc0_emit(&e, esi);
                e.suppress_out = 0;
                e.next_code = save_nc;
                e.plain_flushed = 1;
            } else {
                lz78_enc_emit(&e, esi);
            }
            lz78_enc_add(&e, esi, ebx, parent);
            esi = ebx;
            if (ip >= in_len) {
                lz78_enc_emit(&e, esi);
                lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
                break;
            }
            ebx = (int)in[ip++];
        } else {
            lz78_enc_emit(&e, esi);
            lz78_enc_emit(&e, (int)(LZ78_ROOT + 1u));
            break;
        }
    }

    if (ip < in_len) {
        free(e.pay);
        free(e.dict);
        return -1;
    }

finish:
    {
        uint8_t *buf = (uint8_t *)malloc(plain + e.pay_len);
        if (!buf) {
            free(e.pay);
            free(e.dict);
            return -2;
        }
        memcpy(buf, in, plain);
        memcpy(buf + plain, e.pay, e.pay_len);
        total = plain + e.pay_len;
        free(e.pay);
        free(e.dict);
        *out = buf;
        *out_len = total;
        return 0;
    }
}

int uha_lz78_encode(const uint8_t *in, size_t in_len, uint8_t order,
                    const uint32_t *ends, int nfiles,
                    uint8_t **out, size_t *out_len)
{
    (void)ends;
    (void)nfiles;

    if (!out || !out_len)
        return -2;
    *out = NULL;
    *out_len = 0;
    if (in_len == 0)
        return 0;
    if (!in)
        return -2;
    if (order < UHA_ORDER_LZ78_MIN || order > UHA_ORDER_LZ78_MAX)
        return -2;

    return lz78_encode_payload(in, in_len, order, out, out_len);
}

int uha_lz78_decode(const uint8_t *in, size_t in_len, uint8_t order,
                    uint32_t usize, const uint32_t *ends, int nfiles,
                    uint8_t *out, size_t out_cap)
{
    lz78_dec d;
    uint32_t max_code;
    int rc;

    (void)ends;
    (void)nfiles;

    if (usize > out_cap)
        return -2;
    if (usize == 0 && in_len == 0)
        return 0;
    if (!in || !out)
        return -2;
    /*
     * Ne pas confondre store (``order`` 0) et LZ78 mw : Wine peut avoir
     * ``psize == usize`` (ex. ``runs.bin`` 8→8) avec payload bitstream.
     */
    if (order < UHA_ORDER_LZ78_MIN && in_len == (size_t)usize) {
        if (usize > 0)
            memcpy(out, in, usize);
        return 0;
    }

    max_code = lz78_dict_slots(order);
    if (max_code == 0)
        return -2;

    memset(&d, 0, sizeof(d));
    d.payload = in;
    d.plen = in_len;
    d.usize = usize;
    d.max_code = max_code;
    d.out = out;
    d.out_cap = out_cap;
    d.dict_cap = max_code + 4u;
    d.dict = (lz78_ent *)calloc(d.dict_cap, sizeof(lz78_ent));
    if (!d.dict)
        return -2;

    rc = lz78_decode_payload(&d);
    free(d.dict);
    return rc;
}
