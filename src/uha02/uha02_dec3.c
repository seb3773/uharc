/* UHARC 0.2 decompressor core 3 (methods 8..43, PPM/LZ + range coder).
 * Portable C89 port of the DOS32 decoder in Uharc02.lst / Uharc02.c.
 * All former DGROUP state lives in one malloc'd context; no globals.
 *
 * Method mapping: group 1 = 8..19, group 2 = 20..31, group 3 = 32..43.
 * Dict size = 1 << (((m - 8) % 12) + 10).
 *
 * Original -> port (cseg01 addresses in Uharc02.lst):
 *   sub_18AC8 (init)          d3_init
 *   sub_1BE94 (main loop)     uharc_dec3t_decode
 *   sub_1C600 (token)         d3_token
 *   sub_1C870 (literal)       d3_literal
 *   sub_1C938 (LZ match)      d3_match
 *   sub_1CA90 (byte run)      d3_run
 *   sub_1C6C0 (control)       d3_control
 *   sub_1BEFC/1BF6C           d3_rupd / d3_rget
 *   sub_19A38 (bit in)        d3_bit
 *   sub_1B5D0 (emit literal)  d3_put_orig
 *   sub_1B66C (emit copy)     d3_put_trans
 *   sub_1B8D4 (model update)  d3_model_update
 *   sub_1B7B8 (model rebuild) d3_model_rebuild
 *   sub_1B710 (halve ctx)     d3_model_halve
 *   sub_1C2CC/1C470           d3_dec_tree / d3_dec_tree2
 *   sub_1BF8C (length)        d3_dec_len
 *   sub_1BA30/1BAC4/1BC24/1BCC0  length/distance model updates
 *   sub_1BD60/1BDEC           state/length class updates
 *   sub_19C90 (fill run)      d3_fill_out
 *
 * Return codes follow uharc_dec.h: 0 ok, 1 bad args, 2 nomem, 3 input
 * short, 4 output short, 7 data error.
 *
 * Initial context model: a fresh context block is the Fenwick tree of a
 * uniform 256-symbol distribution (tree[0] = 256, tree[k] = lowbit(k)).
 * sub_18AC8 really does build it that way: it tiles the 512-byte template
 * at dseg02:3A6BC over all 256 contexts and that template is exactly the
 * uniform Fenwick tree (0x100,1,2,1,4,1,2,1,8,...).  Same build on reset.
 *
 * Fixed for larger archives (verified against real 0.2 oracles):
 *  - byte_3ADF8 (d3_df8) is a 256-byte symbol table, not 16 entries:
 *    sub_1B8D4 does `mov ah, ds:byte_3ADF8[sym]` with the full symbol.
 *    The old 16-entry table read past its end for sym >= 16, so every
 *    non-zero mode (multimedia "delta" predictor context) used a wrong
 *    literal context.
 *  - sub_1BAC4's smallm rescale halves (m2-m1) and (m3-m2) around the
 *    fixed base m1 (=0), flooring each gap at 0x400 and updating m2 too
 *    (the old code used m1-m0 and m3-m1 and only rewrote m1/m3).
 *
 * Verified: 02_M1 (method 9), 02_M2 (21), 02_M3 (33) decode the
 * 1243-byte solid file stream byte-exactly (same bytes as the STORE
 * vector, CRCs 9166788F/3CD931D7/5FC97467); uha02.UHA (method 25)
 * extracts all 7 files with tab0 CRCs matching.
 * Larger oracles (V_MMOFF.UHA method 31, 2048K dict, 1462013 bytes /
 * 10 files; UHA02EXE.UHA method 28, one 198723-byte exe) now decode
 * byte-exactly after the 0.2 E8/E9 filter pass (uha02.c), incl.
 * UHARC02.EXE CRC FB1BE745; UH02MMP.UHA (mm+) verifies 9/9 too.
 */
#include <stdlib.h>
#include <string.h>

#include "uharc_dec.h"


/* ------------------------------------------------------------------ */
/* static tables extracted from dseg02 (Uharc02.lst)                   */
/* ------------------------------------------------------------------ */

static const unsigned short d3_ctl_init[13] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B,
    0x000C
};

static const unsigned short d3_state_init[5] = { 0x0000, 0x0001, 0x0002, 0x0C00, 0x2000 };

static const unsigned short d3_len_init[23] = {
    0x0000, 0x0010, 0x0018, 0x0028, 0x0038, 0x0058, 0x007C, 0x00CC, 0x0130, 0x018C, 0x0244, 0x02EF,
    0x0401, 0x04C9, 0x05CD, 0x071F, 0x08E1, 0x0B39, 0x0E59, 0x1241, 0x17B9, 0x2119, 0x2710
};

static const unsigned short d3_dmodel_init[45] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0200, 0x0400, 0x0600, 0x0800, 0x0A00, 0x0C00, 0x0E00, 0x1000
};

static const unsigned short d3_lenclass_init[4] = {
    0x0000, 0x0780, 0x0C80, 0x0F00
};

static const unsigned short d3_small_init[4] = { 0x1000, 0x0000, 0x1194, 0x238C };

static const unsigned short d3_d2_init[14] = {
    0x0000, 0x0190, 0x0352, 0x0546, 0x076C, 0x09C4, 0x0C4E, 0x0F0A, 0x11F8, 0x1518, 0x186A, 0x1BEE,
    0x1FA4, 0x238C
};

static const unsigned char d3_lenbase[22] = {
    0xFF, 0xBF, 0x7F, 0x5F, 0x3F, 0x2F, 0x1F, 0x17, 0x13, 0x0F, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02
};

static const unsigned char d3_lenbits[22] = {
    0x00, 0x40, 0x40, 0x20, 0x20, 0x10, 0x10, 0x08, 0x04, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const unsigned char d3_de8[16] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00
};

/* byte_3ADF8: symbol -> nibble class, indexed by the FULL symbol
 * (sub_1B8D4 uses ds:byte_3ADF8[sym], sym = 0..255), 256 entries. */
static const unsigned char d3_df8[256] = {
    0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0E, 0x0F, 0x0F
};

static const unsigned char d3_ef8[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x08, 0x08, 0x09, 0x09, 0x0A, 0x0A, 0x0A,
    0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x15, 0x15, 0x15, 0x15,
    0x15, 0x16, 0x16, 0x16, 0x17, 0x17, 0x18, 0x18, 0x19, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static const unsigned char d3_excl[16] = {
    0x00, 0x00, 0x01, 0x02, 0x02, 0x00, 0x00, 0x01, 0x04, 0x02, 0x00, 0x00, 0x06, 0x04, 0x02, 0x00
};

static const unsigned char d3_db[4] = {
    0x00, 0x05, 0x08, 0x10
};

static const unsigned long d3_distbase[44] = {
    0x001E0000UL, 0x001C0000UL, 0x001A0000UL, 0x00180000UL, 0x00160000UL, 0x00140000UL,
    0x00120000UL, 0x00100000UL, 0x000E0000UL, 0x000C0000UL, 0x000A0000UL, 0x00080000UL,
    0x00060000UL, 0x00040000UL, 0x00030000UL, 0x00020000UL, 0x00018000UL, 0x00010000UL,
    0x0000C000UL, 0x00008000UL, 0x00006000UL, 0x00004000UL, 0x00003000UL, 0x00002000UL,
    0x00001800UL, 0x00001000UL, 0x00000C00UL, 0x00000800UL, 0x00000600UL, 0x00000400UL,
    0x00000300UL, 0x00000200UL, 0x00000100UL, 0x00000080UL, 0x00000040UL, 0x00000020UL,
    0x00000010UL, 0x00000008UL, 0x00000004UL, 0x00000002UL, 0x00000001UL, 0x00000003UL,
    0x00000001UL, 0x00000000UL
};

static const unsigned long d3_distspan[40] = {
    0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL,
    0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL, 0x00020000UL,
    0x00020000UL, 0x00020000UL, 0x00010000UL, 0x00010000UL, 0x00008000UL, 0x00008000UL,
    0x00004000UL, 0x00004000UL, 0x00002000UL, 0x00002000UL, 0x00001000UL, 0x00001000UL,
    0x00000800UL, 0x00000800UL, 0x00000400UL, 0x00000400UL, 0x00000200UL, 0x00000200UL,
    0x00000100UL, 0x00000100UL, 0x00000100UL, 0x00000080UL, 0x00000040UL, 0x00000020UL,
    0x00000010UL, 0x00000008UL, 0x00000004UL, 0x00000002UL
};

static const unsigned long d3_fillthr[37] = {
    0xFFFFFFFFUL, 0x001E0000UL, 0x001C0000UL, 0x001A0000UL, 0x00180000UL, 0x00160000UL,
    0x00140000UL, 0x00120000UL, 0x00100000UL, 0x000E0000UL, 0x000C0000UL, 0x000A0000UL,
    0x00080000UL, 0x00060000UL, 0x00040000UL, 0x00030000UL, 0x00020000UL, 0x00018000UL,
    0x00010000UL, 0x0000C000UL, 0x00008000UL, 0x00006000UL, 0x00004000UL, 0x00003000UL,
    0x00002000UL, 0x00001800UL, 0x00001000UL, 0x00000C00UL, 0x00000800UL, 0x00000600UL,
    0x00000400UL, 0x00000300UL, 0x00000200UL, 0x00000100UL, 0x00000080UL, 0x00000040UL,
    0x00000020UL
};


/* ------------------------------------------------------------------ */
/* performance notes                                                   */
/* ------------------------------------------------------------------ */
/*
 * This is a speed-oriented rewrite of the original port. The decoded
 * output is bit-identical to the reference implementation (same coder
 * arithmetic, same model updates, same control flow and error points):
 *
 *  - The input is read straight from memory through a 64-bit bit buffer;
 *    range-coder renormalisation shifts in all needed bits at once
 *    instead of one bit per loop iteration (exact bit-serial fallback near
 *    the end of the input, so the EOF error point is unchanged).
 *  - All coder arithmetic is done in 32-bit unsigned integers (the
 *    original masks every intermediate value to 32 bits), so divisions are
 *    32-bit instead of 64-bit.
 *  - The per-context Fenwick tree is replaced by a two-level structure
 *    (16 group suffix sums + 256 frequencies) that is decoded and updated
 *    branch-free with SSE2 (portable C fallback with identical results).
 *    See d3m below for why this is exact.
 *  - The output is written directly into the caller's buffer.
 *  - Runs update the model in batches (closed form up to each rescale) when
 *    the literal context cannot change during the run.
 */
#include <stdint.h>
#if defined(__SSE2__)
#include <emmintrin.h>
#endif

#if defined(__GNUC__)
#define D3_INL static inline __attribute__((always_inline))
#define D3_COLD static __attribute__((noinline, cold))
#define D3_LIKELY(x) __builtin_expect(!!(x), 1)
#define D3_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define D3_INL static
#define D3_COLD static
#define D3_LIKELY(x) (x)
#define D3_UNLIKELY(x) (x)
#endif

/* ------------------------------------------------------------------ */
/* literal model                                                       */
/* ------------------------------------------------------------------ */
/*
 * The legacy decoder keeps one 256-symbol Fenwick tree per context and
 * reads cumulative bounds top-down: symbol s occupies [R(s+1), R(s)) of
 * the context total, with R(s) = sum of fr[t] for t >= s (R(256) = 0).
 * Every frequency is >= 1 and the total is rescaled as soon as it reaches
 * 0x4000 (so it never exceeds 0x4000 + 127), hence all the 16-bit values
 * of the original are exact integers and any structure that yields the
 * same R(s) gives the same coder bounds and the same symbol.
 *
 * Layout per context: gs[g] = R(16 g) for g = 0..15 (gs[0] = total) and the
 * 256 frequencies. R is strictly decreasing, so the symbol of a target v
 * is  #{ s in [1, 255] : v < R(s) }, found with one 16-lane comparison on
 * gs (group) and one on the in-group prefix sums.
 */
typedef struct {
    uint16_t gs[16];
    uint16_t fr[256];
} d3m;

#if defined(__GNUC__)
#define D3_CTZ(x) ((unsigned)__builtin_ctz(x))
#define D3_CLZ(x) ((unsigned)__builtin_clz(x))
#else
static unsigned D3_CTZ(unsigned x) { unsigned n = 0; while (!(x & 1u)) { x >>= 1; n++; } return n; }
static unsigned D3_CLZ(unsigned x) { unsigned n = 0; while (!(x & 0x80000000u)) { x <<= 1; n++; } return n; }
#endif

static void d3m_init(d3m *m)
{
    unsigned i;
    for (i = 0; i < 256; i++) m->fr[i] = 1;
    for (i = 0; i < 16; i++) m->gs[i] = (uint16_t)(256 - 16 * i);
}

static void d3m_sums(d3m *m)
{
    unsigned g, i, s = 0;
    for (g = 16; g-- > 0;) {
        for (i = 0; i < 16; i++) s += m->fr[16 * g + i];
        m->gs[g] = (uint16_t)s;
    }
}

/* fr[i] = (fr[i] + 1) >> 1, `times` times, then rebuild the sums
 * (sub_1B710 / sub_1B7B8: dword trick ((d + 0x10001) & 0xFFFEFFFE) >> 1). */
static void d3m_halve(d3m *m, unsigned times)
{
#if defined(__SSE2__)
    const __m128i z = _mm_setzero_si128();
    unsigned i, t;
    for (i = 0; i < 256; i += 8) {
        __m128i x = _mm_loadu_si128((const __m128i *)(m->fr + i));
        for (t = 0; t < times; t++) x = _mm_avg_epu16(x, z);
        _mm_storeu_si128((__m128i *)(m->fr + i), x);
    }
#else
    unsigned i, t;
    for (t = 0; t < times; t++)
        for (i = 0; i < 256; i++) m->fr[i] = (uint16_t)((m->fr[i] + 1u) >> 1);
#endif
    d3m_sums(m);
}

/* Decode the symbol of target v (symbols >= 16 * gmin only; gmin = 0 for
 * sub_1C2CC, 8 for sub_1C470). Returns the symbol, *hi = R(sym),
 * *lo = R(sym + 1). */
D3_INL unsigned d3m_decode(const d3m *m, uint32_t v, unsigned gmin,
                           uint32_t *lo, uint32_t *hi)
{
    unsigned g, j, sym;
    uint32_t gv, t, rh;
#if defined(__SSE2__)
    uint16_t pre[17];
    __m128i vv = _mm_set1_epi16((short)(v < 0x7FFFu ? v : 0x7FFFu));
    __m128i g0 = _mm_loadu_si128((const __m128i *)m->gs);
    __m128i g1 = _mm_loadu_si128((const __m128i *)(m->gs + 8));
    unsigned msk = (unsigned)_mm_movemask_epi8(
        _mm_packs_epi16(_mm_cmpgt_epi16(g0, vv), _mm_cmpgt_epi16(g1, vv)));
    __m128i a, b, tt;
    g = D3_CTZ(~msk);                  /* lanes with gs > v form a prefix */
    g = (g > gmin + 1) ? g - 1 : gmin;
    gv = m->gs[g];
    t = (gv > v) ? gv - v : 0;
    a = _mm_loadu_si128((const __m128i *)(m->fr + 16 * g));
    b = _mm_loadu_si128((const __m128i *)(m->fr + 16 * g + 8));
    a = _mm_add_epi16(a, _mm_slli_si128(a, 2));
    b = _mm_add_epi16(b, _mm_slli_si128(b, 2));
    a = _mm_add_epi16(a, _mm_slli_si128(a, 4));
    b = _mm_add_epi16(b, _mm_slli_si128(b, 4));
    a = _mm_add_epi16(a, _mm_slli_si128(a, 8));
    b = _mm_add_epi16(b, _mm_slli_si128(b, 8));
    b = _mm_add_epi16(b, _mm_unpackhi_epi64(_mm_shufflehi_epi16(a, 0xFF),
                                            _mm_shufflehi_epi16(a, 0xFF)));
    tt = _mm_set1_epi16((short)t);
    msk = (unsigned)_mm_movemask_epi8(
        _mm_packs_epi16(_mm_cmplt_epi16(a, tt), _mm_cmplt_epi16(b, tt)));
    j = D3_CTZ(~msk);
    pre[0] = 0;
    _mm_storeu_si128((__m128i *)(pre + 1), a);
    _mm_storeu_si128((__m128i *)(pre + 9), b);
    sym = 16 * g + j;
    rh = gv - pre[j];
#else
    uint32_t p;
    for (g = 15; g > gmin && !(v < m->gs[g]); g--) ;
    gv = m->gs[g];
    t = (gv > v) ? gv - v : 0;
    p = 0;
    for (j = 0; j < 15; j++) {
        uint32_t np = p + m->fr[16 * g + j];
        if (!(np < t)) break;
        p = np;
    }
    sym = 16 * g + j;
    rh = gv - p;
#endif
    *hi = rh;
    *lo = rh - m->fr[sym];
    return sym;
}

D3_INL void d3m_add(d3m *m, unsigned sym, unsigned inc)
{
#if defined(__SSE2__)
    const __m128i idx0 = _mm_setr_epi16(0, 1, 2, 3, 4, 5, 6, 7);
    const __m128i idx1 = _mm_setr_epi16(8, 9, 10, 11, 12, 13, 14, 15);
    __m128i gg = _mm_set1_epi16((short)((sym >> 4) + 1));
    __m128i iv = _mm_set1_epi16((short)inc);
    __m128i g0 = _mm_loadu_si128((const __m128i *)m->gs);
    __m128i g1 = _mm_loadu_si128((const __m128i *)(m->gs + 8));
    g0 = _mm_add_epi16(g0, _mm_and_si128(_mm_cmplt_epi16(idx0, gg), iv));
    g1 = _mm_add_epi16(g1, _mm_and_si128(_mm_cmplt_epi16(idx1, gg), iv));
    _mm_storeu_si128((__m128i *)m->gs, g0);
    _mm_storeu_si128((__m128i *)(m->gs + 8), g1);
#else
    unsigned g;
    for (g = 0; g <= (sym >> 4); g++) m->gs[g] = (uint16_t)(m->gs[g] + inc);
#endif
    m->fr[sym] = (uint16_t)(m->fr[sym] + inc);
}

/* ------------------------------------------------------------------ */
/* context                                                             */
/* ------------------------------------------------------------------ */
typedef struct d3ctx_s {
    /* bit reader: next bit is bit 63 of bb, bc valid bits */
    const uint8_t *ip;
    const uint8_t *iend;
    uint64_t bb;
    unsigned bc;

    /* output (bytes past out_expect are counted but not stored) */
    uint8_t *out;
    size_t out_total;
    size_t out_expect;

    int err;                    /* 0, 3 input short, 4 output, 7 data */

    /* range coder */
    uint32_t code, range;
    uint32_t rtotal, rlow, rhigh;

    /* model */
    d3m *mdl;                   /* 256 contexts */
    uint64_t *rtab;             /* lazily filled reciprocals, index < 0x8000 */
    uint16_t state[8][5];       /* word_3C3A0 */
    uint16_t lenA[23];          /* unk_3C59A */
    uint16_t lenB[23];          /* unk_3C56C */
    uint16_t dmodel[45];        /* word_3C50C, total at 44 */
    uint16_t smallm[4];         /* 3C564..3C56A */
    uint16_t d2[14];            /* word_3C45C, total at byte_3C5ED */
    uint16_t lenclass[4];       /* word_3C3F0 */

    uint32_t distlist[16];      /* dword_3AD8C */
    uint8_t *dict;              /* dword_3A580, dict_size + 256 */
    uint32_t dict_size;         /* dword_3C498 */
    uint32_t dict_wrap;         /* dword_3C48C = dict_size - 255 */
    uint32_t dict_mask;         /* dword_3C4A0 = dict_size - 1 */
    uint32_t ring_pos;          /* dword_3C490 */
    uint32_t ring_fill;         /* dword_3C49C */

    uint32_t hash;              /* dword_3C44C */
    uint32_t counter;           /* dword_3C478 */
    uint32_t match_pos;         /* dword_3C4A4 */
    uint32_t list_max;          /* byte_3C5EB (5/8/16) */
    uint32_t class_max;         /* byte_3C5ED (2/5/13) */
    unsigned char group;

    unsigned char state_idx;    /* byte_3C5EA */
    unsigned char prev_ctx;     /* byte_3C5EF */
    unsigned char last_out;     /* byte_3C5E1 */
    unsigned char last_sym;     /* byte_3C5EC */
    unsigned char mode;         /* byte_3C5E6 */
    unsigned char db;           /* byte_3C5DB */
    unsigned char order;        /* byte_3C5DC */
    unsigned char prev_order;   /* byte_3C5DF */
    unsigned char flag7;        /* byte_3C5E7 */
    unsigned char raw_lit;      /* byte_3C5E3 */
    unsigned char exc_lit;      /* byte_3C5E5 */
    unsigned char len_sel;      /* byte_3C5FA */
    unsigned char len_val;      /* byte_3C5FB */
    unsigned char fill_idx;     /* byte_3AB70 */
} d3ctx;

/* ------------------------------------------------------------------ */
/* bit input (sub_19A38)                                               */
/* ------------------------------------------------------------------ */
D3_INL uint64_t d3_bswap64(uint64_t x)
{
#if defined(__GNUC__)
    return __builtin_bswap64(x);
#else
    x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
#endif
}

D3_INL void d3_refill(d3ctx *c)
{
    if (D3_LIKELY(c->iend - c->ip >= 8)) {
        uint64_t w;
        memcpy(&w, c->ip, 8);
        c->bb |= d3_bswap64(w) >> c->bc;
        c->ip += (63u - c->bc) >> 3;
        c->bc |= 56u;
    } else {
        while (c->bc <= 56u && c->ip < c->iend) {
            c->bb |= (uint64_t)*c->ip++ << (56u - c->bc);
            c->bc += 8u;
        }
    }
}

/* one bit, exact EOF behaviour of the original (err 3, bit 0) */
static int d3_bit(d3ctx *c)
{
    int b;
    if (c->bc == 0) {
        d3_refill(c);
        if (c->bc == 0) { c->err = 3; return 0; }
    }
    b = (int)(c->bb >> 63);
    c->bb <<= 1;
    c->bc--;
    return b;
}

/* ------------------------------------------------------------------ */
/* range coder (sub_1BF6C / sub_1BEFC)                                 */
/* ------------------------------------------------------------------ */
D3_INL uint32_t d3_rget(d3ctx *c, uint32_t total)
{
    uint32_t num;
    if (D3_UNLIKELY(total == 0 || c->range == 0)) { c->err = 7; return 0; }
    num = (c->code + 1u) * total - 1u;
    return num / c->range;
}

D3_COLD void d3_norm_slow(d3ctx *c, uint32_t span)
{
    while (span <= 0x8000u) {
        int b = d3_bit(c);
        span <<= 1;
        c->code = (c->code << 1) + (uint32_t)b;
        if (c->err) return;
    }
    c->range = span;
}

/* Exact 32-bit division by a reciprocal: for 1 < d < 2^32 and
 * M = ceil(2^64 / d), floor(n / d) = (n * M) >> 64 for every 32-bit n
 * (Lemire, Kaser, Kurz, "Faster remainder by direct computation", 2019).
 * The reciprocal of the model total is computed before the symbol is
 * decoded, in parallel with the target division, which takes the two
 * divisions of the bound update off the critical path. */
#if defined(__SIZEOF_INT128__)
#define D3_RECIP 1
D3_INL uint64_t d3_recip(uint32_t d)
{
    return d > 1u ? (~(uint64_t)0) / d + 1u : 0u;
}
/* Reciprocal through a per-decoder cache: totals are below 0x8000 on
 * valid streams; the cache avoids a 64-bit division per symbol, which is
 * slow (and poorly pipelined) on older x86 cores. 0 = not computed yet
 * (also the value for d <= 1, which d3_divr handles separately). */
D3_INL uint64_t d3_recip_c(uint64_t *tab, uint32_t d)
{
    uint64_t m;
    if (D3_UNLIKELY(d >= 0x8000u)) return d3_recip(d);
    m = tab[d];
    if (D3_UNLIKELY(m == 0)) tab[d] = m = d3_recip(d);
    return m;
}
D3_INL uint32_t d3_divr(uint32_t n, uint32_t d, uint64_t m)
{
    return d > 1u ? (uint32_t)(((unsigned __int128)n * m) >> 64) : n / d;
}
#else
#define D3_RECIP 0
D3_INL uint64_t d3_recip(uint32_t d) { (void)d; return 0; }
D3_INL uint64_t d3_recip_c(uint64_t *tab, uint32_t d) { (void)tab; (void)d; return 0; }
D3_INL uint32_t d3_divr(uint32_t n, uint32_t d, uint64_t m) { (void)m; return n / d; }
#endif

D3_INL void d3_rupd3m(d3ctx *c, uint32_t rlow, uint32_t rhigh, uint32_t rtotal, uint64_t rm)
{
    uint32_t r = c->range, lo, hi, span, n;
    if (D3_UNLIKELY(rtotal == 0 || r == 0)) { c->err = 7; return; }
    lo = d3_divr(rlow * r, rtotal, rm);
    c->code -= lo;
    hi = d3_divr(rhigh * r, rtotal, rm);
    span = hi - lo;
    if (span > 0x8000u) { c->range = span; return; }
    if (D3_UNLIKELY(span == 0)) { d3_norm_slow(c, span); return; }
    /* smallest n with (span << n) > 0x8000 */
    n = D3_CLZ(2u * span - 1u) - 15u;
    if (D3_UNLIKELY(c->bc < n)) {
        d3_refill(c);
        if (c->bc < n) { d3_norm_slow(c, span); return; }
    }
    c->code = (c->code << n) | (uint32_t)(c->bb >> (64u - n));
    c->bb <<= n;
    c->bc -= n;
    c->range = span << n;
}

/* cold paths: plain divisions (the divisor is not known in advance) */
D3_INL void d3_rupd3(d3ctx *c, uint32_t rlow, uint32_t rhigh, uint32_t rtotal)
{
    uint32_t r = c->range, lo, hi, span, n;
    if (D3_UNLIKELY(rtotal == 0 || r == 0)) { c->err = 7; return; }
    lo = (rlow * r) / rtotal;
    c->code -= lo;
    hi = (rhigh * r) / rtotal;
    span = hi - lo;
    if (span > 0x8000u) { c->range = span; return; }
    if (D3_UNLIKELY(span == 0)) { d3_norm_slow(c, span); return; }
    n = D3_CLZ(2u * span - 1u) - 15u;
    if (D3_UNLIKELY(c->bc < n)) {
        d3_refill(c);
        if (c->bc < n) { d3_norm_slow(c, span); return; }
    }
    c->code = (c->code << n) | (uint32_t)(c->bb >> (64u - n));
    c->bb <<= n;
    c->bc -= n;
    c->range = span << n;
}

D3_INL void d3_rupd(d3ctx *c)
{
    d3_rupd3(c, c->rlow, c->rhigh, c->rtotal);
}

/* ------------------------------------------------------------------ */
/* model update (sub_1B8D4)                                            */
/* ------------------------------------------------------------------ */
static const unsigned short d3_inc_tab[4] = { 2, 8, 32, 128 };

D3_INL unsigned char d3_next_ctx(const d3ctx *c, unsigned char sym)
{
    switch (c->mode) {
    case 0:
    case 5:
        return sym;
    case 1:
        return (unsigned char)((d3_de8[c->prev_ctx & 15] << 4) + d3_df8[sym]);
    case 3:
        return (unsigned char)(d3_ef8[sym] + ((c->counter % 3u) << 5));
    default:
        return (unsigned char)(((c->counter & c->db) << 4) + d3_df8[sym]);
    }
}

D3_INL void d3_model_update(d3ctx *c, unsigned char sym)
{
    d3m *m = c->mdl + c->prev_ctx;
    d3m_add(m, sym, d3_inc_tab[c->order & 3]);
    if (D3_UNLIKELY(m->gs[0] >= 0x4000)) d3m_halve(m, 1);
    c->prev_ctx = d3_next_ctx(c, sym);
    c->counter++;
}

/* k consecutive updates with the same symbol (byte runs) */
static void d3_model_update_n(d3ctx *c, unsigned char sym, size_t k)
{
    if (k && (c->mode == 0 || c->mode == 5)) {
        /* the context becomes `sym` after the first update and stays */
        unsigned inc = d3_inc_tab[c->order & 3];
        d3_model_update(c, sym);
        k--;
        c->counter += (uint32_t)k;
        while (k) {
            d3m *m = c->mdl + sym;
            uint32_t tot = m->gs[0];
            size_t need = tot >= 0x4000u ? 1u : (0x4000u - tot + inc - 1u) / inc;
            size_t a = need < k ? need : k;
            d3m_add(m, sym, (unsigned)(a * inc));
            if (m->gs[0] >= 0x4000) d3m_halve(m, 1);
            k -= a;
        }
        return;
    }
    while (k--) d3_model_update(c, sym);
}

/* ------------------------------------------------------------------ */
/* output transforms (sub_1B5D0 / sub_1B66C)                           */
/* ------------------------------------------------------------------ */
D3_INL unsigned char d3_hash_byte(const d3ctx *c)
{
    return (unsigned char)(c->hash >> (8u * (c->db & 3u)));
}


/* ------------------------------------------------------------------ */
/* token / length helpers                                              */
/* ------------------------------------------------------------------ */
static void d3_upd_state(d3ctx *c, unsigned v)
{
    uint16_t *m = c->state[c->state_idx];
    if (v == 2) m[3] = (uint16_t)(m[3] + 64);
    m[4] = (uint16_t)(m[4] + 64);
    if (m[4] >= 0x4000) {
        uint32_t f2 = (uint16_t)(m[3] - m[2]);
        uint32_t f3 = (uint16_t)(m[4] - m[3]);
        uint32_t h2 = (f2 + 1) >> 1;
        uint32_t h3 = (f3 + 1) >> 1;
        m[3] = (uint16_t)(m[2] + h2);
        m[4] = (uint16_t)(m[3] + h3);
    }
    c->state_idx = (unsigned char)((v + 2 * c->state_idx - 2) & 7);
}

static void d3_upd_lenclass(d3ctx *c, unsigned v)
{
    uint16_t *m = c->lenclass;
    if (v == 0) m[1] = (uint16_t)(m[1] + 64);
    if (v <= 1) m[2] = (uint16_t)(m[2] + 64);
    m[3] = (uint16_t)(m[3] + 64);
    if (m[3] >= 0x4000) {
        uint32_t f0 = (uint32_t)(m[1] - m[0]);
        uint32_t f1 = (uint32_t)(m[2] - m[1]);
        uint32_t f2 = (uint32_t)(m[3] - m[2]);
        uint32_t h0 = (f0 + 1) >> 1;
        uint32_t h1 = (f1 + 1) >> 1;
        uint32_t h2 = (f2 + 1) >> 1;
        m[1] = (uint16_t)(m[0] + h0);
        m[2] = (uint16_t)(m[1] + h1);
        m[3] = (uint16_t)(m[2] + h2);
    }
}

/* generic cumulative model rescale: sub_1BC24 / sub_1BCC0 / sub_1BA30 */
static void d3_rescale_cum(uint16_t *m, unsigned last)
{
    unsigned d, a;
    for (d = last; d >= 1; d--) {
        uint32_t diff = (uint16_t)(m[d] - m[d - 1]);
        m[d] = (uint16_t)((diff + 1) >> 1);
    }
    for (a = 2; a <= last; a++)
        m[a] = (uint16_t)(m[a] + m[a - 1]);
}

static void d3_upd_dmodel(d3ctx *c, unsigned v) /* sub_1BC24 */
{
    unsigned a;
    for (a = v + 1; a < 44; a++)
        c->dmodel[a] = (uint16_t)(c->dmodel[a] + 0x20);
    c->dmodel[44] = (uint16_t)(c->dmodel[44] + 0x20);
    if (c->dmodel[44] >= 0x4000) d3_rescale_cum(c->dmodel, 44);
}

static void d3_fill_step(d3ctx *c, unsigned idx) /* sub_1BCC0 */
{
    unsigned inc = (unsigned)(c->dmodel[idx + 1] + 1) >> 1;
    unsigned a;
    for (a = idx; a < 45; a++)
        c->dmodel[a] = (uint16_t)(c->dmodel[a] + inc);
    d3_rescale_cum(c->dmodel, 44);
}

static void d3_upd_lenmodel(d3ctx *c, unsigned v) /* sub_1BA30 */
{
    uint16_t *m = c->len_sel ? c->lenB : c->lenA;
    unsigned last = c->len_sel ? 22 : 21;
    unsigned a;
    for (a = v + 1; a < last; a++)
        m[a] = (uint16_t)(m[a] + 0x40);
    m[last] = (uint16_t)(m[last] + 0x40);
    if (m[last] >= 0x4000) d3_rescale_cum(m, last);
}

static void d3_upd_distlist(d3ctx *c, unsigned v) /* sub_1BAC4 */
{
    unsigned char cmax = (unsigned char)c->class_max;
    if (v < 3) {
        if (v == 2) c->smallm[2] = (uint16_t)(c->smallm[2] + 0x20);
        c->smallm[3] = (uint16_t)(c->smallm[3] + 0x20);
        if (c->smallm[3] >= 0x4000) {
            /* smallm[1] (0) is the fixed base; the gaps (m2-m1) and
             * (m3-m2) are halved, each floored at 0x400. */
            uint32_t h2 = ((uint32_t)(uint16_t)(c->smallm[2] - c->smallm[1]) + 1) >> 1;
            uint32_t h3 = ((uint32_t)(uint16_t)(c->smallm[3] - c->smallm[2]) + 1) >> 1;
            if (h2 < 0x400) h2 = 0x400;
            if (h3 < 0x400) h3 = 0x400;
            c->smallm[2] = (uint16_t)(c->smallm[1] + h2);
            c->smallm[3] = (uint16_t)(c->smallm[2] + h3);
        }
    } else {
        unsigned a = (unsigned)c->list_max - 1 - v;
        for (;;) {
            a++;
            if (a >= cmax) break;
            c->d2[a] = (uint16_t)(c->d2[a] + 0x20);
        }
        c->d2[cmax] = (uint16_t)(c->d2[cmax] + 0x20);
        if (c->d2[cmax] >= 0x4000) {
            unsigned d, x;
            for (d = cmax; d >= 1; d--) {
                uint32_t diff = (uint16_t)(c->d2[d] - c->d2[d - 1]);
                uint32_t h = (diff + 1) >> 1;
                if (h < 0x100) h = 0x100;
                c->d2[d] = (uint16_t)h;
            }
            for (x = 2; x <= cmax; x++)
                c->d2[x] = (uint16_t)(c->d2[x] + c->d2[x - 1]);
        }
    }
    c->class_max = cmax;
}

/* sub_1BF8C: decode a match length, returns the length class symbol */
static unsigned d3_dec_len(d3ctx *c)
{
    uint16_t *m = c->len_sel ? c->lenB : c->lenA;
    unsigned start = c->len_sel ? 22 : 21;
    uint32_t v;
    unsigned d = start;
    unsigned bits, extra = 0;

    c->rtotal = m[start];
    v = d3_rget(c, c->rtotal);
    do {
        d--;
    } while (v < (uint32_t)m[d] && d);
    c->rlow = m[d];
    c->rhigh = m[d + 1];
    d3_rupd(c);

    bits = d3_lenbits[d];
    if (bits) {
        c->rtotal = bits;
        extra = (unsigned)d3_rget(c, bits);
        c->rlow = extra & 0xFF;
        c->rhigh = (extra + 1) & 0xFFFF;
        d3_rupd(c);
    }
    c->len_val = (unsigned char)(d3_lenbase[d] + (extra & 0xFF));
    return d;
}

/* sub_1C054: decode distance class / repeat index */
static unsigned d3_dec_dist(d3ctx *c)
{
    uint32_t v;
    unsigned d, ebx, ex, low, high;
    uint16_t *m = c->dmodel;

    c->rtotal = m[44];
    v = d3_rget(c, c->rtotal);
    d = 44;
    do {
        d--;
    } while (v < (uint32_t)m[d] && d);
    c->rlow = m[d];
    c->rhigh = m[d + 1];
    d3_rupd(c);
    c->match_pos = (uint32_t)d3_distbase[d];

    if (d == 40) {
        c->len_sel = 0;
        return d;
    }
    if (d == 41) {
        uint16_t *m2 = c->d2;
        ebx = c->class_max;
        ex = ebx * 2;
        c->rtotal = m2[ebx];
        v = d3_rget(c, c->rtotal);
        do {
            high = m2[ebx - 1];
            ex -= 2;
            ebx--;
            if (v >= (uint32_t)high) break;
        } while (ebx);
        c->rlow = m2[ebx];
        c->rhigh = m2[ebx + 1];
        d3_rupd(c);
        c->match_pos += (uint32_t)(c->class_max - 1 - ebx);
        c->len_sel = 1;
        return d;
    }
    if (d == 42) {
        uint16_t *sm = c->smallm;
        ebx = 2;
        c->rtotal = sm[3];
        v = d3_rget(c, c->rtotal);
        do {
            high = sm[ebx];
            ebx--;
            if (v >= (uint32_t)high) break;
        } while (ebx);
        c->rlow = sm[ebx + 1];
        c->rhigh = sm[ebx + 2];
        d3_rupd(c);
        c->match_pos += (uint32_t)(1 - ebx);
        c->len_sel = 1;
        return d;
    }
    if (d == 43) {
        c->len_sel = 1;
        return d;
    }

    /* d <= 39: refine distance inside its class */
    ebx = (unsigned)d3_distspan[d];
    ex = (unsigned)(c->match_pos + ebx - 1);
    if (ex > c->ring_fill) ebx = (unsigned)(c->ring_fill - c->match_pos + 1);
    if (ebx >= 2) {
        if (ebx > 0x1000) {
            uint32_t q;
            c->rtotal = ((ebx - 1) >> 12) + 1;
            q = d3_rget(c, c->rtotal) & 0xFFFF;
            c->rlow = q;
            c->rhigh = q + 1;
            d3_rupd(c);
            c->match_pos = c->match_pos + (q << 12);
            if (c->rhigh == c->rtotal) {
                ebx -= (unsigned)(q << 12);
            } else {
                ebx = 0x1000;
            }
        }
        if (ebx >= 2) {
            c->rtotal = ebx;
            low = (unsigned)d3_rget(c, ebx) & 0xFFFF;
            c->rlow = low;
            c->rhigh = low + 1;
            d3_rupd(c);
            c->match_pos = c->match_pos + low;
        }
    }
    c->len_sel = 0;
    return d;
}

/* sub_1C600: decode the per-symbol token (0..3). The target division is
 * kept here on purpose: the token is well predicted, so the branchy search
 * lets the bound update start before the division completes (a
 * branch-free division-free variant measured slower). */
D3_INL unsigned d3_token(d3ctx *c)
{
    uint16_t *m = c->state[c->state_idx];
    uint32_t v, tot = m[4];
    uint64_t rm = d3_recip_c(c->rtab, tot);
    unsigned d = 4;

    c->rtotal = tot;
    v = d3_rget(c, tot);
    do {
        d--;
        if (v >= (uint32_t)m[d]) break;
    } while (d);
    c->rlow = m[d];
    c->rhigh = m[d + 1];
    d3_rupd3m(c, m[d], m[d + 1], tot, rm);
    if (d <= 1) return d;
    d3_upd_state(c, d);
    return d;
}

/* ------------------------------------------------------------------ */
/* token handlers                                                      */
/* ------------------------------------------------------------------ */
static void d3_reset_models(d3ctx *c)
{
    unsigned i;
    for (i = 0; i < 256; i++) d3m_init(c->mdl + i);
}

/* sub_1C6C0 */
static void d3_control(d3ctx *c)
{
    uint32_t v;
    unsigned d = 12;
    int v15 = 0, v14 = 0;

    c->rtotal = 12;
    v = d3_rget(c, 12);
    do {
        d--;
    } while (v < (uint32_t)d3_ctl_init[d] && d);
    c->rlow = d3_ctl_init[d];
    c->rhigh = d3_ctl_init[d + 1];
    d3_rupd(c);
    if (d > 11) { c->err = 7; return; }

    if (d <= 5) v15 = 1;
    else if (d <= 9) v14 = 1;
    else if (d == 10) c->raw_lit = (unsigned char)!c->raw_lit;
    else if (d == 11) c->exc_lit = (unsigned char)!c->exc_lit;

    if (v15) {
        c->mode = (unsigned char)d;
        c->db = (unsigned char)((d - 1) & 3);
        if (c->out_total) d3_reset_models(c);
    }
    if (v14) {
        unsigned shift;
        c->prev_order = c->order;
        c->order = (unsigned char)(d - 6);
        if (c->out_total && !v15) {
            shift = d3_excl[4 * c->prev_order + c->order];
            if (shift) {
                unsigned i;
                for (i = 0; i < 256; i++)
                    d3m_halve(c->mdl + i, shift);
            }
        }
    }
}

/* sub_1C870 */
D3_INL void d3_literal(d3ctx *c)
{
    unsigned sym;
    unsigned char d;
    if (c->raw_lit) {
        c->rtotal = 256;
        sym = (unsigned)d3_rget(c, 256) & 0xFF;
        c->rlow = sym;
        c->rhigh = (sym + 1) & 0xFFFF;
        d3_rupd(c);
    } else {
        const d3m *m = c->mdl + c->prev_ctx;
        uint32_t lo, hi, tot, v;
        uint64_t rm;
        unsigned gmin = c->exc_lit ? 8u : 0u;
        tot = m->gs[gmin];
        rm = d3_recip_c(c->rtab, tot);
        v = d3_rget(c, tot);
        sym = d3m_decode(m, v, gmin, &lo, &hi);
        c->rlow = lo;
        c->rhigh = hi;
        c->rtotal = tot;
        d3_rupd3m(c, lo, hi, tot, rm);
    }
    d3_model_update(c, (unsigned char)sym);
    /* d3_put_orig */
    d = (unsigned char)(~sym);
    if (c->mode) {
        if (!c->flag7) d = (unsigned char)(0 - d);
        if ((unsigned char)(~sym) >= 0x80) c->flag7 = (unsigned char)!c->flag7;
        d = (unsigned char)(d + d3_hash_byte(c));
    }
    c->hash = (c->hash << 8) + d;
    c->last_out = d;
    c->out[c->out_total++] = d;          /* out_total < out_expect here */
    c->dict[c->ring_pos] = d;
    if (c->ring_fill < c->dict_wrap) c->ring_fill++;
    c->ring_pos = (c->ring_pos + 1) & c->dict_mask;
}

/* sub_1C938 */
static void d3_match(d3ctx *c)
{
    unsigned dist_idx, sym, len_sym;
    uint32_t dist, src, pos, mask, hash;
    unsigned bl;
    size_t room;
    uint8_t *dict, *op;

    for (;;) {
        unsigned idx = c->fill_idx;
        if (c->ring_fill >= (uint32_t)d3_fillthr[idx]) {
            c->fill_idx = (unsigned char)(idx - 1);
            d3_fill_step(c, idx);
        } else break;
    }

    sym = d3_dec_dist(c);
    d3_upd_dmodel(c, sym);

    if (c->len_sel) {
        if (c->len_sel != 1) { c->err = 7; return; }
        dist_idx = (unsigned)(c->match_pos & 0xFF);
        if (dist_idx >= 16) { c->err = 7; return; }
        dist = c->distlist[dist_idx];
        if (dist_idx) d3_upd_distlist(c, dist_idx);
        bl = dist_idx;
    } else {
        dist = c->match_pos;
        bl = (unsigned)c->list_max - 1;
    }
    if (bl && dist > 1) {
        unsigned k = bl;
        while (k) {
            c->distlist[k] = c->distlist[k - 1];
            k--;
        }
        c->distlist[0] = dist;
    }

    src = (c->ring_pos - dist) & c->dict_mask;
    len_sym = d3_dec_len(c);
    d3_upd_lenmodel(c, len_sym);
    bl = c->len_val;
    if (bl < 2) { c->err = 7; return; }

    /* Nothing is decoded after a match, so bytes past the end of the
     * output (dropped by the original flush) need not be produced. */
    room = c->out_expect - c->out_total;
    if (bl > room) bl = (unsigned)room;
    {
        uint32_t nf = c->ring_fill + bl;
        c->ring_fill = nf < c->dict_wrap ? nf : (c->ring_fill > c->dict_wrap ? c->ring_fill : c->dict_wrap);
    }
    dict = c->dict;
    mask = c->dict_mask;
    pos = c->ring_pos;
    hash = c->hash;
    op = c->out + c->out_total;
    c->out_total += bl;
    if (c->mode == 0) {
        while (bl--) {
            unsigned char b = dict[src];
            dict[pos] = b;
            pos = (pos + 1) & mask;
            src = (src + 1) & mask;
            hash = (hash << 8) + b;
            *op++ = b;
            d3_model_update(c, (unsigned char)~b);
        }
        c->last_sym = (unsigned char)~op[-1];
    } else {
        unsigned sh = 8u * (c->db & 3u);
        unsigned char f7 = c->flag7, d = 0;
        while (bl--) {
            unsigned char b = dict[src];
            dict[pos] = b;
            pos = (pos + 1) & mask;
            src = (src + 1) & mask;
            d = (unsigned char)(b - (unsigned char)(hash >> sh));
            if (!f7) d = (unsigned char)(0 - d);
            if (d >= 0x80) f7 = (unsigned char)!f7;
            d = (unsigned char)~d;
            hash = (hash << 8) + b;
            *op++ = b;
            c->flag7 = f7;
            d3_model_update(c, d);
        }
        c->last_sym = d;
    }
    c->hash = hash;
    c->ring_pos = pos;
}

/* sub_1CA90 */
static void d3_run(d3ctx *c)
{
    uint32_t v;
    unsigned d = 3;
    size_t len;
    unsigned char b;
    unsigned i;

    c->rtotal = c->lenclass[3];
    v = d3_rget(c, c->lenclass[3]);
    do {
        d--;
    } while (v < (uint32_t)c->lenclass[d] && d);
    c->rlow = c->lenclass[d];
    c->rhigh = c->lenclass[d + 1];
    d3_rupd(c);
    d3_upd_lenclass(c, d);

    len = 0x100u;
    if (d == 2) {
        c->rtotal = 256;
        v = d3_rget(c, 256) & 0xFF;
        c->rlow = v;
        c->rhigh = v + 1;
        d3_rupd(c);
        len += (size_t)(v & 0xFF) << 16;
    }
    if (d == 1 || d == 2) {
        c->rtotal = 256;
        v = d3_rget(c, 256) & 0xFF;
        c->rlow = v;
        c->rhigh = v + 1;
        d3_rupd(c);
        len += (size_t)(v & 0xFF) << 8;
    }
    c->rtotal = 256;
    v = d3_rget(c, 256) & 0xFF;
    c->rlow = v;
    c->rhigh = v + 1;
    d3_rupd(c);
    len += v & 0xFF;

    c->rtotal = 256;
    v = d3_rget(c, 256) & 0xFF;
    c->rlow = v;
    c->rhigh = v + 1;
    d3_rupd(c);
    b = (unsigned char)v;

    /* fill dictionary ring with 255 copies (only used as match source) */
    if (c->ring_pos + 255 < c->dict_size) {
        memset(c->dict + c->ring_pos, b, 255);
        {
            uint32_t nf = c->ring_fill + 255;
            if (nf > c->dict_wrap) nf = c->dict_wrap;
            c->ring_fill = nf;
        }
        c->ring_pos += 255;
    } else {
        for (i = 0; i < 255; i++) {
            c->dict[c->ring_pos] = b;
            if (c->ring_fill < c->dict_wrap) c->ring_fill++;
            c->ring_pos = (c->ring_pos + 1) & c->dict_mask;
        }
    }

    /* five model-emitted bytes (d3_put_trans) */
    for (i = 0; i < 5; i++) {
        unsigned char dd;
        if (c->mode) {
            dd = (unsigned char)(b - d3_hash_byte(c));
            if (!c->flag7) dd = (unsigned char)(0 - dd);
            if (dd >= 0x80) c->flag7 = (unsigned char)!c->flag7;
        } else {
            dd = b;
        }
        dd = (unsigned char)(~dd);
        c->hash = (c->hash << 8) + b;
        c->last_sym = dd;
        if (c->out_total < c->out_expect) c->out[c->out_total] = b;
        c->out_total++;
        d3_model_update(c, c->last_sym);
    }
    len -= 5;
    /* raw fill: no hash / flag update (sub_19C90) */
    if (c->out_total < c->out_expect) {
        size_t room = c->out_expect - c->out_total;
        memset(c->out + c->out_total, b, len < room ? len : room);
    }
    c->out_total += len;
    /* nothing is decoded once the output is complete */
    if (c->out_total < c->out_expect)
        d3_model_update_n(c, c->last_sym, len);
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */
static void d3_free(d3ctx *c)
{
    if (!c) return;
    free(c->mdl);
    free(c->rtab);
    free(c->dict);
    free(c);
}

int uharc_dec3t_init(void **pctx, int method)
{
    d3ctx *c;
    unsigned group, i;
    uint32_t dict;

    if (!pctx) return 1;
    *pctx = 0;
    if (method < 8 || method > 43) return 1;

    group = (method < 20) ? 1u : (method < 32 ? 2u : 3u);

    c = (d3ctx *)calloc(1, sizeof(*c));
    if (!c) return 2;
    c->mdl = (d3m *)malloc(256 * sizeof(d3m));
    c->rtab = (uint64_t *)calloc(0x8000, sizeof(uint64_t));
    dict = 1u << (((unsigned)(method - 8) % 12u) + 10u);
    c->dict = (unsigned char *)malloc((size_t)dict + 256);
    if (!c->mdl || !c->dict || !c->rtab) {
        d3_free(c);
        return 2;
    }

    c->dict_size = dict;
    c->dict_wrap = dict - 255;
    c->dict_mask = dict - 1;
    c->group = (unsigned char)group;
    c->list_max = d3_db[group];
    c->class_max = (uint32_t)(d3_db[group] - 3);

    d3_reset_models(c);
    for (i = 0; i < 8; i++) memcpy(c->state[i], d3_state_init, 10);
    memcpy(c->lenA, d3_len_init, sizeof(c->lenA));
    memcpy(c->lenB, d3_len_init, sizeof(c->lenB));
    memcpy(c->dmodel, d3_dmodel_init, sizeof(c->dmodel));
    memcpy(c->smallm, d3_small_init, sizeof(c->smallm));
    memcpy(c->d2, d3_d2_init, sizeof(c->d2));
    memcpy(c->lenclass, d3_lenclass_init, sizeof(c->lenclass));
    for (i = 0; i < 16; i++) c->distlist[i] = 0xFFFFFFFFu;

    c->state_idx = 7;
    c->prev_ctx = 0xFF;
    c->last_out = 0;
    c->last_sym = 0;
    c->mode = 0;
    c->db = 0;
    c->order = 3;
    c->prev_order = 3;
    c->flag7 = 1;
    c->raw_lit = 0;
    c->exc_lit = 0;
    c->len_sel = 0;
    c->len_val = 0;
    c->fill_idx = (unsigned char)(sizeof(d3_fillthr) / sizeof(d3_fillthr[0]) - 1);
    c->hash = 0xFFFFFFFFu;
    c->counter = 0;
    c->match_pos = 0xFFFFFFFFu;
    c->ring_pos = 0;
    c->ring_fill = 31;
    c->code = 0;
    c->range = 0xFFFFu;

    *pctx = c;
    return 0;
}

int uharc_dec3t_decode_mem(void *ctx, const unsigned char *in, size_t in_len,
                           unsigned char *out, size_t out_len)
{
    d3ctx *c = (d3ctx *)ctx;
    unsigned i;

    if (!c || (!in && in_len) || (!out && out_len)) return 1;
    c->ip = in;
    c->iend = in + in_len;
    c->bb = 0;
    c->bc = 0;
    c->out = out;
    c->out_expect = out_len;
    c->out_total = 0;
    c->err = 0;

    /* sub_206D0: 16 bits into code, range = 0x10000 */
    c->code = 0;
    for (i = 0; i < 16; i++)
        c->code = (c->code << 1) | (uint32_t)d3_bit(c);
    c->range = 0x10000u;
    if (c->err) return c->err;

    while (c->out_total < c->out_expect && !c->err) {
        unsigned t = d3_token(c);
        if (D3_LIKELY(t == 3)) { d3_literal(c); continue; }
        switch (t) {
        case 0: d3_control(c); break;
        case 1: d3_run(c); break;
        case 2: d3_match(c); break;
        default: c->err = 7; break;
        }
    }
    if (c->err) return c->err;
    if (c->out_total < c->out_expect) return 4;
    return 0;
}

/* Callback interface (kept for API compatibility): reads the whole input,
 * decodes in memory, then writes the output. */
int uharc_dec3t_decode(void *ctx, uharc_dec_read_cb rcb, void *rctx,
                       uharc_dec_write_cb wcb, void *wctx,
                       unsigned long out_len)
{
    unsigned char *in = NULL, *out = NULL;
    size_t in_len = 0, cap = 0;
    int rc;

    if (!ctx || !rcb || !wcb) return 1;
    for (;;) {
        int n;
        if (cap - in_len < 65536) {
            size_t ncap = cap ? cap * 2 : 1u << 20;
            unsigned char *p = (unsigned char *)realloc(in, ncap);
            if (!p) { free(in); return 2; }
            in = p;
            cap = ncap;
        }
        n = rcb(rctx, in + in_len, 65536u);
        if (n <= 0) break;
        in_len += (size_t)n;
    }
    out = (unsigned char *)malloc(out_len ? out_len : 1);
    if (!out) { free(in); return 2; }
    rc = uharc_dec3t_decode_mem(ctx, in, in_len, out, out_len);
    {
        /* the original flushes what was produced, even on error */
        size_t done = ((d3ctx *)ctx)->out_total;
        size_t ofs = 0;
        if (done > out_len) done = out_len;
        while (ofs < done) {
            unsigned n = (unsigned)((done - ofs) > 65536u ? 65536u : (done - ofs));
            if (wcb(wctx, out + ofs, n) != 0) { if (!rc) rc = 4; break; }
            ofs += n;
        }
    }
    free(out);
    free(in);
    return rc;
}

void uharc_dec3t_free(void *ctx)
{
    d3_free((d3ctx *)ctx);
}

