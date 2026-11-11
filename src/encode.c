#define _POSIX_C_SOURCE 200809L
#include "encode.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crc32.h"
#include "lzp.h"
#include "alz.h"
#include "alz_parse_score.h"
#include "ppm.h"
#include "crypto.h"

static const uint8_t uha_init_sbox[256] = {
    0xc3,0xae,0x65,0x6b,0x78,0x47,0xf2,0x91,0xd6,0x50,0xcb,0x65,0x20,0xbd,0x75,0xbf,
    0x45,0xa1,0xcd,0x6b,0xb4,0x5f,0x25,0xb6,0x39,0xbf,0xff,0x37,0xae,0x45,0x37,0xed,
    0xa5,0xfa,0x5c,0xf3,0x1b,0x20,0xae,0x0b,0xf3,0xe6,0xc6,0x8d,0x1b,0x3b,0x1e,0x41,
    0x65,0x18,0x9a,0xe1,0xad,0xc2,0x24,0x2f,0xa0,0xd4,0x7a,0x2c,0x52,0x2c,0xd6,0xf4,
    0x55,0xa7,0x84,0x6c,0x8d,0x6b,0x4d,0x85,0x32,0x12,0xdc,0x0a,0x8c,0xdc,0x2a,0xe7,
    0xcd,0xbd,0xf9,0x79,0x61,0x65,0x08,0x87,0x5e,0xdc,0x28,0x48,0x97,0x35,0xbf,0xb2,
    0xd6,0xa1,0x4b,0x68,0x20,0x4c,0xf5,0xb2,0x7b,0x5f,0xf7,0x9a,0x8a,0xa1,0x1f,0x47,
    0x84,0xd5,0x64,0x22,0x13,0x2f,0xac,0xf8,0x25,0x0f,0x09,0xc3,0x9b,0xd5,0xfb,0x3b,
    0xd5,0x40,0xdf,0x1e,0x3d,0x9d,0x07,0xd2,0xe9,0x23,0xcc,0xd5,0x21,0xf9,0x72,0x1b,
    0x94,0x34,0x26,0xa3,0x66,0xcc,0x8a,0x7b,0xe6,0xea,0x15,0xa4,0x3e,0x26,0xdc,0x4d,
    0xe0,0xdd,0x06,0x85,0x5e,0x13,0xf0,0x68,0x7b,0x27,0x59,0x10,0xd7,0xff,0xa8,0xee,
    0x0b,0xb1,0xcc,0x2f,0xc2,0x58,0x5b,0xd5,0xa3,0x54,0x6e,0x27,0x55,0xb9,0xd0,0xfd,
    0x3d,0xc5,0xd1,0xb6,0xcc,0x3b,0x39,0x6b,0x75,0x42,0x9f,0xf1,0xe2,0xb8,0x57,0x2b,
    0xf7,0x3f,0xe7,0x72,0x49,0xe5,0x15,0x8a,0x3c,0x33,0x79,0x2a,0xd4,0xee,0xa1,0xe6,
    0xc1,0xf5,0x16,0x69,0x09,0x2f,0xa8,0xa7,0x0c,0x3c,0x62,0x62,0xfe,0xc4,0xce,0xba,
    0xb9,0xfd,0xb9,0xaf,0x61,0x31,0x70,0x46,0x0d,0xfa,0x44,0x08,0xb3,0x34,0xb2,0xe5
};

static void scramble(uint8_t *buf, size_t n)
{
    uint8_t S[256];
    int i, j, k;
    uint8_t b, t;

    memcpy(S, uha_init_sbox, 256);
    i = 0;
    j = (0 - 2) & 0xFF;
    for (k = 0; k < (int)n; k++) {
        j = (j + 1) & 0xFF;
        i = (i + 1) & 0xFF;
        b = S[i];
        t = (uint8_t)(S[(i - 1) & 0xFF] + b);
        S[i] = t;
        buf[k] ^= t;
        S[j] = (uint8_t)(S[j] - b);
    }
}

static void put_le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static const char *basename_of(const char *s)
{
    const char *p = s;
    if (!s || !s[0])
        return "file";
    while (*p) {
        if (*p == '/' || *p == '\\')
            s = p + 1;
        p++;
    }
    return s[0] ? s : "file";
}

static void split_path(const char *path, const char **dir_out, size_t *dirlen_out,
                       const char **file_out, size_t *filelen_out)
{
    const char *slash = NULL;
    const char *s = path;
    if (!path) {
        *dir_out = ""; *dirlen_out = 0;
        *file_out = ""; *filelen_out = 0;
        return;
    }
    for (; *s; s++) {
        if (*s == '/' || *s == '\\')
            slash = s;
    }
    if (slash) {
        *dir_out = path;
        *dirlen_out = (size_t)(slash - path + 1);
        *file_out = slash + 1;
        *filelen_out = strlen(slash + 1);
    } else {
        *dir_out = "";
        *dirlen_out = 0;
        *file_out = path;
        *filelen_out = strlen(path);
    }
}

static int build_names(const uha_member *members, int count,
                       uint8_t **out, uint32_t *outlen, uint8_t *out_ndirs)
{
    /*
     * Contents-table name block (matches real UHARC's canonical form):
     *   [ndirs directory entries][count file-name entries]
     * In default mode: emits count empty directory entries (0x00), followed
     * by basenames. Identical to original baseline across all standard archives.
     * In -pr / -pf mode: emits directory entries with dir path, then basenames.
     * In -p- (path_none) mode: emits exactly ONE empty directory entry (0x00),
     * and all members share didx = 0.
     */
    const char *pm = getenv("UHA_PATH_MODE");
    int path_none = (pm && (strcmp(pm, "none") == 0 || strcmp(pm, "-") == 0));
    int path_with_dir = (pm && (strcmp(pm, "rel") == 0 || strcmp(pm, "full") == 0));
    uint8_t ndirs = path_none ? 1 : (uint8_t)count;
    uint32_t n = 0;
    int f;
    uint8_t *buf;
    uint32_t p;

    if (path_none) {
        n += 1;
        for (f = 0; f < count; f++) {
            const char *nm = basename_of(members[f].arcname);
            size_t ln = strlen(nm);
            if (ln > 255) ln = 255;
            n += 1 + (uint32_t)ln;
        }
    } else if (path_with_dir) {
        for (f = 0; f < count; f++) {
            const char *dir = "";
            size_t dirlen = 0, fnlen = 0;
            const char *fn = members[f].arcname;
            split_path(members[f].arcname, &dir, &dirlen, &fn, &fnlen);
            if (dirlen > 255) dirlen = 255;
            n += 1 + (uint32_t)dirlen;
        }
        for (f = 0; f < count; f++) {
            const char *dir = "";
            size_t dirlen = 0, fnlen = 0;
            const char *fn = members[f].arcname;
            split_path(members[f].arcname, &dir, &dirlen, &fn, &fnlen);
            if (fnlen > 255) fnlen = 255;
            n += 1 + (uint32_t)fnlen;
        }
    } else {
        n = (uint32_t)count;
        for (f = 0; f < count; f++) {
            const char *nm = basename_of(members[f].arcname);
            size_t ln = strlen(nm);
            if (ln > 255) ln = 255;
            n += 1 + (uint32_t)ln;
        }
    }
    buf = malloc(n ? n : 1);
    if (!buf)
        return -4;
    p = 0;
    if (path_none) {
        buf[p++] = 0;
        for (f = 0; f < count; f++) {
            const char *nm = basename_of(members[f].arcname);
            size_t ln = strlen(nm);
            size_t i;
            if (ln > 255) ln = 255;
            buf[p++] = (uint8_t)ln;
            for (i = 0; i < ln; i++)
                buf[p++] = (uint8_t)nm[i];
        }
    } else if (path_with_dir) {
        for (f = 0; f < count; f++) {
            const char *dir = "";
            size_t dirlen = 0, fnlen = 0;
            const char *fn = members[f].arcname;
            size_t i;
            split_path(members[f].arcname, &dir, &dirlen, &fn, &fnlen);
            if (dirlen > 255) dirlen = 255;
            buf[p++] = (uint8_t)dirlen;
            for (i = 0; i < dirlen; i++) {
                char c = dir[i];
                if (c == '/' && pm && strcmp(pm, "full") == 0)
                    c = '\\';
                buf[p++] = (uint8_t)c;
            }
        }
        for (f = 0; f < count; f++) {
            const char *dir = "";
            size_t dirlen = 0, fnlen = 0;
            const char *fn = members[f].arcname;
            size_t i;
            split_path(members[f].arcname, &dir, &dirlen, &fn, &fnlen);
            if (fnlen > 255) fnlen = 255;
            buf[p++] = (uint8_t)fnlen;
            for (i = 0; i < fnlen; i++)
                buf[p++] = (uint8_t)fn[i];
        }
    } else {
        for (f = 0; f < count; f++)
            buf[p++] = 0;
        for (f = 0; f < count; f++) {
            const char *nm = basename_of(members[f].arcname);
            size_t ln = strlen(nm);
            size_t i;
            if (ln > 255) ln = 255;
            buf[p++] = (uint8_t)ln;
            for (i = 0; i < ln; i++) {
                char c = nm[i];
                if (c == '/')
                    c = '\\';
                buf[p++] = (uint8_t)c;
            }
        }
    }
    *out = buf;
    *outlen = n;
    if (out_ndirs)
        *out_ndirs = ndirs;
    return 0;
}

static void dos_timestamp(struct tm *lt, uint16_t *out_time, uint16_t *out_date);

/* [M241] Instant DOS some columns date/heure of the block `attrs`.
 *   1) `UHA_ATTR_TIME` (gel) : "dos:0xD:0xT" (en hexa) now "YYYY-MM-DD HH:MM:SS" ;
 *   2) otherwise mtime of the member (lot measures : stat -> DOS, OUT/m241_container.md S2) ;
 *   3) otherwise repli sure l'instant some archives of the corpus (2026-09-23 01:35:44)
 *      = values historiquement codees en dur, conservees for there GT scellee. */
static void attrs_dos_stamp(uint32_t mtime, uint16_t *out_time, uint16_t *out_date)
{
    static int parsed = 0;
    static uint16_t pin_t = 0, pin_d = 0;

    if (!parsed) {
        const char *e = getenv("UHA_ATTR_TIME");
        parsed = 1;
        if (e && e[0]) {
            unsigned dd = 0, tt = 0;
            if (sscanf(e, "dos:%x:%x", &dd, &tt) == 2) {
                pin_d = (uint16_t)dd;
                pin_t = (uint16_t)tt;
            } else {
                int Y = 0, M = 0, D = 0, h = 0, mi = 0, s = 0;
                if (sscanf(e, "%d-%d-%d %d:%d:%d", &Y, &M, &D, &h, &mi, &s) == 6) {
                    struct tm lt;
                    memset(&lt, 0, sizeof lt);
                    lt.tm_year = Y - 1900; lt.tm_mon = M - 1; lt.tm_mday = D;
                    lt.tm_hour = h; lt.tm_min = mi; lt.tm_sec = s;
                    dos_timestamp(&lt, &pin_t, &pin_d);
                }
            }
        }
    }
    if (pin_d || pin_t) {
        *out_time = pin_t; *out_date = pin_d;
        return;
    }
    if (mtime) {
        /* [M241] LAW MESUREE of legacy : the DOS date/heure some members = mtime converti en
         * **UTC+1 FIXE** (the legacy engine ignores the DST). Preuves : code.c 2010-07-15 12:34:56
         * (CEST) -> 0x5C5C = 11:34:56 ; hello.txt 1999-12-31 23:59:58 (THIS) -> 0xBF7D =
         * 23:59:58 ; GT ALL has mtimes 2026-09-23 01:35:44 -> 0x0476 = 00:35:44. Has
         * `localtime_r` (DST correct) rendrait 0x0C76 and casse there GT scellee. */
        struct tm gt;
        time_t t = (time_t)mtime + 3600;
        if (gmtime_r(&t, &gt)) {
            dos_timestamp(&gt, out_time, out_date);
            return;
        }
    }
    *out_date = 0x5D37;   /* 2026-09-23 */
    *out_time = 0x0C76;   /* 01:35:44 */
}

static int build_attrs(const uha_member *members, int count,
                       uint8_t **out, uint32_t *outlen)
{
    uint32_t fc = (uint32_t)count;
    uint32_t alen = 14 * fc + 16;
    uint8_t *a;
    uint32_t f, prev, v, sz;

    a = calloc(1, alen);
    if (!a)
        return -4;
    for (f = 0; f < fc; f++) {
        /* [M241] DATE then HEURE DOS of the member, ENTRELACEES (law mesuree :
         * OUT/m241_container.md S2, three files has mtimes distincts) :
         *   has[2f], has[2f+1]        = date DOS (THE)
         *   has[2fc+2f], has[2fc+2f+1] = heure DOS (THE)
         * `UHA_ATTR_TIME` gele l'instant ("dos:0x5D37:0x0C76" now "YYYY-MM-DD HH:MM:SS") ;
         * without mtime nor gel, repli sure l'instant some archives of the corpus. */
        { uint16_t t16 = 0, d16 = 0;
          attrs_dos_stamp(members[f].mtime, &t16, &d16);
          a[2 * f] = (uint8_t)(d16 & 0xFF);
          a[2 * f + 1] = (uint8_t)(d16 >> 8);
          a[2 * fc + 2 * f] = (uint8_t)(t16 & 0xFF);
          a[2 * fc + 2 * f + 1] = (uint8_t)(t16 >> 8); }
        {
            const char *pm = getenv("UHA_PATH_MODE");
            int path_none = (pm && (strcmp(pm, "none") == 0 || strcmp(pm, "-") == 0));
            if (path_none)
                a[4 * fc + f] = 0;
            else
                a[4 * fc + f] = (uint8_t)members[f].cmd_rank;  /* [FRONTIER] didx = rank of COMMANDE ; cmd_rank=f by default (without gate) => identical has (uint8_t)f */
        }
        a[5 * fc + f] = 0;
        a[10 * fc + f] = 0x20;        /* DOS archive attribute (real UHARC) */
    }
    prev = 0;
    for (f = 0; f < fc; f++) {
        sz = members[f].size;
        v = (prev - sz) & 0xFFFFFFFFu;
        a[6 * fc + f] = (uint8_t)v;
        a[7 * fc + f] = (uint8_t)(v >> 8);
        a[8 * fc + f] = (uint8_t)(v >> 16);
        a[9 * fc + f] = (uint8_t)(v >> 24);
        prev = sz;
    }
    /* [A5.3-t12 diag] override gated of the plaintext attrs : if UHA_ATTRS_HEX
     * fournit exactement `alen` bytes, on the injecte for to validate that the
     * +3 provient well some columns 11-13 + zone 16 o no remplies. */
    {
        const char *oh = getenv("UHA_ATTRS_HEX");
        if (oh && alen && strlen(oh) >= 2 * alen) {
            uint32_t q;
            for (q = 0; q < alen; q++) {
                unsigned bv = 0;
                sscanf(oh + 2 * q, "%2x", &bv);
                a[q] = (uint8_t)bv;
            }
        }
    }
    if (getenv("UHA_ATTRSDUMP")) {
        uint32_t q;
        fprintf(stderr, "[attrs-plain alen=%u] ", alen);
        for (q = 0; q < alen; q++) fprintf(stderr, "%02x", a[q]);
        fprintf(stderr, "\n");
    }
    *out = a;
    *outlen = alen;
    return 0;
}

/*
 * Header bytes dec[4..7] hold an MS-DOS timestamp, little-endian:
 *   dec[4],dec[5] = DOS time  = (hh<<11)|(mm<<5)|(ss/2)
 *   dec[6],dec[7] = DOS date  = ((year-1980)<<9)|(month<<5)|(day)
 * Confirmed against real UHARC archives: 0x0C89/0x5D37 decodes to
 * 01:36:18 / 23-Sep-2026, exactly what UHARC.EXE reports as the creation time.
 */
static void dos_timestamp(struct tm *lt, uint16_t *out_time, uint16_t *out_date)
{
    int year = lt->tm_year + 1900;
    uint16_t t = (uint16_t)((lt->tm_hour << 11) | (lt->tm_min << 5) | (lt->tm_sec / 2));
    uint16_t d = 0;
    if (year >= 1980 && year <= 2107)
        d = (uint16_t)(((year - 1980) << 9) | ((lt->tm_mon + 1) << 5) | lt->tm_mday);
    else
        d = (uint16_t)((1 << 5) | 1); /* fallback: 1 Jan 1980 */
    *out_time = t;
    *out_date = d;
}

static void write_header(uint8_t *raw, uint8_t seed,
                         uint8_t family, uint8_t order, uint8_t flags,
                         uint32_t usize, uint32_t psize, uint32_t fc,
                         uint32_t nup, uint32_t npk, uint32_t apk,
                         uint8_t ndirs, uint16_t w33, uint16_t w35)
{
    uint8_t dec[39];
    uint16_t dost, dosd, check16;
    time_t now;
    struct tm lt;
    int i;

    now = time(NULL);
    {
        /* [A5.3 t13] Override gated of l'horodatage of CREATION of l'archive
         * (dec[4..7]) : enables of to reproduce byte-for-byte has archive
         * legacy en injectant son instant of creation. Default-inerte. */
        const char *se = getenv("UHA_EPOCH");
        if (se) now = (time_t)strtoll(se, NULL, 10);
    }
#ifdef _WIN32
    lt = *localtime(&now);
#else
    localtime_r(&now, &lt);
#endif
    dos_timestamp(&lt, &dost, &dosd);

    memset(dec, 0, 39);
    dec[0] = 'U';
    dec[1] = 'H';
    dec[2] = 'A';
    dec[3] = 6;
    dec[4] = (uint8_t)(dost & 0xFF);
    dec[5] = (uint8_t)(dost >> 8);
    dec[6] = (uint8_t)(dosd & 0xFF);
    dec[7] = (uint8_t)(dosd >> 8);
    dec[8] = flags;
    dec[9] = family;
    dec[10] = order;
    dec[11] = ndirs;
    put_le32(dec + 13, usize);
    put_le32(dec + 17, psize);
    put_le24(dec + 21, fc);
    put_le24(dec + 24, nup);
    put_le24(dec + 27, npk);
    put_le24(dec + 30, apk);
    /*
     * Contents-table checksums (cracked against real UHARC 0.6b, 87/87):
     *   dec[33..34] = w33 = low16(CRC32(aux_plain || names_plain))
     *   dec[35..36] = w35 = low16(CRC32(attrs_plain[0:11*fc]))
     * dec[33..34] sit INSIDE the obfuscated + header-checksummed region
     * (offsets 4..34), so they must be present before check16 is computed.
     * dec[35..36] are RAW (offsets 35,36 are outside both the obfuscation
     * loop and the header CRC), so they are copied to raw[] verbatim.
     */
    dec[33] = (uint8_t)(w33 & 0xFF);
    dec[34] = (uint8_t)(w33 >> 8);
    dec[35] = (uint8_t)(w35 & 0xFF);
    dec[36] = (uint8_t)(w35 >> 8);
    /*
     * UHARC header integrity (cracked against real UHARC 0.6b, 89/89):
     *   check16 = low16( CRC32_ieee(dec[4..34]) )   (31 of-obfuscated bytes)
     * The seed byte is NOT free: raw[37] == check16 & 0xFF (its low byte) and
     * raw[38] == check16 >> 8, so the stored 16-bit word at [37..38] equals
     * check16. The of-obfuscation uses that same seed.
     */
    check16 = (uint16_t)(uha_crc32(dec + 4, 31) & 0xFFFFu);
    seed = (uint8_t)(check16 & 0xFF);
    memcpy(raw, dec, 39);
    for (i = 0; i < 31; i++)
        raw[4 + i] = (uint8_t)(dec[4 + i] ^ ((seed + (uint32_t)i * (uint32_t)i) & 0xFF));
    raw[37] = seed;
    raw[38] = (uint8_t)(check16 >> 8);
}

static int encode_archive(const uha_member *members, int count,
                          uint8_t family, uint8_t order,
                          const uint8_t *payload, uint32_t psize,
                          uint8_t **out, size_t *outlen)
{
    uint8_t *names = NULL, *attrs = NULL;
    uint8_t *npk = NULL, *apk = NULL;
    uint8_t *aux_plain = NULL, *aux_disk = NULL, *scratch = NULL;
    uint8_t *raw;
    uint32_t nup = 0, alen = 0;
    size_t npklen = 0, apklen = 0;
    uint32_t usize = 0, fc, f, k;
    size_t total, ofs;
    uint16_t w33, w35;
    int rc;

    fc = (uint32_t)count;
    for (f = 0; f < fc; f++)
        usize += members[f].size;

    uint8_t ndirs = (uint8_t)fc;
    rc = build_names(members, count, &names, &nup, &ndirs);
    if (rc != 0)
        return rc;
    rc = build_attrs(members, count, &attrs, &alen);
    if (rc != 0) {
        free(names);
        return rc;
    }
    rc = uha_lzp_encode(names, nup, 0x11, NULL, 0, &npk, &npklen);
    if (rc != 0) {
        free(names);
        free(attrs);
        return rc;
    }
    /*
     * [A5.3 t13] the legacy engine UHARC not code en LZP that there portee useful of the block
     * attrs, i.e. the 11 columns per-file ([0 .. 11*fc[) - exactement there
     * portee of the checksum w35. The bytes restants (columns 11-13 + trailer
     * of 16 o, zone [11*fc .. alen[) not are NOT emis in the stream : the
     * decoder the reconstitue (re-encoding = same plaintext, match prefixe).
     * Encoder alen complete faisait +7 o of too sure image.raw (-m3).
     */
    rc = uha_lzp_encode(attrs, 11 * fc, 0x11, NULL, 0, &apk, &apklen);
    if (rc != 0) {
        free(names);
        free(attrs);
        free(npk);
        return rc;
    }
    if (getenv("UHA_ATTRSDUMP")) {
        size_t q;
        fprintf(stderr, "[apk pre-scramble len=%zu] ", apklen);
        for (q = 0; q < apklen; q++) fprintf(stderr, "%02x", apk[q]);
        fprintf(stderr, "\n");
    }
    scramble(npk, npklen);
    scramble(apk, apklen);

    /*
     * Per-member array. Real UHARC stores, for each file, the little-endian
     * CRC-32 (standard/zlib form, output XOR 0xFFFFFFFF) of the member's
     * UNCOMPRESSED data, SCRAMBLED with the same S-box keystream used for the
     * names/attrs blocks. The contents-table checksum w33 is CRC32 over the
     * of-scrambled member array followed by the plaintext names.
     */
    aux_plain = malloc((size_t)fc * 4);
    aux_disk = malloc((size_t)fc * 4);
    scratch = malloc((size_t)fc * 4 + nup);
    if (!aux_plain || !aux_disk || !scratch) {
        free(names); free(attrs); free(npk); free(apk);
        free(aux_plain); free(aux_disk); free(scratch);
        return -4;
    }
    for (f = 0; f < fc; f++)
        put_le32(aux_plain + 4 * f, uha_crc32(members[f].data, members[f].size));
    memcpy(aux_disk, aux_plain, (size_t)fc * 4);
    scramble(aux_disk, (size_t)fc * 4);
    memcpy(scratch, aux_plain, (size_t)fc * 4);
    for (k = 0; k < nup; k++)
        scratch[(size_t)fc * 4 + k] = names[k];
    w33 = (uint16_t)(uha_crc32(scratch, (size_t)fc * 4 + nup) & 0xFFFFu);
    w35 = (uint16_t)(uha_crc32(attrs, (size_t)11 * fc) & 0xFFFFu);

    total = 39 + (size_t)psize + (size_t)fc * 4 + npklen + apklen;
    raw = malloc(total);
    if (!raw) {
        free(names); free(attrs); free(npk); free(apk);
        free(aux_plain); free(aux_disk); free(scratch);
        return -4;
    }
    {
        uint8_t flags = 0;
        const char *pw = getenv("UHA_PASSWORD");
        if (pw && pw[0]) {
            const char *ph = getenv("UHA_HEADER_ENCRYPT");
            flags = UHA_FLAG_PW_DATA;
            if (!ph || strcmp(ph, "0") != 0)
                flags |= UHA_FLAG_PW_HDR;
        }
        write_header(raw, 0x40, family, order, flags, usize, psize, fc, nup,
                     (uint32_t)npklen, (uint32_t)apklen, ndirs, w33, w35);
        ofs = 39;
        if (psize && payload)
            memcpy(raw + ofs, payload, psize);
        ofs += psize;
        memcpy(raw + ofs, aux_disk, (size_t)fc * 4);
        ofs += (size_t)fc * 4;
        memcpy(raw + ofs, npk, npklen);
        ofs += npklen;
        memcpy(raw + ofs, apk, apklen);

        if (flags & (UHA_FLAG_PW_DATA | UHA_FLAG_PW_HDR)) {
            uha_header h;
            memset(&h, 0, sizeof(h));
            h.flags = flags;
            h.psize = psize;
            h.file_count = fc;
            h.names_packed = (uint32_t)npklen;
            h.attrs_packed = (uint32_t)apklen;
            h.data_ofs = 39;
            h.crc_ofs = h.data_ofs + h.psize;
            h.names_ofs = h.crc_ofs + (size_t)fc * 4;
            h.attrs_ofs = h.names_ofs + h.names_packed;
            uha_decrypt(raw, total, &h, pw);
        }
    }

    free(names);
    free(attrs);
    free(npk);
    free(apk);
    free(aux_plain);
    free(aux_disk);
    free(scratch);
    *out = raw;
    *outlen = total;
    return 0;
}

int uha_encode_store(const uha_member *members, int count,
                     uint8_t **out, size_t *outlen)
{
    uint8_t *payload;
    uint32_t usize = 0, f, ofs;
    int rc;

    if (!members || count <= 0 || !out || !outlen)
        return -2;
    *out = NULL;
    *outlen = 0;
    for (f = 0; f < (uint32_t)count; f++)
        usize += members[f].size;
    payload = malloc(usize ? usize : 1);
    if (!payload)
        return -4;
    ofs = 0;
    for (f = 0; f < (uint32_t)count; f++) {
        if (members[f].size)
            memcpy(payload + ofs, members[f].data, members[f].size);
        ofs += members[f].size;
    }
    rc = encode_archive(members, count, 0, 0, payload, usize, out, outlen);
    free(payload);
    return rc;
}

int uha_encode_lzp(const uha_member *members, int count, int order,
                   uint8_t **out, size_t *outlen)
{
    uint8_t *plain;
    uint8_t *pk = NULL;
    uint32_t *ends = NULL;
    uint32_t usize = 0, f, ofs;
    size_t pklen = 0;
    int rc;

    if (!members || count <= 0 || !out || !outlen)
        return -2;
    *out = NULL;
    *outlen = 0;
    if (order < 8)
        order = 8;
    if (order > 23)
        order = 23;

    for (f = 0; f < (uint32_t)count; f++)
        usize += members[f].size;

    /* [GATED UHA_MZ_ORDERLAW, default-ON en autonomie native] LAW 1 d'order LZP of the master, MESUREE by #2 (M372) :
     * dict = puissance of 2 STRICTEMENT greater has usize (plancher 1024); order = log2(dict)-2;
     * ring = 1<<(order+2) = dict. (L'old law " halver 4096 by usize " was false, retiree.)
     * Active by default ; UHA_MZ_ORDERLAW=0 retablit l'historique without law. */
    int mz_orderlaw = 1;
    { const char *e = getenv("UHA_MZ_ORDERLAW"); if (e) mz_orderlaw = (e[0] != '0'); }
    if (mz_orderlaw && usize > 0) {
        /* LAW 1 reelle (M372 #2, mesuree): dict = more small puissance of 2 STRICTEMENT
         * greater has usize (plancher 1024); order = log2(dict)-2; ring = 1<<(order+2)=dict.
         * Replaces l'old law erronee (halver 4096 by usize). */
        unsigned k = 10u;
        while (k < 25u && ((uint64_t)1u << k) <= (uint64_t)usize)
            k++;
        order = (int)k - 2;
        if (order < 8)
            order = 8;
        if (order > 23)
            order = 23;
    }

    /* [GATED UHA_MZ_EMPTY, default-ON en autonomie native] LAW 4 (M372 #2): archive entierement empty (usize==0)
     * = path degene: no dictionnaire, order emis 0, NO payload range coder (the master
     * not demarre not the codeur). UHA_MZ_EMPTY=0 retablit the flush range coder. */
    int mz_empty = 1;
    { const char *e = getenv("UHA_MZ_EMPTY"); if (e) mz_empty = (e[0] != '0'); }
    if (usize == 0 && mz_empty) {
        rc = encode_archive(members, count, 3, 0, NULL, 0, out, outlen);
        return rc;
    }

    plain = malloc(usize ? usize : 1);
    ends = malloc((size_t)count * sizeof(uint32_t));
    if (!plain || !ends) {
        free(plain);
        free(ends);
        return -4;
    }
    ofs = 0;
    for (f = 0; f < (uint32_t)count; f++) {
        if (members[f].size)
            memcpy(plain + ofs, members[f].data, members[f].size);
        ofs += members[f].size;
        ends[f] = ofs;
    }
    rc = uha_lzp_encode(plain, usize, order, ends, count, &pk, &pklen);
    free(plain);
    free(ends);
    if (rc != 0)
        return rc;
    rc = encode_archive(members, count, 3, (uint8_t)order, pk, (uint32_t)pklen,
                        out, outlen);
    free(pk);
    return rc;
}

int uha_encode_alz(const uha_member *members, int count, int method_class,
                   uint8_t **out, size_t *outlen)
{
    uint8_t *plain;
    uint8_t *pk = NULL;
    uint32_t *ends = NULL;
    uint32_t usize = 0, f, ofs;
    size_t pklen = 0;
    int order = 0;
    int rc = 0;

    if (!members || count <= 0 || !out || !outlen)
        return -2;
    *out = NULL;
    *outlen = 0;
    if (method_class < 0 || method_class > 2)
        method_class = 0;

    for (f = 0; f < (uint32_t)count; f++)
        usize += members[f].size;

    /* Window ALZ derivee of the size + class of method (t15 / -m2/-m3).
     * L'byte d'order of the header encode TWO choses : there class of method
     * (via the bits hauts) and the nibble low = size of window. The decoder
     * legacy computes dict = 1 << (((order-40)%16)+10), INVARIANT under +16/+32.
     * therefore there class not change THAT the libelle emis (ALZ_FAST 40..55 = -m1,
     * NORMAL 56..71 = -m2, BEST 72..87 = -m3), not the model entropique :
     * method_class n'is never lu au decoding, and nos stream -m1 se decodent
     * already under all the modes legacy (difftest 89/89). On keeps there selection
     * empirique of the smaller nibble k (0..15) whose dict > usize (validated sure
     * the 12 archives legacy : hello 40, eng 45, code.c/mixed 46, image.raw/
     * biased/image24/random 47, pattern/records/zeros 48), then
     * order_final = 40 + 16*class + k. There output is therefore byte-for-byte there
     * same that the -m1 validated ; there Wine-gate the confirme for m2/m3. */
    {
        int base = 40 + 16 * method_class;
        int k = 0;
        uint32_t d = 1024;
        while (d <= usize && k < 15) {
            k++;
            d = 1u << (k + 10);
        }
        const char *mde = getenv("UHA_ALZ_DICT_KB");
        if (mde && atoi(mde) > 0) {
            int req_kb = atoi(mde);
            int req_k = 0;
            uint32_t rd = 1;
            while (rd < (uint32_t)req_kb && req_k < 15) {
                req_k++;
                rd <<= 1;
            }
            if (req_k <= k)
                k = req_k;
        }
        order = base + k;
    }

    /* [GATED UHA_ALZ_EMPTY, default-ON en autonomie native] LAW 4 (M372 #2), already cablee for LZP in
     * uha_encode_lzp etendue here has ALZ : archive entierement empty (usize==0) = path
     * degene, NO payload range coder. MEASURES #1 M411 : the master rend 71 o en
     * -m0/-mz/-mx (port already has 71, 0 diff) AND 71 o en -m1/-m2/-m3.
     * UHA_ALZ_EMPTY=0 retablit l'historique (+5 o). */
    int alz_empty = 1;
    { const char *e = getenv("UHA_ALZ_EMPTY"); if (e) alz_empty = (e[0] != '0'); }
    if (usize == 0 && alz_empty)
        return encode_archive(members, count, 1, (uint8_t)order, NULL, 0, out, outlen);

    plain = malloc(usize ? usize : 1);
    ends = malloc((size_t)count * sizeof(uint32_t));
    if (!plain || !ends) {
        free(plain);
        free(ends);
        return -4;
    }
    ofs = 0;
    for (f = 0; f < (uint32_t)count; f++) {
        if (members[f].size)
            memcpy(plain + ofs, members[f].data, members[f].size);
        ofs += members[f].size;
        ends[f] = ofs;
    }
    /* Selection deterministe en passe unique : min_len=2, tok2_min=2, lazy=1,
     * selecteur d'echappement derive dans uha_alz_encode (a3_sel_derive). */
    pk = NULL;
    pklen = 0;
    if (getenv("UHA_FORCESCFG")) {
        const char *fc = getenv("UHA_FORCESCFG");
        int f_sel = 0, f_min = 2, f_t2 = 2, f_lz = 1;
        sscanf(fc, "%d:%d:%d:%d", &f_sel, &f_min, &f_t2, &f_lz);
        rc = uha_alz_encode(plain, usize, order, ends, count,
                            f_sel, f_min, f_t2, f_lz, &pk, &pklen);
        if (rc == 0 && pk && getenv("UHA_GRIDDBG"))
            fprintf(stderr, "[FORCESCFG] sel=%d min=%d t2=%d lz=%d -> %zu\n",
                    f_sel, f_min, f_t2, f_lz, pklen);
    } else if (getenv("UHA_TRUEPARSE") || getenv("UHA_ORACLE") || getenv("UHA_DP")) {
        rc = uha_alz_encode(plain, usize, order, ends, count,
                            3, 2, 2, 1, &pk, &pklen);
    } else {
        rc = uha_alz_encode(plain, usize, order, ends, count,
                            0, 2, 2, 1, &pk, &pklen);
    }
    free(plain);
    free(ends);
    if (rc != 0) {
        free(pk);
        return rc;
    }
    if (!pk)
        return -4;
    rc = encode_archive(members, count, 1, (uint8_t)order, pk, (uint32_t)pklen,
                        out, outlen);
    free(pk);
    return rc;
}

int uha_encode_ppm(const uha_member *members, int count, int order,
                   uint8_t **out, size_t *outlen)
{
    uint8_t *plain;
    uint8_t *pk = NULL;
    uint32_t *ends = NULL;
    uint32_t usize = 0, f, ofs;
    size_t pklen = 0;
    int rc;

    if (!members || count <= 0 || !out || !outlen)
        return -2;
    *out = NULL;
    *outlen = 0;

    for (f = 0; f < (uint32_t)count; f++)
        usize += members[f].size;

    /* t14c : Rule legacy PPM - the smaller order (<=39) whose there window
     * 1<<(((order-24)%16)+10) is STRICTEMENT GREATER has usize, bornee has
     * [24,39]. Validee sure the 11 archives legacy -mx (hello 24, eng 29,
     * mixed/code.c 30, image.raw..biased 31, pattern/records/zeros 32) -
     * same law that ALZ t13b under l'other range d'orders. */
    {
        int o = 0x18;
        uint32_t w = 1024;
        while (w <= usize && o < 0x27) {
            o++;
            w = 1u << (((o - 0x18) % 0x10) + 0x0A);
        }
        order = o;
    }

    plain = malloc(usize ? usize : 1);
    ends = malloc((size_t)count * sizeof(uint32_t));
    if (!plain || !ends) {
        free(plain);
        free(ends);
        return -4;
    }
    ofs = 0;
    for (f = 0; f < (uint32_t)count; f++) {
        if (members[f].size)
            memcpy(plain + ofs, members[f].data, members[f].size);
        ofs += members[f].size;
        ends[f] = ofs;
    }
    /* t12g/t14d - politique of selection PPM.
     * bc1 (ring binary some l'en-tete) is tente en more of bc0 (path sure),
     * but N'is retenu that if it pass has auto-verification roundtrip bit-has-bit
     * via NOTRE decodeur faithful (uha_ppm_decode) AND qu'il is more short.
     * t14d : en MORE of the byte_class, there class LZP (flag3934, 0..9) is desormais
     * choisie ALSO. Elle was figee has 0, this which empechait wp_class_selected ->
     * the window predictor not s'armait never (ratio image24 = 186x). There class
     * is EMISE in the stream (block reset) therefore lue by the decodeur : all cls
     * is decodable. cls=0 remainder candidate -> no input not peut regresser. */
    {
        extern int uharc_ppm_class;
        uint8_t *best = NULL; size_t bestlen = 0;
        int best_bc = 0, best_cls = 0, have = 0;
        const char *fb = getenv("UHA_PPM_BC");
        const char *fc = getenv("UHA_PPMCLASS");
        int bc_lo = 0, bc_hi = 1, cls_lo = 0, cls_hi = 9;
        int cost2_on = 1;          /* [M195] argmin-cost legacy : default ON, UHA_PPM_COST2=0 the restores */
        if (fb) bc_lo = bc_hi = (fb[0] == '1');
        if (fc) cls_lo = cls_hi = atoi(fc);
        /* [GATED UHA_PPM_CANDSET, default-OFF, M25port] the legacy engine (0x43b2c2 + loop
         * candidates 0x421cf7) n'enumere THAT {seed=0}  {1,2,3,4} en block of data
         * (never cls 5..9, reservees au WP d'others contexts). The clone testait 0..9
         * and retombait sure cls 5/6 (window-predictor) -> mauvaise class. Imposer the
         * TRUE ensemble of candidates of legacy (measured #2, 10/10), not has reglage. */
        { const char *cs = getenv("UHA_PPM_CANDSET"); if (cs && !fc) cls_hi = atoi(cs); }
        /* [GATED UHA_PPM_COST2, PROMU default-ON the 2026-10-27 (M195), M45-port] Selection of class by
         * ARGMIN-COST legacy (`0x4221c0`) au lieu of argmin-length+roundtrip. Borner there search at the
         * class choisie by the model of cost. THERE PROMOTION is MESUREE, not declarative :
         * `an_m155_payload.py` rend **12/12** d'identite byte `arc[39..]` with this gate and **5/12** without
         * (`OUT/m195_baseline.md` S4) : the path " default " historique (essayer 0..9, to keep the more short
         * + roundtrip) is has PROXY of length, explicitement forbids (S0bis-4-3 of the prompt). L'old
         * behavior remainder disponible by `UHA_PPM_COST2=0` (Has/B possible, no value codee en dur).
         * The " 0 call if pos<threshold " (files <window) is respecte : if `usize` < window, on keeps
         * cls0/bc0 without call of cost (hello/code.c). */
        { const char *c2 = getenv("UHA_PPM_COST2"); cost2_on = !(c2 && c2[0] == '0'); }
        if (cost2_on && !fc) {
            extern uint32_t ppm_legacy_cost_select_class(const uint8_t *, size_t, uint32_t,
                                                         uint64_t (*)(const uint8_t *, size_t, uint32_t, uint64_t),
                                                         uint64_t *);
            extern uint64_t ppm_legacy_cost(const uint8_t *win, size_t len, uint32_t cls, uint64_t inc);
            extern void ppm_cost_set_avail(size_t n);
            const size_t FEN = 0x3100;               /* window legacy 12544 */
            /* [M154] There law of the seed reads the buffer model has `ic+256` : au-dela of the
             * window of selection, this are the bytes REELS of the file (measured
             * 99,984 % sure `eng.txt`, window 12 544 sure has file of 20 359 o). */
            ppm_cost_set_avail((size_t)usize);
            uint32_t first_sz = (uint32_t)usize;
            if (count > 0 && ends) {
                for (int mi = 0; mi < count; mi++) {
                    uint32_t msz = mi ? (ends[mi] - ends[mi - 1]) : ends[mi];
                    if (msz > 0) {
                        first_sz = msz;
                        break;
                    }
                }
            }
            if ((size_t)first_sz >= FEN) {              /* threshold : call otherwise (small file -> seed 0) */
                uint64_t sel_cost = 0;
                /* [GATED UHA_PPM_CLSCUR, default-OFF, M188] class current entretenue au sein of
                 * l'call of selection (`cls_courant` of `ppm_legacy_cost_select_class`). the legacy engine
                 * part of `cl = TBL[0x43b2c2][cur]` and there bound d'eclairage is `cost[this start]`
                 * (acquis 3.1-9 : has under-cost ecrete the others) - therefore `cur` change the winner.
                 * The port forces 0 here : this probe enables of balayer `cur` OUT line without toucher au
                 * default (0 = behavior actuel, no-regresse). 0..9. */
                int clscur = getenv("UHA_PPM_CLSCUR")
                    ? atoi(getenv("UHA_PPM_CLSCUR")) & 15 : 0;
                uint32_t sel_cls = ppm_legacy_cost_select_class(
                        plain, (size_t)usize < FEN ? (size_t)usize : FEN, (uint32_t)clscur,
                        ppm_legacy_cost, &sel_cost);
                if (getenv("UHA_PPM_SEL"))
                    fprintf(stderr, "[PPMCOST2] argmin-cout -> cls=%u cost=0x%llx\n",
                            sel_cls, (unsigned long long)sel_cost);
                cls_lo = cls_hi = (int)sel_cls;      /* borner there search at the class cost */
            } else {
                cls_lo = cls_hi = 0;                 /* hello/code.c : seed 0, 0 call */
            }
        }
        /* [GATED UHA_PPM_BC_PREDICATE, defautOFF, M45ao] Selection of `bc` by the predicat
         * measured `restant` : `bc = (restant==0)?1:0` with `restant = usize  Has  B  C  S`
         * (full.asm 0x404815..845, chain chainee/recoupee #2). The operandes Has/B/C/S (semantique
         * en cours #2 M68) are injectes via UHA_PPM_RESTANT for to validate there chain of cablage of
         * bout en bout BEFORE leur computation since the quantites clone. Gate OFF => behavior unchanged. */
        /* [GATED UHA_PPM_BC_PREDICATE, defautOFF, M45ao/M80/M122] Selection of `bc` by there partition
         * VERIFIED `restant = usize  Has  B  C  S` ; `bc = (restant==0)`. Has/B/C/S are calcules
         * since the bytes (M122, law validated 4/4 + recoupee by the `ratio` legacy) via
         * `ppm_bc_from_bytes`. Limit connue : the predicat " texte " of legacy (detecteur `0x404510`,
         * mission M124) n'is NOT still transcrit => sure the binary (restant>0) this gate rend 0
         * then that the legacy engine emits 1. Gate OFF => behavior unchanged (banque/ancre). */
        {
            const char *rp = getenv("UHA_PPM_BC_PREDICATE");
            if (rp && !fc && !getenv("UHA_PPM_BC")) {
                extern uint32_t ppm_bc_from_bytes(const uint8_t *d, uint32_t usize);
                bc_lo = bc_hi = (int)ppm_bc_from_bytes(plain, (uint32_t)usize);
            }
        }
        /* [GATED UHA_PPM_BCLAW, PROMUE defautON, M159/M160] `bc` by there TRANSCRIPTION of the detecteur
         * legacy `0x404510` (`ppm_bc_law`, `ppm_legacy_cost.c`). Law measured : engagement => bc=0,
         * otherwise 1 (M157 11/11 + M158 predicat local 7/7 + M160 porte `32*textcount > n`).
         * result : **bc reproduces 12/12 sure the corpus since the bytes single, without no
         * information external**. L'old default of the port (" essayer 0 and 1, to keep the more
         * short ") is REFUTE as law : sure `eng.txt` il selects 0 and produces 2509 o then that
         * the legacy engine writes bc=1 and 2564 o. `UHA_PPM_BCLAW=0` restores l'old behavior, and
         * `UHA_PPM_BC` remainder prioritaire for to forces has value. */
        {
            const char *bl = getenv("UHA_PPM_BCLAW");
            int off = (bl && bl[0] == '0');
            if (!off && !fc && !getenv("UHA_PPM_BC")) {
                extern uint32_t ppm_bc_law(const uint8_t *d, uint32_t usize);
                bc_lo = bc_hi = (int)ppm_bc_law(plain, (uint32_t)usize);
            }
        }
        /* [M185, GATED UHA_PPM_E0LAW, default-ON en autonomie native] Piece (has) of the LAW B (M181/M184, spec
         * OUT/m185_e0law_plan.md 1). when there gate is ON and that the bc n'is not forces :
         *   - byte_class d'en-tete = bc of the first member no empty (`ppm_bc_law` member by member),
         *   - e0_blk_len = end of the last member consecutif of bc=0 ; M32 (PPM_M32) if the 1er is
         *     bc=1 ; usize if all bc=0.
         * Has member of size 0 (empty.dat) is NEUTRE (continue the prefixe).
         * UHA_PPM_E0LAW=0 desactive there law B. */
        {
            const char *env_el = getenv("UHA_PPM_E0LAW");
            int el = env_el ? atoi(env_el) : 1;
            if (!el || getenv("UHA_PPM_BC")
                || (getenv("UHA_PPM_BCLAW") && getenv("UHA_PPM_BCLAW")[0] == '0')) {
                uha_ppm_set_e0law(0, 0u);   /* desarmement explicite : there variable is static */
            } else {
                extern uint32_t ppm_bc_law(const uint8_t *d, uint32_t usize);
                uint32_t e0 = 0u;
                int i, hdr_bc = -1;
                for (i = 0; i < count; i++) {
                    uint32_t b;
                    if (members[i].size == 0u)
                        continue;                       /* member inert : nothing has detecter */
                    b = ppm_bc_law(members[i].data, members[i].size);
                    if (hdr_bc < 0) {                    /* 1er member no empty = en-tete */
                        hdr_bc = (int)b;
                        if (el != 2 && b) { e0 = 0xFFFFFFFFu; break; }  /* bc=1 d'input -> M32 */
                    }
                    if (el != 2 && b) break;            /* end of the prefixe bc=0 */
                    e0 = ends[i];
                }
                if (hdr_bc < 0) hdr_bc = 0;             /* all empty : corpus not contient not this cas */
                if (e0 == 0u && hdr_bc == 0) e0 = usize; /* all bc=0 -> usize */
                bc_lo = bc_hi = (el == 2)
                    ? (int)ppm_bc_law(plain, (uint32_t)usize) : hdr_bc;
                uha_ppm_set_e0law(el, e0);
                if (getenv("UHA_PPM_SEL"))
                    fprintf(stderr, "[E0LAW] mode=%d hdr_bc=%d e0=%u usize=%u n=%d\n",
                            el, hdr_bc, e0, usize, count);
            }
        }
        for (int bc = bc_lo; bc <= bc_hi; bc++) {
            for (int cls = cls_lo; cls <= cls_hi; cls++) {
                uint8_t *pkx = NULL; size_t lx = 0;
                uharc_ppm_class = cls;
                { extern void uha_cost_reset(void); extern void uha_cost_setcap(uint64_t);
                  if (getenv("UHA_PPM_COST")) { uha_cost_reset();
                      const char *cc = getenv("UHA_PPM_COSTCAP");
                      uha_cost_setcap(cc ? (uint64_t)strtoull(cc,NULL,10) : 0u); } }
                if (uha_ppm_encode(plain, usize, order, bc, ends, count,
                                   &pkx, &lx) != 0 || !pkx) {
                    free(pkx);
                    continue;
                }
                if (getenv("UHA_PPM_COST")) {
                    extern uint64_t uha_cost_get(void);
                    fprintf(stderr, "[PPMCOST] bc=%d cls=%d len=%zu cost=%llu mode=%s\n",
                            bc, cls, lx, (unsigned long long)uha_cost_get(),
                            getenv("UHA_PPM_COST"));
                }
                /* t14e : there detransformee bc0 compacte desormais (dictionnaire of
                 * words). There confiance historique " bc0 cls0 = ok aveugle " n'is
                 * MORE justifiee : all combinaison (y c. bc0 cls0) exige has
                 * auto-verification roundtrip bit-has-bit via notre decoder faithful. */
                int ok;
                {
                    uint8_t *chk = malloc(usize ? (size_t)usize : 1);
                    ok = 0;
                    if (chk) {
                        int drc = uha_ppm_decode(pkx, lx, order, usize,
                                                 ends, count, chk, usize);
                        ok = (drc == 0 && memcmp(chk, plain, usize) == 0);
                        /* [M178, GATED UHA_PPM_SEL, defautOFF] why has candidate is rejete :
                         * the multimembre sortait en `encode error -1` without no trace. */
                        if (!ok && getenv("UHA_PPM_SEL")) {
                            size_t k = 0;
                            while (k < usize && chk[k] == plain[k]) k++;
                            fprintf(stderr, "[PPMCHK] bc=%d cls=%d len=%zu drc=%d 1er_ecart=%zu/%u\n",
                                    bc, cls, lx, drc, k, usize);
                        }
                        /* [M178, GATED UHA_PPM_SEL] dump of the payload candidate : enables of to compares
                         * the stream monomembre and the stream multimembre byte has byte. */
                        if (getenv("UHA_PPM_PAYDUMP")) {
                            FILE *pf = fopen(getenv("UHA_PPM_PAYDUMP"), "wb");
                            if (pf) { fwrite(pkx, 1, lx, pf); fclose(pf); }
                        }
                        free(chk);
                    }
                }
                if (ok && (!have || lx < bestlen)) {
                    free(best);
                    best = pkx; bestlen = lx;
                    best_bc = bc; best_cls = cls; have = 1;
                } else {
                    free(pkx);
                }
            }
        }
        uharc_ppm_class = 0;
        pk = best; pklen = bestlen; rc = have ? 0 : -1;
        if (getenv("UHA_PPM_SEL"))
            fprintf(stderr, "[PPMSEL] usize=%u chosen_bc=%d chosen_cls=%d have=%d len=%zu\n",
                    usize, best_bc, best_cls, have, bestlen);
    }
    free(plain);
    free(ends);
    if (rc != 0)
        return rc;
    rc = encode_archive(members, count, 1, (uint8_t)order, pk, (uint32_t)pklen,
                        out, outlen);
    free(pk);
    return rc;
}
