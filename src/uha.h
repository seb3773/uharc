#ifndef UHA_H
#define UHA_H

#include <stdint.h>
#include <stddef.h>

/*
 * Minimal UHARC 0.6b format handling.
 *
 * On-disk archive layout:
 *   [0..38]        fixed 39-byte header (bytes 4..34 XOR-obfuscated)
 *   [39..39+psize) packed stream for the (solid) data
 *   [..]           file_count * 4 bytes of per-file CRC32 (THE)
 *   [..]           names block  (S-box scrambled, then LZP order 17)
 *   [..]           attrs block  (S-box scrambled, then LZP order 17)
 */

#define UHA_SIG_LEN      3
#define UHA_HDR_LEN      39
#define UHA_ORDER_STORE  0
#define UHA_ORDER_RLE    1
#define UHA_ORDER_LZ78_MIN 2
#define UHA_ORDER_LZ78_MAX 7
#define UHA_ORDER_LZP_MIN 8
#define UHA_ORDER_LZP_MAX 23
#define UHA_ORDER_PPM_MIN 24
#define UHA_ORDER_PPM_MAX 39
#define UHA_ORDER_ALZ_MIN 40
#define UHA_ORDER_ALZ_MAX 87

typedef struct {
    uint8_t  version;         /* raw[3] */
    uint8_t  family;          /* 0 = store, 1 = ALZ/PPM/EXE, 2 = MM, 3 = EXE+MM */
    uint8_t  order;           /* selects the codec */
    uint8_t  flags;           /* dec[8]: 0x02 payload pw, 0x04 header pw */
    uint16_t ndirs;           /* dec[11..12]: unique directory count */
    uint16_t w33;             /* dec[33..34]: low16(CRC32(aux_plain || names_plain)) */
    uint16_t w35;             /* dec[35..36]: low16(CRC32(attrs_plain[0..11*fc])) */
    uint16_t check16;         /* raw[37..38]: low16(CRC32(dec[4..34])) */
    uint32_t usize;           /* total unpacked size of all members */
    uint32_t psize;           /* packed size of the data stream */
    uint32_t file_count;      /* number of members */
    uint32_t names_unpacked;
    uint32_t names_packed;
    uint32_t attrs_packed;
    size_t   header_ofs;      /* 0 for .uha, or offset of UHA header in SFX .exe */
    size_t   data_ofs;        /* header_ofs + 39 */
    size_t   crc_ofs;         /* data_ofs + psize */
    size_t   names_ofs;       /* crc_ofs + file_count * 4 */
    size_t   attrs_ofs;       /* names_ofs + names_packed */
} uha_header;

typedef struct {
    char    *name;
    uint32_t size;
    uint32_t psize;           /* 0 for solid archives (per-member packed size not stored) */
    uint32_t crc;             /* per-member CRC32 from the crc table (h.crc_ofs + 4*f) */
    uint16_t dos_date;        /* MS-DOS packed date */
    uint16_t dos_time;        /* MS-DOS packed time */
    uint8_t  dos_attr;        /* MS-DOS file attributes (0x01=RO, 0x20=Archive) */
    uint8_t  has_crc;         /* 1 if crc field was decoded */
} uha_entry;

typedef struct {
    uha_entry *items;
    int        count;
} uha_entrylist;

/* Parse and of-obfuscate the 39-byte header. Returns 0 on success. */
int  uha_parse_header(const uint8_t *raw, size_t rawlen, uha_header *h);

/* Decode the names + attribute blocks into has member list. */
int  uha_read_entries(const uint8_t *raw, size_t rawlen, uha_entrylist *out);
void uha_entrylist_free(uha_entrylist *l);

/* Human-readable codec label for has header. */
const char *uha_codec_name(const uha_header *h);

/* CRC-32 helpers. */
uint32_t uha_crc32(const uint8_t *buf, size_t len);

/*
 * Decode the solid payload into `out` (must hold at least h->usize bytes).
 * Returns 0 on success.
 */
int uha_decode_payload(const uint8_t *raw, size_t rawlen,
                       const uha_header *h,
                       const uha_entrylist *entries,
                       uint8_t *out);

#endif /* UHA_H */
