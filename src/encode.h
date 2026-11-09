#ifndef UHA_ENCODE_H
#define UHA_ENCODE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const char *arcname;
    const uint8_t *data;
    uint32_t size;
    /* [M241] mtime Unix of the file source (stat), 0 = inconnu. Alimente the columns
     * date/heure DOS of the block `attrs` (law mesuree : OUT/m241_container.md S2). */
    uint32_t mtime;
    /* [FRONTIER] rank of the member in l'order of COMMANDE (argv). by default = index of
     * construction (identite) => behavior byte-identical without gate. Sets the `didx`
     * (column attrs 4*fc) when l'arrangement reordonne the members (UHA_FRONTIER=1). */
    uint32_t cmd_rank;
} uha_member;

int uha_encode_store(const uha_member *members, int count,
                     uint8_t **out, size_t *outlen);
int uha_encode_lzp(const uha_member *members, int count, int order,
                   uint8_t **out, size_t *outlen);
int uha_encode_alz(const uha_member *members, int count, int method_class,
                   uint8_t **out, size_t *outlen);
int uha_encode_ppm(const uha_member *members, int count, int order,
                   uint8_t **out, size_t *outlen);

#endif
