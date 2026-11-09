#include <string.h>
#include "alz_priv.h"

void alz_state_reset(alz_state *s)
{
    int i;

    memset(s, 0, sizeof(*s));
    s->side_primary = 1;
    s->side_secondary = 0;
    for (i = 0; i < 16; i++) {
        s->slot_hash[i] = 0xFFFFFFFFu;
        s->slot_dir[i] = 0;
    }
    /* t15d - fidelite strict UHARC (cause root t14f) : the stream reels
     * initialisent recent_distance[] has 0 ; all gap (ex. init has 1 +
     * normalisations 0->1) does diverger enc/dec sure has slot never tourne.
     * Has slot has 0 n'is never candidate (alz_find_match) and not peut therefore
     * never to be emits ; the decodeur not rencontrera 0 that if the stream en
     * emits has (the notre n'en emettra never). */
    for (i = 0; i < ALZ_MAX_RECENT; i++)
        s->recent_distance[i] = 0;
}

void alz_remember_distance(alz_state *s, uint32_t dist)
{
    int i;

    if (dist == 0)
        return;
    for (i = ALZ_MAX_RECENT - 1; i >= 1; i--)
        s->recent_distance[i] = s->recent_distance[i - 1];
    s->recent_distance[0] = dist;
}

uint32_t alz_recall_distance(alz_state *s, int slot)
{
    int i;
    uint32_t d;

    if (slot < 0)
        slot = 0;
    else if (slot >= ALZ_MAX_RECENT)
        slot = ALZ_MAX_RECENT - 1;
    d = s->recent_distance[slot];
    if (d == 0)
        d = 1;
    for (i = slot; i >= 1; i--)
        s->recent_distance[i] = s->recent_distance[i - 1];
    s->recent_distance[0] = d;
    return d;
}
