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
    /* t15d — fidelite stricte UHARC (cause racine t14f) : les flux reels
     * initialisent recent_distance[] a 0 ; tout ecart (ex. init a 1 +
     * normalisations 0->1) fait diverger enc/dec sur un slot jamais tourne.
     * Un slot a 0 n'est jamais candidate (alz_find_match) et ne peut donc
     * jamais etre emet ; le decodeur ne rencontrera 0 que si le flux en
     * emet un (le notre n'en emettra jamais). */
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
