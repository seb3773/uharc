#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ppm_priv.h"

/* [GATED UHA_DETRDUMP, defautOFF, M122k] Dump of the symbolisation choisie by notre
 * inverse : `pos  sym  k  flag_avant  flag_apres`. Sert has to compare NOTRE transformee
 * aller has the one of legacy (lue en decodant son archive) - analyse single. */
static FILE *detr_dump_fp(void)
{
    static FILE *fp = NULL;
    static int tried = 0;
    if (!tried) {
        const char *p = getenv("UHA_DETRDUMP");
        tried = 1;
        if (p && p[0])
            fp = fopen(p, "w");
    }
    return fp;
}

int ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                     uint8_t *out, uint32_t *nout);
int ppm_detr_inverse_greedy(const uint8_t *in, uint32_t len,
                            uint8_t *out, uint32_t *nout);

int ppm_detr_inverse(const uint8_t *in, uint32_t len,
                     uint8_t *out, uint32_t *nout)
{
    /* [GATE UHA_DETR_EXACT, M162] Transformee ALLER of legacy (site 0x420c20),
     * " first candidate of the liste by byte initial " + capitalisation 0x63.
     * Measures : 618873/618873 nodes of GT (an_m162_forward_gt.py).
     * value 0 = old heuristique gloutonne (historique). */
    static int exact = -1;
    if (exact < 0) {
        const char *e = getenv("UHA_DETR_EXACT");
        exact = e ? atoi(e) : 1;
    }
    if (exact)
        return ppm_detr_forward(in, len, len, out, nout);
    return ppm_detr_inverse_greedy(in, len, out, nout);
}

int ppm_detr_inverse_greedy(const uint8_t *in, uint32_t len,
                            uint8_t *out, uint32_t *nout)
{
    ppm_detr d;
    uint32_t pos, n;
    int zeros;
    uint32_t cap;

    if (!in || !out || !nout)
        return 0;
    *nout = 0;
    if (len == 0)
        return 1;

    ppm_detr_init(&d);
    pos = 0;
    n = 0;
    zeros = 0;
    cap = len * 4 + 16;
    while (pos < len) {
        int s, best_s, best_k, ident;
        ppm_detr best_st, saved;
        int have;

        ident = (~in[pos]) & 0xFF;
        best_s = -1;
        best_k = -1;
        have = 0;
        saved = d;

        s = ident;
        {
            ppm_detr t = saved;
            uint8_t buf[256];
            int k = 0;
            ppm_detr_emit(&t, (uint8_t)s, pos, PPM_M32, len, buf, &k);
            if (k > 0 && k <= (int)(len - pos) && memcmp(buf, in + pos, (size_t)k) == 0) {
                best_s = s;
                best_k = k;
                best_st = t;
                have = 1;
            }
        }
        /* t14e : search GLOBAL of the match the more long. L'identite (k=1) n'is
         * more has short-circuit : without cela the symboles of the dictionnaire of words
         * (cls<0xC8 -> DetrStr*, 2-3 bytes/symbole) n'were never tries, and
         * l'encoder emetait nsyms=len au lieu of compacter (perte of ratio sure
         * small inputs textuelles type hello). L'identite remainder the meilleur
         * start (k>=1 garanti, no loop infinie) ; has symbole more long there
         * replaces. The stream emis is verified by memcmp -> roundtrip garanti. */
        {
            for (s = 0; s < 256; s++) {
                ppm_detr t = saved;
                uint8_t buf[256];
                int k = 0;

                if (s == ident && have)
                    continue;
                ppm_detr_emit(&t, (uint8_t)s, pos, PPM_M32, len, buf, &k);
                if (k == 0) {
                    if (have || zeros >= 2)
                        continue;
                    if (t.flag == saved.flag && t.arg == saved.arg)
                        continue;
                    best_s = s;
                    best_k = 0;
                    best_st = t;
                    have = 1;
                    continue;
                }
                if (k > (int)(len - pos))
                    continue;
                if (memcmp(buf, in + pos, (size_t)k) != 0)
                    continue;
                /* [GATED UHA_DETR_PREF, defautOFF, M122k] the legacy engine PREFERE has input of
                 * dictionnaire at the identite when the two emit there same length
                 * (`0x0a` -> sym 6, chain DetrStr "\n", au lieu of the raw 245). measured sure
                 * `code.c` : 4/4 newlines literals en sym=6 (the last byte of the file
                 * remainder 245 -> exception of end of stream has traiter separement). */
                { static int pref = -1;
                  if (pref < 0) { const char *e = getenv("UHA_DETR_PREF"); pref = e ? atoi(e) : 2; }
                  /* DEFAULT = 2 (rule measured, M122n) : more long match, **egalite -> smaller
                   * symbole** (identite incluse), **sauf sure the last byte** of the stream (the legacy engine
                   * y emits l'byte raw - GT `code.c`). Resultats : `code.c` byteidentical ;
                   * banc 6 textes : fd 3005->525, 829->62, 2996->48, 1819->43 ; no cas degrade.
                   * pref=1 : variante " preference dictionnaire " (REFUTEE, gardee for memory).
                   * pref=0 : old heuristique (identite winning has egalite) - historique. */
                  int take = 0;
                  if (!have || k > best_k)
                      take = 1;
                  else if (k == best_k) {
                      if (pref == 1 && s != ident && best_s == ident && pos + 1 < len)
                          take = 1;
                      else if (pref == 2 && s < best_s && pos + 1 < len)
                          take = 1;
                  }
                  if (take) {
                    best_s = s;
                    best_k = k;
                    best_st = t;
                    have = 1;
                  }
                }
            }
        }
        if (!have || best_s < 0 || n + 1 >= cap)
            return 0;
        { FILE *fp = detr_dump_fp();
          if (fp) fprintf(fp, "%u\t%d\t%d\t%d\t%d\n",
                          pos, best_s, best_k, saved.flag, best_st.flag); }
        out[n++] = (uint8_t)best_s;
        d = best_st;
        if (best_k == 0)
            zeros++;
        else {
            zeros = 0;
            pos += (uint32_t)best_k;
        }
    }
    *nout = n;
    return 1;
}
