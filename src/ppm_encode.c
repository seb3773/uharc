#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ppm.h"
#include "ppm_priv.h"
#include "ppm_blocklen.h"
#include "ppm_legacy_cost.h"
#include "ppm_blk_cost.h"

/* [M170k] `0x43b290[cand]` = number of contexts by class, MEASURES au run (captures
 * OUT/m170l_tablesA/B/C.log, BP 0x4221c0) : 8, 32, 32, 96, 64, 4, 4, 8, 3, 5.
 * There table has 5 inputs not suffisait not : l'escape of `image` has pos 12 558 selects there
 * class 5. There table some bases `0x43b268[0..9]` = CLS_CTXBASE, verified by there same captures
 * (513, 521, 553, 585, 681, 745, 749, 753, 761, 764). */
static const uint32_t CLS_NCTX10[10] = { 8u, 32u, 32u, 96u, 64u, 4u, 4u, 8u, 3u, 5u };
static int ppm_blk_class(int cl, const uint8_t *w, uint32_t len);   /* define more low */

/* [M278, GATED UHA_FAMSITE, default-OFF, no emissif] NAME of the SITE active. The port has TWO blocks
 * which call the scan of cost of the family (`0x422d00`) and THREE which call
 * `ppm_blk_class_fw` : without marqueur, all correction of has term is has test empty (3.3-5).
 * `=1` imprime has line by call, `tag` = name of the site, `pos`/`len` = ses inputs. */
static void ppm_famsite(const char *tag, uint32_t pos, uint32_t len)
{
    static int on = -1;
    if (on < 0) { const char *e = getenv("UHA_FAMSITE"); on = (e && e[0] != '0') ? 1 : 0; }
    if (on)
        fprintf(stderr, "[FAMSITE] %s pos=%u len=%u\n", tag, (unsigned)pos, (unsigned)len);
}

/* [M170k, UHA_BLKLAW>=8] Machine d'state of the scan of cost (`0x423650` / `0x4232a0`) sure the
 * model live. L'appelant sauve/restores `*m` (machine sure COPIE : nothing n'is emis).
 * `raw` = byte of the stream in the domaine of the model (bh), `sym` = delta consumes (bl).
 * The flag of stack and `m->cls_neg` are the same registre : synchronises in the two direction. */
static void blk_scan_step(void *ud, ppm_blk_state *st, uint8_t raw, uint8_t sym)
{
    ppm_model *m = (ppm_model *)ud;
    /* [M279, GATED UHA_SCANSTEPSYM, default-OFF] TWO arguments, as l'ASM `0x4231e2` :
     * `al = bh` (byte of output, rolling ctx) and `dl = bl` (delta, machine of class). The port
     * passait `raw` to the TWO, this which basculait the flag of signe as soon as `raw - cls_base`
     * franchissait 0x80, same when the true delta not the franchissait not (measures M279 : `it=88`,
     * `raw=0`, `sym=128`, `cls_base=128` -> delta 0 but `0-128 = 0x80` basculait). */
    { static int ss = -1;
      if (ss < 0) { const char *e = getenv("UHA_SCANSTEPSYM"); ss = (e && e[0] != '0') ? 1 : 0; }
      m->cls_neg = st->flag ? 1u : 0u;
      if (ss)
          ppm_scan_step_sym(m, (int)raw, (int)sym);
      else
          ppm_scan_step(m, (int)raw);
    }
    st->last = m->cls_base;
    st->flag = m->cls_neg;
    st->ctx_abs = m->cls_ctx;
}

/* UHA_PPMTRACE (diagnostic t14c, has to remove) */
static int etrace_on = -1;
/* [M417/M423, GATED UHA_M417DBG, default-OFF, NO EMISSIF] Probe of departage (has)/(b) of the front
 * `-mx mixed.bin` (voir OUT/m417). Imprime the quartuplet (chg, ncls, in->base, famcl) by node,
 * en read-only : not mute NO state, n'emits NO byte (fprintf stderr only).
 * default-OFF => behavior strictement inchange (revifier `=0` after rebuild). */
static int m417dbg_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_M417DBG"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
static int et_route[8], et_match, et_mbytes;

/* [M169, GATED UHA_BLKLAW, default-OFF] law of cut of block of class.
 * Lot 1 : there CUT single (frontier = start + ppm_blocklen(...)) + reset of block, without there
 * selection of class (lot 2). But of the lot 1 : prouver that the reset of block is NEUTRE sure
 * the stream (the legacy engine has 6 blocks sure image.raw and l'archive is byte-identical).
 * State of transcription : OUT/m169_blocklen.md, OUT/m169_cutlaw.md, OUT/m169_families.md. */
static ppm_blocklen_ctx g_blc;

/* [M170, UHA_BLKLAW>=3] Order d'emission FAITHFUL : the test of cut of legacy (0x421973)
 * vit in the matchfinder, sure the path literal, BEFORE l'encoding of the class of the node
 * (0x4219a1). The decodeur reads escape -> sel -> class (for(;;) of ppm_lzp_decode_class),
 * therefore l'escape doit preceder there column of class : cf. OUT/m170_order.md.
 * State partage with ppm_blk_node_encode() (appele since ppm_mf.c). */
static const uint8_t *g_blk_raw;
/* [M243] stream of SYMBOLES (transformee `detr`) : there window of the master (`0x43a21c`) contient
 * some SYMBOLES, not the bytes raw. There walk family (`0x422d00`) reads this window for
 * `it < 0x100` (`0x42303b..0x423046`) and the bytes raw au-dela (`0x4231ac`). Measures M243 :
 * has `1 071 003` the node 0 of the master has `sym = 88` (= notre `tgt` of the stream) then that nous
 * lisions `167` = `image.raw[0]` raw => gap some the node 0. */
static const uint8_t *g_blk_sym;
static size_t g_blk_nsyms;   /* [M249] length of the buffer SYMBOLES (keeps of the window of l'estimator) */
extern long g_recg_calls;   /* [M211] diagnostic : calls of rec_globals */

/* [M208 GATED UHA_LENBOUND, default-OFF] bound EN SYMBOLES OF THE MEMBER.
 * Measures M208 : there window of the model is indexee en SYMBOLES (stream transforme `detr`), not en
 * bytes of output. the legacy engine bound there length of comparaison of the match by
 * `[0x4803cc]  [0x4803c0]` (0x421479..0x42148b) : the matches of the stream legacy ATTEIGNENT there end
 * of leur member en symboles (17 cas `marge = 0`, whose `out=45333`, `out=505621`, `out=697476`),
 * then that notre clone, bounded by there end of the STREAM, depasse of has symbole has `out=45333`
 * (`mlen = 4` au lieu of 3, single divergence of parse sure 4 033 decisions).
 * There transformation symbolebytes is `ppm_detr_emit` (already validated 618 873/618 873). */
static int64_t g_lenb_bound = -1;      /* bound win_pos of the member current ; -1 = OFF */

int64_t ppm_lenb_sym_bound(void)
{
    return g_lenb_bound;
}

static void lenb_compute(ppm_model *m, const uint8_t *raw, uint32_t start, uint32_t end)
{
    static int on = -1;
    uint8_t *tmp;
    uint32_t n = 0;

    if (on < 0) { const char *e = getenv("UHA_LENBOUND"); on = (e && e[0] != '0') ? 1 : 0; }
    if (!on || !raw || end <= start) {
        g_lenb_bound = -1;
        return;
    }
    tmp = malloc((size_t)(end - start) * 2u + 64u);
    if (!tmp) {
        g_lenb_bound = -1;
        return;
    }
    if (!ppm_detr_forward(raw + start, end - start, end, tmp, &n)) {
        free(tmp);
        g_lenb_bound = -1;
        return;
    }
    free(tmp);
    g_lenb_bound = (int64_t)m->win_pos + (int64_t)n;
}
static uint32_t g_blk_usize;
static uint32_t g_blk_next;
/* [M203, lu under UHA_PPM_BLKBOUND] bound HIGH of the block current in l'horloge d'emission
 * (= `next_boundary` of the node of `ppm_encode_core`, caps `e0_blk_len`/`detr_thr1` inclus). Publiee
 * systematiquement (no effect of reading out gate). GT M203 : `[0x4826d0]` = this bound to the 16
 * hits (817696 sure all the segment `biased`, 1136539 sure `image`). */
static uint32_t g_blk_bound;

static int g_blkbound = -1;
static int g_blkbound_on(void)
{
    if (g_blkbound < 0) {
        const char *e = getenv("UHA_PPM_BLKBOUND");
        g_blkbound = e ? atoi(e) : 1; /* [M497] Active by default en autonomie native */
    }
    return g_blkbound;
}
/* [M170h, UHA_BLKLAW>=6] CANDIDATE OF START of the next stage 1 = `[0x483934]` :
 *   initialise by l'init of member (0x416ad1) and RE-ARME by 0x421f81 (`al = [esp+0x20]`,
 *   c'is-has-dire the WINNER of l'stage 1) at each decision. GT M170h : start 0 at the
 *   decision 1 (image), then 3 = winner of the decision 1. */
static uint32_t g_blk_start;
/* [M170k] ctx RELATIF of the node 0 = `[0x4803c4] - CTXBASE[cl]` (measures : 68 at the decision 2
 * d'`image`). Not s'applies only to the  candidate equal at the class current. */
static uint32_t g_blk_initctx;
static int g_blklaw;

/* [M202, GATED UHA_PPM_SEEDLAG, default-OFF] MIRROR of the SEED at the HORLOGE D'EMISSION.
 * `g_blk_start` (mirror of `[0x483934]`) is re-arme by the decisions of block, which are
 * pilotees by `win_pos` (position d'write of the window, `ppm_mf.c` l.496) ; there FRONTIER,
 * elle, is evaluee sure `out_pos` (`ppm_encode_core` l.898). The TWO HORLOGES DIVERGENT :
 * measures `OUT/m202_seed_mirror.log` - to the 7 frontiers of `ALL`, there value raw of the mirror is
 * portee by has decision whose `start` is ALREADY AU-DELA of the frontier (3 divergences sure 4
 * exact : `2,2,0,3` contre GT `0,0,0,4,1,0,3` ; there seed GT = class of the member which FINIT,
 * `OUT/m201b_frontier_costs_confrontation.md` 2-2). Law retenue by there measures (3 of the same
 * livrable) : en frontier `p`, the master reads there last write anterieure SURE L'HORLOGE OF THE
 * STREAM, c'is-has-dire
 *   (has) there last decision parue since there frontier previous whose `start < p` ; otherwise
 *   (b) there class ecrite by there frontier previous (`0x421f81` sure the path frontier,
 *       acquis 3.1-19 of the prompt - the master writes also en frontier, therefore l'absence of
 *       decision between two frontiers not " fige " not the mirror : il porte l'write of
 *       frontier).
 * The two terms rendent 7/7 seeds GT (0,0,0,4,1,0,3). Gate OFF : `g_blk_start` raw, stream
 * bit-unchanged - the mirror d'horloge window n'is NOT touche (has variable at the fois). */
#define PPM_SEEDQ 64u
typedef struct { uint32_t seq, start, cl; } ppm_seed_evt;
static ppm_seed_evt g_blk_seedq[PPM_SEEDQ];
static uint32_t g_blk_seed_seq;      /* counter monotone some writes of decision */
static uint32_t g_blk_seed_mark;     /* `seq` au moment of the last frontier */
static uint32_t g_blk_seed_front;    /* class ecrite by there last frontier */
static int g_blk_seedlag = -1;

static int ppm_seedlag_on(void)
{
    if (g_blk_seedlag < 0) {
        const char *e = getenv("UHA_PPM_SEEDLAG");
        g_blk_seedlag = e ? atoi(e) : 0;
    }
    return g_blk_seedlag;
}

/* remise has zero of the mirror d'emission (start of stream, as `g_blk_start = 0`) */
static void ppm_seed_mirror_init(void)
{
    memset(g_blk_seedq, 0, sizeof(g_blk_seedq));
    g_blk_seed_seq = 0u;
    g_blk_seed_mark = 0u;
    g_blk_seed_front = 0u;
}

static void ppm_seed_mirror_push(uint32_t start, uint32_t cl)
{
    uint32_t k;
    g_blk_seed_seq++;
    k = g_blk_seed_seq % PPM_SEEDQ;
    g_blk_seedq[k].seq = g_blk_seed_seq;
    g_blk_seedq[k].start = start;
    g_blk_seedq[k].cl = cl;
}

/* value of the mirror telle that the master there voit at the instant of the frontier `p` */
static uint32_t ppm_seed_mirror_at(uint32_t p)
{
    uint32_t i, v = g_blk_seed_front;
    for (i = g_blk_seed_mark + 1u; i <= g_blk_seed_seq; i++) {
        uint32_t k = i % PPM_SEEDQ;
        if (g_blk_seedq[k].seq == i && g_blk_seedq[k].start < p)
            v = g_blk_seedq[k].cl;
    }
    return v;
}

/* there frontier `p` writes `cl` in `[0x483934]` (0x421f81) and closes the segment current */
static void ppm_seed_mirror_frontier(uint32_t cl)
{
    g_blk_seed_front = cl & 15u;
    g_blk_seed_mark = g_blk_seed_seq;
}

/* [M185, GATED UHA_PPM_E0LAW, default-OFF] Law B (`e0_blk_len` = end of the prefixe of members
 * `bc=0`, M181/M184). g_e0law = value of gate (atoi, 0 = OFF) ; g_e0law_val = `e0` arme by
 * encode.c. Arme by uha_ppm_set_e0law() ; lu by ppm_encode_core (emission (b) + promotion (c))
 * and by uha_ppm_encode (threshold thr2 of the symbolisation). Gate OFF : nothing not change. */
static int g_e0law = 0;
static uint32_t g_e0law_val = 0;

void uha_ppm_set_e0law(int mode, uint32_t e0)
{
    g_e0law = mode;
    g_e0law_val = e0;
}

/* [M195, GATED UHA_PPM_CLSFRONT, PROMUE default-ON (voir ppm_clsfront_mode)] class EMISE at each
 * FRONTIER (S5-1 of the prompt of
 * reprise ; spec and lines figees : OUT/m195_frontier_class_plan.md).
 * State of the port BEFORE this gate : `ppm_block_reset_encode()` (ppm_model.c l.438-457) emis
 * `uharc_ppm_class`, value choisie once for the buffer entier by there loop of candidates of
 * `encode.c` (l.843) - now `[BLKCLS] cls=0` to the 8 frontiers of `ALL` (4/8) then that there carte
 * legacy is `0-1-0-4-1-0-0-5` (8/8, lue by notre clean decodeur, double canal M192/M193).
 * There decision of frontier existe already in the port : c'is l'call measures by
 * `t188_tailclass.sh` (7/8 out line), rendu here by there same couture of function.
 *   mode 1 = geometrie " FILLE ", identical bit has bit has the one of the judge : queue [p, usize) as
 *            unique buffer, prectx = 0, bandbase = 0, avail = usize - p, flag d'input = 0.
 *   mode 2 = geometrie " EN STREAM ", states d'input measurements of l'estimator (M170k) : prectx =
 *            the 4 bytes reels before p, bandbase = p, initctx = `cls_ctx - CTXBASE[cl]`.
 * The TWO are has to measure contre the judge, no n'is postule. thresholds respectes : `remainder < 0x3100`
 * ==> 0 call and class global (law " files < window "). There CANDIDATURE OF THE SCAN (`g_blk_start`,
 * re-armement 0x421f81 at the stage 1) n'is NOT touchee : elle prepare the block next, elle n'is
 * not this which is emis. Gate OFF (default) : there function n'is not appelee, stream bit-inchange. */
/* [M219, GATED UHA_CLSFULL, default-OFF] chain OF class OF FRONTIER COMPLETE, en Has gate.
 * The prompt M219 5-1 demande of porter `0x42201a argmax -> cb -> chg -> 0x422d00 families ->
 * 0x421f81 write` in `ppm_frontier_class`. This chain y is already (mode 5), but elle was
 * eclatee en three gates mesurees separement by M202/M203 : the mode (`CLSFRONT`), there provenance
 * some tables (`FENBLAW`) and the veto of the family (`FAMVETO`). Now the desassemblage slice :
 *   0x421c56 call 0x426bf0(len-0x100)   ; recharge of the window
 *   0x421c5b roulage t <- t5            ; (without effet : 0x422890 resets the two has zero)
 *   0x421c99 ja 0x421ff0 -> 0x421ffa call 0x422890(window, len-0x100) ; `ebp = eax`
 *   0x421ca5..0x421d06                  ; 5 costs, argmin, cb
 *   0x421d5f / 0x42201a                 ; stage 1 / stage 2
 *   0x421d9f / 0x4220ac call 0x422d00   ; family, with `ebx = cost[cl]` for bound
 *   0x421da6 je 0x4220c9                ; family rend 0 -> NO changement
 *   0x421dae / 0x423185                 ; write of the class
 * => the three gates are the three stages of has SINGLE function legacy : `UHA_CLSFULL=1` the arme
 * ensemble (mode 5 + tables fraiches + veto). `UHA_PPM_CLSFRONT`, `UHA_PPM_FENBLAW` and
 * `UHA_PPM_FAMVETO` keep there priorite when ils are poses explicitement (Has/B has variable). */
static int ppm_clsfull_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_CLSFULL"); v = e ? (e[0] != '0') : 1; }
    return v;
}

static int ppm_clsfront_mode(void)
{
    static int cf = -1;
    /* [M195, PROMU default-ON the 2026-10-27] Reason MEASURES (`OUT/m195_frontier_class.md`) : mode 1 rend
     * there carte some classes EMISES en stream `0-1-0-4-1-0-0-3` = **7/8** contre there carte legacy
     * `0-1-0-4-1-0-0-5` (and there reconduction silencieuse of `937 696` sort naturellement), there gate OFF
     * rendant `cls=0` to the 8 frontiers (4/8). No judge closes moves : 12/12 mono, 22/22 costs,
     * 618 873/618 873, 15/15 [BLKCOST], carte [BLOCK] 7/7. Single restant : the `5` of `1 071 003`,
     * whose NO auteur n'is localise (forbids of bricoler) - consigne 5-1 " Forbids ".
     * `UHA_PPM_CLSFRONT=0` restores the behavior historique (Has/B), `=2` keeps there probe " en stream "
     * (measured : 6/8, elle casse `305 696`).
     * [M195 suite has M195] Default toggles of 1 has **4** (measures, not preference) : there carte some
     * frontiers lue in the ARCHIVES SAME of legacy (notre decodeur, canal independant) is there class
     * CLEAN of the member which commence (0,1,0,4,1,0,0 + image.raw 3 ; carte 5 au last). The mode 4 rend
     * bit for bit the same 7/8 that the mode 1 SURE `ALL`, but with there GEOMETRIE of the path mono clos
     * (`avail` = size of the member, no of the queue) : there law is therefore expliquee, not juste reproducee.
     * The 4 modes restent atteignables (1 queue/fille, 2 queue/stream, 3 member/stream, 4 member/fille). */
    if (cf < 0) { const char *e = getenv("UHA_PPM_CLSFRONT");
        if (e) cf = (e[0] == '0') ? 0 : atoi(e);
        else   cf = ppm_clsfull_on() ? 5 : 4; }
    return cf;
}

/* 4 bytes reels precedant `p`, complementes, the more recent en weight faible (`[0x48269c]`). */
static uint32_t ppm_precx_at(const uint8_t *raw, uint32_t p)
{
    if (p < 4u)
        return 0u;
    return ((uint32_t)((~raw[p - 1u]) & 0xffu))
         | ((uint32_t)((~raw[p - 2u]) & 0xffu) << 8)
         | ((uint32_t)((~raw[p - 3u]) & 0xffu) << 16)
         | ((uint32_t)((~raw[p - 4u]) & 0xffu) << 24);
}

static uint32_t member_fin_at(uint32_t p, const uint32_t *member_ends, uint32_t nmembers,
                              uint32_t *fin)
{
    uint32_t f;
    if (!member_ends || !nmembers)
        return 0u;
    for (f = 0; f < nmembers; f++)
        if ((f ? member_ends[f - 1] : 0u) == p) {
            if (member_ends[f] <= p)
                return 0u;                    /* member empty : neutre, to keep there geometrie queue */
            *fin = member_ends[f];
            return 1u;
        }
    return 0u;
}

/* [M203, GATED UHA_PPM_FAMVETO, default-OFF] VETO of the FAMILY SURE THE path OF FRONTIER.
 * The path instream (`ppm_blk_node_encode`, UHA_BLKLAW>=8) has ALREADY transcrit the scan
 * `0x422d00..0x423245` and sa rule : " there family rend there class " is FALSE, `al = class` SSI
 * `ebp < bound` (`0x423199 cmp ebp,ecx ; jae 0x42323d -> xor al,al`). There recopiee of the mode 5
 * (`ppm_frontier_class`) appelait `ppm_blk_class()` without this scan : elle transformait therefore there now
 * the master cancels. Measures M203 : has `505 696`, the master pass the test d'stage 1 (`39*655360 >
 * 65536*64`), calls there family (cl 4 -> 9) and REND 0 (veto) - there carte porte `4`, not `9`.
 * This function replays EXACTEMENT the same call that the path instream (same inputs d'state,
 * arena rechargee since the master live, machine sure COPIE of `*m` then restitution : nothing
 * n'is emis). Return : 1 = the master annulerait (`ebp >= bound`), 0 = there class is rendue. */
/* [M219] arena OF FRONTIER PARTAGEE. The master has only Has buffer of travail (0x43a264,
 * 96 lines * 256 words) : l'estimator `0x4221c0` the nourrit (0x422262) then the MUTE node by
 * node, and the scan of family `0x422d00` writes in the same buffer (0x4231bd/0x4231d0). Notre
 * port en had three copies (estimator instream, estimator of frontier, scan family),
 * therefore no historique. This arena unique is partagee by `ppm_frontier_live_class` and
 * `ppm_family_veto` (gate `UHA_PPM_VETONOFEED` : the veto not recharge more). Default : unchanged. */
static ppm_cost_arena *g_farena;

static int ppm_vetonofeed_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_VETONOFEED"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M219, GATED UHA_PPM_ONEARENA, default-OFF] arena UNIQUE PERSISTANTE. The master has only has buffer
 * (0x43a264 freq, 0x43a26c totals, 0x43a270 escape), never remis has zero : l'estimator `0x4221c0`
 * the nourrit for the SINGLE candidate equal has `[0x483934]` (0x422226 `jne 0x42230e` = nor state d'input
 * nor feed) then the mute node by node, and the scan of family `0x422d00` reads/writes the same buffer
 * (0x42308a `esi = [0x43a264]` ; 0x4231c1 `add WORD [cellule],if`). The port en had THREE copies
 * distinctes, therefore no historique : this gate the reunit. Default OFF : nothing not change. */
static ppm_cost_arena *g_onearena;

static int ppm_onear_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ONEARENA"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

static ppm_cost_arena *ppm_one_arena(void)
{
    if (!g_onearena)
        g_onearena = (ppm_cost_arena *)calloc(1, sizeof *g_onearena);
    return g_onearena;
}

/* [M244, GATED UHA_PPM_ESCANY, default-OFF] LAW D'EMISSION OF L'ESCAPE (`0x4220da`).
 * `0x421dd8` is there seconde moitie of the frontier : there class CANDIDATE (`[esp+0x20]`, posee some
 * l'input has TBL[0x43b2c2][cur], then argmin of cost of l'stage 1, then verdict family) is
 * comparee has `[0x483934]` (`cmp al,[0x483934] ; jne 0x421dcb`) and l'escape part as soon as the two
 * different - there family n'is only to  some sources of the candidate. The port n'emits that if `chg`
 * (family), therefore il manque the escapes "candidate = argmin pur" : cas measures of the master 0 -> 3 has
 * `972 004`, now `0x423152` not frappe NEVER. Cf. OUT/m244_escape_asm.md. Default OFF : inchange. */
/* [M274, GATED UHA_PPM_ET2, default-ON, =0 neutralise] STAGE 2 of the selecteur of class
 * (`0x42201a..0x4220c2` : argmax `t5[1..4]` then `(t5[has]<<6) > fact*t5[0]`, `fact` = 0x41/0x50
 * + (0x0A-cb)*4). Test Has Has VARIABLE of the front localise : at the cut `start=937 440`
 * (len=256, last block of `random.bin`) the 5 costs give l'argmin 0, l'stage 2 toggles
 * `cl` has 2 (t5[2]=7570 is the max), there FAMILY rend 7, l'escape part and the corps diverge some
 * son first byte (`firstdiv = 178 540` = `out` of this cut) then that the master code there
 * class 0 (`m256_route.tsv`, `cls_m=0`). `=0` = stage 2 neutralise (cl remainder l'argmin). */
static int ppm_et2_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ET2"); v = (e && e[0] == '0') ? 0 : 1; }
    return v;
}

/* [M274, GATED UHA_PPM_ET2THR, default -1 = no threshold] threshold OF length of l'stage 2 :
 * `len <= threshold` -> stage 2 NO applies (cl remainder l'argmin). Motivation MESUREE : at the cut
 * `start=937 440` (`len = 256`) l'stage 2 toggles at the class 2/7 then that the master code 0 ;
 * `UHA_PPM_ET2=0` repousse the 1er `cand != cls_lue` of 937 440 has 1 083 561 and the corps of
 * 178 540 has 183 131, but casse the mono (payload 12/12 -> 11/12) : l'stage 2 is therefore requis
 * ailleurs. There single difference mesurable of the cut is `len = 256 = 0x100`. */
static long ppm_et2_thr(void)
{
    static long v = -2;
    if (v == -2) { const char *e = getenv("UHA_PPM_ET2THR"); v = (e && e[0]) ? atol(e) : -1; }
    return v;
}

static int ppm_escany_on(void)
{
    static int v = -1;
    /* [M244 law ASM 0x4220da, PROMUE the 2026-10-29] L'escape is emis as soon as the CANDIDATE differe
     * of the class current (`cand != [0x483934]`), that there family ait parle now no. Bloqueur
     * jusqu'here : l'escape parasite sure the mono `records.bin` (19 088 contre 19 083 o legacy) -
     * cause corrigee en M254b (regard loop au bord of the seed). Measures with there gate ON :
     * payloads mono **12/12 byte-identical**, archive 12 members 260 239 -> **191 350**
     * (legacy 191 159), firstdiv **2 913 -> 1 319**, round-trip 12/12, parse decision inchange.
     * `UHA_PPM_ESCANY=0` = behavior historique (escape only sure verdict of family). */
    if (v < 0) { const char *e = getenv("UHA_PPM_ESCANY"); v = (e && e[0] == '0') ? 0 : 1; }
    return v;
}

/* [M330, GATED UHA_PPM_FAMADV, default-OFF] REPLI of the WALK when ELLE RENTRE 0.
 * Law rendue by `re_asm/OUT/m330_cls_terminal.md` 1.3 and accreditee by there captures runtime
 * `arena2d_re/OUT/m328_*` : there walk `0x422D00` is APPELEE in all the cas (porte of densite
 * `0x421d8c` franchie au block terminal : `q = (cost[cl]/len)/0x249 = 12`, bounded has 10 by
 * `0x421d1e/0x422006` => weight `80` > `64`), but sa output `0x423199 cmp ebp,ecx / jae 0x42323d`
 * rentre **`al = 0`** (" no laureat ") when son cost cumule atteint the budget recu en
 * `0x421d96 -> 0x422d0e` (= `cost[cl]`, the cost incumbent of the class D'STAGE 1). in this cas
 * `0x421da8 je 0x4220c9` skips l'write `0x421dae` : **`[esp+0x20]` preserves there value d'stage 1**
 * (`TBL[0x43b2c2][current]` raffine by the grimpeur strict `0x421cf3`), and c'is this value that
 * `0x4220de` compares has `[0x483934]`.
 *  This which manquait au port n'was therefore NOT l'estimation (already conforme : `init = TBL[cur]` under
 * `UHA_PPM_INILAW`, grimpeur strict, `bud = cost[cl]`) but **the repli** : il rendait the laureat of
 * there walk without condition and, laureat == current => no tete ; the master, lui, retombe sure
 * l'stage 1. Cas measured : block terminal of 255 o (`pos 1 136 284`, `arg = 56`) - laureat `5` ==
 * current `5` but stage 1 `TBL[5] = 1` => **escape inserts, `sel = 1`** ; epreuve `UHA_LZP_ESC=
 * "1136284:56:1"` => size **191 159 = GT**, payload/crc/names **0 diff**, **RT 12/12**, and the 15
 * bytes of the master (`fc 00 52 74 a5 39 c4 01 4b 8e cd 61 5b d1 0a`) reproduits at the identical.
 * Gate OFF : behavior historique strictement unchanged (no emission, `return 0`). */
static int ppm_repli_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_FAMADV"); v = e ? (e[0] != '0') : 1; }
    return v;
}

/* [M245, GATED UHA_PPM_CUTGATE,  PROMUE EN DEFAULT the 2026-10-30 (M259) - `=0` retablit l'historique]
 * GATES D'INPUT of the FRONTIER `0x421be0` (`0x421c1d` flag [0x43d4f6], `0x421c2a` bc [0x483936],
 * `0x421c37` pos vs [0x4826c8]) + ORDER d'input `ebp = fin_de_membre - pos` THEN clamp 0x3200 if
 * `>= 0x4b00`.
 * Measurements GT : OUT/m244_cuts_gt.tsv (58 calls ALL) and OUT/m244_next_gt.tsv (66).
 *   - `gate1` = 1 partout, `lim` = 0xffffffff partout (gates 1 and 3 inertes) ;
 *   - `gate2` = 0 only to the 2 cuts of the phase bc=0 (13 435 / 26 355) - the mono
 *     records.bin is en bc=1 ;
 *   - `cand == ini` has all the calls sauf the 3 escapes (57 883 / 972 004 / 1 136 284).
 *  PROOF of the PROMOTION (M259, judge of grille `an_m255_grid.py`/`an_m259_gagnants.py`, GT
 * `OUT/m256_route.tsv`, env **clean** verified before each run) : there gate closes **D1** (the first
 * `next` of the master = 12 800 n'is NOT there window of `0x422890`, c'is the SAUT INTEGRAL of the chain
 * by `0x421c2a` when `bc == 0`, which re-arme `next = pos + ebpEntree = 13 435 + 12 800 = 26 235`,
 * exactement there column `next` of the hit 3 GT) :
 *   - grille BEFORE (`=0`) : 60 cuts, hits 2/3 en ** position 760**, **1 cut parasite** of the port
 *     (pos 38 515, the master n'y cut not), 1er `next` divergent = **hit 2** ;
 *   - grille with (`=1`) : **58 appariements,  position = 0 SURE all** (min 0, max 253), **0 cut
 *     absente, 0 cut parasite**, 1er `next` divergent rejete has **hit 52** ( +253, l'other anomalie).
 *   - no-regression : corps `arc[39..]` of l'archive 12 members **BYTE-identical** au default
 *     (191 329 o, firstdiv 58 741, md5 of the corps unchanged - there gate not deplace NO emission),
 *     `an_m155_payload` **12/12**, `an_costcmp` 22/22, `an_m162` 618 873/618 873, and the 4 juges d'state
 *     inchanges (16/16, 15/16, 80/80 & 99,90 %, 16/16*15/15*0/324).
 *  CONTRASTE : `UHA_PPM_BLKWIN` (window `remainder` au lieu of `remainder - 0x100`) produces the same corps
 * d'archive (md5 `a238482244064cd4...`) en degradant has payload mono (`mixed.bin` 11/12) : there window
 * n'is not there law, the saut `bc == 0` l'is. */
static int ppm_cutgate_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_CUTGATE"); v = (e && e[0] == '0') ? 0 : 1; }
    return v;
}

/* [M248] start of l'stage 1 = TBL[cur], and re-armement `[0x483934]` ONLY when there class is
 * reellement ecrite (cf. usage in `ppm_blk_node_encode`).  Gate PROMUE en default (voir the block
 * ci-dessous for there proof M261) : `UHA_PPM_INILAW=0` retablit the behavior historique. */
/* [M248, GATED UHA_PPM_INILAW,  PROMUE EN DEFAULT the 2026-10-30 (M261) - `=0` retablit l'historique]
 * THE START OF L'STAGE 1 is TBL[cur], NEVER l'argmin of the cut previous.
 *  PROOF NEUVE (M261, out line) : there SEQUENCE SOME CANDIDATES evalues by the master is publiee
 * by `OUT/m260_arena_multi.tsv` (tete = `ini`, then 0..4 en excluant `ini`). The port, with there gate
 * OFF, evaluates [0,1,2,3,4] has 57 883 (start herite of `g_blk_start`, perime since there cut
 * previous is has cut `bc == 0` which, since `CUTGATE`, not parcourt MORE l'estimator) ; with there
 * gate ON il evaluates [1,0,2,3,4] = THERE SEQUENCE GT.  En MONO this test was IMPOSSIBLE by
 * construction (`cur = 0` partout, therefore `TBL[0] = 0 =` l'old start) : there gate y was declaree
 * " inerte " faute of domaine, not parce qu'elle was juste.
 * Double proof disque already acquise (M248) : `OUT/m245_cost_mono.tsv` column `ini` = 0 partout,
 * `OUT/m244_cuts_gt.tsv` : `ini = TBL[0x43b2c2][cur]` partout (whose `ini = 1` for `cur = 5` has
 * 1 083 561). And the re-armement `0x421f81` n'has lieu that if there class is REELLEMENT ecrite.
 * No-regression mesuree (2026-10-30) : corps `arc[39..]` of l'archive 12 members identical au default
 * previous, `an_m155` 12/12, `an_m246` 16/16, juges d'state inchanges. */
static int g_inilaw_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_INILAW"); v = (e && e[0] == '0') ? 0 : 1; }
    return v;
}

/* [M259, GATED UHA_PPM_TINYLEN, default-OFF] HYPOTHESE of the CUT Has VERY SMALL `ebp`.
 * Measures DISQUE (OUT/m244_cuts_gt.tsv, column `ini` = TBL[0x43b2c2][cur], 58 cuts of ALL) : the
 * SINGLE cuts of the port now `len <= 0x100` are au number of 5 (log [BLKLAW] of the grille 12 members
 * of the 2026-10-30) : 305440, 817440, 937440, 1070747 (len=256) and 1136284 (len=255). To the 5 cuts, the
 * MASTER rend EXACTEMENT `ini` (hit 25 `ini=0 cand=0`, hit 38 `ini=1 cand=1`, hit 49 `ini=0 cand=0`,
 * hit 60 `ini=3 cand=3`, hit 66 `ini=1 cand=1` with cur=5 -> the master ECCHAPE therefore 5->1) : 5/5.
 * The port, lui, not rend `ini` qu'has 2 d'between elles (305440, 1070747) and diverge to the 3 others (0, 7,
 * 5) - and THIS are THE 3 SINGLE divergences `cand != cls_lue` of all there grille (judge an_m259).
 * at input, `0x421c48 cmp ebp,0x100 / jbe` skips the `call 0x426bf0` and `0x421c99 cmp ebp,0x100 / ja`
 * skips the `call 0x422890` : there cut has `ebp <= 0x100` is the SINGLE regime now the two calls of law
 * of length are esquives. The mecanisme internal (costs degeneres vs stage no parcouru) n'is NOT
 * slice here : this gate only does TO FORCES there consequence mesuree (rendre `ini`, without stage 2, without
 * family, without changement) for eprouver there CAUSALITE sure the first byte divergent. Has variable.
 * Judge : an_m259_gagnants.py (0 divergence attendue to the 3 cuts), cmp firstdiv, size, carte,
 * an_m155 (the 12 payloads MONO : no cut mono n'has `len <= 0x100`, there law doit to be INERTE en
 * mono), the 9 juges + the 4 juges d'state. */
static int ppm_tinylaw_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_TINYLEN"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M249, GATED UHA_PPM_COSTSYM, default-OFF] WINDOW OF L'ESTIMATOR : bytes RAW now SYMBOLES ?
 * There law M170d (close for there FAMILY, 0x42303b) dit : the `0x100` first nodes read there
 * WINDOW (symboles), the remainder reads the RAW (0x4231ac). L'estimator `0x4221c0` recoit, lui,
 * `[esp+0x18]` (0x421caf) whose there nature n'has never ete tranchee : notre port lui gives the RAW
 * sure all there walk. Measures which motive l'epreuve (OUT/m245_cost_mono.tsv + score
 * work/an_m246_costscore.py) : the 5 first cuts of the mono `records.bin` rendent **the 5 costs
 * exact**, then there 6e (`76 806`) skips has +36 % then that the master tient 227.97 M ; and `RELOAD`
 * is inerte (measures M248) -> there divergence n'is NOT reload-vs-persistance, elle is in there
 * MATIERE balayee. Gate ON : l'estimator balaye the buffer SYMBOLES (keeps of bound : if there
 * walk deborderait of `nsyms`, on retombe sure the raw). Gate OFF : strictement the default. */
static const uint8_t *g_costwin(uint32_t start)
{
    static int cs = -1;
    if (cs < 0) { const char *e = getenv("UHA_PPM_COSTSYM"); cs = (e && e[0] != '0') ? 1 : 0; }
    if (cs && g_blk_sym && (size_t)start < g_blk_nsyms)
        return g_blk_sym + start;
    return g_blk_raw + start;
}

static int ppm_famveto_on(void)
{
    static int fv = -1;
    if (fv < 0) { const char *e = getenv("UHA_PPM_FAMVETO");
        fv = e ? ((e[0] != '0') ? 1 : 0) : ppm_clsfull_on(); }
    return fv;
}

/* [M219, DIAGNOSTIC UHA_PPM_VETOBUD="pos:hex", default-OFF] EPREUVE OF CAUSALITE of the BUDGET of the veto.
 * There bound recue by `0x422d00` is `ebx = cost[cl]` (`0x421d96` / `0x4220a9`), c.-has-d. has value
 * PRODUITE BY NOTRE ESTIMATOR OF FRONTIER - which n'is bitexact qu'has 8 nombres sure 70 (M202).
 * The verdict of the veto not equals therefore that if this budget is exact. This probe replaces there bound by
 * has value GT connue, has has position donnee, for PROUVER THERE CAUSALITE (same statut that
 * `UHA_FORCE5` : elle not peut not to be promue, elle sert has trancher). Format : `pos:hex`.
 * Default OFF : nothing n'is modifie. */
static uint64_t ppm_vetobud_at(uint32_t pos, int *on)
{
    static const char *e = (const char *)-1;
    static uint32_t vpos = 0;
    static uint64_t vbud = 0;

    if (e == (const char *)-1) {
        e = getenv("UHA_PPM_VETOBUD");
        if (e && e[0]) {
            char *end = NULL;
            unsigned long p = strtoul(e, &end, 10);
            if (end && *end == ':') {
                vpos = (uint32_t)p;
                vbud = (uint64_t)strtoull(end + 1, NULL, 16);
            } else {
                e = NULL;
            }
        }
    }
    *on = (e && e[0] && pos == vpos) ? 1 : 0;
    return vbud;
}

static int ppm_fambasecur_on(void)
{
    static int v = -1;
    /* 0 = OFF (default) ; 1 = base/n/prior of the class current, ctx_abs leaves there value live
     * (rel = 620-585 = 35) ; 2 = idem but ctx_abs = CTXBASE[class current] (rel = 0). */
    if (v < 0) { const char *e = getenv("UHA_FAMBASECUR"); v = (e && e[0] != '0') ? atoi(e) : 0; }
    return v;
}

static int ppm_family_veto(ppm_model *m, uint32_t pos, uint32_t len, int ncls, uint64_t bud)
{
    static ppm_cost_arena *SC;
    static ppm_model *s_save;
    ppm_live_arena SL;
    ppm_blk_scan_in sin;
    ppm_blk_scan_out sout;
    int scl, ovr = 0;
    uint64_t ovbud = ppm_vetobud_at(pos, &ovr);

    if (ovr && ovbud)
        bud = ovbud;                        /* diagnostic : bound GT */

    if (!m || !g_blk_raw || ncls < 0 || ncls >= 10 || !bud || !len)
        return 0;
    if (!SC)
        SC = (ppm_cost_arena *)calloc(1, sizeof *SC);
    if (!s_save)
        s_save = (ppm_model *)malloc(sizeof *s_save);
    if (!SC || !s_save)
        return 0;
    SL.freq = (const uint16_t *)m->freq;
    SL.cum = (const uint16_t *)m->cum;
    SL.ent = m->ent_wt;
    /* [M300, GATED UHA_FAMBASECUR, default-OFF] SURE WHICH lines WALK THERE FAMILY ? The master
     * has only Has buffer (0x43a264) and the feed of l'estimator (0x422226/0x4222fe) is RESERVE au
     * candidate equal has `[0x483934]` : when `0x422d00` reads/writes this buffer, il y finds there matiere
     * of the class current, not the one of the class testee. The port, lui, recharge since
     * `CTXBASE[ncls]` - lines never chauffees here (class 5) - and sa walk no tronquee rend
     * 151 137 700 contre 73 778 814 at the master (2,05x). This probe teste exactement cela :
     * base/n/prior of the class current, there class testee not servant more that of value rendue.
     * Judge : `ebp` has `1 071 003` (GT 73 778 814) without regresser `505 696` (GT 11 140 316). */
    { static int fbc = -1;
      if (fbc < 0) fbc = ppm_fambasecur_on();
      if (fbc && m->flag3934 < 10u) {
          uint32_t cc0 = (uint32_t)m->flag3934;
          SL.base = CLS_CTXBASE[cc0];
          SL.n = CLS_NCTX10[cc0];
          SL.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + cc0) * 256u;
          SL.prior_total = m->cum[772u + cc0][0];
      } else {
          SL.base = CLS_CTXBASE[ncls];
          SL.n = CLS_NCTX10[ncls];
          SL.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)ncls) * 256u;
          SL.prior_total = m->cum[772u + (uint32_t)ncls][0];
      } }
    /* [M219] `UHA_PPM_VETONOFEED` : the scan travaille sure l'arena PARTAGEE laissee by the five
     * evaluations of the frontier (the master has only has buffer 0x43a264). Default : recharge. */
    if (ppm_vetonofeed_on() && g_farena)
        SC = g_farena;
    else if (ppm_onear_on())
        SC = ppm_one_arena();               /* [M219] buffer unique of the master */
    else if (!ppm_cost_arena_load_live(SC, &SL))
        return 0;
    memset(&sin, 0, sizeof sin);
    sin.hist = g_blk_sym ? g_blk_sym : g_blk_raw;   /* [M243] window = SYMBOLES */
    /* [M318 GATED UHA_PPM_FAMADV, default-OFF] SOURCE OF WINDOW of the WALK. Measures M309/M317 :
     * the `buf` of the master = `~concat_raw[out_pos + n]` (byte RAW concatene nie), retrouve exact
     * at the offset 1 071 003 (= start image.raw = the `pos` pass here). The port armait `g_blk_sym`
     * (stream TRANSFORME) -> reading 49 (post-neg 206) au lieu of 88. `=1` forces there walk sure the
     * RAW concatene. In-stream (12/12) inchange : there gate not touche that this walk of veto.
     * Judge : [FAMRAW] doit rendre 88,87,86,84,.. (series M309, 30/30 cls5) then t204 two walks. */
    { static int fa = -1;
      if (fa < 0) { const char *e = getenv("UHA_PPM_FAMADV"); fa = e ? (e[0] != '0') : 1; }
      if (fa && g_blk_raw) sin.hist = g_blk_raw; }
    sin.win = g_blk_raw + pos + 0x100u;    /* 0x4231ac reads win[it-0x100] */
    sin.len = len;                          /* = `ebp` of the decision simulee */
    sin.base = SL.base;
    sin.nctx = SL.n;
    sin.step2 = m->tstep2;
    sin.st.ctx_abs = m->cls_ctx;
    sin.st.last = 0u;
    sin.st.flag = 0u;
    sin.st.win_idx = pos;
    sin.step = getenv("UHA_BLKNOSTEP") ? NULL : blk_scan_step;
    sin.ud = m;
    *s_save = *m;                           /* machine d'state sure COPIE */
    /* same states d'input that the path instream under UHA_BLKSCANCLS : the master (0x422fe3)
     * arme `[0x4803c4] = CTXBASE[class]`, `[0x483934] = class`, `[0x483932] = [0x48392f] =
     * [0x4803d0] = 0` BEFORE the feed ; without cela `rel < 0` and all the nodes tombent line 0. */
    { static int sc = -1;
      if (sc < 0) { const char *e = getenv("UHA_BLKSCANCLS"); sc = (e && e[0] && e[0] != '0') ? 1 : 0; }
      scl = sc;
    }
    if (scl && !ppm_fambasecur_on()) {
        s_save->flag3934 = (uint8_t)ncls;
        s_save->cls_ctx = CLS_CTXBASE[ncls];
        s_save->cls_neg = 0u;
        sin.st.ctx_abs = CLS_CTXBASE[ncls];
    }
    /* [M300b] Variante `UHA_FAMBASECUR=2` : same class current, but `rel = 0` (the ctx is re-arme
     * sure there base of the class current au lieu of to keep 620). Dissocie " which lines " of
     * " which rel " - there value 1 not the faisait not (the two were lies by rel >= 0). */
    if (ppm_fambasecur_on() == 2 && m->flag3934 < 10u) {
        s_save->cls_ctx = SL.base;
        s_save->cls_neg = 0u;
        sin.st.ctx_abs = SL.base;
    }
    memset(&sout, 0, sizeof sout);
    ppm_famsite("F_famveto", (uint32_t)pos, (uint32_t)len);
    if (m417dbg_on())
        fprintf(stderr, "[M417DBG][call VETO] pos=%u ncls=%d in_base=%u bud=%llu\n",
                (unsigned)pos, ncls, (unsigned)sin.base, (unsigned long long)bud);
    (void)ppm_blk_cost_scan(SC, &sin, (uint32_t)bud, &sout);
    *m = *s_save;                           /* restitution : the veto n'emits nothing */
    if (etrace_on >= 1)
        fprintf(stderr, "[FAMVETO] pos=%u ncls=%d len=%u ebp=%llu bud=%llu it=%u cold=%u "
                "verdict=%s\n", (unsigned)pos, ncls, (unsigned)len,
                (unsigned long long)sout.ebp, (unsigned long long)bud,
                (unsigned)sout.niter, (unsigned)sout.ncold,
                sout.ebp >= bud ? "ANNULE" : "classe rendue");
    return sout.ebp >= bud;
}

static void blk_set_payload(ppm_model *m);
static void blk_set_flag(ppm_model *m, uint32_t j);

/* [M203, GATED UHA_PPM_FENBLIVE, default-OFF] EPREUVE D'STATE D'input of the FRONTIER.
 * Measures of the tour : au not `1 071 003`, notre cost COMPLETE (candidate seed, evaluates without
 * elagage) equals `74 061 916` - c'is **exactement** notre decision 1 of `image.raw` en mono
 * (bitexact contre there GT mono, `an_costcmp` 22/22). The master, sure the same bytes, rend
 * `77 581 354`. => there frontier n'is **not** has start of member : the master y arrive with has
 * state **herite of the stream** (here more cold : +4,5 %), and notre mode 5 l'evaluates sure model nine.
 * As the budget of the veto is this same cost, and that there marge of the veto is of +0,023 %, l'order
 * of the comparaison se joue at the state near : this n'is not has decision law which manque.
 * This probe reevalue therefore there frontier with there **machinerie of the path instream promu**
 * (`ppm_legacy_cost_live`, arena rechargee since the master live, `payload`, flag by candidate),
 * en dissociant TWO variables that there value of the gate separe :
 *   `=1` arena live + prefixe/band **reels** (4 bytes and position before there frontier) ;
 *   `=2` arena live + prefixe/band **nus** (as the mode 4 promu) - single difference with `=1`.
 * Judge : the 7 costs complete GT some 7 frontiers (file C) and there carte [BLKCLS].
 * no effect emissif by default ; there function n'is appelee that under there gate. */
static int ppm_fenblive_on(void)
{
    static int fb = -1;
    if (fb < 0) { const char *e = getenv("UHA_PPM_FENBLIVE"); fb = e ? atoi(e) : 0; }
    return fb;
}

/* [M220b] `UHA_PPM_ROWFREE` = EPREUVE OF PROVENANCE : each candidate is evaluates sure has arena
 * PLATE and without feed (nor model live, nor state herite). Hypothese testee : at the frontier of
 * MEMBER the master has has model NINE (reset of member) therefore some lines quasi empty - this that there
 * captures M220 suggere (the 8 totaux of class 0 au feed are identical has pos 83 778, 344 137 and
 * 544 137). Never promotable : probe of causalite. */
static int ppm_rowfree_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ROWFREE"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}

/* [M221] `UHA_PPM_ROWMEMB` = porter there LAW measured at the frontier of MEMBER : arena NEUVE, without
 * feed, `d = 1` (captures M220/M221 : `[0x481c08] = 1` to the 7 frontiers, 8 totaux of class 0
 * identical has 260 000 bytes d'gap => the model is reset before there decision). Gated, default
 * OFF : ON n'agit THAT if there frontier current is has start of member. */
static int ppm_rowmemb_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ROWMEMB"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
/* [M230, REFUTEE] `UHA_PPM_ROWESC` : at the frontier of member, to take l'`escape` of the model
 * (`ent_wt`) au lieu of the `1` plat. Measures : `937 696` pass of +169,92 % has **+741 %** and `505 696`
 * perd 2 of ses 3 bit-exact => the `1` plat is the bon. The values `33`/`49` of the captures M222 are
 * the RESIDU of the walk previous, not l'`ent_wt`. Default OFF, conservee as measures. */
static int ppm_rowesc_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ROWESC"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
/* [M235] `UHA_PPM_ROWPRIOR` : to keep there row of prior of the candidate with some frequencies neuves. */
static int ppm_rowprio_on(void)
{
    static int v = -1;
    if (v < 0) { const char *e = getenv("UHA_PPM_ROWPRIOR"); v = (e && e[0] != '0') ? 1 : 0; }
    return v;
}
static int g_front_member;   /* 1 = there frontier current is has START OF MEMBER */
/* [M255] mirror file-scope some bounds of members, for that `ppm_blk_node_encode` (which not recoit
 * that `start`) sache if this frontier is has END OF MEMBER - cas now the master pass 0xff and
 * n'emits therefore never d'escape (0x417cf0 -> 0x421be0 -> 0x421dc0..0x421dd2 -> 0x421eac). */
static const uint32_t *g_member_ends_x;
static uint32_t g_nmembers_x;

static int ppm_frontier_live_class(ppm_model *m, uint32_t p, uint32_t len, uint32_t seed,
                                   uint64_t *out_best, int realstate)
{
    static ppm_cost_arena *SA;
    static const uint32_t CLS_NCTX_L[10] = { 8u, 0x20u, 0x20u, 0x60u, 0x40u, 4u, 4u, 8u, 3u, 5u };
    uint32_t cands[6], j, n = 0, k, best_cls;
    uint64_t cost[6], inc = 0xffffffffull, cc, initctx = 0u;
    ppm_live_arena L;

    if (!SA)
        SA = (ppm_cost_arena *)calloc(1, sizeof *SA);
    if (ppm_onear_on())
        SA = ppm_one_arena();               /* [M219] buffer unique of the master */
    if (SA)
        g_farena = SA;
    if (!SA || !len)
        return -1;
    /* enumeration of the master : [seed] then 0,1,2,3,4 without doublon (acquis 20) */
    cands[n] = seed & 15u;
    cost[n++] = 0ull;
    for (j = 0u; j <= 4u; j++) {
        int dup = 0;
        for (k = 0u; k < n; k++)
            if (cands[k] == j)
                dup = 1;
        if (!dup) {
            cands[n] = j;
            cost[n++] = 0ull;
        }
    }
    cc = (uint32_t)m->flag3934;
    if (cc < 10u && m->cls_ctx >= CLS_CTXBASE[cc])
        initctx = m->cls_ctx - CLS_CTXBASE[cc];
    /* states d'input : reels (=1) now nus (=2), single elements dissocies by there gate */
    ppm_cost_set_prectx(realstate ? ppm_precx_at(g_blk_raw, p) : 0u);
    for (k = 0u; k < n; k++) {
        j = cands[k];
        L.freq = (const uint16_t *)m->freq;
        L.cum = (const uint16_t *)m->cum;
        L.ent = m->ent_wt;
        L.base = CLS_CTXBASE[j];
        L.n = CLS_NCTX_L[j];
        L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + j) * 256u;
        L.prior_total = m->cum[772u + j][0];
        /* [M219] LAW D'input LUE EN ASM (0x42221a..0x42230e) : `cmp al,ah` now al = candidate and
         * ah = [0x483934] ; if different -> saut 0x42230e = NOR state d'input NOR feed. As there
         * loop of the master part of `[esp+0x20] = TBL[0x43b2c2][[0x483934]]` (table identite), the
         * single candidate which recoit the feed is **the first** (there seed). The mode 5 rend this
         * law telle which : setup + feed for k == 0, NOTHING for the following (l'arena keeps the
         * materiau leaves in place, 0x42230e). */
        if ((realstate != 5 && realstate != 6) || k == 0u)
            ppm_cost_set_window(realstate ? p : 0u,
                                ((realstate == 1 || realstate == 4) && j == cc) ||
                                ((realstate == 5 || realstate == 6) && k == 0u)
                                    ? (realstate == 5 ? (m->cls_ctx >= CLS_CTXBASE[j]
                                                          ? m->cls_ctx - CLS_CTXBASE[j] : 0u) : initctx)
                                    : 0u);
        blk_set_payload(m);
        blk_set_flag(m, j);
        /* [M240] `UHA_PPM_FLAGIN0` : forces the flag of direction d'input has 0 for the 5 candidates
         * (law " the flag not s'herite not "). measured : has 1 071 003, flag 0 -> 74 022 328 (4,55 %) and
         * flag 1 -> 80 497 499 (+3,76 %) ; there GT is between the two. */
        { static int f0 = -1;
          if (f0 < 0) { const char *e = getenv("UHA_PPM_FLAGIN0"); f0 = (e && e[0] != '0') ? 1 : 0; }
          if (f0) ppm_cost_set_flag(0u); }
        /* [M220, UHA_PPM_ROWSEL] LAW 0x422315 in there PROBE : l'snapshot of the model of
         * distance n'is rafraichi that if the first candidate evaluates equals 0 (=`cand ==
         * [0x483934] == 0`). `UHA_PPM_ROWSEL_FORCE` = probe of CAUSALITE (state live has
         * each frontier, whatever the there seed) - never promotable. */
        {
            static int frc = -1, frs = -1;
            if (frc < 0) { const char *e = getenv("UHA_PPM_ROWSEL_FORCE"); frc = (e && e[0] != '0') ? 1 : 0; }
            if (frs < 0) { const char *e = getenv("UHA_PPM_ROWSEED"); frs = (e && e[0] != '0') ? 1 : 0; }
            /* [M220b] LAW CORRIGEE (captures M220, `m220_rowselstate.log`) : `0x422315` is atteint
             * as soon as **`cand == 0`**, whatever the THERE class - the `jne 0x42230e` of 0x422226
             * not skips that the computation d'`initctx` ; the test `test bl,bl / je 0x422315` (0x42225a)
             * is ensuite does sure `bl = cand`. Proof : 63 rafraichissements sure the run, whose
             * some hits has `cls=1`, `cls=3`. */
            if (ppm_cost_rowsel_on() && (j == 0u || frc)) {
                if (frs)
                    ppm_cost_arena_reset(SA);
                else
                    ppm_cost_rowsel_feed_live(SA, g_blk_raw, (size_t)p);
            }
        }
        /* [M219] PROBE D'ARENA : this that the feed va copier for this candidate - sum some
         * `total` of line (`ent_wt[abs] + cum[abs][0]`, law 0x4222fe) and number of lines
         * EMPTY. Enables of distinguer " arena hot " of " arena degeneree " without captures. */
        if (etrace_on >= 1) {
            uint64_t sum = 0;
            uint32_t z = 0u, kk;
            for (kk = 0u; kk < L.n; kk++) {
                uint32_t ab = L.base + kk;
                uint32_t tt = (uint32_t)m->ent_wt[ab] + (uint32_t)m->cum[ab][0];
                sum += tt;
                if (!tt)
                    z++;
            }
            fprintf(stderr, "[CLSFR5A] pos=%u cand=%u base=%u n=%u sumtot=%llu vides=%u ctx=%u\n",
                    (unsigned)p, (unsigned)j, (unsigned)L.base, (unsigned)L.n,
                    (unsigned long long)sum, (unsigned)z, (unsigned)m->cls_ctx);
        }
        /* [M232] `UHA_PPM_RSFULL` : evaluates the 5 candidates without elagage (incumbent = -1) for
         * to count the nodes froids reels - the judge of the M232 (94 froids manquants has 1 071 003). */
        { static int rf = -1;
          if (rf < 0) { const char *e = getenv("UHA_PPM_RSFULL"); rf = (e && e[0] != '0') ? 1 : 0; }
          if (rf) inc = 0xffffffffull; }
        cost[k] = (uint64_t)((ppm_rowfree_on() || (g_front_member && ppm_rowmemb_on()))
            ? (ppm_cost_arena_reset(SA),
               /* [M230] at the frontier of MEMBER the frequencies are neuves but l'`escape` is
                * the one of the model (`ent_wt`, law 0x4222e0) : measures `ent_wt[0] = 49` has 1 071 003
                * then only to  reset plat gives 1. `ROWFREE` (probe) remainder entierement plat. */
               ((ppm_rowesc_on() && !ppm_rowfree_on() && g_front_member && ppm_rowmemb_on())
                    ? ppm_cost_arena_seed_esc(SA, &L) : 0),
               ((ppm_rowprio_on() && !ppm_rowfree_on() && g_front_member && ppm_rowmemb_on())
                    ? ppm_cost_arena_seed_prior(SA, &L) : 0),
               ppm_legacy_cost_live(SA, g_blk_raw + p, len, j, inc, &L, 0))
            : ppm_legacy_cost_live(SA, g_blk_raw + p, len, j, inc, &L,
                                   (realstate == 4) ? ((j == cc) ? 1 : 0)
                                   : (realstate == 5) ? ((k == 0u) ? 1 : 0)
                                   : (realstate == 6) ? ((k == 0u && j != 0u) ? 1 : 0) : 1));
        /* [M220, UHA_PPM_RSSCAN] PROBE OF CAUSALITE (read-only sure l'state emIs) :
         * balaie there distance `reg08` installee by the rafraichissement and rend, for each
         * value, the cost of the single candidate `j`. Sert has TO EXTRACT there value of `[0x481c08]`
         * that the master had has this frontier (the total GT is has function croissante of the
         * number of nodes of bord, therefore of `d`). Never promotable. */
        if (k == 0u && ppm_cost_rowsel_on()) {
            static int rsscan = -1;
            if (rsscan < 0) { const char *e = getenv("UHA_PPM_RSSCAN"); rsscan = (e && e[0] != '0') ? atoi(e) : 0; }
            if (rsscan) {
                ppm_live_arena L0;
                uint32_t d;
                /* [M300, `UHA_PPM_RSSCAN=2`] PROBE GENERALISEE AU first CANDIDATE EVALUATES. There
                 * forme historique balayait `j = 0` en dur ; now, since that there seed is there class
                 * current (M297/M299), the SINGLE cost comparable at the GT is the one of the first
                 * evaluates : the GT some candidates following are TRONQUEES by l'incumbent (m299 3).
                 * Has `1 071 003` the first evaluates is the candidate 3 (GT 77 582 890). Probe of
                 * causalite, never promotable ; appelee only under UHA_PPM_RSSCAN. */
                const uint32_t jj = (rsscan >= 2) ? cands[0u] : 0u;
                L0.freq = (const uint16_t *)m->freq;
                L0.cum = (const uint16_t *)m->cum;
                L0.ent = m->ent_wt;
                L0.base = CLS_CTXBASE[jj];
                L0.n = CLS_NCTX_L[jj];
                L0.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + jj) * 256u;
                L0.prior_total = m->cum[772u + jj][0];
                ppm_cost_set_prectx(ppm_precx_at(g_blk_raw, p));
                ppm_cost_set_window(p, (jj == cc && m->cls_ctx >= CLS_CTXBASE[jj])
                                       ? (m->cls_ctx - CLS_CTXBASE[jj]) : 0u);
                blk_set_payload(m);
                blk_set_flag(m, jj);
                for (d = 1u; d <= 24u; d++) {
                    uint64_t c1;
                    ppm_cost_rowsel_feed_live(SA, g_blk_raw, (size_t)p);
                    SA->reg08 = d;
                    c1 = (uint64_t)ppm_legacy_cost_live(SA, g_blk_raw + p, len, jj,
                                                       0xffffffffull, &L0, 0);
                    fprintf(stderr, "[RSSCAN] pos=%u j=%u d=%u cost=0x%llx\n",
                            (unsigned)p, jj, (unsigned)d, (unsigned long long)c1);
                }
                ppm_cost_rowsel_feed_live(SA, g_blk_raw, (size_t)p);
            }
        }
        if (k == 0u)
            inc = cost[k];
        else if (cost[k] < inc)
            inc = cost[k];
    }
    best_cls = cands[0u];
    /* argmin in l'order of the master (superiorite strict), as there loop instream l.~560 */
    {
        uint32_t bi = 0u;
        for (k = 1u; k < n; k++)
            if (cost[k] < cost[bi])
                bi = k;
        best_cls = cands[bi];
        if (out_best)
            *out_best = cost[bi];
    }
    if (etrace_on >= 1) {
        fprintf(stderr, "[CLSFRONT5L] pos=%u seed=%u len=%u real=%u", (unsigned)p, (unsigned)seed,
                (unsigned)len, (unsigned)realstate);
        for (k = 0u; k < n; k++)
            fprintf(stderr, " c%u:0x%llx", cands[k], (unsigned long long)cost[k]);
        fprintf(stderr, " -> cls=%u\n", (unsigned)best_cls);
    }
    return (int)best_cls;
}

static int ppm_frontier_class(ppm_model *m, uint32_t p,
                              const uint32_t *member_ends, uint32_t nmembers)
{
    const size_t FEN = 0x3100u;               /* window legacy 12 544 */
    extern void ppm_cost_set_avail(size_t n); /* declare localement, as in encode.c */
    uint32_t reste, cc, initctx = 0u, fin = 0u;
    uint64_t cout = 0ull;
    int mode = ppm_clsfront_mode();
    uint32_t cls;

    if (!mode || !g_blk_raw || !g_blk_usize || g_blk_usize <= p)
        return -1;
    reste = g_blk_usize - p;
    /* [M195 mode 3] Geometrie " BY MEMBER " : the legacy engine arme son buffer model sure l'input of the
     * MEMBER en cours (`usize` of the member, law of the payload M172b), and the 12 archives mono of the corpus
     * are byte-identical with this geometrie. Measures of the jour (canal independant : reading some
     * archives LEGACY by notre decodeur) : there carte some frontiers 0-1-0-4-1-0-0-5 is EXACTEMENT
     * there class clean of the member which commence sure the 7 frontiers mesurables, image.raw excepte
     * (mono = 3, carte = 5). therefore there formulation juste is " class of the member ", not " class of the
     * queue ". The mode 1 (queue) is keeps : il rend the same 7/8, and l'gap between the two
     * geometries is has measures, not has supposition. */
    if (mode >= 3 && member_fin_at(p, member_ends, nmembers, &fin))
        reste = fin - p;                      /* usize of the MEMBER which commence, vu since p */
    if (reste < FEN)
        return -1;                            /* 0 call : the legacy engine keeps there class global */
    /* Two choice ORTHOGONAUX, measurements separement (otherwise on confond the two variables) :
     *   geometry : queue [p,usize) (modes 1,2) now member which commence (modes 3,4)
     *   states    : " fille " = prectx/band zero, as the file isole of the judge t188 (1,4)
     *              " stream "  = prectx/band REELS (M170k)                                    (2,3) */
    if (mode == 2 || mode == 3) {
        ppm_cost_set_prectx(ppm_precx_at(g_blk_raw, p));
        cc = (uint32_t)m->flag3934;
        if (cc < 10u && m->cls_ctx >= CLS_CTXBASE[cc])
            initctx = m->cls_ctx - CLS_CTXBASE[cc];
        ppm_cost_set_window(p, initctx);
    } else {
        ppm_cost_set_prectx(0u);              /* as the file isole of the judge t188 */
        ppm_cost_set_window(0u, 0u);
    }
    ppm_cost_set_flag(0u);                    /* law close : input = 0, not s'herite not */
    ppm_cost_set_avail((size_t)reste);        /*  queue ENTIERE : never plafonnee (3.3-1) */
    /* [M198 mode 5] There captures M197 (OUT/m197_frontier_costs.tsv) measures the MASTER at the frontier :
     *   $ebp = 0x3100 (notre window), seed = there class current ([0x483934] = 3 has 1 071 003, and the
     *   candidate 3 is writes BEFORE the others), step 1 = 3, [esp+0x24] (slot of l'step 2) = 1,
     *   store final = 5. Autrement dit : there frontier triggers there STRING COMPLETE of decision of
     *   block, not only l'argmin. This mode replays therefore step 1 + step 2 + family, without emission
     *   and without toucher l'state (there candidature of the scan remainder armee ailleurs), with there length MESUREE.
     *   The lines of l'step 2 are recopiees of ppm_blk_node_encode (0x421d42/0x421d5f/0x42201a) :
     *   there duplication is assumee and signalee, for not not rendre emissif the path of probe. */
    if (mode >= 5) {
        uint32_t cb, fact, len = (uint32_t)FEN;
        uint64_t best = 0ull;
        int cl, e1, a = -1, chg = 0, ncls, vetoed = 0;
        uint32_t seed = ppm_seedlag_on() ? ppm_seed_mirror_at(p) : (g_blk_start & 15u);
        /* [M202, GATED UHA_PPM_FENBLAW, default-OFF] tables of THERE FRONTIER. The master, en
         * frontier, pass BY THERE STRING COMPLETE : 0x421986 (cut) -> 0x421c5b (roulage
         * t <- t5) -> 0x422890 (length, which RECALCULE t/t5 sure there window) -> 0x421be0
         * (decision, reads 0x480390 = notre `t5`) -> 0x421f81 (writing). The mode 5 rejouait there
         * decision with THE TABLES PERIMEES of the last cut in-stream (`g_blc`), this which
         * rend `chg` arbitraire en frontier : measures M202, `697 696` gives chg=1 (family
         * 1 -> 5) there now the master store 1. Here on calls therefore 0x422890 SURE THERE WINDOW OF
         * FRONTIER, in has COPIE local of the context (not not corrompre `g_blc`, which porte there
         * string in-stream byte-identical). There LAW OF WINDOW is the one of the length, not
         * the one of the geometrie of class : `remainder = min(usize-p, 0x3200)` then `len-0x100`
         * (ppm_blk_node_encode l.~413), and GT `ebp_len = 0x3100` to the 7 frontiers (acquis 17).
         * if 0x422890 rend has length more short, on there suit (`ret` = `ebp` of the master). */
        static ppm_blocklen_ctx *s_fbt_F = NULL;
        static int fbt = -1;
        uint32_t ft[5], f5[5], lrest, lret;
        const uint32_t *r5;

        if (fbt < 0) { const char *e = getenv("UHA_PPM_FENBLAW");
            fbt = e ? ((e[0] != '0') ? 1 : 0) : ppm_clsfull_on(); }
        r5 = g_blc.t5;
        if (fbt && g_blk_usize > p) {
            if (!s_fbt_F)
                s_fbt_F = (ppm_blocklen_ctx *)malloc(sizeof *s_fbt_F);
            if (!s_fbt_F) return 0;
            lrest = g_blk_usize - p;
            if (lrest >= 0x4b00u)
                lrest = 0x3200u;
            *s_fbt_F = g_blc;                 /* copie : `cur` herite, `g_blc` intact */
            ppm_blocklen_roll(s_fbt_F);
            lret = (lrest > 0x100u) ? ppm_blocklen(s_fbt_F, g_blk_raw + p, lrest - 0x100u) : lrest;
            memcpy(ft, s_fbt_F->t, sizeof ft);
            memcpy(f5, s_fbt_F->t5, sizeof f5);
            r5 = f5;
            len = lret;                       /* ebp of the master = return of 0x422890 */
            if (etrace_on >= 1)
                fprintf(stderr, "[FENBTAB] pos=%u lrest=%u len=%u t=[%u %u %u %u %u]"
                        " t5=[%u %u %u %u %u]\n", (unsigned)p, (unsigned)lrest,
                        (unsigned)len, ft[0], ft[1], ft[2], ft[3], ft[4],
                        f5[0], f5[1], f5[2], f5[3], f5[4]);
        }

        /* [M219] PROBE OF TABLE : rend the TWO jeux of tables vus by there string - the
         * " perimees " of the last cut instream (`g_blc`) and, if FENBLAW is ON, those
         * recalculees sure there window of frontier. no effect : read-only. */
        if (etrace_on >= 1)
            fprintf(stderr, "[CLSFR5T] pos=%u fb=%d staleT=[%u %u %u %u %u]"
                    " staleT5=[%u %u %u %u %u] r5=[%u %u %u %u %u]\n",
                    (unsigned)p, fbt, (unsigned)g_blc.t[0], (unsigned)g_blc.t[1],
                    (unsigned)g_blc.t[2], (unsigned)g_blc.t[3], (unsigned)g_blc.t[4],
                    (unsigned)g_blc.t5[0], (unsigned)g_blc.t5[1], (unsigned)g_blc.t5[2],
                    (unsigned)g_blc.t5[3], (unsigned)g_blc.t5[4],
                    (unsigned)r5[0], (unsigned)r5[1], (unsigned)r5[2], (unsigned)r5[3],
                    (unsigned)r5[4]);
        cl = (int)ppm_legacy_cost_select_class(g_blk_raw + p, len,
                                               seed, ppm_legacy_cost, &best);
        /* [M203 UHA_PPM_FENBLIVE] mme decision, but sure the model LIVE (machinerie instream).
         * `cb`/family/veto use then the `best` rendu by this path : has single variable.
         * The `ppm_cost_set_prectx/window` sets by the modes more high is reecrit by there probe
         * (prectx/band reels) : c'is l'objet same of l'epreuve. */
        if (ppm_fenblive_on()) {
            int fb = ppm_fenblive_on();
            /* [M219] mode 3 = window/prefixe REELS but `initctx` FORCES has 0 (rel = 0 au 1er
             * node, as has `45 337` now `ctx == CTXBASE[0]`) : epreuve of the ROUTAGE d'input. */
            int rs = (fb == 1) ? 1 : ((fb == 3) ? 3 : ((fb == 4) ? 4 : ((fb == 5) ? 5 : ((fb == 6) ? 6 : 0))));
            int lc;
            uint32_t km;
            /* [M221] marque there nature of the frontier BEFORE there probe (law of member). */
            g_front_member = (p == 0u);
            if (!g_front_member && member_ends)
                for (km = 0u; km < nmembers; km++)
                    if (member_ends[km] == p) { g_front_member = 1; break; }
            lc = ppm_frontier_live_class(m, p, len, seed, &best, rs);
            if (lc >= 0)
                cl = lc;
        }
        e1 = cl;                              /* winner of l'step 1 (compares has [esp+0x20] legacy) */
        cb = len ? (uint32_t)(best / len / 0x249u) : 0x0Au;
        if (cb > 0x0Au)
            cb = 0x0Au;
        fact = (uint32_t)((cl == 1 ? 0x50 : 0x4b) - (0x0Au - cb) * 4u);
        if (cl != 0 && cl != 3 &&
            (uint32_t)(fact * r5[cl]) > (uint32_t)(r5[0] << 6)) {
            chg = 1;
        } else {
            a = 1;
            if (r5[2] > r5[a]) a = 2;
            if (r5[3] > r5[a]) a = 3;
            if (r5[4] > r5[a]) a = 4;
            else if (a == 3) a = -1;
            if (a >= 0) {
                fact = ((len >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
                if ((uint32_t)(r5[a] << 6) > (uint32_t)(fact * r5[0])) {
                    cl = a;
                    chg = 1;
                }
            }
        }
        ppm_famsite("C_class_p", (uint32_t)p, (uint32_t)len);
        ncls = chg ? ppm_blk_class(cl, g_blk_raw + p, len) : -1;
        if (ncls < 0)
            ncls = e1;
        else if (ppm_famveto_on() && ppm_family_veto(m, p, len, ncls, best)) {
            /* 0x423199 : `ebp >= bound` -> `al = 0` -> the caller not change nothing (`je 0x4220c9`) :
             * there class retenue remainder there value d'stage 1 (`e1`, [esp+0x20]), not there class family. */
            vetoed = 1;
            ncls = e1;
        }
        /* [M202 UHA_PPM_SEEDLAG] there frontier writes sa class in `[0x483934]` (0x421f81,
         * acquis 3.1-19) : c'is the term (b) of the law of the mirror d'emission. */
        if (ppm_seedlag_on())
            ppm_seed_mirror_frontier((uint32_t)ncls);
        if (etrace_on >= 1)
            fprintf(stderr, "[CLSFRONT5] pos=%u seed=%u lag=%d e1=%d chg=%d e2=%d veto=%d best=0x%llx cls=%d\n",
                    (unsigned)p, (unsigned)seed, ppm_seedlag_on(), e1, chg, cl, vetoed,
                    (unsigned long long)best, ncls);
        if (m417dbg_on())
            fprintf(stderr, "[M417DBG][sel FRONT] pos=%u chg=%d ncls=%d cl=%d (front: resorbe)\n",
                    (unsigned)p, chg, ncls, cl);
        return ncls;
    }
    cls = ppm_legacy_cost_select_class(g_blk_raw + p, FEN, 0u, ppm_legacy_cost, &cout);
    if (etrace_on >= 1)
        fprintf(stderr, "[CLSFRONT] mode=%d pos=%u reste=%u cls=%u cost=0x%llx\n",
                mode, (unsigned)p, (unsigned)reste, (unsigned)cls,
                (unsigned long long)cout);
    return (int)cls;
}

/* Armement of the class EMISE by there frontier `p` (no effect out gate). */
static void ppm_arm_frontier_class(ppm_model *m, uint32_t p,
                                   const uint32_t *member_ends, uint32_t nmembers)
{
    extern int uharc_ppm_class;
    int c = ppm_frontier_class(m, p, member_ends, nmembers);
    if (c >= 0)
        uharc_ppm_class = c;
    /* [M203, UHA_PPM_BLKBOUND] THERE STRING OF CUT TRAVERSES THERE FRONTIER : at the master there
     * decision of frontier is has decision of block whose `ebp` arme there cut next. Proof
     * numerique (`OUT/m203_frontier_tables.tsv`) : frontier 697 696 with ebp = 0x3100, then the
     * hits in-stream 710 240 = 697 696 + 12 544, 722 784, 735 328 ... (no 697 696 + 38 442
     * as notre port). without ancrage, nos decisions are decalees of +810 and two decisions of the
     * master are absentes at nous. Gate OFF : `g_blk_next` keeps sa value historique. */
    if (c >= 0 && g_blkbound_on() && g_blk_usize > p) {
        uint32_t reste = g_blk_usize - p;
        uint32_t ebp;
        if (reste >= 0x4b00u)
            reste = 0x3200u;
        if (g_blk_bound > p && g_blk_bound - p < reste)
            reste = g_blk_bound - p;
        ebp = (reste > 0x100u) ? reste - 0x100u : reste;
        g_blk_next = p + ebp;        { static int nx = -1;
          if (nx < 0) { const char *e = getenv("UHA_M257EMS"); nx = (e && e[0] != '0') ? 1 : 0; }
          if (nx) fprintf(stderr, "[M257NEXT] FRONTIERE next=%u\n", (unsigned)g_blk_next); }

        if (etrace_on >= 1)
            fprintf(stderr, "[BLKBOUND] frontiere pos=%u reste=%u ebp=%u next=%u bound=%u\n",
                    (unsigned)p, (unsigned)reste, (unsigned)ebp, (unsigned)g_blk_next,
                    (unsigned)g_blk_bound);
    }
}

/* [M172b, GATED UHA_PPM_PAYLOAD, defautOFF] L'estimator of legacy reads `input[i  k*c08]` with
 * `input = base + start + 256` : sure the last block of has member, l'index absolu depasse `usize`
 * and the legacy engine retombe sure son clean buffer of output (measures M172 : 1019 bytes of the dump ==
 * payload already emis). On lui fournit therefore the stream emis jusqu'here. without there gate, no effect. */
static void blk_set_payload(ppm_model *m)
{
    if (m && m->w)
        ppm_cost_set_payload(m->w->buf, m->w->pos, (size_t)g_blk_usize);
}

/* [M172c, GATED UHA_PPM_FLAG0, defautOFF] Flag of direction (`[esp+0x50]` of 0x4221c0) : the legacy engine not the
 * sets since `[0x483932]` THAT for the candidate equal has `[0x483934]` (`0x422224..0x422246`) ; otherwise the
 * slot is has REMAINDER OF STACK (`caller_esp  0x28`, therefore overwrites by the underappels of the callee). Measures
 * GT `OUT/m171_dec3_nodes.log` (reconstruction of the flag node by node) : the flag d'input equals **0**
 * for the 5 candidates of the decision 3, then that the flags of END valent 1/0/0/1 -> no heritage.
 * L'old port heritait of the flag final of the candidate previous : now the 2 nodes false (`i = 0`) en
 * cand 2 and cand 4, and the residus of cost +72 / +4 628 / 1 249 / +52. */
static void blk_set_flag(ppm_model *m, uint32_t j)
{
    static int f0 = -1;
    /* [M177, PROMUE the 2026-10-25] Default = 1 (law faithful : no heritage of the flag of direction).
     * validation : decision 3 of `mixed` 5/5 costs exact (M173) + 1275/1275 nodes. The gaps
     * +72 / +4 628 / 1 249 / +52 cites ci-dessus se are reveles to be has MAUVAISE TRANSCRIPTION
     * of the GT (`OUT/m177_analysis.md` 2) : there law remainder, the chiffres no. */
    if (f0 < 0) { const char *e = getenv("UHA_PPM_FLAG0"); f0 = (e && e[0]) ? atoi(e) : 1; }
    if (f0 && (uint32_t)j != (uint32_t)m->flag3934)
        ppm_cost_set_flag(0u);
    else
        ppm_cost_set_flag(((uint32_t)j == (uint32_t)m->flag3934) ? m->cls_neg : ppm_cost_get_flag());
}

int ppm_detr_inverse(const uint8_t *in, uint32_t len,
                     uint8_t *out, uint32_t *nout);
int ppm_detr_forward(const uint8_t *in, uint32_t len, uint32_t thr2,
                     uint8_t *out, uint32_t *nout);

/* [M169 lot 2] biais of the family 5/6 and 7/8, lu in 0x422d00 (OUT/m169_families.md).
 *   biais "normal" : +1 if (b < 0x40 || b >= 0xC0), otherwise -1.
 *   biais complemente : same test sure (~b & 0xFF). */
static int ppm_blk_bias(const uint8_t *w, uint32_t n, int complement)
{
    uint32_t i;
    int s = 0;

    for (i = 0; i < n; i++) {
        uint8_t b = complement ? (uint8_t)(~w[i] & 0xFF) : w[i];
        s += (b < 0x40 || b >= 0xC0) ? 1 : -1;
    }
    return s;
}

/* class produite by 0x422d00(cl) ; -1 = no (cl 0 now 3) */
/* [M274h, GATED UHA_PBL_FWIN, default 0 = historique] INPUTS of the FAMILY `0x422d00`.
 * ASM `0x422099..0x4220ac` : l'call prepare `eax = [esp+0x18]` (pointer of window, ALREADY
 * decale of +0x100 as the one of `0x422890`), `ebx = cost[cur]`, `ecx = class`,
 * `edx = ebp` = there length d'input (= `remainder`, NOT `remainder - 0x100`). The port passait
 * `raw + start` and `blen`. `UHA_PBL_FWIN=n` decale there window of `n` and allonge there length
 * of `n` (has single variable : `n = 0x100` = forme ASM). */
static int ppm_blk_class_fw(int cl, const uint8_t *w, uint32_t len)
{
    static long fw = -2;
    if (fw == -2) { const char *e = getenv("UHA_PBL_FWIN"); fw = (e && e[0]) ? atol(e) : 0; }
    if (fw > 0)
        return ppm_blk_class(cl, w + fw, len + (uint32_t)fw);
    return ppm_blk_class(cl, w, len);
}

static int ppm_blk_class(int cl, const uint8_t *w, uint32_t len)
{
    if (cl == 1)
        /* [M274h, GATED UHA_PBL_FAM1V, default -1 = historique] TEST OF SENSIBILITE : the master
         * not change not has `pos = 937 440` then that l'stage 2 toggles has `cl = 1` ; il faut therefore
         * that there family rende there class current (0). There family of the port is has transcription
         * EMPIRIQUE by class (`cl==1 -> 5/6`), not `0x422d00`. This gate forces there value rendue
         * for `cl == 1` and sert only has to measure if the front is well there. */
        {
            static long f1 = -2;
            if (f1 == -2) { const char *e = getenv("UHA_PBL_FAM1V"); f1 = (e && e[0]) ? atol(e) : -1; }
            if (f1 >= 0)
                return (int)f1;
        }
    if (cl == 1)
        return 5 + (ppm_blk_bias(w, len < 0x100u ? len : 0x100u, 0)
                    + ppm_blk_bias(w + (len < 0x100u ? len : 0x100u),
                                   len > 0x100u ? len - 0x100u : 0u, 1) > 0);
    if (cl == 2) {
        int esi = ppm_blk_bias(w, len < 0x100u ? len : 0x100u, 0);
        int ecx = ppm_blk_bias(w + (len < 0x100u ? len : 0x100u),
                               len > 0x100u ? len - 0x100u : 0u, 1);
        return 7 + ((esi > 0 || ecx > 0) ? 1 : 0);
    }
    if (cl == 4)
        return 9;
    return -1;
}

/* [M170, UHA_BLKLAW>=3] Node literal : cut + selection + ESCAPE, appeles since
 * ppm_matchfinder_encode() BEFORE ppm_lzp_encode_class(type1c, 2).
 *   - there cut (frontier = start + ppm_blocklen(...), roulage t <- t5) and there selection
 *     of class are those of the lot 2 (0x422890 / 0x422d00), inchangees ;
 *   - SINGLE l'ORDER change : escape before there class of the node (path (has) of OUT/m170_order.md)
 *     and therefore BEFORE ppm_lzp_apply_update (+0x20) => rec[3] vu by l'escape = state d'input.
 * Return : 0 = ok (with now without escape), -1 = error d'writing. */
int ppm_blk_node_encode(ppm_model *m, uint32_t start, int lzp_ctx)
{
    uint32_t reste, ret, blen, cb = 0x0Au, fact;
    uint64_t cbest = 0;
    uint64_t bud = 0;          /* [M170k] budget transmis at the family then au scan (cost[cl]) */
    int j, cl = 1, ncls = -1, chg;
    int stage1 = 1;   /* [M330, M361] value D'STAGE 1 figee BEFORE the recyclage of `cl` by l'stage 2 */
    static uint32_t g_blk_next_entry;   /* [M255] `next` WHICH TRIGGERS (column `next` of the master) */

    if (!m || !g_blk_raw || g_blklaw < 3)
        return 0;
    if (start < g_blk_next)
        return 0;
    if (start >= g_blk_usize)
        return 0;

    reste = g_blk_usize - start;
    g_blk_next_entry = g_blk_next;   /* [M255] before all re-arme : comparable au `next` GT */
    /* [M245, GATED UHA_PPM_CUTGATE, default-OFF] order of THERE LAW D'INPUT (0x421bed..0x421c48) :
     * `ebp` d'input = [0x4826d0] - pos (END OF MEMBER), THEN `cmp ebp,0x4b00 ; jb` -> 0x3200.
     * There bound of member pass therefore BEFORE the clamp. GT (OUT/m244_next_gt.tsv) : pos=26 355 ->
     * ebp=18 982 (= 45 337-26 355, no clampe) tandis that pos=0 -> 12 800 (clampe).
     * Gate OFF : formule historique inchangee (clamp then bound). */
    if (ppm_cutgate_on()) {
        if (g_blkbound_on() && g_blk_bound > start && g_blk_bound - start < reste)
            reste = g_blk_bound - start;
        if (reste >= 0x4b00u)
            reste = 0x3200u;
    } else {
        if (reste >= 0x4b00u)
            reste = 0x3200u;
        /* [M203, GATED UHA_PPM_BLKBOUND, default-OFF] WINDOW BORNEE BY THERE FRONTIER. The master not
         * scanne never au-dela of the next bound of member : 3 nombres GT the measure
         * (`OUT/m203_frontier_tables.tsv`, column `ebp` rendu by 0x422890) :
     *   pos 810592 : 817696-810592 = 7104 -> 7104-0x100 = **0x1AC0 = 6848** = ebp GT
     *   pos 817440 : 817696-817440 = **256** = 0x100 -> `0x421c99` n'calls not -> ebp GT = 256
     *   pos 1136284: 1136539-1136284 = **255** (< 0x100) -> ebp GT = 255 (notre port rendait 256)
     * without there bound, nos blocks near of has frontier debordent sure the member next and there STRING
     * of cut drifts (measures : nos starts = those of the master +810 sure all the segment `biased`, and
     * two decisions of the master absentes at nous). Gate OFF : formule historique inchangee. */
        if (g_blkbound_on() && g_blk_bound > start && g_blk_bound - start < reste)
            reste = g_blk_bound - start;
    }
    /* [M245, GATED UHA_PPM_CUTGATE] GATES D'INPUT 0x421c1d / 0x421c2a / 0x421c37 : if `bc == 0`
     * there STRING ENTIERE is sautee - NOR recharge 0x426bf0, NOR roulage t<-t5, NOR scan 0x422890,
     * NOR estimator, NOR family - and `cand = TBL[cur]` (sets en 0x421bed..0x421c0c).
     * Proof GT (OUT/m244_cuts_gt.tsv + m244_next_gt.tsv) : the 2 single cuts `bc=0` of ALL,
     * pos 13 435 and 26 355, have `gate2 = 0` and has `ebp` = THERE value D'INPUT (12 800 and 18 982,
     * therefore no scan), with `cand == ini` ; notre port y calculait has argmin complete. */
    if (ppm_cutgate_on() && m->byte_class == 0) {
        static const uint8_t TBL[10] = { 0, 1, 2, 3, 4, 1, 1, 2, 2, 4 };   /* 0x43b2c2 (PE) */
        int cand = (int)TBL[m->flag3934 % 10u];
        g_blk_next = start + reste;        { static int nx = -1;
          if (nx < 0) { const char *e = getenv("UHA_M257EMS"); nx = (e && e[0] != '0') ? 1 : 0; }
          if (nx) fprintf(stderr, "[M257NEXT] PETIT_RESTE next=%u\n", (unsigned)g_blk_next); }

        if (etrace_on >= 1)
            fprintf(stderr, "[BLKLAW] start=%u len=%u ret=%u next=%u saut=gate2\n",
                    (unsigned)start, (unsigned)reste, (unsigned)reste, (unsigned)g_blk_next);
        if (g_blklaw >= 4 && lzp_ctx >= 0 && cand != (int)m->flag3934) {
            int erc = ppm_lzp_encode_escape(m, lzp_ctx, cand);
            if (etrace_on >= 1)
                fprintf(stderr, "[BLKESC] ctx=%d sel=%d rc=%d saut=gate2\n", lzp_ctx, cand, erc);
            if (erc < 0)
                return -1;
            /* [M299, SAME GATE UHA_PPM_SEEDLAG, default-OFF] L'escape WRITES `[0x483934]` in the
             * stream : the mirror d'emission doit the suivre, otherwise there seed of the frontier next
             * relit has value perimee. Gate OFF : no effect. */
            if (ppm_seedlag_on())
                ppm_seed_mirror_push(start, (uint32_t)cand);
        }
        /* [M259, probe UHA_M255GRID] There grille of the MASTER COUNTS these cuts (OUT/m244_cuts_gt.tsv :
         * `gate2=0` to the pos 13 435 and 26 355, with `ini=cand=0`) : there probe doit therefore RENDRE there cut
         * same when there string is sautee, otherwise the judge of grille the comptait has tort as
         * " absentes ". Trace single, no effect on l'emission. */
        static int gr2 = -1;
        if (gr2 < 0) { const char *e = getenv("UHA_M255GRID"); gr2 = (e && e[0] != '0') ? 1 : 0; }
        if (gr2)
            fprintf(stderr, "[M255GRID] arg=%d cand=%d cur=%d pos=%u next_lu=%u next_new=%u saut=gate2\n",
                    lzp_ctx, cand, (int)m->flag3934, (unsigned)start,
                    (unsigned)g_blk_next_entry, (unsigned)g_blk_next);
        return 0;
    }
    /* 0x421c5b : the roulage t <- t5 has lieu at each cut, BEFORE the test len > 0x100. */
    ppm_blocklen_roll(&g_blc);
    /* [M256/M255, GATED UHA_PPM_BLKWIN, default-OFF] WINDOW of the CUT : the first `next`
     * declencheur of the MASTER (OUT/m256_route.tsv hit 2) equals **12800 = 0x3200 = `ebp`** (there value
     * bridee of the law d'input 0x421bed..0x421c48), then that the port rend 12544. As `ret` is
     * plafonne by there length of window, passer `remainder - 0x100` (12544) IMPOSE has plafond of
     * 12544 and decale all there grille ( measurements : -875, -1022 then +809 constants, an_m255_grid.py
     * 4) - and therefore the port not teste NO cut has 57 881/70 427, manque l'escape of the master has
     * 57 883 (which installe there class 0), and echappe has 82 971 now the master n'echappe not
     * (`cur` master 0 vs port 1) = the first byte divergent (payload 1 280). The `- 0x100` of
     * 0x421c50/0x421c56 is l'arg of the call `0x426bf0`, NOT there window of the length of block.
     *  There window of the SELECTION (`blen`) remainder `remainder - 0x100` : has single variable. */
    { static int bw = -1;
      if (bw < 0) { const char *e = getenv("UHA_PPM_BLKWIN"); bw = (e && e[0] != '0') ? 1 : 0; }
      /* [M274g/M278, UHA_PBL_WOFF, PROMU default 256] `window = raw + start + 0x100`
       * with `len = remainder - 0x100` : single forme which rende there GT M274 has **20/20 words**
       * (`work/t171_blk_gt`), and `ret = 6848` conforme at the cut has 937 440. */
      { static int woff = -2;
        if (woff == -2) { const char *e = getenv("UHA_PBL_WOFF"); woff = (e && e[0]) ? atoi(e) : 256; }
        if (reste > 0x100u)
            ret = ppm_blocklen(&g_blc, g_blk_raw + start + (size_t)woff,
                               bw ? reste : reste - 0x100u);
        else
            ret = reste;   /* 0x421c99 : no call if len <= 0x100 */
      }
      g_blk_next = start + ret;        { static int nx = -1;
          if (nx < 0) { const char *e = getenv("UHA_M257EMS"); nx = (e && e[0] != '0') ? 1 : 0; }
          if (nx) fprintf(stderr, "[M257NEXT] COUPE next=%u\n", (unsigned)g_blk_next); }

    }
    if (etrace_on >= 1)
        fprintf(stderr, "[BLKLAW] start=%u len=%u ret=%u next=%u\n",
                (unsigned)start, (unsigned)reste, (unsigned)ret,
                (unsigned)g_blk_next);

    blen = (reste > 0x100u) ? reste - 0x100u : reste;
    if (g_blklaw >= 4) {
        /* [M170] LAW COMPLETE of 0x421be0 (two stages, lu en entier - OUT/m170_order.md 2).
         * 0x421ca5 : stage 1 = argmin of COST sure the 5 classes, start cl = TBL[0x43b2c2][cur]
         *             (table lue in the PE = IDENTITE : cl = cur) ; there class of start is
         *             exclue of the loop ([esp+0x1c], never update).
         * 0x421d1e : cb = cost[cl]/ebp/0x249, clampe 0x0A.
         * 0x421d42 : fact1 = (cl == 1 ? 0x50 : 0x4b) - (0x0A - cb)*4  [SOUSTRACTION].
         * 0x421d5f : cl in {0,3} -> stage 2 ; otherwise test fact1*t[cl] > t[0]<<6.
         * 0x42201a : stage 2 = argmax t[1..4], has==3 -> cancels (if t[4] <= t[has]),
         *             fact2 = (ebp >= 0x800 ? 0x50 : 0x41) + (0x0A - cb)*4  [ADDITION].
         * Scores : here `len` = ebp = return of 0x422890 (0x421fff `mov ebp,eax`), not remainder-0x100. */
        uint32_t cost[5];
        uint32_t init, len;
        int a;
        /* [M170g, UHA_BLKLAW>=5] STAGE 1 SURE L'ARENA LIVE. the legacy engine not reconstruit not has
         * model since there window : il copie the lines of the model d'encoding (0x422262).
         * Rules mesurees (OUT/m170g_arenafeed.md 4) :
         *   - feed ONLY for the candidate equal has [0x483934] (there class current, evaluee
         *     en 1er), and NEVER for cl == 0 (0x42225c -> 0x422315) ;
         *   - the others candidates reutilisent l'arena laissee in place (0x42230e) ;
         *   - if there class current n'is not has candidate 0..4, no feed n'has lieu : on
         *     keeps then the path from-scratch (behavior actuel, trace live=0).
         * There table 0x43b290 (nb of contexts by class) is lue in the PE. */
        int live = 0;
        static ppm_cost_arena *s_arena;
        static const uint32_t CLS_NCTX[5] = { 8u, 0x20u, 0x20u, 0x60u, 0x40u }; /* 0x43b290 */
        ppm_live_arena L;

        len = ret;                       /* ebp */
        /* [M248, GATED UHA_PPM_INILAW, default-OFF] THE START OF L'STAGE 1 is TBL[cur], NEVER
         * l'argmin of the cut previous. DOUBLE PROOF sure piece :
         *   - `OUT/m245_cost_mono.tsv` : there column `ini` equals **0** to the 16 cuts of the mono
         *     `records.bin` (cur = 0 partout), then that notre probe `[M247IN]` rend
         *     `cand=4` some `107 526` (value heritee of l'argmin previous) ;
         *   - `OUT/m244_cuts_gt.tsv` : `ini = TBL[0x43b2c2][cur]` partout (whose `ini=1` for
         *     `cur=5` has `1 083 561`).
         * And the re-armement `0x421f81` (`[0x483934] = al`) n'has lieu that if there class is REELLEMENT
         * ecrite (`0x421f79 cmp al,[0x483934] ; je 0x421fda`) : when `cand == cur`, nothing n'is writes
         * nor re-arme. The port, lui, ecrivait `g_blk_start = cl` at each cut. */
        if (g_inilaw_on()) {
            static const uint8_t TBL[10] = { 0, 1, 2, 3, 4, 1, 1, 2, 2, 4 };   /* 0x43b2c2 (PE) */
            init = (uint32_t)TBL[m->flag3934 % 10u];
        } else {
            init = (g_blklaw >= 6) ? g_blk_start : (uint32_t)m->flag3934;
        }
        /* [M170g] `cost[init]` deborderait for has class of model >= 5 (cas produces by has
         * escape : 0x423006 writes 5..9 in [0x483934]). The domaine MEASURES of the start is 0..4
         * (table 0x43b2c2) ; au-dela on revient au start 0 and on trace `oob=1`. */
        if (init >= 5u) {
            if (etrace_on >= 1)
                fprintf(stderr, "[BLKCOST] start=%u init=%u HORS DOMAINE -> depart 0\n",
                        (unsigned)start, (unsigned)init);
            init = 0u;
        }
        if (g_blklaw >= 5) {
            if (!s_arena)
                s_arena = (ppm_cost_arena *)calloc(1, sizeof *s_arena);
            if (ppm_onear_on())
                s_arena = ppm_one_arena();      /* [M219] buffer unique of the master */
            if (s_arena) {
                L.freq = (const uint16_t *)m->freq;
                L.cum = (const uint16_t *)m->cum;
                L.ent = m->ent_wt;
                L.base = CLS_CTXBASE[init];
                L.n = CLS_NCTX[init];
                /* [M170k] 1er term of the node COLD = row of prior 772+cand of the master
                 * (0x30400/0x200 = 772 ; 0x42242b..0x422465). */
                L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + init) * 256u;
                L.prior_total = m->cum[772u + init][0];
                live = 1;
            }
        }
        cl = (int)init;
        /* [M170k] CONTEXT INITIAL of the WINDOW : l'estimator not part no has ctx_bits zero,
         * il the reads in the global `[0x48269c]` (0x422392). This global porte l'state of context
         * 32 bits of the stream, therefore the 4 bytes REELS which previous there window (same convention that
         * ppm_ctx_bits : the more recent en weight FAIBLE, bytes complementes). Has `pos = 0` il
         * equals 0 - c'is why all nos GT (pos = 0) validaient has bord has zero. */
        {
            uint32_t pc = 0u;
            if (start >= 4u)
                pc = (uint32_t)((~g_blk_raw[start - 1u]) & 0xffu)
                   | ((uint32_t)((~g_blk_raw[start - 2u]) & 0xffu) << 8)
                   | ((uint32_t)((~g_blk_raw[start - 3u]) & 0xffu) << 16)
                   | ((uint32_t)((~g_blk_raw[start - 4u]) & 0xffu) << 24);
            ppm_cost_set_prectx(pc);
        }
        /* [M170k] STATES D'INPUT of l'estimator (captures OUT/m170l_state.log) :
         *   bandbase = [0x4803c0] = position of cut of the block (band = (pos+i)%n) ;
         *   initctx  = [0x4803c4] - CTXBASE[cand] for the candidate equal at the class current
         *              (0x422224/0x422232), 0 for the others (0x42230e `xor ebp,ebp`).
         * `m->cls_ctx` porte [0x4803c4] (ppm_post.c : 0x249 + phase*0x20 + T7DC[delta] for
         * there class 3) ; at the decision 2 there measures GT gives 0x28d = 653, i.e. 68 relatif. */
        {
            uint32_t cc = (uint32_t)m->flag3934;
            ppm_cost_set_window(start, 0u);
            ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum));   /* [M267] stream emis reel */
            { extern void ppm_cost_set_outpos(uint32_t), ppm_cost_set_outarm(void);
              ppm_cost_set_outarm();
              ppm_cost_set_outpos((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum)); }
            /* [M271] dump some 4 TABLES OF CONTEXT d'emission (budget/order0_wt/pred_byte/
             * cls_idx, sizes legacy 0x209) at the cut demandee - pairs some `m271_*.bin`. */
            { static int g271 = -1; static long g271p = -2; static int done271 = 0;
              if (g271 < 0) { const char *e = getenv("UHA_M271CTX"); g271 = (e && e[0]) ? 1 : 0;
                              const char *q = getenv("UHA_M271CTX_POS");
                              g271p = (q && q[0]) ? atol(q) : -1; }
              if (g271 && !done271 && (g271p < 0 || (long)start == g271p) && m->budget) {
                  char p2[512]; FILE *f;
                  const char *pfx = getenv("UHA_M271CTX");
                  /* [M280] `UHA_M271CTX_N` etend the dump (default 0x209 = 521, legacy). The front
                   * of the corps is has `pos = 1 070 747` en **class 3** (`cls_ctx = 587`, base 585) :
                   * ses rows (585..680) not are NOT couvertes by 0x209. `=681` the inclut. */
                  static long n271 = -1;
                  if (n271 < 0) { const char *q = getenv("UHA_M271CTX_N"); n271 = (q && q[0]) ? atol(q) : 0x209; }
                  snprintf(p2, sizeof p2, "%s_budget.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) { fwrite(m->budget, 4, (size_t)n271, f); fclose(f); }
                  snprintf(p2, sizeof p2, "%s_order0_wt.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) { fwrite(m->order0_wt, 4, (size_t)n271, f); fclose(f); }
                  snprintf(p2, sizeof p2, "%s_predbyte.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) { fwrite(m->pred_byte, 1, (size_t)n271, f); fclose(f); }
                  snprintf(p2, sizeof p2, "%s_clsidx.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) { fwrite(m->cls_idx, 1, (size_t)n271, f); fclose(f); }
                  snprintf(p2, sizeof p2, "%s_cum0.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) {
                      long r; for (r = 0; r < n271; r++) { uint16_t v = m->cum[r][0]; fwrite(&v, 2, 1, f); } fclose(f); }
                  /* [M307] `_entwt.bin` : there table d'echappement `ent_wt[0..n271-1]` (u16), l'other
                   * term of the feed 0x4222fe. No emissif : single under there gate UHA_M271CTX. */
                  snprintf(p2, sizeof p2, "%s_entwt.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) {
                      fwrite(m->ent_wt, 2, (size_t)n271, f); fclose(f); }
                  /* [M280] `_freq3.bin` : the table `freq` COMPLETE some rows of the class 3
                   * (585..680, 96 x 256 u16 = 49 152 o). `cum[r][0]` (already compares) not dit nothing some
                   * cellules : c'is here that se cache has probabilite legerement false. */
                  snprintf(p2, sizeof p2, "%s_freq3.bin", pfx);
                  if ((f = fopen(p2, "wb")) != NULL) {
                      long r; for (r = 585; r < 681; r++) fwrite(m->freq[r], 2, 256, f);
                      fclose(f); }
                  done271 = 1; } }
            /* [M266, GATED UHA_PPM_AVAILCUT, default-OFF] there queue of stream is desormais armee has
             * l'INPUT of l'estimator : the legacy engine reads son buffer d'input au-dela of the window
             * (`input = base + start + 256`, M172b). Measures : gate ON, there sequence of `cand 0` has
             * `57 883` devient EXACT sure 12 544 nodes and 4 some 5 costs tombent sure there GT
             * (c0/c1/c2/c4) ; gate OFF = behavior historique. En MONO there gate degrade
             * `an_m246` (16/16 -> 8/16) : there bound mono n'is not there same (has trancher). */
            /* [M266, PROMUE 2026-10-30] THERE QUEUE OF STREAM is ARMEE at the INPUT OF L'ESTIMATOR with
             * there SIZE TOTALE of the stream : `g_cost_avail` is compares has has index ABSOLU in
             * `entree_byte`/`law_byte`, now there value laissee by there selection (`0x873`) is has REMAINDER
             * relatif at the beginning of block -> there bound was false some there 1re cut no initiale.
             * Measurements : sequence `cand 0` has `57 883` EXACT sure 12 544 nodes (GT M266) ; mono
             * `an_m246` 16/16 and `an_m155` 12/12 PRESERVES ; front `an_m259_costall` 0/54 -> 4/54
             * single, 36/54 combine has `CTXSAVE`. `=0` restores l'historique (corps identical). */
            { static int av = -1;
              if (av < 0) { const char *e = getenv("UHA_PPM_AVAILCUT"); av = !(e && e[0] == '0'); }
              if (av) { extern void ppm_cost_set_avail(size_t n);
                        if (g_blk_usize) ppm_cost_set_avail((size_t)g_blk_usize); } }
            blk_set_payload(m);
            if (cc < 10u && m->cls_ctx >= CLS_CTXBASE[cc])
                g_blk_initctx = m->cls_ctx - CLS_CTXBASE[cc];
            else
                g_blk_initctx = 0u;
            if (etrace_on >= 1)
                fprintf(stderr, "[BLKWIN] start=%u cls_ctx=%u cl=%u initctx=%u last=%u flag=%u\n",
                        (unsigned)start, (unsigned)m->cls_ctx, (unsigned)cc,
                        (unsigned)g_blk_initctx,
                        (unsigned)m->cls_base, (unsigned)m->cls_neg);
            /* [M247, GATED UHA_M247IN, default-OFF, read-only] STATES D'INPUT of l'estimator
             * at each cut, in the format of the GT demandee (MISSION_M247_estern.md) : these
             * global are lues by `0x4221c0` and NOT are NOT visibles in the stream encode (there
             * window of cut `76 806` of the mono `records.bin` is already false of +36 % then that
             * the 5 cuts previous are bit-exact) : c'is therefore Has STATE which diverge, not there
             * formule. no effect : there gate n'imprime that. */
            { static int ei = -1;
              if (ei < 0) { const char *e = getenv("UHA_M247IN"); ei = (e && e[0] != '0') ? 1 : 0; }
              if (ei)
                  fprintf(stderr, "[M247IN] pos=%u cand=%d len=%u cur=%d bc=%d cls_ctx=%u "
                          "initctx=%u cls_neg=%u r0=%u r1=%u r2=%u step2=%u base46=%d win_pos=%u\n",
                          (unsigned)start, (int)init, (unsigned)len, (int)m->flag3934,
                          (int)m->byte_class, (unsigned)m->cls_ctx, (unsigned)g_blk_initctx,
                          (unsigned)m->cls_neg, (unsigned)m->roll_ctx0, (unsigned)m->roll_ctx1,
                          (unsigned)m->roll_ctx2, (unsigned)(uintptr_t)m->tstep2, (int)m->base46,
                          (unsigned)m->win_pos); }
        }
        /* [M170i, UHA_BLKLAW>=6] AMORCAGE UNIQUE of l'arena of travail : the buffer legacy is
         * persistant and contient already has state validates (nourri) at the 1re decision ; nos lines
         * `n..95` seraient otherwise has `total = 0` as soon as the `ctx` of has candidate depasse `n`.
         * Hypothese testee (and no postulee) : this state = the model live of the class current.
         * The judge is the cost GT of the decision 1 (`0x046a185c`). */
        if (g_blklaw >= 6 && live) {
            static int seeded = 0;
            uint32_t sc = (uint32_t)m->flag3934;
            if (sc >= 5u)
                sc = 0u;
            /* [M246, GATED UHA_PPM_RELOAD, default-OFF] EPROUVE : l'amorce n'was faite qu'once
             * by encoding (`!seeded`), then that the master recharge/nourrit son arena at each
             * frontier (0x421c48 -> 0x426bf0, then feed of the candidate = [0x483934] en 0x422262).
             * GT some 5 costs (OUT/m245_cost_mono.tsv) : exact to the 7 first cuts mono then
             * +45 % au 8e (92 166) -> signature of has arena PERIMEE. Gate ON : re-amorce at each
             * cut. */
            { static int rl = -1;
              if (rl < 0) { const char *e = getenv("UHA_PPM_RELOAD"); rl = (e && e[0] != '0') ? 1 : 0; }
              if (rl) seeded = 0; }
            if (!seeded) {
                ppm_live_arena S = L;
                S.base = CLS_CTXBASE[sc];
                S.n = CLS_NCTX[sc];
                (void)ppm_cost_arena_load_live(s_arena, &S);
                seeded = 1;
            }
        }
        /* [M170h, UHA_BLKLAW>=6] Probe : state of l'arena of travail HERITE, juste before
         * the feed of the 1er candidate = exactement l'instant of the dump GT of `[0x43a26c]` (96 words).
         * at the decision 1 l'arena is vierge (calloc) ; at the decision 2 elle porte l'state leaves
         * by the 5 simulations of the decision 1 -> judge direct of the STRING of simulation. */
        if (live) {
            static int ba = -1;
            uint32_t k96;
            if (ba < 0) { const char *e = getenv("UHA_BLKARENA"); ba = (e && e[0] != '0') ? atoi(e) : 0; }
            if (ba) {
                fprintf(stderr, "[BLKARENA] start=%u n=%u init=%u", (unsigned)start,
                        (unsigned)L.n, (unsigned)init);
                /* [M249] `UHA_BLKARENA=2` publie the 96 rows (and no `n` single) : there GT
                 * `OUT/m249_arena_tot.tsv` montre of the NO-ZERO au-dela of `n` (t8..t11) -> single has
                 * dump complete discrimine has indexation RELATIVE of has indexation ABSOLUE. */
                for (k96 = 0; k96 < (ba >= 2 ? 96u : L.n); k96++)
                    fprintf(stderr, " %u", (unsigned)s_arena->total[k96]);
                fprintf(stderr, "\n");
                /* [M249] `UHA_BLKARENA=3` publie also the 96 `escape[]` : discriminant between has
                 * feed hot surnumeraire (total single +32) and has false cold (total AND escape +32,
                 * same row) - cf. OUT/m249_arena.md 5. */
                if (ba >= 3) {
                    fprintf(stderr, "[BLKARENAE] start=%u", (unsigned)start);
                    for (k96 = 0; k96 < 96u; k96++)
                        fprintf(stderr, " %u", (unsigned)s_arena->escape[k96]);
                    fprintf(stderr, "\n");
                }
            }
            /* [M170k, UHA_BLKMASTER, default-OFF] CONTENU OF THE MASTER by row at the instant of the
             * feed : `total = ent_wt[abs] + cum[abs][0]` (law of 0x4222fe, cf. load_live).
             * Judge direct of the dump GT `OUT/m170h_tot_{dec2,dec2b}.txt` : if l'arena GT less this
             * total is has multiple of 32, the master is EXACT and l'gap vient of the ROUTAGE some
             * nodes (ctx) ; otherwise the master differe. */
            {
                static int bm = -1;
                if (bm < 0) { const char *e = getenv("UHA_BLKMASTER"); bm = (e && e[0] != '0') ? 1 : 0; }
                if (bm) {
                    fprintf(stderr, "[BLKMASTER] start=%u base=%u n=%u", (unsigned)start,
                            (unsigned)L.base, (unsigned)L.n);
                    for (k96 = 0; k96 < L.n; k96++) {
                        uint32_t ab = L.base + k96;
                        fprintf(stderr, " %u",
                                (unsigned)(m->ent_wt[ab] + m->cum[ab][0]));
                    }
                    /* [M204-B] ANCRE DECOMPOSEE. `[BLKMASTER]` publie has sum
                     * (`ent_wt[abs] + cum[abs][0]`, law of 0x4222fe) : no reading mono-cellule
                     * in there memory of the master not peut l'egaler - this negativisme of M204-B phase Has
                     * was therefore structurel, not has question d'offset. This line rend the TWO
                     * terms SEPARERMENT, more the first cellules of the line of frequency, for
                     * that l'adressage i.e. prouve by confrontation cellule has cellule.
                     * Limit to the small classes (n <= 16) for not not emitter some lines long. */
                    if (L.n <= 16u) {
                        for (k96 = 0; k96 < L.n; k96++) {
                            uint32_t ab = L.base + k96;
                            fprintf(stderr,
                                    "\n[BLKMTAB] start=%u cls=%u abs=%u ent=%u cum0=%u sum=%u"
                                    " f0=%u f1=%u f2=%u f3=%u f88=%u f255=%u",
                                    (unsigned)start, (unsigned)init, (unsigned)ab,
                                    (unsigned)m->ent_wt[ab], (unsigned)m->cum[ab][0],
                                    (unsigned)(m->ent_wt[ab] + m->cum[ab][0]),
                                    (unsigned)m->freq[ab][0], (unsigned)m->freq[ab][1],
                                    (unsigned)m->freq[ab][2], (unsigned)m->freq[ab][3],
                                    (unsigned)m->freq[ab][88], (unsigned)m->freq[ab][255]);
                        }
                        fprintf(stderr, "\n");
                    }
                    fprintf(stderr, "\n");
                    /* [M170k] ROWS OF PRIOR 772+cl (0x304..0x30D) : the 1er term of the node COLD
                     * is `LUT[(freq[772+cl][err]<<14) / cum[772+cl][0]]` (0x42242b..0x422465),
                     * NOT has constante. `cl` = class of l'call (0..4 estimator ; 5..9 family
                     * of the scan, 0x422e0a). On imprime cum[0] + freq[0]/freq[1]/freq[88]/freq[255]
                     * for the 10 classes. */
                    {
                        uint32_t pr;
                        for (pr = 0; pr < 10u; pr++) {
                            uint32_t row = 772u + pr;
                            fprintf(stderr, "[BLKPRIOR] start=%u row=%u cum0=%u f0=%u f1=%u f88=%u f255=%u\n",
                                    (unsigned)start, (unsigned)row,
                                    (unsigned)m->cum[row][0], (unsigned)m->freq[row][0],
                                    (unsigned)m->freq[row][1], (unsigned)m->freq[row][88],
                                    (unsigned)m->freq[row][255]);
                        }
                    }
                }
            }
        }
        /* [M220, UHA_PPM_ROWSEL] LAW 0x422315 : l'snapshot of the model of distance
         * (`last[]` 0x46af50, `dhist[]` 0x469f48, registres 0x481c00/04/08) n'is rafraichi
         * since the tables LIVE that if `cand == [0x483934] == 0` - exactement the two
         * frontiers now there path `live` is devastee (305 696, 937 696 ; M219-D 2). */
        if (live && ppm_cost_rowsel_on() && s_arena) {
            static int frc2 = -1;
            if (frc2 < 0) { const char *e = getenv("UHA_PPM_ROWSEL_FORCE"); frc2 = (e && e[0] != '0') ? 1 : 0; }
            if (init == 0u || frc2)
                ppm_cost_rowsel_feed_live(s_arena, g_blk_raw, (size_t)start);
        }
        cost[init] = (uint32_t)(live
            /* [M170h] The NO-feed for `cl == 0` n'is NOT prouve : the dump GT of `tot[]` is pris
             * at the INPUT of l'call, therefore il not dit nothing of the feed of this same call. Test croise :
             * without feed at the decision 1 the 5 costs explosent (94 564 815 au lieu of 74 061 916),
             * with feed ils tombent exactement sure there GT. On nourrit therefore ALWAYS the 1er candidate. */
            ? (ppm_cost_set_window(start, ((uint32_t)init == (uint32_t)m->flag3934) ? g_blk_initctx : 0u),
               ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum)),
               blk_set_payload(m),
               blk_set_flag(m, init),
               ppm_legacy_cost_live(s_arena, g_costwin(start), len, init, 0xFFFFFFFFu, &L, 1))
            : ppm_legacy_cost(g_costwin(start), len, init, 0xFFFFFFFFu));
        /* [M170k, UHA_BLKAFTER, default-OFF] ARENA AFTER there simulation of the 1er candidate = l'instant
         * EXACT of the dump GT `OUT/m170h_tot_dec2b.txt` (hit 7 = input of the 2e call of the decision 2,
         * after that the candidate 3 eut tourne). Judge of the couple (contenu of the feed + sequence). */
        if (live) {
            static int bf = -1;
            if (bf < 0) { const char *e = getenv("UHA_BLKAFTER"); bf = (e && e[0] != '0') ? 1 : 0; }
            if (bf) {
                uint32_t k96;
                fprintf(stderr, "[BLKAFTER] start=%u cand=%d n=%u cost=%u", (unsigned)start,
                        (int)init, (unsigned)L.n, (unsigned)cost[init]);
                for (k96 = 0; k96 < 96u; k96++)
                    fprintf(stderr, " %u", (unsigned)s_arena->total[k96]);
                fprintf(stderr, "\n");
            }
        }
        for (j = 0; j < 5; j++) {
            if ((uint32_t)j == init)
                continue;
            /* [M250B, GATED UHA_M250B, default-OFF, read-only] The 96 `total[]` of l'arena
             * at the INPUT of CHACUN SOME 4 CALLS OF LOOP of l'stage 1 = l'instant EXACT some 64
             * hits GT of the site `0x421ce2` (`OUT/m250_arena_calls.tsv`). The port n'had NO
             * measures between l'call `init` (site `0x421cb7`, already couvert by `[BLKARENA]`) and
             * these 4 calls-there : without this probe, 64 some 80 vecteurs GT restent incomparables and
             * there question " l'arena is-elle RECONSTRUITE by candidate now ACCUMULEE by feeds ? "
             * is indecidable side port. no effect : there gate n'imprime that. Order some candidates
             * in there GT (verified hit has hit) : 1,2,3,4 croissants, `init` exclusive.
             *  The prompt " ter " citait has probe `UHA_M250A` : elle n'existe not in the port
             * (grep 0 hit) ; c'is `[BLKARENA]` which joue this role, at the input of l'call `init`. */
            if (live && s_arena) {
                static int mb = -1;
                if (mb < 0) { const char *e = getenv("UHA_M250B"); mb = (e && e[0] != '0') ? 1 : 0; }
                if (mb) {
                    uint32_t kmb;
                    fprintf(stderr, "[M250B] pos=%u cand=%d len=%u", (unsigned)start, (int)j,
                            (unsigned)len);
                    for (kmb = 0; kmb < 96u; kmb++)
                        fprintf(stderr, " %u", (unsigned)s_arena->total[kmb]);
                    fprintf(stderr, "\n");
                }
            }
            /* [M219, UHA_PPM_ONEARENA] LAW 0x422226 (`jne 0x42230e`) : nor state d'input nor feed
             * for the candidates different of `[0x483934]` - l'arena keeps the materiau leaves by
             * the 1er candidate. Priorite sure there path M170j (feed by candidate), which remainder the default. */
            if (live && ppm_onear_on()) {
                L.base = CLS_CTXBASE[(uint32_t)j];
                L.n = CLS_NCTX[(uint32_t)j];
                L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)j) * 256u;
                L.prior_total = m->cum[772u + (uint32_t)j][0];
                cost[j] = (uint32_t)ppm_legacy_cost_live(s_arena, g_costwin(start), len,
                                                        (uint32_t)j, cost[cl], &L, 0);
            } else if (live && g_blklaw >= 7) {
                L.base = CLS_CTXBASE[(uint32_t)j];
                L.n = CLS_NCTX[(uint32_t)j];
                L.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)j) * 256u;
                L.prior_total = m->cum[772u + (uint32_t)j][0];
                ppm_cost_set_window(start, ((uint32_t)j == (uint32_t)m->flag3934) ? g_blk_initctx : 0u);
                ppm_cost_set_ctxband((uint32_t)(m->w->pos + 1u + (size_t)m->w->ffnum));   /* [M267] stream emis reel */
                blk_set_payload(m);
                blk_set_flag(m, (uint32_t)j);
                cost[j] = (uint32_t)ppm_legacy_cost_live(s_arena, g_costwin(start), len,
                                                        (uint32_t)j, cost[cl], &L, 1);
            } else {
                cost[j] = (uint32_t)(live
                    ? ppm_legacy_cost_live(s_arena, g_costwin(start), len, (uint32_t)j,
                                           cost[cl], &L, 0)
                    : ppm_legacy_cost(g_costwin(start), len, (uint32_t)j, cost[cl]));
            }
            if (cost[j] < cost[cl])
                cl = j;
        }
        /* [M330, M361] CAPTURES of l'stage 1. `cl` is RECYCLE more low by l'stage 2
         * (`cl = has` au ratio, `cl = j` at the argmax of `t[1..4]`) : there value that the master
         * preserves when there walk rentre 0 (`0x421dae` skips) is the one d'BEFORE l'stage 2,
         * rendue by `[BLKCOST] cl=`. Measures of the 2026-11-02, cut 937 440 : `[BLKCOST] cl=0`
         * (GT `ini = 0`, `cur = 0` => no tete) but `[BLKSEL] cl=1` (argmax of `t`) -
         * the repli which lisait `cl` emettait therefore has escape parasite `sel=1`.  The to read here.
         * `bud = cost[cl]` (line next) is already computed sure this value : same seed.
         *  GT M244/M330 : `1 136 284` -> `ini=1, cand=1, cur=5` (repli -> escape) ;
         *   `937 440` -> `ini=0, cand=0, cur=0` (repli -> egalite, NO tete) ;
         *   `1 108 664`/`1 121 693` -> `ini=1, cand=5, cur=5` (walk no annulee, no tete). */
        stage1 = cl;
        /* [M170h, UHA_BLKLAW>=6] RE-ARMEMENT 0x421f81 : `[0x483934] = winner of l'stage 1`
         * (the `dh` rendu by 0x4221c0, remis in `[esp+0x20]`). Does BEFORE l'stage 2, because
         * l'stage 2 writes has other slot ([esp+0x24]). */
        if (g_blklaw >= 6 && !g_inilaw_on()) {
            g_blk_start = (uint32_t)cl;
            /* [M202 UHA_PPM_SEEDLAG] journalise l'writing for the mirror d'emission ; the
             * mirror d'horloge window (`g_blk_start`) remainder THERE SOURCE some decisions in-stream
             * (no regression volontaire : has variable at the fois). */
            if (ppm_seedlag_on())
                ppm_seed_mirror_push(start, (uint32_t)cl);
        }
        bud = cost[cl];                /* [M170k] 0x421d96 : 3 arg (ebx) of the family = budget */
        cb = len ? (cost[cl] / len / 0x249u) : 0x0Au;
        if (cb > 0x0Au)
            cb = 0x0Au;
        /* [M274, GATED UHA_PPM_CBVAL, default -1 = law historique] TEST OF SENSIBILITE sure `cb`
         * (C'is THIS SITE WHICH NOURRIT L'STAGE 2 OF THE path ACTIVE : `[BLKSEL]` affiche `fact=65`
         * has `start=937 440`, value which not peut venir that of the formule ASM `(len>=0x800 ?
         * 0x50 : 0x41) + (0x0A-cb)*4` with `len=256` and `cb=10`).
         * Measures M274 (`OUT/m274_t937440.md`) : has `0x42206f`, `pos = 937 440`, the master has
         * **`ebx(cb) = 0`** ; there reconstruction `cost[cl]/len/0x249` gives 10. with `cb = 0` :
         * `fact = 105` -> `fact*t[0]` (528 570 with the t of the master) `> t[1]<<6` (328 704,
         * argmax master `eax = 1`) -> **no changement** = class 0 = this that code the master.
         * value forcee = TEST of sensibilite, NOT has law : there law of `ebx` remainder has etablir. */
        { static long cbv = -2;
          if (cbv == -2) { const char *e = getenv("UHA_PPM_CBVAL"); cbv = (e && e[0]) ? atol(e) : -1; }
          if (cbv >= 0) cb = (uint32_t)cbv; }
        /* [M170e] `cost[cl]` is there bound transmise at the family (3 arg `ebx`,
         * 0x421d96). Trace for there to compares to the values mesurees (F1). */
        if (etrace_on >= 1)
            fprintf(stderr, "[BLKCOST] start=%u len=%u cost=[%u %u %u %u %u] cl=%d live=%d\n",
                    (unsigned)start, (unsigned)len,
                    (unsigned)cost[0], (unsigned)cost[1], (unsigned)cost[2],
                    (unsigned)cost[3], (unsigned)cost[4], cl, live);
        fact = (uint32_t)((cl == 1 ? 0x50 : 0x4b) - (0x0Au - cb) * 4u);
        /* [M202, GATED UHA_PPM_RATIO2, default-OFF] PROBE D'GAP OF TABLE. L'stage 1 of the path
         * promu reads `g_blc.t[]` (0x4803a4) then that l'ASM 0x421d7c/0x421d83 reads 0x480390 (= notre
         * `t5`, mapping MEASURES C2/C5, OUT/m170c_result.md) and that there recopiee of the mode 5 reads `t5`.
         * Rend the TWO verdicts without nothing changer ; judge = liste some decisions now ils different.
         * Consigne in OUT/m202_seed_mirror.md 6 ; NO correction cablee here. */
        {
            static int r2 = -1;
            if (r2 < 0) { const char *e = getenv("UHA_PPM_RATIO2"); r2 = (e && e[0] != '0') ? 1 : 0; }
            if (r2) {
                int vt = (cl != 0 && cl != 3 &&
                          (uint32_t)(fact * g_blc.t[cl]) > (uint32_t)(g_blc.t[0] << 6));
                int v5 = (cl != 0 && cl != 3 &&
                          (uint32_t)(fact * g_blc.t5[cl]) > (uint32_t)(g_blc.t5[0] << 6));
                fprintf(stderr, "[RATIO2] start=%u len=%u cl=%d cb=%u fact=%u"
                        " t=[%u %u %u %u %u] t5=[%u %u %u %u %u] chg_t=%d chg_t5=%d DIFF=%d\n",
                        (unsigned)start, (unsigned)len, cl, (unsigned)cb, (unsigned)fact,
                        (unsigned)g_blc.t[0], (unsigned)g_blc.t[1], (unsigned)g_blc.t[2],
                        (unsigned)g_blc.t[3], (unsigned)g_blc.t[4],
                        (unsigned)g_blc.t5[0], (unsigned)g_blc.t5[1], (unsigned)g_blc.t5[2],
                        (unsigned)g_blc.t5[3], (unsigned)g_blc.t5[4], vt, v5, vt != v5);
            }
        }
        chg = 0;
        if (cl != 0 && cl != 3 &&
            (uint32_t)(fact * g_blc.t[cl]) > (uint32_t)(g_blc.t[0] << 6)) {
            chg = 1;
        } else if (ppm_et2_on() && (ppm_et2_thr() < 0 || (long)len > ppm_et2_thr())) {
            /* [M170c] stage 2 : the TWO lectures (argmax AND test of ratio) portent sure the
             * table 0x480390 = notre `t5` (C2). PROOF mesuree (H2) : au block 3 of mixed,
             * `ebx = fact2*t[0] = 330330` with `fact2 = 65` => `t[0] = 5082`, and
             * `ecx = t[has]<<6 = 341376` => `t[has] = 5334` : this are the values of notre `t5`
             * (5082..5334), no notre `t` (144712..). To read `t` faussait the verdict. */
            a = 1;
            if (g_blc.t5[2] > g_blc.t5[a])
                a = 2;
            if (g_blc.t5[3] > g_blc.t5[a])
                a = 3;
            if (g_blc.t5[4] > g_blc.t5[a])
                a = 4;
            else if (a == 3)
                a = -1;                  /* 0x4220b1 : argmax == 3 -> no changement */
            if (a >= 0) {
                /* [M274, GATED UHA_PPM_FACT2, default-OFF] `fact` OF L'STAGE 2 - DOUBLE APPLICATION.
                 * ASM : `ebx` is transforme en `(0x0A - cb)*4` some `0x421d32` (`lea esi,[edx*4]`
                 * with `edx = 0x0A - cb`) then clampe has `0x0A` en `0x42205c/0x4220bb` ; has
                 * `0x422061..0x422068` the code refait `ecx = 0x0A - ebx` THEN `ebx = ecx*4`.
                 * There measures M274 the confirme : has `0x42206f` (juste after `0x422068`), `ebx = 0`
                 * for `pos = 937 440`, now `cb = 10` y gives `(0x0A-10)*4 = 0` (cb=0 aurait gives
                 * 40). The port not faisait only to  application (`0x41 + (0x0A-cb)*4` = 65) : there
                 * true value is 105, now `105*t[0] = 528 570 > t[1]<<6 = 328 704` at the
                 * master -> no changement (class 0 = GT), then that the port basculait has 2/7. */
                { static int f2 = -1;
                  if (f2 < 0) { const char *e = getenv("UHA_PPM_FACT2"); f2 = (e && e[0] != '0') ? 1 : 0; }
                  if (f2) {
                      uint32_t e2 = 4u * (0x0Au - cb);
                      if (e2 >= 0x0Au)
                          e2 = 0x0Au;
                      fact = ((len >= 0x800u) ? 0x50u : 0x41u) + 4u * (0x0Au - e2);
                  } else
                      fact = ((len >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
                }
                if ((uint32_t)(g_blc.t5[a] << 6) > (uint32_t)(fact * g_blc.t5[0])) {
                    cl = a;
                    chg = 1;
                }
            }
        }
        /* [M259, GATED UHA_PPM_TINYLEN] voir there definition of the gate : there cut has `len <= 0x100`
         * rend `ini` at the master (5/5 cuts mesurees), and the port n'y rend never `ini` when
         * l'argmin now there family divergent. Forcement of the value RENDUE only : the costs
         * are calcules and nourris as before (l'arena remainder identical). */
        if (ppm_tinylaw_on() && len <= 0x100u) {
            static const uint8_t TBLI[10] = { 0, 1, 2, 3, 4, 1, 1, 2, 2, 4 };   /* 0x43b2c2 (PE) */
            int rendu = (int)TBLI[(uint32_t)m->flag3934 % 10u];
            if (etrace_on >= 1)
                fprintf(stderr, "[M259TINY] start=%u len=%u argmin=%d -> ini=%d cur=%d chg=%d\n",
                        (unsigned)start, (unsigned)len, cl, rendu, (int)m->flag3934, chg);
            cl = rendu;
            chg = 0;
            ncls = -1;
        }
        if (etrace_on >= 1)
            fprintf(stderr, "[BLKSEL] cl=%d t0=%u t1=%u t2=%u t3=%u t4=%u cb=%u fact=%u chg=%d courante=%d lzp_ctx=%d base46=%d\n",
                    cl, (unsigned)g_blc.t5[0], (unsigned)g_blc.t5[1],
                    (unsigned)g_blc.t5[2], (unsigned)g_blc.t5[3], (unsigned)g_blc.t5[4],
                    (unsigned)cb, (unsigned)fact, chg, (int)m->flag3934,
                    lzp_ctx, (int)m->base46);
        ppm_famsite("A1_classfw_start", (uint32_t)start, (uint32_t)len);
        if (chg)
            ncls = ppm_blk_class_fw(cl, g_blk_raw + start, len);
    } else {
        /* [M169 lot 2] stage 2 single (argmax t[1..4]), preserves for comparaison. */
        for (j = 1; j < 5; j++)
            if (g_blc.t[j] > g_blc.t[cl])
                cl = j;
        (void)ppm_legacy_cost_select_class(g_blk_raw + start, blen,
                                           (uint32_t)m->flag3934,
                                           ppm_legacy_cost, &cbest);
        bud = cbest;
        if (blen)
            cb = (uint32_t)(cbest / blen / 0x249u);
        if (cb > 0x0Au)
            cb = 0x0Au;
        fact = ((blen >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
        chg = ((uint32_t)(g_blc.t[cl] << 6) > (uint32_t)(fact * g_blc.t[0])) ? 1 : 0;
        if (etrace_on >= 1)
            fprintf(stderr, "[BLKSEL] cl=%d t0=%u t1=%u t2=%u t3=%u t4=%u cb=%u fact=%u chg=%d courante=%d lzp_ctx=%d base46=%d\n",
                    cl, (unsigned)g_blc.t[0], (unsigned)g_blc.t[1],
                    (unsigned)g_blc.t[2], (unsigned)g_blc.t[3], (unsigned)g_blc.t[4],
                    (unsigned)cb, (unsigned)fact, chg, (int)m->flag3934,
                    lzp_ctx, (int)m->base46);
        ppm_famsite("A2_classfw_blen", (uint32_t)start, (uint32_t)blen);
        if (chg)
            ncls = ppm_blk_class_fw(cl, g_blk_raw + start, blen);
    }
    if (etrace_on >= 1)
        fprintf(stderr, "[BLKSEL]   -> classe=%d\n", ncls);
    if (m417dbg_on())
        fprintf(stderr, "[M417DBG][sel A2] start=%u chg=%d ncls=%d cl=%d courante=%d\n",
                (unsigned)start, chg, ncls, cl, (int)m->flag3934);
    /* [GATED UHA_M255GRID, default-OFF, no emissif, ISOLAT M255] Grille of cuts of the PORT au
     * format of `OUT/m256_route.tsv` (the master publie `arg cls_lue cur pos next` has SES 66
     * cuts). Judge nine : there class WINNING cut by cut en config multi-members, there now the
     * judge some 16 cuts mono is sature but muet sure the multi. `arg` = byte of context
     * (0xff = frontier of member, outside of this site) ; `cand` = this that l'escape coderait
     * (family if elle has parle, otherwise argmin) ; `cur` = `[0x483934]`. */
    { static int gr = -1;
      if (gr < 0) { const char *e = getenv("UHA_M255GRID"); gr = (e && e[0] != '0') ? 1 : 0; }
      if (gr)
          /* [M359-B, columns AJOUTEES, gate inchangee `UHA_M255GRID`, no emissif] `rec0..rec3` =
           * there column of class LZP of l'escape for THIS context. Mirror EXACT of l'enregistrement
           * master of 8 o lu en `0x421de4` has `[0x46B358 + 8*arg]` : the master loads
           * `n=[rec+6]` -> `[0x481C20]`, `low=[rec+0]` -> `[0x481C24]`, `high=[rec+2]` ->
           * `[0x481C28]` (u16 has +0 / +2 / +6 ; the word of +4 n'is NOT consumes by this encode),
           * then `range/=n ; low+=range*low ; range*=(high-low)` = `uha_rcw_encode(low,high,n)`.
           * `pw` = position of buffer au moment of the decision (coordonnee archive = `pw+39`) :
           * c'is THE repere which aligne there grille of the port sure there trainee `[TERMRENORM]` and sure there
           * trace M328 Has.1. `esc_emis` = the verdict reel of the branch (`cand != cur`) : il separe
           * officiellement " the port not code not l'escape here " of " the port the code " (front of the
           * block terminal, M359). */
          fprintf(stderr, "[M255GRID] arg=%d cand=%d cur=%d lzp=%d fin_membre=%d pos=%u next_lu=%u next_new=%u rec0=%u rec1=%u rec2=%u rec3=%u esc_emis=%d pw=%zu\n",
                  lzp_ctx, (ncls >= 0) ? ncls : (int)cl, (int)m->flag3934, lzp_ctx, -1,
                  (unsigned)start,
                  (unsigned)g_blk_next_entry, (unsigned)g_blk_next,
                  (unsigned)m->lzp_class_rec[lzp_ctx & 0xFF][0],
                  (unsigned)m->lzp_class_rec[lzp_ctx & 0xFF][1],
                  (unsigned)m->lzp_class_rec[lzp_ctx & 0xFF][2],
                  (unsigned)m->lzp_class_rec[lzp_ctx & 0xFF][3],
                  ((ncls >= 0 ? ncls : (int)cl) != (int)m->flag3934 && lzp_ctx >= 0) ? 1 : 0,
                  (size_t)m->w->pos);
    }
    /* [M244, GATED UHA_PPM_ESCANY, default-OFF] voir ppm_escany_on(). Gate ON : `cand` = there
     * class CANDIDATE of l'ASM (family if elle has parle, otherwise argmin `cl`) and l'escape is
     * emis as soon as `cand != [0x483934]`, that there family ait parle now no (0x4220da). */
    { int cand = (ncls >= 0) ? ncls : (int)cl;
    int entrer = (cand != (int)m->flag3934 && lzp_ctx >= 0 && (ncls >= 0 || ppm_escany_on()));
    /* [M330, GATED FAMADV] il faut CONSULTER there keeps of budget same when the laureat coincide
     * with there current : at the master there walk is appelee in all the cas and son return 0
     * does vivre the test d'egalite sure there value d'stage 1 (`cl`), which peut differer of the
     * current then that the laureat en coincidait. On n'between here that if this repli is susceptible
     * of changer the verdict (`cl != current`), for not not payer has scan useless.
     * Gate OFF : `entrer` is exactement l'expression historique. */
    if (!entrer && ppm_repli_on() && lzp_ctx >= 0 && ncls >= 0 && bud && g_blklaw >= 8 &&
        stage1 != (int)m->flag3934)
        entrer = 1;
    if (entrer) {
        int erc;
        int go = 1;
        /* [M170k, UHA_BLKLAW>=8] SCAN OF COST `0x422d00..0x423245` : " there family rend there
         * class " is FALSE - `al = class` ssi `ebp < budget` (0x423199 : `ebp >= budget`
         * -> al = 0, therefore no escape). Arena = model live of the class `ncls` (feed
         * 0x422e1a) ; machine d'state 0x423650/0x4232a0 sure has COPIE of the model `*m`.
         * States d'input MEASUREMENTS (OUT/m170g_result_port.md) : last(0) = flag(0) = 0,
         * win_idx(0) = position of cut, ctx_abs(0) = m->cls_ctx. */
        if (g_blklaw >= 8 && ncls >= 0 && ncls < 10 && bud) {
            static ppm_cost_arena *s_scan;
            static ppm_model *s_save;
            static ppm_model *s_rest;   /* [M241] copie PRISTINE of restitution */
            if (!s_scan)
                s_scan = (ppm_cost_arena *)calloc(1, sizeof *s_scan);
            if (ppm_onear_on())
                s_scan = ppm_one_arena();       /* [M219] same buffer that l'estimator */
            /* [M278, GATED UHA_FAMARENA, default-OFF] buffer UNIQUE. The master has only Has arena of
             * cost (`0x43a264`) : l'estimator of frontier (`0x4221c0`, 5 evaluations) there NOURRIT,
             * then there family `0x422d00` there REUTILISE. The port recharge has arena neuve for there
             * family (`t = 1` au 1er node, measures `[FAMN] i=0 t=1`) : the `t` restent ~8 500 there now
             * has buffer pre-nourri donnerait `t` proche of the plafond 0x4000, therefore some costs ~40 000.
             * `=1` consumes `g_farena` (l'arena laissee by l'estimator), without rechargement. */
            { static int fa = -1;
              if (fa < 0) { const char *e = getenv("UHA_FAMARENA"); fa = (e && e[0] != '0') ? 1 : 0; }
              if (fa && g_farena)
                  s_scan = g_farena; }
            if (!s_save)
                s_save = (ppm_model *)malloc(sizeof *s_save);
            if (!s_rest)
                s_rest = (ppm_model *)malloc(sizeof *s_rest);
            if (s_scan && s_save && s_rest) {
                ppm_live_arena SL;
                ppm_blk_scan_in sin;
                ppm_blk_scan_out sout;
                int cs;            /* [M278] class of the MODEL of the scan (base/nctx/prior/machine) */
                SL.freq = (const uint16_t *)m->freq;
                SL.cum = (const uint16_t *)m->cum;
                SL.ent = m->ent_wt;
                /* [M278, UHA_PBL_SCCLS, RETRACTE : default 0] class of the model of the scan of cost.
                 *  There promotion `=1` of the cycle is RETRACTEE : there GT M278 gives `ctx_abs = 745`
                 * sure the 253 nodes, now `745 = CTXBASE[5]` and `rel = ctx_abs - CTXBASE[class]`,
                 * therefore there class of the scan is well `ncls` (5), not `cl` (1). with `=1` the denominateur
                 * partait of `t = 353` au lieu of `t = 1` (arena pre-nourrie has tort).
                 * PROOF of l'inversion : `=0` + `UHA_BLKSCANCLS=1` rend the 4 first nodes
                 * EXACTEMENT equal au master (`sym` 161/174/162/43, `t` 1/65/129/193,
                 * `esc` 1/33/65/97, `ebp` 37440/79456/121524/163609). */
                { static int scl = -1;
                  if (scl < 0) { const char *e = getenv("UHA_PBL_SCCLS"); scl = (e && e[0] != '0') ? 1 : 0; }
                  cs = scl ? cl : ncls; }
                SL.base = CLS_CTXBASE[cs];
                SL.n = CLS_NCTX10[cs];
                SL.prior_freq = (const uint16_t *)m->freq + (size_t)(772u + (uint32_t)cs) * 256u;
                SL.prior_total = m->cum[772u + (uint32_t)cs][0];
                if (s_scan == g_farena || ppm_onear_on() || ppm_cost_arena_load_live(s_scan, &SL)) {
                    memset(&sin, 0, sizeof sin);
                    /* [M243] SYMBOLES. [M278, GATED UHA_FAMHISTNEG] Measures master has pos=937440 :
                     * `sym(it=0) = 161 = ~94 = ~raw[937440]`, then that `g_blk_sym[937440] = 141`.
                     * => l'arena d'historique of legacy (`0x43a21c`) porte l'byte RAW **negate**,
                     * and there branch `it < 0x100` (0x423046) the reads tel which (there branch block does already
                     * `not bh` en 0x4231b0). Armer there gate forces `hist = g_blk_raw` (and there negation
                     * is appliquee side scan). */
                    sin.hist = g_blk_sym ? g_blk_sym : g_blk_raw;
                    { static int hn = -1;
                      if (hn < 0) { const char *e = getenv("UHA_FAMHISTNEG"); hn = (e && e[0] == '0') ? 0 : 1; }
                      if (hn) sin.hist = g_blk_raw; }
                    sin.win = g_blk_raw + start + 0x100u;  /* 0x4231ac reads win[it-0x100] */
                    sin.len = ret;   /* = `ebp` of 0x421fff : there length of the block simule */
                    sin.base = SL.base;
                    sin.nctx = SL.n;
                    sin.step2 = m->tstep2;
                    sin.st.ctx_abs = m->cls_ctx;
                    sin.st.last = 0u;
                    sin.st.flag = 0u;
                    sin.st.win_idx = start;
                    sin.step = getenv("UHA_BLKNOSTEP") ? NULL : blk_scan_step;
                    sin.ud = m;
                    *s_save = *m;                  /* machine sure COPIE */
                    *s_rest = *m;                  /* [M241] state PRISTINE of restitution */
                    /* [M170m, UHA_BLKSCANCLS, default-OFF] STATES D'INPUT of the MACHINE : when
                     * there class of family differe of the class of the model, the legacy engine (0x422fe3)
                     * writes BEFORE the feed `[0x4803c4] = CTXBASE[class]` (0x422feb),
                     * `[0x483934] = class` (0x423006), `[0x483932] = [0x48392f] = [0x4803d0] = 0`,
                     * then calls the reset of machine 0x423250. without cela `cls_ctx` remainder the one
                     * of the class previous and `rel = cls_ctx - CTXBASE[class] < 0` -> all the
                     * nodes tombent sure there line 0. */
                    { static int scl = -1;
                      if (scl < 0) { const char *e = getenv("UHA_BLKSCANCLS"); scl = (e && e[0] == '0') ? 0 : 1; }
                      if (scl) {
                          /* [M278] there class armee is the one OF THE SCAN (`cs` = `[esp+0x54]` of the
                           * legacy), not `ncls` (class rendue by there family empirique of the port).
                           *  There machine tourne sure `sin.ud = m` (model LIVE, restores ensuite
                           * by `*m = *s_rest`) : c'is `m` qu'il faut armer, not there copie
                           * `s_save`. Muter `s_save` was has cablage without effet (measures : `ctx`
                           * restait the one of the class previous, therefore `rel` clampe has 0). */
                          m->flag3934 = (uint8_t)cs;
                          m->cls_ctx = CLS_CTXBASE[cs];
                          m->cls_neg = 0u;
                          sin.st.ctx_abs = CLS_CTXBASE[cs];
                      }
                    }
                    ppm_famsite("G_blklive", (uint32_t)start, (uint32_t)ret);
                    if (m417dbg_on())
                        fprintf(stderr, "[M417DBG][call NODE] start=%u chg=%d ncls=%d cs=%d in_base=%u bud=%llu\n",
                                (unsigned)start, chg, ncls, cs, (unsigned)sin.base, (unsigned long long)bud);
                    (void)ppm_blk_cost_scan(s_scan, &sin, (uint32_t)bud, &sout);
                    /* [M278, GATED UHA_MM6CARRY, default-OFF] STATE MM PERSISTANT. At the legacy engine
                     * l'state of the machine of prediction (`0x462cd0..0x4649xx`) is GLOBAL : il
                     * survit of has call at the other and se nourrit at each node. The port the keeps
                     * in `ppm_model`, therefore `*m = *s_rest` the RAMENE at the state d'input : there
                     * prediction is FIGEE (`[FAMN] last=128` constant sure it 83..92, i.e.
                     * `mm6 -> 0` then `cls_base += 0x80`). `=1` preserves l'state MM mute by there
                     * walk. Judge : `sym(it=89)` doit passer of 169 has 87 (GT M278). */
                    { static int mc = -1;
                      if (mc < 0) { const char *e = getenv("UHA_MM6CARRY"); mc = (e && e[0] != '0') ? 1 : 0; }
                      if (mc) {
                          ppm_mm6 mm6k = m->mm6;
                          uint32_t lc = m->last_ctx;
                          uint8_t ph = m->cls_phase;
                          *m = *s_rest;
                          m->mm6 = mm6k;
                          m->last_ctx = lc;
                          m->cls_phase = ph;
                      } else
                          *m = *s_rest;              /* restitution : nothing n'is emis */
                    }
                    /* [M241] RESTITUTION SINCE THERE COPIE PRISTINE. Before this correctif there
                     * restitution lisait `s_save`, that the block `UHA_BLKSCANCLS` venait of muter
                     * (`s_save->flag3934 = ncls`) : the scan installait therefore there class of FAMILY
                     * (9) in the model REEL without to emit d'escape => the stream devenait
                     * indecodable (1 divergence measured : literal 505 698, enc sym=188 /
                     * dec sym=189, then escape fantome cls=6 has 544 142 side decoder).
                     * Measures M241 : `[M241CLS]` not montre NO `ppm_select_class` between the
                     * reset 505 696 (new=4) and the reset 697 696 (old=9) side encoder => there
                     * class had change by this recopie, not by has escape. */
                    *m = *s_rest;                  /* restitution : nothing n'is emis */
                    if (sout.ebp >= bud)
                        go = 0;
                    if (etrace_on >= 1)
                        fprintf(stderr, "[BLKLIVE] start=%u cl=%d ebp=%llu bud=%llu it=%u cold=%u verdict=%s\n",
                                (unsigned)start, ncls, (unsigned long long)sout.ebp,
                                (unsigned long long)bud, (unsigned)sout.niter,
                                (unsigned)sout.ncold, go ? "ESCAPE" : "annule");
                }
            }
        }
        if (!go) {
            /* [M330] there walk has rentre 0 by there keeps of budget : the master N'WRITES NOT
             * `[esp+0x20]` and teste there value d'stage 1. Gate OFF => historique (nothing n'is emis). */
            if (!ppm_repli_on())
                return 0;
            cand = stage1;     /* [M361] value D'STAGE 1 (before recyclage of `cl` by l'stage 2) */
            if (etrace_on >= 1)
                fprintf(stderr, "[M330REPLI] start=%u laureat=%d annule_donc etage1=%d courante=%d lzp=%d pw=%zu\n",
                        (unsigned)start, ncls, cand, (int)m->flag3934, lzp_ctx, (size_t)m->w->pos);
            if (cand == (int)m->flag3934)
                return 0;    /* 0x4220ea : egalite after repli => NO tete */
        } else if (cand == (int)m->flag3934) {
            /* [M330] atteint only by there probe of repli (laureat == current and walk no
             * annulee) : the master not sets then no tete. Inatteignable gate OFF. */
            return 0;
        }
        /* [M255, GATED UHA_PPM_ESCMEMBER, default-OFF] The master n'emits NEVER d'escape has has
         * frontier of MEMBER : l'appelant 0x417cf5 sets `eax=0xff`, and 0x421dc0..0x421dd2
         * (`cmp BYTE [esp+0x28],0xff` ; `jne 0x4220da` ; `cmp bl,0xff` ; `je 0x421eac`) route
         * then this cas towards l'header 10-way SINGLE - the path d'escape 0x421dd8 is
         * inatteignable. There cut in-stream (0x421986) recopie son clean argument, never
         * 0xff. Has cut which tombe EXACTEMENT sure has end of member not doit therefore not echapper.
         * Date measured of l'1re divergence : payload 1 280 = archive 1 319 = there 1re write of
         * there frontier 45 337 (end of `code.c`), now notre trace emits `[BLKESC] pw=1281` then that
         * the master y code (9,99) and nous (0,1) (`OUT/m255_intermembre.md` 2).
         * Juges : firstdiv > 1 319, size -> 191 159, `an_m155_payload` 12/12 (mono : 0 [BLKESC]
         * measured sure `code.c`), carte 8/8, parse, 9 juges + 4 juges d'state. */
        { static int em = -1, pv = -1;
          int on_end;
          uint32_t fin255 = 0u;
          if (em < 0) { const char *e = getenv("UHA_PPM_ESCMEMBER");
                        em = (e && e[0] != '0') ? 1 : 0; }
          if (pv < 0) { const char *e2 = getenv("UHA_M255ESC");
                        pv = (e2 && e2[0] != '0') ? 1 : 0; }
          on_end = member_fin_at(start, g_member_ends_x, g_nmembers_x, &fin255) ? 1 : 0;
          if (pv)
              fprintf(stderr, "[M255ESC] start=%u cand=%d cur=%d lzp=%d fin_membre=%d pw=%zu\n",
                      (unsigned)start, cand, (int)m->flag3934, lzp_ctx, on_end,
                      (size_t)m->w->pos);
          if (em && on_end) {
              if (pv)
                  fprintf(stderr, "[M255ESC]   -> ESCAPE SAUTE (voie maitre : 10-way seul)\n");
              return 0;
          }
        }
        erc = ppm_lzp_encode_escape(m, lzp_ctx, cand);
        if (etrace_on >= 1)
            fprintf(stderr, "[BLKESC] ctx=%d sel=%d rc=%d rec=%u,%u,%u,%u pw=%zu\n",
                    lzp_ctx, cand, erc,
                    (unsigned)m->lzp_class_rec[lzp_ctx][0],
                    (unsigned)m->lzp_class_rec[lzp_ctx][1],
                    (unsigned)m->lzp_class_rec[lzp_ctx][2],
                    (unsigned)m->lzp_class_rec[lzp_ctx][3], (size_t)m->w->pos);
        if (erc < 0)
            return -1;
        /* [M299, SAME GATE UHA_PPM_SEEDLAG, default-OFF] idem : l'escape installe there class current,
         * the mirror d'emission doit there recorder has `start` for the seeds some frontiers following. */
        if (ppm_seedlag_on())
            ppm_seed_mirror_push(start, (uint32_t)cand);
    } }
    return 0;
}

static int ppm_encode_core(const uint8_t *syms, uint32_t nsyms,
                           uint32_t usize, int order, int bc_mode,
                           const uint32_t *member_ends, int nmembers,
                           const uint8_t *raw,
                           uint8_t **out, size_t *outlen)
{
    ppm_model m;
    uha_rcw w;
    uint8_t *work;
    ppm_match mr;
    int in_pos = 0, out_pos = 0, route, sym, member, rc, target, n, dl;
    int xp_m = 0;   /* [M205 UHA_XPSIZE] rank of member publie */
    int fail_site = 0;   /* [M178] site of the `goto done` : publie by [ENCFAIL] under UHA_PPMTRACE */
    uint32_t next_boundary, boundary_target, period;
    uint32_t blk_next;
    int blklaw;

    *out = NULL;
    *outlen = 0;
    if (order < 0x18 || order > 0x27)
        return PPM_ERR_ORDER;
    if (usize == 0) {
        *out = malloc(1);
        return *out ? PPM_OK : PPM_ERR_NOMEM;
    }
    if (!syms || nsyms == 0)
        return PPM_ERR_CORRUPT;

    memset(&m, 0, sizeof(m));
    if (!ppm_model_alloc(&m, order))
        return PPM_ERR_NOMEM;

    rc = PPM_ERR_CORRUPT;
    fail_site = 0;
    m.blk_len4 = usize;
    /* t12g : mirror of the memset+reading of the header side decode. ppm_model_alloc
     * has already mis e0_blk_len = PPM_M32 ; with has en-tete bc!=0, ppm_read_block
     * _header sort after the uniform(2) without toucher e0_blk_len (remainder M32) nor
     * detr_thr2 (remainder 0 of the memset) - therefore no promotion : the bc1 is active
     * some the start, initialise only via block_reset + bc1_reset. */
    m.byte_class = (uint8_t)(bc_mode ? 1 : 0);

    /* [M185, GATED UHA_PPM_E0LAW, default-OFF] Piece (b) of the law B : the field d'header equals there
     * end of the prefixe of members `bc=0` (and no more `usize`). `ppm_write_block_header()` sets
     * juste after encode this value en chain of 11 bits in THERE SINGLE BRANCH `bc==0` and en
     * drifts `m.detr_thr2 = e0` (ppm_model.c l.519) - therefore the threshold of the transformee `detr` toggles
     * en regime complement AU same endroit that there promotion (mirror strict of the liseur, l.490-491).
     * En `bc_mode==1` the field n'is not emis and l'alloc has already mis `PPM_M32` : law B = `M32`,
     * on not lui impose therefore nothing. Gate OFF : `usize`, behavior historique intact. */
    m.e0_blk_len = (g_e0law && bc_mode == 0 && g_e0law_val) ? g_e0law_val : usize;

    if (uha_rcw_init(&w) != 0) {
        ppm_model_free(&m);
        return PPM_ERR_NOMEM;
    }
    m.w = &w;

    ppm_write_block_header(&m, &w);
    if (w.error)
        { fail_site = 1; goto done; }

    next_boundary = usize;
    member = 0;
    period = 0x40000u >> (m.byte_class * 2);
    boundary_target = (usize > period) ? period : usize;
    if (boundary_target > m.e0_blk_len)
        boundary_target = m.e0_blk_len;
    if (boundary_target > m.detr_thr1)
        boundary_target = m.detr_thr1;
    while (member < nmembers && member_ends && member_ends[member] < boundary_target)
        member++;
    if (member < nmembers && member_ends)
        next_boundary = member_ends[member];
    g_blk_bound = next_boundary;         /* [M203] publie there bound lue by there law of window */
    lenb_compute(&m, raw, 0u, next_boundary);   /* [M208 UHA_LENBOUND] bound en symboles of the member */

    ppm_arm_frontier_class(&m, 0u, member_ends, nmembers);   /* [M195 UHA_PPM_CLSFRONT] frontier of tete (OFF : no-op) */
    /* [M208b GATED UHA_SYMDUMP, default-OFF] the stream of symboles that l'encoder consumes is-il
     * the one of legacy ? M209 : in there window legacy `window[win_pos+3] = 0xf5` (literal final of the
     * member 1) then that notre `syms[in_pos+3] = 0x06` (the match of 4 absorbe this byte). */
    { static int sd = -1;
      if (sd < 0) { const char *e = getenv("UHA_SYMDUMP"); sd = (e && e[0] != '0') ? 1 : 0; }
      if (sd) {
          uint32_t k;
          fprintf(stderr, "[SYMDUMP] nsyms=%u winpos=%u :", (unsigned)nsyms, (unsigned)m.win_pos);
          for (k = 38112u; k <= 38125u && k < nsyms; k++)
              fprintf(stderr, " %u:%02x", k, syms[k]);
          fprintf(stderr, "\n");
      } }
    /* [M208b GATED UHA_SYMFILE] dump of the stream of symboles of l'encoder (mirror of `put_window`). */
    { const char *sf = getenv("UHA_SYMFILE");
      if (sf && sf[0] != '0') {
          FILE *f = fopen(sf, "wb");
          if (f) { fwrite(syms, 1, nsyms, f); fclose(f); }
      } }
    if (!ppm_block_reset_encode(&m))
        { fail_site = 2; goto done; }
    if (m.byte_class != 0)
        ppm_bc1_reset();

    work = malloc((size_t)usize + 0x1000);
    if (!work) {
        rc = PPM_ERR_NOMEM;
        goto done;
    }

    in_pos = 0;
    out_pos = 0;
    /* [M177, PROMUE the 2026-10-25] Default = 8 (mecanisme faithful of the decider of block).
     * Reason : the 15 costs retournes measurements to the sites d'write of legacy (`0x421cbe`/`0x421ce7`,
     * `OUT/m177_returned.log`) are identical au port and l'accumulateur of legacy has only has single
     * write of loop (`0x4224c2`) - more no value of mecanisme n'is inexpliquee sure mx.
     * 0 restores the behavior historique at the identical (Has/B). */
    blklaw = getenv("UHA_BLKLAW") ? atoi(getenv("UHA_BLKLAW")) : 8;
    blk_next = 0u;
    if (blklaw) {
        ppm_blocklen_init(&g_blc);
        blk_next = 0u;        /* 0x4803d4 = 0 at the init (0x416a44) : 1re cut au 1er literal */
        /* [M178]  NOT MORE neutraliser `next_boundary` : there law of cut (0x422890) replaces the
         * mecanisme PERIOD, but there FRONTIER OF MEMBER remainder has not of reset **emis** - the
         * decoder the reads (`ppm_block_reset` sure `out_pos >= next_boundary`, `next_boundary =
         * member_ends[member]`) and this decoder decode `ALL__mx` legacy at the byte near
         * (`tools/difftest.py` 88 OK). without this reset l'encoder multimembre divergeait some there
         * 1re frontier (measures : `pattern.bin`+`zeros.bin`, gap has `pos = 192002`, member has
         * 192000) and sortait en `encode error -1` (rejet of the roundtrip).
         * L'old `next_boundary = usize` venait of the port monomembre now no member not se
         * termine before `usize` : il was neutre. */
    }
    /* [M170] >= 3 : there cut is pilotee since ppm_mf.c (before there class of the node). */
    if (blklaw >= 3) {
        g_blk_raw = raw;
        g_blk_sym = syms;             /* [M243] window = SYMBOLES (see g_blk_sym) */
        g_blk_nsyms = nsyms;
        g_blk_usize = usize;
        g_blk_next = 0u;
        g_blk_start = 0u;     /* [M170h] init of member 0x416ad1 : [0x483934] = dl (0 measures) */
        g_member_ends_x = member_ends;      /* [M255] mirror for ppm_blk_node_encode */
        g_nmembers_x = (uint32_t)(nmembers > 0 ? nmembers : 0);
        ppm_seed_mirror_init();   /* [M202] same initialisation for the mirror d'emission */
        g_blklaw = blklaw;
    } else {
        g_blk_raw = NULL;
        g_blk_sym = NULL;
        g_blk_nsyms = 0u;
        g_blklaw = blklaw;
    }
    etrace_on = getenv("UHA_PPMTRACE") ? (getenv("UHA_PPMTRACE")[0]=='2' ? 2 : 1) : 0;
    if (etrace_on >= 1)
        fprintf(stderr, "[PPMTRC enc init] bc=%d e0=%u nsyms=%u usize=%u\n",
                m.byte_class, m.e0_blk_len, nsyms, usize);
    /* [M170b, UHA_BLKLAW>=3] ARMEMENT of the FRONTIER : has decision of block has lieu has
     * pos = 0 BEFORE there first cut observable. Measures M170 (image.raw AND mixed) :
     * [0x4803d4] = 12544 = 0x3100 au first hit of 0x421986 ; and 6 calls of family
     * (0x421d9f) for 5 cuts has 0x421986 with has call has pos = 0. Law : has pos = 0,
     * remainder = usize >= 0x4b00 -> 0x3200, len = remainder-0x100 = 12544, 0x422890 rend len
     * (no changement) -> frontier = 0 + 12544. no escape here (lzp_ctx = -1). */
    if (blklaw >= 3) {
        if (ppm_blk_node_encode(&m, 0u, -1) < 0) {
            free(work);
            fail_site = 4;
            goto done;
        }
    }
    while (in_pos < (int)nsyms) {
        /* [M205 UHA_XPSIZE, default-OFF, no emissif] SIZE COMPRESSED BY MEMBER OF L'EMETTEUR.
         * The `psize` by member n'is NOT stores in l'archive (`container.c` l.288-292) : there single
         * measures directe is there position of the writer at the end of each member. The decoder publie there
         * same grandeur sure the stream of the master (`ppm.c`, `[XPSIZE] dec`) : the DELTAS by member are
         * therefore comparables (l'advances of the range-coder is has constante additive). */
        { static int xp = -1;
          if (xp < 0) { const char *e = getenv("UHA_XPSIZE"); xp = (e && e[0] != '0') ? 1 : 0; }
          if (xp) {
              while (xp_m < nmembers && member_ends && (uint32_t)out_pos >= member_ends[xp_m]) {
                  fprintf(stderr, "[XPSIZE] enc rang=%d outpos=%u outbytes=%lu\n",
                          xp_m, (unsigned)member_ends[xp_m],
                          m.w ? (unsigned long)m.w->pos : 0ul);
                  xp_m++;
              }
          } }
        /* [M185, GATED UHA_PPM_E0LAW, default-OFF] Piece (c) : PROMOTION mid-stream bc0->bc1.
         * L'old commentaire (" there promotion mid-stream bc0->bc1 n'is not emise by notre
         * encoder ") is REVOQUE : c'is FALSE en multi-member. Proof = `ALL__mx` legacy has son
         * 1er reset of block has `45 337` = `e0_blk_len`, marque `cls=1, bc=1` in there carte lue by
         * NOTRE decoder faithful (`OUT/m178b_analysis.md` 2) - therefore the legacy engine emits has en-tete 10-way
         * at the promotion, and notre encoder doit the to reproduce for to be byte-identical.
         * Mirror STRICT of `ppm.c` l.96-104 : promotion BEFORE the test of frontier, periode
         * recalculee en bc=1 (`0x40000>>2 = 0x10000`), and `next_boundary = out_pos` for that the block
         * suive triggers the reset AU same endroit. `ppm_promote_to_bc1()` resets `e0_blk_len = M32`
         * (ppm_model.c l.625) : there promotion not frappe therefore qu'once. Keeps `out_pos < usize` =
         * condition of loop of the decoder (prevents has promotion fantome when there law rend e0=usize). */
        if (g_e0law && (uint32_t)out_pos < usize && (uint32_t)out_pos >= m.e0_blk_len) {
            if (etrace_on >= 1)
                fprintf(stderr, "[PPMTRC enc promote] @%u bc=%d e0=%u\n",
                        (unsigned)out_pos, m.byte_class, (unsigned)m.e0_blk_len);
            ppm_promote_to_bc1(&m);
            ppm_bc1_reset();
            next_boundary = (uint32_t)out_pos;
        }
        while ((uint32_t)out_pos >= next_boundary && (uint32_t)in_pos < nsyms) {
            period = 0x40000u >> (m.byte_class * 2);
            boundary_target = (usize - next_boundary > period)
                ? next_boundary + period : usize;
            if (boundary_target > m.e0_blk_len)
                boundary_target = m.e0_blk_len;
            if (boundary_target > m.detr_thr1)
                boundary_target = m.detr_thr1;
            while (member < nmembers && member_ends && member_ends[member] < boundary_target)
                member++;
            if (member < nmembers && member_ends)
                next_boundary = member_ends[member];
            else
                next_boundary = usize;
            g_blk_bound = next_boundary;     /* [M203] there bound suit each reset emis */
            lenb_compute(&m, raw, (uint32_t)out_pos, next_boundary);   /* [M208 UHA_LENBOUND] */
            /* [M195 UHA_PPM_CLSFRONT] there class EMISE here is the one of the DECISION of frontier
             * (mesuree by t188 sure there queue [p, usize)), not there class global of the buffer ; there
             * re-arme of the candidature of the scan (`g_blk_start`, 0x421f81) is ailleurs and n'is
             * not touchee. Gate OFF : no-op, `uharc_ppm_class` keeps sa value actuelle. */
            ppm_arm_frontier_class(&m, (uint32_t)out_pos, member_ends, nmembers);
            /* [GATED UHA_ROWAUD, M207] state BEFORE the reset of block (there captures legacy `0x417750`
             * imprime before the sien) - comparable 1:1 has OUT/m207_blockwin.tsv. */
            { static int wc = -1;
              if (wc < 0) { const char *e = getenv("UHA_ROWAUD"); wc = (e && e[0] != '0') ? 1 : 0; }
              if (wc)
                fprintf(stderr, "[WINPRE] out=%u winpos=%u s=%u brf0=%u br14=%u bc=%u cls=%u clsctx=%d"
                        " c4g=%u dcg=%u a8g=%u recg=%lu"
                        " w1=%u w2=%u w4=%u w12=%u w24=%u w48=%u\n",
                        (unsigned)out_pos, m.win_pos, m.br18, m.brf0, m.br14,
                        (unsigned)m.byte_class, (unsigned)(m.flag3934 & 0xFF), m.cls_ctx,
                        (unsigned)m.c4g, (unsigned)m.dcg, (unsigned)m.a8g,
                        (unsigned long)g_recg_calls,
                        (unsigned)m.window[(m.win_pos - 1) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 2) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 4) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 12) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 24) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 48) & m.win_mask]); }
            if (!ppm_block_reset_encode(&m)) {
                free(work);
                fail_site = 5;
                goto done;
            }
            /* [M218 GATED UHA_CLSBLK, default-OFF] PATH LEGACY of the class of frontier : the legacy engine
             * installe there class by `0x422d00` (families) then l'writes en `0x421f81`
             * (`mov [0x483934],al`) - M218 : has `1 071 003`, `newcls=5` with `edx = 12 544`.
             * On applies `ppm_blk_class(1, raw+out_pos, 12 544)` at each frontier. */
            { static int cb = -1;
              if (cb < 0) { const char *e = getenv("UHA_CLSBLK"); cb = (e && e[0] != '0') ? 1 : 0; }
              if (cb && raw && (uint32_t)out_pos < usize) {
                  uint32_t bl = usize - (uint32_t)out_pos;
                  int nc;
                  if (bl > 0x3100u) bl = 0x3100u;
                  ppm_famsite("D_front_class", (uint32_t)out_pos, (uint32_t)bl);
                  nc = ppm_blk_class(1, raw + out_pos, bl);
                  if (nc >= 0 && nc <= 9) {
                      extern int uharc_ppm_class;
                      uharc_ppm_class = nc;
                      if (etrace_on >= 1)
                          fprintf(stderr, "[CLSBLK] out=%u len=%u cls=%d\n",
                                  (unsigned)out_pos, (unsigned)bl, nc);
                  }
              } }
            /* [M217 GATED UHA_FORCE5, default-OFF] experience of CAUSALITE : the block 8
             * (`image.raw`, frontier 1 071 003) is en class **5** at the legacy engine and **3** at
             * nous (M217 : `cls=5` sure 655/655). To forces 5 here dit if there class is there cause root
             * of the divergence rec2/maxlen in this member. */
            { static int f5 = -1;
              if (f5 < 0) { const char *e = getenv("UHA_FORCE5"); f5 = (e && e[0] != '0') ? 1 : 0; }
              if (f5 && (uint32_t)out_pos == 1071003u)
                  ppm_select_class(&m, 5); }
            if (m.byte_class != 0)
                ppm_bc1_block_reset();
            m.out_count = (uint32_t)out_pos;
            { static int bd = -1; if (bd < 0) { const char *e = getenv("UHA_PPMTRACE"); bd = (e && e[0]=='2') ? 1 : 0; }
              if (bd) fprintf(stderr, "[BLOCK] reset out_pos=%u in_pos=%d next_boundary=%u boundary_target=%u rcpos=%u\n",
                              (unsigned)out_pos, in_pos, next_boundary, boundary_target, (unsigned)w.pos); }
            /* [GATED UHA_ROWAUD, M207] state of the window/distance at the input of each block,
             * comparable 1:1 has OUT/m207_blockwin.tsv (captures au site legacy 0x417750). */
            { static int wc = -1;
              if (wc < 0) { const char *e = getenv("UHA_ROWAUD"); wc = (e && e[0] != '0') ? 1 : 0; }
              if (wc)
                fprintf(stderr, "[WINCHK] out=%u winpos=%u s=%u brf0=%u br14=%u bc=%u cls=%u clsctx=%d"
                        " w1=%u w2=%u w4=%u w12=%u w24=%u w48=%u\n",
                        (unsigned)out_pos, m.win_pos, m.br18, m.brf0, m.br14,
                        (unsigned)m.byte_class, (unsigned)(m.flag3934 & 0xFF), m.cls_ctx,
                        (unsigned)m.window[(m.win_pos - 1) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 2) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 4) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 12) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 24) & m.win_mask],
                        (unsigned)m.window[(m.win_pos - 48) & m.win_mask]); }
        }

        /* [M257c, **PROMUE EN DEFAULT**, `UHA_PPM_CUTPOS=0` = historique] rafraichit the curseur
         * d'EMISSION transmis au matchfinder, which pilote there teste of cut (default historique :
         * `winpos`, l'advances of window - cf. `ppm_cutpos_on()` in `ppm_mf.c`, same semantique).
         * Has single variable with the changement d'argument of `ppm_mf.c`. */
        { static int cp = -1;
          if (cp < 0) { const char *e = getenv("UHA_PPM_CUTPOS");
                        cp = (e && e[0] == '0') ? 0 : 1; }   /* DEFAULT = ON */
          if (cp) m.out_count = (uint32_t)out_pos; }
        if (ppm_matchfinder_encode(&m, &mr, syms, nsyms,
                                   (uint32_t)in_pos) < 0) {
            free(work);
            fail_site = 6;
            goto done;
        }
        if (mr.lzp_ctx >= 0) {
            ppm_lzp_apply_update(&m, mr.lzp_ctx, mr.lzp_cls);
            if (mr.lzp_cls != 1)
                ppm_lzp_nomatch_tail(&m);
        }

        if (mr.is_match) {
            int ii;
            n = mr.raw_len;
            et_match++;
            { static int ps = -1;
              if (ps < 0) { const char *e = getenv("UHA_PARSE"); ps = (e && e[0] != '0') ? (e[0] == '2' ? 2 : 1) : 0; }
              if (ps && (ps == 2 || out_pos < 45337))
                  fprintf(stderr, "[PARSEE] pos=%u M len=%d cls=%d\n",
                          (unsigned)out_pos, n, mr.lzp_cls); }
            { static int lsm = -1;
              if (lsm < 0) { const char *e = getenv("UHA_LASTSYM"); lsm = (e && e[0] != '0') ? 1 : 0; }
              if (lsm && out_pos >= 45325 && out_pos <= 45340)
                  fprintf(stderr, "[MFENC] pos=%u len=%d cls=%d syms=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                          (unsigned)out_pos, n, mr.lzp_cls,
                          mr.raw_syms[0], mr.raw_syms[1], mr.raw_syms[2], mr.raw_syms[3],
                          mr.raw_syms[4], mr.raw_syms[5], mr.raw_syms[6], mr.raw_syms[7]); }
            if (etrace_on == 2)
                fprintf(stderr, "[TR2 enc MATCH] pos=%u len=%d cls=%d\n",
                        (unsigned)out_pos, n, mr.lzp_cls);
            et_mbytes += n;
            for (ii = 0; ii < n; ii++) {
                if ((uint32_t)out_pos >= usize)
                    break;
                /* [M256, GATED UHA_PPM_CUTBATCH, default-OFF] D2, 2 location : there loop of
                 * LOT of the match emits `n` symboles without rappeler the matchfinder => between two calls
                 * of the mf, `winpos` skips of `n` : c'is TROU in there grille (measures CUTLIT au
                 * l.431 of ppm_mf.c : has single teste between 45 000 and 96 000, trou of 37 649 has
                 * 83 778 then that `next` was arme has 57 881). Gate distincte of `UHA_PPM_CUTLIT`
                 * for juger the two emplacaments separement (has variable). */
                { static int cb = -1;
                  if (cb < 0) { const char *e = getenv("UHA_PPM_CUTBATCH");
                                cb = (e && e[0] != '0') ? 1 : 0; }
                  if (cb && ppm_blk_node_encode(&m, (uint32_t)out_pos, mr.lzp_ctx) < 0) {
                      free(work);
                      fail_site = 9;
                      goto done;
                  } }
                dl = (n - ii) <= 8;
                /* [GATED UHA_M257EMS, default-OFF, no emissif] Recensement some PATHS d'emission
                 * sure the segment of the trou : which emits what, and that equals `g_blk_next` has this moment. */
                { static int es = -1;
                  if (es < 0) { const char *e = getenv("UHA_M257EMS");
                                es = (e && e[0] != '0') ? 1 : 0; }
                  if (es && (uint32_t)out_pos >= 45300u && (uint32_t)out_pos <= 84000u)
                      fprintf(stderr, "[M257EMS] LOT pos=%u next=%u ii=%d n=%d\n",
                              (unsigned)out_pos, (unsigned)g_blk_next, ii, n); }
                ppm_match_maintain(&m, mr.raw_syms[ii], dl, work, &out_pos);
            }
            in_pos += n;
            if (w.error) {
                free(work);
                fail_site = 7;
                goto done;
            }
            continue;
        }

        target = syms[in_pos];
        /* [GATED UHA_M257EMS, default-OFF, no emissif] idem, path LITERAL. */
        { static int es2 = -1;
          if (es2 < 0) { const char *e = getenv("UHA_M257EMS");
                         es2 = (e && e[0] != '0') ? 1 : 0; }
          if (es2 && (uint32_t)out_pos >= 45300u && (uint32_t)out_pos <= 84000u)
              fprintf(stderr, "[M257EMS] LIT pos=%u next=%u in_pos=%d\n",
                      (unsigned)out_pos, (unsigned)g_blk_next, in_pos); }

        /* [M256] There teste of cut `UHA_PPM_CUTLIT`/`UHA_PPM_CUTBATCH` is cablee AILLEURS
         * (ppm_mf.c after `register_entry` ; loop of LOT ci-dessus) : this not-ci, atteint
         * only when the matchfinder not rend nothing, was redondant. Voir OUT/m257_cutlit.md.
         */

        /* [M169 lot 1, GATED UHA_BLKLAW] there decoupe n'is testee THAT sure the path LITERAL
         * (0x421973, atteint by the two `jb` of rejet of match), and there cut has lieu au
         * first literal whose there position >= frontier. Voir OUT/m169_cutlaw.md. */
        if (blklaw >= 1 && blklaw <= 2 && raw && (uint32_t)out_pos >= blk_next) {
            uint32_t start = (uint32_t)out_pos;
            uint32_t reste = usize - start;
            uint32_t ret;
            if (reste >= 0x4b00u)
                reste = 0x3200u;
            /* 0x421c5b : the roulage t <- t5 has lieu at each cut, BEFORE the test len > 0x100. */
            ppm_blocklen_roll(&g_blc);
            if (reste > 0x100u) {
                /* [M274g, GATED UHA_PBL_WOFF, default 0 = historique] SHIFT of the WINDOW.
                 * ASM : `[esp+0x28]` (there `window` passee has `0x422890`) is the pointer d'input
                 * **advances**, and `0x421ff4` pass `ebp - 0x100` en length : the two vont
                 * ensemble. Measures decisive (`work/t171_blk_gt`, GT M274) :
                 *   window = raw+start       , len = 6848 -> t/t5 FALSE (4978/5102)
                 *   window = raw+start+0x100 , len = 6848 -> **20/20 words EXACT** and
                 *                                            `ret = 6848` conforme at the cut
                 *   window = raw+start       , len = 7104 -> t/t5 justes but `ret = 7104`
                 *                                            (the master cut has 937 440)
                 * => single `+0x100` with `len = remainder - 0x100` reproduces there GT. */
                static int woff = -2;
                if (woff == -2) { const char *e = getenv("UHA_PBL_WOFF"); woff = (e && e[0]) ? atoi(e) : 256; }
                ret = ppm_blocklen(&g_blc, raw + start + (size_t)woff, reste - 0x100u);
            } else {
                ret = reste;   /* 0x421c99 : no call if len <= 0x100 */
            }
            blk_next = start + ret;
            if (etrace_on >= 1)
                fprintf(stderr, "[BLKLAW] start=%u len=%u ret=%u next=%u\n",
                        (unsigned)start, (unsigned)reste, (unsigned)ret,
                        (unsigned)blk_next);

            /* [M169 lot 2b, UHA_BLKLAW>=2] SELECTION + ESCAPE of class.
             *   0x42201a : cl = argmax t[1..4]
             *   0x421d06..0x421d1c : cost normalise cb = (cout_min / len) / 0x249, clamp 0x0A
             *   0x42205c..0x422093 : fact = (len >= 0x800 ? 0x50 : 0x41) + (0x0A - cb)*4 ;
             *        if (t[cl] << 6) <= fact * t[0]  -> no changement
             *   0x422d00 : class (families, OUT/m169_families.md) ; then 0x421dd8 (escape). */
            if (blklaw >= 2) {
                uint32_t blen = (reste > 0x100u) ? reste - 0x100u : reste;
                uint32_t cb = 0x0Au, fact;
                uint64_t cbest = 0;
                int j, cl = 1, ncls = -1, chg;

                for (j = 1; j < 5; j++)
                    if (g_blc.t[j] > g_blc.t[cl])
                        cl = j;
                (void)ppm_legacy_cost_select_class(raw + start, blen,
                                                   (uint32_t)m.flag3934,
                                                   ppm_legacy_cost, &cbest);
                if (blen)
                    cb = (uint32_t)(cbest / blen / 0x249u);
                if (cb > 0x0Au)
                    cb = 0x0Au;
                /* [M274, GATED UHA_PPM_CBVAL, default -1 = law historique] TEST OF SENSIBILITE sure `cb`
                 * (c'is THIS block which decide : `[BLKSEL]` measures sort d'here). Measures M274
                 * (`OUT/m274_t937440.md`) : has `0x42206f` for `pos = 937 440` the master has
                 * **`ebx(cb) = 0`** then that `cbest/blen/0x249` gives 10. with `cb = 0` :
                 * `fact = 0x41 + (0x0A-0)*4 = 105` -> `fact*t[0] = 528 570 > t[1]<<6 = 328 704`
                 * (argmax master `eax = 1` ; the notre equals 2) -> **no changement** = class 0
                 * = this that code the master. value forcee = TEST, there law of `ebx` remainder has etablir. */
                { static long cbv = -2;
                  if (cbv == -2) { const char *e = getenv("UHA_PPM_CBVAL"); cbv = (e && e[0]) ? atol(e) : -1; }
                  if (cbv >= 0) cb = (uint32_t)cbv; }
                fact = ((blen >= 0x800u) ? 0x50u : 0x41u) + (0x0Au - cb) * 4u;
                chg = ((uint32_t)(g_blc.t[cl] << 6) > (uint32_t)(fact * g_blc.t[0])) ? 1 : 0;
                if (etrace_on >= 1)
                    fprintf(stderr, "[BLKSEL] cl=%d t0=%u t1=%u t2=%u t3=%u t4=%u cb=%u fact=%u chg=%d courante=%d lzp_ctx=%d base46=%d\n",
                            cl, (unsigned)g_blc.t[0], (unsigned)g_blc.t[1],
                            (unsigned)g_blc.t[2], (unsigned)g_blc.t[3], (unsigned)g_blc.t[4],
                            (unsigned)cb, (unsigned)fact, chg, (int)m.flag3934,
                            mr.lzp_ctx, (int)m.base46);
                ppm_famsite("E_core_classfw", (uint32_t)start, (uint32_t)blen);
                if (chg)
                    ncls = ppm_blk_class_fw(cl, raw + start, blen);
                if (etrace_on >= 1)
                    fprintf(stderr, "[BLKSEL]   -> classe=%d\n", ncls);
                if (m417dbg_on())
                    fprintf(stderr, "[M417DBG][sel E] start=%u chg=%d ncls=%d cl=%d courante=%d\n",
                            (unsigned)start, chg, ncls, cl, (int)m.flag3934);
                if (ncls >= 0 && ncls != (int)m.flag3934 && mr.lzp_ctx >= 0) {
                    /* Escape (0x421dd8) : [rec0,rec1)/rec3 then sel/10 then select_class(sel).
                     * There class of the node will be encodee normalement by the stream (the decodeur there relit). */
                    int erc = ppm_lzp_encode_escape(&m, mr.lzp_ctx, ncls);
                    if (etrace_on >= 1)
                        fprintf(stderr, "[BLKESC] ctx=%d sel=%d rc=%d rec=%u,%u,%u,%u pw=%zu\n",
                                mr.lzp_ctx, ncls, erc,
                                (unsigned)m.lzp_class_rec[mr.lzp_ctx][0],
                                (unsigned)m.lzp_class_rec[mr.lzp_ctx][1],
                                (unsigned)m.lzp_class_rec[mr.lzp_ctx][2],
                                (unsigned)m.lzp_class_rec[mr.lzp_ctx][3], (size_t)m.w->pos);
                    if (erc < 0) {
                        free(work);
                        fail_site = 8;
                        goto done;
                    }
                    /* [M299, SAME GATE UHA_PPM_SEEDLAG, default-OFF] site `E_core_classfw` : c'is
                     * LUI which emits `sel=3` has `pw = 183 132` (measures `[BLKESC]`), c'is-has-dire has
                     * `in_pos = 964 788` ; M297 mesurant there class current `3` at the frontier
                     * `1 071 003`, the mirror doit there porter, otherwise there seed y remainder has `0`.
                     * Proof GT M197 : seed = class current to the 3 frontiers mesurees
                     * (`45 337` : 0, `937 696` : 0, `1 071 003` : **3**). */
                    if (ppm_seedlag_on())
                        ppm_seed_mirror_push((uint32_t)start, (uint32_t)ncls);
                }
            }
            /* NOT NOT to call ppm_block_reset_encode here : this function EMITS has en-tete
             * 10-way (uha_rcw_encode(cls, cls+1, 10)) then that there cut legacy 0x421be0
             * n'emits no en-tete (M168 5 : no site encoder has total=10, BP 0x417b3c
             * = 0 hit en `has`). Lot 1 = computation PUR, no emissif : l'archive doit rester
             * byte-identical with there gate ON. There selection + l'escape = lot 2. */
        }

        ppm_matchfinder_literal_tail(&m);
        /* [M257b, GATED UHA_PPM_CUTEMIT, default-OFF, **INERT measured** : md5 of the corps identical au
         * default (8a220f71b191), size and firstdiv inchanges]
         * The master teste there cut at the position of the STREAM EMIS, not has `winpos` ; there VARIABLE which
         * counts is the coordonne (`UHA_PPM_CUTPOS`, promu en default), not the SITE d'call : this
         * call supplementaire au not d'emission not change nothing since there keeps internal has already
         * ete consommee by l'advances. preserved default-OFF as instrument.
         * There keeps internal `start < g_blk_next` (l.1070) rend impossible the testes en double.
         * Juges ordonnes : `an_m255_grid.py` (hits GT 5 and 6 out d'" absentes ", more of rearme en
         * advances) -> `cur` no divergent has 82 971 -> `cmp` firstdiv > 1 319 -> size 191 159 -> carte
         * [BLKCLS] 8/8 -> `an_m155_payload` 12/12 -> 9 juges + 4 juges d'state. */
        { static int ce = -1;
          if (ce < 0) { const char *e = getenv("UHA_PPM_CUTEMIT");
                        ce = (e && e[0] != '0') ? 1 : 0; }
          if (ce && raw && blklaw >= 3 &&
              ppm_blk_node_encode(&m, (uint32_t)out_pos, mr.lzp_ctx) < 0) {
              free(work);
              fail_site = 10;
              goto done;
          } }
        { uint32_t lit0 = (uint32_t)out_pos;
          if (!ppm_encode_literal_cascade(&m, work, &out_pos, target,
                                          &route, &sym)) {
              free(work);
              fail_site = 9;
              goto done;
          }
          { static int ps = -1;
            if (ps < 0) { const char *e = getenv("UHA_PARSE"); ps = (e && e[0] != '0') ? (e[0] == '2' ? 2 : 1) : 0; }
            if (ps && (ps == 2 || lit0 < 45337u))
                fprintf(stderr, "[PARSEE] pos=%u L sym=%u route=%d n=%u\n",
                        lit0, (unsigned)sym, route, (unsigned)out_pos - lit0); } }
        if (sym != target) {
            free(work);
            fail_site = 10;
            goto done;
        }
        in_pos++;
        et_route[route]++;
        if (etrace_on == 2)
            fprintf(stderr, "[TR2 enc] i=%u pos=%u route=%d tgt=%u rcpos=%zu\n",
                    (unsigned)in_pos, (unsigned)out_pos, route, (unsigned)target, (size_t)w.pos);
        if (w.error) {
            free(work);
            fail_site = 11;
            goto done;
        }
    }

    free(work);
    if (uha_rcw_flush(&w) != 0)
        { fail_site = 12; goto done; }
    *out = w.buf;
    *outlen = w.pos;
    w.buf = NULL;
    rc = PPM_OK;

done:
    if (rc != PPM_OK && etrace_on >= 1)
        fprintf(stderr, "[ENCFAIL] site=%d rc=%d in_pos=%d out_pos=%u nsyms=%u\n",
                fail_site, rc, in_pos, (unsigned)out_pos, nsyms);
    if (etrace_on == 1)
        fprintf(stderr, "[PPMTRC enc] lit[r0o1=%d pred=%d rec2=%d entry=%d c550=%d] match=%d mbytes=%d\n",
                et_route[CR_ORDER1_HIT], et_route[CR_PREDICTED_HIT],
                et_route[CR_REC2_HIT], et_route[CR_ENTRY_HIT], et_route[CR_C550],
                et_match, et_mbytes);
    uha_rcw_free(&w);
    ppm_model_free(&m);
    return rc;
}

int uha_ppm_encode(const uint8_t *plain, uint32_t usize,
                   int order, int bc_mode,
                   const uint32_t *member_ends, int nmembers,
                   uint8_t **out, size_t *outlen)
{
    uint8_t *syms;
    uint32_t nsyms;
    int rc;

    if (!out || !outlen)
        return PPM_ERR_CORRUPT;
    *out = NULL;
    *outlen = 0;
    if (usize == 0) {
        *out = malloc(1);
        return *out ? PPM_OK : PPM_ERR_NOMEM;
    }
    if (!plain)
        return PPM_ERR_CORRUPT;

    syms = malloc((size_t)usize * 4 + 16);
    if (!syms)
        return PPM_ERR_NOMEM;
    nsyms = 0;
    if (bc_mode == 1) {
        /* t12g : with detr_thr2 = 0 (bc=1 some l'en-tete), the detransform
         * decodeur emits systatiquement (~sym) without state - there symbolisation
         * is therefore l'inversion byte by byte. */
        uint32_t i;
        for (i = 0; i < usize; i++)
            syms[i] = (uint8_t)(~plain[i]);
        nsyms = usize;
    } else if (g_e0law && g_e0law_val && g_e0law_val < usize) {
        /* [M185, GATED UHA_PPM_E0LAW, default-OFF] Law B, threshold of the symbolisation. The decodeur
         * sets `detr_thr2 = e0_blk_len` (ppm_model.c l.491, relu in l'en-tete) and no `usize`.
         * therefore l'encoder doit symboliser with `thr2 = e0` : has single pass `ppm_detr_forward`
         * produces [0,e0) en regime dictionnaire then [e0,usize) en regime complement (`~b`, l.53-57
         * of the same file) - c'is-has-dire the SAME threshold that there promotion mid-stream. Passer `usize`
         * (l'call historique) divergerait some the 1er symbole after e0. */
        if (!ppm_detr_forward(plain, usize, g_e0law_val, syms, &nsyms)) {
            free(syms);
            return PPM_ERR_CORRUPT;
        }
    } else if (!ppm_detr_inverse(plain, usize, syms, &nsyms)) {
        free(syms);
        return PPM_ERR_CORRUPT;
    }
    rc = ppm_encode_core(syms, nsyms, usize, order, bc_mode, member_ends, nmembers,
                         plain, out, outlen);
    free(syms);
    return rc;
}

int uha_ppm_encode_syms(const uint8_t *syms, uint32_t nsyms, uint32_t usize,
                        int order,
                        const uint32_t *member_ends, int nmembers,
                        uint8_t **out, size_t *outlen)
{
    return ppm_encode_core(syms, nsyms, usize, order, 0, member_ends, nmembers,
                           NULL, out, outlen);
}
