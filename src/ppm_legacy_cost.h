#ifndef PPM_LEGACY_COST_H
#define PPM_LEGACY_COST_H
#include <stdint.h>
#include <stddef.h>

#define PPM_COST_MAXCTX 256u

typedef struct {
    uint16_t freq[PPM_COST_MAXCTX * 256];
    uint16_t total[PPM_COST_MAXCTX];
    uint16_t escape[PPM_COST_MAXCTX];
    /* [M170k] row of prior of the candidate (1er term cold, 0x42242b..0x422465) ;
     * NULL => repli sure there constante historique `LUT[(8<<14)/2048]` = 37440. */
    const uint16_t *prior;
    uint32_t        prior_total;
    /* [M220, GATED UHA_PPM_ROWSEL] STATE OF THE MODEL OF DISTANCE OF THE NODE 0x4221c0.
     * Snapshot some tables LIVE (0x422315 : memcpy 0x46ab50->0x46af50 and
     * 0x469b48->0x469f48, then [0x481c00/04/08] <- [0x481c10/14/18]) :
     *   last[]  = 0x46af50 : last position vue by symbole (u32, init 0x80000000)
     *   dhist[] = 0x469f48 : histogramme of distances (256 u32, init 0)
     *   reg00   = 0x481c00 : counter of halving      (init 0)
     *   reg04   = 0x481c04 : distance winning n2     (init 0)
     *   reg08   = 0x481c08 : distance winning n1     (init 1)  <- elle SELECTS there line
     * The three fields following are some slots of STACK ([esp+0x14], [esp+0x38], [esp+0x40]),
     * remis has 0 at each call of l'estimator (0x4221e6..0x4221ee) :
     *   dctr = [esp+0x14] (counter d'order, 0x42268b/0x422664/0x422668)
     *   dma  = [esp+0x38] (moyenne glissante |delta|, 0x4225f2..0x4225ff)
     *   bias = [esp+0x40] (0x800 now (dma<<10)+0x800 ; REPLACES the cost, 0x4224b6)
     * `rowsel_armed` = 1 as soon as l'state has ete initialise once (arena persistante). */
    uint32_t last[256];
    uint32_t dhist[256];
    uint32_t reg00, reg04, reg08;
    uint32_t dctr, dma, bias;
    int      rowsel_armed;
} ppm_cost_arena;

/* [M220] Initialise l'state of the model of distance (law 0x4178f8 : last = 0x80000000,
 * dhist = 0, regs 0/0/1). Appele by ppm_cost_arena_reset and paresseusement by
 * ppm_legacy_cost_live (arena persistante). */
void ppm_cost_rowsel_reset(ppm_cost_arena *a);
/* [M220] 1 if `UHA_PPM_ROWSEL` is arme (default OFF). */
int  ppm_cost_rowsel_on(void);
/* [M220] SELECTION of the line of the node for `cand == 0` (path 2D, 0x42259d..0x422623).
 * Renseigne *row (index of line, replaces `rel`), *err (index d'arena) and *bias (0 if
 * no ; otherwise REPLACES the cost of the node as 0x4224b6). Rend 1 if the path 2D has ete
 * emprunte. `win` = start of the block (win[i] = data[start+i]), `stream` = base of the member,
 * `fn` = length disponible, `bandbase` = start. */
int      ppm_cost_rowsel(ppm_cost_arena *a, const uint8_t *win, const uint8_t *flux,
                         size_t fn, uint32_t i, uint32_t bandbase,
                         uint32_t *row, uint32_t *err, uint32_t *bias);
/* [M220] updates the model of distance en END of node `cand == 0`
 * (0x422704..0x42284e) : last vu, histogramme, registres, halving. */
void     ppm_cost_rowsel_step(ppm_cost_arena *a, const uint8_t *win, const uint8_t *flux,
                              size_t fn, uint32_t i, uint32_t bandbase);
/* [M220] Replays there machine has distance LIVE (0x418fc0..0x41918d) sure `mem[0..upto)` and
 * RECOPIE son state in l'snapshot of l'arena (law 0x422315, atteinte only when
 * `cand == class current == 0`). `mem` = start of the MEMBER. */
void     ppm_cost_rowsel_feed_live(ppm_cost_arena *a, const uint8_t *mem, size_t upto);

void     ppm_cost_arena_reset(ppm_cost_arena *a);

/* [M170g] FEED OF L'ARENA LIVE (law decodee statiquement, OUT/m170g_arenafeed.md 3) :
 * the legacy engine not reconstruit NOT has model since there window, il COPIE the lines of the model
 * PPM live (`master` = freq by context absolu, 0x422262 / 0x422e22) :
 *     freq[rel][sym] = master[base+rel][sym]
 *     escape[rel]    = esc_abs[base+rel]                  (0x43a268)
 *     total[rel]     = esc_abs[base+rel] + cum[base+rel][0]  (cum[0] = sum some freq)
 * `n` = 0x43b290[cl] (number of contexts of the class) ; `base` = 0x43b268[cl].
 * The port fournit these tables directement since the model live : m->freq, m->cum,
 * m->ent_wt (ppm_priv.h). GATED : n'to call that sure the path UHA_BLKLAW>=5. */
typedef struct {
    const uint16_t *freq;    /* [ctx_abs][256] : m->freq                */
    const uint16_t *cum;     /* [ctx_abs][256] : m->cum, cum[0]=sum   */
    const uint16_t *ent;     /* [ctx_abs]      : m->ent_wt (echappement) */
    uint32_t        base;    /* CTXBASE[cl]                             */
    uint32_t        n;       /* number of contexts of the class        */
    /* [M170k] ROW OF PRIOR of the candidate, lue by the 1er term of the node COLD :
     *   0x42242b `eax = (cand<<8) + 0x30400` ; 0x42243b `ax = freq[eax+err]`
     *   0x42244d `div cum[(0x60800 + (cand<<9))]` (words) = cum[772+cand][0]
     *   => cout_froid_1 = LUT[(prior_freq[err]<<14) / prior_total]
     * There table 0x30400/0x200 = 772 is there 1re some 5 rows of prior 772..776. These rows
     * EVOLUENT with the model : has `pos = 0` elles valent 8/2048 (now there constante 37440),
     * but at the decision 2 of `image` there row 775 equals cum0=4144 / f=[232 376 ...]. */
    const uint16_t *prior_freq;  /* &m->freq[772+cand][0]  (NULL = no model live) */
    uint32_t        prior_total; /* m->cum[772+cand][0]                                  */
} ppm_live_arena;

int      ppm_cost_arena_load_live(ppm_cost_arena *a, const ppm_live_arena *L);
/* [M230] arena at the frontier of member : frequencies NEUVES + `escape` = `ent_wt` of the model
 * (law 0x4222e0 ; measures : `ent_wt[0] = 49` at the frontier `1 071 003`, has reset plat gives 1). */
int      ppm_cost_arena_seed_esc(ppm_cost_arena *a, const ppm_live_arena *L);
/* [M235] frequencies neuves + prior of the candidate preserves. */
int      ppm_cost_arena_seed_prior(ppm_cost_arena *a, const ppm_live_arena *L);
uint32_t ppm_cost_node(ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override);
/* [M170g] same node with increment `extra` parametre (scan d'escape 0x422d00) */
uint32_t ppm_cost_node_step(ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override,
                            uint32_t step);
/* [M252] Node SCINDE en cost / nourrissage, for there gate `UHA_PPM_CUTNOFEED` : the master CUT
 * sa walk sure the node which franchit l'incumbent without THE NOURRIR (has occurrence of too by
 * walk tronquee, +32 sure there single row `ctx` of the last node - mesuree sure the 80 vecteurs
 * `OUT/m250_arena_calls.tsv`). `ppm_cost_node_cost` not touche NOT l'arena ; `ppm_cost_node_feed`
 * applies there law M130 (freq/total/escape + rescale). */
uint32_t ppm_cost_node_cost(const ppm_cost_arena *a, uint32_t ctx, uint32_t err, int override);
void     ppm_cost_node_feed(ppm_cost_arena *a, uint32_t ctx, uint32_t err, uint32_t step);
/* [M252] Demi-feed of the node COLD cut : `escape[ctx] += step` and `total[ctx] += step` only
 * (there part " escape " of the update precede the test of cut at the master ; there part
 * " frequency " there suit and therefore not s'execute not sure the node which does franchir l'incumbent). */
void     ppm_cost_feed_esc(ppm_cost_arena *a, uint32_t ctx, uint32_t step);
void     ppm_cost_peek(const ppm_cost_arena *a, uint32_t ctx, uint32_t err,
                       uint32_t *freq, uint32_t *total);
/* [M170k] ctx_bits initial of l'estimator = the 4 bytes REELS precedant there window
 * (the legacy engine reads the global 0x48269c has 0x422392) : `~d[start-1]` en weight FAIBLE,
 * `~d[start-2]` au next, etc. Has `pos = 0` : 0. */
void     ppm_cost_set_prectx(uint32_t v);
/* [M170k] states d'input measurements of l'estimator (captures OUT/m170l_state.log) :
 *   bandbase = [0x4803c0] = position of cut of the block : there band equals `(bandbase + i) % n`
 *              (`(i % n)` n'is valable qu'has pos = 0) ;
 *   initctx  = [0x4803c4] - CTXBASE[cand] = ctx RELATIF of the node 0, applies au single
 *              candidate equal at the class current (otherwise 0x42230e `xor ebp,ebp`). */
void     ppm_cost_set_window(uint32_t bandbase, uint32_t initctx);
/* [M266] band of context `[esp+0x3c]` (= `[0x4803c0]`) : this n'is NOT `pos` ; the legacy engine
 * l'uses for the ctx of cand 2/3/4 (`&1`, `%3`, `&3`). Alimentee by `m->out_count`. */
void     ppm_cost_set_ctxband(uint32_t v);
/* [M172b, GATED UHA_PPM_PAYLOAD, default-OFF] Buffer of output already emis (payload of the member) +
 * usize of the member : au-dela of usize, l'estimator reads son CLEAN stream compressed (the legacy engine has has
 * buffer of output adjacent has son buffer d'input, aligne sure 16 : dump M172 = 1019 bytes).
 * without this reglage, there reading out member rendait some bytes of remplissage (0xff) and faussait
 * the seed cand 0 some the first node depassant there end of the file. */
void     ppm_cost_set_payload(const uint8_t *pay, size_t paylen, size_t usize);
/* [M170k] flag of direction initial (`[esp+0x50]`) : `m->cls_neg` (= [0x483932]) for the candidate
 * equal at the class current, otherwise the flag FINAL of l'call previous (heritage of stack). */
void     ppm_cost_set_flag(uint32_t f);
uint32_t ppm_cost_get_flag(void);
uint64_t ppm_legacy_cost(const uint8_t *win, size_t len, uint32_t cls, uint64_t incumbent);

/* [M170g] Variante " arena live " : the 5 candidates of has decision partagent Has arena
 * (0x421ca5..0x421d96).
 *   feed != 0 -> l'arena is (re)loaded since L before there simulation (0x422262) ;
 *   feed == 0 -> l'arena keeps l'state leaves by the candidate previous (0x42230e).
 * the legacy engine not nourrit THAT the candidate equal at the class current (the 1er), and NEVER cl == 0
 * (0x42225c -> 0x422315). L'appelant respecte this order. */
uint64_t ppm_legacy_cost_live(ppm_cost_arena *a, const uint8_t *win, size_t len,
                              uint32_t cand, uint64_t incumbent,
                              const ppm_live_arena *L, int feed);

/* couture of selection (path consommatrice) : argmin {seed}U{1..4} via oracle injecte. */
typedef uint64_t (*ppm_cost_fn)(const uint8_t *win, size_t len, uint32_t cls, uint64_t incumbent);
uint32_t ppm_legacy_cost_select_class(const uint8_t *win, size_t len, uint32_t cls_courant,
                                      ppm_cost_fn cost_fn, uint64_t *out_cost);
int      ppm_legacy_bc_from_payload(const uint8_t *payload /* archive+40 */);

#endif
