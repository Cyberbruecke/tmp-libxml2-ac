/*
 * mut_xml_suite.c — a GENERIC XML diversity-operator suite. One mutator, no per-sink tuning.
 *
 * WHY THIS EXISTS
 * ---------------
 * The per-sink operators (mut_c1_fresh_ns, mut_c2_two_axis, mut_c5_fresh_attr, mut_c7_deepen)
 * each attack one construct, and choosing which one to point at which sink is itself knowledge
 * derived from having analysed the sink. A supervisor review identified that as circular: the
 * operator finds the bug because we built it knowing where the bug was.
 *
 * This file removes that. It offers a MENU over XML's name-bearing and structural constructs,
 * picks uniformly at random, and is pointed at every sink unchanged. Nothing here encodes which
 * construct matters for which sink -- that is precisely what the experiment is meant to find
 * out.
 *
 * THE OPERATIONS, and why these
 * -----------------------------
 * XML has a small, enumerable set of places a name can appear and a document can grow:
 *   OP_NS     fresh namespace declarations on a start-tag
 *   OP_ATTR   fresh attributes on an element
 *   OP_CHILD  additional child elements
 *   OP_NEST   deeper nesting
 *   OP_XPATH  a fresh XPath location path        (split-input harnesses only, see below)
 * A competent engineer writing an XML mutator suite, with no knowledge of libxml2, would
 * enumerate roughly this list from the XML and XPath specifications alone.
 *
 * OP_XPATH AND SPLIT INPUTS. Some harnesses take TWO attacker-controlled halves rather than one:
 * an XML Signature XPath transform carries the expression inside the signed document, so the
 * verifier evaluates an attacker expression against an attacker document. Our C3 harness models
 * that with the input format `expression \n document`. Built with -DSUITE_SPLIT_LINE1 the suite
 * understands that format: OP_XPATH replaces line 1 and leaves the document untouched, and every
 * other operation mutates the document and copies line 1 through verbatim.
 *
 * Knowing that a harness reads two fields is INTERFACE knowledge -- the same thing every
 * structure-aware fuzzer is given when it is handed a grammar or a protocol description. It is
 * not knowledge of which axis is expensive. The generator draws uniformly over all THIRTEEN axes
 * named in XPath 1.0 REC-xpath-19991116 section 2.2, in the order the specification lists them,
 * with no weighting. If preceding-sibling is found to be superlinear, the search found it.
 *
 * WHAT IS DELIBERATELY ABSENT
 * ---------------------------
 * Each per-sink operator carried one bug-derived refinement, measured by us after analysing
 * the sink. None of them appear here:
 *   - attributes are added to a RANDOMLY CHOSEN element, not concentrated on one. (Concentration
 *     came from our measurement that dilution destroys the per-element quadratic.)
 *   - namespaces and children are weighted EQUALLY, not 2:1. (The weighting came from knowing
 *     C2's cost is K*N^2, so the N axis is worth quadratically more.)
 *   - no axis, node test or predicate form is preferred over any other in OP_XPATH.
 *
 * The ONE construct that is deliberately PRESENT is declare-and-use: a namespace declaration is
 * emitted together with a reference to it. That is a property of real XML documents and is
 * normative in RFC 3741's definition of a "visibly utilized" declaration, so it is domain
 * knowledge rather than knowledge of libxml2 -- see the longer note at OP_NS.
 *
 * SELECTION IS UNIFORM AND NON-ADAPTIVE, on purpose. An operator that noticed which operation
 * was paying off and shifted toward it would re-acquire the knowledge through the side door,
 * and the experiment would be circular again by a subtler route.
 *
 * WHAT IT COSTS. Roughly 1/4 of mutations are relevant to any given sink, so expect ~4x more
 * executions than a targeted operator. Measured context: the targeted operator reached the
 * reference payload in ~260,000 executions, so ~4x is ~1M -- still 60x less than the 62M the
 * no-operator arms consumed without finding anything. Quantifying that penalty IS a result: it
 * says ignorance costs a small constant factor, not infinity.
 *
 * BATCH GROWTH. -DSUITE_DIV=n divides the existing-construct count to size each batch.
 * Default 1 ("double the structure") is the naive choice and the easiest to defend; 4 grows
 * cost ~1.56x per application instead of ~4x, trading speed for finer granularity near the
 * execution-time ceiling. Run both if the constant is questioned.
 *
 * Build:
 *   cc -O2 -shared -fPIC -I ~/github/xml/AFLplusplus/include \
 *      mut_xml_suite.c -o mut_xml_suite.so
 *   cc -O2 -shared -fPIC -DSUITE_SPLIT_LINE1 -I ~/github/xml/AFLplusplus/include \
 *      mut_xml_suite.c -o mut_xml_suite_split.so      # for the C3 `expr \n doc` harness
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_OUT (16 * 1024 * 1024)
#ifndef SUITE_DIV
#define SUITE_DIV 1          /* batch = existing_count / SUITE_DIV */
#endif
#define MAX_NEST 180         /* libxml2 refuses nesting past 256 without XML_PARSE_HUGE */

#ifdef SUITE_SPLIT_LINE1
enum { OP_NS = 0, OP_ATTR, OP_CHILD, OP_NEST, OP_XPATH, OP_COUNT };
#define MAX_EXPR 512         /* the C3 harness caps the expression at 4 KB; stay well inside */
#else
enum { OP_NS = 0, OP_ATTR, OP_CHILD, OP_NEST, OP_COUNT };
#endif

typedef struct { uint8_t *out; uint8_t *out2; unsigned long ctr; int last_tag; } st_t;

#ifdef SUITE_ADAPTIVE
/* ---------------------------------------------------------------------------------------------
 * -DSUITE_ADAPTIVE: let the FUZZER'S OWN FEEDBACK choose among this suite's parameters, instead
 * of drawing them uniformly.
 *
 * WHY THIS IS NOT CIRCULAR. The forbidden thing is knowledge WE hold from having analysed the
 * sinks by hand. Knowledge the mutator acquires AT RUNTIME, from the target under test, is what
 * every feedback-driven fuzzer already does -- AFL keeps the inputs that scored and re-mutates
 * them. So an operator that learns "this construct pays off on this target" is learning from the
 * target, not being told the answer by us.
 *
 * WHICH PARAMETERS, AND WHY THESE THREE. Not our choice: they are the axes AFL's OWN havoc
 * already parameterises, lifted from byte level to structure level.
 *
 *   AFL havoc (src/afl-fuzz-one.c)                    this suite
 *   ---------------------------------------------     ----------------------------------
 *   WHICH operator  `mutation_array[r]`      :2442     which structural operation
 *   HOW MANY edits  `use_stacking = 1 + ...` :2385     batch size
 *   WHERE in buffer `rand_below(temp_len)`   :2451     which element to target
 *
 * MOpt adapts only the first of the three. Taking the decomposition from the reference
 * implementation rather than from our own judgement is what keeps the axis list defensible: each
 * axis is present because AFL has it, not because we know which one a particular sink needs.
 *
 * REWARD. afl_custom_queue_new_entry fires when an input reaches the queue. Under
 * AFL_CUSTOM_MUTATOR_ONLY=1 this suite is the ONLY generator, so the parameters used on the
 * preceding call are the ones responsible. And because the cputime waypoint writes cost
 * monotonically into the coverage bitmap, "new queue entry" is largely "new cost bucket" -- a
 * coverage signal doubles as a cost signal here. It is NOISY: some entries are genuinely new
 * edges rather than new cost, so the credit assignment is approximate. Stated, not hidden.
 *
 * ALGORITHM. Independent epsilon-greedy per axis: with probability EPS draw uniformly, otherwise
 * take the arm with the highest observed reward rate (finds+1)/(tries+1). Laplace-smoothed so an
 * untried arm is not permanently starved, and EPS never decays, so exploration has a floor and
 * the search cannot lock onto one arm after an early fluke. EPS = 15 is a round number and is
 * NOT tuned -- tuning it against these sinks would reintroduce exactly the circularity this
 * variant exists to avoid.
 *
 * PRIORS ARE UNIFORM AND IDENTICAL FOR ALL FIVE SINKS. One binary, no per-sink initialisation.
 * ------------------------------------------------------------------------------------------- */
#include <stdio.h>

#define EPS 15               /* percent of draws that stay uniform, forever */
#define MAX_ARMS 8

enum { CP_OP = 0, CP_WHERE, CP_BATCH, CP_COUNT };

static struct {
    unsigned arms;
    unsigned tries[MAX_ARMS];
    unsigned finds[MAX_ARMS];
    int      pending;        /* arm used on the last afl_custom_fuzz call, -1 = none */
} bandit[CP_COUNT];

static int adaptive_ready = 0;

static void bandit_init(void) {
    memset(bandit, 0, sizeof bandit);
    bandit[CP_OP].arms    = OP_COUNT;   /* which structural operation */
    bandit[CP_WHERE].arms = 2;          /* 0 = fresh random element, 1 = reuse previous */
    bandit[CP_BATCH].arms = 2;          /* 0 = proportional to existing, 1 = small fixed */
    for (int c = 0; c < CP_COUNT; c++) bandit[c].pending = -1;
    adaptive_ready = 1;
}

static int bandit_pick(int cp) {
    unsigned n = bandit[cp].arms;
    int best = 0;
    if ((unsigned) (rand() % 100) < (unsigned) EPS) {
        best = rand() % (int) n;                       /* forced exploration */
    } else {
        double bs = -1.0;
        for (unsigned a = 0; a < n; a++) {
            double sc = (double) (bandit[cp].finds[a] + 1) / (double) (bandit[cp].tries[a] + 1);
            if (sc > bs) { bs = sc; best = (int) a; }
        }
    }
    bandit[cp].tries[best]++;
    bandit[cp].pending = best;
    return best;
}

/* AFL calls this after an input we produced is added to the queue: credit the parameters that
 * produced it. Returns 0 = file contents unchanged. */
uint8_t afl_custom_queue_new_entry(void *data, const uint8_t *fn_new, const uint8_t *fn_orig) {
    (void) data; (void) fn_new; (void) fn_orig;
    for (int c = 0; c < CP_COUNT; c++)
        if (bandit[c].pending >= 0) bandit[c].finds[bandit[c].pending]++;
    return 0;
}

/* What it learned, so the campaign can REPORT the weights rather than only the outcome. If the
 * per-sink weights end up resembling the hand-derived refinements, that resemblance is the
 * result -- it would show the knowledge was recoverable at runtime. */
static void bandit_log(void) {
    const char *path = getenv("SUITE_ADAPTIVE_LOG");
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (!f) return;
    static const char *cpn[CP_COUNT] = { "operation", "where", "batch" };
    for (int c = 0; c < CP_COUNT; c++)
        for (unsigned a = 0; a < bandit[c].arms; a++)
            fprintf(f, "%s\tarm%u\t%u\t%u\n", cpn[c], a, bandit[c].tries[a], bandit[c].finds[a]);
    fclose(f);
}
#endif /* SUITE_ADAPTIVE */

void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    st_t *d = calloc(1, sizeof(st_t));
    if (!d) return NULL;
    d->out = malloc(MAX_OUT);
    if (!d->out) { free(d); return NULL; }
#ifdef SUITE_SPLIT_LINE1
    /* Reassembly buffer: the document mutator may return d->out, so the join needs a second
     * region rather than writing over its own source. */
    d->out2 = malloc(MAX_OUT);
    if (!d->out2) { free(d->out); free(d); return NULL; }
#endif
    d->ctr = 1;
    d->last_tag = -1;
    srand(seed);
#ifdef SUITE_ADAPTIVE
    bandit_init();
#endif
    return d;
}

/* How many of `needle` are already present -> batch size. Keeps the RELATIVE gain per
 * application constant; a fixed batch against a super-linear cost is a shrinking relative gain
 * and stalls against any quantised objective. That is a property of quantised waypoints in
 * general, not of any particular sink. */
static int batch_for(const char *hay, size_t n, const char *needle, size_t nl, int floor_k) {
    int count = 0;
    const char *p = hay, *e = hay + n;
    while (p < e) {
        const char *h = (const char *) memmem(p, (size_t) (e - p), needle, nl);
        if (!h) break;
        count++; p = h + nl;
        if (count > 100000) break;
    }
    int k = count / SUITE_DIV;
    if (k < floor_k) k = floor_k;
    if (k > 4096) k = 4096;
    return k;
}

/* BATCH axis (AFL's "how many edits" lifted to structure). Default build: always proportional.
 * -DSUITE_ADAPTIVE: the fuzzer chooses between growing proportionally to what is already there
 * and adding a small fixed amount. Both arms start equally likely. */
#ifdef SUITE_ADAPTIVE
static int batch_axis(const char *hay, size_t n, const char *needle, size_t nl) {
    if (bandit_pick(CP_BATCH) == 1) return 1 + (rand() % 8);            /* small fixed */
    return batch_for(hay, n, needle, nl, 1 + (rand() % 64));            /* proportional */
}
#define SUITE_BATCH(h, n, ne, nl) batch_axis((h), (n), (ne), (nl))
#else
#define SUITE_BATCH(h, n, ne, nl) batch_for((h), (n), (ne), (nl), 1 + (rand() % 64))
#endif

/* Offset just past the element NAME of the idx-th start-tag, i.e. a legal place to splice
 * attributes or namespace declarations. Returns 0 if none found. */
static size_t nth_start_tag_insert(const char *hay, size_t n, int idx) {
    const char *p = hay, *e = hay + n;
    int seen = 0;
    while (p < e) {
        const char *lt = (const char *) memchr(p, '<', (size_t) (e - p));
        if (!lt || lt + 1 >= e) return 0;
        if (lt[1] == '/' || lt[1] == '?' || lt[1] == '!') { p = lt + 1; continue; }
        const char *q = lt + 1;
        while (q < e && *q != ' ' && *q != '>' && *q != '/') q++;
        if (q >= e) return 0;
        if (seen++ == idx) return (size_t) (q - hay);
        p = q;
    }
    return 0;
}

static int count_start_tags(const char *hay, size_t n) {
    const char *p = hay, *e = hay + n; int c = 0;
    while (p < e) {
        const char *lt = (const char *) memchr(p, '<', (size_t) (e - p));
        if (!lt || lt + 1 >= e) break;
        if (lt[1] != '/' && lt[1] != '?' && lt[1] != '!') c++;
        p = lt + 1;
        if (c > 100000) break;
    }
    return c;
}

/* Copy the element name of a randomly chosen start-tag into `nm`. Leaves `nm` untouched when the
 * document has none. Mimicking names already present is generic mutator practice: without it the
 * suite could never name the element a given application happens to care about. */
static void pick_elem_name(const char *hay, size_t n, char *nm, size_t nmsz) {
    int tg = count_start_tags(hay, n);
    if (tg <= 0) return;
    size_t pick = nth_start_tag_insert(hay, n, rand() % tg);
    if (pick <= 1) return;
    const char *q = hay + pick;              /* end of that tag's name */
    const char *b = q;
    while (b > hay && b[-1] != '<' && b[-1] != '/') b--;
    size_t l = (size_t) (q - b);
    if (l > 0 && l < nmsz - 1) { memcpy(nm, b, l); nm[l] = 0; }
}

#ifdef SUITE_SPLIT_LINE1
/* The thirteen axes of XPath 1.0, REC-xpath-19991116 section 2.2, in specification order.
 * Drawn from UNIFORMLY. No axis is preferred, and none is omitted. */
static const char *const kAxes[] = {
    "ancestor", "ancestor-or-self", "attribute", "child", "descendant", "descendant-or-self",
    "following", "following-sibling", "namespace", "parent", "preceding", "preceding-sibling",
    "self"
};
#define N_AXES ((int) (sizeof kAxes / sizeof kAxes[0]))

/* A node test: either a name borrowed from the document, or one of the wildcard/kind tests the
 * grammar allows. Borrowing matters -- `child::*` matches, `child::zzz` matches nothing, and an
 * expression that selects nothing exercises nothing. */
static void gen_node_test(const char *doc, size_t dlen, char *nt, size_t ntsz) {
    switch (rand() % 4) {
    case 0:  snprintf(nt, ntsz, "*");        break;
    case 1:  snprintf(nt, ntsz, "node()");   break;
    case 2:  snprintf(nt, ntsz, "text()");   break;
    default: { char nm[64] = "*"; pick_elem_name(doc, dlen, nm, sizeof nm);
               snprintf(nt, ntsz, "%s", nm); }
    }
}

/* Build one location path over the XPath 1.0 grammar. Steps, node tests, predicate forms and
 * axes are all drawn uniformly; the generator has no notion of which combination is expensive. */
static size_t gen_xpath(const char *doc, size_t dlen, char *e, size_t esz) {
    size_t o = 0;
    int steps = 1 + (rand() % 4);
    int n;

    n = snprintf(e + o, esz - o, "%s", (rand() % 2) ? "//" : "/");
    if (n <= 0 || (size_t) n >= esz - o) return 0;
    o += (size_t) n;

    for (int s = 0; s < steps; s++) {
        char nt[80];
        gen_node_test(doc, dlen, nt, sizeof nt);
        n = snprintf(e + o, esz - o, "%s%s::%s",
                     s ? ((rand() % 2) ? "//" : "/") : "", kAxes[rand() % N_AXES], nt);
        if (n <= 0 || (size_t) n >= esz - o) break;
        o += (size_t) n;

        if (rand() % 2) {                    /* optional predicate */
            char pnt[80];
            const char *pax = kAxes[rand() % N_AXES];
            gen_node_test(doc, dlen, pnt, sizeof pnt);
            switch (rand() % 6) {
            case 0: n = snprintf(e + o, esz - o, "[position() > %d]", rand() % 8); break;
            case 1: n = snprintf(e + o, esz - o, "[last()]");                      break;
            case 2: n = snprintf(e + o, esz - o, "[count(%s::%s) > %d]",
                                 pax, pnt, rand() % 8);                            break;
            case 3: n = snprintf(e + o, esz - o, "[%s::%s]", pax, pnt);            break;
            case 4: n = snprintf(e + o, esz - o, "[string-length(.) > %d]",
                                 rand() % 8);                                      break;
            default: n = snprintf(e + o, esz - o, "[not(%s::%s)]", pax, pnt);      break;
            }
            if (n <= 0 || (size_t) n >= esz - o) break;
            o += (size_t) n;
        }
    }
    return o;
}
#endif /* SUITE_SPLIT_LINE1 */

/* Mutate one XML document. `op` is chosen by the caller so that split-input harnesses can route
 * OP_XPATH away from here. Sets *out_buf to `buf` (unchanged) or to d->out, and returns length. */
static size_t fuzz_doc(st_t *d, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       size_t max_size, int op) {
    *out_buf = buf;
    if (!buf_size || buf_size > MAX_OUT / 2) return buf_size;

    char  *hay = (char *) buf;
    size_t o = 0;

    /* BOOTSTRAP. A trivial input such as "<a/>" has no interior to grow. Emit a minimal
     * two-level document so every operation below has something to anchor on. */
    if (count_start_tags(hay, buf_size) < 1 || buf_size < 8) {
        int n = snprintf((char *) d->out, MAX_OUT, "<r><e/></r>");
        if (n <= 0) return buf_size;
        *out_buf = d->out;
        return (size_t) n;
    }

    if (op == OP_NEST) {
        /* Wrap the root's body. Wrapping exactly the body keeps the result balanced whatever
         * the body contains. Plain elements only -- no namespaces, no attributes. */
        /* Find the ROOT element's '>', not the XML declaration's. memchr from offset 0 hits
         * "<?xml ... ?>" first, so wrapping started in the wrong place and produced mismatched
         * tags -- C1's seed carries a declaration, the other seeds do not, which is why only C1
         * broke. Skip any leading <? ... ?> and <!-- ... --> first. */
        const char *scan = hay, *end = hay + buf_size;
        while (scan < end && *scan != '<') scan++;
        while (scan + 1 < end && (scan[1] == '?' || scan[1] == '!')) {
            const char *cl = (const char *) memchr(scan, '>', (size_t) (end - scan));
            if (!cl) return buf_size;
            scan = cl + 1;
            while (scan < end && *scan != '<') scan++;
        }
        if (scan >= end) return buf_size;
        char *gt = memchr(scan, '>', (size_t) (end - scan));
        if (!gt) return buf_size;
        size_t open_at = (size_t) ((gt + 1) - hay);
        char *close_p = memrchr(hay, '<', buf_size);
        if (!close_p || (size_t) (close_p - hay) <= open_at) return buf_size;
        size_t close_at = (size_t) (close_p - hay);

        int cur = 0;                        /* how deep are we already? */
        { const char *q = hay, *e2 = hay + buf_size;
          while (q < e2) { const char *h = memmem(q, (size_t)(e2 - q), "<w>", 3);
                           if (!h) break; cur++; q = h + 3; if (cur > 300) break; } }
        int room = MAX_NEST - cur;
        if (room < 1) return buf_size;
        int k = 1 + (rand() % 32); if (k > room) k = room;

        size_t body = close_at - open_at, tail = buf_size - close_at;
        if (open_at + (size_t) k * 3 + body + (size_t) k * 4 + tail >= max_size) return buf_size;

        memcpy(d->out, hay, open_at); o = open_at;
        /* Half the time, nest with NAMESPACED wrappers rather than plain <w>. Nesting plain
         * elements can never exercise namespace machinery at depth; alternating is what a
         * generic suite covering XML's constructs would do, and costs no target knowledge. */
        int ns_nest = rand() % 2;
        for (int i = 0; i < k; i++) {
            if (ns_nest) {
                unsigned long idx = d->ctr++;
                int n = snprintf((char *) d->out + o, MAX_OUT - o,
                                 "<w%lu:e xmlns:w%lu=\"u:%lu\" w%lu:a=\"\">", idx, idx, idx, idx);
                if (n <= 0 || o + (size_t) n + 64 >= max_size) { k = i; break; }
                o += (size_t) n;
            } else { memcpy(d->out + o, "<w>", 3); o += 3; }
        }
        memcpy(d->out + o, hay + open_at, body); o += body;
        for (int i = k - 1; i >= 0; i--) {
            if (ns_nest) {
                /* close in reverse order so prefixes match their opening tags */
                unsigned long idx = d->ctr - (unsigned long) (k - i);
                int n = snprintf((char *) d->out + o, MAX_OUT - o, "</w%lu:e>", idx);
                if (n <= 0 || o + (size_t) n >= max_size) break;
                o += (size_t) n;
            } else { memcpy(d->out + o, "</w>", 4); o += 4; }
        }
        memcpy(d->out + o, hay + close_at, tail); o += tail;
        *out_buf = d->out;
        return o;
    }

    if (op == OP_CHILD) {
        /* Reuse a name already present in the document rather than always emitting <c/>.
         * Mimicking existing structure is generic mutator practice and needs no knowledge of
         * the target: without it the suite could never produce the element name a given
         * application happens to care about. (Measured: with a hardcoded <c/> the suite scored
         * the seed value on C3, whose harness matches elements named `a`.) */
        char nm[64] = "c";
        pick_elem_name(hay, buf_size, nm, sizeof nm);
        /* Additional children, spliced before the last tag so they land inside the document. */
        char *ins = memrchr(hay, '<', buf_size);
        if (!ins || ins == hay) return buf_size;
        size_t at = (size_t) (ins - hay), tail_len = buf_size - at;
        char frag[72]; int fl = snprintf(frag, sizeof frag, "<%s/>", nm);
        if (fl <= 0) return buf_size;
        int k = SUITE_BATCH(hay, buf_size, frag, (size_t) fl);
        memcpy(d->out, hay, at); o = at;
        for (int i = 0; i < k; i++) {
            if (o + (size_t) fl + tail_len >= max_size) break;
            memcpy(d->out + o, frag, (size_t) fl); o += (size_t) fl;
        }
        memcpy(d->out + o, hay + at, tail_len); o += tail_len;
        *out_buf = d->out;
        return o;
    }

    /* OP_NS and OP_ATTR both splice into a start-tag. WHICH start-tag is the WHERE axis:
     * uniformly random in the default build, learned in the -DSUITE_ADAPTIVE build. */
    int tags = count_start_tags(hay, buf_size);
    if (tags < 1) return buf_size;
    int tgt = rand() % tags;
#ifdef SUITE_ADAPTIVE
    /* arm 1 = reuse the previous target (concentrate), arm 0 = draw a fresh one (spread).
     * Both arms start equally likely; the fuzzer's feedback decides which survives. */
    if (bandit_pick(CP_WHERE) == 1 && d->last_tag >= 0 && d->last_tag < tags) tgt = d->last_tag;
    d->last_tag = tgt;
#endif
    size_t at = nth_start_tag_insert(hay, buf_size, tgt);
    if (at == 0) return buf_size;
    size_t tail_len = buf_size - at;

    memcpy(d->out, hay, at); o = at;

    if (op == OP_NS) {
        int k = SUITE_BATCH(hay, buf_size, "xmlns:", 6);
        for (int i = 0; i < k; i++) {
            unsigned long idx = d->ctr++;
            /* DECLARE AND USE. Real XML documents do not carry namespace declarations nothing
             * references -- a prefix is declared in order to be applied to an element or
             * attribute name. A mutator that mimics real documents therefore emits the pair,
             * and RFC 3741 makes the same notion normative for canonicalisation via its
             * definition of a "visibly utilized" declaration.
             *
             * This is DOMAIN knowledge (the XML/C14N specs, public and citable), not
             * VULNERABILITY knowledge (libxml2's implementation). The distinction matters:
             * omitting the reference left both C1 and C7 unreachable by this suite, and C7 was
             * NOT a sink we designed this pairing for -- that it also unlocks reconcile is
             * evidence the principle is general rather than reverse-engineered from one bug. */
            int n = snprintf((char *) d->out + o, MAX_OUT - o,
                             " xmlns:n%lu=\"u:%lu\" n%lu:a%lu=\"\"", idx, idx, idx, idx);
            if (n <= 0 || o + (size_t) n + tail_len >= max_size) break;
            o += (size_t) n;
        }
    } else {                                 /* OP_ATTR */
        int k = SUITE_BATCH(hay, buf_size, "=\"", 2);
        for (int i = 0; i < k; i++) {
            unsigned long idx = d->ctr++;
            /* Fresh name: duplicate attribute names are not well-formed XML, so distinctness
             * is required by the format itself, not chosen for cost. */
            int n = snprintf((char *) d->out + o, MAX_OUT - o, " p%lu=\"\"", idx);
            if (n <= 0 || o + (size_t) n + tail_len >= max_size) break;
            o += (size_t) n;
        }
    }

    memcpy(d->out + o, hay + at, tail_len); o += tail_len;
    *out_buf = d->out;
    return o;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
    st_t *d = (st_t *) data;
    (void) add_buf; (void) add_buf_size;

#ifdef SUITE_ADAPTIVE
    int op = bandit_pick(CP_OP);             /* learned from queue feedback, not uniform */
#else
    int op = rand() % OP_COUNT;              /* uniform, non-adaptive */
#endif

#ifndef SUITE_SPLIT_LINE1
    return fuzz_doc(d, buf, buf_size, out_buf, max_size, op);
#else
    *out_buf = buf;
    if (!buf_size || buf_size > MAX_OUT / 2) return buf_size;

    /* Split on the first newline, exactly as the harness does. */
    uint8_t *nl = memchr(buf, '\n', buf_size);
    if (!nl) {
        /* No separator: the input is not in the harness's format and would score 0. Rebuild it
         * by treating the whole buffer as the document and generating an expression for it. */
        char e[MAX_EXPR];
        size_t el = gen_xpath((char *) buf, buf_size, e, sizeof e);
        if (!el || el + 1 + buf_size >= max_size || el + 1 + buf_size >= MAX_OUT) return buf_size;
        memcpy(d->out2, e, el);
        d->out2[el] = '\n';
        memcpy(d->out2 + el + 1, buf, buf_size);
        *out_buf = d->out2;
        return el + 1 + buf_size;
    }

    size_t   elen = (size_t) (nl - buf);
    uint8_t *doc  = nl + 1;
    size_t   dlen = buf_size - elen - 1;

    if (op == OP_XPATH) {
        /* Replace line 1; the document passes through untouched. */
        char e[MAX_EXPR];
        size_t el = gen_xpath((char *) doc, dlen, e, sizeof e);
        if (!el || el + 1 + dlen >= max_size || el + 1 + dlen >= MAX_OUT) return buf_size;
        memcpy(d->out2, e, el);
        d->out2[el] = '\n';
        memcpy(d->out2 + el + 1, doc, dlen);
        *out_buf = d->out2;
        return el + 1 + dlen;
    }

    /* Document operation: mutate the second half only, and copy line 1 through verbatim. The
     * budget handed to fuzz_doc excludes the expression and its newline. */
    if (!dlen || elen + 1 >= max_size) return buf_size;
    uint8_t *dout = NULL;
    size_t   dnew = fuzz_doc(d, doc, dlen, &dout, max_size - elen - 1, op);
    if (!dout || dnew == 0) return buf_size;
    if (dout == doc && dnew == dlen) return buf_size;   /* unchanged: avoid a pointless copy */
    if (elen + 1 + dnew >= MAX_OUT) return buf_size;

    memcpy(d->out2, buf, elen);
    d->out2[elen] = '\n';
    memcpy(d->out2 + elen + 1, dout, dnew);
    *out_buf = d->out2;
    return elen + 1 + dnew;
#endif
}

/* ---------------------------------------------------------------------------------------------
 * HAVOC ROTATION. Exporting afl_custom_havoc_mutation makes AFL++ include this suite as one
 * operator inside havoc's own mutation STACK, alongside its byte-level operators, instead of
 * confining it to a separate stage. AFL++ detects the pair automatically (it sets
 * `stacked_custom` when the symbol is present, src/afl-fuzz-one.c:2243) -- there is no env var.
 *
 * WHY THIS IS LEGITIMATE. It is the documented custom-mutator API (docs/custom_mutators.md), not
 * knowledge about libxml2. It changes HOW OFTEN the operator is applied and what it composes
 * with, never what it generates.
 *
 * WHY IT MATTERS HERE. Without it the suite and havoc alternate as separate stages, so a
 * structural edit is never composed with byte edits inside one input. With it they interleave --
 * which is the configuration MOpt actually schedules over, and therefore the only way the suite
 * can participate in the adaptive rotation at all.
 *
 * GUARDED BEHIND -DSUITE_HAVOC_HOOK, AND OFF BY DEFAULT. FuzzFactory can only apply the suite via
 * AFL_POST_LIBRARY, where afl_postprocess runs ONCE on the final buffer AFTER havoc has finished.
 * If the AFL++ build stacked the suite inside havoc while the ff build post-processed it, the
 * two engines' positive arms would differ in HOW the operator is applied as well as in engine --
 * reintroducing exactly the confound batch 5's `pos-ff` rows exist to remove. The default build
 * therefore matches ff's mechanism (separate application), and the stacked behaviour lives in its
 * own binary for its own arm.
 *
 * The probability is deliberately NOT adaptive. Returning a fixed value keeps selection
 * non-adaptive for the same reason the operator menu is uniform: an operator that noticed which
 * of its own choices paid off would re-acquire target knowledge through a side door.
 * ------------------------------------------------------------------------------------------- */
#ifdef SUITE_HAVOC_HOOK
size_t afl_custom_havoc_mutation(void *data, uint8_t *buf, size_t buf_size,
                                 uint8_t **out_buf, size_t max_size) {
    st_t *d = (st_t *) data;
    if (!d) { *out_buf = buf; return buf_size; }
    return afl_custom_fuzz(d, buf, buf_size, out_buf, NULL, 0, max_size);
}

/* Percent chance this suite is applied at any one step of a havoc stack.
 *
 * 6 is AFL++'s OWN DOCUMENTED DEFAULT for this callback ("By default, it is 6%",
 * docs/custom_mutators.md), and its shipped reference mutator returns 5
 * (custom_mutators/examples/example.c:291). An earlier version of this file returned 20, a
 * number with no derivation behind it -- 3-4x the convention, which would have quietly made this
 * arm "mostly structure" rather than "havoc plus some structure" and invited exactly the
 * question of where the constant came from. Adopting the upstream default means the value is
 * cited rather than chosen. */
uint8_t afl_custom_havoc_mutation_probability(void *data) {
    (void) data;
    return 6;
}
#endif /* SUITE_HAVOC_HOOK */

void afl_custom_deinit(void *data) {
    st_t *d = (st_t *) data;
#ifdef SUITE_ADAPTIVE
    if (adaptive_ready) bandit_log();
#endif
    if (d) { free(d->out); free(d->out2); free(d); }
}

/* ---------------------------------------------------------------------------------------------
 * -DPOST_BUILD: expose the SAME suite through FuzzFactory's AFL_POST_LIBRARY ABI.
 *
 * WHY. FuzzFactory is AFL 2.52b and has no AFL_CUSTOM_MUTATOR_LIBRARY. Without this, the
 * positive arm on FuzzFactory had to use the per-sink `post_c*` operators -- which are the
 * INFORMED, bug-derived operators -- while the positive arm on AFL++ used this generic suite.
 * Two different kinds of arm under one label makes the comparison meaningless. Building both
 * ABIs from one source means "pos" denotes the same generator on both engines.
 *
 * TWO DIFFERENCES REMAIN, and both are engine limitations rather than choices:
 *   1. afl_postprocess runs AFTER havoc and cannot disable it, so the FuzzFactory positive arm
 *      is "suite + havoc" where the AFL++ arm can be "suite only" (AFL_CUSTOM_MUTATOR_ONLY).
 *   2. a post-processor is applied to EVERY candidate before execution, not selected as one
 *      mutation among many, so the suite is applied more often per execution.
 * Both must be stated when the two engines' positive arms are compared.
 * ------------------------------------------------------------------------------------------- */
#ifdef POST_BUILD
#include <unistd.h>
#include <time.h>

static void *g_state;

uint8_t *afl_postprocess(uint8_t *buf, unsigned int *len) {
    uint8_t *out = buf;
    size_t   n;

    if (!g_state) {
        g_state = afl_custom_init(NULL, (unsigned) time(NULL) ^ (unsigned) getpid());
        if (!g_state) return buf;
    }
    /* No max_size is supplied by this ABI; MAX_OUT/2 matches the guard afl_custom_fuzz already
     * applies to its input, so the two paths bound growth identically. */
    n = afl_custom_fuzz(g_state, buf, (size_t) *len, &out, NULL, 0, MAX_OUT / 2);
    if (!out || n == 0) return buf;
    *len = (unsigned int) n;
    return out;
}
#endif /* POST_BUILD */

/* ---------------------------------------------------------------------------------------------
 * -DLIBFUZZER_BUILD: expose the SAME suite through libFuzzer's LLVMFuzzerCustomMutator ABI, for
 * arm 6 (SlowFuzz + suite).
 *
 * WHY A THIRD ABI. Arms 2 (AFL++), 4 (PerfFuzz/FuzzFactory) and 6 (SlowFuzz) must apply the SAME
 * generator, or an arm-to-arm difference could be a generator difference rather than an engine
 * difference. AFL++ takes afl_custom_fuzz, AFL 2.52b takes afl_postprocess, libFuzzer takes
 * LLVMFuzzerCustomMutator. One source, three entry points, identical body.
 *
 * HOW ARM 6 DIFFERS FROM ARMS 2 AND 4 -- state this when comparing. SlowFuzz selects one mutator
 * uniformly from its menu (FuzzerMutate.cpp:671, idx = TrueRand(Mutators.size())). With the suite
 * registered, the menu is 14 entries, so the suite runs on about 1/14 of mutation steps; with
 * -mutate_depth=5 (libFuzzer's default) that is 1-(13/14)^5 ~= 31% of generated inputs. This is
 * *between* arm 2 (a separate stage with its own budget, seeing clean parents) and arm 4 (applied
 * to every execution, after havoc). It is SlowFuzz's own scheduling, not a choice of ours.
 *
 * ABI CONTRACT. libFuzzer mutates IN PLACE: we must copy our buffer back into Data, bounded by
 * MaxSize, and return the new size. Returning 0 means "declined", and SlowFuzz's MutateImpl then
 * tries the next mutator (FuzzerMutate.cpp:688 requires a non-zero size <= MaxSize), which is the
 * same fallback the suite already relies on elsewhere.
 * ------------------------------------------------------------------------------------------- */
#ifdef LIBFUZZER_BUILD
static void *g_lf_state;

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    uint8_t *out = Data;
    size_t   n;

    if (!g_lf_state) {
        g_lf_state = afl_custom_init(NULL, Seed);
        if (!g_lf_state) return 0;
    }
    /* Make the suite's internal rand() draws follow libFuzzer's -seed, so a run is reproducible
     * from the engine's own seed rather than from wall-clock state. */
    srand(Seed);

    n = afl_custom_fuzz(g_lf_state, Data, Size, &out, NULL, 0,
                        MaxSize < MAX_OUT / 2 ? MaxSize : MAX_OUT / 2);
    if (!out || n == 0 || n > MaxSize) return 0;     /* declined -> SlowFuzz picks another mutator */
    if (out != Data) memcpy(Data, out, n);
    return n;
}
#endif /* LIBFUZZER_BUILD */
