/*
 * mut_xml_suite.c: a generic XML mutation suite, used unchanged against every sink.
 *
 * The per-sink operators (mut_c*_*.c) each target one construct, and choosing which
 * to point at which sink requires knowing where the bug is. This suite does not: it
 * draws uniformly from XML's name-bearing and structural constructs,
 *
 *   OP_NS     fresh namespace declarations on a start-tag
 *   OP_ATTR   fresh attributes on an element
 *   OP_CHILD  additional child elements
 *   OP_NEST   deeper nesting
 *   OP_XPATH  a fresh XPath location path (split-input harnesses only)
 *
 * which is roughly the list one would derive from the XML and XPath specifications
 * without knowing libxml2.
 *
 * Split inputs. An XML Signature XPath transform carries its expression inside the
 * document, and the XPlode harness models that as `expression \n document`. Built
 * with -DSUITE_SPLIT_LINE1, OP_XPATH replaces line 1 and the other operations mutate
 * only the document. Knowing the input has two fields is interface knowledge, like
 * a grammar given to any structure-aware fuzzer; it says nothing about which axis is
 * expensive. OP_XPATH draws uniformly from all thirteen axes of XPath 1.0 (section
 * 2.2), unweighted.
 *
 * Compared with the per-sink operators, the suite does not concentrate attributes on
 * one element, weights namespaces and children equally, and prefers no XPath axis,
 * node test or predicate. The one structural rule it keeps is declare-and-use (see
 * OP_NS), which comes from the XML and C14N specifications.
 *
 * Selection is uniform and does not adapt, so the suite cannot learn which operation
 * pays off on a given sink.
 *
 * -DSUITE_DIV=n sets the batch size to the existing construct count divided by n.
 * The default, 1, doubles the structure on each application.
 *
 * scripts/build-engines.sh builds it for each engine.
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
 * -DSUITE_ADAPTIVE: choose the operation, target element and batch size by
 * epsilon-greedy bandit on queue feedback instead of uniformly. Not used by this
 * artifact; every build here is uniform.
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

/* AFL calls this after an input this suite produced is added to the queue: credit the parameters that
 * produced it. Returns 0 = file contents unchanged. */
uint8_t afl_custom_queue_new_entry(void *data, const uint8_t *fn_new, const uint8_t *fn_orig) {
    (void) data; (void) fn_new; (void) fn_orig;
    for (int c = 0; c < CP_COUNT; c++)
        if (bandit[c].pending >= 0) bandit[c].finds[bandit[c].pending]++;
    return 0;
}

/* Print the learned weights (SUITE_ADAPTIVE only). */
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

/* Batch size from the count of `needle` already present, so each application grows
 * the structure by a constant ratio. A fixed batch gives a shrinking relative gain
 * against a superlinear cost. */
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

/* Batch size: proportional to what is already present. Under -DSUITE_ADAPTIVE the
 * bandit can also pick a small fixed batch. */
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
/* The thirteen axes of XPath 1.0 (REC-xpath-19991116, section 2.2), in specification
 * order, drawn uniformly. */
static const char *const kAxes[] = {
    "ancestor", "ancestor-or-self", "attribute", "child", "descendant", "descendant-or-self",
    "following", "following-sibling", "namespace", "parent", "preceding", "preceding-sibling",
    "self"
};
#define N_AXES ((int) (sizeof kAxes / sizeof kAxes[0]))

/* A node test: either a name borrowed from the document, or one of the wildcard/kind tests the
 * grammar allows. Borrowing matters: `child::*` matches, `child::zzz` matches nothing, and an
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

    /* An input such as "<a/>" has no interior to grow, so start from a minimal
     * two-level document. */
    if (count_start_tags(hay, buf_size) < 1 || buf_size < 8) {
        int n = snprintf((char *) d->out, MAX_OUT, "<r><e/></r>");
        if (n <= 0) return buf_size;
        *out_buf = d->out;
        return (size_t) n;
    }

    if (op == OP_NEST) {
        /* Wrap the root's body. Wrapping exactly the body keeps the result balanced whatever
         * the body contains. Plain elements only, with no namespaces or attributes. */
        /* Find the root element's '>', skipping any leading <? ... ?> and
         * <!-- ... -->, so an XML declaration is not mistaken for the root. */
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
        /* Half the time, nest with namespaced wrappers rather than plain <w>, so depth
         * and namespaces can combine. */
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
        /* Reuse an element name already in the document rather than a fixed one, so
         * the suite can produce names the application actually matches on. */
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

    /* OP_NS and OP_ATTR splice into a start-tag chosen uniformly at random (by the
     * bandit under -DSUITE_ADAPTIVE). */
    int tags = count_start_tags(hay, buf_size);
    if (tags < 1) return buf_size;
    int tgt = rand() % tags;
#ifdef SUITE_ADAPTIVE
    /* Bandit choice 1 reuses the previous target element (concentrate), choice 0 draws
     * a fresh one (spread). Both start equally likely. */
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
            /* Declare and use: emit each namespace declaration together with a name that
             * references it. Real documents declare a prefix to use it, and RFC
             * 3741 makes this normative for canonicalisation through its definition of a
             * "visibly utilized" declaration. This is knowledge of the XML and C14N
             * specifications, not of libxml2. Without the reference, the suite reached
             * neither exclusive C14N1D3 nor Wreckoncile. */
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
 * -DSUITE_HAVOC_HOOK exports afl_custom_havoc_mutation, which makes AFL++ apply the
 * suite as one operator inside havoc's mutation stack (src/afl-fuzz-one.c:2243)
 * rather than as a separate stage. Not used by this artifact: the default build
 * applies the suite as a separate stage, matching how PerfFuzz applies it.
 * ------------------------------------------------------------------------------------------- */
#ifdef SUITE_HAVOC_HOOK
size_t afl_custom_havoc_mutation(void *data, uint8_t *buf, size_t buf_size,
                                 uint8_t **out_buf, size_t max_size) {
    st_t *d = (st_t *) data;
    if (!d) { *out_buf = buf; return buf_size; }
    return afl_custom_fuzz(d, buf, buf_size, out_buf, NULL, 0, max_size);
}

/* Percent chance the suite is applied at a havoc step: AFL++'s documented default
 * for this callback (docs/custom_mutators.md, "By default, it is 6%"). */
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
 * -DPOST_BUILD: the same suite through AFL 2.52b's AFL_POST_LIBRARY interface, for
 * PerfFuzz (perffuzz-suite). Two differences from the AFL++ build follow from that
 * interface: the post-processor runs after havoc and cannot turn it off, and it is
 * applied to every candidate before execution rather than chosen as one mutation
 * among several.
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
 * -DLIBFUZZER_BUILD: the same suite through libFuzzer's LLVMFuzzerCustomMutator, for
 * SlowFuzz (slowfuzz-suite). One source with three entry points, so every engine
 * applies the same generator.
 *
 * SlowFuzz picks one mutator uniformly per step (FuzzerMutate.cpp:671). With the
 * suite registered the menu has 14 entries, and with the default -mutate_depth=5
 * the suite touches about 1-(13/14)^5, or 31%, of generated inputs.
 *
 * libFuzzer mutates in place: copy the result into Data within MaxSize and return
 * the new size. Returning 0 declines, and SlowFuzz tries another mutator
 * (FuzzerMutate.cpp:688).
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
    /* Seed rand() from libFuzzer's -seed so a run is reproducible. */
    srand(Seed);

    n = afl_custom_fuzz(g_lf_state, Data, Size, &out, NULL, 0,
                        MaxSize < MAX_OUT / 2 ? MaxSize : MAX_OUT / 2);
    if (!out || n == 0 || n > MaxSize) return 0;     /* declined -> SlowFuzz picks another mutator */
    if (out != Data) memcpy(Data, out, n);
    return n;
}
#endif /* LIBFUZZER_BUILD */
