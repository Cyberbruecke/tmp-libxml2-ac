/*
 * cputime_afl.c: the fuzzing harness shared by every engine.
 *
 * It parses the input, runs one post-parse operation on the tree, and reports the
 * CPU time of that operation as the fuzzer's objective. -DSINK_OP selects the
 * operation, so one source builds all five targets.
 *
 * CPU time is used rather than the per-sink counters in measure_*.c because the
 * counters sit inside the loops the paper identifies as quadratic; an objective
 * built on them would encode the answer. The counters are used only for scoring.
 *
 * The clock is CLOCK_PROCESS_CPUTIME_ID, not wall time, so the objective is
 * stable when many fuzzers share the machine.
 *
 * scripts/build-engines.sh builds it for each engine.
 */
#define _GNU_SOURCE   /* memmem, for -DBLOCK_DTD */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/c14n.h>
#include <libxml/xmlerror.h>

extern uint8_t *__afl_area_ptr;

#ifndef MAP_SIZE
#define MAP_SIZE (1U << 16)
#endif
/* Sub-steps per octave. 8 means a 9% increase in CPU time registers as progress; plain log2
 * would demand a doubling, which starves operator-driven search. */
#ifndef COST_SCALE
#define COST_SCALE 8
#endif
#define COST_BUCKETS (64 * COST_SCALE)
#define COST_BASE    (MAP_SIZE - COST_BUCKETS)

/* 1=parse only  2=exclusive C14N  3=inclusive C14N  4=XPath from input  5=cross-doc reconcile */
#ifndef SINK_OP
#define SINK_OP 1
#endif

#define CPU_MAX_INPUT (4 * 1024 * 1024)  /* named, not MAX_INPUT: <limits.h> defines that as 255 */
#define MAX_EXPR  4096

static void silentError(void *ctx, const char *msg, ...) { (void) ctx; (void) msg; }

/* ---------------------------------------------------------------------------------------------
 * Reporting paths, chosen at compile time:
 *
 *   -DIJON_BUILD                     AFL++, through ijon_max()
 *   -DPERFFUZZ_BUILD/-DSLOWFUZZ_BUILD the engine's own objective; nothing reported
 *   -DFF_BUILD                       FuzzFactory (not used by this artifact)
 *   (none)                           an older bitmap encoding (not used)
 *
 * ijon_max() writes the exact microsecond count into a region AFL++ 5.03a keeps
 * after the coverage map (instrumentation/afl-compiler-rt.o.c:5511), reduced by
 * maximum. afl-cc enables it when it finds `ijon_max(` in the source.
 * ------------------------------------------------------------------------------------------- */
#ifdef IJON_BUILD
/* Declared by AFL++'s compiler runtime; u64 value, MAX-reduced into a dedicated region. */
extern void ijon_max(uint32_t addr, uint64_t val);
#ifdef USE_VALID
extern void __afl_valid_assumption_failure(void);
#define VALID_FAIL() __afl_valid_assumption_failure()
#else
#define VALID_FAIL() ((void) 0)
#endif
/* Slot 0: one cost variable per harness, and each harness is its own binary. */
static void report_cost(unsigned long usec) { ijon_max(0, (uint64_t) usec); }

#elif defined(PERFFUZZ_BUILD) || defined(SLOWFUZZ_BUILD)
/* PerfFuzz maximises per-edge execution counts and SlowFuzz total edge
 * executions, both from their own instrumentation, so the harness reports nothing.
 * report_cost() stays a real function rather than a macro so that the call
 * sites, and the edges PerfFuzz counts, are the same in every build. */
#define VALID_FAIL() ((void) 0)
static void report_cost(unsigned long usec) { (void) usec; }

#elif defined(FF_BUILD)
#include "waypoints.h"
FUZZFACTORY_DSF_NEW(__cpu_dsf, 1, FUZZFACTORY_REDUCER_MAX, 0);
#define REPORT_US(v) FUZZFACTORY_DSF_MAX(__cpu_dsf, 0, (uint32_t) (v))
/* Called directly rather than through fuzzfactory's ASSUME_OR_RETURN, whose fprintf on every
 * failure would add I/O to every execution, and most mutants here are malformed. */
#ifdef USE_VALID
extern void __afl_valid_assumption_failure(void);
#define VALID_FAIL() __afl_valid_assumption_failure()
#else
#define VALID_FAIL() ((void) 0)
#endif
static void report_cost(unsigned long usec) { REPORT_US(usec); }

#else
#define VALID_FAIL() ((void) 0)

/* Older encoding into the coverage map; not used by this artifact. */
static void report_cost(unsigned long usec) {
    unsigned b = 0;
    if (__afl_area_ptr == NULL) return;
    if (usec > 1) {
        unsigned oct = 0; unsigned long v = usec;
        while (v > 1) { v >>= 1; oct++; }
        unsigned long base = 1UL << oct;
        unsigned sub = 0;
        while (sub + 1 < COST_SCALE) {
            if (usec * COST_SCALE < base * (COST_SCALE + sub + 1)) break;
            sub++;
        }
        b = oct * COST_SCALE + sub;
        if (b >= COST_BUCKETS) b = COST_BUCKETS - 1;
    }
    for (unsigned i = 0; i <= b; i++)
        __afl_area_ptr[COST_BASE + i] = 0xFF;
}
#endif /* reporting path */

static unsigned long cpu_usec(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t) != 0) return 0;
    return (unsigned long) t.tv_sec * 1000000UL + (unsigned long) (t.tv_nsec / 1000);
}

/* The measured operation, shared by the AFL-style main() and the libFuzzer
 * entry point below. */
static int run_bytes(const uint8_t *buf, size_t n) {
    static char    expr[MAX_EXPR + 1];
    const char *docp; size_t doclen;
    unsigned long t0, t1;

    docp = (const char *) buf; doclen = n; expr[0] = '\0';

#ifdef BLOCK_DTD
    /* -DBLOCK_DTD rejects documents with an internal DTD subset, for a control
     * that keeps the search off DTD entity expansion. Not used by this artifact.
     * Only the first 4 KB is scanned, since the DOCTYPE must precede the root
     * element.
     */
    {
        size_t scan = n < 4096 ? n : 4096;
        if (scan >= 9 && memmem(buf, scan, "<!DOCTYPE", 9) != NULL) {
            VALID_FAIL();
            report_cost(0);
            return 0;
        }
    }
#endif

#if SINK_OP == 4
    /* XPath: the expression travels in the input, as it does in an XML Signature transform. */
    {
        uint8_t *nl = memchr(buf, '\n', n);
        if (!nl) { VALID_FAIL(); report_cost(0); return 0; }
        size_t elen = (size_t) (nl - buf);
        if (elen == 0 || elen > MAX_EXPR) { VALID_FAIL(); report_cost(0); return 0; }
        memcpy(expr, buf, elen); expr[elen] = '\0';
        if (strlen(expr) != elen) { VALID_FAIL(); report_cost(0); return 0; }
        docp = (const char *) (nl + 1); doclen = n - elen - 1;
        if (doclen == 0) { VALID_FAIL(); report_cost(0); return 0; }
    }
#endif

    /* The clock starts after the parse. The vectors are costs of operations on an
     * already-parsed tree; timing the parse as well lets the search grow parse
     * cost instead, which it did when the clock covered both. */
    xmlDocPtr doc = xmlReadMemory(docp, (int) doclen, NULL, NULL,
                                  XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc != NULL) {
        /* Run the operation up to SINK_REPEAT times, stopping once SINK_BUDGET_US of
         * CPU is spent, and report the mean per run.
         *
         * Repetition averages out timer noise: a single post-parse run of a cheap
         * input takes tens of microseconds and varied 2x to 5x across identical
         * runs, and a maximum-reducing objective latches onto such spikes. The
         * budget keeps an expensive input from being killed by the per-execution
         * timeout before it reports. The mean rather than the total, because the
         * total of a budget-limited loop is flat at the budget for every input
         * expensive enough to hit it. */
#ifndef SINK_REPEAT
#define SINK_REPEAT 8
#endif
#ifndef SINK_BUDGET_US
#define SINK_BUDGET_US 2000000UL   /* 2 s of CPU across all reps */
#endif
        t0 = cpu_usec();
        int _rep = 0;
        do {
#if SINK_OP == 1
        /* FlAttr: rebuild each element's attributes with xmlNewProp. In libxml2 2.15
         * the parser appends attributes in O(1) (SAX2.c:2374) and never reaches the
         * quadratic tail walk; xmlNewProp does, as when an SP re-serialises a
         * subtree. Every element is visited, so the flood can sit at any depth. */
        {
            xmlNodePtr cur = xmlDocGetRootElement(doc);
            while (cur != NULL) {
                if (cur->type == XML_ELEMENT_NODE && cur->properties != NULL) {
                    xmlNodePtr tgt = xmlNewNode(NULL, (const xmlChar *) "t");
                    if (tgt != NULL) {
                        xmlAttrPtr a;
                        for (a = cur->properties; a != NULL; a = a->next) {
                            xmlChar *v = xmlNodeGetContent((xmlNodePtr) a);
                            xmlNewProp(tgt, a->name, v ? v : (const xmlChar *) "");
                            if (v) xmlFree(v);
                        }
                        xmlFreeNode(tgt);
                    }
                }
                /* Iterative pre-order walk, so a deep tree cannot exhaust the stack.
                 * Descend only into elements: an entity reference's children are its
                 * replacement tree, which can reference further entities, so following
                 * them is unbounded and measures entity expansion, not this sink. */
                if (cur->type == XML_ELEMENT_NODE && cur->children != NULL) { cur = cur->children; }
                else {
                    while (cur != NULL && cur->next == NULL) cur = cur->parent;
                    cur = (cur != NULL) ? cur->next : NULL;
                }
            }
        }
#elif SINK_OP == 2 || SINK_OP == 3
        xmlChar *out = NULL;
        xmlC14NDocDumpMemory(doc, NULL,
#if SINK_OP == 2
                             XML_C14N_EXCLUSIVE_1_0,
#else
                             XML_C14N_1_0,
#endif
                             NULL, 0, &out);
        if (out) xmlFree(out);
#elif SINK_OP == 4
        xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
        if (ctx) {
            xmlXPathObjectPtr o = xmlXPathEvalExpression((const xmlChar *) expr, ctx);
            if (o) xmlXPathFreeObject(o);
            xmlXPathFreeContext(ctx);
        }
#elif SINK_OP == 5
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root) {
            xmlDocPtr dst = xmlNewDoc((const xmlChar *) "1.0");
            if (dst) {
                xmlNodePtr host = xmlNewNode(NULL, (const xmlChar *) "host");
                xmlDocSetRootElement(dst, host);
                xmlNodePtr cp = xmlDocCopyNode(root, dst, 1);
                if (cp) { xmlAddChild(host, cp); xmlReconciliateNs(dst, cp); }
                xmlFreeDoc(dst);
            }
        }
#endif
            _rep++;
        } while (_rep < SINK_REPEAT && (cpu_usec() - t0) < SINK_BUDGET_US);
        t1 = cpu_usec();
        report_cost(t1 > t0 ? (t1 - t0) / (unsigned long) _rep : 0);
        /* Freeing the tree is outside the measured window: its cost grows with input
         * size whether or not the operation was expensive. */
        xmlFreeDoc(doc);
    } else {
        /* Unparseable input, the usual result of byte-level mutation. */
        VALID_FAIL();
        report_cost(0);
    }
    return 0;
}

#ifdef SLOWFUZZ_BUILD
/* libFuzzer entry point, for SlowFuzz. The parser is initialised once, since
 * libFuzzer runs in-process. Oversized inputs are dropped rather than truncated,
 * because a truncated document has an unrelated cost. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        xmlSetGenericErrorFunc(NULL, silentError);
        inited = 1;
    }
    if (size == 0 || size > CPU_MAX_INPUT) return 0;
    (void) run_bytes(data, size);
    return 0;
}
#else
int main(int argc, char **argv) {
    static uint8_t buf[CPU_MAX_INPUT];
    FILE *f; size_t n;

    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 1; }
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, silentError);

    f = fopen(argv[1], "rb"); if (!f) return 0;
    n = fread(buf, 1, sizeof buf, f); fclose(f);
    if (n == 0) return 0;

    return run_bytes(buf, n);
}
#endif
