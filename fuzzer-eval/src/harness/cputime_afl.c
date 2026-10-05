/*
 * cputime_afl.c — a KNOWLEDGE-FREE algorithmic-complexity objective.
 *
 * WHY THIS EXISTS
 * ---------------
 * Our five per-sink counters (xmlC14NScanIters, xmlC3AxisIters, ...) are each incremented
 * inside the exact loop our own analysis identified as quadratic. xmlC3AxisIters, for example,
 * lives in xmlXPathNextPrecedingSibling. That makes them unusable as a fuzzing OBJECTIVE for a
 * "could this have been found from zero?" experiment: the objective encodes the answer, so an
 * expression walking a different axis scores zero no matter how pathological it is. Measured:
 *   //a[count(preceding-sibling::a) > 0]   ->  45,150
 *   //a/ancestor::*                        ->       0
 *
 * This harness measures CPU TIME instead. It requires no knowledge of libxml2, of which loop is
 * hot, or of which sink exists -- only "run the operation and see how long it took", which is
 * what an engineer with no insight into the target would write on day one. It is also what an
 * attacker actually cares about and what a defender measures.
 *
 * CLOCK_PROCESS_CPUTIME_ID, NOT WALL CLOCK. Under heavy oversubscription (our campaign ran 87
 * concurrent fuzzers on 12 cores) wall-clock timing is dominated by scheduler noise, and the
 * fuzzer would chase contention rather than cost. Per-process CPU time excludes time the
 * process was not running, so it stays stable under load.
 *
 * SEPARATION OF ROLES. The per-sink counters remain the right METRIC -- they are exact,
 * noise-free, and attribute cost to a specific sink when reporting results offline. What they
 * must not be is the OBJECTIVE. This file is the objective; measure_*.c stay the metric.
 *
 * WHICH OPERATION. Selected by -DSINK_OP=<n> at build time so one source covers every sink.
 * The operation itself is ordinary API usage, not a hint: parse, canonicalise, evaluate a
 * supplied XPath, or copy across documents.
 *
 * Build (one binary per sink):
 *   AFL_CC=gcc-13 afl-gcc-fast -O2 -DSINK_OP=1 -I include -I . \
 *       cputime_afl.c .libs/libxml2.a -o cputime_c1 -lz -lm -lpthread
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
 * -DFF_BUILD: report through FuzzFactory's DSF instead of our bitmap encoding.
 *
 * WHY. Without this, `cputime` could only run on AFL++ while perf/slow/valid run on FuzzFactory,
 * so any comparison between them would confound the OBJECTIVE with the ENGINE -- the exact
 * confound that forced the Phase 4 no-operator baselines to be re-run on one engine. CPU time is
 * an ordinary u32 quantity and FuzzFactory's MAX reducer takes it directly, so there is no
 * reason for the split. Building both ways from ONE source also guarantees the two arms measure
 * the same thing: the sink selection, the timing window and the failure handling below are
 * shared code, not two implementations that have to be kept in step.
 *
 * The DSF value is the EXACT microsecond count, not a log2 bucket -- FuzzFactory keeps a real
 * u32 per domain, so the quantisation our bitmap needs is unnecessary here.
 * ------------------------------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------------------------
 * THREE REPORTING PATHS, one measurement. Selected at compile time.
 *
 *   -DIJON_BUILD   AFL++ via ijon_max()  -- PREFERRED, see below
 *   -DFF_BUILD     FuzzFactory DSF
 *   (neither)      legacy bitmap encoding -- DEFECTIVE, kept only for controlled comparison
 *
 * WHY IJON REPLACED THE BITMAP ENCODING. The legacy path wrote log2 buckets into the top 512
 * bytes of AFL's COVERAGE bitmap and marked monotonically to fake an ordering, because
 * has_new_bits() is a set-membership test. That shares a hashed index space with the target's
 * edges, and edge ids are `AFL_R(MAP_SIZE)` -- a uniform random draw -- so collisions are
 * unavoidable. MEASURED on this target: 6,495 distinct edge tuples over 5 sinks x 50 seeds
 * polluted **52 of our 512 buckets**, including the bucket meaning 1 SECOND of CPU, set by the
 * seed corpus BEFORE fuzzing begins. Monotone marking then means a genuine 1 s discovery lights
 * nothing new and is DISCARDED. Relocating the window cannot help: every 512-byte window holds
 * 34-72 edges (50.7 expected if uniform).
 *
 * AFL++ 5.03a ships the right mechanism natively (instrumentation/afl-compiler-rt.o.c:5511):
 *     __afl_ijon_bits = (u64 *)(__afl_area_ptr + __afl_set_map_size);   // APPENDED past the edges
 *     if (__afl_ijon_bits[id] < val) __afl_ijon_bits[id] = val;        // real MAX reducer
 * 512 u64 slots, a dedicated region, no collisions, and no patching of the fuzzer. The pass is
 * enabled automatically because afl-cc scans this source for the literal `ijon_max(`
 * (src/afl-cc.c:3604), so no build flag beyond -DIJON_BUILD is required.
 *
 * CONSEQUENCE: no quantisation. The exact microsecond count is reported, so COST_SCALE,
 * COST_BASE and COST_BUCKETS are dead on this path -- and the AFL++ and FuzzFactory arms now use
 * IDENTICAL semantics (exact value + MAX reducer + dedicated region), which turns the
 * cross-engine arm into a clean ENGINE comparison rather than an encoding-equivalence check.
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
/* ARMS 3-6. The objective is NATIVE to the engine, so the harness reports NOTHING.
 *   PerfFuzz (Padhye et al., ISSTA'18) maximises per-edge EXECUTION COUNTS.
 *   SlowFuzz (Petsios et al., CCS'17) maximises EXECUTED INSTRUCTION COUNT.
 * Both derive the signal from their own instrumentation of the same sink code below, which is
 * why this lives in the SAME source file as the aflpp arms: the sink is byte-identical, so a
 * difference between arms is a difference between ENGINES and cannot be a harness artefact.
 *
 * report_cost() must stay a real (non-inlined-away) no-op rather than being #defined out: the
 * call sites double as the control-flow that marks "we got this far", and deleting them would
 * change the edge profile PerfFuzz is measuring. */
#define VALID_FAIL() ((void) 0)
static void report_cost(unsigned long usec) { (void) usec; }

#elif defined(FF_BUILD)
#include "waypoints.h"
FUZZFACTORY_DSF_NEW(__cpu_dsf, 1, FUZZFACTORY_REDUCER_MAX, 0);
#define REPORT_US(v) FUZZFACTORY_DSF_MAX(__cpu_dsf, 0, (uint32_t) (v))
/* Called directly rather than through fuzzfactory's ASSUME_OR_RETURN, whose fprintf on every
 * failure would be per-execution I/O on the common path -- most mutants here are malformed. */
#ifdef USE_VALID
extern void __afl_valid_assumption_failure(void);
#define VALID_FAIL() __afl_valid_assumption_failure()
#else
#define VALID_FAIL() ((void) 0)
#endif
static void report_cost(unsigned long usec) { REPORT_US(usec); }

#else
#define VALID_FAIL() ((void) 0)

/* LEGACY, DEFECTIVE -- see the collision measurement above. Retained so the old encoding can be
 * run as a control against IJON, not because it should be used. */
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

/* THE SINK, shared verbatim by every entry point.
 *
 * Extracted from main() 2026-09-16 so SlowFuzz (libFuzzer, LLVMFuzzerTestOneInput) can call the
 * SAME code the AFL-family arms call. Behaviour-preserving: main() below reads the file exactly
 * as before and hands the bytes straight here. Verify after any rebuild by diffing this binary's
 * behaviour against the pre-refactor one on the seed corpus. */
static int run_bytes(const uint8_t *buf, size_t n) {
    static char    expr[MAX_EXPR + 1];
    const char *docp; size_t doclen;
    unsigned long t0, t1;

    docp = (const char *) buf; doclen = n; expr[0] = '\0';

#ifdef BLOCK_DTD
    /* -DBLOCK_DTD: refuse any document carrying an internal DTD subset.
     *
     * WHY THIS ARM EXISTS. Wave 1's negative arms did NOT find nothing -- every one of them
     * found inputs costing 3-15 s of CPU, and the c2 case was investigated: a 39,368 B document
     * with 37 parameter-entity declarations and 133 `%ref;` uses, whose PARENT cost 0.00 s.
     * That is DTD parameter-entity expansion (the billion-laughs family, CVE-2003-1564), not one
     * of our five sinks -- our sink counter read 0 at that input. So stock fuzzing DOES find an
     * algorithmic-complexity bug here, just the byte-reachable one.
     *
     * THE QUESTION THIS ANSWERS. Was that absorbing the search budget? Entity expansion is
     * reachable by small byte edits from a seed that already contains a DTD (17 of 169 seed-b
     * files do), whereas our five sinks need thousands of DISTINCT names. Blocking the DTD path
     * leaves the fuzzer nowhere to go EXCEPT our sinks.
     *   - still finds nothing -> the negative is stronger; entity expansion was not a distraction
     *   - now reaches a sink  -> the shallow bug was consuming the budget, which is a finding
     *                            about how AC fuzzers allocate effort
     *
     * A SEPARATE BINARY, NEVER A CHANGE TO THE EXISTING ONES. Editing the default harness would
     * invalidate wave 1's 20 h of data and wave 2's 24 h, since the target would no longer be the
     * same program.
     *
     * Detection is textual and deliberately crude: scan the prolog for "<!DOCTYPE" before
     * parsing. Using libxml2's own DTD callbacks would mean the parser has already begun, and
     * the cost we are excluding is incurred DURING that parse. Crude and early beats precise and
     * late here. Scanning only the first 4 KB bounds the cost: XML 1.0 requires the doctypedecl
     * to precede the root element, so a DOCTYPE beyond 4 KB of prolog is not well-formed anyway.
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

    /* THE CLOCK STARTS AFTER THE PARSE. This paper is about POST-PARSE algorithmic complexity:
     * every one of the five primitives is a superlinear loop in an operation an application
     * performs on an ALREADY-PARSED tree (C14N canonicalisation, XPath evaluation, attribute
     * rebuild, namespace reconciliation). Parsing is the attacker's cost of admission, not the
     * sink.
     *
     * THIS WAS PREVIOUSLY WRONG, AND IT COST A CAMPAIGN. With the clock spanning parse+sink, the
     * objective maximised whichever of the two was cheaper to grow -- and that was always the
     * parse. Measured on the 2026-09-11 run: every run's best input cost 1.0-4.8 s of CPU with
     * the sink contributing NOTHING measurable (parse alone 5.29 s vs parse+exclusive-C14N
     * 4.80 s, medians of 7). The fuzzer had spent the whole campaign climbing a parser path.
     * Excluding the parse is not a modelling choice informed by knowing where the cost sits; it
     * is the definition of the quantity this paper measures. */
    xmlDocPtr doc = xmlReadMemory(docp, (int) doclen, NULL, NULL,
                                  XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc != NULL) {
        /* REPEAT THE SINK, AND REPORT THE TOTAL.
         *
         * Moving the clock post-parse dropped the measured quantity from seconds to tens of
         * MICROseconds, and at that scale the measurement is dominated by timer and scheduler
         * noise. Measured on an IDLE core, the same input 30 times: c1 180-404 us (2.2x),
         * c2 33-94 us (2.9x), c7 554-2705 us (4.9x). IJON reduces with MAX, which is biased
         * upward and latches onto outliers -- so the objective retained whichever CHEAP input
         * happened to spike, and after an hour its picks were WORSE than the seed corpus on four
         * of five sinks (c1 0.18x, c3 0.20x, c5 0.37x, c7 0.70x of the seed best).
         *
         * Running the sink K times multiplies the signal by K while the per-execution noise stays
         * put. Validated on c1 with a cheap input and an expensive one, 25 repeats each:
         *   K=1  cheap 130-317 us   vs expensive 523-2790 us  -- ranges nearly touch, and the
         *                                                        2790 spike then blocks the rest
         *   K=8  cheap 1301-2016 us vs expensive 4047-9549 us -- DISJOINT, 2x gap
         * K=8 rather than 16: it separates just as cleanly and had the tighter noise ratio
         * (1.55x vs 2.41x on the cheap input).
         *
         * Throughput cost is far below Kx, because AFL's per-execution overhead is fixed: at
         * ~950 exec/s the sink was only ~0.25 ms of a ~1.05 ms execution.
         *
         * ADAPTIVE, AND IT REPORTS THE MEAN. A fixed 8x multiplies the execution's cost by 8,
         * and `-t` bounds the WHOLE execution -- so a fixed count caps the largest sink cost the
         * objective can ever record at (timeout - parse) / 8, about 600 ms at -t 5000. Worse,
         * exceeding it is not a hang: the target is SIGKILLed before report_cost() runs, so the
         * objective never sees the input AT ALL (verified -- seeding afl-fuzz with a payload whose
         * 8x cost is 8.07 s gives "All test cases time out or crash, giving up!" and 0 ijon_max
         * slots). That ceiling is ~1/10th of a working payload.
         *
         * So the repeat count adapts: keep going until SINK_REPEAT reps OR the CPU budget is
         * spent, whichever comes first.
         *
         * AND REPORT THE MEAN, NOT THE TOTAL. Reporting the total looks simpler but is wrong: for
         * every T between BUDGET/SINK_REPEAT and BUDGET the loop stops as soon as the budget is
         * spent, so the total is ~BUDGET regardless of T. That is a FLAT PLATEAU across exactly
         * the interesting range, and a MAX objective cannot climb a plateau. The mean is ~T for
         * every input, strictly monotone, with no plateau -- and it removes the "divide by
         * SINK_REPEAT" caveat on every absolute figure.
         *
         * Cheap inputs still get the full SINK_REPEAT reps, which is the whole point of the
         * repeat: it averages down the timer noise (same input measured 2.2-4.9x apart on an idle
         * core) that made IJON's MAX reducer latch onto spikes. Expensive inputs get 1-2 reps,
         * where averaging does not matter because their relative noise is already small. */
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
        /* C5, attribute flood -- THE DOM PATH, because on libxml2 2.15 that is the only path left.
         * Measured on the real thing with a 4,000-attribute element: 0 tail-walk iterations after
         * the parse, 0 after a deep copy (xmlDocCopyNode), and 7,994,001 after rebuilding the
         * attributes with xmlNewProp. The parser stopped reaching the quadratic when
         * xmlSAX2StartElementNs began linking each attribute at the tail in O(1)
         * (SAX2.c:2374, "link at the end to preserve order").
         *
         * Rebuilding an element's attributes one at a time is what an SP does when it normalises
         * or re-serialises an assertion subtree before checking the signature, which is the
         * reachability story the C5 disclosure documents. Every element is walked, not just the
         * root, so the fuzzer is free to put the flood at any depth. */
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
                /* iterative pre-order walk; no recursion, so a deep tree cannot blow the stack */
                /* DESCEND ONLY INTO ELEMENTS. libxml2 links an XML_ENTITY_REF_NODE's children
                 * to the entity's replacement tree, and that tree can itself contain entity
                 * references. Descending into them makes this walk UNBOUNDED: an 8 KB seed
                 * (`<!ENTITY WhatHeSaid "...&very_big_entity_name...;">`, body `<doc>&WhatHeSaid;</doc>`)
                 * drove it to 20,000,000 visited nodes / 4,000,001 entity-ref nodes without
                 * terminating, and burned the full 1800 s deep-measurement budget while reporting
                 * ZERO tail-walk iterations. That is entity-expansion cost, not C5. */
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
        /* Teardown is outside the measured window: freeing the tree is proportional to its size
         * and would add a term that grows with input length on EVERY input, flattening the
         * contrast between a sink that fired and one that did not. */
        xmlFreeDoc(doc);
    } else {
        /* THE site that matters for the validity domain. An unparseable document is by far the
         * most common outcome of byte-level mutation on XML, and it is the failure `valid` is
         * meant to push the search away from. Without this call the domain would have almost
         * nothing to reward and the arm would be vacuous. */
        VALID_FAIL();
        report_cost(0);
    }
    return 0;
}

#ifdef SLOWFUZZ_BUILD
/* libFuzzer entry point (arms 5-6). The parser is initialised once, not per execution: libFuzzer
 * is persistent, so doing it per call would add a fixed cost to every input and dilute the very
 * signal SlowFuzz is maximising. Inputs above CPU_MAX_INPUT are dropped rather than truncated --
 * truncating would hand the sink a half document whose cost is unrelated to the input. */
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
