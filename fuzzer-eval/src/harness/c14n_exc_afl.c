/*
 * c14n_exc_afl.c: AFL++ driver for C1 (exclusive C14N) with an ALGORITHMIC-COMPLEXITY
 * objective, in the style of SlowFuzz / PerfFuzz / FuzzFactory's `perf` waypoint domain.
 *
 * WHY WE ROLL OUR OWN OBJECTIVE
 * -----------------------------
 * FuzzFactory's LLVM passes use ModulePass / legacy::PassManagerBase / RegisterStandardPasses,
 * all removed in LLVM 17, so they do not build on a current toolchain. Rather than port them,
 * we reproduce the *idea* — a "waypoint": save an input if it makes progress on a
 * domain-specific measure, not only on code coverage.
 *
 * HOW THE WAYPOINT IS ENCODED
 * ---------------------------
 * AFL saves an input when it sets a previously-unseen byte in the coverage bitmap. So we map
 * the COST onto its own private region of the bitmap:
 *
 *      bucket = floor(log2(scan iterations))       cost -> a small integer
 *      __afl_area_ptr[COST_BASE + bucket] = 0xFF   reaching a higher bucket == "new coverage"
 *
 * An input that pushes the sink into a higher cost bucket therefore looks like a coverage
 * discovery and is kept for further mutation. Log2 bucketing makes the signal immune to the
 * timing noise that a wall-clock measure would suffer.
 *
 * WHY AN EXACT COUNTER RATHER THAN A TIMER
 * ----------------------------------------
 * `xmlC14NScanIters` counts iterations of the linear scan in xmlExcC14NVisibleNsStackFind —
 * the loop that IS the O(N^2). This is deliberately the most generous fitness signal we could
 * give the fuzzer: an exact, noise-free oracle pointing straight at the sink, strictly better
 * than PerfFuzz's per-edge counts. If the fuzzer still cannot produce the input, the failure
 * is unambiguously in MUTATION, not in scoring — which is exactly the hypothesis under test.
 *
 * Build:
 *   AFL_CC=gcc-13 afl-gcc-fast -O2 -I include -I . fuzz/c14n_exc_afl.c .libs/libxml2.a \
 *       -o c14n_exc_afl
 * Run:
 *   afl-fuzz -i seeds -o out -- ./c14n_exc_afl @@
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>
#include <libxml/xmlerror.h>

/* Provided by libxml2 (patched): exact iteration count of the C1 quadratic scan. */
extern unsigned long xmlC14NScanIters;

/* AFL++ coverage bitmap. */
extern uint8_t *__afl_area_ptr;

#ifndef MAP_SIZE
#define MAP_SIZE (1U << 16)
#endif
/* Private slice of the map for the cost waypoint: 64 buckets is log2 up to 2^64. */
/* COST_SCALE sub-steps per octave. Default 1 = plain floor(log2(x)), which requires cost to
 * DOUBLE before a new bucket fires. Measured consequence: with the operator as the only
 * generator (AFL_CUSTOM_MUTATOR_ONLY), 17 of 21 runs saturated permanently -- cost grows as
 * N^2 while the operator adds a FIXED <=64 items per call, so its relative contribution shrinks
 * until it can never double again, and nothing is ever saved. Build with -DCOST_SCALE=8 for
 * eighth-octave resolution (a 9% cost gain registers). */
#ifndef COST_SCALE
#define COST_SCALE 1
#endif
#define COST_BUCKETS (64 * COST_SCALE)
#define COST_BASE    (MAP_SIZE - COST_BUCKETS)

#define MAX_INPUT (4 * 1024 * 1024)

static void
silentError(void *ctx, const char *msg, ...)
{
    (void) ctx;
    (void) msg;
}

static void
report_cost(unsigned long iters)
{
    unsigned b = 0;

    if (__afl_area_ptr == NULL)
        return;
#if COST_SCALE == 1
    while (iters > 1 && b < COST_BUCKETS - 1) {
        iters >>= 1;
        b++;
    }
#else
    /* b = floor(log2(iters) * COST_SCALE), integer-only: count whole octaves, then refine
     * within the octave by comparing against COST_SCALE geometric sub-steps. */
    {
        unsigned oct = 0; unsigned long v = iters;
        while (v > 1) { v >>= 1; oct++; }
        unsigned long base = 1UL << oct;
        unsigned sub = 0;
        while (sub + 1 < COST_SCALE) {
            /* advance while iters >= base * 2^((sub+1)/COST_SCALE), via base*(sub+1)/SCALE
             * as a linear approximation inside the octave -- monotone, which is all we need */
            if (iters * COST_SCALE < base * (COST_SCALE + sub + 1)) break;
            sub++;
        }
        b = oct * COST_SCALE + sub;
        if (b >= COST_BUCKETS) b = COST_BUCKETS - 1;
    }
#endif
    /* Mark this bucket AND every lower one, so the map is monotone in cost: an input that
     * reaches bucket k subsumes k-1. Without this, oscillating costs would look like
     * repeated "new" coverage and pollute the queue. */
    for (unsigned i = 0; i <= b; i++)
        __afl_area_ptr[COST_BASE + i] = 0xFF;
}

int
main(int argc, char **argv)
{
    static uint8_t buf[MAX_INPUT];
    FILE *f;
    size_t n;
    xmlDocPtr doc;
    xmlChar *out = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, silentError);

    f = fopen(argv[1], "rb");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n == 0)
        return 0;

    xmlC14NScanIters = 0;

    doc = xmlReadMemory((const char *) buf, (int) n, NULL, NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        /* Not well-formed. Worth noting for the experiment: attribute-level cloning of an
         * xmlns declaration lands here, i.e. the input dies BEFORE the sink is reached. */
        report_cost(0);
        return 0;
    }

    xmlC14NDocDumpMemory(doc, NULL, XML_C14N_EXCLUSIVE_1_0, NULL, 0, &out);
    report_cost(xmlC14NScanIters);

    if (out != NULL)
        xmlFree(out);
    xmlFreeDoc(doc);
    return 0;
}
