/*
 * c7_recon_afl.c: AFL++ driver for C7 (xmlReconciliateNs) with the algorithmic-complexity
 * waypoint objective. Structure is identical to c14n_exc_afl.c — see that file for the full
 * explanation of the waypoint encoding; only the sink invocation differs.
 *
 * RECONSTRUCTED 2026-09-01. The original source was never committed and existed only in /tmp,
 * which was cleared; only the compiled binary survived. Rebuilt from:
 *   - the sink invocation in measure_c7.c (recovered from /tmp the same day), and
 *   - the waypoint block in c14n_exc_afl.c.
 *
 * THE SINK. C7 is reached by COPYING a subtree into a different document and then reconciling
 * namespaces: xmlDocCopyNode + xmlAddChild + xmlReconciliateNs. That mirrors what a SAML IdP
 * does when it importNode()s an inbound AuthnRequest into its own session document. The
 * reconcile keeps a linear cache of namespace definitions and rescans it per node, so cost
 * grows with DEPTH x namespace width — unlike the flat C1/C2/C5 shapes.
 *
 * WHY THIS SINK NEEDS AFL_CUSTOM_MUTATOR_ONLY. Its cost axis is depth, which requires BALANCED
 * nesting. Havoc's byte edits unbalance the document faster than the operator can deepen it, so
 * the corpus drifts to small malformed inputs that never parse. Measured: 0 for 4.7 h with
 * havoc on, 5,495 in 25 s with it off. That flag is set per-sink in scripts/launch_p4.sh.
 *
 * Build:
 *   AFL_CC=gcc-13 afl-gcc-fast -O2 -I include -I . c7_recon_afl.c .libs/libxml2.a \
 *       -o c7_recon_afl -lz -lm -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

/* Provided by libxml2 (patched): iteration count of the reconcile cache scan in tree.c. */
extern unsigned long xmlC7ReconIters;

/* AFL++ coverage bitmap. */
extern uint8_t *__afl_area_ptr;

#ifndef MAP_SIZE
#define MAP_SIZE (1U << 16)
#endif
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

#define C7_MAX_INPUT (4 * 1024 * 1024)

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
    for (unsigned i = 0; i <= b; i++)
        __afl_area_ptr[COST_BASE + i] = 0xFF;
}

int
main(int argc, char **argv)
{
    static uint8_t buf[C7_MAX_INPUT];
    FILE *f;
    size_t n;
    xmlDocPtr doc, dst;
    xmlNodePtr root, host, copy;

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

    xmlC7ReconIters = 0;

    doc = xmlReadMemory((const char *) buf, (int) n, NULL, NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        report_cost(0);
        return 0;
    }

    /* Cross-document copy, then reconcile — the SAML IdP importNode() pattern. */
    root = xmlDocGetRootElement(doc);
    if (root != NULL) {
        dst = xmlNewDoc((const xmlChar *) "1.0");
        if (dst != NULL) {
            host = xmlNewNode(NULL, (const xmlChar *) "host");
            xmlDocSetRootElement(dst, host);
            copy = xmlDocCopyNode(root, dst, 1);
            if (copy != NULL) {
                xmlAddChild(host, copy);
                xmlReconciliateNs(dst, copy);
            }
            xmlFreeDoc(dst);
        }
    }
    report_cost(xmlC7ReconIters);

    xmlFreeDoc(doc);
    return 0;
}
