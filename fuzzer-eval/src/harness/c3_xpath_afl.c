/*
 * c3_xpath_afl.c: AFL++ driver for C3 (XPath evaluation) with the algorithmic-complexity
 * waypoint objective. See c14n_exc_afl.c for the waypoint encoding; only the sink differs.
 *
 * REDESIGNED 2026-09-03 — THE FUZZER SUPPLIES THE EXPRESSION
 * ---------------------------------------------------------
 * The previous version hardcoded one expression:
 *
 *     "//a[count(preceding-sibling::a) > 0]"
 *
 * That is indefensible for this experiment. Nobody picks that expression by accident: it is
 * contrived to walk the preceding-sibling axis, which is precisely the quadratic we already
 * knew about. A harness that hands the fuzzer the answer cannot then be used as evidence that
 * the fuzzer found it. A supervisor review raised exactly this objection.
 *
 * It also mismeasured the generic operator suite: the suite grew elements named by mimicking
 * the document, so it rarely produced elements named `a`, and scored the seed value not because
 * XPath was hard but because the hardcoded expression could never match what it built.
 *
 * NOW: the input is  <xpath-expression> \n <xml-document>.  The fuzzer mutates BOTH. Nothing
 * about which axis is expensive is supplied; discovering that an axis such as
 * preceding-sibling, ancestor or descendant is superlinear is left to the search, which is the
 * question actually under test.
 *
 * WHY THIS IS ALSO MORE REALISTIC. It matches the real attack surface rather than a synthetic
 * one. XML Signature permits an XPath transform whose expression travels IN the signed
 * document, so a SAML SP or XMLDSig verifier evaluates an expression the attacker chose against
 * a document the attacker chose -- both halves untrusted, exactly as modelled here. The old
 * harness modelled an application that evaluates a fixed query, which is the less interesting
 * and less exposed case.
 *
 * INPUT FORMAT
 *   line 1        the XPath expression (capped at 4 KB; empty or absent -> nothing to evaluate)
 *   remainder     the XML document
 * A malformed split is scored 0, exactly like a malformed document, so the fuzzer is not
 * rewarded for degenerate inputs.
 *
 * Build:
 *   AFL_CC=gcc-13 afl-gcc-fast -O2 -I include -I . c3_xpath_afl.c .libs/libxml2.a \
 *       -o c3_xpath_afl -lz -lm -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlerror.h>

/* Provided by libxml2 (patched): iteration count of the axis walk in xpath.c. */
extern unsigned long xmlC3AxisIters;

/* AFL++ coverage bitmap. */
extern uint8_t *__afl_area_ptr;

#ifndef MAP_SIZE
#define MAP_SIZE (1U << 16)
#endif
/* COST_SCALE: sub-steps per octave. 1 = plain floor(log2(x)), which needs cost to DOUBLE
 * before a bucket fires and starves operator-only search. -DCOST_SCALE=8 registers a 9% gain. */
#ifndef COST_SCALE
#define COST_SCALE 1
#endif
#define COST_BUCKETS (64 * COST_SCALE)
#define COST_BASE    (MAP_SIZE - COST_BUCKETS)

#define C3_MAX_INPUT (4 * 1024 * 1024)
#define C3_MAX_EXPR  4096

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
    {
        unsigned oct = 0; unsigned long v = iters;
        while (v > 1) { v >>= 1; oct++; }
        unsigned long base = 1UL << oct;
        unsigned sub = 0;
        while (sub + 1 < COST_SCALE) {
            if (iters * COST_SCALE < base * (COST_SCALE + sub + 1)) break;
            sub++;
        }
        b = oct * COST_SCALE + sub;
        if (b >= COST_BUCKETS) b = COST_BUCKETS - 1;
    }
#endif
    /* Mark this bucket and every lower one, so the map is monotone in cost. */
    for (unsigned i = 0; i <= b; i++)
        __afl_area_ptr[COST_BASE + i] = 0xFF;
}

int
main(int argc, char **argv)
{
    static uint8_t buf[C3_MAX_INPUT];
    static char    expr[C3_MAX_EXPR + 1];
    FILE          *f;
    size_t         n, elen, dlen;
    uint8_t       *nl;
    xmlDocPtr      doc;
    xmlXPathContextPtr ctx;
    xmlXPathObjectPtr  obj;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>   (line 1 = XPath, rest = XML)\n", argv[0]);
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

    /* Split on the first newline: expression, then document. */
    nl = memchr(buf, '\n', n);
    if (nl == NULL) {
        /* No separator: nothing to evaluate. Scored like a malformed input. */
        report_cost(0);
        return 0;
    }
    elen = (size_t) (nl - buf);
    if (elen == 0 || elen > C3_MAX_EXPR) {
        report_cost(0);
        return 0;
    }
    memcpy(expr, buf, elen);
    expr[elen] = '\0';
    /* An embedded NUL would truncate the expression silently; treat it as malformed. */
    if (strlen(expr) != elen) {
        report_cost(0);
        return 0;
    }

    dlen = n - elen - 1;
    if (dlen == 0) {
        report_cost(0);
        return 0;
    }

    xmlC3AxisIters = 0;

    doc = xmlReadMemory((const char *) (nl + 1), (int) dlen, NULL, NULL,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        report_cost(0);
        return 0;
    }

    ctx = xmlXPathNewContext(doc);
    if (ctx != NULL) {
        /* The expression is attacker-supplied, exactly as in an XML Signature XPath transform.
         * A syntactically invalid expression simply returns NULL and scores 0. */
        obj = xmlXPathEvalExpression((const xmlChar *) expr, ctx);
        if (obj != NULL)
            xmlXPathFreeObject(obj);
        xmlXPathFreeContext(ctx);
    }
    report_cost(xmlC3AxisIters);

    xmlFreeDoc(doc);
    return 0;
}
