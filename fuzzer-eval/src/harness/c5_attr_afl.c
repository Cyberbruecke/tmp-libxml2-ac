/* C5 attribute flood via the PARSER entry point -- the same xmlReadMemory driver PerfFuzz
 * used on libxml2. Unlike C1/C2/C7 this sink IS reachable from the parser: the quadratic is
 * the tail-walk in xmlNewPropInternal that appends each attribute to a singly-linked list.
 * PerfFuzz's blocker here was not the entry point but its 500-byte input cap: attr_flood.xml
 * needs ~300 KB to burn ~10 s. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libxml/parser.h>
extern unsigned long xmlC5AttrWalkIters;
extern uint8_t *__afl_area_ptr;
#define MAP_SIZE (1U << 16)
/* COST_SCALE: sub-steps per octave. See c14n_exc_afl.c for why 1 (plain log2) saturates
 * operator-only runs -- cost must DOUBLE to register, and the operator's fixed batch cannot
 * double once the structure is large. -DCOST_SCALE=8 makes a 9% gain register. */
#ifndef COST_SCALE
#define COST_SCALE 1
#endif
#define COST_BUCKETS (64 * COST_SCALE)
#define COST_BASE (MAP_SIZE - COST_BUCKETS)
static void q(void *c, const char *m, ...) { (void)c; (void)m; }
static void report(unsigned long v) {
    unsigned b = 0; if (!__afl_area_ptr) return;
#if COST_SCALE == 1
    while (v > 1 && b < COST_BUCKETS - 1) { v >>= 1; b++; }
#else
    { unsigned long iters = v; unsigned oct = 0;
      while (v > 1) { v >>= 1; oct++; }
      unsigned long base = 1UL << oct; unsigned sub = 0;
      while (sub + 1 < COST_SCALE) {
          if (iters * COST_SCALE < base * (COST_SCALE + sub + 1)) break;
          sub++; }
      b = oct * COST_SCALE + sub;
      if (b >= COST_BUCKETS) b = COST_BUCKETS - 1; }
#endif
    for (unsigned i = 0; i <= b; i++) __afl_area_ptr[COST_BASE + i] = 0xFF;
}
int main(int argc, char **argv) {
    static uint8_t buf[8<<20]; FILE *f; size_t n; xmlDocPtr d;
    if (argc < 2) return 1;
    xmlInitParser(); xmlSetGenericErrorFunc(NULL, q);
    f = fopen(argv[1], "rb"); if (!f) return 0;
    n = fread(buf, 1, sizeof(buf), f); fclose(f);
    xmlC5AttrWalkIters = 0;
    d = xmlReadMemory((const char*)buf, (int)n, NULL, NULL,
                      XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    report(xmlC5AttrWalkIters);
    if (d) xmlFreeDoc(d);
    return 0;
}
