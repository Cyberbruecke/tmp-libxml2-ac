/* measure_c2.c: report inclusive C14N1D3 scan iterations for one input file. */
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/c14n.h>
extern unsigned long xmlC14NIncScanIters;
static void q(void *c, const char *m, ...) { (void)c; (void)m; }
int main(int argc, char **argv) {
    static char buf[8<<20]; FILE *f; size_t n; xmlDocPtr d; xmlChar *o = NULL;
    xmlInitParser(); xmlSetGenericErrorFunc(NULL, q);
    f = fopen(argv[1], "rb"); if (!f) return 1;
    n = fread(buf, 1, sizeof(buf), f); fclose(f);
    xmlC14NIncScanIters = 0;
    d = xmlReadMemory(buf, (int)n, NULL, NULL, XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    if (d) { xmlC14NDocDumpMemory(d, NULL, XML_C14N_1_0, NULL, 0, &o);
             if (o) xmlFree(o); xmlFreeDoc(d); }
    printf("%lu %zu %d\n", xmlC14NIncScanIters, n, d ? 1 : 0);
    return 0;
}
