/* measure_c7.c: report Wreckoncile reconciliation iterations for one input file. */
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
extern unsigned long xmlC7ReconIters;
static void q(void *c, const char *m, ...) { (void)c; (void)m; }
int main(int argc, char **argv) {
    static char buf[8<<20]; FILE *f; size_t n; xmlDocPtr d;
    xmlInitParser(); xmlSetGenericErrorFunc(NULL, q);
    f = fopen(argv[1], "rb"); if (!f) return 1;
    n = fread(buf, 1, sizeof(buf), f); fclose(f);
    xmlC7ReconIters = 0;
    d = xmlReadMemory(buf, (int)n, NULL, NULL,
                      XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    if (d) { xmlNodePtr r = xmlDocGetRootElement(d);
      if (r) { xmlDocPtr dst = xmlNewDoc((const xmlChar*)"1.0");
        if (dst) { xmlNodePtr h = xmlNewNode(NULL,(const xmlChar*)"host");
          xmlDocSetRootElement(dst,h);
          xmlNodePtr cp = xmlDocCopyNode(r,dst,1);
          if (cp) { xmlAddChild(h,cp); xmlReconciliateNs(dst,cp); }
          xmlFreeDoc(dst); } } }
    printf("%lu %zu %d\n", xmlC7ReconIters, n, d ? 1 : 0);
    if (d) xmlFreeDoc(d);
    return 0;
}
