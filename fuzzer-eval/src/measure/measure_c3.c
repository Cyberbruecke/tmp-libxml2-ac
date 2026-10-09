/* measure_c3.c: report XPlode sink iterations for one input file.
 *
 * Parses its input exactly as cputime_afl.c does with SINK_OP=4, so the fuzzer
 * and the scorer evaluate the same expression against the same document.
 *
 * Input format:
 *   line 1     XPath expression
 *   remainder  XML document
 * Output: "<iterations> <bytes> <parsed>"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

extern unsigned long xmlC3AxisIters;
static void q(void *c, const char *m, ...) { (void) c; (void) m; }

#define MAX_EXPR 4096

int main(int argc, char **argv) {
    static char buf[8 << 20];
    static char expr[MAX_EXPR + 1];
    FILE *f; size_t n, elen, dlen; char *nl; xmlDocPtr d = NULL;

    if (argc < 2) return 1;
    xmlInitParser(); xmlSetGenericErrorFunc(NULL, q);
    f = fopen(argv[1], "rb"); if (!f) return 1;
    n = fread(buf, 1, sizeof buf, f); fclose(f);

    xmlC3AxisIters = 0;

    nl = memchr(buf, '\n', n);
    if (!nl) { printf("0 %zu 0\n", n); return 0; }
    elen = (size_t) (nl - buf);
    if (elen == 0 || elen > MAX_EXPR) { printf("0 %zu 0\n", n); return 0; }
    memcpy(expr, buf, elen); expr[elen] = '\0';
    if (strlen(expr) != elen) { printf("0 %zu 0\n", n); return 0; }
    dlen = n - elen - 1;
    if (dlen == 0) { printf("0 %zu 0\n", n); return 0; }

    d = xmlReadMemory(nl + 1, (int) dlen, NULL, NULL,
                      XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (d) {
        xmlXPathContextPtr c = xmlXPathNewContext(d);
        if (c) {
            xmlXPathObjectPtr o = xmlXPathEvalExpression((const xmlChar *) expr, c);
            if (o) xmlXPathFreeObject(o);
            xmlXPathFreeContext(c);
        }
    }
    printf("%lu %zu %d\n", xmlC3AxisIters, n, d ? 1 : 0);
    if (d) xmlFreeDoc(d);
    return 0;
}
