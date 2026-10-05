/* measure_c3.c — report C3 axis iterations for a file, offline (no waypoint, no AFL).
 *
 * MUST MIRROR c3_xpath_afl.c EXACTLY. When the harness took a hardcoded XPath and this tool
 * took the same one, they agreed by luck. Now that the expression comes from the input, any
 * divergence would mean the fuzzer optimises one thing while we report another -- and a seed
 * that cannot reach its own sink already cost us once (the c3 seed scored 0 for a day because
 * it used <c/> against an expression matching `a`).
 *
 * Input format, identical to the harness:
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
