/* measure_c5.c: report FlAttr attribute tail-walk iterations for one input file.
 *
 * The quadratic is in xmlNewPropInternal's tail walk. In libxml2 2.15 the parser
 * no longer reaches it: xmlSAX2StartElementNs appends each attribute in O(1)
 * (SAX2.c:2374). So, like cputime_afl.c with SINK_OP=1, this rebuilds every
 * element's attributes through xmlNewProp after parsing, the path an SP takes
 * when it re-serialises a subtree.
 */
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
extern unsigned long xmlC5AttrWalkIters;
static void q(void *c, const char *m, ...) { (void)c; (void)m; }
int main(int argc, char **argv) {
    static char buf[8<<20]; FILE *f; size_t n; xmlDocPtr d;
    xmlInitParser(); xmlSetGenericErrorFunc(NULL, q);
    if (argc < 2) return 1;
    f = fopen(argv[1], "rb"); if (!f) return 1;
    n = fread(buf, 1, sizeof buf, f); fclose(f);
    d = xmlReadMemory(buf, (int)n, NULL, NULL,
                      XML_PARSE_NONET|XML_PARSE_NOERROR|XML_PARSE_NOWARNING);
    xmlC5AttrWalkIters = 0;          /* reset after the parse, so only the sink is counted */
    if (d) {
        xmlNodePtr cur = xmlDocGetRootElement(d);
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
            /* Descend only into elements. An entity reference's children are the
            * entity's replacement tree, which can contain further references, so
            * following them makes the walk unbounded and measures entity
            * expansion rather than the attribute sink. */
            if (cur->type == XML_ELEMENT_NODE && cur->children != NULL) { cur = cur->children; }
            else {
                while (cur != NULL && cur->next == NULL) cur = cur->parent;
                cur = (cur != NULL) ? cur->next : NULL;
            }
        }
    }
    printf("%lu %zu %d\n", xmlC5AttrWalkIters, n, d ? 1 : 0);
    if (d) xmlFreeDoc(d);
    return 0;
}
