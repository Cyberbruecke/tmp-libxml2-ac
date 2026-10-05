/* Report exact C5 attribute tail-walk iterations for a file — used to score fuzzer corpora.
 *
 * WAS PARSE-ONLY, AND THAT MADE IT ALWAYS-ZERO ON libxml2 2.15. The C5 quadratic lives in
 * xmlNewPropInternal's tail-walk. On 2.9.7 the PARSER reached it (SAX2.c calls xmlNewNsProp /
 * xmlNewNsPropEatName), so parsing alone scored the sink -- a 4,000-attribute flood read
 * 7,994,001 iterations. On 2.15 xmlSAX2StartElementNs links each attribute at the tail in O(1)
 * with its own `prev` pointer (SAX2.c:2374) and never calls xmlNewPropInternal, so the same file
 * reads 0. A parse-only scorer can therefore NEVER report a non-zero value on 2.15, which is
 * exactly what every c5 run showed.
 *
 * This now mirrors what cputime_afl.c's SINK_OP=1 harness does: walk every element and rebuild
 * its attributes through xmlNewProp, the surviving route to the tail-walk and the one an SP takes
 * when it normalises or re-serialises a subtree before checking a signature.
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
    xmlC5AttrWalkIters = 0;          /* zero AFTER the parse: score the sink, not the parse */
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
    printf("%lu %zu %d\n", xmlC5AttrWalkIters, n, d ? 1 : 0);
    if (d) xmlFreeDoc(d);
    return 0;
}
