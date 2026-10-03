/* cgbench.c -- isolate each libxml2 sink for callgrind. Collection is toggled ON only around
 * the operation of interest (run valgrind with --collect-atstart=no), so the profile is the
 * sink alone, not parse/setup.
 *   c5   N              : marshaller -- N x xmlSetNsProp on one element (attribute flood)
 *   c14n FILE           : inclusive C14N of the whole doc (C14N1D3)
 *   xpath FILE EXPR     : xmlXPathEvalExpression EXPR over the doc (XPlode)
 *   recon FILE          : xmlDocCopyNode(deep) + xmlReconciliateNs (Wreckoncile) */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <valgrind/callgrind.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char** argv){
  xmlInitParser();
  const char* mode = argv[1];
  if(!strcmp(mode,"c5")){
    int N = atoi(argv[2]);
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    xmlNodePtr e = xmlNewNode(NULL, BAD_CAST "e"); xmlDocSetRootElement(doc,e);
    xmlNsPtr ns = xmlNewNs(e, BAD_CAST "urn:x", BAD_CAST "p");
    CALLGRIND_TOGGLE_COLLECT;
    for(int i=0;i<N;i++){ char nm[24]; sprintf(nm,"a%d",i); xmlSetNsProp(e, ns, BAD_CAST nm, BAD_CAST ""); }
    CALLGRIND_TOGGLE_COLLECT;
  } else {
    xmlDocPtr doc = xmlReadFile(argv[2], NULL, XML_PARSE_NONET|XML_PARSE_HUGE);
    if(!strcmp(mode,"c14n")){
      xmlChar* out=NULL;
      CALLGRIND_TOGGLE_COLLECT;
      xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_0, NULL, 0, &out);
      CALLGRIND_TOGGLE_COLLECT;
    } else if(!strcmp(mode,"xpath")){
      xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
      CALLGRIND_TOGGLE_COLLECT;
      xmlXPathEvalExpression(BAD_CAST argv[3], ctx);
      CALLGRIND_TOGGLE_COLLECT;
    } else if(!strcmp(mode,"recon")){
      xmlNodePtr f = xmlDocGetRootElement(doc)->children;
      while(f && f->type!=XML_ELEMENT_NODE) f=f->next;
      xmlDocPtr dst=xmlNewDoc(BAD_CAST "1.0");
      xmlNodePtr copy=xmlDocCopyNode(f,dst,1); xmlDocSetRootElement(dst,copy);
      CALLGRIND_TOGGLE_COLLECT;
      xmlReconciliateNs(dst, copy);
      CALLGRIND_TOGGLE_COLLECT;
    }
  }
  return 0;
}
