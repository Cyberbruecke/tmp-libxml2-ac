/* recon_bench.c -- faithful measurement of the C7 sink: the importNode path
 * (xmlDocCopyNode deep + xmlReconciliateNs), which is what DOMDocument::importNode does,
 * NOT lxml's xmlDOMWrapAdoptNode. Reports copy time and reconcile time separately so we can
 * see which carries the O(). Usage: recon_bench <flood.xml> -> prints "copy_s reconcile_s". */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static double now(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }
int main(int argc, char** argv){
  xmlDocPtr doc = xmlReadFile(argv[1], NULL, XML_PARSE_NONET | XML_PARSE_HUGE);
  if(!doc){ fprintf(stderr,"parse fail\n"); return 1; }
  xmlNodePtr flood = xmlDocGetRootElement(doc)->children;
  while(flood && flood->type != XML_ELEMENT_NODE) flood = flood->next;
  xmlDocPtr dst = xmlNewDoc(BAD_CAST "1.0");
  double t0 = now();
  xmlNodePtr copy = xmlDocCopyNode(flood, dst, 1);   /* deep copy into another doc */
  double t1 = now();
  xmlDocSetRootElement(dst, copy);
  double t2 = now();
  xmlReconciliateNs(dst, copy);                       /* the named sink */
  double t3 = now();
  printf("%.6f %.6f\n", t1 - t0, t3 - t2);
  xmlFreeDoc(dst); xmlFreeDoc(doc);
  return 0;
}
