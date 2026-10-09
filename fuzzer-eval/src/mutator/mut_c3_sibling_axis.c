/* mut_c3_sibling_axis.c: per-sink operator for XPlode (the Informed configuration).
 *
 * It encodes the answer and is an upper bound, there to show the sink is reachable
 * by search at all. It is not evidence that fuzzing finds XPlode unaided; the
 * generic suite is, and it draws uniformly over all thirteen XPath axes.
 *
 * It encodes two things from the analysis of the sink:
 *   1. The axis. The cost is in xmlXPathNextPrecedingSibling (xpath.c:6592), which
 *      re-walks the axis for each context node, so a sibling axis inside a predicate
 *      costs O(N^2) over N siblings. The other axes do not reach that loop.
 *   2. Siblings under one parent. The cost is per parent: N siblings under one parent
 *      cost N^2, spread across N parents they cost N.
 *
 * Input is the XPlode harness format, `expression \n document`. Inputs without a
 * newline are passed through unchanged.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_OUT (16 * 1024 * 1024)
#define SIB_TAG "s"

typedef struct { uint8_t *out; } st_t;

/* Predicate forms that reach xmlXPathNextPrecedingSibling; several, so the search
 * varies the shape, but each uses a sibling axis. */
static const char *const EXPRS[] = {
    "//" SIB_TAG "[count(preceding-sibling::" SIB_TAG ")>0]",
    "//" SIB_TAG "[preceding-sibling::" SIB_TAG "]",
    "//" SIB_TAG "[count(following-sibling::" SIB_TAG ")>0]",
    "//" SIB_TAG "[count(preceding-sibling::*)>0][count(following-sibling::*)>0]",
    "//" SIB_TAG "/preceding-sibling::" SIB_TAG "/following-sibling::" SIB_TAG,
};
#define N_EXPRS ((int) (sizeof EXPRS / sizeof EXPRS[0]))

void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    st_t *d = calloc(1, sizeof(st_t));
    if (!d) return NULL;
    d->out = malloc(MAX_OUT);
    if (!d->out) { free(d); return NULL; }
    srand(seed);
    return d;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
    st_t *d = (st_t *) data;
    (void) add_buf; (void) add_buf_size;

    *out_buf = buf;
    if (!buf_size || buf_size > MAX_OUT / 2) return buf_size;

    char *hay = (char *) buf;
    char *nl = memchr(hay, '\n', buf_size);
    if (!nl) return buf_size;                       /* not the split format: leave it */

    const char *doc = nl + 1;
    size_t doclen = buf_size - (size_t) (nl - hay) - 1;
    if (doclen == 0) return buf_size;

    /* Pass UTF-16 documents through unchanged: their NUL bytes make a byte scan for
     * '<' and '>' find false tag boundaries. Detected by a BOM or an early NUL. */
    {
        const unsigned char *u = (const unsigned char *) doc;
        size_t probe = doclen < 4 ? doclen : 4;
        if (doclen >= 2 && ((u[0] == 0xFF && u[1] == 0xFE) || (u[0] == 0xFE && u[1] == 0xFF)))
            return buf_size;
        for (size_t i = 0; i < probe; i++) if (u[i] == 0x00) return buf_size;
    }

    /* Insert the siblings right after the root start-tag, so they share one parent.
     * Skip the prolog first: the first '>' may close a declaration inside a DOCTYPE
     * internal subset rather than the root tag. */
    const char *p = doc, *end = doc + doclen, *gt = NULL;
    while (p < end) {
        const char *lt = memchr(p, '<', (size_t) (end - p));
        if (!lt) return buf_size;
        size_t avail = (size_t) (end - lt);
        if (avail >= 2 && lt[1] == '?') {                        /* <?pi ... ?> */
            const char *q = memmem(lt + 2, avail - 2, "?>", 2);
            if (!q) return buf_size;
            p = q + 2; continue;
        }
        if (avail >= 4 && lt[1] == '!' && lt[2] == '-' && lt[3] == '-') {   /* <!-- ... --> */
            const char *q = memmem(lt + 4, avail - 4, "-->", 3);
            if (!q) return buf_size;
            p = q + 3; continue;
        }
        if (avail >= 2 && lt[1] == '!') {                        /* <!DOCTYPE ...> or <![...]]> */
            const char *q = lt + 2; int depth = 0;
            while (q < end) {
                if (*q == '[') depth++;
                else if (*q == ']') { if (depth > 0) depth--; }
                else if (*q == '>' && depth == 0) break;
                q++;
            }
            if (q >= end) return buf_size;
            p = q + 1; continue;
        }
        gt = memchr(lt, '>', avail);                             /* the ROOT start-tag */
        if (!gt) return buf_size;
        if (gt > lt && gt[-1] == '/') return buf_size;           /* self-closing root */
        break;
    }
    if (!gt) return buf_size;
    size_t head = (size_t) (gt - doc) + 1;          /* bytes of doc up to and including '>' */

    const char *e = EXPRS[rand() % N_EXPRS];
    size_t elen = strlen(e);
    if (elen + 2 >= max_size) return buf_size;

    size_t o = 0;
    memcpy(d->out + o, e, elen); o += elen;
    d->out[o++] = '\n';
    memcpy(d->out + o, doc, head); o += head;

    int k = 256 + (rand() % 2048);
    for (int i = 0; i < k; i++) {
        static const char sib[] = "<" SIB_TAG "/>";
        if (o + sizeof sib - 1 >= max_size || o + sizeof sib - 1 >= MAX_OUT) break;
        memcpy(d->out + o, sib, sizeof sib - 1);
        o += sizeof sib - 1;
    }

    size_t rest = doclen - head;
    if (o + rest > max_size) rest = (max_size > o) ? max_size - o : 0;
    if (o + rest > MAX_OUT)  rest = (MAX_OUT  > o) ? MAX_OUT  - o : 0;
    memcpy(d->out + o, doc + head, rest); o += rest;

    *out_buf = d->out;
    return o;
}

void afl_custom_deinit(void *data) {
    st_t *d = (st_t *) data;
    if (d) { free(d->out); free(d); }
}
