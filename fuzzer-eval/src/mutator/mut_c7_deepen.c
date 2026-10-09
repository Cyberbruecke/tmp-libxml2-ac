/* mut_c7_deepen.c: per-sink operator for Wreckoncile (the Informed configuration),
 * an upper bound built from the analysis of the sink.
 *
 * xmlReconciliateNs costs O(D^3 * W^2) and is driven by depth D. The operator wraps
 * the document body in k new levels. Each level redeclares W prefixes with fresh
 * URIs and references them, because reconciliation does work only for prefixes that
 * nodes use and whose bindings differ between levels; redundant or unreferenced
 * declarations are dropped. The open and close tags are inserted as a pair, so the
 * document stays balanced.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_OUT (16 * 1024 * 1024)
#define MAX_DEPTH 250          /* libxml2 rejects deeper nesting; past this, widen instead */

typedef struct { uint8_t *out; unsigned long ctr; } st_t;

void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    st_t *d = calloc(1, sizeof(st_t));
    if (!d) return NULL;
    d->out = malloc(MAX_OUT);
    if (!d->out) { free(d); return NULL; }
    d->ctr = 1;
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

    /* Body = between the end of the root's start-tag and the start of its end-tag. Wrapping
     * exactly that keeps the result balanced no matter what the body contains. */
    char *gt = memchr(hay, '>', buf_size);
    if (!gt) return buf_size;
    size_t open_at = (size_t) ((gt + 1) - hay);

    char *close_at_p = memrchr(hay, '<', buf_size);
    size_t close_at;
    if (!close_at_p || (size_t) (close_at_p - hay) <= open_at) {
        /* No body to wrap (for example `<a/>`): emit a root with a body, so later
         * calls can deepen it. */
        size_t g = (size_t) snprintf((char *) d->out, MAX_OUT, "<r>X</r>");
        *out_buf = d->out;
        return g;
    }
    close_at = (size_t) (close_at_p - hay);

    int k = 8 + (rand() % 56);
    int w = 4 + (rand() % 28);          /* prefixes re-declared per level (the W axis) */

    size_t o = open_at;
    memcpy(d->out, hay, open_at);

    /* k opening levels, each with fresh URIs and matching references. */
    for (int i = 0; i < k && i < MAX_DEPTH; i++) {
        int n = snprintf((char *) d->out + o, MAX_OUT - o, "<q:e");
        if (n <= 0 || o + (size_t) n >= max_size) { k = i; break; }
        o += (size_t) n;
        for (int j = 0; j < w; j++) {
            unsigned long u = d->ctr++;
            n = snprintf((char *) d->out + o, MAX_OUT - o,
                         " xmlns:q%d=\"u:%lu\"", j, u);           /* fresh URI per level */
            if (n <= 0 || o + (size_t) n + 64 >= max_size) break;
            o += (size_t) n;
        }
        for (int j = 0; j < w; j++) {
            n = snprintf((char *) d->out + o, MAX_OUT - o, " q%d:a=\"\"", j); /* referenced */
            if (n <= 0 || o + (size_t) n + 64 >= max_size) break;
            o += (size_t) n;
        }
        n = snprintf((char *) d->out + o, MAX_OUT - o, " xmlns:q=\"u:%lu\">", d->ctr++);
        if (n <= 0 || o + (size_t) n >= max_size) { k = i; break; }
        o += (size_t) n;
    }

    /* original body */
    size_t body = close_at - open_at;
    if (o + body + (size_t) k * 8 > max_size) return buf_size;   /* no room to close: abort */
    memcpy(d->out + o, hay + open_at, body);
    o += body;

    /* k matching close tags */
    for (int i = 0; i < k; i++) {
        memcpy(d->out + o, "</q:e>", 6);
        o += 6;
    }

    size_t rest = buf_size - close_at;
    if (o + rest > max_size) return buf_size;
    memcpy(d->out + o, hay + close_at, rest);
    o += rest;

    *out_buf = d->out;
    return o;
}

void afl_custom_deinit(void *data) {
    st_t *d = (st_t *) data;
    if (d) { free(d->out); free(d); }
}
