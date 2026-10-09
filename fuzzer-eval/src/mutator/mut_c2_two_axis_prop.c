/*
 * mut_c2_two_axis_prop.c: per-sink operator for inclusive C14N1D3 (the Informed
 * configuration), an upper bound built from the analysis of the sink.
 *
 * Inclusive C14N costs O(K * N^2) for K descendant elements and N in-scope
 * namespaces. The operator grows both axes, chosen per call:
 *   (a) fresh namespace declarations on the apex element, growing N
 *   (b) <c/> children under it, growing K
 * Namespaces are weighted 2:1, since each adds cost across all K descendants.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_OUT (16 * 1024 * 1024)


/* Batch size proportional to what is already present, so each call grows the cost
 * by a constant ratio. A fixed batch gives a shrinking relative gain against a
 * superlinear cost. */
static int prop_batch(const char *hay, size_t n, const char *needle, size_t nl, int floor_k) {
    int count = 0;
    const char *p = hay, *e = hay + n;
    while (p < e) {
        const char *h = (const char *) memmem(p, (size_t) (e - p), needle, nl);
        if (!h) break;
        count++; p = h + nl;
        if (count > 100000) break;
    }
    int k = count / 4;
    if (k < floor_k) k = floor_k;
    if (k > 4096) k = 4096;
    return k;
}

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

    /* Nothing to anchor on: emit a minimal apex element to grow. */
    char *apex = memmem(hay, buf_size, "xmlns:", 6);
    char *last = memrchr(hay, '<', buf_size);
    if (!apex && (!last || last == hay)) {
        size_t g = 0; int n;
        n = snprintf((char *) d->out, MAX_OUT, "<n0:e xmlns:n0=\"u:0\"");
        if (n <= 0) return buf_size;
        g += (size_t) n;
        n = snprintf((char *) d->out + g, MAX_OUT - g, ">");
        g += (size_t) n;
        for (int i = 0; i < 128 && g + 16 < max_size; i++) { memcpy(d->out + g, "<c/>", 4); g += 4; }
        n = snprintf((char *) d->out + g, MAX_OUT - g, "</n0:e>");
        if (n <= 0 || g + (size_t) n >= max_size) return buf_size;
        g += (size_t) n;
        *out_buf = d->out; return g;
    }

    /* Axis (a): fresh namespaces on the apex. */
    if (apex && (rand() % 3) != 0) {
        char *q1 = memchr(apex, '"', (size_t) ((hay + buf_size) - apex));
        if (!q1) return buf_size;
        char *q2 = memchr(q1 + 1, '"', (size_t) ((hay + buf_size) - (q1 + 1)));
        if (!q2) return buf_size;
        size_t at = (size_t) ((q2 + 1) - hay);
        int k = prop_batch(hay, buf_size, "xmlns:", 6, 1 + (rand() % 32));
    /* Reserve room for the rest of the document before adding items, so the
     * output is never cut off mid-tag when it reaches max_size. */
        size_t tail_len = buf_size - at;
        size_t o = at;
        memcpy(d->out, hay, at);
        for (int i = 0; i < k; i++) {
            unsigned long idx = d->ctr++;
            int n = snprintf((char *) d->out + o, MAX_OUT - o, " xmlns:q%lu=\"u:%lu\"", idx, idx);
            if (n <= 0 || o + (size_t) n + 16 + tail_len >= max_size) break;
            o += (size_t) n;
        }
        size_t rest = buf_size - at;
        if (o + rest > max_size) rest = (max_size > o) ? max_size - o : 0;
        memcpy(d->out + o, hay + at, rest);
        o += rest;
        *out_buf = d->out; return o;
    }

    /* Axis (b): children, inserted before the last tag so they sit inside the apex
     * and inherit its in-scope namespaces. */
    if (!last || last == hay) return buf_size;
    size_t at = (size_t) (last - hay);
    int k = 64 + (rand() % 512);
    /* Reserve room for the rest of the document before adding items, so the
     * output is never cut off mid-tag when it reaches max_size. */
    size_t tail_len = buf_size - at;
    size_t o = at;
    memcpy(d->out, hay, at);
    for (int i = 0; i < k; i++) {
        if (o + 8 + tail_len >= max_size) break;
        memcpy(d->out + o, "<c/>", 4); o += 4;
    }
    size_t rest = buf_size - at;
    if (o + rest > max_size) rest = (max_size > o) ? max_size - o : 0;
    memcpy(d->out + o, hay + at, rest);
    o += rest;
    *out_buf = d->out; return o;
}

void afl_custom_deinit(void *data) {
    st_t *d = (st_t *) data;
    if (d) { free(d->out); free(d); }
}
