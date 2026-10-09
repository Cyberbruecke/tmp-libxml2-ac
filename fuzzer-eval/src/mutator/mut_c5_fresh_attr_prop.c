/* mut_c5_fresh_attr_prop.c: per-sink operator for FlAttr (the Informed
 * configuration), an upper bound built from the analysis of the sink.
 *
 * The cost is the tail walk in xmlNewPropInternal: adding the i-th attribute walks
 * the i-1 already present. Reaching it needs distinct attribute names, since a
 * duplicate is not well-formed, and needs them concentrated on one element, since
 * the cost is per element. The operator splices fresh a<N> attributes into the
 * first start-tag.
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
    char *lt = memchr(hay, '<', buf_size);            /* first start-tag */
    if (!lt) return buf_size;

    /* Insert right after the element name, so every attribute lands on the same
     * element. */
    char *nm = lt + 1;
    while (nm < hay + buf_size && *nm != ' ' && *nm != '>' && *nm != '/') nm++;
    if (nm >= hay + buf_size) return buf_size;

    size_t at = (size_t) (nm - hay);
    int k = prop_batch(hay, buf_size, "=\"\"", 3, 64 + (rand() % 512));

    /* Reserve room for the rest of the document before adding items, so the
     * output is never cut off mid-tag when it reaches max_size. */
    size_t tail_len = buf_size - at;
    size_t o = at;
    memcpy(d->out, hay, at);
    for (int i = 0; i < k; i++) {
        int n = snprintf((char *) d->out + o, MAX_OUT - o, " a%lu=\"\"", d->ctr++);
        if (n <= 0 || o + (size_t) n + tail_len >= max_size) break;
        o += (size_t) n;
    }
    size_t rest = buf_size - at;
    if (o + rest > max_size) rest = (max_size > o) ? max_size - o : 0;
    memcpy(d->out + o, hay + at, rest);
    o += rest;

    *out_buf = d->out;
    return o;
}

void afl_custom_deinit(void *data) {
    st_t *d = (st_t *) data;
    if (d) { free(d->out); free(d); }
}
