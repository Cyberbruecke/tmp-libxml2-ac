/*
 * mut_c1_fresh_ns_prop.c: per-sink operator for exclusive C14N1D3 (the Informed
 * configuration).
 *
 * Like every per-sink operator it is built from the analysis of its sink, so it is
 * an upper bound on reachability, not evidence that fuzzing finds the sink unaided.
 *
 * It locates a namespace declaration and splices in copies with fresh, distinct
 * prefixes, each followed by a reference to it. Distinct prefixes matter because
 * libxml2 keeps one binding per prefix, so repeated declarations cost no more than
 * one, and cloning a declaration verbatim produces a duplicate attribute, which is
 * not well-formed. The reference matters because exclusive C14N renders only the
 * namespaces that are used.
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

typedef struct {
    unsigned int  seed;
    uint8_t      *out;
    unsigned long counter;   /* monotone, so names stay fresh across calls */
} fresh_t;

void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    fresh_t *d = calloc(1, sizeof(fresh_t));
    if (!d) return NULL;
    d->out = malloc(MAX_OUT);
    if (!d->out) { free(d); return NULL; }
    d->seed = seed;
    d->counter = 1;
    srand(seed);
    return d;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    fresh_t *d = (fresh_t *) data;
    (void) add_buf; (void) add_buf_size;

    *out_buf = buf;
    if (buf_size == 0 || buf_size > MAX_OUT / 2) return buf_size;

    char *hay = (char *) buf;

    /* Anchor on an existing namespace declaration and insert immediately after it, so the
     * insertion stays inside the same start-tag and the document remains well-formed. */
    char *hit = memmem(hay, buf_size, "xmlns:", 6);
    if (!hit) {
        /* No declaration to anchor on (for example `<a/>`): emit one, so later
         * calls have something to grow. */
        size_t g = 0;
        int n = snprintf((char *) d->out, MAX_OUT, "<z:e");
        if (n <= 0) return buf_size;
        g += (size_t) n;
        int k0 = 1 + (rand() % 64);
        for (int i = 0; i < k0; i++) {
            unsigned long idx = d->counter++;
            n = snprintf((char *) d->out + g, MAX_OUT - g,
                         " xmlns:z%lu=\"u:%lu\" z%lu:a=\"\"", idx, idx, idx);
            if (n <= 0 || g + (size_t) n + 8 >= max_size) break;
            g += (size_t) n;
        }
        n = snprintf((char *) d->out + g, MAX_OUT - g, "/>");
        if (n <= 0 || g + (size_t) n >= max_size) return buf_size;
        g += (size_t) n;
        *out_buf = d->out;
        return g;
    }

    char *q1 = memchr(hit, '"', (size_t) ((hay + buf_size) - hit));
    if (!q1) return buf_size;
    char *q2 = memchr(q1 + 1, '"', (size_t) ((hay + buf_size) - (q1 + 1)));
    if (!q2) return buf_size;

    size_t ins_at = (size_t) ((q2 + 1) - hay);
    int k = prop_batch(hay, buf_size, "xmlns:", 6, 1 + (rand() % 64));            /* a batch per call, not one at a time */

    /* Reserve room for the rest of the document before adding items, so the
     * output is never cut off mid-tag when it reaches max_size. */
    size_t tail_len = buf_size - ins_at;
    size_t o = ins_at;
    memcpy(d->out, hay, ins_at);

    for (int i = 0; i < k; i++) {
        unsigned long idx = d->counter++;
        int n = snprintf((char *) d->out + o, MAX_OUT - o,
                         " xmlns:z%lu=\"u:%lu\"", idx, idx);
        if (n <= 0 || o + (size_t) n + 32 + tail_len >= max_size) break;
        o += (size_t) n;

        /* The reference half of the pair. Without it exclusive C14N renders nothing. */
        n = snprintf((char *) d->out + o, MAX_OUT - o, " z%lu:a=\"\"", idx);
        if (n <= 0 || o + (size_t) n + tail_len >= max_size) break;
        o += (size_t) n;
    }

    size_t rest = buf_size - ins_at;
    if (o + rest > max_size) rest = (max_size > o) ? max_size - o : 0;
    memcpy(d->out + o, hay + ins_at, rest);
    o += rest;

    *out_buf = d->out;
    return o;
}

void afl_custom_deinit(void *data) {
    fresh_t *d = (fresh_t *) data;
    if (d) { free(d->out); free(d); }
}
