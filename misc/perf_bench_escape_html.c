#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef unsigned char u_char;
typedef size_t ngx_uint_t;
typedef intptr_t ngx_int_t;

/* Dummy stubs for unused functions in ngx_string.c */
void *ngx_pnalloc(void *pool, size_t size) { (void)pool; return malloc(size); }
void *ngx_alloc(size_t size, void *log) { (void)log; return malloc(size); }
void ngx_free(void *p) { free(p); }
void *ngx_cycle = NULL;

/* Real implementation prototype from ngx_string.c */
extern uintptr_t ngx_escape_html(u_char *dst, u_char *src, size_t size);

/* Baseline / previous implementation captured directly */
static uintptr_t
baseline_escape_html(u_char *dst, u_char *src, size_t size)
{
    u_char      ch;
    ngx_uint_t  len;

    if (dst == NULL) {
        len = 0;
        while (size) {
            switch (*src++) {
            case '<':
                len += sizeof("&lt;") - 2;
                break;
            case '>':
                len += sizeof("&gt;") - 2;
                break;
            case '&':
                len += sizeof("&amp;") - 2;
                break;
            case '"':
                len += sizeof("&quot;") - 2;
                break;
            default:
                break;
            }
            size--;
        }
        return (uintptr_t) len;
    }

    while (size) {
        ch = *src++;
        switch (ch) {
        case '<':
            *dst++ = '&'; *dst++ = 'l'; *dst++ = 't'; *dst++ = ';';
            break;
        case '>':
            *dst++ = '&'; *dst++ = 'g'; *dst++ = 't'; *dst++ = ';';
            break;
        case '&':
            *dst++ = '&'; *dst++ = 'a'; *dst++ = 'm'; *dst++ = 'p';
            *dst++ = ';';
            break;
        case '"':
            *dst++ = '&'; *dst++ = 'q'; *dst++ = 'u'; *dst++ = 'o';
            *dst++ = 't'; *dst++ = ';';
            break;
        default:
            *dst++ = ch;
            break;
        }
        size--;
    }
    return (uintptr_t) dst;
}

#define BUF_SIZE 1024
#define NUM_DOCS 100
#define ITERATIONS 200

static u_char test_docs[NUM_DOCS][BUF_SIZE];
static u_char dst_base[BUF_SIZE * 6];
static u_char dst_prod[BUF_SIZE * 6];

int main(void) {
    int d, iter, i;
    clock_t t0, t1;
    double t_base_calc, t_prod_calc;
    double t_base_dump, t_prod_dump;
    volatile uintptr_t sink = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* Generate representative HTML content across 100 documents:
     * ~98% normal alphanumeric/whitespace characters, ~2% HTML entities/tags
     */
    srand(42);
    for (d = 0; d < NUM_DOCS; d++) {
        for (i = 0; i < BUF_SIZE; i++) {
            test_docs[d][i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.,/=\n\t"[rand() % 73];
        }
        /* Inject representative HTML tags and entities */
        test_docs[d][10] = '<';
        test_docs[d][25] = '>';
        test_docs[d][100] = '&';
        test_docs[d][250] = '"';
        test_docs[d][500] = '<';
        test_docs[d][750] = '>';
        test_docs[d][900] = '&';
    }

    /* Strict Parity and Correctness Check */
    for (d = 0; d < NUM_DOCS; d++) {
        uintptr_t len_base = baseline_escape_html(NULL, test_docs[d], BUF_SIZE);
        uintptr_t len_prod = ngx_escape_html(NULL, test_docs[d], BUF_SIZE);
        if (len_base != len_prod) {
            fprintf(stderr, "ERROR: Length calculation mismatch at doc %d (base=%zu, prod=%zu)\n", d, len_base, len_prod);
            return 1;
        }

        uintptr_t res_base = baseline_escape_html(dst_base, test_docs[d], BUF_SIZE);
        uintptr_t res_prod = ngx_escape_html(dst_prod, test_docs[d], BUF_SIZE);
        size_t written_base = res_base - (uintptr_t)dst_base;
        size_t written_prod = res_prod - (uintptr_t)dst_prod;

        if (written_base != written_prod || memcmp(dst_base, dst_prod, written_base) != 0) {
            fprintf(stderr, "ERROR: Content mismatch at doc %d\n", d);
            return 1;
        }
    }

    /* Benchmark Phase 1: Escape Length Calculation (dst == NULL) */
    t0 = clock();
    for (iter = 0; iter < ITERATIONS; iter++) {
        for (d = 0; d < NUM_DOCS; d++) {
            sink += baseline_escape_html(NULL, test_docs[d], BUF_SIZE);
        }
    }
    t1 = clock();
    t_base_calc = (double)(t1 - t0) / CLOCKS_PER_SEC;

    t0 = clock();
    for (iter = 0; iter < ITERATIONS; iter++) {
        for (d = 0; d < NUM_DOCS; d++) {
            sink += ngx_escape_html(NULL, test_docs[d], BUF_SIZE);
        }
    }
    t1 = clock();
    t_prod_calc = (double)(t1 - t0) / CLOCKS_PER_SEC;

    /* Benchmark Phase 2: Full HTML Escaping (dst != NULL) */
    t0 = clock();
    for (iter = 0; iter < ITERATIONS; iter++) {
        for (d = 0; d < NUM_DOCS; d++) {
            sink += baseline_escape_html(dst_base, test_docs[d], BUF_SIZE);
        }
    }
    t1 = clock();
    t_base_dump = (double)(t1 - t0) / CLOCKS_PER_SEC;

    t0 = clock();
    for (iter = 0; iter < ITERATIONS; iter++) {
        for (d = 0; d < NUM_DOCS; d++) {
            sink += ngx_escape_html(dst_prod, test_docs[d], BUF_SIZE);
        }
    }
    t1 = clock();
    t_prod_dump = (double)(t1 - t0) / CLOCKS_PER_SEC;

    printf("=== HTML ESCAPE BENCHMARK RESULTS ===\n");
    printf("Total Documents Processed: %d (%d docs x %d iterations)\n", NUM_DOCS * ITERATIONS, NUM_DOCS, ITERATIONS);
    printf("Phase 1 (Length Calculation - dst=NULL):\n");
    printf("  Baseline Time:   %.4f s\n", t_base_calc);
    printf("  Production Time: %.4f s\n", t_prod_calc);
    printf("Phase 2 (Content Escaping - dst!=NULL):\n");
    printf("  Baseline Time:   %.4f s\n", t_base_dump);
    printf("  Production Time: %.4f s\n", t_prod_dump);
    printf("Total Time:\n");
    printf("  Baseline Total:   %.4f s\n", t_base_calc + t_base_dump);
    printf("  Production Total: %.4f s\n", t_prod_calc + t_prod_dump);
    printf("Sink: %zu\n", (size_t)sink);

    return 0;
}
