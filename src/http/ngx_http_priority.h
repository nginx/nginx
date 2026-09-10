
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PRIORITY_H_INCLUDED_
#define _NGX_HTTP_PRIORITY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * RFC9218: Extensible Prioritization Scheme for HTTP
 *
 * Priority parameters:
 *   - urgency (u): Integer 0-7, lower is more urgent, default 3
 *   - incremental (i): Boolean, whether response can be processed
 *                      incrementally, default false
 */


#define NGX_HTTP_PRIORITY_DEFAULT_URGENCY     3
#define NGX_HTTP_PRIORITY_URGENCY_MIN         0
#define NGX_HTTP_PRIORITY_URGENCY_MAX         7

#define NGX_HTTP_PRIORITY_URGENCY_BACKGROUND  7


typedef struct {
    ngx_uint_t   urgency;          /* 0-7, default 3, lower = more urgent */
    unsigned     incremental:1;    /* default 0 (false) */
    unsigned     valid:1;          /* 1 if any parameter explicitly set */
    unsigned     urgency_set:1;    /* 1 if urgency explicitly set */
    unsigned     incremental_set:1;/* 1 if incremental explicitly set */
} ngx_http_priority_t;


/*
 * Initialize priority to default values (u=3, i=false)
 */
#define ngx_http_priority_init(p)                                             \
    do {                                                                      \
        (p)->urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;                     \
        (p)->incremental = 0;                                                 \
        (p)->valid = 0;                                                       \
        (p)->urgency_set = 0;                                                 \
        (p)->incremental_set = 0;                                             \
    } while (0)


/*
 * Per-stream priority state.  RFC 9218 priority is derived from two
 * independent inputs that can each change at any time: the client's request
 * (its Priority request header and any later PRIORITY_UPDATE frames) and the
 * server's response hint (an upstream Priority response header, RFC 9218
 * Section 8).  Keeping them separate lets the effective, scheduled priority
 * be recomputed by merging the two whenever either input changes -- so a
 * later client PRIORITY_UPDATE no longer discards a previously merged server
 * hint, and vice versa.  "effective" is the merged result actually used for
 * scheduling and pushed to the transport.
 */
typedef struct {
    ngx_http_priority_t   client;
    ngx_http_priority_t   server;
    ngx_http_priority_t   effective;
} ngx_http_priority_state_t;


/*
 * Initialize all three priority slots to defaults.
 */
#define ngx_http_priority_state_init(ps)                                      \
    do {                                                                      \
        ngx_http_priority_init(&(ps)->client);                               \
        ngx_http_priority_init(&(ps)->server);                               \
        ngx_http_priority_init(&(ps)->effective);                            \
    } while (0)


/*
 * Parse RFC9218 Priority header value (Structured Fields Dictionary).
 *
 * Format: "u=<0-7>, i" or "u=<0-7>" or "i" or empty
 * Examples:
 *   "u=0"       -> urgency=0, incremental=false
 *   "u=5, i"    -> urgency=5, incremental=true
 *   "i"         -> urgency=3 (default), incremental=true
 *   "u=3, i=?1" -> urgency=3, incremental=true
 *
 * Invalid or out-of-range values are ignored (defaults preserved).
 */
ngx_int_t ngx_http_priority_parse(ngx_str_t *value, ngx_http_priority_t *p);


/*
 * Merge server-provided priority with client priority per RFC9218 Section 8.
 * Server values override client values when present.
 */
void ngx_http_priority_merge(ngx_http_priority_t *result,
    ngx_http_priority_t *client, ngx_http_priority_t *server);


/*
 * Recompute ps->effective by merging the current client and server inputs.
 * Call after updating either ps->client or ps->server.
 */
void ngx_http_priority_state_update(ngx_http_priority_state_t *ps);


/*
 * Compare two priorities for scheduling.
 * Returns:
 *   < 0 if a has higher priority (lower urgency, should be sent first)
 *   > 0 if b has higher priority
 *   = 0 if equal priority
 */
ngx_int_t ngx_http_priority_compare(ngx_http_priority_t *a,
    ngx_http_priority_t *b);


/*
 * Format priority as a header value (RFC8941 Structured Fields Dictionary).
 * Returns pointer to the character after the last written byte.
 * Writes at most 6 bytes ("u=7, i"). Caller must NUL-terminate if needed.
 */
u_char *ngx_http_priority_format(u_char *buf, ngx_http_priority_t *p);


#endif /* _NGX_HTTP_PRIORITY_H_INCLUDED_ */
