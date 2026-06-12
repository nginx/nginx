
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
    ngx_uint_t   urgency;       /* 0-7, default 3, lower = more urgent */
    unsigned     incremental:1; /* default 0 (false) */
    unsigned     valid:1;       /* 1 if explicitly set by client/server */
} ngx_http_priority_t;


/*
 * Initialize priority to default values (u=3, i=false)
 */
#define ngx_http_priority_init(p)                                             \
    do {                                                                      \
        (p)->urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;                     \
        (p)->incremental = 0;                                                 \
        (p)->valid = 0;                                                       \
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
 * Buffer should have at least 16 bytes capacity ("u=7, i" = 6 bytes max).
 */
u_char *ngx_http_priority_format(u_char *buf, ngx_http_priority_t *p);


#endif /* _NGX_HTTP_PRIORITY_H_INCLUDED_ */
