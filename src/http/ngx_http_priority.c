
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_priority.h>


/*
 * Parse RFC9218 Priority header value.
 *
 * The value is a Structured Fields Dictionary (RFC8941) containing:
 *   - u: Integer 0-7 (urgency)
 *   - i: Boolean (incremental)
 *
 * This is a simplified parser that handles the common formats:
 *   "u=5"
 *   "u=5, i"
 *   "u=5, i=?1"
 *   "i, u=3"
 *
 * Per RFC9218 Section 4, unknown parameters and out-of-range values
 * are ignored, and defaults are used instead.
 */


static ngx_int_t
ngx_http_priority_parse_int(u_char **pos, u_char *end, ngx_int_t *value)
{
    u_char      *p;
    ngx_int_t    n, cutoff, cutlim, d;
    ngx_uint_t   negative;

    p = *pos;
    negative = 0;

    if (p >= end) {
        return NGX_ERROR;
    }

    if (*p == '-') {
        negative = 1;
        p++;
    }

    if (p >= end || *p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    /*
     * Use pre-check to avoid signed overflow.
     * cutoff is the largest value before overflow on next digit.
     */
    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;

    n = 0;

    while (p < end && *p >= '0' && *p <= '9') {
        d = *p - '0';

        if (n > cutoff || (n == cutoff && d > cutlim)) {
            return NGX_ERROR;
        }

        n = n * 10 + d;
        p++;
    }

    *pos = p;
    *value = negative ? -n : n;

    return NGX_OK;
}


static void
ngx_http_priority_skip_ows(u_char **pos, u_char *end)
{
    u_char  *p;

    p = *pos;

    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    *pos = p;
}


/*
 * Advance to the next Structured Fields Dictionary member boundary, i.e.
 * the next top-level ',' or parameter-introducing ';'.
 *
 * Per RFC 8941, a member value or parameter value may be a String enclosed
 * in double quotes, within which ',' and ';' are literal data and a
 * backslash escapes the following character (only '"' and '\' may be
 * escaped).  Skipping on a raw ',' / ';' scan (ignoring quoting) would
 * split a value such as x="a,u=0" at the embedded comma and then misparse
 * the "u=0" tail as a top-level urgency member, applying a priority the
 * peer never signaled. Honour quoted strings here so member boundaries are
 * detected correctly.
 */
static void
ngx_http_priority_skip_member(u_char **pos, u_char *end)
{
    u_char      *p, ch;
    ngx_uint_t   quoted, escaped;

    p = *pos;
    quoted = 0;
    escaped = 0;

    while (p < end) {
        ch = *p;

        if (quoted) {

            if (escaped) {
                escaped = 0;

            } else if (ch == '\\') {
                escaped = 1;

            } else if (ch == '"') {
                quoted = 0;
            }

            p++;
            continue;
        }

        if (ch == '"') {
            quoted = 1;
            p++;
            continue;
        }

        if (ch == ',' || ch == ';') {
            break;
        }

        p++;
    }

    *pos = p;
}


ngx_int_t
ngx_http_priority_parse(ngx_str_t *value, ngx_http_priority_t *p)
{
    u_char     *pos, *end;
    ngx_int_t   n;

    /* Initialize with defaults */
    ngx_http_priority_init(p);

    if (value == NULL || value->len == 0) {
        return NGX_OK;
    }

    pos = value->data;
    end = pos + value->len;

    while (pos < end) {
        ngx_http_priority_skip_ows(&pos, end);

        if (pos >= end) {
            break;
        }

        /* Parse parameter key */
        if (pos + 1 < end && pos[1] == '=') {
            /* Key=Value format */

            if (*pos == 'u' || *pos == 'U') {
                /* urgency parameter: u=<integer> */
                pos += 2;  /* skip "u=" */

                if (ngx_http_priority_parse_int(&pos, end, &n) == NGX_OK) {
                    if (n >= NGX_HTTP_PRIORITY_URGENCY_MIN
                        && n <= NGX_HTTP_PRIORITY_URGENCY_MAX)
                    {
                        p->urgency = (ngx_uint_t) n;
                        p->urgency_set = 1;
                        p->valid = 1;
                    }
                    /* Out of range values are ignored per RFC9218 */
                }

                /* Skip any trailing junk to next delimiter */
                ngx_http_priority_skip_member(&pos, end);

            } else if (*pos == 'i' || *pos == 'I') {
                /* incremental parameter: i=?0 or i=?1 */
                pos += 2;  /* skip "i=" */

                if (pos < end && *pos == '?') {
                    pos++;

                    if (pos < end) {
                        if (*pos == '1') {
                            p->incremental = 1;
                            p->incremental_set = 1;
                            p->valid = 1;
                            pos++;
                        } else if (*pos == '0') {
                            p->incremental = 0;
                            p->incremental_set = 1;
                            p->valid = 1;
                            pos++;
                        }
                    }
                }

                /* Skip any trailing junk to next delimiter */
                ngx_http_priority_skip_member(&pos, end);

            } else {
                /* Unknown parameter - skip value */
                ngx_http_priority_skip_member(&pos, end);
            }

        } else if (*pos == 'i' || *pos == 'I') {
            /*
             * Bare "i" means incremental=true (Structured Fields Boolean)
             * This is the common shorthand form
             */
            pos++;

            /* Check it's not followed by alphanumeric (part of longer key) */
            if (pos >= end || *pos == ',' || *pos == ' ' || *pos == '\t'
                || *pos == ';')
            {
                p->incremental = 1;
                p->incremental_set = 1;
                p->valid = 1;
            } else {
                /* Part of a longer key - skip it */
                ngx_http_priority_skip_member(&pos, end);
            }

        } else {
            /* Unknown parameter - skip to next */
            ngx_http_priority_skip_member(&pos, end);
        }

        /* Skip to next parameter */
        ngx_http_priority_skip_ows(&pos, end);

        if (pos < end && (*pos == ',' || *pos == ';')) {
            pos++;
        }
    }

    return NGX_OK;
}


void
ngx_http_priority_merge(ngx_http_priority_t *result,
    ngx_http_priority_t *client, ngx_http_priority_t *server)
{
    /*
     * Per RFC9218 Section 8:
     * "The absence of a priority parameter in an HTTP response indicates
     * the server's disinterest in changing the client-provided value."
     *
     * Only override parameters that the server explicitly provided.
     */

    /* Start with client values */
    result->urgency = client->urgency;
    result->incremental = client->incremental;
    result->valid = client->valid;
    result->urgency_set = client->urgency_set;
    result->incremental_set = client->incremental_set;

    /* Override only parameters the server explicitly set */
    if (server->urgency_set) {
        result->urgency = server->urgency;
        result->urgency_set = 1;
        result->valid = 1;
    }

    if (server->incremental_set) {
        result->incremental = server->incremental;
        result->incremental_set = 1;
        result->valid = 1;
    }
}


void
ngx_http_priority_state_update(ngx_http_priority_state_t *ps)
{
    ngx_http_priority_merge(&ps->effective, &ps->client, &ps->server);
}


ngx_int_t
ngx_http_priority_compare(ngx_http_priority_t *a, ngx_http_priority_t *b)
{
    /*
     * RFC9218 priority comparison for scheduling.
     *
     * Returns:
     *   < 0 if a should be sent before b
     *   > 0 if b should be sent before a
     *   = 0 if equal priority (caller handles tie-breaking)
     *
     * Ordering rules:
     *   1. Lower urgency value = higher priority
     *   2. At same urgency: non-incremental before incremental
     *      (non-incremental resources should complete quickly)
     */

    /* Primary: compare urgency (lower = higher priority) */
    if (a->urgency < b->urgency) {
        return -1;
    }

    if (a->urgency > b->urgency) {
        return 1;
    }

    /*
     * Same urgency: non-incremental streams should be sent first
     * so they complete quickly. Incremental streams can wait and
     * be interleaved later.
     */
    if (!a->incremental && b->incremental) {
        return -1;  /* a (non-incr) before b (incr) */
    }

    if (a->incremental && !b->incremental) {
        return 1;   /* b (non-incr) before a (incr) */
    }

    return 0;  /* Same urgency and same incremental status */
}


u_char *
ngx_http_priority_format(u_char *buf, ngx_http_priority_t *p)
{
    /*
     * Format priority as RFC9218/RFC8941 Structured Fields Dictionary.
     *
     * Output formats:
     *   "u=0"     - urgency only (non-default)
     *   "u=0, i"  - urgency and incremental
     *   "i"       - incremental only (default urgency)
     *
     * If urgency is default (3) and incremental is false, returns empty.
     */

    u_char  *start = buf;

    if (p->urgency != NGX_HTTP_PRIORITY_DEFAULT_URGENCY) {
        buf = ngx_sprintf(buf, "u=%ui", p->urgency);
    }

    if (p->incremental) {
        if (buf != start) {
            *buf++ = ',';
            *buf++ = ' ';
        }
        *buf++ = 'i';
    }

    return buf;
}
