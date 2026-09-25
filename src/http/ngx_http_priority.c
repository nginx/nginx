
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_PRIORITY_DEFAULT_URGENCY  3
#define NGX_HTTP_PRIORITY_URGENCY_MIN      0
#define NGX_HTTP_PRIORITY_URGENCY_MAX      7


/* bare item types we distinguish; others are parsed and discarded */

#define NGX_HTTP_PRIORITY_INTEGER  0
#define NGX_HTTP_PRIORITY_BOOLEAN  1
#define NGX_HTTP_PRIORITY_OTHER    2


/*
 * Parse limits.  RFC 8941 requires parsers to support at least these many
 * elements and characters; bounding the counts and individual item lengths
 * keeps parse time proportional to a well-formed field rather than to what a
 * peer chooses to send.
 */

#define NGX_HTTP_PRIORITY_MAX_MEMBERS      1024
#define NGX_HTTP_PRIORITY_MAX_INNER_ITEMS  256
#define NGX_HTTP_PRIORITY_MAX_PARAMS       256
#define NGX_HTTP_PRIORITY_MAX_STRING       1024
#define NGX_HTTP_PRIORITY_MAX_TOKEN        512
#define NGX_HTTP_PRIORITY_MAX_BINARY       21848  /* 16384 after decoding */


static ngx_int_t ngx_http_priority_parse_key(u_char **pos, u_char *end,
    ngx_str_t *key);
static ngx_int_t ngx_http_priority_parse_member(u_char **pos, u_char *end,
    ngx_str_t *key, ngx_int_t *type, ngx_int_t *value);
static ngx_int_t ngx_http_priority_parse_value(u_char **pos, u_char *end,
    ngx_int_t *type, ngx_int_t *value);
static ngx_int_t ngx_http_priority_parse_inner_list(u_char **pos, u_char *end);
static ngx_int_t ngx_http_priority_parse_bare_item(u_char **pos, u_char *end,
    ngx_int_t *type, ngx_int_t *value);
static ngx_int_t ngx_http_priority_parse_params(u_char **pos, u_char *end);
static ngx_int_t ngx_http_priority_parse_number(u_char **pos, u_char *end,
    ngx_int_t *type, ngx_int_t *value);
static ngx_int_t ngx_http_priority_parse_string(u_char **pos, u_char *end);
static ngx_int_t ngx_http_priority_parse_token(u_char **pos, u_char *end);
static ngx_int_t ngx_http_priority_parse_binary(u_char **pos, u_char *end);


void
ngx_http_priority_state_init(ngx_http_priority_state_t *ps)
{
    ngx_memzero(ps, sizeof(ngx_http_priority_state_t));

    ps->client.urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;
    ps->server.urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;
    ps->effective.urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;
}


/*
 * Parse an RFC 9218 Priority field, a Structured Fields Dictionary
 * (RFC 8941).  The dictionary is parsed strictly: any syntax error fails
 * the whole field (RFC 8941, Section 4.2), and only then are the RFC 9218
 * rules applied, ignoring unknown members, out-of-range urgency and members
 * of an unexpected type.  On error the field is treated as absent and p is
 * left at defaults; callers keep any previously signalled priority.
 */

ngx_int_t
ngx_http_priority_parse(ngx_str_t *field, ngx_http_priority_t *p)
{
    u_char      *last, *end;
    ngx_str_t    key;
    ngx_int_t    type, value;
    ngx_uint_t   members;

    p->urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;
    p->incremental = 0;
    p->urgency_set = 0;
    p->incremental_set = 0;

    if (field == NULL) {
        return NGX_OK;
    }

    /* RFC 8941, Section 4.2.2 */

    last = field->data;
    end = last + field->len;
    members = 0;

    /* Section 4.2, step 2: discard leading SP */

    while (last < end && *last == ' ') {
        last++;
    }

    while (last < end) {

        if (++members > NGX_HTTP_PRIORITY_MAX_MEMBERS) {
            return NGX_ERROR;
        }

        if (ngx_http_priority_parse_member(&last, end, &key, &type, &value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * RFC 8941, Section 4.2.2, step 2.4: a duplicate key replaces the
         * earlier member.  RFC 9218, Section 4: unknown members and members
         * of an unexpected type are ignored.  A repeated u or i therefore
         * resets to the default first, so a later out-of-range or
         * wrong-typed value leaves the parameter absent rather than keeping
         * the earlier one.
         */

        if (key.len == 1 && key.data[0] == 'u') {

            p->urgency = NGX_HTTP_PRIORITY_DEFAULT_URGENCY;
            p->urgency_set = 0;

            if (type == NGX_HTTP_PRIORITY_INTEGER
                && value >= NGX_HTTP_PRIORITY_URGENCY_MIN
                && value <= NGX_HTTP_PRIORITY_URGENCY_MAX)
            {
                p->urgency = (unsigned) value;
                p->urgency_set = 1;
            }

        } else if (key.len == 1 && key.data[0] == 'i') {

            p->incremental = 0;
            p->incremental_set = 0;

            if (type == NGX_HTTP_PRIORITY_BOOLEAN) {
                p->incremental = (unsigned) value;
                p->incremental_set = 1;
            }
        }

        while (last < end && (*last == ' ' || *last == '\t')) {
            last++;
        }

        if (last == end) {
            break;
        }

        if (*last++ != ',') {
            return NGX_ERROR;
        }

        while (last < end && (*last == ' ' || *last == '\t')) {
            last++;
        }

        /* trailing comma */

        if (last == end) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * Parse one dictionary member and its parameters (RFC 8941, Section 4.2.2).
 * A bare key (no "=") is a Boolean true; type/value then describe the
 * member's value so the caller can pick out u and i and ignore the rest.
 */

static ngx_int_t
ngx_http_priority_parse_member(u_char **pos, u_char *end, ngx_str_t *key,
    ngx_int_t *type, ngx_int_t *value)
{
    u_char  *last;

    last = *pos;

    if (ngx_http_priority_parse_key(&last, end, key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (last < end && *last == '=') {
        last++;

        if (ngx_http_priority_parse_value(&last, end, type, value) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        *type = NGX_HTTP_PRIORITY_BOOLEAN;
        *value = 1;

        if (ngx_http_priority_parse_params(&last, end) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.1.1: an Item or an Inner List, each with Parameters */

static ngx_int_t
ngx_http_priority_parse_value(u_char **pos, u_char *end, ngx_int_t *type,
    ngx_int_t *value)
{
    u_char  *last;

    last = *pos;

    if (last < end && *last == '(') {
        *type = NGX_HTTP_PRIORITY_OTHER;
        *value = 0;

        if (ngx_http_priority_parse_inner_list(&last, end) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        if (ngx_http_priority_parse_bare_item(&last, end, type, value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_http_priority_parse_params(&last, end) != NGX_OK) {
        return NGX_ERROR;
    }

    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.3.3 */

static ngx_int_t
ngx_http_priority_parse_key(u_char **pos, u_char *end, ngx_str_t *key)
{
    u_char  *last, ch;

    last = *pos;

    if (last == end) {
        return NGX_ERROR;
    }

    ch = *last;

    if (!((ch >= 'a' && ch <= 'z') || ch == '*')) {
        return NGX_ERROR;
    }

    key->data = last;

    do {
        last++;

        if (last == end) {
            break;
        }

        ch = *last;

    } while ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
             || ch == '_' || ch == '-' || ch == '.' || ch == '*');

    key->len = last - *pos;
    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.3.2 */

static ngx_int_t
ngx_http_priority_parse_params(u_char **pos, u_char *end)
{
    u_char     *last;
    ngx_str_t   key;
    ngx_int_t   type, value;
    ngx_uint_t  params;

    last = *pos;
    params = 0;

    while (last < end && *last == ';') {
        last++;

        if (++params > NGX_HTTP_PRIORITY_MAX_PARAMS) {
            return NGX_ERROR;
        }

        /* Section 4.2.3.2, step 2.3: discard leading SP */

        while (last < end && *last == ' ') {
            last++;
        }

        if (ngx_http_priority_parse_key(&last, end, &key) != NGX_OK) {
            return NGX_ERROR;
        }

        if (last < end && *last == '=') {
            last++;

            if (ngx_http_priority_parse_bare_item(&last, end, &type, &value)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.1.2: Inner List */

static ngx_int_t
ngx_http_priority_parse_inner_list(u_char **pos, u_char *end)
{
    u_char     *last;
    ngx_int_t   type, value;
    ngx_uint_t  items;

    last = *pos + 1;
    items = 0;

    for ( ;; ) {

        while (last < end && *last == ' ') {
            last++;
        }

        if (last < end && *last == ')') {
            *pos = last + 1;
            return NGX_OK;
        }

        if (++items > NGX_HTTP_PRIORITY_MAX_INNER_ITEMS) {
            return NGX_ERROR;
        }

        if (ngx_http_priority_parse_bare_item(&last, end, &type, &value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_http_priority_parse_params(&last, end) != NGX_OK) {
            return NGX_ERROR;
        }

        if (last == end) {
            return NGX_ERROR;
        }

        if (*last != ' ' && *last != ')') {
            return NGX_ERROR;
        }
    }
}


/* RFC 8941, Section 4.2.3.1 */

static ngx_int_t
ngx_http_priority_parse_bare_item(u_char **pos, u_char *end, ngx_int_t *type,
    ngx_int_t *value)
{
    u_char  ch;

    if (*pos == end) {
        return NGX_ERROR;
    }

    ch = **pos;

    if (ch == '-' || (ch >= '0' && ch <= '9')) {
        return ngx_http_priority_parse_number(pos, end, type, value);
    }

    if (ch == '?') {
        (*pos)++;

        if (*pos == end || (**pos != '0' && **pos != '1')) {
            return NGX_ERROR;
        }

        *type = NGX_HTTP_PRIORITY_BOOLEAN;
        *value = (**pos == '1');
        (*pos)++;

        return NGX_OK;
    }

    *type = NGX_HTTP_PRIORITY_OTHER;

    if (ch == '"') {
        return ngx_http_priority_parse_string(pos, end);
    }

    if (ch == ':') {
        return ngx_http_priority_parse_binary(pos, end);
    }

    if (((ch | 0x20) >= 'a' && (ch | 0x20) <= 'z') || ch == '*') {
        return ngx_http_priority_parse_token(pos, end);
    }

    return NGX_ERROR;
}


/* RFC 8941, Section 4.2.4: Integer or Decimal */

static ngx_int_t
ngx_http_priority_parse_number(u_char **pos, u_char *end, ngx_int_t *type,
    ngx_int_t *value)
{
    u_char     *last, *start;
    ngx_int_t   n;
    ngx_uint_t  neg, decimal, digits, frac;

    last = *pos;
    neg = 0;

    if (*last == '-') {
        neg = 1;
        last++;
    }

    start = last;
    decimal = 0;
    digits = 0;
    frac = 0;

    /* RFC 8941, Section 4.2.4 */

    while (last < end) {

        if (*last >= '0' && *last <= '9') {
            digits++;

            /* step 7.5: an Integer has at most 15 digits */

            if (!decimal && digits > 15) {
                return NGX_ERROR;
            }

            /* step 9.2: a Decimal has at most three fractional digits */

            if (decimal && ++frac > 3) {
                return NGX_ERROR;
            }

            last++;
            continue;
        }

        /* step 8: a single "." starts the fractional part of a Decimal */

        if (*last == '.' && !decimal) {

            /* step 8.1: at most 12 digits before the decimal point */

            if (digits == 0 || digits > 12) {
                return NGX_ERROR;
            }

            decimal = 1;
            last++;
            continue;
        }

        break;
    }

    if (digits == 0) {
        return NGX_ERROR;
    }

    if (decimal) {

        /* step 9.1: a Decimal must not end with "." */

        if (frac == 0) {
            return NGX_ERROR;
        }

        /* a valid Decimal, but not an Integer: parsed and discarded */

        *type = NGX_HTTP_PRIORITY_OTHER;
        *value = 0;
        *pos = last;
        return NGX_OK;
    }

    n = ngx_atoi(start, last - start);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    *type = NGX_HTTP_PRIORITY_INTEGER;
    *value = neg ? -n : n;
    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.5: String */

static ngx_int_t
ngx_http_priority_parse_string(u_char **pos, u_char *end)
{
    u_char      *last, ch;
    ngx_uint_t   len;

    last = *pos + 1;
    len = 0;

    while (last < end) {
        ch = *last++;

        if (ch == '\\') {
            if (last == end || (*last != '"' && *last != '\\')) {
                return NGX_ERROR;
            }
            last++;

            if (++len > NGX_HTTP_PRIORITY_MAX_STRING) {
                return NGX_ERROR;
            }

            continue;
        }

        if (ch == '"') {
            *pos = last;
            return NGX_OK;
        }

        if (ch < 0x20 || ch >= 0x7f) {
            return NGX_ERROR;
        }

        if (++len > NGX_HTTP_PRIORITY_MAX_STRING) {
            return NGX_ERROR;
        }
    }

    return NGX_ERROR;
}


/* RFC 8941, Section 4.2.6: Token */

static ngx_int_t
ngx_http_priority_parse_token(u_char **pos, u_char *end)
{
    u_char  *last, ch;

    last = *pos + 1;

    while (last < end) {
        ch = *last;

        if (ch == ':' || ch == '/'
            || ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '!' || ch == '#' || ch == '$' || ch == '%'
            || ch == '&' || ch == '\'' || ch == '*' || ch == '+'
            || ch == '-' || ch == '.' || ch == '^' || ch == '_'
            || ch == '`' || ch == '|' || ch == '~')
        {
            if ((ngx_uint_t) (last - *pos) >= NGX_HTTP_PRIORITY_MAX_TOKEN) {
                return NGX_ERROR;
            }

            last++;
            continue;
        }

        break;
    }

    *pos = last;

    return NGX_OK;
}


/* RFC 8941, Section 4.2.7: Byte Sequence */

static ngx_int_t
ngx_http_priority_parse_binary(u_char **pos, u_char *end)
{
    u_char      *last, ch;
    ngx_uint_t   len;

    last = *pos + 1;
    len = 0;

    while (last < end) {
        ch = *last++;

        if (ch == ':') {

            /* the content has to decode: 4n + 1 characters cannot */

            if (len % 4 == 1) {
                return NGX_ERROR;
            }

            *pos = last;
            return NGX_OK;
        }

        if (!(((ch | 0x20) >= 'a' && (ch | 0x20) <= 'z')
              || (ch >= '0' && ch <= '9')
              || ch == '+' || ch == '/' || ch == '='))
        {
            return NGX_ERROR;
        }

        if (++len > NGX_HTTP_PRIORITY_MAX_BINARY) {
            return NGX_ERROR;
        }
    }

    return NGX_ERROR;
}


void
ngx_http_priority_state_update(ngx_http_priority_state_t *ps)
{
    ngx_http_priority_t  *e;

    e = &ps->effective;
    *e = ps->client;

    if (ps->server.urgency_set) {
        e->urgency = ps->server.urgency;
        e->urgency_set = 1;
    }

    if (ps->server.incremental_set) {
        e->incremental = ps->server.incremental;
        e->incremental_set = 1;
    }
}
