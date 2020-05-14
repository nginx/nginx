
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_array_t *ngx_http_v3_get_dynamic_table(ngx_connection_t *c);
static ngx_int_t ngx_http_v3_new_header(ngx_connection_t *c);


static ngx_http_v3_header_t  ngx_http_v3_static_table[] = {

    { ngx_string(":authority"),            ngx_string("") },
    { ngx_string(":path"),                 ngx_string("/") },
    { ngx_string("age"),                   ngx_string("0") },
    { ngx_string("content-disposition"),   ngx_string("") },
    { ngx_string("content-length"),        ngx_string("0") },
    { ngx_string("cookie"),                ngx_string("") },
    { ngx_string("date"),                  ngx_string("") },
    { ngx_string("etag"),                  ngx_string("") },
    { ngx_string("if-modified-since"),     ngx_string("") },
    { ngx_string("if-none-match"),         ngx_string("") },
    { ngx_string("last-modified"),         ngx_string("") },
    { ngx_string("link"),                  ngx_string("") },
    { ngx_string("location"),              ngx_string("") },
    { ngx_string("referer"),               ngx_string("") },
    { ngx_string("set-cookie"),            ngx_string("") },
    { ngx_string(":method"),               ngx_string("CONNECT") },
    { ngx_string(":method"),               ngx_string("DELETE") },
    { ngx_string(":method"),               ngx_string("GET") },
    { ngx_string(":method"),               ngx_string("HEAD") },
    { ngx_string(":method"),               ngx_string("OPTIONS") },
    { ngx_string(":method"),               ngx_string("POST") },
    { ngx_string(":method"),               ngx_string("PUT") },
    { ngx_string(":scheme"),               ngx_string("http") },
    { ngx_string(":scheme"),               ngx_string("https") },
    { ngx_string(":status"),               ngx_string("103") },
    { ngx_string(":status"),               ngx_string("200") },
    { ngx_string(":status"),               ngx_string("304") },
    { ngx_string(":status"),               ngx_string("404") },
    { ngx_string(":status"),               ngx_string("503") },
    { ngx_string("accept"),                ngx_string("*/*") },
    { ngx_string("accept"),
          ngx_string("application/dns-message") },
    { ngx_string("accept-encoding"),       ngx_string("gzip, deflate, br") },
    { ngx_string("accept-ranges"),         ngx_string("bytes") },
    { ngx_string("access-control-allow-headers"),
                                           ngx_string("cache-control") },
    { ngx_string("access-control-allow-headers"),
                                           ngx_string("content-type") },
    { ngx_string("access-control-allow-origin"),
                                           ngx_string("*") },
    { ngx_string("cache-control"),         ngx_string("max-age=0") },
    { ngx_string("cache-control"),         ngx_string("max-age=2592000") },
    { ngx_string("cache-control"),         ngx_string("max-age=604800") },
    { ngx_string("cache-control"),         ngx_string("no-cache") },
    { ngx_string("cache-control"),         ngx_string("no-store") },
    { ngx_string("cache-control"),
          ngx_string("public, max-age=31536000") },
    { ngx_string("content-encoding"),      ngx_string("br") },
    { ngx_string("content-encoding"),      ngx_string("gzip") },
    { ngx_string("content-type"),
          ngx_string("application/dns-message") },
    { ngx_string("content-type"),
          ngx_string("application/javascript") },
    { ngx_string("content-type"),          ngx_string("application/json") },
    { ngx_string("content-type"),
          ngx_string("application/x-www-form-urlencoded") },
    { ngx_string("content-type"),          ngx_string("image/gif") },
    { ngx_string("content-type"),          ngx_string("image/jpeg") },
    { ngx_string("content-type"),          ngx_string("image/png") },
    { ngx_string("content-type"),          ngx_string("text/css") },
    { ngx_string("content-type"),
          ngx_string("text/html;charset=utf-8") },
    { ngx_string("content-type"),          ngx_string("text/plain") },
    { ngx_string("content-type"),
          ngx_string("text/plain;charset=utf-8") },
    { ngx_string("range"),                 ngx_string("bytes=0-") },
    { ngx_string("strict-transport-security"),
                                           ngx_string("max-age=31536000") },
    { ngx_string("strict-transport-security"),
          ngx_string("max-age=31536000;includesubdomains") },
    { ngx_string("strict-transport-security"),
          ngx_string("max-age=31536000;includesubdomains;preload") },
    { ngx_string("vary"),                  ngx_string("accept-encoding") },
    { ngx_string("vary"),                  ngx_string("origin") },
    { ngx_string("x-content-type-options"),
                                           ngx_string("nosniff") },
    { ngx_string("x-xss-protection"),      ngx_string("1;mode=block") },
    { ngx_string(":status"),               ngx_string("100") },
    { ngx_string(":status"),               ngx_string("204") },
    { ngx_string(":status"),               ngx_string("206") },
    { ngx_string(":status"),               ngx_string("302") },
    { ngx_string(":status"),               ngx_string("400") },
    { ngx_string(":status"),               ngx_string("403") },
    { ngx_string(":status"),               ngx_string("421") },
    { ngx_string(":status"),               ngx_string("425") },
    { ngx_string(":status"),               ngx_string("500") },
    { ngx_string("accept-language"),       ngx_string("") },
    { ngx_string("access-control-allow-credentials"),
                                           ngx_string("FALSE") },
    { ngx_string("access-control-allow-credentials"),
                                           ngx_string("TRUE") },
    { ngx_string("access-control-allow-headers"),
                                           ngx_string("*") },
    { ngx_string("access-control-allow-methods"),
                                           ngx_string("get") },
    { ngx_string("access-control-allow-methods"),
                                           ngx_string("get, post, options") },
    { ngx_string("access-control-allow-methods"),
                                           ngx_string("options") },
    { ngx_string("access-control-expose-headers"),
                                           ngx_string("content-length") },
    { ngx_string("access-control-request-headers"),
                                           ngx_string("content-type") },
    { ngx_string("access-control-request-method"),
                                           ngx_string("get") },
    { ngx_string("access-control-request-method"),
                                           ngx_string("post") },
    { ngx_string("alt-svc"),               ngx_string("clear") },
    { ngx_string("authorization"),         ngx_string("") },
    { ngx_string("content-security-policy"),
          ngx_string("script-src 'none';object-src 'none';base-uri 'none'") },
    { ngx_string("early-data"),            ngx_string("1") },
    { ngx_string("expect-ct"),             ngx_string("") },
    { ngx_string("forwarded"),             ngx_string("") },
    { ngx_string("if-range"),              ngx_string("") },
    { ngx_string("origin"),                ngx_string("") },
    { ngx_string("purpose"),               ngx_string("prefetch") },
    { ngx_string("server"),                ngx_string("") },
    { ngx_string("timing-allow-origin"),   ngx_string("*") },
    { ngx_string("upgrade-insecure-requests"),
                                           ngx_string("1") },
    { ngx_string("user-agent"),            ngx_string("") },
    { ngx_string("x-forwarded-for"),       ngx_string("") },
    { ngx_string("x-frame-options"),       ngx_string("deny") },
    { ngx_string("x-frame-options"),       ngx_string("sameorigin") }
};


ngx_int_t
ngx_http_v3_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value)
{
    ngx_array_t           *dt;
    ngx_connection_t      *pc;
    ngx_http_v3_header_t  *ref, *h;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 ref insert %s[$ui] \"%V\"",
                   dynamic ? "dynamic" : "static", index, value);

    pc = c->qs->parent;

    ref = ngx_http_v3_lookup_table(c, dynamic, index);
    if (ref == NULL) {
        return NGX_ERROR;
    }

    dt = ngx_http_v3_get_dynamic_table(c);
    if (dt == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(dt);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->name = ref->name;

    h->value.data = ngx_pstrdup(pc->pool, value);
    if (h->value.data == NULL) {
        h->value.len = 0;
        return NGX_ERROR;
    }

    h->value.len = value->len;

    if (ngx_http_v3_new_header(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_array_t           *dt;
    ngx_connection_t      *pc;
    ngx_http_v3_header_t  *h;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 insert \"%V\":\"%V\"", name, value);

    pc = c->qs->parent;

    dt = ngx_http_v3_get_dynamic_table(c);
    if (dt == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(dt);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->name.data = ngx_pstrdup(pc->pool, name);
    if (h->name.data == NULL) {
        h->name.len = 0;
        h->value.len = 0;
        return NGX_ERROR;
    }

    h->name.len = name->len;

    h->value.data = ngx_pstrdup(pc->pool, value);
    if (h->value.data == NULL) {
        h->value.len = 0;
        return NGX_ERROR;
    }

    h->value.len = value->len;

    if (ngx_http_v3_new_header(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_set_capacity(ngx_connection_t *c, ngx_uint_t capacity)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 set capacity %ui", capacity);

    /* XXX ignore capacity */

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_duplicate(ngx_connection_t *c, ngx_uint_t index)
{
    ngx_array_t           *dt;
    ngx_http_v3_header_t  *ref, *h;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 duplicate %ui", index);

    ref = ngx_http_v3_lookup_table(c, 1, index);
    if (ref == NULL) {
        return NGX_ERROR;
    }

    dt = ngx_http_v3_get_dynamic_table(c);
    if (dt == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(dt);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = *ref;

    if (ngx_http_v3_new_header(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_ack_header(ngx_connection_t *c, ngx_uint_t stream_id)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 ack header %ui", stream_id);

    /* XXX */

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 cancel stream %ui", stream_id);

    /* XXX */

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 increment insert count %ui", inc);

    /* XXX */

    return NGX_OK;
}


static ngx_array_t *
ngx_http_v3_get_dynamic_table(ngx_connection_t *c)
{
    ngx_connection_t          *pc;
    ngx_http_v3_connection_t  *h3c;

    pc = c->qs->parent;
    h3c = pc->data;

    if (h3c->dynamic) {
        return h3c->dynamic;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 create dynamic table");

    h3c->dynamic = ngx_array_create(pc->pool, 1, sizeof(ngx_http_v3_header_t));

    return h3c->dynamic;
}


ngx_http_v3_header_t *
ngx_http_v3_lookup_table(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index)
{
    ngx_uint_t             nelts;
    ngx_array_t           *dt;
    ngx_http_v3_header_t  *table;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 lookup %s[%ui]",
                   dynamic ? "dynamic" : "static", index);

    if (dynamic) {
        dt = ngx_http_v3_get_dynamic_table(c);
        if (dt == NULL) {
            return NULL;
        }

        table = dt->elts;
        nelts = dt->nelts;

    } else {
        table = ngx_http_v3_static_table;
        nelts = sizeof(ngx_http_v3_static_table)
                / sizeof(ngx_http_v3_static_table[0]);
    }

    if (index >= nelts) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 lookup out of bounds: %ui", nelts);
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 lookup \"%V\":\"%V\"",
                   &table[index].name, &table[index].value);

    return &table[index];
}


ngx_int_t
ngx_http_v3_check_insert_count(ngx_connection_t *c, ngx_uint_t insert_count)
{
    size_t                     n;
    ngx_http_v3_connection_t  *h3c;

    h3c = c->qs->parent->data;
    n = h3c->dynamic ? h3c->dynamic->nelts : 0;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 check insert count %ui/%ui", insert_count, n);

    if (n < insert_count) {
        /* XXX how to get notified? */
        /* XXX wake all streams on any arrival to the encoder stream? */
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_new_header(ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 new dynamic header");

    /* XXX report all waiting streams of a new header */

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_set_param(ngx_connection_t *c, uint64_t id, uint64_t value)
{
    switch (id) {

    case NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param QPACK_MAX_TABLE_CAPACITY:%uL", value);
        break;

    case NGX_HTTP_V3_PARAM_MAX_HEADER_LIST_SIZE:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param SETTINGS_MAX_HEADER_LIST_SIZE:%uL", value);
        break;

    case NGX_HTTP_V3_PARAM_BLOCKED_STREAMS:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param QPACK_BLOCKED_STREAMS:%uL", value);
        break;

    default:

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param #%uL:%uL", id, value);
    }

    return NGX_OK;
}
