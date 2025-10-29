
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define ngx_http_v3_table_entry_size(n, v) ((n)->len + (v)->len + 32)


static ngx_int_t ngx_http_v3_evict(ngx_connection_t *c, size_t target);
static void ngx_http_v3_unblock(void *data);
static ngx_int_t ngx_http_v3_new_entry(ngx_connection_t *c);


typedef struct {
    ngx_queue_t        queue;
    ngx_connection_t  *connection;
    ngx_uint_t        *nblocked;
} ngx_http_v3_block_t;


static ngx_http_v3_field_t  ngx_http_v3_static_table[] = {

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
          ngx_string("text/javascript") },
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
    ngx_str_t                     name;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    if (dynamic) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 ref insert dynamic[%ui] \"%V\"", index, value);

        h3c = ngx_http_v3_get_session(c);
        dt = &h3c->table;

        if (dt->base + dt->nelts <= index) {
            return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }

        index = dt->base + dt->nelts - 1 - index;

        if (ngx_http_v3_lookup(c, index, &name, NULL) != NGX_OK) {
            return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }

    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 ref insert static[%ui] \"%V\"", index, value);

        if (ngx_http_v3_lookup_static(c, index, &name, NULL) != NGX_OK) {
            return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }
    }

    return ngx_http_v3_insert(c, &name, value);
}


ngx_int_t
ngx_http_v3_insert(ngx_connection_t *c, ngx_str_t *name, ngx_str_t *value)
{
    u_char                       *p;
    size_t                        size;
    ngx_http_v3_field_t          *field;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    size = ngx_http_v3_table_entry_size(name, value);

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    if (size > dt->capacity) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "not enough dynamic table capacity");
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 insert [%ui] \"%V\":\"%V\", size:%uz",
                   dt->base + dt->nelts, name, value, size);

    p = ngx_alloc(sizeof(ngx_http_v3_field_t) + name->len + value->len,
                  c->log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    field = (ngx_http_v3_field_t *) p;

    field->name.data = p + sizeof(ngx_http_v3_field_t);
    field->name.len = name->len;
    field->value.data = ngx_cpymem(field->name.data, name->data, name->len);
    field->value.len = value->len;
    ngx_memcpy(field->value.data, value->data, value->len);

    dt->elts[dt->nelts++] = field;
    dt->size += size;

    dt->insert_count++;

    if (ngx_http_v3_evict(c, dt->capacity) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_post_event(&dt->send_insert_count, &ngx_posted_events);

    if (ngx_http_v3_new_entry(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_http_v3_inc_insert_count_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 inc insert count handler");

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->insert_count > dt->ack_insert_count) {
        if (ngx_http_v3_send_inc_insert_count(c,
                                       dt->insert_count - dt->ack_insert_count)
            != NGX_OK)
        {
            return;
        }

        dt->ack_insert_count = dt->insert_count;
    }
}


ngx_int_t
ngx_http_v3_set_capacity(ngx_connection_t *c, ngx_uint_t capacity)
{
    ngx_uint_t                     max, prev_max;
    ngx_http_v3_field_t          **elts;
    ngx_http_v3_session_t         *h3c;
    ngx_http_v3_srv_conf_t        *h3scf;
    ngx_http_v3_dynamic_table_t   *dt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 set capacity %ui", capacity);

    h3c = ngx_http_v3_get_session(c);
    h3scf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

    if (capacity > h3scf->max_table_capacity) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client exceeded http3_max_table_capacity limit");
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    if (ngx_http_v3_evict(c, capacity) != NGX_OK) {
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    dt = &h3c->table;
    max = capacity / 32;
    prev_max = dt->capacity / 32;

    if (max > prev_max) {
        elts = ngx_alloc((max + 1) * sizeof(void *), c->log);
        if (elts == NULL) {
            return NGX_ERROR;
        }

        if (dt->elts) {
            ngx_memcpy(elts, dt->elts, dt->nelts * sizeof(void *));
            ngx_free(dt->elts);
        }

        dt->elts = elts;
    }

    dt->capacity = capacity;

    return NGX_OK;
}


void
ngx_http_v3_cleanup_table(ngx_http_v3_session_t *h3c)
{
    ngx_uint_t                    n;
    ngx_http_v3_dynamic_table_t  *dt;

    dt = &h3c->table;

    if (dt->elts == NULL) {
        return;
    }

    for (n = 0; n < dt->nelts; n++) {
        ngx_free(dt->elts[n]);
    }

    ngx_free(dt->elts);
}


static ngx_int_t
ngx_http_v3_evict(ngx_connection_t *c, size_t target)
{
    size_t                        size;
    ngx_uint_t                    n;
    ngx_http_v3_field_t          *field;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;
    n = 0;

    while (dt->size > target) {
        field = dt->elts[n++];
        size = ngx_http_v3_table_entry_size(&field->name, &field->value);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 evict [%ui] \"%V\":\"%V\" size:%uz",
                       dt->base, &field->name, &field->value, size);

        ngx_free(field);
        dt->size -= size;
    }

    if (n) {
        dt->nelts -= n;
        dt->base += n;
        ngx_memmove(dt->elts, &dt->elts[n], dt->nelts * sizeof(void *));
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_duplicate(ngx_connection_t *c, ngx_uint_t index)
{
    ngx_str_t                     name, value;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 duplicate %ui", index);

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->base + dt->nelts <= index) {
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    index = dt->base + dt->nelts - 1 - index;

    if (ngx_http_v3_lookup(c, index, &name, &value) != NGX_OK) {
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    return ngx_http_v3_insert(c, &name, &value);
}


ngx_int_t
ngx_http_v3_ack_section(ngx_connection_t *c, ngx_uint_t stream_id)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 ack section %ui", stream_id);

    /* we do not use dynamic tables */

    return NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR;
}


ngx_int_t
ngx_http_v3_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 increment insert count %ui", inc);

    /* we do not use dynamic tables */

    return NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR;
}


ngx_int_t
ngx_http_v3_lookup_static(ngx_connection_t *c, ngx_uint_t index,
    ngx_str_t *name, ngx_str_t *value)
{
    ngx_uint_t            nelts;
    ngx_http_v3_field_t  *field;

    nelts = sizeof(ngx_http_v3_static_table)
            / sizeof(ngx_http_v3_static_table[0]);

    if (index >= nelts) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 static[%ui] lookup out of bounds: %ui",
                       index, nelts);
        return NGX_ERROR;
    }

    field = &ngx_http_v3_static_table[index];

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 static[%ui] lookup \"%V\":\"%V\"",
                   index, &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_lookup(ngx_connection_t *c, ngx_uint_t index, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_http_v3_field_t          *field;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    if (index < dt->base || index - dt->base >= dt->nelts) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 dynamic[%ui] lookup out of bounds: [%ui,%ui]",
                       index, dt->base, dt->base + dt->nelts);
        return NGX_ERROR;
    }

    field = dt->elts[index - dt->base];

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 dynamic[%ui] lookup \"%V\":\"%V\"",
                   index, &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_decode_insert_count(ngx_connection_t *c, ngx_uint_t *insert_count)
{
    ngx_uint_t                    max_entries, full_range, max_value,
                                  max_wrapped, req_insert_count;
    ngx_http_v3_srv_conf_t       *h3scf;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    /* QPACK 4.5.1.1. Required Insert Count */

    if (*insert_count == 0) {
        return NGX_OK;
    }

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    h3scf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

    max_entries = h3scf->max_table_capacity / 32;
    full_range = 2 * max_entries;

    if (*insert_count > full_range) {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    max_value = dt->base + dt->nelts + max_entries;
    max_wrapped = (max_value / full_range) * full_range;
    req_insert_count = max_wrapped + *insert_count - 1;

    if (req_insert_count > max_value) {
        if (req_insert_count <= full_range) {
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        req_insert_count -= full_range;
    }

    if (req_insert_count == 0) {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 decode insert_count %ui -> %ui",
                   *insert_count, req_insert_count);

    *insert_count = req_insert_count;

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_check_insert_count(ngx_connection_t *c, ngx_uint_t insert_count)
{
    size_t                        n;
    ngx_pool_cleanup_t           *cln;
    ngx_http_v3_block_t          *block;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_srv_conf_t       *h3scf;
    ngx_http_v3_dynamic_table_t  *dt;

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    n = dt->base + dt->nelts;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 check insert count req:%ui, have:%ui",
                   insert_count, n);

    if (n >= insert_count) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 block stream");

    block = NULL;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_v3_unblock) {
            block = cln->data;
            break;
        }
    }

    if (block == NULL) {
        cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_v3_block_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_http_v3_unblock;

        block = cln->data;
        block->queue.prev = NULL;
        block->connection = c;
        block->nblocked = &h3c->nblocked;
    }

    if (block->queue.prev == NULL) {
        h3scf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

        if (h3c->nblocked == h3scf->max_blocked_streams) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client exceeded http3_max_blocked_streams limit");

            ngx_http_v3_finalize_connection(c,
                                          NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED,
                                          "too many blocked streams");
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        h3c->nblocked++;
        ngx_queue_insert_tail(&h3c->blocked, &block->queue);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 blocked:%ui", h3c->nblocked);

    return NGX_BUSY;
}


void
ngx_http_v3_ack_insert_count(ngx_connection_t *c, uint64_t insert_count)
{
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_dynamic_table_t  *dt;

    h3c = ngx_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->ack_insert_count < insert_count) {
        dt->ack_insert_count = insert_count;
    }
}


static void
ngx_http_v3_unblock(void *data)
{
    ngx_http_v3_block_t  *block = data;

    if (block->queue.prev) {
        ngx_queue_remove(&block->queue);
        block->queue.prev = NULL;
        (*block->nblocked)--;
    }
}


static ngx_int_t
ngx_http_v3_new_entry(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_connection_t       *bc;
    ngx_http_v3_block_t    *block;
    ngx_http_v3_session_t  *h3c;

    h3c = ngx_http_v3_get_session(c);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 new dynamic entry, blocked:%ui", h3c->nblocked);

    while (!ngx_queue_empty(&h3c->blocked)) {
        q = ngx_queue_head(&h3c->blocked);
        block = (ngx_http_v3_block_t *) q;
        bc = block->connection;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, bc->log, 0, "http3 unblock stream");

        ngx_http_v3_unblock(block);
        ngx_post_event(bc->read, &ngx_posted_events);
    }

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

    case NGX_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param SETTINGS_MAX_FIELD_SECTION_SIZE:%uL",
                       value);
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
