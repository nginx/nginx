
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_v3_process_request(ngx_event_t *rev);
static ngx_int_t ngx_http_v3_process_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_process_pseudo_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_init_pseudo_headers(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_process_request_header(ngx_http_request_t *r);


static const struct {
    ngx_str_t   name;
    ngx_uint_t  method;
} ngx_http_v3_methods[] = {

    { ngx_string("GET"),       NGX_HTTP_GET },
    { ngx_string("POST"),      NGX_HTTP_POST },
    { ngx_string("HEAD"),      NGX_HTTP_HEAD },
    { ngx_string("OPTIONS"),   NGX_HTTP_OPTIONS },
    { ngx_string("PROPFIND"),  NGX_HTTP_PROPFIND },
    { ngx_string("PUT"),       NGX_HTTP_PUT },
    { ngx_string("MKCOL"),     NGX_HTTP_MKCOL },
    { ngx_string("DELETE"),    NGX_HTTP_DELETE },
    { ngx_string("COPY"),      NGX_HTTP_COPY },
    { ngx_string("MOVE"),      NGX_HTTP_MOVE },
    { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
    { ngx_string("LOCK"),      NGX_HTTP_LOCK },
    { ngx_string("UNLOCK"),    NGX_HTTP_UNLOCK },
    { ngx_string("PATCH"),     NGX_HTTP_PATCH },
    { ngx_string("TRACE"),     NGX_HTTP_TRACE }
};


void
ngx_http_v3_init(ngx_connection_t *c)
{
    size_t                     size;
    ngx_buf_t                 *b;
    ngx_event_t               *rev;
    ngx_http_request_t        *r;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    if (ngx_http_v3_init_session(c) != NGX_OK) {
        ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                        "internal error");
        ngx_http_close_connection(c);
        return;
    }

    if (c->quic->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        ngx_http_v3_init_uni_stream(c);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init request stream");

    hc = c->data;

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    size = cscf->client_header_buffer_size;

    b = c->buffer;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    c->log->action = "reading client request";

    r = ngx_http_create_request(c);
    if (r == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    r->http_version = NGX_HTTP_VERSION_30;

    c->data = r;

    rev = c->read;
    rev->handler = ngx_http_v3_process_request;

    ngx_http_v3_process_request(rev);
}


static void
ngx_http_v3_process_request(ngx_event_t *rev)
{
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_v3_parse_headers_t  *st;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http3 process request");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    st = r->h3_parse;

    if (st == NULL) {
        st = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_parse_headers_t));
        if (st == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }

        r->h3_parse = st;
    }

    b = r->header_in;

    for ( ;; ) {

        if (b->pos == b->last) {

            if (!rev->ready) {
                break;
            }

            n = c->recv(c, b->start, b->end - b->start);

            if (n == NGX_AGAIN) {
                if (!rev->timer_set) {
                    cscf = ngx_http_get_module_srv_conf(r,
                                                        ngx_http_core_module);
                    ngx_add_timer(rev, cscf->client_header_timeout);
                }

                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                }

                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                c->log->action = "reading client request";

                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                break;
            }

            b->pos = b->start;
            b->last = b->start + n;
        }

        rc = ngx_http_v3_parse_headers(c, st, *b->pos);

        if (rc > 0) {
            ngx_http_v3_finalize_connection(c, rc,
                                            "could not parse request headers");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            break;
        }

        if (rc == NGX_ERROR) {
            ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                            "internal error");
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            break;
        }

        if (rc == NGX_BUSY) {
            if (rev->error) {
                ngx_http_close_request(r, NGX_HTTP_CLOSE);
                break;
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            break;
        }

        b->pos++;
        r->request_length++;

        if (rc == NGX_AGAIN) {
            continue;
        }

        /* rc == NGX_OK || rc == NGX_DONE */

        if (ngx_http_v3_process_header(r, &st->header_rep.header.name,
                                       &st->header_rep.header.value)
            != NGX_OK)
        {
            break;
        }

        if (rc == NGX_DONE) {
            if (ngx_http_v3_process_request_header(r) != NGX_OK) {
                break;
            }

            ngx_http_process_request(r);
            break;
        }
    }

    ngx_http_run_posted_requests(c);

    return;
}


static ngx_int_t
ngx_http_v3_process_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    if (name->len &&  name->data[0] == ':') {
        return ngx_http_v3_process_pseudo_header(r, name, value);
    }

    if (ngx_http_v3_init_pseudo_headers(r) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->key = *name;
    h->value = *value;
    h->lowcase_key = h->key.data;
    h->hash = ngx_hash_key(h->key.data, h->key.len);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);
    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_uint_t  i;

    if (r->request_line.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent out of order pseudo-headers");
        goto failed;
    }

    if (name->len == 7 && ngx_strncmp(name->data, ":method", 7) == 0) {

        r->method_name = *value;

        for (i = 0; i < sizeof(ngx_http_v3_methods)
                        / sizeof(ngx_http_v3_methods[0]); i++)
        {
            if (value->len == ngx_http_v3_methods[i].name.len
                && ngx_strncmp(value->data,
                               ngx_http_v3_methods[i].name.data, value->len)
                   == 0)
            {
                r->method = ngx_http_v3_methods[i].method;
                break;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 method \"%V\" %ui", value, r->method);
        return NGX_OK;
    }

    if (name->len == 5 && ngx_strncmp(name->data, ":path", 5) == 0) {

        r->uri_start = value->data;
        r->uri_end = value->data + value->len;

        if (ngx_http_parse_uri(r) != NGX_OK) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \":path\" header: \"%V\"",
                          value);
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 path \"%V\"", value);
        return NGX_OK;
    }

    if (name->len == 7 && ngx_strncmp(name->data, ":scheme", 7) == 0) {

        r->schema = *value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 schema \"%V\"", value);
        return NGX_OK;
    }

    if (name->len == 10 && ngx_strncmp(name->data, ":authority", 10) == 0) {

        r->host_start = value->data;
        r->host_end = value->data + value->len;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 authority \"%V\"", value);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \"%V\"", name);

failed:

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_init_pseudo_headers(ngx_http_request_t *r)
{
    size_t      len;
    u_char     *p;
    ngx_int_t   rc;
    ngx_str_t   host;

    if (r->request_line.len) {
        return NGX_OK;
    }

    len = r->method_name.len + 1
          + (r->uri_end - r->uri_start) + 1
          + sizeof("HTTP/3.0") - 1;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = ngx_cpymem(p, r->uri_start, r->uri_end - r->uri_start);
    *p++ = ' ';
    p = ngx_cpymem(p, "HTTP/3.0", sizeof("HTTP/3.0") - 1);

    r->request_line.len = p - r->request_line.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 request line: \"%V\"", &r->request_line);

    ngx_str_set(&r->http_protocol, "HTTP/3.0");

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->host_end) {

        host.len = r->host_end - r->host_start;
        host.data = r->host_start;

        rc = ngx_http_validate_host(&host, r->pool, 0);

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid host in request line");
            goto failed;
        }

        if (rc == NGX_ERROR) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
            return NGX_ERROR;
        }

        r->headers_in.server = host;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    return NGX_OK;

failed:

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_process_request_header(ngx_http_request_t *r)
{
    if (ngx_http_v3_init_pseudo_headers(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->headers_in.server.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent neither \":authority\" nor \"Host\" header");
        goto failed;
    }

    if (r->headers_in.host) {
        if (r->headers_in.host->value.len != r->headers_in.server.len
            || ngx_memcmp(r->headers_in.host->value.data,
                          r->headers_in.server.data,
                          r->headers_in.server.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent \":authority\" and \"Host\" headers "
                          "with different values");
            goto failed;
        }
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            goto failed;
        }
    }

    return NGX_OK;

failed:

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_parse_request_body(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_v3_parse_data_t  *st;
    enum {
        sw_start = 0,
        sw_skip
    };

    c = r->connection;
    st = ctx->h3_parse;

    if (st == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse request body");

        st = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_parse_data_t));
        if (st == NULL) {
            goto failed;
        }

        ctx->h3_parse = st;
    }

    while (b->pos < b->last && ctx->size == 0) {

        rc = ngx_http_v3_parse_data(c, st, *b->pos++);

        if (rc > 0) {
            ngx_http_v3_finalize_connection(c, rc,
                                            "could not parse request body");
            goto failed;
        }

        if (rc == NGX_ERROR) {
            goto failed;
        }

        if (rc == NGX_AGAIN) {
            ctx->state = sw_skip;
            continue;
        }

        if (rc == NGX_DONE) {
            return NGX_DONE;
        }

        /* rc == NGX_OK */

        ctx->size = st->length;
        ctx->state = sw_start;
    }

    if (ctx->state == sw_skip) {
        ctx->length = 1;
        return NGX_AGAIN;
    }

    if (b->pos == b->last) {
        ctx->length = ctx->size;
        return NGX_AGAIN;
    }

    return NGX_OK;

failed:

    return NGX_ERROR;
}
