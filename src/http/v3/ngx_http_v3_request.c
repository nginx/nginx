
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_v3_init_request_stream(ngx_connection_t *c);
static void ngx_http_v3_wait_request_handler(ngx_event_t *rev);
static void ngx_http_v3_cleanup_connection(void *data);
static void ngx_http_v3_cleanup_request(void *data);
static void ngx_http_v3_process_request(ngx_event_t *rev);
static ngx_int_t ngx_http_v3_process_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_validate_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_process_pseudo_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_init_pseudo_headers(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_process_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_cookie(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t ngx_http_v3_construct_cookie_header(ngx_http_request_t *r);
static void ngx_http_v3_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


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
    { ngx_string("TRACE"),     NGX_HTTP_TRACE },
    { ngx_string("CONNECT"),   NGX_HTTP_CONNECT }
};


void
ngx_http_v3_init_stream(ngx_connection_t *c)
{
    ngx_http_connection_t     *hc, *phc;
    ngx_http_v3_srv_conf_t    *h3scf;
    ngx_http_core_loc_conf_t  *clcf;

    hc = c->data;

    hc->ssl = 1;

    clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);

    if (c->quic == NULL) {
        h3scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v3_module);
        h3scf->quic.idle_timeout = clcf->keepalive_timeout;

        ngx_quic_run(c, &h3scf->quic);
        return;
    }

    phc = ngx_http_quic_get_connection(c);

    if (phc->ssl_servername) {
        hc->ssl_servername = phc->ssl_servername;
#if (NGX_PCRE)
        hc->ssl_servername_regex = phc->ssl_servername_regex;
#endif
        hc->conf_ctx = phc->conf_ctx;

        ngx_set_connection_log(c, clcf->error_log);
    }

    if (c->quic->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        ngx_http_v3_init_uni_stream(c);

    } else  {
        ngx_http_v3_init_request_stream(c);
    }
}


ngx_int_t
ngx_http_v3_init(ngx_connection_t *c)
{
    unsigned int               len;
    const unsigned char       *data;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_srv_conf_t    *h3scf;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init");

    if (ngx_http_v3_init_session(c) != NGX_OK) {
        return NGX_ERROR;
    }

    h3c = ngx_http_v3_get_session(c);
    clcf = ngx_http_v3_get_module_loc_conf(c, ngx_http_core_module);
    ngx_add_timer(&h3c->keepalive, clcf->keepalive_timeout);

    h3scf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

    if (h3scf->enable_hq) {
        if (!h3scf->enable) {
            h3c->hq = 1;
            return NGX_OK;
        }

        SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

        if (len == sizeof(NGX_HTTP_V3_HQ_PROTO) - 1
            && ngx_strncmp(data, NGX_HTTP_V3_HQ_PROTO, len) == 0)
        {
            h3c->hq = 1;
            return NGX_OK;
        }
    }

    if (ngx_http_v3_send_settings(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (h3scf->max_table_capacity > 0) {
        if (ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER) == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


void
ngx_http_v3_shutdown(ngx_connection_t *c)
{
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 shutdown");

    h3c = ngx_http_v3_get_session(c);

    if (h3c == NULL) {
        ngx_quic_finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR,
                                     "connection shutdown");
        return;
    }

    if (!h3c->goaway) {
        h3c->goaway = 1;

        if (!h3c->hq) {
            (void) ngx_http_v3_send_goaway(c, h3c->next_request_id);
        }

        ngx_http_v3_shutdown_connection(c, NGX_HTTP_V3_ERR_NO_ERROR,
                                        "connection shutdown");
    }
}


static void
ngx_http_v3_init_request_stream(ngx_connection_t *c)
{
    uint64_t                   n;
    ngx_event_t               *rev;
    ngx_pool_cleanup_t        *cln;
    ngx_http_connection_t     *hc;
    ngx_http_v3_session_t     *h3c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init request stream");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    hc = c->data;

    clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);

    n = c->quic->id >> 2;

    if (n >= clcf->keepalive_requests * 2) {
        ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                        "too many requests per connection");
        ngx_http_close_connection(c);
        return;
    }

    h3c = ngx_http_v3_get_session(c);

    if (h3c->goaway) {
        c->close = 1;
        ngx_http_close_connection(c);
        return;
    }

    h3c->next_request_id = c->quic->id + 0x04;

    if (n + 1 == clcf->keepalive_requests
        || ngx_current_msec - c->start_time > clcf->keepalive_time)
    {
        h3c->goaway = 1;

        if (!h3c->hq) {
            if (ngx_http_v3_send_goaway(c, h3c->next_request_id) != NGX_OK) {
                ngx_http_close_connection(c);
                return;
            }
        }

        ngx_http_v3_shutdown_connection(c, NGX_HTTP_V3_ERR_NO_ERROR,
                                        "reached maximum number of requests");
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln->handler = ngx_http_v3_cleanup_connection;
    cln->data = c;

    h3c->nrequests++;

    if (h3c->keepalive.timer_set) {
        ngx_del_timer(&h3c->keepalive);
    }

    rev = c->read;

    if (!h3c->hq) {
        rev->handler = ngx_http_v3_wait_request_handler;
        c->write->handler = ngx_http_empty_handler;
    }

    if (rev->ready) {
        rev->handler(rev);
        return;
    }

    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    ngx_add_timer(rev, cscf->client_header_timeout);
    ngx_reusable_connection(c, 1);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }
}


static void
ngx_http_v3_wait_request_handler(ngx_event_t *rev)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_http_request_t        *r;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 wait request handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

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

    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {

        if (!rev->timer_set) {
            ngx_add_timer(rev, cscf->client_header_timeout);
            ngx_reusable_connection(c, 1);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->action = "reading client request";

    ngx_reusable_connection(c, 0);

    r = ngx_http_create_request(c);
    if (r == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    r->http_version = NGX_HTTP_VERSION_30;

    r->v3_parse = ngx_pcalloc(r->pool, sizeof(ngx_http_v3_parse_t));
    if (r->v3_parse == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->v3_parse->header_limit = cscf->large_client_header_buffers.size
                                * cscf->large_client_header_buffers.num;

    c->data = r;
    c->requests = (c->quic->id >> 2) + 1;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_v3_cleanup_request;
    cln->data = r;

    rev->handler = ngx_http_v3_process_request;
    ngx_http_v3_process_request(rev);
}


void
ngx_http_v3_reset_stream(ngx_connection_t *c)
{
    ngx_http_v3_session_t  *h3c;

    h3c = ngx_http_v3_get_session(c);

    if (!c->read->eof && !h3c->hq
        && h3c->known_streams[NGX_HTTP_V3_STREAM_SERVER_DECODER]
        && (c->quic->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0)
    {
        (void) ngx_http_v3_send_cancel_stream(c, c->quic->id);
    }

    if (c->timedout) {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR);

    } else if (c->close) {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_REQUEST_REJECTED);

    } else if (c->requests == 0 || c->error) {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR);
    }
}


static void
ngx_http_v3_cleanup_connection(void *data)
{
    ngx_connection_t  *c = data;

    ngx_http_v3_session_t     *h3c;
    ngx_http_core_loc_conf_t  *clcf;

    h3c = ngx_http_v3_get_session(c);

    if (--h3c->nrequests == 0) {
        clcf = ngx_http_v3_get_module_loc_conf(c, ngx_http_core_module);
        ngx_add_timer(&h3c->keepalive, clcf->keepalive_timeout);
    }
}


static void
ngx_http_v3_cleanup_request(void *data)
{
    ngx_http_request_t  *r = data;

    if (!r->response_sent) {
        r->connection->error = 1;
    }
}


static void
ngx_http_v3_process_request(ngx_event_t *rev)
{
    u_char                       *p;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_v3_session_t        *h3c;
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

    h3c = ngx_http_v3_get_session(c);

    st = &r->v3_parse->headers;

    b = r->header_in;

    for ( ;; ) {

        if (b->pos == b->last) {

            if (rev->ready) {
                n = c->recv(c, b->start, b->end - b->start);

            } else {
                n = NGX_AGAIN;
            }

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

        p = b->pos;

        rc = ngx_http_v3_parse_headers(c, st, b);

        if (rc > 0) {
            ngx_quic_reset_stream(c, rc);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            break;
        }

        if (rc == NGX_ERROR) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            break;
        }

        r->request_length += b->pos - p;
        h3c->total_bytes += b->pos - p;

        if (ngx_http_v3_check_flood(c) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_CLOSE);
            break;
        }

        if (rc == NGX_BUSY) {
            if (rev->error) {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                break;
            }

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

        if (rc == NGX_AGAIN) {
            continue;
        }

        /* rc == NGX_OK || rc == NGX_DONE */

        h3c->payload_bytes += ngx_http_v3_encode_field_l(NULL,
                                                   &st->field_rep.field.name,
                                                   &st->field_rep.field.value);

        if (ngx_http_v3_process_header(r, &st->field_rep.field.name,
                                       &st->field_rep.field.value)
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
    size_t                      len;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    len = name->len + value->len;

    if (len > r->v3_parse->header_limit) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too large header");
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
        return NGX_ERROR;
    }

    r->v3_parse->header_limit -= len;

    if (ngx_http_v3_validate_header(r, name, value) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    if (r->invalid_header) {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->ignore_invalid_headers) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", name);

            return NGX_OK;
        }
    }

    if (name->len && name->data[0] == ':') {
        return ngx_http_v3_process_pseudo_header(r, name, value);
    }

    if (ngx_http_v3_init_pseudo_headers(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (name->len == cookie.len
        && ngx_memcmp(name->data, cookie.data, cookie.len) == 0)
    {
        if (ngx_http_v3_cookie(r, value) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

    } else {
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
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);
    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_validate_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char                     ch;
    ngx_uint_t                 i;
    ngx_http_core_srv_conf_t  *cscf;

    r->invalid_header = 0;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    for (i = (name->data[0] == ':'); i != name->len; i++) {
        ch = name->data[i];

        if ((ch >= 'a' && ch <= 'z')
            || (ch == '-')
            || (ch >= '0' && ch <= '9')
            || (ch == '_' && cscf->underscores_in_headers))
        {
            continue;
        }

        if (ch <= 0x20 || ch == 0x7f || ch == ':'
            || (ch >= 'A' && ch <= 'Z'))
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header name: \"%V\"", name);

            return NGX_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != value->len; i++) {
        ch = value->data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"", name, value);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char      ch, c;
    ngx_uint_t  i;

    if (r->request_line.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent out of order pseudo-headers");
        goto failed;
    }

    if (name->len == 7 && ngx_strncmp(name->data, ":method", 7) == 0) {

        if (r->method_name.len) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":method\" header");
            goto failed;
        }

        if (value->len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":method\" header");
            goto failed;
        }

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

        for (i = 0; i < value->len; i++) {
            ch = value->data[i];

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent invalid method: \"%V\"", value);
                goto failed;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 method \"%V\" %ui", value, r->method);
        return NGX_OK;
    }

    if (name->len == 5 && ngx_strncmp(name->data, ":path", 5) == 0) {

        if (r->uri_start) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":path\" header");
            goto failed;
        }

        if (value->len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":path\" header");
            goto failed;
        }

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

        if (r->schema.len) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":scheme\" header");
            goto failed;
        }

        if (value->len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":scheme\" header");
            goto failed;
        }

        for (i = 0; i < value->len; i++) {
            ch = value->data[i];

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                continue;
            }

            if (((ch >= '0' && ch <= '9')
                 || ch == '+' || ch == '-' || ch == '.')
                && i > 0)
            {
                continue;
            }

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \":scheme\" header: \"%V\"",
                          value);
            goto failed;
        }

        r->schema = *value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 schema \"%V\"", value);
        return NGX_OK;
    }

    if (name->len == 10 && ngx_strncmp(name->data, ":authority", 10) == 0) {

        if (r->host_start) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":authority\" header");
            goto failed;
        }

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

    if (r->method_name.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent no \":method\" header");
        goto failed;
    }

    if (r->schema.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent no \":scheme\" header");
        goto failed;
    }

    if (r->uri_start == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent no \":path\" header");
        goto failed;
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
    ssize_t                  n;
    ngx_buf_t               *b;
    ngx_connection_t        *c;
    ngx_http_v3_session_t   *h3c;
    ngx_http_v3_srv_conf_t  *h3scf;

    c = r->connection;

    if (ngx_http_v3_init_pseudo_headers(r) != NGX_OK) {
        return NGX_ERROR;
    }

    h3c = ngx_http_v3_get_session(c);
    h3scf = ngx_http_get_module_srv_conf(r, ngx_http_v3_module);

    if ((h3c->hq && !h3scf->enable_hq) || (!h3c->hq && !h3scf->enable)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client attempted to request the server name "
                      "for which the negotiated protocol is disabled");
        ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
        return NGX_ERROR;
    }

    if (ngx_http_v3_construct_cookie_header(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->headers_in.server.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
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
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
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
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent invalid \"Content-Length\" header");
            goto failed;
        }

    } else {
        b = r->header_in;
        n = b->last - b->pos;

        if (n == 0) {
            n = c->recv(c, b->start, b->end - b->start);

            if (n == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }

            if (n > 0) {
                b->pos = b->start;
                b->last = b->start + n;
            }
        }

        if (n != 0) {
            r->headers_in.chunked = 1;
        }
    }

    if (r->method == NGX_HTTP_CONNECT) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client sent CONNECT method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    if (r->method == NGX_HTTP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client sent TRACE method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    return NGX_OK;

failed:

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_cookie(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_str_t    *val;
    ngx_array_t  *cookies;

    cookies = r->v3_parse->cookies;

    if (cookies == NULL) {
        cookies = ngx_array_create(r->pool, 2, sizeof(ngx_str_t));
        if (cookies == NULL) {
            return NGX_ERROR;
        }

        r->v3_parse->cookies = cookies;
    }

    val = ngx_array_push(cookies);
    if (val == NULL) {
        return NGX_ERROR;
    }

    *val = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    ngx_str_t                  *vals;
    ngx_uint_t                  i;
    ngx_array_t                *cookies;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    cookies = r->v3_parse->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_multi_header_lines()
         */
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_read_request_body(ngx_http_request_t *r)
{
    size_t                     preread;
    ngx_int_t                  rc;
    ngx_chain_t               *cl, out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 client request body preread %uz", preread);

        out.buf = r->header_in;
        out.next = NULL;
        cl = &out;

    } else {
        cl = NULL;
    }

    rc = ngx_http_v3_request_body_filter(r, cl);
    if (rc != NGX_OK) {
        return rc;
    }

    if (rb->rest == 0 && rb->last_saved) {
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    rb->buf = ngx_create_temp_buf(r->pool, clcf->client_body_buffer_size);
    if (rb->buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = ngx_http_v3_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    return ngx_http_v3_do_read_client_request_body(r);
}


static void
ngx_http_v3_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_v3_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


ngx_int_t
ngx_http_v3_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_v3_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static ngx_int_t
ngx_http_v3_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_uint_t                 flush;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;
    flush = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last == rb->buf->end) {

                /* update chains */

                rc = ngx_http_v3_request_body_filter(r, NULL);

                if (rc != NGX_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    if (rb->filter_need_buffering) {
                        clcf = ngx_http_get_module_loc_conf(r,
                                                         ngx_http_core_module);
                        ngx_add_timer(c->read, clcf->client_body_timeout);

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                                  "busy buffers after request body flush");

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                flush = 0;
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            if (size == 0) {
                break;
            }

            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                rb->buf->last_buf = 1;
            }

            if (n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;

            /* pass buffer to request body filter chain */

            flush = 0;
            out.buf = rb->buf;
            out.next = NULL;

            rc = ngx_http_v3_request_body_filter(r, &out);

            if (rc != NGX_OK) {
                return rc;
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 client request body rest %O", rb->rest);

        if (flush) {
            rc = ngx_http_v3_request_body_filter(r, NULL);

            if (rc != NGX_OK) {
                return rc;
            }
        }

        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        if (!c->read->ready || rb->rest == 0) {

            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = ngx_http_block_reading;
        rb->post_handler(r);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      max;
    size_t                     size;
    u_char                    *p;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_uint_t                 last;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_v3_session_t     *h3c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_v3_parse_data_t  *st;

    rb = r->request_body;
    st = &r->v3_parse->body;

    h3c = ngx_http_v3_get_session(r->connection);

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 request body filter");

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        rb->rest = cscf->large_client_header_buffers.size;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    max = r->headers_in.content_length_n;

    if (max == -1 && clcf->client_max_body_size) {
        max = clcf->client_max_body_size;
    }

    out = NULL;
    ll = &out;
    last = 0;

    for (cl = in; cl; cl = cl->next) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http3 body buf "
                       "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (cl->buf->last_buf) {
            last = 1;
        }

        b = NULL;

        while (cl->buf->pos < cl->buf->last) {

            if (st->length == 0) {
                p = cl->buf->pos;

                rc = ngx_http_v3_parse_data(r->connection, st, cl->buf);

                r->request_length += cl->buf->pos - p;
                h3c->total_bytes += cl->buf->pos - p;

                if (ngx_http_v3_check_flood(r->connection) != NGX_OK) {
                    return NGX_HTTP_CLOSE;
                }

                if (rc == NGX_AGAIN) {
                    continue;
                }

                if (rc == NGX_DONE) {
                    last = 1;
                    goto done;
                }

                if (rc > 0) {
                    ngx_quic_reset_stream(r->connection, rc);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client sent invalid body");
                    return NGX_HTTP_BAD_REQUEST;
                }

                if (rc == NGX_ERROR) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* rc == NGX_OK */

                if (max != -1 && (uint64_t) (max - rb->received) < st->length) {

                    if (r->headers_in.content_length_n != -1) {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                      "client intended to send body data "
                                      "larger than declared");

                        return NGX_HTTP_BAD_REQUEST;
                    }

                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large "
                                  "body: %O+%ui bytes",
                                  rb->received, st->length);

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                continue;
            }

            if (b
                && st->length <= 128
                && (uint64_t) (cl->buf->last - cl->buf->pos) >= st->length)
            {
                rb->received += st->length;
                r->request_length += st->length;
                h3c->total_bytes += st->length;
                h3c->payload_bytes += st->length;

                if (st->length < 8) {

                    while (st->length) {
                        *b->last++ = *cl->buf->pos++;
                        st->length--;
                    }

                } else {
                    ngx_memmove(b->last, cl->buf->pos, st->length);
                    b->last += st->length;
                    cl->buf->pos += st->length;
                    st->length = 0;
                }

                continue;
            }

            tl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (tl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = tl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->temporary = 1;
            b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
            b->start = cl->buf->pos;
            b->pos = cl->buf->pos;
            b->last = cl->buf->last;
            b->end = cl->buf->end;
            b->flush = r->request_body_no_buffering;

            *ll = tl;
            ll = &tl->next;

            size = cl->buf->last - cl->buf->pos;

            if (size > st->length) {
                cl->buf->pos += (size_t) st->length;
                rb->received += st->length;
                r->request_length += st->length;
                h3c->total_bytes += st->length;
                h3c->payload_bytes += st->length;
                st->length = 0;

            } else {
                st->length -= size;
                rb->received += size;
                r->request_length += size;
                h3c->total_bytes += size;
                h3c->payload_bytes += size;
                cl->buf->pos = cl->buf->last;
            }

            b->last = cl->buf->pos;
        }
    }

done:

    if (last) {

        if (st->length > 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream");
            r->connection->error = 1;
            return NGX_HTTP_BAD_REQUEST;
        }

        if (r->headers_in.content_length_n == -1) {
            r->headers_in.content_length_n = rb->received;

        } else if (r->headers_in.content_length_n != rb->received) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent less body data than expected: "
                          "%O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);
            return NGX_HTTP_BAD_REQUEST;
        }

        rb->rest = 0;

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->last_buf = 1;

        *ll = tl;

    } else {

        /* set rb->rest, amount of data we want to see next time */

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        rb->rest = (off_t) cscf->large_client_header_buffers.size;
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}
