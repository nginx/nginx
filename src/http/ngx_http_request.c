
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_init_request(ngx_event_t *ev);
#if (NGX_HTTP_SSL)
static void ngx_http_ssl_handshake(ngx_event_t *rev);
#endif
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
                                                    ngx_uint_t request_line);
static ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r);

static void ngx_http_set_write_handler(ngx_http_request_t *r);

static void ngx_http_block_read(ngx_event_t *ev);
static void ngx_http_read_discarded_body_event(ngx_event_t *rev);
static ngx_int_t ngx_http_read_discarded_body(ngx_http_request_t *r);

static void ngx_http_set_keepalive(ngx_http_request_t *r);
static void ngx_http_keepalive_handler(ngx_event_t *ev);
static void ngx_http_set_lingering_close(ngx_http_request_t *r);
static void ngx_http_lingering_close_handler(ngx_event_t *ev);

static void ngx_http_client_error(ngx_http_request_t *r,
                                  int client_error, int error);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);


/* NGX_HTTP_PARSE_... errors */

static char *client_header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent too long URI",
    "client %s sent invalid method in HTTP/0.9 request",

    "client %s sent invalid header, URL: %s",
    "client %s sent too long header line, URL: %s",
    "client %s sent HTTP/1.1 request without \"Host\" header, URL: %s",
    "client %s sent invalid \"Content-Length\" header, URL: %s",
    "client %s sent POST method without \"Content-Length\" header, URL: %s",
    "client %s sent plain HTTP request to HTTPS port, URL: %s",
    "client %s sent invalid \"Host\" header \"%s\", URL: %s"
};


ngx_http_header_t  ngx_http_headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host) },
    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection) },
    { ngx_string("If-Modified-Since"),
                         offsetof(ngx_http_headers_in_t, if_modified_since) },
    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent) },
    { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer) },
    { ngx_string("Content-Length"),
                            offsetof(ngx_http_headers_in_t, content_length) },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range) },
#if 0
    { ngx_string("If-Range"), offsetof(ngx_http_headers_in_t, if_range) },
#endif

#if (NGX_HTTP_GZIP)
    { ngx_string("Accept-Encoding"),
                           offsetof(ngx_http_headers_in_t, accept_encoding) },
    { ngx_string("Via"), offsetof(ngx_http_headers_in_t, via) },
#endif

    { ngx_string("Authorization"),
                             offsetof(ngx_http_headers_in_t, authorization) },

    { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive) },

#if (NGX_HTTP_PROXY)
    { ngx_string("X-Forwarded-For"),
                           offsetof(ngx_http_headers_in_t, x_forwarded_for) },
#endif
    
    { ngx_null_string, 0 }
};


#if 0
static void ngx_http_dummy(ngx_event_t *wev)
{
    return;
}
#endif


void ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *rev;
    ngx_http_log_ctx_t  *ctx;

    if (!(ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t)))) {
        ngx_http_close_connection(c);
        return;
    }

    ctx->connection = c->number;
    ctx->client = c->addr_text.data;
    ctx->action = "reading client request line";
    c->log->data = ctx;
    c->log->handler = ngx_http_log_error;
    c->log_error = NGX_ERROR_INFO;

    rev = c->read;
    rev->event_handler = ngx_http_init_request;

    /* STUB: epoll edge */ c->write->event_handler = ngx_http_empty_handler;

    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_accept_mutex) {
            if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                ngx_http_close_connection(c);
                return;
            }

            ngx_post_event(rev); 

            ngx_mutex_unlock(ngx_posted_events_mutex);
            return;
        }

#if (NGX_STAT_STUB)
        (*ngx_stat_reading)++;
#endif

        ngx_http_init_request(rev);
        return;
    }

    ngx_add_timer(rev, c->listening->post_accept_timeout);

    if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

#if 0
    /* TODO: learn SO_SNDBUF (to use in zerocopy) via kqueue's EV_CLEAR event */

    c->write->ready = 0;
    c->write->event_handler = ngx_http_dummy;

    if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }
#endif

#if (NGX_STAT_STUB)
    (*ngx_stat_reading)++;
#endif

}


static void ngx_http_init_request(ngx_event_t *rev)
{
    ngx_uint_t                 i;
    socklen_t                  len;
    struct sockaddr_in         addr_in;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_in_port_t        *in_port;
    ngx_http_in_addr_t        *in_addr;
    ngx_http_connection_t     *hc;
    ngx_http_server_name_t    *server_name;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;
#if (NGX_HTTP_SSL)
    ngx_http_ssl_srv_conf_t   *sscf;
#endif

    c = rev->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");

#if (NGX_STAT_STUB)
        (*ngx_stat_reading)--;
#endif

        ngx_http_close_connection(c);
        return;
    }

    hc = c->data;

    if (hc) {

#if (NGX_STAT_STUB)
        (*ngx_stat_reading)++;
#endif

    } else {
        if (!(hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t)))) {

#if (NGX_STAT_STUB)
            (*ngx_stat_reading)--;
#endif

            ngx_http_close_connection(c);
            return;
        }
    }

    r = hc->request;

    if (r) {
        ngx_memzero(r, sizeof(ngx_http_request_t));

        r->pipeline = hc->pipeline;

        if (hc->nbusy) {
            r->header_in = hc->busy[0];
        }

    } else {
        if (!(r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)))) {

#if (NGX_STAT_STUB)
            (*ngx_stat_reading)--;
#endif

            ngx_http_close_connection(c);
            return;
        }

        hc->request = r;
    }

#if (NGX_STAT_STUB)
    r->stat_reading = 1;
#endif

    c->data = r;
    r->http_connection = hc;

    c->sent = 0;
    r->signature = NGX_HTTP_MODULE;

    /* find the server configuration for the address:port */

    /* AF_INET only */

    in_port = c->servers;
    in_addr = in_port->addrs.elts;

    r->port = in_port->port;
    r->port_text = &in_port->port_text;

    i = 0;

    if (in_port->addrs.nelts > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

#if (WIN32)
        if (c->local_sockaddr) {
            r->in_addr =
                   ((struct sockaddr_in *) c->local_sockaddr)->sin_addr.s_addr;

        } else {
#endif
            len = sizeof(struct sockaddr_in);
            if (getsockname(c->fd, (struct sockaddr *) &addr_in, &len) == -1) {
                ngx_connection_error(c, ngx_socket_errno,
                                     "getsockname() failed");
                ngx_http_close_connection(c);
                return;
            }

            r->in_addr = addr_in.sin_addr.s_addr;

#if (WIN32)
        }
#endif

        /* the last in_port->addrs address is "*" */

        for ( /* void */ ; i < in_port->addrs.nelts - 1; i++) {
            if (in_addr[i].addr == r->in_addr) {
                break;
            }
        }

    } else {
        r->in_addr = in_addr[0].addr;
    }

    r->virtual_names = &in_addr[i].names;

    /* the default server configuration for the address:port */
    cscf = in_addr[i].core_srv_conf;

    r->main_conf = cscf->ctx->main_conf;
    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    rev->event_handler = ngx_http_process_request_line;

#if (NGX_HTTP_SSL)

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);
    if (sscf->enable) {

        if (c->ssl == NULL) {
            if (ngx_ssl_create_session(sscf->ssl_ctx, c, NGX_SSL_BUFFER)
                                                                  == NGX_ERROR)
            {
                ngx_http_close_connection(c);
                return;
            }

            /*
             * The majority of browsers do not send the "close notify" alert.
             * Among them are MSIE, Mozilla, Netscape 4, Konqueror, and Links.
             * And what is more MSIE ignores the server's alert.
             *
             * Opera always sends the alert.
             */

            c->ssl->no_rcv_shut = 1;
            rev->event_handler = ngx_http_ssl_handshake;
        }

        r->filter_need_in_memory = 1;
    }

#endif

    server_name = cscf->server_names.elts;
    r->server_name = &server_name->name;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    c->log->file = clcf->err_log->file;
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        c->log->log_level = clcf->err_log->log_level;
    }

    if (c->buffer == NULL) {
        c->buffer = ngx_create_temp_buf(c->pool,
                                        cscf->client_header_buffer_size);
        if (c->buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    if (r->header_in == NULL) {
        r->header_in = c->buffer;
    }

    if (!(r->pool = ngx_create_pool(cscf->request_pool_size, c->log))) {
        ngx_http_close_connection(c);
        return;
    }

    if (ngx_array_init(&r->cleanup, r->pool, 5, sizeof(ngx_http_cleanup_t))
                                                                  == NGX_ERROR)
    { 
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_close_connection(c);
        return;
    }


    if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                                         sizeof(ngx_table_elt_t)) == NGX_ERROR)
    {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_close_connection(c);
        return;
    }


    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_close_connection(c);
        return;
    }

    c->single_connection = 1;
    r->connection = c;

    r->file.fd = NGX_INVALID_FILE;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->http_state = NGX_HTTP_READING_REQUEST_STATE;

#if (NGX_STAT_STUB)
    (*ngx_stat_requests)++;
#endif

    rev->event_handler(rev);
}


#if (NGX_HTTP_SSL)

static void ngx_http_ssl_handshake(ngx_event_t *rev)
{
    int                  n;
    ngx_int_t            rc;
    u_char               buf[1];
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK); 

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        return;
    }

    if (n == 1) {
        if (buf[0] == 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%X", buf[0]);

            c->recv = ngx_ssl_recv;
            c->send_chain = ngx_ssl_send_chain;

            rc = ngx_ssl_handshake(c);

            if (rc == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_BAD_REQUEST);
                ngx_http_close_connection(r->connection);
                return;
            }

            if (rc != NGX_OK) {
                return;
            }

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "plain http");

            r->plain_http = 1;
        }
    }

    rev->event_handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}

#endif


static void ngx_http_process_request_line(ngx_event_t *rev)
{
    u_char              *p;
    ssize_t              n;
    ngx_int_t            rc, rv;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    if (rev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {
            n = ngx_http_read_request_header(r);

            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        rc = ngx_http_parse_request_line(r, r->header_in);

        if (rc == NGX_OK) {

            /* the request line has been parsed successfully */

            /* copy unparsed URI */

            r->unparsed_uri.len = r->uri_end - r->uri_start;
            r->unparsed_uri.data = ngx_palloc(r->pool, r->unparsed_uri.len + 1);
            if (r->unparsed_uri.data == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            ngx_cpystrn(r->unparsed_uri.data, r->uri_start,
                        r->unparsed_uri.len + 1);


            /* copy URI */

            if (r->args_start) {
                r->uri.len = r->args_start - 1 - r->uri_start;
            } else {
                r->uri.len = r->uri_end - r->uri_start;
            }

            if (!(r->uri.data = ngx_palloc(r->pool, r->uri.len + 1))) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            if (r->complex_uri) {
                rc = ngx_http_parse_complex_uri(r);

                if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
                    ngx_http_close_request(r, rc);
                    ngx_http_close_connection(c);
                    return;
                }

                if (rc != NGX_OK) {
                    r->request_line.len = r->request_end - r->request_start;
                    r->request_line.data = r->request_start;

                    ngx_http_client_error(r, rc, NGX_HTTP_BAD_REQUEST);
                    return;
                }

            } else {
                ngx_cpystrn(r->uri.data, r->uri_start, r->uri.len + 1);
            }


            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            r->request_line.data[r->request_line.len] = '\0';

            if (r->method == 0) {
                r->method_name.len = r->method_end - r->request_start + 1;
                r->method_name.data = r->request_line.data;
            }

            if (r->uri_ext) {

                /* copy URI extention */

                if (r->args_start) {
                    r->exten.len = r->args_start - 1 - r->uri_ext;
                } else {
                    r->exten.len = r->uri_end - r->uri_ext;
                }

                if (!(r->exten.data = ngx_palloc(r->pool, r->exten.len + 1))) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    ngx_http_close_connection(c);
                    return;
                }

                ngx_cpystrn(r->exten.data, r->uri_ext, r->exten.len + 1);
            }

            if (r->args_start && r->uri_end > r->args_start) {

                /* copy URI arguments */

                r->args.len = r->uri_end - r->args_start;

                if (!(r->args.data = ngx_palloc(r->pool, r->args.len + 1))) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    ngx_http_close_connection(c);
                    return;
                }

                ngx_cpystrn(r->args.data, r->args_start, r->args.len + 1);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%s\"", r->request_line.data);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http uri: \"%s\"", r->uri.data);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http args: \"%s\"",
                           r->args.data ? r->args.data : (u_char *) "");

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http exten: \"%s\"",
                           r->exten.data ? r->exten.data : (u_char *) "");

            if (r->http_version < NGX_HTTP_VERSION_10) {
                rev->event_handler = ngx_http_block_read;
                ngx_http_handler(r);
                return;
            }


            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                                         sizeof(ngx_table_elt_t)) == NGX_ERROR)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }


            if (ngx_array_init(&r->headers_in.cookies, r->pool, 5,
                                       sizeof(ngx_table_elt_t *)) == NGX_ERROR)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }


            ctx = c->log->data;
            ctx->action = "reading client request headers";
            ctx->url = r->unparsed_uri.data;

            rev->event_handler = ngx_http_process_request_headers;
            ngx_http_process_request_headers(rev);

            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a request line parsing */

            for (p = r->request_start; p < r->header_in->last; p++) {
                if (*p == CR || *p == LF) {
                    break;
                }
            }

            r->request_line.len = p - r->request_start;
            r->request_line.data = r->request_start;

            if (rc == NGX_HTTP_PARSE_INVALID_METHOD) {
                r->http_version = NGX_HTTP_VERSION_10;
            }

            ngx_http_client_error(r, rc,
                                  (rc == NGX_HTTP_PARSE_INVALID_METHOD) ?
                                         NGX_HTTP_NOT_IMPLEMENTED:
                                         NGX_HTTP_BAD_REQUEST);
            return;
        }

        /* NGX_AGAIN: a request line parsing is still incomplete */

        if (r->header_in->pos == r->header_in->end) {

            rv = ngx_http_alloc_large_header_buffer(r, 1);

            if (rv == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            if (rv == NGX_DECLINED) {
                ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                      NGX_HTTP_REQUEST_URI_TOO_LARGE);
                return;
            }
        }
    }
}


static void ngx_http_process_request_headers(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc, rv, i;
    ngx_table_elt_t     *h, **cookie;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    if (rev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                rv = ngx_http_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    ngx_http_close_connection(c);
                    return;
                }

                if (rv == NGX_DECLINED) {
                    ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_HEADER,
                                          NGX_HTTP_BAD_REQUEST);
                    return;
                }
            }

            n = ngx_http_read_request_header(r);

            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        rc = ngx_http_parse_header_line(r, r->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            r->headers_n++;

            if (!(h = ngx_list_push(&r->headers_in.headers))) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            if (h->key.len == sizeof("Cookie") - 1
                && ngx_strcasecmp(h->key.data, "Cookie") == 0)
            {
                if (!(cookie = ngx_array_push(&r->headers_in.cookies))) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    ngx_http_close_connection(c);
                    return;
                }

                *cookie = h;

            } else {

                for (i = 0; ngx_http_headers_in[i].name.len != 0; i++) {
                    if (ngx_http_headers_in[i].name.len != h->key.len) {
                        continue;
                    }

                    if (ngx_strcasecmp(ngx_http_headers_in[i].name.data,
                                       h->key.data) == 0)
                    {
                        *((ngx_table_elt_t **) ((char *) &r->headers_in
                                         + ngx_http_headers_in[i].offset)) = h;
                        break;
                    }
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%s: %s\"",
                           h->key.data, h->value.data);

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                ngx_http_client_error(r, rc, NGX_HTTP_BAD_REQUEST);
                return;
            }

            if (rev->timer_set) {
                ngx_del_timer(rev);
            }

#if (NGX_STAT_STUB)
            (*ngx_stat_reading)--;
            r->stat_reading = 0;
            (*ngx_stat_writing)++;
            r->stat_writing = 1;
#endif

            rev->event_handler = ngx_http_block_read;
            ngx_http_handler(r);
            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

#if (NGX_DEBUG)
            if (rc == NGX_HTTP_PARSE_INVALID_HEADER
                && (rev->log->log_level & NGX_LOG_DEBUG_HTTP))
            {
                u_char *p;
                for (p = r->header_name_start;
                     p < r->header_in->last - 1;
                     p++)
                {
                    if (*p == LF) {
                        break;
                    }
                }
                *p = '\0';
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                               "http invalid header: \"%s\"",
                               r->header_name_start);
            }
#endif

            ngx_http_client_error(r, rc, NGX_HTTP_BAD_REQUEST);
            return;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

    }
}


static ssize_t ngx_http_read_request_header(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_http_core_srv_conf_t  *cscf;

    rev = r->connection->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (!rev->ready) {
        return NGX_AGAIN;
    }

    n = r->connection->recv(r->connection, r->header_in->last,
                            r->header_in->end - r->header_in->last);

    if (n == NGX_AGAIN) {
        if (!r->header_timeout_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, cscf->client_header_timeout);
            r->header_timeout_set = 1;
        }

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            ngx_http_close_connection(r->connection);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client closed prematurely connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_BAD_REQUEST);
        ngx_http_close_connection(r->connection);
        return NGX_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
                                                    ngx_uint_t request_line)
{
    u_char                    *old, *new;
    ngx_buf_t                 *b;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NGX_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NGX_DECLINED;
    }

    hc = r->http_connection;

    if (hc->nfree) {
        b = hc->free[--hc->nfree];

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: " PTR_FMT " " SIZE_T_FMT,
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        if (hc->busy == NULL) {
            hc->busy = ngx_palloc(r->connection->pool,
                  cscf->large_client_header_buffers.num * sizeof(ngx_buf_t *));
            if (hc->busy == NULL) {
                return NGX_ERROR;
            }
        }

        b = ngx_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: " PTR_FMT " " SIZE_T_FMT,
                       b->pos, b->end - b->last);

    } else {
        return NGX_DECLINED;
    }

    hc->busy[hc->nbusy++] = b;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %d", r->header_in->pos - old);

    new = b->start;

    ngx_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        r->method_end = new + (r->method_end - old);

        r->uri_start = new + (r->uri_start - old);
        r->uri_end = new + (r->uri_end - old);

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            r->schema_end = new + (r->schema_end - old);
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            r->host_end = new + (r->host_end - old);
        }

        if (r->port_start) {
            r->port_start = new + (r->port_start - old);
            r->port_end = new + (r->port_end - old);
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

    } else {
        r->header_name_start = new;
        r->header_name_end = new + (r->header_name_end - old);
        r->header_start = new + (r->header_start - old);
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = b;

    return NGX_OK;
}


static ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r)
{
    u_char                    *ua, *user_agent;
    size_t                     len;
    ngx_uint_t                 i;
    ngx_http_server_name_t    *name;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->headers_in.host) {
        for (len = 0; len < r->headers_in.host->value.len; len++) {
            if (r->headers_in.host->value.data[len] == ':') {
                break;
            }
        }
        r->headers_in.host_name_len = len;

        /* find the name based server configuration */

        name = r->virtual_names->elts;
        for (i = 0; i < r->virtual_names->nelts; i++) {
            if (r->headers_in.host_name_len != name[i].name.len) {
                continue;
            }

            if (ngx_strncasecmp(r->headers_in.host->value.data,
                                name[i].name.data,
                                r->headers_in.host_name_len) == 0)
            {
                r->srv_conf = name[i].core_srv_conf->ctx->srv_conf;
                r->loc_conf = name[i].core_srv_conf->ctx->loc_conf;
                r->server_name = &name[i].name;

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                r->connection->log->file = clcf->err_log->file;
                if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION))
                {
                    r->connection->log->log_level = clcf->err_log->log_level;
                }

                break;
            }
        }

        if (i == r->virtual_names->nelts) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            if (cscf->restrict_host_names != NGX_HTTP_RESTRICT_HOST_OFF) {
                return NGX_HTTP_PARSE_INVALID_HOST;
            }
        }

    } else {
        if (r->http_version > NGX_HTTP_VERSION_10) {
            return NGX_HTTP_PARSE_NO_HOST_HEADER;
        }
        r->headers_in.host_name_len = 0;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                             ngx_atoi(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            return NGX_HTTP_PARSE_INVALID_CL_HEADER;
        }
    }

    if (r->method == NGX_HTTP_POST && r->headers_in.content_length_n <= 0) {
        return NGX_HTTP_PARSE_POST_WO_CL_HEADER;
    }

    if (r->plain_http) {
        return NGX_HTTP_PARSE_HTTP_TO_HTTPS;
    }

    if (r->headers_in.connection) {
        if (r->headers_in.connection->value.len == 5
            && ngx_strcasecmp(r->headers_in.connection->value.data, "close")
                                                                          == 0)
        {
            r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

        } else if (r->headers_in.connection->value.len == 10
                   && ngx_strcasecmp(r->headers_in.connection->value.data,
                                                            "keep-alive") == 0)
        {
            r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;

            if (r->headers_in.keep_alive) {
                r->headers_in.keep_alive_n =
                                 ngx_atoi(r->headers_in.keep_alive->value.data,
                                          r->headers_in.keep_alive->value.len);
            }
        }
    }

    if (r->headers_in.user_agent) {

        /*
         * check some widespread browsers while the headers are still
         * in CPU cache
         */

        user_agent = r->headers_in.user_agent->value.data;

        ua = (u_char *) ngx_strstr(user_agent, "MSIE");

        if (ua && ua + 8 < user_agent + r->headers_in.user_agent->value.len) {

            r->headers_in.msie = 1;

            if (ua[4] == ' ' && ua[5] == '4' && ua[6] == '.') {
                r->headers_in.msie4 = 1;
            }

#if 0
            /* MSIE ignores the SSL "close notify" alert */

            ngx_ssl_set_nosendshut(r->connection->ssl);
#endif
        }

        if (ngx_strstr(user_agent, "Opera")) {
            r->headers_in.opera = 1;
            r->headers_in.msie = 0;
            r->headers_in.msie4 = 0;
        }

        if (!r->headers_in.msie && !r->headers_in.opera) {

            if (ngx_strstr(user_agent, "Gecko/")) {
                r->headers_in.gecko = 1;

            } else if (ngx_strstr(user_agent, "Konqueror")) {
                r->headers_in.konqueror = 1;
            }
        }
    }

    return NGX_OK;
}


void ngx_http_finalize_request(ngx_http_request_t *r, int rc)
{
    ngx_http_core_loc_conf_t  *clcf;

    /* r can be already destroyed when rc == NGX_DONE */

    if (rc == NGX_DONE || r->main) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalize request: %d", rc);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {

        if (r->connection->read->timer_set) {
            ngx_del_timer(r->connection->read);
        }

        if (r->connection->write->timer_set) {
            ngx_del_timer(r->connection->write);
        }

        if (rc == NGX_HTTP_CLIENT_CLOSED_REQUEST || r->closed) {
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(r->connection);
            return;
        }

        ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));

        return;

    } else if (rc == NGX_ERROR) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
        return;

    } else if (rc == NGX_AGAIN) {
        ngx_http_set_write_handler(r);
        return;
    }

    if (r->connection->read->timer_set) {
        ngx_del_timer(r->connection->read);
    }

    if (r->connection->write->timer_set) {
        r->connection->write->delayed = 0;
        ngx_del_timer(r->connection->write);
    }

    if (r->connection->read->pending_eof) {
#if (NGX_KQUEUE)
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log,
                       r->connection->read->kq_errno,
                       "kevent() reported about an closed connection");
#endif
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive != 0
         && clcf->keepalive_timeout > 0)
    {
        ngx_http_set_keepalive(r);
        return;

    } else if (r->lingering_close && clcf->lingering_timeout > 0) {
        ngx_http_set_lingering_close(r);
        return;
    }

    ngx_http_close_request(r, 0);
    ngx_http_close_connection(r->connection);
}


static void ngx_http_set_write_handler(ngx_http_request_t *r)
{
    ngx_event_t               *wev;
    ngx_http_core_loc_conf_t  *clcf;

    wev = r->connection->write;
    wev->event_handler = ngx_http_writer;

    r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

    if (wev->ready && wev->delayed) {
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                        ngx_http_core_module);
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    wev->available = clcf->send_lowat;
    if (ngx_handle_write_event(wev, NGX_LOWAT_EVENT) == NGX_ERROR) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
    }

    return;
}


void ngx_http_writer(ngx_event_t *wev)
{
    int                        rc;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http writer handler");

    c = wev->data;
    r = c->data;

    if (wev->timedout) {
        if (!wev->delayed) {
            ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
            return;
        }

        wev->timedout = 0;
        wev->delayed = 0;

        if (!wev->ready) {
            clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                ngx_http_core_module);
            ngx_add_timer(wev, clcf->send_timeout);

            wev->available = clcf->send_lowat;

            if (ngx_handle_write_event(wev, NGX_LOWAT_EVENT) == NGX_ERROR) {
                ngx_http_close_request(r, 0);
                ngx_http_close_connection(r->connection);
            }

            return;
        }

    } else {
        if (wev->delayed) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                           "http writer delayed");

            clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                ngx_http_core_module);
            wev->available = clcf->send_lowat;

            if (ngx_handle_write_event(wev, NGX_LOWAT_EVENT) == NGX_ERROR) {
                ngx_http_close_request(r, 0);
                ngx_http_close_connection(r->connection);
            }

            return;
        }
    }

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                  "http writer output filter: %d", rc);

    if (rc == NGX_AGAIN) {
        clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                            ngx_http_core_module);
        if (!wev->ready && !wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        wev->available = clcf->send_lowat;

        if (ngx_handle_write_event(wev, NGX_LOWAT_EVENT) == NGX_ERROR) {
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(r->connection);
        }

        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http writer done");

    ngx_http_finalize_request(r, rc);
}


static void ngx_http_block_read(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *r;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http read blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {
        if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            c = rev->data;
            r = c->data;
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(c);
        }
    }
}


ngx_int_t ngx_http_discard_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_event_t  *rev;

    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (r->headers_in.content_length_n <= 0) {
        return NGX_OK;
    }

    size = r->header_in->last - r->header_in->pos;

    if (size) {
        if (r->headers_in.content_length_n > size) {
            r->headers_in.content_length_n -= size;

        } else {
            r->header_in->pos += r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;
            return NGX_OK;
        }
    }

    rev->event_handler = ngx_http_read_discarded_body_event;

    if (ngx_handle_level_read_event(rev) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_read_discarded_body(r);
}


static void ngx_http_read_discarded_body_event(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = rev->data;
    r = c->data;

    rc = ngx_http_read_discarded_body(r);

    if (rc == NGX_AGAIN) {
        if (ngx_handle_level_read_event(rev) == NGX_ERROR) {
            ngx_http_close_request(r, rc);
            ngx_http_close_connection(c);
            return;
        }
    }

    if (rc != NGX_OK) {
        ngx_http_close_request(r, rc);
        ngx_http_close_connection(c);
    }
}


static ngx_int_t ngx_http_read_discarded_body(ngx_http_request_t *r)
{
    ssize_t  size, n;
    u_char   buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    if (r->headers_in.content_length_n == 0) {
        return NGX_OK;
    }


    size = r->headers_in.content_length_n;

    if (size > NGX_HTTP_DISCARD_BUFFER_SIZE) {
        size = NGX_HTTP_DISCARD_BUFFER_SIZE;
    }

    n = r->connection->recv(r->connection, buffer, size);

    if (n == NGX_ERROR) {

        r->closed = 1;

        /*
         * if a client request body is discarded then we already set
         * some HTTP response code for client and we can ignore the error
         */

        return NGX_OK;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    r->headers_in.content_length_n -= n;

    return NGX_OK;
}


static void ngx_http_set_keepalive(ngx_http_request_t *r)
{
    ngx_int_t                  i;
    ngx_buf_t                 *b, *f;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "closing request";

    hc = r->http_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /* move the large header buffers to the free list */

            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            if (hc->free == NULL) {
                hc->free = ngx_palloc(c->pool,
                  cscf->large_client_header_buffers.num * sizeof(ngx_buf_t *));

                if (hc->free == NULL) {
                    ngx_http_close_connection(c);
                    return;
                }
            }

            for (i = 0; i < hc->nbusy - 1; i++) {
                f = hc->busy[i];
                hc->free[hc->nfree++] = f;
                f->pos = f->start;
                f->last = f->start;
            }

            hc->busy[0] = b;
            hc->nbusy = 1;
        }
    }

    ngx_http_close_request(r, 0);
    c->data = hc;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (ngx_handle_level_read_event(rev) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->event_handler = ngx_http_empty_handler;

    if (b->pos < b->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        hc->pipeline = 1;
        ctx->action = "reading client pipelined request line";
        ngx_http_init_request(rev);
        return;
    }

    hc->pipeline = 0;

    if (ngx_pfree(c->pool, r) == NGX_OK) {
        hc->request = NULL;
    }

    b = c->buffer;

    if (ngx_pfree(c->pool, b->start) == NGX_OK) {
        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc free: " PTR_FMT " %d",
                   hc->free, hc->nfree);

    if (hc->free) {
        for (i = 0; i < hc->nfree; i++) {
            ngx_pfree(c->pool, hc->free[i]);
            hc->free[i] = NULL;
        }

        hc->nfree = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc busy: " PTR_FMT " %d",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (i = 0; i < hc->nbusy; i++) {
            ngx_pfree(c->pool, hc->busy[i]);
            hc->busy[i] = NULL;
        }

        hc->nbusy = 0;
    }

    rev->event_handler = ngx_http_keepalive_handler;

    if (wev->active) {
        if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_DISABLE_EVENT)
                                                                  == NGX_ERROR)
            {
                ngx_http_close_connection(c);
                return;
            }

        } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                ngx_http_close_connection(c);
                return;
            }
        }
    }

    ctx->action = "keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_http_close_connection(c);
            return;
        }
        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

#if 0
    /* if "keepalive_buffers off" then we need some other place */
    r->http_state = NGX_HTTP_KEEPALIVE_STATE;
#endif

    if (rev->ready) {
        ngx_http_keepalive_handler(rev);
    }
}


static void ngx_http_keepalive_handler(ngx_event_t *rev)
{
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_connection_t       *c;
    ngx_http_log_ctx_t     *ctx;
    ngx_http_connection_t  *hc;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout) {
        ngx_http_close_connection(c);
        return;
    }

    ctx = (ngx_http_log_ctx_t *) rev->log->data;

#if (HAVE_KQUEUE)

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %s closed "
                          "keepalive connection", ctx->client);
            ngx_http_close_connection(c);
            return;
        }
    }

#endif

    hc = c->data;
    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {
        if (!(b->pos = ngx_palloc(c->pool, size))) {
            ngx_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    rev->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %s closed keepalive connection", ctx->client);
        ngx_http_close_connection(c);
        return;
    }

    b->last += n;
    rev->log->handler = ngx_http_log_error;
    ctx->action = "reading client request line";

    ngx_http_init_request(rev);
}


static void ngx_http_set_lingering_close(ngx_http_request_t *r)
{   
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    rev = c->read;
    rev->event_handler = ngx_http_lingering_close_handler;

    r->lingering_time = ngx_time() + clcf->lingering_time / 1000;
    ngx_add_timer(rev, clcf->lingering_timeout);

    if (ngx_handle_level_read_event(rev) == NGX_ERROR) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->event_handler = ngx_http_empty_handler;

    if (wev->active) {
        if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_DISABLE_EVENT)
                                                                  == NGX_ERROR)
            {
                ngx_http_close_connection(c);
                return;
            }

        } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                ngx_http_close_connection(c);
                return;
            }
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    if (rev->ready) {
        ngx_http_lingering_close_handler(rev);
    }
}


static void ngx_http_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;
    u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    timer = r->lingering_time - ngx_time();
    if (timer <= 0) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %d", n);

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(c);
            return;
        }

    } while (rev->ready);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);

    return;
}


void ngx_http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


ngx_int_t ngx_http_send_last(ngx_http_request_t *r)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(b = ngx_calloc_buf(r->pool))) {
        return NGX_ERROR;
    }

    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


void ngx_http_close_request(ngx_http_request_t *r, int error)
{
    ngx_uint_t                 i;
    ngx_log_t                 *log;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_cleanup_t        *cleanup;
    ngx_http_core_loc_conf_t  *clcf;
    struct linger              l;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "http request already closed");
        return;
    }

#if (NGX_STAT_STUB)
    if (r->stat_reading) {
        (*ngx_stat_reading)--;
    }

    if (r->stat_writing) {
        (*ngx_stat_writing)--;
    }
#endif

    if (error && r->headers_out.status == 0) {
        r->headers_out.status = error;
    }

    ngx_http_log_handler(r);

    cleanup = r->cleanup.elts;
    for (i = 0; i < r->cleanup.nelts; i++) {
        if (!cleanup[i].valid) {
            continue;
        }

#if (NGX_HTTP_CACHE)

        if (cleanup[i].cache) {
            ngx_http_cache_unlock(cleanup[i].data.cache.hash,
                                  cleanup[i].data.cache.cache, log);
            continue;
        }

#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http cleanup fd: %d",
                       cleanup[i].data.file.fd);

        if (ngx_close_file(cleanup[i].data.file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed",
                          cleanup[i].data.file.name);
        }
    }

    /* STUB */
    if (r->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", r->file.name.data);
        }
    }

    if (r->request_body
        && r->request_body->temp_file
        && r->request_body->temp_file->file.fd != NGX_INVALID_FILE)
    {
        if (ngx_close_file(r->request_body->temp_file->file.fd)
                                                             == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " deleted file \"%s\" failed",
                          r->request_body->temp_file->file.name.data);
        }
    }

    if (r->connection->timedout) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->reset_timedout_connection) {
            l.l_onoff = 1;
            l.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &l, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* ctx->url was allocated from r->pool */
    ctx = log->data;
    ctx->url = NULL;

    r->request_line.len = 0;

    ngx_destroy_pool(r->pool);

    return;
}


#if (NGX_HTTP_SSL)

void ngx_ssl_close_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "http ssl close handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    ngx_http_close_connection(c);
}

#endif


void ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NGX_STAT_STUB)
    (*ngx_stat_active)--;
#endif

    ngx_close_connection(c);
}


static void ngx_http_client_error(ngx_http_request_t *r,
                                  int client_error, int error)
{
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_srv_conf_t  *cscf;

    ctx = r->connection->log->data;

    if (error == NGX_HTTP_REQUEST_TIME_OUT) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                      "client timed out");
        r->connection->timedout = 1;
        ngx_http_close_request(r, error);
        ngx_http_close_connection(r->connection);
        return;
    }

    r->connection->log->handler = NULL;

    if (ctx->url) {
        switch (client_error) {

        case NGX_HTTP_PARSE_INVALID_HOST:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    client_header_errors[client_error - NGX_HTTP_CLIENT_ERROR],
                    ctx->client, r->headers_in.host->value.data, ctx->url);

            error = NGX_HTTP_INVALID_HOST;

            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            if (cscf->restrict_host_names == NGX_HTTP_RESTRICT_HOST_CLOSE) {
                ngx_http_close_request(r, error);
                ngx_http_close_connection(r->connection);
                return;
            }

            break;

        case NGX_HTTP_PARSE_HTTP_TO_HTTPS:
            error = NGX_HTTP_TO_HTTPS;

            /* fall through */

        default:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    client_header_errors[client_error - NGX_HTTP_CLIENT_ERROR],
                    ctx->client, ctx->url);
        }

    } else {
        if (error == NGX_HTTP_REQUEST_URI_TOO_LARGE) {
            r->request_line.len = r->header_in->end - r->request_start;
            r->request_line.data = r->request_start;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    client_header_errors[client_error - NGX_HTTP_CLIENT_ERROR],
                    ctx->client);
    }

    r->connection->log->handler = ngx_http_log_error;

    ngx_http_finalize_request(r, error);
}


static size_t ngx_http_log_error(void *data, char *buf, size_t len)
{
    ngx_http_log_ctx_t *ctx = data;

    if (ctx->action && ctx->url) {
        return ngx_snprintf(buf, len, " while %s, client: %s, URL: %s",
                            ctx->action, ctx->client, ctx->url);

    } else if (ctx->action == NULL && ctx->url) {
        return ngx_snprintf(buf, len, ", client: %s, URL: %s",
                            ctx->client, ctx->url);

    } else {
        return ngx_snprintf(buf, len, " while %s, client: %s",
                            ctx->action, ctx->client);
    }
}
