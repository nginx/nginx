
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_init_request(ngx_event_t *ev);
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
static int ngx_http_process_request_header(ngx_http_request_t *r);

static void ngx_http_set_write_handler(ngx_http_request_t *r);

static void ngx_http_block_read(ngx_event_t *ev);
static void ngx_http_read_discarded_body_event(ngx_event_t *rev);
static int ngx_http_read_discarded_body(ngx_http_request_t *r);

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
    "client %s sent invalid \"Content-Length\" header, URL: %s"
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

    c->addr_text.data = ngx_palloc(c->pool, c->listening->addr_text_max_len);
    if (c->addr_text.data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->addr_text.len = ngx_sock_ntop(c->listening->family, c->sockaddr,
                                     c->addr_text.data,
                                     c->listening->addr_text_max_len);
    if (c->addr_text.len == 0) {
        ngx_http_close_connection(c);
        return;
    }

    if (!(ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t)))) {
        ngx_http_close_connection(c);
        return;
    }

    ctx->connection = c->number;
    ctx->client = c->addr_text.data;
    ctx->action = "reading client request line";
    c->log->data = ctx;
    c->log->handler = ngx_http_log_error;

    rev = c->read;
    rev->event_handler = ngx_http_init_request;
    rev->log_error = NGX_ERROR_INFO;

    /* STUB: epoll */ c->write->event_handler = ngx_http_empty_handler;

    if (rev->ready) {
        /* deferred accept, aio, iocp, epoll */
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
}


static void ngx_http_init_request(ngx_event_t *rev)
{
    ngx_int_t                  i;
    socklen_t                  len;
    struct sockaddr_in         addr_in;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_in_port_t        *in_port;
    ngx_http_in_addr_t        *in_addr;
    ngx_http_server_name_t    *server_name;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    c = rev->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    if (c->data) {
        r = c->data;
        ngx_memzero(r, sizeof(ngx_http_request_t));

    } else {
        if (!(r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)))) {
            ngx_http_close_connection(c);
            return;
        }
    }

    r->http_state = NGX_HTTP_INITING_REQUEST_STATE;

    /* find the server configuration for the address:port */

    /* AF_INET only */

    in_port = c->servers;
    in_addr = in_port->addrs.elts;

    r->port = in_port->port;
    r->port_name = &in_port->port_name;

    i = 0;

    if (in_port->addrs.nelts > 1) {

        /*
         * There are the several addresses on this port and one of them
         * is "*:port" so getsockname() is needed to determine
         * the server address.
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
                ngx_log_error(NGX_LOG_CRIT, rev->log, ngx_socket_errno,
                              "getsockname() failed");
                ngx_http_close_connection(c);
                return;
            }
#if (WIN32)
        }
#endif

        r->in_addr = addr_in.sin_addr.s_addr;

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

    server_name = cscf->server_names.elts;
    r->server_name = &server_name->name;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    c->log->file = clcf->err_log->file;
    c->log->log_level = clcf->err_log->log_level;

    if (c->buffer == NULL) {
        c->buffer = ngx_create_temp_hunk(c->pool,
                                         cscf->client_header_buffer_size);
        if (c->buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    if (!(r->pool = ngx_create_pool(cscf->request_pool_size, c->log))) {
        ngx_http_close_connection(c);
        return;
    }

    r->cleanup.elts = ngx_palloc(r->pool, 5 * sizeof(ngx_http_cleanup_t));
    if (r->cleanup.elts == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_close_connection(c);
        return;
    }
    /*
     * set by ngx_pcalloc():
     *
     * r->cleanup.nelts = 0;
     */
    r->cleanup.nalloc = 5;
    r->cleanup.size = sizeof(ngx_http_cleanup_t);
    r->cleanup.pool = r->pool;

    /* TODO: ngx_init_table */
    if (!(r->headers_out.headers = ngx_create_table(r->pool, 20))) {
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

    c->sent = 0;
    c->data = r;
    r->connection = c;
    r->pipeline = c->pipeline;
    r->header_in = c->buffer;

    r->file.fd = NGX_INVALID_FILE;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    rev->event_handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}


static void ngx_http_process_request_line(ngx_event_t *rev)
{
    char                      *p;
    ssize_t                    n;
    ngx_int_t                  rc, offset;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    if (rev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    n = ngx_http_read_request_header(r);

    if (n == NGX_AGAIN || n == NGX_ERROR) {
        return;
    }

    rc = ngx_http_parse_request_line(r);

    if (rc == NGX_OK) {

        /* the request line has been parsed successfully */

        /* TODO: we need to handle proxy URIs */
        if (r->unusual_uri) {
            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
#if 0
            r->request_line.data[r->request_line.len] = '\0';
#endif

            ngx_http_client_error(r, NGX_HTTP_PARSE_INVALID_REQUEST,
                                  NGX_HTTP_BAD_REQUEST);
            return;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (r->http_version >= NGX_HTTP_VERSION_10
            && cscf->large_client_header == 0
            && r->header_in->pos == r->header_in->end)
        {
            /* no space for "\r\n" at the end of the header */

            ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                  NGX_HTTP_REQUEST_URI_TOO_LARGE);
            return;
        }


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

        if (cscf->large_client_header) {

           /*
            * if the large client headers are enabled then
            * we need to copy the request line
            */

            r->request_line.data = ngx_palloc(r->pool, r->request_line.len + 1);
            if (r->request_line.data == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            ngx_cpystrn(r->request_line.data, r->request_start,
                        r->request_line.len + 1);

        } else {
            r->request_line.data = r->request_start;
            r->request_line.data[r->request_line.len] = '\0';
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
                       "http args: \"%s\"", r->args.data ? r->args.data : "");

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http exten: \"%s\"",
                       r->exten.data ? r->exten.data : "");

        if (r->http_version < NGX_HTTP_VERSION_10) {
            rev->event_handler = ngx_http_block_read;
            ngx_http_handler(r);
            return;
        }

        ctx = c->log->data;
        ctx->action = "reading client request headers";
        ctx->url = r->unparsed_uri.data;
        /* TODO: ngx_init_table */
        r->headers_in.headers = ngx_create_table(r->pool, 20);

        if (cscf->large_client_header
            && r->header_in->pos == r->header_in->last)
        {
            r->header_in->pos = r->header_in->last = r->header_in->start;
        }

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

    /* NGX_AGAIN: a request line parsing is still not complete */

    if (r->header_in->last == r->header_in->end) {

        /*
         * If it's a pipelined request and a request line is not complete
         * then we have to copy it to the start of the r->header_in hunk.
         * We have to copy it here only if the large client headers
         * are enabled otherwise a request line had been already copied
         * to the start of the r->header_in hunk in ngx_http_set_keepalive().
         */

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->large_client_header) {
            offset = r->request_start - r->header_in->start;

            if (offset == 0) {
                ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                      NGX_HTTP_REQUEST_URI_TOO_LARGE);
                return;
            }

            ngx_memcpy(r->header_in->start, r->request_start,
                       r->header_in->last - r->request_start);

            r->header_in->pos -= offset;
            r->header_in->last -= offset;
            r->request_start = r->header_in->start;
            r->request_end -= offset;
            r->uri_start -= offset;
            r->uri_end -= offset;
            if (r->uri_ext) {
                r->uri_ext -= offset;
            }
            if (r->args_start) {
                r->args_start -= offset;
            }

        } else {
            ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                  NGX_HTTP_REQUEST_URI_TOO_LARGE);
        }
    }

    return;
}


static void ngx_http_process_request_headers(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_int_t                  rc, i, offset;
    ngx_table_elt_t           *h;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    if (rev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    rc = NGX_AGAIN;

    for ( ;; ) {
        if (rc == NGX_AGAIN) {
            n = ngx_http_read_request_header(r);

            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        rc = ngx_http_parse_header_line(r, r->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_http_add_header(&r->headers_in, ngx_http_headers_in);
            if (h == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            /* if the large client headers are enabled then
               we need to copy the header name and value */

            if (cscf->large_client_header) {
                h->key.data = ngx_palloc(r->pool,
                                         h->key.len + 1 + h->value.len + 1);
                if (h->key.data == NULL) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    ngx_http_close_connection(c);
                    return;
                }

                h->value.data = h->key.data + h->key.len + 1;
                ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
                ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            } else {
                h->key.data = r->header_name_start;
                h->key.data[h->key.len] = '\0';
                h->value.data = r->header_start;
                h->value.data[h->value.len] = '\0';
            }

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

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%s: %s\"",
                           h->key.data, h->value.data);

            if (cscf->large_client_header
                && r->header_in->pos == r->header_in->last)
            {
                r->header_in->pos = r->header_in->last = r->header_in->start;
            }

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                ngx_http_client_error(r, rc, NGX_HTTP_BAD_REQUEST);
                return;
            }

            if (rev->timer_set) {
                ngx_del_timer(rev);
            }

            rev->event_handler = ngx_http_block_read;
            ngx_http_handler(r);
            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

#if (NGX_LOG_DEBUG)
            if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {
                char  *p;
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

        if (r->header_in->last == r->header_in->end) {

            /* if the large client headers are enabled then
                we need to compact r->header_in hunk */

            if (cscf->large_client_header) {
                offset = r->header_name_start - r->header_in->start;

                if (offset == 0) {
                    ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_HEADER,
                                          NGX_HTTP_BAD_REQUEST);
                    return;
                }

                ngx_memcpy(r->header_in->start, r->header_name_start,
                           r->header_in->last - r->header_name_start);

                r->header_in->last -= offset;
                r->header_in->pos -= offset;
                r->header_name_start = r->header_in->start;
                r->header_name_end -= offset;
                r->header_start -= offset;
                r->header_end -= offset;

            } else {
                ngx_http_client_error(r, NGX_HTTP_PARSE_TOO_LONG_HEADER,
                                      NGX_HTTP_BAD_REQUEST);
                return;
            }
        }
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

    n = ngx_recv(r->connection, r->header_in->last,
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


static ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r)
{
    size_t                     len;
    ngx_int_t                  i;
    ngx_http_server_name_t    *name;
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

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                r->connection->log->file = clcf->err_log->file;
                r->connection->log->log_level = clcf->err_log->log_level;

                break;
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

    return NGX_OK;
}


void ngx_http_finalize_request(ngx_http_request_t *r, int rc)
{
    ngx_http_core_loc_conf_t  *clcf;

    /* r can be already destroyed when rc == NGX_DONE */

    if (rc == NGX_DONE || r->main) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalize request");

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {

        if (r->connection->read->timer_set) {
            ngx_del_timer(r->connection->read);
        }

        if (r->connection->write->timer_set) {
            ngx_del_timer(r->connection->write);
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
        ngx_del_timer(r->connection->write);
    }

    if (r->connection->read->kq_eof) {
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
         && !ngx_quit
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

    if (wev->delayed && wev->ready) {
        return;
    }

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


void ngx_http_writer(ngx_event_t *wev)
{
    int                        rc;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http writer handler");

    c = wev->data;
    r = c->data;

#if 0 /* TODO: THINK */
    if (wev->delayed) {
        return;
    }
#endif

    if (wev->timedout) {
        ngx_http_client_error(r, 0, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                  "http writer output filter: %d", rc);

    if (rc == NGX_AGAIN) {
        if (!wev->ready) {
            clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                ngx_http_core_module);
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_level_write_event(wev) == NGX_ERROR) {
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


int ngx_http_discard_body(ngx_http_request_t *r)
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

    return NGX_OK;
}


static void ngx_http_read_discarded_body_event(ngx_event_t *rev)
{
    int                  rc;
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


static int ngx_http_read_discarded_body(ngx_http_request_t *r)
{
    ssize_t                    size, n;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    if (r->headers_in.content_length_n == 0) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->discarded_buffer == NULL) {
        r->discarded_buffer = ngx_palloc(r->pool, clcf->discarded_buffer_size);
        if (r->discarded_buffer == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    size = r->headers_in.content_length_n;

    if (size > clcf->discarded_buffer_size) {
        size = clcf->discarded_buffer_size;
    }

    n = ngx_recv(r->connection, r->discarded_buffer, size);
    if (n == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    r->headers_in.content_length_n -= n;

    return NGX_OK;
}


static void ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                        len;
    ngx_hunk_t                *h;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "closing request";
    ngx_http_close_request(r, 0);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (ngx_handle_level_read_event(rev) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    h = c->buffer;

    if (h->pos < h->last) {

        /*
         * Pipelined request.
         *
         * We do not know here whether the pipelined request is complete
         * so if the large client headers are not enabled
         * we need to copy the data to the start of c->buffer.
         * This copy should be rare because clients that support
         * pipelined requests (Mozilla 1.x, Opera 6.x+) are still rare.
         */

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (!cscf->large_client_header) {
            len = h->last - h->pos;
            ngx_memcpy(h->start, h->pos, len);
            h->pos = h->start;
            h->last = h->start + len;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->pipeline = 1;
        ctx->action = "reading client pipelined request line";
        ngx_http_init_request(rev);
        return;
    }

    c->pipeline = 0;

    h->pos = h->last = h->start;
    rev->event_handler = ngx_http_keepalive_handler;
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

    ctx->action = "keepalive";

    if (c->tcp_nopush == 1) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
                ngx_http_close_connection(c);
                return;
        }
        c->tcp_nopush = 0;
    }

    if (rev->ready) {
        ngx_http_keepalive_handler(rev);
    }
}


static void ngx_http_keepalive_handler(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout) {
        ngx_http_close_connection(c);
        return;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    rev->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);
    n = ngx_recv(c, c->buffer->last, c->buffer->end - c->buffer->last);
    rev->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    ctx = (ngx_http_log_ctx_t *) rev->log->data;
    rev->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %s closed keepalive connection", ctx->client);
        ngx_http_close_connection(c);
        return;
    }

    c->buffer->last += n;
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

    r->lingering_time = ngx_cached_time + clcf->lingering_time / 1000;
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
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
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

    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    timer = r->lingering_time - ngx_cached_time;
    if (timer <= 0) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->discarded_buffer == NULL) {

        /* TODO: r->header_in->start (if large headers are enabled)
                 or the end of parsed header (otherwise)
                 instead of r->header_in->last */

        if (r->header_in->end - r->header_in->last
                                              >= clcf->discarded_buffer_size) {
            r->discarded_buffer = r->header_in->last;

        } else {
            r->discarded_buffer = ngx_palloc(c->pool,
                                             clcf->discarded_buffer_size);
            if (r->discarded_buffer) {
                ngx_http_close_request(r, 0);
                ngx_http_close_connection(c);
                return;
            }
        }
    }

    do {
        n = ngx_recv(c, r->discarded_buffer, clcf->discarded_buffer_size);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %d", n);

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(c);
            return;
        }

    } while (rev->ready);

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


int ngx_http_send_last(ngx_http_request_t *r)
{
    ngx_hunk_t   *h;
    ngx_chain_t   out;

    ngx_test_null(h, ngx_calloc_hunk(r->pool), NGX_ERROR);
    h->type = NGX_HUNK_LAST;
    out.hunk = h;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


void ngx_http_close_request(ngx_http_request_t *r, int error)
{
    ngx_int_t            i;
    ngx_log_t           *log;
    ngx_http_log_ctx_t  *ctx;
    ngx_http_cleanup_t  *cleanup;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "http request already closed");
        return;
    }

    if (error && r->headers_out.status == 0) {
        r->headers_out.status = error;
    }

    ngx_http_log_handler(r);

    cleanup = r->cleanup.elts;
    for (i = 0; i < r->cleanup.nelts; i++) {
        if (!cleanup[i].valid) {
            continue;
        }

        if (cleanup[i].cache) {
            ngx_http_cache_unlock(cleanup[i].data.cache.hash,
                                  cleanup[i].data.cache.cache, log);
            continue;
        }

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

    /* ctx->url was allocated from r->pool */
    ctx = log->data;
    ctx->url = NULL;

    ngx_destroy_pool(r->pool);

    return;
}


void ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close connection: %d", c->fd);

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (ngx_del_conn) {
        ngx_del_conn(c);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

    if (ngx_close_socket(c->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    c->fd = -1;
    c->data = NULL;

    ngx_destroy_pool(c->pool);

    return;
}


static void ngx_http_client_error(ngx_http_request_t *r,
                                  int client_error, int error)
{
    ngx_http_log_ctx_t  *ctx;

    ctx = r->connection->log->data;

    if (error == NGX_HTTP_REQUEST_TIME_OUT) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                      "client timed out");
        ngx_http_close_request(r, error);
        ngx_http_close_connection(r->connection);
        return;
    }

    r->connection->log->handler = NULL;

    if (ctx->url) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    client_header_errors[client_error - NGX_HTTP_CLIENT_ERROR],
                    ctx->client, ctx->url);

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
