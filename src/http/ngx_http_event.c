
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


static void ngx_http_init_request(ngx_event_t *ev);
static void ngx_http_process_request_line(ngx_event_t *rev);
static void ngx_http_process_request_headers(ngx_event_t *rev);
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);

static void ngx_http_writer(ngx_event_t *ev);

static void ngx_http_block_read(ngx_event_t *ev);
static void ngx_http_read_discarded_body_event(ngx_event_t *rev);
static int ngx_http_read_discarded_body(ngx_http_request_t *r);

static void ngx_http_set_keepalive(ngx_http_request_t *r);
static void ngx_http_keepalive_handler(ngx_event_t *ev);
static void ngx_http_set_lingering_close(ngx_http_request_t *r);
static void ngx_http_lingering_close_handler(ngx_event_t *ev);
static void ngx_http_empty_handler(ngx_event_t *wev);

static void ngx_http_header_parse_error(ngx_http_request_t *r, int parse_err);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);


/* NGX_HTTP_PARSE_ ... errors */

static char *header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent too long URI",
    "client %s sent invalid method in HTTP/0.9 request",

    "client %s sent invalid header, URL: %s",
    "client %s sent too long header line, URL: %s",
    "client %s sent HTTP/1.1 request without \"Host\" header, URL: %s",
    "client %s sent invalid \"Content-Length\" header, URL: %s"
};



static ngx_http_header_t headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host) },
    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection) },
    { ngx_string("If-Modified-Since"),
                         offsetof(ngx_http_headers_in_t, if_modified_since) },
    { ngx_string("Content-Length"),
                            offsetof(ngx_http_headers_in_t, content_length) },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range) },
#if 0
    { ngx_string("If-Range"), offsetof(ngx_http_headers_in_t, if_range) },
#endif

    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent) },

    { ngx_null_string, 0 }
};


void ngx_http_init_connection(ngx_connection_t *c)
{
    int                  event;
    ngx_event_t         *rev;
    ngx_http_log_ctx_t  *lcx;

    c->addr_text.data = ngx_palloc(c->pool, c->addr_text_max_len);
    if (c->addr_text.data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->addr_text.len = ngx_sock_ntop(c->family, c->sockaddr,
                                     c->addr_text.data, c->addr_text_max_len);
    if (c->addr_text.len == 0) {
        ngx_http_close_connection(c);
        return;
    }

    lcx = ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (lcx == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    lcx->client = c->addr_text.data;
    lcx->action = "reading client request line";
    c->log->data = lcx;
    c->log->handler = ngx_http_log_error;

    rev = c->read;
    rev->event_handler = ngx_http_init_request;

    if (rev->ready) {
        /* deferred accept */
        ngx_http_init_request(rev);
        return;
    }

    ngx_add_timer(rev, c->post_accept_timeout);
    rev->timer_set = 1;

    if (ngx_event_flags & (NGX_HAVE_AIO_EVENT|NGX_HAVE_EDGE_EVENT)) {
        /* aio, iocp, epoll */
        ngx_http_init_request(rev);
        return;
    }

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        /* kqueue */
        event = NGX_CLEAR_EVENT;

    } else {
        /* select, poll, /dev/poll */
        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NGX_READ_EVENT, event) == NGX_ERROR) {
        ngx_http_close_connection(c);
    }
}


static void ngx_http_init_request(ngx_event_t *rev)
{
    int                        i;
    socklen_t                  len;
    struct sockaddr_in         addr_in;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_in_port_t        *in_port;
    ngx_http_in_addr_t        *in_addr;
    ngx_http_server_name_t    *server_name;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;

    r = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    /* find the server configuration for the address:port */

    /* AF_INET only */

    in_port = c->servers;
    in_addr = in_port->addrs.elts;

    r->port = in_port->port;
    r->port_name = &in_port->port_name;

    i = 0;

    if (in_port->addrs.nelts > 1) {

        /* there're the several addresses on this port and one of them
           is "*:port" so getsockname() is needed to determine
           the server address */

        /* TODO: AcceptEx() already gave this sockaddr_in */

        len = sizeof(struct sockaddr_in);
        if (getsockname(c->fd, (struct sockaddr *) &addr_in, &len) == -1) {
            ngx_log_error(NGX_LOG_CRIT, rev->log, ngx_socket_errno,
                          "getsockname() failed");
            ngx_http_close_connection(c);
            return;
        }

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

    if (c->buffer == NULL) {
        c->buffer = ngx_create_temp_hunk(c->pool,
                                         cscf->client_header_buffer_size,
                                         0, 0);
        if (c->buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    r->pool = ngx_create_pool(cscf->request_pool_size, c->log);
    if (r->pool == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    r->headers_out.headers = ngx_create_table(r->pool, 10);
    if (r->headers_out.headers == NULL) {
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
    r->headers_out.content_length = -1;
    r->headers_out.last_modified_time = -1;

    rev->event_handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}


static void ngx_http_process_request_line(ngx_event_t *rev)
{
    int                        rc, offset;
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *lcx;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    r = c->data;

    ngx_log_debug(rev->log, "http process request line");

    if (rev->timedout) {
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        ngx_http_close_connection(c);
        return;
    }

    n = ngx_http_read_request_header(r);

    if (n == NGX_AGAIN || n == NGX_ERROR) {
        return;
    }

    rc = ngx_parse_http_request_line(r);

    if (rc == NGX_OK) {

        /* the request line has been parsed successfully */

        /* STUB: we need to handle such URIs */
        if (r->complex_uri || r->unusual_uri) {
            ngx_http_header_parse_error(r, NGX_HTTP_PARSE_INVALID_REQUEST);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (r->http_version >= NGX_HTTP_VERSION_10
            && cscf->large_client_header == 0
            && r->header_in->pos == r->header_in->end)
        {
            /* no space for "\r\n" at the end of the header */

            ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI);
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
            return;
        }

        /* copy URI */

        if (r->args_start) {
            r->uri.len = r->args_start - 1 - r->uri_start;
        } else {
            r->uri.len = r->uri_end - r->uri_start;
        }

        r->uri.data = ngx_palloc(r->pool, r->uri.len + 1);
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            ngx_http_close_connection(c);
            return;
        }

        ngx_cpystrn(r->uri.data, r->uri_start, r->uri.len + 1);

#if 1 /* THINK: needed to log url on errors in proxy only ? */

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

#endif

        r->request_line.len = r->request_end - r->request_start;

        /* if the large client headers are enabled then
           we need to copy a request line */

        if (cscf->large_client_header) {

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

        /* copy URI extention if it exists */

        if (r->uri_ext) {
            if (r->args_start) {
                r->exten.len = r->args_start - 1 - r->uri_ext;
            } else {
                r->exten.len = r->uri_end - r->uri_ext;
            }

            r->exten.data = ngx_palloc(r->pool, r->exten.len + 1);
            if (r->exten.data == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            ngx_cpystrn(r->exten.data, r->uri_ext, r->exten.len + 1);
        }

        /* copy URI arguments if they exist */

        if (r->args_start && r->uri_end > r->args_start) {
            r->args.len = r->uri_end - r->args_start;

            r->args.data = ngx_palloc(r->pool, r->args.len + 1);
            if (r->args.data == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(c);
                return;
            }

            ngx_cpystrn(r->args.data, r->args_start, r->args.len + 1);
        }

#if 1 /* DEBUG */
        if (r->exten.data == NULL) { r->exten.data = ""; }
        if (r->args.data == NULL) { r->args.data = ""; }
        ngx_log_debug(c->log, "HTTP: %d, %d, '%s', '%s', '%s'" _
                      r->method _ r->http_version _
                      r->uri.data _ r->exten.data _ r->args.data);
        if (r->exten.data[0] == '\0') { r->exten.data = NULL; }
        if (r->args.data[0] == '\0') { r->args.data = NULL; }
#endif

        if (r->http_version < NGX_HTTP_VERSION_10) {
            rev->event_handler = ngx_http_block_read;
            ngx_http_handler(r);
            return;
        }

        lcx = c->log->data;
        lcx->action = "reading client request headers";
        lcx->url = r->unparsed_uri.data;
        r->headers_in.headers = ngx_create_table(r->pool, 10);

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

        ngx_http_header_parse_error(r, rc);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

        return;
    }

    /* NGX_AGAIN: a request line parsing is still not complete */

    if (r->header_in->last == r->header_in->end) {

        /* If it's a pipelined request and a request line is not complete
           then we need to copy it to the start of the r->header_in hunk.
           We need to copy it here only if the large client headers
           are enabled otherwise a request line had been already copied
           to the start of the r->header_in hunk in ngx_http_set_keepalive() */

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->large_client_header) {
            offset = r->request_start - r->header_in->start;

            if (offset == 0) {
                ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI);
                ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);

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
            ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI);
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
        }
    }

    return;
}


static void ngx_http_process_request_headers(ngx_event_t *rev)
{
    int                        rc, i, offset;
    size_t                     len;
    ssize_t                    n;
    ngx_table_elt_t           *h;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_server_name_t    *name;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    r = c->data;

    ngx_log_debug(rev->log, "http process request header line");

    if (rev->timedout) {
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        ngx_http_close_connection(c);
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

        rc = ngx_parse_http_header_line(r, r->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_push_table(r->headers_in.headers);
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

            for (i = 0; headers_in[i].name.len != 0; i++) {
                if (headers_in[i].name.len != h->key.len) {
                    continue;
                }

                if (ngx_strcasecmp(headers_in[i].name.data, h->key.data) == 0) {
                    *((ngx_table_elt_t **)
                        ((char *) &r->headers_in + headers_in[i].offset)) = h;
                }
            }

            ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                          h->key.data _ h->value.data);

            if (cscf->large_client_header
                && r->header_in->pos == r->header_in->last)
            {
                r->header_in->pos = r->header_in->last = r->header_in->start;
            }

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug(r->connection->log, "HTTP header done");

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
                        break;
                    }
                }

            } else {
                if (r->http_version > NGX_HTTP_VERSION_10) {
                    ngx_http_header_parse_error(r,
                                                NGX_HTTP_PARSE_NO_HOST_HEADER);
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                    return;
                }
                r->headers_in.host_name_len = 0;
            }

            if (r->headers_in.content_length) {
                r->headers_in.content_length_n =
                             ngx_atoi(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);
                if (r->headers_in.content_length_n == NGX_ERROR) {
                    ngx_http_header_parse_error(r,
                                             NGX_HTTP_PARSE_INVALID_CL_HEADER);
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                    return;
                }
            }

            rev->event_handler = ngx_http_block_read;
            ngx_http_handler(r);
            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

            ngx_http_header_parse_error(r, rc);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

            return;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

        if (r->header_in->last == r->header_in->end) {

            /* if the large client headers are enabled then
                we need to compact r->header_in hunk */

            if (cscf->large_client_header) {
                offset = r->header_name_start - r->header_in->start;

                if (offset == 0) {
                    ngx_http_header_parse_error(r,
                                                NGX_HTTP_PARSE_TOO_LONG_HEADER);
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
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
                ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_HEADER);
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return;
            }
        }
    }
}


static ssize_t ngx_http_read_request_header(ngx_http_request_t *r)
{
    int                        event;
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_http_core_srv_conf_t  *cscf;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    n = ngx_event_recv(r->connection, r->header_in->last,
                       r->header_in->end - r->header_in->last);

    if (n == NGX_AGAIN) {
        rev = r->connection->read;

        if (!r->header_timeout_set) {
            if (rev->timer_set) {
                ngx_del_timer(rev);
            } else {
                rev->timer_set = 1;
            }

            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            ngx_add_timer(rev, cscf->client_header_timeout);
            r->header_timeout_set = 1;
        }

        if (!rev->active) {
            if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
                /* kqueue */
                event = NGX_CLEAR_EVENT;

            } else {
                /* select, poll, /dev/poll */
                event = NGX_LEVEL_EVENT;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, event) == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                ngx_http_close_connection(r->connection);
                return NGX_ERROR;
            }
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


void ngx_http_finalize_request(ngx_http_request_t *r, int error)
{
    int           rc;
    ngx_event_t  *rev, *wev;

    rc = error;

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {

        rev = r->connection->read;
        if (rev->timer_set) {
            ngx_del_timer(rev);
            rev->timer_set = 0;
        }

        wev = r->connection->write;
        if (wev->timer_set) {
            ngx_del_timer(wev);
            wev->timer_set = 0;
        }

        rc = ngx_http_special_response_handler(r, rc);
    }

    rev = r->connection->read;
    if (rev->timer_set) {
        ngx_del_timer(rev);
        rev->timer_set = 0;
    }

    wev = r->connection->write;
    if (wev->timer_set) {
        ngx_del_timer(wev);
        wev->timer_set = 0;
    }

    if (r->keepalive != 0) {
        ngx_http_set_keepalive(r);

    } else if (r->lingering_close) {
        ngx_http_set_lingering_close(r);

    } else {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
    }
}


void ngx_http_set_write_handler(ngx_http_request_t *r)
{
    int                        event;
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
    wev->timer_set = 1;

    if (ngx_event_flags & (NGX_HAVE_AIO_EVENT|NGX_HAVE_EDGE_EVENT)) {
        /* aio, iocp, epoll */
        return;
    }

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */

    if (ngx_event_flags & NGX_HAVE_LOWAT_EVENT) {
        wev->lowat = clcf->send_lowat;
    }

#endif

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        /* kqueue */
        event = NGX_CLEAR_EVENT;

    } else {
        /* select, poll, /dev/poll */
        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(wev, NGX_WRITE_EVENT, event) == NGX_ERROR) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
    }
}


static void ngx_http_writer(ngx_event_t *wev)
{
    int                        rc;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    c = wev->data;
    r = c->data;

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug(c->log, "writer output filter: %d" _ rc);

    if (rc == NGX_AGAIN) {

        clcf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                           ngx_http_core_module);
        if (wev->timer_set) {
            ngx_del_timer(wev);
        } else {
            wev->timer_set = 1;
        }

        ngx_add_timer(wev, clcf->send_timeout);

        return;
    }

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    /* rc == NGX_OK */

    ngx_log_debug(c->log, "http writer done");

    rev = r->connection->read;
    if (rev->timer_set) {
        ngx_del_timer(rev);
        rev->timer_set = 0;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
        wev->timer_set = 0;
    }

    if (r->keepalive != 0) {
        ngx_http_set_keepalive(r);

    } else if (r->lingering_close) {
        ngx_http_set_lingering_close(r);

    } else {
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(r->connection);
    }
}


static void ngx_http_block_read(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *r;

    ngx_log_debug(rev->log, "http read blocked");

    /* aio does not call this handler */

    if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        rev->blocked = 1;

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            c = (ngx_connection_t *) rev->data;
            r = (ngx_http_request_t *) c->data;
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(c);
        }
    }

    /* kqueue, epoll */

    return;
}


int ngx_http_discard_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_event_t  *rev;

    rev = r->connection->read;

    ngx_log_debug(rev->log, "set discard body");

    if (rev->timer_set) {
        ngx_del_timer(rev);
        rev->timer_set = 0;
    }

    if (r->headers_in.content_length_n > 0) {

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

        if (rev->blocked) {
            if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
                if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            rev->blocked = 0;
            return ngx_http_read_discarded_body(r);
        }
    }

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

    if (rc != NGX_OK) {
        ngx_http_close_request(r, rc);
        ngx_http_close_connection(c);
    }
}


static int ngx_http_read_discarded_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug(r->connection->log, "http read discarded body");

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

    n = ngx_event_recv(r->connection, r->discarded_buffer, size);
    if (n == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    r->headers_in.content_length_n -= n;

    return NGX_OK;
}


static void ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                        len, blocked;
    ngx_hunk_t                *h;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    ngx_log_debug(c->log, "set http keepalive handler");

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "closing request";
    ngx_http_close_request(r, 0);

    if (rev->timer_set) {
        ngx_del_timer(rev);
    } else {
        rev->timer_set = 1;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (rev->blocked && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR) {
            ngx_http_close_connection(c);
            return;
        }

        blocked = 1;
        rev->blocked = 0;

    } else {
        blocked = 0;
    }

    h = c->buffer;

    /* pipelined request */
    if (h->pos < h->last) {

        /* We do not know here whether a pipelined request is complete
           so if the large client headers are not enabled
           we need to copy the data to the start of c->buffer.
           This copy should be rare because clients that support
           pipelined requests (Mozilla 1.x, Opera 6.x) are still rare */

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (!cscf->large_client_header) {
            len = h->last - h->pos;
            ngx_memcpy(h->start, h->pos, len);
            h->pos = h->start;
            h->last = h->start + len;
        }

        ngx_log_debug(c->log, "pipelined request");

        c->pipeline = 1;
        ctx->action = "reading client pipelined request line";
        ngx_http_init_request(rev);
        return;
    }

    c->pipeline = 0;

    h->pos = h->last = h->start;
    rev->event_handler = ngx_http_keepalive_handler;
    wev = c->write;

    if (wev->active) {
        if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                ngx_http_close_connection(c);
                return;
            }

        } else if ((ngx_event_flags & NGX_HAVE_AIO_EVENT) == 0) {
            wev->event_handler = ngx_http_empty_handler;
        }
    }

    ctx->action = "keepalive";

    if ((ngx_event_flags & NGX_HAVE_AIO_EVENT) || blocked) {
        ngx_http_keepalive_handler(rev);
    }
}


static void ngx_http_keepalive_handler(ngx_event_t *rev)
{
    ssize_t n;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *lctx;

    c = (ngx_connection_t *) rev->data;

    ngx_log_debug(c->log, "http keepalive handler");

    if (rev->timedout) {
        ngx_http_close_connection(c);
        return;
    }

    /* MSIE closes a keepalive connection with RST flag
       so we ignore ECONNRESET here */

    rev->ignore_econnreset = 1;
    ngx_set_socket_errno(0);
    n = ngx_event_recv(c, c->buffer->last, c->buffer->end - c->buffer->last);
    rev->ignore_econnreset = 0;

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    lctx = (ngx_http_log_ctx_t *) rev->log->data;
    rev->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %s closed keepalive connection", lctx->client);
        ngx_http_close_connection(c);
        return;
    }

    c->buffer->last += n;
    rev->log->handler = ngx_http_log_error;
    lctx->action = "reading client request line";

    ngx_http_init_request(rev);
}


static void ngx_http_set_lingering_close(ngx_http_request_t *r)
{
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    r->lingering_time = ngx_time() + clcf->lingering_time / 1000;
    rev->event_handler = ngx_http_lingering_close_handler;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    } else {
        rev->timer_set = 1;
    }

    ngx_add_timer(rev, clcf->lingering_timeout);

    if (rev->blocked && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR) {
            ngx_http_close_request(r, 0);
            ngx_http_close_connection(c);
            return;
        }
        rev->blocked = 0;
    }

    if (c->write->active) {
        if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
            if (ngx_del_event(c->write, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                ngx_http_close_request(r, 0);
                ngx_http_close_connection(c);
                return;
            }

        } else if ((ngx_event_flags & NGX_HAVE_AIO_EVENT) == 0) {
            c->write->event_handler = ngx_http_empty_handler;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                      ngx_shutdown_socket_n " failed");
        ngx_http_close_request(r, 0);
        ngx_http_close_connection(c);
        return;
    }

    if (rev->ready || (ngx_event_flags & NGX_HAVE_AIO_EVENT)) {
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

    ngx_log_debug(c->log, "http lingering close handler");

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

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->discarded_buffer == NULL) {

        /* TODO: r->header_in->start (if large headers are enabled)
                 or the end of parsed header (otherwise)
                 instead of r->header_in->last */

        if ((size_t)(r->header_in->end - r->header_in->last)
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
        n = ngx_event_recv(c, r->discarded_buffer, clcf->discarded_buffer_size);

        ngx_log_debug(c->log, "lingering read: %d" _ n);

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

    if (rev->timer_set) {
        ngx_del_timer(rev);
    } else {
        rev->timer_set = 1;
    }
    ngx_add_timer(rev, timer);

    return;
}


static void ngx_http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug(wev->log, "http empty handler");

    return;
}


void ngx_http_close_request(ngx_http_request_t *r, int error)
{
    ngx_http_log_ctx_t  *ctx;

    ngx_log_debug(r->connection->log, "close http request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "http request already closed");
        return;
    }

    if (error) {
        r->headers_out.status = error;
    }

    ngx_http_log_handler(r);

    if (r->file.fd != NGX_INVALID_FILE) {
        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", r->file.name.data);
        }
    }

    /* ctx->url was allocated from r->pool */
    ctx = (ngx_http_log_ctx_t *) r->connection->log->data;
    ctx->url = NULL;

    ngx_destroy_pool(r->pool);
}


void ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_log_debug(c->log, "close connection: %d" _ c->fd);

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
        c->read->timer_set = 0;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
        c->write->timer_set = 0;
    }

    if (ngx_del_conn) {
        ngx_del_conn(c);

    } else {
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

    if (ngx_close_socket(c->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    c->fd = -1;

    ngx_destroy_pool(c->pool);
}


static void ngx_http_header_parse_error(ngx_http_request_t *r, int parse_err)
{
    ngx_http_log_ctx_t  *ctx;

    ctx = r->connection->log->data;
    r->connection->log->handler = NULL;

    if (ctx->url) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      header_errors[parse_err - NGX_HTTP_PARSE_INVALID_METHOD],
                      ctx->client, ctx->url);

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      header_errors[parse_err - NGX_HTTP_PARSE_INVALID_METHOD],
                      ctx->client);
    }

    r->connection->log->handler = ngx_http_log_error;
}


static size_t ngx_http_log_error(void *data, char *buf, size_t len)
{
    ngx_http_log_ctx_t *ctx = (ngx_http_log_ctx_t *) data;

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
