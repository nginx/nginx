
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>
#include <ngx_inet.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>
#include <ngx_http_output_filter.h>


static int ngx_http_init_request(ngx_event_t *ev);
static int ngx_http_process_request_header(ngx_event_t *ev);

static int ngx_http_process_request_line(ngx_http_request_t *r);
static int ngx_http_process_request_headers(ngx_http_request_t *r);
static int ngx_http_process_request_header_line(ngx_http_request_t *r);

static int ngx_http_event_request_handler(ngx_http_request_t *r);

static int ngx_http_writer(ngx_event_t *ev);
static int ngx_http_block_read(ngx_event_t *ev);
static int ngx_http_read_discarded_body(ngx_event_t *ev);
static int ngx_http_set_keepalive(ngx_http_request_t *r);
static int ngx_http_keepalive_handler(ngx_event_t *ev);
static int ngx_http_set_lingering_close(ngx_http_request_t *r);
static int ngx_http_lingering_close_handler(ngx_event_t *ev);

static int ngx_http_close_connection(ngx_event_t *ev);
static int ngx_http_header_parse_error(ngx_http_request_t *r,
                                       int parse_err, int err);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);



static char *header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent too long URI",
    "client %s sent HEAD method in HTTP/0.9 request",

    "client %s sent invalid header, URL: %s",
    "client %s sent too long header line, URL: %s",
    "client %s sent HTTP/1.1 request without \"Host\" header, URL: %s"
};



static ngx_http_header_t headers_in[] = {
    { 4, "Host", offsetof(ngx_http_headers_in_t, host) },
    { 10, "Connection", offsetof(ngx_http_headers_in_t, connection) },
    { 17, "If-Modified-Since",
                           offsetof(ngx_http_headers_in_t,if_modified_since) },

    { 10, "User-Agent", offsetof(ngx_http_headers_in_t, user_agent) },

    { 0, NULL, 0 }
};


int ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *ev;
    ngx_http_log_ctx_t  *ctx;

    ev = c->read;
    ev->event_handler = ngx_http_init_request;

    ev->close_handler = ngx_http_close_connection;
    c->write->close_handler = ngx_http_close_connection;

    ngx_test_null(c->addr_text.data, ngx_palloc(c->pool, c->addr_text_max_len),
                  NGX_ERROR);

    c->addr_text.len = ngx_sock_ntop(c->family, c->sockaddr,
                                     c->addr_text.data, c->addr_text_max_len);

    if (c->addr_text.len == 0) {
        return NGX_ERROR;
    }

    ngx_test_null(ctx, ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t)),
                  NGX_ERROR);
    ctx->client = c->addr_text.data;
    ctx->action = "reading client request line";
    c->log->data = ctx;
    c->log->handler = ngx_http_log_error;

#if (HAVE_DEFERRED_ACCEPT)

    if (ev->ready) {
        return ngx_http_init_request(ev);
    }

#endif

    ngx_add_timer(ev, c->post_accept_timeout);
    ev->timer_set = 1;

#if (USE_KQUEUE)

    return ngx_add_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT);

#else

#if (HAVE_CLEAR_EVENT) /* kqueue */

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        return ngx_add_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
    }

#endif

#if (HAVE_EDGE_EVENT) /* epoll */ || (HAVE_AIO_EVENT) /* aio, iocp */

    if (ngx_event_flags & (NGX_HAVE_EDGE_EVENT|NGX_HAVE_AIO_EVENT)) {
        return ngx_http_init_request(ev);
    }

#endif

    /* select, poll, /dev/poll */

    ev->level = 1;
    return ngx_add_event(ev, NGX_READ_EVENT, NGX_LEVEL_EVENT);

#endif /* USE_KQUEUE */
}


static int ngx_http_init_request(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_conf_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;
    c->sent = 0;

    ngx_test_null(r, ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)),
                  NGX_ERROR);

    c->data = r;
    r->connection = c;
    r->file.fd = NGX_INVALID_FILE;

    if (c->buffer == NULL) {
        ngx_test_null(c->buffer,
                      ngx_create_temp_hunk(c->pool,
                                           ngx_http_client_header_buffer_size,
                                           0, 0),
                      NGX_ERROR);
    } else {
        r->header_read = 1;
    }

    r->pipeline = c->pipeline;
    r->header_in = c->buffer;

    ngx_test_null(r->pool, ngx_create_pool(ngx_http_request_pool_size, ev->log),
                  ngx_http_close_request(r));

    ngx_test_null(r->ctx,
                  ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module),
                  ngx_http_close_request(r));

    ctx = (ngx_http_conf_ctx_t *) c->ctx;
    r->srv_conf = ctx->srv_conf;
    r->loc_conf = ctx->loc_conf;

    r->headers_out.headers = ngx_create_table(r->pool, 10);
    r->headers_out.content_length = -1;
    r->headers_out.last_modified_time = -1;

    ev->event_handler = ngx_http_process_request_header;
    r->state_handler = ngx_http_process_request_line;

    return ngx_http_process_request_header(ev);
}


static int ngx_http_process_request_header(ngx_event_t *ev)
{
    int                  n, rc;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http process request");

#if (HAVE_AIO_EVENT)
    do {
#endif

        if (r->header_read) {
            r->header_read = 0;
            ngx_log_debug(ev->log, "http preread %d" _
                          r->header_in->last.mem - r->header_in->pos.mem);

        } else {
            n = ngx_event_recv(c, r->header_in->last.mem,
                               r->header_in->end - r->header_in->last.mem);

            if (n == NGX_AGAIN) {
                if (!r->header_timeout_set) {

                    if (ev->timer_set) {
                        ngx_del_timer(ev);
                    } else {
                        ev->timer_set = 1;
                    }

                    ngx_add_timer(ev, ngx_http_client_header_timeout);
                    r->header_timeout_set = 1;
                }
                return NGX_AGAIN;
            }

            if (n == NGX_ERROR)
                return ngx_http_close_request(r);

            ngx_log_debug(ev->log, "http read %d" _ n);

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client has prematurely closed connection");
                return ngx_http_close_request(r);
            }

            r->header_in->last.mem += n;
        }

        /* state_handlers are called in following order:
            ngx_http_process_request_line(r)
            ngx_http_process_request_headers(r) */

        do {
            /* state_handlers return NGX_OK when whole header done */
            rc = (r->state_handler)(r);

            if (rc == NGX_ERROR)
                return rc;

        } while (rc == NGX_AGAIN
                 && r->header_in->pos.mem < r->header_in->last.mem);

#if (HAVE_AIO_EVENT) /* aio, iocp */
    } while (rc == NGX_AGAIN && ngx_event_flags & NGX_HAVE_AIO_EVENT);
#endif

    if (rc == NGX_OK) {
        /* HTTP header done */

        if (ev->timer_set) {
            ngx_del_timer(ev);
            ev->timer_set = 0;
        }

        return ngx_http_event_request_handler(r);

    } else { /* NGX_AGAIN */

        if (!r->header_timeout_set) {

            if (ev->timer_set) {
                ngx_del_timer(ev);
            } else {
                ev->timer_set = 1;
            }

            ngx_add_timer(ev, ngx_http_client_header_timeout);
            r->header_timeout_set = 1;
        }

        return rc;
    }
}


static int ngx_http_process_request_line(ngx_http_request_t *r)
{
    int                  rc, offset;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    rc = ngx_read_http_request_line(r);

    /* If it's a pipelined request and a request line is not complete
       then we need to copy it to the start of r->header_in hunk.
       We need to copy it here only if the large client headers are enabled
       otherwise a request line had already copied to start
       of r->header_in hunk in ngx_http_set_keepalive() */

    if (ngx_http_large_client_header
        && rc == NGX_AGAIN
        && r->header_in->last.mem == r->header_in->end)
    {
        offset = r->request_start - r->header_in->start;

        if (offset == 0) {
            return ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                               NGX_HTTP_REQUEST_URI_TOO_LARGE);
        }

        ngx_memcpy(r->header_in->start, r->request_start,
                   r->header_in->last.mem - r->request_start);

        r->header_in->pos.mem -= offset;
        r->header_in->last.mem -= offset;
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
    }

    c = r->connection;

    if (rc == NGX_OK) {
        /* copy URI */
        r->uri.len = (r->args_start ? r->args_start - 1 : r->uri_end)
                                                                - r->uri_start;
        ngx_test_null(r->uri.data, ngx_palloc(r->pool, r->uri.len + 1),
                      ngx_http_close_request(r));
        ngx_cpystrn(r->uri.data, r->uri_start, r->uri.len + 1);

        /* if large client headers is supported then
           we need to copy request line */

        r->request_line.len = r->request_end - r->request_start;
        if (ngx_http_large_client_header) {
            ngx_test_null(r->request_line.data,
                          ngx_palloc(r->pool, r->request_line.len + 1),
                          ngx_http_close_request(r));
            ngx_cpystrn(r->request_line.data, r->request_start,
                        r->request_line.len + 1);

        } else {
            r->request_line.data = r->request_start;
            r->request_line.data[r->request_line.len] = '\0';
        }

        /* copy URI extention if it exists */
        if (r->uri_ext) {
            r->exten.len = (r->args_start ? r->args_start - 1 : r->uri_end)
                                                                  - r->uri_ext;
            ngx_test_null(r->exten.data,
                          ngx_palloc(r->pool, r->exten.len + 1), 
                          ngx_http_close_request(r));
            ngx_cpystrn(r->exten.data, r->uri_ext, r->exten.len + 1);
        }

#if 1
        if (r->exten.data == NULL) {
            r->exten.data = "";
        }
        ngx_log_debug(r->connection->log, "HTTP: %d, %d, '%s', '%s'" _
                      r->method _ r->http_version _
                      r->uri.data _ r->exten.data);
        if (r->exten.data[0] == '\0') {
            r->exten.data = NULL;
        }
#endif

        ctx = r->connection->log->data;
        if (ngx_http_url_in_error_log) {
            ngx_test_null(ctx->url,
                          ngx_palloc(r->pool, r->uri_end - r->uri_start + 1),
                          ngx_http_close_request(r));
            ngx_cpystrn(ctx->url, r->uri_start, r->uri_end - r->uri_start + 1);
        }

        if (r->http_version == NGX_HTTP_VERSION_9)
            return NGX_OK;

        r->headers_in.headers = ngx_create_table(r->pool, 10);

        r->state_handler = ngx_http_process_request_headers;
        ctx->action = "reading client request headers";

        return NGX_AGAIN;
    }

    if (r->header_in->last.mem == r->header_in->end) {
        return ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI,
                                           NGX_HTTP_REQUEST_URI_TOO_LARGE);

    } else if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    return ngx_http_header_parse_error(r, rc, NGX_HTTP_BAD_REQUEST);
}


static int ngx_http_process_request_headers(ngx_http_request_t *r)
{
    int                  rc, offset;
    size_t               len;
    ngx_http_log_ctx_t  *ctx;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r, r->header_in);

        /* if large client header is supported then
            we need to compact r->header_in hunk */

        if (ngx_http_large_client_header
            && rc == NGX_AGAIN
            && r->header_in->pos.mem == r->header_in->end)
        {
            offset = r->header_name_start - r->header_in->start;

            if (offset == 0) {
                return ngx_http_header_parse_error(r,
                                                NGX_HTTP_PARSE_TOO_LONG_HEADER,
                                                NGX_HTTP_BAD_REQUEST);
            }

            ngx_memcpy(r->header_in->start, r->header_name_start,
                       r->header_in->last.mem - r->header_name_start);

            r->header_in->last.mem -= offset;
            r->header_in->pos.mem -= offset;
            r->header_name_start = r->header_in->start;
            r->header_name_end -= offset;
            r->header_start -= offset;
            r->header_end -= offset;
        }

        if (rc == NGX_OK) { /* header line is ready */
            if (ngx_http_process_request_header_line(r) == NGX_ERROR) {
                return ngx_http_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return NGX_AGAIN;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug(r->connection->log, "HTTP header done");

            if (r->headers_in.host) {
                for (len = 0; len < r->headers_in.host->value.len; len++) {
                    if (r->headers_in.host->value.data[len] == ':') {
                        break;
                    }
                }
                r->headers_in.host_name_len = len;

            } else {
                if (r->http_version > NGX_HTTP_VERSION_10) {
                    return ngx_http_header_parse_error(r,
                                                 NGX_HTTP_PARSE_NO_HOST_HEADER,
                                                 NGX_HTTP_BAD_REQUEST);
                }
                r->headers_in.host_name_len = 0;
            }

            return NGX_OK;

        } else if (!ngx_http_large_client_header
                   && r->header_in->last.mem == r->header_in->end) {
            return ngx_http_header_parse_error(r,
                                               NGX_HTTP_PARSE_TOO_LONG_HEADER,
                                               NGX_HTTP_BAD_REQUEST);

        } else if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
    }
}


static int ngx_http_process_request_header_line(ngx_http_request_t *r)
{
    int  i;
    ngx_table_elt_t *h;

    ngx_test_null(h, ngx_push_table(r->headers_in.headers), NGX_ERROR);

    /* if large client headers is supported then
       we need to copy header name and value */

    h->key.len = r->header_name_end - r->header_name_start;
    h->value.len = r->header_end - r->header_start;

    if (ngx_http_large_client_header) {
        ngx_test_null(h->key.data, ngx_palloc(r->pool, h->key.len + 1),
                      NGX_ERROR);
        ngx_test_null(h->value.data, ngx_palloc(r->pool, h->value.len + 1),
                      NGX_ERROR);
        ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
        ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

    } else {
        h->key.data = r->header_name_start;
        h->key.data[h->key.len] = '\0';
        h->value.data = r->header_start;
        h->value.data[h->value.len] = '\0';
    }

    for (i = 0; headers_in[i].len != 0; i++) {
        if (headers_in[i].len != h->key.len) {
            continue;
        }

        if (ngx_strcasecmp(headers_in[i].data, h->key.data) == 0) {
            *((ngx_table_elt_t **)
                        ((char *) &r->headers_in + headers_in[i].offset)) = h;
        }
    }

    ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                  h->key.data _ h->value.data);

    return NGX_OK;
}


static int ngx_http_event_request_handler(ngx_http_request_t *r)
{
    int                  rc, event;
    ngx_msec_t           timeout;
    ngx_event_t         *rev, *wev;
    ngx_http_log_ctx_t  *ctx;

    rev = r->connection->read;
    wev = r->connection->write;

    if (rev->timer_set) {
        ngx_del_timer(rev);
        rev->timer_set = 0;
    }

    r->state_handler = NULL;
    rev->event_handler = ngx_http_block_read;

    ctx = r->connection->log->data;
    ctx->action = "processing client request";

    rc = ngx_http_handler(r);

    /* handler is still busy */
    if (rc == NGX_WAITING)
        return rc;

    /* handler has done its work but transfer is still not completed */
    if (rc == NGX_AGAIN) {

        /* STUB: timeouts should be reworked */
        if (r->connection->sent > 0) {
            ngx_log_debug(r->connection->log, "sent: " OFF_FMT _
                          r->connection->sent);
            timeout = (ngx_msec_t) (r->connection->sent * 10);
            ngx_log_debug(r->connection->log, "timeout: %d" _ timeout);
            ngx_add_timer(wev, timeout);

        } else {
            ngx_add_timer(wev, 10000);
        }

        wev->event_handler = ngx_http_writer;

#if (USE_KQUEUE)

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */
        wev->lowat = /* STUB */ NGX_LOWAT;
#endif

        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR) {
            return ngx_http_close_request(r);
        }

        return rc;

#else

#if (HAVE_AIO_EVENT) || (HAVE_EDGE_EVENT) /* aio, iocp, epoll */

        if (ngx_event_flags & (NGX_HAVE_AIO_EVENT|NGX_HAVE_EDGE_EVENT)) {
            return rc;
        }

#endif

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */

        if (ngx_event_flags & NGX_HAVE_LOWAT_EVENT) {
            wev->lowat = /* STUB */ NGX_LOWAT;
        }

#endif

#if (HAVE_CLEAR_EVENT) /* kqueue */

        if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
            event = NGX_CLEAR_EVENT;

        } else {
            event = NGX_LEVEL_EVENT;
            wev->level = 1;
        }

#else /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
        wev->level = 1;

#endif

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) == NGX_ERROR) {
            return ngx_http_close_request(r);
        }

        return rc;


#endif /* USE_KQUEUE */

    }

    if (rc == NGX_ERROR) {
        /* log http request */
        return ngx_http_close_request(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return ngx_http_special_response(r, rc);

    /* rc == NGX_OK */

    if (r->keepalive == 0) {
        if (r->lingering_close) {
            return ngx_http_set_lingering_close(r);

        } else {
            return ngx_http_close_request(r);
        }
    }

    /* keepalive */

    return ngx_http_set_keepalive(r);
}


static int ngx_http_writer(ngx_event_t *ev)
{
    int rc;
    ngx_msec_t                 timeout;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *conf;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug(ev->log, "output filter in writer: %d" _ rc);

    if (rc == NGX_AGAIN) {

        /* STUB: timeouts should be reworked */
        if (c->sent > 0) {
            conf = (ngx_http_core_loc_conf_t *)
                        ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                     ngx_http_core_module_ctx);

            timeout = (ngx_msec_t) (c->sent * conf->send_timeout);

            ngx_log_debug(ev->log, "sent: " OFF_FMT _ c->sent);
            ngx_log_debug(ev->log, "timeout: %d" _ timeout);

            if (ev->timer_set) {
                ngx_del_timer(ev);
            } else {
                ev->timer_set = 1;
            }

            ngx_add_timer(ev, timeout);
        }

        return rc;
    }

    if (rc == NGX_ERROR)
        return rc;

    /* rc == NGX_OK */

    ngx_log_debug(ev->log, "http writer done");

    if (r->keepalive == 0) {
        if (r->lingering_close) {
            return ngx_http_set_lingering_close(r);

        } else {
            return ngx_http_close_request(r);
        }
    }

    /* keepalive */

    return ngx_http_set_keepalive(r);
}


static int ngx_http_block_read(ngx_event_t *ev)
{
    ngx_log_debug(ev->log, "http read blocked");

    /* aio does not call this handler */

#if (USE_KQUEUE)

    return NGX_OK;

#else

    if (ev->level) {       /* select, poll, /dev/poll */
        ev->blocked = 1;
        return ngx_del_event(ev, NGX_READ_EVENT, 0);

    } else {               /* kqueue, epoll */
        return NGX_OK;
    }

#endif /* USE_KQUEUE */
}


/* TODO */
int ngx_http_discard_body(ngx_http_request_t *r)
{
    ngx_event_t  *ev;

    ev = r->connection->read;

    ngx_log_debug(r->connection->log, "set discard body");

    if (ev->timer_set) {
        ngx_del_timer(ev);
        ev->timer_set = 0;
    }

    if (r->client_content_length) {
        ev->event_handler = ngx_http_read_discarded_body;
        /* if blocked - read */
        /* else add timer */
    }

    return NGX_OK;
}


/* TODO */
static int ngx_http_read_discarded_body(ngx_event_t *ev)
{
    size_t   size;
    ssize_t  n;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *lcf;

    ngx_log_debug(ev->log, "http read discarded body");

    if (ev->timedout)
        return NGX_ERROR;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (r->discarded_buffer == NULL)
        ngx_test_null(r->discarded_buffer,
                      ngx_palloc(r->pool, lcf->discarded_buffer_size),
                      NGX_ERROR);

    size = r->client_content_length;
    if (size > lcf->discarded_buffer_size)
        size = lcf->discarded_buffer_size;

    n = ngx_event_recv(c, r->discarded_buffer, size);
    if (n == NGX_ERROR)
        return NGX_ERROR;

    if (n == NGX_AGAIN)
        return NGX_OK;

    r->client_content_length -= n;
    /* XXX: what if r->client_content_length == 0 ? */
    return NGX_OK;
}


static int ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                  len;
    ngx_hunk_t          *h;
    ngx_event_t         *rev, *wev;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) r->connection;
    rev = c->read;
    wev = c->write;

    if (rev->blocked && rev->level) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR) {
            return NGX_ERROR;
        }
        rev->blocked = 0;
    }

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "closing request";
    ngx_http_close_request(r);

    h = c->buffer;

    /* pipelined request */
    if (h->pos.mem < h->last.mem) {

        /* clients that support pipelined requests (Mozilla 1.x, Opera 6.x)
           are rare now so this copy should also be rare */

        if (!ngx_http_large_client_header) {
            len = h->last.mem - h->pos.mem; 
            ngx_memcpy(h->start, h->pos.mem, len);
            h->pos.mem = h->start;
            h->last.mem = h->start + len;
        }

        c->pipeline = 1;
        ctx->action = "reading client pipelined request line";
        return ngx_http_init_request(rev);
    }

    c->pipeline = 0;

    h->pos.mem = h->last.mem = h->start;
    rev->event_handler = ngx_http_keepalive_handler;

    if (wev->active && wev->level) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    ctx->action = "keepalive";

#if (HAVE_AIO_EVENT) /* aio, iocp */

    if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {
        return ngx_http_keepalive_handler(rev);
    }

#endif

    return NGX_OK;
}


static int ngx_http_keepalive_handler(ngx_event_t *ev)
{
    ssize_t n;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "http keepalive handler");

    if (ev->timedout)
        return NGX_DONE;

    /* TODO: MSIE closes keepalive connection with ECONNRESET
             so we need to handle here this error
             1) in INFO (not ERR) level, 2) with time elapsed */
    n = ngx_event_recv(c, c->buffer->last.mem,
                       c->buffer->end - c->buffer->last.mem);

    if (n == NGX_AGAIN || n == NGX_ERROR)
        return n;

    ctx = (ngx_http_log_ctx_t *) ev->log->data;
    ev->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                      "client %s closed keepalive connection", ctx->client);
        return NGX_DONE;
    }

    c->buffer->last.mem += n;
    ev->log->handler = ngx_http_log_error;
    ctx->action = "reading client request line";

    return ngx_http_init_request(ev);
}


static int ngx_http_set_lingering_close(ngx_http_request_t *r)
{
    ngx_event_t  *ev;
    ngx_connection_t    *c;
    ngx_http_core_loc_conf_t  *lcf;

    c = r->connection;
    ev = r->connection->read;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    r->lingering_time = ngx_time() + lcf->lingering_time;
    r->connection->read->event_handler = ngx_http_lingering_close_handler;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    } else {
        ev->timer_set = 1;
    }

    ngx_add_timer(ev, lcf->lingering_timeout);

    if (ev->blocked) {
        if (ngx_event_flags & NGX_HAVE_LEVEL_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                                                                == NGX_ERROR) {
                return ngx_http_close_request(r);
            }
        }
    }

    if (ngx_shutdown_socket(r->connection->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                      ngx_shutdown_socket_n " failed");
        return ngx_http_close_request(r);
    }

#if (HAVE_AIO_EVENT) /* aio, iocp */
    if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {
        return ngx_http_lingering_close_handler(ev);
    }
#endif

#if (HAVE_CLEAR_EVENT) /* kqueue */ || (HAVE_EDGE_EVENT) /* epoll */
    if (ngx_event_flags & (NGX_HAVE_CLEAR_EVENT|NGX_HAVE_EDGE_EVENT)) {
        return NGX_OK;
    }
#endif

    /* select, poll, /dev/poll */

    return ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
}


static int ngx_http_lingering_close_handler(ngx_event_t *ev)
{
    ssize_t              n;
    ngx_msec_t           timer;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_core_loc_conf_t  *lcf;

    ngx_log_debug(ev->log, "http lingering close handler");

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    if (ev->timedout) {
        return ngx_http_close_request(r);
    }

    timer = r->lingering_time - ngx_time();
    if (timer <= 0) {
        return ngx_http_close_request(r);
    }

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (r->discarded_buffer == NULL) {
        if ((size_t)(r->header_in->end - r->header_in->last.mem)
                                               >= lcf->discarded_buffer_size) {
            r->discarded_buffer = r->header_in->last.mem;

        } else {
            ngx_test_null(r->discarded_buffer,
                          ngx_palloc(c->pool, lcf->discarded_buffer_size),
                          ngx_http_close_request(r));
        }
    }

    n = ngx_event_recv(c, r->discarded_buffer, lcf->discarded_buffer_size);

    ngx_log_debug(ev->log, "lingering read: %d" _ n);

    if (n == NGX_ERROR || n == 0) {
        return ngx_http_close_request(r);
    }

    timer *= 1000;
    if (timer > lcf->lingering_timeout) {
        timer = lcf->lingering_timeout;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    } else {
        ev->timer_set = 1;
    }
    ngx_add_timer(ev, timer);

    return NGX_OK;
}


static int ngx_http_close_connection(ngx_event_t *ev)
{
    return ngx_event_close_connection(ev);
}


static int ngx_http_header_parse_error(ngx_http_request_t *r,
                                       int parse_err, int err)
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

    return ngx_http_error(r, err);
}


static size_t ngx_http_log_error(void *data, char *buf, size_t len)
{
    ngx_http_log_ctx_t *ctx = (ngx_http_log_ctx_t *) data;

    if (ctx->url)
        return ngx_snprintf(buf, len, " while %s, client: %s, URL: %s",
                            ctx->action, ctx->client, ctx->url);
    else
        return ngx_snprintf(buf, len, " while %s, client: %s",
                            ctx->action, ctx->client);
}
