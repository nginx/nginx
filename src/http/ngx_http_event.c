
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
static int ngx_http_process_request(ngx_event_t *ev);
static int ngx_http_process_request_line(ngx_http_request_t *r);
static int ngx_http_process_request_headers(ngx_http_request_t *r);
static int ngx_http_process_request_header_line(ngx_http_request_t *r);
static int ngx_http_request_handler(ngx_http_request_t *r, int error);

static int ngx_http_writer(ngx_event_t *ev);
static int ngx_http_block_read(ngx_event_t *ev);
static int ngx_http_read_discarded_body(ngx_event_t *ev);
static int ngx_http_set_keepalive(ngx_http_request_t *r);
static int ngx_http_keepalive_handler(ngx_event_t *ev);
static int ngx_http_set_lingering_close(ngx_http_request_t *r);
static int ngx_http_lingering_close_handler(ngx_event_t *ev);

static int ngx_http_close_connection(ngx_event_t *ev);
static void ngx_http_header_parse_error(ngx_http_request_t *r, int parse_err);
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
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host) },
    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection) },
    { ngx_string("If-Modified-Since"), 
                         offsetof(ngx_http_headers_in_t, if_modified_since) },

    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent) },

    { ngx_null_string, 0 }
};


int ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *rev;
    ngx_http_log_ctx_t  *ctx;

    rev = c->read;
    rev->event_handler = ngx_http_init_request;

    rev->close_handler = ngx_http_close_connection;
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

    if (rev->ready) {
        return ngx_http_init_request(rev);
    }

#endif

    ngx_add_timer(rev, c->post_accept_timeout);
    rev->timer_set = 1;

#if (USE_KQUEUE)

    return ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT);

#else

    /* kqueue */

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        return ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
    }

    /* aio, iocp, epoll */

    if (ngx_event_flags & (NGX_HAVE_AIO_EVENT|NGX_HAVE_EDGE_EVENT)) {
        return ngx_http_init_request(rev);
    }

    /* select, poll, /dev/poll */

    return ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT);

#endif /* USE_KQUEUE */
}


static int ngx_http_init_request(ngx_event_t *rev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_conf_ctx_t  *ctx;

    c = (ngx_connection_t *) rev->data;
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

    ngx_test_null(r->pool, ngx_create_pool(ngx_http_request_pool_size, c->log),
                  NGX_ERROR);

    ngx_test_null(r->ctx,
                  ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module),
                  ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR));

    ctx = (ngx_http_conf_ctx_t *) c->ctx;
    r->srv_conf = ctx->srv_conf;
    r->loc_conf = ctx->loc_conf;

    r->headers_out.headers = ngx_create_table(r->pool, 10);
    r->headers_out.content_length = -1;
    r->headers_out.last_modified_time = -1;

    rev->event_handler = ngx_http_process_request;
    r->state_handler = ngx_http_process_request_line;

    return ngx_http_process_request(rev);
}


static int ngx_http_process_request(ngx_event_t *rev)
{
    int                  n, rc;
    ngx_event_t         *wev;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *lcx;

    c = (ngx_connection_t *) rev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(c->log, "http process request");

    if (rev->timedout) {
        return ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
    }

    do {

        if (r->header_read) {
            r->header_read = 0;
            ngx_log_debug(c->log, "http preread %d" _
                          r->header_in->last - r->header_in->pos);

        } else {
            n = ngx_event_recv(c, r->header_in->last,
                               r->header_in->end - r->header_in->last);

            if (n == NGX_AGAIN) {
                if (!r->header_timeout_set) {

                    if (rev->timer_set) {
                        ngx_del_timer(rev);
                    } else {
                        rev->timer_set = 1;
                    }

                    ngx_add_timer(rev, ngx_http_client_header_timeout);
                    r->header_timeout_set = 1;
                }

                return NGX_AGAIN;
            }

            if (n == NGX_ERROR) {
                return ngx_http_close_request(r, NGX_HTTP_BAD_REQUEST);
            }

            ngx_log_debug(c->log, "http read %d" _ n);

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client closed prematurely connection");
                return ngx_http_close_request(r, NGX_HTTP_BAD_REQUEST);
            }

            r->header_in->last += n;
        }

        /* the state handlers are called in the following order:
            ngx_http_process_request_line(r)
            ngx_http_process_request_headers(r) */

        do {
            rc = r->state_handler(r);

        } while (rc == NGX_AGAIN && r->header_in->pos < r->header_in->last);

    } while (rc == NGX_AGAIN
             && (rev->ready || ngx_event_flags & NGX_HAVE_AIO_EVENT));

    if (rc >= NGX_OK) {

        /* HTTP header done */

        rev->event_handler = ngx_http_block_read;

        if (rc != NGX_OK) {
            return ngx_http_finalize_request(r, rc);
        }

        lcx = c->log->data;
        lcx->action = "processing client request";

#if 0
        wev = c->write;
        ngx_add_timer(wev, 5000);
        wev->delayed = 1;
        wev->timer_set = 1;
#endif

        rc = ngx_http_handler(r);

        /* a handler does its own processing */
        if (rc == NGX_DONE) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return ngx_http_finalize_request(r, rc);

    }

    /* NGX_AGAIN */

    if (!r->header_timeout_set) {

        if (rev->timer_set) {
            ngx_del_timer(rev);
        } else {
            rev->timer_set = 1;
        }

        ngx_add_timer(rev, ngx_http_client_header_timeout);
        r->header_timeout_set = 1;
    }

    return rc;
}


static int ngx_http_process_request_line(ngx_http_request_t *r)
{
    int                  rc, offset;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *lcx;

    rc = ngx_read_http_request_line(r);

    c = r->connection;

    /* a request line has been parsed successfully */

    if (rc == NGX_OK) {

        if (r->http_version >= NGX_HTTP_VERSION_10
            && ngx_http_large_client_header == 0
            && r->header_in->pos == r->header_in->end)
        {
            ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI);
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }

        /* copy URI */

        if (r->args_start) {
            r->uri.len = r->args_start - 1 - r->uri_start;
        } else {
            r->uri.len = r->uri_end - r->uri_start;
        }

        ngx_test_null(r->uri.data, ngx_palloc(r->pool, r->uri.len + 1),
                      NGX_HTTP_INTERNAL_SERVER_ERROR);

        ngx_cpystrn(r->uri.data, r->uri_start, r->uri.len + 1);

        r->request_line.len = r->request_end - r->request_start;

        /* if the large client headers are enabled then
           we need to copy a request line */

        if (ngx_http_large_client_header) {
            ngx_test_null(r->request_line.data,
                          ngx_palloc(r->pool, r->request_line.len + 1),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

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

            ngx_test_null(r->exten.data,
                          ngx_palloc(r->pool, r->exten.len + 1), 
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

            ngx_cpystrn(r->exten.data, r->uri_ext, r->exten.len + 1);
        }

        /* copy URI arguments if they exist */

        if (r->args_start && r->uri_end > r->args_start) {
            r->args.len = r->uri_end - r->args_start;

            ngx_test_null(r->args.data,
                          ngx_palloc(r->pool, r->args.len + 1),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

            ngx_cpystrn(r->args.data, r->args_start, r->args.len + 1);
        }

#if 1
        if (r->exten.data == NULL) {
            r->exten.data = "";
        }
        if (r->args.data == NULL) {
            r->args.data = "";
        }
        ngx_log_debug(r->connection->log, "HTTP: %d, %d, '%s', '%s', '%s'" _
                      r->method _ r->http_version _
                      r->uri.data _ r->exten.data _ r->args.data);
        if (r->exten.data[0] == '\0') {
            r->exten.data = NULL;
        }
        if (r->args.data[0] == '\0') {
            r->args.data = NULL;
        }
#endif

        lcx = r->connection->log->data;

        if (ngx_http_url_in_error_log) {
            ngx_test_null(lcx->url,
                          ngx_palloc(r->pool, r->uri_end - r->uri_start + 1),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

            ngx_cpystrn(lcx->url, r->uri_start, r->uri_end - r->uri_start + 1);
        }

        /* if we need to parse the headers then return NGX_AGAIN
           becuase of HTTP/0.9 has no headers so return NGX_OK */

        if (r->http_version == NGX_HTTP_VERSION_9) {
            r->state_handler = NULL;
            return NGX_OK;
        }

        r->headers_in.headers = ngx_create_table(r->pool, 10);

        r->state_handler = ngx_http_process_request_headers;
        lcx->action = "reading client request headers";

        if (ngx_http_large_client_header
            && r->header_in->pos == r->header_in->last)
        {
            r->header_in->pos = r->header_in->last = r->header_in->start;
        }

        return NGX_AGAIN;

    /* there was error while a request line parsing */

    } else if (rc != NGX_AGAIN) {
        ngx_http_header_parse_error(r, rc);
        return NGX_HTTP_BAD_REQUEST;
    }

    /* NGX_AGAIN: a request line parsing is still not complete */

    if (r->header_in->last == r->header_in->end) {

        /* If it's a pipelined request and a request line is not complete
           then we need to copy it to the start of r->header_in hunk.
           We need to copy it here only if the large client headers
           are enabled otherwise a request line had been already copied
           to the start of r->header_in hunk in ngx_http_set_keepalive() */

        if (ngx_http_large_client_header) {
            offset = r->request_start - r->header_in->start;

            if (offset == 0) {
                ngx_http_header_parse_error(r, NGX_HTTP_PARSE_TOO_LONG_URI);
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
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
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
    }

    return NGX_AGAIN;
}


static int ngx_http_process_request_headers(ngx_http_request_t *r)
{
    int                  rc, offset;
    size_t               len;
    ngx_http_log_ctx_t  *ctx;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r, r->header_in);

        /* a header line has been parsed successfully */

        if (rc == NGX_OK) {
            if (ngx_http_process_request_header_line(r) == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (ngx_http_large_client_header
                && r->header_in->pos == r->header_in->last)
            {
                r->header_in->pos = r->header_in->last = r->header_in->start;
            }

            return NGX_AGAIN;

        /* a whole header has been parsed successfully */

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
                    ngx_http_header_parse_error(r,
                                                NGX_HTTP_PARSE_NO_HOST_HEADER);
                    return NGX_HTTP_BAD_REQUEST;
                }
                r->headers_in.host_name_len = 0;
            }

            r->state_handler = NULL;
            return NGX_OK;

        /* there was error while a header line parsing */

        } else if (rc != NGX_AGAIN) {
            ngx_http_header_parse_error(r, rc);
            return NGX_HTTP_BAD_REQUEST;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

        if (r->header_in->last == r->header_in->end) {

            /* if the large client headers are enabled then
                we need to compact r->header_in hunk */

            if (ngx_http_large_client_header) {
                offset = r->header_name_start - r->header_in->start;

                if (offset == 0) {
                    ngx_http_header_parse_error(r,
                                                NGX_HTTP_PARSE_TOO_LONG_HEADER);
                    return NGX_HTTP_BAD_REQUEST;
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
                return NGX_HTTP_BAD_REQUEST;
            }

        }

        return NGX_AGAIN;
    }
}


static int ngx_http_process_request_header_line(ngx_http_request_t *r)
{
    int               i;
    ngx_table_elt_t  *h;

    ngx_test_null(h, ngx_push_table(r->headers_in.headers), NGX_ERROR);

    h->key.len = r->header_name_end - r->header_name_start;
    h->value.len = r->header_end - r->header_start;

    /* if the large client headers are enabled then
       we need to copy the header name and value */

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

    return NGX_OK;
}


int ngx_http_finalize_request(ngx_http_request_t *r, int error)
{
    int                        rc, event;
    ngx_msec_t                 timeout;
    ngx_event_t               *rev, *wev;
    ngx_http_core_loc_conf_t  *lcf;

    rc = error;

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {

        rev = r->connection->read;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        } else {
            rev->timer_set = 1;
        }

        rc = ngx_http_special_response_handler(r, rc);
    }

    /* a handler has done its work completely */

    if (rc == NGX_OK) {

        if (r->keepalive != 0) {
            return ngx_http_set_keepalive(r);
        }

        if (r->lingering_close) {
            return ngx_http_set_lingering_close(r);
        }

        return ngx_http_close_request(r, 0);
    }

    /* NGX_AGAIN: a handler has done its work
                  but the transfer is still not completed */

    wev = r->connection->write;
    wev->event_handler = ngx_http_writer;

    if (wev->delayed && wev->ready) {
        return NGX_AGAIN;
    }

    lcf = (ngx_http_core_loc_conf_t *)
                        ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                     ngx_http_core_module_ctx);
    ngx_add_timer(wev, lcf->send_timeout);
    wev->timer_set = 1;

#if (USE_KQUEUE)

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */
    wev->lowat = lcf->send_lowat;
#endif

    if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR) {
        return ngx_http_close_request(r, 0);
    }

    return rc;

#else

    /* aio, iocp, epoll */

    if (ngx_event_flags & (NGX_HAVE_AIO_EVENT|NGX_HAVE_EDGE_EVENT)) {
        return rc;
    }

#if (HAVE_LOWAT_EVENT) /* kqueue's NOTE_LOWAT */

    if (ngx_event_flags & NGX_HAVE_LOWAT_EVENT) {
        wev->lowat = lcf->send_lowat;
    }

#endif

    /* kqueue */

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        event = NGX_CLEAR_EVENT;

    /* select, poll, /dev/poll */

    } else {
        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(wev, NGX_WRITE_EVENT, event) == NGX_ERROR) {
        return ngx_http_close_request(r, 0);
    }

    return rc;

#endif /* USE_KQUEUE */
}


static int ngx_http_writer(ngx_event_t *wev)
{
    int                        rc;
    ngx_msec_t                 timeout;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *lcf;

    c = (ngx_connection_t *) wev->data;
    r = (ngx_http_request_t *) c->data;

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug(c->log, "output filter in writer: %d" _ rc);

    if (rc == NGX_AGAIN) {

        lcf = (ngx_http_core_loc_conf_t *)
                        ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                     ngx_http_core_module_ctx);
        if (wev->timer_set) {
            ngx_del_timer(wev);
        } else {
            wev->timer_set = 1;
        }

        ngx_add_timer(wev, lcf->send_timeout);

        return rc;
    }

    if (rc == NGX_ERROR)
        return rc;

    /* rc == NGX_OK */

    ngx_log_debug(c->log, "http writer done");

    if (r->keepalive != 0) {
        return ngx_http_set_keepalive(r);
    }

    if (r->lingering_close) {
        return ngx_http_set_lingering_close(r);
    }

    return ngx_http_close_request(r, 0);
}


static int ngx_http_block_read(ngx_event_t *ev)
{
    ngx_log_debug(ev->log, "http read blocked");

    /* aio does not call this handler */

#if (USE_KQUEUE)

    return NGX_OK;

#else

    if (ngx_event_flags & NGX_USE_LEVEL_EVENT) { /* select, poll, /dev/poll */
        ev->blocked = 1;
        return ngx_del_event(ev, NGX_READ_EVENT, 0);

    } else {                                     /* kqueue, epoll */
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

    if (ev->timedout) {
        return NGX_ERROR;
    }

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (r->discarded_buffer == NULL) {
        ngx_test_null(r->discarded_buffer,
                      ngx_palloc(r->pool, lcf->discarded_buffer_size),
                      NGX_ERROR);
    }

    size = r->client_content_length;
    if (size > lcf->discarded_buffer_size) {
        size = lcf->discarded_buffer_size;
    }

    n = ngx_event_recv(c, r->discarded_buffer, size);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_OK;
    }

    r->client_content_length -= n;
    /* XXX: what if r->client_content_length == 0 ? */
    return NGX_OK;
}


static int ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                  len, blocked;
    ngx_hunk_t          *h;
    ngx_event_t         *rev, *wev;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) r->connection;
    rev = c->read;

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "closing request";
    ngx_http_close_request(r, 0);

    if (rev->blocked && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR) {
            return NGX_ERROR;
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

        if (!ngx_http_large_client_header) {
            len = h->last - h->pos; 
            ngx_memcpy(h->start, h->pos, len);
            h->pos = h->start;
            h->last = h->start + len;
        }

        c->pipeline = 1;
        ctx->action = "reading client pipelined request line";
        return ngx_http_init_request(rev);
    }

    c->pipeline = 0;

    h->pos = h->last = h->start;
    rev->event_handler = ngx_http_keepalive_handler;
    wev = c->write;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    ctx->action = "keepalive";

#if (HAVE_AIO_EVENT) /* aio, iocp */

    if ((ngx_event_flags & NGX_HAVE_AIO_EVENT) || blocked) {
        return ngx_http_keepalive_handler(rev);
    }

#else

    if (blocked) {
        return ngx_http_keepalive_handler(rev);
    }

#endif

    return NGX_OK;
}


static int ngx_http_keepalive_handler(ngx_event_t *rev)
{
    ssize_t n;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *lctx;

    c = (ngx_connection_t *) rev->data;

    ngx_log_debug(c->log, "http keepalive handler");

    if (rev->timedout) {
        return NGX_ERROR;  /* to close connection */
    }

    /* MSIE closes a keepalive connection with RST flag
       so we ignore ECONNRESET here */

    rev->ignore_econnreset = 1;
    ngx_set_socket_errno(0);
    n = ngx_event_recv(c, c->buffer->last, c->buffer->end - c->buffer->last);
    rev->ignore_econnreset = 0;

    if (n == NGX_AGAIN || n == NGX_ERROR) {
        return n;
    }

    lctx = (ngx_http_log_ctx_t *) rev->log->data;
    rev->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %s closed keepalive connection", lctx->client);
        return NGX_ERROR;  /* to close connection */
    }

    c->buffer->last += n;
    rev->log->handler = ngx_http_log_error;
    lctx->action = "reading client request line";

    return ngx_http_init_request(rev);
}


static int ngx_http_set_lingering_close(ngx_http_request_t *r)
{
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *lcf;

    c = r->connection;
    rev = c->read;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    r->lingering_time = ngx_time() + lcf->lingering_time / 1000;
    r->connection->read->event_handler = ngx_http_lingering_close_handler;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    } else {
        rev->timer_set = 1;
    }

    ngx_add_timer(rev, lcf->lingering_timeout);

    if (rev->blocked && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR) {
            return ngx_http_close_request(r, 0);
        }
        rev->blocked = 0;
    }

#if !(USE_KQUEUE)

    if (c->write->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(c->write, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
            return ngx_http_close_request(r, 0);
        }
    }

#endif

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                      ngx_shutdown_socket_n " failed");
        return ngx_http_close_request(r, 0);
    }

#if (USE_KQUEUE)

    if (rev->ready) {
        return ngx_http_lingering_close_handler(rev);
    }

#else

    if (rev->ready || (ngx_event_flags & NGX_HAVE_AIO_EVENT)) {
        return ngx_http_lingering_close_handler(rev);
    }

#endif

    return NGX_OK;
}


static int ngx_http_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *lcf;

    c = (ngx_connection_t *) rev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(c->log, "http lingering close handler");

    if (rev->timedout) {
        return ngx_http_close_request(r, 0);
    }

    timer = r->lingering_time - ngx_time();
    if (timer <= 0) {
        return ngx_http_close_request(r, 0);
    }

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (r->discarded_buffer == NULL) {

        /* TODO: r->header_in->start (if large headers are enabled)
                 or the end of parsed header (otherwise)
                 instead of r->header_in->last */

        if ((size_t)(r->header_in->end - r->header_in->last)
                                               >= lcf->discarded_buffer_size) {
            r->discarded_buffer = r->header_in->last;

        } else {
            ngx_test_null(r->discarded_buffer,
                          ngx_palloc(c->pool, lcf->discarded_buffer_size),
                          ngx_http_close_request(r, 0));
        }
    }

    do {
        n = ngx_event_recv(c, r->discarded_buffer, lcf->discarded_buffer_size);

        ngx_log_debug(c->log, "lingering read: %d" _ n);

        if (n == NGX_ERROR || n == 0) {
            return ngx_http_close_request(r, 0);
        }

    } while (rev->ready);

    timer *= 1000;
    if (timer > lcf->lingering_timeout) {
        timer = lcf->lingering_timeout;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    } else {
        rev->timer_set = 1;
    }
    ngx_add_timer(rev, timer);

    return NGX_OK;
}


static int ngx_http_close_connection(ngx_event_t *ev)
{
    return ngx_event_close_connection(ev);
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

    if (ctx->url) {
        return ngx_snprintf(buf, len, " while %s, client: %s, URL: %s",
                            ctx->action, ctx->client, ctx->url);
    } else {
        return ngx_snprintf(buf, len, " while %s, client: %s",
                            ctx->action, ctx->client);
    }
}
