
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
#include <ngx_inet.h>
#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>

/* STUB */
#include <ngx_http_output_filter.h>
int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_index_handler(ngx_http_request_t *r);
int ngx_http_proxy_handler(ngx_http_request_t *r);
/**/

int ngx_http_init_connection(ngx_connection_t *c);

static int ngx_http_init_request(ngx_event_t *ev);
static int ngx_http_process_request_header(ngx_event_t *ev);

static int ngx_http_process_request_line(ngx_http_request_t *r);
static int ngx_http_process_request_headers(ngx_http_request_t *r);
static int ngx_http_process_request_header_line(ngx_http_request_t *r);

static int ngx_http_event_request_handler(ngx_http_request_t *r);

static int ngx_http_writer(ngx_event_t *ev);
static int ngx_http_block_read(ngx_event_t *ev);
static int ngx_http_read_discarded_body(ngx_event_t *ev);
static int ngx_http_keepalive_handler(ngx_event_t *ev);
static int ngx_http_set_lingering_close(ngx_http_request_t *r);
static int ngx_http_lingering_close_handler(ngx_event_t *ev);

#if 0
int ngx_http_special_response(ngx_http_request_t *r, int error);
int ngx_http_redirect(ngx_http_request_t *r, int redirect);
int ngx_http_error(ngx_http_request_t *r, int error);
int ngx_http_close_request(ngx_http_request_t *r);
#endif

static int ngx_http_close_connection(ngx_event_t *ev);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);



static char *header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent too long URI",
    "client %s sent HEAD method in HTTP/0.9 request"
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
    struct sockaddr     *addr;
    ngx_http_log_ctx_t  *ctx;

    ev = c->read;
    ev->event_handler = ngx_http_init_request;

    ngx_test_null(c->pool,
                  ngx_create_pool(ngx_http_connection_pool_size, ev->log),
                  NGX_ERROR);

    ngx_test_null(c->requests, ngx_create_array(c->pool, 10, sizeof(char *)),
                  NGX_ERROR);

    ev->close_handler = ngx_http_close_connection;
    c->write->close_handler = ngx_http_close_connection;

    ngx_test_null(addr, ngx_palloc(c->pool, c->socklen), NGX_ERROR);
    ngx_memcpy(addr, c->sockaddr, c->socklen);
    c->sockaddr = addr;

    ngx_test_null(c->addr_text.data, ngx_palloc(c->pool, c->addr_text_max_len),
                  NGX_ERROR);

    c->addr_text.len = ngx_inet_ntop(c->family,
                                     (char *)c->sockaddr + c->addr,
                                     c->addr_text.data, c->addr_text_max_len);
    if (c->addr_text.len == 0)
       return NGX_ERROR;

    ngx_test_null(ctx, ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t)),
                  NGX_ERROR);
    ctx->client = c->addr_text.data;
    ctx->action = "reading client request line";
    c->log->data = ctx;
    c->log->handler = ngx_http_log_error;

#if (HAVE_DEFERRED_ACCEPT)
    if (ev->ready) {
        return ngx_http_init_request(ev);
    } else {
#endif
        ngx_add_timer(ev, c->post_accept_timeout);
#if (USE_KQUEUE)
        return ngx_add_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
#else
#if (HAVE_AIO_EVENT)
        if (ngx_event_type == NGX_AIO_EVENT)
            return ngx_http_init_request(ev);
        else
#endif
#if (HAVE_CLEAR_EVENT)
            if (ngx_event_type == NGX_KQUEUE_EVENT)
                return ngx_add_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
            else
#endif
                return ngx_add_event(ev, NGX_READ_EVENT, NGX_LEVEL_EVENT);
#endif /* USE_KQUEUE */
#if (HAVE_DEFERRED_ACCEPT)
    }
#endif
}


static int ngx_http_init_request(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;

    c = (ngx_connection_t *) ev->data;

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

    r->header_in = c->buffer;

    ngx_test_null(r->pool, ngx_create_pool(ngx_http_request_pool_size, ev->log),
                  ngx_http_close_request(r));

    ngx_test_null(r->ctx,
                  ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module),
                  ngx_http_close_request(r));

    r->headers_out.headers = ngx_create_table(r->pool, 10);
    r->headers_out.content_length = -1;
    r->headers_out.last_modified_time = -1;

    ev->event_handler = ngx_http_process_request_header;
    r->state_handler = ngx_http_process_request_line;
    r->header_timeout = 1;

    return ngx_http_process_request_header(ev);
}


static int ngx_http_process_request_header(ngx_event_t *ev)
{
    int n, rc;
    ngx_connection_t *c ;
    ngx_http_request_t *r;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http process request");

    if (r->header_read) {
        r->header_read = 0;
        ngx_log_debug(ev->log, "http preread %d" _
                      r->header_in->last.mem - r->header_in->pos.mem);

    } else {
        n = ngx_event_recv(c, r->header_in->last.mem,
                           r->header_in->end - r->header_in->last.mem);

        if (n == NGX_AGAIN) {
            if (r->header_timeout) {
                r->header_timeout = 0;
                ngx_del_timer(ev);
                ngx_add_timer(ev, ngx_http_client_header_timeout);
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
        rc = (r->state_handler)(r);

        if (rc == NGX_ERROR)
            return rc;

    } while (rc == NGX_AGAIN && r->header_in->pos.mem < r->header_in->last.mem);

    if (r->header_timeout) {
        r->header_timeout = 0;
        ngx_del_timer(ev);
        ngx_add_timer(ev, ngx_http_client_header_timeout);
    }

    if (rc == NGX_OK)
        return ngx_http_event_request_handler(r);
    else
        return rc;
}


static int ngx_http_process_request_line(ngx_http_request_t *r)
{
    int     rc, len;
    char  **request;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    rc = ngx_read_http_request_line(r);

    c = r->connection;

    if (rc == NGX_OK) {
        r->uri.len = (r->args_start ? r->args_start - 1 : r->uri_end)
                                                                - r->uri_start;
        ngx_test_null(r->uri.data, ngx_palloc(r->pool, r->uri.len + 1),
                      ngx_http_close_request(r));
        ngx_cpystrn(r->uri.data, r->uri_start, r->uri.len + 1);

        r->request_line.len = r->request_end - r->header_in->start;
        ngx_test_null(r->request_line.data,
                      ngx_palloc(r->pool, r->request_line.len + 1),
                      ngx_http_close_request(r));
        ngx_cpystrn(r->request_line.data, r->header_in->start,
                    r->request_line.len + 1);

        /* TEMP */
        ngx_test_null(request, ngx_push_array(c->requests),
                      ngx_http_close_request(r));

        if (r->request_end)
            len = r->request_end - r->header_in->start + 1;
        else
            len = 1;
        c->requests_len += len;
        ngx_test_null(*request, ngx_palloc(c->pool, len),
                      ngx_http_close_request(r));
        ngx_cpystrn(*request, r->header_in->start, len);

        ngx_log_debug(c->log, "REQ: '%s'" _ *request);
        /* */

        if (r->uri_ext) {
            r->exten.len = (r->args_start ? r->args_start - 1 : r->uri_end)
                                                                  - r->uri_ext;
            ngx_test_null(r->exten.data,
                          ngx_palloc(r->pool, r->exten.len + 1), 
                          ngx_http_close_request(r));
            ngx_cpystrn(r->exten.data, r->uri_ext, r->exten.len + 1);
        }

#if 0
        ngx_log_debug(r->connection->log, "HTTP: %d, %d, %s %s" _
                      r->method _ r->http_version _
                      r->uri.data _ r->exten.data);
#endif

        if (r->http_version == 9)
            return NGX_OK;

        /* TODO: check too long URI - no space for header, compact buffer */

        r->headers_in.headers = ngx_create_table(r->pool, 10);

        r->state_handler = ngx_http_process_request_headers;
        ctx = r->connection->log->data;
        ctx->action = "reading client request headers";

        return NGX_AGAIN;
    }

    if (r->header_in->last.mem >= r->header_in->end) {
        rc = NGX_HTTP_PARSE_TOO_LONG_URI;

    } else if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    ctx = r->connection->log->data;
    r->connection->log->handler = NULL;
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  header_errors[rc - NGX_HTTP_PARSE_INVALID_METHOD],
                  ctx->client);
    r->connection->log->handler = ngx_http_log_error;

    return ngx_http_error(r, (rc == NGX_HTTP_PARSE_TOO_LONG_URI) ?
                                 NGX_HTTP_REQUEST_URI_TOO_LARGE:
                                 NGX_HTTP_BAD_REQUEST);
}


static int ngx_http_process_request_headers(ngx_http_request_t *r)
{
    int rc;
    ngx_http_log_ctx_t  *ctx;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r, r->header_in);

        /* TODO: check too long header, compact buffer */

        if (rc == NGX_OK) {
            if (ngx_http_process_request_header_line(r) == NGX_ERROR)
                return ngx_http_error(r, NGX_HTTP_BAD_REQUEST);

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug(r->connection->log, "HTTP header done");

            if (r->http_version > NGX_HTTP_VERSION_10
                && r->headers_in.host == NULL)
            {
                return ngx_http_error(r, NGX_HTTP_BAD_REQUEST);
            } else {
                return NGX_OK;
            }

        } else if (rc == NGX_AGAIN) {
            return NGX_AGAIN;

        } else if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {
            ctx = r->connection->log->data;
            r->connection->log->handler = NULL;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client %s sent invalid header", ctx->client);
            r->connection->log->handler = ngx_http_log_error;

            return ngx_http_error(r, NGX_HTTP_BAD_REQUEST);
        }
    }
}


static int ngx_http_process_request_header_line(ngx_http_request_t *r)
{
    int  i;
    ngx_table_elt_t *h;

    ngx_test_null(h, ngx_push_table(r->headers_in.headers), NGX_ERROR);

    h->key.len = r->header_name_end - r->header_name_start;
    ngx_test_null(h->key.data, ngx_palloc(r->pool, h->key.len + 1), NGX_ERROR);
    ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);

    h->value.len = r->header_end - r->header_start;
    ngx_test_null(h->value.data, ngx_palloc(r->pool, h->value.len + 1),
                  NGX_ERROR);
    ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

    for (i = 0; headers_in[i].len != 0; i++) {
        if (headers_in[i].len == h->key.len) {
            if (ngx_strcasecmp(headers_in[i].data, h->key.data) == 0) {
                *((ngx_table_elt_t **)
                    ((char *) &r->headers_in + headers_in[i].offset)) = h;
            }
        }
    }

    ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                  h->key.data _ h->value.data);

    return NGX_OK;
}


static int ngx_http_event_request_handler(ngx_http_request_t *r)
{
    int rc;
    ngx_msec_t  timeout;

    ngx_del_timer(r->connection->read);
    r->header_timeout = 0;

    r->state_handler = NULL;
    r->connection->read->event_handler = ngx_http_block_read;

    rc = ngx_http_handler(r);

    /* handler is still busy */
    if (rc == NGX_WAITING)
        return rc;

    /* handler has done its work but transfer is not completed */
    if (rc == NGX_AGAIN) {
#if (HAVE_CLEAR_EVENT)
        if (ngx_add_event(r->connection->write, NGX_WRITE_EVENT,
                          NGX_CLEAR_EVENT) == NGX_ERROR) {
#else
        if (ngx_add_event(r->connection->write, NGX_WRITE_EVENT,
                          NGX_ONESHOT_EVENT) == NGX_ERROR) {
#endif
            return ngx_http_close_request(r);
        }

        if (r->connection->sent > 0) {
            ngx_log_debug(r->connection->log, "sent: " QD_FMT _
                          r->connection->sent);
            timeout = (ngx_msec_t) (r->connection->sent * 10);
            ngx_log_debug(r->connection->log, "timeout: %d" _ timeout);
            ngx_add_timer(r->connection->write, timeout);

        } else {
            ngx_add_timer(r->connection->write, 10000);
        }

        r->connection->write->event_handler = ngx_http_writer;
        return rc;
    }

    if (rc == NGX_ERROR) {
        /* log http request */
        return ngx_http_close_request(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return ngx_http_special_response(r, rc);

    /* rc == NGX_OK */

    if (!r->keepalive) {
        if (r->lingering_close) {
            return ngx_http_set_lingering_close(r);

        } else {
            return ngx_http_close_request(r);
        }
    }

    /* keepalive */

    ngx_http_close_request(r);
    r->connection->buffer->pos.mem = r->connection->buffer->last.mem
                                               = r->connection->buffer->start;
    r->connection->read->event_handler = ngx_http_keepalive_handler;
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

    c->sent = 0;

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug(ev->log, "output filter in writer: %d" _ rc);

    if (rc == NGX_AGAIN) {

        if (c->sent > 0) {
            conf = (ngx_http_core_loc_conf_t *)
                        ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                                     ngx_http_core_module_ctx);

            timeout = (ngx_msec_t) (c->sent * conf->send_timeout);

            ngx_log_debug(ev->log, "sent: " QD_FMT _ c->sent);
            ngx_log_debug(ev->log, "timeout: %d" _ timeout);

            ngx_del_timer(ev);
            ngx_add_timer(ev, timeout);
        }

        if (ev->oneshot)
            if (ngx_add_event(r->connection->write, NGX_WRITE_EVENT,
                              NGX_ONESHOT_EVENT) == NGX_ERROR) {
            return ngx_http_close_request(r);
        }

        return rc;
    }

    if (rc == NGX_ERROR)
        return rc;

    /* rc == NGX_OK */

    ngx_log_debug(ev->log, "http writer done");

    if (!r->keepalive) {
        if (r->lingering_close) {
            return ngx_http_set_lingering_close(r);

        } else {
            return ngx_http_close_request(r);
        }
    }

    /* keepalive */

    ngx_http_close_request(r);
    c->buffer->pos.mem = c->buffer->last.mem = c->buffer->start;
    c->read->event_handler = ngx_http_keepalive_handler;
}


static int ngx_http_block_read(ngx_event_t *ev)
{
    ngx_log_debug(ev->log, "http read blocked");

    ev->blocked = 1;
    return ngx_del_event(ev, NGX_READ_EVENT, 0);
}


int ngx_http_discard_body(ngx_http_request_t *r)
{
    ngx_log_debug(r->connection->log, "set discard body");

    ngx_del_timer(r->connection->read);

    if (r->client_content_length)
        r->connection->read->event_handler = ngx_http_read_discarded_body;

    return NGX_OK;
}


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


static int ngx_http_keepalive_handler(ngx_event_t *ev)
{
    ssize_t n;
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "http keepalive handler");

    if (ev->timedout)
        return NGX_DONE;

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
    ngx_http_core_loc_conf_t  *lcf;

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    r->lingering_time = ngx_time() + lcf->lingering_time;
    r->connection->read->event_handler = ngx_http_lingering_close_handler;

    ngx_del_timer(r->connection->read);
    ngx_add_timer(r->connection->read, lcf->lingering_timeout);

    if (r->connection->read->blocked) {
        if (ngx_add_event(r->connection->read, NGX_READ_EVENT,
#if (HAVE_CLEAR_EVENT)
                          NGX_CLEAR_EVENT) == NGX_ERROR)
#else
                          NGX_ONESHOT_EVENT) == NGX_ERROR)
#endif
        {
            return ngx_http_close_request(r);
        }
    }

    if (ngx_shutdown_socket(r->connection->fd, NGX_WRITE_SHUTDOWN) == -1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                      ngx_shutdown_socket_n " failed");
        return ngx_http_close_request(r);
    }

    return NGX_OK;
}


static int ngx_http_lingering_close_handler(ngx_event_t *ev)
{
    ssize_t              n;
    ngx_msec_t           timer;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_core_loc_conf_t  *lcf;

    ngx_log_debug(ev->log, "http lingering close handler");

    if (ev->timedout) {
        return ngx_http_close_request(r);
    }

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    timer = r->lingering_time - ngx_time();
    if (timer <= 0) {
        return ngx_http_close_request(r);
    }

    lcf = (ngx_http_core_loc_conf_t *)
                     ngx_http_get_module_loc_conf(r, ngx_http_core_module_ctx);

    if (r->discarded_buffer == NULL) {
        if (r->header_in->end - r->header_in->last.mem
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

    ngx_del_timer(ev);
    ngx_add_timer(ev, timer);

    return NGX_OK;
}


static int ngx_http_close_connection(ngx_event_t *ev)
{
    int    i, len;
    char **requests, *requests_line, *prev, *new;
    ngx_connection_t *c = (ngx_connection_t *) ev->data;

    if (c->requests->nelts > 1) {
        len = c->requests_len + c->requests->nelts * 2 - 1;

        ngx_test_null(requests_line, ngx_palloc(c->pool, len),
                      ngx_event_close_connection(ev));

        requests = (char **) c->requests->elts;
        prev = requests_line;
        new = ngx_cpystrn(prev, requests[0], len);
        len -= new - prev;
        prev = new;

        for (i = 1; i < c->requests->nelts; i++) { 
            new = ngx_cpystrn(prev, ", ", len);
            new = ngx_cpystrn(new, requests[i], len);
            len -= new - prev;
            prev = new;
        }

    } else {
        requests_line = * (char **) c->requests->elts;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "REQUESTS: %d, '%s'", c->requests->nelts, requests_line);

    return ngx_event_close_connection(ev);
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
