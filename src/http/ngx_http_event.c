/*
   TODO Win32 inet_ntoa
        ngx_inet_ntop
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_http.h>
#include <ngx_http_config.h>

/* STUB */
#include <ngx_http_output_filter.h>
int ngx_http_static_handler(ngx_http_request_t *r);
int ngx_http_index_handler(ngx_http_request_t *r);
/* */

/* STUB */
#define LINGERING_TIMEOUT    2 
#define SOME_LINGERING_TIME  30

int ngx_http_init_connection(ngx_connection_t *c);

static int ngx_http_init_request(ngx_event_t *ev);
static int ngx_http_process_request(ngx_event_t *ev);

static int ngx_http_process_request_line(ngx_http_request_t *r);
static int ngx_http_process_request_header(ngx_http_request_t *r);
static int ngx_http_process_request_header_line(ngx_http_request_t *r);

static int ngx_http_block_read(ngx_event_t *ev);
static int ngx_http_read_discarded_body(ngx_event_t *ev);

static int ngx_http_handler(ngx_http_request_t *r);
static int ngx_http_set_default_handler(ngx_http_request_t *r);

static int ngx_http_writer(ngx_event_t *ev);
static int ngx_http_keepalive_handler(ngx_event_t *ev);
static int ngx_http_lingering_close(ngx_event_t *ev);

static int ngx_http_special_response(ngx_http_request_t *r, int error);
static int ngx_http_redirect(ngx_http_request_t *r, int redirect);
static int ngx_http_error(ngx_http_request_t *r, int error);

static int ngx_http_close_request(ngx_http_request_t *r);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);



static char *header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent too long URI",
    "client %s sent HEAD method in HTTP/0.9 request"
};



int ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *ev;
    struct sockaddr     *addr;
    ngx_http_log_ctx_t  *ctx;

    ev = c->read;
    ev->event_handler = ngx_http_init_request;

    ngx_test_null(c->pool,
                  ngx_create_pool(srv->connection_pool_size, ev->log),
                  NGX_ERROR);

    ngx_test_null(addr, ngx_palloc(c->pool, c->socklen), NGX_ERROR);
    ngx_memcpy(addr, c->sockaddr, c->socklen);
    c->sockaddr = addr;

    ngx_test_null(c->addr_text, ngx_palloc(c->pool, c->addr_textlen),
                  NGX_ERROR);
#if (WIN32)
    c->addr_text = inet_ntoa((struct in_addr) ((char *)c->sockaddr + c->addr));
#else
    inet_ntop(c->family, (char *)c->sockaddr + c->addr,
              c->addr_text, c->addr_textlen);
#endif

    ngx_test_null(ctx, ngx_pcalloc(c->pool, sizeof(ngx_http_log_ctx_t)),
                  NGX_ERROR);
    ctx->client = c->addr_text;
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
    ngx_connection_t    *c;
    ngx_http_server_t   *srv;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    srv = (ngx_http_server_t *) c->server;

    if (c->buffer == NULL) {
        ngx_test_null(c->buffer,
                      ngx_create_temp_hunk(c->pool, srv->header_buffer_size,
                                           0, 0),
                      NGX_ERROR);
    } else {
        c->buffer->pos.mem = c->buffer->last.mem = c->buffer->start;
    }

    ngx_test_null(r, ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)),
                  NGX_ERROR);

    c->data = r;
    r->connection = c;
    r->server = srv;
    r->header_in = c->buffer;

    r->srv_conf = ngx_srv_conf;
    r->loc_conf = ngx_loc_conf;

    ngx_test_null(r->pool, ngx_create_pool(srv->request_pool_size, ev->log),
                  ngx_http_close_request(r));

    ngx_test_null(r->ctx, ngx_pcalloc(r->pool, sizeof(void *) * ngx_max_module),
                  ngx_http_close_request(r));

    ev->event_handler = ngx_http_process_request;
    r->state_handler = ngx_http_process_request_line;
    r->process_header = 1;
    r->header_timeout = 1;

    return ngx_http_process_request(ev);
}


static int ngx_http_process_request(ngx_event_t *ev)
{
    int n, rc;
    ngx_connection_t *c ;
    ngx_http_request_t *r;
    ngx_http_log_ctx_t  *ctx;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http process request");

    n = ngx_event_recv(c, r->header_in->last.mem,
                       r->header_in->end - r->header_in->last.mem);

    if (n == NGX_AGAIN) {
        if (r->header_timeout) {
            r->header_timeout = 0;
            ngx_del_timer(ev);
            ngx_add_timer(ev, r->server->header_timeout);
        }
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR)
        return ngx_http_close_request(r);

    ngx_log_debug(ev->log, "http read %d" _ n);

    if (n == 0) {
        if (c->unexpected_eof)
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        return ngx_http_close_request(r);
    }

    r->header_in->last.mem += n;

    /* state_handlers are called in following order:
        ngx_http_process_request_line(r)
        ngx_http_process_request_header(r) */

    do {
        rc = (r->state_handler)(r);

        if (rc == NGX_ERROR)
            return rc;

        /* rc == NGX_OK || rc == NGX_AGAIN */

    } while (r->process_header
             && r->header_in->pos.mem < r->header_in->last.mem);

    if (r->header_timeout) {
        r->header_timeout = 0;
        ngx_del_timer(ev);
        ngx_add_timer(ev, r->server->header_timeout);
    }

    return rc;
}


static int ngx_http_process_request_line(ngx_http_request_t *r)
{
    int rc;
    ngx_http_log_ctx_t  *ctx;

    rc = ngx_read_http_request_line(r);

    if (rc == NGX_OK) {
        ngx_test_null(r->uri,
                      ngx_palloc(r->pool, r->uri_end - r->uri_start + 1), 
                      ngx_http_close_request(r));
        ngx_cpystrn(r->uri, r->uri_start, r->uri_end - r->uri_start + 1);

        ngx_log_debug(r->connection->log, "HTTP: %d, %d, %s" _
                      r->method _ r->http_version _ r->uri);

        if (r->http_version == 9)
            return ngx_http_handler(r);

        /* TODO: check too long URI - no space for header, compact buffer */

        r->state_handler = ngx_http_process_request_header;
        ctx = r->connection->log->data;
        ctx->action = "reading client request headers";

        return NGX_OK;
    }

    if (r->header_in->last.mem >= r->header_in->end) {
        rc == NGX_HTTP_PARSE_TOO_LONG_URI;

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


static int ngx_http_process_request_header(ngx_http_request_t *r)
{
    int rc;
    ngx_http_log_ctx_t  *ctx;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r);

        /* TODO: check too long header, compact buffer */

        if (rc == NGX_OK) {
            if (ngx_http_process_request_header_line(r) == NGX_ERROR)
                return ngx_http_error(r, NGX_HTTP_BAD_REQUEST);

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug(r->connection->log, "HTTP header done");
            return ngx_http_handler(r);

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
    /* STUB */
    *r->header_name_end = '\0';
    *r->header_end = '\0';
    ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                  r->header_name_start _ r->header_start);

    return NGX_OK;
}


/* ******************** */

void ngx_http_discard_body(ngx_http_request_t *r)
{
    ngx_log_debug(r->connection->log, "set discard body");

    ngx_del_timer(r->connection->read);

    if (r->client_content_length)
        r->connection->read->event_handler = ngx_http_read_discarded_body;
}

static int ngx_http_read_discarded_body(ngx_event_t *ev)
{
    size_t   size;
    ssize_t  n;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http read discarded body");

    if (ev->timedout)
        return NGX_ERROR;

    if (r->discarded_buffer == NULL)
        ngx_test_null(r->discarded_buffer,
                      ngx_palloc(r->pool, r->server->discarded_buffer_size),
                      NGX_ERROR);

    size = r->client_content_length;
    if (size > r->server->discarded_buffer_size)
        size = r->server->discarded_buffer_size;

    n = ngx_event_recv(c, r->discarded_buffer, size);
    if (n == NGX_ERROR)
        return NGX_ERROR;

    if (n == NGX_AGAIN)
        return NGX_OK;

    r->client_content_length -= n;
    /* XXX: what if r->client_content_length == 0 ? */
    return NGX_OK;
}

static int ngx_http_discarded_read(ngx_event_t *ev)
{
    ssize_t n;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http discarded read");

    if (ev->timedout)
        return NGX_ERROR;

    if (r->discarded_buffer == NULL)
        ngx_test_null(r->discarded_buffer,
                      ngx_palloc(r->pool, r->server->discarded_buffer_size),
                      NGX_ERROR);

    n = ngx_event_recv(c, r->discarded_buffer,
                       r->server->discarded_buffer_size);

    return n;
}

/* ******************** */

static int ngx_http_handler(ngx_http_request_t *r)
{
    int  rc;
    ngx_msec_t  timeout;

    ngx_del_timer(r->connection->read);
    r->header_timeout = 0;

    r->process_header = 0;
    r->state_handler = NULL;
    r->connection->unexpected_eof = 0;
    r->lingering_close = 1;

    r->connection->read->event_handler = ngx_http_block_read;

    /* STUB: should find handler */
    r->filter = NGX_HTTP_FILTER_NEED_IN_MEMORY;
    rc = ngx_http_set_default_handler(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return ngx_http_special_response(r, rc);

    rc = r->handler(r);

    /* transfer not completed */
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
            r->lingering_time = ngx_time() + SOME_LINGERING_TIME;
            r->connection->read->event_handler = ngx_http_lingering_close;
            ngx_del_timer(r->connection->read);
            ngx_add_timer(r->connection->read, LINGERING_TIMEOUT * 1000);
            if (ngx_add_event(r->connection->read, NGX_READ_EVENT,
                              NGX_ONESHOT_EVENT) == NGX_ERROR) {
               return ngx_http_close_request(r);
            }
            if (ngx_shutdown_socket(r->connection->fd, NGX_WRITE_SHUTDOWN)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                              ngx_shutdown_socket_n " failed");
                return ngx_http_close_request(r);
            }
        } else {
            return ngx_http_close_request(r);
        }
    }
}

int ngx_http_internal_redirect(ngx_http_request_t *r, char *uri)
{
    ngx_log_debug(r->connection->log, "internal redirect: '%s'" _ uri);

    r->uri = uri;
    r->uri_start = uri;
    r->uri_end = uri + strlen(uri);
    return ngx_http_handler(r);
}

static int ngx_http_set_default_handler(ngx_http_request_t *r)
{
    int   err, rc;
    char *name, *loc, *file;

    ngx_test_null(r->headers_out,
                  ngx_pcalloc(r->pool, sizeof(ngx_http_headers_out_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    if (*(r->uri_end - 1) == '/') {
        r->handler = ngx_http_index_handler;
        return NGX_OK;
    }

    /* 20 bytes is spare space for some index name, i.e. index.html */
    r->filename_len = r->uri_end - r->uri_start + r->server->doc_root_len + 20;

    ngx_test_null(r->filename,
                  ngx_palloc(r->pool, r->filename_len),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    r->location = ngx_cpystrn(r->filename, r->server->doc_root,
                              r->server->doc_root_len);
    file = ngx_cpystrn(r->location, r->uri_start,
                       r->uri_end - r->uri_start + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _ r->filename);

    if (ngx_file_type(r->filename, &r->fileinfo) == -1) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                      ngx_file_type_n " %s failed", r->filename);

        if (err == NGX_ENOENT)
            return NGX_HTTP_NOT_FOUND;
        else
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_is_dir(r->fileinfo)) {
        ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->filename);
        *file++ = '/';
        *file = '\0';
        r->headers_out->location = r->location;
        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    r->handler = ngx_http_static_handler;

    return NGX_OK;
}


static int ngx_http_block_read(ngx_event_t *ev)
{
    ngx_log_debug(ev->log, "http read blocked");

    ngx_del_event(ev, NGX_READ_EVENT);
    ev->blocked = 1;
}


static int ngx_http_writer(ngx_event_t *ev)
{
    int rc;
    unsigned int timeout;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    c->sent = 0;

    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug(ev->log, "output_filter: %d" _ rc);

    if (rc == NGX_AGAIN) {

        if (c->sent > 0) {
            ngx_log_debug(ev->log, "sent: " QD_FMT _ c->sent);
            timeout = (ngx_msec_t) (c->sent * 10);
            ngx_log_debug(ev->log, "timeout: %d" _ timeout);
            ngx_del_timer(ev);
            ngx_add_timer(ev, timeout);
        }

        if (ev->oneshot)
            if (ngx_add_event(r->connection->write, NGX_WRITE_EVENT,
                              NGX_ONESHOT_EVENT) == NGX_ERROR) {
            /* log http request */
            return ngx_http_close_request(r);
        }

        return rc;
    }

    if (rc == NGX_ERROR)
        return rc;

    /* rc == NGX_OK */

    ngx_log_debug(ev->log, "ngx_http_writer done");

    if (!r->keepalive) {
        if (r->lingering_close) {
            r->lingering_time = ngx_time() + SOME_LINGERING_TIME;
            r->connection->read->event_handler = ngx_http_lingering_close;
            ngx_del_timer(r->connection->read);
            ngx_add_timer(r->connection->read, LINGERING_TIMEOUT * 1000);
            if (ngx_add_event(r->connection->read, NGX_READ_EVENT,
                              NGX_ONESHOT_EVENT) == NGX_ERROR) {
               return ngx_http_close_request(r);
            }
            if (ngx_shutdown_socket(r->connection->fd, NGX_WRITE_SHUTDOWN)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_socket_errno,
                              ngx_shutdown_socket_n " failed");
                return ngx_http_close_request(r);
            }
        } else {
            return ngx_http_close_request(r);
        }
    }

    /* keepalive */
    ev = r->connection->read;
    ngx_http_close_request(r);
    ev->event_handler = ngx_http_init_request;
}

#if 0

static int ngx_http_keepalive_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

    ngx_log_debug(ev->log, "http keepalive");

    if (ev->timedout)
        return NGX_DONE;

    if (closed)
        /* NGX_LOG_INFO or even silent */
        return NGX_ERROR;

    c = (ngx_connection_t *) ev->data;

    ctx = (ngx_http_log_ctx_t *) c->log->data;
    ctx->action = "reading client request line";
    c->log->handler = ngx_http_log_error;

    return ngx_http_init_request(ev);
}

#endif

static int ngx_http_lingering_close(ngx_event_t *ev)
{
    ssize_t  n;
    ngx_msec_t   timer;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http lingering close");

    if (ev->timedout)
        return NGX_DONE;

    /* STUB */
    timer = r->lingering_time - ngx_time();
    if (timer <= 0)
        return NGX_DONE;

    if (r->discarded_buffer == NULL)
        ngx_test_null(r->discarded_buffer,
                      ngx_palloc(r->pool, r->server->discarded_buffer_size),
                      NGX_ERROR);

    n = ngx_event_recv(c, r->discarded_buffer,
                       r->server->discarded_buffer_size);

    if (n == NGX_ERROR)
        return NGX_ERROR;

    if (n == 0)
        return NGX_DONE;

    if (timer > LINGERING_TIMEOUT)
        timer = LINGERING_TIMEOUT;

    ngx_del_timer(ev);
    ngx_add_timer(ev, timer * 1000);

    return NGX_OK;
}


static int ngx_http_special_response(ngx_http_request_t *r, int error)
{
    return ngx_http_error(r, error);
}

static int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    return ngx_http_close_request(r);
}

static int ngx_http_error(ngx_http_request_t *r, int error)
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    return ngx_http_close_request(r);
}

#if 0

static int ngx_process_http_request(ngx_http_request_t *r)
{
    int fd;
    struct stat sb;
    ngx_http_header_out_t  *header_out;
    ngx_chunk_t            *header, *ch;

    int index = (*(r->uri_end - 1) == '/') ? sizeof(NGX_INDEX) : 1;
    char *name = ngx_palloc(r->pool,
                           r->uri_end - r->uri_start + strlen(ngx_root) + index);
    strcpy(name, ngx_root);
    strcat(name, r->uri_start);
    if (*(r->uri_end - 1) == '/')
        strcat(name, NGX_INDEX);

    ngx_log_debug(r->connection->log, "HTTP URI: '%s'", name);

    if ((fd = open(name, O_RDONLY)) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                     "open %s failed", name);
        return -1;
    }

    if (fstat(fd, &sb) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                     "fstat %s failed", name);
        return -1;
    }

    header_out = ngx_palloc(r->pool, sizeof(ngx_http_header_out_t));

    header_out->status = NGX_HTTP_OK;
    header_out->content_length = sb.st_size;
    header_out->last_modified = sb.st_mtime;
    header_out->content_type = "text/html";
    header_out->charset = "koi8-r";
    header_out->date = time(NULL);
    header_out->connection = NGX_HTTP_CONN_CLOSE;

/*
    header_out->connection = NGX_HTTP_CONN_KEEP_ALIVE;
    r->connection->read->event_handler = ngx_http_init_request;
*/

    header = ngx_http_header(r, header_out);
    ch = ngx_palloc(r->pool, sizeof(ngx_chunk_t));
    ch->ident = fd;
    ch->offset = 0;
    ch->size = sb.st_size;
    ch->next = NULL;
    header->next = ch;

    ngx_event_write(r->connection, header);

    return 0;
}

#endif

static int ngx_http_close_request(ngx_http_request_t *r)
{
/*
    if (r->logging)
        ngx_http_log_request(r);
*/

    ngx_destroy_pool(r->pool);

    ngx_log_debug(r->connection->log, "http close");

    ngx_del_timer(r->connection->read);
    ngx_del_timer(r->connection->write);

    return NGX_DONE;
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
