
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>

#include <ngx_http.h>

int ngx_http_init_connection(ngx_connection_t *c);

static int ngx_http_init_request(ngx_event_t *ev);
static int ngx_http_process_request(ngx_event_t *ev);

static int ngx_http_process_request_line(ngx_http_request_t *r);
static int ngx_http_process_request_header(ngx_http_request_t *r);

static int ngx_http_process_http_request(ngx_http_request_t *r);

static int ngx_http_close_request(ngx_http_request_t *r);
static size_t ngx_http_log_error(void *data, char *buf, size_t len);


/* STUB */
static int ngx_http_writer(ngx_event_t *ev);


static char *header_errors[] = {
    "client %s sent invalid method",
    "client %s sent invalid request",
    "client %s sent HEAD method in HTTP/0.9 request"
};



int ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t         *ev;
    struct sockaddr     *addr;
    ngx_http_log_ctx_t  *ctx;

    ev = c->read;
    ev->event_handler = ngx_http_init_request;

    /* TODO: connection's pool size */
    ngx_test_null(c->pool, ngx_create_pool(1024, ev->log), NGX_ERROR);

    ngx_test_null(addr, ngx_palloc(c->pool, c->socklen), NGX_ERROR);
    ngx_memcpy(addr, c->sockaddr, c->socklen);
    c->sockaddr = addr;

    ngx_test_null(c->addr_text, ngx_palloc(c->pool, c->addr_textlen),
                  NGX_ERROR);
    inet_ntop(c->family, (char *)c->sockaddr + c->addr,
              c->addr_text, c->addr_textlen);

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


int ngx_http_init_request(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_server_t   *srv;
    ngx_http_request_t  *r;

    c = (ngx_connection_t *) ev->data;
    srv = (ngx_http_server_t *) c->server;

    ngx_test_null(r, ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)),
                  NGX_ERROR);

    c->data = r;
    r->connection = c;
    r->server = srv;

    /* TODO: request's pool size */
    ngx_test_null(r->pool, ngx_create_pool(16384, ev->log),
                  ngx_http_close_request(r));

    ngx_test_null(r->header_in,
                  ngx_create_temp_hunk(r->pool, srv->buff_size, 0, 0),
                  ngx_http_close_request(r));

    ev->event_handler = ngx_http_process_request;
    r->state_handler = ngx_http_process_request_line;

    return ngx_http_process_request(ev);
}


int ngx_http_process_request(ngx_event_t *ev)
{
    int n, rc;
    ngx_connection_t *c ;
    ngx_http_request_t *r;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http process request");

    n = ngx_event_recv(c, r->header_in->last.mem,
                       r->header_in->end - r->header_in->last.mem);

    if (n == NGX_AGAIN) {
        if (!r->header_timeout) {
            r->header_timeout = 1;
            ngx_del_timer(ev);
            ngx_add_timer(ev, r->server->header_timeout);
        }
        return NGX_AGAIN;
    }

    if (n == NGX_ERROR)
        return ngx_http_close_request(r);

    ngx_log_debug(ev->log, "http read %d" _ n);

    if (n == 0) {
        /* STUB: c-> */
        if (ev->unexpected_eof)
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

    } while (r->header_in->pos.mem < r->header_in->last.mem);
             
    if (!r->header_timeout) {
        r->header_timeout = 1;
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

        if (r->http_version == 9) {
            /* set lock event */
            return ngx_http_process_http_request(r);
        }

        r->state_handler = ngx_http_process_request_header;
        r->connection->read->action = "reading client request headers";

        return NGX_OK;
    }

    r->connection->log->handler = NULL;
    ctx = r->connection->log->data;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  header_errors[rc - NGX_HTTP_INVALID_METHOD], ctx->client);

    r->connection->log->handler = ngx_http_log_error;

    /* STUB return ngx_http_error(r, NGX_HTTP_BAD_REQUEST)  */
    return ngx_http_close_request(r);
}

static int ngx_http_process_request_header(ngx_http_request_t *r)
{
    int rc;
    ngx_http_log_ctx_t  *ctx;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r);

        if (rc == NGX_OK) {
            *r->header_name_end = '\0';
            *r->header_end = '\0';
            ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                          r->header_name_start _ r->header_start);

        } else if (rc == NGX_AGAIN) {
            return NGX_AGAIN;

        } else if (rc == NGX_HTTP_HEADER_DONE) {
            break;

        } else if (rc == NGX_HTTP_INVALID_HEADER) {
            r->connection->log->handler = NULL;
            ctx = r->connection->log->data;
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client %s sent invalid header", ctx->client);
            r->connection->log->handler = ngx_http_log_error;

            /* STUB return ngx_http_error(r, NGX_HTTP_BAD_REQUEST)  */
            return ngx_http_close_request(r);
        }
    }

    r->state_handler = NULL;
    r->connection->read->action = "reading client request body";

    r->connection->read->read_discarded = 1;
    r->connection->read->unexpected_eof = 0;
    ngx_log_debug(r->connection->log, "HTTP header done");

    ngx_del_timer(r->connection->read);

    return ngx_http_process_http_request(r);
}

#if 0
static int ngx_http_lock_read(ngx_event_t *ev)
{
    ngx_del_event(ev, NGX_READ_EVENT);
    ev->read_blocked = 1;
}
#endif

static int ngx_http_process_http_request(ngx_http_request_t *r)
{
    int   err, rc;
    char *name, *loc, *file;

    ngx_log_debug(r->connection->log, "HTTP request");

    ngx_test_null(r->headers_out,
                  ngx_pcalloc(r->pool, sizeof(ngx_http_headers_out_t)),
                  ngx_http_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR));

    if (*(r->uri_end - 1) == '/') {
        r->handler = NGX_HTTP_DIRECTORY_HANDLER;
        return NGX_OK;
    }

    /* 20 bytes is spare space for some index name, i.e. index.html */
    r->filename_len = r->uri_end - r->uri_start + r->server->doc_root_len + 20;

    ngx_test_null(r->filename,
                  ngx_palloc(r->pool, r->filename_len),
                  ngx_http_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR));

    r->location = ngx_cpystrn(r->filename, r->server->doc_root,
                              r->server->doc_root_len);
    file = ngx_cpystrn(r->location, r->uri_start,
                       r->uri_end - r->uri_start + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _ r->filename);

    if (ngx_file_type(r->filename, &r->file_info) == -1) {
        err = ngx_errno;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                     "ngx_process_http_request: "
                      ngx_file_type_n " %s failed", r->filename);

        if (err == NGX_ENOENT)
            return ngx_http_error(r, NGX_HTTP_NOT_FOUND);
        else
            return ngx_http_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (ngx_is_dir(r->file_info)) {
        ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->filename);
        *file++ = '/';
        *file = '\0';
        r->headers_out->location = r->location;
        return ngx_http_redirect(r, NGX_HTTP_MOVED_PERMANENTLY);
    }

    /* STUB */
    rc =  ngx_http_static_handler(r);
    if (rc == 0) {
        r->connection->write->event_handler = ngx_http_writer;
        ngx_add_event(r->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);
    }
    return rc;

    r->handler = NGX_HTTP_STATIC_HANDLER;
    return NGX_OK;
}

#if 0

static int ngx_http_handler(ngx_http_request_t *r)
{
    find_http_handler();

    if (r->discard_body && r->connection->read->ready)
        ngx_http_discarad_body();

    rc = http_handler();

    /* transfer not completed */
    if (rc == NGX_AGAIN)
        return rc;

    if (rc == NGX_ERROR) {
        log http request
        close http request
        return rc;
    }

    if (rc > 300) {
        send special response
    }

    /* rc == NGX_OK */

    if (!keepalive)
        if (linger)
            set linger timeout on read
            shutdown socket
        else
            close socket

    log http request
    close http request
    if (keepalive)
        return NGX_OK;
    else
        close connection
        return NGX_OK;
}

static int ngx_http_writer(ngx_event_t *ev)
{
    int rc;

    ngx_connection_t   *c = (ngx_connection_t *) ev->data;
    ngx_http_request_t *r = (ngx_http_request_t *) c->data;

    rc = ngx_http_filter(r, NULL);

    if (rc == NGX_AGAIN)
        return rc;

    if (rc == NGX_ERROR)
        return rc;

    /* rc == NGX_OK */


    if (!keepalive)
        if (linger)
            shutdown socket
        else
            close socket

    log http request
    close http request
    if (keepalive)
        return NGX_OK;
    else
        close connection
        return NGX_OK;
}

static int ngx_http_discarded_read(ngx_event_t *ev)
{
    if (ev->timedout)
        return NGX_ERROR;

    while (full) {
        recv();
    }

    return NGX_OK;
}

static int ngx_http_keepalive_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_log_ctx_t  *ctx;

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


static int ngx_http_writer(ngx_event_t *ev)
{
    int rc;
    ngx_connection_t   *c = (ngx_connection_t *) ev->data;
    ngx_http_request_t *r = (ngx_http_request_t *) c->data;

    rc = ngx_http_write_filter(r, NULL);
    ngx_log_debug(r->connection->log, "write_filter: %d" _ rc);
    return rc;
}

static int ngx_http_handler(ngx_http_request_t *r, int handler)
{
    if (handler == NGX_HTTP_STATIC_HANDLER) 
        return ngx_http_static_handler(r);

#if 0
    elsif (handler == NGX_HTTP_DIRECTORY_HANDLER) 
        return ngx_http_index_handler(r);
#endif

    return ngx_http_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */
    return -1;
}

static int ngx_http_error(ngx_http_request_t *r, int error)
{
    /* STUB */
    return -1;
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
    ngx_destroy_pool(r->pool);

    ngx_log_debug(r->connection->log, "http close");

    ngx_del_event(r->connection->read, NGX_TIMER_EVENT);
    ngx_del_event(r->connection->write, NGX_TIMER_EVENT);

    return NGX_ERROR;
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
