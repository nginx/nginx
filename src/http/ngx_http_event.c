
#include <ngx_config.h>
#include <ngx_file.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>

#include <ngx_http.h>

/*
ngx_read should check errors (if we ask) and return
   -2 EAGAIN
   -1 error
    0 EOF
   >0 number of bytes
*/

       int ngx_http_init_connection(ngx_connection_t *c);
static int ngx_http_init_request(ngx_event_t *ev);
static int ngx_http_process_request(ngx_event_t *ev);

static int ngx_process_http_request_line(ngx_http_request_t *r);
static int ngx_process_http_request_header(ngx_http_request_t *r);

static int ngx_process_http_request(ngx_http_request_t *r);

static int ngx_http_close_request(ngx_event_t *ev);

/* STUB */
static int ngx_http_writer(ngx_event_t *ev);

/*
    returns
    -1 if error
     0 need more data or EOF (filter is deleted)
     1 there is unread data
*/

int ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_event_t  *ev;

    ev = c->read;
    ev->event_handler = ngx_http_init_request;
    ev->log->action = "reading client request line";

    ngx_log_debug(ev->log, "ngx_http_init_connection: entered");

    /* XXX: ev->timer ? */
    if (ngx_add_event(ev, NGX_TIMER_EVENT, ev->timer) == -1)
        return -1;

#if (HAVE_DEFERRED_ACCEPT)
    if (ev->ready)
        return ngx_http_init_request(ev);
    else
#endif
#if (NGX_CLEAR_EVENT)
        return ngx_add_event(ev, NGX_READ_EVENT, NGX_CLEAR_EVENT);
#else
        return ngx_add_event(ev, NGX_READ_EVENT, NGX_ONESHOT_EVENT);
#endif
}

int ngx_http_init_request(ngx_event_t *ev)
{
    ngx_connection_t   *c = (ngx_connection_t *) ev->data;
    ngx_http_server_t  *srv = (ngx_http_server_t *) c->server;
    ngx_http_request_t *r;

    ngx_log_debug(ev->log, "ngx_http_init_request: entered");

    ngx_test_null(c->pool, ngx_create_pool(16384, ev->log), -1);
    ngx_test_null(r, ngx_pcalloc(c->pool, sizeof(ngx_http_request_t)), -1);

    c->data = r;
    r->connection = c;
    r->server = srv;

    ngx_test_null(r->pool, ngx_create_pool(16384, ev->log), -1);
    ngx_test_null(r->buff, ngx_palloc(r->pool, sizeof(ngx_buff_t)), -1);
    ngx_test_null(r->buff->buff, ngx_palloc(r->pool, srv->buff_size), -1);

    r->buff->pos = r->buff->last = r->buff->buff;
    r->buff->end = r->buff->buff + srv->buff_size;

    r->state_handler = ngx_process_http_request_line;

    ev->event_handler = ngx_http_process_request;
    ev->close_handler = ngx_http_close_request;
    c->write->close_handler = ngx_http_close_request;
    return ngx_http_process_request(ev);
}

int ngx_http_process_request(ngx_event_t *ev)
{
    int n;
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_http_request_t *r = (ngx_http_request_t *) c->data;

    ngx_log_debug(ev->log, "http process request");

    n = ngx_event_recv(ev, r->buff->last, r->buff->end - r->buff->last);

    if (n == -2)
        return 0;

    if (n == -1)
        return -1;

    ngx_log_debug(ev->log, "http read %d" _ n);

    if (n == 0) {
        if (ev->unexpected_eof) {
            ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                         "ngx_http_process_request: "
                         "connection is closed while %s", ev->action);
            return -1;
        }

        return ngx_http_close_request(ev);
    }

    if (!ev->read_discarded) {
        r->buff->last += n;

        /* state_handlers are called in following order:
            ngx_process_http_request_line()
            ngx_process_http_request_header() */

        do {
            if ((r->state_handler)(r) < 0)
                return -1;
        } while (r->buff->pos < r->buff->last);
    }

    if (ngx_del_event(ev, NGX_TIMER_EVENT) == -1)
        return -1;

    if (ngx_add_event(ev, NGX_TIMER_EVENT, ev->timer) == -1)
        return -1;

    return 0;
}

static int ngx_process_http_request_line(ngx_http_request_t *r)
{
    int n;

    if ((n = ngx_read_http_request_line(r)) == 1) {
        *r->uri_end = '\0';
        ngx_log_debug(r->connection->log, "HTTP: %d, %d, %s" _
                     r->method _ r->http_version _ r->uri_start);
        r->state_handler = ngx_process_http_request_header;
        r->connection->read->action = "reading client request headers";
    }

    return n;
}

static int ngx_process_http_request_header(ngx_http_request_t *r)
{
    int n;

    while ((n = ngx_read_http_header_line(r)) == 1) {
        *r->header_name_end = '\0';
        *r->header_end = '\0';
        ngx_log_debug(r->connection->log, "HTTP header: '%s: %s'" _
                     r->header_name_start _ r->header_start);
    }

    if (n != 2)
        return n;

    r->state_handler = NULL;
    r->connection->read->action = "reading client request body";

    r->connection->read->read_discarded = 1;
    r->connection->read->unexpected_eof = 0;
    ngx_log_debug(r->connection->log, "HTTP header done");

    return ngx_process_http_request(r);
}

static int ngx_process_http_request(ngx_http_request_t *r)
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

static int ngx_http_close_request(ngx_event_t *ev)
{
    ngx_connection_t *c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "http close");

    ngx_del_event(c->read, NGX_TIMER_EVENT);
    ngx_del_event(c->write, NGX_TIMER_EVENT);

    return ngx_event_close(ev);
}
