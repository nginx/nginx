
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_init_upstream(void *data);
static void ngx_http_proxy_reinit_upstream(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_connect(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_send_request_handler(ngx_event_t *wev);
static void ngx_http_proxy_dummy_handler(ngx_event_t *wev);
static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev);
static void ngx_http_proxy_process_upstream_headers(ngx_event_t *rev);
static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *);
static void ngx_http_proxy_send_response(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_process_body(ngx_event_t *ev);
static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p, int ft_type);


static ngx_str_t http_methods[] = {
    ngx_string("GET "),
    ngx_string("HEAD "),
    ngx_string("POST ")
};


static char *upstream_header_errors[] = {
    "upstream sent invalid header",
    "upstream sent too long header line"
};


static char  http_version[] = " HTTP/1.0" CRLF;
static char  host_header[] = "Host: ";
static char  connection_close_header[] = "Connection: close" CRLF;


int ngx_http_proxy_request_upstream(ngx_http_proxy_ctx_t *p)
{
    int                         rc;
    ngx_http_request_t         *r;
    ngx_http_proxy_upstream_t  *u;

    r = p->request;

    if (!(u = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_upstream_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p->upstream = u;

    u->peer.peers = p->lcf->peers;
    u->peer.tries = p->lcf->peers->number;

    u->method = r->method;

    if (r->headers_in.content_length_n > 0) {
        if (!(r->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t)))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->temp_file->file.fd = NGX_INVALID_FILE;
        r->temp_file->file.log = r->connection->log;
        r->temp_file->path = p->lcf->temp_path;
        r->temp_file->pool = r->pool;
        r->temp_file->warn = "a client request body is buffered "
                             "to a temporary file";
        /* r->temp_file->persistent = 0; */

        r->request_body_handler = ngx_http_proxy_init_upstream;
        r->data = p;

        rc = ngx_http_read_client_request_body(r, p->lcf->request_buffer_size);

        if (rc == NGX_AGAIN) {
            return NGX_DONE;
        }

        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_http_proxy_init_upstream(p);

    return NGX_DONE;
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p)
{
    int                              i;
    size_t                           len;
    ngx_hunk_t                      *h;
    ngx_chain_t                     *chain;
    ngx_table_elt_t                 *header;
    ngx_http_request_t              *r;
    ngx_http_proxy_upstream_conf_t  *uc;

    r = p->request;
    uc = p->lcf->upstream;

    len = http_methods[p->upstream->method - 1].len
          + uc->uri.len
          + r->uri.len - uc->location->len
          + 1 + r->args.len                                  /* 1 is for "?" */
          + sizeof(http_version) - 1
          + sizeof(host_header) - 1 + uc->host_header.len + 2
                                                          /* 2 is for "\r\n" */
          + sizeof(connection_close_header) - 1
          + 2;                          /* 2 is for "\r\n" at the header end */

    header = (ngx_table_elt_t *) r->headers_in.headers->elts;
    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        /* 2 is for ": " and 2 is for "\r\n" */
        len += header[i].key.len + 2 + header[i].value.len + 2;
    }

    /* STUB */ len++;

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, len), NULL);
    ngx_alloc_link_and_set_hunk(chain, h, r->pool, NULL);


    /* the request line */

    h->last = ngx_cpymem(h->last, http_methods[p->upstream->method - 1].data,
                         http_methods[p->upstream->method - 1].len);

    h->last = ngx_cpymem(h->last, uc->uri.data, uc->uri.len);

    h->last = ngx_cpymem(h->last,
                         r->uri.data + uc->location->len,
                         r->uri.len - uc->location->len);

    if (r->args.len > 0) {
        *(h->last++) = '?';
        h->last = ngx_cpymem(h->last, r->args.data, r->args.len);
    }

    h->last = ngx_cpymem(h->last, http_version, sizeof(http_version) - 1);


    /* "Host" header */

    h->last = ngx_cpymem(h->last, host_header, sizeof(host_header) - 1);
    h->last = ngx_cpymem(h->last, uc->host_header.data, uc->host_header.len);
    *(h->last++) = CR; *(h->last++) = LF;


    /* "Connection: close" header */

    h->last = ngx_cpymem(h->last, connection_close_header,
                         sizeof(connection_close_header) - 1);


    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        if (&header[i] == r->headers_in.keep_alive) {
            continue;
        }

        h->last = ngx_cpymem(h->last, header[i].key.data, header[i].key.len);

        *(h->last++) = ':'; *(h->last++) = ' ';

        h->last = ngx_cpymem(h->last, header[i].value.data,
                             header[i].value.len);

        *(h->last++) = CR; *(h->last++) = LF;

        ngx_log_debug(r->connection->log, "proxy: '%s: %s'" _
                      header[i].key.data _ header[i].value.data);
    }

    /* add "\r\n" at the header end */
    *(h->last++) = CR; *(h->last++) = LF;

    /* STUB */ *(h->last) = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ h->pos);

    return chain;
}


static void ngx_http_proxy_init_upstream(void *data)
{
    ngx_http_proxy_ctx_t *p = data;

    ngx_chain_t             *cl;
    ngx_http_request_t      *r;
    ngx_output_chain_ctx_t  *octx;
    ngx_chain_writer_ctx_t  *wctx;

    r = p->request;

ngx_log_debug(r->connection->log, "timer_set: %d" _
              r->connection->read->timer_set);

    if (r->connection->read->timer_set) {
        ngx_del_timer(r->connection->read);
    }

    if (!(cl = ngx_http_proxy_create_request(p))) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_hunks) {
        cl->next = r->request_hunks;
    }

    r->request_hunks = cl;

    p->upstream->peer.log = r->connection->log;
    p->saved_ctx = r->connection->log->data;
    p->saved_handler = r->connection->log->handler;
    r->connection->log->data = p;
    r->connection->log->handler = ngx_http_proxy_log_error;
    p->action = "connecting to upstream";

    if (!(octx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t)))) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    p->upstream->output_chain_ctx = octx;

    octx->sendfile = r->sendfile;
    octx->pool = r->pool;
    octx->bufs.num = 1;
    octx->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;
    octx->output_filter = (ngx_output_chain_filter_pt) ngx_chain_writer;

    if (!(wctx = ngx_palloc(r->pool, sizeof(ngx_chain_writer_ctx_t)))) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    octx->output_ctx = wctx;

    wctx->pool = r->pool;

    if (p->lcf->busy_lock && !p->busy_locked) {
        ngx_http_proxy_upstream_busy_lock(p);
    } else {
        ngx_http_proxy_connect(p);
    }
}


static void ngx_http_proxy_reinit_upstream(ngx_http_proxy_ctx_t *p)
{
    ngx_chain_t             *cl;
    ngx_output_chain_ctx_t  *octx;

    octx = p->upstream->output_chain_ctx;

    /* reinit the request chain */

    for (cl = p->request->request_hunks; cl; cl = cl->next) {
        cl->hunk->pos = cl->hunk->start;
    }

    /* reinit ngx_output_chain() context */

    octx->hunk = NULL;
    octx->in = NULL;
    octx->free = NULL;
    octx->busy = NULL;

    /* reinit r->header_in buffer */

    if (p->header_in) {
        if (p->cache) {
            p->header_in->pos = p->header_in->start + p->cache->ctx.header_size;
            p->header_in->last = p->header_in->pos;

        } else {
            p->header_in->pos = p->header_in->start;
            p->header_in->last = p->header_in->start;
        }
    }

    /* add one more state */

    if (!(p->state = ngx_push_array(&p->states))) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    p->status = 0;
    p->status_count = 0;
}


void ngx_http_proxy_upstream_busy_lock(ngx_http_proxy_ctx_t *p)
{
    int  rc, ft_type;

    if (p->busy_lock.time == 0) {
        p->busy_lock.event = p->request->connection->read;
        p->busy_lock.event_handler = ngx_http_proxy_busy_lock_handler;
    }

    rc = ngx_http_busy_lock(p->lcf->busy_lock, &p->busy_lock);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_OK) {
        ngx_http_proxy_connect(p);
        return;
    }

    ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);

    if (rc == NGX_DONE) {
        ft_type = NGX_HTTP_PROXY_FT_BUSY_LOCK;

    } else {
        /* rc == NGX_ERROR */
        ft_type = NGX_HTTP_PROXY_FT_MAX_WAITING;
    }

    if (p->stale && (p->lcf->use_stale & ft_type)) {
        ngx_http_proxy_finalize_request(p,
                                        ngx_http_proxy_send_cached_response(p));
        return;
    }

    p->state->status = NGX_HTTP_SERVICE_UNAVAILABLE;
    ngx_http_proxy_finalize_request(p, NGX_HTTP_SERVICE_UNAVAILABLE);
}


static void ngx_http_proxy_connect(ngx_http_proxy_ctx_t *p)
{
    int                      rc;
    ngx_connection_t        *c;
    ngx_http_request_t      *r;
    ngx_output_chain_ctx_t  *octx;

    p->action = "connecting to upstream";

    rc = ngx_event_connect_peer(&p->upstream->peer);

    if (rc == NGX_ERROR) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    p->state->peer =
     &p->upstream->peer.peers->peers[p->upstream->peer.cur_peer].addr_port_text;

    if (rc == NGX_CONNECT_ERROR) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
        return;
    }

    p->upstream->peer.connection->data = p;
    p->upstream->peer.connection->write->event_handler =
                                           ngx_http_proxy_send_request_handler;
    p->upstream->peer.connection->read->event_handler =
                                   ngx_http_proxy_process_upstream_status_line;

    r = p->request;
    c = p->upstream->peer.connection;
    c->pool = r->pool;
    c->read->log = c->write->log = c->log = r->connection->log;

    octx = p->upstream->output_chain_ctx;

    if (p->upstream->peer.tries > 1 && p->request_sent) {
        ngx_http_proxy_reinit_upstream(p);
    }

    /* init or reinit ngx_output_chain() context */

    if (r->request_body_hunk) {
        if (!(octx->free = ngx_alloc_chain_link(r->pool))) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        octx->free->hunk = r->request_body_hunk;
        octx->free->next = NULL;
        octx->hunks = 1;

        r->request_body_hunk->pos = r->request_body_hunk->start;
        r->request_body_hunk->last = r->request_body_hunk->start;
    }

    p->request_sent = 0;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, p->lcf->connect_timeout);
        return;
    }

    /* rc == NGX_OK */

#if 1 /* test only */

    if (c->read->ready) {
        /* post aio operation */
        ngx_http_proxy_process_upstream_status_line(c->read);
        return;
    }
#endif

    ngx_http_proxy_send_request(p);
}


static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p)
{
    int                      rc;
    ngx_connection_t        *c;
    ngx_chain_writer_ctx_t  *wctx;

    c = p->upstream->peer.connection;

#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)
        && !p->request_sent
        && c->write->kq_eof)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, c->write->kq_errno,
                      "connect() failed");

        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
        return;
    }

#endif

    p->action = "sending request to upstream";

    wctx = p->upstream->output_chain_ctx->output_ctx;
    wctx->out = NULL;
    wctx->last = &wctx->out;
    wctx->connection = c;

    rc = ngx_output_chain(p->upstream->output_chain_ctx,
                          p->request_sent ? NULL : p->request->request_hunks);

    if (rc == NGX_ERROR) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
        return;
    }

    p->request_sent = 1;

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, p->lcf->send_timeout);

        if (ngx_handle_write_event(c->write, /* STUB: lowat */ 0) == NGX_ERROR)
        {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->tcp_nopush) {
        if (ngx_tcp_push(c->fd) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, c->log,
                          ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return; 
        }

        c->tcp_nopush = 0;
        return;
    }

#if 0
    if (c->read->ready) {

        /* post aio operation */

        /*
         * although we can post aio operation just in the end
         * of ngx_http_proxy_connect() CHECK IT !!!
         * it's better to do here because we postpone header buffer allocation
         */

        ngx_http_proxy_process_upstream_status_line(c->read);
        return;
    }
#endif

    p->upstream->peer.connection->write->event_handler =
                                                  ngx_http_proxy_dummy_handler;

    if (ngx_handle_level_write_event(c->write) == NGX_ERROR) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


static void ngx_http_proxy_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = wev->data;
    p = c->data;

    if (wev->timedout) {
        p->action = "sending request to upstream";
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    ngx_http_proxy_send_request(p);
}


static void ngx_http_proxy_dummy_handler(ngx_event_t *wev)
{
    ngx_log_debug(wev->log, "dummy handler");
}


static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev)
{
    int                    rc;
    ssize_t                n;
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = rev->data;
    p = c->data;
    p->action = "reading upstream status line";

    ngx_log_debug(rev->log, "http proxy process status line");

    if (rev->timedout) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    if (p->header_in == NULL) {
        p->header_in = ngx_create_temp_hunk(p->request->pool,
                                            p->lcf->header_buffer_size);
        if (p->header_in == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        p->header_in->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;

        if (p->cache) {
            p->header_in->pos += p->cache->ctx.header_size;
            p->header_in->last = p->header_in->pos;
        }
    }

    n = ngx_http_proxy_read_upstream_header(p);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream prematurely closed connection");
    }

    if (n == NGX_ERROR || n == 0) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
        return;
    }

    p->valid_header_in = 0;

    p->upstream->peer.cached = 0;

    rc = ngx_http_proxy_parse_status_line(p);

    if (rc == NGX_AGAIN) {
        if (p->header_in->pos == p->header_in->last) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too long status line");
            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_INVALID_HEADER);
        }
        return;
    }

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

        if (p->accel) {
            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_INVALID_HEADER);

        } else {
            p->request->http_version = NGX_HTTP_VERSION_9;
            p->upstream->status = NGX_HTTP_OK;
            ngx_http_proxy_send_response(p);
        }

        return;
    }

    /* rc == NGX_OK */

    p->upstream->status = p->status;
    p->state->status = p->status;

    if (p->status == NGX_HTTP_INTERNAL_SERVER_ERROR) {

        if (p->upstream->peer.tries > 1
            && (p->lcf->next_upstream & NGX_HTTP_PROXY_FT_HTTP_500))
        {
            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_500);
            return;
        }

        if (p->upstream->peer.tries == 0
            && p->stale
            && (p->lcf->use_stale & NGX_HTTP_PROXY_FT_HTTP_500))
        {
            ngx_http_proxy_finalize_request(p,
                                       ngx_http_proxy_send_cached_response(p));

            return;
        }
    }

    if (p->status == NGX_HTTP_NOT_FOUND
        && p->upstream->peer.tries > 1
        && p->lcf->next_upstream & NGX_HTTP_PROXY_FT_HTTP_404)
    {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_HTTP_404);
        return;
    }

    /* TODO: "proxy_error_page" */

    p->upstream->status_line.len = p->status_end - p->status_start;
    p->upstream->status_line.data = ngx_palloc(p->request->pool,
                                              p->upstream->status_line.len + 1);
    if (p->upstream->status_line.data == NULL) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_cpystrn(p->upstream->status_line.data, p->status_start,
                p->upstream->status_line.len + 1);

    ngx_log_debug(rev->log, "http proxy status %d '%s'" _
                  p->upstream->status _ p->upstream->status_line.data);

    if (p->upstream->headers_in.headers) {
        p->upstream->headers_in.headers->nelts = 0;
    } else {
        /* TODO: ngx_init_table */
        p->upstream->headers_in.headers = ngx_create_table(p->request->pool,
                                                           20);
    }

    c->read->event_handler = ngx_http_proxy_process_upstream_headers;
    ngx_http_proxy_process_upstream_headers(rev);
}


static void ngx_http_proxy_process_upstream_headers(ngx_event_t *rev)
{
    int                    i, rc;
    ssize_t                n;
    ngx_table_elt_t       *h;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = rev->data;
    p = c->data;
    r = p->request;
    p->action = "reading upstream headers";

    ngx_log_debug(rev->log, "http proxy process header line");

    if (rev->timedout) {
        ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_TIMEOUT);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {
        if (rc == NGX_AGAIN) {
            n = ngx_http_proxy_read_upstream_header(p);

            if (n == 0) {
                ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                              "upstream prematurely closed connection");
            }

            if (n == NGX_ERROR || n == 0) {
                ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_ERROR);
                return;
            }

            if (n == NGX_AGAIN) {
                return;
            }
        }

        rc = ngx_http_parse_header_line(p->request, p->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_http_add_header(&p->upstream->headers_in,
                                    ngx_http_proxy_headers_in);
            if (h == NULL) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_palloc(p->request->pool,
                                     h->key.len + 1 + h->value.len + 1);
            if (h->key.data == NULL) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->value.data = h->key.data + h->key.len + 1;
            ngx_cpystrn(h->key.data, r->header_name_start, h->key.len + 1);
            ngx_cpystrn(h->value.data, r->header_start, h->value.len + 1);

            for (i = 0; ngx_http_proxy_headers_in[i].name.len != 0; i++) {
                if (ngx_http_proxy_headers_in[i].name.len != h->key.len) {
                    continue;
                }

                if (ngx_strcasecmp(ngx_http_proxy_headers_in[i].name.data,
                                                           h->key.data) == 0)
                {
                    *((ngx_table_elt_t **) ((char *) &p->upstream->headers_in
                                   + ngx_http_proxy_headers_in[i].offset)) = h;
                    break;
                }
            }

            ngx_log_debug(c->log, "HTTP proxy header: '%s: %s'" _
                          h->key.data _ h->value.data);

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug(c->log, "HTTP header done");

            /* TODO: hook to process the upstream header */

            if (p->cachable) {
                p->cachable = ngx_http_proxy_is_cachable(p);
            }

            ngx_http_proxy_send_response(p);
            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      upstream_header_errors[rc - NGX_HTTP_PARSE_HEADER_ERROR]);

            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_INVALID_HEADER);
            return;
        }

        /* rc == NGX_AGAIN: a header line parsing is still not complete */

        if (p->header_in->last == p->header_in->end) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");

            ngx_http_proxy_next_upstream(p, NGX_HTTP_PROXY_FT_INVALID_HEADER);
            return;
        }
    }
}


static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *p)
{
    ssize_t       n;
    ngx_event_t  *rev;

    rev = p->upstream->peer.connection->read;

    n = p->header_in->last - p->header_in->pos;

    if (n > 0) {
        return n;
    }

    n = ngx_recv(p->upstream->peer.connection, p->header_in->last,
                 p->header_in->end - p->header_in->last);

    if (n == NGX_AGAIN) {
        ngx_add_timer(rev, p->lcf->read_timeout);

        if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                      "upstream closed prematurely connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        return NGX_ERROR;
    }

    p->header_in->last += n;

    return n;
}


static void ngx_http_proxy_send_response(ngx_http_proxy_ctx_t *p)
{
    int                           rc;
    ngx_event_pipe_t             *ep;
    ngx_http_request_t           *r;
    ngx_http_cache_header_t      *header;
    ngx_http_core_loc_conf_t     *clcf;

    r = p->request;

    r->headers_out.status = p->upstream->status;

#if 0
    r->headers_out.content_length_n = -1;
    r->headers_out.content_length = NULL;
#endif

    /* copy an upstream header to r->headers_out */

    if (ngx_http_proxy_copy_header(p, &p->upstream->headers_in) == NGX_ERROR) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* TODO: preallocate event_pipe hunks, look "Content-Length" */

    rc = ngx_http_send_header(r);

    p->header_sent = 1;

    if (p->cachable) {
        header = (ngx_http_cache_header_t *) p->header_in->start;

        header->expires = p->cache->ctx.expires;
        header->last_modified = p->cache->ctx.last_modified;
        header->date = p->cache->ctx.date;
        header->length = r->headers_out.content_length_n;
        p->cache->ctx.length = r->headers_out.content_length_n;

        header->key_len = p->cache->ctx.key.len;
        ngx_memcpy(&header->key, p->cache->ctx.key.data, header->key_len);
        header->key[header->key_len] = LF;
    }

    ep = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (ep == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    p->upstream->event_pipe = ep;

    ep->input_filter = ngx_event_pipe_copy_input_filter;
    ep->output_filter = (ngx_event_pipe_output_filter_pt)
                                                        ngx_http_output_filter;
    ep->output_ctx = r;
    ep->tag = (ngx_hunk_tag_t) &ngx_http_proxy_module;
    ep->bufs = p->lcf->bufs;
    ep->busy_size = p->lcf->busy_buffers_size;
    ep->upstream = p->upstream->peer.connection;
    ep->downstream = r->connection;
    ep->pool = r->pool;
    ep->log = r->connection->log;

    if (!(ep->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t)))) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    ep->temp_file->file.fd = NGX_INVALID_FILE;
    ep->temp_file->file.log = r->connection->log;
    ep->temp_file->path = p->lcf->temp_path;
    ep->temp_file->pool = r->pool;
    ep->temp_file->warn = "an upstream response is buffered "
                         "to a temporary file";

    ep->max_temp_file_size = p->lcf->max_temp_file_size;
    ep->temp_file_write_size = p->lcf->temp_file_write_size;

    ep->preread_hunks = ngx_alloc_chain_link(r->pool);
    if (ep->preread_hunks == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }
    ep->preread_hunks->hunk = p->header_in;
    ep->preread_hunks->next = NULL;
    p->header_in->type |= NGX_HUNK_PREREAD;

    ep->preread_size = p->header_in->last - p->header_in->pos;

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {

        /* the posted aio operation can currupt shadow buf */
        ep->single_buf = 1;
    }

    /* TODO: ep->free_bufs = 0 if use ngx_create_chain_of_hunks() */
    ep->free_bufs = 1;

    /*
     * event_pipe would do p->header_in->last += ep->preread_size
     * as though these bytes were read.
     */
    p->header_in->last = p->header_in->pos;

    ep->cachable = p->cachable;

    if (p->lcf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data can interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        ep->cyclic_temp_file = 1;
        r->sendfile = 0;

    } else {
        ep->cyclic_temp_file = 0;
        r->sendfile = 1;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ep->read_timeout = p->lcf->read_timeout;
    ep->send_timeout = clcf->send_timeout;
    ep->send_lowat = clcf->send_lowat;

    p->upstream->peer.connection->read->event_handler =
                                                   ngx_http_proxy_process_body;
    r->connection->write->event_handler = ngx_http_proxy_process_body;

    ngx_http_proxy_process_body(p->upstream->peer.connection->read);

    return;
}


static void ngx_http_proxy_process_body(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;
    ngx_event_pipe_t      *ep;

    c = ev->data;

    if (ev->write) {
        ngx_log_debug(ev->log, "http proxy process downstream");
        r = c->data;
        p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
        p->action = "sending to client";

    } else {
        ngx_log_debug(ev->log, "http proxy process upstream");
        p = c->data;
        r = p->request;
        p->action = "reading upstream body";
    }

    ep = p->upstream->event_pipe;

    if (ev->timedout) {
        if (ev->write) {
            ep->downstream_error = 1;
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "client timed out");

        } else {
            ep->upstream_error = 1;
            ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

    } else {
        if (ngx_event_pipe(ep, ev->write) == NGX_ABORT) {
            ngx_http_proxy_finalize_request(p, 0);
            return;
        }
    }

    if (p->upstream->peer.connection) {
        if (ep->upstream_done && p->cachable) {
            if (ngx_http_proxy_update_cache(p) == NGX_ERROR) {
                ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);
                ngx_http_proxy_finalize_request(p, 0);
                return;
            }

        } else if (ep->upstream_eof && p->cachable) {

            /* TODO: check length & update cache */

            if (ngx_http_proxy_update_cache(p) == NGX_ERROR) {
                ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);
                ngx_http_proxy_finalize_request(p, 0);
                return;
            }
        }

        if (ep->upstream_done || ep->upstream_eof || ep->upstream_error) {
            ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);
            ngx_http_proxy_close_connection(p);
        }
    }

    if (ep->downstream_done) {
        ngx_log_debug(ev->log, "http proxy downstream done");
        ngx_http_proxy_finalize_request(p, r->main ? 0 : ngx_http_send_last(r));
        return;
    }

    if (ep->downstream_error) {
        if (!p->cachable && p->upstream->peer.connection) {
            ngx_http_proxy_close_connection(p);
        }
 
        if (p->upstream->peer.connection == NULL) {
            ngx_http_close_connection(c);
        }
    }

    return;
}


static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p, int ft_type)
{
    int  status;

ngx_log_debug(p->request->connection->log, "next upstream: %d" _ ft_type);

    ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);

    if (ft_type != NGX_HTTP_PROXY_FT_HTTP_404) {
        ngx_event_connect_peer_failed(&p->upstream->peer);
    }

    if (ft_type == NGX_HTTP_PROXY_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, p->request->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (p->upstream->peer.cached && ft_type == NGX_HTTP_PROXY_FT_ERROR) {
        status = 0;

    } else {
        switch(ft_type) {
        case NGX_HTTP_PROXY_FT_TIMEOUT:
            status = NGX_HTTP_GATEWAY_TIME_OUT;
            break;

        case NGX_HTTP_PROXY_FT_HTTP_500:
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_PROXY_FT_HTTP_404:
            status = NGX_HTTP_NOT_FOUND;
            break;

        /*
         * NGX_HTTP_PROXY_FT_BUSY_LOCK and NGX_HTTP_PROXY_FT_MAX_WAITING
         * never reach here
         */

        default:
            status = NGX_HTTP_BAD_GATEWAY;
        }
    }

    if (p->upstream->peer.connection) {
        ngx_http_proxy_close_connection(p);
    }

    if (status) {
        p->state->status = status;

        if (p->upstream->peer.tries == 0 || !(p->lcf->next_upstream & ft_type))
        {
            if (p->stale && (p->lcf->use_stale & ft_type)) {
                ngx_http_proxy_finalize_request(p,
                                       ngx_http_proxy_send_cached_response(p));
                return;
            }

            ngx_http_proxy_finalize_request(p, status);
            return;
        }
    }

    if (p->lcf->busy_lock && !p->busy_locked) {
        ngx_http_proxy_upstream_busy_lock(p);
    } else {
        ngx_http_proxy_connect(p);
    }
}
