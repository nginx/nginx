
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
/* STUB */ #include <ngx_event_connect.h>
/* STUB */ #include <ngx_event_proxy.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>



static int ngx_http_proxy_handler(ngx_http_request_t *r);
static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_send_request_handler(ngx_event_t *wev);
static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev);
static void ngx_http_proxy_process_upstream_headers(ngx_event_t *rev);
static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *);
static void ngx_http_proxy_send_response(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_process_body(ngx_event_t *ev);

static int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p);
static void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc);
static void ngx_http_proxy_close_connection(ngx_connection_t *c);

static int ngx_http_proxy_init(ngx_cycle_t *cycle);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_t *u);


static ngx_command_t ngx_http_proxy_commands[] = {

    {ngx_string("proxy_pass"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_proxy_set_pass,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
#if 0
    ngx_http_proxy_merge_conf              /* merge location configration */
#endif

    NULL
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_str_t http_methods[] = {
    ngx_string("GET "),
    ngx_string("HEAD "),
    ngx_string("POST ")
};


#if 0
static char *header_errors[] = {
    "upstream sent too long status line",
    "upstream sent invalid header",
    "upstream sent too long header line"
};
#endif


static ngx_http_header_t headers_in[] = {
    { ngx_string("Date"), offsetof(ngx_http_proxy_headers_in_t, date) },
    { ngx_string("Server"), offsetof(ngx_http_proxy_headers_in_t, server) },
    { ngx_string("Connection"),
                           offsetof(ngx_http_proxy_headers_in_t, connection) },
    { ngx_string("Content-Type"),
                         offsetof(ngx_http_proxy_headers_in_t, content_type) },
    { ngx_string("Content-Length"),
                       offsetof(ngx_http_proxy_headers_in_t, content_length) },
    { ngx_string("Last-Modified"),
                        offsetof(ngx_http_proxy_headers_in_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                        offsetof(ngx_http_proxy_headers_in_t, accept_ranges) },

    { ngx_null_string, 0 }
};


static char http_version[] = " HTTP/1.0" CRLF;
static char host_header[] = "Host: ";
static char conn_close_header[] = "Connection: close" CRLF;



static int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *p;

    ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                        sizeof(ngx_http_proxy_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->lcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    p->upstream.peers = p->lcf->peers;
    p->upstream.tries = p->lcf->peers->number;

    p->request = r;
    p->method = r->method;

    /* TODO: from lcf->upstream */
    p->uri.data = "/";
    p->uri.len = 1;
    p->location_len = 1;

    /* STUB */ p->accel = 1;

    p->host_header = p->upstream.peers->peers[0].host;

    ngx_test_null(p->request_hunks, ngx_http_proxy_create_request(p),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->action = "connecting to upstream";

    /* TODO: log->data would be changed, how to restore log->data ? */
    p->upstream.log = r->connection->log;

    ngx_http_proxy_send_request(p);

    return NGX_DONE;
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p)
{
    int                  i;
    size_t               len;
    ngx_hunk_t          *h;
    ngx_chain_t         *chain;
    ngx_table_elt_t     *header;
    ngx_http_request_t  *r;

    r = p->request;

    len = http_methods[p->method - 1].len
          + p->uri.len
          + r->uri.len - p->location_len
          + 1 + r->args.len                                  /* 1 is for "?" */
          + sizeof(http_version) - 1
          + sizeof(host_header) - 1 + p->host_header.len + 2
                                                          /* 2 is for "\r\n" */
          + sizeof(conn_close_header) - 1
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

    ngx_test_null(h, ngx_create_temp_hunk(r->pool, len, 0, 0), NULL);
    ngx_add_hunk_to_chain(chain, h, r->pool, NULL);


    /* the request line */

    h->last = ngx_cpymem(h->last, http_methods[p->method - 1].data,
                         http_methods[p->method - 1].len);

    h->last = ngx_cpymem(h->last, p->uri.data, p->uri.len);

    h->last = ngx_cpymem(h->last,
                         r->uri.data + p->location_len,
                         r->uri.len - p->location_len);

    if (r->args.len > 0) {
        *(h->last++) = '?';
        h->last = ngx_cpymem(h->last, r->args.data, r->args.len);
    }

    h->last = ngx_cpymem(h->last, http_version, sizeof(http_version) - 1);


    /* the "Host" header */

    h->last = ngx_cpymem(h->last, host_header, sizeof(host_header) - 1);
    h->last = ngx_cpymem(h->last, p->host_header.data, p->host_header.len);
    *(h->last++) = CR; *(h->last++) = LF;


    /* the "Connection: close" header */

    h->last = ngx_cpymem(h->last, conn_close_header,
                         sizeof(conn_close_header) - 1);


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

    /* STUB */ *(h->last++) = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ h->pos);

    return chain;
}


static void ngx_http_proxy_send_request_handler(ngx_event_t *wev)
{
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = wev->data;
    p = c->data;

    ngx_http_proxy_send_request(p);

    return;
}


static void ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p)
{
    int                rc;
    ngx_chain_t       *chain, *ce, *te, **le;
    ngx_connection_t  *c;

    c = p->upstream.connection;

    for ( ;; ) {
        if (c) {
            chain = ngx_write_chain(c, p->work_request_hunks);

            if (chain != NGX_CHAIN_ERROR) {
                p->work_request_hunks = chain;

                if (c->write->timer_set) {
                    ngx_del_timer(c->write);
                }

                if (chain) {
                    ngx_add_timer(c->write, p->lcf->send_timeout);

                } else {
                    /* TODO: del event */
                }

                return;
            }

            ngx_http_proxy_close_connection(c);
        }

        for ( ;; ) {
            rc = ngx_event_connect_peer(&p->upstream);

            if (rc == NGX_ERROR) {
                ngx_http_proxy_finalize_request(p,
                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rc == NGX_CONNECT_ERROR) {
                ngx_event_connect_peer_failed(&p->upstream);

                if (p->upstream.tries == 0) {
                    ngx_http_proxy_finalize_request(p, NGX_HTTP_BAD_GATEWAY);
                    return;
                }

                continue;
            }

            p->upstream.connection->data = p;
            p->upstream.connection->write->event_handler =
                                           ngx_http_proxy_send_request_handler;
            p->upstream.connection->read->event_handler =
                                   ngx_http_proxy_process_upstream_status_line;

            c = p->upstream.connection;
            c->pool = p->request->pool;
            c->read->log = c->write->log = c->log = p->request->connection->log;

            if (p->upstream.tries > 1) {
#if (NGX_SUPPRESS_WARN)
                le = NULL;
#endif
                p->work_request_hunks =
                                       ngx_alloc_chain_entry(p->request->pool);
                if (p->work_request_hunks == NULL) {
                    ngx_http_proxy_finalize_request(p,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                te = p->work_request_hunks;

                for (ce = p->request_hunks; ce; ce = ce->next) {
                    te->hunk = ce->hunk;
                    *le = te;
                    le = &te->next;
                    ce->hunk->pos = ce->hunk->start;

                    te = ngx_alloc_chain_entry(p->request->pool);
                    if (te == NULL) {
                        ngx_http_proxy_finalize_request(p,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                }

                *le = NULL;

            } else {
                p->work_request_hunks = p->request_hunks;
            }

            if (rc == NGX_OK) {
                break;
            }

            /* rc == NGX_AGAIN */

            ngx_add_timer(c->write, p->lcf->connect_timeout);

            return;
        }
    }
}


static void ngx_http_proxy_process_upstream_status_line(ngx_event_t *rev)
{
    int                    rc;
    ssize_t                n;
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    c = rev->data;
    p = c->data;

    ngx_log_debug(rev->log, "http proxy process status line");

    if (rev->timedout) {
        ngx_http_proxy_next_upstream(p);
        return;
    }

    if (p->header_in == NULL) {
        p->header_in = ngx_create_temp_hunk(p->request->pool,
                                            p->lcf->header_size,
                                            0, 0);
        if (p->header_in == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    n = ngx_http_proxy_read_upstream_header(p);

    if (n == NGX_ERROR) {
        ngx_http_proxy_next_upstream(p);
        return;
    }

    if (n == NGX_AGAIN) {
        return;
    }

    rc = ngx_http_proxy_parse_status_line(p);

    if (rc == NGX_AGAIN) {
        if (p->header_in->pos == p->header_in->last) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");
            ngx_http_proxy_finalize_request(p, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        return;
    }

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        /* TODO: HTTP/0.9 */
        return;
    }

    /* rc == NGX_OK */

    p->status_line.len = p->status_end - p->status_start;
    p->status_line.data = ngx_palloc(p->request->pool, p->status_line.len + 1);
    if (p->status_line.data == NULL) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_cpystrn(p->status_line.data, p->status_start, p->status_line.len + 1);

    ngx_log_debug(rev->log, "http proxy status %d '%s'" _
                  p->status _ p->status_line.data);


    if (p->headers_in.headers) {
        p->headers_in.headers->nelts = 0;
    } else {
        p->headers_in.headers = ngx_create_table(p->request->pool, 10);
    }

    c->read->event_handler = ngx_http_proxy_process_upstream_headers;
    ngx_http_proxy_process_upstream_headers(rev);

    return;
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

    ngx_log_debug(rev->log, "http proxy process header line");

    if (rev->timedout) {
        ngx_http_proxy_next_upstream(p);
        return;
    }

    rc = NGX_AGAIN;

    for ( ;; ) {
        if (rc == NGX_AGAIN) {
            n = ngx_http_proxy_read_upstream_header(p);

            if (n == NGX_ERROR) {
                ngx_http_proxy_next_upstream(p);
                return;
            }

            if (n == NGX_AGAIN) {
                return;
            }
        }

        rc = ngx_http_parse_header_line(p->request, p->header_in);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_push_table(p->headers_in.headers);
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

            for (i = 0; headers_in[i].name.len != 0; i++) {
                if (headers_in[i].name.len != h->key.len) {
                    continue;
                }

                if (ngx_strcasecmp(headers_in[i].name.data, h->key.data) == 0) {
                    *((ngx_table_elt_t **)
                        ((char *) &p->headers_in + headers_in[i].offset)) = h;
                }
            }

            ngx_log_debug(c->log, "HTTP proxy header: '%s: %s'" _
                          h->key.data _ h->value.data);

            continue;

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug(c->log, "HTTP header done");

            ngx_http_proxy_send_response(p);

            return;

        } else if (rc != NGX_AGAIN) {

            /* there was error while a header line parsing */

#if 0
            ngx_http_header_parse_error(r, rc);
            ngx_http_proxy_next_upstream(p);
#endif
            ngx_http_proxy_finalize_request(p, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

        if (p->header_in->last == p->header_in->end) {
            ngx_log_error(NGX_LOG_ERR, rev->log, 0,
                          "upstream sent too big header");
            ngx_http_proxy_finalize_request(p, NGX_HTTP_BAD_GATEWAY);
            return;
        }
    }
}


static ssize_t ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *p)
{
    ssize_t       n;
    ngx_event_t  *rev;

    rev = p->upstream.connection->read;

    n = p->header_in->last - p->header_in->pos;

    if (n > 0) {
#if 0
        /* TODO THINK */
        rev->ready = 0;
#endif
        return n;
    }

    n = ngx_recv(p->upstream.connection, p->header_in->last,
                 p->header_in->end - p->header_in->last);

    if (n == NGX_AGAIN) {
        ngx_add_timer(rev, p->lcf->read_timeout);

        if (ngx_handle_read_event(rev) == NGX_ERROR) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, rev->log, 0,
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
    int                  rc, i;
    ngx_table_elt_t     *ch, *ph;
    ngx_event_proxy_t   *ep;
    ngx_http_request_t  *r;

    r = p->request;

    r->headers_out.content_length = -1;

    /* copy an upstream header to r->headers_out */

    ph = (ngx_table_elt_t *) p->headers_in.headers->elts;
    for (i = 0; i < p->headers_in.headers->nelts; i++) {

        if (&ph[i] == p->headers_in.connection) {
            continue;
        }

        if (p->accel) {
            if (&ph[i] == p->headers_in.date
                || &ph[i] == p->headers_in.accept_ranges) {
                continue;
            }
        }

        if (&ph[i] == p->headers_in.content_length) {
            r->headers_out.content_length =
                             ngx_atoi(p->headers_in.content_length->value.data,
                                      p->headers_in.content_length->value.len);
            continue;
        }

        ch = ngx_push_table(r->headers_out.headers);
        if (ch == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        *ch = ph[i];

        if (&ph[i] == p->headers_in.content_type) {
            r->headers_out.content_type = ch;
            r->headers_out.content_type->key.len = 0;
            continue;
        }
    }

    /* STUB */

    if (p->headers_in.server) {
        r->headers_out.server = p->headers_in.server;
    }

    if (!p->accel && p->headers_in.date) {
        r->headers_out.date = p->headers_in.date;
    }

    /* */

#if 0
    /* TODO: look "Content-Length" */
    p->block_size = p->lcf->block_size;
#endif

    r->headers_out.status = p->status;

    rc = ngx_http_send_header(r);

    p->header_sent = 1;

    ep = ngx_pcalloc(r->pool, sizeof(ngx_event_proxy_t));
    if (ep == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    ep->input_filter = ngx_event_proxy_copy_input_filter;
    ep->output_filter = (ngx_event_proxy_output_filter_pt)
                                                        ngx_http_output_filter;
    ep->output_ctx = r;
    ep->bufs = p->lcf->bufs;
    ep->max_busy_len = p->lcf->max_busy_len;
    ep->upstream = p->upstream.connection;
    ep->downstream = r->connection;
    ep->pool = r->pool;
    ep->log = r->connection->log;
    ep->temp_path = p->lcf->temp_path;

    ep->temp_file = ngx_palloc(r->pool, sizeof(ngx_file_t));
    if (ep->temp_file == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }

    ep->temp_file->fd = NGX_INVALID_FILE;
    ep->temp_file->log = r->connection->log;

    ep->max_temp_file_size = p->lcf->max_temp_file_size;
    ep->temp_file_write_size = p->lcf->temp_file_write_size;
    ep->temp_file_warn = "an upstream response is buffered "
                         "to a temporary file";

    ep->preread_hunks = ngx_alloc_chain_entry(r->pool);
    if (ep->preread_hunks == NULL) {
        ngx_http_proxy_finalize_request(p, 0);
        return;
    }
    ep->preread_hunks->hunk = p->header_in;
    ep->preread_hunks->next = NULL;

    ep->preread_size = p->header_in->last - p->header_in->pos;

    /*
     * event_proxy would do p->header_in->last += ep->preread_size
     * as these bytes were read.
     */
    p->header_in->last = p->header_in->pos;

    /* STUB */ ep->cachable = 0;

    p->event_proxy = ep;

#if 0
    lcx = p->log->data;
    lcx->action = "reading an upstream";
#endif

    p->upstream.connection->read->event_handler = ngx_http_proxy_process_body;
    r->connection->write->event_handler = ngx_http_proxy_process_body;

    ngx_http_proxy_process_body(p->upstream.connection->read);

    return;
}


static void ngx_http_proxy_process_body(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;
    ngx_event_proxy_t     *ep;

    c = ev->data;

    if (ev->write) {
        ngx_log_debug(ev->log, "http proxy process downstream");
        r = c->data;
        p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    } else {
        ngx_log_debug(ev->log, "http proxy process upstream");
        p = c->data;
        r = p->request;
    }

    ep = p->event_proxy;

    if (ev->timedout) {
        if (ev->write) {
            ep->downstream_error = 1;

        } else {
            ep->upstream_error = 1;
        }

    } else {
        if (ngx_event_proxy(ep, ev->write) == NGX_ABORT) {
            ngx_http_proxy_finalize_request(p, 0);
            return;
        }
    }

    if (p->upstream.connection) {
        if (ep->upstream_done) {
            /* TODO: update cache */

        } else if (ep->upstream_eof) {
            /* TODO: check length & update cache */
        }

        if (ep->upstream_done || ep->upstream_eof || ep->upstream_error) {
            ngx_http_proxy_close_connection(p->upstream.connection);
            p->upstream.connection = NULL;
        }
    }

    if (ep->downstream_done) {
        ngx_log_debug(ev->log, "http proxy downstream done");
        ngx_http_proxy_finalize_request(p, r->main ? 0 : ngx_http_send_last(r));
        return;
    }

    if (ep->downstream_error) {
        if (!p->cachable && p->upstream.connection) {
            ngx_http_proxy_close_connection(p->upstream.connection);
            p->upstream.connection = NULL;
        }
 
        if (p->upstream.connection == NULL) {
            ngx_http_close_connection(c);
        }
    }

    return;
}


static int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p)
{
    char   ch;
    char  *pos;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done,
        sw_done
    } state;

    state = p->state;
    pos = p->header_in->pos;

    while (pos < p->header_in->last && state < sw_done) {
        ch = *pos++;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            p->status = p->status * 10 + ch - '0';

            if (++p->status_count == 3) {
                state = sw_space_after_status;
                p->status_start = pos - 3;
            }

            break;

         /* space or end of line */
         case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                state = sw_done;
                break;
            }
            break;

        /* end of request line */
        case sw_almost_done:
            p->status_end = pos - 2;
            switch (ch) {
            case LF:
                state = sw_done;
                break;
            default:
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }
            break;
        }
    }

    p->header_in->pos = pos;

    if (state == sw_done) {
        if (p->status_end == NULL) {
            p->status_end = pos - 1;
        }

        p->state = sw_start;
        return NGX_OK;
    }

    p->state = state;
    return NGX_AGAIN;
}


static void ngx_http_proxy_next_upstream(ngx_http_proxy_ctx_t *p)
{
    if (p->upstream.connection) {
        ngx_http_proxy_close_connection(p->upstream.connection);
        p->upstream.connection = NULL;
    }

    if (!p->fatal_error) {
        ngx_http_proxy_send_request(p);
    }

    return;
}

static void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc)
{
    if (p->upstream.connection) {
        ngx_http_proxy_close_connection(p->upstream.connection);
        p->upstream.connection = NULL;
    }

    if (p->header_sent
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    ngx_http_finalize_request(p->request, rc);

    p->fatal_error = 1;

    return;
}



static void ngx_http_proxy_close_connection(ngx_connection_t *c)
{
    ngx_log_debug(c->log, "close connection: %d" _ c->fd);

    if (c->fd == -1) {
#if 0
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
#endif
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* TODO: move connection to the connection pool */

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

    return;
}


static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_ctx_t *p = data;

    return ngx_snprintf(buf, len,
            " while %s, upstream: %s, client: %s, URL: %s",
            p->action,
            p->upstream.peers->peers[p->upstream.cur_peer].addr_port_text.data,
            p->request->connection->addr_text.data,
            p->request->unparsed_uri.data);
}


static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    int                         i;
    ngx_http_proxy_loc_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* STUB */
    ngx_test_null(conf->peers, ngx_pcalloc(cf->pool, sizeof(ngx_peers_t)),
                  NGX_CONF_ERROR);

    conf->peers->number = 1;
    conf->peers->peers[0].addr = inet_addr("127.0.0.1");
    conf->peers->peers[0].host.data = "localhost";
    conf->peers->peers[0].host.len = sizeof("localhost") - 1;
    conf->peers->peers[0].port = htons(9000);
    conf->peers->peers[0].addr_port_text.data = "127.0.0.1:9000";
    conf->peers->peers[0].addr_port_text.len = sizeof("127.0.0.1:9000") - 1;

    conf->connect_timeout = 30000;
    conf->send_timeout = 30000;
    conf->header_size = 4096;
    conf->read_timeout = 30000;

    conf->bufs.num = 10;
    conf->bufs.size = 4096;
    conf->max_busy_len = 8192 + 4096;


    /* CHECK in _init conf->max_temp_size >= conf->bufs.size !!! */
    conf->max_temp_file_size = 4096 * 6;


    conf->temp_file_write_size = 4096 * 2;

    ngx_test_null(conf->temp_path, ngx_pcalloc(cf->pool, sizeof(ngx_path_t)),
                  NULL);

    conf->temp_path->name.data = "temp";
    conf->temp_path->name.len = 4;
    conf->temp_path->level[0] = 1;
    conf->temp_path->level[1] = 2;
    conf->temp_path->level[2] = 3;
    conf->temp_path->len = 0;

    for (i = 0; i < 3; i++) {
        if (conf->temp_path->level[i] == 0) {
            break;
        }
        conf->temp_path->len += conf->temp_path->level[i] + 1;
    }

    /* */

    return conf;
}


static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    int                        i, len;
    char                      *err, *host;
    ngx_str_t                 *value;
    struct hostent            *h;
    u_int32_t                  addr;
    ngx_http_conf_ctx_t       *ctx;
    ngx_http_core_loc_conf_t  *clcf;


    value = cf->args->elts;

    if (ngx_strncasecmp(value[1].data, "http://", 7) != 0) {
        return "invalid URL prefix";
    }

    ngx_test_null(lcf->upstream,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_upstream_t)),
                  NGX_CONF_ERROR);

    value[1].data += 7;
    value[1].len -= 7;

    err = ngx_http_proxy_parse_upstream(&value[1], lcf->upstream);

    if (err) {
        return err;
    }

    ngx_test_null(host, ngx_palloc(cf->pool, lcf->upstream->host.len + 1),
                  NGX_CONF_ERROR);
    ngx_cpystrn(host, lcf->upstream->host.data, lcf->upstream->host.len + 1);

    addr = inet_addr(host);

    if (addr == INADDR_NONE) {
        h = gethostbyname(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "host %s not found", host);
            return NGX_CONF_ERROR;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers,
                      ngx_pcalloc(cf->pool,
                                  sizeof(ngx_peers_t)
                                  + sizeof(ngx_peer_t) * (i - 1)),
                      NGX_CONF_ERROR);

        lcf->peers->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {
            lcf->peers->peers[i].host.data = host;
            lcf->peers->peers[i].host.len = lcf->upstream->host.len;
            lcf->peers->peers[i].addr = *(u_int32_t *)(h->h_addr_list[i]);
            lcf->peers->peers[i].port = lcf->upstream->port;

            len = INET_ADDRSTRLEN + lcf->upstream->port_text.len + 1;
            ngx_test_null(lcf->peers->peers[i].addr_port_text.data,
                          ngx_palloc(cf->pool, len),
                          NGX_CONF_ERROR);

            len = ngx_inet_ntop(AF_INET,
                                (char *) &lcf->peers->peers[i].addr,
                                lcf->peers->peers[i].addr_port_text.data,
                                len);

            lcf->peers->peers[i].addr_port_text.data[len++] = ':';

            ngx_cpystrn(lcf->peers->peers[i].addr_port_text.data + len,
                        lcf->upstream->port_text.data,
                        lcf->upstream->port_text.len + 1);

            lcf->peers->peers[i].addr_port_text.len =
                                        len + lcf->upstream->port_text.len + 1;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers, ngx_pcalloc(cf->pool, sizeof(ngx_peers_t)),
                      NGX_CONF_ERROR);

        lcf->peers->number = 1;

        lcf->peers->peers[0].host.data = host;
        lcf->peers->peers[0].host.len = lcf->upstream->host.len;
        lcf->peers->peers[0].addr = addr;
        lcf->peers->peers[0].port = lcf->upstream->port;

        len = lcf->upstream->host.len + lcf->upstream->port_text.len + 1;

        ngx_test_null(lcf->peers->peers[0].addr_port_text.data,
                      ngx_palloc(cf->pool, len + 1),
                      NGX_CONF_ERROR);

        len = lcf->upstream->host.len;

        ngx_memcpy(lcf->peers->peers[0].addr_port_text.data,
                   lcf->upstream->host.data, len);

        lcf->peers->peers[0].addr_port_text.data[len++] = ':';

        ngx_cpystrn(lcf->peers->peers[0].addr_port_text.data + len,
                    lcf->upstream->port_text.data,
                    lcf->upstream->port_text.len + 1);
    }

    ctx = cf->ctx;
    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    lcf->upstream->location = &clcf->name;
    clcf->handler = ngx_http_proxy_handler;

    return NULL;
}

static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_t *u)
{
    size_t  i;

    if (url->data[0] == ':' || url->data[0] == '/') {
        return "invalid upstream URL";
    }

    u->host.data = url->data;
    u->host_header.data = url->data;

    for (i = 1; i < url->len; i++) {
        if (url->data[i] == ':') {
            u->port_text.data = &url->data[i] + 1;
            u->host.len = i;
        }

        if (url->data[i] == '/') {
            u->uri.data = &url->data[i];
            u->uri.len = url->len - i;
            u->host_header.len = i;

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (u->port_text.data == NULL) {
                u->port = htons(80);
                u->port_text.len = 2;
                u->port_text.data = "80";
                return NULL;
            }

            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len > 0) {
                u->port = ngx_atoi(u->port_text.data, u->port_text.len);
                if (u->port > 0) {
                    u->port = htons((u_short) u->port);
                    return NULL;
                }
            }

            return "invalid port in upstream URL";
        }
    }

    if (u->host.len == 0) {
        u->host.len = i;
    }

    u->host_header.len = i;

    u->uri.data = "/";
    u->uri.len = 1;

    if (u->port_text.data == NULL) {
        u->port = htons(80);
        u->port_text.len = 2;
        u->port_text.data = "80";
        return NULL;
    }

    u->port_text.len = &url->data[i] - u->port_text.data;

    if (u->port_text.len > 0) {
        u->port = ngx_atoi(u->port_text.data, u->port_text.len);
        if (u->port > 0) {
            u->port = htons((u_short) u->port);
            return NULL;
        }
    }

    return "invalid port in upstream URL";
}
