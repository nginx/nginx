
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_inet.h>
#include <ngx_conf_file.h>
#include <ngx_event_write.h>
#include <ngx_event_proxy.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_event_proxy_handler.h>


/* STUB */
typedef struct {
    int   type;
} ngx_cache_header_t;


static int ngx_http_proxy_handler(ngx_http_request_t *r);

static int ngx_http_proxy_read_client_body(ngx_http_proxy_ctx_t *p);
static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_process_upstream(ngx_http_proxy_ctx_t *p,
                                           ngx_event_t *ev);
static int ngx_http_proxy_connect(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_process_upstream_event(ngx_event_t *ev);
static int ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_init_upstream(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *p);

static int ngx_http_proxy_process_upstream_status_line(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_process_upstream_headers(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_process_upstream_header_line(ngx_http_proxy_ctx_t *p);

static int ngx_http_proxy_read_upstream_body(ngx_http_proxy_ctx_t *p);
static int ngx_http_proxy_write_upstream_body(ngx_http_proxy_ctx_t *p);


static int ngx_http_proxy_read_response_body(ngx_event_t *ev);
static int ngx_http_proxy_write_to_client(ngx_event_t *ev);

static int ngx_read_http_proxy_status_line(ngx_http_proxy_ctx_t *ctx);

static int ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int error);
static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len);

static int ngx_http_proxy_init(ngx_pool_t *pool);
static void *ngx_http_proxy_create_loc_conf(ngx_pool_t *pool);

static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     char *conf);

static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_url_t *uu);


static ngx_command_t  ngx_http_proxy_commands[] = {

    {ngx_string("proxy_pass"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_proxy_set_pass,
     NGX_HTTP_LOC_CONF_OFFSET,
     0},

    {ngx_string("proxy_large_header"),
     NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_proxy_loc_conf_t, large_header)},

    {ngx_null_string, 0, NULL, 0, 0}
};


static ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */

    ngx_http_proxy_create_loc_conf,        /* create location config */
    NULL                                   /* merge location config */
};


ngx_module_t  ngx_http_proxy_module = {
    0,                                     /* module index */
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    ngx_http_proxy_init                    /* init module */
};


static ngx_str_t http_methods[] = {
    ngx_string("GET "),
    ngx_string("HEAD "),
    ngx_string("POST ")
};


static char *header_errors[] = {
    "upstream sent too long status line",
    "upstream sent invalid header",
    "upstream sent too long header line"
};


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

    { ngx_null_string, 0 }
};


static char http_version[] = " HTTP/1.0" CRLF;
static char host_header[] = "Host: ";
static char conn_close_header[] = "Connection: close" CRLF;


/* AF_INET only */


static int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    int                         rc;
    struct sockaddr_in          addr;
    ngx_chain_t                *chain;
    ngx_http_proxy_ctx_t       *p;
    ngx_http_log_ctx_t         *hcx;
    ngx_http_proxy_log_ctx_t   *lcx;
    ngx_http_proxy_loc_conf_t  *lcf;

    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    if (p == NULL) {
        ngx_http_create_ctx(r, p, ngx_http_proxy_module_ctx,
                            sizeof(ngx_http_proxy_ctx_t),
                            NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (p->upstream_url == NULL) {
        lcf = (ngx_http_proxy_loc_conf_t *)
                    ngx_http_get_module_loc_conf(r, ngx_http_proxy_module_ctx);

        p->lcf = lcf;
        p->request = r;
        p->upstream_url = lcf->upstream_url;
        p->upstreams = lcf->upstreams;
        p->tries = lcf->upstreams->number;
    }

    ngx_test_null(p->log, ngx_palloc(r->pool, sizeof(ngx_log_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);
    ngx_memcpy(p->log, r->connection->log, sizeof(ngx_log_t));
    ngx_test_null(lcx, ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_log_ctx_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->log->data = lcx;
    hcx = r->connection->log->data;
    lcx->client = hcx->client;
    lcx->url = hcx->url;

    r->proxy = 1;
    p->accel = 1;

    p->method = r->method;
    p->headers_in.headers = ngx_create_table(r->pool, 10);

    if (r->headers_in.content_length_n > 0) {
        if (ngx_http_proxy_read_client_body(p) == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    chain = ngx_http_proxy_create_request(p);
    if (chain == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TODO: duplicate the hunks and chain if there is backend farm */
    p->request_hunks = chain;

    p->last_error = NGX_HTTP_BAD_GATEWAY;
    ngx_http_proxy_process_upstream(p, NULL);

    /* On an error ngx_http_proxy_process_upstream() calls
       ngx_http_proxy_finalize_request() so we return NGX_DONE to avoid
       the additional NGX_HTTP_INTERNAL_SERVER_ERROR error
       that would be generated by ngx_http_process_request() */

    return NGX_DONE;
}


static int ngx_http_proxy_read_client_body(ngx_http_proxy_ctx_t *p)
{
    int                  size, first_part;
    ngx_hunk_t          *h;
    ngx_http_request_t  *r;

    r = p->request;

    first_part = r->header_in->last - r->header_in->pos;

    if (first_part > r->headers_in.content_length_n) {
        first_part = r->headers_in.content_length_n;
        size = 0;

    } else {
        size = r->headers_in.content_length_n - first_part;
        if (size > p->lcf->client_request_buffer_size) {
            size = p->lcf->client_request_buffer_size;

        } else if (size > NGX_PAGE_SIZE) {
            size = ((size + NGX_PAGE_SIZE) / NGX_PAGE_SIZE) * NGX_PAGE_SIZE;
        }

        if (size) {
            ngx_test_null(p->client_request_hunk, ngx_palloc(r->pool, size),
                          NGX_ERROR);
        }
    }

    if (first_part) {
        ngx_test_null(h, ngx_alloc_hunk(r->pool), NGX_ERROR);

        h->type = NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP;
        h->pos = h->start = h->pre_start = r->header_in->pos;
        h->last = h->end = h->post_end = r->header_in->pos + first_part;
        h->file_pos = h->file_last = 0;
        h->file = NULL;
        h->shadow = NULL;
        h->tag = 0;

        p->client_first_part_hunk = h;
    }

    return NGX_OK;
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_proxy_ctx_t *p)
{
    int                  i;
    size_t               len;
    ngx_hunk_t          *hunk;
    ngx_chain_t         *chain;
    ngx_table_elt_t     *header;
    ngx_http_request_t  *r;

    r = p->request;

    len = http_methods[p->method - 1].len
          + p->upstream_url->uri.len
          + (r->uri.len - p->upstream_url->location->len)
          + r->args.len + 1   /* 1 is for "?" */
          + sizeof(http_version) - 1
          + sizeof(host_header) - 1 + p->upstream_url->host.len + 2
          + sizeof(conn_close_header) - 1
          + 2;   /* 2 is for "\r\n" at the header end */

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

    ngx_test_null(hunk, ngx_create_temp_hunk(r->pool, len, 0, 0), NULL);
    ngx_add_hunk_to_chain(chain, hunk, r->pool, NULL);

    /* the request line */

    hunk->last = ngx_cpymem(hunk->last, http_methods[p->method - 1].data,
                            http_methods[p->method - 1].len);

    hunk->last = ngx_cpymem(hunk->last, p->upstream_url->uri.data,
                            p->upstream_url->uri.len);

    hunk->last = ngx_cpymem(hunk->last,
                            r->uri.data + p->upstream_url->location->len,
                            r->uri.len - p->upstream_url->location->len);

    if (r->args.len > 0) {
        *(hunk->last++) = '?';
        hunk->last = ngx_cpymem(hunk->last, r->args.data, r->args.len);
    }

    hunk->last = ngx_cpymem(hunk->last, http_version, sizeof(http_version) - 1);

    /* the "Host" header */

    hunk->last = ngx_cpymem(hunk->last, host_header, sizeof(host_header) - 1);

    hunk->last = ngx_cpymem(hunk->last, p->upstream_url->host.data,
                            p->upstream_url->host.len);

    *(hunk->last++) = CR; *(hunk->last++) = LF;

    /* the "Connection: close" header */

    hunk->last = ngx_cpymem(hunk->last, conn_close_header,
                            sizeof(conn_close_header) - 1);

    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        hunk->last = ngx_cpymem(hunk->last, header[i].key.data,
                                header[i].key.len);

        *(hunk->last++) = ':'; *(hunk->last++) = ' ';

        hunk->last = ngx_cpymem(hunk->last, header[i].value.data,
                                header[i].value.len);

        *(hunk->last++) = CR; *(hunk->last++) = LF;

        ngx_log_debug(r->connection->log, "proxy: '%s: %s'" _
                      header[i].key.data _ header[i].value.data);
    }

    /* add "\r\n" at the header end */
    *(hunk->last++) = CR; *(hunk->last++) = LF;

    /* STUB */ *(hunk->last++) = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ hunk->pos);

    return chain;
}


static int ngx_http_proxy_process_upstream(ngx_http_proxy_ctx_t *p,
                                           ngx_event_t *ev)
{
    int                         rc;
    time_t                      now;
    ngx_connection_t           *c;
    ngx_http_proxy_upstream_t  *u;

    for ( ;; ) {

        if (ev == NULL) {
            /* STUB: look up cached connection */
            c  = NULL;

            if (c) {
                p->cached_connection = 1;
                p->connection = c;
                c->write->event_handler = c->read->event_handler =
                                         ngx_http_proxy_process_upstream_event;
                rc = ngx_http_proxy_send_request(p);

            } else {
                p->cached_connection = 0;
                p->connection = NULL;
                rc = ngx_http_proxy_connect(p);
            }

            if (p->connection) {
                ev = p->connection->write;
            }

        } else {

            if (ev->timedout) {
                rc = NGX_HTTP_GATEWAY_TIME_OUT;

            } else if (ev->write) {

                rc = p->state_write_upstream_handler(p);

            } else { /* ev->read */

                rc = p->state_read_upstream_handler(p);
            }
        }

        if (rc == NGX_DONE || rc == NGX_AGAIN) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_proxy_finalize_request(p,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }

        if (p->tries > 1
            && (rc == NGX_HTTP_BAD_GATEWAY
                || rc == NGX_HTTP_GATEWAY_TIME_OUT
                || (rc == NGX_OK
                    && p->status == NGX_HTTP_INTERNAL_SERVER_ERROR
                    && p->lcf->retry_500_error)))
        {
            if (ev) {
                ngx_event_close_connection(ev);
                ev = NULL;
            }

            if (!p->cached_connection) {
                if (p->upstreams->number > 1) {
                    now = ngx_time();
                    u = &p->upstreams->u[p->cur_upstream];

                    /* Here is the race condition when the upstreams are shared
                       between threads or processes but it's not serious */

                    u->fails++;
                    u->accessed = now;

                    /* */
                }

                p->tries--;
                p->last_error = rc;
            }

            if (p->tries == 0) {
                ngx_http_proxy_finalize_request(p, p->last_error);
                return NGX_ERROR;
            }

            /* reinitialize the proxy context for the next upstream */

            p->headers_in.server->key.len = 0;
            p->headers_in.connection->key.len = 0;
            p->headers_in.content_type->key.len = 0;
            p->headers_in.content_length->key.len = 0;
            p->headers_in.last_modified->key.len = 0;

            p->headers_in.headers->nelts = 0;
        }

        if (rc == NGX_OK) {
            ngx_http_proxy_finalize_request(p, p->status);
            return NGX_DONE;
        }

        if (rc > NGX_OK) {
            ngx_http_proxy_finalize_request(p, rc);
        }

        return NGX_DONE;
    }
}


static int ngx_http_proxy_connect(ngx_http_proxy_ctx_t *p)
{
    int                         rc, event;
    struct sockaddr_in         *addr;
    ngx_err_t                   err;
    ngx_socket_t                s;
    ngx_event_t                *rev, *wev;
    ngx_connection_t           *c;
    ngx_http_proxy_log_ctx_t   *lcx;
    ngx_http_proxy_upstream_t  *u;

    if (p->upstreams->number > 1) {
        if (p->tries == p->upstreams->number) {

            /* Here is the race condition
               when the upstreams are shared between
               the threads or the processes but it should not be serious */

            p->cur_upstream = p->upstreams->current++;

            if (p->upstreams->current >= p->upstreams->number) {
                p->upstreams->current = 0;
            }

            /* */

#if (NGX_MULTITHREADED || NGX_MULTIPROCESSED)
            /* eliminate the sequences of the race condition */
            if (p->cur_upstream >= p->upstreams->number) {
                p->cur_upstream = 0;
            }
#endif
        }

        if (p->upstreams->max_fails > 0) {

            for ( ;; ) {
                u = &p->upstreams->u[p->cur_upstream];


                /* Here is the race condition
                   when the upstreams are shared between
                   the threads or the processes but it should not be serious */

                if (u->fails > p->upstreams->max_fails
                    || u->accessed < p->upstreams->fail_timeout)
                {
                    break;
                }

                /* */

                p->cur_upstream++;

                if (p->cur_upstream >= p->upstreams->number) {
                    p->cur_upstream = 0;
                }

                p->tries--;

                if (p->tries == 0) {
                    return p->last_error;
                }
            }
        }
    }

    lcx = p->log->data;
    lcx->action = "connecting to an upstream";
    lcx->upstream = p->upstreams->u[p->cur_upstream].addr_port_name.data;
    p->log->handler = ngx_http_proxy_log_error;

    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (p->lcf->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &p->lcf->rcvbuf, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    c = &ngx_connections[s];
    rev = &ngx_read_events[s];
    wev = &ngx_write_events[s];

    ngx_memzero(c, sizeof(ngx_connection_t));
    ngx_memzero(rev, sizeof(ngx_event_t));
    ngx_memzero(wev, sizeof(ngx_event_t));

    rev->index = wev->index = NGX_INVALID_INDEX;
    rev->data = wev->data = c;
    c->read = rev;
    c->write = wev;
    rev->first = wev->first = 1;
    rev->log = wev->log = c->log = p->log;
    c->fd = s;
    wev->close_handler = rev->close_handler = ngx_event_close_connection;

    if (ngx_event_flags & NGX_HAVE_EDGE_EVENT) {
        if (ngx_edge_add_event(wev) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_test_null(c->pool, ngx_create_pool(p->lcf->conn_pool_size, p->log),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    ngx_test_null(p->sockaddr,
                  ngx_pcalloc(c->pool, sizeof(struct sockaddr_in)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    addr = (struct sockaddr_in *) p->sockaddr;

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = p->upstreams->u[p->cur_upstream].addr;
    addr->sin_port = htons(p->upstreams->u[p->cur_upstream].port);

    rc = connect(s, p->sockaddr, sizeof(struct sockaddr_in));

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS) {
            ngx_log_error(NGX_LOG_CRIT, p->log, err, "connect() failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_HTTP_BAD_GATEWAY;
        }
    }

    c->data = p->request;
    p->connection = c;

    if ((ngx_event_flags & NGX_HAVE_EDGE_EVENT) == 0) {   /* not epoll */

        if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {     /* kqueue */
            event = NGX_CLEAR_EVENT;

        } else {                                  /* select, poll, /dev/poll */
            event = NGX_LEVEL_EVENT;
        }

        /* TODO: aio, iocp */

        if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rev->event_handler = ngx_http_proxy_process_upstream_event;
    p->request->connection->write->event_handler = NULL;

    p->state_write_upstream_handler = ngx_http_proxy_send_request;
    p->state_read_upstream_handler = ngx_http_proxy_init_upstream;

    /* The connection has been established */
    if (rc == 0) {
        wev->write = 1;
        wev->ready = 1;

        return ngx_http_proxy_send_request(p);
    }

    /* The connection is in a progress */

    wev->timer_set = 1;
    ngx_add_timer(wev, p->lcf->connect_timeout);

    /* TODO: aio, iocp */

    if (ngx_event_flags & NGX_HAVE_EDGE_EVENT) {
        return NGX_DONE;
    }

    if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DONE;
}


static int ngx_http_proxy_process_upstream_event(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    return ngx_http_proxy_process_upstream(p, ev);
}


static int ngx_http_proxy_send_request(ngx_http_proxy_ctx_t *p)
{
    ngx_chain_t  *chain;
    ngx_event_t  *wev;

    chain = ngx_write_chain(p->connection, p->request_hunks, 0);
    if (chain == (ngx_chain_t *) -1) {
        return NGX_ERROR;
    }

    p->request_hunks = chain;

    wev = p->connection->write;

    ngx_del_timer(wev);

    if (chain) {
        ngx_add_timer(wev, p->lcf->send_timeout);
        wev->timer_set = 1;

    } else {
        wev->timer_set = 0;
    }

    return NGX_DONE;
}


static int ngx_http_proxy_init_upstream(ngx_http_proxy_ctx_t *p)
{
    int                   n;
    ngx_hunk_t          **ph;
    ngx_http_request_t   *r;

    r = p->request;

    ngx_test_null(p->header_in,
                  ngx_create_temp_hunk(r->pool, p->lcf->header_size, 0, 0),
                  NGX_ERROR);

#if 0
    ngx_test_null(p->header_in,
                  ngx_create_temp_hunk(r->pool,
                                       p->lcf->header_size
                                                  - sizeof(ngx_cache_header_t),
                                       sizeof(ngx_cache_header_t),
                                       0),
                  NGX_ERROR);

    p->header_in->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
#endif

#if 0
    ngx_test_null(p->headers_in,
                  ngx_palloc(r->pool, sizeof(ngx_http_proxy_headers_in_t)),
                  NGX_ERROR);
#endif

    p->nhunks = p->lcf->max_block_size / p->lcf->block_size;
    if (p->nhunks * p->lcf->block_size < p->lcf->max_block_size) {
        p->nhunks++;
    }

    ngx_init_array(p->hunks, r->pool, p->nhunks, sizeof(ngx_hunk_t *),
                   NGX_ERROR);

    ngx_test_null(ph, ngx_push_array(&p->hunks), NGX_ERROR);
    *ph = p->header_in;

    p->state_handler = ngx_http_proxy_process_upstream_status_line;

    return ngx_http_proxy_read_upstream_header(p);
}


static int ngx_http_proxy_read_upstream_header(ngx_http_proxy_ctx_t *p)
{
    int                  i, n, rc;
    ngx_event_t         *rev;
    ngx_chain_t         *temp;
    ngx_table_elt_t     *ch, *ph;
    ngx_event_proxy_t   *ep;
    ngx_http_request_t  *r;
    ngx_http_proxy_log_ctx_t   *lcx;

    rev = p->connection->read;

    do {
        n = ngx_event_recv(p->connection, p->header_in->last,
                           p->header_in->end - p->header_in->last);

        if (n == NGX_AGAIN) {
            if (rev->timer_set) {
                ngx_del_timer(rev);
            } else {
                rev->timer_set = 1;
            }

            ngx_add_timer(rev, p->lcf->read_timeout);
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_HTTP_BAD_GATEWAY;
        }

        ngx_log_debug(p->log, "http proxy read %d" _ n);

        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, p->log, 0,
                          "upstream closed prematurely connection");
            return NGX_HTTP_BAD_GATEWAY;
        }

        p->header_in->last += n;

        /* the state handlers are called in the following order:
            ngx_http_proxy_process_upstream_status_line(p)
            ngx_http_proxy_process_upstream_headers(p) */

        do {
            rc = p->state_handler(p);
        } while (rc == NGX_AGAIN && p->header_in->pos < p->header_in->last);

    } while (rc == NGX_AGAIN
             && (rev->ready || ngx_event_flags & NGX_HAVE_AIO_EVENT));

    if (rc == NGX_OK) {

        r = p->request;

        /* copy an upstream header to r->headers_out */

        ph = (ngx_table_elt_t *) p->headers_in.headers->elts;
        for (i = 0; i < p->headers_in.headers->nelts; i++) {

            if (&ph[i] == p->headers_in.connection) {
                continue;
            }

            if (p->accel && &ph[i] == p->headers_in.date) {
                continue;
            }

            ngx_test_null(ch, ngx_push_table(r->headers_out.headers),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

            ch->key.len = ph[i].key.len;
            ch->key.data = ph[i].key.data;
            ch->value.len = ph[i].value.len;
            ch->value.data = ph[i].value.data;
        }

        if (p->headers_in.server) {
            r->headers_out.server = p->headers_in.server;
        }

        if (!p->accel && p->headers_in.date) {
            r->headers_out.date = p->headers_in.date;
        }

        /* TODO: look "Content-Length" */
        p->block_size = p->lcf->block_size;

        r->headers_out.status = p->status;

        rc = ngx_http_send_header(r);

#if 1
#if 0
        rc = ngx_http_output_filter(r, p->header_in);
#endif

        ngx_test_null(ep, ngx_pcalloc(r->pool, sizeof(ngx_event_proxy_t)),
                      NGX_ERROR);

        ep->output_filter = (ngx_event_proxy_output_filter_pt)
                                                        ngx_http_output_filter;
        ep->output_data = r;
        ep->block_size = p->lcf->block_size;
        ep->max_block_size = p->lcf->max_block_size;
        ep->upstream = p->connection;
        ep->downstream = r->connection;
        ep->pool = r->pool;
        ep->log = p->log;
        ep->temp_path = p->lcf->temp_path;

        ngx_test_null(ep->temp_file, ngx_palloc(r->pool, sizeof(ngx_file_t)),
                      NGX_ERROR);
        ep->temp_file->fd = NGX_INVALID_FILE;
        ep->temp_file->log = p->log;

        ep->max_temp_file_size = p->lcf->max_temp_file_size;
        ep->temp_file_write_size = p->lcf->temp_file_write_size;
        ep->temp_file_warn = "an upstream response is buffered "
                             "to a temporary file";

        ngx_test_null(ep->preread_hunks, ngx_alloc_chain_entry(r->pool),
                      NGX_ERROR);
        ep->preread_hunks->hunk = p->header_in;
        ep->preread_hunks->next = NULL;
#if 0
        ep->last_preread_hunk = ep->preread_hunks;
#endif

        ep->preread_size = p->header_in->last - p->header_in->pos;

        p->event_proxy = ep;

        lcx = p->log->data;
        lcx->action = "reading an upstream";

        p->state_read_upstream_handler = ngx_http_proxy_read_upstream_body;
        p->state_write_upstream_handler = ngx_http_proxy_write_upstream_body;

        ngx_http_proxy_read_upstream_body(p);
#endif

#if 0
        /* STUB */
        p->header_in->type |= NGX_HUNK_LAST;
        rc = ngx_http_output_filter(r, p->header_in);
        ngx_http_proxy_finalize_request(p, NGX_OK);
#endif

        /* STUB */ return NGX_DONE;
    }

    if (rc > NGX_OK) {
        return rc;
    }

    /* STUB */ return NGX_DONE;
}


static int ngx_http_proxy_process_upstream_status_line(ngx_http_proxy_ctx_t *p)
{
    int  rc;

    rc = ngx_read_http_proxy_status_line(p);

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        p->status = 200;
        p->status_line.len = 0;
        p->full_status_line.len = 0;
        p->state_handler = ngx_http_proxy_process_upstream_headers;

    } else if (rc == NGX_OK) {
        p->status_line.len = p->status_end - p->status_start;
        p->full_status_line.len = p->status_end - p->header_in->start;

        if (p->lcf->large_header) {
            ngx_test_null(p->full_status_line.data,
                          ngx_palloc(p->request->pool,
                                     p->full_status_line.len + 1),
                          NGX_HTTP_INTERNAL_SERVER_ERROR);

            ngx_cpystrn(p->full_status_line.data, p->header_in->start,
                        p->full_status_line.len + 1);

            if (p->header_in->pos == p->header_in->end) {
                p->header_in->pos = p->header_in->last = p->header_in->start;
            }

        } else {
            p->status_line.data = p->status_start;
            p->full_status_line.data = p->header_in->start;
            *p->status_end = '\0';

            if (p->header_in->pos == p->header_in->end) {
                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "upstream sent too long status line");
                return NGX_HTTP_BAD_GATEWAY;
            }
        }

        ngx_log_debug(p->log, "upstream status: %d, '%s'" _
                      p->status _ p->full_status_line.data);

        p->state_handler = ngx_http_proxy_process_upstream_headers;
    }

    /* rc == NGX_AGAIN */

    return NGX_AGAIN;
}


static int ngx_http_proxy_process_upstream_headers(ngx_http_proxy_ctx_t *p)
{
    int                  rc, offset;
    ngx_http_request_t  *r;

    r = p->request;

    for ( ;; ) {
        rc = ngx_read_http_header_line(r, p->header_in);

        /* a header line has been parsed successfully */

        if (rc == NGX_OK) {
            if (ngx_http_proxy_process_upstream_header_line(p) == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (p->lcf->large_header
                && p->header_in->pos == p->header_in->last)
            {
                p->header_in->pos = p->header_in->last = p->header_in->start;
            }

            return NGX_AGAIN;

        /* a whole header has been parsed successfully */

        } else if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug(p->log, "proxy HTTP header done");

            p->state_handler = NULL;
            return NGX_OK;

        /* there was error while a header line parsing */

        } else if (rc != NGX_AGAIN) {
            ngx_log_error(NGX_LOG_ERR, p->log, 0,
                          "upstream sent ERROR %d", rc);
            return NGX_HTTP_BAD_GATEWAY;
        }

        /* NGX_AGAIN: a header line parsing is still not complete */

        if (p->header_in->pos == p->header_in->last) {
            /* if the large upstream headers are enabled then
                we need to compact p->header_in hunk */

            if (p->lcf->large_header) {
                offset = r->header_name_start - p->header_in->start;

                if (offset == 0) {
                    ngx_log_error(NGX_LOG_ERR, p->log, 0,
                                  "upstream sent too long header line");
                    return NGX_HTTP_BAD_GATEWAY;
                }

                ngx_memcpy(p->header_in->start, r->header_name_start,
                           p->header_in->last - r->header_name_start);

                p->header_in->last -= offset;
                p->header_in->pos -= offset;
                r->header_name_start = p->header_in->start;
                r->header_name_end -= offset;
                r->header_start -= offset;
                r->header_end -= offset;

            } else {
                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "upstream sent too long header line");
                /* NGX_HTTP_PARSE_TOO_LONG_HEADER */
                return NGX_HTTP_BAD_GATEWAY;
            }
        }

        return NGX_AGAIN;
    }
}


static int ngx_http_proxy_process_upstream_header_line(ngx_http_proxy_ctx_t *p)
{
    int                  i;
    ngx_table_elt_t     *h;
    ngx_http_request_t  *r;

    r = p->request;

    ngx_test_null(h, ngx_push_table(p->headers_in.headers), NGX_ERROR);

    h->key.len = r->header_name_end - r->header_name_start;
    h->value.len = r->header_end - r->header_start;

    /* if the large upstream headers are enabled then
       we need to copy the header name and value */

    if (p->lcf->large_header) {
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
                        ((char *) &p->headers_in + headers_in[i].offset)) = h;
        }
    }

    ngx_log_debug(p->log, "proxy HTTP header: '%s: %s'" _
                  h->key.data _ h->value.data);

    return NGX_OK;
}


static int ngx_http_proxy_read_upstream_body(ngx_http_proxy_ctx_t *p)
{
    int  rc;

    rc = ngx_event_proxy_read_upstream(p->event_proxy);

    if (p->event_proxy->fatal_error) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (p->event_proxy->upstream_eof || p->event_proxy->upstream_error) {
        rc = ngx_event_close_connection(p->connection->read);
    }

    return rc;
}


static int ngx_http_proxy_process_client_event(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    return ngx_http_proxy_process_upstream(p, ev);
}


static int ngx_http_proxy_write_upstream_body(ngx_http_proxy_ctx_t *p)
{
    return ngx_event_proxy_write_to_downstream(p->event_proxy);
}




static int ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int error)
{
#if 0

    if (p->event_proxy->upstream_eof) {
        rc = ngx_event_close_connection(p->connection->read);
        link cache;
    }

    if (p->event_proxy->upstream_error) {
        rc = ngx_event_close_connection(p->connection->read);
    }

    if (p->event_proxy->downstream_error) {
        rc = ngx_event_close_connection(p->request->connection->write);
    }

#endif

    return ngx_http_finalize_request(p->request, error);
}


static int ngx_http_proxy_error(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p,
                                int error)
{
    ngx_event_close_connection(p->connection->read);

    return ngx_http_error(r, error);
} 


static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_log_ctx_t *lcx = (ngx_http_proxy_log_ctx_t *) data;

    return ngx_snprintf(buf, len,
                        " while %s, upstream: %s, client: %s, URL: %s",
                        lcx->action, lcx->upstream, lcx->client, lcx->url);
}



static int ngx_read_http_proxy_status_line(ngx_http_proxy_ctx_t *ctx)
{
    char   ch;
    char  *p;
    enum  {
        sw_start = 0,
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

    state = ctx->state;
    p = ctx->header_in->pos;

    while (p < ctx->header_in->last && state < sw_done) {
        ch = *p++;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (p + 3 >= ctx->header_in->last) {
                return NGX_AGAIN;
            }

            if (ch != 'H' || *p != 'T' || *(p + 1) != 'T' || *(p + 2) != 'P'
                          || *(p + 3) != '/')
            {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            p += 4;
            state = sw_first_major_digit;
            break;

        /* first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_major_digit;
            break;

        /* major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            break;

        /* first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_HTTP_PROXY_PARSE_NO_HEADER;
            }

            state = sw_minor_digit;
            break;

        /* minor HTTP version or end of request line */
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

            ctx->status = ctx->status * 10 + ch - '0';

            if (++ctx->status_count == 3) {
                state = sw_space_after_status;
                ctx->status_start = p - 3;
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
            ctx->status_end = p - 2;
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

    ctx->header_in->pos = p;

    if (state == sw_done) {
        if (ctx->status_end == NULL) {
            ctx->status_end = p - 1;
        }

        ctx->state = sw_start;
        return NGX_OK;

    } else {
        ctx->state = state;
        return NGX_AGAIN;
    }
}


static int ngx_http_proxy_init(ngx_pool_t *pool)
{
    int         i;
    ngx_file_t  file;
    ngx_path_t  path;

    file.log = pool->log;

    path.name.data = "temp";
    path.name.len = 4;
    path.level[0] = 1;
    path.level[1] = 2;
    path.level[2] = 3;
    path.len = 0;

    for (i = 0; i < 3; i++) {
        if (path.level[i] == 0) {
            break;
        }
        path.len += path.level[i] + 1;
    }

    return ngx_create_temp_file(&file, &path, pool, 0);
}


static void *ngx_http_proxy_create_loc_conf(ngx_pool_t *pool)
{
    int                         i;
    ngx_http_proxy_loc_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NULL);

    /* STUB */
    conf->conn_pool_size = 16384;
    conf->connect_timeout = 10000;
    conf->send_timeout = 10000;
    conf->read_timeout = 10000;
    conf->header_size = 2048;

#if 1
    conf->block_size = 4096;
    conf->max_block_size = 4096 * 3;
    conf->max_temp_file_size = 4096 * 5;
    conf->temp_file_write_size = 4096 * 2;
#else
    conf->block_size = 2048;
    conf->max_block_size = 4096 * 6;
    conf->max_temp_file_size = 4096 * 5;
    conf->temp_file_write_size = 4096 * 5;
#endif

    ngx_test_null(conf->temp_path, ngx_pcalloc(pool, sizeof(ngx_path_t)), NULL);

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
    /**/

    return conf;
}


static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     char *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = (ngx_http_proxy_loc_conf_t *) conf;

    int                        i, s, len;
    char                      *err, *host;
    struct hostent            *h;
    u_int32_t                  addr;
    ngx_str_t                 *value;
    ngx_http_conf_ctx_t       *ctx;
    ngx_http_core_loc_conf_t  *core_lcf;

    value = (ngx_str_t *) cf->args->elts;

    if (ngx_strncasecmp(value[1].data, "http://", 7) != 0) {
        return "invalid URL prefix";
    }

    ngx_test_null(lcf->upstream_url,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_upstream_url_t)),
                  NGX_CONF_ERROR);

    value[1].data += 7;
    value[1].len -= 7;

    err = ngx_http_proxy_parse_upstream(&value[1], lcf->upstream_url);

    if (err) {
        return err;
    }

    if (lcf->upstream_url->port == 0) {
        lcf->upstream_url->port = 80;
    }

    ngx_test_null(host, ngx_palloc(cf->pool, lcf->upstream_url->host.len + 1),
                  NGX_CONF_ERROR);
    ngx_cpystrn(host, lcf->upstream_url->host.data,
                lcf->upstream_url->host.len + 1);

    /* TODO: look up upstreams */

    addr = inet_addr(host);
    if (addr == INADDR_NONE) {
        h = gethostbyname(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            /* STUB: "host %s not found", host */
            return "host not found";
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) {
            /* void */
        }

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->upstreams,
                      ngx_pcalloc(cf->pool,
                                sizeof(ngx_http_proxy_upstreams_t)
                                + sizeof(ngx_http_proxy_upstream_t) * (i - 1)),
                      NGX_CONF_ERROR);

        lcf->upstreams->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {
            lcf->upstreams->u[i].host.data = host;
            lcf->upstreams->u[i].host.len = lcf->upstream_url->host.len;
            lcf->upstreams->u[i].addr = *(u_int32_t *)(h->h_addr_list[i]);
            lcf->upstreams->u[i].port = lcf->upstream_url->port;

            len = INET_ADDRSTRLEN + lcf->upstream_url->port_name.len + 1;
            ngx_test_null(lcf->upstreams->u[i].addr_port_name.data,
                          ngx_palloc(cf->pool, len),
                          NGX_CONF_ERROR);

            s = ngx_inet_ntop(AF_INET,
                              (char *) &lcf->upstreams->u[i].addr,
                              lcf->upstreams->u[i].addr_port_name.data,
                              len);

            lcf->upstreams->u[i].addr_port_name.data[s++] = ':';

            ngx_cpystrn(lcf->upstreams->u[i].addr_port_name.data + s,
                        lcf->upstream_url->port_name.data,
                        lcf->upstream_url->port_name.len + 1);

            lcf->upstreams->u[i].addr_port_name.len =
                                      s + lcf->upstream_url->port_name.len + 1;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->upstreams,
                      ngx_palloc(cf->pool, sizeof(ngx_http_proxy_upstreams_t)),
                      NGX_CONF_ERROR);

        lcf->upstreams->number = 1;

        lcf->upstreams->u[0].host.data = host;
        lcf->upstreams->u[0].host.len = lcf->upstream_url->host.len;
        lcf->upstreams->u[0].addr = addr;
        lcf->upstreams->u[0].port = lcf->upstream_url->port;

        len = lcf->upstream_url->host.len
              + lcf->upstream_url->port_name.len + 1;

        ngx_test_null(lcf->upstreams->u[0].addr_port_name.data,
                      ngx_palloc(cf->pool, len + 1),
                      NGX_CONF_ERROR);

        ngx_memcpy(lcf->upstreams->u[0].addr_port_name.data,
                   lcf->upstream_url->host.data,
                   lcf->upstream_url->host.len);

        s = lcf->upstream_url->host.len;

        lcf->upstreams->u[0].addr_port_name.data[s++] = ':';

        ngx_cpystrn(lcf->upstreams->u[0].addr_port_name.data + s,
                    lcf->upstream_url->port_name.data,
                    lcf->upstream_url->port_name.len + 1);

        lcf->upstreams->u[0].addr_port_name.len = len;
    }

    ctx = cf->ctx;
    core_lcf = ctx->loc_conf[ngx_http_core_module_ctx.index];
    core_lcf->handler = ngx_http_proxy_handler;
    lcf->upstream_url->location = &core_lcf->name;

    return NULL;
}


static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_url_t *uu)
{
    size_t  i;

    if (url->data[0] == ':' || url->data[0] == '/') {
        return "invalid upstream URL";
    }

    uu->host.data = url->data;
    uu->host_header.data = url->data;

    for (i = 1; i < url->len; i++) {
        if (url->data[i] == ':') {
            uu->port_name.data = &url->data[i] + 1;
            uu->host.len = i;
        }

        if (url->data[i] == '/') {
            uu->uri.data = &url->data[i];
            uu->uri.len = url->len - i;
            uu->host_header.len = i;

            if (uu->host.len == 0) {
                uu->host.len = i;
            }

            if (uu->port_name.data == NULL) {
                return NULL;
            }

            uu->port_name.len = &url->data[i] - uu->port_name.data;

            if (uu->port_name.len > 0) {
                uu->port = ngx_atoi(uu->port_name.data, uu->port_name.len);
                if (uu->port > 0) {
                    return NULL;
                }
            }

            return "invalid port in upstream URL";
        }
    }

    if (uu->host.len == 0) {
        uu->host.len = i;
    }

    uu->host_header.len = i;

    uu->uri.data = "/";
    uu->uri.len = 1;

    if (uu->port_name.data == NULL) {
        return NULL;
    }

    uu->port_name.len = &url->data[i] - uu->port_name.data;

    if (uu->port_name.len > 0) {
        uu->port = ngx_atoi(uu->port_name.data, uu->port_name.len);
        if (uu->port > 0) {
            return NULL;
        }
    }

    return "invalid port in upstream URL";
}
