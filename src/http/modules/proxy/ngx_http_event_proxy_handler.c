
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_inet.h>
#include <ngx_conf_file.h>
#include <ngx_event_write.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_event_proxy_handler.h>


static int ngx_http_proxy_handler(ngx_http_request_t *r);

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


static int ngx_http_proxy_read_response_body(ngx_event_t *ev);
static int ngx_http_proxy_write_to_client(ngx_event_t *ev);

static int ngx_read_http_proxy_status_line(ngx_http_proxy_ctx_t *ctx);

static int ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int error);
static size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len);

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
    NULL                                   /* init module */
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

    /* TODO: read a client's body */

    chain = ngx_http_proxy_create_request(p);
    if (chain == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TODO: duplicate the hunks and chain if there is backend farm */
    p->out = chain;

    p->last_error = NGX_HTTP_BAD_GATEWAY;
    ngx_http_proxy_process_upstream(p, NULL);

    /* On an error ngx_http_proxy_process_upstream() calls
       ngx_http_proxy_finalize_request() so we return NGX_DONE to avoid
       the additional NGX_HTTP_INTERNAL_SERVER_ERROR error
       that would be generated by ngx_http_process_request() */

    return NGX_DONE;
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

    ngx_memcpy(hunk->last, http_methods[p->method - 1].data,
               http_methods[p->method - 1].len);
    hunk->last += http_methods[p->method - 1].len;

    ngx_memcpy(hunk->last, p->upstream_url->uri.data, p->upstream_url->uri.len);
    hunk->last += p->upstream_url->uri.len;

    ngx_memcpy(hunk->last, r->uri.data + p->upstream_url->location->len,
               r->uri.len - p->upstream_url->location->len);
    hunk->last += r->uri.len - p->upstream_url->location->len;

    if (r->args.len > 0) {
        *(hunk->last++) = '?';
        ngx_memcpy(hunk->last, r->args.data, r->args.len);
        hunk->last += r->args.len;
    }

    ngx_memcpy(hunk->last, http_version, sizeof(http_version) - 1);
    hunk->last += sizeof(http_version) - 1;

    /* the "Host" header */

    ngx_memcpy(hunk->last, host_header, sizeof(host_header) - 1);
    hunk->last += sizeof(host_header) - 1;

    ngx_memcpy(hunk->last, p->upstream_url->host.data,
               p->upstream_url->host.len);
    hunk->last += p->upstream_url->host.len;

    *(hunk->last++) = CR; *(hunk->last++) = LF;

    /* the "Connection: close" header */

    ngx_memcpy(hunk->last, conn_close_header, sizeof(conn_close_header) - 1);
    hunk->last += sizeof(conn_close_header) - 1;

    for (i = 0; i < r->headers_in.headers->nelts; i++) {

        if (&header[i] == r->headers_in.host) {
            continue;
        }

        if (&header[i] == r->headers_in.connection) {
            continue;
        }

        ngx_memcpy(hunk->last, header[i].key.data, header[i].key.len);
        hunk->last += header[i].key.len;

        *(hunk->last++) = ':'; *(hunk->last++) = ' ';

        ngx_memcpy(hunk->last, header[i].value.data, header[i].value.len);
        hunk->last += header[i].value.len;

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
                c->write->event_handler = ngx_http_proxy_process_upstream_event;
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

        if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT
            || (rc == NGX_OK
                && p->status == NGX_HTTP_INTERNAL_SERVER_ERROR
                && p->lcf->retry_500_error))
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
               when the upstreams are shared between threads or processes
               but it should not be serious */

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
                   when the upstreams are shared between threads or processes
                   but it should not be serious */

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
        return NGX_ERROR;
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

            return NGX_ERROR;
        }
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, p->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
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

#if !(USE_KQUEUE)

#if (HAVE_EDGE_EVENT) /* epoll */

    if (ngx_event_flags & NGX_HAVE_EDGE_EVENT) {
        if (ngx_edge_add_event(wev) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#endif

#endif

    ngx_test_null(c->pool, ngx_create_pool(p->lcf->conn_pool_size, p->log),
                  NGX_ERROR);

    ngx_test_null(p->sockaddr,
                  ngx_pcalloc(c->pool, sizeof(struct sockaddr_in)),
                  NGX_ERROR);

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

            ngx_destroy_pool(c->pool);

            return NGX_HTTP_BAD_GATEWAY;
        }
    }

    c->data = p->request;
    p->connection = c;

    ngx_test_null(c->pool, ngx_create_pool(p->lcf->conn_pool_size, p->log),
                  NGX_ERROR);

#if (USE_KQUEUE)

    if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) {
        return NGX_ERROR;
    }

#else

    if ((ngx_event_flags & NGX_HAVE_EDGE_EVENT) == 0) { /* not epoll */

        if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {  /* kqueue */
            event = NGX_CLEAR_EVENT;

        } else {                             /* select, poll, /dev/poll */
            event = NGX_LEVEL_EVENT;
        }

        /* TODO: aio, iocp */

        if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#endif /* USE_KQUEUE */

    wev->event_handler = rev->event_handler =
                                         ngx_http_proxy_process_upstream_event;

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

#if (USE_KQUEUE)

    if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) {
        return NGX_ERROR;
    }

#else

    /* TODO: aio, iocp */

    if (ngx_event_flags & NGX_HAVE_EDGE_EVENT) {
        return NGX_DONE;
    }

    if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
        return NGX_ERROR;
    }

#endif /* USE_KQUEUE */

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

    chain = ngx_write_chain(p->connection, p->out, 0);
    if (chain == (ngx_chain_t *) -1) {
        return NGX_ERROR;
    }

    p->out = chain;

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

    p->header_in->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;

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
    ngx_table_elt_t     *ch, *ph;
    ngx_http_request_t  *r;

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

        /* STUB */
        p->header_in->type |= NGX_HUNK_LAST;
        rc = ngx_http_output_filter(r, p->header_in);
        ngx_http_proxy_finalize_request(p, NGX_OK);

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


#if 0

static int ngx_http_proxy_read_upstream_body(ngx_event_t *rev)
{
    ngx_hunk_t            *h;
    ngx_chain_t           *chain, ce;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) rev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    ce.next = NULL;

    do {

#if (USE_KQUEUE)

        if (ev->eof && ev->available == 0) {
            break;
        }

#elif (HAVE_KQUEUE)

        if (ngx_event_type == NGX_HAVE_KQUEUE_EVENT
            && ev->eof && ev->available == 0)
        {
            break;
        }

#endif

        if (p->free_hunks) {
            chain = p->free_hunks;

        } else if (p->allocated < p->lcf->max_block_size) {
            ngx_test_null(h,
                          ngx_create_temp_hunk(r->pool, p->block_size, 50, 50),
                          NGX_ERROR);

            p->allocated += p->block_size;
            ce.hunk = h;
            chain = &ce;

        } else {
            if (p->temp_fd == NGX_INVALID_FILE) {
                rc = ngx_create_temp_file(p->temp_file, r->cachable);

                if (rc != NGX_OK) {
                    return rc;
                }

                if (p->lcf->temp_file_warn) {
                    ngx_log_error(NGX_LOG_WARN, p->log, 0,
                                  "an upstream response is buffered "
                                  "to a temporary file");
                }
            }

            n = ngx_write_chain_to_file(p->temp_file, p->in_hunks,
                                        p->temp_offset);

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_test_null(h, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                          NGX_ERROR);

            h->type = NGX_HUNK_FILE
                      |NGX_HUNK_IN_MEMORY|NGX_HUNK_TEMP|NGX_HUNK_RECYCLED;

            h->file_pos = p->temp_offset;
            p->temp_offset += n;
            h->file_last = p->temp_offset;

            h->file->fd = p->temp_file.fd;
            h->file->log = p->log;

            h->pos = p->in_hunks->hunk->pos;
            h->last = p->in_hunks->hunk->last;
            h->start = p->in_hunks->hunk->start;
            h->end = p->in_hunks->hunk->end;
            h->pre_start = p->in_hunks->hunk->pre_start;
            h->post_end = p->in_hunks->hunk->post_end;

            ngx_add_hunk_to_chain(p->last_out_hunk, h, r->pool, NGX_ERROR);

            ce.hunk = p->in_hunks->next;
            p->in_hunks = p->in_hunks->next;
            chain = &ce;
        }

        n = ngx_recv_chain(c, chain);

        h->last += n;
        left = hunk->end - hunk->last;

    } while (n > 0 && left == 0);

    if (p->out_hunks && p->request->connection->write->ready) {
        ngx_http_proxy_write_upstream_body(p->request->connection->write);
    }
}


static int ngx_http_proxy_write_upstream_body(ngx_event_t *wev)
{
    while (out) {
        output_filter(r, hunk);
        if (again)
            return

        if (hunk done)
            remove from out
            if (hunk is memory)
                add it to free
    }
}



#endif





static int ngx_http_proxy_read_response_body(ngx_event_t *ev)
{
    int                    n;
    char                  *buf;
    size_t                 left, size;
    ngx_hunk_t            *h, **ph;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    if (ev->timedout) {
        return NGX_ERROR;
    }

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    if (p->hunks.nelts > 0) {
        h = ((ngx_hunk_t **) p->hunks.elts)[p->hunks.nelts - 1];
        left = h->end - h->last;

    } else {
        h = NULL;
        left = 0;
    }

    do {

#if (USE_KQUEUE)

        /* do not allocate new block if there is EOF */
        if (ev->eof && ev->available == 0) {
            left = 1;
        }

#elif (HAVE_KQUEUE)

        if (ngx_event_type == NGX_HAVE_KQUEUE_EVENT) {
            /* do not allocate new block if there is EOF */
            if (ev->eof && ev->available == 0) {
                left = 1;
            }
        }

#endif

        if (left == 0) {
            ngx_test_null(ph, ngx_push_array(&p->hunks), NGX_ERROR);
            ngx_test_null(h,
                          ngx_create_temp_hunk(r->pool,
                                               /* STUB */ 4096 /**/, 0, 0),
                          NGX_ERROR);

            h->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;
            *ph = h;
        }

        if (h != NULL) {
            buf = h->last;
            size = h->end - h->last;

        } else {
            buf = (char *) &buf;
            size = 0;
        }

        n = ngx_event_recv(c, buf, size);

        ngx_log_debug(c->log, "READ:%d" _ n);

        if (n == NGX_AGAIN) {
            return NGX_DONE;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        h->last += n;
        left = h->end - h->last;

        /* STUB */
        *h->last = '\0';
        ngx_log_debug(c->log, "PROXY:\n'%s'" _ h->pos);
        /**/

    } while (n > 0 && left == 0);

    if (n == 0) {
        ngx_log_debug(c->log, "CLOSE proxy");
#if 0
        ngx_del_event(ev, NGX_READ_EVENT, NGX_CLOSE_EVENT);
#endif
        ngx_event_close_connection(ev);

        p->hunk_n = 0;
        c->write->event_handler = ngx_http_proxy_write_to_client;
        return ngx_http_proxy_write_to_client(c->write);
    }

    /* STUB */ return NGX_DONE;
}


static int ngx_http_proxy_write_to_client(ngx_event_t *ev)
{
    int  rc;
    ngx_hunk_t            *h;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    do {
        h = ((ngx_hunk_t **) p->hunks.elts)[p->hunk_n];

        rc = ngx_http_output_filter(r, h);
        if (rc != NGX_OK) {
            return rc;
        }

        if (p->hunk_n >= p->hunks.nelts) {
            break;
        }

        p->hunk_n++;

    } while (rc == NGX_OK);

    return NGX_OK;
}


static int ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int error)
{
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


static void *ngx_http_proxy_create_loc_conf(ngx_pool_t *pool)
{
    ngx_http_proxy_loc_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NULL);

    /* STUB */
    conf->conn_pool_size = 16384;
    conf->connect_timeout = 10000;
    conf->send_timeout = 10000;
    conf->read_timeout = 10000;
    conf->header_size = 1024;
    conf->block_size = 4096;
    conf->max_block_size = 32768;
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
