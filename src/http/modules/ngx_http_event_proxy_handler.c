
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>
#include <ngx_event_write.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_core_module.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_event_proxy_handler.h>


static ngx_command_t  ngx_http_proxy_commands[] = {

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
    NULL,                                  /* create location config */
    NULL,                                  /* merge location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    NULL,                                  /* output body filter */
    NULL                                   /* next output body filter */
};


ngx_module_t  ngx_http_proxy_module = {
    0,                                     /* module index */
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};



static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_request_t *r);
static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text);
static int ngx_http_proxy_send_request(ngx_event_t *ev);

static int ngx_http_proxy_init_response(ngx_event_t *ev);
static int ngx_http_proxy_read_response_header(ngx_event_t *ev);
static int ngx_http_proxy_process_status_line(ngx_http_request_t *r,
                                               ngx_http_proxy_ctx_t *p);

static int ngx_http_proxy_read_response_body(ngx_event_t *ev);
static int ngx_http_proxy_write_to_client(ngx_event_t *ev);

static int ngx_read_http_proxy_status_line(ngx_http_proxy_ctx_t *ctx);


static char conn_close[] = "Connection: close" CRLF;


/* AF_INET only */


int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    struct sockaddr_in     addr;
    ngx_chain_t           *chain;
    ngx_http_proxy_ctx_t  *p;

    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    if (p == NULL) {
        ngx_http_create_ctx(r, p, ngx_http_proxy_module_ctx,
                            sizeof(ngx_http_proxy_ctx_t),
                            NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    chain = ngx_http_proxy_create_request(r);
    if (chain == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p->out = chain;

    ngx_memzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);

    return ngx_http_proxy_connect(r, &addr, "connecting to 127.0.0.1:9000");
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    int     i;
    size_t  len;
    ngx_hunk_t       *hunk;
    ngx_chain_t      *chain;
    ngx_table_elt_t  *header;

    /* 2 is for "\r\n" after request line
       and 2 is for "\r\n" at the header end */

    /* STUB: "method p->url HTTP/1.0" length */

    len = r->request_line.len + 2 + 2;

    /* TODO: Host length */

    /* "Connection: close\r\n" */
    len += sizeof(conn_close) - 1;

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

    /* STUB: "method p->url HTTP/1.0" */

    ngx_memcpy(hunk->last, r->request_line.data, r->request_line.len);
    hunk->last += r->request_line.len;
    *(hunk->last++) = CR; *(hunk->last++) = LF;

    /* TODO: Host header */

    ngx_memcpy(hunk->last, conn_close, sizeof(conn_close) - 1);
    hunk->last += sizeof(conn_close) - 1;

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


static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text)
{
    int                  rc, event;
    ngx_err_t            err;
    ngx_socket_t         s;
    ngx_event_t         *rev, *wev;
    ngx_connection_t    *c, *pc;
    ngx_http_log_ctx_t  *ctx;

    c = r->connection;
    ctx = c->log->data;
    ctx->action = addr_text;

    s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, 0);
    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if 0
    if (rcvbuf) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &rcvbuf, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
#endif

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = connect(s, (struct sockaddr *) addr, sizeof(struct sockaddr_in));

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err, "connect() failed");

            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    pc = &ngx_connections[s];
    rev = &ngx_read_events[s];
    wev = &ngx_write_events[s];

    ngx_memzero(rev, sizeof(ngx_event_t));
    ngx_memzero(wev, sizeof(ngx_event_t));
    ngx_memzero(pc, sizeof(ngx_connection_t));

    rev->data = wev->data = pc;
    pc->read = rev;
    pc->write = wev;

    pc->data = r;

    pc->fd = s;
    pc->servers = c->servers;

    pc->log = rev->log = wev->log = c->log;

    ngx_test_null(pc->pool,
                  ngx_create_pool(/* STUB */ 1024 /**/, pc->log),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    wev->event_handler = ngx_http_proxy_send_request;
    rev->event_handler = ngx_http_proxy_init_response;

#if (USE_KQUEUE)

    if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#else

#if (HAVE_CLEAR_EVENT) /* kqueue */

    if (ngx_event_flags & NGX_HAVE_CLEAR_EVENT) {
        event = NGX_CLEAR_EVENT;

    } else {
        event = NGX_LEVEL_EVENT;
    }

#else /* select, poll, /dev/poll */

    event = NGX_LEVEL_EVENT;

#endif

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#endif /* USE_KQUEUE */

    /* TODO: aio, iocp */

    /* The connection is in a progress */
    if (rc == -1) {
        /* TODO: oneshot */
        if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_ONESHOT_EVENT) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    wev->write = 1;
    wev->ready = 1;

    return ngx_http_proxy_send_request(wev);
}


static int ngx_http_proxy_send_request(ngx_event_t *ev)
{
    ngx_chain_t           *chain;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    chain = ngx_write_chain(c, p->out, 0);
    if (chain == (ngx_chain_t *) -1) {
        return NGX_ERROR;
    }

    p->out = chain;

    return NGX_WAITING;
}


static int ngx_http_proxy_init_response(ngx_event_t *ev)
{
    int                    n;
    ngx_hunk_t           **ph;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;

    if (ev->timedout) {
        return ngx_http_proxy_error(r, p, NGX_HTTP_GATEWAY_TIME_OUT);
    }

    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module_ctx);

    ngx_test_null(p->header_in,
                  ngx_create_temp_hunk(r->pool,
                                       /* STUB */ 1024 /**/, 0, 0),
                  ngx_http_proxy_error(r, p, NGX_HTTP_INTERNAL_SERVER_ERROR));

    p->header_in->type = NGX_HUNK_MEMORY|NGX_HUNK_IN_MEMORY;

    ngx_test_null(p->headers_in,
                  ngx_palloc(r->pool, sizeof(ngx_http_proxy_headers_in_t)),
                  ngx_http_proxy_error(r, p, NGX_HTTP_INTERNAL_SERVER_ERROR));

    ngx_init_array(p->hunks, r->pool,
                   /* STUB */ 10 /**/,
                   sizeof(ngx_hunk_t *),
                   ngx_http_proxy_error(r, p, NGX_HTTP_INTERNAL_SERVER_ERROR));

    ngx_test_null(ph, ngx_push_array(&p->hunks), NGX_ERROR);
    *ph = p->header_in;

    p->state_handler = ngx_http_proxy_process_status_line;

    return ngx_http_proxy_read_response_header(ev);
}


static int ngx_http_proxy_read_response_header(ngx_event_t *ev)
{
    int                         n;
    ngx_hunk_t                **ph;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_http_proxy_ctx_t       *p;
    ngx_http_proxy_loc_conf_t  *lcf;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *)
                         ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ev->timedout) {
        return ngx_http_proxy_error(r, p, NGX_HTTP_GATEWAY_TIME_OUT);
    }

    lcf = (ngx_http_proxy_loc_conf_t *)
                        ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);


#if 0

    do {
        n = ngx_event_recv(c, p->header_in->last,
                           p->header_in->end - p->header_in->last;

        if (n == NGX_AGAIN) {
            if (ev->timer_set) {
                ngx_del_timer(ev);
            } else {
                ev->timer_set = 1;
            }

            ngx_add_timer(ev, lcf->timeout);
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            ngx_http_proxy_close_request(r, p);
            return ngx_http_error(r, NGX_HTTP_BAD_GATEWAY);
        }

        ngx_log_debug(c->log, "http proxy read %d" _ n);

        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client has prematurely closed connection");
            ngx_http_proxy_close_request(r, p);
        }

        p->header_in->last += n;

        if (lcf->large_header && p->header_in->end == p->header_in->last) {
            again = 1;
        } else {
            again = 0;
        }




#if (HAVE_AIO_EVENT) /* aio, iocp */

        if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {
            again = 1;
        }

#endif

    } while (rc == NGX_AGAIN && again);

#endif

    n = ngx_event_recv(c, p->header_in->last,
                       p->header_in->end - p->header_in->last);

    ngx_log_debug(c->log, "READ:%d" _ n);

    p->header_in->last += n;

    /* STUB */
    *p->header_in->last = '\0';
    ngx_log_debug(c->log, "PROXY:\n'%s'" _ p->header_in->pos);
    /**/

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

    /* state_handlers are called in following order:
        ngx_http_proxy_process_status_line(r, p)
        ngx_http_proxy_process_reponse_header(r, p) */

#if 0
    do {
        rc = (p->state_handler)(r, p);

        if (rc == NGX_ERROR) {
            return rc;
        }

        /* rc == NGX_OK || rc == NGX_AGAIN */

    } while (p->header_in->pos.mem < p->header_in->last.mem);
#endif

    ev->event_handler = ngx_http_proxy_read_response_body;
    if (p->header_in->end - p->header_in->last == 0) {
        return ngx_http_proxy_read_response_body(ev);
    }

    return NGX_WAITING;
}


static int ngx_http_proxy_process_status_line(ngx_http_request_t *r,
                                              ngx_http_proxy_ctx_t *p)
{
    int  rc;

    rc = ngx_read_http_proxy_status_line(p);

    if (rc == NGX_HTTP_PROXY_PARSE_NO_HEADER) {
        p->status = 200;
    }

    if (rc == NGX_OK) {
        /* STUB */
        ngx_log_debug(r->connection->log, "STATUS: %d" _ p->status);

        p->state_handler = NULL;
    }

    if (p->header_in->last >= p->header_in->end) {
        rc = NGX_HTTP_PARSE_TOO_LONG_STATUS_LINE;

    } else if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* STUB */ return NGX_ERROR;
}


#if 0
static int ngx_http_proxy_process_response_header(ngx_http_request_t *r,
                                                  ngx_http_proxy_ctx_t *p)
{
    return NGX_OK;
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
            return NGX_WAITING;
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

    /* STUB */ return NGX_WAITING;
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


static int ngx_http_proxy_error(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p,
                                int error)
{
    ngx_event_close_connection(p->connection->read);

    return ngx_http_error(r, error);
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
                ctx->status_line = p - 3;
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
            ctx->request_end = p - 2;
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
        if (ctx->request_end == NULL) {
            ctx->request_end = p - 1;
        }

        ctx->state = sw_start;
        return NGX_OK;

    } else {
        ctx->state = state;
        return NGX_AGAIN;
    }
}
