
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_event_write.h>
#include <ngx_http.h>
#include <ngx_http_event_proxy_handler.h>

ngx_http_module_t  ngx_http_proxy_module;


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_request_t *r);
static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text);
static int ngx_http_proxy_send_request(ngx_event_t *ev);
static int ngx_http_proxy_read_response_header(ngx_event_t *ev);


static char conn_close[] = "Connection: close" CRLF;


int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    struct sockaddr_in     addr;
    ngx_chain_t           *chain;
    ngx_http_proxy_ctx_t  *p;

    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL)
        ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                            sizeof(ngx_http_proxy_ctx_t));

    chain = ngx_http_proxy_create_request(r);
    if (chain == NULL)
        return NGX_ERROR;

    p->out = chain;

    ngx_memzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);

    ngx_http_proxy_connect(r, &addr, "connecting to 127.0.0.1:9000");
}


static ngx_chain_t *ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    int     i;
    size_t  len;
    ngx_hunk_t       *hunk;
    ngx_chain_t      *chain;
    ngx_table_elt_t  *header;

    /* "+ 4" is for "\r\n" after request line and at the header end */
    len = r->request_line.len + 4;

    /* "Connection: close\r\n" */
    len += sizeof(conn_close) - 1;

    header = (ngx_table_elt_t *) r->headers_in.headers->elts;
    for (i = 0; i < r->headers_in.headers->nelts; i++) {
        if (&header[i] == r->headers_in.host)
            continue;

        /* "+ 4" is for ": " and "\r\n" */
        len += header[i].key.len + header[i].value.len + 4;
    }

    /* STUB */ len++;

    ngx_test_null(hunk, ngx_create_temp_hunk(r->pool, len, 0, 0), NULL);
    ngx_add_hunk_to_chain(chain, hunk, r->pool, NULL);

    ngx_memcpy(hunk->last.mem, r->request_line.data, r->request_line.len);
    hunk->last.mem += r->request_line.len;
    *(hunk->last.mem++) = CR; *(hunk->last.mem++) = LF;

    ngx_memcpy(hunk->last.mem, conn_close, sizeof(conn_close) - 1);
    hunk->last.mem += sizeof(conn_close) - 1;

    for (i = 0; i < r->headers_in.headers->nelts; i++) {
        if (&header[i] == r->headers_in.host)
            continue;

        if (&header[i] == r->headers_in.connection)
            continue;

        ngx_memcpy(hunk->last.mem, header[i].key.data, header[i].key.len);
        hunk->last.mem += header[i].key.len;

        *(hunk->last.mem++) = ':'; *(hunk->last.mem++) = ' ';

        ngx_memcpy(hunk->last.mem, header[i].value.data, header[i].value.len);
        hunk->last.mem += header[i].value.len;

        *(hunk->last.mem++) = CR; *(hunk->last.mem++) = LF;

        ngx_log_debug(r->connection->log, "proxy: '%s: %s'" _
                  header[i].key.data _ header[i].value.data);
    }

    /* add "\r\n" at the header end */
    *(hunk->last.mem++) = CR; *(hunk->last.mem++) = LF;

    /* STUB */ *(hunk->last.mem++) = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ hunk->pos.mem);

    return chain;
}


static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text)
{
    int                  rc;
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
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

#if 0
    if (rcvbuf) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &rcvbuf, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");

            if (ngx_close_socket(s) == -1)
                ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");

            return NGX_ERROR;
        }
    }
#endif

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        if (ngx_close_socket(s) == -1)
            ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");

        return NGX_ERROR;
    }

    rc = connect(s, (struct sockaddr *) addr, sizeof(struct sockaddr_in));

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, err, "connect() failed");

            if (ngx_close_socket(s) == -1)
                ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");

            return NGX_ERROR;
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
    pc->server = c->server;
    pc->servers = c->servers;

    pc->log = rev->log = wev->log = c->log;

    ngx_test_null(pc->pool,
                  ngx_create_pool(/* STUB */ 1024 /* */, pc->log),
                  NGX_ERROR);

    wev->event_handler = ngx_http_proxy_send_request;
    rev->event_handler = ngx_http_proxy_read_response_header;

#if (HAVE_CLEAR_EVENT)
    if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK)
#else
    if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK)
#endif
        return NGX_ERROR;

    if (rc == -1)
        return ngx_add_event(wev, NGX_WRITE_EVENT, NGX_ONESHOT_EVENT);

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
    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    chain = ngx_event_write(c, p->out, 0);
    if (chain == (ngx_chain_t *) -1)
        return NGX_ERROR;

    p->out = chain;

    return NGX_AGAIN;
}


static int ngx_http_proxy_read_response_header(ngx_event_t *ev)
{
    int  n;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    if (ev->timedout)
        return NGX_ERROR;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    if (p->header_in == NULL) {
        ngx_test_null(p->header_in,
                      ngx_palloc(r->pool, sizeof(ngx_http_proxy_header_in_t)),
                      NGX_ERROR);

        ngx_test_null(p->hunk,
                      ngx_create_temp_hunk(r->pool,
                                           /* STUB */ 1024 /* */, 0, 0),
                      NGX_ERROR);
    }

    n = ngx_event_recv(c, p->hunk->last.mem, p->hunk->end - p->hunk->last.mem);

    ngx_log_debug(r->connection->log, "READ:%d" _ n);

    p->hunk->last.mem += n;

    *p->hunk->last.mem = '\0';
    ngx_log_debug(r->connection->log, "PROXY:\n'%s'" _ p->hunk->pos.mem);

    /* STUB */ return NGX_ERROR;
}

#if 0
static int ngx_http_proxy_read_response_body(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    if (ev->timedout)
        return NGX_ERROR;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

}

static int ngx_http_proxy_write_to_client(ngx_event_t *ev)
{
    /* если бэкенд быстрее, то CLEAR, иначе - ONESHOT */

    rc = ngx_http_output_filter(r, h);
}

#endif
