
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_file.h>
#include <ngx_hunk.h>
#include <ngx_http.h>
#include <ngx_http_event_proxy_handler.h>

ngx_http_module_t  ngx_http_proxy_module;


static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text);
static int ngx_http_proxy_send_request(ngx_event_t *ev);


int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    struct sockaddr_in addr;
    ngx_http_proxy_ctx_t  *p;

    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    if (p == NULL)
        ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                            sizeof(ngx_http_proxy_ctx_t));

    ngx_memzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);

    ngx_http_proxy_connect(r, &addr, "connecting to 127.0.0.1:9000");
}

static int ngx_http_proxy_connect(ngx_http_request_t *r,
                                  struct sockaddr_in *addr,
                                  char *addr_text)
{
    int                  rc;
    ngx_err_t            err;
    ngx_socket_t         s;
    ngx_event_t         *ev;
    ngx_connection_t    *c;
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

    ngx_memzero(&ngx_read_events[s], sizeof(ngx_event_t));
    ngx_memzero(&ngx_write_events[s], sizeof(ngx_event_t));
    ngx_memzero(&ngx_connections[s], sizeof(ngx_connection_t));

    ngx_read_events[s].data = ngx_write_events[s].data = &ngx_connections[s];
    ngx_connections[s].read = &ngx_read_events[s];
    ngx_connections[s].write = &ngx_write_events[s];

    ngx_connections[s].fd = s;
    ngx_connections[s].server = c->server;
    ngx_connections[s].servers = c->servers;

    ngx_connections[s].log =
        ngx_read_events[s].log = ngx_write_events[s].log = c->log;

    if (rc == -1) {
        ngx_write_events[s].event_handler = ngx_http_proxy_send_request;

        return ngx_add_event(&ngx_write_events[s],
                             NGX_WRITE_EVENT, NGX_ONESHOT_EVENT);
    }

    ngx_write_events[s].write = 1;
    ngx_write_events[s].ready = 1;

    return ngx_http_proxy_send_request(ev);
}

static int ngx_http_proxy_send_request(ngx_event_t *ev)
{
    return NGX_ERROR;
}

#if 0

static int ngx_http_proxy_send_request(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    n = ngx_send(p->fd, p->header_out->pos.mem,
                 p->header_out->end.mem - p->header_out->pos.mem);

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->log, ngx_socket_errno,
                      ngx_send_n " %s falied", p->addr_text);
        return NGX_ERROR;
    }

    p->header_out->pos.mem += n;

    if (p->header_out->end.mem - p->header_out->pos.mem > 0)
        return NGX_AGAIN;

    /* TODO: body */

    return NGX_OK;
}

static int ngx_http_proxy_read_response_header(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    if (ev->timedout)
        return NGX_ERROR;

    c = (ngx_connection_t *) ev->data;
    r = (ngx_http_request_t *) c->data;
    p = (ngx_http_proxy_ctx_t *) ngx_get_module_ctx(r, ngx_http_proxy_module);

    n = ngx_event_recv(c, p->header_in->last.mem,
                       p->header_in->end - p->header_in->last.mem);

}

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
