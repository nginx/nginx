
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    int           rc;
    char         *prev;
    u_int         flags;
    size_t        bytes, size;
    WSABUF       *wsabuf;
    ngx_err_t     err;
    ngx_array_t   io;
    ngx_event_t  *rev;

    prev = NULL;
    wsabuf = NULL;
    flags = 0;
    size = 0;
    bytes = 0;

    ngx_init_array(io, c->pool, 10, sizeof(WSABUF), NGX_ERROR);

    /* coalesce the neighbouring hunks */

    while (chain) {
        if (prev == chain->hunk->last) {
            wsabuf->len += chain->hunk->end - chain->hunk->last;

        } else {
            ngx_test_null(wsabuf, ngx_push_array(&io), NGX_ERROR);
            wsabuf->buf = chain->hunk->last;
            wsabuf->len = chain->hunk->end - chain->hunk->last;
        }

        size += chain->hunk->end - chain->hunk->last;
        prev = chain->hunk->end;
        chain = chain->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecv: %d:%d", io.nelts, wsabuf->len);


    rc = WSARecv(c->fd, io.elts, io.nelts, &bytes, &flags, NULL, NULL);

    rev = c->read;

    if (rc == -1) {
        rev->ready = 0;
        err = ngx_socket_errno;

        if (err == WSAEWOULDBLOCK) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "WSARecv() not ready");
            return NGX_AGAIN;
        }

        rev->error = 1;
        ngx_connection_error(c, err, "WSARecv() failed");
        return NGX_ERROR;
    }

    if (bytes < size) {
        rev->ready = 0;
    }

    if (bytes == 0) {
        rev->eof = 1;
    }

    return bytes;
}
