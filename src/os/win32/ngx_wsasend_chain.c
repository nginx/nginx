
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit)
{
    int           rc;
    u_char       *prev;
    size_t        size;
    u_long        sent;
    LPWSABUF      wsabuf;
    ngx_err_t     err;
    ngx_event_t  *wev;
    ngx_array_t   wsabufs;
    ngx_chain_t  *cl;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    /*
     * WSABUFs must be 4-byte aligned otherwise
     * WSASend() will return undocumented WSAEINVAL error.
     */

    ngx_init_array(wsabufs, c->pool, 10, sizeof(WSABUF), NGX_CHAIN_ERROR);

    prev = NULL;
    wsabuf = NULL;

    /* create the WSABUF and coalesce the neighbouring bufs */

    for (cl = in; cl; cl = cl->next) {

        if (prev == cl->buf->pos) {
            wsabuf->len += cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;

        } else {
            ngx_test_null(wsabuf, ngx_push_array(&wsabufs), NGX_CHAIN_ERROR);
            wsabuf->buf = (char *) cl->buf->pos;
            wsabuf->len = cl->buf->last - cl->buf->pos;
            prev = cl->buf->last;
        }
    }

    rc = WSASend(c->fd, wsabufs.elts, wsabufs.nelts, &sent, 0, NULL, NULL);

    if (rc == -1) {
        err = ngx_errno;

        if (err == WSAEWOULDBLOCK) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "WSASend() not ready");
            wev->ready = 0;
            return in;

        } else {
            wev->error = 1;
            ngx_connection_error(c, err, "WSASend() failed");
            return NGX_CHAIN_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "WSASend: %d", sent);

    c->sent += sent;

    for (cl = in; cl && sent > 0; cl = cl->next) {

        size = cl->buf->last - cl->buf->pos;

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(cl->buf)) {
                cl->buf->pos = cl->buf->last;
            }

            continue;
        }

        if (ngx_buf_in_memory(cl->buf)) {
            cl->buf->pos += sent;
        }

        break;
    }

    if (cl) {
        wev->ready = 0;
    }

    return cl;
}


ngx_chain_t *ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
                                          off_t limit)
{
    int               rc;
    u_char           *prev;
    size_t            size;
    u_long            sent;
    LPWSABUF          wsabuf;
    ngx_err_t         err;
    ngx_event_t      *wev;
    ngx_array_t       wsabufs;
    ngx_chain_t      *cl;
    LPWSAOVERLAPPED   ovlp;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    if (!wev->complete) {

        /* post the overlapped WSASend() */
 
        /*
         * WSABUFs must be 4-byte aligned otherwise
         * WSASend() will return undocumented WSAEINVAL error.
         */

        ngx_init_array(wsabufs, c->pool, 10, sizeof(WSABUF), NGX_CHAIN_ERROR);

        prev = NULL;
        wsabuf = NULL;
 
        /* create the WSABUF and coalesce the neighbouring bufs */

        for (cl = in; cl; cl = cl->next) {

            if (prev == cl->buf->pos) {
                wsabuf->len += cl->buf->last - cl->buf->pos;
                prev = cl->buf->last;
 
            } else {
                ngx_test_null(wsabuf, ngx_push_array(&wsabufs),
                              NGX_CHAIN_ERROR);
                wsabuf->buf = (char *) cl->buf->pos;
                wsabuf->len = cl->buf->last - cl->buf->pos;
                prev = cl->buf->last;
            }
        }

        ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
        ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
 
        rc = WSASend(c->fd, wsabufs.elts, wsabufs.nelts, &sent, 0, ovlp, NULL);

        wev->complete = 0;

        if (rc == -1) {
            err = ngx_errno;

            if (err == WSA_IO_PENDING) {
                wev->active = 1;
                return in;

            } else {
                wev->error = 1;
                ngx_connection_error(c, err, "WSASend() failed");
                return NGX_CHAIN_ERROR;
            }
 
        } else if (ngx_event_flags & NGX_USE_IOCP_EVENT) {

             /*
              * if a socket was bound with I/O completion port then
              * GetQueuedCompletionStatus() would anyway return its status
              * despite that WSASend() was already complete
              */

            wev->active = 1;
            return in;
        }

    } else {

        /* the overlapped WSASend() complete */

        wev->complete = 0;
        wev->active = 0;

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            if (wev->ovlp.error) {
                ngx_connection_error(c, wev->ovlp.error, "WSASend() failed");
                return NGX_CHAIN_ERROR;
            }

            sent = wev->available;

        } else {
            if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &wev->ovlp,
                                       &sent, 0, NULL) == 0) {
                ngx_connection_error(c, ngx_socket_errno,
                               "WSASend() or WSAGetOverlappedResult() failed");
    
                return NGX_CHAIN_ERROR;
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "WSASend: %d", sent);

    c->sent += sent;

    for (cl = in; cl && sent > 0; cl = cl->next) {

        size = cl->buf->last - cl->buf->pos;

        if (sent >= size) {
            sent -= size;

            if (ngx_buf_in_memory(cl->buf)) {
                cl->buf->pos = cl->buf->last;
            }

            continue;
        }

        if (ngx_buf_in_memory(cl->buf)) {
            cl->buf->pos += sent;
        }

        break;
    }

    if (cl) {
        wev->ready = 0;

    } else {
        wev->ready = 1;
    }

    return cl;
}
