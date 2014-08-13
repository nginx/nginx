
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_WSABUFS  8


ngx_chain_t *
ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int           rc;
    u_char       *prev;
    u_long        size, sent, send, prev_send;
    ngx_err_t     err;
    ngx_event_t  *wev;
    ngx_array_t   vec;
    ngx_chain_t  *cl;
    LPWSABUF      wsabuf;
    WSABUF        wsabufs[NGX_WSABUFS];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    /* the maximum limit size is the maximum u_long value - the page size */

    if (limit == 0 || limit > NGX_MAX_UINT32_VALUE - ngx_pagesize) {
        limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
    }

    send = 0;

    /*
     * WSABUFs must be 4-byte aligned otherwise
     * WSASend() will return undocumented WSAEINVAL error.
     */

    vec.elts = wsabufs;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NGX_WSABUFS;
    vec.pool = c->pool;

    for ( ;; ) {
        prev = NULL;
        wsabuf = NULL;
        prev_send = send;

        vec.nelts = 0;

        /* create the WSABUF and coalesce the neighbouring bufs */

        for (cl = in;
             cl && vec.nelts < ngx_max_wsabufs && send < limit;
             cl = cl->next)
        {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = (u_long) (limit - send);
            }

            if (prev == cl->buf->pos) {
                wsabuf->len += cl->buf->last - cl->buf->pos;

            } else {
                wsabuf = ngx_array_push(&vec);
                if (wsabuf == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                wsabuf->buf = (char *) cl->buf->pos;
                wsabuf->len = cl->buf->last - cl->buf->pos;
            }

            prev = cl->buf->last;
            send += size;
        }

        sent = 0;

        rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, NULL, NULL);

        if (rc == -1) {
            err = ngx_errno;

            if (err == WSAEWOULDBLOCK) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "WSASend() not ready");

            } else {
                wev->error = 1;
                ngx_connection_error(c, err, "WSASend() failed");
                return NGX_CHAIN_ERROR;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "WSASend: fd:%d, s:%ul", c->fd, sent);

        c->sent += sent;

        in = ngx_handle_sent_chain(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


ngx_chain_t *
ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int               rc;
    u_char           *prev;
    u_long            size, send, sent;
    ngx_err_t         err;
    ngx_event_t      *wev;
    ngx_array_t       vec;
    ngx_chain_t      *cl;
    LPWSAOVERLAPPED   ovlp;
    LPWSABUF          wsabuf;
    WSABUF            wsabufs[NGX_WSABUFS];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "wev->complete: %d", wev->complete);

    if (!wev->complete) {

        /* post the overlapped WSASend() */

        /* the maximum limit size is the maximum u_long value - the page size */

        if (limit == 0 || limit > NGX_MAX_UINT32_VALUE - ngx_pagesize) {
            limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
        }

        /*
         * WSABUFs must be 4-byte aligned otherwise
         * WSASend() will return undocumented WSAEINVAL error.
         */

        vec.elts = wsabufs;
        vec.nelts = 0;
        vec.size = sizeof(WSABUF);
        vec.nalloc = NGX_WSABUFS;
        vec.pool = c->pool;

        send = 0;
        prev = NULL;
        wsabuf = NULL;

        /* create the WSABUF and coalesce the neighbouring bufs */

        for (cl = in;
             cl && vec.nelts < ngx_max_wsabufs && send < limit;
             cl = cl->next)
        {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = (u_long) (limit - send);
            }

            if (prev == cl->buf->pos) {
                wsabuf->len += cl->buf->last - cl->buf->pos;

            } else {
                wsabuf = ngx_array_push(&vec);
                if (wsabuf == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                wsabuf->buf = (char *) cl->buf->pos;
                wsabuf->len = cl->buf->last - cl->buf->pos;
            }

            prev = cl->buf->last;
            send += size;
        }

        ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
        ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));

        rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, ovlp, NULL);

        wev->complete = 0;

        if (rc == -1) {
            err = ngx_errno;

            if (err == WSA_IO_PENDING) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "WSASend() posted");
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

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "WSASend: fd:%d, s:%ul", c->fd, sent);

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
                                       &sent, 0, NULL)
                == 0)
            {
                ngx_connection_error(c, ngx_socket_errno,
                               "WSASend() or WSAGetOverlappedResult() failed");

                return NGX_CHAIN_ERROR;
            }
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSASend ovlp: fd:%d, s:%ul", c->fd, sent);

    c->sent += sent;

    in = ngx_handle_sent_chain(in, sent);

    if (in) {
        wev->ready = 0;

    } else {
        wev->ready = 1;
    }

    return in;
}
