
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t ngx_wsarecv(ngx_connection_t *c, char *buf, size_t size)
{
    int           rc;
    u_int         flags;
    size_t        bytes;
    ngx_err_t     err;
    WSABUF        wsabuf[1];
    ngx_event_t  *ev;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE  handler;

    ev = c->read;

/* DEBUG */ bytes = 0;

    if (ev->timedout) {
        ngx_set_socket_errno(NGX_ETIMEDOUT);
        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "WSARecv() timed out");

        return NGX_ERROR;
    }

    if (ev->ready) {
        ev->ready = 0;

#if (HAVE_IOCP_EVENT) /* iocp */

        if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
            if (ev->ovlp.error) {
                ngx_log_error(NGX_LOG_ERR, c->log, ev->ovlp.error,
                              "WSARecv() failed");
                return NGX_ERROR;
            }

            return ev->available;
        }

#endif

        if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &ev->ovlp,
                                   &bytes, 0, NULL) == 0) {
            err = ngx_socket_errno;
            ngx_log_error(NGX_LOG_CRIT, ev->log, err,
                         "WSARecv() or WSAGetOverlappedResult() failed");

            return NGX_ERROR;
        }

        return bytes;
    }

    ngx_memzero(&ev->ovlp, sizeof(WSAOVERLAPPED));
    wsabuf[0].buf = buf;
    wsabuf[0].len = size;
    flags = 0;

#if 0
    handler = ev->handler;
#else
    handler = NULL;
#endif

    rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags,
                 (LPWSAOVERLAPPED) &ev->ovlp, handler);

    ngx_log_debug(ev->log, "WSARecv: %d:%d" _ rc _ bytes);

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err == WSA_IO_PENDING) {
            return NGX_AGAIN;

        } else {
            ngx_log_error(NGX_LOG_CRIT, ev->log, err, "WSARecv() failed");
            return NGX_ERROR;
        }
    }

#if (HAVE_IOCP_EVENT) /* iocp */

    if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
        return NGX_AGAIN;
    }

#endif

    return bytes;
}
