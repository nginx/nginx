
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t ngx_wsarecv(ngx_connection_t *c, char *buf, size_t size)
{
    int               rc;
    u_int             flags;
    size_t            bytes;
    WSABUF            wsabuf[1];
    ngx_err_t         err;
    ngx_event_t      *rev;
    LPWSAOVERLAPPED   ovlp;

    rev = c->read;
    bytes = 0;

    if ((ngx_event_flags & NGX_HAVE_AIO_EVENT) && rev->ready) {
        rev->ready = 0;

        /* the overlapped WSARecv() completed */

        if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
            if (rev->ovlp.error) {
                ngx_log_error(NGX_LOG_ERR, c->log, rev->ovlp.error,
                              "WSARecv() failed");
                return NGX_ERROR;
            }

            return rev->available;
        }

        if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &rev->ovlp,
                                   &bytes, 0, NULL) == 0) {
            err = ngx_socket_errno;
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                         "WSARecv() or WSAGetOverlappedResult() failed");

            return NGX_ERROR;
        }

        return bytes;
    }

    if (ngx_event_flags & NGX_HAVE_AIO_EVENT) {
        ovlp = (LPWSAOVERLAPPED) &c->read->ovlp;
        ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));

    } else {
        ovlp = NULL;
    }

    wsabuf[0].buf = buf;
    wsabuf[0].len = size;
    flags = 0;

    rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);

    ngx_log_debug(c->log, "WSARecv: %d:%d" _ rc _ bytes);

    if (rc == -1) {
        err = ngx_socket_errno;
        if (err == WSA_IO_PENDING) {
            return NGX_AGAIN;

        } else if (err == WSAEWOULDBLOCK) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "WSARecv() EAGAIN");
            return NGX_AGAIN;

        } else {
            ngx_log_error(NGX_LOG_CRIT, c->log, err, "WSARecv() failed");
            return NGX_ERROR;
        }
    }

    if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {

        /*
         * If a socket was bound with I/O completion port
         * then GetQueuedCompletionStatus() would anyway return its status
         * despite that WSARecv() was already completed.
         */

        return NGX_AGAIN;
    }

    return bytes;
}
