
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static int ngx_unix_recv_error(ngx_event_t *rev, ngx_err_t err);


#if (HAVE_KQUEUE)

ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size)
{
    ssize_t       n;
    ngx_event_t  *rev;

    rev = c->read;

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->kq_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->kq_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);
                    ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                                  "kevent() reported about closed connection");

                    if (rev->kq_errno == NGX_ECONNRESET
                        && rev->log_error == NGX_ERROR_IGNORE_ECONNRESET)
                    {
                        return 0;
                    }

                    return NGX_ERROR;
                }

                return 0;

            } else {
                return NGX_AGAIN;
            }
        }
    }

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,"recv: %d:%d", n, size);

        if (n >= 0) {
            if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available can be negative here because some additional
                 * bytes can be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->kq_eof) {
                        rev->ready = 0;
                    }

                    if (rev->available < 0) {
                        rev->available = 0;
                    }
                }

                return n;
            }

            if ((size_t) n < size) {
                rev->ready = 0;
            }

            if (n == 0) {
                rev->eof = 1;
            }

            return n;
        }

        n = ngx_unix_recv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

    /* NGX_ERROR || NGX_AGAIN */

    rev->ready = 0;

    if (n == NGX_ERROR){
        rev->error = 1;
    }

    return n;
}

#else /* ! NAVE_KQUEUE */

ssize_t ngx_unix_recv(ngx_connection_t *c, char *buf, size_t size)
{
    ssize_t       n;
    ngx_event_t  *rev;

    rev = c->read;

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,"recv: %d:%d", n, size);

        if (n >= 0) {
            if ((size_t) n < size) {
                rev->ready = 0;
            }

            if (n == 0) {
                rev->eof = 1;
            }

            return n;
        }

        n = ngx_unix_recv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

    /* NGX_ERROR || NGX_AGAIN */

    rev->ready = 0;

    if (n == NGX_ERROR){
        rev->error = 1;
    }

    return n;
}

#endif /* NAVE_KQUEUE */


static int ngx_unix_recv_error(ngx_event_t *rev, ngx_err_t err)
{
    ngx_int_t  level;

    if (err == NGX_EAGAIN || err == NGX_EINTR) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, err, "recv() not ready");
        return NGX_AGAIN;
    }

    if (err == NGX_ECONNRESET) {

        switch (rev->log_error) {
        case NGX_ERROR_IGNORE_ECONNRESET:
            return 0;
        case NGX_ERROR_INFO:
            level = NGX_LOG_INFO;
            break;
        case NGX_ERROR_ERR:
            level = NGX_LOG_ERR;
            break;
        default:
            level = NGX_LOG_CRIT;
        }

    } else {
        level = NGX_LOG_CRIT;
    }

    ngx_log_error(level, rev->log, err, "recv() failed");

    return NGX_ERROR;
}
