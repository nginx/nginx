
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
        ngx_log_debug(c->log, "recv: eof:%d, avail:%d, err:%d" _
                      rev->eof _ rev->available _ rev->error);

        if (rev->available == 0) {
            if (rev->eof) {
                if (rev->error) {
                    rev->ready = 0;
                    ngx_set_socket_errno(rev->error);
                    return ngx_unix_recv_error(rev, rev->error);
                }
                return 0;

            } else {
                return NGX_AGAIN;
            }
        }
    }

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug(c->log, "recv: %d:%d" _ n _ size);

        if (n >= 0) {
            if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
                rev->available -= n;
                if (rev->available <= 0) {
                    rev->ready = 0;
                    if (rev->available < 0) {
                        rev->available = 0;
                    }
                }

                return n;
            }

            if ((size_t) n < size) {
                rev->ready = 0;
            }

            return n;
        }

        rev->ready = 0;
        n = ngx_unix_recv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

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

        ngx_log_debug(c->log, "recv: %d:%d" _ n _ size);

        if (n >= 0) {
            if ((size_t) n < size) {
                rev->ready = 0;
            }
            return n;
        }

        rev->ready = 0;
        n = ngx_unix_recv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

    return n;
}

#endif /* NAVE_KQUEUE */


static int ngx_unix_recv_error(ngx_event_t *rev, ngx_err_t err)
{
    if (err == NGX_ECONNRESET && rev->ignore_econnreset) {
        return 0;
    }

    if (err == NGX_EAGAIN) {
        ngx_log_error(NGX_LOG_INFO, rev->log, err, "recv() returned EAGAIN");
        return NGX_AGAIN;
    }

    if (err == NGX_EINTR) {
        ngx_log_error(NGX_LOG_INFO, rev->log, err, "recv() returned EINTR");
        return NGX_EINTR;
    }

    ngx_log_error(NGX_LOG_ERR, rev->log, err, "recv() failed");

    return NGX_ERROR;
}
