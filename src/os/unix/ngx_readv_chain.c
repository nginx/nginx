
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static int ngx_readv_error(ngx_event_t *rev, ngx_err_t err);

#if (HAVE_KQUEUE)

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    char          *prev;
    ssize_t        n, size;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;
    ngx_event_t   *rev;

    rev = c->read; 

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug(c->log, "recv: eof:%d, avail:%d, err:%d" _
                      rev->kq_eof _ rev->available _ rev->kq_errno);

        if (rev->available == 0) {
            if (rev->kq_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);
                    return ngx_readv_error(rev, rev->kq_errno);
                }

                return 0;

            } else {
                return NGX_AGAIN;
            }
        }
    }

    prev = NULL;
    iov = NULL;
    size = 0;

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_ERROR);

    /* coalesce the neighbouring hunks */

    while (chain) {
        if (prev == chain->hunk->last) {
            iov->iov_len += chain->hunk->end - chain->hunk->last;

        } else {
            ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
            iov->iov_base = chain->hunk->last;
            iov->iov_len = chain->hunk->end - chain->hunk->last;
        }

        size += chain->hunk->end - chain->hunk->last;
        prev = chain->hunk->end;
        chain = chain->next;
    }

ngx_log_debug(c->log, "recv: %d:%d" _ io.nelts _ iov->iov_len);

    rev = c->read;

    do {
        n = readv(c->fd, (struct iovec *) io.elts, io.nelts);

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

            if (n < size) {
                rev->ready = 0;
            }

            if (n == 0) {
                rev->eof = 1;
            }

            return n;
        }

        n = ngx_readv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

    /* NGX_ERROR || NGX_AGAIN */

    rev->ready = 0;

    if (n == NGX_ERROR){
        c->read->error = 1;
    }

    return n;
}

#else /* ! NAVE_KQUEUE */

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    char          *prev;
    ssize_t        n, size;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;
    ngx_event_t   *rev;

    prev = NULL;
    iov = NULL;
    size = 0;

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_ERROR);

    /* coalesce the neighbouring hunks */

    while (chain) {
        if (prev == chain->hunk->last) {
            iov->iov_len += chain->hunk->end - chain->hunk->last;

        } else {
            ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
            iov->iov_base = chain->hunk->last;
            iov->iov_len = chain->hunk->end - chain->hunk->last;
        }

        size += chain->hunk->end - chain->hunk->last;
        prev = chain->hunk->end;
        chain = chain->next;
    }

ngx_log_debug(c->log, "recv: %d:%d" _ io.nelts _ iov->iov_len);

    rev = c->read;

    do {
        n = readv(c->fd, (struct iovec *) io.elts, io.nelts);

        if (n >= 0) {
            if (n < size) {
                rev->ready = 0;
            }

            if (n == 0) {
                rev->eof = 1;
            }

            return n;
        }

        n = ngx_readv_error(rev, ngx_socket_errno);

    } while (n == NGX_EINTR);

    /* NGX_ERROR || NGX_AGAIN */

    rev->ready = 0;

    if (n == NGX_ERROR){
        c->read->error = 1;
    }

    return n;
}

#endif /* NAVE_KQUEUE */


static int ngx_readv_error(ngx_event_t *rev, ngx_err_t err)
{
    if (err == NGX_EAGAIN) {
        ngx_log_error(NGX_LOG_INFO, rev->log, err, "readv() returned EAGAIN");
        return NGX_AGAIN;
    }

    if (err == NGX_EINTR) {
        ngx_log_error(NGX_LOG_INFO, rev->log, err, "readv() returned EINTR");
        return NGX_EINTR;
    }

    ngx_log_error(NGX_LOG_ERR, rev->log, err, "readv() failed");

    return NGX_ERROR;
}
