
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (HAVE_KQUEUE)

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    u_char        *prev;
    ssize_t        n, size;
    ngx_err_t      err;
    ngx_array_t    io;
    ngx_event_t   *rev;
    struct iovec  *iov;

    rev = c->read; 

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "readv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                              "kevent() reported about an closed connection");

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);
                    return NGX_ERROR;
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

    /* coalesce the neighbouring bufs */

    while (chain) {
        if (prev == chain->buf->last) {
            iov->iov_len += chain->buf->end - chain->buf->last;

        } else {
            ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
            iov->iov_base = (void *) chain->buf->last;
            iov->iov_len = chain->buf->end - chain->buf->last;
        }

        size += chain->buf->end - chain->buf->last;
        prev = chain->buf->end;
        chain = chain->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "readv: %d, last:%d", io.nelts, iov->iov_len);

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
                    if (!rev->pending_eof) {
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

        err = ngx_socket_errno;

        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "readv() not ready");
            n = NGX_AGAIN;

        } else {
            n = ngx_connection_error(c, err, "readv() failed");
            break;
        }

    } while (err == NGX_EINTR);

    rev->ready = 0;

    if (n == NGX_ERROR){
        c->read->error = 1;
    }

    return n;
}

#else /* ! NAVE_KQUEUE */

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    u_char        *prev;
    ssize_t        n, size;
    ngx_err_t      err;
    ngx_array_t    io;
    ngx_event_t   *rev;
    struct iovec  *iov;

    prev = NULL;
    iov = NULL;
    size = 0;

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_ERROR);

    /* coalesce the neighbouring bufs */

    while (chain) {
        if (prev == chain->buf->last) {
            iov->iov_len += chain->buf->end - chain->buf->last;

        } else {
            ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
            iov->iov_base = chain->buf->last;
            iov->iov_len = chain->buf->end - chain->buf->last;
        }

        size += chain->buf->end - chain->buf->last;
        prev = chain->buf->end;
        chain = chain->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "readv: %d:%d", io.nelts, iov->iov_len);

    rev = c->read;

    do {
        n = readv(c->fd, (struct iovec *) io.elts, io.nelts);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

            return n;

        } else if (n > 0) {

            if (n < size && !(ngx_event_flags & NGX_HAVE_GREEDY_EVENT)) {
                rev->ready = 0;
            }

            return n;
        }

        err = ngx_socket_errno;

        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "readv() not ready");
            n = NGX_AGAIN;

        } else {
            n = ngx_connection_error(c, err, "readv() failed");
            break;
        }

    } while (err == NGX_EINTR);

    rev->ready = 0;

    if (n == NGX_ERROR){
        c->read->error = 1;
    }

    return n;
}

#endif /* NAVE_KQUEUE */
