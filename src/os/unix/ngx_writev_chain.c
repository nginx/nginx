
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    u_char          *prev;
    ssize_t          n, size;
    off_t            sent;
    struct iovec    *iov;
    ngx_int_t        eintr;
    ngx_err_t        err;
    ngx_array_t      io;
    ngx_chain_t     *cl;
    ngx_event_t     *wev;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) && wev->kq_eof) {
        ngx_log_error(NGX_LOG_INFO, c->log, wev->kq_errno,
                      "kevent() reported about an closed connection");

        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_CHAIN_ERROR);

    do {
        prev = NULL;
        iov = NULL;
        eintr = 0;

        /* create the iovec and coalesce the neighbouring bufs */

        for (cl = in; cl; cl = cl->next) {

            if (prev == cl->buf->pos) {
                iov->iov_len += cl->buf->last - cl->buf->pos;
                prev = cl->buf->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&io), NGX_CHAIN_ERROR);
                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = cl->buf->last - cl->buf->pos;
                prev = cl->buf->last;
            }
        }

        n = writev(c->fd, io.elts, io.nelts);

        if (n == -1) {
            err = ngx_errno;

            if (err == NGX_EAGAIN || err == NGX_EINTR) {
                if (err == NGX_EINTR) {
                    eintr = 1;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "writev() not ready");

            } else {
                wev->error = 1;
                ngx_connection_error(c, err, "writev() failed");
                return NGX_CHAIN_ERROR;
            }
        }

        sent = n > 0 ? n : 0;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "writev: " OFF_T_FMT, sent);

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

    } while (eintr);

    if (cl) {
        wev->ready = 0;
    }

    return cl;
}
