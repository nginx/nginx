
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    char            *prev;
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

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_CHAIN_ERROR);

    do {
        prev = NULL;
        iov = NULL;
        eintr = 0;

        /* create the iovec and coalesce the neighbouring hunks */

        for (cl = in; cl; cl = cl->next) {

            if (prev == cl->hunk->pos) {
                iov->iov_len += cl->hunk->last - cl->hunk->pos;
                prev = cl->hunk->last;

            } else {
                ngx_test_null(iov, ngx_push_array(&io), NGX_CHAIN_ERROR);
                iov->iov_base = cl->hunk->pos;
                iov->iov_len = cl->hunk->last - cl->hunk->pos;
                prev = cl->hunk->last;
            }
        }

        n = writev(c->fd, io.elts, io.nelts);

        if (n == -1) {
            err = ngx_errno;
            if (err == NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EAGAIN");

            } else if (err == NGX_EINTR) {
                eintr = 1;
                ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EINTR");

            } else {
                wev->error = 1;
                ngx_log_error(NGX_LOG_CRIT, c->log, err, "writev() failed");
                return NGX_CHAIN_ERROR;
            }
        }

        sent = n > 0 ? n : 0;

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "writev: " OFF_T_FMT  _ sent);
#endif

        c->sent += sent;

        for (cl = in; cl && sent > 0; cl = cl->next) {

            size = cl->hunk->last - cl->hunk->pos;

ngx_log_debug(c->log, "SIZE: %d" _ size);

            if (sent >= size) {
                sent -= size;

                if (cl->hunk->type & NGX_HUNK_IN_MEMORY) {
                    cl->hunk->pos = cl->hunk->last;
                }

                continue;
            }

            if (cl->hunk->type & NGX_HUNK_IN_MEMORY) {
                cl->hunk->pos += sent;
            }

            break;
        }

    } while (eintr);

    if (cl) {
        wev->ready = 0;
    }

    return cl;
}
