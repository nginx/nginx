
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    char            *prev;
    ssize_t          n, size;
    off_t            sent;
    struct iovec    *iov;
    ngx_err_t        err;
    ngx_array_t      iovecs;
    ngx_chain_t     *ce;

    if (!c->write->ready) {
        return in;
    }

    ngx_init_array(iovecs, c->pool, 10, sizeof(struct iovec), NGX_CHAIN_ERROR);

    prev = NULL;
    iov = NULL;

    /* create the iovec and coalesce the neighbouring chain entries */
    for (ce = in; ce; ce = ce->next) {

        if (prev == ce->hunk->pos) {
            iov->iov_len += ce->hunk->last - ce->hunk->pos;
            prev = ce->hunk->last;

        } else {
            ngx_test_null(iov, ngx_push_array(&iovecs), NGX_CHAIN_ERROR);
            iov->iov_base = ce->hunk->pos;
            iov->iov_len = ce->hunk->last - ce->hunk->pos;
            prev = ce->hunk->last;
        }
    }

    n = writev(c->fd, iovecs.elts, iovecs.nelts);

    if (n == -1) {
        err = ngx_errno;
        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EAGAIN");

        } else if (err == NGX_EINTR) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EINTR");

        } else {
            ngx_log_error(NGX_LOG_CRIT, c->log, err, "writev() failed");
            return NGX_CHAIN_ERROR;
        }
    }

    sent = n > 0 ? n : 0;

#if (NGX_DEBUG_WRITE_CHAIN)
    ngx_log_debug(c->log, "writev: %qd" _ sent);
#endif

    c->sent += sent;

    for (ce = in; ce && sent > 0; ce = ce->next) {

        size = ce->hunk->last - ce->hunk->pos;

ngx_log_debug(c->log, "SIZE: %d" _ size);

        if (sent >= size) {
            sent -= size;

            if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
                ce->hunk->pos = ce->hunk->last;
            }

#if 0
            if (ce->hunk->type & NGX_HUNK_FILE) {
                ce->hunk->file_pos = ce->hunk->file_last;
            }
#endif

            continue;
        }

        if (ce->hunk->type & NGX_HUNK_IN_MEMORY) {
            ce->hunk->pos += sent;
        }

#if 0
        if (ce->hunk->type & NGX_HUNK_FILE) {
            ce->hunk->file_pos += sent;
        }
#endif

        break;
    }

    ngx_destroy_array(&iovecs);

    return ce;
}
