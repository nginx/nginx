
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain)
{
    char          *prev;
    ssize_t        n;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;

    prev = NULL;
    iov = NULL;

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

        prev = chain->hunk->end;
        chain = chain->next;
    }

ngx_log_debug(c->log, "recv: %d:%d" _ io.nelts _ iov->iov_len);

    n = readv(c->fd, (struct iovec *) io.elts, io.nelts);

    if (n == 0) {
        c->read->eof = 1;

    } else if (n == -1) {
        c->read->ready = 0;
        c->read->error = 1;

        err = ngx_errno;
        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "readv() returned EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "readv() failed");
        return NGX_ERROR;
    }

    return n;
}
