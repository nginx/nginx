
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_errno.h>
#include <ngx_log.h>
#include <ngx_connection.h>


ssize_t ngx_recv_chain(ngx_connection_t *c, ngx_chain_t *ce)
{
    ssize_t         n;
    struct iovec  *iov;
    ngx_err_t      err;
    ngx_array_t    io;

    ngx_init_array(io, c->pool, 10, sizeof(struct iovec), NGX_ERROR);

    while (ce) {
        ngx_test_null(iov, ngx_push_array(&io), NGX_ERROR);
        iov->iov_base = ce->hunk->pos;
        iov->iov_len = ce->hunk->last - ce->hunk->pos;
        ce = ce->next;
    }

    n = readv(c->fd, (struct iovec *) io.elts, io.nelts);

    ngx_destroy_array(&io);

    if (n == -1) {
        c->read->ready = 0;

        if (err == NGX_EAGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, err, "readv() returned EAGAIN");
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, err, "readv() failed");
        return NGX_ERROR;
    }

    return n;
}
