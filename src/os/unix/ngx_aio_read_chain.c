
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ssize_t ngx_aio_read_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    int           n;
    char         *buf, *prev;
    size_t        size, total;
    ngx_err_t     err;

    total = 0;

    while (cl) {

        /* we can post the single aio operation only */

        if (c->read->active) {
            return total ? total : NGX_AGAIN;
        }

        buf = cl->hunk->pos;
        prev = buf;
        size = 0;

        /* coalesce the neighbouring hunks */

        while (cl && prev == cl->hunk->pos) {
            size += cl->hunk->last - cl->hunk->pos;
            prev = cl->hunk->last;
            cl = cl->next;
        }

        n = ngx_aio_read(c, buf, size);

        ngx_log_debug(c->log, "aio_read: %d" _ n);

        if (n == NGX_AGAIN) {
            return total ? total : NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n > 0) {
            total += n;
        }

        ngx_log_debug(c->log, "aio_read total: %d" _ total);
    }

    return total ? total : NGX_AGAIN;
}
