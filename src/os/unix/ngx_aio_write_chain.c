
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int           n;
    char         *buf, *prev;
    off_t         sent;
    size_t        size;
    ngx_err_t     err;
    ngx_chain_t  *cl;

    sent = 0;
    cl = in;

    while (cl) {

        if (cl->hunk->last - cl->hunk->pos == 0) {
            cl = cl->next;
            continue;
        }

        /* we can post the single aio operation only */

        if (!c->write->ready) {
            return cl;
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

        n = ngx_aio_write(c, buf, size);

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "aio_write: %d" _ n);
#endif

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n > 0) {
            sent += n;
            c->sent += n;
        }

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "aio_write sent: " OFF_T_FMT _ c->sent);
#endif

        for (cl = in; cl; cl = cl->next) {

            if (sent >= cl->hunk->last - cl->hunk->pos) {
                sent -= cl->hunk->last - cl->hunk->pos;
                cl->hunk->pos = cl->hunk->last;

                continue;
            }

            cl->hunk->pos += sent;

            break;
        }
    }

    return cl;
}
