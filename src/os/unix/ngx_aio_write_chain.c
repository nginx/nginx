
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int              rc;
    char            *buf, *prev;
    off_t            sent;
    size_t           size;
    ngx_err_t        err;
    ngx_chain_t     *ce;

    sent = 0;
    ce = in;

    while (ce) {

        /* we can post the single aio operation only */

        if (c->write->active) {
            return ce;
        }

        buf = prev = ce->hunk->pos;
        size = 0;

        /* coalesce the neighbouring chain entries */

        while (ce && prev == ce->hunk->pos) {
            size += ce->hunk->last - ce->hunk->pos;
            prev = ce->hunk->last;
            ce = ce->next;
        }

        rc = ngx_aio_write(c, buf, size);

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "aio_write rc: %d" _ rc);
#endif

        if (rc == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (rc > 0) {
            sent += rc;
            c->sent += rc;
        }

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "aio_write sent: " OFF_FMT _ c->sent);
#endif

        for (ce = in; ce; ce = ce->next) {

            if (sent >= ce->hunk->last - ce->hunk->pos) {
                sent -= ce->hunk->last - ce->hunk->pos;
                ce->hunk->pos = ce->hunk->last;

                continue;
            }

            ce->hunk->pos += sent;

            break;
        }
    }

    return ce;
}
