
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_hunk.h>
#include <ngx_connection.h>
#include <ngx_sendv.h>
#include <ngx_sendfile.h>


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

ngx_log_debug(c->log, "aio_write ce: %x" _ ce->hunk->pos.mem);

        buf = prev = ce->hunk->pos.mem;
        size = 0;

        /* coalesce the neighbouring chain entries */
        while (ce && prev == ce->hunk->pos.mem) {
            size += ce->hunk->last.mem - ce->hunk->pos.mem;
            prev = ce->hunk->last.mem;
            ce = ce->next;
        }

        rc = ngx_event_aio_write(c, buf, size);

ngx_log_debug(c->log, "aio_write rc: %d" _ rc);

        if (rc > 0) {
            sent += rc;
            c->sent += rc;

        } else if (rc == NGX_ERROR) {
            return NGX_CHAIN_ERROR;

        } else if (rc == NGX_AGAIN) {
            break;
        }
    }

#if (NGX_DEBUG_WRITE_CHAIN)
    ngx_log_debug(c->log, "aio_write sent: " OFF_FMT _ c->sent);
#endif

    for (ce = in; ce; ce = ce->next) {

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "write chain: %x %qx %qd" _
                      ce->hunk->type _
                      ce->hunk->pos.file _
                      ce->hunk->last.file - ce->hunk->pos.file);
#endif

        if (sent >= ce->hunk->last.file - ce->hunk->pos.file) {
            sent -= ce->hunk->last.file - ce->hunk->pos.file;
            ce->hunk->pos.file = ce->hunk->last.file;

#if (NGX_DEBUG_WRITE_CHAIN)
            ngx_log_debug(c->log, "write chain done: %qx %qd" _
                          ce->hunk->pos.file _ sent);
#endif
            continue;
        }

        ce->hunk->pos.file += sent;

#if (NGX_DEBUG_WRITE_CHAIN)
        ngx_log_debug(c->log, "write chain rest: %qx %qd" _
                      ce->hunk->pos.file _
                      ce->hunk->last.file - ce->hunk->pos.file);
#endif

        break;
    }

    return ce;
}
