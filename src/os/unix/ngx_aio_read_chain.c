
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ssize_t ngx_aio_read_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    int           n;
    u_char       *buf, *prev;
    size_t        size;
    ssize_t       total;
    ngx_err_t     err;

    if (c->read->pending_eof) {
        c->read->ready = 0;
        return 0;
    }

    total = 0;

    while (cl) {

        /* we can post the single aio operation only */

        if (!c->read->ready) {
            return total ? total : NGX_AGAIN;
        }

        buf = cl->buf->last;
        prev = cl->buf->last;
        size = 0;

        /* coalesce the neighbouring bufs */

        while (cl && prev == cl->buf->last) {
            size += cl->buf->end - cl->buf->last;
            prev = cl->buf->end;
            cl = cl->next;
        }

        n = ngx_aio_read(c, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "aio_read: %d", n);

        if (n == NGX_AGAIN) {
            return total ? total : NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n == 0) {
            c->read->pending_eof = 1;
            if (total) {
                c->read->eof = 0;
                c->read->ready = 1;
            }
            return total;
        }

        if (n > 0) {
            total += n;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "aio_read total: %d", total);
    }

    return total ? total : NGX_AGAIN;
}
