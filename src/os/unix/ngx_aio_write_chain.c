
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>


ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in,
                                 off_t limit)
{
    int           n;
    u_char       *buf, *prev;
    off_t         send, sent;
    size_t        len;
    ssize_t       size;
    ngx_err_t     err;
    ngx_chain_t  *cl;

    send = 0;
    sent = 0;
    cl = in;

    while (cl) {

        if (cl->buf->pos == cl->buf->last) {
            cl = cl->next;
            continue;
        }

        /* we can post the single aio operation only */

        if (!c->write->ready) {
            return cl;
        }

        buf = cl->buf->pos;
        prev = buf;
        len = 0;

        /* coalesce the neighbouring bufs */

        while (cl && prev == cl->buf->pos && send < limit) {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = limit - send;
            }

            len += size;
            prev = cl->buf->pos + size;
            send += size;
            cl = cl->next;
        }

        n = ngx_aio_write(c, buf, len);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "aio_write: %d", n);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n > 0) {
            sent += n;
            c->sent += n;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "aio_write sent: " OFF_T_FMT, c->sent);

        for (cl = in; cl; cl = cl->next) {

            if (sent >= cl->buf->last - cl->buf->pos) {
                sent -= cl->buf->last - cl->buf->pos;
                cl->buf->pos = cl->buf->last;

                continue;
            }

            cl->buf->pos += sent;

            break;
        }
    }

    return cl;
}
