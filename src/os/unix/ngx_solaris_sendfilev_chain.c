
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_SENDFILEVECS   16


ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in,
                                         off_t limit)
{
    int             fd;
    u_char         *prev;
    off_t           fprev, sprev, send, aligned;
    ssize_t         size, sent, n;
    ngx_int_t       eintr, complete;
    ngx_err_t       err;
    sendfilevec_t  *sfv, sfvs[NGX_SENDFILEVECS];
    ngx_array_t     vec;
    ngx_event_t    *wev;
    ngx_chain_t    *cl, *tail;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    send = 0;
    complete = 0;

    vec.elts = sfvs;
    vec.size = sizeof(sendfilevec_t);
    vec.nalloc = NGX_SENDFILEVECS;
    vec.pool = c->pool;

    for ( ;; ) {
        fd = SFV_FD_SELF;
        prev = NULL;
        fprev = 0;
        sfv = NULL;
        eintr = 0;
        sent = 0;
        sprev = send;

        vec.nelts = 0;

        /* create the sendfilevec and coalesce the neighbouring bufs */

        for (cl = in; cl && vec.nelts < IOV_MAX && send < limit; cl = cl->next)
        {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (ngx_buf_in_memory_only(cl->buf)) {
                fd = SFV_FD_SELF;

                size = cl->buf->last - cl->buf->pos;

                if (send + size > limit) {
                    size = limit - send;
                }

                if (prev == cl->buf->pos) {
                    sfv->sfv_len += size;

                } else {
                    if (!(sfv = ngx_array_push(&vec))) {
                        return NGX_CHAIN_ERROR;
                    }

                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
                    sfv->sfv_len = size;
                }

                prev = cl->buf->pos + size;
                send += size;

            } else {
                prev = NULL;

                size = (size_t) (cl->buf->file_last - cl->buf->file_pos);

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                                                      & ~(ngx_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
                    sfv->sfv_len += size;

                } else {
                    if (!(sfv = ngx_array_push(&vec))) {
                        return NGX_CHAIN_ERROR;
                    }

                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = size;
                }

                fprev = cl->buf->file_pos + size;
                send += size;
            }
        }

        n = sendfilev(c->fd, vec.elts, vec.nelts, &sent);

        if (n == -1) {
            err = ngx_errno;

            if (err == NGX_EAGAIN || err == NGX_EINTR) {
                if (err == NGX_EINTR) {
                    eintr = 1;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
                              "sendfilev() sent only " SIZE_T_FMT " bytes",
                              sent);

            } else {
                wev->error = 1;
                ngx_connection_error(c, err, "sendfilev() failed");
                return NGX_CHAIN_ERROR;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "sendfilev: %d " SIZE_T_FMT, n, sent);

        if (send - sprev == sent) {
            complete = 1;
        }

        c->sent += sent;

        for (cl = in; cl; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue; 
            }

            if (sent == 0) {
                break;
            }

            size = ngx_buf_size(cl->buf);

            if (sent >= size) {
                sent -= size;

                if (ngx_buf_in_memory(cl->buf)) {
                    cl->buf->pos = cl->buf->last;
                }

                if (cl->buf->in_file) {
                    cl->buf->file_pos = cl->buf->file_last;
                }

                continue;
            }

            if (ngx_buf_in_memory(cl->buf)) {
                cl->buf->pos += sent;
            }

            if (cl->buf->in_file) {
                cl->buf->file_pos += sent;
            }

            break;
        }

        if (eintr) {
            continue;
        }

        if (!complete) {
            wev->ready = 0;
            return cl;
        }

        if (send >= limit || cl == NULL) {
            return cl;
        }

        in = cl;
    }
}
