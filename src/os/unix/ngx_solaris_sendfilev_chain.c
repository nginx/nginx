
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_SOLARIS_SENDFILEV)

/* Solaris declarations */

typedef struct sendfilevec {
    int     sfv_fd;
    u_int   sfv_flag;
    off_t   sfv_off;
    size_t  sfv_len;
} sendfilevec_t;

#define SFV_FD_SELF  -2

static ssize_t sendfilev(int fd, const struct sendfilevec *vec,
    int sfvcnt, size_t *xferred)
{
    return -1;
}

ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

#endif


#if (IOV_MAX > 64)
#define NGX_SENDFILEVECS  64
#else
#define NGX_SENDFILEVECS  IOV_MAX
#endif



ngx_chain_t *
ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int             fd;
    u_char         *prev;
    off_t           size, send, prev_send, aligned, fprev;
    size_t          sent;
    ssize_t         n;
    ngx_int_t       eintr, complete;
    ngx_err_t       err;
    sendfilevec_t  *sfv, sfvs[NGX_SENDFILEVECS];
    ngx_array_t     vec;
    ngx_event_t    *wev;
    ngx_chain_t    *cl;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    if (!c->sendfile) {
        return ngx_writev_chain(c, in, limit);
    }


    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }


    send = 0;

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
        complete = 0;
        sent = 0;
        prev_send = send;

        vec.nelts = 0;

        /* create the sendfilevec and coalesce the neighbouring bufs */

        for (cl = in; cl && send < limit; cl = cl->next) {

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
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (vec.nelts >= IOV_MAX) {
                        break;
                    }

                    sfv = ngx_array_push(&vec);
                    if (sfv == NULL) {
                        return NGX_CHAIN_ERROR;
                    }

                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
                    sfv->sfv_len = (size_t) size;
                }

                prev = cl->buf->pos + (size_t) size;
                send += size;

            } else {
                prev = NULL;

                size = cl->buf->file_last - cl->buf->file_pos;

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                               & ~((off_t) ngx_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (vec.nelts >= IOV_MAX) {
                        break;
                    }

                    sfv = ngx_array_push(&vec);
                    if (sfv == NULL) {
                        return NGX_CHAIN_ERROR;
                    }

                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = (size_t) size;
                }

                fprev = cl->buf->file_pos + size;
                send += size;
            }
        }

        n = sendfilev(c->fd, vec.elts, vec.nelts, &sent);

        if (n == -1) {
            err = ngx_errno;

            switch (err) {
            case NGX_EAGAIN:
                break;

            case NGX_EINTR:
                eintr = 1;
                break;

            default:
                wev->error = 1;
                ngx_connection_error(c, err, "sendfilev() failed");
                return NGX_CHAIN_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
                          "sendfilev() sent only %uz bytes", sent);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "sendfilev: %z %z", n, sent);

        if (send - prev_send == (off_t) sent) {
            complete = 1;
        }

        c->sent += sent;

        in = ngx_handle_sent_chain(in, sent);

        if (eintr) {
            continue;
        }

        if (!complete) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
