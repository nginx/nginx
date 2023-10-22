
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


#define NGX_SENDFILEVECS  NGX_IOVS_PREALLOCATE


ngx_chain_t *
ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int             fd;
    u_char         *prev;
    off_t           size, send, prev_send, aligned, fprev;
    size_t          sent;
    ssize_t         n;
    ngx_int_t       eintr;
    ngx_err_t       err;
    ngx_buf_t      *file;
    ngx_uint_t      nsfv;
    sendfilevec_t  *sfv, sfvs[NGX_SENDFILEVECS];
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

    for ( ;; ) {
        fd = SFV_FD_SELF;
        prev = NULL;
        fprev = 0;
        file = NULL;
        sfv = NULL;
        eintr = 0;
        sent = 0;
        prev_send = send;

        nsfv = 0;

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
                    if (nsfv == NGX_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

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
                    if (nsfv == NGX_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = (size_t) size;
                }

                file = cl->buf;
                fprev = cl->buf->file_pos + size;
                send += size;
            }
        }

        n = sendfilev(c->fd, sfvs, nsfv, &sent);

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

        } else if (n == 0 && sent == 0) {

            /*
             * sendfilev() is documented to return -1 with errno
             * set to EINVAL if svf_len is greater than the file size,
             * but at least Solaris 11 returns 0 instead
             */

            if (file) {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                        "sendfilev() reported that \"%s\" was truncated at %O",
                        file->file->name.data, file->file_pos);

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "sendfilev() returned 0 with memory buffers");
            }

            return NGX_CHAIN_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "sendfilev: %z %z", n, sent);

        c->sent += sent;

        in = ngx_chain_update_sent(in, sent);

        if (eintr) {
            send = prev_send + sent;
            continue;
        }

        if (send - prev_send != (off_t) sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
