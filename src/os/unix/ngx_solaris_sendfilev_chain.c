
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int             fd;
    u_char         *prev;
    off_t           fprev;
    size_t          sent, size;
    ssize_t         n;
    ngx_int_t       eintr;
    ngx_err_t       err;
    sendfilevec_t  *sfv;
    ngx_array_t     vec;
    ngx_event_t    *wev;
    ngx_chain_t    *cl, *tail;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    do {
        fd = SFV_FD_SELF;
        prev = NULL;
        fprev = 0;
        sfv = NULL;
        eintr = 0;
        sent = 0;

        ngx_init_array(vec, c->pool, 10, sizeof(sendfilevec_t),
                       NGX_CHAIN_ERROR);

        /* create the sendfilevec and coalesce the neighbouring bufs */

        for (cl = in; cl && vec.nelts < IOV_MAX; cl = cl->next) {
            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (ngx_buf_in_memory_only(cl->buf)) {
                fd = SFV_FD_SELF;

                if (prev == cl->buf->pos) {
                    sfv->sfv_len += cl->buf->last - cl->buf->pos;

                } else {
                    ngx_test_null(sfv, ngx_push_array(&vec), NGX_CHAIN_ERROR);
                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
                    sfv->sfv_len = cl->buf->last - cl->buf->pos;
                }

                prev = cl->buf->last;

            } else {
                prev = NULL;

                if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
                    sfv->sfv_len += cl->buf->file_last - cl->buf->file_pos;

                } else {
                    ngx_test_null(sfv, ngx_push_array(&vec), NGX_CHAIN_ERROR);
                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = cl->buf->file_last - cl->buf->file_pos;
                }

                fprev = cl->buf->file_last;
            }
        }

        /*
         * the tail is the rest of the chain that exceedes a single
         * sendfilev() capability, IOV_MAX in Solaris is limited by 16
         */

        tail = cl;

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

        in = cl;

        /* "tail == in" means that a single sendfilev() is complete */

    } while ((tail && tail == in) || eintr);

    if (in) {
        wev->ready = 0;
    }

    return in;
}
