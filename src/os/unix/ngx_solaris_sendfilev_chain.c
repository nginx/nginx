
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

        /* create the sendfilevec and coalesce the neighbouring hunks */

        for (cl = in; cl && vec.nelts < IOV_MAX; cl = cl->next) {
            if (ngx_hunk_special(cl->hunk)) {
                continue;
            }

            if (ngx_hunk_in_memory_only(cl->hunk)) {
                fd = SFV_FD_SELF;

                if (prev == cl->hunk->pos) {
                    sfv->sfv_len += cl->hunk->last - cl->hunk->pos;

                } else {
                    ngx_test_null(sfv, ngx_push_array(&vec), NGX_CHAIN_ERROR);
                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->hunk->pos;
                    sfv->sfv_len = cl->hunk->last - cl->hunk->pos;
                }

                prev = cl->hunk->last;

            } else {
                prev = NULL;

                if (fd == cl->hunk->file->fd && fprev == cl->hunk->file_pos) {
                    sfv->sfv_len += cl->hunk->file_last - cl->hunk->file_pos;

                } else {
                    ngx_test_null(sfv, ngx_push_array(&vec), NGX_CHAIN_ERROR);
                    fd = cl->hunk->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->hunk->file_pos;
                    sfv->sfv_len = cl->hunk->file_last - cl->hunk->file_pos;
                }

                fprev = cl->hunk->file_last;
            }
        }

        /*
         * the tail is the rest of the chain that exceeded a single
         * sendfilev() capability, IOV_MAX in Solaris is only 16
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

            if (ngx_hunk_special(cl->hunk)) {
                continue; 
            }

            if (sent == 0) {
                break;
            }

            size = ngx_hunk_size(cl->hunk);

            if (sent >= size) {
                sent -= size;

                if (cl->hunk->type & NGX_HUNK_IN_MEMORY) {
                    cl->hunk->pos = cl->hunk->last;
                }

                if (cl->hunk->type & NGX_HUNK_FILE) {
                    cl->hunk->file_pos = cl->hunk->file_last;
                }

                continue;
            }

            if (cl->hunk->type & NGX_HUNK_IN_MEMORY) {
                cl->hunk->pos += sent;
            }

            if (cl->hunk->type & NGX_HUNK_FILE) {
                cl->hunk->file_pos += sent;
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
