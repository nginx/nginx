
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * FreeBSD's sendfile() often sends 4K pages over ethernet in 3 packets: 2x1460
 * and 1176 or in 6 packets: 5x1460 and 892.  Besides although sendfile()
 * allows to pass the header and the trailer it never sends the header or
 * the trailer with the part of the file in one packet.  So we use TCP_NOPUSH
 * (similar to Linux's TCP_CORK) to postpone the sending - it not only sends
 * the header and the first part of the file in one packet but also sends
 * 4K pages in the full packets.
 *
 * Until FreeBSD 4.5 the turning TCP_NOPUSH off does not flush a pending
 * data that less than MSS so that data can be sent with 5 second delay.
 * We do not use TCP_NOPUSH on FreeBSD prior to 4.5 although it can be used
 * for non-keepalive HTTP connections.
 */


ngx_chain_t *ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in)
{
    int              rc;
    char            *prev;
    off_t            sent, fprev;
    size_t           hsize, fsize, size;
    ngx_int_t        eintr, eagain;
    struct iovec    *iov;
    struct sf_hdtr   hdtr;
    ngx_err_t        err;
    ngx_hunk_t      *file;
    ngx_array_t      header, trailer;
    ngx_event_t     *wev;
    ngx_chain_t     *cl, *tail;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) && wev->kq_eof) {
        ngx_log_error(NGX_LOG_ERR, c->log, wev->kq_errno,
                      "kevent() reported about closed connection");

        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    do {
        file = NULL;
        fsize = 0;
        hsize = 0;
        eintr = 0;
        eagain = 0;

        ngx_init_array(header, c->pool, 10, sizeof(struct iovec),
                       NGX_CHAIN_ERROR);
        ngx_init_array(trailer, c->pool, 10, sizeof(struct iovec),
                       NGX_CHAIN_ERROR);

        /* create the header iovec and coalesce the neighbouring hunks */

        prev = NULL;
        iov = NULL;

        for (cl = in; cl; cl = cl->next) {
            if (ngx_hunk_special(cl->hunk)) {
                continue;
            }

            if (!ngx_hunk_in_memory_only(cl->hunk)) {
                break;
            }

            if (prev == cl->hunk->pos) {
                iov->iov_len += cl->hunk->last - cl->hunk->pos;

            } else {
                ngx_test_null(iov, ngx_push_array(&header), NGX_CHAIN_ERROR);
                iov->iov_base = cl->hunk->pos;
                iov->iov_len = cl->hunk->last - cl->hunk->pos;
            }

            prev = cl->hunk->last;
            hsize += cl->hunk->last - cl->hunk->pos;
        }

        /* get the file hunk */

        if (cl && (cl->hunk->type & NGX_HUNK_FILE)) {
            file = cl->hunk;
            fsize = (size_t) (file->file_last - file->file_pos);
            fprev = file->file_last;
            cl = cl->next;

            /* coalesce the neighbouring file hunks */

            while (cl && (cl->hunk->type & NGX_HUNK_FILE)) {
                if (file->file->fd != cl->hunk->file->fd
                    || fprev != cl->hunk->file_pos)
                {
                    break;
                }

                fsize += (size_t) (cl->hunk->file_last - cl->hunk->file_pos);
                fprev = cl->hunk->file_last;
                cl = cl->next;
            }
        }

        /* create the tailer iovec and coalesce the neighbouring hunks */

        prev = NULL;
        iov = NULL;

        for ( /* void */; cl; cl = cl->next) {
            if (ngx_hunk_special(cl->hunk)) {
                continue;
            }

            if (!ngx_hunk_in_memory_only(cl->hunk)) {
                break;
            }

            if (prev == cl->hunk->pos) {
                iov->iov_len += cl->hunk->last - cl->hunk->pos;

            } else {
                ngx_test_null(iov, ngx_push_array(&trailer), NGX_CHAIN_ERROR);
                iov->iov_base = cl->hunk->pos;
                iov->iov_len = cl->hunk->last - cl->hunk->pos;
            }

            prev = cl->hunk->last;
        }

        /*
         * the tail is the rest of the chain that exceeded
         * a single sendfile() capability
         */

        tail = cl;

        if (file) {

            if (ngx_freebsd_use_tcp_nopush && !c->tcp_nopush) {
                c->tcp_nopush = 1;

ngx_log_debug(c->log, "NOPUSH");

                if (ngx_tcp_nopush(c->fd) == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, c->log, ngx_errno,
                                  ngx_tcp_nopush_n " failed");
                    return NGX_CHAIN_ERROR;
                }
            }

            hdtr.headers = (struct iovec *) header.elts;
            hdtr.hdr_cnt = header.nelts;
            hdtr.trailers = (struct iovec *) trailer.elts;
            hdtr.trl_cnt = trailer.nelts;

            /*
             * the "nbytes bug" of the old sendfile() syscall:
             * http://www.freebsd.org/cgi/query-pr.cgi?pr=33771
             */

            if (ngx_freebsd_sendfile_nbytes_bug == 0) {
                hsize = 0;
            }

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          fsize + hsize, &hdtr, &sent, 0);

            if (rc == -1) {
                err = ngx_errno;

                if (err == NGX_EINTR) {
                    eintr = 1;
                }

                if (err == NGX_EAGAIN) {
                    eagain = 1;
                }

                if (err == NGX_EAGAIN || err == NGX_EINTR) {
                    ngx_log_error(NGX_LOG_INFO, c->log, err,
                                  "sendfile() sent only " OFF_T_FMT " bytes",
                                  sent);

                } else {
                    wev->error = 1;
                    ngx_log_error(NGX_LOG_CRIT, c->log, err,
                                  "sendfile() failed");
                    return NGX_CHAIN_ERROR;
                }
            }

#if (NGX_DEBUG_WRITE_CHAIN)
            ngx_log_debug(c->log, "sendfile: %d, @%qd %qd:%d" _
                          rc _ file->file_pos _ sent _ fsize + hsize);
#endif

        } else {
            rc = writev(c->fd, header.elts, header.nelts);

            if (rc == -1) {
                err = ngx_errno;
                if (err == NGX_EAGAIN) {
                    ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EAGAIN");

                } else if (err == NGX_EINTR) {
                    eintr = 1;
                    ngx_log_error(NGX_LOG_INFO, c->log, err, "writev() EINTR");

                } else {
                    wev->error = 1;
                    ngx_log_error(NGX_LOG_CRIT, c->log, err, "writev() failed");
                    return NGX_CHAIN_ERROR;
                }
            }

            sent = rc > 0 ? rc : 0;

#if (NGX_DEBUG_WRITE_CHAIN)
            ngx_log_debug(c->log, "writev: %qd" _ sent);
#endif
        }

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

        if (eagain) {

            /*
             * sendfile() can return EAGAIN even if it has sent
             * a whole file part and successive sendfile() would
             * return EAGAIN right away and would not send anything
             */

            wev->ready = 0;
            break;
        }

        /* "tail == in" means that a single sendfile() is complete */

    } while ((tail && tail == in) || eintr);

    if (in) {
        wev->ready = 0;
    }

    return in;
}
