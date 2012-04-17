
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * It seems that Darwin 9.4 (Mac OS X 1.5) sendfile() has the same
 * old bug as early FreeBSD sendfile() syscall:
 * http://www.freebsd.org/cgi/query-pr.cgi?pr=33771
 *
 * Besides sendfile() has another bug: if one calls sendfile()
 * with both a header and a trailer, then sendfile() ignores a file part
 * at all and sends only the header and the trailer together.
 * For this reason we send a trailer only if there is no a header.
 *
 * Although sendfile() allows to pass a header or a trailer,
 * it may send the header or the trailer and a part of the file
 * in different packets.  And FreeBSD workaround (TCP_NOPUSH option)
 * does not help.
 */


#if (IOV_MAX > 64)
#define NGX_HEADERS   64
#define NGX_TRAILERS  64
#else
#define NGX_HEADERS   IOV_MAX
#define NGX_TRAILERS  IOV_MAX
#endif


ngx_chain_t *
ngx_darwin_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int              rc;
    u_char          *prev;
    off_t            size, send, prev_send, aligned, sent, fprev;
    off_t            header_size, file_size;
    ngx_uint_t       eintr, complete;
    ngx_err_t        err;
    ngx_buf_t       *file;
    ngx_array_t      header, trailer;
    ngx_event_t     *wev;
    ngx_chain_t     *cl;
    struct sf_hdtr   hdtr;
    struct iovec    *iov, headers[NGX_HEADERS], trailers[NGX_TRAILERS];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    send = 0;

    header.elts = headers;
    header.size = sizeof(struct iovec);
    header.nalloc = NGX_HEADERS;
    header.pool = c->pool;

    trailer.elts = trailers;
    trailer.size = sizeof(struct iovec);
    trailer.nalloc = NGX_TRAILERS;
    trailer.pool = c->pool;

    for ( ;; ) {
        file = NULL;
        file_size = 0;
        header_size = 0;
        eintr = 0;
        complete = 0;
        prev_send = send;

        header.nelts = 0;
        trailer.nelts = 0;

        /* create the header iovec and coalesce the neighbouring bufs */

        prev = NULL;
        iov = NULL;

        for (cl = in; cl && send < limit; cl = cl->next) {

            if (ngx_buf_special(cl->buf)) {
                continue;
            }

            if (!ngx_buf_in_memory_only(cl->buf)) {
                break;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = limit - send;
            }

            if (prev == cl->buf->pos) {
                iov->iov_len += (size_t) size;

            } else {
                if (header.nelts >= IOV_MAX) {
                    break;
                }

                iov = ngx_array_push(&header);
                if (iov == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                iov->iov_base = (void *) cl->buf->pos;
                iov->iov_len = (size_t) size;
            }

            prev = cl->buf->pos + (size_t) size;
            header_size += size;
            send += size;
        }


        if (cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            do {
                size = cl->buf->file_last - cl->buf->file_pos;

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                               & ~((off_t) ngx_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                file_size += size;
                send += size;
                fprev = cl->buf->file_pos + size;
                cl = cl->next;

            } while (cl
                     && cl->buf->in_file
                     && send < limit
                     && file->file->fd == cl->buf->file->fd
                     && fprev == cl->buf->file_pos);
        }

        if (file && header.nelts == 0) {

            /* create the trailer iovec and coalesce the neighbouring bufs */

            prev = NULL;
            iov = NULL;

            while (cl && send < limit) {

                if (ngx_buf_special(cl->buf)) {
                    cl = cl->next;
                    continue;
                }

                if (!ngx_buf_in_memory_only(cl->buf)) {
                    break;
                }

                size = cl->buf->last - cl->buf->pos;

                if (send + size > limit) {
                    size = limit - send;
                }

                if (prev == cl->buf->pos) {
                    iov->iov_len += (size_t) size;

                } else {
                    if (trailer.nelts >= IOV_MAX) {
                        break;
                    }

                    iov = ngx_array_push(&trailer);
                    if (iov == NULL) {
                        return NGX_CHAIN_ERROR;
                    }

                    iov->iov_base = (void *) cl->buf->pos;
                    iov->iov_len = (size_t) size;
                }

                prev = cl->buf->pos + (size_t) size;
                send += size;
                cl = cl->next;
            }
        }

        if (file) {

            /*
             * sendfile() returns EINVAL if sf_hdtr's count is 0,
             * but corresponding pointer is not NULL
             */

            hdtr.headers = header.nelts ? (struct iovec *) header.elts: NULL;
            hdtr.hdr_cnt = header.nelts;
            hdtr.trailers = trailer.nelts ? (struct iovec *) trailer.elts: NULL;
            hdtr.trl_cnt = trailer.nelts;

            sent = header_size + file_size;

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: @%O %O h:%O",
                           file->file_pos, sent, header_size);

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          &sent, &hdtr, 0);

            if (rc == -1) {
                err = ngx_errno;

                switch (err) {
                case NGX_EAGAIN:
                    break;

                case NGX_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    (void) ngx_connection_error(c, err, "sendfile() failed");
                    return NGX_CHAIN_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() sent only %O bytes", sent);
            }

            if (rc == 0 && sent == 0) {

                /*
                 * if rc and sent equal to zero, then someone
                 * has truncated the file, so the offset became beyond
                 * the end of the file
                 */

                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "sendfile() reported that \"%s\" was truncated",
                              file->file->name.data);

                return NGX_CHAIN_ERROR;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%O",
                           rc, file->file_pos, sent, file_size + header_size);

        } else {
            rc = writev(c->fd, header.elts, header.nelts);

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "writev: %d of %uz", rc, send);

            if (rc == -1) {
                err = ngx_errno;

                switch (err) {
                case NGX_EAGAIN:
                    break;

                case NGX_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    ngx_connection_error(c, err, "writev() failed");
                    return NGX_CHAIN_ERROR;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                               "writev() not ready");
            }

            sent = rc > 0 ? rc : 0;
        }

        if (send - prev_send == sent) {
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
                cl->buf->pos += (size_t) sent;
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
