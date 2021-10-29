
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ssize_t ngx_linux_sendfile(ngx_connection_t *c, ngx_buf_t *file,
    size_t size);

#if (NGX_THREADS)
#include <ngx_thread_pool.h>

#if !(NGX_HAVE_SENDFILE64)
#error sendfile64() is required!
#endif

static ssize_t ngx_linux_sendfile_thread(ngx_connection_t *c, ngx_buf_t *file,
    size_t size);
static void ngx_linux_sendfile_thread_handler(void *data, ngx_log_t *log);
#endif


/*
 * On Linux up to 2.4.21 sendfile() (syscall #187) works with 32-bit
 * offsets only, and the including <sys/sendfile.h> breaks the compiling,
 * if off_t is 64 bit wide.  So we use own sendfile() definition, where offset
 * parameter is int32_t, and use sendfile() for the file parts below 2G only,
 * see src/os/unix/ngx_linux_config.h
 *
 * Linux 2.4.21 has the new sendfile64() syscall #239.
 *
 * On Linux up to 2.6.16 sendfile() does not allow to pass the count parameter
 * more than 2G-1 bytes even on 64-bit platforms: it returns EINVAL,
 * so we limit it to 2G-1 bytes.
 *
 * On Linux 2.6.16 and later, sendfile() silently limits the count parameter
 * to 2G minus the page size, even on 64-bit platforms.
 */

#define NGX_SENDFILE_MAXSIZE  2147483647L


ngx_chain_t *
ngx_linux_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int            tcp_nodelay;
    off_t          send, prev_send;
    size_t         file_size, sent;
    ssize_t        n;
    ngx_err_t      err;
    ngx_buf_t     *file;
    ngx_event_t   *wev;
    ngx_chain_t   *cl;
    ngx_iovec_t    header;
    struct iovec   headers[NGX_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }


    /* the maximum limit size is 2G-1 - the page size */

    if (limit == 0 || limit > (off_t) (NGX_SENDFILE_MAXSIZE - ngx_pagesize)) {
        limit = NGX_SENDFILE_MAXSIZE - ngx_pagesize;
    }


    send = 0;

    header.iovs = headers;
    header.nalloc = NGX_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = ngx_output_chain_to_iovec(&header, in, limit - send, c->log);

        if (cl == NGX_CHAIN_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        send += header.size;

        /* set TCP_CORK if there is a header before a file */

        if (c->tcp_nopush == NGX_TCP_NOPUSH_UNSET
            && header.count != 0
            && cl
            && cl->buf->in_file)
        {
            /* the TCP_CORK and TCP_NODELAY are mutually exclusive */

            if (c->tcp_nodelay == NGX_TCP_NODELAY_SET) {

                tcp_nodelay = 0;

                if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
                {
                    err = ngx_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing with the TCP_NODELAY
                     * and without the TCP_CORK
                     */

                    if (err != NGX_EINTR) {
                        wev->error = 1;
                        ngx_connection_error(c, err,
                                             "setsockopt(TCP_NODELAY) failed");
                        return NGX_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nodelay = NGX_TCP_NODELAY_UNSET;

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "no tcp_nodelay");
                }
            }

            if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {

                if (ngx_tcp_nopush(c->fd) == -1) {
                    err = ngx_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_CORK
                     */

                    if (err != NGX_EINTR) {
                        wev->error = 1;
                        ngx_connection_error(c, err,
                                             ngx_tcp_nopush_n " failed");
                        return NGX_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = NGX_TCP_NOPUSH_SET;

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }
        }

        /* get the file buf */

        if (header.count == 0 && cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            file_size = (size_t) ngx_chain_coalesce_file(&cl, limit - send);

            send += file_size;
#if 1
            if (file_size == 0) {
                ngx_debug_point();
                return NGX_CHAIN_ERROR;
            }
#endif

            n = ngx_linux_sendfile(c, file, file_size);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_DONE) {
                /* thread task posted */
                return in;
            }

            sent = (n == NGX_AGAIN) ? 0 : n;

        } else {
            n = ngx_writev(c, &header);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            sent = (n == NGX_AGAIN) ? 0 : n;
        }

        c->sent += sent;

        in = ngx_chain_update_sent(in, sent);

        if (n == NGX_AGAIN) {
            wev->ready = 0;
            return in;
        }

        if ((size_t) (send - prev_send) != sent) {

            /*
             * sendfile() on Linux 4.3+ might be interrupted at any time,
             * and provides no indication if it was interrupted or not,
             * so we have to retry till an explicit EAGAIN
             *
             * sendfile() in threads can also report less bytes written
             * than we are prepared to send now, since it was started in
             * some point in the past, so we again have to retry
             */

            send = prev_send + sent;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static ssize_t
ngx_linux_sendfile(ngx_connection_t *c, ngx_buf_t *file, size_t size)
{
#if (NGX_HAVE_SENDFILE64)
    off_t      offset;
#else
    int32_t    offset;
#endif
    ssize_t    n;
    ngx_err_t  err;

#if (NGX_THREADS)

    if (file->file->thread_handler) {
        return ngx_linux_sendfile_thread(c, file, size);
    }

#endif

#if (NGX_HAVE_SENDFILE64)
    offset = file->file_pos;
#else
    offset = (int32_t) file->file_pos;
#endif

eintr:

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sendfile: @%O %uz", file->file_pos, size);

    n = sendfile(c->fd, file->file->fd, &offset, size);

    if (n == -1) {
        err = ngx_errno;

        switch (err) {
        case NGX_EAGAIN:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() is not ready");
            return NGX_AGAIN;

        case NGX_EINTR:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            ngx_connection_error(c, err, "sendfile() failed");
            return NGX_ERROR;
        }
    }

    if (n == 0) {
        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "sendfile() reported that \"%s\" was truncated at %O",
                      file->file->name.data, file->file_pos);

        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0, "sendfile: %z of %uz @%O",
                   n, size, file->file_pos);

    return n;
}


#if (NGX_THREADS)

typedef struct {
    ngx_buf_t     *file;
    ngx_socket_t   socket;
    size_t         size;

    size_t         sent;
    ngx_err_t      err;
} ngx_linux_sendfile_ctx_t;


static ssize_t
ngx_linux_sendfile_thread(ngx_connection_t *c, ngx_buf_t *file, size_t size)
{
    ngx_event_t               *wev;
    ngx_thread_task_t         *task;
    ngx_linux_sendfile_ctx_t  *ctx;

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, c->log, 0,
                   "linux sendfile thread: %d, %uz, %O",
                   file->file->fd, size, file->file_pos);

    task = c->sendfile_task;

    if (task == NULL) {
        task = ngx_thread_task_alloc(c->pool, sizeof(ngx_linux_sendfile_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        task->handler = ngx_linux_sendfile_thread_handler;

        c->sendfile_task = task;
    }

    ctx = task->ctx;
    wev = c->write;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->err == NGX_EAGAIN) {
            /*
             * if wev->complete is set, this means that a write event
             * happened while we were waiting for the thread task, so
             * we have to retry sending even on EAGAIN
             */

            if (wev->complete) {
                return 0;
            }

            return NGX_AGAIN;
        }

        if (ctx->err) {
            wev->error = 1;
            ngx_connection_error(c, ctx->err, "sendfile() failed");
            return NGX_ERROR;
        }

        if (ctx->sent == 0) {
            /*
             * if sendfile returns zero, then someone has truncated the file,
             * so the offset became beyond the end of the file
             */

            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "sendfile() reported that \"%s\" was truncated at %O",
                          file->file->name.data, file->file_pos);

            return NGX_ERROR;
        }

        return ctx->sent;
    }

    if (task->event.active && ctx->file == file) {
        /*
         * tolerate duplicate calls; they can happen due to subrequests
         * or multiple calls of the next body filter from a filter
         */

        return NGX_DONE;
    }

    ctx->file = file;
    ctx->socket = c->fd;
    ctx->size = size;

    wev->complete = 0;

    if (file->file->thread_handler(task, file->file) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static void
ngx_linux_sendfile_thread_handler(void *data, ngx_log_t *log)
{
    ngx_linux_sendfile_ctx_t *ctx = data;

    off_t       offset;
    ssize_t     n;
    ngx_buf_t  *file;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "linux sendfile thread handler");

    file = ctx->file;
    offset = file->file_pos;

again:

    n = sendfile(ctx->socket, file->file->fd, &offset, ctx->size);

    if (n == -1) {
        ctx->err = ngx_errno;

    } else {
        ctx->sent = n;
        ctx->err = 0;
    }

#if 0
    ngx_time_update();
#endif

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                   "sendfile: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, file->file_pos);

    if (ctx->err == NGX_EINTR) {
        goto again;
    }
}

#endif /* NGX_THREADS */
