
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_int_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);


ngx_int_t ngx_ssl_init(ngx_log_t *log)
{
    SSL_library_init();
    SSL_load_error_strings();

    return NGX_OK;
}


ngx_int_t ngx_ssl_create_session(ngx_ssl_ctx_t *ssl_ctx, ngx_connection_t *c,
                                 ngx_uint_t flags)
{   
    ngx_ssl_t  *ssl;

    if (!(ssl = ngx_pcalloc(c->pool, sizeof(ngx_ssl_t)))) {
        return NGX_ERROR;
    }

    if (!(ssl->buf = ngx_create_temp_buf(c->pool, NGX_SSL_BUFSIZE))) {
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_BUFFER) {
        ssl->buffer = 1;
    }

    ssl->ssl = SSL_new(ssl_ctx);

    if (ssl->ssl == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(ssl->ssl, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return NGX_ERROR;
    }

    SSL_set_accept_state(ssl->ssl);

    c->ssl = ssl;

    return NGX_OK;
}


ngx_int_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int         n, sslerr;
    ngx_err_t   err;
    char       *handshake;

    n = SSL_read(c->ssl->ssl, buf, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n); 

    if (n > 0) {
        return n;
    }

    sslerr = SSL_get_error(c->ssl->ssl, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        ngx_log_error(NGX_LOG_ALERT, c->log, err,
                      "SSL wants to write%s", handshake);
        return NGX_ERROR;
#if 0
        return NGX_AGAIN;
#endif
    }

    if (!SSL_is_init_finished(c->ssl->ssl)) {
        handshake = "in SSL handshake";

    } else {
        handshake = "";
    }

    c->ssl->no_rcv_shut = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, err,
                      "client closed connection%s", handshake);

        return NGX_ERROR;
    }

    ngx_ssl_error(NGX_LOG_ALERT, c->log, err,
                  "SSL_read() failed%s", handshake);

    return NGX_ERROR;
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
                                off_t limit)
{
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

    buf = c->ssl->buf;

    if (in && in->next == NULL && !c->buffered && !c->ssl->buffer) {

        /*
         * we avoid a buffer copy if the incoming buf is a single,
         * our buffer is empty, and we do not need to buffer the output
         */

        n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n < 0) {
            n = 0;
        }

        in->buf->pos += n;

        return in;
    }

    send = 0;
    flush = (in == NULL) ? 1 : 0;

    for ( ;; ) {

        while (in && buf->last < buf->end) {
            if (in->buf->last_buf) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            /*
             * TODO: the taking in->buf->flush into account can be
             *       implemented using the limit on the higher level
             */

            if (send + size > limit) {
                size = limit - send;
                flush = 1;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %d", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;

            in->buf->pos += size;
            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        size = buf->last - buf->pos;

        if (!flush && buf->last < buf->end && c->ssl->buffer) {
            break;
        }

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n < 0) {
            n = 0;
        }

        buf->pos += n;
        send += n;
        c->sent += n;

        if (n < size) {
            break;
        }

        if (buf->pos == buf->last) {
            buf->pos = buf->start;
            buf->last = buf->start;
        }

        if (in == NULL || send == limit) {
            break;
        }
    }

    c->buffered = (buf->pos < buf->last) ? 1 : 0;

    return in;
}


static ngx_int_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    ngx_err_t  err;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %d", size);

    n = SSL_write(c->ssl->ssl, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {
        return n;
    }

    sslerr = SSL_get_error(c->ssl->ssl, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {
        ngx_log_error(NGX_LOG_ALERT, c->log, err,
                      "SSL wants to read%s", handshake);
        return NGX_ERROR;
#if 0
        return NGX_AGAIN;
    }
#endif

    c->ssl->no_rcv_shut = 1;

    ngx_ssl_error(NGX_LOG_ALERT, c->log, err, "SSL_write() failed");

    return NGX_ERROR;
}


ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c)
{
    int         n, sslerr;
    ngx_uint_t  again;

    if (c->timedout) {
        SSL_set_shutdown(c->ssl->ssl, SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN);

    } else {
        if (c->ssl->no_rcv_shut) {
            SSL_set_shutdown(c->ssl->ssl, SSL_RECEIVED_SHUTDOWN);
        }

        if (c->ssl->no_send_shut) {
            SSL_set_shutdown(c->ssl->ssl, SSL_SENT_SHUTDOWN);
        }
    }

    again = 0;

    for ( ;; ) {
        n = SSL_shutdown(c->ssl->ssl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

        if (n == 0) {
            again = 1;
            break;
        }

        if (n == 1) {
            SSL_free(c->ssl->ssl);
            c->ssl = NULL;
            return NGX_OK;
        }

        break;
    }

    if (!again) {
        sslerr = SSL_get_error(c->ssl->ssl, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);
    }

    if (again || sslerr == SSL_ERROR_WANT_READ) {

        ngx_add_timer(c->read, 10000);

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_shutdown() failed");

    return NGX_ERROR;
}


void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
                   char *fmt, ...)
{   
    int        len;
    char       errstr[NGX_MAX_CONF_ERRSTR];
    va_list    args;

    va_start(args, fmt);
    len = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    errstr[len++] = ' ';
    errstr[len++] = '(';
    errstr[len++] = 'S';
    errstr[len++] = 'S';
    errstr[len++] = 'L';
    errstr[len++] = ':';
    errstr[len++] = ' ';

    ERR_error_string_n(ERR_get_error(), errstr + len, sizeof(errstr) - len - 1);

    ngx_log_error(level, log, err, "%s)", errstr);
}
