
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_int_t ngx_ssl_init(ngx_log_t *log)
{
    SSL_library_init();
    SSL_load_error_strings();

    return NGX_OK;
}


ngx_int_t ngx_ssl_create_session(ngx_ssl_ctx_t *ssl_ctx, ngx_connection_t *c)
{   
    ngx_ssl_t  *ssl;

    ssl = SSL_new(ssl_ctx);

    if (ssl == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(ssl, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, "SSL_set_fd() failed");
        return NGX_ERROR;
    }

    SSL_set_accept_state(ssl);

    c->ssl = ssl;

    return NGX_OK;
}


ngx_int_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int         n;
    char       *handshake;

    n = SSL_read(c->ssl, buf, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n); 

    if (n > 0) {
        return n;
    }

    n = SSL_get_error(c->ssl, n);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", n);

    if (n == SSL_ERROR_WANT_READ) {
        return NGX_AGAIN;
    }

#if 0
    if (n == SSL_ERROR_WANT_WRITE) {
        return NGX_AGAIN;
    }
#endif

    if (!SSL_is_init_finished(c->ssl)) {
        handshake = "in SSL handshake";

    } else {
        handshake = "";
    }

    if (n == SSL_ERROR_ZERO_RETURN) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection%s", handshake);

        SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN);

        return NGX_ERROR;
    }

    if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "client sent plain HTTP request to HTTPS port");

        SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN);

        return NGX_SSL_HTTP_ERROR;
    }

    ngx_ssl_error(NGX_LOG_ALERT, c->log, "SSL_read() failed%s", handshake);

    SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN);

    return NGX_ERROR;
}


ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
                                off_t limit)
{
    int      n;
    ssize_t  send, size;

    send = 0;

    for (/* void */; in; in = in->next) {
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        size = in->buf->last - in->buf->pos;

        if (send + size > limit) {
            size = limit - send;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL to write: %d", size);

        n = SSL_write(c->ssl, in->buf->pos, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

        if (n > 0) {
            in->buf->pos += n;
            send += n;

            if (n == size) {
                if (send < limit) {
                    continue;
                }

                return in;
            }

            c->write->ready = 0;
            return in;
        }

        n = SSL_get_error(c->ssl, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", n);

        if (n == SSL_ERROR_WANT_WRITE) {
            c->write->ready = 0;
            return in;
        }

#if 0
        if (n == SSL_ERROR_WANT_READ) {
            return NGX_AGAIN;
        }
#endif

        ngx_ssl_error(NGX_LOG_ALERT, c->log, "SSL_write() failed");

        return NGX_CHAIN_ERROR;
    }

    return in;
}


ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c)
{
    int  n;
    ngx_uint_t  again;

#if 0
    if (c->read->timedout || c->write->timedout) {
        SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN);
    }
#endif

#if 0
    SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN);
#endif

    again = 0;

    for ( ;; ) {
        n = SSL_shutdown(c->ssl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

        if (n == 0) {
            again = 1;
            break;
        }

        if (n == 1) {
            SSL_free(c->ssl);
            c->ssl = NULL;
            return NGX_OK;
        }

        break;
    }

    if (!again) {
        n = SSL_get_error(c->ssl, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", n);
    }

    if (again || n == SSL_ERROR_WANT_READ) {

        ngx_add_timer(c->read, 10000);

        if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == SSL_ERROR_WANT_WRITE) {

        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    ngx_ssl_error(NGX_LOG_ALERT, c->log, "SSL_shutdown() failed");

    return NGX_ERROR;
}


void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, char *fmt, ...)
{   
    int      len;
    char     errstr[NGX_MAX_CONF_ERRSTR];
    va_list  args;

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

    ngx_log_error(level, log, 0, "%s)", errstr);
}
