#include <ngx_config.h>
#include <ngx_core.h>


static void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, int err,
                          char *fmt, ...);


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
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NGX_ERROR;
    }

    if (SSL_set_fd(ssl, c->fd) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
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

    ngx_ssl_error(NGX_LOG_ALERT, c->log, n, "SSL_read() failed%s", handshake);

    SSL_set_shutdown(c->ssl, SSL_RECEIVED_SHUTDOWN);

    return NGX_ERROR;
}


static void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, int err,
                          char *fmt, ...)
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
