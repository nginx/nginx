#ifndef _NGX_HTTP_SSL_FILTER_H_INCLUDED_
#define _NGX_HTTP_SSL_FILTER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_SSL_ERROR         -10
#define NGX_SSL_HTTP_ERROR    -11


ngx_int_t ngx_http_ssl_read(ngx_http_request_t *r, u_char *buf, size_t size);
ngx_int_t ngx_http_ssl_shutdown(ngx_http_request_t *r);
ngx_chain_t *ngx_http_ssl_write(ngx_connection_t *c, ngx_chain_t *in,
                                off_t limit);

void ngx_http_ssl_close_connection(SSL *ssl, ngx_log_t *log);


#endif /* _NGX_HTTP_SSL_FILTER_H_INCLUDED_ */
