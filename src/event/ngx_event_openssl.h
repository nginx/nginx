#ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
#define _NGX_EVENT_OPENSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


typedef SSL      ngx_ssl_t;
typedef SSL_CTX  ngx_ssl_ctx_t;


#define NGX_SSL_HTTP_ERROR  -10


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create_session(ngx_ssl_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
                                off_t limit);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, char *fmt, ...);


#endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
