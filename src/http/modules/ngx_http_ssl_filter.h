#ifndef _NGX_HTTP_SSL_FILTER_H_INCLUDED_
#define _NGX_HTTP_SSL_FILTER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_ssl_read(ngx_http_request_t *r);


#endif /* _NGX_HTTP_SSL_FILTER_H_INCLUDED_ */
