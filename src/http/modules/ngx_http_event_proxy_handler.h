#ifndef _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_
#define _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_array.h>
#include <ngx_http.h>


#define NGX_HTTP_PROXY_PARSE_NO_HEADER          20
#define NGX_HTTP_PARSE_TOO_LONG_STATUS_LINE     21

typedef struct {
    int dummy;
} ngx_http_proxy_headers_in_t;

typedef struct ngx_http_proxy_ctx_s  ngx_http_proxy_ctx_t;

struct ngx_http_proxy_ctx_s {
    ngx_chain_t  *out;

    int           last_hunk;
    ngx_array_t   hunks;

    int           hunk_n;

    ngx_http_proxy_headers_in_t  *headers_in;

    ngx_hunk_t  *header_in;
    int          state;
    int          status;
    int          status_count;
    char        *status_line;
    char        *request_end;
    int        (*state_handler)(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p);
};


extern ngx_http_module_t  ngx_http_proxy_module;


#endif /* _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_ */
