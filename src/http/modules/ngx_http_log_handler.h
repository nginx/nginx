#ifndef _NGX_HTTP_LOG_HANDLER_H_INCLUDED_
#define _NGX_HTTP_LOG_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    int   dummy;
} ngx_http_log_conf_t;


typedef enum {

    NGX_HTTP_LOG_HANDLER = 0,

#if 0
    /* the ngx_str_t field of the request */
    NGX_HTTP_LOG_REQUEST_STR_FIELD,

    /* the ngx_str_t field of the r->headers_in */
    NGX_HTTP_LOG_REQUEST_HEADER_IN_FIELD,

    /* the ngx_str_t field of the r->headers_out */
    NGX_HTTP_LOG_REQUEST_HEADER_OUT_FIELD,
#endif

} ngx_http_log_code_e;


typedef struct {
    int      type;
    int      size;
    char  *(*handler) (ngx_http_request_t *r, char *p);
    int      offset;
} ngx_http_log_code_t;


#endif /* _NGX_HTTP_LOG_HANDLER_H_INCLUDED_ */
