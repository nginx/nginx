#ifndef _NGX_HTTP_WRITE_FILTER_H_INCLUDED_
#define _NGX_HTTP_WRITE_FILTER_H_INCLUDED_


typedef struct {
    ngx_chain_t  *out;
    size_t        buffer_output;
} ngx_http_write_filter_ctx_t;


#endif /* _NGX_HTTP_WRITE_FILTER_H_INCLUDED_ */
