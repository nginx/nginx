#ifndef _NGX_HTTP_FILTER_H_INCLUDED_
#define _NGX_HTTP_FILTER_H_INCLUDED_


#include <ngx_core.h>

#define NGX_HTTP_FILTER_NEED_IN_MEMORY  1
#define NGX_HTTP_FILTER_NEED_TEMP       2

typedef struct {
    int         (*next_filter)(ngx_http_request_t *r, ngx_chain_t *ch);
    ngx_hunk_t   *hunk;
    ngx_chain_t  *in;
    ngx_chain_t   out;
    size_t        hunk_size;
    unsigned      last;
} ngx_http_filter_ctx_t;


#endif /* _NGX_HTTP_FILTER_H_INCLUDED_ */
