
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
} ngx_http_ssi_filter_ctx_t;


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle);

    
static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};  


ngx_module_t  ngx_http_ssi_filter_module = {
    NGX_MODULE,
    &ngx_http_ssi_filter_module_ctx,       /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_ssi_filter_init,              /* init module */
    NULL                                   /* init child */
};


static int (*next_header_filter) (ngx_http_request_t *r);
static int (*next_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


static int ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{

}


static void ngx_http_ssi_parse()
{
    for ( ) {
        switch (state) {
        case ssi_start_state:

            /* tight loop */
            while (p < h->last) {
                if (*p++ == '<') {
                    state = ssi_comment_state;
                    length = 1;
                    break;
                }
            }

            /* fall through */

        case ssi_comment_state:
            break;

    }
}


static int ngx_http_ssi_filter_init(ngx_cycle_t *cycle)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_ssi_header_filter;

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_ssi_body_filter;

    return NGX_OK;
}
