
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_command_t  ngx_http_status_commands[] = {

      ngx_null_command
};


ngx_http_module_t  ngx_http_status_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_status_create_loc_conf,       /* create location configration */
    ngx_http_status_merge_loc_conf         /* merge location configration */
};


ngx_module_t  ngx_http_status_module = {
    NGX_MODULE,
    &ngx_http_status_module_ctx,           /* module context */ 
    ngx_http_status_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_status_init,                  /* init module */
    NULL                                   /* init child */
};


static char http_states = "IRPCUWLK";


int ngx_http_status_handler(ngx_http_request_t *r)
{
    ngx_int_t            i, http;
    ngx_connection_t    *c;
    ngx_http_request_t  *sr;

    c = ngx_cycle->connections;

    for (i = 0; i < ngx_cycle->connection_n; i++) {
        if (c[i].module != http || c[i].data == NULL) {
            continue;
        }

        if (c[i].data == NULL && c[i].fd != -1) {
            'A'
        }

        sr = c[i].data;
    }

    return NGX_OK;
}
