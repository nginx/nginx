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


typedef struct {
    int         large_header;
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_str_t  host;
    ngx_str_t  uri;
    ngx_str_t  host_header;
    ngx_str_t  port_name;
    int        port;
} ngx_http_proxy_upstream_url_t;


typedef struct {
    struct     sockaddr_in;
    ngx_str_t  name;
    time_t     access;
    int        fails;
} ngx_http_proxy_upstream_t;


typedef struct {
    int                         amount;
    ngx_http_proxy_upstream_t  *upstreams;
} ngx_http_proxy_upstream_farm_t;


#if 0
/* location /one/ { proxy_pass  http://localhost:9000/two/; } */

typedef struct {
                           /* "/one/" */
                           /* "http://localhost:9000/two/" */
                           /* "/two/" */
                *upstream_farm;
} ngx_http_proxy_pass_t;
#endif


typedef struct ngx_http_proxy_ctx_s  ngx_http_proxy_ctx_t;

struct ngx_http_proxy_ctx_s {
    ngx_chain_t  *out;

    int           last_hunk;
    ngx_array_t   hunks;

    int           hunk_n;

    ngx_connection_t             *connection;
    ngx_http_request_t           *request;
    ngx_http_proxy_headers_in_t  *headers_in;

    ngx_http_proxy_upstream_farm_t   *upstream;
    int                               cur_upstream;
    int                               upstreams;

    ngx_log_t    *log;

    ngx_hunk_t  *header_in;
    int          state;
    int          status;
    int          status_count;
    char        *status_line;
    char        *request_end;
    int        (*state_handler)(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p);
};


typedef struct {
    char  *action;
    char  *upstream;
    char  *client;
    char  *url;
} ngx_http_proxy_log_ctx_t;


extern ngx_module_t  ngx_http_proxy_module;


static int ngx_http_proxy_error(ngx_http_request_t *r, ngx_http_proxy_ctx_t *p,
                                int error);


#endif /* _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_ */
