#ifndef _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_
#define _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_array.h>
#include <ngx_event_proxy.h>
#include <ngx_http.h>


#define NGX_HTTP_PROXY_PARSE_NO_HEADER          20
#define NGX_HTTP_PARSE_TOO_LONG_STATUS_LINE     21

typedef struct {
    ngx_table_elt_t  *date;
    ngx_table_elt_t  *server;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *content_type;
    ngx_table_elt_t  *content_length;
    ngx_table_elt_t  *last_modified;

    ngx_table_t      *headers;
} ngx_http_proxy_headers_in_t;


typedef struct {
    u_int32_t  addr;
    ngx_str_t  host;
    int        port;
    ngx_str_t  addr_port_name;

    int        fails;
    time_t     accessed;
} ngx_http_proxy_upstream_t;


typedef struct {
    int                        current;
    int                        number;
    int                        max_fails;
    int                        fail_timeout;

 /* ngx_mutex_t                mutex; */
 /* ngx_connection_t          *cached; ??? */

    ngx_http_proxy_upstream_t  u[1];
} ngx_http_proxy_upstreams_t;


typedef struct {
    ngx_str_t   host;
    ngx_str_t   uri;
    ngx_str_t  *location;
    ngx_str_t   host_header;
    ngx_str_t   port_name;
    int         port;
} ngx_http_proxy_upstream_url_t;


typedef struct {
    ngx_http_proxy_upstreams_t     *upstreams;
    ngx_http_proxy_upstream_url_t  *upstream_url;

    int   rcvbuf;
    int   conn_pool_size;
    int   connect_timeout;
    int   send_timeout;
    int   read_timeout;
    int   header_size;
    int   large_header;

    int   block_size;
    int   max_block_size;
    int   file_block_size;

    ngx_path_t  *temp_path;
    int   temp_file_warn;

    int   retry_500_error;

} ngx_http_proxy_loc_conf_t;


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
    ngx_event_proxy_t  *event_proxy;

    ngx_chain_t   *in_hunks;
    ngx_chain_t   *last_in_hunk;

    ngx_chain_t   *shadow_hunks;

    ngx_chain_t   *out_hunks;
    ngx_chain_t   *last_out_hunk;

    ngx_chain_t   *free_hunks;

    ngx_chain_t   *request_hunks;

    ngx_connection_t               *connection;
    ngx_http_request_t             *request;
    ngx_http_proxy_headers_in_t     headers_in;


    int           block_size;
    int           allocated;

    ngx_file_t   *temp_file;
    off_t         temp_offset;

    int           last_hunk;
    ngx_array_t   hunks;
    int           nhunks;

    int           hunk_n;

    ngx_http_proxy_upstream_url_t  *upstream_url;
    ngx_http_proxy_upstreams_t     *upstreams;
    int                             cur_upstream;
    int                             tries;

    struct sockaddr                *sockaddr;

    ngx_http_proxy_loc_conf_t      *lcf;

    ngx_log_t    *log;

    int          method;

    ngx_hunk_t  *header_in;
    int          status;
    ngx_str_t    status_line;
    ngx_str_t    full_status_line;

    int          state;
    int          status_count;
    char        *status_start;
    char        *status_end;
    int        (*state_write_upstream_handler) (ngx_http_proxy_ctx_t *p);
    int        (*state_read_upstream_handler) (ngx_http_proxy_ctx_t *p);
    int        (*state_handler)(ngx_http_proxy_ctx_t *p);

    int          last_error;

    unsigned     accel:1;

    unsigned     cached_connection:1;
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
