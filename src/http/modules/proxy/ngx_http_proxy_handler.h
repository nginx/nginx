#ifndef _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_
#define _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t   url;
    ngx_str_t   host;
    ngx_str_t   uri;
    ngx_str_t   host_header;
    ngx_str_t   port_text;
    ngx_str_t  *location;
    int         port;
} ngx_http_proxy_upstream_t;


typedef struct {
    ssize_t                       request_buffer_size;
    ngx_msec_t                    connect_timeout;
    ngx_msec_t                    send_timeout;
    ssize_t                       header_buffer_size;
    ngx_msec_t                    read_timeout;

    ngx_bufs_t                    bufs;
    ssize_t                       busy_buffers_size;

    ssize_t                       max_temp_file_size;
    ssize_t                       temp_file_write_size;
    int                           cyclic_temp_file;

    int                           cache;
    int                           pass_server;

    int                           next_upstream;
    int                           use_stale;

    ngx_path_t                   *cache_path;
    ngx_path_t                   *temp_path;

    ngx_http_proxy_upstream_t    *upstream;
    ngx_peers_t                  *peers;
} ngx_http_proxy_loc_conf_t;


typedef struct {
    int                           status;
    ngx_str_t                    *peer;
} ngx_http_proxy_state_t;


typedef struct {
    ngx_table_t                  *headers;   /* it must be first field */

    ngx_table_elt_t              *date;
    ngx_table_elt_t              *server;
    ngx_table_elt_t              *connection;
    ngx_table_elt_t              *content_type;
    ngx_table_elt_t              *content_length;
    ngx_table_elt_t              *last_modified;
    ngx_table_elt_t              *accept_ranges;

    off_t                         content_length_n;
} ngx_http_proxy_headers_in_t;


typedef struct {
    ngx_http_cache_ctx_t          ctx;
    int                           status;
    ngx_str_t                     status_line;
    ngx_http_proxy_headers_in_t   headers_in;
} ngx_http_proxy_cache_t;


typedef struct ngx_http_proxy_ctx_s  ngx_http_proxy_ctx_t;

struct ngx_http_proxy_ctx_s {
    ngx_peer_connection_t         upstream;
    ngx_peer_t                   *peer;

    ngx_http_request_t           *request;
    ngx_http_proxy_loc_conf_t    *lcf;
    ngx_http_proxy_cache_t       *cache;
    ngx_http_proxy_headers_in_t   headers_in;

    ngx_hunk_t                   *header_in;
    int                           status;
    ngx_str_t                     status_line;

    ngx_output_chain_ctx_t       *output_chain_ctx;

    int                           method;

    ngx_event_pipe_t             *event_pipe;

    unsigned                      accel:1;

    unsigned                      cachable:1;
    unsigned                      stale:1;

    unsigned                      request_sent:1;
    unsigned                      header_sent:1;

    /* used to parse an upstream HTTP header */
    char                         *status_start;
    char                         *status_end;
    int                           status_count;
    int                           state;

    ngx_array_t                   states;    /* of ngx_http_proxy_state_t */

    char                         *action;
    ngx_http_log_ctx_t           *saved_ctx;
    ngx_log_handler_pt            saved_handler;
};


#define NGX_STALE                            1

#define NGX_HTTP_PROXY_PARSE_NO_HEADER       20

#define NGX_HTTP_PROXY_FT_ERROR              2
#define NGX_HTTP_PROXY_FT_TIMEOUT            4
#define NGX_HTTP_PROXY_FT_INVALID_HEADER     8
#define NGX_HTTP_PROXY_FT_HTTP_500           16
#define NGX_HTTP_PROXY_FT_HTTP_404           32
#define NGX_HTTP_PROXY_FT_BUSY_LOCK          64
#define NGX_HTTP_PROXY_FT_MAX_WAITING        128


void ngx_http_proxy_reinit_upstream(ngx_http_proxy_ctx_t *p);

int ngx_http_proxy_get_cached_response(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_process_cached_response(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_send_cached_response(ngx_http_proxy_ctx_t *p);

int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_copy_header(ngx_http_proxy_ctx_t *p,
                               ngx_http_proxy_headers_in_t *headers_in);



extern ngx_module_t  ngx_http_proxy_module;
extern ngx_http_header_t ngx_http_proxy_headers_in[];



#endif /* _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_ */
