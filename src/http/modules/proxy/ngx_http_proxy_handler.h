#ifndef _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_
#define _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t   host;
    ngx_str_t   uri;
    ngx_str_t   host_header;
    ngx_str_t   port_text;
    ngx_str_t  *location;
    int         port;
} ngx_http_proxy_upstream_t;


typedef struct {
    ngx_msec_t                  connect_timeout;
    ngx_msec_t                  send_timeout;
    ssize_t                     header_buffer_size;
    ngx_msec_t                  read_timeout;

    ngx_bufs_t                  bufs;
    ssize_t                     busy_buffers_size;

    ssize_t                     max_temp_file_size;
    ssize_t                     temp_file_write_size;
    int                         cyclic_temp_file;

    ngx_path_t                 *temp_path;

    ngx_http_proxy_upstream_t  *upstream;
    ngx_peers_t                *peers;
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_table_elt_t  *date;
    ngx_table_elt_t  *server;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *content_type;
    ngx_table_elt_t  *content_length;
    ngx_table_elt_t  *last_modified;
    ngx_table_elt_t  *accept_ranges;

    off_t             content_length_n;

    ngx_table_t      *headers;
} ngx_http_proxy_headers_in_t;


typedef struct ngx_http_proxy_ctx_s  ngx_http_proxy_ctx_t;

struct ngx_http_proxy_ctx_s {
    ngx_peer_connection_t         upstream;
    ngx_peer_t                   *peer;

    ngx_http_request_t           *request;
    ngx_http_proxy_loc_conf_t    *lcf;
    ngx_http_proxy_headers_in_t   headers_in;

    ngx_hunk_t                 *header_in;
    int                         status;
    ngx_str_t                   status_line;

    ngx_chain_t                *work_request_hunks;
    ngx_chain_t                *request_hunks;

    int                         method;

    ngx_event_pipe_t           *event_pipe;

    unsigned                    accel:1;
    unsigned                    cachable:1;
    unsigned                    fatal_error:1;
    unsigned                    request_sent:1;
    unsigned                    timedout:1;
    unsigned                    header_sent:1;

    /* used to parse an upstream HTTP header */
    char                       *status_start;
    char                       *status_end;
    int                         status_count;
    int                         state;

    char                       *action;
    ngx_http_log_ctx_t         *saved_ctx;
};


#define NGX_HTTP_PROXY_PARSE_NO_HEADER  20


#endif /* _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_ */
