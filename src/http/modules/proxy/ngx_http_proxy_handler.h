
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_
#define _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


typedef enum {
    NGX_HTTP_PROXY_CACHE_PASS = 1,
    NGX_HTTP_PROXY_CACHE_BYPASS,
    NGX_HTTP_PROXY_CACHE_AUTH,
    NGX_HTTP_PROXY_CACHE_PGNC,
    NGX_HTTP_PROXY_CACHE_MISS,
    NGX_HTTP_PROXY_CACHE_EXPR,
    NGX_HTTP_PROXY_CACHE_AGED,
    NGX_HTTP_PROXY_CACHE_HIT
} ngx_http_proxy_state_e;


typedef enum {
    NGX_HTTP_PROXY_CACHE_BPS = 1,
    NGX_HTTP_PROXY_CACHE_XAE,
    NGX_HTTP_PROXY_CACHE_CTL,
    NGX_HTTP_PROXY_CACHE_EXP,
    NGX_HTTP_PROXY_CACHE_MVD,
    NGX_HTTP_PROXY_CACHE_LMF,
    NGX_HTTP_PROXY_CACHE_PDE
} ngx_http_proxy_reason_e;


typedef struct {
    ngx_str_t                        url;
    ngx_str_t                        host;
    ngx_str_t                        uri;
    ngx_str_t                        host_header;
    ngx_str_t                        port_text;
    ngx_str_t                       *location;

    in_port_t                        port;

    unsigned                         default_port:1;
} ngx_http_proxy_upstream_conf_t;


typedef struct {
    size_t                           header_buffer_size;
    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    time_t                           default_expires;

    ngx_int_t                        lm_factor;

    ngx_uint_t                       next_upstream;
    ngx_uint_t                       use_stale;

    ngx_bufs_t                       bufs;

    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       cache;
    ngx_flag_t                       preserve_host;
    ngx_flag_t                       set_x_real_ip;
    ngx_flag_t                       add_x_forwarded_for;
    ngx_flag_t                       pass_server;
    ngx_flag_t                       pass_x_accel_expires;
    ngx_flag_t                       ignore_expires;

    ngx_path_t                      *cache_path;
    ngx_path_t                      *temp_path;

    ngx_http_busy_lock_t            *busy_lock;

    ngx_http_proxy_upstream_conf_t  *upstream;
    ngx_peers_t                     *peers;
} ngx_http_proxy_loc_conf_t;


/*
 * "EXPR/10/5/- 200/EXP/60 4"
 * "MISS/-/-/B 503/-/- -"
 * "EXPR/10/20/SB HIT/-/- -"
 * "EXPR/10/15/NB HIT/-/- -"
 */

typedef struct {
    ngx_http_proxy_state_e           cache_state;
    time_t                           expired;
    time_t                           bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    ngx_http_proxy_reason_e          reason;
    time_t                           time;
    time_t                           expires;

    ngx_str_t                       *peer;
} ngx_http_proxy_state_t;


typedef struct {
    ngx_list_t                       headers;
#if 0
    ngx_table_t                      headers;   /* it must be first field */
#endif

    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *cache_control;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;

    ngx_table_elt_t                 *connection;
    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;
    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *x_pad;

    off_t                            content_length_n;
} ngx_http_proxy_headers_in_t;


typedef struct {
    ngx_http_cache_ctx_t             ctx;
    ngx_uint_t                       status;
    ngx_str_t                        status_line;

    ngx_http_proxy_headers_in_t      headers_in;
} ngx_http_proxy_cache_t;


typedef struct {
    ngx_peer_connection_t            peer;
    ngx_uint_t                       status;
    ngx_str_t                        status_line;
    ngx_uint_t                       method;

    ngx_output_chain_ctx_t          *output_chain_ctx;
    ngx_event_pipe_t                *event_pipe;

    ngx_http_proxy_headers_in_t      headers_in;
} ngx_http_proxy_upstream_t;


typedef struct ngx_http_proxy_ctx_s  ngx_http_proxy_ctx_t;

struct ngx_http_proxy_ctx_s {
    ngx_http_request_t           *request;
    ngx_http_proxy_loc_conf_t    *lcf;
    ngx_http_proxy_upstream_t    *upstream;
    ngx_http_proxy_cache_t       *cache;

    ngx_buf_t                    *header_in;

    ngx_http_busy_lock_ctx_t      busy_lock;

    unsigned                      accel:1;

    unsigned                      cachable:1;
    unsigned                      stale:1;
    unsigned                      try_busy_lock:1;
    unsigned                      busy_locked:1;
    unsigned                      valid_header_in:1;

    unsigned                      request_sent:1;
    unsigned                      header_sent:1;


    /* used to parse an upstream HTTP header */
    ngx_uint_t                    status;
    u_char                       *status_start;
    u_char                       *status_end;
    ngx_uint_t                    status_count;
    ngx_uint_t                    parse_state;

    ngx_http_proxy_state_t       *state;
    ngx_array_t                   states;    /* of ngx_http_proxy_state_t */

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * all the time their types
     */

    char                         *action;
    ngx_http_log_ctx_t           *saved_ctx;
    ngx_log_handler_pt            saved_handler;
};


typedef struct {
    ngx_uint_t             connection;
    ngx_http_proxy_ctx_t  *proxy;
} ngx_http_proxy_log_ctx_t;


#define NGX_HTTP_PROXY_PARSE_NO_HEADER       30


#define NGX_HTTP_PROXY_FT_ERROR              0x02
#define NGX_HTTP_PROXY_FT_TIMEOUT            0x04
#define NGX_HTTP_PROXY_FT_INVALID_HEADER     0x08
#define NGX_HTTP_PROXY_FT_HTTP_500           0x10
#define NGX_HTTP_PROXY_FT_HTTP_404           0x20
#define NGX_HTTP_PROXY_FT_BUSY_LOCK          0x40
#define NGX_HTTP_PROXY_FT_MAX_WAITING        0x80


int ngx_http_proxy_request_upstream(ngx_http_proxy_ctx_t *p);

#if (NGX_HTTP_FILE_CACHE)

int ngx_http_proxy_get_cached_response(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_send_cached_response(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_is_cachable(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_update_cache(ngx_http_proxy_ctx_t *p);

void ngx_http_proxy_cache_busy_lock(ngx_http_proxy_ctx_t *p);

#endif

void ngx_http_proxy_check_broken_connection(ngx_event_t *ev);

void ngx_http_proxy_busy_lock_handler(ngx_event_t *rev);
void ngx_http_proxy_upstream_busy_lock(ngx_http_proxy_ctx_t *p);

size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len);
void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc);
void ngx_http_proxy_close_connection(ngx_http_proxy_ctx_t *p);

int ngx_http_proxy_parse_status_line(ngx_http_proxy_ctx_t *p);
int ngx_http_proxy_copy_header(ngx_http_proxy_ctx_t *p,
                               ngx_http_proxy_headers_in_t *headers_in);



extern ngx_module_t  ngx_http_proxy_module;
extern ngx_http_header_t ngx_http_proxy_headers_in[];



#endif /* _NGX_HTTP_PROXY_HANDLER_H_INCLUDED_ */
