
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x02
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x04
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x08
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x10
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x20
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x40
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x80


#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


typedef struct {
    time_t                          bl_time;
    ngx_uint_t                      bl_state;

    ngx_uint_t                      status;
    time_t                          time;
    
    ngx_str_t                      *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                      headers_in_hash;
} ngx_http_upstream_main_conf_t;


typedef struct {
    ngx_msec_t                      connect_timeout;
    ngx_msec_t                      send_timeout;
    ngx_msec_t                      read_timeout;

    size_t                          send_lowat;
    size_t                          header_buffer_size;
    size_t                          busy_buffers_size;
    size_t                          max_temp_file_size;
    size_t                          temp_file_write_size;

    ngx_uint_t                      next_upstream;
    ngx_uint_t                      method;

    ngx_bufs_t                      bufs;

    ngx_flag_t                      pass_request_headers;
    ngx_flag_t                      pass_request_body;

    ngx_flag_t                      redirect_errors;
    ngx_flag_t                      pass_unparsed_uri;
    ngx_flag_t                      cyclic_temp_file;

    ngx_flag_t                      pass_x_powered_by;
    ngx_flag_t                      pass_server;
    ngx_flag_t                      pass_date;
    ngx_flag_t                      pass_x_accel_expires;

    ngx_path_t                     *temp_path;

    ngx_str_t                       schema;
    ngx_str_t                       uri;
    ngx_str_t                      *location;
    ngx_str_t                       url;  /* used in proxy_rewrite_location */
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                       name;
    ngx_http_header_handler_pt      handler;
    ngx_uint_t                      offset;
    ngx_http_header_handler_pt      copy_handler;
    ngx_uint_t                      conf;
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                      headers;

    ngx_table_elt_t                *status;
    ngx_table_elt_t                *date;
    ngx_table_elt_t                *server;
    ngx_table_elt_t                *connection;

    ngx_table_elt_t                *expires;
    ngx_table_elt_t                *etag;
    ngx_table_elt_t                *x_accel_expires;

    ngx_table_elt_t                *content_type;
    ngx_table_elt_t                *content_length;

    ngx_table_elt_t                *last_modified;
    ngx_table_elt_t                *location;
    ngx_table_elt_t                *accept_ranges;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                *content_encoding;
#endif

    ngx_array_t                     cache_control;
} ngx_http_upstream_headers_in_t;


struct ngx_http_upstream_s {
    ngx_http_request_t             *request;

    ngx_peer_connection_t           peer;

    ngx_event_pipe_t                pipe;

    ngx_chain_t                    *request_bufs;

    ngx_output_chain_ctx_t          output;
    ngx_chain_writer_ctx_t          writer;

    ngx_http_upstream_conf_t       *conf;

    ngx_http_upstream_headers_in_t  headers_in;

    ngx_buf_t                       header_in;

    ngx_int_t                     (*create_request)(ngx_http_request_t *r);
    ngx_int_t                     (*reinit_request)(ngx_http_request_t *r);
    ngx_int_t                     (*process_header)(ngx_http_request_t *r);
    void                          (*abort_request)(ngx_http_request_t *r);
    void                          (*finalize_request)(ngx_http_request_t *r,
                                        ngx_int_t rc);
    ngx_int_t                     (*rewrite_redirect)(ngx_http_request_t *r,
                                        ngx_table_elt_t *h, size_t prefix);

    ngx_uint_t                      method;

    ngx_http_log_handler_pt         saved_log_handler;

    ngx_http_upstream_state_t      *state;
    ngx_array_t                     states;  /* of ngx_http_upstream_state_t */

    unsigned                        cachable:1;
    unsigned                        accel:1;

    unsigned                        request_sent:1;
    unsigned                        header_sent:1;
};


void ngx_http_upstream_init(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_upstream_module;

extern char *ngx_http_upstream_header_errors[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
