
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
    time_t                      bl_time;
    ngx_uint_t                  bl_state;

    ngx_uint_t                  status;
    time_t                      time;
    
    ngx_str_t                  *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_msec_t                  connect_timeout;
    ngx_msec_t                  send_timeout;
    ngx_msec_t                  read_timeout;

    size_t                      send_lowat;
    size_t                      header_buffer_size;
    size_t                      busy_buffers_size;
    size_t                      max_temp_file_size;
    size_t                      temp_file_write_size;

    ngx_uint_t                  next_upstream;

    ngx_bufs_t                  bufs;

    ngx_flag_t                  redirect_errors;
    ngx_flag_t                  x_powered_by;
    ngx_flag_t                  cyclic_temp_file;

    ngx_path_t                 *temp_path;
} ngx_http_upstream_conf_t;


typedef struct ngx_http_upstream_s  ngx_http_upstream_t;

struct ngx_http_upstream_s {
    ngx_http_request_t         *request;

    ngx_peer_connection_t       peer;

    ngx_event_pipe_t            pipe;

    ngx_output_chain_ctx_t      output;
    ngx_chain_writer_ctx_t      writer;

    ngx_http_upstream_conf_t   *conf;

    ngx_buf_t                   header_in;

    ngx_int_t                 (*create_request)(ngx_http_request_t *r);
    ngx_int_t                 (*reinit_request)(ngx_http_request_t *r);
    ngx_int_t                 (*process_header)(ngx_http_request_t *r);
    ngx_int_t                 (*send_header)(ngx_http_request_t *r);
    void                      (*abort_request)(ngx_http_request_t *r);
    void                      (*finalize_request)(ngx_http_request_t *r,
                                                  ngx_int_t rc);
    ngx_uint_t                  method;

    ngx_str_t                   schema;
    ngx_str_t                   uri;
    ngx_str_t                  *location;

    ngx_http_log_ctx_t         *log_ctx;
    ngx_log_handler_pt          log_handler;
    ngx_http_log_ctx_t         *saved_log_ctx;
    ngx_log_handler_pt          saved_log_handler;

    ngx_http_upstream_state_t  *state;
    ngx_array_t                 states;    /* of ngx_http_upstream_state_t */

    unsigned                    cachable:1;

    unsigned                    request_sent:1;
    unsigned                    header_sent:1;
};


void ngx_http_upstream_init(ngx_http_request_t *r);
u_char *ngx_http_upstream_log_error(ngx_log_t *log, u_char *buf, size_t len);


extern char *ngx_http_upstream_header_errors[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
