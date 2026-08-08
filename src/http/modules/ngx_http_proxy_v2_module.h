
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_MODULE_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>
#include <ngx_http_proxy_v2_frame.h>


typedef enum {
    ngx_http_proxy_v2_phase_header = 0,
    ngx_http_proxy_v2_phase_non_buffered,
    ngx_http_proxy_v2_phase_buffered
} ngx_http_proxy_v2_phase_e;


typedef struct {
    ngx_connection_t                *connection;
    ngx_http_request_t              *request;
    void                            *data;

    ngx_http_proxy_v2_parse_t        parse;
    ngx_buf_t                        buffer;

    size_t                         init_window;
    size_t                         send_window;
    size_t                         recv_window;
    ngx_uint_t                     last_stream_id;
    ngx_uint_t                     continuation_stream_id;
    ngx_uint_t                     goaway_stream_id;
    ngx_uint_t                     goaway_error;
    ngx_uint_t                     pings;
    ngx_uint_t                     settings;

    ngx_buf_t                      connection_start;
    ngx_chain_t                   *out;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_chain_writer_ctx_t         writer;

    unsigned                       connected:1;
    unsigned                       goaway:1;
    unsigned                       new_frame:1;
} ngx_http_proxy_v2_conn_t;


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_uint_t                     fragment_state;

    ngx_chain_t                   *in;
    ngx_chain_t                   *out;
    ngx_chain_t                   *frames;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_http_proxy_v2_conn_t      *connection;

    ngx_uint_t                     id;
    ngx_http_proxy_v2_phase_e      phase;

    off_t                          length;

    size_t                         init_window;
    ssize_t                        send_window;
    size_t                         recv_window;

    ngx_uint_t                     index;
    ngx_str_t                      name;
    ngx_str_t                      value;

    u_char                        *field_end;
    size_t                         header_limit;
    size_t                         field_length;
    size_t                         field_rest;
    u_char                         field_state;

    unsigned                       literal:1;
    unsigned                       field_huffman:1;

    unsigned                       header_sent:1;
    unsigned                       output_closed:1;
    unsigned                       output_blocked:1;
    unsigned                       response_header_done:1;
    unsigned                       end_stream:1;
    unsigned                       done:1;
    unsigned                       status:1;
    unsigned                       rst:1;
} ngx_http_proxy_v2_ctx_t;


static ngx_inline ngx_int_t
ngx_http_proxy_v2_connection_output_pending(ngx_connection_t *c,
    ngx_http_proxy_v2_conn_t *h2c)
{
    return h2c->out != NULL
           || h2c->busy != NULL
           || h2c->writer.out != NULL
           || (c && c->buffered);
}


static ngx_inline ngx_int_t
ngx_http_proxy_v2_output_pending(ngx_connection_t *c,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_proxy_v2_conn_t  *h2c;

    h2c = ctx->connection;

    return ctx->out != NULL
           || ctx->frames != NULL
           || ctx->busy != NULL
           || ctx->output_blocked
           || ngx_http_proxy_v2_connection_output_pending(c, h2c);
}


static ngx_inline ngx_int_t
ngx_http_proxy_v2_response_closed(ngx_http_proxy_v2_ctx_t *ctx)
{
    return ctx->done
           || (ctx->response_header_done && ctx->end_stream);
}


static ngx_inline ngx_int_t
ngx_http_proxy_v2_cached(ngx_http_request_t *r)
{
#if (NGX_HTTP_CACHE)
    return r->cached;
#else
    return 0;
#endif
}


ngx_chain_t *ngx_http_proxy_v2_get_buf(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
ngx_int_t ngx_http_proxy_v2_process_trailers(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);


extern ngx_module_t  ngx_http_proxy_v2_module;


#endif /* _NGX_HTTP_PROXY_V2_MODULE_H_INCLUDED_ */
