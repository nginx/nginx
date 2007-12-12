
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_garbage_collector.h>


typedef struct ngx_http_request_s   ngx_http_request_t;
typedef struct ngx_http_upstream_s  ngx_http_upstream_t;
typedef struct ngx_http_log_ctx_s   ngx_http_log_ctx_t;

typedef ngx_int_t (*ngx_http_header_handler_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
typedef u_char *(*ngx_http_log_handler_pt)(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);


#if (NGX_HTTP_CACHE)
#include <ngx_http_cache.h>
#endif
/* STUB */
#include <ngx_http_cache.h>

#include <ngx_http_variables.h>
#include <ngx_http_request.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_config.h>
#include <ngx_http_busy_lock.h>
#include <ngx_http_core_module.h>
#include <ngx_http_script.h>

#if (NGX_HTTP_SSI)
#include <ngx_http_ssi_filter_module.h>
#endif
#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif


struct ngx_http_log_ctx_s {
    ngx_str_t           *client;
    ngx_http_request_t  *request;
    ngx_http_request_t  *current_request;
};


#define ngx_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define ngx_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


void ngx_http_init_connection(ngx_connection_t *c);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
int ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif

ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r,
    ngx_uint_t merge_slashes);
ngx_int_t ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, ngx_uint_t *flags);
ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_parse_multi_header_lines(ngx_array_t *headers,
    ngx_str_t *name, ngx_str_t *value);

ngx_int_t ngx_http_find_server_conf(ngx_http_request_t *r);
void ngx_http_update_location_config(ngx_http_request_t *r);
void ngx_http_handler(ngx_http_request_t *r);
void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

void ngx_http_empty_handler(ngx_event_t *wev);
void ngx_http_request_empty_handler(ngx_http_request_t *r);

#define NGX_HTTP_LAST   1
#define NGX_HTTP_FLUSH  2

ngx_int_t ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags);


ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler);

ngx_int_t ngx_http_send_header(ngx_http_request_t *r);
ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r,
    ngx_int_t error);


time_t ngx_http_parse_time(u_char *value, size_t len);
size_t ngx_http_get_time(char *buf, time_t t);



ngx_int_t ngx_http_discard_body(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_module;


extern ngx_uint_t  ngx_http_total_requests;
extern uint64_t    ngx_http_total_sent;


extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
extern ngx_http_output_body_filter_pt    ngx_http_top_body_filter;


#endif /* _NGX_HTTP_H_INCLUDED_ */
