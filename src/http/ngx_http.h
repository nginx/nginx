
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_garbage_collector.h>

typedef struct ngx_http_request_s  ngx_http_request_t;
typedef struct ngx_http_log_ctx_s  ngx_http_log_ctx_t;
typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;
typedef struct ngx_http_in_addr_s  ngx_http_in_addr_t;

#if (NGX_HTTP_CACHE)
#include <ngx_http_cache.h>
#endif
/* STUB */
#include <ngx_http_cache.h>

#include <ngx_http_upstream.h>
#include <ngx_http_request.h>
#include <ngx_http_config.h>
#include <ngx_http_busy_lock.h>
#include <ngx_http_log_handler.h>
#include <ngx_http_core_module.h>

#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif


struct ngx_http_log_ctx_s {
    ngx_str_t           *client;
    ngx_http_request_t  *request;
};


#define ngx_http_get_module_ctx(r, module)       r->ctx[module.ctx_index]
#define ngx_http_get_module_err_ctx(r, module)                                \
         (r->err_ctx ? r->err_ctx[module.ctx_index] : r->ctx[module.ctx_index])

/* STUB */
#define ngx_http_create_ctx(r, cx, module, size, error)                       \
            do {                                                              \
                ngx_test_null(cx, ngx_pcalloc(r->pool, size), error);         \
                r->ctx[module.ctx_index] = cx;                                \
            } while (0)
/**/

#define ngx_http_set_ctx(r, c, module)                                        \
            r->ctx[module.ctx_index] = c;

#define ngx_http_delete_ctx(r, module)                                        \
            r->ctx[module.ctx_index] = NULL;


void ngx_http_init_connection(ngx_connection_t *c);

ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);
ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r);
ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_find_server_conf(ngx_http_request_t *r);
void ngx_http_handler(ngx_http_request_t *r);
void ngx_http_finalize_request(ngx_http_request_t *r, int error);
void ngx_http_writer(ngx_event_t *wev);

void ngx_http_empty_handler(ngx_event_t *wev);

ngx_int_t ngx_http_send_last(ngx_http_request_t *r);
void ngx_http_close_request(ngx_http_request_t *r, int error);
void ngx_http_close_connection(ngx_connection_t *c);


ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
                                 ngx_http_client_body_handler_pt post_handler);

ngx_int_t ngx_http_send_header(ngx_http_request_t *r);
ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r, int error);


time_t ngx_http_parse_time(u_char *value, size_t len);
size_t ngx_http_get_time(char *buf, time_t t);



ngx_int_t ngx_http_discard_body(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_module;


extern ngx_uint_t  ngx_http_total_requests;
extern uint64_t    ngx_http_total_sent;


extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
extern ngx_http_output_body_filter_pt    ngx_http_top_body_filter;


/* STUB */
ngx_int_t ngx_http_log_handler(ngx_http_request_t *r);
/**/


#endif /* _NGX_HTTP_H_INCLUDED_ */
