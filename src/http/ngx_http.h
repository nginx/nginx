#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http_request.h>
#include <ngx_http_config.h>
#include <ngx_http_filter.h>
#include <ngx_http_core_module.h>


typedef struct {
    char  *action;
    char  *client;
    char  *url;
} ngx_http_log_ctx_t;


typedef int (*ngx_http_output_header_filter_p)(ngx_http_request_t *r);

typedef int (*ngx_http_output_body_filter_p)
                                   (ngx_http_request_t *r, ngx_chain_t *chain);


#define ngx_http_get_module_ctx(r, module)       r->ctx[module.ctx_index]

#define ngx_http_create_ctx(r, cx, module, size, error)                       \
            do {                                                              \
                ngx_test_null(cx, ngx_pcalloc(r->pool, size), error);         \
                r->ctx[module.ctx_index] = cx;                                \
            } while (0)

#define ngx_http_delete_ctx(r, module)                                        \
            r->ctx[module.ctx_index] = NULL;


/* STUB */
#define NGX_INDEX "index.html"


/* STUB */
int ngx_http_init(ngx_pool_t *pool, ngx_log_t *log);
/**/

void ngx_http_init_connection(ngx_connection_t *c);
int ngx_http_parse_request_line(ngx_http_request_t *r);
int ngx_http_parse_header_line(ngx_http_request_t *r, ngx_hunk_t *h);
int ngx_http_find_server_conf(ngx_http_request_t *r);
void ngx_http_handler(ngx_http_request_t *r);
void ngx_http_finalize_request(ngx_http_request_t *r, int error);
void ngx_http_writer(ngx_event_t *wev);


int ngx_http_send_last(ngx_http_request_t *r);
void ngx_http_close_request(ngx_http_request_t *r, int error);
void ngx_http_close_connection(ngx_connection_t *c);



int ngx_http_init_client_request_body(ngx_http_request_t *r, int size);
int ngx_http_read_client_request_body(ngx_http_request_t *r);
int ngx_http_init_client_request_body_chain(ngx_http_request_t *r);
void ngx_http_reinit_client_request_body_hunks(ngx_http_request_t *r);


int ngx_http_send_header(ngx_http_request_t *r);
int ngx_http_special_response_handler(ngx_http_request_t *r, int error);


time_t ngx_http_parse_time(char *value, size_t len);
size_t ngx_http_get_time(char *buf, time_t t);


int ngx_http_discard_body(ngx_http_request_t *r);



extern ngx_module_t  ngx_http_module;


extern int  ngx_max_module;


extern ngx_array_t  ngx_http_translate_handlers;
extern ngx_array_t  ngx_http_index_handlers;

extern int (*ngx_http_top_header_filter) (ngx_http_request_t *r);
extern int (*ngx_http_top_body_filter) (ngx_http_request_t *r, ngx_chain_t *ch);


/* STUB */
int ngx_http_log_handler(ngx_http_request_t *r);
/**/


#endif /* _NGX_HTTP_H_INCLUDED_ */
