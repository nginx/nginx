#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_connection.h>


#define NGX_SYS_ERROR             -1
#define NGX_HTTP_INVALID_METHOD   -2
#define NGX_HTTP_INVALID_REQUEST  -3
#define NGX_HTTP_INVALID_HEADER   -4

#define NGX_HTTP_GET   1
#define NGX_HTTP_HEAD  2
#define NGX_HTTP_POST  3

#define NGX_HTTP_CONN_CLOSE       0
#define NGX_HTTP_CONN_KEEP_ALIVE  1

#define NGX_HTTP_OK               200


typedef struct {
    void *ctx;   /* STUB */
} ngx_http_module_t;

/* STUB */
#define ngx_get_module_ctx(r, module)  (module)->ctx

typedef struct {
    char *buff;
    char *pos;
    char *last;
    char *end;
} ngx_buff_t;

typedef struct {
    int     status;
    int     connection;
    size_t  content_length;
    char   *content_type;
    char   *charset;
    char   *etag;
    time_t  date;
    time_t  last_modified;
} ngx_http_header_out_t;

typedef struct ngx_http_request_s ngx_http_request_t;

struct ngx_http_request_s {
    int    method;

    int    http_version;
    int    http_major;
    int    http_minor;

    char  *uri;
    ngx_http_request_t *main;

    ngx_connection_t *connection;
    ngx_buff_t  *buff;
    ngx_pool_t  *pool;

    /* internal */
    unsigned  unusual_uri:1;
    unsigned  complex_uri:1;

    int    state;
    char  *uri_start;
    char  *uri_end;
    char  *uri_ext;
    char  *args_start;
    char  *header_name_start;
    char  *header_name_end;
    char  *header_start;
    char  *header_end;
#ifdef NGX_EVENT
    int  (*state_handler)(ngx_http_request_t *r);
#endif
};


#define NGX_INDEX "index.html"


int ngx_http_init_connection(ngx_connection_t *c);


#endif /* _NGX_HTTP_H_INCLUDED_ */
