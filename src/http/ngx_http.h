#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_types.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_files.h>
#include <ngx_connection.h>
#include <ngx_conf_file.h>

/* STUB */
#include <ngx_event_timer.h>

#define NGX_HTTP_VERSION_9           9
#define NGX_HTTP_VERSION_10       1000
#define NGX_HTTP_VERSION_11       1001

#define NGX_HTTP_GET   1
#define NGX_HTTP_HEAD  2
#define NGX_HTTP_POST  3

#define NGX_HTTP_CONN_CLOSE       0
#define NGX_HTTP_CONN_KEEP_ALIVE  1


#define NGX_HTTP_PARSE_HEADER_DONE      1
#define NGX_HTTP_PARSE_INVALID_METHOD   10
#define NGX_HTTP_PARSE_INVALID_REQUEST  11
#define NGX_HTTP_PARSE_TOO_LONG_URI     12
#define NGX_HTTP_PARSE_INVALID_HEAD     13
#define NGX_HTTP_PARSE_INVALID_HEADER   14
#define NGX_HTTP_PARSE_TOO_LONG_HEADER  15
#define NGX_HTTP_PARSE_NO_HOST_HEADER   16


#define NGX_HTTP_OK                     200

#define NGX_HTTP_SPECIAL_RESPONSE       300
#define NGX_HTTP_MOVED_PERMANENTLY      301
#define NGX_HTTP_MOVED_TEMPORARILY      302
#define NGX_HTTP_NOT_MODIFIED           304

#define NGX_HTTP_BAD_REQUEST            400
#define NGX_HTTP_FORBIDDEN              403
#define NGX_HTTP_NOT_FOUND              404
#define NGX_HTTP_REQUEST_TIME_OUT       408
#define NGX_HTTP_REQUEST_URI_TOO_LARGE  414

#define NGX_HTTP_INTERNAL_SERVER_ERROR  500
#define NGX_HTTP_NOT_IMPLEMENTED        501
#define NGX_HTTP_BAD_GATEWAY            502
#define NGX_HTTP_SERVICE_UNAVAILABLE    503
#define NGX_HTTP_GATEWAY_TIME_OUT       504



#define NGX_HTTP_STATIC_HANDLER     0
#define NGX_HTTP_DIRECTORY_HANDLER  1


typedef struct {
    ngx_str_t  name;
    int        offset;
} ngx_http_header_t;


typedef struct {
    size_t            host_name_len;

    ngx_table_elt_t  *host;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *if_modified_since;
    ngx_table_elt_t  *accept_encoding;

    ngx_table_elt_t  *user_agent;

    ngx_table_t      *headers;
} ngx_http_headers_in_t;


typedef struct {
    int               status;
    ngx_str_t         status_line;

    ngx_table_elt_t  *server;
    ngx_table_elt_t  *date;
    ngx_table_elt_t  *content_type;
    ngx_table_elt_t  *location;
    ngx_table_elt_t  *last_modified;

    ngx_table_t      *headers;

    off_t             content_length;
    char             *charset;
    char             *etag;
    time_t            date_time;
    time_t            last_modified_time;
} ngx_http_headers_out_t;


typedef struct ngx_http_request_s ngx_http_request_t;

struct ngx_http_request_s {
    ngx_connection_t    *connection;

    void               **ctx;
    void               **srv_conf;
    void               **loc_conf;

    ngx_file_t           file;

    ngx_pool_t          *pool;
    ngx_hunk_t          *header_in;

    ngx_http_headers_in_t   headers_in;
    ngx_http_headers_out_t  headers_out;

    int  (*handler)(ngx_http_request_t *r);

    time_t  lingering_time;

    int                  method;
    int                  http_version;
    int                  http_major;
    int                  http_minor;

    ngx_str_t            request_line;
    ngx_str_t            uri;
    ngx_str_t            args;
    ngx_str_t            exten;
    ngx_http_request_t  *main;

    u_int       in_addr;

    int         port;
    ngx_str_t   port_name;

    int         filter;

    ssize_t     client_content_length;
    char       *discarded_buffer;

    ngx_str_t   path;
    int         path_err;

    unsigned  pipeline:1;
    unsigned  keepalive:1;
    unsigned  lingering_close:1;

    unsigned  header_read:1;
    unsigned  header_timeout_set:1;

    unsigned  logging:1;

    unsigned  header_only:1;
    unsigned  unusual_uri:1;  /* URI is not started with '/' - "GET http://" */
    unsigned  complex_uri:1;  /* URI with "/." or with "//" (WIN32) */
    unsigned  path_not_found:1;
#ifdef NGX_EVENT
    unsigned  write_level_event:1;
#endif

    int    state;
    char  *uri_start;
    char  *uri_end;
    char  *uri_ext;
    char  *args_start;
    char  *request_start;
    char  *request_end;
    char  *header_name_start;
    char  *header_name_end;
    char  *header_start;
    char  *header_end;
#ifdef NGX_EVENT
    int  (*state_handler)(ngx_http_request_t *r);
#endif
};


typedef struct {
    char  *action;
    char  *client;
    char  *url;
} ngx_http_log_ctx_t;


typedef int (*ngx_http_handler_pt)(ngx_http_request_t *r);

typedef int (*ngx_http_output_header_filter_p)(ngx_http_request_t *r);

typedef int (*ngx_http_output_body_filter_p)
                                   (ngx_http_request_t *r, ngx_chain_t *chain);


#define ngx_http_get_module_ctx(r, module)       r->ctx[module.index]

#define ngx_http_create_ctx(r, cx, module, size, error)                       \
            do {                                                              \
                ngx_test_null(cx, ngx_pcalloc(r->pool, size), error);         \
                r->ctx[module.index] = cx;                                    \
            } while (0)



/* STUB */
#define NGX_INDEX "index.html"


/* STUB */
int ngx_http_init(ngx_pool_t *pool, ngx_log_t *log);
/**/

int ngx_http_init_connection(ngx_connection_t *c);
int ngx_read_http_request_line(ngx_http_request_t *r);
int ngx_read_http_header_line(ngx_http_request_t *r, ngx_hunk_t *h);
int ngx_http_handler(ngx_http_request_t *r);


int ngx_http_send_header(ngx_http_request_t *r);
int ngx_http_special_response_handler(ngx_http_request_t *r, int error);


time_t ngx_http_parse_time(char *value, size_t len);
size_t ngx_http_get_time(char *buf, time_t t);


int ngx_http_discard_body(ngx_http_request_t *r);




extern int  ngx_max_module;
extern ngx_array_t  ngx_http_servers;


extern int  ngx_http_post_accept_timeout;
extern int  ngx_http_connection_pool_size;
extern int  ngx_http_request_pool_size;
extern int  ngx_http_client_header_timeout;
extern int  ngx_http_client_header_buffer_size;
extern int  ngx_http_large_client_header;
extern int  ngx_http_discarded_buffer_size;

extern int  ngx_http_url_in_error_log;

extern ngx_array_t  ngx_http_translate_handlers;
extern ngx_array_t  ngx_http_index_handlers;


/* STUB */
int ngx_http_log_handler(ngx_http_request_t *r);
/**/


#endif /* _NGX_HTTP_H_INCLUDED_ */
