#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_types.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_files.h>
#include <ngx_connection.h>
#include <ngx_config_command.h>


#define NGX_HTTP_VERSION_10       1000

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


#define NGX_HTTP_OK                     200
#define NGX_HTTP_SPECIAL_RESPONSE       300
#define NGX_HTTP_MOVED_PERMANENTLY      301
#define NGX_HTTP_MOVED_TEMPORARILY      302
#define NGX_HTTP_NOT_MODIFIED           304
#define NGX_HTTP_BAD_REQUEST            400
#define NGX_HTTP_NOT_FOUND              404
#define NGX_HTTP_REQUEST_URI_TOO_LARGE  414
#define NGX_HTTP_INTERNAL_SERVER_ERROR  500


#define NGX_HTTP_STATIC_HANDLER     0
#define NGX_HTTP_DIRECTORY_HANDLER  1



typedef struct {
    char          *doc_root;
    size_t         doc_root_len;

    size_t         connection_pool_size;
    size_t         request_pool_size;

    size_t         header_buffer_size;
    size_t         discarded_buffer_size;

    ngx_msec_t     header_timeout;
    ngx_msec_t     lingering_timeout;
    time_t         lingering_time;
} ngx_http_server_t;


typedef struct {
    int    len;
    char  *data;
    int    offset;
} ngx_http_header_t;


typedef struct {
    ngx_table_elt_t  *host;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *if_modified_since;
    ngx_table_elt_t  *user_agent;
    ngx_table_elt_t  *accept_encoding;

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
    ngx_file_t  file;

#if 0
    ngx_str_t   filename;
    ngx_file_info_t fileinfo;
    ngx_fd_t  fd;
    int    filename_len;
#endif

    void  **ctx;
    void  **loc_conf;
    void  **srv_conf;

    ngx_pool_t  *pool;
    ngx_hunk_t  *header_in;

    ngx_http_headers_in_t   headers_in;
    ngx_http_headers_out_t  headers_out;

    int  (*handler)(ngx_http_request_t *r);

    int    method;

    time_t  lingering_time;

    int    http_version;
    int    http_major;
    int    http_minor;

    ngx_str_t  request_line;
    ngx_str_t  uri;
    ngx_str_t  exten;
    ngx_http_request_t *main;

    ngx_connection_t  *connection;
    ngx_http_server_t *server;

    int       filter;

    ssize_t   client_content_length;
    char     *discarded_buffer;

    unsigned  keepalive:1;
    unsigned  lingering_close:1;

    unsigned  header_read:1;
    unsigned  header_timeout:1;

    unsigned  logging:1;

    unsigned  header_only:1;
    unsigned  unusual_uri:1;  /* URI is not started with '/' - "GET http://" */
    unsigned  complex_uri:1;  /* URI with "/." or with "//" (WIN32) */

    int    state;
    char  *uri_start;
    char  *uri_end;
    char  *uri_ext;
    char  *args_start;
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


typedef struct {
    int               index;

    void           *(*create_srv_conf)(ngx_pool_t *p);
    void           *(*create_loc_conf)(ngx_pool_t *p);
    ngx_command_t    *commands;

    int             (*init_module)(ngx_pool_t *p);

    int             (*translate_handler)(ngx_http_request_t *r);

    int             (*output_header_filter) (ngx_http_request_t *r);
    int             (*next_output_header_filter) (ngx_http_request_t *r);

    int             (*output_body_filter)();
    int             (*next_output_body_filter)
                                      (ngx_http_request_t *r, ngx_chain_t *ch);

#if 0
    int             (*next_output_body_filter)(int (**next_filter)
                                     (ngx_http_request_t *r, ngx_chain_t *ch));
#endif
} ngx_http_module_t;


#define NGX_HTTP_MODULE  0

#define ngx_get_module_loc_conf(r, module)  r->loc_conf[module.index]
#define ngx_get_module_ctx(r, module)  r->ctx[module.index]

#define ngx_http_create_ctx(r, cx, module, size)                              \
            do {                                                              \
               ngx_test_null(cx, ngx_pcalloc(r->pool, size), NGX_ERROR);      \
               r->ctx[module.index] = cx;                                     \
            } while (0)



/* STUB */
#define NGX_INDEX "index.html"


/* STUB */
int ngx_http_init(ngx_pool_t *pool, ngx_log_t *log);
/**/

int ngx_http_init_connection(ngx_connection_t *c);


int ngx_http_discard_body(ngx_http_request_t *r);


extern int ngx_max_module;

extern ngx_http_module_t *ngx_http_modules[];



#endif /* _NGX_HTTP_H_INCLUDED_ */
