#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001

#define NGX_HTTP_GET                       1
#define NGX_HTTP_HEAD                      2
#define NGX_HTTP_POST                      3

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_TOO_LONG_URI        12
#define NGX_HTTP_PARSE_INVALID_09_METHOD   13

#define NGX_HTTP_PARSE_HEADER_ERROR        14
#define NGX_HTTP_PARSE_INVALID_HEADER      14
#define NGX_HTTP_PARSE_TOO_LONG_HEADER     15
#define NGX_HTTP_PARSE_NO_HOST_HEADER      16
#define NGX_HTTP_PARSE_INVALID_CL_HEADER   17


#define NGX_HTTP_OK                        200
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_NOT_MODIFIED              304

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499

#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t         name;
    ngx_uint_t        offset;
} ngx_http_header_t;


typedef struct {
    ngx_table_t       headers;   /* it must be first field */

    ngx_table_elt_t  *host;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *if_modified_since;
    ngx_table_elt_t  *user_agent;
    ngx_table_elt_t  *referer;
    ngx_table_elt_t  *content_length;

    ngx_table_elt_t  *range;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t  *accept_encoding;
#endif

    ngx_table_elt_t  *authorization;

    ngx_table_elt_t  *keep_alive;

#if (NGX_HTTP_PROXY)
    ngx_table_elt_t  *x_forwarded_for;
#endif

    size_t            host_name_len;
    ssize_t           content_length_n;
    size_t            connection_type;
    ssize_t           keep_alive_n;
} ngx_http_headers_in_t;


typedef struct {
    off_t             start;
    off_t             end;
    ngx_str_t         content_range;
} ngx_http_range_t;


typedef struct {
    ngx_table_t       headers;   /* it must be first field */

    ngx_uint_t        status;
    ngx_str_t         status_line;

    ngx_table_elt_t  *server;
    ngx_table_elt_t  *date;
    ngx_table_elt_t  *content_type;
    ngx_table_elt_t  *content_length;
    ngx_table_elt_t  *content_encoding;
    ngx_table_elt_t  *location;
    ngx_table_elt_t  *last_modified;
    ngx_table_elt_t  *content_range;
    ngx_table_elt_t  *accept_ranges;

    ngx_str_t         charset;
    ngx_array_t       ranges;

    off_t             content_length_n;
    u_char           *etag;
    time_t            date_time;
    time_t            last_modified_time;
} ngx_http_headers_out_t;


typedef struct {
    ngx_temp_file_t   *temp_file;
    ngx_chain_t       *bufs;
    ngx_hunk_t        *buf;
    size_t             rest;
    size_t             buf_size;
    void             (*handler) (void *data); 
    void              *data;
} ngx_http_request_body_t;


struct ngx_http_cleanup_s {
    union {
        struct {
            ngx_fd_t                 fd;
            u_char                  *name;
        } file;

        struct {
            ngx_http_cache_hash_t   *hash;
            ngx_http_cache_t        *cache;
        } cache;
    } data;

    unsigned                         valid:1;
    unsigned                         cache:1;
};


typedef int (*ngx_http_handler_pt)(ngx_http_request_t *r);

struct ngx_http_request_s {
    ngx_connection_t         *connection;

    void                    **ctx;
    void                    **main_conf;
    void                    **srv_conf;
    void                    **loc_conf;

    ngx_http_cache_t         *cache;

    ngx_file_t                file;

    ngx_pool_t               *pool;
    ngx_hunk_t               *header_in;

    ngx_http_headers_in_t     headers_in;
    ngx_http_headers_out_t    headers_out;

    ngx_http_request_body_t  *request_body;

#if 0
    ngx_temp_file_t     *temp_file;
    ngx_chain_t         *request_hunks;
    ngx_hunk_t          *request_body_hunk;
    size_t               remaining_body_len;
    void               (*request_body_handler) (void *data); 
    void                *data;
#endif

    time_t               lingering_time;

    ngx_uint_t           method;
    ngx_uint_t           http_version;
    ngx_uint_t           http_major;
    ngx_uint_t           http_minor;

    ngx_str_t            request_line;
    ngx_str_t            uri;
    ngx_str_t            args;
    ngx_str_t            exten;
    ngx_str_t            unparsed_uri;

    ngx_http_request_t  *main;

    uint32_t             in_addr;
    ngx_uint_t           port;
    ngx_str_t           *port_name;    /* ":80" */
    ngx_str_t           *server_name;
    ngx_array_t         *virtual_names;

    ngx_uint_t           phase;
    ngx_int_t            phase_handler;
    ngx_http_handler_pt  content_handler;

    ngx_array_t          cleanup;

    /* used to learn the Apache compatible response length without a header */
    size_t               header_size;

    u_char              *discarded_buffer;
    void               **err_ctx;
    ngx_uint_t           err_status;

    unsigned             http_state:4;

    /* URI is not started with '/' - "GET http://" */
    unsigned             unusual_uri:1;
    /* URI with "/.", "%" and on Win32 with "//" */
    unsigned             complex_uri:1;
    unsigned             header_timeout_set:1;

    unsigned             proxy:1;
    unsigned             bypass_cache:1;
    unsigned             no_cache:1;

#if 0
    unsigned             cachable:1;
#endif
    unsigned             pipeline:1;

    /* can we use sendfile ? */
    unsigned             sendfile:1;

    unsigned             chunked:1;
    unsigned             header_only:1;
    unsigned             keepalive:1;
    unsigned             lingering_close:1;
    unsigned             closed:1;

    /* TODO: use the filter flags or the separate bits ???? */
    u_int                filter;

    /* used to parse HTTP headers */
    ngx_int_t            state;
    u_char              *uri_start;
    u_char              *uri_end;
    u_char              *uri_ext;
    u_char              *args_start;
    u_char              *request_start;
    u_char              *request_end;
    u_char              *header_name_start;
    u_char              *header_name_end;
    u_char              *header_start;
    u_char              *header_end;
};


extern ngx_http_header_t ngx_http_headers_in[];
extern ngx_http_header_t ngx_http_headers_out[];



#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
