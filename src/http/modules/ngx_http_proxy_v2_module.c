
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>


/* Upstream's initial header/trailer arrays and amortized list growth. */

#define NGX_HTTP_PROXY_V2_HEADER_BLOCK_COST                                   \
    (ngx_align(8 * sizeof(ngx_table_elt_t), NGX_ALIGNMENT)                     \
     + ngx_align(2 * sizeof(ngx_table_elt_t), NGX_ALIGNMENT))

#define NGX_HTTP_PROXY_V2_HEADER_FIELD_COST                                   \
    (ngx_align(sizeof(ngx_table_elt_t), NGX_ALIGNMENT)                         \
     + ngx_align(sizeof(ngx_list_part_t), NGX_ALIGNMENT))

#define NGX_HTTP_PROXY_V2_MAX_CONTROL  64


typedef enum {
    ngx_http_proxy_v2_st_start = 0,
    ngx_http_proxy_v2_st_length_2,
    ngx_http_proxy_v2_st_length_3,
    ngx_http_proxy_v2_st_type,
    ngx_http_proxy_v2_st_flags,
    ngx_http_proxy_v2_st_stream_id,
    ngx_http_proxy_v2_st_stream_id_2,
    ngx_http_proxy_v2_st_stream_id_3,
    ngx_http_proxy_v2_st_stream_id_4,
    ngx_http_proxy_v2_st_payload,
    ngx_http_proxy_v2_st_padding
} ngx_http_proxy_v2_state_e;


typedef struct {
    ngx_queue_t                    idle;
    ngx_uint_t                     nidle;
} ngx_http_proxy_v2_srv_conf_t;


typedef struct {
    ngx_rbtree_node_t              node;
    ngx_queue_t                    queue;
    ngx_http_proxy_v2_srv_conf_t  *srv_conf;
    ngx_http_upstream_srv_conf_t  *upstream;
    ngx_http_upstream_conf_t      *conf;
    ngx_sockaddr_t                 sockaddr;
    socklen_t                      socklen;

    ngx_sockaddr_t                 local_sockaddr;
    socklen_t                      local_socklen;
    int                            socket_type;
    int                            rcvbuf;
    int                            sndbuf;

    ngx_log_t                      log;
    ngx_connection_t              *connection;
    ngx_pool_t                    *pool;
    ngx_queue_t                    sessions_queue;
    ngx_uint_t                     ref_count;

    ngx_chain_t                   *control;
    ngx_chain_t                  **control_last;
    ngx_chain_t                   *control_free;
    ngx_chain_t                   *control_busy;
    ngx_uint_t                     controls;

    ngx_rbtree_t                   streams;
    ngx_rbtree_node_t              sentinel;
    ngx_uint_t                     nstreams;

    ngx_http_proxy_v2_state_e      state;
    ngx_uint_t                     frame_state;
    size_t                         rest;
    ngx_uint_t                     stream_id;
    ngx_uint_t                     header_stream_id;
    u_char                         type;
    u_char                         flags;
    u_char                         padding;

    ngx_uint_t                     error;
    ngx_uint_t                     frame_goaway_last_stream_id;
    ngx_uint_t                     window_update;
    ngx_uint_t                     setting_id;
    ngx_uint_t                     setting_value;
    u_char                         ping_data[8];

    ngx_uint_t                     fragment_state;
    ngx_uint_t                     index;

    ngx_str_t                      name;
    ngx_str_t                      value;
    ngx_str_t                     *field;
    u_char                        *field_end;

    size_t                         header_limit;
    size_t                         header_block_limit;
    size_t                         header_size;
    size_t                         field_length;
    size_t                         field_rest;
    u_char                         field_state;

    size_t                         init_window;
    size_t                         send_window;
    size_t                         recv_window;
    ngx_uint_t                     last_stream_id;

    ngx_uint_t                     goaway_last_stream_id;
    ngx_uint_t                     goaway_error;

    unsigned                       literal:1;
    unsigned                       field_huffman:1;
    unsigned                       header_discard:1;
    unsigned                       goaway:1;
    unsigned                       registered:1;
    unsigned                       idle:1;
    unsigned                       closing:1;
    unsigned                       transparent:1;
    unsigned                       so_keepalive:1;
} ngx_http_proxy_v2_session_t;


typedef struct {
    ngx_connection_t               connection;
    ngx_event_t                    read;
    ngx_event_t                    write;
    ngx_rbtree_node_t              node;
    ngx_http_proxy_v2_session_t   *session;
    ngx_http_request_t            *request;
    ngx_uint_t                     id;

    size_t                         header_budget;

    ngx_chain_t                   *in;

    ssize_t                        send_window;
    size_t                         recv_window;

    off_t                          length;

    ngx_uint_t                     error;

    unsigned                       header_sent:1;
    unsigned                       output_closed:1;
    unsigned                       response_received:1;
    unsigned                       end_stream:1;
    unsigned                       input_closed:1;
    unsigned                       done:1;
    unsigned                       rst:1;
} ngx_http_proxy_v2_stream_t;


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_http_proxy_v2_stream_t    *stream;

    unsigned                       output_blocked:1;
    unsigned                       status:1;
#if (NGX_HTTP_CACHE)
    unsigned                       cache_header_failed:1;
    unsigned                       cache_buffer_expanded:1;
#endif
} ngx_http_proxy_v2_ctx_t;


typedef struct {
    ngx_http_request_t             *request;
    ngx_http_proxy_v2_ctx_t        *ctx;
    ngx_http_proxy_v2_stream_t     *stream;
    ngx_http_proxy_v2_session_t    *session;

    void                           *data;
    ngx_event_get_peer_pt           get;
    ngx_event_free_peer_pt          free;
    ngx_event_notify_peer_pt        notify;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt   set_session;
    ngx_event_save_peer_session_pt  save_session;
#endif
} ngx_http_proxy_v2_peer_t;


typedef struct {
    u_char                        length_0;
    u_char                        length_1;
    u_char                        length_2;
    u_char                        type;
    u_char                        flags;
    u_char                        stream_id_0;
    u_char                        stream_id_1;
    u_char                        stream_id_2;
    u_char                        stream_id_3;
} ngx_http_proxy_v2_frame_t;


static ngx_int_t ngx_http_proxy_v2_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_init_header_budget(ngx_http_request_t *r,
    size_t *budget);
static ngx_int_t ngx_http_proxy_v2_account_header(ngx_http_request_t *r,
    size_t size);
static u_char *ngx_http_proxy_v2_alloc_header(ngx_http_request_t *r, size_t len);
static ngx_int_t ngx_http_proxy_v2_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_proxy_v2_init_stream(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_create_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_peer_t *peer);
static void ngx_http_proxy_v2_connection_handler(ngx_event_t *ev);
static void ngx_http_proxy_v2_stream_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_proxy_v2_test_io(ngx_connection_t *c,
    ngx_uint_t write);
static void ngx_http_proxy_v2_set_read_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static void ngx_http_proxy_v2_set_write_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static ssize_t ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_http_proxy_v2_recv_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ssize_t ngx_http_proxy_v2_handle_stream_read(ngx_connection_t *c,
    ssize_t n);
static ngx_chain_t *ngx_http_proxy_v2_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_http_proxy_v2_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_v2_process_header(ngx_http_request_t *r);
#if (NGX_HTTP_CACHE)
static void ngx_http_proxy_v2_check_cache_format(ngx_http_request_t *r);
static void ngx_http_proxy_v2_create_cache_header(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_proxy_v2_filter_init(void *data);
static ngx_int_t ngx_http_proxy_v2_finish_response(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_process_body(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, size_t *size);
static ngx_int_t ngx_http_proxy_v2_non_buffered_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_v2_process_control_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_process_closed_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, size_t *size);
static ngx_int_t ngx_http_proxy_v2_process_header_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_parse_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_frame(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_parse_data(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b, size_t *size);
static ngx_int_t ngx_http_proxy_v2_process_data(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b, size_t size);
static ngx_int_t ngx_http_proxy_v2_parse_header(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_fragment(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_field(
    ngx_http_proxy_v2_session_t *sess, ngx_str_t *field, u_char *p,
    size_t size);
static ngx_int_t ngx_http_proxy_v2_alloc_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_process_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_clear_header(ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_validate_header_name(ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_validate_header_value(ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_parse_rst_stream(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_settings(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_send_settings_ack(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_send_window_update(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream);
static ngx_chain_t *ngx_http_proxy_v2_get_control(
    ngx_http_proxy_v2_session_t *sess);

static ngx_chain_t *ngx_http_proxy_v2_get_buf(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static void ngx_http_proxy_v2_detach_stream(
    ngx_http_proxy_v2_stream_t *stream);
static ngx_rbtree_key_t ngx_http_proxy_v2_session_key(ngx_http_upstream_t *u);
static ngx_http_proxy_v2_session_t *
    ngx_http_proxy_v2_find_session(ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_match_session(
    ngx_http_proxy_v2_session_t *session, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_reusable_session(
    ngx_http_proxy_v2_session_t *session);
static ngx_http_proxy_v2_session_t *
    ngx_http_proxy_v2_create_session(ngx_http_request_t *r);
static u_char *ngx_http_proxy_v2_log_error(ngx_log_t *log, u_char *buf,
    size_t len);
static void ngx_http_proxy_v2_close_connection(ngx_connection_t *c);
static void ngx_http_proxy_v2_close_session(ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_release_session(
    ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_remove_idle(ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_idle_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static void ngx_http_proxy_v2_notify_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_v2_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_save_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_ssl_save_session(ngx_connection_t *c);
#endif

static void ngx_http_proxy_v2_session_cleanup(void *data);

static void ngx_http_proxy_v2_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static void *ngx_http_proxy_v2_create_srv_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_proxy_v2_init_process(ngx_cycle_t *cycle);
static void ngx_http_proxy_v2_exit_process(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_proxy_v2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_proxy_v2_create_srv_conf,     /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_v2_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_v2_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_proxy_v2_init_process,        /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_proxy_v2_exit_process,        /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_rbtree_t       ngx_http_proxy_v2_sessions;
static ngx_rbtree_node_t  ngx_http_proxy_v2_sessions_sentinel;
static ngx_queue_t        ngx_http_proxy_v2_sessions_queue;


static u_char  ngx_http_proxy_v2_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


ngx_int_t
ngx_http_proxy_v2_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_loc_conf_t   *plcf;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_main_conf_t  *pmcf;
#endif

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_v2_module);

    ngx_http_set_ctx(r, &ctx->ctx, ngx_http_proxy_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    plcf->upstream.preserve_output = 1;

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
        ctx->ctx.vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if (NGX_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif

    } else {
        if (ngx_http_proxy_eval(r, &ctx->ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#if (NGX_HTTP_SSL)
    ngx_str_set(&u->ssl_alpn_protocol, NGX_HTTP_V2_ALPN_PROTO);
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_module;

    u->conf = &plcf->upstream;
    u->keepalive_pass = 1;

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_proxy_v2_create_request;
    u->reinit_request = ngx_http_proxy_v2_reinit_request;
    u->init_peer = ngx_http_proxy_v2_init_peer;
    u->init_connection = ngx_http_proxy_v2_init_stream;
    u->process_header = ngx_http_proxy_v2_process_header;
    u->abort_request = ngx_http_proxy_v2_abort_request;
    u->finalize_request = ngx_http_proxy_v2_finalize_request;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_v2_body_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_proxy_v2_filter_init;
    u->input_filter = ngx_http_proxy_v2_non_buffered_filter;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL && plcf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_create_request(ngx_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame,
                                 *headers_end;
    size_t                        len, headers_len, tmp_len,
                                  key_len, val_len, uri_len,
                                  loc_len, body_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method, host;
    ngx_uint_t                    i, next, unparsed_uri;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_proxy_v2_frame_t    *f;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if (NGX_HTTP_CACHE)
    ngx_http_proxy_v2_check_cache_format(r);

    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;

    } else if (plcf->method) {
        if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        method = r->method_name;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->ctx.head = 1;
    }

    len = sizeof(ngx_http_proxy_v2_connection_start) - 1
          + sizeof(ngx_http_proxy_v2_frame_t);             /* headers frame */

    headers_len = 0;

    /* :method header */

    if ((method.len == 3 && ngx_strncmp(method.data, "GET", 3) == 0)
        || (method.len == 4 && ngx_strncmp(method.data, "POST", 4) == 0))
    {
        len += 1;
        tmp_len = 0;

    } else {
        if (method.len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 method: \"%V\"", &method);
            return NGX_ERROR;
        }

        len += 1 + NGX_HTTP_V2_INT_OCTETS + method.len;
        tmp_len = method.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->ctx.vars.uri.len) {
        uri_len = ctx->ctx.vars.uri.len;

    } else if (ctx->ctx.vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->ctx.vars.uri.len)
                  ? ngx_min(plcf->location.len, r->uri.len) : 0;

        if (r->quoted_uri || r->internal) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        uri_len = ctx->ctx.vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return NGX_ERROR;
    }

    if (uri_len > NGX_HTTP_V2_MAX_FIELD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too long http2 URI");
        return NGX_ERROR;
    }

    len += 1 + NGX_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    host.len = 0;
#if (NGX_SUPPRESS_WARN)
    host.data = NULL;
#endif

    if (plcf->host_value
        && ngx_http_complex_value(r, plcf->host_value, &host) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (host.len == 0) {
        host = ctx->ctx.vars.host_header;
    }

    if (host.len > NGX_HTTP_V2_MAX_FIELD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too long http2 host: \"%V\"", &host);
        return NGX_ERROR;
    }

    len += 1 + NGX_HTTP_V2_INT_OCTETS + host.len;

    if (tmp_len < host.len) {
        tmp_len = host.len;
    }

    /* other headers */

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    body_len = 0;

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->ctx.internal_body_length = body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->ctx.internal_body_length = -1;

    } else if (r->discard_body) {
        ctx->ctx.internal_body_length = 0;

    } else {
        ctx->ctx.internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        if (key_len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 header name");
            return NGX_ERROR;
        }

        if (val_len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 header value");
            return NGX_ERROR;
        }

        headers_len += 1 + NGX_HTTP_V2_INT_OCTETS + key_len
                         + NGX_HTTP_V2_INT_OCTETS + val_len;

        if (tmp_len < key_len) {
            tmp_len = key_len;
        }

        if (tmp_len < val_len) {
            tmp_len = val_len;
        }
    }

    len += headers_len;

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            if (header[i].key.len > NGX_HTTP_V2_MAX_FIELD) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "too long http2 header name: \"%V\"",
                              &header[i].key);
                return NGX_ERROR;
            }

            if (header[i].value.len > NGX_HTTP_V2_MAX_FIELD) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "too long http2 header value: \"%V: %V\"",
                              &header[i].key, &header[i].value);
                return NGX_ERROR;
            }

            len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
                     + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(ngx_http_proxy_v2_frame_t)
           * (len / NGX_HTTP_V2_DEFAULT_FRAME_SIZE);


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    tmp = ngx_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    key_tmp = tmp + tmp_len;
    val_tmp = tmp + 2 * tmp_len;

    /* connection preface */

    b->last = ngx_copy(b->last, ngx_http_proxy_v2_connection_start,
                       sizeof(ngx_http_proxy_v2_connection_start) - 1);

    /* headers frame */

    headers_frame = b->last;

    f = (ngx_http_proxy_v2_frame_t *) b->last;
    b->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_HEADERS_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (method.len == 3 && ngx_strncmp(method.data, "GET", 3) == 0) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_GET_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: GET\"");

    } else if (method.len == 4 && ngx_strncmp(method.data, "POST", 4) == 0) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_POST_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: POST\"");

    } else {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_METHOD_INDEX);
        b->last = ngx_http_v2_write_value(b->last, method.data,
                                          method.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: %V\"", &method);
    }

#if (NGX_HTTP_SSL)
    if (u->ssl) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":scheme: http\"");
    }

    if (plcf->proxy_lengths && ctx->ctx.vars.uri.len) {

        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, ctx->ctx.vars.uri.data,
                                          ctx->ctx.vars.uri.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %V\"", &ctx->ctx.vars.uri);

    } else if (unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
            b->last = ngx_http_v2_write_value(b->last, r->unparsed_uri.data,
                                              r->unparsed_uri.len, tmp);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %V\"", &r->unparsed_uri);

    } else {
        p = val_tmp;

        if (r->valid_location) {
            p = ngx_copy(p, ctx->ctx.vars.uri.data, ctx->ctx.vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = ngx_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %*s\"", p - val_tmp,
                       val_tmp);
    }

    *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX);
    b->last = ngx_http_v2_write_value(b->last, host.data, host.len, tmp);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: \":authority: %V\"", &host);

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    headers_end = b->last + headers_len;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        if (headers_end - b->last < 1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        *b->last++ = 0;

        e.pos = key_tmp;
        e.end = key_tmp + tmp_len;

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        if (e.status) {
            return NGX_ERROR;
        }

        key_len = e.pos - key_tmp;

        if (headers_end - b->last
            < (ssize_t) (NGX_HTTP_V2_INT_OCTETS + key_len))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        b->last = ngx_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;
        e.end = val_tmp + tmp_len;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        if (e.status) {
            return NGX_ERROR;
        }

        val_len = e.pos - val_tmp;

        if (headers_end - b->last
            < (ssize_t) (NGX_HTTP_V2_INT_OCTETS + val_len))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        b->last = ngx_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (NGX_DEBUG)
        if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
            ngx_strlow(key_tmp, key_tmp, key_len);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%*s: %*s\"",
                           key_len, key_tmp, val_len, val_tmp);
        }
#endif
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = ngx_http_v2_write_name(b->last, header[i].key.data,
                                             header[i].key.len, tmp);

            b->last = ngx_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (NGX_DEBUG)
            if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
                ngx_strlow(tmp, header[i].key.data, header[i].key.len);

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(ngx_http_proxy_v2_frame_t);

    if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (ngx_http_proxy_v2_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(ngx_http_proxy_v2_frame_t) + NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        ngx_memmove(p + sizeof(ngx_http_proxy_v2_frame_t), p, len);
        b->last += sizeof(ngx_http_proxy_v2_frame_t);

        if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (ngx_http_proxy_v2_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = NGX_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= NGX_HTTP_V2_END_HEADERS_FLAG;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: %*xs%s, len: %uz",
                   (size_t) ngx_min(b->last - b->pos, 256), b->pos,
                   b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        if (body == NULL) {
            f = (ngx_http_proxy_v2_frame_t *) headers_frame;
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;
        }

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->last_buf = 1;

    } else if (body_len) {

        u->request_bufs = cl;

        b = ngx_create_temp_buf(r->pool, body_len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;

        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.end = b->last + body_len;
        e.request = r;
        e.flushed = 1;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        if (e.status) {
            return NGX_ERROR;
        }

        b->last = e.pos;
        b->last_buf = 1;

    } else {
        u->request_bufs = cl;

        f = (ngx_http_proxy_v2_frame_t *) headers_frame;
        f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        b->last_buf = 1;
    }

    u->output.output_filter = ngx_http_proxy_v2_body_output_filter;
    u->output.filter_ctx = r;

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->output_blocked = 0;
    ctx->status = 0;
    ctx->stream = NULL;
    ctx->busy = NULL;

#if (NGX_HTTP_CACHE)
    if (ctx->cache_header_failed) {
        /* Only undo this attempt's serialization failure, before no_cache. */
        r->upstream->cacheable = 1;
        ctx->cache_header_failed = 0;
    }

    if (ctx->cache_buffer_expanded) {
        /* A replacement must retain the configured response header limit. */
        r->upstream->buffer.end = r->upstream->buffer.start
                                 + r->upstream->conf->buffer_size;
        ctx->cache_buffer_expanded = 0;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_init_header_budget(ngx_http_request_t *r, size_t *budget)
{
    size_t  size;

    /*
     * Nonempty names bound the field count by the decoded header limit.
     * A Huffman code uses at most 30 bits per decoded byte; the decoder's
     * 8/5 expansion buffer therefore needs at most six times the decoded
     * length plus one byte.  Allow two terminated, aligned strings per
     * field in addition to the amortized list storage.
     *
     * Reserve two initial array pairs outside the remaining allowance:
     * upstream reinitialization can allocate them before the first read
     * allocates them again.  Subsequent 103 responses prepay the next pair.
     */

    size = NGX_HTTP_PROXY_V2_HEADER_FIELD_COST + 2 * (NGX_ALIGNMENT + 1) + 6;

    if (r->upstream->conf->buffer_size
        > (NGX_MAX_SIZE_T_VALUE - 2 * NGX_HTTP_PROXY_V2_HEADER_BLOCK_COST)
          / size)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too large http2 header buffer size");
        return NGX_ERROR;
    }

    *budget = r->upstream->conf->buffer_size * size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_account_header(ngx_http_request_t *r, size_t size)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (size > ctx->stream->header_budget) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent too much http2 header data");
        return NGX_ERROR;
    }

    ctx->stream->header_budget -= size;

    return NGX_OK;
}


static u_char *
ngx_http_proxy_v2_alloc_header(ngx_http_request_t *r, size_t len)
{
    if (len > NGX_MAX_SIZE_T_VALUE - NGX_ALIGNMENT
        || ngx_http_proxy_v2_account_header(r,
                                     ngx_align(len + 1, NGX_ALIGNMENT))
           != NGX_OK)
    {
        return NULL;
    }

    return ngx_pnalloc(r->pool, len + 1);
}


static ngx_int_t
ngx_http_proxy_v2_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                         file_pos;
    u_char                       *p, *pos, *start;
    size_t                        len, limit;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    next, last;
    ngx_chain_t                  *cl, *out, *ln, **ll;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_frame_t    *f;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    sess = stream->session;

    if (sess->closing) {
        return stream->done ? NGX_OK : NGX_ERROR;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &stream->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!stream->header_sent) {
        /* first buffer contains headers */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output header");

        stream->header_sent = 1;

        b = stream->in->buf;
        p = b->pos + sizeof(ngx_http_proxy_v2_connection_start) - 1;

        if (stream->id != 1) {
            /* keepalive connection: skip connection preface */

            b->pos = p;
        }

        /* update stream identifiers, including retries on a new connection */

        while (p < b->last) {
            f = (ngx_http_proxy_v2_frame_t *) p;
            p += sizeof(ngx_http_proxy_v2_frame_t);

            f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (stream->id & 0xff);

            p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
        }

        if (stream->in->buf->last_buf) {
            stream->output_closed = 1;
        }

        *ll = stream->in;
        ll = &stream->in->next;

        stream->in = stream->in->next;
    }

    if (sess->control) {
        /* queued control frames */

        *ll = NULL;
        if (ngx_chain_add_copy(r->pool, ll, sess->control) != NGX_OK) {
            return NGX_ERROR;
        }

        for (cl = *ll; cl; cl = cl->next) {
            ll = &cl->next;
        }

        if (sess->control_busy) {
            for (cl = sess->control_busy; cl->next; cl = cl->next) { /* void */ }
            cl->next = sess->control;

        } else {
            sess->control_busy = sess->control;
        }

        sess->control = NULL;
        sess->control_last = &sess->control;
    }

    f = NULL;
    last = 0;

    limit = ngx_max(0, stream->send_window);

    if (limit > sess->send_window) {
        limit = sess->send_window;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, stream->send_window, sess->send_window);

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = stream->in;

    while (in && limit > 0) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http proxy output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (ngx_buf_special(in->buf)) {
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {

            cl = ngx_http_proxy_v2_get_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_proxy_v2_frame_t *) b->last;
            b->last += sizeof(ngx_http_proxy_v2_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;
            start = b->start;

            ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for frame headers
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (ngx_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (ngx_uint_t) (pos - b->pos);
            }

            b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = 0;
            f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (stream->id & 0xff);

            limit -= len;
            stream->send_window -= len;
            sess->send_window -= len;

        } while (!next && limit > 0);

        if (!next) {
            /*
             * if the buffer wasn't fully sent due to flow control limits,
             * preserve position for future use
             */

            if (in->buf->in_file) {
                in->buf->file_pos = file_pos;

            } else {
                in->buf->pos = pos;
            }

            break;
        }

    next:

        if (in->buf->last_buf) {
            last = 1;
        }

        ln = in;
        in = in->next;

        ngx_free_chain(r->pool, ln);
    }

    stream->in = in;

    if (last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output last");

        stream->output_closed = 1;

        if (f) {
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = ngx_http_proxy_v2_get_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_proxy_v2_frame_t *) b->last;
            b->last += sizeof(ngx_http_proxy_v2_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = NGX_HTTP_V2_END_STREAM_FLAG;
            f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (stream->id & 0xff);

            *ll = cl;
            ll = &cl->next;
        }

        cl->buf->last_buf = 1;
    }

    *ll = NULL;

#if (NGX_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http proxy output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, stream->send_window, sess->send_window);

#endif

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                         (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter);

    ngx_chain_update_chains(sess->pool, &sess->control_free,
                           &sess->control_busy, &out,
                           (ngx_buf_tag_t) &ngx_http_proxy_v2_get_control);

    for (cl = ctx->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == NGX_OK && stream->in) {
        rc = NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        ctx->output_blocked = 1;

    } else {
        ctx->output_blocked = 0;
    }

    if (stream->done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;
        u->pipe->length = 0;

        if (stream->in == NULL
            && sess->control == NULL
            && stream->output_closed
            && !ctx->output_blocked
            && !sess->goaway
            && sess->state == ngx_http_proxy_v2_st_start)
        {
            u->keepalive = 1;
        }

        ngx_post_event(u->connection->read, &ngx_posted_events);
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_process_header(ngx_http_request_t *r)
{
    u_char                         *p, *pos;
    size_t                          size;
    ngx_str_t                      *status_line;
    ngx_int_t                       rc, status;
    ngx_buf_t                      *b;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_v2_ctx_t        *ctx;
    ngx_http_proxy_v2_stream_t     *stream;
    ngx_http_upstream_header_t     *hh;
    ngx_http_proxy_v2_session_t    *sess;
    ngx_http_upstream_main_conf_t  *umcf;

#if (NGX_HTTP_CACHE)
    if (r->cached) {
        return ngx_http_proxy_process_cache_header(r);
    }
#endif

    u = r->upstream;
    b = &u->buffer;
    pos = b->start;

#if (NGX_HTTP_CACHE)
    if (r->cache) {
        pos += r->cache->header_start;
    }
#endif

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy response: %*xs%s, len: %uz",
                   (size_t) ngx_min(b->last - b->pos, 256),
                   b->pos, b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    sess = stream->session;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        if (sess->state < ngx_http_proxy_v2_st_payload) {

            /* Retain an incomplete initial frame header in the buffer. */

            if ((!sess->header_stream_id || sess->header_discard)
                && b->last - b->pos < NGX_HTTP_V2_FRAME_HEADER_SIZE)
            {
                goto again;
            }

            p = b->pos;
            rc = ngx_http_proxy_v2_parse_frame(sess, b);

            if (rc == NGX_AGAIN) {
                goto again;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /* DATA frames cannot appear before the response headers. */

            if (sess->type == NGX_HTTP_V2_DATA_FRAME
                && sess->stream_id == stream->id)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              sess->type);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (sess->type == NGX_HTTP_V2_HEADERS_FRAME
                && sess->stream_id == stream->id)
            {
                /* Reclaim controls preceding headers in the same read. */

                size = b->pos - p;
                b->last = ngx_movemem(pos, p, b->last - p);
                b->pos = pos + size;
            }
        }

        /* frame payload */

        if (sess->stream_id && sess->stream_id != stream->id) {
            rc = ngx_http_proxy_v2_process_closed_frame(sess, b);

            if (sess->control) {
                ngx_post_event(u->connection->write, &ngx_posted_events);
            }

            if (rc == NGX_OK) {
                continue;
            }

            if (rc == NGX_AGAIN) {
                goto again;
            }

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (sess->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
            rc = ngx_http_proxy_v2_parse_rst_stream(sess, b);

            if (rc == NGX_AGAIN) {
                goto again;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            stream->error = sess->error;
            stream->rst = 1;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          stream->error);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        rc = ngx_http_proxy_v2_process_control_frame(sess, stream, b);

        if (rc == NGX_AGAIN) {
            goto again;
        }

        if (rc == NGX_HTTP_UPSTREAM_CONNECTION_ERROR) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (sess->type != NGX_HTTP_V2_HEADERS_FRAME
            && sess->type != NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(sess, b);

            if (rc == NGX_AGAIN) {
                goto again;
            }

            continue;
        }

        /* headers */

        /* control frames do not count as a response to this attempt */

        stream->response_received = 1;

        for ( ;; ) {

            rc = ngx_http_proxy_v2_process_header_frame(r, ctx, b);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%V: %V\"",
                               &sess->name, &sess->value);

                if (sess->name.len && sess->name.data[0] == ':') {

                    if (sess->name.len != sizeof(":status") - 1
                        || ngx_strncmp(sess->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &sess->name, &sess->value);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &sess->value;

                    if (status_line->len != 3) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = ngx_atoi(status_line->data, 3);

                    if (status == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < NGX_HTTP_OK && status != NGX_HTTP_EARLY_HINTS)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->status = 1;

                    continue;

                } else if (!ctx->status) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if (ngx_http_proxy_v2_account_header(r,
                                        NGX_HTTP_PROXY_V2_HEADER_FIELD_COST)
                    != NGX_OK)
                {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->key = sess->name;
                h->value = sess->value;
                h->lowcase_key = h->key.data;
                h->hash = ngx_hash_key(h->key.data, h->key.len);

                if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                    continue;
                }

                hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh) {
                    rc = hh->handler(r, h, hh->offset);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                continue;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                if (!ctx->status) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header done");

                if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                    if (stream->end_stream) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ngx_http_proxy_v2_account_header(r,
                                        NGX_HTTP_PROXY_V2_HEADER_BLOCK_COST)
                        != NGX_OK)
                    {
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    ctx->status = 0;
                    return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                }

                if (stream->input_closed
                    && stream->in == NULL
                    && sess->control == NULL
                    && stream->output_closed
                    && !ctx->output_blocked
                    && !sess->goaway
                    && b->last == b->pos)
                {
                    u->keepalive = 1;
                }

                /* Cache original fields before adding synthetic defaults. */

#if (NGX_HTTP_CACHE)
                if (u->cacheable) {
                    ngx_http_proxy_v2_create_cache_header(r);
                }
#endif

                return ngx_http_proxy_set_default_headers(r);
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == NGX_AGAIN */

        if (sess->rest == 0) {
            sess->state = ngx_http_proxy_v2_st_start;
            continue;
        }

        return NGX_AGAIN;
    }

again:

    if (!sess->header_stream_id || sess->header_discard) {
        /* Retain only undecoded frame-header bytes before the response. */

        b->last = ngx_movemem(pos, b->pos, b->last - b->pos);
        b->pos = pos;
    }

    return NGX_AGAIN;
}


#if (NGX_HTTP_CACHE)

static void
ngx_http_proxy_v2_check_cache_format(ngx_http_request_t *r)
{
    ngx_buf_t            *b;
    ngx_http_cache_t     *c;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->cache_status != NGX_HTTP_CACHE_EXPIRED) {
        return;
    }

    c = r->cache;
    b = c->buf;

    if (c->body_start >= c->header_start
        && c->body_start - c->header_start >= sizeof("HTTP/") - 1
        && (size_t) (b->last - b->start) >= c->body_start
        && ngx_strncmp(b->start + c->header_start, "HTTP/",
                       sizeof("HTTP/") - 1) == 0)
    {
        return;
    }

    /*
     * Expired entries have not passed through the cached header reader.
     * Discard wire-format entries before building conditional requests
     * or allowing stale fallback.
     */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy incompatible cached header format");

    u->cache_status = NGX_HTTP_CACHE_MISS;
    c->valid_sec = 0;
    c->updating_sec = 0;
    c->error_sec = 0;
    c->valid_msec = 0;
    c->stale_updating = 0;
    c->stale_error = 0;
    c->last_modified = -1;
    ngx_str_null(&c->etag);
    ngx_str_null(&c->vary);
}


static void
ngx_http_proxy_v2_create_cache_header(ngx_http_request_t *r)
{
    size_t                   size, left, rest;
    ngx_buf_t                buffer, *b;
    ngx_uint_t               i;
    ngx_list_part_t         *part;
    ngx_table_elt_t         *h;
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    buffer = u->buffer;
    b = &buffer;

    /* Measure the cache prefix independently of unread wire input. */

    size = ngx_min(u->conf->buffer_size - 1, (size_t) (u_short) -1);
    left = sizeof("HTTP/1.1 200" CRLF CRLF) - 1;

    if (r->cache->header_start > size
        || left > size - r->cache->header_start)
    {
        goto declined;
    }

    left = size - r->cache->header_start - left;
    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len > left || h[i].value.len > left - h[i].key.len
            || sizeof(": " CRLF) - 1 > left - h[i].key.len - h[i].value.len)
        {
            goto declined;
        }

        /* The text parser strips these spaces; retain live header semantics. */

        if (h[i].value.len
            && (h[i].value.data[0] == ' '
                || h[i].value.data[h[i].value.len - 1] == ' '))
        {
            goto declined;
        }

        left -= h[i].key.len + h[i].value.len + sizeof(": " CRLF) - 1;
    }

    size -= left;
    rest = b->last - b->pos;

    /* HPACK may be smaller than text: preserve all preread frame bytes. */

    if (rest > (size_t) (b->end - b->start) - size) {
        if (rest > NGX_MAX_SIZE_T_VALUE - size) {
            goto declined;
        }

        b->start = ngx_palloc(r->pool, size + rest);
        if (b->start == NULL) {
            goto declined;
        }

        b->end = b->start + size + rest;
        ctx->cache_buffer_expanded = 1;
    }

    ngx_memmove(b->start + size, b->pos, rest);
    b->last = b->start + r->cache->header_start;
    b->last = ngx_sprintf(b->last, "HTTP/1.1 %03ui" CRLF,
                         u->headers_in.status_n);
    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /* Preserve original fields, including duplicates ignored by handlers. */

        b->last = ngx_cpymem(b->last, h[i].key.data, h[i].key.len);
        *b->last++ = ':';
        *b->last++ = ' ';
        b->last = ngx_cpymem(b->last, h[i].value.data, h[i].value.len);
        *b->last++ = CR;
        *b->last++ = LF;
    }

    *b->last++ = CR;
    *b->last++ = LF;
    b->pos = b->last;
    b->last += rest;
    u->buffer = buffer;

    return;

declined:

    ctx->cache_header_failed = 1;
    u->cacheable = 0;
}

#endif


static ngx_int_t
ngx_http_proxy_v2_filter_init(void *data)
{
    ngx_http_request_t          *r = data;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_v2_stream_t  *stream;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->ctx.head)
    {
        stream->length = 0;

    } else {
        stream->length = u->headers_in.content_length_n;
    }

    if (stream->input_closed) {

        if (ngx_http_proxy_v2_finish_response(r, stream) != NGX_OK) {
            return NGX_ERROR;
        }

        u->length = 0;
        u->pipe->length = 0;

    } else {
        u->length = 1;
        u->pipe->length = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_finish_response(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (!stream->input_closed || stream->done) {
        return NGX_OK;
    }

    if (stream->length > 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream prematurely closed stream");
        return NGX_ERROR;
    }

    stream->done = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_body(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, size_t *size)
{
    ngx_int_t                     rc;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    rc = ngx_http_proxy_v2_process_frames(r, ctx, b, size);

    if (rc != NGX_AGAIN && rc != NGX_DONE) {
        return rc;
    }

    stream = ctx->stream;
    sess = stream->session;

    if (ngx_http_proxy_v2_finish_response(r, stream) != NGX_OK) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /*
     * We have finished parsing the response and the remaining control
     * frames.  If there are unsent control frames, post a write event
     * to send them.
     */

    if (sess->control) {
        ngx_post_event(r->upstream->connection->write, &ngx_posted_events);
        return NGX_AGAIN;
    }

    if (stream->in == NULL
        && stream->output_closed
        && !ctx->output_blocked
        && !sess->goaway
        && sess->state == ngx_http_proxy_v2_st_start)
    {
        r->upstream->keepalive = 1;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_non_buffered_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    size_t                        size;
    ngx_int_t                     rc;
    ngx_buf_t                    *b, *buf;
    ngx_chain_t                  *cl, **ll;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", bytes);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    sess = stream->session;
    u = r->upstream;
    b = &u->buffer;

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = ngx_http_proxy_v2_process_body(r, ctx, b, &size);

        if (rc == NGX_OK) {

            cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            buf = cl->buf;

            buf->flush = 1;
            buf->memory = 1;

            buf->pos = b->pos;
            buf->tag = u->output.tag;

            if (ngx_http_proxy_v2_process_data(sess, b, size) != NGX_OK) {
                return NGX_ERROR;
            }

            buf->last = b->pos;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy output buf %p", buf->pos);

            if (stream->length != -1) {

                if (buf->last - buf->pos > stream->length) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NGX_ERROR;
                }

                stream->length -= buf->last - buf->pos;
            }

            continue;
        }

        if (rc == NGX_DONE) {
            u->length = 0;
            break;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* invalid response */

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    size_t                        size;
    ngx_int_t                     rc;
    ngx_buf_t                    *buf, **prev;
    ngx_chain_t                  *cl;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    if (b->pos == b->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    sess = stream->session;
    buf = NULL;
    prev = &b->shadow;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", b->last - b->pos);

    for ( ;; ) {

        rc = ngx_http_proxy_v2_process_body(r, ctx, b, &size);

        if (rc == NGX_OK) {

            /* copy data frame payload for buffering */

            cl = ngx_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            buf = cl->buf;

            ngx_memzero(buf, sizeof(ngx_buf_t));

            buf->pos = b->pos;
            buf->start = b->start;
            buf->end = b->end;
            buf->tag = p->tag;
            buf->temporary = 1;
            buf->recycled = 1;

            *prev = buf;
            prev = &buf->shadow;

            if (p->in) {
                *p->last_in = cl;

            } else {
                p->in = cl;
            }

            p->last_in = &cl->next;

            /* STUB */ buf->num = b->num;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy copy buf %p", buf->pos);

            if (ngx_http_proxy_v2_process_data(sess, b, size) != NGX_OK) {
                return NGX_ERROR;
            }

            buf->last = b->pos;

            if (stream->length != -1) {

                if (buf->last - buf->pos > stream->length) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NGX_ERROR;
                }

                stream->length -= buf->last - buf->pos;
            }

            continue;
        }

        if (rc == NGX_DONE) {
            p->length = 0;
            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        /* invalid response */

        return NGX_ERROR;
    }

    if (buf) {
        buf->shadow = b;
        buf->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", buf->pos, buf->last - buf->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, b) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_control_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
{
    ssize_t                      window_update;
    ngx_int_t                    rc;
    ngx_rbtree_t                *tree;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *s;

    if (sess->type == NGX_HTTP_V2_GOAWAY_FRAME) {

        rc = ngx_http_proxy_v2_parse_goaway(sess, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (!sess->goaway
            || sess->frame_goaway_last_stream_id < sess->goaway_last_stream_id)
        {
            sess->goaway_last_stream_id = sess->frame_goaway_last_stream_id;
        }

        if (sess->goaway_error == 0) {
            sess->goaway_error = sess->error;
        }

        sess->goaway = 1;

        if (stream == NULL) {
            return NGX_OK;
        }

        stream->request->upstream->keepalive = 0;

        /*
         * Streams above the confirmed last stream ID need to be retried.
         * Other streams can continue, but the connection cannot be used
         * for additional requests.
         */

        if (sess->goaway_last_stream_id < stream->id) {

            if (sess->goaway_error || stream->response_received) {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent goaway with error %ui",
                              sess->goaway_error);
            }

            if (!stream->response_received) {
                return NGX_HTTP_UPSTREAM_CONNECTION_ERROR;
            }

            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (sess->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {

        rc = ngx_http_proxy_v2_parse_window_update(sess, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (sess->window_update == 0) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent zero window update");
            return NGX_ERROR;
        }

        if (sess->stream_id) {

            if (sess->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                      - stream->send_window)
            {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent too large window update");
                return NGX_ERROR;
            }

            stream->send_window += sess->window_update;

        } else {

            if (sess->window_update > NGX_HTTP_V2_MAX_WINDOW
                                      - sess->send_window)
            {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent too large window update");
                return NGX_ERROR;
            }

            sess->send_window += sess->window_update;
        }

        if (stream && stream->in) {
            ngx_post_event(&stream->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (sess->type == NGX_HTTP_V2_SETTINGS_FRAME) {

        tree = &sess->streams;

        for ( ;; ) {
            rc = ngx_http_proxy_v2_parse_settings(sess, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                break;
            }

            /* consume each setting before the parser reuses its result */

            if (sess->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                window_update = (ssize_t) sess->setting_value
                                - (ssize_t) sess->init_window;

                if (tree->root != tree->sentinel) {
                    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
                         node;
                         node = ngx_rbtree_next(tree, node))
                    {
                        s = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t,
                                            node);

                        if (s->send_window > 0
                            && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                               - s->send_window)
                        {
                            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                                          "upstream sent settings frame "
                                          "with too large initial window "
                                          "size: %ui", sess->setting_value);
                            return NGX_ERROR;
                        }

                        s->send_window += window_update;
                    }
                }

                sess->init_window = sess->setting_value;
            }
        }

        if (!(sess->flags & NGX_HTTP_V2_ACK_FLAG)) {
            if (ngx_http_proxy_v2_send_settings_ack(sess) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (stream && (sess->control || stream->in)) {
            ngx_post_event(&stream->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (sess->type == NGX_HTTP_V2_PING_FRAME) {

        rc = ngx_http_proxy_v2_parse_ping(sess, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_http_proxy_v2_send_ping_ack(sess) != NGX_OK) {
            return NGX_ERROR;
        }

        if (stream) {
            ngx_post_event(&stream->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (sess->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "upstream sent unexpected push promise frame");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_v2_process_closed_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    size_t     size;
    ngx_int_t  rc;

    switch (sess->type) {

    case NGX_HTTP_V2_DATA_FRAME:

        if (sess->frame_state == 0) {
            if (sess->rest > sess->recv_window) {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream violated connection flow control");
                return NGX_ERROR;
            }

            sess->recv_window -= sess->rest;
            sess->frame_state = 1;
            sess->padding = 0;
        }

        for ( ;; ) {
            rc = ngx_http_proxy_v2_parse_data(sess, b, &size);

            if (rc != NGX_OK) {
                break;
            }

            if (ngx_http_proxy_v2_process_data(sess, b, size) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (sess->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4) {
            return ngx_http_proxy_v2_send_window_update(sess, NULL);
        }

        return NGX_OK;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        if (sess->frame_state == 0 && sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
            sess->header_limit = sess->conf->buffer_size;
            sess->header_discard = 1;
            ngx_http_proxy_v2_clear_header(sess);
        }

        rc = ngx_http_proxy_v2_parse_header(sess, b);

        if (rc == NGX_HTTP_PARSE_HEADER_DONE
            || (rc == NGX_AGAIN && sess->state == ngx_http_proxy_v2_st_start))
        {
            return NGX_OK;
        }

        return rc;

    case NGX_HTTP_V2_RST_STREAM_FRAME:
        return ngx_http_proxy_v2_parse_rst_stream(sess, b);

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
        return ngx_http_proxy_v2_parse_window_update(sess, b);

    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:
        return NGX_ERROR;
    }

    return ngx_http_proxy_v2_skip_frame(sess, b);
}


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) sess->rest) {
        sess->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += sess->rest;
    sess->rest = 0;
    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, size_t *size)
{
    ngx_int_t                     rc;
    ngx_table_elt_t              *h;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    u = r->upstream;
    stream = ctx->stream;
    sess = stream->session;

    for ( ;; ) {

        if (sess->state < ngx_http_proxy_v2_st_payload) {

            rc = ngx_http_proxy_v2_parse_frame(sess, b);

            if (rc == NGX_AGAIN) {
                return stream->input_closed ? NGX_DONE : NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (sess->type == NGX_HTTP_V2_DATA_FRAME
                && sess->stream_id == stream->id)
            {

                if (sess->rest > stream->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  sess->rest, stream->recv_window);
                    return NGX_ERROR;
                }

                if (sess->rest > sess->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  sess->rest, sess->recv_window);
                    return NGX_ERROR;
                }

                stream->recv_window -= sess->rest;
                sess->recv_window -= sess->rest;

                if (sess->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
                    || stream->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (ngx_http_proxy_v2_send_window_update(sess, stream)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    ngx_post_event(u->connection->write,
                                   &ngx_posted_events);
                }
            }

            if (sess->stream_id == stream->id && stream->input_closed
                && sess->type != NGX_HTTP_V2_RST_STREAM_FRAME
                && sess->type != NGX_HTTP_V2_WINDOW_UPDATE_FRAME)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              sess->stream_id);
                return NGX_ERROR;
            }

            sess->padding = 0;
        }

        /* frame payload */

        if (sess->stream_id && sess->stream_id != stream->id) {
            rc = ngx_http_proxy_v2_process_closed_frame(sess, b);

            if (sess->control) {
                ngx_post_event(u->connection->write, &ngx_posted_events);
            }

            if (rc == NGX_OK) {
                continue;
            }

            return rc;
        }

        if (sess->type == NGX_HTTP_V2_RST_STREAM_FRAME) {

            rc = ngx_http_proxy_v2_parse_rst_stream(sess, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (stream->rst) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              sess->stream_id);
                return NGX_ERROR;
            }

            stream->error = sess->error;
            stream->rst = 1;

            if (stream->error || !stream->input_closed) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream rejected request with error %ui",
                              stream->error);
                return NGX_ERROR;
            }

            continue;
        }

        rc = ngx_http_proxy_v2_process_control_frame(sess, stream, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR || rc == NGX_HTTP_UPSTREAM_CONNECTION_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME
            || sess->type == NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = ngx_http_proxy_v2_process_header_frame(r, ctx, b);

                if (rc == NGX_AGAIN) {
                    break;
                }

                if (rc == NGX_OK) {

                    /* a header line has been parsed successfully */

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer: \"%V: %V\"",
                                   &sess->name, &sess->value);

                    if (sess->name.len && sess->name.data[0] == ':') {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &sess->name, &sess->value);
                        return NGX_ERROR;
                    }

                    if (ngx_http_proxy_v2_account_header(r,
                                        NGX_HTTP_PROXY_V2_HEADER_FIELD_COST)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    h = ngx_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return NGX_ERROR;
                    }

                    h->key = sess->name;
                    h->value = sess->value;
                    h->lowcase_key = h->key.data;
                    h->hash = ngx_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer done");

                    if (stream->input_closed) {
                        break;
                    }

                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return NGX_ERROR;
                }

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return NGX_ERROR;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
                continue;
            }

            /* rc == NGX_AGAIN */

            if (sess->rest == 0) {
                sess->state = ngx_http_proxy_v2_st_start;
                continue;
            }

            return NGX_AGAIN;
        }

        if (sess->type != NGX_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(sess, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            continue;
        }

        rc = ngx_http_proxy_v2_parse_data(sess, b, size);

        if (rc == NGX_DONE) {

            if (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                stream->input_closed = 1;
            }

            continue;
        }

        return rc;
    }
}


static ngx_int_t
ngx_http_proxy_v2_parse_data(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b,
    size_t *size)
{
    /*
     * data frame:
     *
     * +---------------+
     * |Pad Length? (8)|
     * +---------------+-----------------------------------------------+
     * |                            Data (*)                         ...
     * +---------------------------------------------------------------+
     * |                           Padding (*)                       ...
     * +---------------------------------------------------------------+
     */

    for ( ;; ) {

        if (sess->state == ngx_http_proxy_v2_st_padding) {

            if (b->last - b->pos < (ssize_t) sess->rest) {
                sess->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += sess->rest;
            sess->rest = 0;
            sess->state = ngx_http_proxy_v2_st_start;

            return NGX_DONE;
        }

        if (sess->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (sess->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            sess->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
            sess->padding = *b->pos++;
            sess->rest -= 1;

            if (sess->padding > sess->rest) {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              sess->padding, sess->rest);
                return NGX_ERROR;
            }

            continue;
        }

        if (sess->padding == sess->rest) {

            if (sess->padding) {
                sess->state = ngx_http_proxy_v2_st_padding;

            } else {
                sess->state = ngx_http_proxy_v2_st_start;

                return NGX_DONE;
            }

            continue;
        }

        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        *size = ngx_min((size_t) (b->last - b->pos),
                        sess->rest - sess->padding);

        return NGX_OK;
    }
}


static ngx_int_t
ngx_http_proxy_v2_process_data(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b,
    size_t size)
{
    if (sess->type != NGX_HTTP_V2_DATA_FRAME
        || sess->state != ngx_http_proxy_v2_st_payload
        || (sess->flags & NGX_HTTP_V2_PADDED_FLAG)
        || size == 0
        || sess->rest < sess->padding
        || size > sess->rest - sess->padding
        || size > (size_t) (b->last - b->pos))
    {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "invalid http2 data consumption: %uz", size);
        return NGX_ERROR;
    }

    b->pos += size;
    sess->rest -= size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    u_char                     ch, *p;
    ngx_http_proxy_v2_state_e  state;

    state = sess->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_proxy_v2_st_start:
            sess->rest = ch << 16;
            state = ngx_http_proxy_v2_st_length_2;
            break;

        case ngx_http_proxy_v2_st_length_2:
            sess->rest |= ch << 8;
            state = ngx_http_proxy_v2_st_length_3;
            break;

        case ngx_http_proxy_v2_st_length_3:
            sess->rest |= ch;

            if (sess->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              sess->rest);
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_st_type;
            break;

        case ngx_http_proxy_v2_st_type:
            sess->type = ch;
            state = ngx_http_proxy_v2_st_flags;
            break;

        case ngx_http_proxy_v2_st_flags:
            sess->flags = ch;
            state = ngx_http_proxy_v2_st_stream_id;
            break;

        case ngx_http_proxy_v2_st_stream_id:
            sess->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_st_stream_id_2;
            break;

        case ngx_http_proxy_v2_st_stream_id_2:
            sess->stream_id |= ch << 16;
            state = ngx_http_proxy_v2_st_stream_id_3;
            break;

        case ngx_http_proxy_v2_st_stream_id_3:
            sess->stream_id |= ch << 8;
            state = ngx_http_proxy_v2_st_stream_id_4;
            break;

        case ngx_http_proxy_v2_st_stream_id_4:
            sess->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           sess->type, sess->rest, sess->flags,
                           sess->stream_id);

            b->pos = p + 1;

            sess->state = ngx_http_proxy_v2_st_payload;
            sess->frame_state = 0;

            return ngx_http_proxy_v2_validate_frame(sess);

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
        case ngx_http_proxy_v2_st_padding:
            break;
        }
    }

    b->pos = p;
    sess->state = state;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_proxy_v2_validate_frame(ngx_http_proxy_v2_session_t *sess)
{
    /* Even unknown frame types cannot interrupt a header block. */

    if ((sess->type == NGX_HTTP_V2_CONTINUATION_FRAME
         && sess->header_stream_id == 0)
        || (sess->type != NGX_HTTP_V2_CONTINUATION_FRAME
            && sess->header_stream_id))
    {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "upstream sent unexpected http2 frame: %d", sess->type);
        return NGX_ERROR;
    }

    if (sess->type == NGX_HTTP_V2_CONTINUATION_FRAME
        && sess->stream_id != sess->header_stream_id)
    {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "upstream sent continuation frame "
                      "for wrong stream %ui, expected %ui",
                      sess->stream_id, sess->header_stream_id);
        return NGX_ERROR;
    }

    switch (sess->type) {

    case NGX_HTTP_V2_DATA_FRAME:
    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_PRIORITY_FRAME:
    case NGX_HTTP_V2_RST_STREAM_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        if (sess->stream_id == 0) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent http2 frame %d with zero stream id",
                          sess->type);
            return NGX_ERROR;
        }

        break;

    case NGX_HTTP_V2_SETTINGS_FRAME:
    case NGX_HTTP_V2_PING_FRAME:
    case NGX_HTTP_V2_GOAWAY_FRAME:

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent http2 frame %d with nonzero stream id",
                          sess->type);
            return NGX_ERROR;
        }

        break;
    }

    if (sess->type == NGX_HTTP_V2_PRIORITY_FRAME && sess->rest != 5) {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "upstream sent priority frame with invalid length: %uz",
                      sess->rest);
        return NGX_ERROR;
    }

    switch (sess->type) {

    case NGX_HTTP_V2_DATA_FRAME:
    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_RST_STREAM_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:
    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (sess->stream_id
            && (!(sess->stream_id & 1)
                || sess->stream_id > sess->last_stream_id))
        {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent frame for unknown stream %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_header_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_int_t                     rc;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    stream = ctx->stream;
    sess = stream->session;

    if (sess->header_discard || sess->stream_id != stream->id
        || (sess->header_stream_id && sess->header_stream_id != stream->id))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid http2 header consumer for stream %ui",
                      sess->stream_id);
        return NGX_ERROR;
    }

    if (sess->frame_state == 0 && sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
        sess->header_limit = r->upstream->conf->buffer_size;

        if (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
            stream->end_stream = 1;
        }
    }

    for ( ;; ) {
        rc = ngx_http_proxy_v2_parse_header(sess, b);

        if (rc != NGX_BUSY) {
            break;
        }

        if (ngx_http_proxy_v2_alloc_field(r, sess) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (rc == NGX_OK) {
        return ngx_http_proxy_v2_process_field(r, sess);
    }

    if (rc == NGX_HTTP_PARSE_HEADER_DONE && stream->end_stream) {
        stream->input_closed = 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      min, size;
    ngx_int_t   rc;
    ngx_log_t  *log;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    log = &sess->log;
    state = sess->frame_state;

    if (state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy parse header: start");

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
            sess->header_block_limit = sess->header_limit;
            sess->header_size = 0;
        }

        /* Charge the complete frame once, before consuming its payload. */

        size = NGX_HTTP_V2_FRAME_HEADER_SIZE + sess->rest;

        if (size > sess->header_block_limit
            || sess->header_size > sess->header_block_limit - size)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 header block");
            return NGX_ERROR;
        }

        sess->header_size += size;

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
            sess->header_stream_id = sess->stream_id;
            sess->fragment_state = 0;

            min = (sess->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (sess->rest < min) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              sess->rest);
                return NGX_ERROR;
            }

            if (sess->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (sess->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        sess->padding = 0;
        sess->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) sess->rest) {
            last = b->last;

        } else {
            last = b->pos + sess->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                sess->padding = ch;

                if (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        sess->rest -= p - b->pos;
        b->pos = p;

        sess->frame_state = state;
        return NGX_AGAIN;

    fragment:

        p++;
        sess->rest -= p - b->pos;
        b->pos = p;

        if (sess->padding > sess->rest) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          sess->padding, sess->rest);
            return NGX_ERROR;
        }

        state = sw_fragment;
        sess->frame_state = state;
    }

    if (state == sw_fragment) {

        for ( ;; ) {
            rc = ngx_http_proxy_v2_parse_fragment(sess, b);

            if (rc == NGX_BUSY) {
                if (!sess->header_discard) {
                    return NGX_BUSY;
                }

                sess->field = NULL;
                continue;
            }

            if (rc != NGX_OK) {
                break;
            }

            if (!sess->header_discard) {
                return NGX_OK;
            }

            ngx_http_proxy_v2_clear_header(sess);
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        /* rc == NGX_DONE */

        state = sw_padding;
        sess->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) sess->rest) {

            sess->rest -= b->last - b->pos;
            b->pos = b->last;

            return NGX_AGAIN;
        }

        b->pos += sess->rest;
        sess->rest = 0;

        sess->state = ngx_http_proxy_v2_st_start;

        if (sess->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {

            if (sess->fragment_state) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent truncated http2 header");
                return NGX_ERROR;
            }

            ngx_http_proxy_v2_clear_header(sess);
            sess->header_stream_id = 0;
            sess->header_discard = 0;

            return NGX_HTTP_PARSE_HEADER_DONE;
        }

        return NGX_AGAIN;
    }

    /* unreachable */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_parse_fragment(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      len, size;
    ngx_log_t  *log;
    ngx_uint_t  index, size_update;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    log = &sess->log;

    /* header block fragment */

#if 0
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy header fragment %p:%p rest:%uz",
                   b->pos, b->last, sess->rest);
#endif

    if (b->last - b->pos < (ssize_t) sess->rest - sess->padding) {
        last = b->last;

    } else {
        last = b->pos + sess->rest - sess->padding;
    }

    state = sess->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                               "http proxy indexed header: %ui", index);

                sess->index = index;
                sess->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                               "http proxy literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                sess->index = index;
                sess->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                               "http proxy table size update: %ui",
                               size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    sess->index = index;
                    sess->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                               "http proxy literal header never indexed: %ui",
                               index);

                sess->index = index;
                sess->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    sess->index = index;
                    sess->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                             "http proxy literal header without indexing: %ui",
                               index);

                sess->index = index;
                sess->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NGX_ERROR;

        case sw_index:
            sess->index = sess->index + (ch & ~0x80);

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NGX_ERROR;
            }

            if (sess->index > 61) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", sess->index);
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy header index: %ui", sess->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            sess->field_huffman = ch & 0x80 ? 1 : 0;
            sess->field_length = ch & ~0x80;

            if (sess->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (sess->field_length == 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            sess->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            sess->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            sess->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            sess->field = &sess->name;
            state = sw_name_bytes;
            goto allocate;

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy name: len:%uz h:%d last:%uz, rest:%uz",
                           sess->field_length,
                           sess->field_huffman,
                           last - p,
                           sess->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) sess->field_rest);

            if (ngx_http_proxy_v2_parse_field(sess, &sess->name, p, size)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            p += size - 1;

            if (sess->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            sess->field_huffman = ch & 0x80 ? 1 : 0;
            sess->field_length = ch & ~0x80;

            if (sess->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (sess->field_length == 0) {
                ngx_str_set(&sess->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            sess->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            sess->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            sess->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NGX_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            sess->field = &sess->value;
            state = sw_value_bytes;
            goto allocate;

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy value: len:%uz h:%d last:%uz, rest:%uz",
                           sess->field_length,
                           sess->field_huffman,
                           last - p,
                           sess->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) sess->field_rest);

            if (ngx_http_proxy_v2_parse_field(sess, &sess->value, p, size)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            p += size - 1;

            if (sess->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    allocate:

        sess->field->len = sess->field_huffman ?
                          sess->field_length * 8 / 5 : sess->field_length;

        if (sess->field->len > sess->header_limit) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 header %s length: %uz",
                          sess->field == &sess->name ? "name" : "value",
                          sess->field->len);
            return NGX_ERROR;
        }

        sess->field->data = NULL;
        sess->field_end = NULL;
        sess->field_rest = sess->field_length;
        sess->field_state = 0;

        sess->rest -= p - b->pos;
        sess->fragment_state = state;
        b->pos = p;

        return NGX_BUSY;

    done:

        p++;
        sess->rest -= p - b->pos;
        sess->fragment_state = sw_start;
        b->pos = p;

        if (sess->index) {
            sess->name = *ngx_http_v2_get_static_name(sess->index);
        }

        if (sess->index && !sess->literal) {
            sess->value = *ngx_http_v2_get_static_value(sess->index);
        }

        len = sess->name.len + sess->value.len;

        if (len > sess->header_limit) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        sess->header_limit -= len;

        return NGX_OK;
    }

    sess->rest -= p - b->pos;
    sess->fragment_state = state;
    b->pos = p;

    if (sess->rest > sess->padding) {
        return NGX_AGAIN;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_parse_field(ngx_http_proxy_v2_session_t *sess,
    ngx_str_t *field, u_char *p, size_t size)
{
    size_t   n;
    u_char  *dst, *start, scratch[256];

    if (sess->field_huffman && sess->field_rest == sess->field_length) {
        field->len = 0;
    }

    sess->field_rest -= size;

    if (!sess->field_huffman) {
        if (!sess->header_discard) {
            sess->field_end = ngx_cpymem(sess->field_end, p, size);
            field->data[field->len] = '\0';
        }

        return NGX_OK;
    }

    do {
        n = sess->header_discard ? ngx_min(size, sizeof(scratch) / 2) : size;
        start = sess->header_discard ? scratch : sess->field_end;
        dst = start;

        if (ngx_http_huff_decode(&sess->field_state, p, n, &dst,
                                sess->field_rest == 0 && n == size,
                                &sess->log)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent invalid encoded header");
            return NGX_ERROR;
        }

        field->len += dst - start;

        if (!sess->header_discard) {
            sess->field_end = dst;
            *dst = '\0';
        }

        p += n;
        size -= n;
    } while (size);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_alloc_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_session_t *sess)
{
    ngx_str_t  *field;

    field = sess->field;

    field->data = ngx_http_proxy_v2_alloc_header(r, field->len);
    if (field->data == NULL) {
        return NGX_ERROR;
    }

    sess->field_end = field->data;
    sess->field = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_session_t *sess)
{
    if ((!sess->index
         && ngx_http_proxy_v2_validate_header_name(&sess->name) != NGX_OK)
        || ((!sess->index || sess->literal)
            && ngx_http_proxy_v2_validate_header_value(&sess->value)
               != NGX_OK))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header: \"%V: %V\"",
                      &sess->name, &sess->value);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_clear_header(ngx_http_proxy_v2_session_t *sess)
{
    sess->name.data = NULL;
    sess->value.data = NULL;
    sess->field = NULL;
    sess->field_end = NULL;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_name(ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return NGX_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return NGX_ERROR;
        }

        if (ch <= 0x20 || ch == 0x7f) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_value(ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_rst_stream(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {
        if (sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          sess->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            sess->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            sess->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            sess->error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                           "http proxy error: %ui", sess->error);

            break;
        }
    }

    sess->rest -= p - b->pos;
    sess->frame_state = state;
    b->pos = p;

    if (sess->rest > 0) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_goaway(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->rest < 8) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          sess->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                       "http proxy goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->frame_goaway_last_stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            sess->frame_goaway_last_stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            sess->frame_goaway_last_stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            sess->frame_goaway_last_stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            sess->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            sess->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            sess->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            sess->error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    sess->rest -= p - b->pos;
    sess->frame_state = state;
    b->pos = p;

    if (sess->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   sess->error, sess->frame_goaway_last_stream_id);

    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {
        if (sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          sess->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                       "http proxy window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            sess->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            sess->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            sess->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    sess->rest -= p - b->pos;
    sess->frame_state = state;
    b->pos = p;

    if (sess->rest > 0) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                   "http proxy window update: %ui", sess->window_update);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_settings(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    ngx_log_t  *log;
    enum {
        sw_start = 0,
        sw_id,
        sw_id_2,
        sw_value,
        sw_value_2,
        sw_value_3,
        sw_value_4
    } state;

    log = &sess->log;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy settings ack");

            if (sess->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              sess->rest);
                return NGX_ERROR;
            }

            sess->state = ngx_http_proxy_v2_st_start;

            return NGX_DONE;
        }

        if (sess->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          sess->rest);
            return NGX_ERROR;
        }

        state = sw_id;
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            sess->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            sess->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            sess->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            sess->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            sess->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            sess->setting_value |= ch;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy setting: %ui %ui",
                           sess->setting_id, sess->setting_value);

            if (sess->setting_id == 0x04
                && sess->setting_value > NGX_HTTP_V2_MAX_WINDOW)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with too large initial window size: %ui",
                              sess->setting_value);
                return NGX_ERROR;
            }

            p++;
            sess->rest -= p - b->pos;
            sess->frame_state = sw_id;
            b->pos = p;

            return NGX_OK;
        }
    }

    sess->rest -= p - b->pos;
    sess->frame_state = state;
    b->pos = p;

    if (sess->rest > 0) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_data_2,
        sw_data_3,
        sw_data_4,
        sw_data_5,
        sw_data_6,
        sw_data_7,
        sw_data_8
    } state;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          sess->rest);
            return NGX_ERROR;
        }

        if (sess->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent ping frame with ack flag");
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                       "http proxy ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            sess->ping_data[state] = ch;
            state++;

        } else {
            sess->ping_data[7] = ch;
            state = sw_start;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                           "http proxy ping");
        }
    }

    sess->rest -= p - b->pos;
    sess->frame_state = state;
    b->pos = p;

    if (sess->rest > 0) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_settings_ack(ngx_http_proxy_v2_session_t *sess)
{
    ngx_chain_t                *cl;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                   "http proxy send settings ack");

    cl = ngx_http_proxy_v2_get_control(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_SETTINGS_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_ping_ack(ngx_http_proxy_v2_session_t *sess)
{
    ngx_chain_t                *cl;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                   "http proxy send ping ack");

    cl = ngx_http_proxy_v2_get_control(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_PING_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = ngx_copy(cl->buf->last, sess->ping_data, 8);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_window_update(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream)
{
    size_t                     n;
    ngx_chain_t               *cl;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, &sess->log, 0,
                   "http proxy send window update: %uz %uz",
                   sess->recv_window, stream ? stream->recv_window : 0);

    cl = ngx_http_proxy_v2_get_control(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    n = NGX_HTTP_V2_MAX_WINDOW - sess->recv_window;
    sess->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    if (stream == NULL) {
        return NGX_OK;
    }

    cl = ngx_http_proxy_v2_get_control(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (stream->id & 0xff);

    n = NGX_HTTP_V2_MAX_WINDOW - stream->recv_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_control(ngx_http_proxy_v2_session_t *sess)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = sess->control_free;

    if (cl) {
        sess->control_free = cl->next;

    } else {
        if (sess->controls == NGX_HTTP_PROXY_V2_MAX_CONTROL) {
            ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                          "upstream sent too many http2 control frames");
            return NULL;
        }

        b = ngx_create_temp_buf(sess->pool,
                               sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (b == NULL) {
            return NULL;
        }

        cl = ngx_alloc_chain_link(sess->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        sess->controls++;
    }

    cl->buf->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_get_control;
    cl->buf->flush = 1;
    cl->next = NULL;
    *sess->control_last = cl;
    sess->control_last = &cl->next;

    return cl;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_buf(ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {

        start = ngx_palloc(r->pool, sizeof(ngx_http_proxy_v2_frame_t));
        if (start == NULL) {
            return NULL;
        }

    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + sizeof(ngx_http_proxy_v2_frame_t);

    b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static ngx_int_t
ngx_http_proxy_v2_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_peer_connection_t     *pc;
    ngx_http_proxy_v2_peer_t  *peer;

    peer = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_peer_t));
    if (peer == NULL) {
        return NGX_ERROR;
    }

    pc = &r->upstream->peer;

    peer->request = r;
    peer->ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    peer->data = pc->data;
    peer->get = pc->get;
    peer->free = pc->free;
    peer->notify = pc->notify;

    pc->data = peer;
    pc->get = ngx_http_proxy_v2_get_peer;
    pc->free = ngx_http_proxy_v2_free_peer;

    if (pc->notify) {
        pc->notify = ngx_http_proxy_v2_notify_peer;
    }

#if (NGX_HTTP_SSL)
    peer->set_session = pc->set_session;
    peer->save_session = pc->save_session;

    if (pc->set_session) {
        pc->set_session = ngx_http_proxy_v2_set_session;
    }

    if (pc->save_session) {
        pc->save_session = ngx_http_proxy_v2_save_session;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_init_stream(ngx_http_request_t *r)
{
    ngx_connection_t            *c, *sc;
    ngx_http_proxy_v2_peer_t    *peer;
    ngx_http_proxy_v2_stream_t  *stream;

    peer = r->upstream->peer.data;

    if (peer->stream) {
        /* Retry reinitialization clears the module context after checkout. */

        peer->ctx->stream = peer->stream;

    } else {
        peer->session = ngx_http_proxy_v2_create_session(r);
        if (peer->session == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_proxy_v2_create_stream(r, peer) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    stream = peer->stream;
    c = peer->session->connection;
    sc = &stream->connection;

    sc->fd = (ngx_socket_t) -1;
    sc->logical = 1;
    sc->data = r;
    sc->pool = r->pool;
    sc->log = r->connection->log;
    sc->read = &stream->read;
    sc->write = &stream->write;
    sc->recv = ngx_http_proxy_v2_recv;
    sc->recv_chain = ngx_http_proxy_v2_recv_chain;
    sc->send_chain = ngx_http_proxy_v2_send_chain;
    sc->sendfile = c->sendfile && r->connection->sendfile;
    sc->buffered = c->buffered;
    sc->number = c->number;
    sc->start_time = c->start_time;
    sc->type = c->type;
    sc->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    sc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    sc->read->data = sc;
    sc->read->log = sc->log;
    sc->read->index = NGX_INVALID_INDEX;
    sc->read->available = -1;
    sc->read->ready = c->read->ready;
    sc->read->handler = ngx_http_proxy_v2_stream_handler;

    sc->write->data = sc;
    sc->write->log = sc->log;
    sc->write->index = NGX_INVALID_INDEX;
    sc->write->write = 1;
    sc->write->ready = c->write->ready;
    sc->write->handler = ngx_http_proxy_v2_stream_handler;

    r->upstream->connection = sc;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_connection_handler(ngx_event_t *ev)
{
    ngx_event_t                  *sev;
    ngx_connection_t             *c, *sc;
    ngx_rbtree_node_t            *node;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *session;

    c = ev->data;
    session = c->data;

    if (session->closing) {
        return;
    }

    if (c->error || c->close || c->read->error || c->write->error) {
        ngx_http_proxy_v2_close_session(session);
        return;
    }

    if (session->idle) {
        if (!ev->write) {
            ngx_http_proxy_v2_idle_handler(ev);
        }

        return;
    }

    if (session->nstreams == 0) {
        return;
    }

    node = ngx_rbtree_min(session->streams.root, session->streams.sentinel);
    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    sc = &stream->connection;

    if (!sc->logical) {
        return;
    }

    sev = ev->write ? sc->write : sc->read;

    /* TLS can redirect readiness from the opposite socket event. */

    if (ngx_handle_read_event(c->read, 0) != NGX_OK
        || ngx_handle_write_event(c->write, 0) != NGX_OK)
    {
        c->error = 1;
        ngx_http_proxy_v2_close_session(session);
        return;
    }

    sc->error |= c->error || c->close;
    sev->error |= ev->error;
    sev->ready = 1;

    ngx_post_event(sev, &ngx_posted_events);
}


static void
ngx_http_proxy_v2_stream_handler(ngx_event_t *ev)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_http_request_t          *r;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_stream_t  *stream;

    c = ev->data;
    stream = (ngx_http_proxy_v2_stream_t *) c;

    if (ev->timedout
        || (!ev->write && stream->session->closing && stream->done))
    {
        goto done;
    }

    rc = ngx_http_proxy_v2_test_io(c, ev->write);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        r = c->data;
        u = r->upstream;

        /* Failure must reach a pipe which has no receive buffer available. */

        if (u->pipe && u->pipe->upstream == c) {
            u->pipe->upstream_error = 1;
        }

        ev = c->read;
        ev->error = 1;
        ev->ready = 1;
        ev->delayed = 0;

        if (ev->timer_set) {
            ngx_del_timer(ev);
        }
    }

done:

    ngx_http_upstream_handler(ev);
}


static ngx_int_t
ngx_http_proxy_v2_test_io(ngx_connection_t *c, ngx_uint_t write)
{
    ngx_event_t                 *ev;
    ngx_connection_t            *pc;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = (ngx_http_proxy_v2_stream_t *) c;
    pc = stream->session->connection;

    if (stream->session->closing || pc == NULL
        || c->error || c->read->error || c->write->error
        || pc->error || pc->close || pc->read->error || pc->write->error)
    {
        c->error = 1;
        ev = write ? c->write : c->read;
        ev->ready = 0;
        ev->error = 1;
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL)
    if (pc->ssl) {
        if (write && pc->ssl->saved_write_handler) {
            c->write->ready = 0;

            if (pc->write->ready) {
                c->read->ready = 1;
                ngx_post_event(c->read, &ngx_posted_events);
            }

            return NGX_AGAIN;
        }

        if (!write && pc->ssl->saved_read_handler) {
            c->read->ready = 0;

            if (pc->read->ready) {
                c->write->ready = 1;
                ngx_post_event(c->write, &ngx_posted_events);
            }

            return NGX_AGAIN;
        }

        if (write && pc->ssl->saved_read_handler && !pc->read->ready) {
            c->write->ready = 0;
            return NGX_AGAIN;
        }

        if (!write && pc->ssl->saved_write_handler && !pc->write->ready) {
            c->read->ready = 0;
            return NGX_AGAIN;
        }
    }
#endif

    return NGX_OK;
}


static void
ngx_http_proxy_v2_set_read_handler(ngx_connection_t *c,
    ngx_event_handler_pt handler)
{
#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler) {
        c->ssl->saved_read_handler = handler;
        return;
    }
#endif

    c->read->handler = handler;
}


static void
ngx_http_proxy_v2_set_write_handler(ngx_connection_t *c,
    ngx_event_handler_pt handler)
{
#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_write_handler) {
        c->ssl->saved_write_handler = handler;
        return;
    }
#endif

    c->write->handler = handler;
}


static ssize_t
ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                      n;
    ngx_connection_t            *pc;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = (ngx_http_proxy_v2_stream_t *) c;
    pc = stream->session->connection;

    if (stream->session->closing && stream->done) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    n = ngx_http_proxy_v2_test_io(c, 0);
    if (n != NGX_OK) {
        return n;
    }

    n = pc->recv(pc, buf, size);

    return ngx_http_proxy_v2_handle_stream_read(c, n);
}


static ssize_t
ngx_http_proxy_v2_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ssize_t                      n;
    ngx_connection_t            *pc;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = (ngx_http_proxy_v2_stream_t *) c;
    pc = stream->session->connection;

    if (stream->session->closing && stream->done) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    n = ngx_http_proxy_v2_test_io(c, 0);
    if (n != NGX_OK) {
        return n;
    }

    n = pc->recv_chain(pc, in, limit);

    return ngx_http_proxy_v2_handle_stream_read(c, n);
}


static ssize_t
ngx_http_proxy_v2_handle_stream_read(ngx_connection_t *c, ssize_t n)
{
    ngx_connection_t            *pc;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = (ngx_http_proxy_v2_stream_t *) c;
    pc = stream->session->connection;

    c->read->ready = pc->read->ready;
    c->read->eof = pc->read->eof;
    c->read->error = pc->read->error;
    c->error |= pc->error;

    if (n == NGX_AGAIN) {
        c->read->ready = 0;

        if (pc->read->posted) {
            ngx_delete_posted_event(pc->read);
        }
    }

    if (ngx_handle_read_event(pc->read, pc->read->eof ? NGX_CLOSE_EVENT : 0)
        != NGX_OK)
    {
        pc->error = 1;
        c->error = 1;
        c->read->ready = 0;
        c->read->error = 1;
        return NGX_ERROR;
    }

    return n;
}


static ngx_chain_t *
ngx_http_proxy_v2_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    off_t                        sent;
    ngx_int_t                    rc;
    ngx_chain_t                 *cl;
    ngx_connection_t            *pc;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = (ngx_http_proxy_v2_stream_t *) c;
    pc = stream->session->connection;
    r = c->data;

    rc = ngx_http_proxy_v2_test_io(c, 1);
    if (rc != NGX_OK) {
        return (rc == NGX_ERROR) ? NGX_CHAIN_ERROR : in;
    }

    sent = pc->sent;
    cl = pc->send_chain(pc, in, limit);

    c->sent += pc->sent - sent;
    c->buffered = pc->buffered;
    c->write->ready = pc->write->ready;
    c->write->error = pc->write->error;
    c->error |= pc->error;

    if (cl == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

#if (NGX_HTTP_SSL)
    if (pc->ssl && pc->ssl->saved_read_handler && !pc->read->ready) {
        c->write->ready = 0;
    }
#endif

    if (ngx_handle_write_event(pc->write, r->upstream->conf->send_lowat)
        != NGX_OK)
    {
        pc->error = 1;
        c->error = 1;
        c->write->error = 1;
        return NGX_CHAIN_ERROR;
    }

    if (cl == NULL && c->buffered && c->write->ready) {
        ngx_post_event(c->write, &ngx_posted_next_events);
    }

    return cl;
}


static ngx_int_t
ngx_http_proxy_v2_create_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_peer_t *peer)
{
    size_t                        budget;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *session;

    if (ngx_http_proxy_v2_init_header_budget(r, &budget) != NGX_OK) {
        return NGX_ERROR;
    }

    session = peer->session;

    /* only one stream can use the request-driven I/O path */

    if (session->nstreams) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too many active http2 streams");
        return NGX_ERROR;
    }

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_stream_t));
    if (stream == NULL) {
        return NGX_ERROR;
    }

    stream->session = session;
    stream->request = r;
    stream->id = session->last_stream_id ? session->last_stream_id + 2 : 1;
    stream->header_budget = budget;
    stream->send_window = session->init_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    stream->node.key = stream->id;
    ngx_rbtree_insert(&session->streams, &stream->node);
    session->nstreams++;
    session->ref_count++;

    session->last_stream_id = stream->id;
    peer->ctx->stream = stream;
    peer->stream = stream;

    return NGX_OK;
}


static void
ngx_http_proxy_v2_detach_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;

    /* Checkout can fail before the logical endpoint is installed. */

    if (stream->connection.logical) {
        if (stream->read.timer_set) {
            ngx_del_timer(&stream->read);
        }

        if (stream->write.timer_set) {
            ngx_del_timer(&stream->write);
        }

        if (stream->read.posted) {
            ngx_delete_posted_event(&stream->read);
        }

        if (stream->write.posted) {
            ngx_delete_posted_event(&stream->write);
        }

        stream->read.closed = 1;
        stream->write.closed = 1;
        stream->connection.data = NULL;
    }

    if (session->header_stream_id == stream->id) {
        session->header_discard = 1;
        ngx_http_proxy_v2_clear_header(session);
    }

    ngx_rbtree_delete(&session->streams, &stream->node);
    session->nstreams--;

    stream->in = NULL;
    stream->request = NULL;
    stream->session = NULL;

    ngx_http_proxy_v2_release_session(session);
}


static ngx_rbtree_key_t
ngx_http_proxy_v2_session_key(ngx_http_upstream_t *u)
{
    uint32_t  hash;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) &u->upstream, sizeof(u->upstream));
    ngx_crc32_update(&hash, (u_char *) &u->conf, sizeof(u->conf));
    ngx_crc32_update(&hash, (u_char *) u->peer.sockaddr, u->peer.socklen);
    ngx_crc32_final(hash);

    return hash;
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_find_session(ngx_http_upstream_t *u)
{
    ngx_rbtree_key_t              key;
    ngx_rbtree_node_t            *node, *next, *first, *sentinel;
    ngx_http_proxy_v2_session_t  *session;

    key = ngx_http_proxy_v2_session_key(u);
    node = ngx_http_proxy_v2_sessions.root;
    sentinel = ngx_http_proxy_v2_sessions.sentinel;
    first = NULL;

    /* Equal keys can be on either side after tree rotations. */

    while (node != sentinel) {
        if (key > node->key) {
            node = node->right;

        } else {
            if (key == node->key) {
                first = node;
            }

            node = node->left;
        }
    }

    for (node = first; node && node->key == key; node = next) {
        next = ngx_rbtree_next(&ngx_http_proxy_v2_sessions, node);
        session = ngx_rbtree_data(node, ngx_http_proxy_v2_session_t, node);

        if (!session->idle
            || ngx_http_proxy_v2_match_session(session, u) != NGX_OK)
        {
            continue;
        }

        if (ngx_http_proxy_v2_reusable_session(session) != NGX_OK
            || (ngx_msec_int_t) (ngx_current_msec
                                 - session->connection->read->timer.key) >= 0)
        {
            ngx_http_proxy_v2_close_session(session);
            continue;
        }

        return session;
    }

    return NULL;
}


static ngx_int_t
ngx_http_proxy_v2_match_session(ngx_http_proxy_v2_session_t *session,
    ngx_http_upstream_t *u)
{
    ngx_peer_connection_t  *pc;

    pc = &u->peer;

    if (session->upstream != u->upstream
        || session->conf != u->conf
        || ngx_memn2cmp((u_char *) &session->sockaddr,
                       (u_char *) pc->sockaddr, session->socklen, pc->socklen)
           != 0
        || session->socket_type != (pc->type ? pc->type : SOCK_STREAM)
        || session->rcvbuf != pc->rcvbuf
        || session->sndbuf != pc->sndbuf
        || session->transparent != pc->transparent
        || session->so_keepalive != pc->so_keepalive)
    {
        return NGX_DECLINED;
    }

    if (pc->local) {
        if (ngx_memn2cmp((u_char *) &session->local_sockaddr,
                        (u_char *) pc->local->sockaddr,
                        session->local_socklen, pc->local->socklen)
            != 0)
        {
            return NGX_DECLINED;
        }

    } else if (session->local_socklen) {
        return NGX_DECLINED;
    }

#if (NGX_HTTP_SSL)
    if (u->ssl != (session->connection->ssl != NULL)) {
        return NGX_DECLINED;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_reusable_session(ngx_http_proxy_v2_session_t *session)
{
    ngx_connection_t                   *c;
    ngx_http_upstream_keepalive_conf_t  *kcf;

    if (session->closing || session->connection == NULL
        || session->srv_conf == NULL || session->upstream->keepalive == NULL)
    {
        return NGX_DECLINED;
    }

    c = session->connection;
    kcf = session->upstream->keepalive;

    if (kcf->max_cached == 0
        || c->requests >= kcf->requests
        || ngx_current_msec - c->start_time > kcf->time
        || c->error
        || c->close
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout
        || c->buffered
        || session->nstreams
        || session->goaway
        || session->state != ngx_http_proxy_v2_st_start
        || session->header_stream_id
        || session->last_stream_id == 0x7fffffff
        || ngx_terminate
        || ngx_exiting)
    {
        return NGX_DECLINED;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl
        && (c->ssl->saved_read_handler || c->ssl->saved_write_handler
            || SSL_pending(c->ssl->connection)
            || (c->read->posted && !c->read->ready)))
    {
        return NGX_DECLINED;
    }
#endif

    return NGX_OK;
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_create_session(ngx_http_request_t *r)
{
    ngx_connection_t             *c;
    ngx_pool_cleanup_t           *cln;
    ngx_peer_connection_t        *pc;
    ngx_http_upstream_t          *u;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_proxy_v2_session_t  *session;

    u = r->upstream;
    pc = &u->peer;
    c = pc->connection;

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NULL;
    }

    session = cln->data;

    ngx_memzero(session, sizeof(ngx_http_proxy_v2_session_t));

    if (u->upstream && u->upstream->srv_conf) {
        session->srv_conf = ngx_http_conf_upstream_srv_conf(u->upstream,
                                                     ngx_http_proxy_v2_module);
    }

    session->upstream = u->upstream;
    session->conf = u->conf;
    session->socklen = pc->socklen;
    ngx_memcpy(&session->sockaddr, pc->sockaddr, pc->socklen);

    if (pc->local) {
        session->local_socklen = pc->local->socklen;
        ngx_memcpy(&session->local_sockaddr, pc->local->sockaddr,
                   pc->local->socklen);
    }

    session->socket_type = pc->type ? pc->type : SOCK_STREAM;
    session->rcvbuf = pc->rcvbuf;
    session->sndbuf = pc->sndbuf;
    session->transparent = pc->transparent;
    session->so_keepalive = pc->so_keepalive;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    session->log = *clcf->error_log;
    session->log.connection = c->number;
    session->log.handler = ngx_http_proxy_v2_log_error;
    session->log.data = session;
    session->log.action = "proxying HTTP/2 upstream";

    session->connection = c;
    session->pool = c->pool;
    session->ref_count = 1;
    ngx_queue_insert_tail(&ngx_http_proxy_v2_sessions_queue,
                          &session->sessions_queue);
    session->control_last = &session->control;
    ngx_rbtree_init(&session->streams, &session->sentinel,
                    ngx_rbtree_insert_value);
    session->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    session->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    session->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    cln->handler = ngx_http_proxy_v2_session_cleanup;

    session->node.key = ngx_http_proxy_v2_session_key(u);
    ngx_rbtree_insert(&ngx_http_proxy_v2_sessions, &session->node);
    session->registered = 1;

    u->peer_managed = 1;
    c->data = session;
    c->log = &session->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    ngx_http_proxy_v2_set_read_handler(c,
                                          ngx_http_proxy_v2_connection_handler);
    ngx_http_proxy_v2_set_write_handler(c,
                                          ngx_http_proxy_v2_connection_handler);

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->handler = NULL;
        c->ssl->save_session = u->conf->ssl_session_reuse
                              ? ngx_http_proxy_v2_ssl_save_session : NULL;
    }
#endif

    return session;
}


static u_char *
ngx_http_proxy_v2_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    ngx_http_proxy_v2_session_t  *session = log->data;

    ngx_str_t  address;
    u_char     text[NGX_SOCKADDR_STRLEN];

    address.data = text;
    address.len = ngx_sock_ntop((struct sockaddr *) &session->sockaddr,
                               session->socklen, text, sizeof(text), 1);

    return ngx_snprintf(buf, len, ", upstream: \"%V\"", &address);
}


static ngx_int_t
ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_session_t  *session;

    peer->session = NULL;

    rc = peer->get(pc, peer->data);
    if (rc != NGX_OK && rc != NGX_DONE) {
        return rc;
    }

    u = peer->request->upstream;

    if (rc == NGX_DONE) {
        c = pc->connection;
        pc->connection = NULL;
        pc->cached = 0;

        if (c) {
            c->data = NULL;
            c->log = ngx_cycle->log;
            c->read->log = c->log;
            c->write->log = c->log;

            if (c->pool) {
                c->pool->log = c->log;
            }

            ngx_http_proxy_v2_close_connection(c);
        }
    }

    session = ngx_http_proxy_v2_find_session(u);
    if (session == NULL) {
        return NGX_OK;
    }

    ngx_http_proxy_v2_remove_idle(session);

    c = session->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http2 pool using connection %p", c);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;
    peer->session = session;
    u->peer_managed = 1;

    if (ngx_http_proxy_v2_create_stream(peer->request, peer) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}


static void
ngx_http_proxy_v2_remove_idle(ngx_http_proxy_v2_session_t *session)
{
    if (session->idle) {
        ngx_queue_remove(&session->queue);
        session->srv_conf->nidle--;
        session->idle = 0;
        session->connection->idle = 0;
    }
}


static void
ngx_http_proxy_v2_close_session(ngx_http_proxy_v2_session_t *session)
{
    ngx_connection_t            *c, *sc;
    ngx_rbtree_node_t           *node;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_stream_t  *stream;

    if (session->closing) {
        return;
    }

    session->ref_count++;
    ngx_http_proxy_v2_remove_idle(session);
    session->closing = 1;
    c = session->connection;

    if (session->nstreams) {
        for (node = ngx_rbtree_min(session->streams.root,
                                  session->streams.sentinel);
             node; node = ngx_rbtree_next(&session->streams, node))
        {
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
            u = stream->request->upstream;
            u->keepalive = 0;
            u->peer.connection = NULL;

            if (u->connection == c) {
                u->connection = NULL;
                u->writer.connection = NULL;
            }

            sc = &stream->connection;

            if (!sc->logical) {
                continue;
            }

            sc->buffered = 0;

            if (stream->done) {
                u->length = 0;

                if (u->pipe) {
                    u->pipe->length = 0;
                }

                sc->read->eof = 1;

            } else {
                sc->error = 1;
                sc->read->error = 1;
            }

            if (sc->read->timer_set) {
                ngx_del_timer(sc->read);
            }

            sc->read->timedout = 0;
            sc->read->delayed = 0;

            if (sc->write->timer_set) {
                ngx_del_timer(sc->write);
            }

            if (sc->write->posted) {
                ngx_delete_posted_event(sc->write);
            }

            sc->read->ready = 1;
            ngx_post_event(sc->read, &ngx_posted_events);
        }
    }

    ngx_http_proxy_v2_close_connection(c);
    ngx_http_proxy_v2_release_session(session);
}


static void
ngx_http_proxy_v2_close_connection(ngx_connection_t *c)
{
    ngx_pool_t                   *pool;
    ngx_http_proxy_v2_session_t  *session;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->save_session = NULL;
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_proxy_v2_close_connection;
            return;
        }
    }

#endif

    pool = c->pool;
    session = c->data;
    ngx_close_connection(c);

    if (session) {
        session->connection = NULL;
        ngx_http_proxy_v2_session_cleanup(session);
        ngx_http_proxy_v2_release_session(session);

    } else if (pool) {
        ngx_destroy_pool(pool);
    }
}


static void
ngx_http_proxy_v2_release_session(ngx_http_proxy_v2_session_t *session)
{
    if (--session->ref_count == 0) {
        ngx_queue_remove(&session->sessions_queue);
        ngx_destroy_pool(session->pool);
    }
}


static void
ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    ngx_uint_t                          keep;
    ngx_queue_t                        *q;
    ngx_connection_t                   *c;
    ngx_http_upstream_t                *u;
    ngx_http_proxy_v2_stream_t         *stream;
    ngx_http_proxy_v2_session_t        *session, *old;
    ngx_http_proxy_v2_srv_conf_t       *conf;
    ngx_http_upstream_keepalive_conf_t  *kcf;

    u = peer->request->upstream;
    c = pc->connection;
    session = peer->session;
    stream = peer->stream;

    if (session) {
        session->ref_count++;
    }

    keep = !(state & NGX_PEER_FAILED) && c && stream
           && u->keepalive && u->request_body_sent
           && stream->input_closed && stream->output_closed
           && stream->in == NULL && session->control == NULL
           && !peer->ctx->output_blocked && u->writer.out == NULL
           && !stream->connection.error && !stream->connection.close
           && !stream->read.eof && !stream->read.error && !stream->read.timedout
           && !stream->write.error && !stream->write.timedout;

    /* module contexts may have been cleared by an internal redirect */

    if (stream) {
        ngx_http_proxy_v2_detach_stream(stream);

        if (peer->ctx->stream == stream) {
            peer->ctx->stream = NULL;
        }

        peer->stream = NULL;
    }

    peer->session = NULL;

    if (session == NULL) {
        peer->free(pc, peer->data, state);
        return;
    }

    pc->connection = NULL;
    peer->free(pc, peer->data, state);

    if (!keep || ngx_http_proxy_v2_reusable_session(session) != NGX_OK
        || ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        ngx_http_proxy_v2_close_session(session);
        ngx_http_proxy_v2_release_session(session);
        return;
    }

    conf = session->srv_conf;
    kcf = session->upstream->keepalive;

    if (conf->nidle == kcf->max_cached) {
        q = ngx_queue_last(&conf->idle);
        old = ngx_queue_data(q, ngx_http_proxy_v2_session_t, queue);
        ngx_http_proxy_v2_close_session(old);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http2 pool saving connection %p", c);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->idle = 1;
    c->read->delayed = 0;

    ngx_queue_insert_head(&conf->idle, &session->queue);
    conf->nidle++;
    session->idle = 1;

    ngx_add_timer(c->read, kcf->timeout);

    if (c->read->ready) {
        ngx_http_proxy_v2_idle_handler(c->read);
    }

    ngx_http_proxy_v2_release_session(session);
}


static void
ngx_http_proxy_v2_idle_handler(ngx_event_t *ev)
{
    char                          buf[1];
    ssize_t                       n;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *session;

    c = ev->data;
    session = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 pool idle handler");

    if (!c->close && !ev->timedout) {
        n = recv(c->fd, buf, 1, MSG_PEEK);

        if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
            ev->ready = 0;

            if (ngx_handle_read_event(ev, 0) == NGX_OK) {
                return;
            }
        }
    }

    ngx_http_proxy_v2_close_session(session);
}


static void
ngx_http_proxy_v2_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    peer->notify(pc, peer->data, type);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_proxy_v2_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    return peer->set_session(pc, peer->data);
}


static void
ngx_http_proxy_v2_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    peer->save_session(pc, peer->data);
}


static void
ngx_http_proxy_v2_ssl_save_session(ngx_connection_t *c)
{
    ngx_rbtree_node_t            *node;
    ngx_http_request_t           *r;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *session;

    session = c->data;

    if (session->closing || session->idle || session->nstreams == 0) {
        return;
    }

    node = ngx_rbtree_min(session->streams.root, session->streams.sentinel);
    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

    if (!stream->connection.logical || stream->connection.data == NULL) {
        return;
    }

    r = stream->connection.data;
    u = r->upstream;

    if (u->connection != &stream->connection || u->peer.connection != c
        || u->peer.sockaddr == NULL || u->peer.save_session == NULL
        || !u->conf->ssl_session_reuse)
    {
        return;
    }

    ngx_http_set_log_request(r->connection->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}

#endif


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    ngx_http_proxy_v2_session_t  *session = data;

    ngx_http_proxy_v2_remove_idle(session);

    if (session->registered) {
        ngx_rbtree_delete(&ngx_http_proxy_v2_sessions, &session->node);
        session->registered = 0;
    }
}


static void
ngx_http_proxy_v2_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort proxy http2 request");
    return;
}


static void
ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize proxy http2 request");
    return;
}


static void *
ngx_http_proxy_v2_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_v2_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_v2_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_queue_init(&conf->idle);

    return conf;
}


static ngx_int_t
ngx_http_proxy_v2_init_process(ngx_cycle_t *cycle)
{
    /* Preserve registrations across single-process configuration reloads. */

    ngx_rbtree_init(&ngx_http_proxy_v2_sessions,
                    &ngx_http_proxy_v2_sessions_sentinel,
                    ngx_rbtree_insert_value);

    ngx_queue_init(&ngx_http_proxy_v2_sessions_queue);

    return NGX_OK;
}


static void
ngx_http_proxy_v2_exit_process(ngx_cycle_t *cycle)
{
    ngx_queue_t                  *q;
    ngx_connection_t             *c;
    ngx_rbtree_node_t            *node;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *session;

    while (!ngx_queue_empty(&ngx_http_proxy_v2_sessions_queue)) {
        q = ngx_queue_head(&ngx_http_proxy_v2_sessions_queue);
        session = ngx_queue_data(q, ngx_http_proxy_v2_session_t, sessions_queue);
        session->ref_count++;

        ngx_http_proxy_v2_remove_idle(session);

        while (session->nstreams) {
            node = ngx_rbtree_min(session->streams.root,
                                 session->streams.sentinel);
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
            u = stream->request->upstream;
            u->keepalive = 0;
            ngx_http_proxy_v2_free_peer(&u->peer, u->peer.data, 0);
            u->peer.sockaddr = NULL;
            u->connection = NULL;
            u->writer.connection = NULL;

            if (u->pipe) {
                u->pipe->upstream = NULL;
            }
        }

        c = session->connection;

        if (c) {
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->save_session = NULL;
                ngx_ssl_ocsp_cleanup(c);
                SSL_free(c->ssl->connection);
                c->ssl = NULL;
            }
#endif

            ngx_http_proxy_v2_close_connection(c);
        }

        ngx_http_proxy_v2_release_session(session);
    }
}
