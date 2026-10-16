
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>


#define NGX_HTTP_PROXY_V2_PROTOCOL_ERROR        0x1
#define NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR       0x3
#define NGX_HTTP_PROXY_V2_STREAM_CLOSED         0x5
#define NGX_HTTP_PROXY_V2_ENHANCE_YOUR_CALM     0xb


#define NGX_HTTP_PROXY_V2_MAX_OUTPUT_FRAMES  16
#define NGX_HTTP_PROXY_V2_MAX_INPUT_FRAMES   16

#define NGX_HTTP_PROXY_V2_MAX_ATTACHED_STREAMS  1

#define NGX_HTTP_PROXY_V2_MAX_IDLE           32
#define NGX_HTTP_PROXY_V2_IDLE_TIMEOUT       60000
#define NGX_HTTP_PROXY_V2_SESSION_TIME       3600000
#define NGX_HTTP_PROXY_V2_SESSION_REQUESTS   1000


typedef struct {
    ngx_rbtree_t                         sessions;
    ngx_rbtree_node_t                    sentinel;

    ngx_queue_t                          idle;
    ngx_uint_t                           nidle;

    ngx_http_upstream_keepalive_conf_t  *keepalive;
} ngx_http_proxy_v2_conf_t;


typedef struct ngx_http_proxy_v2_peer_s  ngx_http_proxy_v2_peer_t;


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
    ngx_http_proxy_v2_st_payload
} ngx_http_proxy_v2_state_e;


typedef struct ngx_http_proxy_v2_headers_s  ngx_http_proxy_v2_headers_t;


typedef struct {
    ngx_connection_t              *connection;
    ngx_http_proxy_v2_conf_t      *conf;
    ngx_rbtree_node_t              node;
    ngx_queue_t                    cache;
    ngx_str_t                      key;
    ngx_sockaddr_t                 sockaddr;
    socklen_t                      socklen;
    ngx_log_t                      log;
    ngx_buf_t                     *buffer;
    off_t                          received;

    ngx_rbtree_t                   streams;
    ngx_rbtree_node_t              sentinel;
    ngx_uint_t                     nstreams;  /* attached request streams */
    ngx_uint_t                     nreserved;
    ngx_msec_t                     idle_deadline;

    ngx_chain_writer_ctx_t         writer;
    size_t                         send_lowat;
    ngx_chain_t                   *out;
    ngx_chain_t                  **last_out;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
    ngx_uint_t                     detached_output_id;
    ngx_uint_t                     pings;
    ngx_uint_t                     settings;

    ngx_http_proxy_v2_state_e      state;
    ngx_uint_t                     frame_state;
    size_t                         rest;
    ngx_uint_t                     stream_id;
    ngx_uint_t                     header_stream_id;
    u_char                         type;
    u_char                         flags;

    ngx_uint_t                     goaway_last_stream_id;
    ngx_uint_t                     goaway_error;
    ngx_uint_t                     rst_error;
    ngx_uint_t                     window_update;
    ngx_uint_t                     setting_id;
    ngx_uint_t                     setting_value;
    u_char                         ping_data[8];

    ngx_pool_t                    *header_pool;
    ngx_http_proxy_v2_headers_t   *header_in;
    size_t                         header_block_limit;
    size_t                         discard_header_limit;
    ngx_uint_t                     fragment_state;
    ngx_uint_t                     index;
    ngx_str_t                      name;
    ngx_str_t                      value;
    u_char                        *field_end;
    size_t                         header_limit;
    size_t                         field_length;
    size_t                         field_rest;
    u_char                         field_state;
    u_char                         padding;

    size_t                         init_window;
    size_t                         send_window;
    size_t                         recv_window;
    size_t                         recv_credit;
    ngx_uint_t                     last_stream_id;
    ngx_uint_t                     max_streams;  /* peer concurrency limit */

    unsigned                       indexed:1;
    unsigned                       cacheable:1;
    unsigned                       draining:1;
    unsigned                       closing:1;
    unsigned                       preface_sent:1;
    unsigned                       request_output:1;
    unsigned                       error:1;
    unsigned                       goaway:1;
    unsigned                       frame_closed:1;
    unsigned                       input_discard:1;
    unsigned                       literal:1;
    unsigned                       field_huffman:1;
} ngx_http_proxy_v2_session_t;


typedef struct ngx_http_proxy_v2_header_s  ngx_http_proxy_v2_header_t;

struct ngx_http_proxy_v2_header_s {
    ngx_str_t                      name;
    ngx_str_t                      value;
    ngx_http_proxy_v2_header_t    *next;
};


struct ngx_http_proxy_v2_headers_s {
    ngx_http_proxy_v2_header_t    *first;
    ngx_http_proxy_v2_header_t    *last;
    ngx_http_proxy_v2_header_t    *current;
    ngx_http_proxy_v2_headers_t   *next;
    ngx_uint_t                     count;
    off_t                          body_offset;
    size_t                         size;
    unsigned                       end_stream:1;
};


typedef struct {
    ngx_connection_t               connection;
    ngx_event_t                    read;
    ngx_event_t                    write;
    ngx_rbtree_node_t              node;
    ngx_http_proxy_v2_session_t   *session;
    ngx_http_proxy_v2_peer_t      *peer;
    ngx_pool_t                    *pool;
    ngx_uint_t                     id;
    off_t                          received;

    ngx_chain_t                   *in;

    ssize_t                        send_window;
    size_t                         recv_window;
    size_t                         recv_credit;

    ngx_uint_t                     error;

    size_t                         header_limit;
    size_t                         header_budget;  /* metadata left */
    ngx_str_t                      name;
    ngx_str_t                      value;

    ngx_http_proxy_v2_headers_t    *headers;
    ngx_http_proxy_v2_headers_t    *last_headers;
    ngx_http_proxy_v2_headers_t    *trailers;
    ngx_uint_t                     header_count;

    /*
     * Stream credit reserves ring capacity independently of connection credit.
     * The local attached-stream limit bounds total body buffering per session.
     */

    u_char                        *body;
    size_t                         body_pos;
    size_t                         body_size;
    off_t                          body_parsed;
    off_t                          body_read;
    off_t                          body_processed;

    unsigned                       header_sent:1;
    unsigned                       output_closed:1;
    unsigned                       trailer:1;
    unsigned                       end_stream:1;
    unsigned                       input_closing:1;
    unsigned                       input_closed:1;
    unsigned                       done:1;
    unsigned                       rst:1;
    unsigned                       invalid_header:1;
    unsigned                       reset_sent:1;  /* local reset queued */
} ngx_http_proxy_v2_stream_t;


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_http_proxy_v2_stream_t    *stream;

    ngx_str_t                      host;
    off_t                          length;

    unsigned                       status:1;
} ngx_http_proxy_v2_ctx_t;


struct ngx_http_proxy_v2_peer_s {
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_stream_t    *stream;
    ngx_http_proxy_v2_session_t   *session;
    ngx_http_proxy_v2_conf_t      *conf;
    ngx_http_upstream_t           *upstream;
    ngx_log_t                     *log;
    ngx_str_t                      key;

    void                          *data;
    ngx_event_get_peer_pt          get;
    ngx_event_free_peer_pt         free;
    ngx_event_notify_peer_pt       notify;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt  set_session;
    ngx_event_save_peer_session_pt save_session;
    unsigned                       ssl_session_reuse:1;
#endif

    unsigned                       cacheable:1;
    unsigned                       reserved:1;
    unsigned                       rejected:1;
};


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
static ngx_int_t ngx_http_proxy_v2_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_proxy_v2_init_connection(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_v2_output_stream(
    ngx_http_proxy_v2_stream_t *stream);
static void ngx_http_proxy_v2_read_handler(ngx_event_t *ev);
static void ngx_http_proxy_v2_write_handler(ngx_event_t *ev);
static void ngx_http_proxy_v2_stream_read_handler(ngx_event_t *ev);
static ngx_event_handler_pt ngx_http_proxy_v2_set_read_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static ngx_event_handler_pt ngx_http_proxy_v2_set_write_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static void ngx_http_proxy_v2_notify(ngx_http_proxy_v2_session_t *sess,
    ngx_uint_t write);
static ssize_t ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_http_proxy_v2_recv_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_http_proxy_v2_send(ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_input_pending(
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_post_write(ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_write(ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_output_pending(
    ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_output_has_shadow(
    ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_session_need_close(
    ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_session_stream_limit(
    ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_session_io_pending(
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_discard_output(ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_process_headers(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_process_trailers(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_filter_init(void *data);
static ngx_int_t ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_v2_process_body(ngx_event_pipe_t *p,
    ngx_buf_t *b);
static ngx_uint_t ngx_http_proxy_v2_stream_closed(
    ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_stream_error(
    ngx_http_proxy_v2_stream_t *stream, ngx_uint_t error);
static ngx_int_t ngx_http_proxy_v2_process_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_process_connection_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b, ngx_uint_t new_frame);
static ngx_int_t ngx_http_proxy_v2_process_stream_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b, ngx_uint_t new_frame);
static ngx_int_t ngx_http_proxy_v2_process_closed_stream_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b, ngx_uint_t new_frame);
static ngx_int_t ngx_http_proxy_v2_process_data(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b, ngx_uint_t new_frame);
static ngx_int_t ngx_http_proxy_v2_process_header_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b, ngx_uint_t new_frame);
static ngx_int_t ngx_http_proxy_v2_process_window_update(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_parse_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_data(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static size_t ngx_http_proxy_v2_read_body(ngx_http_proxy_v2_stream_t *stream,
    u_char *data, size_t size);
static void ngx_http_proxy_v2_discard_body(ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_parse_header(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_fragment(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_account_header(
    ngx_http_proxy_v2_session_t *sess, size_t size);
static ngx_int_t ngx_http_proxy_v2_copy_headers(
    ngx_http_proxy_v2_stream_t *stream, ngx_http_proxy_v2_headers_t *headers);
static void ngx_http_proxy_v2_close_header(ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_read_header(
    ngx_http_proxy_v2_stream_t *stream, ngx_uint_t trailers);
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
static ngx_int_t ngx_http_proxy_v2_parse_ping(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_send_settings_ack(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(
    ngx_http_proxy_v2_session_t *sess, u_char *data);
static ngx_int_t ngx_http_proxy_v2_send_window_update(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_send_rst_stream(
    ngx_http_proxy_v2_session_t *sess, ngx_uint_t id, ngx_uint_t error);

static ngx_chain_t *ngx_http_proxy_v2_get_buf(
    ngx_http_proxy_v2_session_t *sess);
static ngx_chain_t *ngx_http_proxy_v2_get_shadow(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *buf);
static void ngx_http_proxy_v2_close_stream(ngx_http_proxy_v2_stream_t *stream);
static ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_find_stream(
    ngx_http_proxy_v2_session_t *sess, ngx_uint_t id);
static ngx_http_proxy_v2_session_t *
    ngx_http_proxy_v2_find_session(ngx_connection_t *c);
static ngx_int_t ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session);
static void ngx_http_proxy_v2_reserve_session(ngx_http_proxy_v2_peer_t *peer,
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_unreserve_session(ngx_http_proxy_v2_peer_t *peer);
static uint32_t ngx_http_proxy_v2_session_hash(ngx_str_t *key,
    struct sockaddr *sockaddr, socklen_t socklen);
static ngx_int_t ngx_http_proxy_v2_session_cmp(ngx_str_t *key,
    struct sockaddr *sockaddr, socklen_t socklen,
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_http_proxy_v2_session_t *ngx_http_proxy_v2_lookup_session(
    ngx_http_proxy_v2_peer_t *peer, ngx_peer_connection_t *pc);
static void ngx_http_proxy_v2_session_index(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_unindex(ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static void ngx_http_proxy_v2_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_v2_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_save_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_ssl_save_session(ngx_connection_t *c);
#endif

static void ngx_http_proxy_v2_session_release(
    ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_idle(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_unidle(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_retire(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_close(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_close_connection(ngx_connection_t *c);
static void ngx_http_proxy_v2_set_connection(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_session_cleanup(void *data);
static void *ngx_http_proxy_v2_create_conf(ngx_conf_t *cf);

static void ngx_http_proxy_v2_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);


static ngx_http_module_t  ngx_http_proxy_v2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_proxy_v2_create_conf,          /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_proxy_v2_create_conf,          /* create server configuration */
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
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_upstream_keepalive_conf_t  ngx_http_proxy_v2_keepalive = {
    NGX_HTTP_PROXY_V2_MAX_IDLE,
    NGX_HTTP_PROXY_V2_SESSION_REQUESTS,
    NGX_HTTP_PROXY_V2_SESSION_TIME,
    NGX_HTTP_PROXY_V2_IDLE_TIMEOUT,
    0
};


static u_char  ngx_http_proxy_v2_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x00\x00\xff\xff";                /* initial window */


ngx_int_t
ngx_http_proxy_v2_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_v2_ctx_t    *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

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
    plcf->upstream.ignore_input = 1;

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

    u->create_request = ngx_http_proxy_v2_create_request;
    u->reinit_request = ngx_http_proxy_v2_reinit_request;
    u->init_peer = ngx_http_proxy_v2_init_peer;
    u->init_connection = ngx_http_proxy_v2_init_connection;
    u->process_header = ngx_http_proxy_v2_process_header;
    u->abort_request = ngx_http_proxy_v2_abort_request;
    u->finalize_request = ngx_http_proxy_v2_finalize_request;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = 1;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_v2_body_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_proxy_v2_filter_init;
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

    headers = &plcf->headers;

    if (plcf->method) {
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

    len = sizeof(ngx_http_proxy_v2_frame_t);               /* headers frame */

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

    ctx->host = host;

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

    ctx->status = 0;
    ctx->stream = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    ngx_int_t                     rc;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    stream = ctx->stream;
    sess = stream->session;

    if (stream->read.error
        || (stream->input_closed
            && (sess->connection->error || sess->connection->read->error
                || sess->connection->read->eof)))
    {
        stream->write.ready = 0;
        stream->read.ready = 1;
        ngx_post_event(&stream->read, &ngx_posted_events);
        return NGX_AGAIN;
    }

    if (sess->connection->error) {
        return NGX_ERROR;
    }

    if (in) {
        if (ngx_chain_add_copy(stream->pool, &stream->in, in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_http_proxy_v2_post_write(sess);
    }

    rc = stream->in || ngx_http_proxy_v2_output_pending(sess)
         ? NGX_AGAIN : NGX_OK;

    stream->write.ready = (rc == NGX_OK);

    if (rc == NGX_OK && stream->input_closed) {
        stream->read.ready = 1;
        ngx_post_event(&stream->read, &ngx_posted_events);
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_output_stream(ngx_http_proxy_v2_stream_t *stream)
{
    off_t                         size;
    u_char                       *p;
    size_t                        len, limit;
    ngx_buf_t                    *b;
    ngx_log_t                    *log;
    ngx_uint_t                    next, last, frames;
    ngx_chain_t                  *cl, *in, *out, *ln, **ll;
    ngx_http_proxy_v2_frame_t    *f;
    ngx_http_proxy_v2_session_t  *sess;

    sess = stream->session;
    log = sess->connection->log;

    if (stream->in == NULL || stream->rst || stream->connection.error) {
        return NGX_OK;
    }

    out = NULL;
    ll = &out;

    if (!stream->header_sent) {
        /* SETTINGS may have arrived after the stream was attached */

        if (sess->max_streams == 0) {
            return NGX_OK;
        }

        /* first buffer contains headers */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy output header");

        /* retries rewind the header buffer without rebuilding its frames */

        b = stream->in->buf;
        p = b->pos;

        while (p < b->last) {
            f = (ngx_http_proxy_v2_frame_t *) p;
            p += sizeof(ngx_http_proxy_v2_frame_t);

            f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (stream->id & 0xff);

            p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
        }

        if (b->last_buf) {
            stream->output_closed = 1;
        }

        cl = ngx_http_proxy_v2_get_shadow(sess, b);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        stream->header_sent = 1;
        ln = stream->in;
        stream->in = stream->in->next;
        ngx_free_chain(stream->pool, ln);
    }

    f = NULL;
    last = 0;
    frames = 0;

    limit = ngx_max(0, stream->send_window);

    if (limit > sess->send_window) {
        limit = sess->send_window;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, stream->send_window, sess->send_window);

#if (NGX_SUPPRESS_WARN)
    cl = NULL;
#endif

    in = stream->in;

    while (in) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, log, 0,
                       "http proxy output in  l:%d f:%d %p, pos %p, size: %O "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       ngx_buf_size(in->buf),
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        size = ngx_buf_size(in->buf);

        if (ngx_buf_special(in->buf) || size == 0) {
            goto next;
        }

        if (size < 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "negative size http2 request body buffer");
            return NGX_ERROR;
        }

        if (limit == 0 || frames == NGX_HTTP_PROXY_V2_MAX_OUTPUT_FRAMES) {
            break;
        }

        len = ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);
        len = (size_t) ngx_min(size, (off_t) len);
        next = (size == (off_t) len);

        cl = ngx_http_proxy_v2_get_buf(sess);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;
        f = (ngx_http_proxy_v2_frame_t *) b->last;
        b->last += sizeof(ngx_http_proxy_v2_frame_t);

        *ll = cl;
        ll = &cl->next;

        cl = ngx_http_proxy_v2_get_shadow(sess, in->buf);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;

        /* both representations must describe the same DATA payload */

        if (ngx_buf_in_memory(b)) {
            b->last = b->pos + len;
        }

        if (b->in_file) {
            b->file_last = b->file_pos + len;
        }

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
        frames++;

        if (!next) {
            /* the final shadow acknowledges complete buffer consumption */

            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos += len;
            }

            if (in->buf->in_file) {
                in->buf->file_pos += len;
            }

            continue;
        }

    next:

        if (in->buf->last_buf) {
            last = 1;
        }

        ln = in;
        in = in->next;

        ngx_free_chain(stream->pool, ln);
    }

    stream->in = in;

    if (last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy output last");

        stream->output_closed = 1;

        if (f) {
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = ngx_http_proxy_v2_get_buf(sess);
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
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, log, 0,
                       "http proxy output out l:%d f:%d %p, pos %p, size: %O "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       ngx_buf_size(cl->buf),
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, stream->send_window, sess->send_window);

#endif

    if (out) {
        sess->request_output = 1;
        *sess->last_out = out;
        sess->last_out = ll;
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_read_handler(ngx_event_t *ev)
{
    size_t                        received;
    ssize_t                       n;
    ngx_int_t                     rc;
    ngx_buf_t                    *b;
    ngx_uint_t                    frames;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *sess;

    c = ev->data;
    sess = ngx_http_proxy_v2_find_session(c);
    b = sess->buffer;
    frames = 0;
    received = 0;

    if (ev->timedout || c->close) {
        goto failed;
    }

    if (c->error || ev->error || ev->eof) {
        goto notify;
    }

    for ( ;; ) {
        if (b->pos != b->last
            && (frames == NGX_HTTP_PROXY_V2_MAX_INPUT_FRAMES
                || received >= NGX_HTTP_PROXY_V2_MAX_INPUT_FRAMES
                               * NGX_HTTP_V2_DEFAULT_FRAME_SIZE))
        {
            if (ev->posted) {
                ngx_delete_posted_event(ev);
            }

            ngx_post_event(ev, &ngx_posted_next_events);
            break;
        }

        rc = ngx_http_proxy_v2_process_frame(sess, b);

        if (rc == NGX_ERROR) {
            sess->error = 1;
            goto failed;
        }

        if (rc == NGX_OK) {
            frames++;
            continue;
        }

        b->pos = b->start;
        b->last = b->start;

#if (NGX_HTTP_SSL)
        if (c->ssl && c->ssl->saved_write_handler && !c->write->ready) {
            if (ev->posted) {
                ngx_delete_posted_event(ev);
            }

            break;
        }
#endif

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_AGAIN) {
            /* discard read continuations already covered by this receive */

            if (ev->posted) {
                ngx_delete_posted_event(ev);
            }

            break;
        }

        if (n == NGX_ERROR) {
            goto failed;
        }

        if (n == 0) {
            ngx_http_proxy_v2_close_header(sess);
            ev->eof = 1;
            break;
        }

        b->last += n;
        received += n;
    }

    if (ngx_handle_read_event(ev, ev->eof ? NGX_CLOSE_EVENT : 0) != NGX_OK) {
        goto failed;
    }

notify:

    ngx_http_proxy_v2_notify(sess, 0);
    return;

failed:

    ngx_http_proxy_v2_close_header(sess);
    c->error = 1;
    goto notify;
}


static void
ngx_http_proxy_v2_write_handler(ngx_event_t *ev)
{
    size_t                        lowat;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *sess;

    c = ev->data;
    sess = ngx_http_proxy_v2_find_session(c);

    if (ev->timedout || c->error || c->close) {
        goto notify;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler && !c->read->ready) {

        /* SSL_write() needs input, not another writable-socket wakeup */

        if (ev->posted) {
            ngx_delete_posted_event(ev);
        }

        if (ngx_handle_write_event(ev, 0) != NGX_OK) {
            goto failed;
        }

        return;
    }
#endif

    rc = ngx_http_proxy_v2_send(sess);

    if (rc == NGX_ERROR) {
        goto failed;
    }

    lowat = 0;

    if (rc == NGX_AGAIN) {
        lowat = sess->send_lowat;
    }

    if (ngx_handle_write_event(ev, lowat) != NGX_OK) {
        goto failed;
    }

    if (rc == NGX_AGAIN && !ev->ready) {
        goto done;
    }

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            goto failed;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

done:

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler && ev->posted) {
        ngx_delete_posted_event(ev);
    }
#endif

notify:

    ngx_http_proxy_v2_notify(sess, 1);
    return;

failed:

    c->error = 1;
    goto done;
}


static void
ngx_http_proxy_v2_stream_read_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    if (c->error && r->upstream->header_sent) {
        /* report failure even when the pipe has no free receive buffers */

        r->upstream->pipe->upstream_error = 1;
    }

    ngx_http_upstream_handler(ev);
}


static ngx_event_handler_pt
ngx_http_proxy_v2_set_read_handler(ngx_connection_t *c,
    ngx_event_handler_pt handler)
{
    ngx_event_handler_pt  previous;

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler) {
        previous = c->ssl->saved_read_handler;
        c->ssl->saved_read_handler = handler;
        return previous;
    }
#endif

    previous = c->read->handler;
    c->read->handler = handler;

    return previous;
}


static ngx_event_handler_pt
ngx_http_proxy_v2_set_write_handler(ngx_connection_t *c,
    ngx_event_handler_pt handler)
{
    ngx_event_handler_pt  previous;

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_write_handler) {
        previous = c->ssl->saved_write_handler;
        c->ssl->saved_write_handler = handler;
        return previous;
    }
#endif

    previous = c->write->handler;
    c->write->handler = handler;

    return previous;
}


static void
ngx_http_proxy_v2_notify(ngx_http_proxy_v2_session_t *sess, ngx_uint_t write)
{
    ngx_uint_t                   failed;
    ngx_rbtree_t                *tree;
    ngx_connection_t            *c, *sc;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *stream;

    c = sess->connection;
    tree = &sess->streams;

    if (ngx_http_proxy_v2_session_need_close(sess)) {
        ngx_http_proxy_v2_session_retire(sess);
    }

    if (tree->root == tree->sentinel) {
        ngx_http_proxy_v2_session_release(sess);
        return;
    }

    failed = c->error || c->close || c->read->error || c->read->eof
             || c->read->timedout || c->write->error || c->write->timedout;

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
        sc = &stream->connection;
        sc->sent = c->sent;

        /* transport failure cannot undo a completely received response */

        if (sess->error || (failed && !stream->input_closed)) {
            sc->error = 1;
            sc->read->error = 1;
        }

        if (c->read->timedout) {
            sc->read->timedout = 1;
        }

        if (c->write->timedout) {
            sc->write->timedout = 1;
        }

        if (sc->error || failed) {
            /* the reader owns response consumption and error reporting */

            if (sc->write->posted) {
                ngx_delete_posted_event(sc->write);
            }

            if (sc->error && sc->write->timer_set) {
                ngx_del_timer(sc->write);
            }

            sc->write->ready = 0;

        } else if (write) {
            sc->write->ready = 1;
            ngx_post_event(sc->write, &ngx_posted_events);
        }

        if (stream->headers || stream->body_size || stream->input_closed
            || sc->error || sc->read->timedout)
        {
            sc->read->ready = 1;
            ngx_post_event(sc->read, &ngx_posted_events);
        }
    }
}


static ssize_t
ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t                        n;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    /* the logical connection is the first member of the stream */

    stream = (ngx_http_proxy_v2_stream_t *) c;
    sess = stream->session;

    n = ngx_http_proxy_v2_read_body(stream, buf, size);

    if (n) {
        if (ngx_http_proxy_v2_send_window_update(sess, stream) != NGX_OK) {
            sess->connection->error = 1;
            c->error = 1;
        }

        if (sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }

        c->read->ready = stream->body_size || stream->input_closed || c->error
                        || sess->connection->read->eof;
        return n;
    }

    if (c->error || sess->error
        || (!stream->input_closed
            && (sess->connection->error || sess->connection->read->error
                || sess->connection->read->eof)))
    {
        c->error = 1;
        c->read->error = 1;
        c->read->ready = 0;
        return NGX_ERROR;
    }

    c->read->ready = 0;

    if (stream->input_closed) {
        c->read->eof = 1;
        return 0;
    }

    return NGX_AGAIN;
}


static ssize_t
ngx_http_proxy_v2_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    size_t   size;
    ssize_t  n, received;

    received = 0;

    for ( /* void */; in; in = in->next) {
        size = in->buf->end - in->buf->last;

        if (limit && (off_t) size > limit - received) {
            size = (size_t) (limit - received);
        }

        if (size == 0) {
            continue;
        }

        n = ngx_http_proxy_v2_recv(c, in->buf->last, size);

        if (n <= 0) {
            return received ? received : n;
        }

        received += n;

        if ((size_t) n < size || !c->read->ready
            || (limit && received == limit))
        {
            break;
        }
    }

    return received ? received : NGX_AGAIN;
}


/* NGX_OK means submitted output is drained, not that the body has arrived. */

static ngx_int_t
ngx_http_proxy_v2_send(ngx_http_proxy_v2_session_t *sess)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    ngx_rbtree_t                *tree;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *stream;

    if (sess->connection->error || sess->connection->close) {
        return NGX_ERROR;
    }

    if (!sess->preface_sent) {
        cl = ngx_http_proxy_v2_get_buf(sess);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        /* static startup bytes precede even already queued control frames */

        b = cl->buf;
        b->pos = ngx_http_proxy_v2_connection_start;
        b->last = b->pos + sizeof(ngx_http_proxy_v2_connection_start) - 1;
        b->temporary = 0;
        b->memory = 1;

        cl->next = sess->out;
        sess->out = cl;

        if (cl->next == NULL) {
            sess->last_out = &cl->next;
        }

        sess->preface_sent = 1;
    }

    /* drain committed output before retaining another batch of DATA frames */

    rc = ngx_http_proxy_v2_write(sess);
    if (rc != NGX_OK) {
        return rc;
    }

    tree = &sess->streams;

    if (tree->root == tree->sentinel) {
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

        if (ngx_http_proxy_v2_output_stream(stream) != NGX_OK) {
            sess->connection->error = 1;
            return NGX_ERROR;
        }
    }

    rc = ngx_http_proxy_v2_write(sess);
    if (rc != NGX_OK) {
        return rc;
    }

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

        if (stream->in == NULL || stream->rst || stream->connection.error) {
            continue;
        }

        rc = NGX_AGAIN;
        b = stream->in->buf;

        if (!stream->header_sent && sess->max_streams == 0) {
            /* a later SETTINGS frame resumes admission */

            continue;
        }

        if (!stream->header_sent || ngx_buf_special(b) || ngx_buf_size(b) == 0
            || (stream->send_window > 0 && sess->send_window > 0))
        {
            /* the batch yielded; a writable socket may have no new edge */

            ngx_post_event(sess->connection->write, &ngx_posted_next_events);
            break;
        }
    }

    return rc;
}


static ngx_uint_t
ngx_http_proxy_v2_input_pending(ngx_http_proxy_v2_session_t *sess)
{
    ngx_rbtree_t                *tree;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *stream;

    tree = &sess->streams;

    if (tree->root != tree->sentinel) {
        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

            if (stream->in && !stream->rst && !stream->connection.error) {
                return 1;
            }
        }
    }

    return 0;
}


static void
ngx_http_proxy_v2_post_write(ngx_http_proxy_v2_session_t *sess)
{
#if (NGX_HTTP_SSL)
    ngx_connection_t  *c;

    c = sess->connection;

    if (c->ssl && c->ssl->saved_read_handler && !c->read->ready) {
        return;
    }
#endif

    ngx_post_event(sess->connection->write, &ngx_posted_events);
}


static ngx_int_t
ngx_http_proxy_v2_write(ngx_http_proxy_v2_session_t *sess)
{
    u_char       *start;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *out, *cl, *free;

    if (sess->connection->error || sess->connection->close) {
        return NGX_ERROR;
    }

    out = sess->out;
    sess->out = NULL;
    sess->last_out = &sess->out;

    /* a NULL chain still flushes output retained by the transport */

    rc = ngx_chain_writer(&sess->writer, out);

    free = sess->free;

    ngx_chain_update_chains(sess->connection->pool, &sess->free, &sess->busy,
                           &out, (ngx_buf_tag_t) &ngx_http_proxy_v2_write);

    for (cl = sess->free; cl != free; cl = cl->next) {
        b = cl->buf;

        if (b->shadow && b->last_shadow) {
            b->shadow->pos = b->shadow->last;
            b->shadow->file_pos = b->shadow->file_last;
        }

        /* retain only session-owned scratch memory for the next use */

        start = b->start;
        ngx_memzero(b, sizeof(ngx_buf_t));
        b->start = start;
    }

    if (rc == NGX_ERROR) {
        sess->connection->error = 1;
    }

    if (!ngx_http_proxy_v2_output_pending(sess)) {
        sess->detached_output_id = 0;
        sess->request_output = 0;
    }

    return rc;
}


static ngx_uint_t
ngx_http_proxy_v2_output_pending(ngx_http_proxy_v2_session_t *sess)
{
    return sess->out || sess->busy || sess->writer.out
           || sess->connection->buffered;
}


/* with one active stream, all output shadows belong to its request */

static ngx_uint_t
ngx_http_proxy_v2_output_has_shadow(ngx_http_proxy_v2_session_t *sess)
{
    ngx_chain_t  *cl;

    /* session-owned control output may outlive the request */

    for (cl = sess->out; cl; cl = cl->next) {
        if (cl->buf->shadow) {
            return 1;
        }
    }

    for (cl = sess->busy; cl; cl = cl->next) {
        if (cl->buf->shadow) {
            return 1;
        }
    }

    for (cl = sess->writer.out; cl; cl = cl->next) {
        if (cl->buf->shadow) {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_proxy_v2_session_need_close(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    c = sess->connection;

    /* retire immediately, but close only after attached requests release */

    return !sess->cacheable
           || sess->draining || sess->closing || sess->error || sess->goaway
           || c->close || c->error
           || c->read->error || c->read->eof || c->read->timedout
           || c->write->error || c->write->timedout
           || ngx_terminate || ngx_exiting
           || c->requests >= sess->conf->keepalive->requests
           || ngx_current_msec - c->start_time >= sess->conf->keepalive->time
           || sess->last_stream_id >= 0x7fffffff;
}


static ngx_uint_t
ngx_http_proxy_v2_session_stream_limit(ngx_http_proxy_v2_session_t *sess)
{
    /*
     * Reservations and attached request streams share this limit, including
     * streams not yet opened and protocol-closed streams awaiting teardown.
     * This conservative limit is independent of pending connection I/O.
     */

    return ngx_min(sess->max_streams, NGX_HTTP_PROXY_V2_MAX_ATTACHED_STREAMS);
}


static ngx_uint_t
ngx_http_proxy_v2_session_io_pending(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    c = sess->connection;

#if (NGX_HTTP_SSL)
    if (c->ssl
        && (c->ssl->saved_read_handler || c->ssl->saved_write_handler))
    {
        return 1;
    }
#endif

    return ngx_http_proxy_v2_output_pending(sess)
           || c->read->ready
           || c->read->posted
           || c->write->posted
           || sess->header_pool != NULL
           || sess->state != ngx_http_proxy_v2_st_start
           || sess->buffer->pos != sess->buffer->last;
}


static void
ngx_http_proxy_v2_discard_output(ngx_http_proxy_v2_session_t *sess)
{
    /* only closing sessions discard output, before request buffers expire */

    sess->out = NULL;
    sess->last_out = &sess->out;
    sess->busy = NULL;
    sess->writer.out = NULL;
    sess->writer.last = &sess->writer.out;
}


static ngx_int_t
ngx_http_proxy_v2_process_header(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_v2_stream_t  *stream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    stream = ctx->stream;

    if (stream->session->error || stream->invalid_header) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (stream->connection.error) {
        return NGX_AGAIN;
    }

    rc = ngx_http_proxy_v2_process_headers(r, stream);

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_process_headers(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream)
{
    ngx_str_t                     *status_line;
    ngx_int_t                      rc, status;
    ngx_table_elt_t               *h;
    ngx_http_upstream_t           *u;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_upstream_header_t    *hh;
    ngx_http_upstream_main_conf_t *umcf;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (stream->headers) {
        u->headers_in.header_size = stream->headers->size;

        for ( ;; ) {

            rc = ngx_http_proxy_v2_read_header(stream, 0);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%V: %V\"",
                               &stream->name, &stream->value);

                if (stream->name.len && stream->name.data[0] == ':') {

                    if (stream->name.len != sizeof(":status") - 1
                        || ngx_strncmp(stream->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &stream->name, &stream->value);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &stream->value;

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

                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->key = stream->name;
                h->value = stream->value;
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

                    ctx->status = 0;
                    return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                }

                return NGX_OK;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_proxy_v2_filter_init(void *data)
{
    ngx_http_request_t          *r = data;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_v2_stream_t  *stream;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->ctx.head)
    {
        ctx->length = 0;

    } else {
        ctx->length = u->headers_in.content_length_n;
    }

    if (stream->end_stream) {

        if (ctx->length > 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream prematurely closed stream");
            (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        u->length = 0;
        u->pipe->length = 0;
        u->pipe->upstream_done = 1;
        stream->done = 1;

    } else {
        u->length = 1;
        u->pipe->length = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_int_t                    rc;
    ngx_http_request_t          *r;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_v2_stream_t  *stream;

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    u = r->upstream;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", b->last - b->pos);

    rc = ngx_http_proxy_v2_process_body(p, b);

    if (rc == NGX_ERROR || stream->connection.error) {
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        u->length = 0;
        p->length = 0;
        p->upstream_done = 1;
    }

    return NGX_OK;
}


/*
 * Consume decoded payload and retained trailers without processing frames.
 * NGX_OK completes the response; NGX_AGAIN accepts the payload and waits
 * for more response results.
 */

static ngx_int_t
ngx_http_proxy_v2_process_body(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    size_t                       size;
    ngx_int_t                    rc;
    ngx_buf_t                   *buf;
    ngx_chain_t                 *cl;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_v2_stream_t  *stream;

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    stream = ctx->stream;
    size = b->pos == b->last ? 0 : (size_t) (b->last - b->pos);

    if (size) {
        if (ctx->length != -1) {
            if ((off_t) size > ctx->length) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent response body larger "
                              "than indicated content length");
                (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
                return NGX_ERROR;
            }

            ctx->length -= size;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        buf = cl->buf;
        ngx_memzero(buf, sizeof(ngx_buf_t));

        buf->pos = b->pos;
        buf->last = b->last;
        buf->start = b->start;
        buf->end = b->end;
        buf->tag = p->tag;
        buf->temporary = 1;
        buf->recycled = 1;
        buf->shadow = b;
        buf->last_shadow = 1;
        b->shadow = buf;

        if (p->in) {
            *p->last_in = cl;

        } else {
            p->in = cl;
        }

        p->last_in = &cl->next;

        /* STUB */ buf->num = b->num;

        stream->body_processed += size;
    }

    rc = ngx_http_proxy_v2_process_trailers(r, stream);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (stream->input_closed && stream->header_count == 0
        && stream->body_processed == stream->body_parsed)
    {
        if (ctx->length > 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream prematurely closed stream");
            (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        stream->end_stream = 1;
        stream->done = 1;
    }

    return stream->done ? NGX_OK : NGX_AGAIN;
}


/* Protocol closure does not depend on request consumption or detachment. */

static ngx_uint_t
ngx_http_proxy_v2_stream_closed(ngx_http_proxy_v2_stream_t *stream)
{
    return stream->rst || (stream->input_closed && stream->output_closed);
}


/* A stream failure must leave the connection parser at its current position. */

static ngx_int_t
ngx_http_proxy_v2_stream_error(ngx_http_proxy_v2_stream_t *stream,
    ngx_uint_t error)
{
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *sess;

    sess = stream->session;
    c = sess->connection;

    if (!stream->connection.error) {
        stream->error = error;
    }

    stream->invalid_header = 1;
    stream->connection.error = 1;
    stream->read.error = 1;

    if (sess->header_stream_id == stream->id && !sess->input_discard) {
        sess->input_discard = 1;
        stream->header_count--;
    }

    if (sess->state == ngx_http_proxy_v2_st_payload
        && sess->type == NGX_HTTP_V2_DATA_FRAME
        && sess->stream_id == stream->id && sess->frame_state)
    {
        sess->input_discard = 1;
    }

    ngx_http_proxy_v2_discard_body(stream);

    if (stream->rst) {
        ngx_http_proxy_v2_notify(sess, 0);
        return NGX_OK;
    }

    stream->rst = 1;

    /*
     * Until output ownership is tracked per stream, request buffers cannot
     * outlive their failed request.  Pending request output, including a
     * session-owned END_STREAM or transport-buffered bytes, must not escape
     * after a reset.  Control-only output can precede our reset safely.
     */

    if (stream->in || !stream->output_closed || sess->request_output
        || ngx_http_proxy_v2_output_has_shadow(sess))
    {
        c->close = 1;

    } else if (!c->close && !c->error && !sess->error) {
        if (ngx_http_proxy_v2_send_rst_stream(sess, stream->id, error)
            != NGX_OK)
        {
            c->error = 1;
            ngx_http_proxy_v2_notify(sess, 0);
            return NGX_ERROR;
        }

        stream->reset_sent = 1;
        ngx_http_proxy_v2_post_write(sess);
    }

    ngx_http_proxy_v2_notify(sess, 0);

    return NGX_OK;
}


/* NGX_OK completes one frame; NGX_AGAIN needs more input. */

static ngx_int_t
ngx_http_proxy_v2_process_frame(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    size_t                       received;
    ngx_int_t                    rc;
    ngx_log_t                   *log;
    ngx_uint_t                   new_frame, closed_stream;
    ngx_http_proxy_v2_stream_t  *stream;

    log = &sess->log;
    new_frame = (sess->state < ngx_http_proxy_v2_st_payload);

    if (new_frame) {
        rc = ngx_http_proxy_v2_parse_frame(sess, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            goto failed;
        }
    }

    /* resolve the target again when resuming a fragmented frame */

    stream = sess->stream_id
             ? ngx_http_proxy_v2_find_stream(sess, sess->stream_id) : NULL;

    /*
     * Preserve the admission state across payload fragments.  Detachment
     * and local failure switch accepted input to discard, including control
     * frames whose payload was only partially received.
     */

    if (new_frame || stream == NULL || stream->invalid_header) {
        sess->frame_closed = stream
                             ? ngx_http_proxy_v2_stream_closed(stream)
                             : ((sess->stream_id & 1)
                                && sess->stream_id <= sess->last_stream_id);
    }

    closed_stream = sess->frame_closed || sess->input_discard;

    /*
     * Attribute wire bytes only after the stream ID is known.  Count the
     * header once and only the available payload of this frame, excluding
     * closed-stream traffic and read-ahead beyond the current frame.
     * Connection traffic only contributes to the session total.
     */

    if (!closed_stream) {
        received = ngx_min((size_t) (b->last - b->pos), sess->rest);

        if (new_frame) {
            received += sizeof(ngx_http_proxy_v2_frame_t);
        }

        sess->received += received;

        if (stream) {
            stream->received += received;
        }
    }

    if (new_frame) {
        if (sess->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 frame: %uz",
                          sess->rest);
            goto failed;
        }

        /* only CONTINUATION on the same stream can extend a header block */

        if ((sess->type == NGX_HTTP_V2_CONTINUATION_FRAME
             && (sess->header_stream_id == 0
                 || sess->stream_id != sess->header_stream_id))
            || (sess->type != NGX_HTTP_V2_CONTINUATION_FRAME
                && sess->header_stream_id))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent unexpected http2 frame: %d",
                          sess->type);
            goto failed;
        }

        if (sess->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent unexpected push promise frame");
            goto failed;
        }

        sess->frame_state = 0;
    }

    rc = ngx_http_proxy_v2_process_connection_frame(sess, b, new_frame);

    if (rc != NGX_DECLINED) {
        goto done;
    }

    if (sess->type == NGX_HTTP_V2_PRIORITY_FRAME
        || sess->type > NGX_HTTP_V2_CONTINUATION_FRAME)
    {
        if (new_frame && sess->type == NGX_HTTP_V2_PRIORITY_FRAME
            && (sess->stream_id == 0 || sess->rest != 5))
        {
            goto failed;
        }

        rc = ngx_http_proxy_v2_skip_frame(sess, b);
        goto done;
    }

    /* all remaining frame types require a non-zero stream ID */

    if (sess->stream_id == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent http2 frame %d with zero stream id",
                      sess->type);
        goto failed;
    }

    if (stream && !closed_stream) {
        rc = ngx_http_proxy_v2_process_stream_frame(sess, stream, b, new_frame);
        goto done;
    }

    if (!closed_stream) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent frame for unknown stream %ui",
                      sess->stream_id);
        goto failed;
    }

    rc = ngx_http_proxy_v2_process_closed_stream_frame(sess, stream, b,
                                                      new_frame);

done:

    if (rc != NGX_ERROR) {
        return rc;
    }

failed:

    ngx_http_proxy_v2_close_header(sess);

    return NGX_ERROR;
}


/* NGX_DECLINED leaves non-connection frames untouched. */

static ngx_int_t
ngx_http_proxy_v2_process_connection_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b, ngx_uint_t new_frame)
{
    ssize_t                      window_delta;
    ngx_int_t                    rc;
    ngx_log_t                   *log;
    ngx_uint_t                   level;
    ngx_rbtree_t                *tree;
    ngx_rbtree_node_t           *node;
    ngx_http_proxy_v2_stream_t  *stream;

    log = sess->connection->log;
    tree = &sess->streams;

    switch (sess->type) {

    case NGX_HTTP_V2_GOAWAY_FRAME:

        if (new_frame) {
            if (sess->stream_id) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent goaway frame "
                              "with non-zero stream id: %ui", sess->stream_id);
                return NGX_ERROR;
            }

            if (sess->rest < 8) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent goaway frame "
                              "with invalid length: %uz", sess->rest);
                return NGX_ERROR;
            }
        }

        rc = ngx_http_proxy_v2_parse_goaway(sess, b);

        if (rc != NGX_OK) {
            return rc;
        }

        /* report unaccepted streams through their logical read events */

        if (tree->root != tree->sentinel) {
            for (node = ngx_rbtree_min(tree->root, tree->sentinel);
                 node;
                 node = ngx_rbtree_next(tree, node))
            {
                stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t,
                                         node);

                if (sess->goaway_last_stream_id < stream->id
                    && !stream->connection.error
                    && !ngx_http_proxy_v2_stream_closed(stream))
                {

                    /* TODO: we can retry non-idempotent requests */

                    level = sess->goaway_error ? NGX_LOG_ERR : NGX_LOG_INFO;

                    ngx_log_error(level, log, 0,
                                  "upstream sent goaway with error %ui "
                                  "for stream %ui",
                                  sess->goaway_error, stream->id);

                    stream->error = sess->goaway_error;
                    stream->connection.error = 1;
                    stream->read.error = 1;
                }
            }
        }

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (sess->stream_id) {
            return NGX_DECLINED;
        }

        if (new_frame && sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        return ngx_http_proxy_v2_process_window_update(sess, NULL, b);

    case NGX_HTTP_V2_SETTINGS_FRAME:

        if (new_frame) {
            if (sess->stream_id) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with non-zero stream id: %ui", sess->stream_id);
                return NGX_ERROR;
            }

            if ((sess->flags & NGX_HTTP_V2_ACK_FLAG) && sess->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              sess->rest);
                return NGX_ERROR;
            }

            if (sess->rest % 6 != 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with invalid length: %uz", sess->rest);
                return NGX_ERROR;
            }
        }

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

            /* consume the setting before the parser reuses its result */

            if (sess->setting_id == 0x03) {
                /* SETTINGS_MAX_CONCURRENT_STREAMS */

                sess->max_streams = sess->setting_value;
            }

            if (sess->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                window_delta = (ssize_t) sess->setting_value
                               - (ssize_t) sess->init_window;

                if (tree->root != tree->sentinel) {
                    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
                         node;
                         node = ngx_rbtree_next(tree, node))
                    {
                        stream = ngx_rbtree_data(node,
                                                ngx_http_proxy_v2_stream_t,
                                                node);

                        if (ngx_http_proxy_v2_stream_closed(stream)) {
                            continue;
                        }

                        if (stream->send_window > 0
                            && window_delta > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                               - stream->send_window)
                        {
                            ngx_log_error(NGX_LOG_ERR, log, 0,
                                          "upstream sent settings frame "
                                          "with too large initial window "
                                          "size: %ui", sess->setting_value);
                            return NGX_ERROR;
                        }

                        stream->send_window += window_delta;
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

        if (ngx_http_proxy_v2_input_pending(sess) || sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }

        return NGX_OK;

    case NGX_HTTP_V2_PING_FRAME:

        if (new_frame) {
            if (sess->stream_id) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent ping frame "
                              "with non-zero stream id: %ui", sess->stream_id);
                return NGX_ERROR;
            }

            if (sess->rest != 8) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent ping frame "
                              "with invalid length: %uz", sess->rest);
                return NGX_ERROR;
            }

            if (sess->flags & NGX_HTTP_V2_ACK_FLAG) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent ping frame with ack flag");
                return NGX_ERROR;
            }
        }

        rc = ngx_http_proxy_v2_parse_ping(sess, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_http_proxy_v2_send_ping_ack(sess, sess->ping_data)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_http_proxy_v2_post_write(sess);

        return NGX_OK;

    default:
        return NGX_DECLINED;
    }
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
ngx_http_proxy_v2_process_trailers(ngx_http_request_t *r,
    ngx_http_proxy_v2_stream_t *stream)
{
    ngx_int_t                 rc;
    ngx_table_elt_t          *h;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    for ( ;; ) {
        rc = ngx_http_proxy_v2_read_header(stream, 1);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_OK) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer: \"%V: %V\"",
                           &stream->name, &stream->value);

            if (stream->name.len && stream->name.data[0] == ':') {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer \"%V: %V\"",
                              &stream->name, &stream->value);
                (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
                return NGX_ERROR;
            }

            h = ngx_list_push(&r->upstream->headers_in.trailers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->key = stream->name;
            h->value = stream->value;
            h->lowcase_key = h->key.data;
            h->hash = ngx_hash_key(h->key.data, h->key.len);
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer done");

            if (stream->end_stream) {
                if (ctx->length > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream prematurely closed stream");
                    (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
                    return NGX_ERROR;
                }

                stream->done = 1;
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent trailer without end stream flag");
            (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid trailer");
        (void) ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
        return NGX_ERROR;
    }
}


/* Called for frames admitted before protocol closure. */

static ngx_int_t
ngx_http_proxy_v2_process_stream_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b, ngx_uint_t new_frame)
{
    ngx_int_t   rc;
    ngx_log_t  *log;

    log = sess->connection->log;

    switch (sess->type) {

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        return ngx_http_proxy_v2_process_header_frame(sess, stream, b,
                                                     new_frame);

    case NGX_HTTP_V2_DATA_FRAME:

        return ngx_http_proxy_v2_process_data(sess, stream, b, new_frame);

    case NGX_HTTP_V2_RST_STREAM_FRAME:

        if (new_frame && sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        rc = ngx_http_proxy_v2_parse_rst_stream(sess, b);

        if (rc != NGX_OK) {
            return rc;
        }

        stream->rst = 1;
        stream->error = sess->rst_error;

        if (stream->in || !stream->output_closed
            || ngx_http_proxy_v2_output_pending(sess))
        {
            /* even session-owned output can contain frames for this stream */

            sess->connection->close = 1;
        }

        if (stream->error || !(stream->input_closed || stream->done)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream rejected request with error %ui",
                          stream->error);

            stream->connection.error = 1;
            stream->read.error = 1;
        }

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (new_frame && sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        return ngx_http_proxy_v2_process_window_update(sess, stream, b);

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_http_proxy_v2_process_closed_stream_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b, ngx_uint_t new_frame)
{
    ngx_int_t  rc;

    switch (sess->type) {

    case NGX_HTTP_V2_RST_STREAM_FRAME:
    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (new_frame && sess->rest != 4) {
            return NGX_ERROR;
        }

        rc = ngx_http_proxy_v2_skip_frame(sess, b);

        if (rc == NGX_OK && sess->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
            if (stream) {
                /* a later consumer error must not generate a reset response */

                stream->rst = 1;
            }

            /* queued output may still belong to the closed stream */

            if (stream && !stream->reset_sent) {
                if (stream->in || !stream->output_closed
                    || ngx_http_proxy_v2_output_pending(sess))
                {
                    sess->connection->close = 1;
                }

            } else if (stream == NULL && sess->nstreams == 0
                       && sess->stream_id == sess->detached_output_id)
            {
                sess->connection->close = 1;
            }
        }

        return rc;

    case NGX_HTTP_V2_DATA_FRAME:

        return ngx_http_proxy_v2_process_data(sess, NULL, b, new_frame);

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        return ngx_http_proxy_v2_process_header_frame(sess, NULL, b, new_frame);
    }

    ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                  "upstream sent frame for unknown stream %ui",
                  sess->stream_id);

    return NGX_ERROR;
}


/*
 * For each receive window, recv_window + recv_credit + reserved DATA equals
 * NGX_HTTP_V2_DEFAULT_WINDOW.  Connection reservations cover unread frame
 * payload; stream reservations also include buffered body bytes.
 *
 * A NULL destination discards DATA while preserving connection flow control.
 */

static ngx_int_t
ngx_http_proxy_v2_process_data(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b, ngx_uint_t new_frame)
{
    ngx_int_t   rc;
    ngx_log_t  *log;
    ngx_uint_t  error;

    log = &sess->log;

    if (new_frame) {
        if ((sess->flags & NGX_HTTP_V2_PADDED_FLAG) && sess->rest == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too short http2 frame");
            return NGX_ERROR;
        }

        if (sess->rest > sess->recv_window) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream violated connection flow control, "
                          "received %uz data frame with window %uz",
                          sess->rest, sess->recv_window);
            return NGX_ERROR;
        }

        error = 0;

        if (stream) {
            if (stream->input_closed || stream->rst) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent frame for closed stream %ui",
                              stream->id);
                error = NGX_HTTP_PROXY_V2_STREAM_CLOSED;

            } else if (!stream->trailer || stream->trailers) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent unexpected http2 data frame");
                error = NGX_HTTP_PROXY_V2_PROTOCOL_ERROR;

            } else if (sess->rest > stream->recv_window) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream violated stream flow control, "
                              "received %uz data frame with window %uz",
                              sess->rest, stream->recv_window);
                error = NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR;
            }

            if (error) {
                if (ngx_http_proxy_v2_stream_error(stream, error) != NGX_OK) {
                    return NGX_ERROR;
                }

                stream = NULL;
            }
        }

        /* reserve the entire frame, including padding, only once */

        if (stream) {
            stream->recv_window -= sess->rest;

            if (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                stream->input_closing = 1;
            }
        }

        sess->recv_window -= sess->rest;
        sess->input_discard = (stream == NULL);
    }

    rc = ngx_http_proxy_v2_parse_data(sess, stream, b);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_v2_send_window_update(sess, stream) != NGX_OK) {
        return NGX_ERROR;
    }

    if (sess->out) {
        ngx_http_proxy_v2_post_write(sess);
    }

    return rc == NGX_DONE ? NGX_OK : rc;
}


/* A NULL destination discards a header block for a validated closed stream. */

static ngx_int_t
ngx_http_proxy_v2_process_header_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b, ngx_uint_t new_frame)
{
    size_t                        min, size, limit;
    ngx_int_t                     rc;
    ngx_log_t                    *log;
    ngx_http_proxy_v2_headers_t  *headers;

    log = &sess->log;

    if (new_frame) {
        size = sizeof(ngx_http_proxy_v2_frame_t) + sess->rest;

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
            if (sess->stream_id == 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent http2 frame %d with zero stream id",
                              sess->type);
                return NGX_ERROR;
            }

            if (stream) {
                if (stream->input_closed || stream->rst || stream->trailers) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent headers for invalid stream %ui",
                                  stream->id);

                    if (ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_STREAM_CLOSED)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    stream = NULL;
                }
            }

            if (stream) {
                if (stream->trailer
                    && !(sess->flags & NGX_HTTP_V2_END_STREAM_FLAG))
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent trailer without end stream "
                                  "flag");

                    if (ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    stream = NULL;
                }
            }

            if (stream) {
                limit = stream->header_limit;

            } else {
                limit = sess->discard_header_limit;
            }

            min = (sess->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (sess->rest < min) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz", sess->rest);
                return NGX_ERROR;
            }

            if (size > limit) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 header");
                return NGX_ERROR;
            }

            sess->header_pool = ngx_create_pool(1024, log);
            if (sess->header_pool == NULL) {
                return NGX_ERROR;
            }

            headers = ngx_pcalloc(sess->header_pool,
                                 sizeof(ngx_http_proxy_v2_headers_t));
            if (headers == NULL) {
                return NGX_ERROR;
            }

            headers->size = size;
            headers->end_stream =
                               (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) != 0;

            sess->header_in = headers;
            sess->header_stream_id = sess->stream_id;
            sess->header_block_limit = limit;
            sess->header_limit = limit;
            sess->fragment_state = 0;
            sess->input_discard = (stream == NULL);

            if (stream) {
                headers->body_offset = stream->body_parsed;
                stream->header_count++;

                if (headers->end_stream) {
                    stream->input_closing = 1;
                }

                if (ngx_http_proxy_v2_account_header(sess,
                          ngx_align(sizeof(ngx_http_proxy_v2_headers_t),
                                    NGX_ALIGNMENT))
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }

        } else {
            headers = sess->header_in;

            if (size > sess->header_block_limit
                || headers->size > sess->header_block_limit - size)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 header");
                return NGX_ERROR;
            }

            headers->size += size;
        }
    }

    /* discarded blocks still require complete HPACK and CONTINUATION parsing */

    rc = ngx_http_proxy_v2_parse_header(sess, b);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
        if (!sess->input_discard) {
            stream = ngx_http_proxy_v2_find_stream(sess, sess->header_stream_id);

            if (stream == NULL) {
                return NGX_ERROR;
            }

            if (ngx_http_proxy_v2_copy_headers(stream, sess->header_in)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        ngx_http_proxy_v2_close_header(sess);
    }

    return sess->state == ngx_http_proxy_v2_st_start ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_proxy_v2_process_window_update(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
{
    ngx_int_t  rc;

    rc = ngx_http_proxy_v2_parse_window_update(sess, b);

    if (rc != NGX_OK) {
        return rc;
    }

    if (sess->window_update == 0) {
        ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                      "upstream sent zero window update");

        return stream
               ? ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR)
               : NGX_ERROR;
    }

    if (stream) {
        if (sess->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                   - stream->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                          "upstream sent too large window update");
            return ngx_http_proxy_v2_stream_error(stream,
                                           NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
        }

        stream->send_window += sess->window_update;

    } else {
        if (sess->window_update > NGX_HTTP_V2_MAX_WINDOW - sess->send_window) {
            ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        sess->send_window += sess->window_update;
    }

    if (ngx_http_proxy_v2_input_pending(sess)) {
        ngx_http_proxy_v2_post_write(sess);
    }

    return NGX_OK;
}


/* NGX_OK completes the wire header; processing validates the new frame. */

static ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
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

            return NGX_OK;

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
            break;
        }
    }

    b->pos = p;
    sess->state = state;

    return NGX_AGAIN;
}


/* A NULL stream consumes DATA without retaining its payload. */

static ngx_int_t
ngx_http_proxy_v2_parse_data(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
{
    size_t      size, pos, n;
    ngx_log_t  *log;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_data,
        sw_padding
    } state;

    log = &sess->log;
    state = sess->frame_state;

    if (state == sw_start) {
        sess->padding = 0;

        if (sess->flags & NGX_HTTP_V2_PADDED_FLAG) {
            state = sw_padding_length;

        } else {
            state = sw_data;
        }

        sess->frame_state = state;
    }

    if (state == sw_padding_length) {
        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        sess->padding = *b->pos++;
        sess->rest--;

        if (sess->padding > sess->rest) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          sess->padding, sess->rest);
            return NGX_ERROR;
        }

        if (stream) {
            stream->recv_credit++;
        }

        sess->recv_credit++;

        state = sw_data;
        sess->frame_state = state;
    }

    if (state == sw_data) {
        if (sess->rest > sess->padding) {
            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            size = ngx_min((size_t) (b->last - b->pos),
                           sess->rest - sess->padding);

            if (stream) {
                if (size > NGX_HTTP_V2_DEFAULT_WINDOW - stream->body_size) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "no buffer space for http2 body");
                    return NGX_ERROR;
                }

                if (stream->body == NULL) {
                    stream->body = ngx_palloc(stream->pool,
                                             NGX_HTTP_V2_DEFAULT_WINDOW);
                    if (stream->body == NULL) {
                        return NGX_ERROR;
                    }
                }

                pos = (stream->body_pos + stream->body_size)
                      % NGX_HTTP_V2_DEFAULT_WINDOW;
                n = ngx_min(size, NGX_HTTP_V2_DEFAULT_WINDOW - pos);
                ngx_memcpy(stream->body + pos, b->pos, n);

                if (size > n) {
                    ngx_memcpy(stream->body, b->pos + n, size - n);
                }

                stream->body_size += size;
                stream->body_parsed += size;
            }

            b->pos += size;
            sess->rest -= size;

            /* buffered or discarded bytes release only connection capacity */

            sess->recv_credit += size;

            if (sess->rest > sess->padding) {
                return NGX_AGAIN;
            }
        }

        sess->frame_state = sw_padding;
    }

    size = ngx_min((size_t) (b->last - b->pos), sess->rest);
    b->pos += size;
    sess->rest -= size;

    if (stream) {
        stream->recv_credit += size;
    }

    sess->recv_credit += size;

    if (sess->rest) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;
    sess->input_discard = 0;

    if (stream && (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG)) {
        stream->input_closed = 1;
    }

    return NGX_DONE;
}


static size_t
ngx_http_proxy_v2_read_body(ngx_http_proxy_v2_stream_t *stream, u_char *data,
    size_t size)
{
    size_t  n;

    /* body processing and trailer consumption determine normal completion */

    size = ngx_min(size, stream->body_size);

    if (size == 0) {
        return 0;
    }

    n = ngx_min(size, NGX_HTTP_V2_DEFAULT_WINDOW - stream->body_pos);
    ngx_memcpy(data, stream->body + stream->body_pos, n);

    if (size > n) {
        ngx_memcpy(data + n, stream->body, size - n);
    }

    stream->body_pos = (stream->body_pos + size) % NGX_HTTP_V2_DEFAULT_WINDOW;
    stream->body_size -= size;
    stream->body_read += size;

    /* connection capacity was released when the DATA was buffered */

    stream->recv_credit += size;

    return size;
}


static void
ngx_http_proxy_v2_discard_body(ngx_http_proxy_v2_stream_t *stream)
{
    /* buffered DATA has already released its connection capacity */

    stream->recv_credit += stream->body_size;
    stream->body_size = 0;
    stream->body_pos = 0;

    if (stream->body) {
        ngx_pfree(stream->pool, stream->body);
        stream->body = NULL;
    }
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char      ch, *p, *last;
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
            if (sess->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (sess->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;

        } else {
            return NGX_ERROR;
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

        do {
            rc = ngx_http_proxy_v2_parse_fragment(sess, b);
        } while (rc == NGX_OK);

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
    u_char                        ch, *p, *last;
    size_t                        len, size;
    ngx_log_t                    *log;
    ngx_uint_t                    index, size_update;
    ngx_http_proxy_v2_stream_t    *stream;
    ngx_http_proxy_v2_header_t    *field;
    ngx_http_proxy_v2_headers_t   *headers;
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

    headers = sess->header_in;

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
                ngx_str_set(&sess->name, "");
                state = sw_value_length;
                break;
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
            sess->name.len = sess->field_huffman ?
                             sess->field_length * 8 / 5 : sess->field_length;

            if (sess->name.len > sess->header_limit) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 "
                              "header name length: %uz",
                              sess->name.len);
                return NGX_ERROR;
            }

            sess->name.data = ngx_pnalloc(sess->header_pool, sess->name.len + 1);
            if (sess->name.data == NULL) {
                return NGX_ERROR;
            }

            sess->field_end = sess->name.data;
            sess->field_rest = sess->field_length;
            sess->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy name: len:%uz h:%d last:%uz, rest:%uz",
                           sess->field_length,
                           sess->field_huffman,
                           last - p,
                           sess->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) sess->field_rest);
            sess->field_rest -= size;

            if (sess->field_huffman) {
                if (ngx_http_huff_decode(&sess->field_state, p, size,
                                        &sess->field_end,
                                        sess->field_rest == 0, log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                sess->name.len = sess->field_end - sess->name.data;
                sess->name.data[sess->name.len] = '\0';

            } else {
                sess->field_end = ngx_cpymem(sess->field_end, p, size);
                sess->name.data[sess->name.len] = '\0';
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
            sess->value.len = sess->field_huffman ?
                              sess->field_length * 8 / 5 : sess->field_length;

            if (sess->value.len > sess->header_limit) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 "
                              "header value length: %uz",
                              sess->value.len);
                return NGX_ERROR;
            }

            sess->value.data = ngx_pnalloc(sess->header_pool, sess->value.len + 1);
            if (sess->value.data == NULL) {
                return NGX_ERROR;
            }

            sess->field_end = sess->value.data;
            sess->field_rest = sess->field_length;
            sess->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy value: len:%uz h:%d last:%uz, rest:%uz",
                           sess->field_length,
                           sess->field_huffman,
                           last - p,
                           sess->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) sess->field_rest);
            sess->field_rest -= size;

            if (sess->field_huffman) {
                if (ngx_http_huff_decode(&sess->field_state, p, size,
                                        &sess->field_end,
                                        sess->field_rest == 0, log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                sess->value.len = sess->field_end - sess->value.data;
                sess->value.data[sess->value.len] = '\0';

            } else {
                sess->field_end = ngx_cpymem(sess->field_end, p, size);
                sess->value.data[sess->value.len] = '\0';
            }

            p += size - 1;

            if (sess->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

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

        if (!sess->input_discard
            && ((!sess->index
                 && ngx_http_proxy_v2_validate_header_name(&sess->name)
                    != NGX_OK)
                || ((!sess->index || sess->literal)
                    && ngx_http_proxy_v2_validate_header_value(&sess->value)
                       != NGX_OK)))
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent invalid header: \"%V: %V\"",
                          &sess->name, &sess->value);

            stream = ngx_http_proxy_v2_find_stream(sess, sess->header_stream_id);

            if (stream == NULL
                || ngx_http_proxy_v2_stream_error(stream,
                                            NGX_HTTP_PROXY_V2_PROTOCOL_ERROR)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        len = sess->name.len + sess->value.len;

        if (len > sess->header_limit
            || headers->count == sess->header_block_limit)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        sess->header_limit -= len;
        headers->count++;

        /* reserve the request-owned copy before retaining a decoded field */

        size = ngx_align(sizeof(ngx_http_proxy_v2_header_t) + len + 2,
                         NGX_ALIGNMENT);

        if (ngx_http_proxy_v2_account_header(sess, size) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!sess->input_discard) {
            field = ngx_palloc(sess->header_pool,
                              sizeof(ngx_http_proxy_v2_header_t));
            if (field == NULL) {
                return NGX_ERROR;
            }

            field->name = sess->name;
            field->value = sess->value;
            field->next = NULL;

            if (headers->last) {
                headers->last->next = field;

            } else {
                headers->first = field;
            }

            headers->last = field;
        }

        ngx_str_null(&sess->name);
        ngx_str_null(&sess->value);
        sess->field_end = NULL;

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


/*
 * Charge retained protocol metadata for this upstream attempt, including hints
 * and trailers.  Consumption does not free request-pool allocations, so this
 * budget is never replenished.  Bounding blocks, fields and strings bounds the
 * corresponding consumer metadata, independently of the temporary parser pool.
 */

static ngx_int_t
ngx_http_proxy_v2_account_header(ngx_http_proxy_v2_session_t *sess, size_t size)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (sess->input_discard) {
        return NGX_OK;
    }

    stream = ngx_http_proxy_v2_find_stream(sess, sess->header_stream_id);
    if (stream == NULL) {
        return NGX_ERROR;
    }

    if (size > stream->header_budget) {
        ngx_log_error(NGX_LOG_ERR, &sess->log, 0,
                      "upstream sent too much http2 header metadata");

        /* retain parser limits while discarding the rest of this block */

        return ngx_http_proxy_v2_stream_error(stream,
                                          NGX_HTTP_PROXY_V2_ENHANCE_YOUR_CALM);
    }

    stream->header_budget -= size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_copy_headers(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_proxy_v2_headers_t *headers)
{
    u_char                       *p;
    ngx_http_proxy_v2_header_t   *field, *h;
    ngx_http_proxy_v2_headers_t  *copy;

    copy = ngx_pcalloc(stream->pool, sizeof(ngx_http_proxy_v2_headers_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->count = headers->count;
    copy->body_offset = headers->body_offset;
    copy->size = headers->size;
    copy->end_stream = headers->end_stream;

    for (h = headers->first; h; h = h->next) {
        field = ngx_palloc(stream->pool, sizeof(ngx_http_proxy_v2_header_t)
                                        + h->name.len + h->value.len + 2);
        if (field == NULL) {
            return NGX_ERROR;
        }

        p = (u_char *) (field + 1);
        field->name.data = p;
        field->name.len = h->name.len;
        p = ngx_cpymem(p, h->name.data, h->name.len);
        *p++ = '\0';

        field->value.data = p;
        field->value.len = h->value.len;
        p = ngx_cpymem(p, h->value.data, h->value.len);
        *p = '\0';
        field->next = NULL;

        if (copy->last) {
            copy->last->next = field;

        } else {
            copy->first = field;
        }

        copy->last = field;
    }

    /* publish only a complete result; consumers retain request-owned strings */

    copy->current = copy->first;

    if (stream->trailer) {
        stream->trailers = copy;

    } else {
        if (stream->last_headers) {
            stream->last_headers->next = copy;

        } else {
            stream->headers = copy;
        }

        stream->last_headers = copy;

        /* classify later blocks by receive progress, not consumption */

        field = copy->first;
        if (field && field->name.len == sizeof(":status") - 1
            && ngx_strncmp(field->name.data, ":status",
                           sizeof(":status") - 1) == 0
            && field->value.len == 3
            && ngx_atoi(field->value.data, 3) >= NGX_HTTP_OK)
        {
            stream->trailer = 1;
        }
    }

    if (copy->end_stream) {
        stream->input_closed = 1;
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_close_header(ngx_http_proxy_v2_session_t *sess)
{
    ngx_pool_t  *pool;

    pool = sess->header_pool;

    sess->header_pool = NULL;
    sess->header_in = NULL;
    sess->header_stream_id = 0;
    sess->header_block_limit = 0;
    sess->header_limit = 0;
    sess->input_discard = 0;
    sess->fragment_state = 0;
    ngx_str_null(&sess->name);
    ngx_str_null(&sess->value);
    sess->field_end = NULL;

    if (pool) {
        ngx_destroy_pool(pool);
    }
}


static ngx_int_t
ngx_http_proxy_v2_read_header(ngx_http_proxy_v2_stream_t *stream,
    ngx_uint_t trailers)
{
    ngx_http_proxy_v2_header_t   *field;
    ngx_http_proxy_v2_headers_t  *headers;

    if (trailers) {
        if (stream->headers) {
            return NGX_AGAIN;
        }

        headers = stream->trailers;

    } else {
        headers = stream->headers;
    }

    if (headers == NULL || headers->body_offset > stream->body_processed) {
        return NGX_AGAIN;
    }

    if (headers->current) {
        field = headers->current;
        headers->current = field->next;
        stream->name = field->name;
        stream->value = field->value;
        return NGX_OK;
    }

    stream->end_stream = headers->end_stream;

    if (trailers) {
        stream->trailers = NULL;

    } else {
        stream->headers = headers->next;
        if (stream->headers == NULL) {
            stream->last_headers = NULL;
        }
    }

    stream->header_count--;

    return NGX_HTTP_PARSE_HEADER_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_name(ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    if (s->len == 0) {
        return NGX_ERROR;
    }

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

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->rst_error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            sess->rst_error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            sess->rst_error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            sess->rst_error |= ch;
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy error: %ui", sess->rst_error);

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

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                       "http proxy goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            sess->goaway_last_stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            sess->goaway_last_stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            sess->goaway_last_stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            sess->goaway_last_stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            sess->goaway_error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            sess->goaway_error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            sess->goaway_error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            sess->goaway_error |= ch;
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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   sess->goaway_error, sess->goaway_last_stream_id);

    sess->goaway = 1;
    sess->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_proxy_v2_session_t *sess,
    ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    ngx_log_t  *log;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    log = sess->connection->log;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy window update: %ui", sess->window_update);

    return NGX_OK;
}


/*
 * NGX_OK returns one setting in the session; consume it before calling again.
 * NGX_DONE marks frame completion, including empty SETTINGS and SETTINGS ACK.
 */

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

    log = sess->connection->log;

    if (b->last - b->pos < (ssize_t) sess->rest) {
        last = b->last;

    } else {
        last = b->pos + sess->rest;
    }

    state = sess->frame_state;

    if (state == sw_start) {
        if (sess->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy settings ack");

            sess->state = ngx_http_proxy_v2_st_start;

            return NGX_DONE;
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

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                       "http proxy ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            sess->ping_data[state] = ch;
            state++;

        } else {
            sess->ping_data[7] = ch;
            state = sw_start;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy send settings ack");

    if (sess->free == NULL && sess->settings++ > 1000) {
        ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                      "upstream sent too many settings frames");
        return NGX_ERROR;
    }

    cl = ngx_http_proxy_v2_get_buf(sess);
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

    *sess->last_out = cl;
    sess->last_out = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_ping_ack(ngx_http_proxy_v2_session_t *sess, u_char *data)
{
    ngx_chain_t                *cl;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy send ping ack");

    if (sess->free == NULL && sess->pings++ > 1000) {
        ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                      "upstream sent too many ping frames");
        return NGX_ERROR;
    }

    cl = ngx_http_proxy_v2_get_buf(sess);
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

    cl->buf->last = ngx_copy(cl->buf->last, data, 8);

    *sess->last_out = cl;
    sess->last_out = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_window_update(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream)
{
    size_t                      n, connection, window;
    ngx_uint_t                  i, id;
    ngx_chain_t                *cl;
    ngx_http_proxy_v2_frame_t  *f;

    /* connection receive credit is independent of the destination's lifetime */

    connection = sess->recv_window <= NGX_HTTP_V2_DEFAULT_WINDOW / 2
                 ? sess->recv_credit : 0;
    window = stream && !stream->input_closing && !stream->rst
             && stream->recv_window <= NGX_HTTP_V2_DEFAULT_WINDOW / 2
             ? stream->recv_credit : 0;

    if (connection == 0 && window == 0) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy send window update: %uz %uz",
                   sess->recv_window, stream ? stream->recv_window : 0);

    cl = ngx_http_proxy_v2_get_buf(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 2; i++) {
        n = i ? window : connection;

        if (n == 0) {
            continue;
        }

        id = i ? stream->id : 0;
        f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
        cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

        f->length_0 = 0;
        f->length_1 = 0;
        f->length_2 = 4;
        f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
        f->flags = 0;
        f->stream_id_0 = (u_char) ((id >> 24) & 0xff);
        f->stream_id_1 = (u_char) ((id >> 16) & 0xff);
        f->stream_id_2 = (u_char) ((id >> 8) & 0xff);
        f->stream_id_3 = (u_char) (id & 0xff);

        *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
        *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
        *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
        *cl->buf->last++ = (u_char) (n & 0xff);
    }

    sess->recv_window += connection;
    sess->recv_credit -= connection;

    if (window) {
        stream->recv_window += window;
        stream->recv_credit -= window;
    }

    *sess->last_out = cl;
    sess->last_out = &cl->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_rst_stream(ngx_http_proxy_v2_session_t *sess,
    ngx_uint_t id, ngx_uint_t error)
{
    ngx_chain_t                *cl;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy send rst stream: %ui, error: %ui", id, error);

    cl = ngx_http_proxy_v2_get_buf(sess);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_RST_STREAM_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (id & 0xff);

    *cl->buf->last++ = (u_char) ((error >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((error >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((error >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (error & 0xff);

    *sess->last_out = cl;
    sess->last_out = &cl->next;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_buf(ngx_http_proxy_v2_session_t *sess)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_chain_get_free_buf(sess->connection->pool, &sess->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {

        /*
         * each buffer is large enough to hold two window update
         * frames in a row
         */

        start = ngx_palloc(sess->connection->pool,
                          2 * sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8;

    b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_write;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_shadow(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *buf)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_chain_get_free_buf(sess->connection->pool, &sess->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));

    /* preserve session-owned memory for reuse as a frame buffer */

    b->start = start;
    b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_write;
    b->shadow = buf;
    b->last_shadow = 1;

    return cl;
}


static ngx_int_t
ngx_http_proxy_v2_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    u_char                    *p;
    size_t                     len;
    socklen_t                  local;
    ngx_str_t                 *origin;
    ngx_peer_connection_t     *pc;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_proxy_v2_peer_t  *peer;
    struct {
        ngx_http_upstream_srv_conf_t  *upstream;
        ngx_http_upstream_conf_t      *conf;
        ngx_log_t                     *log;
        ngx_uint_t                     flags;
        int                            type;
        int                            rcvbuf;
        int                            sndbuf;
        size_t                         send_lowat;
        off_t                          sendfile_limit;
#if (NGX_HTTP_SSL)
        ngx_ssl_t                     *ssl;
        ngx_http_complex_value_t      *ssl_name;
        ngx_flag_t                     ssl_server_name;
#endif
    } profile;

    u = r->upstream;
    pc = &u->peer;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    peer = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_peer_t));
    if (peer == NULL) {
        return NGX_ERROR;
    }

    peer->ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (us && us->srv_conf) {
        peer->conf = ngx_http_conf_upstream_srv_conf(us,
                                                   ngx_http_proxy_v2_module);
        if (us->keepalive) {
            peer->conf->keepalive = us->keepalive;
        }

    } else {
        peer->conf = ngx_http_get_module_main_conf(r, ngx_http_proxy_v2_module);
    }

    peer->upstream = u;
    peer->log = clcf->error_log;
    peer->cacheable = 1;

#if (NGX_HTTP_SSL)
    /* variable TLS identities need a handshake, not a cached connection */

    if (u->ssl
        && ((u->conf->ssl_name && u->conf->ssl_name->lengths)
            || (u->conf->ssl_certificate
                && u->conf->ssl_certificate->lengths)
            || (u->conf->ssl_certificate_key
                && u->conf->ssl_certificate_key->lengths)))
    {
        peer->cacheable = 0;
    }

    /* the balancer's ticket cache is not partitioned by TLS client identity */

    peer->ssl_session_reuse = peer->cacheable && !u->conf->ssl_certificate;
#endif

    if (peer->conf->keepalive->max_cached == 0) {
        peer->cacheable = 0;
    }

    origin = &peer->ctx->ctx.vars.host_header;
    local = pc->local ? pc->local->socklen : 0;

    /* connection settings and an optional location tag partition the pool */

    ngx_memzero(&profile, sizeof(profile));
    profile.upstream = us;
    profile.conf = peer->conf->keepalive->local ? u->conf : NULL;
    profile.log = clcf->error_log;
    profile.flags = u->ssl | (pc->transparent << 1) | (pc->so_keepalive << 2)
                    | (clcf->tcp_nodelay << 3);
    profile.type = pc->type;
    profile.rcvbuf = pc->rcvbuf;
    profile.sndbuf = pc->sndbuf;
    profile.send_lowat = u->conf->send_lowat;
    profile.sendfile_limit = clcf->sendfile_max_chunk;

#if (NGX_HTTP_SSL)
    if (u->ssl) {
        /* the SSL context includes verification and static client credentials */

        profile.ssl = u->conf->ssl;
        profile.ssl_name = u->conf->ssl_name;
        profile.ssl_server_name = u->conf->ssl_server_name;
    }
#endif

    len = sizeof(profile) + sizeof(local)
          + local + sizeof(origin->len) + origin->len + peer->ctx->host.len;

    peer->key.data = ngx_pnalloc(r->pool, len);
    if (peer->key.data == NULL) {
        return NGX_ERROR;
    }

    peer->key.len = len;
    p = ngx_cpymem(peer->key.data, &profile, sizeof(profile));
    p = ngx_cpymem(p, &local, sizeof(local));

    if (local) {
        p = ngx_cpymem(p, pc->local->sockaddr, local);
    }

    p = ngx_cpymem(p, &origin->len, sizeof(origin->len));
    p = ngx_cpymem(p, origin->data, origin->len);
    ngx_memcpy(p, peer->ctx->host.data, peer->ctx->host.len);

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
ngx_http_proxy_v2_init_connection(ngx_http_request_t *r)
{
    size_t                       size, budget;
    ngx_int_t                    rc;
    ngx_uint_t                   limit;
    ngx_connection_t            *c, *sc;
    ngx_peer_connection_t       *pc;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_peer_t     *peer;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    /* each upstream attempt has its own stream in the request pool */

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_stream_t));
    if (stream == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    pc = &u->peer;
    peer = pc->data;

    /*
     * A block allows buffer_size fields and decoded bytes.  Cover their
     * descriptors, two NULs per field and alignment, plus one block descriptor,
     * so the cumulative budget also accepts any previously allowed block.
     */

    size = sizeof(ngx_http_proxy_v2_header_t) + NGX_ALIGNMENT + 2;
    budget = ngx_align(sizeof(ngx_http_proxy_v2_headers_t), NGX_ALIGNMENT);

    if (u->conf->buffer_size > ((size_t) -1 - budget) / size) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "\"proxy_buffer_size\" is too large "
                      "for http2 header metadata budget");
        return NGX_ERROR;
    }

    budget += u->conf->buffer_size * size;

    rc = ngx_http_proxy_v2_get_session(pc, &sess);
    if (rc != NGX_OK) {
        return rc;
    }

    c = sess->connection;

    if (pc->cached && ngx_http_proxy_v2_session_need_close(sess)) {
        ngx_http_proxy_v2_session_retire(sess);
    }

    if (sess->draining || sess->closing) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0,
                      "cannot attach to retired http2 session");

        peer->rejected = !sess->error && !sess->goaway_error
                         && !c->close && !c->error
                         && !c->read->error && !c->read->eof
                         && !c->read->timedout
                         && !c->write->error && !c->write->timedout;

        return NGX_DECLINED;
    }

    if (!peer->reserved) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "no reservation for http2 stream");
        return NGX_ERROR;
    }

    limit = ngx_http_proxy_v2_session_stream_limit(sess);

    /* this request already owns one of the reserved stream slots */

    if (sess->nstreams + sess->nreserved > limit) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0,
                      "http2 stream capacity changed: %ui attached, "
                      "%ui reserved, limit: %ui (peer: %ui)",
                      sess->nstreams, sess->nreserved, limit,
                      sess->max_streams);
        peer->rejected = 1;
        return NGX_DECLINED;
    }

    if (sess->goaway) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "cannot create http2 stream after goaway");
        return NGX_DECLINED;
    }

    if (sess->last_stream_id >= 0x7fffffff) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "http2 stream identifiers exhausted");
        peer->rejected = 1;
        return NGX_DECLINED;
    }

    stream->session = sess;
    stream->peer = peer;
    stream->pool = r->pool;
    stream->id = sess->last_stream_id ? sess->last_stream_id + 2 : 1;
    stream->send_window = sess->init_window;
    stream->recv_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    stream->header_limit = r->upstream->conf->buffer_size;
    stream->header_budget = budget;

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
    sc->sendfile = c->sendfile && r->connection->sendfile;
    sc->number = c->number;
    sc->start_time = c->start_time;
    sc->sent = c->sent;
    sc->type = c->type;
    sc->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    sc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    sc->read->data = sc;
    sc->read->log = sc->log;
    sc->read->index = NGX_INVALID_INDEX;
    sc->read->available = -1;

    sc->write->data = sc;
    sc->write->log = sc->log;
    sc->write->index = NGX_INVALID_INDEX;
    sc->write->write = 1;
    sc->write->ready = 1;

    sess->writer.limit = r->upstream->writer.limit;
    sess->send_lowat = r->upstream->conf->send_lowat;

    stream->node.key = stream->id;
    ngx_rbtree_insert(&sess->streams, &stream->node);
    sess->nstreams++;

    /* transfer ownership before any fallible post-attachment initialization */

    peer->stream = stream;
    ngx_http_proxy_v2_unreserve_session(peer);

    /* retain the largest configured allowance for discarded header blocks */

    sess->discard_header_limit = ngx_max(sess->discard_header_limit,
                                        stream->header_limit);

    sess->last_stream_id = stream->id;
    ctx->stream = stream;

    sc->read->handler = ngx_http_proxy_v2_stream_read_handler;
    sc->write->handler = ngx_http_upstream_handler;

    u->connection = sc;
    u->writer.connection = sc;

    if (pc->cached) {
        c->requests++;

    } else {
        ngx_http_proxy_v2_set_connection(sess);

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }

    /* the accepted request may consume the session's final allowance */

    if (ngx_http_proxy_v2_session_need_close(sess)) {
        ngx_http_proxy_v2_session_retire(sess);
    }

    if (ngx_http_proxy_v2_send_window_update(sess, stream) != NGX_OK) {
        return NGX_ERROR;
    }

    /* publish initialized sessions independently of stream occupancy */

    ngx_http_proxy_v2_session_index(sess);

    /* read-first initialization still needs the initial request submission */

    ngx_post_event(sc->write, &ngx_posted_events);
    ngx_post_event(c->read, &ngx_posted_events);

    return NGX_OK;
}


static ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_find_stream(ngx_http_proxy_v2_session_t *sess, ngx_uint_t id)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = sess->streams.root;
    sentinel = sess->streams.sentinel;

    while (node != sentinel) {

        if (id < node->key) {
            node = node->left;
            continue;
        }

        if (id > node->key) {
            node = node->right;
            continue;
        }

        return ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    }

    return NULL;
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_find_session(ngx_connection_t *c)
{
    ngx_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_proxy_v2_session_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session)
{
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_pool_cleanup_t           *cln;
    ngx_http_proxy_v2_peer_t     *peer;
    ngx_http_proxy_v2_session_t  *sess;

    c = pc->connection;
    peer = pc->data;

    /* a physical connection has one session, whether active or cached */

    sess = peer->session;
    if (sess) {
        *session = sess;
        return NGX_OK;
    }

    if (pc->cached) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no session found for cached http2 connection");
        return NGX_DECLINED;
    }

    b = ngx_create_temp_buf(c->pool, NGX_HTTP_V2_DEFAULT_FRAME_SIZE);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_proxy_v2_session_cleanup;
    sess = cln->data;

    ngx_memzero(sess, sizeof(ngx_http_proxy_v2_session_t));

    sess->conf = peer->conf;
    sess->connection = c;
    sess->cacheable = peer->cacheable;

    sess->log = *peer->log;
    sess->log.connection = c->number;
    sess->log.handler = NULL;
    sess->log.data = NULL;
    sess->log.action = NULL;

    ngx_http_proxy_v2_reserve_session(peer, sess);

    sess->key.len = peer->key.len;
    sess->key.data = ngx_pnalloc(c->pool, peer->key.len);

    if (sess->key.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sess->key.data, peer->key.data, peer->key.len);
    sess->socklen = pc->socklen;
    ngx_memcpy(&sess->sockaddr, pc->sockaddr, pc->socklen);

    sess->buffer = b;
    sess->received = 0;
    ngx_rbtree_init(&sess->streams, &sess->sentinel, ngx_rbtree_insert_value);
    sess->nstreams = 0;

    ngx_memzero(&sess->writer, sizeof(ngx_chain_writer_ctx_t));
    sess->writer.last = &sess->writer.out;
    sess->writer.connection = c;
    sess->writer.pool = c->pool;
    sess->send_lowat = 0;
    sess->out = NULL;
    sess->last_out = &sess->out;
    sess->free = NULL;
    sess->busy = NULL;
    sess->detached_output_id = 0;
    sess->pings = 0;
    sess->settings = 0;

    sess->state = ngx_http_proxy_v2_st_start;
    sess->frame_state = 0;
    sess->rest = 0;
    sess->stream_id = 0;
    sess->header_stream_id = 0;
    sess->type = 0;
    sess->flags = 0;

    sess->goaway_last_stream_id = 0;
    sess->goaway_error = 0;
    sess->rst_error = 0;
    sess->window_update = 0;
    sess->setting_id = 0;
    sess->setting_value = 0;
    ngx_memzero(sess->ping_data, sizeof(sess->ping_data));

    sess->header_pool = NULL;
    sess->header_in = NULL;
    sess->header_block_limit = 0;
    sess->discard_header_limit = 0;
    sess->fragment_state = 0;
    sess->index = 0;
    ngx_str_null(&sess->name);
    ngx_str_null(&sess->value);
    sess->field_end = NULL;
    sess->header_limit = 0;
    sess->field_length = 0;
    sess->field_rest = 0;
    sess->field_state = 0;
    sess->padding = 0;

    sess->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->recv_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->recv_credit = 0;
    sess->last_stream_id = 0;
    sess->max_streams = (ngx_uint_t) -1;
    sess->preface_sent = 0;
    sess->error = 0;
    sess->goaway = 0;
    sess->frame_closed = 0;
    sess->input_discard = 0;
    sess->literal = 0;
    sess->field_huffman = 0;

    *session = sess;

    return NGX_OK;
}


static void
ngx_http_proxy_v2_reserve_session(ngx_http_proxy_v2_peer_t *peer,
    ngx_http_proxy_v2_session_t *sess)
{
    peer->session = sess;
    peer->reserved = 1;
    sess->nreserved++;
}


static void
ngx_http_proxy_v2_unreserve_session(ngx_http_proxy_v2_peer_t *peer)
{
    if (peer->reserved) {
        peer->session->nreserved--;
        peer->reserved = 0;
    }
}


static uint32_t
ngx_http_proxy_v2_session_hash(ngx_str_t *key, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    uint32_t  hash;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, key->data, key->len);
    ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);
    ngx_crc32_final(hash);

    return hash;
}


static ngx_int_t
ngx_http_proxy_v2_session_cmp(ngx_str_t *key, struct sockaddr *sockaddr,
    socklen_t socklen, ngx_http_proxy_v2_session_t *sess)
{
    ngx_int_t  rc;

    rc = ngx_memn2cmp(key->data, sess->key.data, key->len, sess->key.len);

    if (rc != 0) {
        return rc;
    }

    return ngx_memn2cmp((u_char *) sockaddr, (u_char *) &sess->sockaddr,
                       socklen, sess->socklen);
}


static void
ngx_http_proxy_v2_session_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_int_t                     rc;
    ngx_rbtree_node_t            **p;
    ngx_http_proxy_v2_session_t   *sess, *tsess;

    sess = ngx_rbtree_data(node, ngx_http_proxy_v2_session_t, node);

    for ( ;; ) {
        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else {
            tsess = ngx_rbtree_data(temp, ngx_http_proxy_v2_session_t, node);

            rc = ngx_http_proxy_v2_session_cmp(&sess->key,
                                              &sess->sockaddr.sockaddr,
                                              sess->socklen, tsess);

            /* equal sessions are ordered newest first, as in the idle LRU */

            p = (rc <= 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_lookup_session(ngx_http_proxy_v2_peer_t *peer,
    ngx_peer_connection_t *pc)
{
    uint32_t                      hash;
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_proxy_v2_session_t  *sess, *found;

    hash = ngx_http_proxy_v2_session_hash(&peer->key, pc->sockaddr, pc->socklen);
    node = peer->conf->sessions.root;
    sentinel = peer->conf->sessions.sentinel;
    found = NULL;

    while (node != sentinel) {
        if (hash != node->key) {
            node = (hash < node->key) ? node->left : node->right;
            continue;
        }

        sess = ngx_rbtree_data(node, ngx_http_proxy_v2_session_t, node);
        rc = ngx_http_proxy_v2_session_cmp(&peer->key, pc->sockaddr,
                                          pc->socklen, sess);

        if (rc == 0) {
            found = sess;
        }

        /* find the first equal session, including after tree rotations */

        node = (rc <= 0) ? node->left : node->right;
    }

    return found;
}


static void
ngx_http_proxy_v2_session_index(ngx_http_proxy_v2_session_t *sess)
{
    if (sess->indexed || sess->draining) {
        return;
    }

    /* ngx_rbtree_delete() clears the node key */

    sess->node.key = ngx_http_proxy_v2_session_hash(&sess->key,
                                     &sess->sockaddr.sockaddr, sess->socklen);
    ngx_rbtree_insert(&sess->conf->sessions, &sess->node);
    sess->indexed = 1;
}


static void
ngx_http_proxy_v2_session_unindex(ngx_http_proxy_v2_session_t *sess)
{
    if (sess->indexed) {
        ngx_rbtree_delete(&sess->conf->sessions, &sess->node);
        sess->indexed = 0;
    }
}


static ngx_int_t
ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    ngx_int_t                     rc;
    ngx_rbtree_t                 *tree;
    ngx_rbtree_node_t            *node, *next;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *sess;

    rc = peer->get(pc, peer->data);
    if (rc != NGX_OK || !peer->cacheable || ngx_terminate || ngx_exiting) {
        return rc;
    }

    sess = ngx_http_proxy_v2_lookup_session(peer, pc);
    if (sess == NULL) {
        return NGX_OK;
    }

    tree = &peer->conf->sessions;

    for (node = &sess->node; node; node = next) {
        sess = ngx_rbtree_data(node, ngx_http_proxy_v2_session_t, node);

        if (ngx_http_proxy_v2_session_cmp(&peer->key, pc->sockaddr,
                                          pc->socklen, sess) != 0)
        {
            break;
        }

        /* retiring this session removes it and may rebalance the tree */

        next = ngx_rbtree_next(tree, node);
        c = sess->connection;

        if (ngx_http_proxy_v2_session_need_close(sess)) {
            ngx_http_proxy_v2_session_retire(sess);

            /* notify attached streams; an unowned session may close here */

            ngx_http_proxy_v2_notify(sess, 0);
            continue;
        }

        /* a full session may regain capacity and does not need to close */

        if (sess->nstreams + sess->nreserved
            >= ngx_http_proxy_v2_session_stream_limit(sess))
        {
            continue;
        }

        /*
         * Pending protocol I/O is normal for an active session.  With no
         * attached streams, reuse still requires a drained handoff, even
         * if a reservation has already removed the session from the idle LRU.
         */

        if (sess->nstreams == 0
            && ngx_http_proxy_v2_session_io_pending(sess))
        {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get http2 session: %p", sess);

        /* reservations remain indexed; occupancy controls admission */

        ngx_http_proxy_v2_reserve_session(peer, sess);

        if (c->idle) {
            c->sent = 0;
        }

        ngx_http_proxy_v2_session_unidle(sess);
        pc->connection = c;
        pc->cached = 1;

        return NGX_DONE;
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_close_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *sess;

    sess = stream->session;

    /*
     * Retention requires a complete response or a reset, along with a
     * committed request end and no output borrowing request buffers.
     */

    if ((!stream->input_closed && !stream->rst) || !stream->output_closed
        || stream->in || ngx_http_proxy_v2_output_has_shadow(sess))
    {
        sess->connection->close = 1;
    }

    /* reuse requires drained output, so detached streams cannot overlap */

    sess->detached_output_id = !stream->reset_sent
                               && ngx_http_proxy_v2_output_pending(sess)
                               ? stream->id : 0;

    if (sess->header_stream_id == stream->id && !sess->input_discard) {
        sess->input_discard = 1;
        stream->header_count--;
    }

    if (sess->state == ngx_http_proxy_v2_st_payload
        && sess->type == NGX_HTTP_V2_DATA_FRAME
        && sess->stream_id == stream->id
        && sess->frame_state)
    {
        sess->input_discard = 1;
    }

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

    ngx_http_proxy_v2_discard_body(stream);
    stream->in = NULL;

    ngx_rbtree_delete(&sess->streams, &stream->node);
    sess->nstreams--;

    if (sess->nstreams == 0) {
        sess->idle_deadline = ngx_current_msec + sess->conf->keepalive->timeout;
    }

    stream->session = NULL;
}


static void
ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    ngx_connection_t            *c;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    sess = peer->session;

    if (sess == NULL) {
        /* connect/TLS setup failed before the session adopted the connection */

#if (NGX_HTTP_SSL)
        c = pc->connection;
        if (c && c->ssl) {
            c->ssl->save_session = NULL;
        }
#endif

        peer->free(pc, peer->data, state);
        return;
    }

    c = sess->connection;
    stream = peer->stream;

    if (peer->rejected && (state & NGX_PEER_FAILED)) {
        /* an admission change does not imply a failed backend */

        state = (state & ~NGX_PEER_FAILED) | NGX_PEER_NEXT;
    }

    if (stream) {
        peer->upstream->state->bytes_received = stream->received;

        if ((state & NGX_PEER_FAILED) && sess->goaway && !sess->goaway_error
            && !sess->error && sess->goaway_last_stream_id < stream->id
            && !stream->error)
        {
            /* a graceful shutdown can race with reuse of an idle session */

            state = (state & ~NGX_PEER_FAILED) | NGX_PEER_NEXT;
        }

    } else if (!pc->cached) {
        /* a new session failed setup before registering a stream */

        c->close = 1;
    }

    /*
     * Only the session manager may close an adopted physical connection.
     * Retain ownership while the balancer handles the reported peer state.
     */

    pc->connection = NULL;
    peer->free(pc, peer->data, state);

    if (stream) {
        ngx_http_proxy_v2_close_stream(stream);

        if (peer->ctx->stream == stream) {
            peer->ctx->stream = NULL;
        }
    }

    ngx_http_proxy_v2_unreserve_session(peer);
    peer->stream = NULL;
    peer->session = NULL;
    peer->rejected = 0;

    ngx_http_proxy_v2_session_release(sess);
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

    if (!peer->ssl_session_reuse) {
        return NGX_OK;
    }

    return peer->set_session(pc, peer->data);
}


static void
ngx_http_proxy_v2_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_proxy_v2_peer_t  *peer = data;

    if (peer->ssl_session_reuse) {
        peer->save_session(pc, peer->data);
    }
}


static void
ngx_http_proxy_v2_ssl_save_session(ngx_connection_t *c)
{
    ngx_rbtree_node_t            *node;
    ngx_http_proxy_v2_peer_t     *peer;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    sess = ngx_http_proxy_v2_find_session(c);

    if (sess->closing || sess->nstreams == 0) {
        return;
    }

    node = ngx_rbtree_min(sess->streams.root, sess->streams.sentinel);
    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    peer = stream->peer;

    if (peer->save_session) {
        ngx_http_proxy_v2_save_session(&peer->upstream->peer, peer);
    }
}

#endif


static void
ngx_http_proxy_v2_set_connection(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    c = sess->connection;
    c->data = sess;
    c->log = &sess->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    (void) ngx_http_proxy_v2_set_read_handler(c, ngx_http_proxy_v2_read_handler);
    (void) ngx_http_proxy_v2_set_write_handler(c, ngx_http_proxy_v2_write_handler);

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->save_session = ngx_http_proxy_v2_ssl_save_session;
    }
#endif
}


static void
ngx_http_proxy_v2_session_release(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    if (sess->closing) {
        return;
    }

    c = sess->connection;

    if (ngx_http_proxy_v2_session_need_close(sess)) {
        ngx_http_proxy_v2_session_retire(sess);
    }

    if (sess->nstreams) {
        if (sess->error || c->close || c->error
            || c->read->error || c->read->eof || c->read->timedout
            || c->write->error || c->write->timedout)
        {
            ngx_http_proxy_v2_notify(sess, 0);
            return;
        }

        /* flush pending connection credit while other streams remain attached */

        if (ngx_http_proxy_v2_send_window_update(sess, NULL) != NGX_OK) {
            c->error = 1;
            ngx_http_proxy_v2_notify(sess, 0);
            return;
        }

        if (sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }

        return;
    }

    /* a reservation alone does not imply an initialized session */

    if (sess->nreserved) {
        return;
    }

    if (!c->idle) {
        ngx_http_proxy_v2_set_connection(sess);
    }

    if (sess->draining) {
        ngx_http_proxy_v2_session_close(sess);
        return;
    }

    /* protocol traffic does not extend an idle session's lifetime */

    if (c->idle) {
        return;
    }

    if ((ngx_msec_int_t) (sess->idle_deadline - ngx_current_msec) <= 0) {
        ngx_http_proxy_v2_session_close(sess);
        return;
    }

    /* flush pending connection credit before entering the idle cache */

    if (ngx_http_proxy_v2_send_window_update(sess, NULL) != NGX_OK) {
        ngx_http_proxy_v2_session_close(sess);
        return;
    }

    ngx_http_proxy_v2_session_idle(sess);
}


static void
ngx_http_proxy_v2_session_idle(ngx_http_proxy_v2_session_t *sess)
{
    ngx_msec_t                    timeout;
    ngx_queue_t                  *q;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_conf_t      *conf;
    ngx_http_proxy_v2_session_t   *old;

    c = sess->connection;
    conf = sess->conf;

    while (conf->nidle >= conf->keepalive->max_cached) {
        q = ngx_queue_last(&conf->idle);
        old = ngx_queue_data(q, ngx_http_proxy_v2_session_t, cache);
        ngx_http_proxy_v2_session_close(old);
    }

    ngx_queue_insert_head(&conf->idle, &sess->cache);
    conf->nidle++;
    c->idle = 1;

    /* admission is checked at lookup, so zero capacity can recover */

    ngx_http_proxy_v2_session_unindex(sess);
    ngx_http_proxy_v2_session_index(sess);

    timeout = conf->keepalive->time - (ngx_current_msec - c->start_time);
    timeout = ngx_min(timeout, sess->idle_deadline - ngx_current_msec);

    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_proxy_v2_session_close(sess);
        return;
    }

    if (ngx_http_proxy_v2_output_pending(sess)) {
        ngx_http_proxy_v2_post_write(sess);
    }

    if (c->read->ready || sess->buffer->pos != sess->buffer->last) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "idle http2 session: %p", sess);
}


static void
ngx_http_proxy_v2_session_unidle(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    c = sess->connection;

    if (!c->idle) {
        return;
    }

    ngx_queue_remove(&sess->cache);
    sess->conf->nidle--;
    c->idle = 0;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
}


static void
ngx_http_proxy_v2_session_retire(ngx_http_proxy_v2_session_t *sess)
{
    if (sess->draining) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "retire http2 session: %p", sess);

    sess->draining = 1;
    ngx_http_proxy_v2_session_unindex(sess);
}


static void
ngx_http_proxy_v2_session_close(ngx_http_proxy_v2_session_t *sess)
{
    ngx_connection_t  *c;

    if (sess->closing) {
        return;
    }

    ngx_http_proxy_v2_session_retire(sess);

    if (sess->nstreams || sess->nreserved) {
        return;
    }

    sess->closing = 1;
    c = sess->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http2 session: %p", sess);

    ngx_http_proxy_v2_session_cleanup(sess);
    ngx_http_proxy_v2_discard_output(sess);

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

    ngx_http_proxy_v2_close_connection(c);
}


static void
ngx_http_proxy_v2_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

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
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    ngx_http_proxy_v2_session_t  *sess = data;

    ngx_http_proxy_v2_close_header(sess);

    ngx_http_proxy_v2_session_unindex(sess);
    ngx_http_proxy_v2_session_unidle(sess);
}


static void *
ngx_http_proxy_v2_create_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_v2_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_v2_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_rbtree_init(&conf->sessions, &conf->sentinel,
                   ngx_http_proxy_v2_session_rbtree_insert);
    ngx_queue_init(&conf->idle);
    conf->keepalive = &ngx_http_proxy_v2_keepalive;

    return conf;
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
