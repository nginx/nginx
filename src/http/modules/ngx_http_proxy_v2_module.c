
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>


#define NGX_HTTP_PROXY_V2_MAX_OUTPUT_FRAMES  16
#define NGX_HTTP_PROXY_V2_MAX_OUTPUT_BUFS    2048
#define NGX_HTTP_PROXY_V2_MAX_HEADER_BLOCKS  16
#define NGX_HTTP_PROXY_V2_READ_BUDGET        (64 * 1024)
#define NGX_HTTP_PROXY_V2_HEADER_BUDGET      (1024 * 1024)


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


typedef struct ngx_http_proxy_v2_stream_s  ngx_http_proxy_v2_stream_t;


typedef struct {
    ngx_connection_t              *connection;
    ngx_http_proxy_v2_stream_t    *active_stream;
    ngx_buf_t                     *buffer;
    ngx_event_handler_pt           read_handler;
    ngx_event_handler_pt           write_handler;
    size_t                         send_lowat;

    ngx_chain_writer_ctx_t         writer;
    ngx_chain_t                   *out;
    ngx_chain_t                  **last_out;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;
    ngx_uint_t                     pings;
    ngx_uint_t                     settings;
    ngx_uint_t                     allocated;

    ngx_http_proxy_v2_state_e      state;
    ngx_uint_t                     frame_state;
    size_t                         rest;
    ngx_uint_t                     stream_id;
    u_char                         type;
    u_char                         flags;

    ngx_uint_t                     goaway_last_stream_id;
    ngx_uint_t                     goaway_error;
    ngx_uint_t                     rst_error;
    ngx_uint_t                     window_update;
    ngx_uint_t                     setting_id;
    ngx_uint_t                     setting_value;
    u_char                         ping_data[8];

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

    unsigned                       preface_sent:1;
    unsigned                       goaway:1;
    unsigned                       parsing_headers:1;
    unsigned                       literal:1;
    unsigned                       field_huffman:1;
    unsigned                       read_pending:1;
    unsigned                       read_blocked:1;
    unsigned                       failed:1;
    unsigned                       protocol_error:1;
    unsigned                       closed:1;
} ngx_http_proxy_v2_session_t;


typedef struct ngx_http_proxy_v2_header_s  ngx_http_proxy_v2_header_t;

struct ngx_http_proxy_v2_header_s {
    ngx_str_t                      name;
    ngx_str_t                      value;
    ngx_http_proxy_v2_header_t    *next;
};


typedef struct ngx_http_proxy_v2_headers_s  ngx_http_proxy_v2_headers_t;

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


struct ngx_http_proxy_v2_stream_s {
    ngx_http_proxy_v2_session_t   *session;
    ngx_event_free_peer_pt         free_peer;
    ngx_pool_t                    *pool;
    ngx_uint_t                     id;

    ngx_connection_t               connection;
    ngx_event_t                    read;
    ngx_event_t                    write;
    off_t                          received;

    ngx_chain_t                   *in;

    ssize_t                        send_window;
    size_t                         recv_window;
    size_t                         recv_credit;

    ngx_uint_t                     error;
    ngx_uint_t                     window_update;

    size_t                         header_limit;
    size_t                         header_budget;
    ngx_str_t                      name;
    ngx_str_t                      value;

    ngx_http_proxy_v2_headers_t    *headers;
    ngx_http_proxy_v2_headers_t    *last_headers;
    ngx_http_proxy_v2_headers_t    *trailers;
    ngx_http_proxy_v2_headers_t    *header_in;
    ngx_uint_t                     header_count;

    /* receive credit reserves space in this stream-owned ring buffer */

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
    unsigned                       input_closed:1;
    unsigned                       done:1;
    unsigned                       rst:1;
    unsigned                       final_write:1;
};


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_http_proxy_v2_stream_t     *stream;

    off_t                          length;

    unsigned                       status:1;
} ngx_http_proxy_v2_ctx_t;


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
static ngx_int_t ngx_http_proxy_v2_init_connection(ngx_http_request_t *r);
static void ngx_http_proxy_v2_read_handler(ngx_event_t *ev);
static ngx_event_handler_pt ngx_http_proxy_v2_set_read_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static void ngx_http_proxy_v2_post_read(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_notify_read(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_fail(ngx_http_proxy_v2_session_t *sess,
    ngx_uint_t protocol);
static ngx_uint_t ngx_http_proxy_v2_input_drained(
    ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_reusable(ngx_http_proxy_v2_stream_t *stream);
static ssize_t ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_http_proxy_v2_recv_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_http_proxy_v2_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_v2_output_stream(
    ngx_http_proxy_v2_stream_t *stream);
static void ngx_http_proxy_v2_write_handler(ngx_event_t *ev);
static ngx_event_handler_pt ngx_http_proxy_v2_set_write_handler(
    ngx_connection_t *c, ngx_event_handler_pt handler);
static ngx_int_t ngx_http_proxy_v2_send(ngx_http_proxy_v2_session_t *sess);
static void ngx_http_proxy_v2_post_write(ngx_http_proxy_v2_session_t *sess);
static ngx_uint_t ngx_http_proxy_v2_output_pending(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_write(ngx_http_proxy_v2_session_t *sess);
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
static ngx_int_t ngx_http_proxy_v2_process_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_parse_frame(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_frame(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_parse_data(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static size_t ngx_http_proxy_v2_read_body(ngx_http_proxy_v2_stream_t *stream,
    u_char *data, size_t size);
static void ngx_http_proxy_v2_discard_body(ngx_http_proxy_v2_stream_t *stream);
static ngx_int_t ngx_http_proxy_v2_parse_header(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_fragment(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_read_header(
    ngx_http_proxy_v2_stream_t *stream, ngx_uint_t trailers);
static ngx_int_t ngx_http_proxy_v2_validate_header_name(ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_validate_header_value(ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_parse_rst_stream(
    ngx_http_proxy_v2_session_t *sess, ngx_http_proxy_v2_stream_t *stream,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b,
    ngx_uint_t *window_update);
static ngx_int_t ngx_http_proxy_v2_parse_settings(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_ping(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_send_settings_ack(
    ngx_http_proxy_v2_session_t *sess);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(
    ngx_http_proxy_v2_session_t *sess, u_char *data);
static ngx_int_t ngx_http_proxy_v2_send_window_update(
    ngx_http_proxy_v2_stream_t *stream);

static ngx_chain_t *ngx_http_proxy_v2_get_buf(
    ngx_http_proxy_v2_session_t *sess);
static ngx_chain_t *ngx_http_proxy_v2_get_output_buf(
    ngx_http_proxy_v2_session_t *sess);
static void *ngx_http_proxy_v2_alloc_header(ngx_http_proxy_v2_stream_t *stream,
    size_t size);
static ngx_chain_t *ngx_http_proxy_v2_get_shadow(
    ngx_http_proxy_v2_session_t *sess, ngx_buf_t *buf);
static ngx_http_proxy_v2_session_t *
    ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc);
static ngx_http_proxy_v2_session_t *
    ngx_http_proxy_v2_find_session(ngx_connection_t *c);
static void ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static void ngx_http_proxy_v2_session_cleanup(void *data);

static void ngx_http_proxy_v2_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);


static ngx_http_module_t  ngx_http_proxy_v2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
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


static ngx_uint_t
ngx_http_proxy_v2_input_drained(ngx_http_proxy_v2_session_t *sess)
{
    return sess->closed
           || (!sess->read_pending && !sess->read_blocked
               && sess->buffer->pos == sess->buffer->last
               && (!ngx_http_proxy_v2_output_pending(sess)
                   || (sess->active_stream && sess->active_stream->final_write)));
}


static void
ngx_http_proxy_v2_notify_read(ngx_http_proxy_v2_session_t *sess)
{
    ngx_event_t                 *rev;
    ngx_http_proxy_v2_stream_t  *stream;

    stream = sess->active_stream;
    if (stream == NULL) {
        return;
    }

    rev = stream->connection.read;

    if (stream->headers || stream->body_size || sess->failed
        || ((stream->input_closed || stream->trailers || sess->closed)
            && ngx_http_proxy_v2_input_drained(sess)))
    {
        rev->ready = 1;
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_http_proxy_v2_post_read(ngx_http_proxy_v2_session_t *sess)
{
    if (sess->failed || sess->closed) {
        return;
    }

    sess->read_pending = 1;
    ngx_post_event(sess->connection->read, &ngx_posted_events);
}


static void
ngx_http_proxy_v2_fail(ngx_http_proxy_v2_session_t *sess, ngx_uint_t protocol)
{
    ngx_connection_t            *c;
    ngx_http_proxy_v2_stream_t  *stream;

    c = sess->connection;
    stream = sess->active_stream;

    sess->failed = 1;
    sess->protocol_error = protocol;
    c->error = 1;

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }
    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    if (stream) {
        stream->connection.read->error = 1;

        /* let the response path preserve protocol-error retry classification */

        if (stream->connection.write->posted) {
            ngx_delete_posted_event(stream->connection.write);
        }

        ngx_http_proxy_v2_notify_read(sess);
    }
}


static void
ngx_http_proxy_v2_read_handler(ngx_event_t *ev)
{
    size_t                        bytes;
    ssize_t                       n;
    ngx_int_t                     rc;
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    c = ev->data;
    sess = ngx_http_proxy_v2_find_session(c);
    stream = sess->active_stream;

    if (sess->failed || sess->closed) {
        ngx_http_proxy_v2_notify_read(sess);
        return;
    }

    if (c->close || ev->timedout) {
        ngx_http_proxy_v2_fail(sess, 0);
        return;
    }

    b = sess->buffer;
    bytes = 0;
    sess->read_pending = 0;
    sess->read_blocked = 0;

    for ( ;; ) {
        if (sess->state < ngx_http_proxy_v2_st_payload) {
            rc = ngx_http_proxy_v2_parse_frame(sess, b);
            if (rc == NGX_ERROR) {
                ngx_http_proxy_v2_fail(sess, 1);
                return;
            }
            if (rc == NGX_AGAIN) {
                goto read;
            }

            sess->frame_state = 0;
        }

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME && stream
            && stream->header_in == NULL
            && stream->header_count >= NGX_HTTP_PROXY_V2_MAX_HEADER_BLOCKS)
        {
            sess->read_blocked = 1;
            break;
        }

        rc = ngx_http_proxy_v2_process_frame(sess, b);
        if (rc == NGX_ERROR) {
            ngx_http_proxy_v2_fail(sess, 1);
            return;
        }
        if (rc == NGX_OK) {
            continue;
        }

    read:

        if (b->pos != b->last) {
            ngx_http_proxy_v2_fail(sess, 1);
            return;
        }

        b->pos = b->start;
        b->last = b->start;

        if (bytes >= NGX_HTTP_PROXY_V2_READ_BUDGET) {
            sess->read_pending = 1;
            ngx_post_event(c->read, &ngx_posted_next_events);
            break;
        }

        /* the SSL write wrapper can retry SSL_read() without read readiness */

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            if (stream && stream->input_closed) {
                sess->closed = 1;
                c->read->eof = (n == 0);
                c->read->error = (n == NGX_ERROR);
                ngx_http_proxy_v2_discard_output(sess);

                if (c->write->posted) {
                    ngx_delete_posted_event(c->write);
                }

                break;
            }

            ngx_http_proxy_v2_fail(sess, 0);
            return;
        }

        b->last += n;
        bytes += n;
        if (stream) {
            stream->received += n;
        }
    }

    if (!sess->closed && ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_proxy_v2_fail(sess, 0);
        return;
    }

    if (stream && (stream->input_closed || stream->trailers)
        && !stream->final_write && ngx_http_proxy_v2_output_pending(sess))
    {
        ngx_http_proxy_v2_post_write(sess);
    }

    ngx_http_proxy_v2_notify_read(sess);
}


static ssize_t
ngx_http_proxy_v2_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t                        n;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    stream = ctx->stream;
    sess = stream->session;

    if (sess->failed) {
        return NGX_ERROR;
    }

    if (size == 0) {
        return 0;
    }

    n = ngx_http_proxy_v2_read_body(stream, buf, size);

    if (n) {
        if (ngx_http_proxy_v2_send_window_update(stream) != NGX_OK) {
            ngx_http_proxy_v2_fail(sess, 0);
            return NGX_ERROR;
        }

        if (sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }
    }

    c->read->ready = stream->body_size
                    || ((stream->input_closed || stream->trailers
                         || sess->closed)
                        && ngx_http_proxy_v2_input_drained(sess));

    if (n) {
        return n;
    }

    if (c->read->ready) {
        /* input exhaustion lets the body filter consume final metadata */
        c->read->eof = 1;
        return 0;
    }

    return NGX_AGAIN;
}


static ssize_t
ngx_http_proxy_v2_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    size_t   size;
    ssize_t  n, total;

    total = 0;

    if (limit < 0) {
        return NGX_ERROR;
    }

    for ( /* void */ ; in; in = in->next) {
        size = in->buf->end - in->buf->last;
        if (limit) {
            size = (size_t) ngx_min((off_t) size, limit - total);
        }
        if (size == 0) {
            continue;
        }

        n = ngx_http_proxy_v2_recv(c, in->buf->last, size);
        if (n <= 0) {
            return total ? total : n;
        }

        total += n;
        if (n < (ssize_t) size || (limit && total == limit)) {
            break;
        }
    }

    return total ? total : NGX_AGAIN;
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

    if (stream == NULL) {
        return NGX_ERROR;
    }

    sess = stream->session;

    if (sess->failed) {
        return sess->protocol_error ? NGX_AGAIN : NGX_ERROR;
    }

    if (in) {
        if (ngx_chain_add_copy(stream->pool, &stream->in, in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_http_proxy_v2_post_write(sess);
    }

    rc = (stream->in && !stream->rst) || ngx_http_proxy_v2_output_pending(sess)
         ? NGX_AGAIN : NGX_OK;

    stream->connection.write->ready = (rc == NGX_OK);

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

    if (stream->in == NULL || stream->rst) {
        return NGX_OK;
    }

    out = NULL;
    ll = &out;

    if (!stream->header_sent) {
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
        *sess->last_out = out;
        sess->last_out = ll;
    }

    return NGX_OK;
}


static void
ngx_http_proxy_v2_write_handler(ngx_event_t *ev)
{
    ngx_int_t                     rc;
    ngx_event_t                  *wev;
    ngx_connection_t             *c;
    ngx_event_handler_pt          handler;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    c = ev->data;
    sess = ngx_http_proxy_v2_find_session(c);
    stream = sess->active_stream;

    if (sess->failed || sess->closed) {
        ngx_http_proxy_v2_notify_read(sess);
        return;
    }

    if (ev->timedout || c->error) {
        ngx_http_proxy_v2_fail(sess, 0);
        return;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler && !c->read->ready) {

        /* SSL_write() needs input, not another writable-socket wakeup */

        if (ev->posted) {
            ngx_delete_posted_event(ev);
        }

        if (ngx_handle_write_event(ev, 0) == NGX_OK) {
            return;
        }

        ngx_http_proxy_v2_fail(sess, 0);
        return;
    }
#endif

    rc = ngx_http_proxy_v2_send(sess);
    if (rc == NGX_ERROR) {
        if (stream && stream->input_closed) {
            sess->closed = 1;
            c->error = 1;
            ngx_http_proxy_v2_discard_output(sess);
            ngx_http_proxy_v2_notify_read(sess);
        } else {
            ngx_http_proxy_v2_fail(sess, 0);
        }
        return;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && c->ssl->saved_read_handler && ev->posted) {
        ngx_delete_posted_event(ev);
    }
#endif

    if (ngx_handle_write_event(c->write, sess->send_lowat) != NGX_OK) {
        ngx_http_proxy_v2_fail(sess, 0);
        return;
    }

    if (c->write->ready && c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_http_proxy_v2_fail(sess, 0);
            return;
        }
        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    if (stream) {
        /* remaining output after this final attempt prevents connection reuse */

        if (c->read->posted) {
            sess->read_pending = 1;
        }

        if (stream->input_closed || stream->trailers) {
            stream->final_write = 1;
        }

        stream->connection.sent = c->sent;
        wev = stream->connection.write;
        wev->ready = (rc == NGX_OK);
        handler = wev->handler;

        if (wev->posted) {
            ngx_delete_posted_event(wev);
        }

        ngx_http_proxy_v2_notify_read(sess);

        /* the request adapter can retry or finalize and release both pools */

        handler(wev);
    }
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


/* NGX_OK means submitted output is drained, not that the body has arrived. */

static ngx_int_t
ngx_http_proxy_v2_send(ngx_http_proxy_v2_session_t *sess)
{
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    ngx_http_proxy_v2_stream_t  *stream;

    if (sess->connection->error) {
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

    stream = sess->active_stream;

    if (stream == NULL || stream->in == NULL || stream->rst) {
        return NGX_OK;
    }

    if (ngx_http_proxy_v2_output_stream(stream) != NGX_OK) {
        sess->connection->error = 1;
        return NGX_ERROR;
    }

    rc = ngx_http_proxy_v2_write(sess);
    if (rc != NGX_OK) {
        return rc;
    }

    if (stream->in == NULL) {
        return NGX_OK;
    }

    b = stream->in->buf;

    if (ngx_buf_special(b) || ngx_buf_size(b) == 0
        || (stream->send_window > 0 && sess->send_window > 0))
    {
        /* the batch limit yielded; a writable socket may have no new edge */

        ngx_post_event(sess->connection->write, &ngx_posted_next_events);
    }

    return NGX_AGAIN;
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

    if (sess->failed || sess->closed) {
        return;
    }

    if (sess->active_stream) {
        sess->active_stream->final_write = 0;
    }

    ngx_post_event(sess->connection->write, &ngx_posted_events);
}


static ngx_uint_t
ngx_http_proxy_v2_output_pending(ngx_http_proxy_v2_session_t *sess)
{
    return sess->out || sess->busy || sess->writer.out
           || sess->connection->buffered;
}


static ngx_int_t
ngx_http_proxy_v2_write(ngx_http_proxy_v2_session_t *sess)
{
    u_char       *start;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *out, *cl, *free;

    if (sess->connection->error) {
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

    return rc;
}


static void
ngx_http_proxy_v2_discard_output(ngx_http_proxy_v2_session_t *sess)
{
    /* the single-stream connection is closing; no output can be resumed */

    sess->out = NULL;
    sess->last_out = &sess->out;
    sess->busy = NULL;
    sess->writer.out = NULL;
    sess->writer.last = &sess->writer.out;
}


static ngx_int_t
ngx_http_proxy_v2_process_header(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    stream = ctx->stream;

    if (stream == NULL) {
        return NGX_ERROR;
    }

    sess = stream->session;
    u->state->bytes_received = stream->received;

    if (stream->headers && stream->headers->end_stream) {
        if (sess->failed) {
            return sess->protocol_error ? NGX_HTTP_UPSTREAM_INVALID_HEADER
                                        : NGX_AGAIN;
        }

        if (!ngx_http_proxy_v2_input_drained(sess)) {
            return NGX_AGAIN;
        }
    }

    u->headers_in.header_size = stream->headers ? stream->headers->size : 0;
    rc = ngx_http_proxy_v2_process_headers(r, stream);

    if (sess->read_blocked
        && stream->header_count < NGX_HTTP_PROXY_V2_MAX_HEADER_BLOCKS)
    {
        ngx_http_proxy_v2_post_read(sess);
    }

    if (rc == NGX_AGAIN) {
        if (sess->protocol_error) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

    } else if (rc == NGX_OK && stream->end_stream) {
        u->keepalive = ngx_http_proxy_v2_reusable(stream);
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

    if (stream->session->failed) {
        return NGX_ERROR;
    }

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
            return NGX_ERROR;
        }

        u->length = 0;
        u->pipe->length = 0;
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
    ngx_int_t                     rc;
    ngx_http_request_t           *r;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    sess = stream->session;
    u = r->upstream;

    if (sess->failed) {
        return NGX_ERROR;
    }

    rc = ngx_http_proxy_v2_process_body(p, b);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_OK && ngx_http_proxy_v2_input_drained(sess)) {
        p->length = 0;
        p->upstream_done = 1;
        u->keepalive = ngx_http_proxy_v2_reusable(stream);
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

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    stream = ctx->stream;
    size = b->pos == b->last ? 0 : (size_t) (b->last - b->pos);

    if (size) {
        if (ctx->length != -1 && (off_t) size > ctx->length) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent response body larger "
                          "than indicated content length");
            return NGX_ERROR;
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

        if (ctx->length != -1) {
            ctx->length -= size;
        }

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
            return NGX_ERROR;
        }

        stream->end_stream = 1;
        stream->done = 1;
    }

    return stream->done ? NGX_OK : NGX_AGAIN;
}


/* NGX_OK completes one frame; NGX_AGAIN needs more input. */

static ngx_int_t
ngx_http_proxy_v2_process_frame(ngx_http_proxy_v2_session_t *sess, ngx_buf_t *b)
{
    ssize_t                       window_delta;
    ngx_int_t                     rc;
    ngx_log_t                    *log;
    ngx_uint_t                   *window_update;
    ngx_http_proxy_v2_stream_t   *stream;

    log = sess->connection->log;
    stream = sess->active_stream;

    if (sess->state < ngx_http_proxy_v2_st_payload) {
        rc = ngx_http_proxy_v2_parse_frame(sess, b);

        if (rc != NGX_OK) {
            return rc;
        }

        sess->frame_state = 0;
    }

    switch (sess->type) {

    case NGX_HTTP_V2_DATA_FRAME:

        rc = ngx_http_proxy_v2_parse_data(sess, stream, b);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_http_proxy_v2_send_window_update(stream) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }

        return rc == NGX_DONE ? NGX_OK : rc;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        rc = ngx_http_proxy_v2_parse_header(sess, stream, b);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        return sess->state == ngx_http_proxy_v2_st_start ? NGX_OK : NGX_AGAIN;

    case NGX_HTTP_V2_RST_STREAM_FRAME:

        rc = ngx_http_proxy_v2_parse_rst_stream(sess, stream, b);

        if (rc != NGX_OK) {
            return rc;
        }

        stream->rst = 1;

        if (stream->error || !stream->input_closed) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream rejected request with error %ui",
                          stream->error);
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_GOAWAY_FRAME:

        rc = ngx_http_proxy_v2_parse_goaway(sess, b);

        if (rc != NGX_OK) {
            return rc;
        }

        /*
         * If stream_id is lower than one we use, our
         * request won't be processed and needs to be retried.
         * If stream_id is greater or equal to the one we use,
         * we can continue normally (except we can't use this
         * connection for additional requests).  If there is
         * a real error, the connection will be closed.
         */

        if (stream && sess->goaway_last_stream_id < stream->id) {

            /* TODO: we can retry non-idempotent requests */

            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway with error %ui",
                          sess->goaway_error);

            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (sess->stream_id) {
            window_update = &stream->window_update;

        } else {
            window_update = &sess->window_update;
        }

        rc = ngx_http_proxy_v2_parse_window_update(sess, b, window_update);

        if (rc != NGX_OK) {
            return rc;
        }

        if (sess->stream_id) {

            if (*window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                  - stream->send_window)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large window update");
                return NGX_ERROR;
            }

            stream->send_window += *window_update;

        } else {

            if (*window_update > NGX_HTTP_V2_MAX_WINDOW - sess->send_window) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large window update");
                return NGX_ERROR;
            }

            sess->send_window += *window_update;
        }

        if (stream && stream->in) {
            ngx_http_proxy_v2_post_write(sess);
        }

        return NGX_OK;

    case NGX_HTTP_V2_SETTINGS_FRAME:

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

            if (sess->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                window_delta = (ssize_t) sess->setting_value
                               - (ssize_t) sess->init_window;

                if (stream && stream->send_window > 0
                    && window_delta > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                                       - stream->send_window)
                {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  sess->setting_value);
                    return NGX_ERROR;
                }

                sess->init_window = sess->setting_value;

                if (stream) {
                    stream->send_window += window_delta;
                }
            }
        }

        if (!(sess->flags & NGX_HTTP_V2_ACK_FLAG)) {
            if (ngx_http_proxy_v2_send_settings_ack(sess) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        if ((stream && stream->in) || sess->out) {
            ngx_http_proxy_v2_post_write(sess);
        }

        return NGX_OK;

    case NGX_HTTP_V2_PING_FRAME:

        rc = ngx_http_proxy_v2_parse_ping(sess, b);

        if (rc != NGX_OK) {
            return rc;
        }

        if (ngx_http_proxy_v2_send_ping_ack(sess, sess->ping_data)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_http_proxy_v2_post_write(sess);

        return NGX_OK;

    default:

        /* priority, unknown frames */

        return ngx_http_proxy_v2_skip_frame(sess, b);
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
                    return NGX_ERROR;
                }

                stream->done = 1;
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent trailer without end stream flag");
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid trailer");
        return NGX_ERROR;
    }
}


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
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
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

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           sess->type, sess->rest, sess->flags,
                           sess->stream_id);

            b->pos = p + 1;

            sess->state = ngx_http_proxy_v2_st_payload;

            return ngx_http_proxy_v2_validate_frame(sess);

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
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
    size_t                       min;
    ngx_log_t                   *log;
    ngx_http_proxy_v2_stream_t  *stream;

    log = sess->connection->log;
    stream = sess->active_stream;

    if (sess->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent too large http2 frame: %uz", sess->rest);
        return NGX_ERROR;
    }

    if ((sess->type == NGX_HTTP_V2_CONTINUATION_FRAME
         && (!sess->parsing_headers || stream == NULL
             || sess->stream_id != stream->id || stream->header_in == NULL))
        || (sess->type != NGX_HTTP_V2_CONTINUATION_FRAME
            && sess->parsing_headers))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent unexpected http2 frame: %d", sess->type);
        return NGX_ERROR;
    }

    switch (sess->type) {

    case NGX_HTTP_V2_DATA_FRAME:

        if (sess->stream_id == 0 || stream == NULL
            || sess->stream_id != stream->id)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent data frame for unknown stream %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (stream->input_closed || stream->rst) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent frame for closed stream %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (!stream->trailer || stream->trailers) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent unexpected http2 data frame");
            return NGX_ERROR;
        }

        if ((sess->flags & NGX_HTTP_V2_PADDED_FLAG) && sess->rest == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too short http2 frame");
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        if (sess->stream_id == 0 || stream == NULL
            || sess->stream_id != stream->id
            || stream->input_closed || stream->rst || stream->trailers)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent headers for invalid stream %ui",
                          sess->stream_id);
            return NGX_ERROR;
        }

        if (sess->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            return NGX_OK;
        }

        min = (sess->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
              + (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

        if (sess->rest < min) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent headers frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_PRIORITY_FRAME:

        if (sess->rest != 5 || sess->stream_id == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent invalid priority frame");
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_RST_STREAM_FRAME:

        if (sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        break;

    case NGX_HTTP_V2_SETTINGS_FRAME:

        if (sess->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui", sess->stream_id);
            return NGX_ERROR;
        }

        if ((sess->flags & NGX_HTTP_V2_ACK_FLAG) && sess->rest != 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with ack flag and non-zero length: %uz", sess->rest);
            return NGX_ERROR;
        }

        if (sess->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        return NGX_OK;

    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:

        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent unexpected push promise frame");
        return NGX_ERROR;

    case NGX_HTTP_V2_PING_FRAME:

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

        return NGX_OK;

    case NGX_HTTP_V2_GOAWAY_FRAME:

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

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:

        if (sess->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz", sess->rest);
            return NGX_ERROR;
        }

        if (sess->stream_id == 0) {
            return NGX_OK;
        }

        break;

    default:
        return NGX_OK;
    }

    if (sess->stream_id == 0 || stream == NULL
        || sess->stream_id != stream->id)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent frame for unknown stream %ui",
                      sess->stream_id);
        return NGX_ERROR;
    }

    if (sess->type == NGX_HTTP_V2_RST_STREAM_FRAME && stream->rst) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent frame for closed stream %ui",
                      sess->stream_id);
        return NGX_ERROR;
    }

    return NGX_OK;
}


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

    log = sess->connection->log;
    state = sess->frame_state;

    if (state == sw_start) {

        if (sess->rest > stream->recv_window) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream violated stream flow control, "
                          "received %uz data frame with window %uz",
                          sess->rest, stream->recv_window);
            return NGX_ERROR;
        }

        if (sess->rest > sess->recv_window) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream violated connection flow control, "
                          "received %uz data frame with window %uz",
                          sess->rest, sess->recv_window);
            return NGX_ERROR;
        }

        stream->recv_window -= sess->rest;
        sess->recv_window -= sess->rest;

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

        stream->recv_credit++;
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

            b->pos += size;
            sess->rest -= size;

            if (sess->rest > sess->padding) {
                return NGX_AGAIN;
            }
        }

        sess->frame_state = sw_padding;
    }

    size = ngx_min((size_t) (b->last - b->pos), sess->rest);
    b->pos += size;
    sess->rest -= size;
    stream->recv_credit += size;
    sess->recv_credit += size;

    if (sess->rest) {
        return NGX_AGAIN;
    }

    sess->state = ngx_http_proxy_v2_st_start;

    if (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
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
    stream->recv_credit += size;
    stream->session->recv_credit += size;

    return size;
}


static void
ngx_http_proxy_v2_discard_body(ngx_http_proxy_v2_stream_t *stream)
{
    stream->recv_credit += stream->body_size;
    stream->session->recv_credit += stream->body_size;
    stream->body_size = 0;
    stream->body_pos = 0;

    if (stream->body) {
        ngx_pfree(stream->pool, stream->body);
        stream->body = NULL;
    }
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_proxy_v2_session_t *sess,
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
{
    u_char                       ch, *p, *last;
    ngx_int_t                    rc;
    ngx_log_t                   *log;
    ngx_http_proxy_v2_header_t   *field;
    ngx_http_proxy_v2_headers_t  *headers;
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

    log = sess->connection->log;
    state = sess->frame_state;

    if (state == sw_start) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy parse header: start");

        if (sess->type == NGX_HTTP_V2_HEADERS_FRAME) {
            headers = ngx_http_proxy_v2_alloc_header(stream,
                                         sizeof(ngx_http_proxy_v2_headers_t));
            if (headers == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(headers, sizeof(ngx_http_proxy_v2_headers_t));

            headers->body_offset = stream->body_parsed;
            headers->size = 9 + sess->rest;
            headers->end_stream =
                               (sess->flags & NGX_HTTP_V2_END_STREAM_FLAG) != 0;
            stream->header_in = headers;
            stream->header_count++;

            sess->parsing_headers = 1;
            sess->fragment_state = 0;
            sess->header_limit = stream->header_limit;

            if (sess->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (sess->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (sess->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            stream->header_in->size += 9 + sess->rest;
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
            rc = ngx_http_proxy_v2_parse_fragment(sess, stream, b);
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

            sess->parsing_headers = 0;

            headers = stream->header_in;
            headers->current = headers->first;

            if (stream->trailer) {
                stream->trailers = headers;

            } else {
                if (stream->last_headers) {
                    stream->last_headers->next = headers;
                } else {
                    stream->headers = headers;
                }

                stream->last_headers = headers;

                /* classify later blocks by receive progress, not consumption */

                field = headers->first;
                if (field && field->name.len == sizeof(":status") - 1
                    && ngx_strncmp(field->name.data, ":status",
                                   sizeof(":status") - 1) == 0
                    && field->value.len == 3
                    && ngx_atoi(field->value.data, 3) >= NGX_HTTP_OK)
                {
                    stream->trailer = 1;
                }
            }

            stream->header_in = NULL;

            if (headers->end_stream) {
                stream->input_closed = 1;
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
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
{
    u_char                        ch, *p, *last;
    size_t                        len, size;
    ngx_log_t                    *log;
    ngx_uint_t                    index, size_update;
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

    log = sess->connection->log;

    headers = stream->header_in;

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
            sess->name.len = sess->field_huffman ?
                             sess->field_length * 8 / 5 : sess->field_length;

            if (sess->name.len > sess->header_limit) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 "
                              "header name length: %uz",
                              sess->name.len);
                return NGX_ERROR;
            }

            sess->name.data = ngx_http_proxy_v2_alloc_header(stream,
                                                           sess->name.len + 1);
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

            sess->value.data = ngx_http_proxy_v2_alloc_header(stream,
                                                          sess->value.len + 1);
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

        if (!sess->index) {
            if (ngx_http_proxy_v2_validate_header_name(&sess->name)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &sess->name, &sess->value);
                return NGX_ERROR;
            }
        }

        if (!sess->index || sess->literal) {
            if (ngx_http_proxy_v2_validate_header_value(&sess->value)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &sess->name, &sess->value);
                return NGX_ERROR;
            }
        }

        len = sess->name.len + sess->value.len;

        if (len > sess->header_limit
            || headers->count == stream->header_limit)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        sess->header_limit -= len;

        field = ngx_http_proxy_v2_alloc_header(stream,
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
        headers->count++;

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
    ngx_http_proxy_v2_stream_t *stream, ngx_buf_t *b)
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

    stream->error = sess->rst_error;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy error: %ui", stream->error);

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
    ngx_buf_t *b, ngx_uint_t *window_update)
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

    if (sess->window_update == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent zero window update");
        return NGX_ERROR;
    }

    *window_update = sess->window_update;

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
ngx_http_proxy_v2_send_window_update(ngx_http_proxy_v2_stream_t *stream)
{
    size_t                        n, connection, window;
    ngx_uint_t                    i, id;
    ngx_chain_t                  *cl;
    ngx_http_proxy_v2_frame_t    *f;
    ngx_http_proxy_v2_session_t  *sess;

    sess = stream->session;

    connection = sess->recv_window <= NGX_HTTP_V2_DEFAULT_WINDOW / 2
                 ? sess->recv_credit : 0;
    window = !stream->input_closed
             && stream->recv_window <= NGX_HTTP_V2_DEFAULT_WINDOW / 2
             ? stream->recv_credit : 0;

    if (connection == 0 && window == 0) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sess->connection->log, 0,
                   "http proxy send window update: %uz %uz",
                   sess->recv_window, stream->recv_window);

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
    stream->recv_window += window;
    stream->recv_credit -= window;

    *sess->last_out = cl;
    sess->last_out = &cl->next;

    return NGX_OK;
}


static void *
ngx_http_proxy_v2_alloc_header(ngx_http_proxy_v2_stream_t *stream, size_t size)
{
    size_t  charge;

    /* consumed fields can remain referenced until the request pool is freed */

    charge = ngx_align(size, NGX_ALIGNMENT);
    if (charge < size || charge > stream->header_budget) {
        ngx_log_error(NGX_LOG_ERR, stream->session->connection->log, 0,
                      "upstream sent too much http2 header data");
        return NULL;
    }

    stream->header_budget -= charge;
    return ngx_palloc(stream->pool, size);
}


static ngx_chain_t *
ngx_http_proxy_v2_get_output_buf(ngx_http_proxy_v2_session_t *sess)
{
    if (sess->free == NULL) {
        if (sess->allocated == NGX_HTTP_PROXY_V2_MAX_OUTPUT_BUFS) {
            ngx_log_error(NGX_LOG_ERR, sess->connection->log, 0,
                          "too much pending http2 output");
            return NULL;
        }

        sess->allocated++;
    }

    return ngx_chain_get_free_buf(sess->connection->pool, &sess->free);
}


static ngx_chain_t *
ngx_http_proxy_v2_get_buf(ngx_http_proxy_v2_session_t *sess)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_http_proxy_v2_get_output_buf(sess);
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

    cl = ngx_http_proxy_v2_get_output_buf(sess);
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
ngx_http_proxy_v2_init_connection(ngx_http_request_t *r)
{
    ngx_connection_t             *c, *pc;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    u = r->upstream;
    pc = u->peer.connection;

    /* each upstream attempt has its own stream in the request pool */

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_stream_t));
    if (stream == NULL) {
        return NGX_ERROR;
    }

    sess = ngx_http_proxy_v2_get_session(&r->upstream->peer);
    if (sess == NULL) {
        return NGX_ERROR;
    }

    if (sess->active_stream || sess->failed || sess->closed) {
        return NGX_ERROR;
    }

    stream->session = sess;
    stream->free_peer = r->upstream->peer.free;
    stream->pool = r->pool;
    stream->id = sess->last_stream_id ? sess->last_stream_id + 2 : 1;
    stream->send_window = sess->init_window;
    stream->recv_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    stream->header_limit = r->upstream->conf->buffer_size;

    if (stream->header_limit > NGX_MAX_SIZE_T_VALUE / 64) {
        return NGX_ERROR;
    }

    stream->header_budget = ngx_max(NGX_HTTP_PROXY_V2_HEADER_BUDGET,
                                   stream->header_limit * 64);

    c = &stream->connection;
    c->data = r;
    c->pool = r->pool;
    c->log = pc->log;
    c->fd = (ngx_socket_t) -1;
    c->logical = 1;
    c->type = pc->type;
    c->number = pc->number;
    c->start_time = pc->start_time;
    c->sendfile = pc->sendfile;
    c->recv = ngx_http_proxy_v2_recv;
    c->recv_chain = ngx_http_proxy_v2_recv_chain;
    c->read = &stream->read;
    c->write = &stream->write;

    c->read->data = c;
    c->read->log = c->log;
    c->read->active = 1;
    c->read->available = -1;
    c->write->data = c;
    c->write->log = c->log;
    c->write->active = 1;
    c->write->write = 1;
    c->write->ready = 1;

    if (pc->read->timer_set) {
        ngx_del_timer(pc->read);
    }
    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    sess->last_stream_id = stream->id;
    sess->active_stream = stream;
    sess->writer.limit = r->upstream->writer.limit;
    sess->send_lowat = u->conf->send_lowat;
    sess->read_handler = ngx_http_proxy_v2_set_read_handler(pc,
                                               ngx_http_proxy_v2_read_handler);
    sess->write_handler = ngx_http_proxy_v2_set_write_handler(sess->connection,
                                              ngx_http_proxy_v2_write_handler);

    c->read->handler = sess->read_handler;
    c->write->handler = sess->write_handler;
    r->upstream->peer.free = ngx_http_proxy_v2_free_peer;
    ctx->stream = stream;

    u->connection = c;
    u->writer.connection = c;

    /* physical c->data remains the request for TLS session-save callbacks */

    ngx_post_event(c->write, &ngx_posted_events);
    ngx_http_proxy_v2_post_read(sess);

    return NGX_OK;
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc)
{
    ngx_connection_t             *c;
    ngx_pool_cleanup_t           *cln;
    ngx_http_proxy_v2_session_t  *sess;

    c = pc->connection;

    if (pc->cached) {

        sess = ngx_http_proxy_v2_find_session(c);
        if (sess) {
            return sess;
        }

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "no session found for keepalive http2 connection");
        return NULL;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_proxy_v2_session_cleanup;
    sess = cln->data;

    ngx_memzero(sess, sizeof(ngx_http_proxy_v2_session_t));
    sess->connection = c;

    sess->buffer = ngx_create_temp_buf(c->pool, NGX_HTTP_V2_DEFAULT_FRAME_SIZE);
    if (sess->buffer == NULL) {
        return NULL;
    }

    sess->writer.last = &sess->writer.out;
    sess->writer.connection = c;
    sess->writer.pool = c->pool;
    sess->last_out = &sess->out;

    sess->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    sess->recv_window = NGX_HTTP_V2_DEFAULT_WINDOW;

    return sess;
}


static ngx_uint_t
ngx_http_proxy_v2_reusable(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *sess;

    sess = stream->session;
    c = sess->connection;

    if (!stream->input_closed || stream->header_count || stream->body_size
        || stream->body_processed != stream->body_parsed
        || stream->in || !stream->output_closed
        || ngx_http_proxy_v2_output_pending(sess)
        || sess->failed || sess->closed || sess->goaway
        || sess->state != ngx_http_proxy_v2_st_start || sess->parsing_headers
        || !ngx_http_proxy_v2_input_drained(sess)
        || c->error || c->read->eof || c->read->error || c->write->error)
    {
        return 0;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl && (c->ssl->saved_read_handler || c->ssl->saved_write_handler)) {
        return 0;
    }
#endif

    return 1;
}


static void
ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_event_free_peer_pt        free_peer;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_stream_t   *stream;
    ngx_http_proxy_v2_session_t  *sess;

    c = pc->connection;
    sess = ngx_http_proxy_v2_find_session(c);
    stream = sess->active_stream;
    free_peer = stream->free_peer;
    r = stream->connection.data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (r->upstream->state) {
        r->upstream->state->bytes_received = stream->received;
        r->upstream->state->bytes_sent = c->sent;
    }

    if (!ngx_http_proxy_v2_reusable(stream)
        || stream->read.timedout || stream->write.timedout)
    {
        r->upstream->keepalive = 0;
        c->error = 1;
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

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }
    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    (void) ngx_http_proxy_v2_set_write_handler(c, sess->write_handler);
    (void) ngx_http_proxy_v2_set_read_handler(c, sess->read_handler);

    ngx_http_proxy_v2_discard_output(sess);
    ngx_http_proxy_v2_discard_body(stream);
    stream->in = NULL;

    sess->active_stream = NULL;
    stream->session = NULL;
    ctx->stream = NULL;
    pc->free = free_peer;

    /* the original handler can cache or close the physical connection */

    free_peer(pc, data, state);
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


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    /* identifies the session in the connection pool */

    return;
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
