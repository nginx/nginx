
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>
#include <ngx_http_proxy_v2_frame.h>
#include <ngx_http_proxy_v2_session.h>


#define NGX_HTTP_PROXY_V2_FRAME_BUFFER_SIZE                              \
    (NGX_HTTP_V2_FRAME_HEADER_SIZE + NGX_HTTP_V2_DEFAULT_FRAME_SIZE)


typedef enum {
    ngx_http_proxy_v2_st_start = 0,
    ngx_http_proxy_v2_st_payload,
    ngx_http_proxy_v2_st_padding
} ngx_http_proxy_v2_state_e;


typedef struct ngx_http_proxy_v2_in_frame_s  ngx_http_proxy_v2_in_frame_t;

struct ngx_http_proxy_v2_in_frame_s {
    ngx_http_proxy_v2_frame_parse_t  parse;
    ngx_http_proxy_v2_in_frame_t    *next;

    unsigned                         error:1;
};


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_http_proxy_v2_frame_parse_t cache_frame_parse;
    ngx_http_proxy_v2_state_e      state;
    ngx_uint_t                     frame_state;
    ngx_uint_t                     fragment_state;

    ngx_chain_t                   *in;
    ngx_chain_t                   *out;
    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    ngx_http_proxy_v2_in_frame_t  *frames;
    ngx_http_proxy_v2_in_frame_t  *free_frames;
    ngx_http_proxy_v2_in_frame_t **last_frame;

    ngx_http_proxy_v2_session_t   *session;
    ngx_connection_t              *stream_connection;
    ngx_event_free_peer_pt         original_free_peer;

    ngx_uint_t                     id;

    off_t                          length;

    ssize_t                        send_window;
    size_t                         recv_window;

    size_t                         rest;
    ngx_uint_t                     stream_id;
    u_char                         type;
    u_char                         flags;
    u_char                         padding;

    ngx_uint_t                     error;
    ngx_uint_t                     window_update;

    ngx_uint_t                     index;
    ngx_str_t                      name;
    ngx_str_t                      value;

    u_char                        *field_end;
    size_t                         header_limit;
    size_t                         field_length;
    size_t                         field_rest;
    u_char                         field_state;

    unsigned                       literal:1;
    unsigned                       field_huffman:1;

    unsigned                       header_sent:1;
    unsigned                       output_closed:1;
    unsigned                       output_blocked:1;
    unsigned                       parsing_headers:1;
    unsigned                       end_stream:1;
    unsigned                       done:1;
    unsigned                       status:1;
    unsigned                       rst:1;
    unsigned                       goaway:1;
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
static ngx_int_t ngx_http_proxy_v2_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_v2_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_filter_init(void *data);
static ngx_int_t ngx_http_proxy_v2_non_buffered_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_v2_process_stream_window_update(
    ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_get_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_stream_window_update(
    ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_send_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);

static ngx_chain_t *ngx_http_proxy_v2_get_buf(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_http_proxy_v2_ctx_t *
    ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_get_connection_data(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_peer_connection_t *pc);
static ngx_inline ngx_int_t ngx_http_proxy_v2_cached(ngx_http_request_t *r);
static void ngx_http_proxy_v2_cleanup(void *data);
static ngx_int_t ngx_http_proxy_v2_attach_request(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_peer_connection_t *pc,
    ngx_connection_t *c);
static void ngx_http_proxy_v2_detach_request(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_init_stream_connection(
    ngx_http_request_t *r, ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_stream_dispatch_frame(
    ngx_connection_t *sc, ngx_http_proxy_v2_ctx_t *ctx,
    ngx_http_proxy_v2_session_t *s);
static ngx_int_t ngx_http_proxy_v2_session_read_frame(
    ngx_http_proxy_v2_session_t *s);
static ngx_int_t ngx_http_proxy_v2_session_process_connection_frame(
    ngx_http_proxy_v2_session_t *s);
static void ngx_http_proxy_v2_stream_frame_done(ngx_connection_t *sc,
    ngx_http_proxy_v2_session_t *s);
static ssize_t ngx_http_proxy_v2_stream_recv(ngx_connection_t *sc,
    u_char *buf, size_t size);
static ssize_t ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *sc,
    ngx_chain_t *chain, off_t limit);
static ssize_t ngx_http_proxy_v2_stream_send(ngx_connection_t *sc,
    u_char *buf, size_t size);
static ngx_chain_t *ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *sc,
    ngx_chain_t *in, off_t limit);
static void ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev);
static void ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev);
static void ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);

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

    ctx->last_frame = &ctx->frames;

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

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_proxy_v2_create_request;
    u->reinit_request = ngx_http_proxy_v2_reinit_request;
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
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_in_frame_t  *f;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_http_proxy_v2_detach_request(r, ctx);

    ctx->state = 0;
    ctx->cache_frame_parse.state = 0;
    ctx->header_sent = 0;
    ctx->output_closed = 0;
    ctx->output_blocked = 0;
    ctx->parsing_headers = 0;
    ctx->end_stream = 0;
    ctx->done = 0;
    ctx->status = 0;
    ctx->rst = 0;
    ctx->goaway = 0;
    while (ctx->frames) {
        f = ctx->frames;
        ctx->frames = f->next;
        f->next = ctx->free_frames;
        ctx->free_frames = f;
    }

    ctx->last_frame = &ctx->frames;
    ctx->session = NULL;
    ctx->stream_connection = NULL;
    ctx->in = NULL;
    ctx->busy = NULL;
    ctx->out = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                       file_pos;
    u_char                     *p, *pos, *start;
    size_t                      len, limit;
    ngx_buf_t                  *b;
    ngx_int_t                  rc;
    ngx_uint_t                 next, last;
    ngx_chain_t                *cl, *out, *ln, **ll;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_v2_ctx_t    *ctx;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output filter");

    ctx = ngx_http_proxy_v2_get_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output header");

        ctx->header_sent = 1;

        if (ctx->id != 1) {
            /*
             * keepalive connection: skip connection preface,
             * update stream identifiers
             */

            b = ctx->in->buf;
            b->pos += sizeof(ngx_http_proxy_v2_connection_start) - 1;

            p = b->pos;

            while (p < b->last) {
                f = (ngx_http_proxy_v2_frame_t *) p;
                p += sizeof(ngx_http_proxy_v2_frame_t);

                f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
                f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
                f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
                f->stream_id_3 = (u_char) (ctx->id & 0xff);

                p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
            }
        }

        if (ctx->in->buf->last_buf) {
            ctx->output_closed = 1;
        }

        *ll = ctx->in;
        ll = &ctx->in->next;

        ctx->in = ctx->in->next;
    }

    if (ctx->out) {
        /* queued control frames */

        *ll = ctx->out;

        for (cl = ctx->out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->out = NULL;
    }

    f = NULL;
    last = 0;

    limit = ngx_max(0, ctx->send_window);

    if (limit > ctx->session->send_window) {
        limit = ctx->session->send_window;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->session->send_window);

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->in;

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
             * to reuse it later for headers and control frames
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
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            limit -= len;
            ctx->send_window -= len;
            ctx->session->send_window -= len;

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

    ctx->in = in;

    if (last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output last");

        ctx->output_closed = 1;

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
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

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
                   limit, ctx->send_window, ctx->session->send_window);

#endif

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                         (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter);

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

    if (rc == NGX_OK && ctx->in) {
        rc = NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        ctx->output_blocked = 1;

    } else {
        ctx->output_blocked = 0;
    }

    if (ctx->done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;
        u->pipe->length = 0;

        if (ctx->in == NULL
            && ctx->out == NULL
            && ctx->output_closed
            && !ctx->output_blocked
            && !ctx->goaway
            && ctx->state == ngx_http_proxy_v2_st_start)
        {
            u->keepalive = 1;
        }

        ngx_post_event(u->peer.connection->read, &ngx_posted_events);
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_process_header(ngx_http_request_t *r)
{
    u_char                         *pos;
    ngx_str_t                      *status_line;
    ngx_int_t                       rc, status;
    ngx_buf_t                      *b;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_v2_ctx_t        *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;
    pos = b->pos;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy response: %*xs%s, len: %uz",
                   (size_t) ngx_min(b->last - b->pos, 256),
                   b->pos, b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    ctx = ngx_http_proxy_v2_get_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        if (ctx->state < ngx_http_proxy_v2_st_payload) {

            rc = ngx_http_proxy_v2_get_frame(r, ctx, b);

            if (rc == NGX_AGAIN) {

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */

                if (!ctx->parsing_headers) {
                    b->pos = pos;
                    b->last = b->pos;
                }

                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->type == NGX_HTTP_V2_DATA_FRAME
                || (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->parsing_headers)
                || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->id && ctx->stream_id && ctx->stream_id != ctx->id) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (!ngx_http_proxy_v2_cached(r)) {

            if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
                rc = ngx_http_proxy_v2_parse_rst_stream(r, ctx, b);

                if (rc == NGX_AGAIN) {
                    return NGX_AGAIN;
                }

                if (rc == NGX_ERROR) {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream rejected request with error %ui",
                              ctx->error);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            rc = ngx_http_proxy_v2_process_stream_window_update(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (rc == NGX_OK) {
                continue;
            }
        }

        if (ctx->type != NGX_HTTP_V2_HEADERS_FRAME
            && ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = ngx_http_proxy_v2_parse_header(r, ctx, b);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%V: %V\"",
                               &ctx->name, &ctx->value);

                if (ctx->name.len && ctx->name.data[0] == ':') {

                    if (ctx->name.len != sizeof(":status") - 1
                        || ngx_strncmp(ctx->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->value;

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

                h->key = ctx->name;
                h->value = ctx->value;
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

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header done");

                if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                    if (ctx->end_stream) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    ctx->status = 0;
                    return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                }

                if (ctx->end_stream
                    && ctx->in == NULL
                    && ctx->out == NULL
                    && ctx->output_closed
                    && !ctx->output_blocked
                    && !ctx->goaway
                    && b->last == b->pos)
                {
                    u->keepalive = 1;
                }

                return NGX_OK;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == NGX_AGAIN */

        if (ctx->rest == 0) {
            ctx->state = ngx_http_proxy_v2_st_start;
            continue;
        }

        return NGX_AGAIN;
    }
}


static ngx_int_t
ngx_http_proxy_v2_filter_init(void *data)
{
    ngx_http_request_t       *r = data;
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
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

    if (ctx->end_stream) {

        if (ctx->length > 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream prematurely closed stream");
            return NGX_ERROR;
        }

        u->length = 0;
        u->pipe->length = 0;
        ctx->done = 1;

    } else {
        u->length = 1;
        u->pipe->length = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_non_buffered_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_int_t                 rc;
    ngx_buf_t                *b, *buf;
    ngx_chain_t              *cl, **ll;
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", bytes);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    b = &u->buffer;

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = ngx_http_proxy_v2_process_frames(r, ctx, b);

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

            if (b->last - b->pos >= (ssize_t) ctx->rest - ctx->padding) {
                b->pos += ctx->rest - ctx->padding;
                buf->last = b->pos;
                ctx->rest = ctx->padding;

            } else {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                buf->last = b->pos;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy output buf %p", buf->pos);

            if (ctx->length != -1) {

                if (buf->last - buf->pos > ctx->length) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NGX_ERROR;
                }

                ctx->length -= buf->last - buf->pos;
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
    ngx_int_t                 rc;
    ngx_buf_t                *buf, **prev;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r;
    ngx_http_proxy_v2_ctx_t  *ctx;

    if (b->pos == b->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    buf = NULL;
    prev = &b->shadow;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", b->last - b->pos);

    for ( ;; ) {

        rc = ngx_http_proxy_v2_process_frames(r, ctx, b);

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

            if (b->last - b->pos >= (ssize_t) ctx->rest - ctx->padding) {
                b->pos += ctx->rest - ctx->padding;
                buf->last = b->pos;
                ctx->rest = ctx->padding;

            } else {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                buf->last = b->pos;
            }

            if (ctx->length != -1) {

                if (buf->last - buf->pos > ctx->length) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NGX_ERROR;
                }

                ctx->length -= buf->last - buf->pos;
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
ngx_http_proxy_v2_process_stream_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_int_t             rc;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {

        rc = ngx_http_proxy_v2_parse_stream_window_update(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ctx->in) {
            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) ctx->rest) {
        ctx->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += ctx->rest;
    ctx->rest = 0;
    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_int_t             rc;
    ngx_table_elt_t      *h;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for ( ;; ) {

        if (ctx->state < ngx_http_proxy_v2_st_payload) {

            rc = ngx_http_proxy_v2_get_frame(r, ctx, b);

            if (rc == NGX_AGAIN) {

                if (ctx->done) {

                    if (ctx->length > 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NGX_ERROR;
                    }

                    /*
                     * We have finished parsing the response and the
                     * remaining control frames.  If there are unsent
                     * control frames, post a write event to send them.
                     */

                    if (ctx->out) {
                        ngx_post_event(u->peer.connection->write,
                                       &ngx_posted_events);
                        return NGX_AGAIN;
                    }

                    if (ctx->in == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && !ctx->goaway
                        && ctx->state == ngx_http_proxy_v2_st_start)
                    {
                        u->keepalive = 1;
                    }

                    return NGX_DONE;
                }

                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if ((ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->parsing_headers)
                || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NGX_ERROR;
            }

            if (ctx->type == NGX_HTTP_V2_DATA_FRAME) {

                if (ctx->stream_id != ctx->id) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent data frame "
                                  "for unknown stream %ui",
                                  ctx->stream_id);
                    return NGX_ERROR;
                }

                if (ctx->rest > ctx->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->recv_window);
                    return NGX_ERROR;
                }

                if (ctx->rest > ctx->session->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->session->recv_window);
                    return NGX_ERROR;
                }

                ctx->recv_window -= ctx->rest;
                ctx->session->recv_window -= ctx->rest;

                if (ctx->session->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
                    || ctx->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (ngx_http_proxy_v2_send_window_update(r, ctx)
                        != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    ngx_post_event(u->peer.connection->write,
                                   &ngx_posted_events);
                }
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NGX_ERROR;
            }

            if (ctx->stream_id && ctx->done
                && ctx->type != NGX_HTTP_V2_RST_STREAM_FRAME
                && ctx->type != NGX_HTTP_V2_WINDOW_UPDATE_FRAME)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return NGX_ERROR;
            }

            ctx->padding = 0;
        }

        if (ctx->state == ngx_http_proxy_v2_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = ngx_http_proxy_v2_st_start;

            if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->done = 1;
            }

            continue;
        }

        /* frame payload */

        if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {

            rc = ngx_http_proxy_v2_parse_rst_stream(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ctx->error || !ctx->done) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream rejected request with error %ui",
                              ctx->error);
                return NGX_ERROR;
            }

            if (ctx->rst) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return NGX_ERROR;
            }

            ctx->rst = 1;

            continue;
        }

        rc = ngx_http_proxy_v2_process_stream_window_update(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME
            || ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = ngx_http_proxy_v2_parse_header(r, ctx, b);

                if (rc == NGX_AGAIN) {
                    break;
                }

                if (rc == NGX_OK) {

                    /* a header line has been parsed successfully */

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer: \"%V: %V\"",
                                   &ctx->name, &ctx->value);

                    if (ctx->name.len && ctx->name.data[0] == ':') {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NGX_ERROR;
                    }

                    h = ngx_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return NGX_ERROR;
                    }

                    h->key = ctx->name;
                    h->value = ctx->value;
                    h->lowcase_key = h->key.data;
                    h->hash = ngx_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer done");

                    if (ctx->end_stream) {
                        ctx->done = 1;
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

            if (ctx->rest == 0) {
                ctx->state = ngx_http_proxy_v2_st_start;
                continue;
            }

            return NGX_AGAIN;
        }

        if (ctx->type != NGX_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            continue;
        }

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

        if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            ctx->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return NGX_ERROR;
            }

            continue;
        }

        if (ctx->padding == ctx->rest) {

            if (ctx->padding) {
                ctx->state = ngx_http_proxy_v2_st_padding;

            } else {
                ctx->state = ngx_http_proxy_v2_st_start;

                if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                    ctx->done = 1;
                }
            }

            continue;
        }

        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        return NGX_OK;
    }
}


static ngx_int_t
ngx_http_proxy_v2_get_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_int_t                        rc;
    ngx_http_proxy_v2_in_frame_t    *f;
    ngx_http_proxy_v2_frame_parse_t *parse;

    if (ctx->frames) {
        if (b->last - b->pos < NGX_HTTP_V2_FRAME_HEADER_SIZE) {
            return NGX_AGAIN;
        }

        b->pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;

        f = ctx->frames;
        ctx->frames = f->next;

        if (ctx->frames == NULL) {
            ctx->last_frame = &ctx->frames;
        }

        parse = &f->parse;

        if (f->error) {
            f->next = ctx->free_frames;
            ctx->free_frames = f;

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large http2 frame: %uz",
                          parse->length);
            return NGX_ERROR;
        }

        f->next = ctx->free_frames;
        ctx->free_frames = f;

        rc = NGX_OK;

    } else if (ngx_http_proxy_v2_cached(r)) {
        parse = &ctx->cache_frame_parse;
        rc = ngx_http_proxy_v2_frame_parse(parse, b);

    } else if (b->pos == b->last) {
        return NGX_AGAIN;

    } else {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "no http2 frame available from upstream session");
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent too large http2 frame: %uz",
                      parse->length);
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    ctx->rest = parse->length;
    ctx->type = parse->type;
    ctx->flags = parse->flags;
    ctx->stream_id = parse->stream_id;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                   ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

    ctx->state = ngx_http_proxy_v2_st_payload;
    ctx->frame_state = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_stream_dispatch_frame(ngx_connection_t *sc,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_http_proxy_v2_session_t *s)
{
    ngx_buf_t                     *b;
    ngx_http_request_t            *r;
    ngx_http_proxy_v2_in_frame_t  *f;

    b = s->input;

    if (b->pos != b->start || s->frame_dispatched) {
        return NGX_OK;
    }

    if (ctx->free_frames) {
        f = ctx->free_frames;
        ctx->free_frames = f->next;

    } else {
        r = sc->data;

        f = ngx_palloc(r->pool, sizeof(ngx_http_proxy_v2_in_frame_t));
        if (f == NULL) {
            return NGX_ERROR;
        }
    }

    f->parse = s->frame_parse;
    f->error = s->frame_error;
    f->next = NULL;

    *ctx->last_frame = f;
    ctx->last_frame = &f->next;

    s->frame_dispatched = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    ngx_int_t  rc;
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

    state = ctx->frame_state;

    if (state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy parse header: start");

        if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1;
            ctx->fragment_state = 0;
            ctx->header_limit = r->upstream->conf->buffer_size;

            min = (ctx->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->padding = 0;
        ctx->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                ctx->padding = ch;

                if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
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

        ctx->rest -= p - b->pos;
        b->pos = p;

        ctx->frame_state = state;
        return NGX_AGAIN;

    fragment:

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return NGX_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = ngx_http_proxy_v2_parse_fragment(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            return NGX_OK;
        }

        /* rc == NGX_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return NGX_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = ngx_http_proxy_v2_st_start;

        if (ctx->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return NGX_ERROR;
            }

            ctx->parsing_headers = 0;

            return NGX_HTTP_PARSE_HEADER_DONE;
        }

        return NGX_AGAIN;
    }

    /* unreachable */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      len, size;
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

    /* header block fragment */

#if 0
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest - ctx->padding;
    }

    state = ctx->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->index = 0;

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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy indexed header: %ui", index);

                ctx->index = index;
                ctx->literal = 0;

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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ctx->index = index;
                ctx->literal = 1;

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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
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
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header never indexed: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

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
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                             "http proxy literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NGX_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NGX_ERROR;
            }

            if (ctx->index > 61) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header index: %ui", ctx->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            if (ctx->name.len > ctx->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length: %uz",
                              ctx->name.len);
                return NGX_ERROR;
            }

            ctx->name.data = ngx_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->name.data[ctx->name.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_str_set(&ctx->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NGX_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            if (ctx->value.len > ctx->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length: %uz",
                              ctx->value.len);
                return NGX_ERROR;
            }

            ctx->value.data = ngx_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->value.data[ctx->value.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    done:

        p++;
        ctx->rest -= p - b->pos;
        ctx->fragment_state = sw_start;
        b->pos = p;

        if (ctx->index) {
            ctx->name = *ngx_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *ngx_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (ngx_http_proxy_v2_validate_header_name(r, &ctx->name)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (ngx_http_proxy_v2_validate_header_value(r, &ctx->value)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        len = ctx->name.len + ctx->value.len;

        if (len > ctx->header_limit) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        ctx->header_limit -= len;

        return NGX_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return NGX_AGAIN;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r, ngx_str_t *s)
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
ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r, ngx_str_t *s)
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
ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_stream_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->stream_id == 0) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "connection window update dispatched to request");
            return NGX_ERROR;
        }

        if (ctx->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            ctx->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            ctx->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            ctx->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy window update: %ui", ctx->window_update);

    if (ctx->window_update == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent zero window update");
        return NGX_ERROR;
    }

    if (ctx->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                             - ctx->send_window)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent too large window update");
        return NGX_ERROR;
    }

    ctx->send_window += ctx->window_update;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    size_t                      n;
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy send window update: %uz %uz",
                   ctx->session->recv_window, ctx->recv_window);

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_buf(r, ctx);
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

    n = NGX_HTTP_V2_MAX_WINDOW - ctx->session->recv_window;
    ctx->session->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (ctx->id & 0xff);

    n = NGX_HTTP_V2_MAX_WINDOW - ctx->recv_window;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NGX_OK;
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

        /*
         * each buffer is large enough to hold two window update
         * frames in a row
         */

        start = ngx_palloc(r->pool, 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8;

    b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static ngx_http_proxy_v2_ctx_t *
ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r)
{
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx->session == NULL) {
        u = r->upstream;

        if (ngx_http_proxy_v2_get_connection_data(r, ctx, &u->peer) != NGX_OK) {
            return NULL;
        }
    }

    return ctx;
}


static ngx_int_t
ngx_http_proxy_v2_get_connection_data(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_peer_connection_t *pc)
{
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = NULL;

    if (ngx_http_proxy_v2_cached(r)) {
        ctx->session = ngx_palloc(r->pool,
                                  sizeof(ngx_http_proxy_v2_session_t));
        if (ctx->session == NULL) {
            return NGX_ERROR;
        }

        ctx->id = 0;

        goto done;
    }

    c = pc->connection;

    if (pc->cached) {

        /*
         * for cached connections, connection data can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_proxy_v2_cleanup) {
                ctx->session = cln->data;
                break;
            }
        }

        if (ctx->session == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no connection data found for "
                          "keepalive http2 connection");
            return NGX_ERROR;
        }

        ctx->send_window = ctx->session->init_window;
        ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;

        ctx->session->last_stream_id += 2;
        ctx->id = ctx->session->last_stream_id;

        if (ngx_http_proxy_v2_attach_request(r, ctx, pc, c) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(c->pool,
                               sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_proxy_v2_cleanup;
    ctx->session = cln->data;

    ctx->id = 1;

done:

    ngx_http_proxy_v2_session_init(ctx->session);

    ctx->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    if (c) {
        if (ngx_http_proxy_v2_attach_request(r, ctx, pc, c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_inline ngx_int_t
ngx_http_proxy_v2_cached(ngx_http_request_t *r)
{
#if (NGX_HTTP_CACHE)
    return r->cached;
#else
    return 0;
#endif
}


static void
ngx_http_proxy_v2_cleanup(void *data)
{
#if 0
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http proxy cleanup");
#endif
    return;
}


static ngx_int_t
ngx_http_proxy_v2_attach_request(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_peer_connection_t *pc,
    ngx_connection_t *c)
{
    ngx_http_proxy_v2_session_attach(ctx->session, c, r);

    if (ngx_http_proxy_v2_init_stream_connection(r, ctx) != NGX_OK) {
        ngx_http_proxy_v2_session_detach(ctx->session, r);
        return NGX_ERROR;
    }

    ctx->original_free_peer = pc->free;
    pc->free = ngx_http_proxy_v2_free_peer;

    return NGX_OK;
}


/*
 * Give the request a logical connection with request-owned events.  Its I/O
 * callbacks forward to the real session connection, whose events wake the
 * logical connection through the session handlers below.
 */

static ngx_int_t
ngx_http_proxy_v2_init_stream_connection(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c, *sc;

    c = ctx->session->connection;

    sc = ngx_palloc(r->pool, sizeof(ngx_connection_t));
    rev = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
    wev = ngx_pcalloc(r->pool, sizeof(ngx_event_t));

    if (sc == NULL || rev == NULL || wev == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sc, c, sizeof(ngx_connection_t));

    rev->data = sc;
    rev->ready = c->read->ready;
    rev->active = 1;
    rev->handler = c->read->handler;
    rev->log = c->log;

    wev->data = sc;
    wev->write = 1;
    wev->ready = c->write->ready;
    wev->active = 1;
    wev->handler = c->write->handler;
    wev->log = c->log;

    sc->read = rev;
    sc->write = wev;
    sc->data = r;
    sc->recv = ngx_http_proxy_v2_stream_recv;
    sc->recv_chain = ngx_http_proxy_v2_stream_recv_chain;
    sc->send = ngx_http_proxy_v2_stream_send;
    sc->send_chain = ngx_http_proxy_v2_stream_send_chain;

    ctx->stream_connection = sc;

    c->read->handler = ngx_http_proxy_v2_session_read_handler;
    c->write->handler = ngx_http_proxy_v2_session_write_handler;

    r->upstream->peer.connection = sc;
    r->upstream->writer.connection = sc;

    return NGX_OK;
}


static ssize_t
ngx_http_proxy_v2_stream_recv(ngx_connection_t *sc, u_char *buf, size_t size)
{
    size_t                         n;
    ngx_buf_t                     *b;
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_session_t   *s;

    r = sc->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    s = ctx->session;
    c = s->connection;

    if (!s->frame_ready) {
        sc->read->ready = 0;
        sc->read->eof = c->read->eof;
        sc->read->error = c->read->error;

        if (c->read->error) {
            return NGX_ERROR;
        }

        if (c->read->eof) {
            return 0;
        }

        if (c->read->ready && !c->read->posted) {
            ngx_post_event(c->read, &ngx_posted_events);
            return NGX_AGAIN;
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            sc->read->error = 1;
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    b = s->input;

    if (ngx_http_proxy_v2_stream_dispatch_frame(sc, ctx, s) != NGX_OK) {
        return NGX_ERROR;
    }

    n = ngx_min(size, (size_t) (b->last - b->pos));

    ngx_memcpy(buf, b->pos, n);
    b->pos += n;

    if (b->pos == b->last) {
        ngx_http_proxy_v2_stream_frame_done(sc, s);

    } else {
        sc->read->ready = 1;
    }

    return n;
}


static ssize_t
ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *sc, ngx_chain_t *chain,
    off_t limit)
{
    size_t                         n, size;
    ssize_t                        total;
    ngx_buf_t                     *b, *dst;
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_session_t   *s;

    r = sc->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    s = ctx->session;
    c = s->connection;

    if (!s->frame_ready) {
        sc->read->ready = 0;
        sc->read->eof = c->read->eof;
        sc->read->error = c->read->error;

        if (c->read->error) {
            return NGX_ERROR;
        }

        if (c->read->eof) {
            return 0;
        }

        if (c->read->ready && !c->read->posted) {
            ngx_post_event(c->read, &ngx_posted_events);
            return NGX_AGAIN;
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            sc->read->error = 1;
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    b = s->input;
    total = 0;

    if (ngx_http_proxy_v2_stream_dispatch_frame(sc, ctx, s) != NGX_OK) {
        return NGX_ERROR;
    }

    while (chain && b->pos < b->last) {
        dst = chain->buf;
        size = dst->end - dst->last;

        if (limit && (off_t) (total + size) > limit) {
            size = (size_t) (limit - total);

            if (size == 0) {
                break;
            }
        }

        n = ngx_min(size, (size_t) (b->last - b->pos));

        ngx_memcpy(dst->last, b->pos, n);
        b->pos += n;
        total += n;

        if (n < size) {
            break;
        }

        chain = chain->next;
    }

    if (b->pos == b->last) {
        ngx_http_proxy_v2_stream_frame_done(sc, s);

    } else {
        sc->read->ready = 1;
    }

    return total;
}


static void
ngx_http_proxy_v2_stream_frame_done(ngx_connection_t *sc,
    ngx_http_proxy_v2_session_t *s)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = s->connection;

    ngx_http_proxy_v2_session_frame_done(s);

    sc->read->ready = 0;

    while (c->read->ready) {
        rc = ngx_http_proxy_v2_session_read_frame(s);

        if (rc == NGX_ERROR) {
            sc->read->error = 1;
            sc->read->ready = 1;
            return;
        }

        if (rc == NGX_OK) {
            rc = ngx_http_proxy_v2_session_process_connection_frame(s);

            if (rc == NGX_ERROR) {
                sc->read->error = 1;
                sc->read->ready = 1;
                return;
            }

            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc == NGX_OK) {
                continue;
            }

            sc->read->ready = 1;
            return;
        }
    }

    if (c->read->ready && !c->read->posted) {
        ngx_post_event(c->read, &ngx_posted_events);
    }
}


static ngx_int_t
ngx_http_proxy_v2_session_process_connection_frame(
    ngx_http_proxy_v2_session_t *s)
{
    ngx_connection_t            *c;
    ssize_t                      window_update;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_ctx_t     *ctx;

    r = s->request;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (s->frame_error) {
        return NGX_DECLINED;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_GOAWAY_FRAME) {
        if (ngx_http_proxy_v2_session_process_goaway(s) != NGX_OK) {
            return NGX_ERROR;
        }

        ctx->goaway = 1;

        if (s->peer_last_stream_id < ctx->id) {

            /* TODO: we can retry non-idempotent requests */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway with error %ui",
                          s->goaway_error);

            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent unexpected push promise frame");

        s->connection_error = NGX_HTTP_PROXY_V2_PROTOCOL_ERROR;

        return NGX_ERROR;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_PING_FRAME) {
        if (ngx_http_proxy_v2_session_process_ping(s) != NGX_OK) {
            return NGX_ERROR;
        }

        goto output;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME
        && s->frame_parse.stream_id == 0)
    {
        if (ngx_http_proxy_v2_session_process_window_update(s) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ctx->in) {
            c = s->connection;

            if (!c->write->posted) {
                ngx_post_event(c->write, &ngx_posted_events);
            }
        }

        return NGX_OK;
    }

    if (s->frame_parse.type == NGX_HTTP_V2_SETTINGS_FRAME) {
        if (ngx_http_proxy_v2_session_process_settings(s, &window_update)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ctx->send_window > 0
            && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                               - ctx->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with too large initial window size");
            return NGX_ERROR;
        }

        ctx->send_window += window_update;

        goto output;
    }

    return NGX_DECLINED;

output:

    if (s->output_pos == s->output_last) {
        return NGX_OK;
    }

    c = s->connection;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!c->write->posted) {
        ngx_post_event(c->write, &ngx_posted_events);
    }

    return NGX_AGAIN;
}


static ssize_t
ngx_http_proxy_v2_stream_send(ngx_connection_t *sc, u_char *buf, size_t size)
{
    ssize_t                       n;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;

    r = sc->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    c = ctx->session->connection;

    c->data = r;

    n = c->send(c, buf, size);

    if (n == NGX_ERROR) {
        sc->write->error = 1;
        return NGX_ERROR;
    }

    sc->write->ready = c->write->ready;
    sc->buffered = c->buffered;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        sc->write->error = 1;
        return NGX_ERROR;
    }

    if (n > 0) {
        sc->sent += n;
    }

    return n;
}


static ngx_chain_t *
ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *sc, ngx_chain_t *in,
    off_t limit)
{
    off_t                          sent;
    ngx_chain_t                   *cl;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;

    r = sc->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    c = ctx->session->connection;

    c->data = r;
    sent = c->sent;

    cl = c->send_chain(c, in, limit);

    sc->sent += c->sent - sent;

    if (cl == NGX_CHAIN_ERROR) {
        sc->write->error = 1;
        sc->error = 1;
        return NGX_CHAIN_ERROR;
    }

    sc->write->ready = c->write->ready;
    sc->buffered = c->buffered;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        sc->write->error = 1;
        sc->error = 1;
        return NGX_CHAIN_ERROR;
    }

    return cl;
}


static ngx_int_t
ngx_http_proxy_v2_session_read_frame(ngx_http_proxy_v2_session_t *s)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b, header;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = s->connection;
    b = s->input;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool,
                                NGX_HTTP_PROXY_V2_FRAME_BUFFER_SIZE);
        if (b == NULL) {
            return NGX_ERROR;
        }

        s->input = b;
    }

    for ( ;; ) {

        if (!s->frame_header
            && b->last - b->start == NGX_HTTP_V2_FRAME_HEADER_SIZE)
        {
            ngx_memcpy(&header, b, sizeof(ngx_buf_t));
            header.pos = header.start;

            rc = ngx_http_proxy_v2_frame_parse(&s->frame_parse, &header);

            if (rc == NGX_ERROR) {
                s->frame_parse.state = 0;
                s->frame_size = NGX_HTTP_V2_FRAME_HEADER_SIZE;
                s->frame_ready = 1;
                s->frame_error = 1;
                b->pos = b->start;
                return NGX_OK;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            s->frame_size = NGX_HTTP_V2_FRAME_HEADER_SIZE
                            + s->frame_parse.length;
            s->frame_header = 1;

            if ((size_t) (b->last - b->start) == s->frame_size) {
                s->frame_ready = 1;
                b->pos = b->start;
                return NGX_OK;
            }
        }

        size = (s->frame_header ? s->frame_size
                                : NGX_HTTP_V2_FRAME_HEADER_SIZE)
               - (b->last - b->start);

        n = c->recv(c, b->last, size);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        if (n == NGX_ERROR || n == 0) {
            return NGX_ERROR;
        }

        b->last += n;

        if (s->frame_header
            && (size_t) (b->last - b->start) == s->frame_size)
        {
            s->frame_ready = 1;
            b->pos = b->start;
            return NGX_OK;
        }
    }
}


static void
ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev)
{
    ngx_connection_t             *c, *sc;
    ngx_int_t                      rc;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *s;

    c = rev->data;
    r = c->data;

    if (r == NULL) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return;
    }

    s = ctx->session;

    if (s == NULL || s->request != r || ctx->stream_connection == NULL) {
        return;
    }

    sc = ctx->stream_connection;

    if (rev->timedout) {
        sc->read->timedout = 1;
        sc->read->handler(sc->read);
        return;
    }

    for ( ;; ) {
        rc = ngx_http_proxy_v2_session_read_frame(s);

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_ERROR) {
            sc->read->error = 1;
            sc->read->ready = 1;
            sc->read->handler(sc->read);
            return;
        }

        rc = ngx_http_proxy_v2_session_process_connection_frame(s);

        if (rc == NGX_ERROR) {
            sc->read->error = 1;
            sc->read->ready = 1;
            sc->read->handler(sc->read);
            return;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        if (rc == NGX_OK) {
            continue;
        }

        break;
    }

    sc->read->ready = 1;
    sc->read->eof = 0;
    sc->read->error = 0;
    sc->read->timedout = 0;

    if (rev->timer_set && !rev->timedout) {
        ngx_del_timer(rev);
        ngx_add_timer(sc->read, r->upstream->conf->read_timeout);
    }

    sc->read->handler(sc->read);
}


static void
ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev)
{
    ngx_connection_t             *c, *sc;
    ngx_int_t                      rc;
    ngx_http_request_t           *r;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *s;

    c = wev->data;
    r = c->data;

    if (r == NULL) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return;
    }

    s = ctx->session;

    if (s == NULL || s->request != r || ctx->stream_connection == NULL) {
        return;
    }

    sc = ctx->stream_connection;
    u = r->upstream;

    sc->write->ready = wev->ready;
    sc->write->error = wev->error;
    sc->write->timedout = wev->timedout;

    if (s->output_pos != s->output_last) {

        if (u->writer.out) {
            sc->write->handler(sc->write);

            if (c->write->ready && !c->write->posted) {
                ngx_post_event(c->write, &ngx_posted_events);
            }

            return;
        }

        if (wev->timedout) {
            sc->write->handler(sc->write);
            return;
        }

        rc = ngx_http_proxy_v2_session_send(s);

        if (rc == NGX_ERROR) {
            sc->write->error = 1;
            sc->write->handler(sc->write);
            return;
        }

        if (rc == NGX_AGAIN) {
            if (!wev->timer_set) {
                ngx_add_timer(wev, u->conf->send_timeout);
                s->output_blocked = 1;
            }

            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                sc->write->error = 1;
                sc->write->handler(sc->write);
            }

            return;
        }

        if (s->output_blocked) {
            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            s->output_blocked = 0;
        }

        if (c->read->ready && !c->read->posted) {
            ngx_post_event(c->read, &ngx_posted_events);
        }
    }

    if (wev->timer_set && !wev->timedout) {
        ngx_del_timer(wev);
        ngx_add_timer(sc->write, r->upstream->conf->send_timeout);
    }

    sc->write->handler(sc->write);
}


static void
ngx_http_proxy_v2_detach_request(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_connection_t            *c, *sc;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_v2_session_t *s;

    s = ctx->session;

    if (s == NULL) {
        return;
    }

    u = r->upstream;
    c = s->connection;
    sc = ctx->stream_connection;

    if (sc) {
        if (sc->read->timer_set) {
            ngx_del_timer(sc->read);
        }

        if (sc->write->timer_set) {
            ngx_del_timer(sc->write);
        }

        if (sc->read->posted) {
            ngx_delete_posted_event(sc->read);
        }

        if (sc->write->posted) {
            ngx_delete_posted_event(sc->write);
        }

        if (u && u->peer.connection == sc) {
            u->peer.connection = c;
        }

        if (u && u->writer.connection == sc) {
            u->writer.connection = c;
        }

        ctx->stream_connection = NULL;
    }

    if (c && s->input && s->input->pos < s->input->last) {
        c->read->error = 1;
    }

    ngx_http_proxy_v2_session_detach(s, r);
}


static void
ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_event_free_peer_pt       free_peer;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_ctx_t     *ctx;

    r = pc->connection->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    free_peer = ctx->original_free_peer;

    ngx_http_proxy_v2_detach_request(r, ctx);
    ctx->session = NULL;

    ctx->original_free_peer = NULL;
    pc->free = free_peer;

    free_peer(pc, data, state);
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
    ngx_http_proxy_v2_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize proxy http2 request");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx) {
        ngx_http_proxy_v2_detach_request(r, ctx);
    }

    return;
}
