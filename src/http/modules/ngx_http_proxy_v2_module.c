
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_module.h>


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
static ngx_int_t ngx_http_proxy_v2_process_control_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_header_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_trailer(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_settings(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_setting(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_process_ping(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);

static ngx_int_t ngx_http_proxy_v2_send_settings_ack(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_v2_send_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);

static ngx_chain_t *ngx_http_proxy_v2_get_buf(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static ngx_http_proxy_v2_ctx_t *
    ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r);

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

    if (ngx_http_proxy_v2_upstream_create(r) != NGX_OK) {
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

    rc = ngx_http_read_client_request_body(r, ngx_http_proxy_v2_upstream_init);

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
    ngx_str_t                     method, *host;
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

    host = &ctx->ctx.vars.host_header;

    if (!plcf->host_set) {
        if (host->len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 host: \"%V\"", host);
            return NGX_ERROR;
        }

        len += 1 + NGX_HTTP_V2_INT_OCTETS + host->len;

        if (tmp_len < host->len) {
            tmp_len = host->len;
        }
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

    if (!plcf->host_set) {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX);
        b->last = ngx_http_v2_write_value(b->last, host->data, host->len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":authority: %V\"", host);
    }

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

    ctx->state = 0;
    ctx->header_sent = 0;
    ctx->output_closed = 0;
    ctx->output_blocked = 0;
    ctx->parsing_headers = 0;
    ctx->header_initialized = 0;
    ctx->end_stream = 0;
    ctx->done = 0;
    ctx->status = 0;
    ctx->rst = 0;
    ctx->goaway = 0;
    ctx->connection = NULL;
    ctx->in = NULL;
    ctx->out = NULL;
    ctx->pending = NULL;

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

    if (limit > ctx->connection->send_window) {
        limit = ctx->connection->send_window;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

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

            b->tag = ngx_http_proxy_v2_frame_tag;
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
            ctx->connection->send_window -= len;

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
                   limit, ctx->send_window, ctx->connection->send_window);

#endif

    rc = ngx_http_proxy_v2_append_chain(r, ctx, out);

    if (ctx->done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;

        if (u->pipe) {
            u->pipe->length = 0;
        }

        if (ctx->in == NULL
            && ctx->out == NULL
            && ctx->pending == NULL
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
    ngx_buf_t                      *b;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_v2_ctx_t        *ctx;

    u = r->upstream;
    ctx = ngx_http_proxy_v2_get_ctx(r);

    b = &ctx->connection->buffer;

    if (ctx->state != ngx_http_proxy_v2_st_start) {
        return ngx_http_proxy_v2_process_header_field(r, ctx);
    }

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
        && ctx->pending == NULL
        && ctx->output_closed
        && !ctx->output_blocked
        && !ctx->goaway
        && b->last == b->pos)
    {
        u->keepalive = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_header_field(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_str_t                      *status_line;
    ngx_int_t                       rc, status;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    u = r->upstream;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: \"%V: %V\"",
                   &ctx->name, &ctx->value);

    if (ctx->name.len && ctx->name.data[0] == ':') {

        if (ctx->name.len != sizeof(":status") - 1
            || ngx_strncmp(ctx->name.data, ":status", sizeof(":status") - 1)
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

        if (status < NGX_HTTP_OK && status != NGX_HTTP_EARLY_HINTS) {
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

        return NGX_OK;
    }

    if (!ctx->status) {
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
        return NGX_OK;
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh) {
        rc = hh->handler(r, h, hh->offset);

        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
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

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    buf = cl->buf;

    buf->flush = 1;
    buf->memory = 1;

    buf->pos = b->pos;
    buf->last = b->last;
    buf->tag = u->output.tag;

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

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p, ngx_buf_t *b)
{
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

    /* copy data frame payload for buffering */

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

    *prev = buf;

    if (p->in) {
        *p->last_in = cl;

    } else {
        p->in = cl;
    }

    p->last_in = &cl->next;

    /* STUB */ buf->num = b->num;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy copy buf %p", buf->pos);

    if (ctx->length != -1) {

        if (buf->last - buf->pos > ctx->length) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent response body larger "
                          "than indicated content length");
            return NGX_ERROR;
        }

        ctx->length -= buf->last - buf->pos;
    }

    b->pos = b->last;
    buf->shadow = b;
    buf->last_shadow = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "input buf %p %z", buf->pos, buf->last - buf->pos);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_process_frame_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_uint_t body)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    /*
     * RFC 7540 says that implementations MUST discard frames
     * that have unknown or unsupported types.  However, extension
     * frames that appear in the middle of a header block are
     * not permitted.  Also, for obvious reasons CONTINUATION frames
     * cannot appear before headers.
     */

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

    if (!body) {

        /*
         * DATA frames are not expected to appear before all headers
         * are parsed.
         */

        if (ctx->type == NGX_HTTP_V2_DATA_FRAME) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected http2 frame: %d",
                          ctx->type);
            return NGX_ERROR;
        }

        if (ctx->id && ctx->stream_id && ctx->stream_id != ctx->id) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent frame for unknown stream %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ctx->type == NGX_HTTP_V2_DATA_FRAME) {

        if (ctx->stream_id != ctx->id) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent data frame for unknown stream %ui",
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

        if (ctx->rest > ctx->connection->recv_window) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream violated connection flow control, "
                          "received %uz data frame with window %uz",
                          ctx->rest, ctx->connection->recv_window);
            return NGX_ERROR;
        }

        ctx->recv_window -= ctx->rest;
        ctx->connection->recv_window -= ctx->rest;

        if (ctx->connection->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
            || ctx->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
        {
            if (ngx_http_proxy_v2_send_window_update(r, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
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

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_control_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (ctx->type == NGX_HTTP_V2_GOAWAY_FRAME) {

        /*
         * If stream_id is lower than one we use, our
         * request won't be processed and needs to be retried.
         * If stream_id is greater or equal to the one we use,
         * we can continue normally (except we can't use this
         * connection for additional requests).  If there is
         * a real error, the connection will be closed.
         */

        if (ctx->stream_id < ctx->id) {

            /* TODO: we can retry non-idempotent requests */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway with error %ui",
                          ctx->error);

            return NGX_ERROR;
        }

        ctx->goaway = 1;

        return NGX_OK;
    }

    if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {

        if (ngx_http_proxy_v2_process_window_update(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ctx->in || ctx->out || ctx->pending) {
            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (ctx->type == NGX_HTTP_V2_SETTINGS_FRAME) {
        return ngx_http_proxy_v2_process_settings(r, ctx);
    }

    if (ctx->type == NGX_HTTP_V2_PING_FRAME) {
        return ngx_http_proxy_v2_process_ping(r, ctx);
    }

    if (ctx->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent unexpected push promise frame");
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_proxy_v2_process_frame_payload(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_uint_t body)
{
    ngx_int_t  rc;

    switch (ctx->type) {

    case NGX_HTTP_V2_RST_STREAM_FRAME:

        if (!body) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);
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

        return NGX_DECLINED;

    case NGX_HTTP_V2_GOAWAY_FRAME:
    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
    case NGX_HTTP_V2_SETTINGS_FRAME:
    case NGX_HTTP_V2_PING_FRAME:
    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:

        rc = ngx_http_proxy_v2_process_control_frame(r, ctx);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        return rc == NGX_AGAIN ? NGX_AGAIN : NGX_DECLINED;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:

        if (body) {
            return ngx_http_proxy_v2_process_trailer(r, ctx);
        }

        return NGX_OK;

    case NGX_HTTP_V2_DATA_FRAME:
        return body ? NGX_OK : NGX_ERROR;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_http_proxy_v2_process_trailer(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_table_elt_t      *h;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (ctx->state != ngx_http_proxy_v2_st_start) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy trailer: \"%V: %V\"",
                       &ctx->name, &ctx->value);

        if (ctx->name.len && ctx->name.data[0] == ':') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid trailer \"%V: %V\"",
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

        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy trailer done");

    if (ctx->end_stream) {
        ctx->done = 1;
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "upstream sent trailer without end stream flag");
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_process_settings(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (ctx->state != ngx_http_proxy_v2_st_start) {
        if (ngx_http_proxy_v2_process_setting(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy settings ack");

        if (ctx->in || ctx->out || ctx->pending) {
            ngx_post_event(u->peer.connection->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (ngx_http_proxy_v2_send_settings_ack(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_post_event(u->peer.connection->write, &ngx_posted_events);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy window update: %ui",
                   ctx->window_update);

    if (ctx->stream_id) {

        if (ctx->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                 - ctx->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        ctx->send_window += ctx->window_update;

    } else {

        if (ctx->window_update > NGX_HTTP_V2_MAX_WINDOW
                                 - ctx->connection->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return NGX_ERROR;
        }

        ctx->connection->send_window += ctx->window_update;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_setting(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ssize_t  window_update;

    /*
     * The following settings are defined by the protocol:
     *
     * SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
     * SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
     * SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE
     *
     * Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed in
     * a simple client.
     */

    if (ctx->setting_id != 0x04) {
        return NGX_OK;
    }

    /* SETTINGS_INITIAL_WINDOW_SIZE */

    if (ctx->setting_value > NGX_HTTP_V2_MAX_WINDOW) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent settings frame "
                      "with too large initial window size: %ui",
                      ctx->setting_value);
        return NGX_ERROR;
    }

    window_update = ctx->setting_value - ctx->connection->init_window;
    ctx->connection->init_window = ctx->setting_value;

    if (ctx->send_window > 0
        && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
                           - ctx->send_window)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent settings frame "
                      "with too large initial window size: %ui",
                      ctx->setting_value);
        return NGX_ERROR;
    }

    ctx->send_window += window_update;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_ping(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (ngx_http_proxy_v2_send_ping_ack(r, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_post_event(u->peer.connection->write, &ngx_posted_events);

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_settings_ack(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy send settings ack");

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
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_SETTINGS_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    *ll = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_ping_ack(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy send ping ack");

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
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_PING_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = ngx_copy(cl->buf->last, ctx->ping_data, 8);

    *ll = cl;

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
                   ctx->connection->recv_window, ctx->recv_window);

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

    n = NGX_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
    ctx->connection->recv_window = NGX_HTTP_V2_MAX_WINDOW;

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

    b->tag = ngx_http_proxy_v2_frame_tag;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static ngx_http_proxy_v2_ctx_t *
ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx->connection == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no http2 connection for proxy request");
        return NULL;
    }

    return ctx;
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
