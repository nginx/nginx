
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>


typedef struct {
    ngx_http_proxy_ctx_t          ctx;
    ngx_http_v3_parse_headers_t   parse_headers;
    ngx_http_v3_parse_data_t      parse_data;
    off_t                         body_received;
    ngx_uint_t                    pseudo_done; /* unsigned  pseudo_done:1; */
} ngx_http_v3_proxy_ctx_t;


static ngx_int_t ngx_http_v3_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_create_stream(ngx_http_request_t *r);
static void ngx_http_v3_proxy_quic_handler(ngx_connection_t *c);
static ngx_int_t ngx_http_v3_proxy_handle_quic_connection(ngx_connection_t *c);
static ngx_int_t ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_body_output_filter(void *data,
     ngx_chain_t *in);
static ngx_int_t ngx_http_v3_proxy_process_response(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_process_header(void *data,
    ngx_str_t *name, ngx_str_t *value, ngx_uint_t index, ngx_uint_t dynamic);
static ngx_int_t ngx_http_v3_proxy_process_insert_count(void *data,
    ngx_uint_t *insert_count);
static ngx_int_t ngx_http_v3_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_v3_proxy_body_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_v3_proxy_non_buffered_body_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_v3_proxy_process_trailer(ngx_http_request_t *r,
    ngx_buf_t *buf);
static void ngx_http_v3_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);


ngx_module_t  ngx_http_v3_proxy_module;


static ngx_http_module_t  ngx_http_v3_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_v3_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_v3_proxy_module_ctx,         /* module context */
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


ngx_int_t
ngx_http_v3_proxy_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_upstream_t          *u;
    ngx_http_v3_proxy_ctx_t      *ctx;
    ngx_http_proxy_loc_conf_t    *plcf;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_main_conf_t   *pmcf;
#endif
    ngx_http_v3_parse_headers_t  *st;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    if (!plcf->ssl) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                      "unsupported \"http\" scheme");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_v3_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    st = &ctx->parse_headers;
    st->max_literal = plcf->upstream.buffer_size;
    st->process_insert_count = ngx_http_v3_proxy_process_insert_count;
    st->process_header = ngx_http_v3_proxy_process_header;
    st->data = r;

    ngx_http_set_ctx(r, ctx, ngx_http_v3_proxy_module);

    ngx_http_set_ctx(r, &ctx->ctx, ngx_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
        ctx->ctx.vars = plcf->vars;
        u->schema = plcf->vars.schema;
        u->ssl = 1;

    } else {
        if (ngx_http_proxy_eval(r, &ctx->ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!u->ssl) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "unsupported \"http\" scheme");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_str_set(&u->ssl_alpn_protocol, NGX_HTTP_V3_ALPN_PROTO);

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_v3_proxy_create_request;
    u->create_stream = ngx_http_v3_proxy_create_stream;
    u->reinit_request = ngx_http_v3_proxy_reinit_request;
    u->process_header = ngx_http_v3_proxy_process_response;
    u->abort_request = ngx_http_v3_proxy_abort_request;
    u->finalize_request = ngx_http_v3_proxy_finalize_request;
    r->state = 0;

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

    u->pipe->input_filter = ngx_http_v3_proxy_body_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_v3_proxy_input_filter_init;
    u->input_filter = ngx_http_v3_proxy_non_buffered_body_filter;
    u->input_filter_ctx = r;

    u->accel = 1;
    u->quic = 1;
    u->peer.type = SOCK_DGRAM;

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
ngx_http_v3_proxy_create_request(ngx_http_request_t *r)
{
    u_char                       *p, *key, *val;
    size_t                        len, uri_len, loc_len, header_len, body_len,
                                  key_len, val_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method, *host;
    ngx_uint_t                    i, unparsed_uri, internal_chunked;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_v3_proxy_ctx_t      *ctx;
    ngx_http_script_code_pt       code;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_script_engine_t      e, le;
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

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    len = ngx_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    /* :method header */

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->ctx.head = 1;

        len += ngx_http_v3_encode_field_ri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_METHOD_HEAD);

    } else if (method.len == sizeof("GET") - 1
               && ngx_strncasecmp(method.data, (u_char *) "GET", 3) == 0)
    {
        len += ngx_http_v3_encode_field_ri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_METHOD_GET);

    } else if (method.len == sizeof("POST") - 1
               && ngx_strncasecmp(method.data, (u_char *) "POST", 4) == 0)
    {
        len += ngx_http_v3_encode_field_ri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_METHOD_POST);

    } else if (method.len == sizeof("PUT") - 1
               && ngx_strncasecmp(method.data, (u_char *) "PUT", 3) == 0)
    {
        len += ngx_http_v3_encode_field_ri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_METHOD_PUT);

    } else {
        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_METHOD_GET,
                                           NULL, method.len);
    }

    /* :scheme header */

    len += ngx_http_v3_encode_field_ri(NULL, 0,
                                       NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    /* :path header */

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;
    internal_chunked = 0;

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

    len += ngx_http_v3_encode_field_lri(NULL, 0, NGX_HTTP_V3_HEADER_PATH_ROOT,
                                        NULL, uri_len);

    /* :authority header */

    host = &ctx->ctx.vars.host_header;

    if (!plcf->host_set) {
        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_AUTHORITY,
                                            NULL, host->len);
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

        len += ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA);
        len += ngx_http_v3_encode_varlen_int(NULL, body_len);

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->ctx.internal_body_length = -1;
        internal_chunked = 1;

    } else {
        ctx->ctx.internal_body_length = r->headers_in.content_length_n;

        len += ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA);
        len += ngx_http_v3_encode_varlen_int(NULL,
                                                ctx->ctx.internal_body_length);
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

        len += ngx_http_v3_encode_field_l(NULL, NULL, key_len, NULL, val_len)
               * 2;
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

            len += ngx_http_v3_encode_field_l(NULL, NULL, header[i].key.len,
                                              NULL, header[i].value.len);
        }
    }

    header_len = len;

    len += ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
          + ngx_http_v3_encode_varlen_int(NULL, header_len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    b->last += ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
               + ngx_http_v3_encode_varlen_int(NULL, header_len);

    p = b->last;

    b->last = (u_char *) ngx_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_HEAD);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: HEAD\"");

    } else if (method.len == sizeof("GET") - 1
               && ngx_strncasecmp(method.data, (u_char *) "GET", 3) == 0)
    {
        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_GET);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: GET\"");

    } else if (method.len == sizeof("POST") - 1
               && ngx_strncasecmp(method.data, (u_char *) "POST", 4) == 0)
    {
        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_POST);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: POST\"");

    } else if (method.len == sizeof("PUT") - 1
               && ngx_strncasecmp(method.data, (u_char *) "PUT", 3) == 0)
    {
        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_PUT);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: PUT\"");

    } else {
        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_GET,
                                                method.data, method.len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: %V\"", &method);
    }

    b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                              NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: \":scheme: https\"");

    b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_PATH_ROOT,
                                                NULL, uri_len);
    u->uri.data = b->last;

    if (plcf->proxy_lengths && ctx->ctx.vars.uri.len) {
        b->last = ngx_copy(b->last, ctx->ctx.vars.uri.data,
                           ctx->ctx.vars.uri.len);

    } else if (unparsed_uri) {
        b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = ngx_copy(b->last, ctx->ctx.vars.uri.data,
                               ctx->ctx.vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = ngx_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: \":path: %V\"", &u->uri);

    if (!plcf->host_set) {
        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_AUTHORITY,
                                                host->data, host->len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":authority: %V\"", host);
    }

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

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

        e.pos += ngx_http_v3_encode_field_l(NULL, NULL, key_len, NULL, val_len);
        key = e.pos;

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        val = e.pos;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last, key, key_len,
                                                        val, val_len);
        e.pos = b->last;
    }

    b->last = e.pos;


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

            b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                    header[i].key.data, header[i].key.len,
                                    header[i].value.data, header[i].value.len);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http3 proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    len = b->last - p;
    b->pos += (ngx_http_v3_encode_varlen_int(NULL, header_len)
               - ngx_http_v3_encode_varlen_int(NULL, len));
    p = (u_char *) ngx_http_v3_encode_varlen_int(b->pos,
                                                 NGX_HTTP_V3_FRAME_HEADERS);
    (void) ngx_http_v3_encode_varlen_int(p, len);

    if (plcf->body_values) {
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, body_len);

        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 proxy header:%N\"%*xs\"",
                   (size_t) (b->last - b->pos), b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        if (internal_chunked) {
            u->output.output_filter = ngx_http_v3_proxy_body_output_filter;
            u->output.filter_ctx = r;

        } else {
            b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                NGX_HTTP_V3_FRAME_DATA);
            b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                ctx->ctx.internal_body_length);
        }

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        body_len = 0;

        while (body) {
            body_len += ngx_buf_size(body->buf);
            body = body->next;
        }

        body = u->request_bufs;
        u->request_bufs = cl;

        len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
              + ngx_http_v3_encode_varlen_int(NULL, body_len);

        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                   NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, body_len);

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;

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

    } else {
        u->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_create_stream(ngx_http_request_t *r)
{
    ngx_log_t              *log;
    ngx_connection_t       *c, *sc;
    ngx_http_upstream_t    *u;
    ngx_http_v3_session_t  *h3c;

    u = r->upstream;
    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 proxy create stream");

    c->ssl->handler = ngx_http_v3_proxy_quic_handler;

    if (ngx_http_v3_init_session(c) != NGX_OK) {
        return NGX_ERROR;
    }

    h3c = ngx_http_v3_get_session(c);
    h3c->max_literal = u->conf->buffer_size;

    /*
     * h3c->max_table_capacity = 0;
     * h3c->max_blocked_streams = 0;
     */

    if (ngx_http_v3_send_settings(c) != NGX_OK) {
        return NGX_ERROR;
    }

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NGX_ERROR;
    }

    /* XXX */
    *log = r->connection->listening->log;
    log->connection = c->number;

    /* XXX do not create log here */
    sc = ngx_quic_open_stream(c, 1);
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->log = c->log;
    sc->pool->log = sc->log;
    sc->read->log = sc->log;
    sc->write->log = sc->log;

    /* QUIC connection may outlive client connection */

    c->log = log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    sc->data = r;

    sc->requests++;
    c->requests++;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u->peer.connection = sc;
    u->writer.connection = sc;

    if (ngx_http_v3_proxy_handle_quic_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_v3_proxy_quic_handler(ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 proxy handler");

    if (c->close) {
        ngx_http_v3_close_connection(c);
        return;
    }

    if (ngx_http_v3_proxy_handle_quic_connection(c) != NGX_OK) {
        ngx_http_v3_close_connection(c);
    }
}


static ngx_int_t
ngx_http_v3_proxy_handle_quic_connection(ngx_connection_t *c)
{
    ngx_connection_t  *sc;

    if (c->read->timedout) {
        ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_NO_ERROR,
                               "keepalive shutdown");
        return NGX_DONE;
    }

    while (!ngx_quic_get_error(c)) {

        sc = ngx_quic_accept_stream(c);
        if (sc == NULL) {
            break;
        }

        if (!(sc->quic->stream->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "upstream opened a quic bidi stream");
            return NGX_ERROR;
        }

        ngx_http_v3_init_uni_stream(sc);
    }

    if (ngx_quic_has_streams(c, 1, 1) == NGX_DECLINED) {
        ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_NO_ERROR, "shutdown");
        return NGX_DONE;
    }

    if (ngx_quic_get_error(c)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_v3_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->pseudo_done = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                  size;
    size_t                 len;
    u_char                *chunk;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_chain_t           *out, *cl, *tl, **ll, **fl;
    ngx_http_proxy_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 proxy output header");

        ctx->header_sent = 1;

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    size = 0;
    cl = in;
    fl = ll;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 proxy output chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
                  + ngx_http_v3_encode_varlen_int(NULL, 0xffffffffffffffffull);

            chunk = ngx_palloc(r->pool, len);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + len;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last_buf = cl->buf->last_buf;

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

        cl->buf->last_buf = 0;

        tl->next = *fl;
        *fl = tl;

    } else if (cl->buf->last_buf) {

        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 0;
        b->last_buf = 1;
        b->pos = b->last;

        cl->buf->last_buf = 0;

        *ll = tl;
    }

    *ll = NULL;

out:

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                        (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter);

    return rc;
}


static ngx_int_t
ngx_http_v3_proxy_process_response(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_table_elt_t          *h;
    ngx_connection_t         *c;
    ngx_http_upstream_t      *u;
    ngx_http_v3_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    c = r->connection;
    u = r->upstream;

    rc = ngx_http_v3_parse_headers(c, &ctx->parse_headers, &u->buffer);

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (rc > 0) {
        if (u->peer.connection) {
            ngx_quic_reset_stream(u->peer.connection, rc);
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "upstream sent invalid header");
        }

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* XXX flood check */

    if (rc != NGX_DONE) {
        return rc;
    }

    /* a whole header has been parsed successfully */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 proxy header done");

    if (u->headers_in.status_n == 0) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
        ctx->pseudo_done = 0;
        return NGX_HTTP_UPSTREAM_EARLY_HINTS;
    }

    /*
     * if no "Server" and "Date" in header line,
     * then add the special empty headers
     */

    if (r->upstream->headers_in.server == NULL) {
        h = ngx_list_push(&r->upstream->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                            ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

        ngx_str_set(&h->key, "Server");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "server";
        h->next = NULL;
    }

    if (r->upstream->headers_in.date == NULL) {
        h = ngx_list_push(&r->upstream->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

        ngx_str_set(&h->key, "Date");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "date";
        h->next = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_header(void *data, ngx_str_t *name, ngx_str_t *value,
    ngx_uint_t index, ngx_uint_t dynamic)
{
    ngx_http_request_t  *r = data;

    ngx_int_t                       rc;
    ngx_str_t                       namet, valuet;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_v3_proxy_ctx_t        *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    if (name == NULL) {

        if (dynamic) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream is using dynamic table");
            return NGX_ERROR;
        }

        if (ngx_http_v3_lookup_static(r->connection, index, &namet, &valuet)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        name = &namet;

        if (value == NULL) {
            value = &valuet;
        }
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (name->len && name->data[0] == ':') {

        if (ctx->pseudo_done) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (name->len == 7 && ngx_strncmp(name->data, ":status", 7)
            == 0)
        {
            rc = ngx_atoi(value->data, value->len);

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            u->headers_in.status_n = rc;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http3 proxy status %ui",
                           u->headers_in.status_n);

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http3 proxy pseudo header: \"%V: %V\"",
                           name, value);
        }

        return NGX_OK;
    }

    ctx->pseudo_done = 1;

    h = ngx_list_push(ctx->ctx.trailers ? &r->upstream->headers_in.trailers
                                       : &r->upstream->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = r->header_hash;

    h->key.len = name->len;
    h->value.len = value->len;

    h->key.data = ngx_pnalloc(r->pool,
                              h->key.len + 1 + h->value.len + 1 + h->key.len);
    if (h->key.data == NULL) {
        h->hash = 0;
        return NGX_ERROR;
    }

    h->value.data = h->key.data + h->key.len + 1;
    h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

    ngx_memcpy(h->key.data, name->data, h->key.len);
    h->key.data[h->key.len] = '\0';
    ngx_memcpy(h->value.data, value->data, h->value.len);
    h->value.data[h->value.len] = '\0';

    if (h->key.len == r->lowcase_index) {
        ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

    } else {
        ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 proxy header: \"%V: %V\"",
                   name, value);

    if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS || ctx->ctx.trailers) {
        return NGX_OK;
    }

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
ngx_http_v3_proxy_process_insert_count(void *data, ngx_uint_t *insert_count)
{
    ngx_http_request_t  *r = data;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "upstream is using dynamic table");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_proxy_input_filter_init(void *data)
{
    ngx_http_request_t    *r = data;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 proxy filter init s:%ui h:%d l:%O",
                   u->headers_in.status_n, ctx->head,
                   u->headers_in.content_length_n);

    /* as per RFC9110, 6.4.1. Content Semantics */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;

    } else {
        u->pipe->length = 1;
        u->length = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_body_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    off_t                       n;
    ngx_int_t                   rc;
    ngx_buf_t                  *b, **prev;
    ngx_chain_t                *cl;
    ngx_http_request_t         *r;
    ngx_http_upstream_t        *u;
    ngx_http_v3_proxy_ctx_t    *ctx;
    ngx_http_v3_parse_data_t   *st;
    ngx_http_proxy_loc_conf_t  *plcf;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    st = &ctx->parse_data;

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http3 proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent data after trailers");

        p->upstream_done = 1;

        return NGX_OK;
    }

    b = NULL;

    if (ctx->ctx.trailers) {
        rc = ngx_http_v3_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            p->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent data after trailers");
            }
        }

        goto free_buf;
    }

    n = r->headers_in.content_length_n;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    prev = &buf->shadow;

    while (buf->pos < buf->last) {

        if (st->length == 0) {
            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            /* XXX check flood */

            if (rc == NGX_AGAIN) {
                continue;
            }

            if (rc == NGX_DONE) {

                if (plcf->upstream.pass_trailers) {
                    rc = ngx_http_v3_proxy_process_trailer(r, buf);

                    if (rc == NGX_ERROR) {
                        return NGX_ERROR;
                    }

                    if (rc == NGX_AGAIN) {
                        p->length = 1;
                        goto free_buf;
                    }
                }

                p->length = 0;
                goto free_buf;
            }

            if (rc > 0) {

                if (u->peer.connection) {
                    ngx_quic_reset_stream(u->peer.connection, rc);
                }

                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "upstream sent invalid body");
                return NGX_ERROR;
            }

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "upstream sent invalid body");
                return NGX_ERROR;
            }

            /* rc == NGX_OK */
        }

        if (n != -1 && n - ctx->body_received < (off_t) st->length) {
            ngx_log_error(NGX_LOG_WARN, p->log, 0,
                          "upstream sent more data than specified in "
                          "\"Content-Length\" header");
            return NGX_ERROR;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->pos = buf->pos;
        b->start = buf->start;
        b->end = buf->end;
        b->tag = p->tag;
        b->temporary = 1;
        b->recycled = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;
        } else {
            p->in = cl;
        }
        p->last_in = &cl->next;

        if (buf->last - buf->pos > (ssize_t) st->length) {
            ctx->body_received += st->length;
            buf->pos += st->length;
            st->length = 0;

        } else {
            ctx->body_received += (buf->last - buf->pos);
            st->length -= buf->last - buf->pos;
            buf->pos = buf->last;
        }

        b->last = buf->pos;
    }

    if (st->length == 0) {

        if (n != -1 && ctx->body_received < n) {
            p->length = 1;

        } else {
            /* possible trailers */
            p->length = -1;
        }

    } else {
        p->length = st->length;
    }

free_buf:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http3 proxy body wait length %O", p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_non_buffered_body_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    off_t                       n;
    ngx_int_t                   rc;
    ngx_buf_t                  *b, *buf;
    ngx_chain_t                *cl, **ll;
    ngx_http_upstream_t        *u;
    ngx_http_v3_proxy_ctx_t    *ctx;
    ngx_http_v3_parse_data_t   *st;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    st = &ctx->parse_data;

    n = r->headers_in.content_length_n;

    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    if (ctx->ctx.trailers) {
        rc = ngx_http_v3_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            r->upstream->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after trailers");
                u->keepalive = 0;
            }
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (buf->pos < buf->last) {

        if (st->length == 0) {
            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            /* XXX check flood */

            if (rc == NGX_AGAIN) {
                continue;
            }

            if (rc == NGX_DONE) {

                if (plcf->upstream.pass_trailers) {
                    rc = ngx_http_v3_proxy_process_trailer(r, buf);

                    if (rc == NGX_ERROR) {
                        return NGX_ERROR;
                    }

                    if (rc == NGX_AGAIN) {
                        u->length = 1;
                        return NGX_OK;
                    }
                }

                u->length = 0;
                return NGX_OK;
            }

            if (rc > 0) {

                if (u->peer.connection) {
                    ngx_quic_reset_stream(u->peer.connection, rc);
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid body");
                return NGX_ERROR;
            }

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid body");
                return NGX_ERROR;
            }

            /* rc == NGX_OK */
        }

        if (n != -1 && n - ctx->body_received < (off_t) st->length) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "upstream sent more data than specified in "
                          "\"Content-Length\" header");
            return NGX_ERROR;
        }

        cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->flush = 1;
        b->memory = 1;

        b->pos = buf->pos;
        b->tag = u->output.tag;

        if (buf->last - buf->pos > (ssize_t) st->length) {
            ctx->body_received += st->length;
            buf->pos += st->length;
            st->length = 0;

        } else {
            ctx->body_received += (buf->last - buf->pos);
            st->length -= buf->last - buf->pos;
            buf->pos = buf->last;
        }

        b->last = buf->pos;
    }

    if (st->length == 0) {

        if (n != -1 && ctx->body_received < n) {
            u->length = 1;

        } else {
            /* possible trailers */
            u->length = -1;
        }

    } else {
        u->length = st->length;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_trailer(ngx_http_request_t *r, ngx_buf_t *buf)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_http_upstream_t        *u;
    ngx_http_v3_proxy_ctx_t    *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_proxy_module);

    if (ctx->ctx.trailers == NULL) {
        ctx->ctx.trailers = ngx_create_temp_buf(r->pool,
                                                plcf->upstream.buffer_size);
        if (ctx->ctx.trailers == NULL) {
            return NGX_ERROR;
        }
    }

    u = r->upstream;

    b = ctx->ctx.trailers;
    len = ngx_min(buf->last - buf->pos, b->end - b->last);

    b->last = ngx_cpymem(b->last, buf->pos, len);
    buf->pos += len;

    rc = ngx_http_v3_parse_headers(r->connection, &ctx->parse_headers, b);

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (rc > 0) {
        if (u->peer.connection) {
            ngx_quic_reset_stream(u->peer.connection, rc);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");
        }

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* XXX flood check */

    if (rc != NGX_DONE) {
        return rc;
    }

    /* a whole trailer has been parsed successfully */

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 proxy trailer done");

    return NGX_OK;
}


static void
ngx_http_v3_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http3 proxy request");

    return;
}


static void
ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http3 proxy request");

    return;
}
