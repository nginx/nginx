
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* static table indices */
#define NGX_HTTP_V3_HEADER_AUTHORITY                 0
#define NGX_HTTP_V3_HEADER_PATH_ROOT                 1
#define NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO       4
#define NGX_HTTP_V3_HEADER_DATE                      6
#define NGX_HTTP_V3_HEADER_LAST_MODIFIED             10
#define NGX_HTTP_V3_HEADER_LOCATION                  12
#define NGX_HTTP_V3_HEADER_METHOD_GET                17
#define NGX_HTTP_V3_HEADER_SCHEME_HTTP               22
#define NGX_HTTP_V3_HEADER_SCHEME_HTTPS              23
#define NGX_HTTP_V3_HEADER_STATUS_200                25
#define NGX_HTTP_V3_HEADER_ACCEPT_ENCODING           31
#define NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN   53
#define NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING      59
#define NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE           72
#define NGX_HTTP_V3_HEADER_SERVER                    92
#define NGX_HTTP_V3_HEADER_USER_AGENT                95


typedef struct {
    ngx_chain_t         *free;
    ngx_chain_t         *busy;
} ngx_http_v3_filter_ctx_t;


static ngx_int_t ngx_http_v3_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_chain_t *ngx_http_v3_create_trailers(ngx_http_request_t *r,
    ngx_http_v3_filter_ctx_t *ctx);
static ngx_int_t ngx_http_v3_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_v3_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_v3_filter_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_v3_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_v3_filter_module_ctx,        /* module context */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_v3_header_filter(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len, n;
    ngx_buf_t                 *b;
    ngx_str_t                  host, location;
    ngx_uint_t                 i, port;
    ngx_chain_t               *out, *hl, *cl, **ll;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_filter_ctx_t  *ctx;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    if (r->http_version != NGX_HTTP_VERSION_30) {
        return ngx_http_next_header_filter(r);
    }

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NGX_OK;
    }

    h3c = ngx_http_v3_get_session(r->connection);

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    if (r->headers_out.status == NGX_HTTP_NO_CONTENT) {
        r->header_only = 1;
        ngx_str_null(&r->headers_out.content_type);
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;
    }

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        r->header_only = 1;
    }

    c = r->connection;

    out = NULL;
    ll = &out;

    len = ngx_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    if (r->headers_out.status == NGX_HTTP_OK) {
        len += ngx_http_v3_encode_field_ri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_STATUS_200);

    } else {
        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_STATUS_200,
                                            NULL, 3);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            n = sizeof(NGINX_VER) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            n = sizeof(NGINX_VER_BUILD) - 1;

        } else {
            n = sizeof("nginx") - 1;
        }

        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_SERVER,
                                            NULL, n);
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_v3_encode_field_lri(NULL, 0, NGX_HTTP_V3_HEADER_DATE,
                                            NULL, ngx_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                    NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    NULL, n);
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n > 0) {
            len += ngx_http_v3_encode_field_lri(NULL, 0,
                                        NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, NGX_OFF_T_LEN);

        } else if (r->headers_out.content_length_n == 0) {
            len += ngx_http_v3_encode_field_ri(NULL, 0,
                                       NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                  NGX_HTTP_V3_HEADER_LAST_MODIFIED, NULL,
                                  sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {

        if (r->headers_out.location->value.data[0] == '/'
            && clcf->absolute_redirect)
        {
            if (clcf->server_name_in_redirect) {
                cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
                host = cscf->server_name;

            } else if (r->headers_in.server.len) {
                host = r->headers_in.server;

            } else {
                host.len = NGX_SOCKADDR_STRLEN;
                host.data = addr;

                if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                    return NGX_ERROR;
                }
            }

            port = ngx_inet_get_port(c->local_sockaddr);

            location.len = sizeof("https://") - 1 + host.len
                           + r->headers_out.location->value.len;

            if (clcf->port_in_redirect) {
                port = (port == 443) ? 0 : port;

            } else {
                port = 0;
            }

            if (port) {
                location.len += sizeof(":65535") - 1;
            }

            location.data = ngx_pnalloc(r->pool, location.len);
            if (location.data == NULL) {
                return NGX_ERROR;
            }

            p = ngx_cpymem(location.data, "https://", sizeof("https://") - 1);
            p = ngx_cpymem(p, host.data, host.len);

            if (port) {
                p = ngx_sprintf(p, ":%ui", port);
            }

            p = ngx_cpymem(p, r->headers_out.location->value.data,
                              r->headers_out.location->value.len);

            /* update r->headers_out.location->value for possible logging */

            r->headers_out.location->value.len = p - location.data;
            r->headers_out.location->value.data = location.data;
            ngx_str_set(&r->headers_out.location->key, "Location");
        }

        r->headers_out.location->hash = 0;

        len += ngx_http_v3_encode_field_lri(NULL, 0,
                                           NGX_HTTP_V3_HEADER_LOCATION, NULL,
                                           r->headers_out.location->value.len);
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += ngx_http_v3_encode_field_ri(NULL, 0,
                                      NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    part = &r->headers_out.headers.part;
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

        if (header[i].hash == 0) {
            continue;
        }

        len += ngx_http_v3_encode_field_l(NULL, &header[i].key,
                                          &header[i].value);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 header len:%uz", len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 output header: \":status: %03ui\"",
                   r->headers_out.status);

    if (r->headers_out.status == NGX_HTTP_OK) {
        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_STATUS_200);

    } else {
        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                 NGX_HTTP_V3_HEADER_STATUS_200,
                                                 NULL, 3);
        b->last = ngx_sprintf(b->last, "%03ui", r->headers_out.status);
    }

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            p = (u_char *) NGINX_VER;
            n = sizeof(NGINX_VER) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            p = (u_char *) NGINX_VER_BUILD;
            n = sizeof(NGINX_VER_BUILD) - 1;

        } else {
            p = (u_char *) "nginx";
            n = sizeof("nginx") - 1;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"server: %*s\"", n, p);

        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                     NGX_HTTP_V3_HEADER_SERVER,
                                                     p, n);
    }

    if (r->headers_out.date == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"date: %V\"",
                       &ngx_cached_http_time);

        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                                     NGX_HTTP_V3_HEADER_DATE,
                                                     ngx_cached_http_time.data,
                                                     ngx_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n = r->headers_out.content_type.len + sizeof("; charset=") - 1
                + r->headers_out.charset.len;

            p = ngx_pnalloc(r->pool, n);
            if (p == NULL) {
                return NGX_ERROR;
            }

            p = ngx_cpymem(p, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

            p = ngx_cpymem(p, "; charset=", sizeof("; charset=") - 1);

            p = ngx_cpymem(p, r->headers_out.charset.data,
                           r->headers_out.charset.len);

            /* updated r->headers_out.content_type is also needed for logging */

            r->headers_out.content_type.len = n;
            r->headers_out.content_type.data = p - n;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"content-type: %V\"",
                       &r->headers_out.content_type);

        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                    NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    r->headers_out.content_type.data,
                                    r->headers_out.content_type.len);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"content-length: %O\"",
                       r->headers_out.content_length_n);

        if (r->headers_out.content_length_n > 0) {
            p = ngx_sprintf(b->last, "%O", r->headers_out.content_length_n);
            n = p - b->last;

            b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                        NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, n);

            b->last = ngx_sprintf(b->last, "%O",
                                  r->headers_out.content_length_n);

        } else {
            b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                       NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        n = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;

        p = ngx_pnalloc(r->pool, n);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_http_time(p, r->headers_out.last_modified_time);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"last-modified: %*s\"", n, p);

        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                              NGX_HTTP_V3_HEADER_LAST_MODIFIED,
                                              p, n);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"location: %V\"",
                       &r->headers_out.location->value);

        b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                                           NGX_HTTP_V3_HEADER_LOCATION,
                                           r->headers_out.location->value.data,
                                           r->headers_out.location->value.len);
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"vary: Accept-Encoding\"");

        b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                      NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);
    }
#endif

    part = &r->headers_out.headers.part;
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

        if (header[i].hash == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                        &header[i].key,
                                                        &header[i].value);
    }

    if (r->header_only) {
        b->last_buf = 1;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    n = b->last - b->pos;

    h3c->payload_bytes += n;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
          + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                    NGX_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    hl = ngx_alloc_chain_link(r->pool);
    if (hl == NULL) {
        return NGX_ERROR;
    }

    hl->buf = b;
    hl->next = cl;

    *ll = hl;
    ll = &cl->next;

    if (r->headers_out.content_length_n >= 0
        && !r->header_only && !r->expect_trailers)
    {
        len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
              + ngx_http_v3_encode_varlen_int(NULL,
                                              r->headers_out.content_length_n);

        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                              r->headers_out.content_length_n);

        h3c->payload_bytes += r->headers_out.content_length_n;
        h3c->total_bytes += r->headers_out.content_length_n;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        *ll = cl;

    } else {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_v3_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_v3_filter_module);
    }

    for (cl = out; cl; cl = cl->next) {
        h3c->total_bytes += cl->buf->last - cl->buf->pos;
        r->header_size += cl->buf->last - cl->buf->pos;
    }

    return ngx_http_write_filter(r, out);
}


static ngx_int_t
ngx_http_v3_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                    *chunk;
    off_t                      size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *out, *cl, *tl, **ll;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_filter_ctx_t  *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    h3c = ngx_http_v3_get_session(r->connection);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 chunk: %O", ngx_buf_size(cl->buf));

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
            chunk = ngx_palloc(r->pool, NGX_HTTP_V3_VARLEN_INT_LEN * 2);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + NGX_HTTP_V3_VARLEN_INT_LEN * 2;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_v3_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(chunk,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

        tl->next = out;
        out = tl;

        h3c->payload_bytes += size;
    }

    if (cl->buf->last_buf) {
        tl = ngx_http_v3_create_trailers(r, ctx);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    for (cl = out; cl; cl = cl->next) {
        h3c->total_bytes += cl->buf->last - cl->buf->pos;
    }

    rc = ngx_http_next_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_v3_filter_module);

    return rc;
}


static ngx_chain_t *
ngx_http_v3_create_trailers(ngx_http_request_t *r,
    ngx_http_v3_filter_ctx_t *ctx)
{
    size_t                  len, n;
    u_char                 *p;
    ngx_buf_t              *b;
    ngx_uint_t              i;
    ngx_chain_t            *cl, *hl;
    ngx_list_part_t        *part;
    ngx_table_elt_t        *header;
    ngx_http_v3_session_t  *h3c;

    h3c = ngx_http_v3_get_session(r->connection);

    len = 0;

    part = &r->headers_out.trailers.part;
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

        if (header[i].hash == 0) {
            continue;
        }

        len += ngx_http_v3_encode_field_l(NULL, &header[i].key,
                                          &header[i].value);
    }

    cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (ngx_buf_tag_t) &ngx_http_v3_filter_module;
    b->memory = 0;
    b->last_buf = 1;

    if (len == 0) {
        b->temporary = 0;
        b->pos = b->last = NULL;
        return cl;
    }

    b->temporary = 1;

    len += ngx_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    b->pos = ngx_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_section_prefix(b->pos,
                                                                 0, 0, 0);

    part = &r->headers_out.trailers.part;
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

        if (header[i].hash == 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 output trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                        &header[i].key,
                                                        &header[i].value);
    }

    n = b->last - b->pos;

    h3c->payload_bytes += n;

    hl = ngx_chain_get_free_buf(r->pool, &ctx->free);
    if (hl == NULL) {
        return NULL;
    }

    b = hl->buf;
    p = b->start;

    if (p == NULL) {
        p = ngx_palloc(r->pool, NGX_HTTP_V3_VARLEN_INT_LEN * 2);
        if (p == NULL) {
            return NULL;
        }

        b->start = p;
        b->end = p + NGX_HTTP_V3_VARLEN_INT_LEN * 2;
    }

    b->tag = (ngx_buf_tag_t) &ngx_http_v3_filter_module;
    b->memory = 0;
    b->temporary = 1;
    b->pos = p;

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(p,
                                                    NGX_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    hl->next = cl;

    return hl;
}


static ngx_int_t
ngx_http_v3_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_v3_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_v3_body_filter;

    return NGX_OK;
}
