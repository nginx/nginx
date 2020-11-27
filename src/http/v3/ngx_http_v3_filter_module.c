
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
static ngx_int_t ngx_http_v3_push_resources(ngx_http_request_t *r,
    ngx_chain_t ***out);
static ngx_int_t ngx_http_v3_push_resource(ngx_http_request_t *r,
    ngx_str_t *path, ngx_chain_t ***out);
static ngx_int_t ngx_http_v3_create_push_request(
    ngx_http_request_t *pr, ngx_str_t *path, uint64_t push_id);
static ngx_int_t ngx_http_v3_set_push_header(ngx_http_request_t *r,
    const char *name, ngx_str_t *value);
static void ngx_http_v3_push_request_handler(ngx_event_t *ev);
static ngx_chain_t *ngx_http_v3_create_push_promise(ngx_http_request_t *r,
    ngx_str_t *path, uint64_t push_id);
static ngx_int_t ngx_http_v3_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_chain_t *ngx_http_v3_create_trailers(ngx_http_request_t *r);
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
    ngx_str_t                  host;
    ngx_uint_t                 i, port;
    ngx_chain_t               *out, *hl, *cl, **ll;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
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

    if ((c->quic->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0
        && r->method != NGX_HTTP_HEAD)
    {
        if (ngx_http_v3_push_resources(r, &ll) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    len = ngx_http_v3_encode_header_block_prefix(NULL, 0, 0, 0);

    if (r->headers_out.status == NGX_HTTP_OK) {
        len += ngx_http_v3_encode_header_ri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_STATUS_200);

    } else {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
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

        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                             NGX_HTTP_V3_HEADER_SERVER,
                                             NULL, n);
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_v3_encode_header_lri(NULL, 0, NGX_HTTP_V3_HEADER_DATE,
                                             NULL, ngx_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                    NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    NULL, n);
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n > 0) {
            len += ngx_http_v3_encode_header_lri(NULL, 0,
                                        NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, NGX_OFF_T_LEN);

        } else if (r->headers_out.content_length_n == 0) {
            len += ngx_http_v3_encode_header_ri(NULL, 0,
                                       NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                  NGX_HTTP_V3_HEADER_LAST_MODIFIED, NULL,
                                  sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/'
        && clcf->absolute_redirect)
    {
        r->headers_out.location->hash = 0;

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

        n = sizeof("https://") - 1 + host.len
            + r->headers_out.location->value.len;

        if (clcf->port_in_redirect) {
            port = (port == 443) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            n += sizeof(":65535") - 1;
        }

        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                         NGX_HTTP_V3_HEADER_LOCATION, NULL, n);

    } else {
        ngx_str_null(&host);
        port = 0;
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += ngx_http_v3_encode_header_ri(NULL, 0,
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

        len += ngx_http_v3_encode_header_l(NULL, &header[i].key,
                                           &header[i].value);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 header len:%uz", len);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_header_block_prefix(b->last,
                                                                0, 0, 0);

    if (r->headers_out.status == NGX_HTTP_OK) {
        b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_STATUS_200);

    } else {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
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

        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                     NGX_HTTP_V3_HEADER_SERVER,
                                                     p, n);
    }

    if (r->headers_out.date == NULL) {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                     NGX_HTTP_V3_HEADER_DATE,
                                                     ngx_cached_http_time.data,
                                                     ngx_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                    NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    NULL, n);

        p = b->last;
        b->last = ngx_cpymem(b->last, r->headers_out.content_type.data,
                             r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_cpymem(b->last, r->headers_out.charset.data,
                                 r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n > 0) {
            p = ngx_sprintf(b->last, "%O", r->headers_out.content_length_n);
            n = p - b->last;

            b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                        NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, n);

            b->last = ngx_sprintf(b->last, "%O",
                                  r->headers_out.content_length_n);

        } else if (r->headers_out.content_length_n == 0) {
            b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                       NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                  NGX_HTTP_V3_HEADER_LAST_MODIFIED, NULL,
                                  sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);

        b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);
    }

    if (host.data) {
        n = sizeof("https://") - 1 + host.len
            + r->headers_out.location->value.len;

        if (port) {
            n += ngx_sprintf(b->last, ":%ui", port) - b->last;
        }

        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                   NGX_HTTP_V3_HEADER_LOCATION,
                                                   NULL, n);

        p = b->last;
        b->last = ngx_cpymem(b->last, "https://", sizeof("https://") - 1);
        b->last = ngx_cpymem(b->last, host.data, host.len);

        if (port) {
            b->last = ngx_sprintf(b->last, ":%ui", port);
        }

        b->last = ngx_cpymem(b->last, r->headers_out.location->value.data,
                             r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "Location");
    }

#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
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

        b->last = (u_char *) ngx_http_v3_encode_header_l(b->last,
                                                         &header[i].key,
                                                         &header[i].value);
    }

    if (r->header_only) {
        b->last_buf = 1;
    }

    cl = ngx_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    n = b->last - b->pos;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
          + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(c->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                    NGX_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    hl = ngx_alloc_chain_link(c->pool);
    if (hl == NULL) {
        return NGX_ERROR;
    }

    hl->buf = b;
    hl->next = cl;

    *ll = hl;
    ll = &cl->next;

    if (r->headers_out.content_length_n >= 0 && !r->header_only) {
        len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
              + ngx_http_v3_encode_varlen_int(NULL,
                                              r->headers_out.content_length_n);

        b = ngx_create_temp_buf(c->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                              r->headers_out.content_length_n);

        cl = ngx_alloc_chain_link(c->pool);
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

    return ngx_http_write_filter(r, out);
}


static ngx_int_t
ngx_http_v3_push_resources(ngx_http_request_t *r, ngx_chain_t ***out)
{
    u_char                     *start, *end, *last;
    ngx_str_t                   path;
    ngx_int_t                   rc;
    ngx_uint_t                  i, push;
    ngx_table_elt_t           **h;
    ngx_http_v3_loc_conf_t     *h3lcf;
    ngx_http_complex_value_t   *pushes;

    h3lcf = ngx_http_get_module_loc_conf(r, ngx_http_v3_module);

    if (h3lcf->pushes) {
        pushes = h3lcf->pushes->elts;

        for (i = 0; i < h3lcf->pushes->nelts; i++) {

            if (ngx_http_complex_value(r, &pushes[i], &path) != NGX_OK) {
                return NGX_ERROR;
            }

            if (path.len == 0) {
                continue;
            }

            if (path.len == 3 && ngx_strncmp(path.data, "off", 3) == 0) {
                continue;
            }

            rc = ngx_http_v3_push_resource(r, &path, out);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_ABORT) {
                return NGX_OK;
            }

            /* NGX_OK, NGX_DECLINED */
        }
    }

    if (!h3lcf->push_preload) {
        return NGX_OK;
    }

    h = r->headers_out.link.elts;

    for (i = 0; i < r->headers_out.link.nelts; i++) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 parse link: \"%V\"", &h[i]->value);

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

    next_link:

        while (start < end && *start == ' ') { start++; }

        if (start == end || *start++ != '<') {
            continue;
        }

        while (start < end && *start == ' ') { start++; }

        for (last = start; last < end && *last != '>'; last++) {
            /* void */
        }

        if (last == start || last == end) {
            continue;
        }

        path.len = last - start;
        path.data = start;

        start = last + 1;

        while (start < end && *start == ' ') { start++; }

        if (start == end) {
            continue;
        }

        if (*start == ',') {
            start++;
            goto next_link;
        }

        if (*start++ != ';') {
            continue;
        }

        last = ngx_strlchr(start, end, ',');

        if (last == NULL) {
            last = end;
        }

        push = 0;

        for ( ;; ) {

            while (start < last && *start == ' ') { start++; }

            if (last - start >= 6
                && ngx_strncasecmp(start, (u_char *) "nopush", 6) == 0)
            {
                start += 6;

                if (start == last || *start == ' ' || *start == ';') {
                    push = 0;
                    break;
                }

                goto next_param;
            }

            if (last - start >= 11
                && ngx_strncasecmp(start, (u_char *) "rel=preload", 11) == 0)
            {
                start += 11;

                if (start == last || *start == ' ' || *start == ';') {
                    push = 1;
                }

                goto next_param;
            }

            if (last - start >= 4
                && ngx_strncasecmp(start, (u_char *) "rel=", 4) == 0)
            {
                start += 4;

                while (start < last && *start == ' ') { start++; }

                if (start == last || *start++ != '"') {
                    goto next_param;
                }

                for ( ;; ) {

                    while (start < last && *start == ' ') { start++; }

                    if (last - start >= 7
                        && ngx_strncasecmp(start, (u_char *) "preload", 7) == 0)
                    {
                        start += 7;

                        if (start < last && (*start == ' ' || *start == '"')) {
                            push = 1;
                            break;
                        }
                    }

                    while (start < last && *start != ' ' && *start != '"') {
                        start++;
                    }

                    if (start == last) {
                        break;
                    }

                    if (*start == '"') {
                        break;
                    }

                    start++;
                }
            }

        next_param:

            start = ngx_strlchr(start, last, ';');

            if (start == NULL) {
                break;
            }

            start++;
        }

        if (push) {
            while (path.len && path.data[path.len - 1] == ' ') {
                path.len--;
            }
        }

        if (push && path.len
            && !(path.len > 1 && path.data[0] == '/' && path.data[1] == '/'))
        {
            rc = ngx_http_v3_push_resource(r, &path, out);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_ABORT) {
                return NGX_OK;
            }

            /* NGX_OK, NGX_DECLINED */
        }

        if (last < end) {
            start = last + 1;
            goto next_link;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_push_resource(ngx_http_request_t *r, ngx_str_t *path,
    ngx_chain_t ***ll)
{
    uint64_t                   push_id;
    ngx_int_t                  rc;
    ngx_chain_t               *cl;
    ngx_connection_t          *c;
    ngx_http_v3_srv_conf_t    *h3scf;
    ngx_http_v3_connection_t  *h3c;

    c = r->connection;
    h3c = c->quic->parent->data;
    h3scf = ngx_http_get_module_srv_conf(r, ngx_http_v3_module);

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 push \"%V\" pushing:%ui/%ui id:%uL/%uL",
                   path, h3c->npushing, h3scf->max_concurrent_pushes,
                   h3c->next_push_id, h3c->max_push_id);

    if (!ngx_path_separator(path->data[0])) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "non-absolute path \"%V\" not pushed", path);
        return NGX_DECLINED;
    }

    if (h3c->next_push_id > h3c->max_push_id) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 abort pushes due to max_push_id");
        return NGX_ABORT;
    }

    if (h3c->npushing >= h3scf->max_concurrent_pushes) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 abort pushes due to max_concurrent_pushes");
        return NGX_ABORT;
    }

    push_id = h3c->next_push_id++;

    rc = ngx_http_v3_create_push_request(r, path, push_id);
    if (rc != NGX_OK) {
        return rc;
    }

    cl = ngx_http_v3_create_push_promise(r, path, push_id);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    for (**ll = cl; **ll; *ll = &(**ll)->next);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_create_push_request(ngx_http_request_t *pr, ngx_str_t *path,
    uint64_t push_id)
{
    ngx_pool_t                *pool;
    ngx_connection_t          *c, *pc;
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_v3_connection_t  *h3c;

    pc = pr->connection;

    r = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http3 create push request id:%uL", push_id);

    c = ngx_http_v3_create_push_stream(pc, push_id);
    if (c == NULL) {
        return NGX_ABORT;
    }

    hc = ngx_palloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        goto failed;
    }

    h3c = c->quic->parent->data;
    ngx_memcpy(hc, h3c, sizeof(ngx_http_connection_t));
    c->data = hc;

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        goto failed;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->handler = ngx_http_log_error;
    c->log->data = ctx;
    c->log->action = "processing pushed request headers";

    c->log_error = NGX_ERROR_INFO;

    r = ngx_http_create_request(c);
    if (r == NULL) {
        goto failed;
    }

    c->data = r;

    ngx_str_set(&r->http_protocol, "HTTP/3.0");

    r->method_name = ngx_http_core_get_method;
    r->method = NGX_HTTP_GET;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        goto failed;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        goto failed;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    r->schema.data = ngx_pstrdup(r->pool, &pr->schema);
    if (r->schema.data == NULL) {
        goto failed;
    }

    r->schema.len = pr->schema.len;

    r->uri_start = ngx_pstrdup(r->pool, path);
    if (r->uri_start == NULL) {
        goto failed;
    }

    r->uri_end = r->uri_start + path->len;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_v3_set_push_header(r, "host", &pr->headers_in.server)
        != NGX_OK)
    {
        goto failed;
    }

    if (pr->headers_in.accept_encoding) {
        if (ngx_http_v3_set_push_header(r, "accept-encoding",
                                        &pr->headers_in.accept_encoding->value)
            != NGX_OK)
        {
            goto failed;
        }
    }

    if (pr->headers_in.accept_language) {
        if (ngx_http_v3_set_push_header(r, "accept-language",
                                        &pr->headers_in.accept_language->value)
            != NGX_OK)
        {
            goto failed;
        }
    }

    if (pr->headers_in.user_agent) {
        if (ngx_http_v3_set_push_header(r, "user-agent",
                                        &pr->headers_in.user_agent->value)
            != NGX_OK)
        {
            goto failed;
        }
    }

    c->read->handler = ngx_http_v3_push_request_handler;
    c->read->handler = ngx_http_v3_push_request_handler;

    ngx_post_event(c->read, &ngx_posted_events);

    return NGX_OK;

failed:

    if (r) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_set_push_header(ngx_http_request_t *r, const char *name,
    ngx_str_t *value)
{
    u_char                     *p;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 push header \"%s\": \"%V\"", name, value);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    p = ngx_pnalloc(r->pool, value->len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, value->data, value->len);
    p[value->len] = '\0';

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.data = (u_char *) name;
    h->key.len = ngx_strlen(name);
    h->hash = ngx_hash_key(h->key.data, h->key.len);
    h->lowcase_key = (u_char *) name;
    h->value.data = p;
    h->value.len = value->len;

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_v3_push_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 push request handler");

    ngx_http_process_request(r);
}


static ngx_chain_t *
ngx_http_v3_create_push_promise(ngx_http_request_t *r, ngx_str_t *path,
    uint64_t push_id)
{
    size_t        n, len;
    ngx_buf_t    *b;
    ngx_chain_t  *hl, *cl;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 create push promise id:%uL", push_id);

    len = ngx_http_v3_encode_varlen_int(NULL, push_id);

    len += ngx_http_v3_encode_header_block_prefix(NULL, 0, 0, 0);

    len += ngx_http_v3_encode_header_ri(NULL, 0,
                                        NGX_HTTP_V3_HEADER_METHOD_GET);

    len += ngx_http_v3_encode_header_lri(NULL, 0,
                                         NGX_HTTP_V3_HEADER_AUTHORITY,
                                         NULL, r->headers_in.server.len);

    if (path->len == 1 && path->data[0] == '/') {
        len += ngx_http_v3_encode_header_ri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_PATH_ROOT);

    } else {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                             NGX_HTTP_V3_HEADER_PATH_ROOT,
                                             NULL, path->len);
    }

    if (r->schema.len == 5 && ngx_strncmp(r->schema.data, "https", 5) == 0) {
        len += ngx_http_v3_encode_header_ri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    } else if (r->schema.len == 4
               && ngx_strncmp(r->schema.data, "http", 4) == 0)
    {
        len += ngx_http_v3_encode_header_ri(NULL, 0,
                                            NGX_HTTP_V3_HEADER_SCHEME_HTTP);

    } else {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                             NGX_HTTP_V3_HEADER_SCHEME_HTTP,
                                             NULL, r->schema.len);
    }

    if (r->headers_in.accept_encoding) {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                     NGX_HTTP_V3_HEADER_ACCEPT_ENCODING, NULL,
                                     r->headers_in.accept_encoding->value.len);
    }

    if (r->headers_in.accept_language) {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                     NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE, NULL,
                                     r->headers_in.accept_language->value.len);
    }

    if (r->headers_in.user_agent) {
        len += ngx_http_v3_encode_header_lri(NULL, 0,
                                          NGX_HTTP_V3_HEADER_USER_AGENT, NULL,
                                          r->headers_in.user_agent->value.len);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, push_id);

    b->last = (u_char *) ngx_http_v3_encode_header_block_prefix(b->last,
                                                                0, 0, 0);

    b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_METHOD_GET);

    b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                  NGX_HTTP_V3_HEADER_AUTHORITY,
                                                  r->headers_in.server.data,
                                                  r->headers_in.server.len);

    if (path->len == 1 && path->data[0] == '/') {
        b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                                 NGX_HTTP_V3_HEADER_PATH_ROOT);

    } else {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                  NGX_HTTP_V3_HEADER_PATH_ROOT,
                                                  path->data, path->len);
    }

    if (r->schema.len == 5 && ngx_strncmp(r->schema.data, "https", 5) == 0) {
        b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                              NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    } else if (r->schema.len == 4
               && ngx_strncmp(r->schema.data, "http", 4) == 0)
    {
        b->last = (u_char *) ngx_http_v3_encode_header_ri(b->last, 0,
                                               NGX_HTTP_V3_HEADER_SCHEME_HTTP);

    } else {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                                NGX_HTTP_V3_HEADER_SCHEME_HTTP,
                                                r->schema.data, r->schema.len);
    }

    if (r->headers_in.accept_encoding) {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                     NGX_HTTP_V3_HEADER_ACCEPT_ENCODING,
                                     r->headers_in.accept_encoding->value.data,
                                     r->headers_in.accept_encoding->value.len);
    }

    if (r->headers_in.accept_language) {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                     NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE,
                                     r->headers_in.accept_language->value.data,
                                     r->headers_in.accept_language->value.len);
    }

    if (r->headers_in.user_agent) {
        b->last = (u_char *) ngx_http_v3_encode_header_lri(b->last, 0,
                                          NGX_HTTP_V3_HEADER_USER_AGENT,
                                          r->headers_in.user_agent->value.data,
                                          r->headers_in.user_agent->value.len);
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    n = b->last - b->pos;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_PUSH_PROMISE)
          + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                               NGX_HTTP_V3_FRAME_PUSH_PROMISE);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    hl = ngx_alloc_chain_link(r->pool);
    if (hl == NULL) {
        return NULL;
    }

    hl->buf = b;
    hl->next = cl;

    return hl;
}


static ngx_int_t
ngx_http_v3_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                    *chunk;
    off_t                      size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *out, *cl, *tl, **ll;
    ngx_http_v3_filter_ctx_t  *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_v3_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

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
    }

    if (cl->buf->last_buf) {
        tl = ngx_http_v3_create_trailers(r);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    rc = ngx_http_next_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_v3_filter_module);

    return rc;
}


static ngx_chain_t *
ngx_http_v3_create_trailers(ngx_http_request_t *r)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 create trailers");

    /* XXX */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->last_buf = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    cl->next = NULL;

    return cl;
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
