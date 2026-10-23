
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Sergey A. Osokin
 */

#define NGX_ESCAPE_REDIS   4

#define REDIS_AUTH_CMD      "*2\r\n$4\r\nauth\r\n"
#define REDIS_GET_CMD       "*2\r\n$3\r\nget\r\n"
#define REDIS_SELECT_CMD    "*2\r\n$6\r\nselect\r\n"
#define REDIS_PLUSOKCRLF    "+OK\r\n"
#define REDIS_ERR           "$-1"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


typedef struct {
    ngx_http_upstream_conf_t   upstream;
    ngx_int_t                  index;
    ngx_int_t                  db;
    ngx_int_t                  auth;
    ngx_uint_t                 gzip_flag;
} ngx_http_redis_loc_conf_t;


typedef struct {
    size_t                     rest;
    ngx_http_request_t        *request;
    ngx_str_t                  key;
} ngx_http_redis_ctx_t;


static ngx_int_t ngx_http_redis_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_filter_init(void *data);
static ngx_int_t ngx_http_redis_filter(void *data, ssize_t bytes);
static void ngx_http_redis_abort_request(ngx_http_request_t *r);
static void ngx_http_redis_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_redis_add_variables(ngx_conf_t *cf);
static void *ngx_http_redis_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_redis_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_conf_bitmask_t  ngx_http_redis_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_redis_commands[] = {

    { ngx_string("redis_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_redis_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("redis_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("redis_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { ngx_string("redis_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("redis_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("redis_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("redis_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("redis_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.next_upstream),
      &ngx_http_redis_next_upstream_masks },

    { ngx_string("redis_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("redis_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("redis_gzip_flag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, gzip_flag),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_redis_module_ctx = {
    ngx_http_redis_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_redis_create_loc_conf,        /* create location configuration */
    ngx_http_redis_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_redis_module = {
    NGX_MODULE_V1,
    &ngx_http_redis_module_ctx,            /* module context */
    ngx_http_redis_commands,               /* module directives */
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

static ngx_str_t  ngx_http_redis_key  = ngx_string("redis_key");
static ngx_str_t  ngx_http_redis_db   = ngx_string("redis_db");
static ngx_str_t  ngx_http_redis_auth = ngx_string("redis_auth");
static ngx_uint_t ngx_http_redis_db_index;
static ngx_uint_t ngx_http_redis_auth_index;


#define NGX_HTTP_REDIS_END   (sizeof(ngx_http_redis_end) - 1)
static u_char  ngx_http_redis_end[] = CRLF;


static ngx_int_t
ngx_http_redis_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_redis_ctx_t       *ctx;
    ngx_http_redis_loc_conf_t  *rlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "redis://");

    u->output.tag = (ngx_buf_tag_t) &ngx_http_redis_module;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);

    u->conf = &rlcf->upstream;

    u->create_request = ngx_http_redis_create_request;
    u->reinit_request = ngx_http_redis_reinit_request;
    u->process_header = ngx_http_redis_process_header;
    u->abort_request = ngx_http_redis_abort_request;
    u->finalize_request = ngx_http_redis_finalize_request;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_redis_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->rest = NGX_HTTP_REDIS_END;
    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_redis_module);

    u->input_filter_init = ngx_http_redis_filter_init;
    u->input_filter = ngx_http_redis_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_redis_create_request(ngx_http_request_t *r)
{
    size_t                      len = 0;
    uintptr_t                   escape;
    ngx_buf_t                  *b;
    ngx_chain_t                *cl;
    ngx_http_redis_ctx_t       *ctx;
    ngx_http_variable_value_t  *vv[3];
    ngx_http_redis_loc_conf_t  *rlcf;
    u_char                      lenbuf[NGX_INT_T_LEN];

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);

    vv[0] = ngx_http_get_indexed_variable(r, ngx_http_redis_auth_index);
    if (vv[0] == NULL || vv[0]->not_found || vv[0]->len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "no auth command provided" );
    } else {
        len += sizeof(REDIS_AUTH_CMD) + sizeof("$") - 1;
        len += ngx_sprintf(lenbuf, "%d", vv[0]->len) - lenbuf;
        len += sizeof(CRLF) - 1 + vv[0]->len;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth info: %s", vv[0]->data);
    }
    len += sizeof(CRLF) - 1;

    vv[1] = ngx_http_get_indexed_variable(r, ngx_http_redis_db_index);

    if (vv[1] == NULL || vv[1]->not_found || vv[1]->len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "select 0 redis database" );
        len += sizeof(REDIS_SELECT_CMD) + sizeof("$1") + sizeof(CRLF) + sizeof("0") - 1;

    } else {
        len += sizeof(REDIS_SELECT_CMD) + sizeof("$") - 1;
        len += ngx_sprintf(lenbuf, "%d", vv[1]->len) - lenbuf;
        len += sizeof(CRLF) - 1 + vv[1]->len;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "select %s redis database", vv[1]->data);
    }
    len += sizeof(CRLF) - 1;

    vv[2] = ngx_http_get_indexed_variable(r, rlcf->index);

    if (vv[2] == NULL || vv[2]->not_found || vv[2]->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"$redis_key\" variable is not set");
        return NGX_ERROR;
    }

    escape = 2 * ngx_escape_uri(NULL, vv[2]->data, vv[2]->len, NGX_ESCAPE_REDIS);

    len += sizeof(REDIS_GET_CMD) + sizeof("$") - 1;
    len += ngx_sprintf(lenbuf, "%d", vv[2]->len) - lenbuf;
    len += sizeof(CRLF) - 1 + vv[2]->len + escape + sizeof(CRLF) - 1;

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

    r->upstream->request_bufs = cl;

    if (vv[0] != NULL && !(vv[0]->not_found) && vv[0]->len != 0) {
        b->last = ngx_sprintf(b->last, "%s$%d%s", REDIS_AUTH_CMD, vv[0]->len, CRLF);
        b->last = ngx_copy(b->last, vv[0]->data, vv[0]->len);
        *b->last++ = CR; *b->last++ = LF;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_redis_module);

    ctx->key.data = b->last;

    if (vv[1] == NULL || vv[1]->not_found || vv[1]->len == 0) {
        b->last = ngx_sprintf(b->last, "%s$1%s", REDIS_SELECT_CMD, CRLF);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "select 0 redis database" );
        *b->last++ = '0';

    } else {
        b->last = ngx_sprintf(b->last, "%s$%d%s", REDIS_SELECT_CMD, vv[1]->len, CRLF);
        b->last = ngx_copy(b->last, vv[1]->data, vv[1]->len);
        ctx->key.len = b->last - ctx->key.data;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "select %V redis database", &ctx->key);
    }

    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_sprintf(b->last, "%s$%d%s", REDIS_GET_CMD, vv[2]->len + escape, CRLF);
    ctx = ngx_http_get_module_ctx(r, ngx_http_redis_module);

    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = ngx_copy(b->last, vv[2]->data, vv[2]->len);

    } else {
        b->last = (u_char *) ngx_escape_uri(b->last, vv[2]->data, vv[2]->len,
                                            NGX_ESCAPE_REDIS);
    }

    ctx->key.len = b->last - ctx->key.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http redis request: \"%V\"", &ctx->key);

    *b->last++ = CR; *b->last++ = LF;

    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_process_header(ngx_http_request_t *r)
{
    u_char                     *p, *len;
    u_int                       c, try;
    ngx_str_t                   line;
    ngx_table_elt_t            *h;
    ngx_http_upstream_t        *u;
    ngx_http_redis_ctx_t       *ctx;
    ngx_http_redis_loc_conf_t  *rlcf;
    ngx_http_variable_value_t  *vv;
    ngx_int_t                   no_auth_cmd;

    vv = ngx_http_get_indexed_variable(r, ngx_http_redis_auth_index);
    no_auth_cmd = (vv == NULL || vv->not_found || vv->len == 0);

    c = try = 0;

    u = r->upstream;

    p = u->buffer.pos;

    if ((u->buffer.last - p) <= 0) {
        return NGX_AGAIN;
    }

    if (*p == '+') {
        if (no_auth_cmd) {
            try = 2;

        } else {
            try = 3;
        }

    } else if (*p == '-') {
        try = 1;

    } else {
        goto no_valid;
    }

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            c++;
            if (c == try) {
                goto found;
            }
        }
    }

    return NGX_AGAIN;

found:

    *p = '\0';

    line.len = p - u->buffer.pos - 1;
    line.data = u->buffer.pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "redis: \"%V\"", &line);

    p = u->buffer.pos;

    ctx = ngx_http_get_module_ctx(r, ngx_http_redis_module);
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);

    if (ngx_strncmp(p, "-ERR", sizeof("-ERR") - 1) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "redis sent error in response \"%V\" "
                      "for key \"%V\"",
                      &line, &ctx->key);

        goto no_valid;
    }

    vv = ngx_http_get_indexed_variable(r, ngx_http_redis_auth_index);
    if (no_auth_cmd) {
        if (ngx_strncmp(p, REDIS_PLUSOKCRLF, sizeof(REDIS_PLUSOKCRLF) - 1) == 0) {
            p += sizeof(REDIS_PLUSOKCRLF) - 1;

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "+OK\\r\\n was expected here");
        }

    } else {
        if ((ngx_strncmp(p, REDIS_PLUSOKCRLF, sizeof(REDIS_PLUSOKCRLF) - 1) == 0) &&
            (ngx_strncmp(p + sizeof(REDIS_PLUSOKCRLF) - 1,
                            REDIS_PLUSOKCRLF, sizeof(REDIS_PLUSOKCRLF) - 1) == 0)) {
             p += 2 * (sizeof(REDIS_PLUSOKCRLF) - 1);

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "+OK\\r\\n+OK\\r\\n was expected here");
        }
    }

    if (ngx_strncmp(p, REDIS_ERR, sizeof(REDIS_ERR) - 1) == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by redis", &ctx->key);

        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->buffer.pos = p + sizeof(REDIS_ERR CRLF) - 1;
        u->keepalive = 1;

        return NGX_OK;
    }

    if (ngx_strncmp(p, "$", sizeof("$") - 1) == 0) {

        p += sizeof("$") - 1;

        len = p;

        if (rlcf->gzip_flag) {
            h = ngx_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = 1;
            h->next = NULL;
            ngx_str_set(&h->key, "Content-Encoding");
            ngx_str_set(&h->value, "gzip");
            r->headers_out.content_encoding = h;
        }

        while (*p && *p++ != CR) { /* void */ }

        u->headers_in.content_length_n = ngx_atoof(len, p - len - 1);
        if (u->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "redis sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->buffer.pos = p + 1;

        return NGX_OK;
    }

no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "redis sent invalid response: \"%V\"", &line);

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
}


static ngx_int_t
ngx_http_redis_filter_init(void *data)
{
    ngx_http_redis_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + NGX_HTTP_REDIS_END;
        ctx->rest = NGX_HTTP_REDIS_END;

    } else {
        u->length = 0;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_filter(void *data, ssize_t bytes)
{
    ngx_http_redis_ctx_t  *ctx = data;

    u_char               *last;
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (bytes > u->length
            || ngx_strncmp(b->last,
                   ngx_http_redis_end + NGX_HTTP_REDIS_END - ctx->rest,
                   bytes)
               != 0)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "redis sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return NGX_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "redis filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - NGX_HTTP_REDIS_END)) {
        u->length -= bytes;
        return NGX_OK;
    }

    last += (size_t) (u->length - NGX_HTTP_REDIS_END);

    if (bytes > u->length
        || ngx_strncmp(last, ngx_http_redis_end, b->last - last) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "redis sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return NGX_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
       u->keepalive = 1;
    }

    return NGX_OK;
}


static void
ngx_http_redis_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http redis request");
    return;
}


static void
ngx_http_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http redis request");
    return;
}


static void *
ngx_http_redis_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_redis_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_redis_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;

    conf->index = NGX_CONF_UNSET;
    conf->db = NGX_CONF_UNSET;
    conf->auth = NGX_CONF_UNSET;
    conf->gzip_flag = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_redis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_redis_loc_conf_t *prev = parent;
    ngx_http_redis_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries,
0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NGX_CONF_UNSET) {
        conf->index = prev->index;
    }

    if (conf->db == NGX_CONF_UNSET) {
        conf->db = prev->db;
    }

    if (conf->auth == NGX_CONF_UNSET) {
        conf->auth = prev->auth;
    }

    ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_redis_loc_conf_t *rlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (rlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    rlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (rlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_redis_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    rlcf->index = ngx_http_get_variable_index(cf, &ngx_http_redis_key);

    if (rlcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    rlcf->db = ngx_http_get_variable_index(cf, &ngx_http_redis_db);
    rlcf->auth = ngx_http_get_variable_index(cf, &ngx_http_redis_auth);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_redis_reset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_add_variables(ngx_conf_t *cf)
{
    ngx_int_t             n;
    ngx_http_variable_t  *var;
    ngx_http_variable_t  *authvar;

    var = ngx_http_add_variable(cf, &ngx_http_redis_db,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_redis_reset_variable;

    n = ngx_http_get_variable_index(cf, &ngx_http_redis_db);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_redis_db_index = n;

    authvar = ngx_http_add_variable(cf, &ngx_http_redis_auth,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (authvar == NULL) {
        return NGX_ERROR;
    }

    authvar->get_handler = ngx_http_redis_reset_variable;

    n = ngx_http_get_variable_index(cf, &ngx_http_redis_auth);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_redis_auth_index = n;

    return NGX_OK;
}
