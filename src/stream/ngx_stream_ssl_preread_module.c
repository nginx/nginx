
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_flag_t      enabled;
} ngx_stream_ssl_preread_srv_conf_t;


typedef struct {
    size_t          left;
    size_t          size;
    u_char         *pos;
    u_char         *dst;
    u_char          buf[4];
    ngx_str_t       host;
    ngx_log_t      *log;
    ngx_pool_t     *pool;
    ngx_uint_t      state;
} ngx_stream_ssl_preread_ctx_t;


static ngx_int_t ngx_stream_ssl_preread_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_ssl_preread_parse_record(
    ngx_stream_ssl_preread_ctx_t *ctx, u_char *pos, u_char *last);
static ngx_int_t ngx_stream_ssl_preread_server_name_variable(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_ssl_preread_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_ssl_preread_commands[] = {

    { ngx_string("ssl_preread"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ssl_preread_srv_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_ssl_preread_module_ctx = {
    ngx_stream_ssl_preread_add_variables,   /* preconfiguration */
    ngx_stream_ssl_preread_init,            /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_stream_ssl_preread_create_srv_conf, /* create server configuration */
    ngx_stream_ssl_preread_merge_srv_conf   /* merge server configuration */
};


ngx_module_t  ngx_stream_ssl_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_preread_module_ctx,     /* module context */
    ngx_stream_ssl_preread_commands,        /* module directives */
    NGX_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_ssl_preread_vars[] = {

    { ngx_string("ssl_preread_server_name"), NULL,
      ngx_stream_ssl_preread_server_name_variable, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_stream_ssl_preread_handler(ngx_stream_session_t *s)
{
    u_char                             *last, *p;
    size_t                              len;
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_stream_ssl_preread_ctx_t       *ctx;
    ngx_stream_ssl_preread_srv_conf_t  *sscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "ssl preread handler");

    sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_preread_module);

    if (!sscf->enabled) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_ssl_preread_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_ssl_preread_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = c->buffer->pos;
    }

    p = ctx->pos;
    last = c->buffer->last;

    while (last - p >= 5) {

        if (p[0] != 0x16) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                          "ssl preread: not a handshake");
            return NGX_DECLINED;
        }

        if (p[1] != 3 || p[2] == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                          "ssl preread: unsupported SSL version");
            return NGX_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = ngx_stream_ssl_preread_parse_record(ctx, p, p + len);
        if (rc != NGX_AGAIN) {
            return rc;
        }

        p += len;
    }

    ctx->pos = p;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_stream_ssl_preread_parse_record(ngx_stream_ssl_preread_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size;
    u_char  *dst, *p;

    enum {
        sw_start = 0,
        sw_header,          /* handshake msg_type, length */
        sw_head_tail,       /* version, random */
        sw_sid_len,         /* session_id length */
        sw_sid,             /* session_id */
        sw_cs_len,          /* cipher_suites length */
        sw_cs,              /* cipher_suites */
        sw_cm_len,          /* compression_methods length */
        sw_cm,              /* compression_methods */
        sw_ext,             /* extension */
        sw_ext_header,      /* extension_type, extension_data length */
        sw_sni_len,         /* SNI length */
        sw_sni_host_head,   /* SNI name_type, host_name length */
        sw_sni_host         /* SNI host_name */
    } state;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                   "ssl preread: state %ui left %z", ctx->state, ctx->left);

    state = ctx->state;
    size = ctx->size;
    left = ctx->left;
    dst = ctx->dst;
    p = ctx->buf;

    for ( ;; ) {
        n = ngx_min((size_t) (last - pos), size);

        if (dst) {
            dst = ngx_cpymem(dst, pos, n);
        }

        pos += n;
        size -= n;
        left -= n;

        if (size != 0) {
            break;
        }

        switch (state) {

        case sw_start:
            state = sw_header;
            dst = p;
            size = 4;
            left = size;
            break;

        case sw_header:
            if (p[0] != 1) {
                ngx_log_debug(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                              "ssl preread: not a client hello");
                return NGX_DECLINED;
            }

            state = sw_head_tail;
            dst = NULL;
            size = 34;
            left = (p[1] << 16) + (p[2] << 8) + p[3];
            break;

        case sw_head_tail:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            state = sw_sid;
            dst = NULL;
            size = p[0];
            break;

        case sw_sid:
            state = sw_cs_len;
            dst = p;
            size = 2;
            break;

        case sw_cs_len:
            state = sw_cs;
            dst = NULL;
            size = (p[0] << 8) + p[1];
            break;

        case sw_cs:
            state = sw_cm_len;
            dst = p;
            size = 1;
            break;

        case sw_cm_len:
            state = sw_cm;
            dst = NULL;
            size = p[0];
            break;

        case sw_cm:
            if (left == 0) {
                /* no extensions */
                return NGX_OK;
            }

            state = sw_ext;
            dst = p;
            size = 2;
            break;

        case sw_ext:
            if (left == 0) {
                return NGX_OK;
            }

            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if (p[0] == 0 && p[1] == 0) {
                /* SNI extension */
                state = sw_sni_len;
                dst = NULL;
                size = 2;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = (p[2] << 8) + p[3];
            break;

        case sw_sni_len:
            state = sw_sni_host_head;
            dst = p;
            size = 3;
            break;

        case sw_sni_host_head:
            if (p[0] != 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI hostname type is not DNS");
                return NGX_DECLINED;
            }

            state = sw_sni_host;
            size = (p[1] << 8) + p[2];

            ctx->host.data = ngx_pnalloc(ctx->pool, size);
            if (ctx->host.data == NULL) {
                return NGX_ERROR;
            }

            ctx->host.len = size;
            dst = ctx->host.data;
            break;

        case sw_sni_host:
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: SNI hostname \"%V\"", &ctx->host);
            return NGX_OK;
        }

        if (left < size) {
           ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                          "ssl preread: failed to parse handshake");
           return NGX_DECLINED;
        }
    }

    ctx->state = state;
    ctx->size = size;
    ctx->left = left;
    ctx->dst = dst;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_stream_ssl_preread_server_name_variable(ngx_stream_session_t *s,
    ngx_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_preread_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->host.len;
    v->data = ctx->host.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ssl_preread_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_ssl_preread_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ssl_preread_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_ssl_preread_srv_conf_t *prev = parent;
    ngx_stream_ssl_preread_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_ssl_preread_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_ssl_preread_handler;

    return NGX_OK;
}
