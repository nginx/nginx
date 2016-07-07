
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_USERID_OFF   0
#define NGX_HTTP_USERID_LOG   1
#define NGX_HTTP_USERID_V1    2
#define NGX_HTTP_USERID_ON    3

/* 31 Dec 2037 23:55:55 GMT */
#define NGX_HTTP_USERID_MAX_EXPIRES  2145916555


typedef struct {
    ngx_uint_t  enable;

    ngx_int_t   service;

    ngx_str_t   name;
    ngx_str_t   domain;
    ngx_str_t   path;
    ngx_str_t   p3p;

    time_t      expires;

    u_char      mark;
} ngx_http_userid_conf_t;


typedef struct {
    uint32_t    uid_got[4];
    uint32_t    uid_set[4];
    ngx_str_t   cookie;
    ngx_uint_t  reset;
} ngx_http_userid_ctx_t;


static ngx_http_userid_ctx_t *ngx_http_userid_get_uid(ngx_http_request_t *r,
    ngx_http_userid_conf_t *conf);
static ngx_int_t ngx_http_userid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_str_t *name, uint32_t *uid);
static ngx_int_t ngx_http_userid_set_uid(ngx_http_request_t *r,
    ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);
static ngx_int_t ngx_http_userid_create_uid(ngx_http_request_t *r,
    ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);

static ngx_int_t ngx_http_userid_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_userid_init(ngx_conf_t *cf);
static void *ngx_http_userid_create_conf(ngx_conf_t *cf);
static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_userid_init_worker(ngx_cycle_t *cycle);



static uint32_t  start_value;
static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_conf_enum_t  ngx_http_userid_state[] = {
    { ngx_string("off"), NGX_HTTP_USERID_OFF },
    { ngx_string("log"), NGX_HTTP_USERID_LOG },
    { ngx_string("v1"), NGX_HTTP_USERID_V1 },
    { ngx_string("on"), NGX_HTTP_USERID_ON },
    { ngx_null_string, 0 }
};


static ngx_conf_post_handler_pt  ngx_http_userid_domain_p =
    ngx_http_userid_domain;
static ngx_conf_post_handler_pt  ngx_http_userid_path_p = ngx_http_userid_path;
static ngx_conf_post_handler_pt  ngx_http_userid_p3p_p = ngx_http_userid_p3p;


static ngx_command_t  ngx_http_userid_commands[] = {

    { ngx_string("userid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, enable),
      ngx_http_userid_state },

    { ngx_string("userid_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, service),
      NULL },

    { ngx_string("userid_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, name),
      NULL },

    { ngx_string("userid_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, domain),
      &ngx_http_userid_domain_p },

    { ngx_string("userid_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, path),
      &ngx_http_userid_path_p },

    { ngx_string("userid_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_userid_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("userid_p3p"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_userid_conf_t, p3p),
      &ngx_http_userid_p3p_p },

    { ngx_string("userid_mark"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_userid_mark,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_userid_filter_module_ctx = {
    ngx_http_userid_add_variables,         /* preconfiguration */
    ngx_http_userid_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_userid_create_conf,           /* create location configuration */
    ngx_http_userid_merge_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_userid_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_userid_filter_module_ctx,    /* module context */
    ngx_http_userid_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_userid_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t   ngx_http_userid_got = ngx_string("uid_got");
static ngx_str_t   ngx_http_userid_set = ngx_string("uid_set");
static ngx_str_t   ngx_http_userid_reset = ngx_string("uid_reset");
static ngx_uint_t  ngx_http_userid_reset_index;


static ngx_int_t
ngx_http_userid_filter(ngx_http_request_t *r)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);

    if (conf->enable < NGX_HTTP_USERID_V1) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_userid_get_uid(r, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_userid_set_uid(r, ctx, conf) == NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_userid_got_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);

    if (conf->enable == NGX_HTTP_USERID_OFF) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->uid_got[3] != 0) {
        return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_set_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_userid_ctx_t   *ctx;
    ngx_http_userid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);

    if (conf->enable < NGX_HTTP_USERID_V1) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_userid_create_uid(r->main, ctx, conf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
}


static ngx_http_userid_ctx_t *
ngx_http_userid_get_uid(ngx_http_request_t *r, ngx_http_userid_conf_t *conf)
{
    ngx_int_t                n;
    ngx_str_t                src, dst;
    ngx_table_elt_t        **cookies;
    ngx_http_userid_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_userid_filter_module);

    if (ctx) {
        return ctx;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_userid_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_userid_filter_module);
    }

    n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
                                          &ctx->cookie);
    if (n == NGX_DECLINED) {
        return ctx;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &ctx->cookie);

    if (ctx->cookie.len < 22) {
        cookies = r->headers_in.cookies.elts;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent too short userid cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }

    src = ctx->cookie;

    /*
     * we have to limit the encoded string to 22 characters because
     *  1) cookie may be marked by "userid_mark",
     *  2) and there are already the millions cookies with a garbage
     *     instead of the correct base64 trail "=="
     */

    src.len = 22;

    dst.data = (u_char *) ctx->uid_got;

    if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
        cookies = r->headers_in.cookies.elts;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid userid cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid: %08XD%08XD%08XD%08XD",
                   ctx->uid_got[0], ctx->uid_got[1],
                   ctx->uid_got[2], ctx->uid_got[3]);

    return ctx;
}


static ngx_int_t
ngx_http_userid_set_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
    ngx_http_userid_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    ngx_str_t         src, dst;
    ngx_table_elt_t  *set_cookie, *p3p;

    if (ngx_http_userid_create_uid(r, ctx, conf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        return NGX_OK;
    }

    len = conf->name.len + 1 + ngx_base64_encoded_length(16) + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    if (ctx->uid_got[3] == 0 || ctx->reset) {
        src.len = 16;
        src.data = (u_char *) ctx->uid_set;
        dst.data = p;

        ngx_encode_base64(&dst, &src);

        p += dst.len;

        if (conf->mark) {
            *(p - 2) = conf->mark;
        }

    } else {
        p = ngx_cpymem(p, ctx->cookie.data, 22);
        *p++ = conf->mark;
        *p++ = '=';
    }

    if (conf->expires == NGX_HTTP_USERID_MAX_EXPIRES) {
        p = ngx_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
    }

    p = ngx_copy(p, conf->domain.data, conf->domain.len);

    p = ngx_copy(p, conf->path.data, conf->path.len);

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return NGX_OK;
    }

    p3p = ngx_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NGX_ERROR;
    }

    p3p->hash = 1;
    ngx_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_create_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
    ngx_http_userid_conf_t *conf)
{
    ngx_connection_t           *c;
    struct sockaddr_in         *sin;
    ngx_http_variable_value_t  *vv;
#if (NGX_HAVE_INET6)
    u_char                     *p;
    struct sockaddr_in6        *sin6;
#endif

    if (ctx->uid_set[3] != 0) {
        return NGX_OK;
    }

    if (ctx->uid_got[3] != 0) {

        vv = ngx_http_get_indexed_variable(r, ngx_http_userid_reset_index);

        if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {

            if (conf->mark == '\0'
                || (ctx->cookie.len > 23
                    && ctx->cookie.data[22] == conf->mark
                    && ctx->cookie.data[23] == '='))
            {
                return NGX_OK;
            }

            ctx->uid_set[0] = ctx->uid_got[0];
            ctx->uid_set[1] = ctx->uid_got[1];
            ctx->uid_set[2] = ctx->uid_got[2];
            ctx->uid_set[3] = ctx->uid_got[3];

            return NGX_OK;

        } else {
            ctx->reset = 1;

            if (vv->len == 3 && ngx_strncmp(vv->data, "log", 3) == 0) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "userid cookie \"%V=%08XD%08XD%08XD%08XD\" was reset",
                        &conf->name, ctx->uid_got[0], ctx->uid_got[1],
                        ctx->uid_got[2], ctx->uid_got[3]);
            }
        }
    }

    /*
     * TODO: in the threaded mode the sequencers should be in TLS and their
     * ranges should be divided between threads
     */

    if (conf->enable == NGX_HTTP_USERID_V1) {
        if (conf->service == NGX_CONF_UNSET) {
            ctx->uid_set[0] = 0;
        } else {
            ctx->uid_set[0] = conf->service;
        }
        ctx->uid_set[1] = (uint32_t) ngx_time();
        ctx->uid_set[2] = start_value;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        if (conf->service == NGX_CONF_UNSET) {

            c = r->connection;

            if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

                p = (u_char *) &ctx->uid_set[0];

                *p++ = sin6->sin6_addr.s6_addr[12];
                *p++ = sin6->sin6_addr.s6_addr[13];
                *p++ = sin6->sin6_addr.s6_addr[14];
                *p = sin6->sin6_addr.s6_addr[15];

                break;
#endif
            default: /* AF_INET */
                sin = (struct sockaddr_in *) c->local_sockaddr;
                ctx->uid_set[0] = sin->sin_addr.s_addr;
                break;
            }

        } else {
            ctx->uid_set[0] = htonl(conf->service);
        }

        ctx->uid_set[1] = htonl((uint32_t) ngx_time());
        ctx->uid_set[2] = htonl(start_value);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    ngx_str_t *name, uint32_t *uid)
{
    v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
                name, uid[0], uid[1], uid[2], uid[3]);

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_reset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_userid_add_variables(ngx_conf_t *cf)
{
    ngx_int_t             n;
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_userid_got, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_got_variable;

    var = ngx_http_add_variable(cf, &ngx_http_userid_set, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_set_variable;

    var = ngx_http_add_variable(cf, &ngx_http_userid_reset,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_userid_reset_variable;

    n = ngx_http_get_variable_index(cf, &ngx_http_userid_reset);
    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_userid_reset_index = n;

    return NGX_OK;
}


static void *
ngx_http_userid_create_conf(ngx_conf_t *cf)
{
    ngx_http_userid_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_userid_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->name = { 0, NULL };
     *     conf->domain = { 0, NULL };
     *     conf->path = { 0, NULL };
     *     conf->p3p = { 0, NULL };
     */

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->service = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;
    conf->mark = (u_char) '\xFF';

    return conf;
}


static char *
ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_userid_conf_t *prev = parent;
    ngx_http_userid_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable,
                              NGX_HTTP_USERID_OFF);

    ngx_conf_merge_str_value(conf->name, prev->name, "uid");
    ngx_conf_merge_str_value(conf->domain, prev->domain, "");
    ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
    ngx_conf_merge_str_value(conf->p3p, prev->p3p, "");

    ngx_conf_merge_value(conf->service, prev->service, NGX_CONF_UNSET);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->mark == (u_char) '\xFF') {
        if (prev->mark == (u_char) '\xFF') {
            conf->mark = '\0';
        } else {
            conf->mark = prev->mark;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_userid_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_userid_filter;

    return NGX_OK;
}


static char *
ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *domain = data;

    u_char  *p, *new;

    if (ngx_strcmp(domain->data, "none") == 0) {
        ngx_str_set(domain, "");
        return NGX_CONF_OK;
    }

    new = ngx_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    ngx_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *path = data;

    u_char  *p, *new;

    new = ngx_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
    ngx_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_userid_conf_t *ucf = conf;

    ngx_str_t  *value;

    if (ucf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NGX_HTTP_USERID_MAX_EXPIRES;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NGX_CONF_OK;
    }

    ucf->expires = ngx_parse_time(&value[1], 1);
    if (ucf->expires == (time_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *p3p = data;

    if (ngx_strcmp(p3p->data, "none") == 0) {
        ngx_str_set(p3p, "");
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_userid_conf_t *ucf = conf;

    ngx_str_t  *value;

    if (ucf->mark != (u_char) '\xFF') {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ucf->mark = '\0';
        return NGX_CONF_OK;
    }

    if (value[1].len != 1
        || !((value[1].data[0] >= '0' && value[1].data[0] <= '9')
              || (value[1].data[0] >= 'A' && value[1].data[0] <= 'Z')
              || (value[1].data[0] >= 'a' && value[1].data[0] <= 'z')
              || value[1].data[0] == '='))
    {
        return "value must be \"off\" or a single letter, digit or \"=\"";
    }

    ucf->mark = value[1].data[0];

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_userid_init_worker(ngx_cycle_t *cycle)
{
    struct timeval  tp;

    ngx_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | ngx_pid;

    return NGX_OK;
}
