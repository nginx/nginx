
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_REALIP_XREALIP  0
#define NGX_HTTP_REALIP_XFWD     1
#define NGX_HTTP_REALIP_HEADER   2


typedef struct {
    in_addr_t          mask;
    in_addr_t          addr;
} ngx_http_realip_from_t;


typedef struct {
    ngx_array_t       *from;     /* array of ngx_http_realip_from_t */
    ngx_uint_t         type;
    ngx_uint_t         hash;
    ngx_str_t          header;
} ngx_http_realip_loc_conf_t;


typedef struct {
    ngx_connection_t  *connection;
    in_addr_t          addr;
    ngx_str_t          addr_text;
} ngx_http_realip_ctx_t;


static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
static void ngx_http_realip_cleanup(void *data);
static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_realip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



static ngx_http_module_t  ngx_http_realip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_realip_create_loc_conf,       /* create location configuration */
    ngx_http_realip_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_realip_module_ctx,           /* module context */
    ngx_http_realip_commands,              /* module directives */
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


static ngx_int_t
ngx_http_realip_handler(ngx_http_request_t *r)
{
    u_char                      *ip, *p;
    size_t                       len;
    in_addr_t                    addr;
    ngx_uint_t                   i, hash;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *header;
    struct sockaddr_in          *sin;
    ngx_connection_t            *c;
    ngx_pool_cleanup_t          *cln;
    ngx_http_realip_ctx_t       *ctx;
    ngx_http_realip_from_t      *from;
    ngx_http_realip_loc_conf_t  *rlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_realip_module);

    if (ctx) {
        return NGX_DECLINED;
    }

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_realip_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);

    if (rlcf->from == NULL) {
        return NGX_DECLINED;
    }

    switch (rlcf->type) {

    case NGX_HTTP_REALIP_XREALIP:

        if (r->headers_in.x_real_ip == NULL) {
            return NGX_DECLINED;
        }

        len = r->headers_in.x_real_ip->value.len;
        ip = r->headers_in.x_real_ip->value.data;

        break;

    case NGX_HTTP_REALIP_XFWD:

        if (r->headers_in.x_forwarded_for == NULL) {
            return NGX_DECLINED;
        }

        len = r->headers_in.x_forwarded_for->value.len;
        ip = r->headers_in.x_forwarded_for->value.data;

        for (p = ip + len - 1; p > ip; p--) {
            if (*p == ' ' || *p == ',') {
                p++;
                len -= p - ip;
                ip = p;
                break;
            }
        }

        break;

    default: /* NGX_HTTP_REALIP_HEADER */

        part = &r->headers_in.headers.part;
        header = part->elts;

        hash = rlcf->hash;
        len = rlcf->header.len;
        p = rlcf->header.data;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (hash == header[i].hash
                && len == header[i].key.len
                && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                len = header[i].value.len;
                ip = header[i].value.data;

                goto found;
            }
        }

        return NGX_DECLINED;
    }

found:

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "realip: \"%s\"", ip);

    /* AF_INET only */

    if (r->connection->sockaddr->sa_family != AF_INET) {
        return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *) c->sockaddr;

    from = rlcf->from->elts;
    for (i = 0; i < rlcf->from->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "realip: %08XD %08XD %08XD",
                       sin->sin_addr.s_addr, from[i].mask, from[i].addr);

        if ((sin->sin_addr.s_addr & from[i].mask) == from[i].addr) {

            ctx = cln->data;

            ngx_http_set_ctx(r, ctx, ngx_http_realip_module);

            addr = inet_addr((char *) ip);

            if (addr == INADDR_NONE) {
                return NGX_DECLINED;
            }

            p = ngx_pnalloc(c->pool, len);
            if (p == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_memcpy(p, ip, len);

            cln->handler = ngx_http_realip_cleanup;

            ctx->connection = c;
            ctx->addr = sin->sin_addr.s_addr;
            ctx->addr_text = c->addr_text;

            sin->sin_addr.s_addr = addr;

            c->addr_text.len = len;
            c->addr_text.data = p;

            return NGX_DECLINED;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_http_realip_cleanup(void *data)
{
    ngx_http_realip_ctx_t *ctx = data;

    ngx_connection_t    *c;
    struct sockaddr_in  *sin;

    c = ctx->connection;

    sin = (struct sockaddr_in *) c->sockaddr;
    sin->sin_addr.s_addr = ctx->addr;

    c->addr_text = ctx->addr_text;
}


static char *
ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t               cidr;
    ngx_http_realip_from_t  *from;

    if (rlcf->from == NULL) {
        rlcf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_http_realip_from_t));
        if (rlcf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    from = ngx_array_push(rlcf->from);
    if (from == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    rc = ngx_ptocidr(&value[1], &cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cidr.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"realip_from\" supports IPv4 only");
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    from->mask = cidr.u.in.mask;
    from->addr = cidr.u.in.addr;

    return NGX_CONF_OK;
}


static char *
ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_realip_loc_conf_t *rlcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XREALIP;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = NGX_HTTP_REALIP_XFWD;
        return NGX_CONF_OK;
    }

    rlcf->type = NGX_HTTP_REALIP_HEADER;
    rlcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return NGX_CONF_OK;
}


static void *
ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_realip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_realip_loc_conf_t  *prev = parent;
    ngx_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_REALIP_XREALIP);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_realip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_realip_handler;

    return NGX_OK;
}
