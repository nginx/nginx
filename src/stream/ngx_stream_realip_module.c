
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_array_t       *from;     /* array of ngx_cidr_t */
} ngx_stream_realip_srv_conf_t;


typedef struct {
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    ngx_str_t          addr_text;
} ngx_stream_realip_ctx_t;


static ngx_int_t ngx_stream_realip_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_realip_set_addr(ngx_stream_session_t *s,
    ngx_addr_t *addr);
static char *ngx_stream_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_stream_realip_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_realip_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_realip_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_stream_realip_init(ngx_conf_t *cf);


static ngx_int_t ngx_stream_realip_remote_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_realip_remote_port_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_stream_realip_commands[] = {

    { ngx_string("set_real_ip_from"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_realip_from,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_realip_module_ctx = {
    ngx_stream_realip_add_variables,       /* preconfiguration */
    ngx_stream_realip_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_realip_create_srv_conf,     /* create server configuration */
    ngx_stream_realip_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_stream_realip_module = {
    NGX_MODULE_V1,
    &ngx_stream_realip_module_ctx,         /* module context */
    ngx_stream_realip_commands,            /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_realip_vars[] = {

    { ngx_string("realip_remote_addr"), NULL,
      ngx_stream_realip_remote_addr_variable, 0, 0, 0 },

    { ngx_string("realip_remote_port"), NULL,
      ngx_stream_realip_remote_port_variable, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_stream_realip_handler(ngx_stream_session_t *s)
{
    ngx_addr_t                     addr;
    ngx_connection_t              *c;
    ngx_stream_realip_srv_conf_t  *rscf;

    rscf = ngx_stream_get_module_srv_conf(s, ngx_stream_realip_module);

    if (rscf->from == NULL) {
        return NGX_DECLINED;
    }

    c = s->connection;

    if (c->proxy_protocol_addr.len == 0) {
        return NGX_DECLINED;
    }

    if (ngx_cidr_match(c->sockaddr, rscf->from) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_parse_addr(c->pool, &addr, c->proxy_protocol_addr.data,
                       c->proxy_protocol_addr.len)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ngx_inet_set_port(addr.sockaddr, c->proxy_protocol_port);

    return ngx_stream_realip_set_addr(s, &addr);
}


static ngx_int_t
ngx_stream_realip_set_addr(ngx_stream_session_t *s, ngx_addr_t *addr)
{
    size_t                    len;
    u_char                   *p;
    u_char                    text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t         *c;
    ngx_stream_realip_ctx_t  *ctx;

    c = s->connection;

    ctx = ngx_palloc(c->pool, sizeof(ngx_stream_realip_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NGX_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, text, len);

    ngx_stream_set_ctx(s, ctx, ngx_stream_realip_module);

    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


static char *
ngx_stream_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_realip_srv_conf_t *rscf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t              *cidr;

    value = cf->args->elts;

    if (rscf->from == NULL) {
        rscf->from = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (rscf->from == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(rscf->from);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    return NGX_CONF_OK;
}


static void *
ngx_stream_realip_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_realip_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_realip_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->from = NULL;
     */

    return conf;
}


static char *
ngx_stream_realip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_realip_srv_conf_t *prev = parent;
    ngx_stream_realip_srv_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_realip_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_realip_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_realip_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    cmcf->realip_handler = ngx_stream_realip_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_realip_remote_addr_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                *addr_text;
    ngx_stream_realip_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_realip_module);

    addr_text = ctx ? &ctx->addr_text : &s->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_realip_remote_port_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t                port;
    struct sockaddr          *sa;
    ngx_stream_realip_ctx_t  *ctx;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_realip_module);

    sa = ctx ? ctx->sockaddr : s->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    port = ngx_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}
