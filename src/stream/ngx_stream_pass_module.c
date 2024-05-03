
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


#define NGX_STREAM_PASS_MAX_PASSES  10


typedef struct {
    ngx_addr_t                  *addr;
    ngx_stream_complex_value_t  *addr_value;
} ngx_stream_pass_srv_conf_t;


static void ngx_stream_pass_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_pass_check_cycle(ngx_connection_t *c);
static void ngx_stream_pass_cleanup(void *data);
static ngx_int_t ngx_stream_pass_match(ngx_listening_t *ls, ngx_addr_t *addr);
static void *ngx_stream_pass_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_pass_commands[] = {

    { ngx_string("pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_pass_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_pass_create_srv_conf,       /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_pass_module = {
    NGX_MODULE_V1,
    &ngx_stream_pass_module_ctx,           /* module context */
    ngx_stream_pass_commands,              /* module directives */
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


static void
ngx_stream_pass_handler(ngx_stream_session_t *s)
{
    ngx_url_t                    u;
    ngx_str_t                    url;
    ngx_addr_t                  *addr;
    ngx_uint_t                   i;
    ngx_listening_t             *ls;
    ngx_connection_t            *c;
    ngx_stream_pass_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "passing connection to port";

    if (c->type == SOCK_DGRAM) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "cannot pass udp connection");
        goto failed;
    }

    if (c->buffer && c->buffer->pos != c->buffer->last) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "cannot pass connection with preread data");
        goto failed;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_pass_module);

    addr = pscf->addr;

    if (addr == NULL) {
        if (ngx_stream_complex_value(s, pscf->addr_value, &url) != NGX_OK) {
            goto failed;
        }

        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url = url;
        u.no_resolve = 1;

        if (ngx_parse_url(c->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "%s in pass \"%V\"", u.err, &u.url);
            }

            goto failed;
        }

        if (u.naddrs == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no addresses in pass \"%V\"", &u.url);
            goto failed;
        }

        if (u.no_port) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no port in pass \"%V\"", &u.url);
            goto failed;
        }

        addr = &u.addrs[0];
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream pass addr: \"%V\"", &addr->name);

    if (ngx_stream_pass_check_cycle(c) != NGX_OK) {
        goto failed;
    }

    ls = ngx_cycle->listening.elts;

    for (i = 0; i < ngx_cycle->listening.nelts; i++) {

        if (ngx_stream_pass_match(&ls[i], addr) != NGX_OK) {
            continue;
        }

        c->listening = &ls[i];

        c->data = NULL;
        c->buffer = NULL;

        *c->log = c->listening->log;
        c->log->handler = NULL;
        c->log->data = NULL;

        c->local_sockaddr = addr->sockaddr;
        c->local_socklen = addr->socklen;

        c->listening->handler(c);

        return;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "port not found for \"%V\"", &addr->name);

    ngx_stream_finalize_session(s, NGX_STREAM_OK);

    return;

failed:

    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}


static ngx_int_t
ngx_stream_pass_check_cycle(ngx_connection_t *c)
{
    ngx_uint_t          *num;
    ngx_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != ngx_stream_pass_cleanup) {
            continue;
        }

        num = cln->data;

        if (++(*num) > NGX_STREAM_PASS_MAX_PASSES) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "stream pass cycle");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_uint_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_stream_pass_cleanup;

    num = cln->data;
    *num = 1;

    return NGX_OK;
}


static void
ngx_stream_pass_cleanup(void *data)
{
    return;
}


static ngx_int_t
ngx_stream_pass_match(ngx_listening_t *ls, ngx_addr_t *addr)
{
    if (ls->type == SOCK_DGRAM) {
        return NGX_DECLINED;
    }

    if (!ls->wildcard) {
        return ngx_cmp_sockaddr(ls->sockaddr, ls->socklen,
                                addr->sockaddr, addr->socklen, 1);
    }

    if (ls->sockaddr->sa_family == addr->sockaddr->sa_family
        && ngx_inet_get_port(ls->sockaddr) == ngx_inet_get_port(addr->sockaddr))
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static void *
ngx_stream_pass_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_pass_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_pass_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->addr = NULL;
     *     conf->addr_value = NULL;
     */

    return conf;
}


static char *
ngx_stream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_pass_srv_conf_t *pscf = conf;

    ngx_url_t                            u;
    ngx_str_t                           *value, *url;
    ngx_stream_complex_value_t           cv;
    ngx_stream_core_srv_conf_t          *cscf;
    ngx_stream_compile_complex_value_t   ccv;

    if (pscf->addr || pscf->addr_value) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_pass_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->addr_value = ngx_palloc(cf->pool,
                                      sizeof(ngx_stream_complex_value_t));
        if (pscf->addr_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *pscf->addr_value = cv;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"pass\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    if (u.naddrs == 0) {
        return "has no addresses";
    }

    if (u.no_port) {
        return "has no port";
    }

    pscf->addr = &u.addrs[0];

    return NGX_CONF_OK;
}
