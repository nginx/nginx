
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_DEFLAUT_CERTIFICATE      "cert.pem"
#define NGX_DEFLAUT_CERTIFICATE_KEY  "cert.pem"


static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
                                         void *parent, void *child);


static ngx_command_t  ngx_http_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_key),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_module = {
    NGX_MODULE,
    &ngx_http_ssl_module_ctx,              /* module context */
    ngx_http_ssl_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *scf;

    if (!(scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    scf->enable = NGX_CONF_UNSET;

    return scf;
}


static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
                                         void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->enable == 0) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_str_value(conf->certificate, prev->certificate,
                             NGX_DEFLAUT_CERTIFICATE);

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key,
                             NGX_DEFLAUT_CERTIFICATE_KEY);

    /* TODO: configure methods */

    conf->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    if (conf->ssl_ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_new() failed");
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_use_certificate_file(conf->ssl_ctx,
                                     (char *) conf->certificate.data,
                                     SSL_FILETYPE_PEM) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_use_certificate_file(\"%s\") failed",
                      conf->certificate.data);
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(conf->ssl_ctx,
                                    (char *) conf->certificate_key.data,
                                    SSL_FILETYPE_PEM) == 0) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_use_PrivateKey_file(\"%s\") failed",
                      conf->certificate_key.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if 0

static ngx_int_t ngx_http_ssl_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        sscf = cscfp[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->enable) {
            cscfp[i]->recv = ngx_ssl_recv;
            cscfp[i]->send_chain = ngx_ssl_send_chain;
        }
    }

    return NGX_OK;
}

#endif
