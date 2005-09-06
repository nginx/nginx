
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_imap.h>


#define NGX_DEFLAUT_CERTIFICATE      "cert.pem"
#define NGX_DEFLAUT_CERTIFICATE_KEY  "cert.pem"


static void *ngx_imap_ssl_create_conf(ngx_conf_t *cf);
static char *ngx_imap_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_imap_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, certificate_key),
      NULL },

    { ngx_string("ssl_ciphers"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, ciphers),
      NULL },

      ngx_null_command
};


static ngx_imap_module_t  ngx_imap_ssl_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_imap_ssl_create_conf,              /* create server configuration */
    ngx_imap_ssl_merge_conf                /* merge server configuration */
};


ngx_module_t  ngx_imap_ssl_module = {
    NGX_MODULE_V1,
    &ngx_imap_ssl_module_ctx,              /* module context */
    ngx_imap_ssl_commands,                 /* module directives */
    NGX_IMAP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};


static void *
ngx_imap_ssl_create_conf(ngx_conf_t *cf)
{           
    ngx_imap_ssl_conf_t  *scf;
            
    scf = ngx_pcalloc(cf->pool, sizeof(ngx_imap_ssl_conf_t));
    if (scf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():  
     *
     *     scf->certificate.len = 0;
     *     scf->certificate.data = NULL;
     *     scf->certificate_key.len = 0;
     *     scf->certificate_key.data = NULL;
     *     scf->ciphers.len = 0;
     *     scf->ciphers.data = NULL;
     */

    scf->enable = NGX_CONF_UNSET;

    return scf;
}


static char *
ngx_imap_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_imap_ssl_conf_t *prev = parent;
    ngx_imap_ssl_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    if (conf->enable == 0) {
        return NGX_CONF_OK;
    }

    ngx_conf_merge_str_value(conf->certificate, prev->certificate,
                             NGX_DEFLAUT_CERTIFICATE);

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key,
                             NGX_DEFLAUT_CERTIFICATE_KEY);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, "");


    /* TODO: configure methods */

    conf->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    if (conf->ssl_ctx == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_new() failed");
        return NGX_CONF_ERROR;
    }

    if (ngx_pool_cleanup_add(cf->pool, ngx_ssl_cleanup_ctx, conf->ssl_ctx)
        == NULL)
    {
        return NGX_CONF_ERROR;
    }


#if 0
    SSL_CTX_set_options(conf->ssl_ctx, SSL_OP_ALL);
    SSL_CTX_set_options(conf->ssl_ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(conf->ssl_ctx, SSL_OP_SINGLE_DH_USE);
#endif

    if (conf->ciphers.len) {
        if (SSL_CTX_set_cipher_list(conf->ssl_ctx,
                                   (const char *) conf->ciphers.data) == 0)
        {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "SSL_CTX_set_cipher_list(\"%V\") failed",
                          &conf->ciphers);
        }
    }

    if (SSL_CTX_use_certificate_chain_file(conf->ssl_ctx,
                                         (char *) conf->certificate.data) == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_use_certificate_chain_file(\"%s\") failed",
                      conf->certificate.data);
        return NGX_CONF_ERROR;
    }


    if (SSL_CTX_use_PrivateKey_file(conf->ssl_ctx,
                                    (char *) conf->certificate_key.data,
                                    SSL_FILETYPE_PEM) == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_use_PrivateKey_file(\"%s\") failed",
                      conf->certificate_key.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
