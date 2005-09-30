
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_imap.h>


#define NGX_DEFLAUT_CERTIFICATE      "cert.pem"
#define NGX_DEFLAUT_CERTIFICATE_KEY  "cert.pem"
#define NGX_DEFLAUT_CIPHERS  "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"


static void *ngx_imap_ssl_create_conf(ngx_conf_t *cf);
static char *ngx_imap_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_conf_bitmask_t  ngx_imap_ssl_protocols[] = { 
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_null_string, 0 }
};


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

    { ngx_string("ssl_protocols"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_bitmask_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, protocols),
      &ngx_imap_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_IMAP_MAIN_CONF|NGX_IMAP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_IMAP_SRV_CONF_OFFSET,
      offsetof(ngx_imap_ssl_conf_t, prefer_server_ciphers),
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
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char ngx_imap_session_id_ctx[] = "IMAP";


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
     *     scf->protocols = 0;
     *
     *     scf->certificate.len = 0;
     *     scf->certificate.data = NULL;
     *     scf->certificate_key.len = 0;
     *     scf->certificate_key.data = NULL;
     *     scf->ciphers.len = 0;
     *     scf->ciphers.data = NULL;
     */

    scf->enable = NGX_CONF_UNSET;
    scf->prefer_server_ciphers = NGX_CONF_UNSET;

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

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET
                          |NGX_SSL_SSLv2|NGX_SSL_SSLv3|NGX_SSL_TLSv1));

    ngx_conf_merge_str_value(conf->certificate, prev->certificate,
                             NGX_DEFLAUT_CERTIFICATE);

    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key,
                             NGX_DEFLAUT_CERTIFICATE_KEY);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFLAUT_CIPHERS);


    conf->ssl.log = cf->log;

    if (ngx_ssl_create(&conf->ssl, conf->protocols) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_pool_cleanup_add(cf->pool, ngx_ssl_cleanup_ctx, &conf->ssl) == NULL)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_certificate(&conf->ssl, conf->certificate.data,
                            conf->certificate_key.data) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->ciphers.len) {
        if (SSL_CTX_set_cipher_list(conf->ssl.ctx,
                                   (const char *) conf->ciphers.data) == 0)
        {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "SSL_CTX_set_cipher_list(\"%V\") failed",
                          &conf->ciphers);
        }
    }

    if (ngx_ssl_generate_rsa512_key(&conf->ssl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    SSL_CTX_set_session_cache_mode(conf->ssl.ctx, SSL_SESS_CACHE_SERVER);

    SSL_CTX_set_session_id_context(conf->ssl.ctx, ngx_imap_session_id_ctx,
                                   sizeof(ngx_imap_session_id_ctx) - 1);

    return NGX_CONF_OK;
}
