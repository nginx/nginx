
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>


#define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_DEFAULT_ECDH_CURVE  "auto"


static void *ngx_mail_ssl_create_conf(ngx_conf_t *cf);
static char *ngx_mail_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_mail_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_ssl_starttls(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_mail_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_enum_t  ngx_mail_starttls_state[] = {
    { ngx_string("off"), NGX_MAIL_STARTTLS_OFF },
    { ngx_string("on"), NGX_MAIL_STARTTLS_ON },
    { ngx_string("only"), NGX_MAIL_STARTTLS_ONLY },
    { ngx_null_string, 0 }
};



static ngx_conf_bitmask_t  ngx_mail_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_mail_ssl_verify[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("optional"), 2 },
    { ngx_string("optional_no_ca"), 3 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_mail_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_mail_ssl_enable,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, enable),
      NULL },

    { ngx_string("starttls"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_mail_ssl_starttls,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, starttls),
      ngx_mail_starttls_state },

    { ngx_string("ssl_certificate"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, certificates),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, certificate_keys),
      NULL },

    { ngx_string("ssl_password_file"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_mail_ssl_password_file,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, dhparam),
      NULL },

    { ngx_string("ssl_ecdh_curve"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, ecdh_curve),
      NULL },

    { ngx_string("ssl_protocols"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, protocols),
      &ngx_mail_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_session_cache"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE12,
      ngx_mail_ssl_session_cache,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_tickets"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, session_tickets),
      NULL },

    { ngx_string("ssl_session_ticket_key"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, session_ticket_keys),
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, session_timeout),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, verify),
      &ngx_mail_ssl_verify },

    { ngx_string("ssl_verify_depth"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_trusted_certificate"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, trusted_certificate),
      NULL },

    { ngx_string("ssl_crl"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_ssl_conf_t, crl),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_ssl_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_ssl_create_conf,              /* create server configuration */
    ngx_mail_ssl_merge_conf                /* merge server configuration */
};


ngx_module_t  ngx_mail_ssl_module = {
    NGX_MODULE_V1,
    &ngx_mail_ssl_module_ctx,              /* module context */
    ngx_mail_ssl_commands,                 /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t ngx_mail_ssl_sess_id_ctx = ngx_string("MAIL");


static void *
ngx_mail_ssl_create_conf(ngx_conf_t *cf)
{
    ngx_mail_ssl_conf_t  *scf;

    scf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     scf->protocols = 0;
     *     scf->dhparam = { 0, NULL };
     *     scf->ecdh_curve = { 0, NULL };
     *     scf->client_certificate = { 0, NULL };
     *     scf->trusted_certificate = { 0, NULL };
     *     scf->crl = { 0, NULL };
     *     scf->ciphers = { 0, NULL };
     *     scf->shm_zone = NULL;
     */

    scf->enable = NGX_CONF_UNSET;
    scf->starttls = NGX_CONF_UNSET_UINT;
    scf->certificates = NGX_CONF_UNSET_PTR;
    scf->certificate_keys = NGX_CONF_UNSET_PTR;
    scf->passwords = NGX_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = NGX_CONF_UNSET;
    scf->verify = NGX_CONF_UNSET_UINT;
    scf->verify_depth = NGX_CONF_UNSET_UINT;
    scf->builtin_session_cache = NGX_CONF_UNSET;
    scf->session_timeout = NGX_CONF_UNSET;
    scf->session_tickets = NGX_CONF_UNSET;
    scf->session_ticket_keys = NGX_CONF_UNSET_PTR;

    return scf;
}


static char *
ngx_mail_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_ssl_conf_t *prev = parent;
    ngx_mail_ssl_conf_t *conf = child;

    char                *mode;
    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->starttls, prev->starttls,
                         NGX_MAIL_STARTTLS_OFF);

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                          |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NGX_DEFAULT_ECDH_CURVE);

    ngx_conf_merge_str_value(conf->client_certificate,
                         prev->client_certificate, "");
    ngx_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);


    conf->ssl.log = cf->log;

    if (conf->enable) {
        mode = "ssl";

    } else if (conf->starttls != NGX_MAIL_STARTTLS_OFF) {
        mode = "starttls";

    } else {
        mode = "";
    }

    if (conf->file == NULL) {
        conf->file = prev->file;
        conf->line = prev->line;
    }

    if (*mode) {

        if (conf->certificates == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"%s\" directive in %s:%ui",
                          mode, conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_keys == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"%s\" directive in %s:%ui",
                          mode, conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_keys->nelts < conf->certificates->nelts) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\" and "
                          "the \"%s\" directive in %s:%ui",
                          ((ngx_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1,
                          mode, conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

    } else {

        if (conf->certificates == NULL) {
            return NGX_CONF_OK;
        }

        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((ngx_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_create(&conf->ssl, conf->protocols, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
                             conf->certificate_keys, conf->passwords)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_client_verify");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
                                        &conf->trusted_certificate,
                                        conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (ngx_ssl_session_cache(&conf->ssl, &ngx_mail_ssl_sess_id_ctx,
                              conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    ngx_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_mail_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (scf->enable && (ngx_int_t) scf->starttls > NGX_MAIL_STARTTLS_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"starttls\" directive conflicts with \"ssl on\"");
        return NGX_CONF_ERROR;
    }

    scf->file = cf->conf_file->file.name.data;
    scf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_mail_ssl_starttls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = ngx_conf_set_enum_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (scf->enable == 1 && (ngx_int_t) scf->starttls > NGX_MAIL_STARTTLS_OFF) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"ssl\" directive conflicts with \"starttls\"");
        return NGX_CONF_ERROR;
    }

    scf->file = cf->conf_file->file.name.data;
    scf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_mail_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_ssl_conf_t  *scf = conf;

    ngx_str_t  *value;

    if (scf->passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_mail_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_ssl_conf_t  *scf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = NGX_SSL_NO_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            scf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            scf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_mail_ssl_module);
            if (scf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            scf->shm_zone->init = ngx_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == NGX_CONF_UNSET) {
        scf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}
