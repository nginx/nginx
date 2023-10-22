
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_v3_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_v3_add_variables(ngx_conf_t *cf);
static void *ngx_http_v3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_v3_commands[] = {

    { ngx_string("http3"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, enable),
      NULL },

    { ngx_string("http3_hq"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, enable_hq),
      NULL },

    { ngx_string("http3_max_concurrent_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_concurrent_streams),
      NULL },

    { ngx_string("http3_stream_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.stream_buffer_size),
      NULL },

    { ngx_string("quic_retry"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.retry),
      NULL },

    { ngx_string("quic_gso"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.gso_enabled),
      NULL },

    { ngx_string("quic_host_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_quic_host_key,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("quic_active_connection_id_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.active_connection_id_limit),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_v3_module_ctx = {
    ngx_http_v3_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_v3_create_srv_conf,           /* create server configuration */
    ngx_http_v3_merge_srv_conf,            /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_v3_module = {
    NGX_MODULE_V1,
    &ngx_http_v3_module_ctx,               /* module context */
    ngx_http_v3_commands,                  /* module directives */
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


static ngx_http_variable_t  ngx_http_v3_vars[] = {

    { ngx_string("http3"), NULL, ngx_http_v3_variable, 0, 0, 0 },

      ngx_http_null_variable
};

static ngx_str_t  ngx_http_quic_salt = ngx_string("ngx_quic");


static ngx_int_t
ngx_http_v3_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_v3_session_t  *h3c;

    if (r->connection->quic) {
        h3c = ngx_http_v3_get_session(r->connection);

        if (h3c->hq) {
            v->len = sizeof("hq") - 1;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = (u_char *) "hq";

            return NGX_OK;
        }

        v->len = sizeof("h3") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h3";

        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_v3_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_v3_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_v3_srv_conf_t  *h3scf;

    h3scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_srv_conf_t));
    if (h3scf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     h3scf->quic.host_key = { 0, NULL }
     *     h3scf->quic.stream_reject_code_uni = 0;
     *     h3scf->quic.disable_active_migration = 0;
     *     h3scf->quic.idle_timeout = 0;
     *     h3scf->max_blocked_streams = 0;
     */

    h3scf->enable = NGX_CONF_UNSET;
    h3scf->enable_hq = NGX_CONF_UNSET;
    h3scf->max_table_capacity = NGX_HTTP_V3_MAX_TABLE_CAPACITY;
    h3scf->max_concurrent_streams = NGX_CONF_UNSET_UINT;

    h3scf->quic.stream_buffer_size = NGX_CONF_UNSET_SIZE;
    h3scf->quic.max_concurrent_streams_bidi = NGX_CONF_UNSET_UINT;
    h3scf->quic.max_concurrent_streams_uni = NGX_HTTP_V3_MAX_UNI_STREAMS;
    h3scf->quic.retry = NGX_CONF_UNSET;
    h3scf->quic.gso_enabled = NGX_CONF_UNSET;
    h3scf->quic.stream_close_code = NGX_HTTP_V3_ERR_NO_ERROR;
    h3scf->quic.stream_reject_code_bidi = NGX_HTTP_V3_ERR_REQUEST_REJECTED;
    h3scf->quic.active_connection_id_limit = NGX_CONF_UNSET_UINT;

    h3scf->quic.init = ngx_http_v3_init;
    h3scf->quic.shutdown = ngx_http_v3_shutdown;

    return h3scf;
}


static char *
ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v3_srv_conf_t *prev = parent;
    ngx_http_v3_srv_conf_t *conf = child;

    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_conf_merge_value(conf->enable, prev->enable, 1);

    ngx_conf_merge_value(conf->enable_hq, prev->enable_hq, 0);

    ngx_conf_merge_uint_value(conf->max_concurrent_streams,
                              prev->max_concurrent_streams, 128);

    conf->max_blocked_streams = conf->max_concurrent_streams;

    ngx_conf_merge_size_value(conf->quic.stream_buffer_size,
                              prev->quic.stream_buffer_size,
                              65536);

    conf->quic.max_concurrent_streams_bidi = conf->max_concurrent_streams;

    ngx_conf_merge_value(conf->quic.retry, prev->quic.retry, 0);
    ngx_conf_merge_value(conf->quic.gso_enabled, prev->quic.gso_enabled, 0);

    ngx_conf_merge_str_value(conf->quic.host_key, prev->quic.host_key, "");

    ngx_conf_merge_uint_value(conf->quic.active_connection_id_limit,
                              prev->quic.active_connection_id_limit,
                              2);

    if (conf->quic.host_key.len == 0) {

        conf->quic.host_key.len = NGX_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->quic.host_key.data = ngx_palloc(cf->pool,
                                              conf->quic.host_key.len);
        if (conf->quic.host_key.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (RAND_bytes(conf->quic.host_key.data, NGX_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_quic_derive_key(cf->log, "av_token_key",
                            &conf->quic.host_key, &ngx_http_quic_salt,
                            conf->quic.av_token_key, NGX_QUIC_AV_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_quic_derive_key(cf->log, "sr_token_key",
                            &conf->quic.host_key, &ngx_http_quic_salt,
                            conf->quic.sr_token_key, NGX_QUIC_SR_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    conf->quic.handshake_timeout = cscf->client_header_timeout;

    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    conf->quic.ssl = &sscf->ssl;

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v3_srv_conf_t  *h3scf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    ngx_str_t        *value;
    ngx_file_t        file;
    ngx_file_info_t   fi;
    ngx_quic_conf_t  *qcf;

    qcf = &h3scf->quic;

    if (qcf->host_key.len) {
        return "is duplicate";
    }

    buf = NULL;
#if (NGX_SUPPRESS_WARN)
    size = 0;
#endif

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = value[1];
    file.log = cf->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &file.name);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &file.name);
        goto failed;
    }

    size = ngx_file_size(&fi);

    if (size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" zero key size", &file.name);
        goto failed;
    }

    buf = ngx_pnalloc(cf->pool, size);
    if (buf == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, buf, size, 0);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed", &file.name);
        goto failed;
    }

    if ((size_t) n != size) {
        ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
                           ngx_read_file_n " \"%V\" returned only "
                           "%z bytes instead of %uz", &file.name, n, size);
        goto failed;
    }

    qcf->host_key.data = buf;
    qcf->host_key.len = n;

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &file.name);
    }

    return NGX_CONF_OK;

failed:

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &file.name);
    }

    if (buf) {
        ngx_explicit_memzero(buf, size);
    }

    return NGX_CONF_ERROR;
}
