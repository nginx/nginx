
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


static ngx_int_t ngx_stream_variable_quic(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_quic_add_variables(ngx_conf_t *cf);
static void *ngx_stream_quic_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_quic_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_quic_mtu(ngx_conf_t *cf, void *post, void *data);
static char *ngx_stream_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_conf_post_t  ngx_stream_quic_mtu_post =
    { ngx_stream_quic_mtu };

static ngx_command_t  ngx_stream_quic_commands[] = {

    { ngx_string("quic_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, timeout),
      NULL },

    { ngx_string("quic_mtu"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, mtu),
      &ngx_stream_quic_mtu_post },

    { ngx_string("quic_stream_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, stream_buffer_size),
      NULL },

    { ngx_string("quic_retry"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, retry),
      NULL },

    { ngx_string("quic_gso"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, gso_enabled),
      NULL },

    { ngx_string("quic_host_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_quic_host_key,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("quic_active_connection_id_limit"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, active_connection_id_limit),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_quic_module_ctx = {
    ngx_stream_quic_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_quic_create_srv_conf,       /* create server configuration */
    ngx_stream_quic_merge_srv_conf,        /* merge server configuration */
};


ngx_module_t  ngx_stream_quic_module = {
    NGX_MODULE_V1,
    &ngx_stream_quic_module_ctx,           /* module context */
    ngx_stream_quic_commands,              /* module directives */
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


static ngx_stream_variable_t  ngx_stream_quic_vars[] = {

    { ngx_string("quic"), NULL, ngx_stream_variable_quic, 0, 0, 0 },

      ngx_stream_null_variable
};

static ngx_str_t  ngx_stream_quic_salt = ngx_string("ngx_quic");


static ngx_int_t
ngx_stream_variable_quic(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (s->connection->quic) {

        v->len = 4;
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        v->data = (u_char *) "quic";
        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_quic_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_quic_vars; v->name.len; v++) {
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
ngx_stream_quic_create_srv_conf(ngx_conf_t *cf)
{
    ngx_quic_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_quic_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->host_key = { 0, NULL }
     *     conf->stream_close_code = 0;
     *     conf->stream_reject_code_uni = 0;
     *     conf->stream_reject_code_bidi= 0;
     */

    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->mtu = NGX_CONF_UNSET_SIZE;
    conf->stream_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_concurrent_streams_bidi = NGX_CONF_UNSET_UINT;
    conf->max_concurrent_streams_uni = NGX_CONF_UNSET_UINT;

    conf->retry = NGX_CONF_UNSET;
    conf->gso_enabled = NGX_CONF_UNSET;

    conf->active_connection_id_limit = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_quic_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_quic_conf_t *prev = parent;
    ngx_quic_conf_t *conf = child;

    ngx_stream_ssl_conf_t  *scf;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    ngx_conf_merge_size_value(conf->mtu, prev->mtu,
                              NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

    ngx_conf_merge_size_value(conf->stream_buffer_size,
                              prev->stream_buffer_size,
                              65536);

    ngx_conf_merge_uint_value(conf->max_concurrent_streams_bidi,
                              prev->max_concurrent_streams_bidi, 16);

    ngx_conf_merge_uint_value(conf->max_concurrent_streams_uni,
                              prev->max_concurrent_streams_uni, 3);

    ngx_conf_merge_value(conf->retry, prev->retry, 0);
    ngx_conf_merge_value(conf->gso_enabled, prev->gso_enabled, 0);

    ngx_conf_merge_str_value(conf->host_key, prev->host_key, "");

    ngx_conf_merge_uint_value(conf->active_connection_id_limit,
                              conf->active_connection_id_limit,
                              2);

    if (conf->host_key.len == 0) {

        conf->host_key.len = NGX_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->host_key.data = ngx_palloc(cf->pool, conf->host_key.len);
        if (conf->host_key.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (RAND_bytes(conf->host_key.data, NGX_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_quic_derive_key(cf->log, "av_token_key",
                            &conf->host_key, &ngx_stream_quic_salt,
                            conf->av_token_key, NGX_QUIC_AV_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_quic_derive_key(cf->log, "sr_token_key",
                            &conf->host_key, &ngx_stream_quic_salt,
                            conf->sr_token_key, NGX_QUIC_SR_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    scf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_ssl_module);
    conf->ssl = &scf->ssl;

    return NGX_CONF_OK;
}


static char *
ngx_stream_quic_mtu(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_QUIC_MIN_INITIAL_SIZE
        || *sp > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"quic_mtu\" must be between %d and %d",
                           NGX_QUIC_MIN_INITIAL_SIZE,
                           NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_quic_conf_t  *qcf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    ngx_str_t        *value;
    ngx_file_t        file;
    ngx_file_info_t   fi;

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
