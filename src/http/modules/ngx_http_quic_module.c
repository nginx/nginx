
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_event_quic_protection.h>


static ngx_int_t ngx_http_variable_quic(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_quic_add_variables(ngx_conf_t *cf);
static void *ngx_http_quic_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_quic_max_ack_delay(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_quic_max_udp_payload_size(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_conf_post_t  ngx_http_quic_max_ack_delay_post =
    { ngx_http_quic_max_ack_delay };
static ngx_conf_post_t  ngx_http_quic_max_udp_payload_size_post =
    { ngx_http_quic_max_udp_payload_size };
static ngx_conf_num_bounds_t  ngx_http_quic_ack_delay_exponent_bounds =
    { ngx_conf_check_num_bounds, 0, 20 };
static ngx_conf_num_bounds_t  ngx_http_quic_active_connection_id_limit_bounds =
    { ngx_conf_check_num_bounds, 2, -1 };


static ngx_command_t  ngx_http_quic_commands[] = {

    { ngx_string("quic_max_idle_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.max_idle_timeout),
      NULL },

    { ngx_string("quic_max_ack_delay"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.max_ack_delay),
      &ngx_http_quic_max_ack_delay_post },

    { ngx_string("quic_max_udp_payload_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.max_udp_payload_size),
      &ngx_http_quic_max_udp_payload_size_post },

    { ngx_string("quic_initial_max_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_data),
      NULL },

    { ngx_string("quic_initial_max_stream_data_bidi_local"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_stream_data_bidi_local),
      NULL },

    { ngx_string("quic_initial_max_stream_data_bidi_remote"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_stream_data_bidi_remote),
      NULL },

    { ngx_string("quic_initial_max_stream_data_uni"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_stream_data_uni),
      NULL },

    { ngx_string("quic_initial_max_streams_bidi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_streams_bidi),
      NULL },

    { ngx_string("quic_initial_max_streams_uni"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.initial_max_streams_uni),
      NULL },

    { ngx_string("quic_ack_delay_exponent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.ack_delay_exponent),
      &ngx_http_quic_ack_delay_exponent_bounds },

    { ngx_string("quic_disable_active_migration"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.disable_active_migration),
      NULL },

    { ngx_string("quic_active_connection_id_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, tp.active_connection_id_limit),
      &ngx_http_quic_active_connection_id_limit_bounds },

    { ngx_string("quic_retry"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_quic_conf_t, retry),
      NULL },

    { ngx_string("quic_host_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_quic_host_key,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_quic_module_ctx = {
    ngx_http_quic_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_quic_create_srv_conf,         /* create server configuration */
    ngx_http_quic_merge_srv_conf,          /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_quic_module = {
    NGX_MODULE_V1,
    &ngx_http_quic_module_ctx,             /* module context */
    ngx_http_quic_commands,                /* module directives */
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


static ngx_http_variable_t  ngx_http_quic_vars[] = {

    { ngx_string("quic"), NULL, ngx_http_variable_quic, 0, 0, 0 },

      ngx_http_null_variable
};

static ngx_str_t  ngx_http_quic_salt = ngx_string("ngx_quic");


ngx_int_t
ngx_http_quic_init(ngx_connection_t *c)
{
    ngx_quic_conf_t           *qcf;
    ngx_http_connection_t     *hc, *phc;
    ngx_http_core_loc_conf_t  *clcf;

    hc = c->data;

    hc->ssl = 1;

    if (c->quic == NULL) {
        c->log->connection = c->number;

        qcf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_quic_module);

        ngx_quic_run(c, qcf);

        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http init quic stream");

    phc = c->quic->parent->data;

    if (phc->ssl_servername) {
        hc->ssl_servername = phc->ssl_servername;
        hc->conf_ctx = phc->conf_ctx;

        clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);
        ngx_set_connection_log(c, clcf->error_log);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_variable_quic(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->quic) {

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
ngx_http_quic_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_quic_vars; v->name.len; v++) {
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
ngx_http_quic_create_srv_conf(ngx_conf_t *cf)
{
    ngx_quic_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_quic_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->tp.original_dcid = { 0, NULL };
     *     conf->tp.initial_scid = { 0, NULL };
     *     conf->tp.retry_scid = { 0, NULL };
     *     conf->tp.sr_token = { 0 }
     *     conf->tp.sr_enabled = 0
     *     conf->tp.preferred_address = NULL
     *     conf->host_key = { 0, NULL }
     */

    conf->tp.max_idle_timeout = NGX_CONF_UNSET_MSEC;
    conf->tp.max_ack_delay = NGX_CONF_UNSET_MSEC;
    conf->tp.max_udp_payload_size = NGX_CONF_UNSET_SIZE;
    conf->tp.initial_max_data = NGX_CONF_UNSET_SIZE;
    conf->tp.initial_max_stream_data_bidi_local = NGX_CONF_UNSET_SIZE;
    conf->tp.initial_max_stream_data_bidi_remote = NGX_CONF_UNSET_SIZE;
    conf->tp.initial_max_stream_data_uni = NGX_CONF_UNSET_SIZE;
    conf->tp.initial_max_streams_bidi = NGX_CONF_UNSET_UINT;
    conf->tp.initial_max_streams_uni = NGX_CONF_UNSET_UINT;
    conf->tp.ack_delay_exponent = NGX_CONF_UNSET_UINT;
    conf->tp.disable_active_migration = NGX_CONF_UNSET;
    conf->tp.active_connection_id_limit = NGX_CONF_UNSET_UINT;

    conf->retry = NGX_CONF_UNSET;
    conf->require_alpn = 1;

    return conf;
}


static char *
ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_quic_conf_t *prev = parent;
    ngx_quic_conf_t *conf = child;

    ngx_http_ssl_srv_conf_t  *sscf;

    ngx_conf_merge_msec_value(conf->tp.max_idle_timeout,
                              prev->tp.max_idle_timeout, 60000);

    ngx_conf_merge_msec_value(conf->tp.max_ack_delay,
                              prev->tp.max_ack_delay,
                              NGX_QUIC_DEFAULT_MAX_ACK_DELAY);

    ngx_conf_merge_size_value(conf->tp.max_udp_payload_size,
                              prev->tp.max_udp_payload_size,
                              NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

    ngx_conf_merge_size_value(conf->tp.initial_max_data,
                              prev->tp.initial_max_data,
                              16 * NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_size_value(conf->tp.initial_max_stream_data_bidi_local,
                              prev->tp.initial_max_stream_data_bidi_local,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_size_value(conf->tp.initial_max_stream_data_bidi_remote,
                              prev->tp.initial_max_stream_data_bidi_remote,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_size_value(conf->tp.initial_max_stream_data_uni,
                              prev->tp.initial_max_stream_data_uni,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_uint_value(conf->tp.initial_max_streams_bidi,
                              prev->tp.initial_max_streams_bidi, 16);

    ngx_conf_merge_uint_value(conf->tp.initial_max_streams_uni,
                              prev->tp.initial_max_streams_uni, 16);

    ngx_conf_merge_uint_value(conf->tp.ack_delay_exponent,
                              prev->tp.ack_delay_exponent,
                              NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT);

    ngx_conf_merge_value(conf->tp.disable_active_migration,
                              prev->tp.disable_active_migration, 0);

    ngx_conf_merge_uint_value(conf->tp.active_connection_id_limit,
                              prev->tp.active_connection_id_limit, 2);

    ngx_conf_merge_value(conf->retry, prev->retry, 0);

    ngx_conf_merge_str_value(conf->host_key, prev->host_key, "");

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
                            &conf->host_key, &ngx_http_quic_salt,
                            conf->av_token_key, NGX_QUIC_AV_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_quic_derive_key(cf->log, "sr_token_key",
                            &conf->host_key, &ngx_http_quic_salt,
                            conf->sr_token_key, NGX_QUIC_SR_KEY_LEN)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    conf->ssl = &sscf->ssl;

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_max_ack_delay(ngx_conf_t *cf, void *post, void *data)
{
    ngx_msec_t *sp = data;

    if (*sp > 16384) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"quic_max_ack_delay\" must be less than 16384");

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_max_udp_payload_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_QUIC_MIN_INITIAL_SIZE
        || *sp > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"quic_max_udp_payload_size\" must be between "
                           "%d and %d",
                           NGX_QUIC_MIN_INITIAL_SIZE,
                           NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_host_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
