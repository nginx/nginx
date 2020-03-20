
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_command_t  ngx_http_v3_commands[] = {

    { ngx_string("quic_max_idle_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.max_idle_timeout),
      NULL },

    { ngx_string("quic_max_ack_delay"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.max_ack_delay),
      NULL },

    { ngx_string("quic_max_packet_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.max_packet_size),
      NULL },

    { ngx_string("quic_initial_max_data"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_data),
      NULL },

    { ngx_string("quic_initial_max_stream_data_bidi_local"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_stream_data_bidi_local),
      NULL },

    { ngx_string("quic_initial_max_stream_data_bidi_remote"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_stream_data_bidi_remote),
      NULL },

    { ngx_string("quic_initial_max_stream_data_uni"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_stream_data_uni),
      NULL },

    { ngx_string("quic_initial_max_streams_bidi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_streams_bidi),
      NULL },

    { ngx_string("quic_initial_max_streams_uni"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.initial_max_streams_uni),
      NULL },

    { ngx_string("quic_ack_delay_exponent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.ack_delay_exponent),
      NULL },

    { ngx_string("quic_active_migration"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.disable_active_migration),
      NULL },

    { ngx_string("quic_active_connection_id_limit"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, quic.active_connection_id_limit),
      NULL },

      ngx_null_command
};


static void *ngx_http_v3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_http_module_t  ngx_http_v3_module_ctx = {
    NULL,                                  /* preconfiguration */
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


static void *
ngx_http_v3_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_v3_srv_conf_t  *v3cf;

    v3cf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_srv_conf_t));
    if (v3cf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *  v3cf->quic.original_connection_id = 0;
     *  v3cf->quic.stateless_reset_token = { 0 }
     *  conf->quic.preferred_address = NULL
     */

    v3cf->quic.max_idle_timeout = NGX_CONF_UNSET_MSEC;
    v3cf->quic.max_ack_delay = NGX_CONF_UNSET_MSEC;

    v3cf->quic.max_packet_size = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_data = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_stream_data_bidi_local = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_stream_data_bidi_remote = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_stream_data_uni = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_streams_bidi = NGX_CONF_UNSET_UINT;
    v3cf->quic.initial_max_streams_uni = NGX_CONF_UNSET_UINT;
    v3cf->quic.ack_delay_exponent = NGX_CONF_UNSET_UINT;
    v3cf->quic.disable_active_migration = NGX_CONF_UNSET_UINT;
    v3cf->quic.active_connection_id_limit = NGX_CONF_UNSET_UINT;

    return v3cf;
}


static char *
ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v3_srv_conf_t *prev = parent;
    ngx_http_v3_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->quic.max_idle_timeout,
                              prev->quic.max_idle_timeout, 10000);

    // > 2 ^ 14 is invalid
    ngx_conf_merge_msec_value(conf->quic.max_ack_delay,
                              prev->quic.max_ack_delay, 25);

    // < 1200 is invalid
    ngx_conf_merge_uint_value(conf->quic.max_packet_size,
                              prev->quic.max_packet_size, 65527);

    ngx_conf_merge_uint_value(conf->quic.initial_max_data,
                              prev->quic.initial_max_data, 10000000);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_bidi_local,
                              prev->quic.initial_max_stream_data_bidi_local,
                              255);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_bidi_remote,
                              prev->quic.initial_max_stream_data_bidi_remote,
                              255);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_uni,
                              prev->quic.initial_max_stream_data_uni, 255);

    ngx_conf_merge_uint_value(conf->quic.initial_max_streams_bidi,
                              prev->quic.initial_max_streams_bidi, 16);

    ngx_conf_merge_uint_value(conf->quic.initial_max_streams_uni,
                              prev->quic.initial_max_streams_uni, 16);

    // > 20 is invalid
    ngx_conf_merge_uint_value(conf->quic.ack_delay_exponent,
                              prev->quic.ack_delay_exponent, 3);

    ngx_conf_merge_uint_value(conf->quic.disable_active_migration,
                              prev->quic.disable_active_migration, 1);

    // < 2 is invalid
    ngx_conf_merge_uint_value(conf->quic.active_connection_id_limit,
                              prev->quic.active_connection_id_limit, 2);

    return NGX_CONF_OK;
}

