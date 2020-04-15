
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


static ngx_int_t ngx_http_variable_quic(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_http3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_v3_add_variables(ngx_conf_t *cf);
static void *ngx_http_v3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);


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
    { ngx_string("quic"), NULL, ngx_http_variable_quic,
      0, 0, 0 },

    { ngx_string("http3"), NULL, ngx_http_variable_http3,
      0, 0, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_variable_quic(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->qs) {

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
ngx_http_variable_http3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("h3-xx") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "h3-%d", NGX_QUIC_DRAFT_VERSION) - v->data;

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
                              prev->quic.max_idle_timeout, 60000);

    // > 2 ^ 14 is invalid
    ngx_conf_merge_msec_value(conf->quic.max_ack_delay,
                              prev->quic.max_ack_delay,
                              NGX_QUIC_DEFAULT_MAX_ACK_DELAY);

    // < 1200 is invalid
    ngx_conf_merge_uint_value(conf->quic.max_packet_size,
                              prev->quic.max_packet_size,
                              NGX_QUIC_DEFAULT_MAX_PACKET_SIZE);

    ngx_conf_merge_uint_value(conf->quic.initial_max_data,
                              prev->quic.initial_max_data,
                              16 * NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_bidi_local,
                              prev->quic.initial_max_stream_data_bidi_local,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_bidi_remote,
                              prev->quic.initial_max_stream_data_bidi_remote,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_uint_value(conf->quic.initial_max_stream_data_uni,
                              prev->quic.initial_max_stream_data_uni,
                              NGX_QUIC_STREAM_BUFSIZE);

    ngx_conf_merge_uint_value(conf->quic.initial_max_streams_bidi,
                              prev->quic.initial_max_streams_bidi, 16);

    ngx_conf_merge_uint_value(conf->quic.initial_max_streams_uni,
                              prev->quic.initial_max_streams_uni, 16);

    // > 20 is invalid
    ngx_conf_merge_uint_value(conf->quic.ack_delay_exponent,
                              prev->quic.ack_delay_exponent,
                              NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT);

    ngx_conf_merge_uint_value(conf->quic.disable_active_migration,
                              prev->quic.disable_active_migration, 1);

    // < 2 is invalid
    ngx_conf_merge_uint_value(conf->quic.active_connection_id_limit,
                              prev->quic.active_connection_id_limit, 2);

    return NGX_CONF_OK;
}

