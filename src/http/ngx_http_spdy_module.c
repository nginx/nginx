
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_spdy_module.h>


static ngx_int_t ngx_http_spdy_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_spdy_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_spdy_request_priority_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_spdy_module_init(ngx_cycle_t *cycle);

static void *ngx_http_spdy_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_spdy_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_spdy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_spdy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_spdy_recv_buffer_size(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_spdy_pool_size(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_spdy_streams_index_mask(ngx_conf_t *cf, void *post,
    void *data);


static ngx_conf_num_bounds_t  ngx_http_spdy_headers_comp_bounds = {
    ngx_conf_check_num_bounds, 0, 9
};

static ngx_conf_post_t  ngx_http_spdy_recv_buffer_size_post =
    { ngx_http_spdy_recv_buffer_size };
static ngx_conf_post_t  ngx_http_spdy_pool_size_post =
    { ngx_http_spdy_pool_size };
static ngx_conf_post_t  ngx_http_spdy_streams_index_mask_post =
    { ngx_http_spdy_streams_index_mask };


static ngx_command_t  ngx_http_spdy_commands[] = {

    { ngx_string("spdy_recv_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_spdy_main_conf_t, recv_buffer_size),
      &ngx_http_spdy_recv_buffer_size_post },

    { ngx_string("spdy_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, pool_size),
      &ngx_http_spdy_pool_size_post },

    { ngx_string("spdy_max_concurrent_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, concurrent_streams),
      NULL },

    { ngx_string("spdy_streams_index_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, streams_index_mask),
      &ngx_http_spdy_streams_index_mask_post },

    { ngx_string("spdy_recv_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, recv_timeout),
      NULL },

    { ngx_string("spdy_keepalive_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, keepalive_timeout),
      NULL },

    { ngx_string("spdy_headers_comp"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_spdy_srv_conf_t, headers_comp),
      &ngx_http_spdy_headers_comp_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_spdy_module_ctx = {
    ngx_http_spdy_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_spdy_create_main_conf,        /* create main configuration */
    ngx_http_spdy_init_main_conf,          /* init main configuration */

    ngx_http_spdy_create_srv_conf,         /* create server configuration */
    ngx_http_spdy_merge_srv_conf,          /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_spdy_module = {
    NGX_MODULE_V1,
    &ngx_http_spdy_module_ctx,             /* module context */
    ngx_http_spdy_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_spdy_module_init,             /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_spdy_vars[] = {

    { ngx_string("spdy"), NULL,
      ngx_http_spdy_variable, 0, 0, 0 },

    { ngx_string("spdy_request_priority"), NULL,
      ngx_http_spdy_request_priority_variable, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_spdy_add_variables(ngx_conf_t *cf)
{
   ngx_http_variable_t  *var, *v;

    for (v = ngx_http_spdy_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->spdy_stream) {
        v->len = 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "2";

        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_request_priority_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->spdy_stream) {
        v->len = 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        v->data = ngx_pnalloc(r->pool, 1);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->data[0] = '0' + (u_char) r->spdy_stream->priority;

        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_module_init(ngx_cycle_t *cycle)
{
    ngx_http_spdy_request_headers_init();

    return NGX_OK;
}


static void *
ngx_http_spdy_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_spdy_main_conf_t  *smcf;

    smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_spdy_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    smcf->recv_buffer_size = NGX_CONF_UNSET_SIZE;

    return smcf;
}


static char *
ngx_http_spdy_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_spdy_main_conf_t *smcf = conf;

    if (smcf->recv_buffer_size == NGX_CONF_UNSET_SIZE) {
        smcf->recv_buffer_size = 256 * 1024;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_spdy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_spdy_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_spdy_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->pool_size = NGX_CONF_UNSET_SIZE;

    sscf->concurrent_streams = NGX_CONF_UNSET_UINT;
    sscf->streams_index_mask = NGX_CONF_UNSET_UINT;

    sscf->recv_timeout = NGX_CONF_UNSET_MSEC;
    sscf->keepalive_timeout = NGX_CONF_UNSET_MSEC;

    sscf->headers_comp = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_http_spdy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_spdy_srv_conf_t *prev = parent;
    ngx_http_spdy_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);

    ngx_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 100);

    ngx_conf_merge_uint_value(conf->streams_index_mask,
                              prev->streams_index_mask, 32 - 1);

    ngx_conf_merge_msec_value(conf->recv_timeout,
                              prev->recv_timeout, 30000);
    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 180000);

    ngx_conf_merge_value(conf->headers_comp, prev->headers_comp, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_spdy_recv_buffer_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp <= 2 * NGX_SPDY_STATE_BUFFER_SIZE) {
        return "value is too small";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_spdy_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);
        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_spdy_streams_index_mask(ngx_conf_t *cf, void *post, void *data)
{
    ngx_uint_t *np = data;

    ngx_uint_t  mask;

    mask = *np - 1;

    if (*np == 0 || (*np & mask)) {
        return "must be a power of two";
    }

    *np = mask;

    return NGX_CONF_OK;
}
