
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_command_t  ngx_http_v3_commands[] = {

    { ngx_string("http3_max_field_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_field_size),
      NULL },

    { ngx_string("http3_max_table_capacity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_table_capacity),
      NULL },

    { ngx_string("http3_max_blocked_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_blocked_streams),
      NULL },

      ngx_null_command
};


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

    { ngx_string("http3"), NULL, ngx_http_variable_http3,
      0, 0, 0 },

      ngx_http_null_variable
};


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
    ngx_http_v3_srv_conf_t  *h3scf;

    h3scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_srv_conf_t));
    if (h3scf == NULL) {
        return NULL;
    }

    h3scf->max_field_size = NGX_CONF_UNSET_SIZE;
    h3scf->max_table_capacity = NGX_CONF_UNSET_SIZE;
    h3scf->max_blocked_streams = NGX_CONF_UNSET_UINT;

    return h3scf;
}


static char *
ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v3_srv_conf_t *prev = parent;
    ngx_http_v3_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->max_field_size,
                              prev->max_field_size,
                              NGX_HTTP_V3_DEFAULT_MAX_FIELD_SIZE);

    ngx_conf_merge_size_value(conf->max_table_capacity,
                              prev->max_table_capacity,
                              NGX_HTTP_V3_DEFAULT_MAX_TABLE_CAPACITY);

    ngx_conf_merge_uint_value(conf->max_blocked_streams,
                              prev->max_blocked_streams,
                              NGX_HTTP_V3_DEFAULT_MAX_BLOCKED_STREAMS);

    return NGX_CONF_OK;
}
