
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_variable_http3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_v3_add_variables(ngx_conf_t *cf);
static void *ngx_http_v3_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_v3_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_v3_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_v3_push(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


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

    { ngx_string("http3_max_concurrent_pushes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_srv_conf_t, max_concurrent_pushes),
      NULL },

    { ngx_string("http3_push"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_v3_push,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("http3_push_preload"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_v3_loc_conf_t, push_preload),
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

    ngx_http_v3_create_loc_conf,           /* create location configuration */
    ngx_http_v3_merge_loc_conf             /* merge location configuration */
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

    { ngx_string("http3"), NULL, ngx_http_variable_http3, 0, 0, 0 },

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
    h3scf->max_concurrent_pushes = NGX_CONF_UNSET_UINT;

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

    ngx_conf_merge_uint_value(conf->max_concurrent_pushes,
                              prev->max_concurrent_pushes,
                              NGX_HTTP_V3_DEFAULT_MAX_CONCURRENT_PUSHES);

    return NGX_CONF_OK;
}


static void *
ngx_http_v3_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_v3_loc_conf_t  *h3lcf;

    h3lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_loc_conf_t));
    if (h3lcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     h3lcf->pushes = NULL;
     */

    h3lcf->push_preload = NGX_CONF_UNSET;
    h3lcf->push = NGX_CONF_UNSET;

    return h3lcf;
}


static char *
ngx_http_v3_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_v3_loc_conf_t *prev = parent;
    ngx_http_v3_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->push, prev->push, 1);

    if (conf->push && conf->pushes == NULL) {
        conf->pushes = prev->pushes;
    }

    ngx_conf_merge_value(conf->push_preload, prev->push_preload, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_v3_push(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v3_loc_conf_t *h3lcf = conf;

    ngx_str_t                         *value;
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {

        if (h3lcf->pushes) {
            return "\"off\" parameter cannot be used with URI";
        }

        if (h3lcf->push == 0) {
            return "is duplicate";
        }

        h3lcf->push = 0;
        return NGX_CONF_OK;
    }

    if (h3lcf->push == 0) {
        return "URI cannot be used with \"off\" parameter";
    }

    h3lcf->push = 1;

    if (h3lcf->pushes == NULL) {
        h3lcf->pushes = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_http_complex_value_t));
        if (h3lcf->pushes == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cv = ngx_array_push(h3lcf->pushes);
    if (cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
