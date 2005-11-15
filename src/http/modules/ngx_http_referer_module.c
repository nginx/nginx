
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t     name;
    ngx_uint_t    wildcard;
} ngx_http_referer_t;

typedef struct {
    ngx_array_t  *referers;     /* ngx_http_referer_t */

    ngx_flag_t    no_referer;
    ngx_flag_t    blocked_referer;
} ngx_http_referer_conf_t;


static void * ngx_http_referer_create_conf(ngx_conf_t *cf);
static char * ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_referer_commands[] = {

    { ngx_string("valid_referers"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_valid_referers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_referer_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_referer_create_conf,          /* create location configuration */
    ngx_http_referer_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_referer_module = {
    NGX_MODULE_V1,
    &ngx_http_referer_module_ctx,          /* module context */
    ngx_http_referer_commands,             /* module directives */
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


static ngx_int_t
ngx_http_referer_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
     uintptr_t data)
{
    u_char                  *ref;
    size_t                   len;
    ngx_uint_t               i, n;
    ngx_http_referer_t       *refs;
    ngx_http_referer_conf_t  *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_referer_module);

    if (cf->referers == NULL) {
        *v = ngx_http_variable_null_value;
        return NGX_OK;
    }

    if (r->headers_in.referer == NULL) {
        if (cf->no_referer) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;

        } else {
            *v = ngx_http_variable_true_value;
            return NGX_OK;
        }
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len < sizeof("http://i.ru") - 1
        || (ngx_strncasecmp(ref, "http://", 7) != 0))
    {
        if (cf->blocked_referer) {
            *v = ngx_http_variable_null_value;
            return NGX_OK;

        } else {
            *v = ngx_http_variable_true_value;
            return NGX_OK;
        }
    }

    len -= 7;
    ref += 7;

    refs = cf->referers->elts;
    for (i = 0; i < cf->referers->nelts; i++ ){

        if (refs[i].name.len > len) {
            continue;
        }

        if (refs[i].wildcard) {
            for (n = 0; n < len; n++) {
                if (ref[n] == '/' || ref[n] == ':') {
                    break;
                }

                if (ref[n] != '.') {
                    continue;
                }

                if (ngx_strncmp(&ref[n], refs[i].name.data,
                                refs[i].name.len) == 0)
                {
                    *v = ngx_http_variable_null_value;
                    return NGX_OK;
                }
            }

        } else {
            if (ngx_strncasecmp(refs[i].name.data, ref, refs[i].name.len) == 0)
            {
                *v = ngx_http_variable_null_value;
                return NGX_OK;
            }
        }
    }

    *v = ngx_http_variable_true_value;

    return NGX_OK;
}


static void *
ngx_http_referer_create_conf(ngx_conf_t *cf)
{
    ngx_http_referer_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_referer_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->referers = NULL;
    conf->no_referer = NGX_CONF_UNSET;
    conf->blocked_referer = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_referer_conf_t *prev = parent;
    ngx_http_referer_conf_t *conf = child;

    if (conf->referers == NULL) {
        conf->referers = prev->referers;
        ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        ngx_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
    }

    if (conf->no_referer == NGX_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == NGX_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_referer_conf_t  *lcf = conf;

    ngx_uint_t                 i, server_names;
    ngx_str_t                 *value, name;
    ngx_http_referer_t        *ref;
    ngx_http_variable_t       *var;
    ngx_http_server_name_t    *sn;
    ngx_http_core_srv_conf_t  *cscf;

    name.len = sizeof("invalid_referer") - 1;
    name.data = (u_char *) "invalid_referer";

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->handler = ngx_http_referer_variable;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    if (lcf->referers == NULL) {
        lcf->referers = ngx_array_create(cf->pool,
                                    cf->args->nelts + cscf->server_names.nelts,
                                    sizeof(ngx_http_referer_t));
        if (lcf->referers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    server_names = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            lcf->no_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "blocked") == 0) {
            lcf->blocked_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "server_names") == 0) {
            server_names = 1;
            continue;
        }

        ref = ngx_array_push(lcf->referers);
        if (ref == NULL) {
            return NGX_CONF_ERROR;
        }

        if (value[i].data[0] != '*') {
            ref->name = value[i];
            ref->wildcard = 0;
            continue;
        }


        if (value[i].data[1] != '.') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid wildcard referer \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        ref->name.len = value[i].len - 1;
        ref->name.data = value[i].data + 1;
        ref->wildcard = 1;
    }

    if (!server_names) {
        return NGX_CONF_OK;
    }

    sn = cscf->server_names.elts;
    for (i = 0; i < cscf->server_names.nelts; i++) {
        ref = ngx_array_push(lcf->referers);
        if (ref == NULL) {
            return NGX_CONF_ERROR;
        }

        ref->name.len = sn[i].name.len + 1;
        ref->name.data = ngx_palloc(cf->pool, ref->name.len);
        if (ref->name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(ref->name.data, sn[i].name.data, sn[i].name.len);
        ref->name.data[sn[i].name.len] = '/';
        ref->wildcard = sn[i].wildcard;
    }

    return NGX_CONF_OK;
}
