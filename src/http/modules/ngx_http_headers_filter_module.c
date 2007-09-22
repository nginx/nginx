
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_header_val_s  ngx_http_header_val_t;

typedef ngx_int_t (*ngx_http_set_header_pt)(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);


typedef struct {
    ngx_str_t                name;
    ngx_uint_t               offset;
    ngx_http_set_header_pt   handler;
} ngx_http_set_header_t;


struct ngx_http_header_val_s {
    ngx_table_elt_t          value;
    ngx_uint_t               offset;
    ngx_http_set_header_pt   handler;
    ngx_array_t             *lengths;
    ngx_array_t             *values;
};


typedef struct {
    time_t                   expires;
    ngx_array_t             *headers;
} ngx_http_headers_conf_t;


#define NGX_HTTP_EXPIRES_UNSET   -2147483647
#define NGX_HTTP_EXPIRES_OFF     -2147483646
#define NGX_HTTP_EXPIRES_EPOCH   -2147483645
#define NGX_HTTP_EXPIRES_MAX     -2147483644


static ngx_int_t ngx_http_set_expires(ngx_http_request_t *r,
    ngx_http_headers_conf_t *conf);
static ngx_int_t ngx_http_add_cache_control(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);
static ngx_int_t ngx_http_set_last_modified(ngx_http_request_t *r,
    ngx_http_header_val_t *hv, ngx_str_t *value);

static void *ngx_http_headers_create_conf(ngx_conf_t *cf);
static char *ngx_http_headers_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_headers_filter_init(ngx_conf_t *cf);
static char *ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_http_set_header_t  ngx_http_set_headers[] = {

    { ngx_string("Cache-Control"), 0, ngx_http_add_cache_control },

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified),
                 ngx_http_set_last_modified },

    { ngx_null_string, 0, NULL }
};


static ngx_command_t  ngx_http_headers_filter_commands[] = {

    { ngx_string("expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_headers_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("add_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_headers_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_headers_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_headers_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_headers_create_conf,          /* create location configuration */
    ngx_http_headers_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_headers_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_headers_filter_module_ctx,   /* module context */
    ngx_http_headers_filter_commands,      /* module directives */
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


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_headers_filter(ngx_http_request_t *r)
{
    ngx_str_t                 value;
    ngx_uint_t                i;
    ngx_http_header_val_t    *h;
    ngx_http_headers_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);

    if ((conf->expires == NGX_HTTP_EXPIRES_OFF && conf->headers == NULL)
        || r != r->main
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_NO_CONTENT
            && r->headers_out.status != NGX_HTTP_MOVED_PERMANENTLY
            && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED))
    {
        return ngx_http_next_header_filter(r);
    }

    if (conf->expires != NGX_HTTP_EXPIRES_OFF) {
        if (ngx_http_set_expires(r, conf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (h[i].lengths == NULL) {
                value = h[i].value.value;

            } else {
                if (ngx_http_script_run(r, &value, h[i].lengths->elts, 0,
                                        h[i].values->elts)
                    == NULL)
                {
                    return NGX_ERROR;
                }
            }

            if (h[i].handler(r, &h[i], &value) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_set_expires(ngx_http_request_t *r, ngx_http_headers_conf_t *conf)
{
    size_t            len;
    ngx_uint_t        i;
    ngx_table_elt_t  *expires, *cc, **ccp;

    expires = r->headers_out.expires;

    if (expires == NULL) {

        expires = ngx_list_push(&r->headers_out.headers);
        if (expires == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = expires;

        expires->hash = 1;
        expires->key.len = sizeof("Expires") - 1;
        expires->key.data = (u_char *) "Expires";
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    expires->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        cc->key.len = sizeof("Cache-Control") - 1;
        cc->key.data = (u_char *) "Cache-Control";

        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    if (conf->expires == NGX_HTTP_EXPIRES_EPOCH) {
        expires->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";

        cc->value.len = sizeof("no-cache") - 1;
        cc->value.data = (u_char *) "no-cache";

        return NGX_OK;
    }

    if (conf->expires == NGX_HTTP_EXPIRES_MAX) {
        expires->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";

        /* 10 years */
        cc->value.len = sizeof("max-age=315360000") - 1;
        cc->value.data = (u_char *) "max-age=315360000";

        return NGX_OK;
    }

    expires->value.data = ngx_palloc(r->pool, len);
    if (expires->value.data == NULL) {
        return NGX_ERROR;
    }

    if (conf->expires == 0) {
        ngx_memcpy(expires->value.data, ngx_cached_http_time.data,
                   ngx_cached_http_time.len + 1);

        cc->value.len = sizeof("max-age=0") - 1;
        cc->value.data = (u_char *) "max-age=0";

        return NGX_OK;
    }

    ngx_http_time(expires->value.data, ngx_time() + conf->expires);

    if (conf->expires < 0) {
        cc->value.len = sizeof("no-cache") - 1;
        cc->value.data = (u_char *) "no-cache";

        return NGX_OK;
    }

    cc->value.data = ngx_palloc(r->pool,
                                sizeof("max-age=") + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", conf->expires)
                    - cc->value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_add_header(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = hv->value.hash;
    h->key = hv->value.key;
    h->value = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_add_cache_control(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *cc, **ccp;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ccp = ngx_array_push(&r->headers_out.cache_control);
    if (ccp == NULL) {
        return NGX_ERROR;
    }

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    cc->hash = 1;
    cc->key.len = sizeof("Cache-Control") - 1;
    cc->key.data = (u_char *) "Cache-Control";
    cc->value = *value;

    *ccp = cc;

    return NGX_OK;
}


static ngx_int_t
ngx_http_set_last_modified(ngx_http_request_t *r, ngx_http_header_val_t *hv,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    } else {
        old = NULL;
    }

    if (old == NULL || *old == NULL) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

    } else {
        h = *old;
    }

    h->hash = hv->value.hash;
    h->key = hv->value.key;
    h->value = *value;

    r->headers_out.last_modified_time = -1;

    return NGX_OK;
}


static void *
ngx_http_headers_create_conf(ngx_conf_t *cf)
{
    ngx_http_headers_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_headers_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->headers = NULL;
     */

    conf->expires = NGX_HTTP_EXPIRES_UNSET;

    return conf;
}


static char *
ngx_http_headers_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_headers_conf_t *prev = parent;
    ngx_http_headers_conf_t *conf = child;

    if (conf->expires == NGX_HTTP_EXPIRES_UNSET) {
        conf->expires = (prev->expires == NGX_HTTP_EXPIRES_UNSET) ?
                            NGX_HTTP_EXPIRES_OFF : prev->expires;
    }

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_headers_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_headers_filter;

    return NGX_OK;
}


static char *
ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_headers_conf_t *hcf = conf;

    ngx_uint_t   minus;
    ngx_str_t   *value;

    if (hcf->expires != NGX_HTTP_EXPIRES_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "epoch") == 0) {
        hcf->expires = NGX_HTTP_EXPIRES_EPOCH;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "max") == 0) {
        hcf->expires = NGX_HTTP_EXPIRES_MAX;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        hcf->expires = NGX_HTTP_EXPIRES_OFF;
        return NGX_CONF_OK;
    }

    if (value[1].data[0] == '+') {
        value[1].data++;
        value[1].len--;
        minus = 0;

    } else if (value[1].data[0] == '-') {
        value[1].data++;
        value[1].len--;
        minus = 1;

    } else {
        minus = 0;
    }

    hcf->expires = ngx_parse_time(&value[1], 1);

    if (hcf->expires == NGX_ERROR) {
        return "invalid value";
    }

    if (hcf->expires == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 68 years";
    }

    if (minus) {
        hcf->expires = - hcf->expires;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_headers_conf_t *hcf = conf;

    ngx_int_t                   n;
    ngx_str_t                  *value;
    ngx_uint_t                  i;
    ngx_http_header_val_t      *h;
    ngx_http_set_header_t      *sh;
    ngx_http_script_compile_t   sc;

    value = cf->args->elts;

    if (hcf->headers == NULL) {
        hcf->headers = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_header_val_t));
        if (hcf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(hcf->headers);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    h->value.hash = 1;
    h->value.key = value[1];
    h->value.value = value[2];
    h->offset = 0;
    h->handler = ngx_http_add_header;
    h->lengths = NULL;
    h->values = NULL;

    sh = ngx_http_set_headers;
    for (i = 0; sh[i].name.len; i++) {
        if (ngx_strcasecmp(value[1].data, sh[i].name.data) != 0) {
            continue;
        }

        h->offset = sh[i].offset;
        h->handler = sh[i].handler;
        break;
    }

    n = ngx_http_script_variables_count(&value[2]);

    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &h->lengths;
    sc.values = &h->values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
