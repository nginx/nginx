
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    time_t  expires;
} ngx_http_headers_conf_t;


#define NGX_HTTP_EXPIRES_UNSET   -2147483647
#define NGX_HTTP_EXPIRES_OFF     -2147483646
#define NGX_HTTP_EXPIRES_EPOCH   -2147483645


static ngx_int_t ngx_http_headers_filter_init(ngx_cycle_t *cycle);
static void *ngx_http_headers_create_conf(ngx_conf_t *cf);
static char *ngx_http_headers_merge_conf(ngx_conf_t *cf,
                                         void *parent, void *child);
char *ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_headers_filter_commands[] = {

    { ngx_string("expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_headers_expires,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_headers_filter_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_headers_create_conf,          /* create location configuration */
    ngx_http_headers_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_headers_filter_module = {
    NGX_MODULE,
    &ngx_http_headers_filter_module_ctx,   /* module context */
    ngx_http_headers_filter_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_headers_filter_init,          /* init module */
    NULL                                   /* init child */
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t ngx_http_headers_filter(ngx_http_request_t *r)
{
    size_t                    len;
    ngx_table_elt_t          *expires, *cc;
    ngx_http_headers_conf_t  *conf;

    if (r->headers_out.status != NGX_HTTP_OK) {
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);

    if (conf->expires != NGX_HTTP_EXPIRES_OFF) {

        if (!(expires = ngx_list_push(&r->headers_out.headers))) {
            return NGX_ERROR;
        }

        r->headers_out.expires = expires;

        if (!(cc = ngx_list_push(&r->headers_out.headers))) {
            return NGX_ERROR;
        }

        r->headers_out.cache_control = cc;

        len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");

        expires->key.len = sizeof("Expires") - 1;
        expires->key.data = (u_char *) "Expires";
        expires->value.len = len - 1;

        cc->key.len = sizeof("Cache-Control") - 1;
        cc->key.data = (u_char *) "Cache-Control";

        if (conf->expires == NGX_HTTP_EXPIRES_EPOCH) {
            expires->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";

            cc->value.len = sizeof("no-cache") - 1;
            cc->value.data = (u_char *) "no-cache";

        } else {
            expires->value.data = ngx_palloc(r->pool, len);
            if (expires->value.data == NULL) {
                return NGX_ERROR;
            }

            if (conf->expires == 0) {
                ngx_memcpy(expires->value.data, ngx_cached_http_time.data,
                           ngx_cached_http_time.len + 1);

                cc->value.len = sizeof("max-age=0") - 1;
                cc->value.data = (u_char *) "max-age=0";

            } else {
                ngx_http_time(expires->value.data, ngx_time() + conf->expires);

                if (conf->expires < 0) {
                    cc->value.len = sizeof("no-cache") - 1;
                    cc->value.data = (u_char *) "no-cache";

                } else {
                    cc->value.data = ngx_palloc(r->pool,
                                          sizeof("max-age=") + TIME_T_LEN + 1);
                    if (cc->value.data == NULL) {
                        return NGX_ERROR;
                    }

                    cc->value.len = ngx_snprintf((char *) cc->value.data,
                                               sizeof("max-age=") + TIME_T_LEN,
                                               "max-age=" TIME_T_FMT,
                                               conf->expires);
                }
            }
        }
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_headers_filter_init(ngx_cycle_t *cycle)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_headers_filter;

    return NGX_OK;
}


static void *ngx_http_headers_create_conf(ngx_conf_t *cf)
{   
    ngx_http_headers_conf_t  *conf;

    if (!(conf = ngx_palloc(cf->pool, sizeof(ngx_http_headers_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    conf->expires = NGX_HTTP_EXPIRES_UNSET;

    return conf;
}


static char *ngx_http_headers_merge_conf(ngx_conf_t *cf,
                                         void *parent, void *child)
{
    ngx_http_headers_conf_t *prev = parent;
    ngx_http_headers_conf_t *conf = child;

    if (conf->expires == NGX_HTTP_EXPIRES_UNSET) {
        conf->expires = (prev->expires == NGX_HTTP_EXPIRES_UNSET) ?
                                          NGX_HTTP_EXPIRES_OFF : prev->expires;
    }

    return NGX_CONF_OK;
}


char *ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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
