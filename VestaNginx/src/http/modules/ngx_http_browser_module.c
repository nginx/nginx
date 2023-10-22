
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * The module can check browser versions conforming to the following formats:
 * X, X.X, X.X.X, and X.X.X.X.  The maximum values of each format may be
 * 4000, 4000.99, 4000.99.99, and 4000.99.99.99.
 */


#define  NGX_HTTP_MODERN_BROWSER   0
#define  NGX_HTTP_ANCIENT_BROWSER  1


typedef struct {
    u_char                      browser[12];
    size_t                      skip;
    size_t                      add;
    u_char                      name[12];
} ngx_http_modern_browser_mask_t;


typedef struct {
    ngx_uint_t                  version;
    size_t                      skip;
    size_t                      add;
    u_char                      name[12];
} ngx_http_modern_browser_t;


typedef struct {
    ngx_array_t                *modern_browsers;
    ngx_array_t                *ancient_browsers;
    ngx_http_variable_value_t  *modern_browser_value;
    ngx_http_variable_value_t  *ancient_browser_value;

    unsigned                    modern_unlisted_browsers:1;
    unsigned                    netscape4:1;
} ngx_http_browser_conf_t;


static ngx_int_t ngx_http_msie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_browser_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_uint_t ngx_http_browser(ngx_http_request_t *r,
    ngx_http_browser_conf_t *cf);

static ngx_int_t ngx_http_browser_add_variables(ngx_conf_t *cf);
static void *ngx_http_browser_create_conf(ngx_conf_t *cf);
static char *ngx_http_browser_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static int ngx_libc_cdecl ngx_http_modern_browser_sort(const void *one,
    const void *two);
static char *ngx_http_modern_browser(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ancient_browser(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_modern_browser_value(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ancient_browser_value(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_browser_commands[] = {

    { ngx_string("modern_browser"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_modern_browser,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ancient_browser"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_ancient_browser,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("modern_browser_value"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_modern_browser_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ancient_browser_value"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ancient_browser_value,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_browser_module_ctx = {
    ngx_http_browser_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_browser_create_conf,          /* create location configuration */
    ngx_http_browser_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_browser_module = {
    NGX_MODULE_V1,
    &ngx_http_browser_module_ctx,          /* module context */
    ngx_http_browser_commands,             /* module directives */
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


static ngx_http_modern_browser_mask_t  ngx_http_modern_browser_masks[] = {

    /* Opera must be the first browser to check */

    /*
     * "Opera/7.50 (X11; FreeBSD i386; U)  [en]"
     * "Mozilla/5.0 (X11; FreeBSD i386; U) Opera 7.50  [en]"
     * "Mozilla/4.0 (compatible; MSIE 6.0; X11; FreeBSD i386) Opera 7.50  [en]"
     * "Opera/8.0 (Windows NT 5.1; U; ru)"
     * "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; en) Opera 8.0"
     * "Opera/9.01 (X11; FreeBSD 6 i386; U; en)"
     */

    { "opera",
      0,
      sizeof("Opera ") - 1,
      "Opera"},

    /* "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" */

    { "msie",
      sizeof("Mozilla/4.0 (compatible; ") - 1,
      sizeof("MSIE ") - 1,
      "MSIE "},

    /*
     * "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.0.0) Gecko/20020610"
     * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.5) Gecko/20031006"
     * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.6) Gecko/20040206
     *              Firefox/0.8"
     * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.7.8)
     *              Gecko/20050511 Firefox/1.0.4"
     * "Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.8.0.5) Gecko/20060729
     *              Firefox/1.5.0.5"
     */

    { "gecko",
      sizeof("Mozilla/5.0 (") - 1,
      sizeof("rv:") - 1,
      "rv:"},

    /*
     * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ru-ru) AppleWebKit/125.2
     *              (KHTML, like Gecko) Safari/125.7"
     * "Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413
     *              (KHTML, like Gecko) Safari/413"
     * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/418
     *              (KHTML, like Gecko) Safari/417.9.3"
     * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ru-ru) AppleWebKit/418.8
     *              (KHTML, like Gecko) Safari/419.3"
     */

    { "safari",
      sizeof("Mozilla/5.0 (") - 1,
      sizeof("Safari/") - 1,
      "Safari/"},

    /*
     * "Mozilla/5.0 (compatible; Konqueror/3.1; Linux)"
     * "Mozilla/5.0 (compatible; Konqueror/3.4; Linux) KHTML/3.4.2 (like Gecko)"
     * "Mozilla/5.0 (compatible; Konqueror/3.5; FreeBSD) KHTML/3.5.1
     *              (like Gecko)"
     */

    { "konqueror",
      sizeof("Mozilla/5.0 (compatible; ") - 1,
      sizeof("Konqueror/") - 1,
      "Konqueror/"},

    { "", 0, 0, "" }

};


static ngx_http_variable_t  ngx_http_browser_vars[] = {

    { ngx_string("msie"), NULL, ngx_http_msie_variable,
      0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("modern_browser"), NULL, ngx_http_browser_variable,
      NGX_HTTP_MODERN_BROWSER, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ancient_browser"), NULL, ngx_http_browser_variable,
      NGX_HTTP_ANCIENT_BROWSER, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_browser_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_uint_t                rc;
    ngx_http_browser_conf_t  *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_browser_module);

    rc = ngx_http_browser(r, cf);

    if (data == NGX_HTTP_MODERN_BROWSER && rc == NGX_HTTP_MODERN_BROWSER) {
        *v = *cf->modern_browser_value;
        return NGX_OK;
    }

    if (data == NGX_HTTP_ANCIENT_BROWSER && rc == NGX_HTTP_ANCIENT_BROWSER) {
        *v = *cf->ancient_browser_value;
        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;
    return NGX_OK;
}


static ngx_uint_t
ngx_http_browser(ngx_http_request_t *r, ngx_http_browser_conf_t *cf)
{
    size_t                      len;
    u_char                     *name, *ua, *last, c;
    ngx_str_t                  *ancient;
    ngx_uint_t                  i, version, ver, scale;
    ngx_http_modern_browser_t  *modern;

    if (r->headers_in.user_agent == NULL) {
        if (cf->modern_unlisted_browsers) {
            return NGX_HTTP_MODERN_BROWSER;
        }

        return NGX_HTTP_ANCIENT_BROWSER;
    }

    ua = r->headers_in.user_agent->value.data;
    len = r->headers_in.user_agent->value.len;
    last = ua + len;

    if (cf->modern_browsers) {
        modern = cf->modern_browsers->elts;

        for (i = 0; i < cf->modern_browsers->nelts; i++) {
            name = ua + modern[i].skip;

            if (name >= last) {
                continue;
            }

            name = (u_char *) ngx_strstr(name, modern[i].name);

            if (name == NULL) {
                continue;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "browser: \"%s\"", name);

            name += modern[i].add;

            if (name >= last) {
                continue;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "version: \"%ui\" \"%s\"", modern[i].version, name);

            version = 0;
            ver = 0;
            scale = 1000000;

            while (name < last) {

                c = *name++;

                if (c >= '0' && c <= '9') {
                    ver = ver * 10 + (c - '0');
                    continue;
                }

                if (c == '.') {
                    version += ver * scale;

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "version: \"%ui\" \"%ui\"",
                                   modern[i].version, version);

                    if (version > modern[i].version) {
                        return NGX_HTTP_MODERN_BROWSER;
                    }

                    ver = 0;
                    scale /= 100;
                    continue;
                }

                break;
            }

            version += ver * scale;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "version: \"%ui\" \"%ui\"",
                           modern[i].version, version);

            if (version >= modern[i].version) {
                return NGX_HTTP_MODERN_BROWSER;
            }

            return NGX_HTTP_ANCIENT_BROWSER;
        }

        if (!cf->modern_unlisted_browsers) {
            return NGX_HTTP_ANCIENT_BROWSER;
        }
    }

    if (cf->netscape4) {
        if (len > sizeof("Mozilla/4.72 ") - 1
            && ngx_strncmp(ua, "Mozilla/", sizeof("Mozilla/") - 1) == 0
            && ua[8] > '0' && ua[8] < '5')
        {
            return NGX_HTTP_ANCIENT_BROWSER;
        }
    }

    if (cf->ancient_browsers) {
        ancient = cf->ancient_browsers->elts;

        for (i = 0; i < cf->ancient_browsers->nelts; i++) {
            if (len >= ancient[i].len
                && ngx_strstr(ua, ancient[i].data) != NULL)
            {
                return NGX_HTTP_ANCIENT_BROWSER;
            }
        }
    }

    if (cf->modern_unlisted_browsers) {
        return NGX_HTTP_MODERN_BROWSER;
    }

    return NGX_HTTP_ANCIENT_BROWSER;
}


static ngx_int_t
ngx_http_msie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    if (r->headers_in.msie) {
        *v = ngx_http_variable_true_value;
        return NGX_OK;
    }

    *v = ngx_http_variable_null_value;
    return NGX_OK;
}


static ngx_int_t
ngx_http_browser_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_browser_vars; v->name.len; v++) {

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
ngx_http_browser_create_conf(ngx_conf_t *cf)
{
    ngx_http_browser_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_browser_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->modern_browsers = NULL;
     *     conf->ancient_browsers = NULL;
     *     conf->modern_browser_value = NULL;
     *     conf->ancient_browser_value = NULL;
     *
     *     conf->modern_unlisted_browsers = 0;
     *     conf->netscape4 = 0;
     */

    return conf;
}


static char *
ngx_http_browser_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_browser_conf_t *prev = parent;
    ngx_http_browser_conf_t *conf = child;

    ngx_uint_t                  i, n;
    ngx_http_modern_browser_t  *browsers, *opera;

    /*
     * At the merge the skip field is used to store the browser slot,
     * it will be used in sorting and then will overwritten
     * with a real skip value.  The zero value means Opera.
     */

    if (conf->modern_browsers == NULL && conf->modern_unlisted_browsers == 0) {
        conf->modern_browsers = prev->modern_browsers;
        conf->modern_unlisted_browsers = prev->modern_unlisted_browsers;

    } else if (conf->modern_browsers != NULL) {
        browsers = conf->modern_browsers->elts;

        for (i = 0; i < conf->modern_browsers->nelts; i++) {
            if (browsers[i].skip == 0) {
                goto found;
            }
        }

        /*
         * Opera may contain MSIE string, so if Opera was not enumerated
         * as modern browsers, then add it and set a unreachable version
         */

        opera = ngx_array_push(conf->modern_browsers);
        if (opera == NULL) {
            return NGX_CONF_ERROR;
        }

        opera->skip = 0;
        opera->version = 4001000000U;

        browsers = conf->modern_browsers->elts;

found:

        ngx_qsort(browsers, (size_t) conf->modern_browsers->nelts,
                  sizeof(ngx_http_modern_browser_t),
                  ngx_http_modern_browser_sort);

        for (i = 0; i < conf->modern_browsers->nelts; i++) {
             n = browsers[i].skip;

             browsers[i].skip = ngx_http_modern_browser_masks[n].skip;
             browsers[i].add = ngx_http_modern_browser_masks[n].add;
             (void) ngx_cpystrn(browsers[i].name,
                                ngx_http_modern_browser_masks[n].name, 12);
        }
    }

    if (conf->ancient_browsers == NULL && conf->netscape4 == 0) {
        conf->ancient_browsers = prev->ancient_browsers;
        conf->netscape4 = prev->netscape4;
    }

    if (conf->modern_browser_value == NULL) {
        conf->modern_browser_value = prev->modern_browser_value;
    }

    if (conf->modern_browser_value == NULL) {
        conf->modern_browser_value = &ngx_http_variable_true_value;
    }

    if (conf->ancient_browser_value == NULL) {
        conf->ancient_browser_value = prev->ancient_browser_value;
    }

    if (conf->ancient_browser_value == NULL) {
        conf->ancient_browser_value = &ngx_http_variable_true_value;
    }

    return NGX_CONF_OK;
}


static int ngx_libc_cdecl
ngx_http_modern_browser_sort(const void *one, const void *two)
{
    ngx_http_modern_browser_t *first = (ngx_http_modern_browser_t *) one;
    ngx_http_modern_browser_t *second = (ngx_http_modern_browser_t *) two;

    return (first->skip - second->skip);
}


static char *
ngx_http_modern_browser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_browser_conf_t *bcf = conf;

    u_char                           c;
    ngx_str_t                       *value;
    ngx_uint_t                       i, n, version, ver, scale;
    ngx_http_modern_browser_t       *browser;
    ngx_http_modern_browser_mask_t  *mask;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[1].data, "unlisted") == 0) {
            bcf->modern_unlisted_browsers = 1;
            return NGX_CONF_OK;
        }

        return NGX_CONF_ERROR;
    }

    if (bcf->modern_browsers == NULL) {
        bcf->modern_browsers = ngx_array_create(cf->pool, 5,
                                            sizeof(ngx_http_modern_browser_t));
        if (bcf->modern_browsers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    browser = ngx_array_push(bcf->modern_browsers);
    if (browser == NULL) {
        return NGX_CONF_ERROR;
    }

    mask = ngx_http_modern_browser_masks;

    for (n = 0; mask[n].browser[0] != '\0'; n++) {
        if (ngx_strcasecmp(mask[n].browser, value[1].data) == 0) {
            goto found;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown browser name \"%V\"", &value[1]);

    return NGX_CONF_ERROR;

found:

    /*
     * at this stage the skip field is used to store the browser slot,
     * it will be used in sorting in merge stage and then will overwritten
     * with a real value
     */

    browser->skip = n;

    version = 0;
    ver = 0;
    scale = 1000000;

    for (i = 0; i < value[2].len; i++) {

        c = value[2].data[i];

        if (c >= '0' && c <= '9') {
            ver = ver * 10 + (c - '0');
            continue;
        }

        if (c == '.') {
            version += ver * scale;
            ver = 0;
            scale /= 100;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid browser version \"%V\"", &value[2]);

        return NGX_CONF_ERROR;
    }

    version += ver * scale;

    browser->version = version;

    return NGX_CONF_OK;
}


static char *
ngx_http_ancient_browser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_browser_conf_t *bcf = conf;

    ngx_str_t   *value, *browser;
    ngx_uint_t   i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "netscape4") == 0) {
            bcf->netscape4 = 1;
            continue;
        }

        if (bcf->ancient_browsers == NULL) {
            bcf->ancient_browsers = ngx_array_create(cf->pool, 4,
                                                     sizeof(ngx_str_t));
            if (bcf->ancient_browsers == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        browser = ngx_array_push(bcf->ancient_browsers);
        if (browser == NULL) {
            return NGX_CONF_ERROR;
        }

        *browser = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_modern_browser_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_browser_conf_t *bcf = conf;

    ngx_str_t  *value;

    bcf->modern_browser_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_http_variable_value_t));
    if (bcf->modern_browser_value == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    bcf->modern_browser_value->len = value[1].len;
    bcf->modern_browser_value->valid = 1;
    bcf->modern_browser_value->no_cacheable = 0;
    bcf->modern_browser_value->not_found = 0;
    bcf->modern_browser_value->data = value[1].data;

    return NGX_CONF_OK;
}


static char *
ngx_http_ancient_browser_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_browser_conf_t *bcf = conf;

    ngx_str_t  *value;

    bcf->ancient_browser_value = ngx_palloc(cf->pool,
                                            sizeof(ngx_http_variable_value_t));
    if (bcf->ancient_browser_value == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    bcf->ancient_browser_value->len = value[1].len;
    bcf->ancient_browser_value->valid = 1;
    bcf->ancient_browser_value->no_cacheable = 0;
    bcf->ancient_browser_value->not_found = 0;
    bcf->ancient_browser_value->data = value[1].data;

    return NGX_CONF_OK;
}
