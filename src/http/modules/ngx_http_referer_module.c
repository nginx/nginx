
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_REFERER_NO_URI_PART  ((void *) 4)

#if (NGX_PCRE)

typedef struct {
    ngx_regex_t             *regex;
    ngx_str_t                name;
} ngx_http_referer_regex_t;

#else

#define ngx_regex_t          void

#endif


typedef struct {
    ngx_hash_combined_t      hash;

#if (NGX_PCRE)
    ngx_array_t             *regex;
#endif

    ngx_flag_t               no_referer;
    ngx_flag_t               blocked_referer;

    ngx_hash_keys_arrays_t  *keys;
} ngx_http_referer_conf_t;


static void * ngx_http_referer_create_conf(ngx_conf_t *cf);
static char * ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_add_referer(ngx_conf_t *cf, ngx_hash_keys_arrays_t *keys,
    ngx_str_t *value, ngx_str_t *uri);
static char *ngx_http_add_regex_referer(ngx_conf_t *cf,
    ngx_http_referer_conf_t *rlcf, ngx_str_t *name, ngx_regex_t *regex);
static int ngx_libc_cdecl ngx_http_cmp_referer_wildcards(const void *one,
    const void *two);


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
    u_char                    *p, *ref, *last;
    size_t                     len;
    ngx_str_t                 *uri;
    ngx_uint_t                 i, key;
    ngx_http_referer_conf_t   *rlcf;
    u_char                     buf[256];
#if (NGX_PCRE)
    ngx_int_t                  n;
    ngx_str_t                  referer;
    ngx_http_referer_regex_t  *regex;
#endif

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_referer_module);

    if (rlcf->hash.hash.buckets == NULL
        && rlcf->hash.wc_head == NULL
        && rlcf->hash.wc_tail == NULL
#if (NGX_PCRE)
        && rlcf->regex == NULL
#endif
       )
    {
        goto valid;
    }

    if (r->headers_in.referer == NULL) {
        if (rlcf->no_referer) {
            goto valid;
        }

        goto invalid;
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len < sizeof("http://i.ru") - 1
        || (ngx_strncasecmp(ref, (u_char *) "http://", 7) != 0))
    {
        if (rlcf->blocked_referer) {
            goto valid;
        }

        goto invalid;
    }

    last = ref + len;
    ref += 7;
    i = 0;
    key = 0;

    for (p = ref; p < last; p++) {
        if (*p == '/' || *p == ':') {
            break;
        }

        buf[i] = ngx_tolower(*p);
        key = ngx_hash(key, buf[i++]);

        if (i == 256) {
            goto invalid;
        }
    }

    uri = ngx_hash_find_combined(&rlcf->hash, key, buf, p - ref);

    if (uri) {
        goto uri;
    }

#if (NGX_PCRE)

    if (rlcf->regex) {

        referer.len = len - 7;
        referer.data = ref;

        regex = rlcf->regex->elts;

        for (i = 0; i < rlcf->regex->nelts; i++) {
            n = ngx_regex_exec(regex[i].regex, &referer, NULL, 0);

            if (n == NGX_REGEX_NO_MATCHED) {
                continue;
            }

            if (n < 0) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              ngx_regex_exec_n
                              " failed: %d on \"%V\" using \"%V\"",
                              n, &referer, &regex[i].name);
                return NGX_ERROR;
            }

            /* match */

            goto valid;
        }
    }

#endif

invalid:

    *v = ngx_http_variable_true_value;

    return NGX_OK;

uri:

    for ( /* void */ ; p < last; p++) {
        if (*p == '/') {
            break;
        }
    }

    len = last - p;

    if (uri == NGX_HTTP_REFERER_NO_URI_PART) {
        goto valid;
    }

    if (len < uri->len || ngx_strncmp(uri->data, p, uri->len) != 0) {
        goto invalid;
    }

valid:

    *v = ngx_http_variable_null_value;

    return NGX_OK;
}


static void *
ngx_http_referer_create_conf(ngx_conf_t *cf)
{
    ngx_http_referer_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_referer_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->no_referer = NGX_CONF_UNSET;
    conf->blocked_referer = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_referer_conf_t *prev = parent;
    ngx_http_referer_conf_t *conf = child;

    ngx_hash_init_t  hash;

    if (conf->keys == NULL) {
        conf->hash = prev->hash;

        ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        ngx_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);

        return NGX_CONF_OK;
    }

    if ((conf->no_referer == 1 || conf->blocked_referer == 1)
        && conf->keys->keys.nelts == 0
        && conf->keys->dns_wc_head.nelts == 0
        && conf->keys->dns_wc_tail.nelts == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "the \"none\" or \"blocked\" referers are specified "
                      "in the \"valid_referers\" directive "
                      "without any valid referer");
        return NGX_CONF_ERROR;
    }

    hash.key = ngx_hash_key_lc;
    hash.max_size = 2048; /* TODO: referer_hash_max_size; */
    hash.bucket_size = 64; /* TODO: referer_hash_bucket_size; */
    hash.name = "referers_hash";
    hash.pool = cf->pool;

    if (conf->keys->keys.nelts) {
        hash.hash = &conf->hash.hash;
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->keys->dns_wc_head.nelts) {

        ngx_qsort(conf->keys->dns_wc_head.elts,
                  (size_t) conf->keys->dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t),
                  ngx_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
                                   conf->keys->dns_wc_head.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        conf->hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (conf->keys->dns_wc_tail.nelts) {

        ngx_qsort(conf->keys->dns_wc_tail.elts,
                  (size_t) conf->keys->dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t),
                  ngx_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
                                   conf->keys->dns_wc_tail.nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        conf->hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    if (conf->no_referer == NGX_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == NGX_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    conf->keys = NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_referer_conf_t  *rlcf = conf;

    u_char                    *p;
    ngx_str_t                 *value, uri, name;
    ngx_uint_t                 i, n;
    ngx_http_variable_t       *var;
    ngx_http_server_name_t    *sn;
    ngx_http_core_srv_conf_t  *cscf;

    name.len = sizeof("invalid_referer") - 1;
    name.data = (u_char *) "invalid_referer";

    var = ngx_http_add_variable(cf, &name,
                                NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ngx_http_referer_variable;

    if (rlcf->keys == NULL) {
        rlcf->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
        if (rlcf->keys == NULL) {
            return NGX_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (ngx_hash_keys_array_init(rlcf->keys, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            rlcf->no_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "blocked") == 0) {
            rlcf->blocked_referer = 1;
            continue;
        }

        uri.len = 0;
        uri.data = NULL;

        if (ngx_strcmp(value[i].data, "server_names") == 0) {

            cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

            sn = cscf->server_names.elts;
            for (n = 0; n < cscf->server_names.nelts; n++) {

#if (NGX_PCRE)
                if (sn[n].regex) {

                    if (ngx_http_add_regex_referer(cf, rlcf, &sn[n].name,
                                                   sn[n].regex)
                        != NGX_OK)
                    {
                        return NGX_CONF_ERROR;
                    }

                    continue;
                }
#endif

                if (ngx_http_add_referer(cf, rlcf->keys, &sn[n].name, &uri)
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }
            }

            continue;
        }

        if (value[i].data[0] == '~') {
            if (ngx_http_add_regex_referer(cf, rlcf, &value[i], NULL) != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        p = (u_char *) ngx_strchr(value[i].data, '/');

        if (p) {
            uri.len = (value[i].data + value[i].len) - p;
            uri.data = p;
            value[i].len = p - value[i].data;
        }

        if (ngx_http_add_referer(cf, rlcf->keys, &value[i], &uri) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_add_referer(ngx_conf_t *cf, ngx_hash_keys_arrays_t *keys,
    ngx_str_t *value, ngx_str_t *uri)
{
    ngx_int_t   rc;
    ngx_str_t  *u;

    if (uri->len == 0) {
        u = NGX_HTTP_REFERER_NO_URI_PART;

    } else {
        u = ngx_palloc(cf->pool, sizeof(ngx_str_t));
        if (u == NULL) {
            return NGX_CONF_ERROR;
        }

        *u = *uri;
    }

    rc = ngx_hash_add_key(keys, value, u, NGX_HASH_WILDCARD_KEY);

    if (rc == NGX_OK) {
        return NGX_CONF_OK;
    }

    if (rc == NGX_DECLINED) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", value);
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", value);
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_http_add_regex_referer(ngx_conf_t *cf, ngx_http_referer_conf_t *rlcf,
    ngx_str_t *name, ngx_regex_t *regex)
{
#if (NGX_PCRE)
    ngx_str_t                  err;
    ngx_http_referer_regex_t  *rr;
    u_char                     errstr[NGX_MAX_CONF_ERRSTR];

    if (rlcf->regex == NULL) {
        rlcf->regex = ngx_array_create(cf->pool, 2,
                                       sizeof(ngx_http_referer_regex_t));
        if (rlcf->regex == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rr = ngx_array_push(rlcf->regex);
    if (rr == NULL) {
        return NGX_CONF_ERROR;
    }

    if (regex) {
        rr->regex = regex;
        rr->name = *name;

        return NGX_CONF_OK;
    }

    err.len = NGX_MAX_CONF_ERRSTR;
    err.data = errstr;

    name->len--;
    name->data++;

    rr->regex = ngx_regex_compile(name, NGX_REGEX_CASELESS, cf->pool, &err);

    if (rr->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
        return NGX_CONF_ERROR;
    }

    rr->name = *name;

    return NGX_CONF_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "the using of the regex \"%V\" requires PCRE library",
                       name);

    return NGX_CONF_ERROR;

#endif
}


static int ngx_libc_cdecl
ngx_http_cmp_referer_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_strcmp(first->key.data, second->key.data);
}
