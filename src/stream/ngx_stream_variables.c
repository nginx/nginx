
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>


static ngx_int_t ngx_stream_variable_nginx_version(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);


static ngx_stream_variable_t  ngx_stream_core_variables[] = {

    { ngx_string("nginx_version"), NULL, ngx_stream_variable_nginx_version,
      0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


ngx_stream_variable_value_t  ngx_stream_variable_null_value =
    ngx_stream_variable("");
ngx_stream_variable_value_t  ngx_stream_variable_true_value =
    ngx_stream_variable("1");


ngx_stream_variable_t *
ngx_stream_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                     rc;
    ngx_uint_t                    i;
    ngx_hash_key_t               *key;
    ngx_stream_variable_t        *v;
    ngx_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NGX_STREAM_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_stream_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


ngx_int_t
ngx_stream_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                    i;
    ngx_stream_variable_t        *v;
    ngx_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NGX_ERROR;
    }

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_stream_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


ngx_stream_variable_value_t *
ngx_stream_get_indexed_variable(ngx_stream_session_t *s, ngx_uint_t index)
{
    ngx_stream_variable_t        *v;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (s->variables[index].not_found || s->variables[index].valid) {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (v[index].get_handler(s, &s->variables[index], v[index].data)
        == NGX_OK)
    {
        if (v[index].flags & NGX_STREAM_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}


ngx_stream_variable_value_t *
ngx_stream_get_flushed_variable(ngx_stream_session_t *s, ngx_uint_t index)
{
    ngx_stream_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_stream_get_indexed_variable(s, index);
}


ngx_stream_variable_value_t *
ngx_stream_get_variable(ngx_stream_session_t *s, ngx_str_t *name,
    ngx_uint_t key)
{
    ngx_stream_variable_t        *v;
    ngx_stream_variable_value_t  *vv;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_STREAM_VAR_INDEXED) {
            return ngx_stream_get_flushed_variable(s, v->index);

        } else {

            vv = ngx_palloc(s->connection->pool,
                            sizeof(ngx_stream_variable_value_t));

            if (vv && v->get_handler(s, vv, v->data) == NGX_OK) {
                return vv;
            }

            return NULL;
        }
    }

    vv = ngx_palloc(s->connection->pool, sizeof(ngx_stream_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static ngx_int_t
ngx_stream_variable_nginx_version(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NGINX_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NGINX_VERSION;

    return NGX_OK;
}


void *
ngx_stream_map_find(ngx_stream_session_t *s, ngx_stream_map_t *map,
    ngx_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    ngx_uint_t   key;

    len = match->len;

    if (len) {
        low = ngx_pnalloc(s->connection->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = ngx_hash_strlow(low, match->data, len);

    value = ngx_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NGX_PCRE)

    if (len && map->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_stream_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = ngx_stream_regex_exec(s, reg[i].regex, match);

            if (n == NGX_OK) {
                return reg[i].value;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            /* NGX_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_stream_variable_not_found(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_stream_regex_t *
ngx_stream_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
{
    u_char                       *p;
    size_t                        size;
    ngx_str_t                     name;
    ngx_uint_t                    i, n;
    ngx_stream_variable_t        *v;
    ngx_stream_regex_t           *re;
    ngx_stream_regex_variable_t  *rv;
    ngx_stream_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = ngx_pcalloc(cf->pool, sizeof(ngx_stream_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

    n = (ngx_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = ngx_palloc(rc->pool, n * sizeof(ngx_stream_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = ngx_strlen(name.data);

        v = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = ngx_stream_get_variable_index(cf, &name);
        if (rv[i].index == NGX_ERROR) {
            return NULL;
        }

        v->get_handler = ngx_stream_variable_not_found;

        p += size;
    }

    return re;
}


ngx_int_t
ngx_stream_regex_exec(ngx_stream_session_t *s, ngx_stream_regex_t *re,
    ngx_str_t *str)
{
    ngx_int_t                     rc, index;
    ngx_uint_t                    i, n, len;
    ngx_stream_variable_value_t  *vv;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (s->captures == NULL) {
            s->captures = ngx_palloc(s->connection->pool, len * sizeof(int));
            if (s->captures == NULL) {
                return NGX_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = ngx_regex_exec(re->regex, str, s->captures, len);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return NGX_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &s->variables[index];

        vv->len = s->captures[n + 1] - s->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &str->data[s->captures[n]];

#if (NGX_DEBUG)
        {
        ngx_stream_variable_t  *v;

        v = cmcf->variables.elts;

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    s->ncaptures = rc * 2;
    s->captures_data = str->data;

    return NGX_OK;
}

#endif


ngx_int_t
ngx_stream_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_int_t                     rc;
    ngx_stream_variable_t        *cv, *v;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (cv = ngx_stream_core_variables; cv->name.len; cv++) {
        v = ngx_palloc(cf->pool, sizeof(ngx_stream_variable_t));
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;

        rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v,
                              NGX_HASH_READONLY_KEY);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting variable name \"%V\"", &v->name);
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_stream_variables_init_vars(ngx_conf_t *cf)
{
    ngx_uint_t                    i, n;
    ngx_hash_key_t               *key;
    ngx_hash_init_t               hash;
    ngx_stream_variable_t        *v, *av;
    ngx_stream_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed stream variables */

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    v = cmcf->variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NGX_STREAM_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL) {
                    break;
                }

                goto next;
            }
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown \"%V\" variable", &v[i].name);

        return NGX_ERROR;

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_STREAM_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf->variables_keys = NULL;

    return NGX_OK;
}
