
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


#define NGX_HTTP_VARS_HASH_PRIME  29

#define ngx_http_vars_hash_key(key, vn)                                      \
    {                                                                        \
        ngx_uint_t  n;                                                       \
        for (key = 0, n = 0; n < (vn)->len; n++) {                           \
            key += (vn)->data[n];                                            \
        }                                                                    \
        key %= NGX_HTTP_VARS_HASH_PRIME;                                     \
    }


static ngx_http_variable_value_t *
    ngx_http_variable_header(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_unknown_header(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_remote_addr(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_uri(ngx_http_request_t *r, uintptr_t data);
static ngx_http_variable_value_t *
    ngx_http_variable_query_string(ngx_http_request_t *r, uintptr_t data);


static ngx_array_t  *ngx_http_core_variables_hash;


static ngx_http_core_variable_t  ngx_http_core_variables[] = {

    { ngx_string("HTTP_HOST"), ngx_http_variable_header,
      offsetof(ngx_http_headers_in_t, host) },

    { ngx_string("HTTP_USER_AGENT"), ngx_http_variable_header,
      offsetof(ngx_http_headers_in_t, user_agent) },

    { ngx_string("HTTP_REFERER"), ngx_http_variable_header,
      offsetof(ngx_http_headers_in_t, referer) },

#if (NGX_HTTP_GZIP)
    { ngx_string("HTTP_VIA"), ngx_http_variable_header,
      offsetof(ngx_http_headers_in_t, via) },
#endif

#if (NGX_HTTP_PROXY)
    { ngx_string("HTTP_X_FORWARDED_FOR"), ngx_http_variable_header,
      offsetof(ngx_http_headers_in_t, x_forwarded_for) },
#endif

    { ngx_string("REMOTE_ADDR"), ngx_http_variable_remote_addr, 0 },

    { ngx_string("DOCUMENT_URI"), ngx_http_variable_uri, 0 },

    { ngx_string("QUERY_STRING"), ngx_http_variable_query_string, 0 },

    { ngx_null_string, NULL, 0 }
};


ngx_http_variable_t *
ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t set)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_http_variable_t)) == NGX_ERROR)
        {
            return NULL;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            if (set && v[i].handler) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the duplicate \"%V\" variable", name);
                return NULL;
            }

            return &v[i];
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_palloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    for (i = 0; i < name->len; i++) {
        v->name.data[i] = ngx_toupper(name->data[i]);
    }

    v->index = cmcf->variables.nelts - 1;
    v->handler = NULL;
    v->data = 0;

    return v;
}


ngx_http_variable_value_t *
ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (cmcf->variables.elts == NULL || cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }

    if (r->variables && r->variables[index]) {
        return r->variables[index];
    }

    v = cmcf->variables.elts;

    vv = v[index].handler(r, v[index].data);

    if (r->variables == NULL) {
        r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t *));
        if (r->variables == NULL) {
            return NULL;
        }
    }

    r->variables[index] = vv;

    return vv;
}


ngx_http_variable_value_t *
ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                  i, key;
    ngx_http_variable_t        *v;
    ngx_http_core_variable_t   *cv;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    v = cmcf->variables.elts;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (v[i].name.len != name->len) {
            continue;
        }

        if (ngx_strncmp(v[i].name.data, name->data, name->len) == 0) {
            return ngx_http_get_indexed_variable(r, v[i].index);
        }
    }

    ngx_http_vars_hash_key(key, name);

    cv = ngx_http_core_variables_hash[key].elts;
    for (i = 0; i < ngx_http_core_variables_hash[key].nelts; i++) {
        if (cv[i].name.len != name->len) {
            continue;
        }

        if (ngx_strncmp(cv[i].name.data, name->data, name->len) == 0) {
            return cv[i].handler(r, cv[i].data);
        }
    }

    if (ngx_strncmp(name->data, "HTTP_", 5) == 0) {
        return ngx_http_variable_unknown_header(r, (uintptr_t) name);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "unknown \"%V\" variable", name);

    return NGX_HTTP_VARIABLE_NOT_FOUND;
}


static ngx_http_variable_value_t *
ngx_http_variable_header(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t            *h;
    ngx_http_variable_value_t  *vv;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

    if (h == NULL) {
        return NGX_HTTP_VARIABLE_NOT_FOUND;
    }

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = h->value;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_unknown_header(ngx_http_request_t *r, uintptr_t data)
{
    ngx_str_t  *var = (ngx_str_t *) data;

    u_char                      ch;
    ngx_uint_t                  i, n;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *header;
    ngx_http_variable_value_t  *vv;

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        for (n = 0; n + 5 < var->len && n < header[i].key.len; n++)
        {
            ch = header[i].key.data[n];

            if (ch >= 'a' && ch <= 'z') {
                ch &= ~0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + 5] != ch) {
                break;
            }
        }

        if (n + 5 == var->len) {
            vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
            if (vv == NULL) {
                return NULL;
            }

            vv->value = 0;
            vv->text = header[i].value;
            return vv;
        }
    }

    return NGX_HTTP_VARIABLE_NOT_FOUND;
}


static ngx_http_variable_value_t *
ngx_http_variable_remote_addr(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = r->connection->addr_text;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_uri(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = r->uri;

    return vv;
}


static ngx_http_variable_value_t *
ngx_http_variable_query_string(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *vv;

    vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->value = 0;
    vv->text = r->args;

    return vv;
}


ngx_int_t
ngx_http_variables_init(ngx_cycle_t *cycle)
{
    ngx_uint_t                  i, j, key;
    ngx_http_variable_t        *v;
    ngx_http_core_variable_t   *cv, *vp;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_core_variables_hash = ngx_palloc(cycle->pool,
                                              NGX_HTTP_VARS_HASH_PRIME
                                              * sizeof(ngx_array_t));
    if (ngx_http_core_variables_hash == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < NGX_HTTP_VARS_HASH_PRIME; i++) {
        if (ngx_array_init(&ngx_http_core_variables_hash[i], cycle->pool, 4,
                           sizeof(ngx_http_core_variable_t)) == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    for (cv = ngx_http_core_variables; cv->name.len; cv++) {
        ngx_http_vars_hash_key(key, &cv->name);

        vp = ngx_array_push(&ngx_http_core_variables_hash[key]);
        if (vp == NULL) {
            return NGX_ERROR;
        }

        *vp = *cv;
    }


    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    v = cmcf->variables.elts;
    for (i = 0; i < cmcf->variables.nelts; i++) {

        if (v[i].handler) {
            continue;
        }

        ngx_http_vars_hash_key(key, &v[i].name);

        cv = ngx_http_core_variables_hash[key].elts;
        for (j = 0; j < ngx_http_core_variables_hash[key].nelts; j++) {
            if (cv[j].name.len != v[i].name.len) {
                continue;
            }

            if (ngx_strncmp(cv[j].name.data, v[i].name.data, v[i].name.len)
                == 0)
            {
                v[i].handler = cv[j].handler;
                v[i].data = cv[j].data;
                continue;
            }
        }

        if (ngx_strncmp(v[i].name.data, "HTTP_", 5) == 0) {
            v[i].handler = ngx_http_variable_unknown_header;
            v[i].data = (uintptr_t) &v[i].name;
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "unknown \"%V\" variable", &v[i].name);

        return NGX_ERROR;
    }

    return NGX_OK;
}
