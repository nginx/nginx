
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
    ngx_http_variable_unknown_header(ngx_http_request_t *r, ngx_str_t *var);
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
ngx_http_add_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t        *var;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (cmcf->variables.elts == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_http_variable_t)) == NGX_ERROR)
        {
            return NULL;
        }
    }

    if (!(var = ngx_array_push(&cmcf->variables))) {
        return NULL;
    }

    var->index = cmcf->variables.nelts - 1;

    return var;
}


ngx_http_variable_value_t *
ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index)
{
    ngx_http_variable_t        *var;
    ngx_http_core_main_conf_t  *cmcf;

    /* TODO: cached variables */

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    if (cmcf->variables.elts == NULL || cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }

    var = cmcf->variables.elts;

    return var[index].handler(r, var[index].data);
}


ngx_int_t
ngx_http_get_variable_index(ngx_http_core_main_conf_t *cmcf, ngx_str_t *name)
{
    ngx_uint_t            i;
    ngx_http_variable_t  *var;

    var = cmcf->variables.elts;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (var[i].name.len != name->len) {
            continue;
        }

        if (ngx_strncasecmp(var[i].name.data, name->data, name->len) == 0) {
            return var[i].index;
        }
    }

    return -1;
}


ngx_http_variable_value_t *
ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_int_t                   index;
    ngx_uint_t                  i, key;
    ngx_http_core_variable_t   *var;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    index = ngx_http_get_variable_index(cmcf, name);

    if (index != -1) {
        return ngx_http_get_indexed_variable(r, index);
    }

    ngx_http_vars_hash_key(key, name);

    var = ngx_http_core_variables_hash[key].elts;
    for (i = 0; i < ngx_http_core_variables_hash[key].nelts; i++) {

        if (var[i].name.len != name->len
            || ngx_strncasecmp(var[i].name.data, name->data, name->len) != 0)
        {
            continue;
        }

        return var[i].handler(r, var[i].data);
    }

    if (ngx_strncasecmp(name->data, "HTTP_", 5) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "unknown \"%V\" variable", name);
        return NGX_HTTP_VARIABLE_NOT_FOUND;
    }

    return ngx_http_variable_unknown_header(r, name);
}


static ngx_http_variable_value_t *
ngx_http_variable_header(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t            *h;
    ngx_http_variable_value_t  *v;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

    if (h == NULL) {
        return NGX_HTTP_VARIABLE_NOT_FOUND;
    }

    if (!(v = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)))) {
        return NULL;
    }

    v->value = 0;
    v->text = h->value;

    return v;
}


static ngx_http_variable_value_t *
ngx_http_variable_unknown_header(ngx_http_request_t *r, ngx_str_t *var)
{
    u_char                      ch;
    ngx_uint_t                  i, n;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *header;
    ngx_http_variable_value_t  *v;

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
            if (!(v = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)))) {
                return NULL;
            }

            v->value = 0;
            v->text = header[i].value;
            return v;
        }
    }

    return NGX_HTTP_VARIABLE_NOT_FOUND;
}


static ngx_http_variable_value_t *
ngx_http_variable_remote_addr(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *v;

    if (!(v = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)))) {
        return NULL;
    }

    v->value = 0;
    v->text = r->connection->addr_text;

    return v;
}


static ngx_http_variable_value_t *
ngx_http_variable_uri(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *v;

    if (!(v = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)))) {
        return NULL;
    }

    v->value = 0;
    v->text = r->uri;

    return v;
}


static ngx_http_variable_value_t *
ngx_http_variable_query_string(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *v;

    if (!(v = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t)))) {
        return NULL;
    }

    v->value = 0;
    v->text = r->args;

    return v;
}


ngx_int_t
ngx_http_core_variables_init(ngx_cycle_t *cycle)
{
    ngx_uint_t                 i, key;
    ngx_http_core_variable_t  *var, *v;

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

    for (var = ngx_http_core_variables; var->name.len; var++) {
        ngx_http_vars_hash_key(key, &var->name);

        if (!(v = ngx_array_push(&ngx_http_core_variables_hash[key]))) {
            return NGX_ERROR;
        }

        *v = *var;
    }

    return NGX_OK;
}
