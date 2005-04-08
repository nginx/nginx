
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t
ngx_http_script_compile_lite(ngx_conf_t *cf, ngx_array_t *sources,
    ngx_array_t **lengths, ngx_array_t **values,
    ngx_http_script_compile_lite_start_pt start,
    ngx_http_script_compile_lite_end_pt end)
{
    uintptr_t                   *code;
    ngx_uint_t                   i;
    ngx_table_elt_t             *src;
    ngx_http_variable_t         *var;
    ngx_http_script_var_code_t  *var_code;

    if (sources->nelts == 0) {
        return NGX_OK;
    }

    if (*lengths == NULL) {
        *lengths = ngx_array_create(cf->pool, 64, 1);
        if (*lengths == NULL) {
            return NGX_ERROR;
        }
    }

    if (*values == NULL) {
        *values = ngx_array_create(cf->pool, 256, 1);
        if (*values == NULL) {
            return NGX_ERROR;
        }
    }

    src = sources->elts;
    for (i = 0; i < sources->nelts; i++) {

        if (src[i].value.data[0] == '$') {
            if (start(&src[i], *lengths, *values, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            src[i].value.len--;
            src[i].value.data++;

            var = ngx_http_add_variable(cf, &src[i].value, 0);

            if (var == NULL) {
                return NGX_ERROR;
            }

            var_code = ngx_array_push_n(*lengths,
                                        sizeof(ngx_http_script_var_code_t));
            if (var_code == NULL) {
                return NGX_ERROR;
            }

            var_code->code = (ngx_http_script_code_pt)
                                                  ngx_http_script_copy_var_len;
            var_code->index = var->index;


            var_code = ngx_array_push_n(*values,
                                        sizeof(ngx_http_script_var_code_t));
            if (var_code == NULL) {
                return NGX_ERROR;
            }

            var_code->code = ngx_http_script_copy_var;
            var_code->index = var->index;


            if (end(*lengths, *values) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (start(&src[i], *lengths, *values, 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    code = ngx_array_push_n(*lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    code = ngx_array_push_n(*values, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_OK;
}


#if 0

static void *
ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        *codes = ngx_array_create(pool, 256, 1);
        if (*codes == NULL) {
            return NULL;
        }
    }

    return ngx_array_push_n(*codes, size);
}

#endif


size_t
ngx_http_script_copy_len(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_code_t  *code;

    code = (ngx_http_script_copy_code_t *) e->lite.ip;

    e->lite.ip += sizeof(ngx_http_script_copy_code_t);

    return code->len;
}


void
ngx_http_script_copy(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_code_t  *code;

    code = (ngx_http_script_copy_code_t *) e->lite.ip;

    e->lite.pos = ngx_cpymem(e->lite.pos,
                             e->lite.ip + sizeof(ngx_http_script_copy_code_t),
                             code->len);

    e->lite.ip += sizeof(ngx_http_script_copy_code_t)
            + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
}


size_t
ngx_http_script_copy_var_len(ngx_http_script_engine_t *e)
{
    ngx_http_variable_value_t   *value;
    ngx_http_script_var_code_t  *code;

    code = (ngx_http_script_var_code_t *) e->lite.ip;

    e->lite.ip += sizeof(ngx_http_script_var_code_t);

    value = ngx_http_get_indexed_variable(e->lite.request, code->index);

    if (value == NULL || value == NGX_HTTP_VARIABLE_NOT_FOUND) {
        return 0;
    }

    return value->text.len;
}


void
ngx_http_script_copy_var(ngx_http_script_engine_t *e)
{
    ngx_http_variable_value_t   *value;
    ngx_http_script_var_code_t  *code;

    code = (ngx_http_script_var_code_t *) e->lite.ip;

    e->lite.ip += sizeof(ngx_http_script_var_code_t);

    value = ngx_http_get_indexed_variable(e->lite.request, code->index);

    if (value == NULL || value == NGX_HTTP_VARIABLE_NOT_FOUND) {
        return;
    }

    e->lite.pos = ngx_cpymem(e->lite.pos, value->text.data, value->text.len);
}
