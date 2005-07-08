
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define ngx_http_script_exit  (u_char *) &ngx_http_script_exit_code

static uintptr_t ngx_http_script_exit_code = (uintptr_t) NULL;


ngx_uint_t
ngx_http_script_variables_count(ngx_str_t *value)
{
    ngx_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


ngx_int_t
ngx_http_script_compile(ngx_http_script_compile_t *sc)
{
    u_char                                ch;
    size_t                                size;
    ngx_int_t                             index;
    ngx_str_t                             name;
    uintptr_t                            *code;
    ngx_uint_t                            i, n, bracket;
    ngx_http_script_var_code_t           *var_code;
    ngx_http_script_copy_code_t          *copy;
    ngx_http_script_copy_capture_code_t  *copy_capture;

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(ngx_http_script_copy_code_t)
                             + sizeof(ngx_http_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return NGX_ERROR;
        }
    }


    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(ngx_http_script_copy_code_t)
                              + sizeof(ngx_http_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = ngx_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return NGX_ERROR;
        }
    }

    sc->variables = 0;

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {

                copy_capture = ngx_http_script_add_code(*sc->lengths,
                                   sizeof(ngx_http_script_copy_capture_code_t),
                                   NULL);
                if (copy_capture == NULL) {
                    return NGX_ERROR;
                }

                copy_capture->code = (ngx_http_script_code_pt)
                                         ngx_http_script_copy_capture_len_code;
                copy_capture->n = 2 * (sc->source->data[i] - '0');

                copy_capture = ngx_http_script_add_code(*sc->values,
                                   sizeof(ngx_http_script_copy_capture_code_t),
                                   &sc->main);
                if (copy_capture == NULL) {
                    return NGX_ERROR;
                }

                copy_capture->code = ngx_http_script_copy_capture_code;
                copy_capture->n = sc->source->data[i] - '0';

                if (sc->ncaptures < copy_capture->n) {
                    sc->ncaptures = copy_capture->n;
                }

                copy_capture->n *= 2;

                i++;

                continue;
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return NGX_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            index = ngx_http_get_variable_index(sc->cf, &name);

            if (index == NGX_ERROR) {
                return NGX_ERROR;
            }

            var_code = ngx_http_script_add_code(*sc->lengths,
                                            sizeof(ngx_http_script_var_code_t),
                                            NULL);
            if (var_code == NULL) {
                return NGX_ERROR;
            }

            var_code->code = (ngx_http_script_code_pt)
                                            ngx_http_script_copy_var_len_code;
            var_code->index = (uintptr_t) index;


            var_code = ngx_http_script_add_code(*sc->values,
                                            sizeof(ngx_http_script_var_code_t),
                                            &sc->main);
            if (var_code == NULL) {
                return NGX_ERROR;
            }

            var_code->code = ngx_http_script_copy_var_code;
            var_code->index = (uintptr_t) index;

            continue;
        }

        if (sc->source->data[i] == '?' && sc->compile_args) {
            sc->args = 1;
            sc->compile_args = 0;

            code = ngx_http_script_add_code(*sc->values, sizeof(uintptr_t),
                                            &sc->main);
            if (code == NULL) {
                return NGX_ERROR;
            }

            *code = (uintptr_t) ngx_http_script_start_args_code;

            i++;

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len
               && sc->source->data[i] != '$'
               && !(sc->source->data[i] == '?' && sc->compile_args))
        {
            i++;
            name.len++;
        }

        sc->size += name.len;

        copy = ngx_http_script_add_code(*sc->lengths,
                                        sizeof(ngx_http_script_copy_code_t),
                                        NULL);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) ngx_http_script_copy_len_code;
        copy->len = name.len;

        size = (sizeof(ngx_http_script_copy_code_t) + name.len
                   + sizeof(uintptr_t) - 1)
                & ~(sizeof(uintptr_t) - 1);

        copy = ngx_http_script_add_code(*sc->values, size, &sc->main);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = ngx_http_script_copy_code;
        copy->len = name.len;

        ngx_memcpy((u_char *) copy + sizeof(ngx_http_script_copy_code_t),
                   name.data, name.len);
    }

    if (sc->complete_lengths) {
        code = ngx_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = ngx_http_script_add_code(*sc->values, sizeof(uintptr_t),
                                        &sc->main);
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return NGX_OK;

invalid_variable:

    ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return NGX_ERROR;
}


void *
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


void *
ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = ngx_array_push_n(codes, size);
    if (new == NULL) {
        return NGX_CONF_ERROR;
    }

    if (code) {
        if (elts != codes->elts) {
            p = code;
            *p += (u_char *) codes->elts - elts;
        }
    }

    return new;
}


size_t
ngx_http_script_copy_len_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_code_t  *code;

    code = (ngx_http_script_copy_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_copy_code_t);

    return code->len;
}


void
ngx_http_script_copy_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_code_t  *code;

    code = (ngx_http_script_copy_code_t *) e->ip;

    if (!e->skip) {
        e->pos = ngx_cpymem(e->pos, e->ip + sizeof(ngx_http_script_copy_code_t),
                            code->len);
    }

    e->ip += sizeof(ngx_http_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    if (e->log) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script copy: \"%V\"", &e->buf);
    }
}


size_t
ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e)
{
    ngx_http_variable_value_t   *value;
    ngx_http_script_var_code_t  *code;

    code = (ngx_http_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_var_code_t);

    value = ngx_http_get_indexed_variable(e->request, code->index);

    if (value == NULL || value == NGX_HTTP_VAR_NOT_FOUND) {
        return 0;
    }

    return value->text.len;
}


void
ngx_http_script_copy_var_code(ngx_http_script_engine_t *e)
{
    ngx_http_variable_value_t   *value;
    ngx_http_script_var_code_t  *code;

    code = (ngx_http_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_var_code_t);

    if (!e->skip) {
        value = ngx_http_get_indexed_variable(e->request, code->index);

        if (value == NULL || value == NGX_HTTP_VAR_NOT_FOUND) {
            return;
        }

        e->pos = ngx_cpymem(e->pos, value->text.data, value->text.len);

        if (e->log) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script var: \"%V\"", &e->buf);
        }
    }
}


size_t
ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_capture_code_t  *code;

    code = (ngx_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_copy_capture_code_t);

    if (code->n < e->ncaptures) {
        if ((e->args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            return e->captures[code->n + 1] - e->captures[code->n]
                   + ngx_escape_uri(NULL,
                                &e->line.data[e->captures[code->n]],
                                e->captures[code->n + 1] - e->captures[code->n],
                                NGX_ESCAPE_ARGS);
        } else {
            return e->captures[code->n + 1] - e->captures[code->n];
        }
    }

    return 0;
}


void
ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_copy_capture_code_t  *code;

    code = (ngx_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_copy_capture_code_t);

    if (code->n < e->ncaptures) {
        if ((e->args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            e->pos = (u_char *) ngx_escape_uri(e->pos,
                                &e->line.data[e->captures[code->n]],
                                e->captures[code->n + 1] - e->captures[code->n],
                                NGX_ESCAPE_ARGS);
        } else {
            e->pos = ngx_cpymem(e->pos,
                               &e->line.data[e->captures[code->n]],
                               e->captures[code->n + 1] - e->captures[code->n]);
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script capture: \"%V\"", &e->buf);
}


void
ngx_http_script_start_args_code(ngx_http_script_engine_t *e)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script args");
    
    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}



#if (NGX_PCRE)

void
ngx_http_script_regex_start_code(ngx_http_script_engine_t *e)
{
    size_t                         len;
    ngx_int_t                      rc;
    ngx_uint_t                     n;
    ngx_http_request_t            *r;
    ngx_http_script_engine_t       le;
    ngx_http_script_len_code_pt    lcode;
    ngx_http_script_regex_code_t  *code;

    code = (ngx_http_script_regex_code_t *) e->ip;

    r = e->request;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex: \"%V\"", &code->name);

    if (code->uri) {
        e->line = r->uri;
    } else {
        e->sp--;
        e->line = e->sp->text;
    }

    rc = ngx_regex_exec(code->regex, &e->line, e->captures, code->ncaptures);

    if (rc == NGX_REGEX_NO_MATCHED) {
        if (e->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "\"%V\" does not match \"%V\"",
                          &code->name, &e->line);
        }

        e->ncaptures = 0;

        if (code->test) {
            e->sp->value = 0; 
            e->sp->text.len = 0;
            e->sp->text.data = (u_char *) "";
            e->sp++;

            e->ip += sizeof(ngx_http_script_regex_code_t);
            return;
        }

        e->ip += code->next;
        return;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
                      rc, &e->line, &code->name);

        e->ip = ngx_http_script_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->log) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "\"%V\" matches \"%V\"", &code->name, &e->line);
    }

    e->ncaptures = code->ncaptures;

    if (code->test) {
        e->sp->value = 1; 
        e->sp->text.len = 1;
        e->sp->text.data = (u_char *) "1";
        e->sp++;

        e->ip += sizeof(ngx_http_script_regex_code_t);
        return;
    }

    if (code->status) {
        e->status = code->status;

        if (!code->redirect) {
            e->ip = ngx_http_script_exit;
            return;
        }
    }

    if (code->uri) {
        r->internal = 1;
        r->valid_unparsed_uri = 0;

        if (code->break_cycle) {
            r->valid_location = 0;
            r->uri_changed = 0;

        } else {
            r->uri_changed = 1;
        }
    }

    if (code->lengths == NULL) {
        e->buf.len = code->size;

        if (code->uri) {
            if (rc && (r->quoted_uri || r->plus_in_uri)) {
                e->buf.len += 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
                                                 NGX_ESCAPE_ARGS);
            }
        }

        for (n = 1; n < (ngx_uint_t) rc; n++) {
            e->buf.len += e->captures[2 * n + 1] - e->captures[2 * n];
        }

    } else {
        ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

        le.ip = code->lengths->elts;
        le.request = r;
        le.captures = e->captures;
        le.ncaptures = e->ncaptures;

        len = 1;  /* reserve 1 byte for possible "?" */

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }

        e->buf.len = len;
    }

    if (code->add_args && r->args.len) {
        e->buf.len += r->args.len + 1;
    }

    e->buf.data = ngx_palloc(r->pool, e->buf.len);
    if (e->buf.data == NULL) {
        e->ip = ngx_http_script_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->quote = code->redirect;

    e->pos = e->buf.data;

    e->ip += sizeof(ngx_http_script_regex_code_t);
}


void
ngx_http_script_regex_end_code(ngx_http_script_engine_t *e)
{
    ngx_http_request_t                *r;
    ngx_http_script_regex_end_code_t  *code;

    code = (ngx_http_script_regex_end_code_t *) e->ip;

    r = e->request;

    e->quote = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex end");

    if (code->redirect) {

        if (code->add_args && r->args.len) { 
            *e->pos++ = (u_char) (code->args ? '&' : '?');
            e->pos = ngx_cpymem(e->pos, r->args.data, r->args.len);
        }

        e->buf.len = e->pos - e->buf.data;

        if (e->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "rewritten redirect: \"%V\"", &e->buf);
        }

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            e->ip = ngx_http_script_exit;
            e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        r->headers_out.location->hash = 1; 
        r->headers_out.location->key.len = sizeof("Location") - 1;
        r->headers_out.location->key.data = (u_char *) "Location";
        r->headers_out.location->value = e->buf;

        e->ip += sizeof(ngx_http_script_regex_end_code_t);
        return;
    }

    if (e->args) { 
        e->buf.len = e->args - e->buf.data;

        if (code->add_args && r->args.len) {
            *e->pos++ = '&';
            e->pos = ngx_cpymem(e->pos, r->args.data, r->args.len);
        }

        r->args.len = e->pos - e->args;
        r->args.data = e->args;

        e->args = NULL;

    } else {
        e->buf.len = e->pos - e->buf.data;
    }

    if (e->log) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "rewritten data: \"%V\", args: \"%V\"",
                      &e->buf, &r->args);
    }

    if (code->uri) {
        r->uri = e->buf;

        if (ngx_http_set_exten(r) != NGX_OK) {
            e->ip = ngx_http_script_exit;
            e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }
    }

    e->ip += sizeof(ngx_http_script_regex_end_code_t);
}

#endif


void
ngx_http_script_return_code(ngx_http_script_engine_t *e)
{   
    ngx_http_script_return_code_t  *code;
    
    code = (ngx_http_script_return_code_t *) e->ip;

    e->status = code->status;

    e->ip += sizeof(ngx_http_script_return_code_t) - sizeof(uintptr_t);
}


void
ngx_http_script_break_code(ngx_http_script_engine_t *e)
{
    e->request->uri_changed = 0;

    e->ip = ngx_http_script_exit;
}


void
ngx_http_script_if_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_if_code_t  *code;

    code = (ngx_http_script_if_code_t *) e->ip;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if");

    e->sp--;

    if (e->sp->value) {
        if (code->loc_conf) {
            e->request->loc_conf = code->loc_conf;
        }

        e->ip += sizeof(ngx_http_script_if_code_t);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if false");

    e->ip += code->next;
}


void
ngx_http_script_complex_value_code(ngx_http_script_engine_t *e)
{
    size_t                                 len;
    ngx_http_script_engine_t               le;
    ngx_http_script_len_code_pt            lcode;
    ngx_http_script_complex_value_code_t  *code;

    code = (ngx_http_script_complex_value_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_complex_value_code_t);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script complex value");

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    le.ip = code->lengths->elts;
    le.request = e->request;
    le.captures = e->captures;
    le.ncaptures = e->ncaptures;

    for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;
    }

    e->buf.len = len;
    e->buf.data = ngx_palloc(e->request->pool, len);
    if (e->buf.data == NULL) {
        e->ip = ngx_http_script_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->pos = e->buf.data;

    e->sp->value = 0;
    e->sp->text = e->buf;
    e->sp++;
}


void
ngx_http_script_value_code(ngx_http_script_engine_t *e)
{
    ngx_http_script_value_code_t  *code;

    code = (ngx_http_script_value_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_value_code_t);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script value");

    e->sp->value = (ngx_uint_t) code->value;
    e->sp->text.len = (size_t) code->text_len;
    e->sp->text.data = (u_char *) code->text_data;
    e->sp++;
}


void
ngx_http_script_set_var_code(ngx_http_script_engine_t *e)
{
    ngx_http_request_t          *r;
    ngx_http_variable_value_t   *value;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_script_var_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set var");

    code = (ngx_http_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_var_code_t);

    r = e->request;

    if (r->variables == NULL) {
        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t *));
        if (r->variables == NULL) {
            e->ip = ngx_http_script_exit;
            e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }
    }

    value = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (value == NULL) {
        e->ip = ngx_http_script_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->sp--;

    *value = *e->sp;

    r->variables[code->index] = value;
}


void
ngx_http_script_var_code(ngx_http_script_engine_t *e)
{
    ngx_http_variable_value_t   *value;
    ngx_http_script_var_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script var");

    code = (ngx_http_script_var_code_t *) e->ip;

    e->ip += sizeof(ngx_http_script_var_code_t);

    value = ngx_http_get_indexed_variable(e->request, code->index);

    if (value == NULL || value == NGX_HTTP_VAR_NOT_FOUND) {
        e->sp->value = 0;
        e->sp->text.len = 0;
        e->sp->text.data = (u_char *) "";
        e->sp++;

        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script var: %ui, \"%V\"", value->value, &value->text);

    *e->sp = *value;
    e->sp++;
}


void
ngx_http_script_nop_code(ngx_http_script_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}
