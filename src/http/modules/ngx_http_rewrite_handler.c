
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_rewrite_engine_s  ngx_http_rewrite_engine_t;

typedef void (*ngx_http_rewrite_code_pt) (ngx_http_rewrite_engine_t *e);


typedef struct {
    ngx_str_t                     name;
    ngx_uint_t                    wildcard;
} ngx_http_rewrite_referer_t;


typedef struct {
    ngx_array_t                  *codes;        /* uintptr_t */
    ngx_array_t                  *referers;     /* ngx_http_rewrite_referer_t */

    ngx_uint_t                    max_captures;
    ngx_uint_t                    stack_size;

    ngx_flag_t                    log;

    ngx_flag_t                    no_referer;
} ngx_http_rewrite_loc_conf_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;
    ngx_regex_t                  *regex;
    uintptr_t                     size;
    uintptr_t                     ncaptures;
    uintptr_t                     status;
    uintptr_t                     next;

    uintptr_t                     uri:1;

    /* add the r->args to the new arguments */
    uintptr_t                     args:1;

    uintptr_t                     redirect:1;
    uintptr_t                     break_cycle:1;

    ngx_str_t                     name;
} ngx_http_rewrite_regex_code_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;

    uintptr_t                     uri:1;

    /* add the r->args to the new arguments */
    uintptr_t                     args:1;

    uintptr_t                     redirect:1;
} ngx_http_rewrite_regex_end_code_t;

typedef struct {
    ngx_http_rewrite_code_pt      code;
    uintptr_t                     n;
} ngx_http_rewrite_copy_capture_code_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;
    uintptr_t                     len;
} ngx_http_rewrite_copy_code_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;
    uintptr_t                     status;
    uintptr_t                     null;
} ngx_http_rewrite_return_code_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;
    uintptr_t                     next;
    void                        **loc_conf;
} ngx_http_rewrite_if_code_t;


typedef struct {
    ngx_http_rewrite_code_pt      code;
    uintptr_t                     index;
} ngx_http_rewrite_var_code_t;


struct ngx_http_rewrite_engine_s {
    u_char                       *ip;
    uintptr_t                    *sp;

    ngx_str_t                     buf;
    ngx_str_t                    *line;

    u_char                       *pos;

    /* the start of the rewritten arguments */
    u_char                       *args;

    unsigned                      quote:1;

    ngx_int_t                     status;

    int                          *captures;

    ngx_http_request_t           *request;
    ngx_http_rewrite_loc_conf_t  *conf;
};


static ngx_int_t ngx_http_rewrite_init(ngx_cycle_t *cycle);
static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rewrite_return(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_rewrite_valid_referers(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_rewrite_start_code(ngx_pool_t *pool,
    ngx_array_t **codes, size_t size);
static void *ngx_http_rewrite_add_code(ngx_array_t *codes, size_t size,
    void *code);


static ngx_command_t  ngx_http_rewrite_commands[] = {

    { ngx_string("rewrite"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE23,
      ngx_http_rewrite,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("return"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE1,
      ngx_http_rewrite_return,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("if"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_1MORE,
      ngx_http_rewrite_if,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("valid_referers"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_rewrite_valid_referers,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("rewrite_log"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rewrite_loc_conf_t, log),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_rewrite_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_rewrite_create_loc_conf,      /* create location configration */
    ngx_http_rewrite_merge_loc_conf        /* merge location configration */
};


ngx_module_t  ngx_http_rewrite_module = {
    NGX_MODULE,
    &ngx_http_rewrite_module_ctx,          /* module context */ 
    ngx_http_rewrite_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_rewrite_init,                 /* init module */
    NULL                                   /* init process */
};


#define ngx_http_rewrite_exit  (u_char *) &ngx_http_rewrite_exit_code

uintptr_t ngx_http_rewrite_exit_code = (uintptr_t) NULL;


static ngx_int_t
ngx_http_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_rewrite_code_pt      code;
    ngx_http_rewrite_engine_t    *e;
    ngx_http_rewrite_loc_conf_t  *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_rewrite_module);

    if (cf->codes == NULL) {
        return NGX_DECLINED;
    }

    if (!(e = ngx_palloc(r->pool, sizeof(ngx_http_rewrite_engine_t)))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->sp = ngx_palloc(r->pool, cf->stack_size * sizeof(ngx_int_t));
    if (e->sp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cf->max_captures) {
        e->captures = ngx_palloc(r->pool, cf->max_captures * sizeof(int));
        if (e->captures == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        e->captures = NULL;
    }

    e->ip = cf->codes->elts;
    e->buf.len = 0;
    e->buf.data = NULL;
    e->line = NULL;
    e->pos = NULL;
    e->args = NULL;
    e->quote = 1;
    e->status = NGX_DECLINED;
    e->request = r;
    e->conf = cf;

    while (*(uintptr_t *) e->ip) {
        code = *(ngx_http_rewrite_code_pt *) e->ip;
        code(e);
    }

    return e->status;
}


static void
ngx_http_rewrite_regex_start_code(ngx_http_rewrite_engine_t *e)
{
    ngx_int_t                       rc;
    ngx_uint_t                      n;
    ngx_http_request_t             *r;
    ngx_http_rewrite_regex_code_t  *code;

    code = (ngx_http_rewrite_regex_code_t *) e->ip;

    r = e->request;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http rewrite start: \"%V\"", &code->name);

    if (code->uri) {
        e->line = &r->uri;
    } else {
        e->line = *(ngx_str_t **) e->sp--;
    }

    rc = ngx_regex_exec(code->regex, e->line, e->captures, code->ncaptures);

    if (rc == NGX_REGEX_NO_MATCHED) {
        if (e->conf->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "\"%V\" does not match \"%V\"", &code->name, e->line);
        }

        e->ip += code->next;
        return;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
                      rc, e->line, &code->name);

        e->ip = ngx_http_rewrite_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->conf->log) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "\"%V\" matches \"%V\"", &code->name, e->line);
    }

    if (code->status) {
        e->status = code->status;

        if (!code->redirect) {
            e->ip = ngx_http_rewrite_exit;
            return;
        }
    }

    e->buf.len = code->size;

    if (code->uri) {
        if (!code->break_cycle) {
            r->uri_changed = 1;
        }

        if (rc && (r->quoted_uri || r->plus_in_uri)) {
            e->buf.len += 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
                                             NGX_ESCAPE_ARGS);
        }
    }

    for (n = 1; n < (ngx_uint_t) rc; n++) {
        e->buf.len += e->captures[2 * n + 1] - e->captures[2 * n];
    }

    if (code->args && r->args.len) {
        e->buf.len += r->args.len + 1;
    }

    if (!(e->buf.data = ngx_palloc(r->pool, e->buf.len))) {
        e->ip = ngx_http_rewrite_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->quote = code->redirect;

    e->pos = e->buf.data;

    e->ip += sizeof(ngx_http_rewrite_regex_code_t);
}


static void
ngx_http_rewrite_regex_end_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_request_t                 *r;
    ngx_http_rewrite_regex_end_code_t  *code;

    code = (ngx_http_rewrite_regex_end_code_t *) e->ip;

    r = e->request;

    e->quote = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http rewrite end");

    if (e->args) {
        e->buf.len = e->args - e->buf.data;

        if (code->args && r->args.len) {
            *e->pos++ = '&';
            e->pos = ngx_cpymem(e->pos, r->args.data, r->args.len);
        }

        r->args.len = e->pos - e->args;
        r->args.data = e->args;

        e->args = NULL;

    } else {
        if (code->args && r->args.len) {
            *e->pos++ = '?';
            e->pos = ngx_cpymem(e->pos, r->args.data, r->args.len);
        }

        e->buf.len = e->pos - e->buf.data;
    }

    if (!code->redirect) {
        if (e->conf->log) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "rewritten data: \"%V\", args: \"%V\"",
                          &e->buf, &r->args);
        }

        if (code->uri) {
            r->uri = e->buf;

            if (ngx_http_set_exten(r) != NGX_OK) {
                e->ip = ngx_http_rewrite_exit;
                e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return;
            }
        }

        e->ip += sizeof(ngx_http_rewrite_regex_end_code_t);
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "rewritten redirect: \"%V\"", &e->buf);

    if (!(r->headers_out.location = ngx_list_push(&r->headers_out.headers))) {
        e->ip = ngx_http_rewrite_exit;
        e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->buf.data[0] != '/') {
        r->headers_out.location->key.len = sizeof("Location") - 1;
        r->headers_out.location->key.data = (u_char *) "Location";
    }

    r->headers_out.location->value = e->buf;

    e->ip += sizeof(ngx_http_rewrite_regex_end_code_t);
}


static void
ngx_http_rewrite_copy_capture_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_rewrite_copy_capture_code_t  *code;

    code = (ngx_http_rewrite_copy_capture_code_t *) e->ip;

    e->ip += sizeof(ngx_http_rewrite_copy_capture_code_t);

    if ((e->args || e->quote)
        && (e->request->quoted_uri || e->request->plus_in_uri))
    {
        e->pos = (u_char *) ngx_escape_uri(e->pos,
                                &e->line->data[e->captures[code->n]],
                                e->captures[code->n + 1] - e->captures[code->n],
                                NGX_ESCAPE_ARGS);
    } else {
        e->pos = ngx_cpymem(e->pos, &e->line->data[e->captures[code->n]],
                        e->captures[code->n + 1] - e->captures[code->n]);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite capture: \"%V\"", &e->buf);
}


static void
ngx_http_rewrite_copy_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_rewrite_copy_code_t  *code;

    code = (ngx_http_rewrite_copy_code_t *) e->ip;

    e->pos = ngx_cpymem(e->pos, e->ip + sizeof(ngx_http_rewrite_copy_code_t),
                        code->len);

    e->ip += sizeof(ngx_http_rewrite_copy_code_t)
             + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite copy: \"%V\"", &e->buf);
}


static void
ngx_http_rewrite_start_args_code(ngx_http_rewrite_engine_t *e)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite args");

    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}


static void
ngx_http_rewrite_return_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_rewrite_return_code_t  *code;

    code = (ngx_http_rewrite_return_code_t *) e->ip;

    e->status = code->status;

    e->ip += sizeof(ngx_http_rewrite_return_code_t) - sizeof(uintptr_t);
}


static void
ngx_http_rewrite_if_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_rewrite_if_code_t  *code;

    code = (ngx_http_rewrite_if_code_t *) e->ip;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite if");

    if (*e->sp--) {
        if (code->loc_conf) {
            e->request->loc_conf = code->loc_conf;
        }

        e->ip += sizeof(ngx_http_rewrite_if_code_t);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite if false");

    e->ip += code->next;
}


static void
ngx_http_rewrite_var_code(ngx_http_rewrite_engine_t *e)
{
    ngx_http_variable_value_t    *value;
    ngx_http_rewrite_var_code_t  *code;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite var");

    code = (ngx_http_rewrite_var_code_t *) e->ip;

    e->sp++;

    e->ip += sizeof(ngx_http_rewrite_var_code_t);

    if (!(value = ngx_http_get_indexed_variable(e->request, code->index))) {
        *e->sp = (uintptr_t) 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http rewrite var: %p", value->value);

    *e->sp = value->value;
}


static void
ngx_http_rewrite_invalid_referer_code(ngx_http_rewrite_engine_t *e)
{
    u_char                       *ref;
    size_t                        len;
    ngx_uint_t                    i, n;
    ngx_http_request_t           *r;
    ngx_http_rewrite_referer_t   *refs;
    ngx_http_rewrite_loc_conf_t  *cf;

    r = e->request;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http rewrite invalid referer");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_rewrite_module);

    e->sp++;
    e->ip += sizeof(uintptr_t);

    if (cf->referers == NULL) {
        *e->sp = (uintptr_t) 0;
        return;
    }

    if (r->headers_in.referer == NULL) {
        if (cf->no_referer) {
            *e->sp = (uintptr_t) 0;
            return;
        } else {
            *e->sp = (uintptr_t) 1;
            return;
        }
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len < sizeof("http://i.ru") - 1
        || (ngx_strncasecmp(ref, "http://", 7) != 0))
    {
        *e->sp = (uintptr_t) 1;
        return;
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
                    *e->sp = (uintptr_t) 0;
                    return;
                }
            }

        } else {
            if (ngx_strncasecmp(refs[i].name.data, ref, refs[i].name.len) == 0)
            {
                *e->sp = (uintptr_t) 0;
                return;
            }
        }
    }

    *e->sp = (uintptr_t) 1;
}


static void
ngx_http_rewrite_nop_code(ngx_http_rewrite_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}


static ngx_int_t
ngx_http_rewrite_init(ngx_cycle_t *cycle)
{   
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    
    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_push_array(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    
    *h = ngx_http_rewrite_handler;
    
    return NGX_OK;
}   


static void *
ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rewrite_loc_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rewrite_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    conf->stack_size = NGX_CONF_UNSET_UINT;
    conf->log = NGX_CONF_UNSET;
    conf->no_referer = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rewrite_loc_conf_t *prev = parent;
    ngx_http_rewrite_loc_conf_t *conf = child;

    uintptr_t                      *code, *last;
    ngx_http_rewrite_regex_code_t  *regex;

    ngx_conf_merge_value(conf->log, prev->log, 0);
    ngx_conf_merge_unsigned_value(conf->stack_size, prev->stack_size, 10);

    if (conf->referers == NULL) {
        conf->referers = prev->referers;
        ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
    }

    if (conf->no_referer == NGX_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->codes == NULL) {
        return NGX_CONF_OK;
    }

    if (conf->codes == prev->codes) {
        return NGX_CONF_OK;
    }

    code = conf->codes->elts;
    last = (uintptr_t *) ((u_char *) code + conf->codes->nelts);

    while (code < last) {
        if (*code == (uintptr_t) NULL) {
            return NGX_CONF_OK;
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_regex_start_code) {
            regex = (ngx_http_rewrite_regex_code_t *) code;
            if (conf->max_captures < regex->ncaptures) {
                conf->max_captures = regex->ncaptures;
            }
            code = (uintptr_t *) ((u_char *) code + regex->next);
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_if_code) {
            code += sizeof(ngx_http_rewrite_if_code_t) / sizeof(uintptr_t);
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_return_code) {
            code += sizeof(ngx_http_rewrite_return_code_t) / sizeof(uintptr_t);
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_var_code) {
            code += sizeof(ngx_http_rewrite_var_code_t) / sizeof(uintptr_t);
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_invalid_referer_code) {
            code++;
        }

        if (*code == (uintptr_t) &ngx_http_rewrite_nop_code) {
            code++;
        }
    }

    if (!(code = ngx_array_push_n(conf->codes, sizeof(uintptr_t)))) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;
    
    u_char                                *data;
    size_t                                 len, size;
    ngx_str_t                             *value, err;
    ngx_uint_t                             i, n, last;
    ngx_http_rewrite_code_pt              *code;
    ngx_http_rewrite_copy_code_t          *copy;
    ngx_http_rewrite_regex_code_t         *regex;
    ngx_http_rewrite_regex_end_code_t     *regex_end;
    ngx_http_rewrite_copy_capture_code_t  *copy_capture;
    u_char                                 errstr[NGX_MAX_CONF_ERRSTR];

    regex = ngx_http_rewrite_start_code(cf->pool, &lcf->codes,
                                        sizeof(ngx_http_rewrite_regex_code_t));
    if (regex == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    err.len = NGX_MAX_CONF_ERRSTR;
    err.data = errstr;

    /* TODO: NGX_REGEX_CASELESS */

    regex->regex = ngx_regex_compile(&value[1], 0, cf->pool, &err);

    if (regex->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
        return NGX_CONF_ERROR;
    }

    regex->code = ngx_http_rewrite_regex_start_code;
    regex->size = 0;
    regex->ncaptures = 0;
    regex->status = 0;
    regex->uri = 1;
    regex->args = 1;
    regex->redirect = 0;
    regex->name = value[1];

    last = 0;

    if (ngx_strncmp(value[2].data, "http://", sizeof("http://") - 1) == 0) {
        regex->status = NGX_HTTP_MOVED_TEMPORARILY;
        regex->redirect = 1;
        last = 1;
    }

    if (cf->args->nelts == 4) {
        if (ngx_strcmp(value[3].data, "last") == 0) {
            last = 1;

        } else if (ngx_strcmp(value[3].data, "break") == 0) {
            regex->break_cycle = 1;
            last = 1;

        } else if (ngx_strcmp(value[3].data, "redirect") == 0) {
            regex->status = NGX_HTTP_MOVED_TEMPORARILY;
            regex->redirect = 1;
            last = 1;

        } else if (ngx_strcmp(value[3].data, "permanent") == 0) {
            regex->status = NGX_HTTP_MOVED_PERMANENTLY;
            regex->redirect = 1;
            last = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }
    }

    i = 0;

    while (i < value[2].len) {

        data = &value[2].data[i];

        if (value[2].data[i] == '$' && i < value[2].len
            && value[2].data[i + 1] >= '1' && value[2].data[i + 1] <= '9')
        {

            /* the "$1" - "$9" captures */

            copy_capture = ngx_http_rewrite_add_code(lcf->codes,
                                  sizeof(ngx_http_rewrite_copy_capture_code_t),
                                  &regex);
            if (copy_capture == NULL) {
                return NGX_CONF_ERROR;
            }

            i++;

            copy_capture->code = ngx_http_rewrite_copy_capture_code;
            copy_capture->n = value[2].data[i] - '0';

            if (regex->ncaptures < copy_capture->n) {
                regex->ncaptures = copy_capture->n;
            }

            copy_capture->n *= 2;

            i++;

            continue;
        }

        if (value[2].data[i] == '?') {

            /* the arguments */

            if (i == value[2].len - 1) {
                /* the last "?" drops the original arguments */
                regex->args = 0;
                break;
            }

            if (!regex->redirect) {
                code = ngx_http_rewrite_add_code(lcf->codes, sizeof(uintptr_t),
                                                 &regex);
                if (code == NULL) {
                    return NGX_CONF_ERROR;
                }

                *code = ngx_http_rewrite_start_args_code;

                i++;

                continue;
            }
        }

        i++;

        /* the substituion strings */

        while (i < value[2].len && value[2].data[i] != '$') {

            if (value[2].data[i] == '?') {

                if (i == value[2].len - 1) {
                    /*
                     * the last "?" drops the original arguments,
                     * and it should not be copied to a substituion
                     */
                    regex->args = 0;
                    break;
                }

                if (!regex->redirect) {
                    break;
                }
            }

            i++;
        }

        len = &value[2].data[i] - data;

        if (len == 0) {
            continue;
        }

        regex->size += len;

        size = (len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

        copy = ngx_http_rewrite_add_code(lcf->codes,
                                   sizeof(ngx_http_rewrite_copy_code_t) + size,
                                   &regex);
        if (copy == NULL) {
            return NGX_CONF_ERROR;
        }

        copy->code = ngx_http_rewrite_copy_code;
        copy->len = len;

        ngx_memcpy((u_char *) copy + sizeof(ngx_http_rewrite_copy_code_t),
                   data, len);
    }

    n = ngx_regex_capture_count(regex->regex);

    if (regex->ncaptures > n) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pattern \"%V\" has less captures "
                           "than referrenced in substitution \"%V\"",
                           &value[1], &value[2]);
        return NGX_CONF_ERROR;
    }

    if (regex->ncaptures < n) {
        regex->ncaptures = n;
    }

    if (regex->ncaptures) {
        regex->ncaptures = (regex->ncaptures + 1) * 3;
    }

    regex_end = ngx_http_rewrite_add_code(lcf->codes,
                                     sizeof(ngx_http_rewrite_regex_end_code_t),
                                     &regex);
    if (regex_end == NULL) {
        return NGX_CONF_ERROR;
    }

    regex_end->code = ngx_http_rewrite_regex_end_code;
    regex_end->uri = regex->uri;
    regex_end->args = regex->args;
    regex_end->redirect = regex->redirect;

    if (last) {
        code = ngx_http_rewrite_add_code(lcf->codes, sizeof(uintptr_t),
                                         &regex);
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    regex->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                              - (u_char *) regex;

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    ngx_str_t                       *value;
    ngx_http_rewrite_return_code_t  *ret;

    ret = ngx_http_rewrite_start_code(cf->pool, &lcf->codes,
                                      sizeof(ngx_http_rewrite_return_code_t));
    if (ret == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ret->code = ngx_http_rewrite_return_code;
    ret->null = (uintptr_t) NULL;

    ret->status = ngx_atoi(value[1].data, value[1].len);

    if (ret->status == (uintptr_t) NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    void                         *mconf;
    char                         *rv;
    u_char                       *elts;
    ngx_str_t                    *value;
    ngx_int_t                     index;
    ngx_uint_t                    i;
    ngx_conf_t                    save;
    ngx_http_rewrite_code_pt     *code;
    ngx_http_module_t            *module;
    ngx_http_conf_ctx_t          *ctx, *pctx;
    ngx_http_core_loc_conf_t     *clcf, *pclcf, **clcfp;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_rewrite_if_code_t   *if_code;
    ngx_http_rewrite_var_code_t  *var_code;
    ngx_http_rewrite_loc_conf_t  *nlcf;

    if (!(ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)))) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf; 

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;
    
        if (module->create_loc_conf) {

            if (!(mconf = module->create_loc_conf(cf))) {
                 return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
        }
    }

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    if (pclcf->locations.elts == NULL) {
        if (ngx_array_init(&pclcf->locations, cf->pool, 4, sizeof(void *))
                                                                  == NGX_ERROR)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (!(clcfp = ngx_push_array(&pclcf->locations))) {
        return NGX_CONF_ERROR;
    }

    *clcfp = clcf;


    /* STUB: "if ($var)" */

    value = cf->args->elts;

    if (value[1].len < 2
        || value[1].data[0] != '('
        || value[1].data[1] != '$'
        || value[1].data[value[1].len - 1] != ')')
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len -= 3;
    value[1].data += 2;

    if (value[1].len == sizeof("invalid_referer") - 1
        && ngx_strncmp(value[1].data, "invalid_referer",
                       sizeof("invalid_referer") - 1) == 0)
    {
        code = ngx_http_rewrite_start_code(cf->pool, &lcf->codes,
                                           sizeof(ngx_http_rewrite_code_pt));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = ngx_http_rewrite_invalid_referer_code;

    } else {
        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        index = ngx_http_get_variable_index(cmcf, &value[1]);

        if (index == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown variable name \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        var_code = ngx_http_rewrite_start_code(cf->pool, &lcf->codes,
                                           sizeof(ngx_http_rewrite_var_code_t));
        if (var_code == NULL) {
            return NGX_CONF_ERROR;
        }

        var_code->code = ngx_http_rewrite_var_code;
        var_code->index = index;
    }

    if_code = ngx_array_push_n(lcf->codes, sizeof(ngx_http_rewrite_if_code_t));
    if (if_code == NULL) {
        return NULL;
    }

    if_code->code = ngx_http_rewrite_if_code;

    elts = lcf->codes->elts;


    /* the inside directives must compile to the same code array */

    nlcf = ctx->loc_conf[ngx_http_rewrite_module.ctx_index];
    nlcf->codes = lcf->codes;


    save = *cf;
    cf->ctx = ctx;

    if (pclcf->name.len == 0) {
        if_code->loc_conf = NULL;
        cf->cmd_type = NGX_HTTP_SIF_CONF;

    } else {
        if_code->loc_conf = ctx->loc_conf;
        cf->cmd_type = NGX_HTTP_LIF_CONF;
    }

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }


    if (elts != lcf->codes->elts) {
        if_code = (ngx_http_rewrite_if_code_t *)
                   ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
    }

    if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                                - (u_char *) if_code;

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    ngx_uint_t                   i, server_names;
    ngx_str_t                   *value;
    ngx_http_server_name_t      *sn;
    ngx_http_core_srv_conf_t    *cscf;
    ngx_http_rewrite_referer_t  *ref;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    if (lcf->referers == NULL) {
        lcf->referers = ngx_array_create(cf->pool,
                                    cf->args->nelts + cscf->server_names.nelts,
                                    sizeof(ngx_http_rewrite_referer_t));
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

        if (ngx_strcmp(value[i].data, "server_names") == 0) {
            server_names = 1;
            continue;
        }

        if (!(ref = ngx_array_push(lcf->referers))) {
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
        if (!(ref = ngx_array_push(lcf->referers))) {
            return NGX_CONF_ERROR;
        }

        ref->name.len = sn[i].name.len + 1;
        if (!(ref->name.data = ngx_palloc(cf->pool, ref->name.len))) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(ref->name.data, sn[i].name.data, sn[i].name.len);
        ref->name.data[sn[i].name.len] = '/';
        ref->wildcard = sn[i].wildcard;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_rewrite_start_code(ngx_pool_t *pool, ngx_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        if (!(*codes = ngx_array_create(pool, 256, 1))) {
            return NULL;
        }
    }

    return ngx_array_push_n(*codes, size);
}


static void *
ngx_http_rewrite_add_code(ngx_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    if (!(new = ngx_array_push_n(codes, size))) {
        return NGX_CONF_ERROR;
    }

    if (elts != codes->elts) {
        p = code;
        *p += (u_char *) codes->elts - elts;
    }

    return new;
}
