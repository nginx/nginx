
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                   name;
    ngx_uint_t                  wildcard;
} ngx_http_rewrite_referer_t;


typedef struct {
    ngx_array_t                *codes;        /* uintptr_t */
    ngx_array_t                *referers;     /* ngx_http_rewrite_referer_t */

    ngx_uint_t                  captures;
    ngx_uint_t                  stack_size;

    ngx_flag_t                  log;

    ngx_flag_t                  no_referer;
    ngx_flag_t                  blocked_referer;
} ngx_http_rewrite_loc_conf_t;


static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_rewrite_init(ngx_cycle_t *cycle);
static char *ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_rewrite_return(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_rewrite_break(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char * ngx_http_rewrite_if_condition(ngx_conf_t *cf,
    ngx_http_rewrite_loc_conf_t *lcf);
static char *ngx_http_rewrite_variable(ngx_conf_t *cf,
    ngx_http_rewrite_loc_conf_t *lcf, ngx_str_t *value);
static char *ngx_http_rewrite_valid_referers(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_rewrite_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


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

    { ngx_string("break"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_NOARGS,
      ngx_http_rewrite_break,
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

    { ngx_string("set"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE2,
      ngx_http_rewrite_set,
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
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_rewrite_create_loc_conf,      /* create location configration */
    ngx_http_rewrite_merge_loc_conf        /* merge location configration */
};


ngx_module_t  ngx_http_rewrite_module = {
    NGX_MODULE_V1,
    &ngx_http_rewrite_module_ctx,          /* module context */ 
    ngx_http_rewrite_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_http_rewrite_init,                 /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_value_t  ngx_http_rewrite_null_value =
    { 0, ngx_string("") };


static ngx_int_t
ngx_http_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t     *e;
    ngx_http_rewrite_loc_conf_t  *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_rewrite_module);

    if (cf->codes == NULL) {
        return NGX_DECLINED;
    }

    e = ngx_pcalloc(r->pool, sizeof(ngx_http_script_engine_t));
    if (e == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->sp = ngx_pcalloc(r->pool,
                        cf->stack_size * sizeof(ngx_http_variable_value_t));
    if (e->sp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (cf->captures) {
        e->captures = ngx_palloc(r->pool, cf->captures * sizeof(int));
        if (e->captures == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        e->captures = NULL;
    }

    e->ip = cf->codes->elts;
    e->request = r;
    e->quote = 1;
    e->log = cf->log;
    e->status = NGX_DECLINED;

    while (*(uintptr_t *) e->ip) {
        code = *(ngx_http_script_code_pt *) e->ip;
        code(e);
    }

    return e->status;
}


static void
ngx_http_rewrite_invalid_referer_code(ngx_http_script_engine_t *e)
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

    e->ip += sizeof(uintptr_t);

    if (cf->referers == NULL) {
        e->sp->value = 0;
        e->sp->text.len = 0;
        e->sp->text.data = (u_char *) "";
        e->sp++;

        return;
    }

    if (r->headers_in.referer == NULL) {
        if (cf->no_referer) {
            e->sp->value = 0;
            e->sp->text.len = 0;
            e->sp->text.data = (u_char *) "";
            e->sp++;

            return;

        } else {
            e->sp->value = 1;
            e->sp->text.len = 1;
            e->sp->text.data = (u_char *) "1";
            e->sp++;

            return;
        }
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len < sizeof("http://i.ru") - 1
        || (ngx_strncasecmp(ref, "http://", 7) != 0))
    {
        if (cf->blocked_referer) {
            e->sp->value = 0;
            e->sp->text.len = 0;
            e->sp->text.data = (u_char *) "0";
            e->sp++;

            return;

        } else {
            e->sp->value = 1;
            e->sp->text.len = 1;
            e->sp->text.data = (u_char *) "1";
            e->sp++;

            return;
        }
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
                    e->sp->value = 0;
                    e->sp->text.len = 0;
                    e->sp->text.data = (u_char *) "";
                    e->sp++;

                    return;
                }
            }

        } else {
            if (ngx_strncasecmp(refs[i].name.data, ref, refs[i].name.len) == 0)
            {
                e->sp->value = 0;
                e->sp->text.len = 0;
                e->sp->text.data = (u_char *) "";
                e->sp++;

                return;
            }
        }
    }

    e->sp->value = 1;
    e->sp->text.len = 1;
    e->sp->text.data = (u_char *) "1";
    e->sp++;
}


static ngx_http_variable_value_t *
ngx_http_rewrite_var(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_t        *var;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    var = cmcf->variables.elts;

    /*
     * the ngx_http_rewrite_module sets variables directly in r->variables,
     * and they should be handled by ngx_http_get_indexed_variable(),
     * so the handler is called only if the variable is not initialized
     */

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "using uninitialized \"%V\" variable", &var[data].name);

    return &ngx_http_rewrite_null_value;
}


static void *
ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_rewrite_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rewrite_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->stack_size = NGX_CONF_UNSET_UINT;
    conf->log = NGX_CONF_UNSET;
    conf->no_referer = NGX_CONF_UNSET;
    conf->blocked_referer = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rewrite_loc_conf_t *prev = parent;
    ngx_http_rewrite_loc_conf_t *conf = child;

    uintptr_t  *code;

    ngx_conf_merge_value(conf->log, prev->log, 0);
    ngx_conf_merge_unsigned_value(conf->stack_size, prev->stack_size, 10);

    if (conf->referers == NULL) {
        conf->referers = prev->referers;
        ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        ngx_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
    }

    if (conf->no_referer == NGX_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == NGX_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    if (conf->codes == NULL) {
        return NGX_CONF_OK;
    }

    if (conf->codes == prev->codes) {
        return NGX_CONF_OK;
    }

    code = ngx_array_push_n(conf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_rewrite_init(ngx_cycle_t *cycle)
{   
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rewrite_handler;

    return NGX_OK;
}   


static char *
ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;
    
    ngx_str_t                         *value, err;
    ngx_int_t                          n;
    ngx_uint_t                         last;
    ngx_http_script_code_pt           *code;
    ngx_http_script_compile_t          sc;
    ngx_http_script_regex_code_t      *regex;
    ngx_http_script_regex_end_code_t  *regex_end;
    u_char                             errstr[NGX_MAX_CONF_ERRSTR];

    regex = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(ngx_http_script_regex_code_t));
    if (regex == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));

    value = cf->args->elts;

    err.len = NGX_MAX_CONF_ERRSTR;
    err.data = errstr;

    /* TODO: NGX_REGEX_CASELESS */

    regex->regex = ngx_regex_compile(&value[1], 0, cf->pool, &err);

    if (regex->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
        return NGX_CONF_ERROR;
    }

    regex->code = ngx_http_script_regex_start_code;
    regex->uri = 1;
    regex->name = value[1];

    if (value[2].data[value[2].len - 1] == '?') {

        /* the last "?" drops the original arguments */
        value[2].len--;

    } else {
        regex->add_args = 1;
    }

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

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &regex->lengths;
    sc.values = &lcf->codes;
    sc.variables = ngx_http_script_variables_count(&value[2]);
    sc.main = regex;
    sc.complete_lengths = 1;
    sc.compile_args = !regex->redirect;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    regex = sc.main;

    regex->ncaptures = sc.ncaptures;
    regex->size = sc.size;
    regex->args = sc.args;

    if (sc.variables == 0) {
        regex->lengths = NULL;
    }

    n = ngx_regex_capture_count(regex->regex);

    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_regex_capture_count_n " failed for "
                           "pattern \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (regex->ncaptures > (ngx_uint_t) n) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pattern \"%V\" has less captures "
                           "than referrenced in substitution \"%V\"",
                           &value[1], &value[2]);
        return NGX_CONF_ERROR;
    }

    if (regex->ncaptures < (ngx_uint_t) n) {
        regex->ncaptures = (ngx_uint_t) n;
    }

    if (regex->ncaptures) {
        regex->ncaptures = (regex->ncaptures + 1) * 3;

        if (lcf->captures < regex->ncaptures) {
            lcf->captures = regex->ncaptures;
        }
    }

    regex_end = ngx_http_script_add_code(lcf->codes,
                                      sizeof(ngx_http_script_regex_end_code_t),
                                      &regex);
    if (regex_end == NULL) {
        return NGX_CONF_ERROR;
    }

    regex_end->code = ngx_http_script_regex_end_code;
    regex_end->uri = regex->uri;
    regex_end->args = regex->args;
    regex_end->add_args = regex->add_args;
    regex_end->redirect = regex->redirect;

    if (last) {
        code = ngx_http_script_add_code(lcf->codes, sizeof(uintptr_t), &regex);
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

    ngx_str_t                      *value;
    ngx_http_script_return_code_t  *ret;

    ret = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                     sizeof(ngx_http_script_return_code_t));
    if (ret == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ret->code = ngx_http_script_return_code;
    ret->null = (uintptr_t) NULL;

    ret->status = ngx_atoi(value[1].data, value[1].len);

    if (ret->status == (uintptr_t) NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_break(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    ngx_http_script_code_pt  *code;

    code = ngx_http_script_start_code(cf->pool, &lcf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = ngx_http_script_break_code;

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    void                         *mconf;
    char                         *rv;
    u_char                       *elts;
    ngx_uint_t                    i;
    ngx_conf_t                    save;
    ngx_http_module_t            *module;
    ngx_http_conf_ctx_t          *ctx, *pctx;
    ngx_http_core_loc_conf_t     *clcf, *pclcf, **clcfp;
    ngx_http_script_if_code_t    *if_code;
    ngx_http_rewrite_loc_conf_t  *nlcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
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

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
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

    clcfp = ngx_array_push(&pclcf->locations);
    if (clcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *clcfp = clcf;


    if (ngx_http_rewrite_if_condition(cf, lcf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if_code = ngx_array_push_n(lcf->codes, sizeof(ngx_http_script_if_code_t));
    if (if_code == NULL) {
        return NULL;
    }

    if_code->code = ngx_http_script_if_code;

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


    if (lcf->captures < nlcf->captures) {
        lcf->captures = nlcf->captures;
    }


    if (elts != lcf->codes->elts) {
        if_code = (ngx_http_script_if_code_t *)
                   ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
    }

    if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                                - (u_char *) if_code;

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_if_condition(ngx_conf_t *cf, ngx_http_rewrite_loc_conf_t *lcf)
{
    ngx_str_t                     *value, err;
    ngx_uint_t                     cur, last, n;
    ngx_http_script_regex_code_t  *regex;
    u_char                         errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return NGX_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    if (value[cur].len > 1 && value[cur].data[0] == '$') {

        if (cur != last && cur + 2 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_rewrite_variable(cf, lcf, &value[cur])!= NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        if (cur == last) {
            return NGX_CONF_OK;
        }

        cur++;

        if ((value[cur].len == 1 && value[cur].data[0] != '~')
            || (value[cur].len == 2
                && value[cur].data[0] != '~' && value[cur].data[1] != '*'))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unexpected \"%V\" in condition", &value[cur]);
            return NGX_CONF_ERROR;
        }

        regex = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(ngx_http_script_regex_code_t));
        if (regex == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));

        err.len = NGX_MAX_CONF_ERRSTR;
        err.data = errstr;

        regex->regex = ngx_regex_compile(&value[last],
                                (value[cur].len == 2) ? NGX_REGEX_CASELESS : 0,
                                cf->pool, &err);

        if (regex->regex == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
            return NGX_CONF_ERROR;
        }

        regex->code = ngx_http_script_regex_start_code;
        regex->next = sizeof(ngx_http_script_regex_code_t);
        regex->test = 1;
        regex->name = value[last];

        n = ngx_regex_capture_count(regex->regex);

        if (n) {
            regex->ncaptures = (n + 1) * 3;

            if (lcf->captures < regex->ncaptures) {
                lcf->captures = regex->ncaptures;
            }
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_rewrite_variable(ngx_conf_t *cf, ngx_http_rewrite_loc_conf_t *lcf,
    ngx_str_t *value)
{
    ngx_int_t                    index;
    ngx_http_script_code_pt     *code;
    ngx_http_script_var_code_t  *var_code;

    value->len--;
    value->data++;

    if (value->len == sizeof("invalid_referer") - 1
        && ngx_strncmp(value->data, "invalid_referer",
                       sizeof("invalid_referer") - 1) == 0)
    {
        code = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(ngx_http_script_code_pt));
        if (code == NULL) {
            return NGX_CONF_ERROR;
        }

        *code = ngx_http_rewrite_invalid_referer_code;

    } else {
        index = ngx_http_get_variable_index(cf, value);

        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        var_code = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                           sizeof(ngx_http_script_var_code_t));
        if (var_code == NULL) {
            return NGX_CONF_ERROR;
        }

        var_code->code = ngx_http_script_var_code;
        var_code->index = index;
    }

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

        if (ngx_strcmp(value[i].data, "blocked") == 0) {
            lcf->blocked_referer = 1;
            continue;
        }

        if (ngx_strcmp(value[i].data, "server_names") == 0) {
            server_names = 1;
            continue;
        }

        ref = ngx_array_push(lcf->referers);
        if (ref == NULL) {
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
        ref = ngx_array_push(lcf->referers);
        if (ref == NULL) {
            return NGX_CONF_ERROR;
        }

        ref->name.len = sn[i].name.len + 1;
        ref->name.data = ngx_palloc(cf->pool, ref->name.len);
        if (ref->name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(ref->name.data, sn[i].name.data, sn[i].name.len);
        ref->name.data[sn[i].name.len] = '/';
        ref->wildcard = sn[i].wildcard;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_rewrite_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_rewrite_loc_conf_t *lcf = conf;

    ngx_int_t                              n, index;
    ngx_str_t                             *value;
    ngx_http_variable_t                   *v;
    ngx_http_script_compile_t              sc;
    ngx_http_script_var_code_t            *var;
    ngx_http_script_value_code_t          *val;
    ngx_http_script_complex_value_code_t  *complex;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    v->handler = ngx_http_rewrite_var;
    v->data = index;

    n = ngx_http_script_variables_count(&value[2]);

    if (n == 0) {
        val = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(ngx_http_script_value_code_t));
        if (val == NULL) {
            return NGX_CONF_ERROR;
        }

        n = ngx_atoi(value[2].data, value[2].len);

        if (n == NGX_ERROR) {
            n = 0;
        }

        val->code = ngx_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value[2].len;
        val->text_data = (uintptr_t) value[2].data;

    } else {
        complex = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                 sizeof(ngx_http_script_complex_value_code_t));
        if (complex == NULL) {
            return NGX_CONF_ERROR;
        }

        complex->code = ngx_http_script_complex_value_code;
        complex->lengths = NULL;

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf; 
        sc.source = &value[2];
        sc.lengths = &complex->lengths;
        sc.values = &lcf->codes;
        sc.variables = n;
        sc.complete_lengths = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_http_script_start_code(cf->pool, &lcf->codes,
                                     sizeof(ngx_http_script_var_code_t));
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->code = ngx_http_script_set_var_code;
    var->index = (uintptr_t) index;

    return NGX_CONF_OK;
}
