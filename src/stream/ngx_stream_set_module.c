
/*
 * Copyright (C) Pavel Pautov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


typedef struct {
    ngx_int_t                   index;
    ngx_stream_set_variable_pt  set_handler;
    uintptr_t                   data;
    ngx_stream_complex_value_t  value;
} ngx_stream_set_cmd_t;


typedef struct {
    ngx_array_t                 commands;
} ngx_stream_set_srv_conf_t;


static ngx_int_t ngx_stream_set_handler(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_set_var(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_set_init(ngx_conf_t *cf);
static void *ngx_stream_set_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_stream_set_commands[] = {

    { ngx_string("set"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
      ngx_stream_set,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_set_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_set_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_set_create_srv_conf,        /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_set_module = {
    NGX_MODULE_V1,
    &ngx_stream_set_module_ctx,            /* module context */
    ngx_stream_set_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
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
ngx_stream_set_handler(ngx_stream_session_t *s)
{
    ngx_str_t                     str;
    ngx_uint_t                    i;
    ngx_stream_set_cmd_t         *cmds;
    ngx_stream_set_srv_conf_t    *scf;
    ngx_stream_variable_value_t   vv;

    scf = ngx_stream_get_module_srv_conf(s, ngx_stream_set_module);
    cmds = scf->commands.elts;
    vv = ngx_stream_variable_null_value;

    for (i = 0; i < scf->commands.nelts; i++) {
        if (ngx_stream_complex_value(s, &cmds[i].value, &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (cmds[i].set_handler != NULL) {
            vv.len = str.len;
            vv.data = str.data;
            cmds[i].set_handler(s, &vv, cmds[i].data);

        } else {
            s->variables[cmds[i].index].len = str.len;
            s->variables[cmds[i].index].valid = 1;
            s->variables[cmds[i].index].no_cacheable = 0;
            s->variables[cmds[i].index].not_found = 0;
            s->variables[cmds[i].index].data = str.data;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_set_var(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    *v = ngx_stream_variable_null_value;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_set_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_set_handler;

    return NGX_OK;
}


static void *
ngx_stream_set_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_set_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_set_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->commands = { NULL };
     */

    return conf;
}


static char *
ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_set_srv_conf_t  *scf = conf;

    ngx_str_t                           *args;
    ngx_int_t                            index;
    ngx_stream_set_cmd_t                *set_cmd;
    ngx_stream_variable_t               *v;
    ngx_stream_compile_complex_value_t   ccv;

    args = cf->args->elts;

    if (args[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &args[1]);
        return NGX_CONF_ERROR;
    }

    args[1].len--;
    args[1].data++;

    v = ngx_stream_add_variable(cf, &args[1],
                                NGX_STREAM_VAR_CHANGEABLE|NGX_STREAM_VAR_WEAK);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_stream_get_variable_index(cf, &args[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_stream_set_var;
    }

    if (scf->commands.elts == NULL) {
        if (ngx_array_init(&scf->commands, cf->pool, 1,
                           sizeof(ngx_stream_set_cmd_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    set_cmd = ngx_array_push(&scf->commands);
    if (set_cmd == NULL) {
        return NGX_CONF_ERROR;
    }

    set_cmd->index = index;
    set_cmd->set_handler = v->set_handler;
    set_cmd->data = v->data;

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &args[2];
    ccv.complex_value = &set_cmd->value;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
