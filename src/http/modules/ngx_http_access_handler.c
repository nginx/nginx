
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* AF_INET only */

typedef struct {
    in_addr_t     mask;
    in_addr_t     addr;
    unsigned      deny;
} ngx_http_access_rule_t;


typedef struct {
    ngx_array_t  *rules;     /* array of ngx_http_access_rule_t */
} ngx_http_access_loc_conf_t;


static ngx_int_t ngx_http_access_handler(ngx_http_request_t *r);
static char *ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static void *ngx_http_access_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_access_merge_loc_conf(ngx_conf_t *cf,
                                            void *parent, void *child);
static ngx_int_t ngx_http_access_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_access_commands[] = {

    { ngx_string("allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_access_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};



ngx_http_module_t  ngx_http_access_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_access_create_loc_conf,       /* create location configuration */
    ngx_http_access_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_access_module = {
    NGX_MODULE,
    &ngx_http_access_module_ctx,           /* module context */
    ngx_http_access_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_access_init,                  /* init module */
    NULL                                   /* init process */
};


static ngx_int_t ngx_http_access_handler(ngx_http_request_t *r)
{
    ngx_uint_t                   i;
    struct sockaddr_in          *addr_in;
    ngx_http_access_rule_t      *rule;
    ngx_http_access_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_access_module);

    if (alcf->rules == NULL) {
        return NGX_OK;
    }

    /* AF_INET only */

    addr_in = (struct sockaddr_in *) r->connection->sockaddr;

    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%08X %08X %08X",
               addr_in->sin_addr.s_addr, rule[i].mask, rule[i].addr);

        if ((addr_in->sin_addr.s_addr & rule[i].mask) == rule[i].addr) {
            if (rule[i].deny) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "access forbidden by rule");

                return NGX_HTTP_FORBIDDEN;
            }

            return NGX_OK;
        }
    }

    return NGX_OK;
}


static char *ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_http_access_loc_conf_t *alcf = conf;

    ngx_str_t               *value;
    ngx_inet_cidr_t          in_cidr;
    ngx_http_access_rule_t  *rule;

    if (alcf->rules == NULL) {
        alcf->rules = ngx_create_array(cf->pool, 5,
                                       sizeof(ngx_http_access_rule_t));
        if (alcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (!(rule = ngx_push_array(alcf->rules))) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    rule->deny = (value[0].data[0] == 'd') ? 1 : 0;

    if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
        rule->mask = 0;
        rule->addr = 0;

        return NGX_CONF_OK;
    }

    rule->addr = inet_addr((char *) value[1].data);

    if (rule->addr != INADDR_NONE) {
        rule->mask = 0xffffffff;

        return NGX_CONF_OK;
    }

    if (ngx_ptocidr(&value[1], &in_cidr) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid paramter \"%s\"",
                           value[1].data);
        return NGX_CONF_ERROR;
    }

    rule->mask = in_cidr.mask;
    rule->addr = in_cidr.addr;

    return NGX_CONF_OK;
}


static void *ngx_http_access_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_loc_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *ngx_http_access_merge_loc_conf(ngx_conf_t *cf,
                                            void *parent, void *child)
{
    ngx_http_access_loc_conf_t  *prev = parent;
    ngx_http_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_access_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_push_array(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_access_handler;

    return NGX_OK;
}
