
#include <ngx_config.h>
#include <ngx_config_command.h>
#include <ngx_http.h>
#include <ngx_http_core.h>
#include <ngx_http_config.h>


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool);
static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool);


static ngx_command_t ngx_http_core_commands[];


ngx_http_module_t  ngx_http_core_module = {
    NGX_HTTP_MODULE,
    ngx_http_core_create_srv_conf,         /* create server config */
    ngx_http_core_create_loc_conf,         /* create location config */
    ngx_http_core_commands,                /* module directives */
    NULL,                                  /* init module */
    NULL                                   /* init output body filter */
};


static ngx_command_t ngx_http_core_commands[] = {

    {"send_timeout", ngx_conf_set_time_slot,
     offsetof(ngx_http_core_loc_conf_t, send_timeout),
     NGX_HTTP_LOC_CONF, NGX_CONF_TAKE1,
     "set timeout for sending response"},

    {NULL}

};


static void *ngx_http_core_create_srv_conf(ngx_pool_t *pool)
{
    ngx_http_core_srv_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_srv_conf_t)),
                  NULL);

    return conf;
}

static void *ngx_http_core_create_loc_conf(ngx_pool_t *pool)
{
    ngx_http_core_loc_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_core_loc_conf_t)),
                  NULL);

    conf->send_timeout = NGX_CONF_UNSET;

    return conf;
}

#if 0
static void *ngx_http_core_create_conf(ngx_pool_t *pool)
{

    ngx_test_null(conf, ngx_palloc(pool, sizeof(ngx_http_core_conf_t)), NULL);

    ngx_test_null(conf->srv, ngx_http_core_create_srv_conf_t(pool), NULL);
    ngx_test_null(conf->loc, ngx_http_core_create_loc_conf_t(pool), NULL);
    conf->parent = 
    conf->next = NULL;
}
#endif
