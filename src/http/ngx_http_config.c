
#include <ngx_core.h>
#include <ngx_config_command.h>
#include <ngx_http.h>
#include <ngx_http_write_filter.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_index_handler.h>


int ngx_max_module;

/* STUB: gobal srv and loc conf */
void **ngx_srv_conf;
void **ngx_loc_conf;


int ngx_http_config_modules(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;

    for (i = 0; modules[i]; i++) {
        modules[i]->index = i;
    }

    ngx_max_module = i;

    ngx_test_null(ngx_srv_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);
    ngx_test_null(ngx_loc_conf,
                  ngx_pcalloc(pool, sizeof(void *) * ngx_max_module),
                  NGX_ERROR);

    for (i = 0; modules[i]; i++) {
        if (modules[i]->create_srv_conf)
            ngx_srv_conf[i] = modules[i]->create_srv_conf(pool);

        if (modules[i]->create_loc_conf)
            ngx_loc_conf[i] = modules[i]->create_loc_conf(pool);
    }
}

int ngx_http_init_modules(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->init_module)
            modules[i]->init_module(pool);
    }
}

int ngx_http_init_filters(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    int (*filter)(ngx_http_request_t *r, ngx_chain_t *ch);

    filter = ngx_http_write_filter;

    for (i = 0; modules[i]; i++) {
        if (modules[i]->init_output_body_filter)
            modules[i]->init_output_body_filter(&filter);
    }
}


/* STUB */
ngx_http_output_filter_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_output_filter_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "output_buffer") == 0) {
                    cmd->set(ngx_loc_conf[i], cmd->offset, "32768");
                }
            }
        }
    }
}

ngx_http_write_filter_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_write_filter_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "write_buffer") == 0) {
                    cmd->set(ngx_loc_conf[i], cmd->offset, "1500");
                }
            }
        }
    }
}

ngx_http_index_set_stub(ngx_pool_t *pool, ngx_http_module_t **modules)
{
    int i;
    ngx_str_t index;
    ngx_command_t *cmd;

    for (i = 0; modules[i]; i++) {
        if (modules[i] == &ngx_http_index_module) {
            for (cmd = modules[i]->commands; cmd->name; cmd++) {
                if (strcmp(cmd->name, "index") == 0) {
                    index.len = sizeof("index.html") - 1;
                    index.data = "index.html";
                    cmd->set(pool, ngx_loc_conf[i], &index);
                }
            }
        }
    }
}
