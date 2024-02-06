/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2023 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_ssl_engine.h>

/* dummy async engine provided by OpenSSL */


typedef struct {
    /* only async for dasync engine, typically sync or async */
    ngx_str_t       offload_mode;

    /* no need for dasync engine, typically event or poll */
    ngx_str_t       notify_mode;

    /* no need for dasync engine */
    ngx_str_t       poll_mode;
} ngx_ssl_engine_dasync_conf_t;


static ngx_int_t ngx_ssl_engine_dasync_send_ctrl(ngx_cycle_t *cycle);
static ngx_int_t ngx_ssl_engine_dasync_register_handler(ngx_cycle_t *cycle);

static char *ngx_ssl_engine_dasync_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_ssl_engine_dasync_create_conf(ngx_cycle_t *cycle);
static char *ngx_ssl_engine_dasync_init_conf(ngx_cycle_t *cycle, void *conf);

static void ngx_ssl_engine_dasync_process_exit(ngx_cycle_t *cycle);


static ngx_str_t      ssl_engine_dasync_name = ngx_string("dasync");

static ngx_command_t  ngx_ssl_engine_dasync_commands[] = {

    { ngx_string("dasync_engine"),
      NGX_SSL_ENGINE_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_ssl_engine_dasync_block,
      0,
      0,
      NULL },

    { ngx_string("dasync_offload_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_dasync_conf_t, offload_mode),
      NULL },

    { ngx_string("dasync_notify_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_dasync_conf_t, notify_mode),
      NULL },

    { ngx_string("dasync_poll_mode"),
      NGX_SSL_ENGINE_SUB_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_engine_dasync_conf_t, poll_mode),
      NULL },

      ngx_null_command
};

ngx_ssl_engine_module_t  ngx_ssl_engine_dasync_module_ctx = {
    &ssl_engine_dasync_name,
    ngx_ssl_engine_dasync_create_conf,               /* create configuration */
    ngx_ssl_engine_dasync_init_conf,                 /* init configuration */

    {
        NULL,
        ngx_ssl_engine_dasync_send_ctrl,
        ngx_ssl_engine_dasync_register_handler,
        NULL,
        NULL
    }
};

ngx_module_t  ngx_ssl_engine_dasync_module = {
    NGX_MODULE_V1,
    &ngx_ssl_engine_dasync_module_ctx,      /* module context */
    ngx_ssl_engine_dasync_commands,         /* module directives */
    NGX_SSL_ENGINE_MODULE,                  /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_ssl_engine_dasync_process_exit,     /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_ssl_engine_dasync_send_ctrl(ngx_cycle_t *cycle)
{
    const char *engine_id = "dasync";
    ENGINE     *e;

    e = ENGINE_by_id(engine_id);
    if (e == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ENGINE_by_id(\"dasync\") failed");
        return NGX_ERROR;
    }

    /* send ctrl before engine init */

    /* ssl engine global variable set */

    ENGINE_free(e);

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_engine_dasync_register_handler(ngx_cycle_t *cycle)
{

    /* set corresponding handler, e.g., external poll handler */

    return NGX_OK;
}


static char *
ngx_ssl_engine_dasync_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char           *rv;
    ngx_conf_t      pcf;

    pcf = *cf;
    cf->cmd_type = NGX_SSL_ENGINE_SUB_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}


static void *
ngx_ssl_engine_dasync_create_conf(ngx_cycle_t *cycle)
{
    ngx_ssl_engine_dasync_conf_t  *sedcf;

    sedcf = ngx_pcalloc(cycle->pool, sizeof(ngx_ssl_engine_dasync_conf_t));
    if (sedcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sedcf->offload_mode = NULL
     *     sedcf->notify_mode = NULL
     *     sedcf->poll_mode = NULL
     */

    return sedcf;
}


static char *
ngx_ssl_engine_dasync_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_ssl_engine_dasync_conf_t *sedcf = conf;

    /* init the conf values not set by the user */

    ngx_conf_init_str_value(sedcf->offload_mode, "async");

    /* check the validity of the conf vaules */

    if (ngx_strcmp(sedcf->offload_mode.data, "async") != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "wrong type for dasync_offload_mode");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_ssl_engine_dasync_process_exit(ngx_cycle_t *cycle)
{
    ENGINE_cleanup();
}
