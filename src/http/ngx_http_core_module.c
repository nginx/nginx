
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <nginx.h>


static void ngx_http_phase_event_handler(ngx_event_t *rev);
static void ngx_http_run_phases(ngx_http_request_t *r);

static void *ngx_http_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
                                          void *parent, void *child);
static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child);

static int ngx_http_core_init(ngx_cycle_t *cycle);
static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static int ngx_cmp_locations(const void *first, const void *second);
static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                void *dummy);
static char *ngx_types_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_type(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);
static char *ngx_set_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_lowat_post = { ngx_http_lowat_check } ;


static ngx_command_t  ngx_http_core_commands[] = {

    {ngx_string("server"),
     NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_server_block,
     0,
     0,
     NULL},

    {ngx_string("connection_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
     NULL},

    {ngx_string("post_accept_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, post_accept_timeout),
     NULL},

    {ngx_string("request_pool_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, request_pool_size),
     NULL},

    {ngx_string("client_header_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, client_header_timeout),
     NULL},

    {ngx_string("client_header_buffer_size"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, client_header_buffer_size),
     NULL},

    {ngx_string("large_client_header"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_core_srv_conf_t, large_client_header),
     NULL},

    {ngx_string("location"),
     NGX_HTTP_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_location_block,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("listen"),
#if 0
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
#else
     NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
#endif
     ngx_set_listen,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("server_name"),
     NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
     ngx_set_server_name,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("types"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                                         |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
     ngx_types_block,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("default_type"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, default_type),
     NULL},

    {ngx_string("root"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, doc_root),
     NULL},

    {ngx_string("client_body_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, client_body_timeout),
     NULL},

    {ngx_string("sendfile"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, sendfile),
     NULL},

    {ngx_string("send_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, send_timeout),
     NULL},

    {ngx_string("send_lowat"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, send_lowat),
     &ngx_http_lowat_post},

    {ngx_string("keepalive_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, keepalive_timeout),
     NULL},

    {ngx_string("lingering_time"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_time),
     NULL},

    {ngx_string("lingering_timeout"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_msec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, lingering_timeout),
     NULL},

    {ngx_string("msie_padding"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_core_loc_conf_t, msie_padding),
     NULL},

    {ngx_string("error_page"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
     ngx_set_error_page,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("error_log"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_set_error_log,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_core_module_ctx = {
    NULL,                                  /* pre conf */

    ngx_http_core_create_main_conf,        /* create main configuration */
    ngx_http_core_init_main_conf,          /* init main configuration */

    ngx_http_core_create_srv_conf,         /* create server configuration */
    ngx_http_core_merge_srv_conf,          /* merge server configuration */

    ngx_http_core_create_loc_conf,         /* create location configuration */
    ngx_http_core_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_core_module = {
    NGX_MODULE,
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_core_init,                    /* init module */
    NULL                                   /* init child */
};


void ngx_http_handler(ngx_http_request_t *r)
{
    ngx_http_log_ctx_t  *lcx;

    r->connection->unexpected_eof = 0;

    lcx = r->connection->log->data;
    lcx->action = NULL;

    switch (r->headers_in.connection_type) {
    case 0:
        if (r->http_version > NGX_HTTP_VERSION_10) {
            r->keepalive = 1;
        } else {
            r->keepalive = 0;
        }
        break;

    case NGX_HTTP_CONNECTION_CLOSE:
        r->keepalive = 0;
        break;

    case NGX_HTTP_CONNECTION_KEEP_ALIVE:
        r->keepalive = 1;
        break;
    }

#if 0
    /* TEST STUB */ r->http_version = NGX_HTTP_VERSION_10;
    /* TEST STUB */ r->keepalive = 0;
#endif

    if (r->headers_in.content_length_n > 0) {
        r->lingering_close = 1;

    } else {
        r->lingering_close = 0;
    }

#if 0
    /* TEST STUB */ r->lingering_close = 1;
#endif

    r->connection->write->event_handler = ngx_http_phase_event_handler;

    ngx_http_run_phases(r);

    return;
}


static void ngx_http_phase_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    c = ev->data;
    r = c->data;

    ngx_log_debug(ev->log, "phase event handler");

    ngx_http_run_phases(r);

    return;
}


static void ngx_http_run_phases(ngx_http_request_t *r)
{
    int                         rc;
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    rc = NGX_DECLINED;

    for (/* void */; r->phase < NGX_HTTP_LAST_PHASE; r->phase++) {

        h = cmcf->phases[r->phase].handlers.elts;
        for (r->phase_handler = cmcf->phases[r->phase].handlers.nelts - 1;
             r->phase_handler >= 0;
             r->phase_handler--)
        {
            rc = h[r->phase_handler](r);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_DECLINED) {
                continue;
            }

            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                ngx_http_finalize_request(r, rc);
                return;
            }

            if (rc == NGX_OK && cmcf->phases[r->phase].type == NGX_OK) {
                break;
            }
        }

        if (cmcf->phases[r->phase].post_handler) {
            rc = cmcf->phases[r->phase].post_handler(r);

            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                ngx_http_finalize_request(r, rc);
                return;
            }
        }
    }

    if (r->content_handler) {
        r->connection->write->event_handler = ngx_http_empty_handler;
        rc = r->content_handler(r);
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
}


int ngx_http_find_location_config(ngx_http_request_t *r)
{
    int                            i, rc;
    ngx_str_t                     *auto_redirect;
    ngx_http_core_loc_conf_t      *clcf, **clcfp;
    ngx_http_core_srv_conf_t      *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    auto_redirect = NULL;

    clcfp = cscf->locations.elts;
    for (i = 0; i < cscf->locations.nelts; i++) {
#if 0
ngx_log_debug(r->connection->log, "trans: %s" _ clcfp[i]->name.data);
#endif
        if (clcfp[i]->auto_redirect
            && r->uri.len == clcfp[i]->name.len - 1
            && ngx_strncmp(r->uri.data, clcfp[i]->name.data,
                           clcfp[i]->name.len - 1) == 0)
        {
            auto_redirect = &clcfp[i]->name;
            continue;
        }

        if (r->uri.len < clcfp[i]->name.len) {
            continue;
        }

        rc = ngx_strncmp(r->uri.data, clcfp[i]->name.data, clcfp[i]->name.len);

        if (rc < 0) {
            /* locations are lexicographically sorted */
            break;
        }

        if (rc == 0) {
            r->loc_conf = clcfp[i]->loc_conf;
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            r->connection->log->file = clcf->err_log->file;
            r->connection->log->log_level = clcf->err_log->log_level;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!(ngx_io.flags & NGX_IO_SENDFILE) || !clcf->sendfile) {
        r->sendfile = 0;

    } else {
        r->sendfile = 1;
    }

    if (auto_redirect) {
        if (!(r->headers_out.location =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

#if 0
        r->headers_out.location->key.len = 8;
        r->headers_out.location->key.data = "Location";
#endif
        r->headers_out.location->value = *auto_redirect;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    if (clcf->handler) {
        /*
         * if the location already has content handler then skip
         * the translation phase
         */

        r->content_handler = clcf->handler;
        r->phase++;
    }

    return NGX_OK;
}


int ngx_http_send_header(ngx_http_request_t *r)
{
    if (r->main) {
        return NGX_OK;
    }

    if (r->err_ctx) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return (*ngx_http_top_header_filter)(r);
}


int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    ngx_http_close_request(r, 0);
    return NGX_OK;
}


int ngx_http_error(ngx_http_request_t *r, int error)
{
    /* STUB */
    ngx_log_debug(r->connection->log, "http error: %d" _ error);

    /* log request */

    ngx_http_special_response_handler(r, error);
    ngx_http_close_request(r, 0);
    return NGX_OK;
}


int ngx_http_internal_redirect(ngx_http_request_t *r,
                               ngx_str_t *uri, ngx_str_t *args)
{
    int  i;

    ngx_log_debug(r->connection->log, "internal redirect: '%s'" _ uri->data);

    r->uri.len = uri->len;
    r->uri.data = uri->data;

    if (args) {
        r->args.len = args->len;
        r->args.data = args->data;
    }

    r->exten.len = 0;
    r->exten.data = NULL;

    for (i = uri->len - 1; i > 1; i--) {
        if (uri->data[i] == '.' && uri->data[i - 1] != '/') {
            r->exten.len = uri->len - i - 1;

            if (r->exten.len > 0) {
                ngx_test_null(r->exten.data,
                              ngx_palloc(r->pool, r->exten.len + 1),
                              NGX_HTTP_INTERNAL_SERVER_ERROR);

                ngx_cpystrn(r->exten.data, &uri->data[i + 1], r->exten.len + 1);
            }

            break;

        } else if (uri->data[i] == '/') {
            break;
        }
    }

    if (r->err_ctx) {

        /* allocate the new modules contexts */

        r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
        if (r->ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {

        /* clear the modules contexts */

        ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
    }

    r->phase = 0;
    r->phase_handler = 0;

    ngx_http_handler(r);

    return NGX_DONE;
}


#if 1       /* STUB: test the delay http handler */

int ngx_http_delay_handler(ngx_http_request_t *r)
{
    static int  on;

    if (on++ == 0) {
        ngx_log_debug(r->connection->log, "SET http delay");
        ngx_add_timer(r->connection->write, 10000);
        return NGX_AGAIN;
    }

    r->connection->write->timedout = 0;
    ngx_log_debug(r->connection->log, "RESET http delay");
    return NGX_DECLINED;
}

#endif


static int ngx_http_core_init(ngx_cycle_t *cycle)
{
#if 0
    ngx_http_handler_pt        *h;
#endif
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_core_main_conf_t  *cmcf;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

#if 0
    ngx_test_null(h, ngx_push_array(
                             &cmcf->phases[NGX_HTTP_TRANSLATE_PHASE].handlers),
                  NGX_ERROR);
    *h = ngx_http_delay_handler;
#endif

    return NGX_OK;
}


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    int                          m;
    char                        *rv;
    ngx_http_module_t           *module;
    ngx_conf_t                   pcf;
    ngx_http_conf_ctx_t         *ctx, *hctx, *pctx;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_core_srv_conf_t    *cscf, **cscfp;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    hctx = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->main_conf = hctx->main_conf;

    /* the server{}'s srv_conf */

    ngx_test_null(ctx->srv_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    /* the server{}'s loc_conf */

    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            ngx_test_null(ctx->srv_conf[ngx_modules[m]->ctx_index],
                          module->create_srv_conf(cf),
                          NGX_CONF_ERROR);
        }

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[ngx_modules[m]->ctx_index],
                          module->create_loc_conf(cf),
                          NGX_CONF_ERROR);
        }
    }

    /* create links of the srv_conf's */

    cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    ngx_test_null(cscfp, ngx_push_array(&cmcf->servers), NGX_CONF_ERROR);
    *cscfp = cscf;

    /* parse inside server{} */

    pcf = *cf;
    pctx = cf->ctx;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_SRV_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ngx_qsort(cscf->locations.elts, cscf->locations.nelts,
              sizeof(void *), ngx_cmp_locations);

    return rv;
}


static int ngx_cmp_locations(const void *first, const void *second)
{
    ngx_http_core_loc_conf_t *one = *(ngx_http_core_loc_conf_t **) first;
    ngx_http_core_loc_conf_t *two = *(ngx_http_core_loc_conf_t **) second;

    return ngx_strcmp(one->name.data, two->name.data);
}


static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    int                        m;
    char                      *rv;
    ngx_str_t                 *location;
    ngx_http_module_t         *module;
    ngx_conf_t                 pvcf;
    ngx_http_conf_ctx_t       *ctx, *pvctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf, **clcfp;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    pvctx = (ngx_http_conf_ctx_t *) cf->ctx;
    ctx->main_conf = pvctx->main_conf;
    ctx->srv_conf = pvctx->srv_conf;

    ngx_test_null(ctx->loc_conf,
                  ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module),
                  NGX_CONF_ERROR);

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_loc_conf) {
            ngx_test_null(ctx->loc_conf[ngx_modules[m]->ctx_index],
                          module->create_loc_conf(cf),
                          NGX_CONF_ERROR);
        }
    }

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    location = (ngx_str_t *) cf->args->elts;
    clcf->name.len = location[1].len;
    clcf->name.data = location[1].data;
    clcf->loc_conf = ctx->loc_conf;

    cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];
    ngx_test_null(clcfp, ngx_push_array(&cscf->locations), NGX_CONF_ERROR);
    *clcfp = clcf;

    pvcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pvcf;

    return rv;
}


static char *ngx_types_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *rv;
    ngx_conf_t   pcf;

    pcf = *cf;
    cf->handler = ngx_set_type;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

    return rv;
}


static char *ngx_set_type(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    int               i, key;
    ngx_str_t        *args;
    ngx_http_type_t  *t;

    if (lcf->types == NULL) {
        ngx_test_null(lcf->types,
                      ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t)),
                      NGX_CONF_ERROR);

        for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
            ngx_init_array(lcf->types[i], cf->pool, 5, sizeof(ngx_http_type_t),
                           NGX_CONF_ERROR);
        }
    }

    args = (ngx_str_t *) cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_http_types_hash_key(key, args[i]);

        ngx_test_null(t, ngx_push_array(&lcf->types[key]), NGX_CONF_ERROR);
        t->exten.len = args[i].len;
        t->exten.data = args[i].data;
        t->type.len = args[0].len;
        t->type.data = args[0].data;
    }

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;

    ngx_test_null(cmcf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_core_main_conf_t)),
                  NGX_CONF_ERROR);

    ngx_init_array(cmcf->servers, cf->pool,
                   5, sizeof(ngx_http_core_srv_conf_t *),
                   NGX_CONF_ERROR);

    return cmcf;
}


static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = conf;

    /* TODO: remove it if no directives */

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_core_srv_conf_t  *cscf;

    ngx_test_null(cscf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_core_srv_conf_t)),
                  NGX_CONF_ERROR);

    ngx_init_array(cscf->locations, cf->pool,
                   5, sizeof(void *), NGX_CONF_ERROR);
    ngx_init_array(cscf->listen, cf->pool, 5, sizeof(ngx_http_listen_t),
                   NGX_CONF_ERROR);
    ngx_init_array(cscf->server_names, cf->pool,
                   5, sizeof(ngx_http_server_name_t), NGX_CONF_ERROR);

    cscf->connection_pool_size = NGX_CONF_UNSET;
    cscf->post_accept_timeout = NGX_CONF_UNSET;
    cscf->request_pool_size = NGX_CONF_UNSET;
    cscf->client_header_timeout = NGX_CONF_UNSET;
    cscf->client_header_buffer_size = NGX_CONF_UNSET;
    cscf->large_client_header = NGX_CONF_UNSET;

    return cscf;
}


static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
                                          void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = parent;
    ngx_http_core_srv_conf_t *conf = child;

    ngx_http_listen_t        *l;
    ngx_http_server_name_t   *n;

    /* TODO: it does not merge, it inits only */

    if (conf->listen.nelts == 0) {
        ngx_test_null(l, ngx_push_array(&conf->listen), NGX_CONF_ERROR);
        l->addr = INADDR_ANY;
#if (WIN32)
        l->port = 80;
#else
        /* STUB: getuid() should be cached */
        l->port = (getuid() == 0) ? 80 : 8000;
#endif
        l->family = AF_INET;
    }

    if (conf->server_names.nelts == 0) {
        ngx_test_null(n, ngx_push_array(&conf->server_names), NGX_CONF_ERROR);
        ngx_test_null(n->name.data, ngx_palloc(cf->pool, NGX_MAXHOSTNAMELEN),
                      NGX_CONF_ERROR);

        if (gethostname(n->name.data, NGX_MAXHOSTNAMELEN) == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "gethostname() failed");
            return NGX_CONF_ERROR;
        }

        n->name.len = ngx_strlen(n->name.data);
        n->core_srv_conf = conf;
    }

    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 16384);
    ngx_conf_merge_msec_value(conf->post_accept_timeout,
                              prev->post_accept_timeout, 30000);
    ngx_conf_merge_size_value(conf->request_pool_size,
                              prev->request_pool_size, 16384);
    ngx_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);
    ngx_conf_merge_size_value(conf->client_header_buffer_size,
                              prev->client_header_buffer_size, 1024);
    ngx_conf_merge_value(conf->large_client_header,
                         prev->large_client_header, 1);

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_core_loc_conf_t *lcf;

    ngx_test_null(lcf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_core_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* set by ngx_pcalloc():

    lcf->doc_root.len = 0;
    lcf->doc_root.data = NULL;
    lcf->types = NULL;
    lcf->default_type.len = 0;
    lcf->default_type.data = NULL;
    lcf->err_log = NULL;
    lcf->error_pages = NULL;

    */

    lcf->client_body_timeout = NGX_CONF_UNSET;
    lcf->sendfile = NGX_CONF_UNSET;
    lcf->send_timeout = NGX_CONF_UNSET;
    lcf->send_lowat = NGX_CONF_UNSET;
    lcf->discarded_buffer_size = NGX_CONF_UNSET;
    lcf->keepalive_timeout = NGX_CONF_UNSET;
    lcf->lingering_time = NGX_CONF_UNSET;
    lcf->lingering_timeout = NGX_CONF_UNSET;

    lcf->msie_padding = NGX_CONF_UNSET;

    return lcf;
}


static ngx_http_type_t default_types[] = {
    { ngx_string("html"), ngx_string("text/html") },
    { ngx_string("gif"), ngx_string("image/gif") },
    { ngx_string("jpg"), ngx_string("image/jpeg") },
    { ngx_null_string, ngx_null_string }
};


static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child)
{
    ngx_http_core_loc_conf_t *prev = parent;
    ngx_http_core_loc_conf_t *conf = child;

    int               i, key;
    ngx_http_type_t  *t;

    ngx_conf_merge_str_value(conf->doc_root, prev->doc_root, "html");

    if (conf->types == NULL) {
        if (prev->types) {
            conf->types = prev->types;

        } else {
            ngx_test_null(conf->types,
                          ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t)),
                          NGX_CONF_ERROR);

            for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
                ngx_init_array(conf->types[i], cf->pool,
                               5, sizeof(ngx_http_type_t), NGX_CONF_ERROR);
            }

            for (i = 0; default_types[i].exten.len; i++) {
                ngx_http_types_hash_key(key, default_types[i].exten);

                ngx_test_null(t, ngx_push_array(&conf->types[key]),
                              NGX_CONF_ERROR);
                t->exten.len = default_types[i].exten.len;
                t->exten.data = default_types[i].exten.data;
                t->type.len = default_types[i].type.len;
                t->type.data = default_types[i].type.data;
            }
        }
    }

    if (conf->err_log == NULL) {
        if (prev->err_log) {
            conf->err_log = prev->err_log;
        } else {
            conf->err_log = cf->cycle->log;
        }
    }

    if (conf->error_pages == NULL && prev->error_pages) {
        conf->error_pages = prev->error_pages;
    }

    ngx_conf_merge_str_value(conf->default_type,
                             prev->default_type, "text/plain");

    ngx_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 10000);
    ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 10000);
    ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
    ngx_conf_merge_size_value(conf->discarded_buffer_size,
                              prev->discarded_buffer_size, 1500);
    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 70000);
    ngx_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    ngx_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);

    ngx_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);

    return NGX_CONF_OK;
}


static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    char               *addr;
    u_int               p;
    struct hostent     *h;
    ngx_str_t          *args;
    ngx_http_listen_t  *ls;

    /* TODO: check duplicate 'listen' directives,
             add resolved name to server names ??? */

    ngx_test_null(ls, ngx_push_array(&scf->listen), NGX_CONF_ERROR);

    /* AF_INET only */

    ls->family = AF_INET;
    ls->flags = 0;
    ls->file_name = cf->conf_file->file.name;
    ls->line = cf->conf_file->line;

    args = cf->args->elts;
    addr = args[1].data;

    for (p = 0; p < args[1].len; p++) {
        if (addr[p] == ':') {
            addr[p++] = '\0';
            break;
        }
    }

    if (p == args[1].len) {
        /* no ":" in the "listen" */
        p = 0;
    }

    ls->port = ngx_atoi(&addr[p], args[1].len - p);
    if (ls->port == NGX_ERROR && p == 0) {

        /* "listen host" */
        ls->port = 80;

    } else if ((ls->port == NGX_ERROR && p != 0) /* "listen host:NONNUMBER" */
               || (ls->port < 1 || ls->port > 65536)) { /* "listen 99999" */

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid port \"%s\" in \"%s\" directive, "
                           "it must be a number between 1 and 65535",
                           &addr[p], cmd->name.data);

        return NGX_CONF_ERROR;

    } else if (p == 0) {
        ls->addr = INADDR_ANY;
        return NGX_CONF_OK;
    }

    ls->addr = inet_addr(addr);
    if (ls->addr == INADDR_NONE) {
        h = gethostbyname(addr);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                              "can not resolve host \"%s\" "
                              "in \"%s\" directive", addr, cmd->name.data);
            return NGX_CONF_ERROR;
        }

        ls->addr = *(u_int32_t *)(h->h_addr_list[0]);
    }

    return NGX_CONF_OK;
}


static char *ngx_set_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    int                      i;
    ngx_str_t               *value;
    ngx_http_server_name_t  *sn;

    /* TODO: several names */
    /* TODO: warn about duplicate 'server_name' directives */

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server name \"%s\" is invalid "
                               "in \"%s\" directive",
                               value[i].data, cmd->name.data);
            return NGX_CONF_ERROR;
        }

        ngx_test_null(sn, ngx_push_array(&scf->server_names), NGX_CONF_ERROR);

        sn->name.len = value[i].len;
        sn->name.data = value[i].data;
        sn->core_srv_conf = scf;
    }

    return NGX_CONF_OK;
}


static char *ngx_set_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    int                   i;
    ngx_str_t            *value;
    ngx_http_err_page_t  *err;

    if (lcf->error_pages == NULL) {
        lcf->error_pages = ngx_create_array(cf->pool, 5,
                                            sizeof(ngx_http_err_page_t));
        if (lcf->error_pages == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts - 1; i++) {
        ngx_test_null(err, ngx_push_array(lcf->error_pages), NGX_CONF_ERROR);
        err->code = ngx_atoi(value[i].data, value[i].len);
        if (err->code == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        if (err->code < 400 || err->code > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "value \"%s\" must be between 400 and 599",
                               value[i].data);
            return NGX_CONF_ERROR;
        }

        err->uri = value[cf->args->nelts - 1];
    }

    return NGX_CONF_OK;
}


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    ngx_test_null(lcf->err_log,
                  ngx_log_create_errlog(cf->cycle, &value[1]),
                  NGX_CONF_ERROR);

    return NGX_CONF_OK;
}


static char *ngx_http_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (HAVE_LOWAT_EVENT)

    int *np = data;

    if (*np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

#endif

    return NGX_CONF_OK;
}
