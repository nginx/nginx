
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <nginx.h>

/* STUB */
#define NGX_HTTP_LOCATION_EXACT           1
#define NGX_HTTP_LOCATION_AUTO_REDIRECT   2
#define NGX_HTTP_LOCATION_REGEX           3


static void ngx_http_phase_event_handler(ngx_event_t *rev);
static void ngx_http_run_phases(ngx_http_request_t *r);
static ngx_int_t ngx_http_find_location(ngx_http_request_t *r,
                                        ngx_array_t *locations, size_t len);

static void *ngx_http_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
                                          void *parent, void *child);
static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child);

static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static int ngx_cmp_locations(const void *first, const void *second);
static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd,
                                void *dummy);
static char *ngx_types_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_type(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);
static char *ngx_set_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_lowat_post = { ngx_http_lowat_check } ;


static ngx_conf_enum_t  ngx_http_restrict_host_names[] = {
    { ngx_string("off"), NGX_HTTP_RESTRICT_HOST_OFF },
    { ngx_string("on"), NGX_HTTP_RESTRICT_HOST_ON },
    { ngx_string("close"), NGX_HTTP_RESTRICT_HOST_CLOSE },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_core_commands[] = {

    { ngx_string("server"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_server_block,
      0,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
      NULL },

    { ngx_string("post_accept_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, post_accept_timeout),
      NULL },

    { ngx_string("request_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, request_pool_size),
      NULL },

    { ngx_string("client_header_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, client_header_timeout),
      NULL },

    { ngx_string("client_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, client_header_buffer_size),
      NULL },

    { ngx_string("large_client_header_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, large_client_header_buffers),
      NULL },

    { ngx_string("restrict_host_names"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, restrict_host_names),
      &ngx_http_restrict_host_names },

    { ngx_string("location"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
      ngx_location_block,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("listen"),
#if 0
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
#else
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
#endif
      ngx_set_listen,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("server_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_set_server_name,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                                          |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_types_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("default_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, default_type),
      NULL },

    { ngx_string("root"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_set_root,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("alias"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_set_root,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("client_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_max_body_size),
      NULL },

    { ngx_string("client_body_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_buffer_size),
      NULL },

    { ngx_string("client_body_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_timeout),
      NULL },

    { ngx_string("sendfile"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, sendfile),
      NULL },

    { ngx_string("tcp_nopush"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, tcp_nopush),
      NULL },

    { ngx_string("send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, send_timeout),
      NULL },

    { ngx_string("send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, send_lowat),
      &ngx_http_lowat_post },

    { ngx_string("postpone_output"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, postpone_output),
      NULL },

    { ngx_string("limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, limit_rate),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_set_keepalive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lingering_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, lingering_time),
      NULL },

    { ngx_string("lingering_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, lingering_timeout),
      NULL },

    { ngx_string("reset_timedout_connection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, reset_timedout_connection),
      NULL },

    { ngx_string("msie_padding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, msie_padding),
      NULL },

    { ngx_string("error_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_set_error_page,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("error_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_set_error_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#if (NGX_HTTP_CACHE)

    { ngx_string("open_file_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE4,
      ngx_http_set_cache_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, open_files),
      NULL },

#endif

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
    NULL,                                  /* init module */
    NULL                                   /* init process */
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

    if (r->keepalive && r->headers_in.msie && r->method == NGX_HTTP_POST) {

        /*
         * MSIE may wait for some time if the response for the POST request
         * is sent over the keepalive connection
         */

        r->keepalive = 0;
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "phase event handler");

    ngx_http_run_phases(r);

    return;
}


static void ngx_http_run_phases(ngx_http_request_t *r)
{
    char                       *path;
    ngx_int_t                   rc;
    ngx_http_handler_pt        *h;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    for (/* void */; r->phase < NGX_HTTP_LAST_PHASE; r->phase++) {

        if (r->phase == NGX_HTTP_CONTENT_PHASE && r->content_handler) {
            r->connection->write->event_handler = ngx_http_empty_handler;
            rc = r->content_handler(r);
            ngx_http_finalize_request(r, rc);
            return;
        }

        h = cmcf->phases[r->phase].handlers.elts;
        for (r->phase_handler = cmcf->phases[r->phase].handlers.nelts - 1;
             r->phase_handler >= 0;
             r->phase_handler--)
        {
            rc = h[r->phase_handler](r);

            if (rc == NGX_DONE) {

                /*
                 * we should never use r here because 
                 * it could point to already freed data
                 */

                return;
            }

            if (rc == NGX_DECLINED) {
                continue;
            }

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_ERROR) {
                ngx_http_finalize_request(r, rc);
                return;
            }

            if (r->phase == NGX_HTTP_CONTENT_PHASE) {
                ngx_http_finalize_request(r, rc);
                return;
            }

            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc == NGX_OK && cmcf->phases[r->phase].type == NGX_OK) {
                break;
            }
        }
    }


    if (r->uri.data[r->uri.len - 1] == '/') {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (!(path = ngx_palloc(r->pool, clcf->root.len + r->uri.len))) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    
        ngx_cpystrn(ngx_cpymem(path, clcf->root.data, clcf->root.len),
                    r->uri.data, r->uri.len + 1);
    
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "directory index of \"%s\" is forbidden", path);

        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no handler found");

    ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
    return;
}


ngx_int_t ngx_http_find_location_config(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    rc = ngx_http_find_location(r, &cscf->locations, 0);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        return rc;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    r->connection->log->file = clcf->err_log->file;
    if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        r->connection->log->log_level = clcf->err_log->log_level;
    }

    if (!(ngx_io.flags & NGX_IO_SENDFILE) || !clcf->sendfile) {
        r->sendfile = 0;

    } else {
        r->sendfile = 1;
    }

    if (!clcf->tcp_nopush) {
        /* disable TCP_NOPUSH/TCP_CORK use */
        r->connection->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }


    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl: " SIZE_T_FMT " max: " SIZE_T_FMT,
                   r->headers_in.content_length_n,
                   clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && clcf->client_max_body_size
        && clcf->client_max_body_size < (size_t) r->headers_in.content_length_n)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client intented to send too large body: "
                      SIZE_T_FMT " bytes",
                      r->headers_in.content_length_n);

        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }


    if (rc == NGX_HTTP_LOCATION_AUTO_REDIRECT) {
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->value = clcf->name;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_find_location(ngx_http_request_t *r,
                                        ngx_array_t *locations, size_t len)
{
    ngx_int_t                  n, rc;
    ngx_uint_t                 i, found;
    ngx_http_core_loc_conf_t  *clcf, **clcfp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "find location");

    found = 0;

    clcfp = locations->elts;
    for (i = 0; i < locations->nelts; i++) {

#if (HAVE_PCRE)
        if (clcfp[i]->regex) {
            break;
        }
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "find location: %s\"%s\"",
                       clcfp[i]->exact_match ? "= " : "",
                       clcfp[i]->name.data);

        if (clcfp[i]->auto_redirect
            && r->uri.len == clcfp[i]->name.len - 1
            && ngx_strncmp(r->uri.data, clcfp[i]->name.data,
                                                  clcfp[i]->name.len - 1) == 0)
        {
            /* the locations are lexicographically sorted */

            r->loc_conf = clcfp[i]->loc_conf;

            return NGX_HTTP_LOCATION_AUTO_REDIRECT;
        }

        if (r->uri.len < clcfp[i]->name.len) {
            continue;
        }

        n = ngx_strncmp(r->uri.data, clcfp[i]->name.data, clcfp[i]->name.len);

        if (n < 0) {
            /* the locations are lexicographically sorted */
            break;
        }

        if (n == 0) {
            if (clcfp[i]->exact_match && r->uri.len == clcfp[i]->name.len) {
                r->loc_conf = clcfp[i]->loc_conf;
                return NGX_HTTP_LOCATION_EXACT;
            }

            if (len > clcfp[i]->name.len) {
                /* the previous match is longer */
                break;
            }

            r->loc_conf = clcfp[i]->loc_conf;
            found = 1;
        }
    }

    if (found) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->locations.nelts) {
            rc = ngx_http_find_location(r, &clcf->locations, len);

            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

#if (HAVE_PCRE)

    /* regex matches */

    for (/* void */; i < locations->nelts; i++) {

        if (!clcfp[i]->regex) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "find location: ~ \"%s\"",
                       clcfp[i]->name.data);

        n = ngx_regex_exec(clcfp[i]->regex, &r->uri, NULL, 0);

        if (n == NGX_DECLINED) {
            continue;
        }

        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          ngx_regex_exec_n
                          " failed: %d on \"%s\" using \"%s\"",
                          n, r->uri.data, clcfp[i]->name.data);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* match */

        r->loc_conf = clcfp[i]->loc_conf;

        return NGX_HTTP_LOCATION_REGEX;
    }

#endif /* HAVE_PCRE */

    return NGX_OK;
}


ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r)
{
    uint32_t                   key;
    ngx_uint_t                 i;
    ngx_http_type_t           *type;
    ngx_http_core_loc_conf_t  *clcf;

    r->headers_out.content_type = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.content_type == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.content_type->key.len = 0;
    r->headers_out.content_type->key.data = NULL;
    r->headers_out.content_type->value.len = 0;
    r->headers_out.content_type->value.data = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->exten.len) {
#if 0
        key = ngx_crc(r->exten.data, r->exten.key);
#endif
        ngx_http_types_hash_key(key, r->exten);

        type = clcf->types[key].elts;
        for (i = 0; i < clcf->types[key].nelts; i++) {
            if (r->exten.len != type[i].exten.len) {
                continue;
            }

            if (ngx_memcmp(r->exten.data, type[i].exten.data, r->exten.len)
                                                                           == 0)
            {
                r->headers_out.content_type->value = type[i].type;
                break;
            }
        }
    }

    if (r->headers_out.content_type->value.len == 0) {
        r->headers_out.content_type->value = clcf->default_type;
    }

    return NGX_OK;
}


ngx_int_t ngx_http_send_header(ngx_http_request_t *r)
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


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t  rc;

    if (r->connection->write->error) {
        return NGX_ERROR;
    }

    rc = ngx_http_top_body_filter(r, in);

    if (rc == NGX_ERROR) {

        /* NGX_ERROR could be returned by any filter */

        r->connection->write->error = 1;
    }

    return rc;
}


int ngx_http_redirect(ngx_http_request_t *r, int redirect)
{
    /* STUB */

    /* log request */

    ngx_http_close_request(r, 0);
    return NGX_OK;
}


ngx_int_t ngx_http_set_exten(ngx_http_request_t *r)
{
    ngx_int_t  i;

    r->exten.len = 0;
    r->exten.data = NULL;

    for (i = r->uri.len - 1; i > 1; i--) {
        if (r->uri.data[i] == '.' && r->uri.data[i - 1] != '/') {
            r->exten.len = r->uri.len - i - 1;

            if (r->exten.len > 0) {
                if (!(r->exten.data = ngx_palloc(r->pool, r->exten.len + 1))) {
                    return NGX_ERROR;
                }

                ngx_cpystrn(r->exten.data, &r->uri.data[i + 1],
                            r->exten.len + 1);
            }

            break;

        } else if (r->uri.data[i] == '/') {
            break;
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
                                     ngx_str_t *uri, ngx_str_t *args)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%s\"", uri->data);

    r->uri.len = uri->len;
    r->uri.data = uri->data;

    if (args) {
        r->args.len = args->len;
        r->args.data = args->data;
    }

    if (ngx_http_set_exten(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
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


#if 0       /* STUB: test the delay http handler */

int ngx_http_delay_handler(ngx_http_request_t *r)
{
    static int  on;

    if (on++ == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http set delay");
        ngx_add_timer(r->connection->write, 10000);
        return NGX_AGAIN;
    }

    r->connection->write->timedout = 0;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reset delay");
    return NGX_DECLINED;
}

#endif


#if 0

static ngx_int_t ngx_http_core_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

#if 0
    ngx_http_core_init_module:

    ngx_http_handler_pt         *h;

    ngx_test_null(h, ngx_push_array(
                             &cmcf->phases[NGX_HTTP_TRANSLATE_PHASE].handlers),
                  NGX_ERROR);
    *h = ngx_http_delay_handler;
#endif

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        if (cscfp[i]->recv == NULL) {
            cscfp[i]->recv = ngx_io.recv;
            cscfp[i]->send_chain = ngx_io.send_chain;
        }
    }

    return NGX_OK;
}

#endif


static char *ngx_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    int                          m;
    char                        *rv;
    ngx_http_module_t           *module;
    ngx_conf_t                   pvcf;
    ngx_http_conf_ctx_t         *ctx, *http_ctx;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_core_srv_conf_t    *cscf, **cscfp;

    ngx_test_null(ctx,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t)),
                  NGX_CONF_ERROR);

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

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

    pvcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_SRV_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pvcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ngx_qsort(cscf->locations.elts, (size_t) cscf->locations.nelts,
              sizeof(ngx_http_core_loc_conf_t *), ngx_cmp_locations);

    return rv;
}


static int ngx_cmp_locations(const void *one, const void *two)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *first, *second;

    first = *(ngx_http_core_loc_conf_t **) one;
    second = *(ngx_http_core_loc_conf_t **) two;

#if (HAVE_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = ngx_strcmp(first->name.data, second->name.data);

    if (rc == 0 && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static char *ngx_location_block(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    ngx_int_t                  m;
    ngx_str_t                 *value;
    ngx_conf_t                 pcf;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf, *pclcf, **clcfp;
#if (HAVE_PCRE)
    ngx_str_t                  err;
    u_char                     errstr[NGX_MAX_CONF_ERRSTR];
#endif

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

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[ngx_modules[m]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[ngx_modules[m]->ctx_index] == NULL) {
                 return NGX_CONF_ERROR;
            }
        }
    }

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;

    value = cf->args->elts;

    if (cf->args->nelts == 3) {
        if (value[1].len == 1 && value[1].data[0] == '=') {
            clcf->name.len = value[2].len;
            clcf->name.data = value[2].data;
            clcf->exact_match = 1;

        } else if ((value[1].len == 1 && value[1].data[0] == '~')
                   || (value[1].len == 2
                       && value[1].data[0] == '~'
                       && value[1].data[1] == '*'))
        {
#if (HAVE_PCRE)
            err.len = NGX_MAX_CONF_ERRSTR;
            err.data = errstr;

            clcf->regex = ngx_regex_compile(&value[2],
                                     value[1].len == 2 ? NGX_REGEX_CASELESS: 0,
                                     cf->pool, &err);

            if (clcf->regex == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
                return NGX_CONF_ERROR;
            }

            clcf->name = value[2];
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the using of the regex \"%s\" "
                               "requires PCRE library",
                               value[2].data);
            return NGX_CONF_ERROR;
#endif

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%s\"",
                               value[1].data);
            return NGX_CONF_ERROR;
        }

    } else {
        clcf->name.len = value[1].len;
        clcf->name.data = value[1].data;
    }

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    if (pclcf->name.len == 0) {
        cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];
        if (!(clcfp = ngx_push_array(&cscf->locations))) {
            return NGX_CONF_ERROR;
        }

    } else {
        clcf->prev_location = pclcf;

        if (pclcf->exact_match) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%s\" could not be inside "
                               "the exact location \"%s\"",
                               clcf->name.data, pclcf->name.data);
            return NGX_CONF_ERROR;
        }

#if (HAVE_PCRE)
        if (clcf->regex == NULL
            && ngx_strncmp(clcf->name.data, pclcf->name.data, pclcf->name.len)
                                                                         != 0)
#else
        if (ngx_strncmp(clcf->name.data, pclcf->name.data, pclcf->name.len)
                                                                         != 0)
#endif
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%s\" is outside location \"%s\"",
                               clcf->name.data, pclcf->name.data);
            return NGX_CONF_ERROR;
        }

        if (pclcf->locations.elts == NULL) {
            ngx_init_array(pclcf->locations, cf->pool, 5, sizeof(void *),
                           NGX_CONF_ERROR);
        }

        if (!(clcfp = ngx_push_array(&pclcf->locations))) {
            return NGX_CONF_ERROR;
        }
    }

    *clcfp = clcf;

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;

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

    uint32_t          key;
    ngx_uint_t        i;
    ngx_str_t        *args;
    ngx_http_type_t  *type;

    if (lcf->types == NULL) {
        lcf->types = ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t));
        if (lcf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
            if (ngx_array_init(&lcf->types[i], cf->pool, 5,
                                         sizeof(ngx_http_type_t)) == NGX_ERROR)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    args = (ngx_str_t *) cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_http_types_hash_key(key, args[i]);

        if (!(type = ngx_array_push(&lcf->types[key]))) {
            return NGX_CONF_ERROR;
        }

        type->exten = args[i];
        type->type = args[0];
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
#if 0
    ngx_http_core_main_conf_t *cmcf = conf;

    /* TODO: remove it if no directives */
#endif

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_core_srv_conf_t  *cscf;

    ngx_test_null(cscf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_core_srv_conf_t)),
                  NGX_CONF_ERROR);

    /*

    set by ngx_pcalloc():

    conf->client_large_buffers.num = 0;

    */


    ngx_init_array(cscf->locations, cf->pool,
                   5, sizeof(void *), NGX_CONF_ERROR);
    ngx_init_array(cscf->listen, cf->pool, 5, sizeof(ngx_http_listen_t),
                   NGX_CONF_ERROR);
    ngx_init_array(cscf->server_names, cf->pool,
                   5, sizeof(ngx_http_server_name_t), NGX_CONF_ERROR);

    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->post_accept_timeout = NGX_CONF_UNSET_MSEC;
    cscf->request_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->client_header_timeout = NGX_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->restrict_host_names = NGX_CONF_UNSET_UINT;

    return cscf;
}


static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
                                          void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = parent;
    ngx_http_core_srv_conf_t *conf = child;

    ngx_http_listen_t          *l;
    ngx_http_server_name_t     *n;
    ngx_http_core_main_conf_t  *cmcf;

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

        if (gethostname((char *) n->name.data, NGX_MAXHOSTNAMELEN) == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "gethostname() failed");
            return NGX_CONF_ERROR;
        }

        n->name.len = ngx_strlen(n->name.data);
        n->core_srv_conf = conf;

#if 0
        ctx = (ngx_http_conf_ctx_t *)
                                    cf->cycle->conf_ctx[ngx_http_module.index];
        cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
#endif
        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        if (cmcf->max_server_name_len < n->name.len) {
            cmcf->max_server_name_len = n->name.len;
        }
    }

    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 256);
    ngx_conf_merge_msec_value(conf->post_accept_timeout,
                              prev->post_accept_timeout, 60000);
    ngx_conf_merge_size_value(conf->request_pool_size,
                              prev->request_pool_size, 4096);
    ngx_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);
    ngx_conf_merge_size_value(conf->client_header_buffer_size,
                              prev->client_header_buffer_size, 1024);
    ngx_conf_merge_bufs_value(conf->large_client_header_buffers,
                              prev->large_client_header_buffers,
                              4, ngx_pagesize);

    if (conf->large_client_header_buffers.size < conf->connection_pool_size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the \"large_client_header_buffers\" size must be "
                           "equal to or bigger than \"connection_pool_size\"");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_unsigned_value(conf->restrict_host_names,
                                  prev->restrict_host_names, 0);

    return NGX_CONF_OK;
}


static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_core_loc_conf_t *lcf;

    ngx_test_null(lcf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_core_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* set by ngx_pcalloc():

    lcf->root.len = 0;
    lcf->root.data = NULL;
    lcf->types = NULL;
    lcf->default_type.len = 0;
    lcf->default_type.data = NULL;
    lcf->err_log = NULL;
    lcf->error_pages = NULL;

    lcf->regex = NULL;
    lcf->exact_match = 0;
    lcf->auto_redirect = 0;
    lcf->alias = 0;

    */

    lcf->client_max_body_size = NGX_CONF_UNSET_SIZE;
    lcf->client_body_buffer_size = NGX_CONF_UNSET_SIZE;
    lcf->client_body_timeout = NGX_CONF_UNSET_MSEC;
    lcf->sendfile = NGX_CONF_UNSET;
    lcf->tcp_nopush = NGX_CONF_UNSET;
    lcf->send_timeout = NGX_CONF_UNSET_MSEC;
    lcf->send_lowat = NGX_CONF_UNSET_SIZE;
    lcf->postpone_output = NGX_CONF_UNSET_SIZE;
    lcf->limit_rate = NGX_CONF_UNSET_SIZE;
    lcf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    lcf->keepalive_header = NGX_CONF_UNSET;
    lcf->lingering_time = NGX_CONF_UNSET_MSEC;
    lcf->lingering_timeout = NGX_CONF_UNSET_MSEC;
    lcf->reset_timedout_connection = NGX_CONF_UNSET;
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

    ngx_conf_merge_str_value(conf->root, prev->root, "html");

    if (ngx_conf_full_name(cf->cycle, &conf->root) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

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
            conf->err_log = cf->cycle->new_log;
        }
    }

    if (conf->error_pages == NULL && prev->error_pages) {
        conf->error_pages = prev->error_pages;
    }

    ngx_conf_merge_str_value(conf->default_type,
                             prev->default_type, "text/plain");

    ngx_conf_merge_size_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1 * 1024 * 1024);
    ngx_conf_merge_size_value(conf->client_body_buffer_size,
                              prev->client_body_buffer_size,
                              (size_t) 2 * ngx_pagesize);
    ngx_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 60000);
    ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    ngx_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
    ngx_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);
    ngx_conf_merge_size_value(conf->limit_rate, prev->limit_rate, 0);
    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);
    ngx_conf_merge_sec_value(conf->keepalive_header,
                              prev->keepalive_header, 0);
    ngx_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    ngx_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);

    ngx_conf_merge_value(conf->reset_timedout_connection,
                         prev->reset_timedout_connection, 0);
    ngx_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);

    if (conf->open_files == NULL) {
        conf->open_files = prev->open_files;
    }

    return NGX_CONF_OK;
}


static char *ngx_set_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    u_char             *addr;
    ngx_int_t           port;
    ngx_uint_t          p;
    struct hostent     *h;
    ngx_str_t          *args;
    ngx_http_listen_t  *ls;

    /*
     * TODO: check duplicate 'listen' directives,
     *       add resolved name to server names ???
     */

    if (!(ls = ngx_array_push(&scf->listen))) {
        return NGX_CONF_ERROR;
    }

    /* AF_INET only */

    ls->family = AF_INET;
    ls->default_server = 0;
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

    port = ngx_atoi(&addr[p], args[1].len - p);

    if (port == NGX_ERROR && p == 0) {

        /* "listen host" */
        ls->port = 80;

    } else if ((port == NGX_ERROR && p != 0) /* "listen host:NONNUMBER" */
               || (port < 1 || port > 65536)) { /* "listen 99999" */

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid port \"%s\" in \"%s\" directive, "
                           "it must be a number between 1 and 65535",
                           &addr[p], cmd->name.data);

        return NGX_CONF_ERROR;

    } else if (p == 0) {
        ls->addr = INADDR_ANY;
        ls->port = (in_port_t) port;
        return NGX_CONF_OK;

    } else {
        ls->port = (in_port_t) port;
    }

    ls->addr = inet_addr((const char *) addr);
    if (ls->addr == INADDR_NONE) {
        h = gethostbyname((const char *) addr);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                              "can not resolve host \"%s\" "
                              "in \"%s\" directive", addr, cmd->name.data);
            return NGX_CONF_ERROR;
        }

        ls->addr = *(in_addr_t *)(h->h_addr_list[0]);
    }

    return NGX_CONF_OK;
}


static char *ngx_set_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    ngx_uint_t                  i;
    ngx_str_t                  *value;
    ngx_http_server_name_t     *sn;
    ngx_http_core_main_conf_t  *cmcf;

    /* TODO: several names */
    /* TODO: warn about duplicate 'server_name' directives */

#if 0
    ctx = (ngx_http_conf_ctx_t *) cf->cycle->conf_ctx[ngx_http_module.index];
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
#endif
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

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

        if (cmcf->max_server_name_len < sn->name.len) {
            cmcf->max_server_name_len = sn->name.len;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_set_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_uint_t   alias;
    ngx_str_t   *value;

    alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;

    if (lcf->root.data) {

        /* the (ngx_uint_t) cast is required by gcc 2.7.2.3 */

        if ((ngx_uint_t) lcf->alias == alias) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%s\" directive is duplicate",
                               cmd->name.data);
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%s\" directive is duplicate, "
                               "\"%s\" directive is specified before",
                               cmd->name.data, lcf->alias ? "alias" : "root");
        }

        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    lcf->alias = alias;
    lcf->root = value[1];

    if (!alias && lcf->root.data[lcf->root.len - 1] == '/') {
        lcf->root.len--;
    }

    return NGX_CONF_OK;
}


static char *ngx_set_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    int                   overwrite;
    ngx_uint_t            i, n;
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

    i = cf->args->nelts - 2;

    if (value[i].data[0] == '=') {
        if (i == 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        overwrite = ngx_atoi(&value[i].data[1], value[i].len - 1);

        if (overwrite == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        n = 2;

    } else {
        overwrite = 0;
        n = 1;
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        if (!(err = ngx_push_array(lcf->error_pages))) {
            return NGX_CONF_ERROR;
        }

        err->status = ngx_atoi(value[i].data, value[i].len);
        if (err->status == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);
            return NGX_CONF_ERROR;
        }

        if (err->status < 400 || err->status > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "value \"%s\" must be between 400 and 599",
                               value[i].data);
            return NGX_CONF_ERROR;
        }

        err->overwrite = overwrite;
        err->uri = value[cf->args->nelts - 1];
    }

    return NGX_CONF_OK;
}


static char *ngx_set_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_str_t  *value;

    if (lcf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lcf->keepalive_timeout = ngx_parse_time(&value[1], 0);
    if (lcf->keepalive_timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    if (lcf->keepalive_timeout == (ngx_msec_t) NGX_PARSE_LARGE_TIME) {
        return "value must be less than 597 hours";
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    lcf->keepalive_header = ngx_parse_time(&value[2], 1);
    if (lcf->keepalive_header == NGX_ERROR) {
        return "invalid value";
    }

    if (lcf->keepalive_header == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 68 years";
    }

    return NGX_CONF_OK;
}


static char *ngx_set_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    if (!(lcf->err_log = ngx_log_create_errlog(cf->cycle, cf->args))) {
        return NGX_CONF_ERROR;
    }

    return ngx_set_error_log_levels(cf, lcf->err_log);
}


static char *ngx_http_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (HAVE_LOWAT_EVENT)

    ssize_t *np = data;

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
