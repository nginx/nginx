
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <nginx.h>


#define NGX_HTTP_LOCATION_EXACT           1
#define NGX_HTTP_LOCATION_AUTO_REDIRECT   2
#define NGX_HTTP_LOCATION_NOREGEX         3
#define NGX_HTTP_LOCATION_REGEX           4


static void ngx_http_core_run_phases(ngx_http_request_t *r);
static ngx_int_t ngx_http_core_find_location(ngx_http_request_t *r,
    ngx_array_t *locations, size_t len);

static ngx_int_t ngx_http_core_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_core_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static char *ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);
static int ngx_libc_cdecl ngx_http_core_cmp_locations(const void *first,
    const void *second);

static char *ngx_http_core_types(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_type(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);

static char *ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_internal(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_core_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_core_lowat_post =
                                                 { ngx_http_core_lowat_check };


static ngx_conf_enum_t  ngx_http_restrict_host_names[] = {
    { ngx_string("off"), NGX_HTTP_RESTRICT_HOST_OFF },
    { ngx_string("on"), NGX_HTTP_RESTRICT_HOST_ON },
    { ngx_string("close"), NGX_HTTP_RESTRICT_HOST_CLOSE },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_core_commands[] = {

    { ngx_string("server_names_hash"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, server_names_hash),
      NULL },

    { ngx_string("server_names_hash_threshold"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, server_names_hash_threshold),
      NULL },

    { ngx_string("server"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_core_server,
      0,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
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

    { ngx_string("ignore_invalid_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, ignore_invalid_headers),
      NULL },

    { ngx_string("location"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
      ngx_http_core_location,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("listen"),
#if 0
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
#else
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
#endif
      ngx_http_core_listen,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("server_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_core_server_name,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                                          |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_core_types,
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_core_root,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("alias"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_core_root,
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

    { ngx_string("client_body_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_temp_path),
      (void *) ngx_garbage_collector_temp_handler },

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

    { ngx_string("tcp_nodelay"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, tcp_nodelay),
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
      &ngx_http_core_lowat_post },

    { ngx_string("postpone_output"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, postpone_output),
      NULL },

    { ngx_string("limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, limit_rate),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_core_keepalive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("satisfy_any"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, satisfy_any),
      NULL },

    { ngx_string("internal"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_core_internal,
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

    { ngx_string("port_in_redirect"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, port_in_redirect),
      NULL },

    { ngx_string("msie_padding"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, msie_padding),
      NULL },

    { ngx_string("log_not_found"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, log_not_found),
      NULL },

    { ngx_string("error_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_2MORE,
      ngx_http_core_error_page,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("error_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_core_error_log,
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
    ngx_http_core_preconfiguration,        /* preconfiguration */
    ngx_http_core_postconfiguration,       /* postconfiguration */

    ngx_http_core_create_main_conf,        /* create main configuration */
    ngx_http_core_init_main_conf,          /* init main configuration */

    ngx_http_core_create_srv_conf,         /* create server configuration */
    ngx_http_core_merge_srv_conf,          /* merge server configuration */

    ngx_http_core_create_loc_conf,         /* create location configuration */
    ngx_http_core_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_core_module = {
    NGX_MODULE_V1,
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


void
ngx_http_handler(ngx_http_request_t *r)
{
    r->connection->log->action = NULL;

    r->connection->unexpected_eof = 0;

    if (r->err_ctx == NULL) {
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

        if (r->headers_in.content_length_n > 0) {
            r->lingering_close = 1;

        } else {
            r->lingering_close = 0;
        }
    }

    r->write_event_handler = ngx_http_core_run_phases;

    r->valid_unparsed_uri = 1;
    r->valid_location = 1;
    r->uri_changed = 1;
    r->uri_changes = NGX_HTTP_MAX_REWRITE_CYCLES + 1;

    r->phase = NGX_HTTP_REWRITE_PHASE;
    r->phase_handler = 0;

    ngx_http_core_run_phases(r);
}


static void
ngx_http_core_run_phases(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_handler_pt        *h;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http phase handler");

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    for (/* void */; r->phase < NGX_HTTP_LAST_PHASE; r->phase++) {

        if (r->phase == NGX_HTTP_REWRITE_PHASE + 1 && r->uri_changed) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uri changes: %d", r->uri_changes);

            /*
             * gcc before 3.3 compiles the broken code for
             *     if (r->uri_changes-- == 0)
             * if the r->uri_changes is defined as
             *     unsigned  uri_changes:4
             */

            r->uri_changes--;

            if (r->uri_changes == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "rewrite cycle");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            r->phase = NGX_HTTP_FIND_CONFIG_PHASE;
        }

        if (r->phase == NGX_HTTP_ACCESS_PHASE && r->main != r) {
            continue;
        }

        if (r->phase == NGX_HTTP_CONTENT_PHASE && r->content_handler) {
            r->write_event_handler = ngx_http_request_empty_handler;
            ngx_http_finalize_request(r, r->content_handler(r));
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
                 * it may point to already freed data
                 */

                return;
            }

            if (rc == NGX_DECLINED) {
                continue;
            }

            if (r->phase == NGX_HTTP_ACCESS_PHASE) {
                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->satisfy_any) {

                    if (rc == NGX_OK) {
                        r->access_code = 0;

                        if (r->headers_out.www_authenticate) {
                            r->headers_out.www_authenticate->hash = 0;
                        }

                        break;
                    }

                    if (rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED)
                    {
                        r->access_code = rc;

                        continue;
                    }
                }
            }

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE
                || rc == NGX_HTTP_NO_CONTENT
                || rc == NGX_ERROR)
            {
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

        if (r->phase == NGX_HTTP_ACCESS_PHASE && r->access_code) {
            ngx_http_finalize_request(r, r->access_code);
            return;
        }
    }

    /* no content handler was found */

    if (r->uri.data[r->uri.len - 1] == '/' && !r->zero_in_uri) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "directory index of \"%V%V\" is forbidden",
                      &clcf->root, &r->uri);

        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no handler found");

    ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
}


ngx_int_t
ngx_http_find_location_config(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    r->content_handler = NULL;
    r->uri_changed = 0;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    rc = ngx_http_core_find_location(r, &cscf->locations, 0);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        return rc;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->internal && clcf->internal) {
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_http_update_location_config(r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl:%z max:%uz",
                   r->headers_in.content_length_n, clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && clcf->client_max_body_size
        && clcf->client_max_body_size < (size_t) r->headers_in.content_length_n)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client intented to send too large body: %z bytes",
                      r->headers_in.content_length_n);

        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }


    if (rc == NGX_HTTP_LOCATION_AUTO_REDIRECT) {
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value = clcf->name;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    return NGX_OK;
}


void
ngx_http_update_location_config(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    r->connection->log->file = clcf->err_log->file;
    if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
        r->connection->log->log_level = clcf->err_log->log_level;
    }

    if ((ngx_io.flags & NGX_IO_SENDFILE) && clcf->sendfile) {
        r->connection->sendfile = 1;

    } else {
        r->connection->sendfile = 0;
    }

    if (r->keepalive && clcf->keepalive_timeout == 0) {
        r->keepalive = 0;
    }

    if (!clcf->tcp_nopush) {
        /* disable TCP_NOPUSH/TCP_CORK use */
        r->connection->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

    r->limit_rate = clcf->limit_rate;

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }
}


static ngx_int_t
ngx_http_core_find_location(ngx_http_request_t *r,
    ngx_array_t *locations, size_t len)
{
    ngx_int_t                  n, rc;
    ngx_uint_t                 i, found, noregex;
    ngx_http_core_loc_conf_t  *clcf, **clcfp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "find location");

    found = 0;
    noregex = 0;

    clcfp = locations->elts;
    for (i = 0; i < locations->nelts; i++) {

#if (NGX_PCRE)
        if (clcfp[i]->regex) {
            break;
        }
#endif

        if (clcfp[i]->noname) {
            break;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "find location: %s\"%V\"",
                       clcfp[i]->exact_match ? "= " : "", &clcfp[i]->name);

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
            if (clcfp[i]->exact_match) {

                if (r->uri.len == clcfp[i]->name.len) {
                    r->loc_conf = clcfp[i]->loc_conf;
                    return NGX_HTTP_LOCATION_EXACT;
                }

                continue;
            }

            if (len > clcfp[i]->name.len) {
                /* the previous match is longer */
                break;
            }

            r->loc_conf = clcfp[i]->loc_conf;
            noregex = clcfp[i]->noregex;
            found = 1;
        }
    }

    if (found) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->locations.nelts) {
            rc = ngx_http_core_find_location(r, &clcf->locations, len);

            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

#if (NGX_PCRE)

    if (noregex) {
        return NGX_HTTP_LOCATION_NOREGEX;
    }

    /* regex matches */

    for (/* void */; i < locations->nelts; i++) {

        if (!clcfp[i]->regex) {
            continue;
        }

        if (clcfp[i]->noname) {
            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "find location: ~ \"%V\"", &clcfp[i]->name);

        n = ngx_regex_exec(clcfp[i]->regex, &r->uri, NULL, 0);

        if (n == NGX_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          ngx_regex_exec_n
                          " failed: %d on \"%V\" using \"%V\"",
                          n, &r->uri, &clcfp[i]->name);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* match */

        r->loc_conf = clcfp[i]->loc_conf;

        return NGX_HTTP_LOCATION_REGEX;
    }

#endif /* NGX_PCRE */

    return NGX_OK;
}


ngx_int_t
ngx_http_set_content_type(ngx_http_request_t *r)
{
    u_char                     c, *p, *exten;
    uint32_t                   key;
    ngx_uint_t                 i;
    ngx_http_type_t           *type;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->exten.len) {

        if (!r->low_case_exten) {
            for (i = 0; i < r->exten.len; i++) {
                c = r->exten.data[i];
                if (c >= 'A' && c <= 'Z') {
                    break;
                }
            }

            if (i < r->exten.len) {
                p = ngx_palloc(r->pool, r->exten.len);
                if (p == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                exten = p;

                for (i = 0; i < r->exten.len; i++) {
                    c = r->exten.data[i];
                    if (c >= 'A' && c <= 'Z') {
                        *p++ = (u_char) (c | 0x20);
                    } else {
                        *p++ = c;
                    }
                }

                r->exten.data = exten;
            }

            r->low_case_exten = 1;
        }

        ngx_http_types_hash_key(key, r->exten);

        type = clcf->types[key].elts;
        for (i = 0; i < clcf->types[key].nelts; i++) {
            if (r->exten.len != type[i].exten.len) {
                continue;
            }

            if (ngx_memcmp(r->exten.data, type[i].exten.data, r->exten.len)
                                                                           == 0)
            {
                r->headers_out.content_type = type[i].type;
                break;
            }
        }
    }

    if (r->headers_out.content_type.len == 0) {
        r->headers_out.content_type= clcf->default_type;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_send_header(ngx_http_request_t *r)
{
    if (r->err_ctx) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return ngx_http_top_header_filter(r);
}


ngx_int_t
ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t  rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http output filter \"%V\"", &r->uri);

    rc = ngx_http_top_body_filter(r, in);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        r->connection->closed = 1;
    }

    return rc;
}


ngx_int_t
ngx_http_set_exten(ngx_http_request_t *r)
{
    ngx_int_t  i;

    r->exten.len = 0;
    r->exten.data = NULL;

    for (i = r->uri.len - 1; i > 1; i--) {
        if (r->uri.data[i] == '.' && r->uri.data[i - 1] != '/') {
            r->exten.len = r->uri.len - i - 1;

            if (r->exten.len > 0) {
                r->exten.data = ngx_palloc(r->pool, r->exten.len + 1);
                if (r->exten.data == NULL) {
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

    r->low_case_exten = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_auth_basic_user(ngx_http_request_t *r)
{
    ngx_str_t   auth, encoded;
    ngx_uint_t  len;

    if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return NGX_DECLINED;
    }

    if (r->headers_in.authorization == NULL) {
        r->headers_in.user.data = (u_char *) "";
        return NGX_DECLINED;
    }

    encoded = r->headers_in.authorization->value;

    if (encoded.len < sizeof("Basic ") - 1
        || ngx_strncasecmp(encoded.data, "Basic ", sizeof("Basic ") - 1) != 0)
    {
        r->headers_in.user.data = (u_char *) "";
        return NGX_DECLINED;
    }

    encoded.len -= sizeof("Basic ") - 1;
    encoded.data += sizeof("Basic ") - 1;

    while (encoded.len && encoded.data[0] == ' ') {
        encoded.len--;
        encoded.data++;
    }

    if (encoded.len == 0) {
        r->headers_in.user.data = (u_char *) "";
        return NGX_DECLINED;
    }
    
    auth.len = ngx_base64_decoded_length(encoded.len);
    auth.data = ngx_palloc(r->pool, auth.len + 1); 
    if (auth.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&auth, &encoded) != NGX_OK) {
        r->headers_in.user.data = (u_char *) "";
        return NGX_DECLINED;
    }
    
    auth.data[auth.len] = '\0';
    
    for (len = 0; len < auth.len; len++) { 
        if (auth.data[len] == ':') {
            break;
        }
    }
    
    if (len == auth.len) {
        r->headers_in.user.data = (u_char *) "";
        return NGX_DECLINED;
    }

    r->headers_in.user.len = len;
    r->headers_in.user.data = auth.data;
    r->headers_in.passwd.len = auth.len - len - 1;
    r->headers_in.passwd.data = &auth.data[len + 1];

    return NGX_OK;
}


ngx_int_t
ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args)
{
    ngx_http_request_t            *sr;
    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_postponed_request_t  *pr, *p;

    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;
    sr->connection = r->connection;

    sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t)) == NGX_ERROR)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in = r->headers_in;

    sr->start_time = ngx_time();
    sr->headers_out.content_length_n = -1;
    sr->headers_out.last_modified_time = -1;

    sr->request_body = r->request_body;

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;
    sr->http_major = r->http_minor;

    sr->request_line = r->request_line;
    sr->uri = *uri;
    if (args) {
        sr->args = *args;
    }
    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = r->method_name;
    sr->http_protocol = r->http_protocol;

    if (ngx_http_set_exten(sr) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    sr->main = r->main;
    sr->parent = r;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_request_empty_handler;

    if (r->connection->data == r) {
        sr->connection->data = sr;
    }

    sr->in_addr = r->in_addr;
    sr->port = r->port;
    sr->port_text = r->port_text;
    sr->server_name = r->server_name;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    pr->request = sr;
    pr->out = NULL;
    pr->next = NULL;

    if (r->postponed) {
        for (p = r->postponed; p->next; p = p->next) { /* void */ }
        p->next = pr;

    } else {
        r->postponed = pr;
    }

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http subrequest \"%V\"", uri);

    ngx_http_handler(sr);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http subrequest \"%V\" done", uri);

    return NGX_OK;
}


ngx_int_t
ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args)
{
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%V\"", uri);

    r->uri = *uri;

    if (args) {
        r->args = *args;

    } else {
        r->args.len = 0;
        r->args.data = NULL;
    }

    if (ngx_http_set_exten(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->err_ctx) {

        /* allocate the new module's contexts */

        r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
        if (r->ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {

        /* clear the modules contexts */

        ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    ngx_http_update_location_config(r);

    r->internal = 1;

    ngx_http_handler(r);

    return NGX_DONE;
}


#if 0       /* STUB: test the delay http handler */

ngx_int_t
ngx_http_delay_handler(ngx_http_request_t *r)
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


static char *
ngx_http_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t        *ctx, *http_ctx;
    ngx_http_core_srv_conf_t   *cscf, **cscfp;
    ngx_http_core_main_conf_t  *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }


    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];
    cscf->ctx = ctx;


    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ngx_qsort(cscf->locations.elts, (size_t) cscf->locations.nelts,
              sizeof(ngx_http_core_loc_conf_t *), ngx_http_core_cmp_locations);

    return rv;
}


static char *
ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    ngx_int_t                  m;
    ngx_str_t                 *value;
    ngx_conf_t                 save;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf, *pclcf, **clcfp;
#if (NGX_PCRE)
    ngx_str_t                  err;
    u_char                     errstr[NGX_MAX_CONF_ERRSTR];
#endif

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
            clcf->name = value[2];
            clcf->exact_match = 1;

        } else if (value[1].len == 2
                   && value[1].data[0] == '^'
                   && value[1].data[1] == '~')
        {
            clcf->name = value[2];
            clcf->noregex = 1;

        } else if ((value[1].len == 1 && value[1].data[0] == '~')
                   || (value[1].len == 2
                       && value[1].data[0] == '~'
                       && value[1].data[1] == '*'))
        {
#if (NGX_PCRE)
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
                               "the using of the regex \"%V\" "
                               "requires PCRE library", &value[2]);
            return NGX_CONF_ERROR;
#endif

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        clcf->name = value[1];
    }

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    if (pclcf->name.len == 0) {
        cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];

        clcfp = ngx_array_push(&cscf->locations);
        if (clcfp == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
#if 0
        clcf->prev_location = pclcf;
#endif

        if (pclcf->exact_match) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" could not be inside "
                               "the exact location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        if (clcf->regex == NULL
            && ngx_strncmp(clcf->name.data, pclcf->name.data, pclcf->name.len)
                                                                         != 0)
#else
        if (ngx_strncmp(clcf->name.data, pclcf->name.data, pclcf->name.len)
                                                                         != 0)
#endif
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" is outside location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NGX_CONF_ERROR;
        }

        if (pclcf->locations.elts == NULL) {
            if (ngx_array_init(&pclcf->locations, cf->pool, 4, sizeof(void *))
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        clcfp = ngx_array_push(&pclcf->locations);
        if (clcfp == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    *clcfp = clcf;

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    ngx_qsort(clcf->locations.elts, (size_t) clcf->locations.nelts,
              sizeof(ngx_http_core_loc_conf_t *), ngx_http_core_cmp_locations);

    return rv;
}


static int ngx_libc_cdecl
ngx_http_core_cmp_locations(const void *one, const void *two)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *first, *second;

    first = *(ngx_http_core_loc_conf_t **) one;
    second = *(ngx_http_core_loc_conf_t **) two;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

#if (NGX_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
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

    return (int) rc;
}


static char *
ngx_http_core_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *rv;
    ngx_conf_t   save;

    save = *cf;
    cf->handler = ngx_http_core_type;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
ngx_http_core_type(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    uint32_t          key;
    ngx_uint_t        i;
    ngx_str_t        *value;
    ngx_http_type_t  *type;

    if (lcf->types == NULL) {
        lcf->types = ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t));
        if (lcf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
            if (ngx_array_init(&lcf->types[i], cf->pool, 4,
                                         sizeof(ngx_http_type_t)) == NGX_ERROR)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_http_types_hash_key(key, value[i]);

        type = ngx_array_push(&lcf->types[key]);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->exten = value[i];
        type->type = value[0];
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_core_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_variables_add_core_vars(cf);
}


static ngx_int_t
ngx_http_core_postconfiguration(ngx_conf_t *cf)
{
    return ngx_http_variables_init_vars(cf);
}


static void *
ngx_http_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_main_conf_t));
    if (cmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_http_core_srv_conf_t *)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->server_names_hash = NGX_CONF_UNSET_UINT;
    cmcf->server_names_hash_threshold = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = conf;

    if (cmcf->server_names_hash == NGX_CONF_UNSET_UINT) {
        cmcf->server_names_hash = 1009;
    }

    if (cmcf->server_names_hash_threshold == NGX_CONF_UNSET_UINT) {
        cmcf->server_names_hash_threshold = 50;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_srv_conf_t));
    if (cscf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->client_large_buffers.num = 0;
     */

    if (ngx_array_init(&cscf->locations, cf->pool, 4, sizeof(void *))
                                                                  == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cscf->listen, cf->pool, 4, sizeof(ngx_http_listen_t))
                                                                  == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&cscf->server_names, cf->pool, 4,
                       sizeof(ngx_http_server_name_t)) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->request_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->client_header_timeout = NGX_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->restrict_host_names = NGX_CONF_UNSET_UINT;
    cscf->ignore_invalid_headers = NGX_CONF_UNSET;

    return cscf;
}


static char *
ngx_http_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = parent;
    ngx_http_core_srv_conf_t *conf = child;

    ngx_http_listen_t          *ls;
    ngx_http_server_name_t     *sn;
    ngx_http_core_main_conf_t  *cmcf;

    /* TODO: it does not merge, it inits only */

    if (conf->listen.nelts == 0) {
        ls = ngx_array_push(&conf->listen);
        if (ls == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(ls, sizeof(ngx_http_listen_t));

        ls->addr = INADDR_ANY;
#if (NGX_WIN32)
        ls->port = 80;
#else
        /* STUB: getuid() should be cached */
        ls->port = (getuid() == 0) ? 80 : 8000;
#endif
        ls->family = AF_INET;
    }

    if (conf->server_names.nelts == 0) {
        sn = ngx_array_push(&conf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

        sn->name.data = ngx_palloc(cf->pool, NGX_MAXHOSTNAMELEN);
        if (sn->name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (gethostname((char *) sn->name.data, NGX_MAXHOSTNAMELEN) == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "gethostname() failed");
            return NGX_CONF_ERROR;
        }

        sn->name.len = ngx_strlen(sn->name.data);
        sn->core_srv_conf = conf;
        sn->wildcard = 0;

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        if (cmcf->max_server_name_len < sn->name.len) {
            cmcf->max_server_name_len = sn->name.len;
        }
    }

    ngx_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 256);
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

    ngx_conf_merge_value(conf->ignore_invalid_headers,
                              prev->ignore_invalid_headers, 1);

    return NGX_CONF_OK;
}


static void *
ngx_http_core_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_core_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_loc_conf_t));
    if (lcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     lcf->root.len = 0;
     *     lcf->root.data = NULL;
     *     lcf->types = NULL;
     *     lcf->default_type.len = 0;
     *     lcf->default_type.data = NULL;
     *     lcf->err_log = NULL;
     *     lcf->error_pages = NULL;
     *     lcf->client_body_path = NULL;
     *     lcf->regex = NULL;
     *     lcf->exact_match = 0;
     *     lcf->auto_redirect = 0;
     *     lcf->alias = 0;
     */

    lcf->client_max_body_size = NGX_CONF_UNSET_SIZE;
    lcf->client_body_buffer_size = NGX_CONF_UNSET_SIZE;
    lcf->client_body_timeout = NGX_CONF_UNSET_MSEC;
    lcf->satisfy_any = NGX_CONF_UNSET;
    lcf->internal = NGX_CONF_UNSET;
    lcf->sendfile = NGX_CONF_UNSET;
    lcf->tcp_nopush = NGX_CONF_UNSET;
    lcf->tcp_nodelay = NGX_CONF_UNSET;
    lcf->send_timeout = NGX_CONF_UNSET_MSEC;
    lcf->send_lowat = NGX_CONF_UNSET_SIZE;
    lcf->postpone_output = NGX_CONF_UNSET_SIZE;
    lcf->limit_rate = NGX_CONF_UNSET_SIZE;
    lcf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    lcf->keepalive_header = NGX_CONF_UNSET;
    lcf->lingering_time = NGX_CONF_UNSET_MSEC;
    lcf->lingering_timeout = NGX_CONF_UNSET_MSEC;
    lcf->reset_timedout_connection = NGX_CONF_UNSET;
    lcf->port_in_redirect = NGX_CONF_UNSET;
    lcf->msie_padding = NGX_CONF_UNSET;
    lcf->log_not_found = NGX_CONF_UNSET;

    return lcf;
}


static ngx_http_type_t ngx_http_core_default_types[] = {
    { ngx_string("html"), ngx_string("text/html") },
    { ngx_string("gif"), ngx_string("image/gif") },
    { ngx_string("jpg"), ngx_string("image/jpeg") },
    { ngx_null_string, ngx_null_string }
};


static char *
ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child)
{
    ngx_http_core_loc_conf_t *prev = parent;
    ngx_http_core_loc_conf_t *conf = child;

    uint32_t          key;
    ngx_uint_t        i;
    ngx_http_type_t  *type;

    ngx_conf_merge_str_value(conf->root, prev->root, "html");

    if (ngx_conf_full_name(cf->cycle, &conf->root) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (conf->types == NULL) {
        if (prev->types) {
            conf->types = prev->types;

        } else {
            conf->types = ngx_palloc(cf->pool, NGX_HTTP_TYPES_HASH_PRIME
                                                        * sizeof(ngx_array_t)); 
            if (conf->types == NULL) {
                return NGX_CONF_ERROR;
            }

            for (i = 0; i < NGX_HTTP_TYPES_HASH_PRIME; i++) {
                if (ngx_array_init(&conf->types[i], cf->pool, 4,
                                   sizeof(ngx_http_type_t)) == NGX_ERROR)
                {
                    return NGX_CONF_ERROR;
                }
            }

            for (i = 0; ngx_http_core_default_types[i].exten.len; i++) {
                ngx_http_types_hash_key(key,
                                        ngx_http_core_default_types[i].exten);

                type = ngx_array_push(&conf->types[key]);
                if (type == NULL) {
                    return NGX_CONF_ERROR;
                }

                *type = ngx_http_core_default_types[i];
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

    ngx_conf_merge_value(conf->satisfy_any, prev->satisfy_any, 0);
    ngx_conf_merge_value(conf->internal, prev->internal, 0);
    ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    ngx_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 0);

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

    ngx_conf_merge_path_value(conf->client_body_temp_path,
                              prev->client_body_temp_path,
                              NGX_HTTP_CLIENT_TEMP_PATH, 0, 0, 0,
                              ngx_garbage_collector_temp_handler, cf);

    ngx_conf_merge_value(conf->reset_timedout_connection,
                              prev->reset_timedout_connection, 0);
    ngx_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 1);
    ngx_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);
    ngx_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);

    if (conf->open_files == NULL) {
        conf->open_files = prev->open_files;
    }

    return NGX_CONF_OK;
}


/* AF_INET only */

static char *
ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    char                 *err;
    ngx_str_t            *value;
    ngx_uint_t            n;
    struct hostent       *h;
    ngx_http_listen_t    *ls;
    ngx_inet_upstream_t   inet_upstream;

    /*
     * TODO: check duplicate 'listen' directives,
     *       add resolved name to server names ???
     */

    value = cf->args->elts;
    
    ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

    inet_upstream.url = value[1];
    inet_upstream.port_only = 1;

    err = ngx_inet_parse_host_port(&inet_upstream);

    if (err) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%s in \"%V\" of the \"listen\" directive",
                           err, &inet_upstream.url);
        return NGX_CONF_ERROR; 
    }

    ls = ngx_array_push(&scf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_http_listen_t));

    ls->family = AF_INET;
    ls->port = (in_port_t) (inet_upstream.default_port ?
                                                      80 : inet_upstream.port);
    ls->file_name = cf->conf_file->file.name;
    ls->line = cf->conf_file->line;
    ls->conf.backlog = -1;

    if (inet_upstream.host.len) {
        inet_upstream.host.data[inet_upstream.host.len] = '\0';

        ls->addr = inet_addr((const char *) inet_upstream.host.data);

        if (ls->addr == INADDR_NONE) {
            h = gethostbyname((const char *) inet_upstream.host.data);

            if (h == NULL || h->h_addr_list[0] == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "can not resolve host \"%s\" "
                                   "in the \"listen\" directive",
                                   inet_upstream.host.data);
                return NGX_CONF_ERROR;
            }
    
            ls->addr = *(in_addr_t *)(h->h_addr_list[0]);
        }

    } else {
        ls->addr = INADDR_ANY;
    }

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[2].data, "default") == 0) {
        ls->conf.default_server = 1;
        n = 3;
    } else {
        n = 2;
    }

    for ( /* void */ ; n < cf->args->nelts; n++) {

        if (ls->conf.default_server == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" parameter can be specified for "
                               "the default \"listen\" directive only",
                               &value[n]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(value[n].data, "bind") == 0) {
            ls->conf.bind = 1;
            continue;
        }

        if (ngx_strncmp(value[n].data, "bl=", 3) == 0) {
            ls->conf.backlog = ngx_atoi(value[n].data + 3, value[n].len - 3);
            ls->conf.bind = 1;

            if (ls->conf.backlog == NGX_ERROR || ls->conf.backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "af=", 3) == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            ls->conf.accept_filter = (char *) &value[n].data[3];
            ls->conf.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (ngx_strcmp(value[n].data, "deferred") == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            ls->conf.deferred_accept = 1;
            ls->conf.bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[n]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_srv_conf_t *scf = conf;

    ngx_uint_t                  i;
    ngx_str_t                  *value;
    ngx_http_server_name_t     *sn;
    ngx_http_core_main_conf_t  *cmcf;

    /* TODO: warn about duplicate 'server_name' directives */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid "
                               "in \"%V\" directive",
                               &value[i], &cmd->name);
            return NGX_CONF_ERROR;
        }

        sn = ngx_array_push(&scf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

        sn->name.len = value[i].len;
        sn->name.data = value[i].data;
        sn->core_srv_conf = scf;

        if (sn->name.data[0] == '*') {
            sn->name.len--;
            sn->name.data++;
            sn->wildcard = 1;

        } else {
            sn->wildcard = 0;
        }

        if (cmcf->max_server_name_len < sn->name.len) {
            cmcf->max_server_name_len = sn->name.len;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_uint_t   alias;
    ngx_str_t   *value;

    alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;

    if (lcf->root.data) {

        /* the (ngx_uint_t) cast is required by gcc 2.7.2.3 */

        if ((ngx_uint_t) lcf->alias == alias) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" directive is duplicate",
                               &cmd->name);
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" directive is duplicate, "
                               "\"%s\" directive is specified before",
                               &cmd->name, lcf->alias ? "alias" : "root");
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


static char *
ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_int_t             overwrite;
    ngx_uint_t            i, n;
    ngx_str_t            *value;
    ngx_http_err_page_t  *err;

    if (lcf->error_pages == NULL) {
        lcf->error_pages = ngx_array_create(cf->pool, 4,
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
                               "invalid value \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        overwrite = ngx_atoi(&value[i].data[1], value[i].len - 1);

        if (overwrite == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        n = 2;

    } else {
        overwrite = 0;
        n = 1;
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        err = ngx_array_push(lcf->error_pages);
        if (err == NULL) {
            return NGX_CONF_ERROR;
        }

        err->status = ngx_atoi(value[i].data, value[i].len);

        if (err->status == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (err->status < 400 || err->status > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "value \"%V\" must be between 400 and 599",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        err->overwrite = overwrite;
        err->uri = value[cf->args->nelts - 1];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    lcf->err_log = ngx_log_create_errlog(cf->cycle, cf->args);
    if (lcf->err_log == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_set_error_log_levels(cf, lcf->err_log);
}


static char *
ngx_http_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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


static char *
ngx_http_core_internal(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    if (lcf->internal != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    lcf->internal = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_core_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if (*np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}
