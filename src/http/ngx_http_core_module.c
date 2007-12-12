
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <nginx.h>


typedef struct {
    u_char    *name;
    uint32_t   method;
} ngx_http_method_name_t;


#define NGX_HTTP_LOCATION_EXACT           1
#define NGX_HTTP_LOCATION_AUTO_REDIRECT   2
#define NGX_HTTP_LOCATION_NOREGEX         3
#define NGX_HTTP_LOCATION_REGEX           4


#define NGX_HTTP_REQUEST_BODY_FILE_OFF    0
#define NGX_HTTP_REQUEST_BODY_FILE_ON     1
#define NGX_HTTP_REQUEST_BODY_FILE_CLEAN  2


static ngx_int_t ngx_http_core_find_location(ngx_http_request_t *r,
    ngx_array_t *locations, ngx_uint_t regex_start, size_t len);

static ngx_int_t ngx_http_core_preconfiguration(ngx_conf_t *cf);
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
static int ngx_http_core_cmp_locations(const void *first, const void *second);

static char *ngx_http_core_types(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_type(ngx_conf_t *cf, ngx_command_t *dummy,
    void *conf);

static char *ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_core_limit_except(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_core_internal(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_core_lowat_check(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_core_pool_size(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_core_lowat_post =
    { ngx_http_core_lowat_check };

static ngx_conf_post_handler_pt  ngx_http_core_pool_size_p =
    ngx_http_core_pool_size;

static ngx_conf_deprecated_t  ngx_conf_deprecated_optimize_host_names = {
    ngx_conf_deprecated, "optimize_host_names", "optimize_server_names"
};


static ngx_conf_enum_t  ngx_http_core_request_body_in_file[] = {
    { ngx_string("off"), NGX_HTTP_REQUEST_BODY_FILE_OFF },
    { ngx_string("on"), NGX_HTTP_REQUEST_BODY_FILE_ON },
    { ngx_string("clean"), NGX_HTTP_REQUEST_BODY_FILE_CLEAN },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_core_commands[] = {

    { ngx_string("variables_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, variables_hash_max_size),
      NULL },

    { ngx_string("variables_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { ngx_string("server_names_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, server_names_hash_max_size),
      NULL },

    { ngx_string("server_names_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_core_main_conf_t, server_names_hash_bucket_size),
      NULL },

    { ngx_string("server"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS,
      ngx_http_core_server,
      0,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
      &ngx_http_core_pool_size_p },

    { ngx_string("request_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, request_pool_size),
      &ngx_http_core_pool_size_p },

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

    { ngx_string("optimize_server_names"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, optimize_server_names),
      NULL },

    { ngx_string("optimize_host_names"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, optimize_server_names),
      &ngx_conf_deprecated_optimize_host_names },

    { ngx_string("ignore_invalid_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, ignore_invalid_headers),
      NULL },

    { ngx_string("merge_slashes"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, merge_slashes),
      NULL },

    { ngx_string("location"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
      ngx_http_core_location,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("listen"),
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
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

    { ngx_string("types_hash_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, types_hash_max_size),
      NULL },

    { ngx_string("types_hash_bucket_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, types_hash_bucket_size),
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

    { ngx_string("limit_except"),
      NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_1MORE,
      ngx_http_core_limit_except,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("client_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
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

    { ngx_string("client_body_in_file_only"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_in_file_only),
      &ngx_http_core_request_body_in_file },

    { ngx_string("sendfile"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, sendfile),
      NULL },

    { ngx_string("sendfile_max_chunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, sendfile_max_chunk),
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

    { ngx_string("msie_refresh"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, msie_refresh),
      NULL },

    { ngx_string("log_not_found"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, log_not_found),
      NULL },

    { ngx_string("recursive_error_pages"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, recursive_error_pages),
      NULL },

    { ngx_string("server_tokens"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, server_tokens),
      NULL },

    { ngx_string("error_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_2MORE,
      ngx_http_core_error_page,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("post_action"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, post_action),
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


static ngx_http_module_t  ngx_http_core_module_ctx = {
    ngx_http_core_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

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
    ngx_http_core_main_conf_t  *cmcf;

    r->connection->log->action = NULL;

    r->connection->unexpected_eof = 0;

    if (!r->internal) {
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
             * MSIE may wait for some time if an response for
             * a POST request was sent over a keepalive connection
             */

            r->keepalive = 0;
        }

        if (r->headers_in.content_length_n > 0) {
            r->lingering_close = 1;

        } else {
            r->lingering_close = 0;
        }

        r->phase_handler = 0;

    } else {
        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
        r->phase_handler = cmcf->phase_engine.server_rewrite_index;
    }

    if (r->unparsed_uri.len) {
        r->valid_unparsed_uri = 1;
    }

    r->valid_location = 1;

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


void
ngx_http_core_run_phases(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_phase_handler_t   *ph;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[r->phase_handler].checker) {

        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);

        if (rc == NGX_OK) {
            return;
        }
    }
}


ngx_int_t
ngx_http_core_generic_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
{
    ngx_int_t  rc;

    /*
     * generic phase checker,
     * used by the post read, server rewrite, rewrite, and pre-access phases
     */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generic phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NGX_OK) {
        r->phase_handler = ph->next;
        return NGX_AGAIN;
    }

    if (rc == NGX_DECLINED) {
        r->phase_handler++;
        return NGX_AGAIN;
    }

    if (rc == NGX_AGAIN || rc == NGX_DONE) {
        return NGX_OK;
    }

    /* rc == NGX_ERROR || rc == NGX_HTTP_...  */

    ngx_http_finalize_request(r, rc);

    return NGX_OK;
}


ngx_int_t
ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph)
{
    u_char                    *p;
    size_t                     len;
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    r->content_handler = NULL;
    r->uri_changed = 0;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    rc = ngx_http_core_find_location(r, &cscf->locations, cscf->regex_start, 0);

    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!r->internal && clcf->internal) {
        ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "using configuration \"%s%V\"",
                   (clcf->noname ? "*" : (clcf->exact_match ? "=" : "")),
                   &clcf->name);

    ngx_http_update_location_config(r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl:%O max:%O",
                   r->headers_in.content_length_n, clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && !r->discard_body
        && clcf->client_max_body_size
        && clcf->client_max_body_size < r->headers_in.content_length_n)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client intended to send too large body: %O bytes",
                      r->headers_in.content_length_n);

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return NGX_OK;
    }


    if (rc == NGX_HTTP_LOCATION_AUTO_REDIRECT) {
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        if (r->args.len == 0) {
            r->headers_out.location->value = clcf->name;

        } else {
            len = clcf->name.len + 1 + r->args.len;
            p = ngx_palloc(r->pool, len);

            if (p == NULL) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_OK;
            }

            r->headers_out.location->value.len = len;
            r->headers_out.location->value.data = p;

            p = ngx_cpymem(p, clcf->name.data, clcf->name.len);
            *p++ = '?';
            ngx_memcpy(p, r->args.data, r->args.len);
        }

        ngx_http_finalize_request(r, NGX_HTTP_MOVED_PERMANENTLY);
        return NGX_OK;
    }

    r->phase_handler++;
    return NGX_AGAIN;
}


ngx_int_t
ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post rewrite phase: %ui", r->phase_handler);

    if (!r->uri_changed) {
        r->phase_handler++;
        return NGX_AGAIN;
    }

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
                      "rewrite or internal redirection cycle "
                      "while processing \"%V\"", &r->uri);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    r->phase_handler = ph->next;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_core_access_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;

    if (r != r->main) {
        r->phase_handler = ph->next;
        return NGX_AGAIN;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "access phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NGX_DECLINED) {
        r->phase_handler++;
        return NGX_AGAIN;
    }

    if (rc == NGX_AGAIN || rc == NGX_DONE) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->satisfy_any == 0) {

        if (rc == NGX_OK) {
            r->phase_handler++;
            return NGX_AGAIN;
        }

    } else {
        if (rc == NGX_OK) {
            r->access_code = 0;

            if (r->headers_out.www_authenticate) {
                r->headers_out.www_authenticate->hash = 0;
            }

            r->phase_handler = ph->next;
            return NGX_AGAIN;
        }

        if (rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED) {
            r->access_code = rc;

            r->phase_handler++;
            return NGX_AGAIN;
        }
    }

    /* rc == NGX_ERROR || rc == NGX_HTTP_...  */

    ngx_http_finalize_request(r, rc);
    return NGX_OK;
}


ngx_int_t
ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post access phase: %ui", r->phase_handler);

    if (r->access_code) {

        if (r->access_code == NGX_HTTP_FORBIDDEN) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        ngx_http_finalize_request(r, r->access_code);
        return NGX_OK;
    }

    r->phase_handler++;
    return NGX_AGAIN;
}


ngx_int_t
ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph)
{
    size_t     root;
    ngx_int_t  rc;
    ngx_str_t  path;

    if (r->content_handler) {
        r->write_event_handler = ngx_http_request_empty_handler;
        ngx_http_finalize_request(r, r->content_handler(r));
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "content phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NGX_DONE) {
        return NGX_OK;
    }

    if (rc != NGX_DECLINED) {
        ngx_http_finalize_request(r, rc);
        return NGX_OK;
    }

    /* rc == NGX_DECLINED */

    ph++;

    if (ph->checker) {
        r->phase_handler++;
        return NGX_AGAIN;
    }

    /* no content handler was found */

    if (r->uri.data[r->uri.len - 1] == '/' && !r->zero_in_uri) {

        if (ngx_http_map_uri_to_path(r, &path, &root, 0) != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "directory index of \"%s\" is forbidden", path.data);
        }

        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no handler found");

    ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
    return NGX_OK;
}


void
ngx_http_update_location_config(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->method & clcf->limit_except) {
        r->loc_conf = clcf->limit_except_loc_conf;
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    }

    if (r == r->main) {
        r->connection->log->file = clcf->err_log->file;

        if (!(r->connection->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
            r->connection->log->log_level = clcf->err_log->log_level;
        }
    }

    if ((ngx_io.flags & NGX_IO_SENDFILE) && clcf->sendfile) {
        r->connection->sendfile = 1;

    } else {
        r->connection->sendfile = 0;
    }

    if (clcf->client_body_in_file_only) {
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file =
            clcf->client_body_in_file_only == NGX_HTTP_REQUEST_BODY_FILE_CLEAN;
        r->request_body_file_log_level = NGX_LOG_NOTICE;

    } else {
        r->request_body_file_log_level = NGX_LOG_WARN;
    }

    if (r->keepalive && clcf->keepalive_timeout == 0) {
        r->keepalive = 0;
    }

    if (!clcf->tcp_nopush) {
        /* disable TCP_NOPUSH/TCP_CORK use */
        r->connection->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

    if (r->limit_rate == 0) {
        r->limit_rate = clcf->limit_rate;
    }

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }
}


static ngx_int_t
ngx_http_core_find_location(ngx_http_request_t *r,
    ngx_array_t *locations, ngx_uint_t regex_start, size_t len)
{
    ngx_int_t                  n, rc;
    ngx_uint_t                 i, found;
    ngx_http_core_loc_conf_t  *clcf, **clcfp;
#if (NGX_PCRE)
    ngx_uint_t                 noregex;
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "find location for \"%V\"", &r->uri);

    found = 0;
#if (NGX_PCRE)
    noregex = 0;
#endif

    clcfp = locations->elts;
    for (i = 0; i < locations->nelts; i++) {

        if (clcfp[i]->noname
#if (NGX_PCRE)
            || clcfp[i]->regex
#endif
            || clcfp[i]->named)
        {
            break;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "find location: %s\"%V\"",
                       clcfp[i]->exact_match ? "= " : "", &clcfp[i]->name);

        if (clcfp[i]->auto_redirect
            && r->uri.len == clcfp[i]->name.len - 1
            && ngx_strncmp(r->uri.data, clcfp[i]->name.data,
                           clcfp[i]->name.len - 1)
                == 0)
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

            found = 1;

            r->loc_conf = clcfp[i]->loc_conf;
#if (NGX_PCRE)
            noregex = clcfp[i]->noregex;
#endif
        }
    }

    if (found) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->locations) {
            rc = ngx_http_core_find_location(r, clcf->locations,
                                             clcf->regex_start, len);

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

    for (i = regex_start; i < locations->nelts; i++) {

        if (!clcfp[i]->regex) {
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
    ngx_str_t                 *type;
    ngx_uint_t                 i, hash;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->headers_out.content_type.len) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->exten.len) {

        hash = 0;

        for (i = 0; i < r->exten.len; i++) {
            c = r->exten.data[i];

            if (c >= 'A' && c <= 'Z') {

                p = ngx_palloc(r->pool, r->exten.len);
                if (p == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                hash = 0;
                exten = p;

                for (i = 0; i < r->exten.len; i++) {
                    c = ngx_tolower(r->exten.data[i]);
                    hash = ngx_hash(hash, c);
                    *p++ = c;
                }

                r->exten.data = exten;

                break;
            }

            hash = ngx_hash(hash, c);
        }

        type = ngx_hash_find(&clcf->types_hash, hash,
                             r->exten.data, r->exten.len);

        if (type) {
            r->headers_out.content_type_len = type->len;
            r->headers_out.content_type = *type;

            return NGX_OK;
        }
    }

    r->headers_out.content_type_len = clcf->default_type.len;
    r->headers_out.content_type = clcf->default_type;

    return NGX_OK;
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
            r->exten.data = &r->uri.data[i + 1];

            break;

        } else if (r->uri.data[i] == '/') {
            break;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_send_header(ngx_http_request_t *r)
{
    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return ngx_http_top_header_filter(r);
}


ngx_int_t
ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t  rc;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http output filter \"%V?%V\"", &r->uri, &r->args);

    rc = ngx_http_top_body_filter(r, in);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        r->connection->error = 1;
    }

    return rc;
}


u_char *
ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *path,
    size_t *root_length, size_t reserved)
{
    u_char                    *last;
    size_t                     alias;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    alias = clcf->alias ? clcf->name.len : 0;

    if (alias && !r->valid_location) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "\"alias\" could not be used in location \"%V\" "
                      "where URI was rewritten", &clcf->name);
        return NULL;
    }

    reserved += r->uri.len - alias + 1;

    if (clcf->root_lengths == NULL) {

        *root_length = clcf->root.len;

        path->len = clcf->root.len + reserved;

        path->data = ngx_palloc(r->pool, path->len);
        if (path->data == NULL) {
            return NULL;
        }

        last = ngx_copy(path->data, clcf->root.data, clcf->root.len);

    } else {
        if (ngx_http_script_run(r, path, clcf->root_lengths->elts, reserved,
                                clcf->root_values->elts)
            == NULL)
        {
            return NULL;
        }

        if (ngx_conf_full_name((ngx_cycle_t *) ngx_cycle, path) == NGX_ERROR) {
            return NULL;
        }

        *root_length = path->len - reserved;
        last = path->data + *root_length;
    }

    last = ngx_cpystrn(last, r->uri.data + alias, r->uri.len - alias + 1);

    return last;
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
        || ngx_strncasecmp(encoded.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1)
           != 0)
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

    if (len == 0 || len == auth.len) {
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
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags)
{
    ngx_connection_t              *c;
    ngx_http_request_t            *sr;
    ngx_http_log_ctx_t            *ctx;
    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_postponed_request_t  *pr, *p;

    r->main->subrequests--;

    if (r->main->subrequests == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        r->main->subrequests = 1;
        return NGX_ERROR;
    }

    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in = r->headers_in;

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    ngx_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->zero_in_uri = (flags & NGX_HTTP_ZERO_IN_URI) != 0;
    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = r->method_name;
    sr->http_protocol = r->http_protocol;

    if (ngx_http_set_exten(sr) != NGX_OK) {
        return NGX_ERROR;
    }

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_request_empty_handler;

    if (c->data == r) {
        c->data = sr;
    }

    sr->in_addr = r->in_addr;
    sr->port = r->port;
    sr->port_text = r->port_text;
    sr->server_name = r->server_name;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
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

    ctx = c->log->data;
    ctx->current_request = sr;

    sr->internal = 1;
    sr->fast_subrequest = 1;

    sr->discard_body = r->discard_body;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    ngx_http_handler(sr);

    if (!c->destroyed) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http subrequest done \"%V?%V\"", uri, &sr->args);

        r->main->subrequests++;

        *psr = sr;

        if (sr->fast_subrequest) {
            sr->fast_subrequest = 0;

            if (sr->done) {
                return NGX_OK;
            }
        }

        return NGX_AGAIN;
    }

    return NGX_DONE;
}


ngx_int_t
ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args)
{
    ngx_http_core_srv_conf_t  *cscf;

    r->uri_changes--;

    if (r->uri_changes == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while internal redirect to \"%V\"", uri);

        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    r->uri = *uri;

    if (args) {
        r->args = *args;

    } else {
        r->args.len = 0;
        r->args.data = NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%V?%V\"", uri, &r->args);

    if (ngx_http_set_exten(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    /* clear the modules contexts */
    ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    ngx_http_update_location_config(r);

    r->internal = 1;

    ngx_http_handler(r);

    return NGX_DONE;
}


ngx_int_t
ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                   i;
    ngx_http_core_srv_conf_t    *cscf;
    ngx_http_core_loc_conf_t   **clcfp;
    ngx_http_core_main_conf_t   *cmcf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    clcfp = cscf->locations.elts;

    for (i = cscf->named_start; i < cscf->locations.nelts; i++) {

        if (name->len != clcfp[i]->name.len
            || ngx_strncmp(name->data, clcfp[i]->name.data, name->len) != 0)
        {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "named location: %V \"%V?%V\"", name, &r->uri, &r->args);

        r->internal = 1;

        r->loc_conf = clcfp[i]->loc_conf;

        ngx_http_update_location_config(r);

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        r->phase_handler = cmcf->phase_engine.location_rewrite_index;
        ngx_http_core_run_phases(r);

        return NGX_DONE;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "could not find named location \"%V\"", name);

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return NGX_DONE;
}


ngx_http_cleanup_t *
ngx_http_cleanup_add(ngx_http_request_t *r, size_t size)
{
    ngx_http_cleanup_t  *cln;

    r = r->main;

    cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = ngx_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cleanup add: %p", cln);

    return cln;
}


static char *
ngx_http_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                        *rv;
    void                        *mconf;
    ngx_uint_t                   i;
    ngx_conf_t                   pcf;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *ctx, *http_ctx;
    ngx_http_core_srv_conf_t    *cscf, **cscfp;
    ngx_http_core_loc_conf_t   **clcfp;
    ngx_http_core_main_conf_t   *cmcf;

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

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[i]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
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

    ngx_sort(cscf->locations.elts, (size_t) cscf->locations.nelts,
             sizeof(ngx_http_core_loc_conf_t *), ngx_http_core_cmp_locations);

    clcfp = cscf->locations.elts;

#if (NGX_PCRE)

    cscf->regex_start = cscf->locations.nelts;

    for (i = 0; i < cscf->locations.nelts; i++) {
        if (clcfp[i]->regex) {
            cscf->regex_start = i;
            break;
        }
    }

#endif

    cscf->named_start = cscf->locations.nelts;

    for (i = 0; i < cscf->locations.nelts; i++) {
        if (clcfp[i]->named) {
            cscf->named_start = i;
            break;
        }
    }

    return rv;
}


static char *
ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                      *rv;
    ngx_uint_t                 i;
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

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[ngx_modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[ngx_modules[i]->ctx_index] == NULL) {
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

        if (value[1].data[0] == '@') {
            clcf->named = 1;
        }
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

        if (pclcf->named) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "location \"%V\" could not be inside "
                               "the named location \"%V\"",
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

        if (pclcf->locations == NULL) {
            pclcf->locations = ngx_array_create(cf->pool, 2, sizeof(void *));

            if (pclcf->locations == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        clcfp = ngx_array_push(pclcf->locations);
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

    if (clcf->locations == NULL) {
        return rv;
    }

    ngx_sort(clcf->locations->elts, (size_t) clcf->locations->nelts,
             sizeof(ngx_http_core_loc_conf_t *), ngx_http_core_cmp_locations);

#if (NGX_PCRE)

    clcf->regex_start = clcf->locations->nelts;
    clcfp = clcf->locations->elts;

    for (i = 0; i < clcf->locations->nelts; i++) {
        if (clcfp[i]->regex) {
            clcf->regex_start = i;
            break;
        }
    }

#endif

    return rv;
}


static int
ngx_http_core_cmp_locations(const void *one, const void *two)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *first, *second;

    first = *(ngx_http_core_loc_conf_t **) one;
    second = *(ngx_http_core_loc_conf_t **) two;

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return ngx_strcmp(first->name.data, second->name.data);
    }

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
    ngx_http_core_loc_conf_t *lcf = conf;

    char        *rv;
    ngx_conf_t   save;

    if (lcf->types == NULL) {
        lcf->types = ngx_array_create(cf->pool, 64, sizeof(ngx_hash_key_t));
        if (lcf->types == NULL) {
            return NGX_CONF_ERROR;
        }
    }

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

    ngx_str_t       *value, *content_type, *old, file;
    ngx_uint_t       i, n;
    ngx_hash_key_t  *type;

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "include") == 0) {
        file = value[1];

        if (ngx_conf_full_name(cf->cycle, &file) == NGX_ERROR){
            return NGX_CONF_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return ngx_conf_parse(cf, &file);
    }

    content_type = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (content_type == NULL) {
        return NGX_CONF_ERROR;
    }

    *content_type = value[0];

    for (i = 1; i < cf->args->nelts; i++) {

        for (n = 0; n < value[i].len; n++) {
            value[i].data[n] = ngx_tolower(value[i].data[n]);
        }

        type = lcf->types->elts;
        for (n = 0; n < lcf->types->nelts; n++) {
            if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
                old = type[n].value;
                type[n].value = content_type;

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate extention \"%V\", "
                                   "content type: \"%V\", "
                                   "old content type: \"%V\"",
                                   &value[i], content_type, old);
                continue;
            }
        }


        type = ngx_array_push(lcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = ngx_hash_key(value[i].data, value[i].len);
        type->value = content_type;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_core_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_variables_add_core_vars(cf);
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
                       sizeof(ngx_http_core_srv_conf_t *))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cmcf->server_names_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = NGX_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_core_main_conf_t *cmcf = conf;

    if (cmcf->server_names_hash_max_size == NGX_CONF_UNSET_UINT) {
        cmcf->server_names_hash_max_size = 512;
    }

    if (cmcf->server_names_hash_bucket_size == NGX_CONF_UNSET_UINT) {
        cmcf->server_names_hash_bucket_size = ngx_cacheline_size;
    }

    cmcf->server_names_hash_bucket_size =
            ngx_align(cmcf->server_names_hash_bucket_size, ngx_cacheline_size);


    if (cmcf->variables_hash_max_size == NGX_CONF_UNSET_UINT) {
        cmcf->variables_hash_max_size = 512;
    }

    if (cmcf->variables_hash_bucket_size == NGX_CONF_UNSET_UINT) {
        cmcf->variables_hash_bucket_size = 64;
    }

    cmcf->variables_hash_bucket_size =
               ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

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

    if (ngx_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(ngx_http_server_name_t))
        == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->request_pool_size = NGX_CONF_UNSET_SIZE;
    cscf->client_header_timeout = NGX_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->optimize_server_names = NGX_CONF_UNSET;
    cscf->ignore_invalid_headers = NGX_CONF_UNSET;
    cscf->merge_slashes = NGX_CONF_UNSET;

    return cscf;
}


static char *
ngx_http_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_srv_conf_t *prev = parent;
    ngx_http_core_srv_conf_t *conf = child;

    ngx_http_listen_t       *ls;
    ngx_http_server_name_t  *sn;

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

        ls->conf.backlog = NGX_LISTEN_BACKLOG;
        ls->conf.rcvbuf = -1;
        ls->conf.sndbuf = -1;
    }

    if (conf->server_name.data == NULL) {
        conf->server_name.data = ngx_palloc(cf->pool, NGX_MAXHOSTNAMELEN);
        if (conf->server_name.data == NULL) {
            return NGX_CONF_ERROR;
        }

        if (gethostname((char *) conf->server_name.data, NGX_MAXHOSTNAMELEN)
            == -1)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               "gethostname() failed");
            return NGX_CONF_ERROR;
        }

        conf->server_name.len = ngx_strlen(conf->server_name.data);

        sn = ngx_array_push(&conf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        sn->regex = NULL;
#endif
        sn->core_srv_conf = conf;
        sn->name.len = conf->server_name.len;
        sn->name.data = conf->server_name.data;
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

    ngx_conf_merge_value(conf->optimize_server_names,
                              prev->optimize_server_names, 1);

    ngx_conf_merge_value(conf->ignore_invalid_headers,
                              prev->ignore_invalid_headers, 1);

    ngx_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);

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
     *     lcf->root = { 0, NULL };
     *     lcf->limit_except = 0;
     *     lcf->post_action = { 0, NULL };
     *     lcf->types = NULL;
     *     lcf->default_type = { 0, NULL };
     *     lcf->err_log = NULL;
     *     lcf->error_pages = NULL;
     *     lcf->client_body_path = NULL;
     *     lcf->regex = NULL;
     *     lcf->exact_match = 0;
     *     lcf->auto_redirect = 0;
     *     lcf->alias = 0;
     */

    lcf->client_max_body_size = NGX_CONF_UNSET;
    lcf->client_body_buffer_size = NGX_CONF_UNSET_SIZE;
    lcf->client_body_timeout = NGX_CONF_UNSET_MSEC;
    lcf->satisfy_any = NGX_CONF_UNSET;
    lcf->internal = NGX_CONF_UNSET;
    lcf->client_body_in_file_only = NGX_CONF_UNSET;
    lcf->sendfile = NGX_CONF_UNSET;
    lcf->sendfile_max_chunk = NGX_CONF_UNSET_SIZE;
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
    lcf->msie_refresh = NGX_CONF_UNSET;
    lcf->log_not_found = NGX_CONF_UNSET;
    lcf->recursive_error_pages = NGX_CONF_UNSET;
    lcf->server_tokens = NGX_CONF_UNSET;
    lcf->types_hash_max_size = NGX_CONF_UNSET_UINT;
    lcf->types_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return lcf;
}


static ngx_str_t  ngx_http_core_text_html_type = ngx_string("text/html");
static ngx_str_t  ngx_http_core_image_gif_type = ngx_string("image/gif");
static ngx_str_t  ngx_http_core_image_jpeg_type = ngx_string("image/jpeg");

static ngx_hash_key_t  ngx_http_core_default_types[] = {
    { ngx_string("html"), 0, &ngx_http_core_text_html_type },
    { ngx_string("gif"), 0, &ngx_http_core_image_gif_type },
    { ngx_string("jpg"), 0, &ngx_http_core_image_jpeg_type },
    { ngx_null_string, 0, NULL }
};


static char *
ngx_http_core_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_loc_conf_t *prev = parent;
    ngx_http_core_loc_conf_t *conf = child;

    ngx_uint_t        i;
    ngx_hash_key_t   *type;
    ngx_hash_init_t   types_hash;

    if (conf->root.data == NULL) {

        conf->alias = prev->alias;
        conf->root = prev->root;
        conf->root_lengths = prev->root_lengths;
        conf->root_values = prev->root_values;

        if (prev->root.data == NULL) {
            conf->root.len = sizeof("html") - 1;
            conf->root.data = (u_char *) "html";

            if (ngx_conf_full_name(cf->cycle, &conf->root) == NGX_ERROR) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (conf->post_action.data == NULL) {
        conf->post_action = prev->post_action;
    }

    ngx_conf_merge_uint_value(conf->types_hash_max_size,
                              prev->types_hash_max_size, 1024);

    ngx_conf_merge_uint_value(conf->types_hash_bucket_size,
                              prev->types_hash_bucket_size,
                              ngx_cacheline_size);

    conf->types_hash_bucket_size = ngx_align(conf->types_hash_bucket_size,
                                             ngx_cacheline_size);

    /*
     * the special handling the "types" directive in the "http" section
     * to inherit the http's conf->types_hash to all servers
     */

    if (prev->types && prev->types_hash.buckets == NULL) {

        types_hash.hash = &prev->types_hash;
        types_hash.key = ngx_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (ngx_hash_init(&types_hash, prev->types->elts, prev->types->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->types == NULL) {
        conf->types = prev->types;
        conf->types_hash = prev->types_hash;
    }

    if (conf->types == NULL) {
        conf->types = ngx_array_create(cf->pool, 4, sizeof(ngx_hash_key_t));
        if (conf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; ngx_http_core_default_types[i].key.len; i++) {
            type = ngx_array_push(conf->types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->key = ngx_http_core_default_types[i].key;
            type->key_hash =
                       ngx_hash_key_lc(ngx_http_core_default_types[i].key.data,
                                       ngx_http_core_default_types[i].key.len);
            type->value = ngx_http_core_default_types[i].value;
        }
    }

    if (conf->types_hash.buckets == NULL) {

        types_hash.hash = &conf->types_hash;
        types_hash.key = ngx_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "mime_types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (ngx_hash_init(&types_hash, conf->types->elts, conf->types->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
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

    ngx_conf_merge_off_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1 * 1024 * 1024);
    ngx_conf_merge_size_value(conf->client_body_buffer_size,
                              prev->client_body_buffer_size,
                              (size_t) 2 * ngx_pagesize);
    ngx_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 60000);

    ngx_conf_merge_value(conf->satisfy_any, prev->satisfy_any, 0);
    ngx_conf_merge_value(conf->internal, prev->internal, 0);
    ngx_conf_merge_value(conf->client_body_in_file_only,
                              prev->client_body_in_file_only, 0);
    ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    ngx_conf_merge_size_value(conf->sendfile_max_chunk,
                              prev->sendfile_max_chunk, 0);
    ngx_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

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
    ngx_conf_merge_value(conf->msie_refresh, prev->msie_refresh, 0);
    ngx_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);
    ngx_conf_merge_value(conf->recursive_error_pages,
                              prev->recursive_error_pages, 0);
    ngx_conf_merge_value(conf->server_tokens, prev->server_tokens, 1);

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

    ngx_str_t          *value, size;
    ngx_url_t           u;
    ngx_uint_t          n;
    ngx_http_listen_t  *ls;

    /*
     * TODO: check duplicate 'listen' directives,
     *       add resolved name to server names ???
     */

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&scf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_http_listen_t));

    ls->family = AF_INET;
    ls->addr = u.addr.in_addr;
    ls->port = u.port;
    ls->file_name = cf->conf_file->file.name.data;
    ls->line = cf->conf_file->line;
    ls->conf.backlog = NGX_LISTEN_BACKLOG;
    ls->conf.rcvbuf = -1;
    ls->conf.sndbuf = -1;

    n = ngx_inet_ntop(AF_INET, &ls->addr, ls->conf.addr, INET_ADDRSTRLEN + 6);
    ngx_sprintf(&ls->conf.addr[n], ":%ui", ls->port);

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

        if (ngx_strncmp(value[n].data, "backlog=", 8) == 0) {
            ls->conf.backlog = ngx_atoi(value[n].data + 8, value[n].len - 8);
            ls->conf.bind = 1;

            if (ls->conf.backlog == NGX_ERROR || ls->conf.backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            ls->conf.rcvbuf = ngx_parse_size(&size);
            ls->conf.bind = 1;

            if (ls->conf.rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            ls->conf.sndbuf = ngx_parse_size(&size);
            ls->conf.bind = 1;

            if (ls->conf.sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            ls->conf.accept_filter = (char *) &value[n].data[14];
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
    ngx_http_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    ngx_str_t               *value, name;
    ngx_uint_t               i;
    ngx_http_server_name_t  *sn;
#if (NGX_PCRE)
    ngx_str_t                err;
    u_char                   errstr[NGX_MAX_CONF_ERRSTR];
#endif

    value = cf->args->elts;

    ch = value[1].data[0];

    if (cscf->server_name.data == NULL && value[1].len) {
        if (ngx_strchr(value[1].data, '*')) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "first server name \"%V\" must not be wildcard",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        if (value[1].data[0] == '~') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "first server name \"%V\" "
                               "must not be regular expression", &value[1]);
            return NGX_CONF_ERROR;
        }

        name = value[1];

        if (ch == '.') {
            name.len--;
            name.data++;
        }

        cscf->server_name.len = name.len;
        cscf->server_name.data = ngx_pstrdup(cf->pool, &name);
        if (cscf->server_name.data == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if (value[i].len == 1 && ch == '*') {
            cscf->wildcard = 1;
            continue;
        }

        if (value[i].len == 0
            || (ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strchr(value[i].data, '/')) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "server name \"%V\" has strange symbols",
                               &value[i]);
        }

        sn = ngx_array_push(&cscf->server_names);
        if (sn == NULL) {
            return NGX_CONF_ERROR;
        }

#if (NGX_PCRE)
        sn->regex = NULL;
#endif
        sn->core_srv_conf = cscf;
        sn->name.len = value[i].len;
        sn->name.data = value[i].data;

        if (value[i].data[0] != '~') {
            continue;
        }

#if (NGX_PCRE)
        err.len = NGX_MAX_CONF_ERRSTR;
        err.data = errstr;

        value[i].len--;
        value[i].data++;

        sn->regex = ngx_regex_compile(&value[i], NGX_REGEX_CASELESS, cf->pool,
                                      &err);

        if (sn->regex == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
            return NGX_CONF_ERROR;
        }

        sn->name.len = value[i].len;
        sn->name.data = value[i].data;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the using of the regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return NGX_CONF_ERROR;
#endif
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_str_t                  *value;
    ngx_uint_t                  alias, n;
    ngx_http_script_compile_t   sc;

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

    if (lcf->named && alias) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the \"alias\" directive may not be used "
                           "inside named location");

        return NGX_CONF_ERROR;
    }

#if (NGX_PCRE)

    if (lcf->regex && alias) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the \"alias\" directive may not be used "
                           "inside location given by regular expression");

        return NGX_CONF_ERROR;
    }

#endif

    value = cf->args->elts;

    if (ngx_strstr(value[1].data, "$document_root")
        || ngx_strstr(value[1].data, "${document_root}"))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the $document_root variable may not be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return NGX_CONF_ERROR;
    }

    lcf->alias = alias;
    lcf->root = value[1];

    if (!alias && lcf->root.data[lcf->root.len - 1] == '/') {
        lcf->root.len--;
    }

    if (lcf->root.data[0] != '$') {
        if (ngx_conf_full_name(cf->cycle, &lcf->root) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    n = ngx_http_script_variables_count(&lcf->root);

    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &lcf->root;
    sc.lengths = &lcf->root_lengths;
    sc.values = &lcf->root_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_http_method_name_t  ngx_methods_names[] = {
   { (u_char *) "GET",       (uint32_t) ~NGX_HTTP_GET },
   { (u_char *) "HEAD",      (uint32_t) ~NGX_HTTP_HEAD },
   { (u_char *) "POST",      (uint32_t) ~NGX_HTTP_POST },
   { (u_char *) "PUT",       (uint32_t) ~NGX_HTTP_PUT },
   { (u_char *) "DELETE",    (uint32_t) ~NGX_HTTP_DELETE },
   { (u_char *) "MKCOL",     (uint32_t) ~NGX_HTTP_MKCOL },
   { (u_char *) "COPY",      (uint32_t) ~NGX_HTTP_COPY },
   { (u_char *) "MOVE",      (uint32_t) ~NGX_HTTP_MOVE },
   { (u_char *) "OPTIONS",   (uint32_t) ~NGX_HTTP_OPTIONS },
   { (u_char *) "PROPFIND" , (uint32_t) ~NGX_HTTP_PROPFIND },
   { (u_char *) "PROPPATCH", (uint32_t) ~NGX_HTTP_PROPPATCH },
   { (u_char *) "LOCK",      (uint32_t) ~NGX_HTTP_LOCK },
   { (u_char *) "UNLOCK",    (uint32_t) ~NGX_HTTP_UNLOCK },
   { NULL, 0 }
};


static char *
ngx_http_core_limit_except(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = conf;

    char                      *rv;
    void                      *mconf;
    ngx_str_t                 *value;
    ngx_uint_t                 i;
    ngx_conf_t                 save;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_method_name_t    *name;
    ngx_http_core_loc_conf_t  *lcf, **clcfp;

    if (clcf->limit_except) {
        return "duplicate";
    }

    clcf->limit_except = 0xffffffff;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        for (name = ngx_methods_names; name->name; name++) {

            if (ngx_strcasecmp(value[i].data, name->name) == 0) {
                clcf->limit_except &= name->method;
                goto next;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid method \"%V\"", &value[i]);
        return NGX_CONF_ERROR;

    next:
        continue;
    }

    if (!(clcf->limit_except & NGX_HTTP_GET)) {
        clcf->limit_except &= (uint32_t) ~NGX_HTTP_HEAD;
    }

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


    lcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->limit_except_loc_conf = ctx->loc_conf;
    lcf->loc_conf = ctx->loc_conf;
    lcf->name = clcf->name;
    lcf->noname = 1;

    if (clcf->locations == NULL) {
        clcf->locations = ngx_array_create(cf->pool, 2, sizeof(void *));
        if (clcf->locations == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    clcfp = ngx_array_push(clcf->locations);
    if (clcfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *clcfp = lcf;


    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LMT_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *lcf = conf;

    ngx_int_t                   overwrite;
    ngx_str_t                  *value, uri;
    ngx_uint_t                  i, n, nvar;
    ngx_array_t                *uri_lengths, *uri_values;
    ngx_http_err_page_t        *err;
    ngx_http_script_compile_t   sc;

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

        if (value[i].len > 1) {
            overwrite = ngx_atoi(&value[i].data[1], value[i].len - 1);

            if (overwrite == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

        } else {
            overwrite = 0;
        }

        n = 2;

    } else {
        overwrite = -1;
        n = 1;
    }

    uri = value[cf->args->nelts - 1];
    uri_lengths = NULL;
    uri_values = NULL;

    nvar = ngx_http_script_variables_count(&uri);

    if (nvar) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &uri;
        sc.lengths = &uri_lengths;
        sc.values = &uri_values;
        sc.variables = nvar;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        err = ngx_array_push(lcf->error_pages);
        if (err == NULL) {
            return NGX_CONF_ERROR;
        }

        err->status = ngx_atoi(value[i].data, value[i].len);

        if (err->status == NGX_ERROR || err->status == 499) {
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

        err->overwrite = (overwrite >= 0) ? overwrite : err->status;

        err->uri = uri;
        err->uri_lengths = uri_lengths;
        err->uri_values = uri_values;
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

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
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


static char *
ngx_http_core_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pool must be no less than %uz", NGX_MIN_POOL_SIZE);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
