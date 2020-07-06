
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_fastcgi_main_conf_t;


typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_uint_t                     number;
    ngx_hash_t                     hash;
} ngx_http_fastcgi_params_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_str_t                      index;

    ngx_http_fastcgi_params_t      params;
#if (NGX_HTTP_CACHE)
    ngx_http_fastcgi_params_t      params_cache;
#endif

    ngx_array_t                   *params_source;
    ngx_array_t                   *catch_stderr;

    ngx_array_t                   *fastcgi_lengths;
    ngx_array_t                   *fastcgi_values;

    ngx_flag_t                     keep_conn;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

#if (NGX_PCRE)
    ngx_regex_t                   *split_regex;
    ngx_str_t                      split_name;
#endif
} ngx_http_fastcgi_loc_conf_t;


typedef enum {
    ngx_http_fastcgi_st_version = 0,
    ngx_http_fastcgi_st_type,
    ngx_http_fastcgi_st_request_id_hi,
    ngx_http_fastcgi_st_request_id_lo,
    ngx_http_fastcgi_st_content_length_hi,
    ngx_http_fastcgi_st_content_length_lo,
    ngx_http_fastcgi_st_padding_length,
    ngx_http_fastcgi_st_reserved,
    ngx_http_fastcgi_st_data,
    ngx_http_fastcgi_st_padding
} ngx_http_fastcgi_state_e;


typedef struct {
    u_char                        *start;
    u_char                        *end;
} ngx_http_fastcgi_split_part_t;


typedef struct {
    ngx_http_fastcgi_state_e       state;
    u_char                        *pos;
    u_char                        *last;
    ngx_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    off_t                          rest;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    unsigned                       fastcgi_stdout:1;
    unsigned                       large_stderr:1;
    unsigned                       header_sent:1;
    unsigned                       closed:1;

    ngx_array_t                   *split_parts;

    ngx_str_t                      script_name;
    ngx_str_t                      path_info;
} ngx_http_fastcgi_ctx_t;


#define NGX_HTTP_FASTCGI_RESPONDER      1

#define NGX_HTTP_FASTCGI_KEEP_CONN      1

#define NGX_HTTP_FASTCGI_BEGIN_REQUEST  1
#define NGX_HTTP_FASTCGI_ABORT_REQUEST  2
#define NGX_HTTP_FASTCGI_END_REQUEST    3
#define NGX_HTTP_FASTCGI_PARAMS         4
#define NGX_HTTP_FASTCGI_STDIN          5
#define NGX_HTTP_FASTCGI_STDOUT         6
#define NGX_HTTP_FASTCGI_STDERR         7
#define NGX_HTTP_FASTCGI_DATA           8


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
    u_char  content_length_hi;
    u_char  content_length_lo;
    u_char  padding_length;
    u_char  reserved;
} ngx_http_fastcgi_header_t;


typedef struct {
    u_char  role_hi;
    u_char  role_lo;
    u_char  flags;
    u_char  reserved[5];
} ngx_http_fastcgi_begin_request_t;


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
} ngx_http_fastcgi_header_small_t;


typedef struct {
    ngx_http_fastcgi_header_t         h0;
    ngx_http_fastcgi_begin_request_t  br;
    ngx_http_fastcgi_header_small_t   h1;
} ngx_http_fastcgi_request_start_t;


static ngx_int_t ngx_http_fastcgi_eval(ngx_http_request_t *r,
    ngx_http_fastcgi_loc_conf_t *flcf);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_fastcgi_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_fastcgi_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_fastcgi_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_fastcgi_input_filter_init(void *data);
static ngx_int_t ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_fastcgi_non_buffered_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_fastcgi_process_record(ngx_http_request_t *r,
    ngx_http_fastcgi_ctx_t *f);
static void ngx_http_fastcgi_abort_request(ngx_http_request_t *r);
static void ngx_http_fastcgi_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_fastcgi_add_variables(ngx_conf_t *cf);
static void *ngx_http_fastcgi_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_fastcgi_init_params(ngx_conf_t *cf,
    ngx_http_fastcgi_loc_conf_t *conf, ngx_http_fastcgi_params_t *params,
    ngx_keyval_t *default_params);

static ngx_int_t ngx_http_fastcgi_script_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_fastcgi_path_info_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_http_fastcgi_ctx_t *ngx_http_fastcgi_split(ngx_http_request_t *r,
    ngx_http_fastcgi_loc_conf_t *flcf);

static char *ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fastcgi_split_path_info(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_fastcgi_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#if (NGX_HTTP_CACHE)
static char *ngx_http_fastcgi_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_fastcgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#endif

static char *ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post,
    void *data);


static ngx_conf_post_t  ngx_http_fastcgi_lowat_post =
    { ngx_http_fastcgi_lowat_check };


static ngx_conf_bitmask_t  ngx_http_fastcgi_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


ngx_module_t  ngx_http_fastcgi_module;


static ngx_command_t  ngx_http_fastcgi_commands[] = {

    { ngx_string("fastcgi_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_index"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, index),
      NULL },

    { ngx_string("fastcgi_split_path_info"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_split_path_info,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_store,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.store_access),
      NULL },

    { ngx_string("fastcgi_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.buffering),
      NULL },

    { ngx_string("fastcgi_request_buffering"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { ngx_string("fastcgi_ignore_client_abort"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { ngx_string("fastcgi_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("fastcgi_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { ngx_string("fastcgi_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("fastcgi_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("fastcgi_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_lowat),
      &ngx_http_fastcgi_lowat_post },

    { ngx_string("fastcgi_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("fastcgi_pass_request_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { ngx_string("fastcgi_pass_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { ngx_string("fastcgi_intercept_errors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { ngx_string("fastcgi_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("fastcgi_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("fastcgi_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { ngx_string("fastcgi_force_ranges"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { ngx_string("fastcgi_limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (NGX_HTTP_CACHE)

    { ngx_string("fastcgi_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_cache,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fastcgi_cache_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("fastcgi_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_main_conf_t, caches),
      &ngx_http_fastcgi_module },

    { ngx_string("fastcgi_cache_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { ngx_string("fastcgi_no_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.no_cache),
      NULL },

    { ngx_string("fastcgi_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { ngx_string("fastcgi_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { ngx_string("fastcgi_cache_max_range_offset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { ngx_string("fastcgi_cache_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_use_stale),
      &ngx_http_fastcgi_next_upstream_masks },

    { ngx_string("fastcgi_cache_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_methods),
      &ngx_http_upstream_cache_method_mask },

    { ngx_string("fastcgi_cache_lock"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { ngx_string("fastcgi_cache_lock_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { ngx_string("fastcgi_cache_lock_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { ngx_string("fastcgi_cache_revalidate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { ngx_string("fastcgi_cache_background_update"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { ngx_string("fastcgi_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_path),
      NULL },

    { ngx_string("fastcgi_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { ngx_string("fastcgi_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { ngx_string("fastcgi_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream),
      &ngx_http_fastcgi_next_upstream_masks },

    { ngx_string("fastcgi_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("fastcgi_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { ngx_string("fastcgi_param"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_http_upstream_param_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, params_source),
      NULL },

    { ngx_string("fastcgi_pass_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { ngx_string("fastcgi_hide_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { ngx_string("fastcgi_ignore_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, upstream.ignore_headers),
      &ngx_http_upstream_ignore_headers_masks },

    { ngx_string("fastcgi_catch_stderr"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, catch_stderr),
      NULL },

    { ngx_string("fastcgi_keep_conn"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fastcgi_loc_conf_t, keep_conn),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_fastcgi_module_ctx = {
    ngx_http_fastcgi_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_fastcgi_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fastcgi_create_loc_conf,      /* create location configuration */
    ngx_http_fastcgi_merge_loc_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_fastcgi_module = {
    NGX_MODULE_V1,
    &ngx_http_fastcgi_module_ctx,          /* module context */
    ngx_http_fastcgi_commands,             /* module directives */
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


static ngx_http_fastcgi_request_start_t  ngx_http_fastcgi_request_start = {
    { 1,                                               /* version */
      NGX_HTTP_FASTCGI_BEGIN_REQUEST,                  /* type */
      0,                                               /* request_id_hi */
      1,                                               /* request_id_lo */
      0,                                               /* content_length_hi */
      sizeof(ngx_http_fastcgi_begin_request_t),        /* content_length_lo */
      0,                                               /* padding_length */
      0 },                                             /* reserved */

    { 0,                                               /* role_hi */
      NGX_HTTP_FASTCGI_RESPONDER,                      /* role_lo */
      0, /* NGX_HTTP_FASTCGI_KEEP_CONN */              /* flags */
      { 0, 0, 0, 0, 0 } },                             /* reserved[5] */

    { 1,                                               /* version */
      NGX_HTTP_FASTCGI_PARAMS,                         /* type */
      0,                                               /* request_id_hi */
      1 },                                             /* request_id_lo */

};


static ngx_http_variable_t  ngx_http_fastcgi_vars[] = {

    { ngx_string("fastcgi_script_name"), NULL,
      ngx_http_fastcgi_script_name_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("fastcgi_path_info"), NULL,
      ngx_http_fastcgi_path_info_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_fastcgi_hide_headers[] = {
    ngx_string("Status"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_fastcgi_cache_headers[] = {
    { ngx_string("HTTP_IF_MODIFIED_SINCE"),
      ngx_string("$upstream_cache_last_modified") },
    { ngx_string("HTTP_IF_UNMODIFIED_SINCE"), ngx_string("") },
    { ngx_string("HTTP_IF_NONE_MATCH"), ngx_string("$upstream_cache_etag") },
    { ngx_string("HTTP_IF_MATCH"), ngx_string("") },
    { ngx_string("HTTP_RANGE"), ngx_string("") },
    { ngx_string("HTTP_IF_RANGE"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif


static ngx_path_init_t  ngx_http_fastcgi_temp_path = {
    ngx_string(NGX_HTTP_FASTCGI_TEMP_PATH), { 1, 2, 0 }
};


static ngx_int_t
ngx_http_fastcgi_handler(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_upstream_t           *u;
    ngx_http_fastcgi_ctx_t        *f;
    ngx_http_fastcgi_loc_conf_t   *flcf;
#if (NGX_HTTP_CACHE)
    ngx_http_fastcgi_main_conf_t  *fmcf;
#endif

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
    if (f == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    if (flcf->fastcgi_lengths) {
        if (ngx_http_fastcgi_eval(r, flcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "fastcgi://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_fastcgi_module;

    u->conf = &flcf->upstream;

#if (NGX_HTTP_CACHE)
    fmcf = ngx_http_get_module_main_conf(r, ngx_http_fastcgi_module);

    u->caches = &fmcf->caches;
    u->create_key = ngx_http_fastcgi_create_key;
#endif

    u->create_request = ngx_http_fastcgi_create_request;
    u->reinit_request = ngx_http_fastcgi_reinit_request;
    u->process_header = ngx_http_fastcgi_process_header;
    u->abort_request = ngx_http_fastcgi_abort_request;
    u->finalize_request = ngx_http_fastcgi_finalize_request;
    r->state = 0;

    u->buffering = flcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_fastcgi_input_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_fastcgi_input_filter_init;
    u->input_filter = ngx_http_fastcgi_non_buffered_filter;
    u->input_filter_ctx = r;

    if (!flcf->upstream.request_buffering
        && flcf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_fastcgi_eval(ngx_http_request_t *r, ngx_http_fastcgi_loc_conf_t *flcf)
{
    ngx_url_t             url;
    ngx_http_upstream_t  *u;

    ngx_memzero(&url, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &url.url, flcf->fastcgi_lengths->elts, 0,
                            flcf->fastcgi_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = r->upstream;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_fastcgi_create_key(ngx_http_request_t *r)
{
    ngx_str_t                    *key;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    key = ngx_array_push(&r->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    if (ngx_http_complex_value(r, &flcf->cache_key, key) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_fastcgi_create_request(ngx_http_request_t *r)
{
    off_t                         file_pos;
    u_char                        ch, *pos, *lowcase_key;
    size_t                        size, len, key_len, val_len, padding,
                                  allocated;
    ngx_uint_t                    i, n, next, hash, skip_empty, header_params;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header, **ignored;
    ngx_http_upstream_t          *u;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_fastcgi_header_t    *h;
    ngx_http_fastcgi_params_t    *params;
    ngx_http_fastcgi_loc_conf_t  *flcf;
    ngx_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    u = r->upstream;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

#if (NGX_HTTP_CACHE)
    params = u->cacheable ? &flcf->params_cache : &flcf->params;
#else
    params = &flcf->params;
#endif

    if (params->lengths) {
        ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

        ngx_http_script_flush_no_cacheable_variables(r, params->flushes);
        le.flushed = 1;

        le.ip = params->lengths->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                continue;
            }

            len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
        }
    }

    if (flcf->upstream.pass_request_headers) {

        allocated = 0;
        lowcase_key = NULL;

        if (params->number) {
            n = 0;
            part = &r->headers_in.headers.part;

            while (part) {
                n += part->nelts;
                part = part->next;
            }

            ignored = ngx_palloc(r->pool, n * sizeof(void *));
            if (ignored == NULL) {
                return NGX_ERROR;
            }
        }

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (params->number) {
                if (allocated < header[i].key.len) {
                    allocated = header[i].key.len + 16;
                    lowcase_key = ngx_pnalloc(r->pool, allocated);
                    if (lowcase_key == NULL) {
                        return NGX_ERROR;
                    }
                }

                hash = 0;

                for (n = 0; n < header[i].key.len; n++) {
                    ch = header[i].key.data[n];

                    if (ch >= 'A' && ch <= 'Z') {
                        ch |= 0x20;

                    } else if (ch == '-') {
                        ch = '_';
                    }

                    hash = ngx_hash(hash, ch);
                    lowcase_key[n] = ch;
                }

                if (ngx_hash_find(&params->hash, hash, lowcase_key, n)) {
                    ignored[header_params++] = &header[i];
                    continue;
                }

                n += sizeof("HTTP_") - 1;

            } else {
                n = sizeof("HTTP_") - 1 + header[i].key.len;
            }

            len += ((n > 127) ? 4 : 1) + ((header[i].value.len > 127) ? 4 : 1)
                + n + header[i].value.len;
        }
    }


    if (len > 65535) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "fastcgi request record is too big: %uz", len);
        return NGX_ERROR;
    }


    padding = 8 - len % 8;
    padding = (padding == 8) ? 0 : padding;


    size = sizeof(ngx_http_fastcgi_header_t)
           + sizeof(ngx_http_fastcgi_begin_request_t)

           + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */
           + len + padding
           + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */

           + sizeof(ngx_http_fastcgi_header_t); /* NGX_HTTP_FASTCGI_STDIN */


    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    ngx_http_fastcgi_request_start.br.flags =
        flcf->keep_conn ? NGX_HTTP_FASTCGI_KEEP_CONN : 0;

    ngx_memcpy(b->pos, &ngx_http_fastcgi_request_start,
               sizeof(ngx_http_fastcgi_request_start_t));

    h = (ngx_http_fastcgi_header_t *)
             (b->pos + sizeof(ngx_http_fastcgi_header_t)
                     + sizeof(ngx_http_fastcgi_begin_request_t));

    h->content_length_hi = (u_char) ((len >> 8) & 0xff);
    h->content_length_lo = (u_char) (len & 0xff);
    h->padding_length = (u_char) padding;
    h->reserved = 0;

    b->last = b->pos + sizeof(ngx_http_fastcgi_header_t)
                     + sizeof(ngx_http_fastcgi_begin_request_t)
                     + sizeof(ngx_http_fastcgi_header_t);


    if (params->lengths) {
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                e.skip = 1;

                while (*(uintptr_t *) e.ip) {
                    code = *(ngx_http_script_code_pt *) e.ip;
                    code((ngx_http_script_engine_t *) &e);
                }
                e.ip += sizeof(uintptr_t);

                e.skip = 0;

                continue;
            }

            *e.pos++ = (u_char) key_len;

            if (val_len > 127) {
                *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
                *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
                *e.pos++ = (u_char) (val_len & 0xff);

            } else {
                *e.pos++ = (u_char) val_len;
            }

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }


    if (flcf->upstream.pass_request_headers) {

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            for (n = 0; n < header_params; n++) {
                if (&header[i] == ignored[n]) {
                    goto next;
                }
            }

            key_len = sizeof("HTTP_") - 1 + header[i].key.len;
            if (key_len > 127) {
                *b->last++ = (u_char) (((key_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((key_len >> 16) & 0xff);
                *b->last++ = (u_char) ((key_len >> 8) & 0xff);
                *b->last++ = (u_char) (key_len & 0xff);

            } else {
                *b->last++ = (u_char) key_len;
            }

            val_len = header[i].value.len;
            if (val_len > 127) {
                *b->last++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((val_len >> 16) & 0xff);
                *b->last++ = (u_char) ((val_len >> 8) & 0xff);
                *b->last++ = (u_char) (val_len & 0xff);

            } else {
                *b->last++ = (u_char) val_len;
            }

            b->last = ngx_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);

            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }

            b->last = ngx_copy(b->last, header[i].value.data, val_len);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + val_len),
                           val_len, b->last - val_len);
        next:

            continue;
        }
    }


    if (padding) {
        ngx_memzero(b->last, padding);
        b->last += padding;
    }


    h = (ngx_http_fastcgi_header_t *) b->last;
    b->last += sizeof(ngx_http_fastcgi_header_t);

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        u->output.output_filter = ngx_http_fastcgi_body_output_filter;
        u->output.filter_ctx = r;

    } else if (flcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

#if (NGX_SUPPRESS_WARN)
        file_pos = 0;
        pos = NULL;
#endif

        while (body) {

            if (ngx_buf_special(body->buf)) {
                body = body->next;
                continue;
            }

            if (body->buf->in_file) {
                file_pos = body->buf->file_pos;

            } else {
                pos = body->buf->pos;
            }

            next = 0;

            do {
                b = ngx_alloc_buf(r->pool);
                if (b == NULL) {
                    return NGX_ERROR;
                }

                ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

                if (body->buf->in_file) {
                    b->file_pos = file_pos;
                    file_pos += 32 * 1024;

                    if (file_pos >= body->buf->file_last) {
                        file_pos = body->buf->file_last;
                        next = 1;
                    }

                    b->file_last = file_pos;
                    len = (ngx_uint_t) (file_pos - b->file_pos);

                } else {
                    b->pos = pos;
                    b->start = pos;
                    pos += 32 * 1024;

                    if (pos >= body->buf->last) {
                        pos = body->buf->last;
                        next = 1;
                    }

                    b->last = pos;
                    len = (ngx_uint_t) (pos - b->pos);
                }

                padding = 8 - len % 8;
                padding = (padding == 8) ? 0 : padding;

                h = (ngx_http_fastcgi_header_t *) cl->buf->last;
                cl->buf->last += sizeof(ngx_http_fastcgi_header_t);

                h->version = 1;
                h->type = NGX_HTTP_FASTCGI_STDIN;
                h->request_id_hi = 0;
                h->request_id_lo = 1;
                h->content_length_hi = (u_char) ((len >> 8) & 0xff);
                h->content_length_lo = (u_char) (len & 0xff);
                h->padding_length = (u_char) padding;
                h->reserved = 0;

                cl->next = ngx_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return NGX_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

                b = ngx_create_temp_buf(r->pool,
                                        sizeof(ngx_http_fastcgi_header_t)
                                        + padding);
                if (b == NULL) {
                    return NGX_ERROR;
                }

                if (padding) {
                    ngx_memzero(b->last, padding);
                    b->last += padding;
                }

                cl->next = ngx_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return NGX_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

            } while (!next);

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    if (!r->request_body_no_buffering) {
        h = (ngx_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(ngx_http_fastcgi_header_t);

        h->version = 1;
        h->type = NGX_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;
    }

    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_reinit_request(ngx_http_request_t *r)
{
    ngx_http_fastcgi_ctx_t  *f;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (f == NULL) {
        return NGX_OK;
    }

    f->state = ngx_http_fastcgi_st_version;
    f->fastcgi_stdout = 0;
    f->large_stderr = 0;

    if (f->split_parts) {
        f->split_parts->nelts = 0;
    }

    r->state = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                       file_pos;
    u_char                     *pos, *start;
    size_t                      len, padding;
    ngx_buf_t                  *b;
    ngx_int_t                   rc;
    ngx_uint_t                  next, last;
    ngx_chain_t                *cl, *tl, *out, **ll;
    ngx_http_fastcgi_ctx_t     *f;
    ngx_http_fastcgi_header_t  *h;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fastcgi output filter");

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!f->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "fastcgi output header");

        f->header_sent = 1;

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    cl = ngx_chain_get_free_buf(r->pool, &f->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
    b->temporary = 1;

    if (b->start == NULL) {
        /* reserve space for maximum possible padding, 7 bytes */

        b->start = ngx_palloc(r->pool,
                              sizeof(ngx_http_fastcgi_header_t) + 7);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->pos = b->start;
        b->last = b->start;

        b->end = b->start + sizeof(ngx_http_fastcgi_header_t) + 7;
    }

    *ll = cl;

    last = 0;
    padding = 0;

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
#endif

    while (in) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (in->buf->last_buf) {
            last = 1;
        }

        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {
            tl = ngx_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            b = tl->buf;
            start = b->start;

            ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and padding
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += 32 * 1024;

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (ngx_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += 32 * 1024;

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (ngx_uint_t) (pos - b->pos);
            }

            b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            padding = 8 - len % 8;
            padding = (padding == 8) ? 0 : padding;

            h = (ngx_http_fastcgi_header_t *) cl->buf->last;
            cl->buf->last += sizeof(ngx_http_fastcgi_header_t);

            h->version = 1;
            h->type = NGX_HTTP_FASTCGI_STDIN;
            h->request_id_hi = 0;
            h->request_id_lo = 1;
            h->content_length_hi = (u_char) ((len >> 8) & 0xff);
            h->content_length_lo = (u_char) (len & 0xff);
            h->padding_length = (u_char) padding;
            h->reserved = 0;

            cl->next = tl;
            cl = tl;

            tl = ngx_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            b = tl->buf;

            b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
            b->temporary = 1;

            if (b->start == NULL) {
                /* reserve space for maximum possible padding, 7 bytes */

                b->start = ngx_palloc(r->pool,
                                      sizeof(ngx_http_fastcgi_header_t) + 7);
                if (b->start == NULL) {
                    return NGX_ERROR;
                }

                b->pos = b->start;
                b->last = b->start;

                b->end = b->start + sizeof(ngx_http_fastcgi_header_t) + 7;
            }

            if (padding) {
                ngx_memzero(b->last, padding);
                b->last += padding;
            }

            cl->next = tl;
            cl = tl;

        } while (!next);

        in = in->next;
    }

    if (last) {
        h = (ngx_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(ngx_http_fastcgi_header_t);

        h->version = 1;
        h->type = NGX_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;

        cl->buf->last_buf = 1;

    } else if (padding == 0) {
        /* TODO: do not allocate buffers instead */
        cl->buf->temporary = 0;
        cl->buf->sync = 1;
    }

    cl->next = NULL;

out:

#if (NGX_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &f->free, &f->busy, &out,
                         (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter);

    for (cl = f->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    return rc;
}


static ngx_int_t
ngx_http_fastcgi_process_header(ngx_http_request_t *r)
{
    u_char                         *p, *msg, *start, *last,
                                   *part_start, *part_end;
    size_t                          size;
    ngx_str_t                      *status_line, *pattern;
    ngx_int_t                       rc, status;
    ngx_buf_t                       buf;
    ngx_uint_t                      i;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_fastcgi_ctx_t         *f;
    ngx_http_upstream_header_t     *hh;
    ngx_http_fastcgi_loc_conf_t    *flcf;
    ngx_http_fastcgi_split_part_t  *part;
    ngx_http_upstream_main_conf_t  *umcf;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    u = r->upstream;

    for ( ;; ) {

        if (f->state < ngx_http_fastcgi_st_data) {

            f->pos = u->buffer.pos;
            f->last = u->buffer.last;

            rc = ngx_http_fastcgi_process_record(r, f);

            u->buffer.pos = f->pos;
            u->buffer.last = f->last;

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type != NGX_HTTP_FASTCGI_STDOUT
                && f->type != NGX_HTTP_FASTCGI_STDERR)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI record: %ui",
                              f->type);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed FastCGI stdout");

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        if (f->state == ngx_http_fastcgi_st_padding) {

            if (u->buffer.pos + f->padding < u->buffer.last) {
                f->state = ngx_http_fastcgi_st_version;
                u->buffer.pos += f->padding;

                continue;
            }

            if (u->buffer.pos + f->padding == u->buffer.last) {
                f->state = ngx_http_fastcgi_st_version;
                u->buffer.pos = u->buffer.last;

                return NGX_AGAIN;
            }

            f->padding -= u->buffer.last - u->buffer.pos;
            u->buffer.pos = u->buffer.last;

            return NGX_AGAIN;
        }


        /* f->state == ngx_http_fastcgi_st_data */

        if (f->type == NGX_HTTP_FASTCGI_STDERR) {

            if (f->length) {
                msg = u->buffer.pos;

                if (u->buffer.pos + f->length <= u->buffer.last) {
                    u->buffer.pos += f->length;
                    f->length = 0;
                    f->state = ngx_http_fastcgi_st_padding;

                } else {
                    f->length -= u->buffer.last - u->buffer.pos;
                    u->buffer.pos = u->buffer.last;
                }

                for (p = u->buffer.pos - 1; msg < p; p--) {
                    if (*p != LF && *p != CR && *p != '.' && *p != ' ') {
                        break;
                    }
                }

                p++;

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"", p - msg, msg);

                flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

                if (flcf->catch_stderr) {
                    pattern = flcf->catch_stderr->elts;

                    for (i = 0; i < flcf->catch_stderr->nelts; i++) {
                        if (ngx_strnstr(msg, (char *) pattern[i].data,
                                        p - msg)
                            != NULL)
                        {
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }
                    }
                }

                if (u->buffer.pos == u->buffer.last) {

                    if (!f->fastcgi_stdout) {

                        /*
                         * the special handling the large number
                         * of the PHP warnings to not allocate memory
                         */

#if (NGX_HTTP_CACHE)
                        if (r->cache) {
                            u->buffer.pos = u->buffer.start
                                                     + r->cache->header_start;
                        } else {
                            u->buffer.pos = u->buffer.start;
                        }
#else
                        u->buffer.pos = u->buffer.start;
#endif
                        u->buffer.last = u->buffer.pos;
                        f->large_stderr = 1;
                    }

                    return NGX_AGAIN;
                }

            } else {
                f->state = ngx_http_fastcgi_st_padding;
            }

            continue;
        }


        /* f->type == NGX_HTTP_FASTCGI_STDOUT */

#if (NGX_HTTP_CACHE)

        if (f->large_stderr && r->cache) {
            ssize_t                     len;
            ngx_http_fastcgi_header_t  *fh;

            start = u->buffer.start + r->cache->header_start;

            len = u->buffer.pos - start - 2 * sizeof(ngx_http_fastcgi_header_t);

            /*
             * A tail of large stderr output before HTTP header is placed
             * in a cache file without a FastCGI record header.
             * To workaround it we put a dummy FastCGI record header at the
             * start of the stderr output or update r->cache_header_start,
             * if there is no enough place for the record header.
             */

            if (len >= 0) {
                fh = (ngx_http_fastcgi_header_t *) start;
                fh->version = 1;
                fh->type = NGX_HTTP_FASTCGI_STDERR;
                fh->request_id_hi = 0;
                fh->request_id_lo = 1;
                fh->content_length_hi = (u_char) ((len >> 8) & 0xff);
                fh->content_length_lo = (u_char) (len & 0xff);
                fh->padding_length = 0;
                fh->reserved = 0;

            } else {
                r->cache->header_start += u->buffer.pos - start
                                          - sizeof(ngx_http_fastcgi_header_t);
            }

            f->large_stderr = 0;
        }

#endif

        f->fastcgi_stdout = 1;

        start = u->buffer.pos;

        if (u->buffer.pos + f->length < u->buffer.last) {

            /*
             * set u->buffer.last to the end of the FastCGI record data
             * for ngx_http_parse_header_line()
             */

            last = u->buffer.last;
            u->buffer.last = u->buffer.pos + f->length;

        } else {
            last = NULL;
        }

        for ( ;; ) {

            part_start = u->buffer.pos;
            part_end = u->buffer.last;

            rc = ngx_http_parse_header_line(r, &u->buffer, 1);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi parser: %i", rc);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                if (f->split_parts && f->split_parts->nelts) {

                    part = f->split_parts->elts;
                    size = u->buffer.pos - part_start;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        size += part[i].end - part[i].start;
                    }

                    p = ngx_pnalloc(r->pool, size);
                    if (p == NULL) {
                        h->hash = 0;
                        return NGX_ERROR;
                    }

                    buf.pos = p;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        p = ngx_cpymem(p, part[i].start,
                                       part[i].end - part[i].start);
                    }

                    p = ngx_cpymem(p, part_start, u->buffer.pos - part_start);

                    buf.last = p;

                    f->split_parts->nelts = 0;

                    rc = ngx_http_parse_header_line(r, &buf, 1);

                    if (rc != NGX_OK) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                      "invalid header after joining "
                                      "FastCGI records");
                        h->hash = 0;
                        return NGX_ERROR;
                    }

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->key.data = r->header_name_start;
                    h->key.data[h->key.len] = '\0';

                    h->value.len = r->header_end - r->header_start;
                    h->value.data = r->header_start;
                    h->value.data[h->value.len] = '\0';

                    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
                    if (h->lowcase_key == NULL) {
                        return NGX_ERROR;
                    }

                } else {

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->value.len = r->header_end - r->header_start;

                    h->key.data = ngx_pnalloc(r->pool,
                                              h->key.len + 1 + h->value.len + 1
                                              + h->key.len);
                    if (h->key.data == NULL) {
                        h->hash = 0;
                        return NGX_ERROR;
                    }

                    h->value.data = h->key.data + h->key.len + 1;
                    h->lowcase_key = h->key.data + h->key.len + 1
                                     + h->value.len + 1;

                    ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
                    h->key.data[h->key.len] = '\0';
                    ngx_memcpy(h->value.data, r->header_start, h->value.len);
                    h->value.data[h->value.len] = '\0';
                }

                h->hash = r->header_hash;

                if (h->key.len == r->lowcase_index) {
                    ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

                } else {
                    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
                }

                hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                    return NGX_ERROR;
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header: \"%V: %V\"",
                               &h->key, &h->value);

                if (u->buffer.pos < u->buffer.last) {
                    continue;
                }

                /* the end of the FastCGI record */

                break;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header done");

                if (u->headers_in.status) {
                    status_line = &u->headers_in.status->value;

                    status = ngx_atoi(status_line->data, 3);

                    if (status == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;
                    u->headers_in.status_line = *status_line;

                } else if (u->headers_in.location) {
                    u->headers_in.status_n = 302;
                    ngx_str_set(&u->headers_in.status_line,
                                "302 Moved Temporarily");

                } else {
                    u->headers_in.status_n = 200;
                    ngx_str_set(&u->headers_in.status_line, "200 OK");
                }

                if (u->state && u->state->status == 0) {
                    u->state->status = u->headers_in.status_n;
                }

                break;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (last) {
            u->buffer.last = last;
        }

        f->length -= u->buffer.pos - start;

        if (f->length == 0) {
            f->state = ngx_http_fastcgi_st_padding;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            return NGX_OK;
        }

        if (rc == NGX_OK) {
            continue;
        }

        /* rc == NGX_AGAIN */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "upstream split a header line in FastCGI records");

        if (f->split_parts == NULL) {
            f->split_parts = ngx_array_create(r->pool, 1,
                                        sizeof(ngx_http_fastcgi_split_part_t));
            if (f->split_parts == NULL) {
                return NGX_ERROR;
            }
        }

        part = ngx_array_push(f->split_parts);
        if (part == NULL) {
            return NGX_ERROR;
        }

        part->start = part_start;
        part->end = part_end;

        if (u->buffer.pos < u->buffer.last) {
            continue;
        }

        return NGX_AGAIN;
    }
}


static ngx_int_t
ngx_http_fastcgi_input_filter_init(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_upstream_t          *u;
    ngx_http_fastcgi_ctx_t       *f;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    u = r->upstream;

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    u->pipe->length = flcf->keep_conn ?
                      (off_t) sizeof(ngx_http_fastcgi_header_t) : -1;

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
    {
        f->rest = 0;

    } else if (r->method == NGX_HTTP_HEAD) {
        f->rest = -2;

    } else {
        f->rest = u->headers_in.content_length_n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    u_char                       *m, *msg;
    ngx_int_t                     rc;
    ngx_buf_t                    *b, **prev;
    ngx_chain_t                  *cl;
    ngx_http_request_t           *r;
    ngx_http_fastcgi_ctx_t       *f;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    if (p->upstream_done || f->closed) {
        r->upstream->keepalive = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http fastcgi data after close");

        return NGX_OK;
    }

    b = NULL;
    prev = &buf->shadow;

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < ngx_http_fastcgi_st_data) {

            rc = ngx_http_fastcgi_process_record(r, f);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = ngx_http_fastcgi_st_padding;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi closed stdout");

                if (f->rest > 0) {
                    ngx_log_error(NGX_LOG_ERR, p->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI stdout");

                    p->upstream_error = 1;
                    p->upstream_eof = 0;
                    f->closed = 1;

                    break;
                }

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                }

                continue;
            }

            if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi sent end request");

                if (f->rest > 0) {
                    ngx_log_error(NGX_LOG_ERR, p->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI request");

                    p->upstream_error = 1;
                    p->upstream_eof = 0;
                    f->closed = 1;

                    break;
                }

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                    break;
                }

                continue;
            }
        }


        if (f->state == ngx_http_fastcgi_st_padding) {

            if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {

                if (f->pos + f->padding < f->last) {
                    p->upstream_done = 1;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    p->upstream_done = 1;
                    r->upstream->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = ngx_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = ngx_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == ngx_http_fastcgi_st_data */

        if (f->type == NGX_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = ngx_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                ngx_log_error(NGX_LOG_ERR, p->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = ngx_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = ngx_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == NGX_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->pos = f->pos;
        b->start = buf->start;
        b->end = buf->end;
        b->tag = p->tag;
        b->temporary = 1;
        b->recycled = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;
        } else {
            p->in = cl;
        }
        p->last_in = &cl->next;


        /* STUB */ b->num = buf->num;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf #%d %p", b->num, b->pos);

        if (f->pos + f->length <= f->last) {
            f->state = ngx_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

        } else {
            f->length -= f->last - f->pos;
            f->pos = f->last;
            b->last = f->last;
        }

        if (f->rest == -2) {
            f->rest = r->upstream->headers_in.content_length_n;
        }

        if (f->rest >= 0) {

            if (b->last - b->pos > f->rest) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent more data than specified in "
                              "\"Content-Length\" header");

                b->last = b->pos + f->rest;
                p->upstream_done = 1;

                break;
            }

            f->rest -= b->last - b->pos;
        }
    }

    if (flcf->keep_conn) {

        /* set p->length, minimal amount of data we want to see */

        if (f->state < ngx_http_fastcgi_st_data) {
            p->length = 1;

        } else if (f->state == ngx_http_fastcgi_st_padding) {
            p->length = f->padding;

        } else {
            /* ngx_http_fastcgi_st_data */

            p->length = f->length;
        }
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_non_buffered_filter(void *data, ssize_t bytes)
{
    u_char                  *m, *msg;
    ngx_int_t                rc;
    ngx_buf_t               *b, *buf;
    ngx_chain_t             *cl, **ll;
    ngx_http_request_t      *r;
    ngx_http_upstream_t     *u;
    ngx_http_fastcgi_ctx_t  *f;

    r = data;
    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < ngx_http_fastcgi_st_data) {

            rc = ngx_http_fastcgi_process_record(r, f);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = ngx_http_fastcgi_st_padding;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi closed stdout");

                continue;
            }
        }

        if (f->state == ngx_http_fastcgi_st_padding) {

            if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {

                if (f->rest > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI request");
                    u->error = 1;
                    break;
                }

                if (f->pos + f->padding < f->last) {
                    u->length = 0;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    u->length = 0;
                    u->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = ngx_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = ngx_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == ngx_http_fastcgi_st_data */

        if (f->type == NGX_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = ngx_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = ngx_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = ngx_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == NGX_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->flush = 1;
        b->memory = 1;

        b->pos = f->pos;
        b->tag = u->output.tag;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi output buf %p", b->pos);

        if (f->pos + f->length <= f->last) {
            f->state = ngx_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

        } else {
            f->length -= f->last - f->pos;
            f->pos = f->last;
            b->last = f->last;
        }

        if (f->rest >= 0) {

            if (b->last - b->pos > f->rest) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent more data than specified in "
                              "\"Content-Length\" header");

                b->last = b->pos + f->rest;
                u->length = 0;

                break;
            }

            f->rest -= b->last - b->pos;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_process_record(ngx_http_request_t *r,
    ngx_http_fastcgi_ctx_t *f)
{
    u_char                     ch, *p;
    ngx_http_fastcgi_state_e   state;

    state = f->state;

    for (p = f->pos; p < f->last; p++) {

        ch = *p;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi record byte: %02Xd", ch);

        switch (state) {

        case ngx_http_fastcgi_st_version:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unsupported FastCGI "
                              "protocol version: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_type;
            break;

        case ngx_http_fastcgi_st_type:
            switch (ch) {
            case NGX_HTTP_FASTCGI_STDOUT:
            case NGX_HTTP_FASTCGI_STDERR:
            case NGX_HTTP_FASTCGI_END_REQUEST:
                f->type = (ngx_uint_t) ch;
                break;
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid FastCGI "
                              "record type: %d", ch);
                return NGX_ERROR;

            }
            state = ngx_http_fastcgi_st_request_id_hi;
            break;

        /* we support the single request per connection */

        case ngx_http_fastcgi_st_request_id_hi:
            if (ch != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id high byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_request_id_lo;
            break;

        case ngx_http_fastcgi_st_request_id_lo:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id low byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_content_length_hi;
            break;

        case ngx_http_fastcgi_st_content_length_hi:
            f->length = ch << 8;
            state = ngx_http_fastcgi_st_content_length_lo;
            break;

        case ngx_http_fastcgi_st_content_length_lo:
            f->length |= (size_t) ch;
            state = ngx_http_fastcgi_st_padding_length;
            break;

        case ngx_http_fastcgi_st_padding_length:
            f->padding = (size_t) ch;
            state = ngx_http_fastcgi_st_reserved;
            break;

        case ngx_http_fastcgi_st_reserved:
            state = ngx_http_fastcgi_st_data;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi record length: %z", f->length);

            f->pos = p + 1;
            f->state = state;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_fastcgi_st_data:
        case ngx_http_fastcgi_st_padding:
            break;
        }
    }

    f->pos = p;
    f->state = state;

    return NGX_AGAIN;
}


static void
ngx_http_fastcgi_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http fastcgi request");

    return;
}


static void
ngx_http_fastcgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http fastcgi request");

    return;
}


static ngx_int_t
ngx_http_fastcgi_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_fastcgi_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_fastcgi_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_fastcgi_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_HTTP_CACHE)
    if (ngx_array_init(&conf->caches, cf->pool, 4,
                       sizeof(ngx_http_file_cache_t *))
        != NGX_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fastcgi_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->index.len = { 0, NULL };
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.force_ranges = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = NGX_CONF_UNSET;
    conf->upstream.cache_background_update = NGX_CONF_UNSET;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "fastcgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    conf->catch_stderr = NGX_CONF_UNSET_PTR;

    conf->keep_conn = NGX_CONF_UNSET;

    ngx_str_set(&conf->upstream.module, "fastcgi");

    return conf;
}


static char *
ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fastcgi_loc_conf_t *prev = parent;
    ngx_http_fastcgi_loc_conf_t *conf = child;

    size_t                        size;
    ngx_int_t                     rc;
    ngx_hash_init_t               hash;
    ngx_http_core_loc_conf_t     *clcf;

#if (NGX_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);


    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"fastcgi_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be less than "
             "the size of all \"fastcgi_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_fastcgi_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              NGX_MAX_OFF_T_VALUE);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "no \"fastcgi_cache_key\" for \"fastcgi_cache\"");
    }

    ngx_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    ngx_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    ngx_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

    ngx_conf_merge_ptr_value(conf->catch_stderr, prev->catch_stderr, NULL);

    ngx_conf_merge_value(conf->keep_conn, prev->keep_conn, 0);


    ngx_conf_merge_str_value(conf->index, prev->index, "");

    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "fastcgi_hide_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
             &prev->upstream, ngx_http_fastcgi_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->fastcgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->fastcgi_lengths = prev->fastcgi_lengths;
        conf->fastcgi_values = prev->fastcgi_values;
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->fastcgi_lengths))
    {
        clcf->handler = ngx_http_fastcgi_handler;
    }

#if (NGX_PCRE)
    if (conf->split_regex == NULL) {
        conf->split_regex = prev->split_regex;
        conf->split_name = prev->split_name;
    }
#endif

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (NGX_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = ngx_http_fastcgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = ngx_http_fastcgi_init_params(cf, conf, &conf->params_cache,
                                          ngx_http_fastcgi_cache_headers);
        if (rc != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->params in the "http" section
     * to inherit it to all servers
     */

    if (prev->params.hash.buckets == NULL
        && conf->params_source == prev->params_source)
    {
        prev->params = conf->params;
#if (NGX_HTTP_CACHE)
        prev->params_cache = conf->params_cache;
#endif
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_fastcgi_init_params(ngx_conf_t *cf, ngx_http_fastcgi_loc_conf_t *conf,
    ngx_http_fastcgi_params_t *params, ngx_keyval_t *default_params)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_uint_t                    i, nsrc;
    ngx_array_t                   headers_names, params_merged;
    ngx_keyval_t                 *h;
    ngx_hash_key_t               *hk;
    ngx_hash_init_t               hash;
    ngx_http_upstream_param_t    *src, *s;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (params->hash.buckets) {
        return NGX_OK;
    }

    if (conf->params_source == NULL && default_params == NULL) {
        params->hash.buckets = (void *) 1;
        return NGX_OK;
    }

    params->lengths = ngx_array_create(cf->pool, 64, 1);
    if (params->lengths == NULL) {
        return NGX_ERROR;
    }

    params->values = ngx_array_create(cf->pool, 512, 1);
    if (params->values == NULL) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (conf->params_source) {
        src = conf->params_source->elts;
        nsrc = conf->params_source->nelts;

    } else {
        src = NULL;
        nsrc = 0;
    }

    if (default_params) {
        if (ngx_array_init(&params_merged, cf->temp_pool, 4,
                           sizeof(ngx_http_upstream_param_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        for (i = 0; i < nsrc; i++) {

            s = ngx_array_push(&params_merged);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = src[i];
        }

        h = default_params;

        while (h->key.len) {

            src = params_merged.elts;
            nsrc = params_merged.nelts;

            for (i = 0; i < nsrc; i++) {
                if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                    goto next;
                }
            }

            s = ngx_array_push(&params_merged);
            if (s == NULL) {
                return NGX_ERROR;
            }

            s->key = h->key;
            s->value = h->value;
            s->skip_empty = 1;

        next:

            h++;
        }

        src = params_merged.elts;
        nsrc = params_merged.nelts;
    }

    for (i = 0; i < nsrc; i++) {

        if (src[i].key.len > sizeof("HTTP_") - 1
            && ngx_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
        {
            hk = ngx_array_push(&headers_names);
            if (hk == NULL) {
                return NGX_ERROR;
            }

            hk->key.len = src[i].key.len - 5;
            hk->key.data = src[i].key.data + 5;
            hk->key_hash = ngx_hash_key_lc(hk->key.data, hk->key.len);
            hk->value = (void *) 1;

            if (src[i].value.len == 0) {
                continue;
            }
        }

        copy = ngx_array_push_n(params->lengths,
                                sizeof(ngx_http_script_copy_code_t));
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) (void *)
                                                 ngx_http_script_copy_len_code;
        copy->len = src[i].key.len;

        copy = ngx_array_push_n(params->lengths,
                                sizeof(ngx_http_script_copy_code_t));
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) (void *)
                                                 ngx_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(ngx_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = ngx_array_push_n(params->values, size);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = ngx_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
        ngx_memcpy(p, src[i].key.data, src[i].key.len);


        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &params->flushes;
        sc.lengths = &params->lengths;
        sc.values = &params->values;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_ERROR;
        }

        code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = ngx_array_push_n(params->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    params->number = headers_names.nelts;

    hash.hash = &params->hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "fastcgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static ngx_int_t
ngx_http_fastcgi_script_name_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    ngx_http_fastcgi_ctx_t       *f;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    f = ngx_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return NGX_ERROR;
    }

    if (f->script_name.len == 0
        || f->script_name.data[f->script_name.len - 1] != '/')
    {
        v->len = f->script_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = f->script_name.data;

        return NGX_OK;
    }

    v->len = f->script_name.len + flcf->index.len;

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(v->data, f->script_name.data, f->script_name.len);
    ngx_memcpy(p, flcf->index.data, flcf->index.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_fastcgi_path_info_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_fastcgi_ctx_t       *f;
    ngx_http_fastcgi_loc_conf_t  *flcf;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);

    f = ngx_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return NGX_ERROR;
    }

    v->len = f->path_info.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = f->path_info.data;

    return NGX_OK;
}


static ngx_http_fastcgi_ctx_t *
ngx_http_fastcgi_split(ngx_http_request_t *r, ngx_http_fastcgi_loc_conf_t *flcf)
{
    ngx_http_fastcgi_ctx_t       *f;
#if (NGX_PCRE)
    ngx_int_t                     n;
    int                           captures[(1 + 2) * 3];

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (f == NULL) {
        f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);
    }

    if (f->script_name.len) {
        return f;
    }

    if (flcf->split_regex == NULL) {
        f->script_name = r->uri;
        return f;
    }

    n = ngx_regex_exec(flcf->split_regex, &r->uri, captures, (1 + 2) * 3);

    if (n >= 0) { /* match */
        f->script_name.len = captures[3] - captures[2];
        f->script_name.data = r->uri.data + captures[2];

        f->path_info.len = captures[5] - captures[4];
        f->path_info.data = r->uri.data + captures[4];

        return f;
    }

    if (n == NGX_REGEX_NO_MATCHED) {
        f->script_name = r->uri;
        return f;
    }

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                  n, &r->uri, &flcf->split_name);
    return NULL;

#else

    f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);

    if (f == NULL) {
        f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);
    }

    f->script_name = r->uri;

    return f;

#endif
}


static char *
ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastcgi_loc_conf_t *flcf = conf;

    ngx_url_t                   u;
    ngx_str_t                  *value, *url;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (flcf->upstream.upstream || flcf->fastcgi_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_fastcgi_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &flcf->fastcgi_lengths;
        sc.values = &flcf->fastcgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (flcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_fastcgi_split_path_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_PCRE)
    ngx_http_fastcgi_loc_conf_t *flcf = conf;

    ngx_str_t            *value;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    flcf->split_name = value[1];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }

    if (rc.captures != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pattern \"%V\" must have 2 captures", &value[1]);
        return NGX_CONF_ERROR;
    }

    flcf->split_regex = rc.regex;

    return NGX_CONF_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" requires PCRE library", &cmd->name);
    return NGX_CONF_ERROR;

#endif
}


static char *
ngx_http_fastcgi_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastcgi_loc_conf_t *flcf = conf;

    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;

    if (flcf->upstream.store != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.store = 0;
        return NGX_CONF_OK;
    }

#if (NGX_HTTP_CACHE)
    if (flcf->upstream.cache > 0) {
        return "is incompatible with \"fastcgi_cache\"";
    }
#endif

    flcf->upstream.store = 1;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        return NGX_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &flcf->upstream.store_lengths;
    sc.values = &flcf->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_CACHE)

static char *
ngx_http_fastcgi_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastcgi_loc_conf_t *flcf = conf;

    ngx_str_t                         *value;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->upstream.cache != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.cache = 0;
        return NGX_CONF_OK;
    }

    if (flcf->upstream.store > 0) {
        return "is incompatible with \"fastcgi_store\"";
    }

    flcf->upstream.cache = 1;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        flcf->upstream.cache_value = ngx_palloc(cf->pool,
                                             sizeof(ngx_http_complex_value_t));
        if (flcf->upstream.cache_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *flcf->upstream.cache_value = cv;

        return NGX_CONF_OK;
    }

    flcf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                                      &ngx_http_fastcgi_module);
    if (flcf->upstream.cache_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_fastcgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_fastcgi_loc_conf_t *flcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->cache_key.value.data) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &flcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static char *
ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"fastcgi_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}
