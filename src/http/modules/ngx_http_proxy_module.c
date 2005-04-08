
/*  
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t   upstream;

    ngx_peers_t               *peers;

    ngx_array_t               *headers_set_len;
    ngx_array_t               *headers_set;
    ngx_hash_t                *headers_set_hash;

    ngx_flag_t                 preserve_host;
    ngx_flag_t                 set_x_url;
    ngx_flag_t                 set_x_real_ip;
    ngx_flag_t                 add_x_forwarded_for;
    ngx_flag_t                 pass_server;
    ngx_flag_t                 pass_x_accel_expires;

    ngx_str_t                 *location0;

    ngx_str_t                  host_header;
    ngx_str_t                  uri0;

    ngx_array_t               *headers_sources;
    ngx_array_t               *headers_names;
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_list_t                 headers;
    
    ngx_table_elt_t           *date;
    ngx_table_elt_t           *server;

    ngx_table_elt_t           *expires;
    ngx_table_elt_t           *cache_control;
    ngx_table_elt_t           *etag;
    ngx_table_elt_t           *x_accel_expires;

    ngx_table_elt_t           *connection;
    ngx_table_elt_t           *content_type;
    ngx_table_elt_t           *content_length;
    
#if (NGX_HTTP_GZIP)
    ngx_table_elt_t           *content_encoding;
#endif
    
    ngx_table_elt_t           *last_modified;
    ngx_table_elt_t           *location;
    ngx_table_elt_t           *accept_ranges;
    ngx_table_elt_t           *x_pad;

    off_t                      content_length_n;
} ngx_http_proxy_headers_in_t;


static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_send_header(ngx_http_request_t *r);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_proxy_compile_header_start(ngx_table_elt_t *h,
    ngx_array_t *lengths, ngx_array_t *values, ngx_uint_t value);
static ngx_int_t ngx_http_proxy_compile_header_end(ngx_array_t *lengths,
    ngx_array_t *values);

static ngx_int_t ngx_http_proxy_init(ngx_cycle_t *cycle);
static ngx_http_variable_value_t *ngx_http_proxy_host_variable
    (ngx_http_request_t *r, uintptr_t data);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_proxy_set_x_var(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_proxy_lowat_post =
                                                { ngx_http_proxy_lowat_check };

static ngx_conf_bitmask_t  ngx_http_proxy_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("proxy_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.send_lowat),
      &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_pass_unparsed_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_unparsed_uri),
      NULL },

    { ngx_string("proxy_preserve_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, preserve_host),
      NULL },

    { ngx_string("proxy_set_x_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, set_x_url),
      NULL },

    { ngx_string("proxy_set_x_real_ip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, set_x_real_ip),
      NULL },

    { ngx_string("proxy_set_x_var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_set_x_var,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_add_x_forwarded_for"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, add_x_forwarded_for),
      NULL },

    { ngx_string("proxy_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.header_buffer_size),
      NULL },

    { ngx_string("proxy_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { ngx_string("proxy_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.busy_buffers_size),
      NULL },

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_path),
      (void *) ngx_garbage_collector_temp_handler },

    { ngx_string("proxy_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.max_temp_file_size),
      NULL },

    { ngx_string("proxy_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_file_write_size),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream),
      &ngx_http_proxy_next_upstream_masks },

    { ngx_string("proxy_pass_server"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, pass_server),
      NULL },

    { ngx_string("proxy_pass_x_accel_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, pass_x_accel_expires),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_create_loc_conf,        /* create location configration */
    ngx_http_proxy_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_proxy_module = {
    NGX_MODULE,
    &ngx_http_proxy_module_ctx,            /* module context */
    ngx_http_proxy_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_proxy_init,                   /* init module */
    NULL                                   /* init process */
};


static ngx_str_t ngx_http_proxy_methods[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST")
};


static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;

static ngx_str_t  ngx_http_proxy_host = ngx_string("PROXY_HOST");


#if (NGX_PCRE)
static ngx_str_t ngx_http_proxy_uri = ngx_string("/");
#endif


#if 0

ngx_http_header_t ngx_http_proxy_headers_in[] = {
    { ngx_string("Date"), offsetof(ngx_http_proxy_headers_in_t, date) },
    { ngx_string("Server"), offsetof(ngx_http_proxy_headers_in_t, server) },

    { ngx_string("Expires"), offsetof(ngx_http_proxy_headers_in_t, expires) },
    { ngx_string("Cache-Control"),
                 offsetof(ngx_http_proxy_headers_in_t, cache_control) },
    { ngx_string("ETag"), offsetof(ngx_http_proxy_headers_in_t, etag) },
    { ngx_string("X-Accel-Expires"),
                 offsetof(ngx_http_proxy_headers_in_t, x_accel_expires) },

    { ngx_string("Connection"),
                 offsetof(ngx_http_proxy_headers_in_t, connection) },
    { ngx_string("Content-Type"),
                 offsetof(ngx_http_proxy_headers_in_t, content_type) },
    { ngx_string("Content-Length"),
                 offsetof(ngx_http_proxy_headers_in_t, content_length) },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_proxy_headers_in_t, content_encoding) },
#endif

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_proxy_headers_in_t, last_modified) },
    { ngx_string("Location"),
                 offsetof(ngx_http_proxy_headers_in_t, location) },
    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_proxy_headers_in_t, accept_ranges) },
    { ngx_string("X-Pad"), offsetof(ngx_http_proxy_headers_in_t, x_pad) },

    { ngx_null_string, 0 }
};

#endif


static ngx_int_t
ngx_http_proxy_handler(ngx_http_request_t *r)
{   
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_loc_conf_t  *plcf;
    
    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    
    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
    u->peer.peers = plcf->peers;
    u->peer.tries = plcf->peers->number;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_header;
    u->send_header = ngx_http_proxy_send_header;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;

    u->pipe.input_filter = ngx_event_pipe_copy_input_filter;

    u->log_ctx = r->connection->log->data;
    u->log_handler = ngx_http_upstream_log_error;

    u->schema0.len = sizeof("http://") - 1;
    u->schema0.data = (u_char *) "http://";
    u->uri0 = plcf->uri0;
    u->location0 = plcf->location0;
    
    r->upstream = u;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    size_t                          len;
    ngx_uint_t                      i, key;
    uintptr_t                       escape;
    ngx_buf_t                      *b;
    ngx_str_t                      *hh;
    ngx_chain_t                    *cl;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *header;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_loc_conf_t      *plcf;
    ngx_http_script_code_pt         code;
    ngx_http_script_len_code_pt     lcode;
    ngx_http_script_lite_engine_t   e;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    len = sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1;

    if (u->method) {
        len += ngx_http_proxy_methods[u->method - 1].len + u->uri0.len;
    } else {
        len += r->method_name.len + u->uri0.len;
    }

    escape = 0;
    
    if (plcf->upstream.pass_unparsed_uri && r->valid_unparsed_uri) {
        len += r->unparsed_uri.len - 1;

    } else {
        if (r->quoted_uri) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + u->location0->len,
                                        r->uri.len - u->location0->len,
                                        NGX_ESCAPE_URI);
        }

        len += r->uri.len - u->location0->len + escape
            + sizeof("?") - 1 + r->args.len;
    }


    e.ip = plcf->headers_set_len->elts;
    e.request = r;

    while (*(uintptr_t *) e.ip) {
        lcode = *(ngx_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    part = &r->headers_in.headers.part;
    header = part->elts;
    hh = (ngx_str_t *) plcf->headers_set_hash->buckets;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0; 
        }

        key = header[i].hash % plcf->headers_set_hash->hash_size;

        if (hh[key].len == header[i].key.len
            && ngx_strcasecmp(hh[key].data, header[i].key.data) == 0)
        {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1
            + header[i].value.len + sizeof(CRLF) - 1;
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->request_body->bufs = cl;


    /* the request line */

    if (u->method) {
        b->last = ngx_cpymem(b->last,
                             ngx_http_proxy_methods[u->method - 1].data,
                             ngx_http_proxy_methods[u->method - 1].len);
    } else {
        b->last = ngx_cpymem(b->last, r->method_name.data, r->method_name.len);
    }

    b->last = ngx_cpymem(b->last, u->uri0.data, u->uri0.len);

    if (plcf->upstream.pass_unparsed_uri && r->valid_unparsed_uri) {
        b->last = ngx_cpymem(b->last, r->unparsed_uri.data + 1,
                             r->unparsed_uri.len - 1);
    } else {
        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + u->location0->len,
                           r->uri.len - u->location0->len, NGX_ESCAPE_URI);
            b->last += r->uri.len - u->location0->len + escape;

        } else { 
            b->last = ngx_cpymem(b->last, r->uri.data + u->location0->len,
                                 r->uri.len - u->location0->len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_cpymem(b->last, r->args.data, r->args.len);
        }
    }

    b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
                         sizeof(ngx_http_proxy_version) - 1);


    e.ip = plcf->headers_set->elts;
    e.pos = b->last;

    while (*(uintptr_t *) e.ip) {
        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);
    }

    b->last = e.pos;


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

        key = header[i].hash % plcf->headers_set_hash->hash_size;

        if (hh[key].len == header[i].key.len
            && ngx_strcasecmp(hh[key].data, header[i].key.data) == 0)
        {
            continue;
        }

        b->last = ngx_cpymem(b->last, header[i].key.data, header[i].key.len);

        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_cpymem(b->last, header[i].value.data,
                             header[i].value.len);

        *b->last++ = CR; *b->last++ = LF;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \"%V: %V\"",
                       &header[i].key, &header[i].value);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG)
    {
    ngx_str_t  s;

    s.len = b->last - b->pos;
    s.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:\n\"%V\"", &s);
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_send_header(ngx_http_request_t *r)
{
    return NGX_OK;
}


static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");
    
    return;
}


static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{   
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static ngx_int_t
ngx_http_proxy_init(ngx_cycle_t *cycle)
{
#if 0
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_proxy_host, 1);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->handler = ngx_http_proxy_host_variable;
#endif

    return NGX_OK;

#if 0
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_proxy_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    for (op = ngx_http_log_fmt_ops; op->run; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->run;
        }
    }

    op->run = (ngx_http_log_op_run_pt) ngx_http_proxy_log_fmt_ops;

#endif
}


static ngx_http_variable_value_t *
ngx_http_proxy_host_variable(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *var;
    ngx_http_proxy_loc_conf_t  *plcf;

    var = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
    if (var == NULL) {
        return NULL;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    var->value = 0;
    var->text = plcf->host_header;

    return var;
}


static void *
ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.path = NULL;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */
    
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.header_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.busy_buffers_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size = NGX_CONF_UNSET_SIZE;  
    conf->upstream.temp_file_write_size = NGX_CONF_UNSET_SIZE;
    
    conf->upstream.redirect_errors = NGX_CONF_UNSET;
    conf->upstream.pass_unparsed_uri = NGX_CONF_UNSET;
    conf->upstream.x_powered_by = NGX_CONF_UNSET;

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->preserve_host = NGX_CONF_UNSET;
    conf->set_x_url = NGX_CONF_UNSET;
    conf->set_x_real_ip = NGX_CONF_UNSET;
    conf->add_x_forwarded_for = NGX_CONF_UNSET;

    conf->pass_server = NGX_CONF_UNSET;
    conf->pass_x_accel_expires = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    size_t            size;
    ngx_str_t        *name;
    ngx_table_elt_t  *src;
    ngx_http_variable_t  *var;
    
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.header_buffer_size,
                              prev->upstream.header_buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }
    

    size = conf->upstream.header_buffer_size;
    if (size < conf->upstream.bufs.size) { 
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size,
                              prev->upstream.busy_buffers_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;

    } else if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;

    } else if (conf->upstream.busy_buffers_size
               > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }
    

    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size,
                              prev->upstream.temp_file_write_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;

    } else if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size,
                              prev->upstream.max_temp_file_size,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size == NGX_CONF_UNSET_SIZE) {

        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;

    } else if (conf->upstream.max_temp_file_size != 0
               && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"fastcgi_header_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    ngx_conf_merge_msec_value(conf->upstream.redirect_errors,
                              prev->upstream.redirect_errors, 0);

    ngx_conf_merge_msec_value(conf->upstream.pass_unparsed_uri,
                              prev->upstream.pass_unparsed_uri, 0);

    if (conf->upstream.pass_unparsed_uri && conf->location0->len > 1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "\"proxy_pass_unparsed_uri\" can be set for "
                      "location \"/\" or given by regular expression.");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_msec_value(conf->upstream.x_powered_by,
                              prev->upstream.x_powered_by, 1);

    ngx_conf_merge_value(conf->preserve_host, prev->preserve_host, 0);
    ngx_conf_merge_value(conf->set_x_url, prev->set_x_url, 0);
    ngx_conf_merge_value(conf->set_x_real_ip, prev->set_x_real_ip, 0);
    ngx_conf_merge_value(conf->add_x_forwarded_for,
                              prev->add_x_forwarded_for, 0);

    if (conf->peers == NULL) {
        conf->peers = prev->peers;
        conf->upstream = prev->upstream;
    }

    if (conf->headers_set_hash == NULL) {
        conf->headers_set_len = prev->headers_set_len;
        conf->headers_set = prev->headers_set;
        conf->headers_set_hash = prev->headers_set_hash;
    }

    if (conf->headers_set_hash == NULL) {

        if (conf->headers_names == NULL) {
            conf->headers_names = ngx_array_create(cf->pool, 4,
                                                   sizeof(ngx_str_t));
            if (conf->headers_names == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->headers_sources == NULL) {
            conf->headers_sources = ngx_array_create(cf->pool, 4,
                                                     sizeof(ngx_table_elt_t));
            if (conf->headers_sources == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        /* STUB */
        var = ngx_http_add_variable(cf, &ngx_http_proxy_host, 0);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->handler = ngx_http_proxy_host_variable;
        /**/


        name = ngx_array_push(conf->headers_names);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        name->len = sizeof("Host") - 1;
        name->data = (u_char *) "Host";

        src = ngx_array_push(conf->headers_sources);
        if (src == NULL) {
            return NGX_CONF_ERROR;
        }

        src->hash = 0;
        src->key.len = sizeof("Host") - 1;
        src->key.data = (u_char *) "Host";
        src->value.len = sizeof("$PROXY_HOST") - 1;
        src->value.data = (u_char *) "$PROXY_HOST";


        name = ngx_array_push(conf->headers_names);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        name->len = sizeof("Connection") - 1;
        name->data = (u_char *) "Connection";

        src = ngx_array_push(conf->headers_sources);
        if (src == NULL) {
            return NGX_CONF_ERROR;
        }

        src->hash = 0;
        src->key.len = sizeof("Connection") - 1;
        src->key.data = (u_char *) "Connection";
        src->value.len = sizeof("close") - 1;
        src->value.data = (u_char *) "close";


        name = ngx_array_push(conf->headers_names);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        name->len = 0;
        name->data = NULL;


        if (ngx_http_script_compile_lite(cf, conf->headers_sources,
                &conf->headers_set_len, &conf->headers_set,
                ngx_http_proxy_compile_header_start,
                ngx_http_proxy_compile_header_end) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }


        conf->headers_set_hash = ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
        if (conf->headers_set_hash == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->headers_set_hash->max_size = 100;
        conf->headers_set_hash->bucket_limit = 1;
        conf->headers_set_hash->bucket_size = sizeof(ngx_str_t);
        conf->headers_set_hash->name = "proxy_headers";

        if (ngx_hash_init(conf->headers_set_hash, cf->pool,
                          conf->headers_names->elts) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
#endif
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                       "proxy_headers hash size: %ui, "
                       "max buckets per entry: %ui",
                       conf->headers_set_hash->hash_size,
                       conf->headers_set_hash->min_buckets);
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_compile_header_start(ngx_table_elt_t *h,
    ngx_array_t *lengths, ngx_array_t *values, ngx_uint_t value)
{
    u_char                       *p;
    size_t                        size;
    ngx_http_script_copy_code_t  *copy;

    copy = ngx_array_push_n(lengths, sizeof(ngx_http_script_copy_code_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->code = (ngx_http_script_code_pt) ngx_http_script_copy_len;
    copy->len = h->key.len + sizeof(": ") - 1;

    if (value) {
        copy->len += h->value.len + sizeof(CRLF) - 1;
    }

    size = (copy->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

    copy = ngx_array_push_n(values,
                            sizeof(ngx_http_script_copy_code_t) + size);
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->code = ngx_http_script_copy;
    copy->len = h->key.len + sizeof(": ") - 1;

    if (value) {
        copy->len += h->value.len + sizeof(CRLF) - 1;
    }

    p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

    p = ngx_cpymem(p, h->key.data, h->key.len);
    p = ngx_cpymem(p, ": ", sizeof(": ") - 1);

    if (value) {
        p = ngx_cpymem(p, h->value.data, h->value.len);
        ngx_memcpy(p, CRLF, sizeof(CRLF) - 1);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_compile_header_end(ngx_array_t *lengths, ngx_array_t *values)
{
    size_t                        size;
    ngx_http_script_copy_code_t  *copy;

    copy = ngx_array_push_n(lengths, sizeof(ngx_http_script_copy_code_t));
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->code = (ngx_http_script_code_pt) ngx_http_script_copy_len;
    copy->len = sizeof(CRLF) - 1;

    size = (sizeof(CRLF) - 1 + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    copy = ngx_array_push_n(values,
                            sizeof(ngx_http_script_copy_code_t) + size);
    if (copy == NULL) {
        return NGX_ERROR;
    }

    copy->code = ngx_http_script_copy;
    copy->len = sizeof(CRLF) - 1;

    ngx_memcpy((u_char *) copy + sizeof(ngx_http_script_copy_code_t),
               CRLF, sizeof(CRLF) - 1);

    return NGX_OK;
}


static char *
ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    ngx_uint_t                   i;
    ngx_str_t                   *value, *url;
    ngx_inet_upstream_t          inet_upstream;
    ngx_http_core_loc_conf_t    *clcf;
#if (NGX_HAVE_UNIX_DOMAIN)
    ngx_unix_domain_upstream_t   unix_upstream;
#endif

    value = cf->args->elts;

    url = &value[1];

    if (ngx_strncasecmp(url->data, "http://", 7) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    if (ngx_strncasecmp(url->data + 7, "unix:", 5) == 0) {

#if (NGX_HAVE_UNIX_DOMAIN)

        ngx_memzero(&unix_upstream, sizeof(ngx_unix_domain_upstream_t));

        unix_upstream.name = *url;
        unix_upstream.url.len = url->len - 7;
        unix_upstream.url.data = url->data + 7;
        unix_upstream.uri_part = 1;

        lcf->peers = ngx_unix_upstream_parse(cf, &unix_upstream);
        if (lcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        lcf->peers->peer[0].uri_separator = ":";

        lcf->host_header.len = sizeof("localhost") - 1;
        lcf->host_header.data = (u_char *) "localhost";
        lcf->uri0 = unix_upstream.uri;
#if 0
	STUB
        lcf->upstream->default_port = 1;
#endif

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the unix domain sockets are not supported "
                           "on this platform");
        return NGX_CONF_ERROR;

#endif

    } else {
        ngx_memzero(&inet_upstream, sizeof(ngx_inet_upstream_t));

        inet_upstream.name = *url;
        inet_upstream.url.len = url->len - 7;
        inet_upstream.url.data = url->data + 7;
        inet_upstream.default_port_value = 80;
        inet_upstream.uri_part = 1;

        lcf->peers = ngx_inet_upstream_parse(cf, &inet_upstream);
        if (lcf->peers == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < lcf->peers->number; i++) {
            lcf->peers->peer[i].uri_separator = ":";
        }

        lcf->host_header = inet_upstream.host_header;
        lcf->uri0 = inet_upstream.uri;
#if 0
	STUB
        lcf->port_text = inet_upstream.port_text;
        lcf->upstream->default_port = inet_upstream.default_port;
#endif
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_proxy_handler;

#if (NGX_PCRE)
    lcf->location0 = clcf->regex ? &ngx_http_proxy_uri : &clcf->name;
#else
    lcf->location0 = &clcf->name;
#endif

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_set_x_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if (*np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}
