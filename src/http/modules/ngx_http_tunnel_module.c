
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *tunnel_lengths;
    ngx_array_t                   *tunnel_values;
} ngx_http_tunnel_loc_conf_t;


static ngx_int_t ngx_http_tunnel_eval(ngx_http_request_t *r,
    ngx_http_tunnel_loc_conf_t *tlcf);
static ngx_int_t ngx_http_tunnel_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_tunnel_process_header(ngx_http_request_t *r);
static void ngx_http_tunnel_abort_request(ngx_http_request_t *r);
static void ngx_http_tunnel_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_tunnel_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_tunnel_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_tunnel_lowat_check(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_t  ngx_http_tunnel_lowat_post =
    { ngx_http_tunnel_lowat_check };


static ngx_conf_bitmask_t  ngx_http_tunnel_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


ngx_module_t  ngx_http_tunnel_module;


static ngx_command_t  ngx_http_tunnel_commands[] = {

    { ngx_string("tunnel_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_tunnel_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tunnel_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("tunnel_socket_keepalive"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { ngx_string("tunnel_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("tunnel_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("tunnel_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.send_lowat),
      &ngx_http_tunnel_lowat_post },

    { ngx_string("tunnel_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("tunnel_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("tunnel_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.next_upstream),
      &ngx_http_tunnel_next_upstream_masks },

    { ngx_string("tunnel_next_upstream_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { ngx_string("tunnel_next_upstream_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_tunnel_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tunnel_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_tunnel_create_loc_conf,       /* create location configuration */
    ngx_http_tunnel_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_tunnel_module = {
    NGX_MODULE_V1,
    &ngx_http_tunnel_module_ctx,           /* module context */
    ngx_http_tunnel_commands,              /* module directives */
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


static ngx_int_t
ngx_http_tunnel_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_tunnel_loc_conf_t  *tlcf;

    if (r->method != NGX_HTTP_CONNECT) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    tlcf = ngx_http_get_module_loc_conf(r, ngx_http_tunnel_module);

    if (tlcf->tunnel_lengths) {
        if (ngx_http_tunnel_eval(r, tlcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    u->conf = &tlcf->upstream;

    u->create_request = ngx_http_tunnel_create_request;
    u->reinit_request = ngx_http_tunnel_reinit_request;
    u->process_header = ngx_http_tunnel_process_header;
    u->abort_request = ngx_http_tunnel_abort_request;
    u->finalize_request = ngx_http_tunnel_finalize_request;
    r->state = 0;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_tunnel_eval(ngx_http_request_t *r, ngx_http_tunnel_loc_conf_t *tlcf)
{
    ngx_url_t             url;
    ngx_http_upstream_t  *u;

    ngx_memzero(&url, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &url.url, tlcf->tunnel_lengths->elts, 0,
                            tlcf->tunnel_values->elts)
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

    return NGX_OK;
}


static ngx_int_t
ngx_http_tunnel_create_request(ngx_http_request_t *r)
{
    /* u->request_bufs = NULL */

    return NGX_OK;
}


static ngx_int_t
ngx_http_tunnel_reinit_request(ngx_http_request_t *r)
{
    r->state = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tunnel_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.status_n = NGX_HTTP_OK;
    ngx_str_set(&u->headers_in.status_line, "200 OK");

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http tunnel status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->keepalive = 0;
    u->upgrade = 1;

    return NGX_OK;
}


static void
ngx_http_tunnel_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http tunnel request");

    return;
}


static void
ngx_http_tunnel_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http tunnel request");

    return;
}


static void *
ngx_http_tunnel_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_tunnel_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tunnel_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.next_upstream = 0;
     */

    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.ignore_input = 1;

    ngx_str_set(&conf->upstream.module, "tunnel");

    return conf;
}


static char *
ngx_http_tunnel_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tunnel_loc_conf_t *prev = parent;
    ngx_http_tunnel_loc_conf_t *conf = child;

    ngx_http_core_loc_conf_t  *clcf;

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

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

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->tunnel_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;

        conf->tunnel_lengths = prev->tunnel_lengths;
        conf->tunnel_values = prev->tunnel_values;
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->tunnel_lengths))
    {
        clcf->handler = ngx_http_tunnel_handler;
    }


    return NGX_CONF_OK;
}


static char *
ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tunnel_loc_conf_t *tlcf = conf;

    ngx_url_t                   u;
    ngx_str_t                  *value, *url;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (tlcf->upstream.upstream || tlcf->tunnel_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_tunnel_handler;

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
        sc.lengths = &tlcf->tunnel_lengths;
        sc.values = &tlcf->tunnel_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    tlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (tlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_tunnel_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"tunnel_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"tunnel_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}
