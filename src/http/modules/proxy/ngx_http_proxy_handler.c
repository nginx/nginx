
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static int ngx_http_proxy_handler(ngx_http_request_t *r);

static int ngx_http_proxy_init(ngx_cycle_t *cycle);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child);

static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_conf_t *u);


static ngx_conf_bitmask_t  next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_PROXY_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_PROXY_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_PROXY_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_PROXY_FT_HTTP_500 },
    { ngx_string("http_404"), NGX_HTTP_PROXY_FT_HTTP_404 },
    { ngx_null_string, 0 }
};


static ngx_conf_bitmask_t  use_stale_masks[] = {
    { ngx_string("error"), NGX_HTTP_PROXY_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_PROXY_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_PROXY_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_PROXY_FT_HTTP_500 },
    { ngx_string("busy_lock"), NGX_HTTP_PROXY_FT_BUSY_LOCK },
    { ngx_string("max_waiting"), NGX_HTTP_PROXY_FT_MAX_WAITING },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_proxy_lm_factor_bounds = {
    ngx_conf_check_num_bounds, 0, 100
};


static ngx_command_t  ngx_http_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_set_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_request_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, request_buffer_size),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, connect_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, send_timeout),
      NULL },

    { ngx_string("proxy_header_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, header_buffer_size),
      NULL },

    { ngx_string("proxy_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, read_timeout),
      NULL },

    { ngx_string("proxy_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, bufs),
      NULL },

    { ngx_string("proxy_busy_buffers_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, busy_buffers_size),
      NULL },

    { ngx_string("proxy_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, cache_path),
      NULL },

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, temp_path),
      NULL },

    { ngx_string("proxy_temp_file_write_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, temp_file_write_size),
      NULL },

    { ngx_string("proxy_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, cache),
      NULL },


    { ngx_string("proxy_busy_lock"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_set_busy_lock_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, busy_lock),
      NULL },


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

    { ngx_string("proxy_ignore_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, ignore_expires),
      NULL },

    { ngx_string("proxy_lm_factor"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, lm_factor),
      &ngx_http_proxy_lm_factor_bounds },

    { ngx_string("proxy_default_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, default_expires),
      NULL },


    { ngx_string("proxy_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, next_upstream),
      &next_upstream_masks },

    { ngx_string("proxy_use_stale"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, use_stale),
      &use_stale_masks },

      ngx_null_command
};


ngx_http_module_t  ngx_http_proxy_module_ctx = {
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
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


ngx_http_header_t ngx_http_proxy_headers_in[] = {
    { ngx_string("Date"), offsetof(ngx_http_proxy_headers_in_t, date) },
    { ngx_string("Server"), offsetof(ngx_http_proxy_headers_in_t, server) },

    { ngx_string("Expires"), offsetof(ngx_http_proxy_headers_in_t, expires) },
    { ngx_string("Cache-Control"),
                        offsetof(ngx_http_proxy_headers_in_t, cache_control) },
    { ngx_string("X-Accel-Expires"),
                      offsetof(ngx_http_proxy_headers_in_t, x_accel_expires) },

    { ngx_string("Connection"),
                           offsetof(ngx_http_proxy_headers_in_t, connection) },
    { ngx_string("Content-Type"),
                         offsetof(ngx_http_proxy_headers_in_t, content_type) },
    { ngx_string("Content-Length"),
                       offsetof(ngx_http_proxy_headers_in_t, content_length) },
    { ngx_string("Last-Modified"),
                        offsetof(ngx_http_proxy_headers_in_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                        offsetof(ngx_http_proxy_headers_in_t, accept_ranges) },

    { ngx_null_string, 0 }
};


static int ngx_http_proxy_handler(ngx_http_request_t *r)
{
    int                    rc;
    ngx_http_proxy_ctx_t  *p;

    ngx_http_create_ctx(r, p, ngx_http_proxy_module,
                        sizeof(ngx_http_proxy_ctx_t),
                        NGX_HTTP_INTERNAL_SERVER_ERROR);

    p->lcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    p->request = r;

    /* TODO: we currently support reverse proxy only */
    p->accel = 1;

    ngx_init_array(p->states, r->pool, p->lcf->peers->number,
                   sizeof(ngx_http_proxy_state_t),
                   NGX_HTTP_INTERNAL_SERVER_ERROR);

    if (!(p->state = ngx_push_array(&p->states))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(p->state, sizeof(ngx_http_proxy_state_t));


    if (!p->lcf->cache
        || (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD))
    {
        p->state->cache = NGX_HTTP_PROXY_CACHE_PASS;

    } else if (r->bypass_cache) {
        p->state->cache = NGX_HTTP_PROXY_CACHE_BYPASS;

    } else if (r->headers_in.authorization) {
        p->state->cache = NGX_HTTP_PROXY_CACHE_AUTH;

    } else if (r->no_cache) {
        p->state->cache = NGX_HTTP_PROXY_CACHE_PGNC;
        p->cachable = 1;

    } else {
        p->cachable = 1;
    }


    if (p->state->cache) {
        return ngx_http_proxy_request_upstream(p);
    }

    rc = ngx_http_proxy_get_cached_response(p);

    if (rc == NGX_DONE || rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        return rc;
    }

    p->valid_header_in = 1;

    if (rc == NGX_OK) {
        return ngx_http_proxy_send_cached_response(p);
    }

    /* rc == NGX_DECLINED || NGX_HTTP_CACHE_STALE || NGX_HTTP_CACHE_AGED */

    return ngx_http_proxy_request_upstream(p);
}


void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc)
{
    ngx_log_debug(p->request->connection->log,
                  "finalize http proxy request");

    if (p->upstream->peer.connection) {
        ngx_http_proxy_close_connection(p);
    }

    if (p->header_sent
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    p->request->connection->log->data = p->saved_ctx;
    p->request->connection->log->handler = p->saved_handler;

    ngx_http_finalize_request(p->request, rc);
}


void ngx_http_proxy_close_connection(ngx_http_proxy_ctx_t *p)
{
    ngx_connection_t  *c;

    c = p->upstream->peer.connection;
    p->upstream->peer.connection = NULL;

    if (p->lcf->busy_lock) {
        p->lcf->busy_lock->conn_n--;
    }

    ngx_log_debug(c->log, "proxy close connection: %d" _ c->fd);

    if (c->fd == -1) {
#if 0
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
#endif
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* TODO: move connection to the connection pool */

    if (ngx_del_conn) {
        ngx_del_conn(c);

    } else {
        if (c->read->active) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

    if (ngx_close_socket(c->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    c->fd = -1;
}


size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_ctx_t *p = data;

    ngx_http_request_t     *r;
    ngx_peer_connection_t  *peer;

    r = p->request;
    peer = &p->upstream->peer;

    return ngx_snprintf(buf, len,
                        " while %s, client: %s, URL: %s, upstream: %s%s%s%s%s",
                        p->action,
                        r->connection->addr_text.data,
                        r->unparsed_uri.data,
                        peer->peers->peers[peer->cur_peer].addr_port_text.data,
                        p->lcf->upstream->uri.data,
                        r->uri.data + p->lcf->upstream->location->len,
                        r->args.len ? "?" : "",
                        r->args.len ? r->args.data : "");
}


static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t)),
                  NGX_CONF_ERROR);

    /* set by ngx_pcalloc():

    conf->bufs.num = 0;

    conf->path = NULL;

    conf->next_upstream = 0;
    conf->use_stale = 0;

    conf->upstreams = NULL;
    conf->peers = NULL;

    conf->cache_path = NULL;
    conf->temp_path = NULL;

    conf->busy_lock = NULL;

    */

    conf->request_buffer_size = NGX_CONF_UNSET;
    conf->connect_timeout = NGX_CONF_UNSET;
    conf->send_timeout = NGX_CONF_UNSET;
    conf->header_buffer_size = NGX_CONF_UNSET;
    conf->read_timeout = NGX_CONF_UNSET;
    conf->busy_buffers_size = NGX_CONF_UNSET;

    /*
     * "proxy_max_temp_file_size" is hardcoded to 1G for reverse proxy,
     * it should be configurable in the generic proxy
     */
    conf->max_temp_file_size = 1024 * 1024 * 1024;

    conf->temp_file_write_size = NGX_CONF_UNSET;

    /* "proxy_cyclic_temp_file" is disabled */
    conf->cyclic_temp_file = 0;

    conf->cache = NGX_CONF_UNSET;

    conf->pass_server = NGX_CONF_UNSET;
    conf->pass_x_accel_expires = NGX_CONF_UNSET;
    conf->ignore_expires = NGX_CONF_UNSET;
    conf->lm_factor = NGX_CONF_UNSET;
    conf->default_expires = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->request_buffer_size,
                              prev->request_buffer_size, 8192);
    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 30000);
    ngx_conf_merge_size_value(conf->header_buffer_size,
                              prev->header_buffer_size, 4096);
    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 30000);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 8, 4096);
    ngx_conf_merge_size_value(conf->busy_buffers_size,
                              prev->busy_buffers_size, 8192);

#if 0
    if (conf->max_temp_file_size > conf->bufs.size) {
        return "\"proxy_max_temp_file\" must be greater "
               "than one of the \"proxy_buffers\"";
    }
#endif

    ngx_conf_merge_size_value(conf->temp_file_write_size,
                              prev->temp_file_write_size, 16384);

    ngx_conf_merge_bitmask_value(conf->next_upstream, prev->next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_PROXY_FT_ERROR
                                  |NGX_HTTP_PROXY_FT_TIMEOUT));

    ngx_conf_merge_bitmask_value(conf->use_stale, prev->use_stale,
                                 NGX_CONF_BITMASK_SET);

    ngx_conf_merge_path_value(conf->cache_path, prev->cache_path,
                              "cache", 1, 2, 0, cf->pool);

    ngx_conf_merge_path_value(conf->temp_path, prev->temp_path,
                              "temp", 1, 2, 0, cf->pool);

    ngx_conf_merge_value(conf->cache, prev->cache, 0);


    /* conf->cache must be merged */

    if (conf->busy_lock == NULL) {
        conf->busy_lock = prev->busy_lock;
    }

    if (conf->busy_lock && conf->cache && conf->busy_lock->busy == NULL) {

        /* ngx_alloc_shared() */
        conf->busy_lock->busy_mask =
                     ngx_palloc(cf->pool, (conf->busy_lock->max_conn + 7) / 8);
        if (conf->busy_lock->busy_mask == NULL) {
            return NGX_CONF_ERROR;
        }

        /* 16 bytes are 128 bits of the md5 */

        /* ngx_alloc_shared() */
        conf->busy_lock->busy = ngx_palloc(cf->pool,
                                           16 * conf->busy_lock->max_conn);
        if (conf->busy_lock->busy == NULL) {
            return NGX_CONF_ERROR;
        }
    }


    ngx_conf_merge_value(conf->pass_server, prev->pass_server, 0);
    ngx_conf_merge_value(conf->pass_x_accel_expires,
                         prev->pass_x_accel_expires, 0);
    ngx_conf_merge_value(conf->ignore_expires, prev->ignore_expires, 0);
    ngx_conf_merge_value(conf->lm_factor, prev->lm_factor, 0);
    ngx_conf_merge_sec_value(conf->default_expires, prev->default_expires, 0);

    return NULL;
}



static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    int                        i, len;
    char                      *err, *host;
    ngx_str_t                 *value;
    struct hostent            *h;
    u_int32_t                  addr;
    ngx_http_conf_ctx_t       *ctx;
    ngx_http_core_loc_conf_t  *clcf;


    value = cf->args->elts;

    if (ngx_strncasecmp(value[1].data, "http://", 7) != 0) {
        return "invalid URL prefix";
    }

    ngx_test_null(lcf->upstream,
                  ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_upstream_conf_t)),
                  NGX_CONF_ERROR);

    lcf->upstream->url.len = value[1].len;
    if (!(lcf->upstream->url.data = ngx_palloc(cf->pool, value[1].len + 1))) {
        return NGX_CONF_ERROR;
    }
    ngx_cpystrn(lcf->upstream->url.data, value[1].data, value[1].len + 1);

    value[1].data += 7;
    value[1].len -= 7;

    err = ngx_http_proxy_parse_upstream(&value[1], lcf->upstream);

    if (err) {
        return err;
    }

    ngx_test_null(host, ngx_palloc(cf->pool, lcf->upstream->host.len + 1),
                  NGX_CONF_ERROR);
    ngx_cpystrn(host, lcf->upstream->host.data, lcf->upstream->host.len + 1);

    addr = inet_addr(host);

    if (addr == INADDR_NONE) {
        h = gethostbyname(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "host %s not found", host);
            return NGX_CONF_ERROR;
        }

        for (i = 0; h->h_addr_list[i] != NULL; i++) { /* void */ }

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers,
                      ngx_pcalloc(cf->pool,
                                  sizeof(ngx_peers_t)
                                  + sizeof(ngx_peer_t) * (i - 1)),
                      NGX_CONF_ERROR);

        lcf->peers->number = i;

        for (i = 0; h->h_addr_list[i] != NULL; i++) {
            lcf->peers->peers[i].host.data = host;
            lcf->peers->peers[i].host.len = lcf->upstream->host.len;
            lcf->peers->peers[i].addr = *(u_int32_t *)(h->h_addr_list[i]);
            lcf->peers->peers[i].port = lcf->upstream->port;

            len = INET_ADDRSTRLEN + lcf->upstream->port_text.len + 1;
            ngx_test_null(lcf->peers->peers[i].addr_port_text.data,
                          ngx_palloc(cf->pool, len),
                          NGX_CONF_ERROR);

            len = ngx_inet_ntop(AF_INET,
                                (char *) &lcf->peers->peers[i].addr,
                                lcf->peers->peers[i].addr_port_text.data,
                                len);

            lcf->peers->peers[i].addr_port_text.data[len++] = ':';

            ngx_cpystrn(lcf->peers->peers[i].addr_port_text.data + len,
                        lcf->upstream->port_text.data,
                        lcf->upstream->port_text.len + 1);

            lcf->peers->peers[i].addr_port_text.len =
                                        len + lcf->upstream->port_text.len + 1;
        }

    } else {

        /* MP: ngx_shared_palloc() */

        ngx_test_null(lcf->peers, ngx_pcalloc(cf->pool, sizeof(ngx_peers_t)),
                      NGX_CONF_ERROR);

        lcf->peers->number = 1;

        lcf->peers->peers[0].host.data = host;
        lcf->peers->peers[0].host.len = lcf->upstream->host.len;
        lcf->peers->peers[0].addr = addr;
        lcf->peers->peers[0].port = lcf->upstream->port;

        len = lcf->upstream->host.len + lcf->upstream->port_text.len + 1;

        ngx_test_null(lcf->peers->peers[0].addr_port_text.data,
                      ngx_palloc(cf->pool, len + 1),
                      NGX_CONF_ERROR);

        len = lcf->upstream->host.len;

        ngx_memcpy(lcf->peers->peers[0].addr_port_text.data,
                   lcf->upstream->host.data, len);

        lcf->peers->peers[0].addr_port_text.data[len++] = ':';

        ngx_cpystrn(lcf->peers->peers[0].addr_port_text.data + len,
                    lcf->upstream->port_text.data,
                    lcf->upstream->port_text.len + 1);
    }

    ctx = cf->ctx;
    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    lcf->upstream->location = &clcf->name;
    clcf->handler = ngx_http_proxy_handler;

    return NULL;
}


static char *ngx_http_proxy_parse_upstream(ngx_str_t *url,
                                           ngx_http_proxy_upstream_conf_t *u)
{
    size_t  i;

    if (url->data[0] == ':' || url->data[0] == '/') {
        return "invalid upstream URL";
    }

    u->host.data = url->data;
    u->host_header.data = url->data;

    for (i = 1; i < url->len; i++) {
        if (url->data[i] == ':') {
            u->port_text.data = &url->data[i] + 1;
            u->host.len = i;
        }

        if (url->data[i] == '/') {
            u->uri.data = &url->data[i];
            u->uri.len = url->len - i;
            u->host_header.len = i;

            if (u->host.len == 0) {
                u->host.len = i;
            }

            if (u->port_text.data == NULL) {
                u->port = htons(80);
                u->port_text.len = 2;
                u->port_text.data = "80";
                return NULL;
            }

            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len > 0) {
                u->port = ngx_atoi(u->port_text.data, u->port_text.len);
                if (u->port > 0) {
                    u->port = htons((u_short) u->port);
                    return NULL;
                }
            }

            return "invalid port in upstream URL";
        }
    }

    if (u->host.len == 0) {
        u->host.len = i;
    }

    u->host_header.len = i;

    u->uri.data = "/";
    u->uri.len = 1;

    if (u->port_text.data == NULL) {
        u->port = htons(80);
        u->port_text.len = 2;
        u->port_text.data = "80";
        return NULL;
    }

    u->port_text.len = &url->data[i] - u->port_text.data;

    if (u->port_text.len > 0) {
        u->port = ngx_atoi(u->port_text.data, u->port_text.len);
        if (u->port > 0) {
            u->port = htons((u_short) u->port);
            return NULL;
        }
    }

    return "invalid port in upstream URL";
}
