
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static ngx_int_t ngx_http_proxy_handler(ngx_http_request_t *r);
#if 0
static ngx_int_t ngx_http_proxy_cache_get(ngx_http_proxy_ctx_t *p);
#endif

static size_t ngx_http_proxy_log_proxy_state_getlen(ngx_http_request_t *r,
                                                    uintptr_t data);
static u_char *ngx_http_proxy_log_proxy_state(ngx_http_request_t *r,
                                              u_char *buf,
                                              ngx_http_log_op_t *op);

#if 0
static u_char *ngx_http_proxy_log_cache_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data);
static u_char *ngx_http_proxy_log_reason(ngx_http_request_t *r, u_char *buf,
                                         uintptr_t data);
#endif

static ngx_int_t ngx_http_proxy_add_log_formats(ngx_conf_t *cf);
static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
                                           void *parent, void *child);

static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);

static char *ngx_http_proxy_set_x_var(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);
static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_t  ngx_http_proxy_lowat_post =
                                               { ngx_http_proxy_lowat_check } ;


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

    { ngx_string("proxy_send_lowat"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, send_lowat),
      &ngx_http_proxy_lowat_post },

    { ngx_string("proxy_preserve_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, preserve_host),
      NULL },

    { ngx_string("proxy_pass_unparsed_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, pass_unparsed_uri),
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

#if 0

    { ngx_string("proxy_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, cache_path),
      (void *) ngx_http_cache_cleaner_handler },

#endif

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, temp_path),
      (void *) ngx_garbage_collector_temp_handler },

    { ngx_string("proxy_max_temp_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, max_temp_file_size),
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE13,
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
    ngx_http_proxy_add_log_formats,        /* pre conf */

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
    NULL                                   /* init process */
};



static ngx_http_log_op_name_t ngx_http_proxy_log_fmt_ops[] = {
    { ngx_string("proxy"), 0, NULL,
                              ngx_http_proxy_log_proxy_state_getlen,
                              ngx_http_proxy_log_proxy_state },

#if 0
    { ngx_string("proxy_cache_state"), 0, ngx_http_proxy_log_cache_state },
    { ngx_string("proxy_reason"), 0, ngx_http_proxy_log_reason },
#endif

    { ngx_null_string, 0, NULL, NULL, NULL }
};



ngx_http_header0_t ngx_http_proxy_headers_in[] = {
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


static ngx_str_t cache_states[] = {
    ngx_string("PASS"),
    ngx_string("BYPASS"),
    ngx_string("AUTH"),
    ngx_string("PGNC"),
    ngx_string("MISS"),
    ngx_string("EXPR"),
    ngx_string("AGED"),
    ngx_string("HIT")
};


static ngx_str_t cache_reasons[] = {
    ngx_string("BPS"),
    ngx_string("XAE"),
    ngx_string("CTL"),
    ngx_string("EXP"),
    ngx_string("MVD"),
    ngx_string("LMF"),
    ngx_string("PDE")
};


#if (NGX_PCRE)
static ngx_str_t ngx_http_proxy_uri = ngx_string("/");
#endif


static ngx_int_t ngx_http_proxy_handler(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, p, ngx_http_proxy_module);


    p->lcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    p->request = r;

    /* TODO: we currently support reverse proxy only */
    p->accel = 1;

    if (ngx_array_init(&p->states, r->pool, p->lcf->peers->number,
                                  sizeof(ngx_http_proxy_state_t)) == NGX_ERROR)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p->state = ngx_array_push(&p->states);
    if (p->state == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(p->state, sizeof(ngx_http_proxy_state_t));

#if 0

    if (!p->lcf->cache
        || (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD))
    {
        p->state->cache_state = NGX_HTTP_PROXY_CACHE_PASS;

    } else if (r->bypass_cache) {
        p->state->cache_state = NGX_HTTP_PROXY_CACHE_BYPASS;

    } else if (r->headers_in.authorization) {
        p->state->cache_state = NGX_HTTP_PROXY_CACHE_AUTH;

    } else if (r->no_cache) {
        p->state->cache_state = NGX_HTTP_PROXY_CACHE_PGNC;
        p->cachable = 1;

    } else {
        p->cachable = 1;
    }


    if (p->state->cache_state != 0) {
        return ngx_http_proxy_request_upstream(p);
    }

    return ngx_http_proxy_cache_get(p);

#else

    p->state->cache_state = NGX_HTTP_PROXY_CACHE_PASS;

    return ngx_http_proxy_request_upstream(p);

#endif
}


#if 0

static ngx_int_t ngx_http_proxy_cache_get(ngx_http_proxy_ctx_t *p)
{
    u_char                          *last;
    ngx_http_request_t              *r;
    ngx_http_cache_ctx_t             ctx;
    ngx_http_proxy_upstream_conf_t  *u;

    r = p->request;
    u = p->lcf->upstream;

    ctx.key.len = u->url.len + r->uri.len - u->location->len + r->args.len;
    ctx.key.data = ngx_palloc(r->pool, ctx.key.len);
    if (ctx.key.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_cpymem(ctx.key.data, u->url.data, u->url.len);

    last = ngx_cpymem(last, r->uri.data + u->location->len,
                      r->uri.len - u->location->len);

    if (r->args.len > 0) {
        *(last++) = '?';
        last = ngx_cpymem(last, r->args.data, r->args.len);
    }

    p->header_in = ngx_create_temp_buf(r->pool, p->lcf->header_buffer_size);
    if (p->header_in == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p->header_in->tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    ctx.buf = p->header_in;
    ctx.path = p->lcf->cache_path;
    ctx.file = 1;
    ctx.primary = 1;

    ngx_http_cache_get(r, &ctx);

    return ngx_http_proxy_request_upstream(p);
}

#endif


void ngx_http_proxy_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_proxy_check_broken_connection(r, r->connection->read);
}


void ngx_http_proxy_wr_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_proxy_check_broken_connection(r, r->connection->read);
}


void ngx_http_proxy_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev)
{
    int                    n;
    char                   buf[1];
    ngx_err_t              err;
    ngx_connection_t      *c;
    ngx_http_proxy_ctx_t  *p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http proxy check client, write event:%d", ev->write);

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        c = r->connection;
        p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

        ev->eof = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!p->cachable && p->upstream->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client closed "
                          "prematurely connection, "
                          "so upstream connection is closed too");
            ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client closed "
                      "prematurely connection");

        if (p->upstream == NULL || p->upstream->peer.connection == NULL) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    c = r->connection;
    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    /*
     * we do not need to disable the write event because
     * that event has NGX_USE_CLEAR_EVENT type
     */

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        if (ngx_del_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    if (n > 0) {
        return;
    }

    ev->eof = 1;

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else {
        /* n == 0 */
        err = 0;
    }

    if (!p->cachable && p->upstream->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client closed prematurely connection, "
                      "so upstream connection is closed too");
        ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client closed prematurely connection");

    if (p->upstream == NULL || p->upstream->peer.connection == NULL) {
        ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


void ngx_http_proxy_busy_lock_handler(ngx_event_t *rev)
{
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http proxy busy lock");

    c = rev->data;
    r = c->data;
    p = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
    p->action = "waiting upstream in busy lock";

    if (p->request->connection->write->eof) {
        ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);
        ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    if (rev->timedout) {
        rev->timedout = 0;
        p->busy_lock.time++;
        p->state->bl_time = p->busy_lock.time;

#if (NGX_HTTP_FILE_CACHE)

        if (p->state->cache_state < NGX_HTTP_PROXY_CACHE_MISS) {
            ngx_http_proxy_upstream_busy_lock(p);

        } else {
            ngx_http_proxy_cache_busy_lock(p);
        }
#else

        ngx_http_proxy_upstream_busy_lock(p);

#endif

        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http proxy: client sent while busy lock");

    /*
     * TODO: kevent() notify about error, otherwise we need to
     * call ngx_peek(): recv(MSG_PEEK) to get errno. THINK about aio.
     * if there's no error we need to disable event.
     */

#if 0
#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && rev->kq_eof) {
        ngx_http_busy_unlock(p->lcf->busy_lock, &p->busy_lock);

        ngx_del_timer(rev);

        ngx_log_error(NGX_LOG_ERR, c->log, rev->kq_errno,
                      "client() closed connection");

        if (ngx_del_event(rev, NGX_READ_EVENT, NGX_CLOSE_EVENT) == NGX_ERROR) {
            ngx_http_proxy_finalize_request(p, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_http_proxy_finalize_request(p, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

#endif
#endif

}


void ngx_http_proxy_finalize_request(ngx_http_proxy_ctx_t *p, int rc)
{
    ngx_http_request_t  *r;

    r = p->request;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    if (p->upstream && p->upstream->peer.connection) {
        ngx_http_proxy_close_connection(p);
    }

    if (p->header_sent
        && (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (p->saved_ctx) {
        r->connection->log->data = p->saved_ctx;
        r->connection->log->handler = p->saved_handler;
    }

    if (p->upstream && p->upstream->event_pipe) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy temp fd: %d",
                       p->upstream->event_pipe->temp_file->file.fd);
    }

    if (p->cache) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy cache fd: %d",
                       p->cache->ctx.file.fd);
    }

    if (rc == 0 && r->main == NULL) {
        rc = ngx_http_send_last(r);
    }

    ngx_http_finalize_request(r, rc);
}


void ngx_http_proxy_close_connection(ngx_http_proxy_ctx_t *p)
{
    ngx_socket_t       fd;
    ngx_connection_t  *c;

    c = p->upstream->peer.connection;
    p->upstream->peer.connection = NULL;

    if (p->lcf->busy_lock) {
        p->lcf->busy_lock->busy--;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http proxy close connection: %d", c->fd);

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
        ngx_del_conn(c, NGX_CLOSE_EVENT);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->read->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

    /*
     * we have to clean the connection information before the closing
     * because another thread may reopen the same file descriptor
     * before we clean the connection
     */

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_OK) {

        if (c->read->prev) {
            ngx_delete_posted_event(c->read);
        }

        if (c->write->prev) {
            ngx_delete_posted_event(c->write);
        }

        c->read->closed = 1;
        c->write->closed = 1;

        ngx_mutex_unlock(ngx_posted_events_mutex);
    }

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;
    c->data = NULL;

    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }
}


u_char *ngx_http_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                          *p;
    ngx_int_t                        escape;
    ngx_http_request_t              *r;
    ngx_peer_connection_t           *peer;
    ngx_http_proxy_log_ctx_t        *ctx;
    ngx_http_proxy_upstream_conf_t  *uc;

    ctx = log->data;
    r = ctx->proxy->request;
    uc = ctx->proxy->lcf->upstream;
    peer = &ctx->proxy->upstream->peer;

    p = ngx_snprintf(buf, len,
                     " while %s, client: %V, server: %V, URL: \"%V\","
                     " upstream: http://%V%s%V",
                     ctx->proxy->action,
                     &r->connection->addr_text,
                     &r->server_name,
                     &r->unparsed_uri,
                     &peer->peers->peer[peer->cur_peer].name,
                     ctx->proxy->lcf->upstream->uri_separator,
                     &ctx->proxy->lcf->upstream->uri);
    len -= p - buf;
    buf = p;

    if (ctx->proxy->lcf->pass_unparsed_uri && r->valid_unparsed_uri) {
        p = ngx_cpymem(buf, r->unparsed_uri.data + 1, r->unparsed_uri.len - 1);
        len -= p - buf;

        return ngx_http_log_error_info(r, p, len);
    }

    if (r->quoted_uri) {
        escape = 2 * ngx_escape_uri(NULL, r->uri.data + uc->location->len,
                                    r->uri.len - uc->location->len,
                                    NGX_ESCAPE_URI);
    } else {
        escape = 0;
    }

    if (escape) {
        if (len >= r->uri.len - uc->location->len + escape) {

            ngx_escape_uri(buf, r->uri.data + uc->location->len,
                           r->uri.len - uc->location->len, NGX_ESCAPE_URI);

            buf += r->uri.len - uc->location->len + escape;
            len -= r->uri.len - uc->location->len + escape;

            if (r->args.len) {
                p = ngx_snprintf(buf, len, "?%V", &r->args);
                len -= p - buf;
                buf = p;
            }

            return ngx_http_log_error_info(r, buf, len);
        }

        p = ngx_palloc(r->pool, r->uri.len - uc->location->len + escape);
        if (p == NULL) {
            return buf;
        }

        ngx_escape_uri(p, r->uri.data + uc->location->len,
                       r->uri.len - uc->location->len, NGX_ESCAPE_URI);

        p = ngx_cpymem(buf, p, r->uri.len - uc->location->len + escape);

    } else {
        p = ngx_cpymem(buf, r->uri.data + uc->location->len,
                       r->uri.len - uc->location->len);
    }

    len -= p - buf;
    buf = p;

    if (r->args.len) {
        p = ngx_snprintf(buf, len, "?%V", &r->args);
        len -= p - buf;
        buf = p;
    }

    return ngx_http_log_error_info(r, buf, len);
}


static size_t ngx_http_proxy_log_proxy_state_getlen(ngx_http_request_t *r,
                                                    uintptr_t data)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        return 1;
    }

    return p->states.nelts * /* STUB */ 100;
}


static u_char *ngx_http_proxy_log_proxy_state(ngx_http_request_t *r,
                                              u_char *buf,
                                              ngx_http_log_op_t *op)
{
    ngx_uint_t               i;
    ngx_http_proxy_ctx_t    *p;
    ngx_http_proxy_state_t  *state;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        *buf = '-';
        return buf + 1;
    }

    i = 0;
    state = p->states.elts;

    for ( ;; ) {
        if (state[i].cache_state == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_cpymem(buf, cache_states[state[i].cache_state - 1].data,
                             cache_states[state[i].cache_state - 1].len);
        }

        *buf++ = '/';

        if (state[i].expired == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%T", state[i].expired);
        }

        *buf++ = '/';

        if (state[i].bl_time == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%T", state[i].bl_time);
        }

        *buf++ = '/';

        *buf++ = '*';

        *buf++ = ' ';

        if (state[i].status == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%ui", state[i].status);
        }

        *buf++ = '/';

        if (state[i].reason == 0) {
            *buf++ = '-';

        } else {
            buf = ngx_cpymem(buf, cache_reasons[state[i].reason - 1].data,
                             cache_reasons[state[i].reason - 1].len);
        }

        *buf++ = '/';

        if (state[i].reason < NGX_HTTP_PROXY_CACHE_XAE) {
            *buf++ = '-';

        } else {
            buf = ngx_sprintf(buf, "%T", state[i].expires);
        }

        *buf++ = ' ';
        *buf++ = '*';

        if (++i == p->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}


#if 0

static u_char *ngx_http_proxy_log_cache_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data)
{
    ngx_uint_t               i;
    ngx_http_proxy_ctx_t    *p;
    ngx_http_proxy_state_t  *state;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL || p->state->cache_state == 0) {
        if (buf == NULL) {
            return (u_char *) 1;
        }

        *buf = '-';
        return buf + 1;
    }

    if (buf == NULL) {
        /* find the request line length */
        return (u_char *) (p->states.nelts * sizeof("BYPASS") - 1);
    }

    i = 0;
    state = p->states.elts;

    for ( ;; ) {
        buf = ngx_cpymem(buf, cache_states[state[i].cache_state - 1].data,
                         cache_states[state[i].cache_state - 1].len);

        if (++i == p->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}


static u_char *ngx_http_proxy_log_reason(ngx_http_request_t *r, u_char *buf,
                                         uintptr_t data)
{
    ngx_uint_t               i;
    ngx_http_proxy_ctx_t    *p;
    ngx_http_proxy_state_t  *state;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL || p->state->reason == 0) {
        if (buf == NULL) {
            return (u_char *) 1;
        }

        *buf = '-';
        return buf + 1;
    }

    if (buf == NULL) {
        /* find the request line length */
        return (u_char *) (p->states.nelts * sizeof("BPS") - 1);
    }

    i = 0;
    state = p->states.elts;

    for ( ;; ) {
        buf = ngx_cpymem(buf, cache_reasons[state[i].reason - 1].data,
                         cache_reasons[state[i].reason - 1].len);

        if (++i == p->states.nelts) {
            return buf;
        }

        *buf++ = ',';
        *buf++ = ' ';
    }
}

#endif


static ngx_int_t ngx_http_proxy_add_log_formats(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_proxy_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    for (op = ngx_http_log_fmt_ops; op->run; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->run;
        }
    }

    op->run = (ngx_http_log_op_run_pt) ngx_http_proxy_log_fmt_ops;

    return NGX_OK;
}


static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *    conf->bufs.num = 0;
     *    conf->path = NULL;
     *    conf->next_upstream = 0;
     *    conf->use_stale = 0;
     *    conf->upstreams = NULL;
     *    conf->peers = NULL;
     *    conf->cache_path = NULL;
     *    conf->temp_path = NULL;
     *    conf->x_vars;
     *    conf->busy_lock = NULL;
     */

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_lowat = NGX_CONF_UNSET_SIZE;

    conf->pass_unparsed_uri = NGX_CONF_UNSET;
    conf->preserve_host = NGX_CONF_UNSET;
    conf->set_x_url = NGX_CONF_UNSET;
    conf->set_x_real_ip = NGX_CONF_UNSET;
    conf->add_x_forwarded_for = NGX_CONF_UNSET;

    conf->header_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->busy_buffers_size = NGX_CONF_UNSET_SIZE;

    conf->max_temp_file_size = NGX_CONF_UNSET_SIZE;
    conf->temp_file_write_size = NGX_CONF_UNSET_SIZE;

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

    size_t   size;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);

    ngx_conf_merge_value(conf->pass_unparsed_uri, prev->pass_unparsed_uri, 0);

    if (conf->pass_unparsed_uri && conf->upstream->location->len > 1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "\"proxy_pass_unparsed_uri\" can be set for "
                      "location \"/\" or given by regular expression.");
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->preserve_host, prev->preserve_host, 0);
    ngx_conf_merge_value(conf->set_x_url, prev->set_x_url, 0);
    ngx_conf_merge_value(conf->set_x_real_ip, prev->set_x_real_ip, 0);
    ngx_conf_merge_value(conf->add_x_forwarded_for,
                         prev->add_x_forwarded_for, 0);

    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 60000);

    ngx_conf_merge_size_value(conf->header_buffer_size,
                              prev->header_buffer_size, (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 8, ngx_pagesize);

    if (conf->bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }

    size = conf->header_buffer_size;
    if (size < conf->bufs.size) {
        size = conf->bufs.size;
    }


    ngx_conf_merge_size_value(conf->busy_buffers_size,
                              prev->busy_buffers_size, NGX_CONF_UNSET_SIZE);

    if (conf->busy_buffers_size == NGX_CONF_UNSET_SIZE) {
        conf->busy_buffers_size = 2 * size;

    } else if (conf->busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;

    } else if (conf->busy_buffers_size > (conf->bufs.num - 1) * conf->bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->temp_file_write_size,
                              prev->temp_file_write_size, NGX_CONF_UNSET_SIZE);

    if (conf->temp_file_write_size == NGX_CONF_UNSET_SIZE) {
        conf->temp_file_write_size = 2 * size;

    } else if (conf->temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->max_temp_file_size,
                              prev->max_temp_file_size, NGX_CONF_UNSET_SIZE);

    if (conf->max_temp_file_size == NGX_CONF_UNSET_SIZE) {

        /*
         * "proxy_max_temp_file_size" is set to 1G for reverse proxy,
         * it should be much less in the generic proxy
         */

        conf->max_temp_file_size = 1024 * 1024 * 1024;

#if 0
        conf->max_temp_file_size = 2 * size;
#endif


    } else if (conf->max_temp_file_size != 0
               && conf->max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "the temporary files usage or must be equal or bigger than "
             "maximum of the value of \"proxy_header_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->next_upstream, prev->next_upstream,
                                 (NGX_CONF_BITMASK_SET
                                  |NGX_HTTP_PROXY_FT_ERROR
                                  |NGX_HTTP_PROXY_FT_TIMEOUT));

    ngx_conf_merge_bitmask_value(conf->use_stale, prev->use_stale,
                                 NGX_CONF_BITMASK_SET);

#if 0
    ngx_conf_merge_path_value(conf->cache_path, prev->cache_path,
                              NGX_HTTP_PROXY_CACHE_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);
#endif

    ngx_conf_merge_path_value(conf->temp_path, prev->temp_path,
                              NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);

    ngx_conf_merge_value(conf->cache, prev->cache, 0);


    /* conf->cache must be merged */

    if (conf->busy_lock == NULL) {
        conf->busy_lock = prev->busy_lock;
    }

    if (conf->busy_lock && conf->cache && conf->busy_lock->md5 == NULL) {

        /* ngx_calloc_shared() */
        conf->busy_lock->md5_mask =
                     ngx_pcalloc(cf->pool, (conf->busy_lock->max_busy + 7) / 8);
        if (conf->busy_lock->md5_mask == NULL) {
            return NGX_CONF_ERROR;
        }

        /* 16 bytes are 128 bits of the md5 */

        /* ngx_alloc_shared() */
        conf->busy_lock->md5 = ngx_palloc(cf->pool,
                                          16 * conf->busy_lock->max_busy);
        if (conf->busy_lock->md5 == NULL) {
            return NGX_CONF_ERROR;
        }
    }


    ngx_conf_merge_value(conf->pass_server, prev->pass_server, 0);
    ngx_conf_merge_value(conf->pass_x_accel_expires,
                         prev->pass_x_accel_expires, 0);
    ngx_conf_merge_value(conf->ignore_expires, prev->ignore_expires, 0);
    ngx_conf_merge_value(conf->lm_factor, prev->lm_factor, 0);
    ngx_conf_merge_sec_value(conf->default_expires, prev->default_expires, 0);

    if (conf->x_vars == NULL) {
        conf->x_vars = prev->x_vars;
    }

    if (conf->peers == NULL) {
        conf->peers = prev->peers;
        conf->upstream = prev->upstream;
    }

    return NULL;
}


static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

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

    lcf->upstream = ngx_pcalloc(cf->pool,
                                sizeof(ngx_http_proxy_upstream_conf_t));
    if (lcf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    lcf->upstream->url = *url;

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

        lcf->upstream->host_header.len = sizeof("localhost") - 1;
        lcf->upstream->host_header.data = (u_char *) "localhost";
        lcf->upstream->uri = unix_upstream.uri;
        lcf->upstream->uri_separator = ":";
        lcf->upstream->default_port = 1;

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

        lcf->upstream->host_header = inet_upstream.host_header;
        lcf->upstream->port_text = inet_upstream.port_text;
        lcf->upstream->uri = inet_upstream.uri;
        lcf->upstream->uri_separator = "";
        lcf->upstream->default_port = inet_upstream.default_port;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_proxy_handler;

#if (NGX_PCRE)
    lcf->upstream->location = clcf->regex ? &ngx_http_proxy_uri : &clcf->name;
#else
    lcf->upstream->location = &clcf->name;
#endif

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}


static char *ngx_http_proxy_set_x_var(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    ngx_uint_t                  i, *index;
    ngx_str_t                  *value;
    ngx_http_variable_t        *var;
    ngx_http_core_main_conf_t  *cmcf;

    if (lcf->x_vars == NULL) {
        lcf->x_vars = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_variable_t *));
        if (lcf->x_vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    value = cf->args->elts;

    var = cmcf->variables.elts;
    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (ngx_strcasecmp(var[i].name.data, value[1].data) == 0) {

            index = ngx_array_push(lcf->x_vars);
            if (index == NULL) {
                return NGX_CONF_ERROR;
            }

            *index = var[i].index;
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown variable name \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
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
