
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_handler.h>


static ngx_int_t ngx_http_proxy_handler(ngx_http_request_t *r);

static u_char *ngx_http_proxy_log_proxy_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data);
static u_char *ngx_http_proxy_log_cache_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data);
static u_char *ngx_http_proxy_log_reason(ngx_http_request_t *r, u_char *buf,
                                         uintptr_t data);

static ngx_int_t ngx_http_proxy_pre_conf(ngx_conf_t *cf);
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

    { ngx_string("proxy_preserve_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, preserve_host),
      NULL },

    { ngx_string("proxy_set_x_real_ip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, set_x_real_ip),
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

#if (NGX_HTTP_FILE_CACHE)

    { ngx_string("proxy_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, cache_path),
      ngx_garbage_collector_http_cache_handler },

#endif

    { ngx_string("proxy_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_loc_conf_t, temp_path),
      (void *) ngx_garbage_collector_temp_handler },

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
    ngx_http_proxy_pre_conf,               /* pre conf */

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



static ngx_http_log_op_name_t ngx_http_proxy_log_fmt_ops[] = {
    { ngx_string("proxy"), /* STUB */ 100,
                           ngx_http_proxy_log_proxy_state },
    { ngx_string("proxy_cache_state"), sizeof("BYPASS") - 1,
                                       ngx_http_proxy_log_cache_state },
    { ngx_string("proxy_reason"), sizeof("BPS") - 1,
                                  ngx_http_proxy_log_reason },
    { ngx_null_string, 0, NULL }
};



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


static ngx_int_t ngx_http_proxy_handler(ngx_http_request_t *r)
{
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

#if (NGX_HTTP_FILE_CACHE)

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

    return ngx_http_proxy_get_cached_response(p);

#else

    p->state->cache_state = NGX_HTTP_PROXY_CACHE_PASS;

    return ngx_http_proxy_request_upstream(p);

#endif
}


void ngx_http_proxy_check_broken_connection(ngx_event_t *ev)
{
    int                    n;
    char                   buf[1];
    ngx_err_t              err;
    ngx_connection_t      *c;
    ngx_http_request_t    *r;
    ngx_http_proxy_ctx_t  *p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http proxy check client, write event:%d", ev->write);

#if (HAVE_KQUEUE)

    if (ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        c = ev->data;
        r = c->data;
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

    c = ev->data;
    r = c->data;
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
#if (HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT) && rev->kq_eof) {
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

    if (p->upstream && p->upstream->event_pipe) {
        r->file.fd = p->upstream->event_pipe->temp_file->file.fd;

    } else if (p->cache) {
        r->file.fd = p->cache->ctx.file.fd;
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


size_t ngx_http_proxy_log_error(void *data, char *buf, size_t len)
{
    ngx_http_proxy_log_ctx_t *ctx = data;

    ngx_http_request_t     *r;
    ngx_peer_connection_t  *peer;

    r = ctx->proxy->request;
    peer = &ctx->proxy->upstream->peer;

    return ngx_snprintf(buf, len,
                        " while %s, client: %s, URL: %s, upstream: %s%s%s%s%s",
                        ctx->proxy->action,
                        r->connection->addr_text.data,
                        r->unparsed_uri.data,
                        peer->peers->peers[peer->cur_peer].addr_port_text.data,
                        ctx->proxy->lcf->upstream->uri.data,
                        r->uri.data + ctx->proxy->lcf->upstream->location->len,
                        r->args.len ? "?" : "",
                        r->args.len ? r->args.data : (u_char *) "");
}


static u_char *ngx_http_proxy_log_proxy_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL) {
        *buf = '-';
        return buf + 1;
    }

    if (p->state->cache_state == 0) {
        *buf++ = '-';

    } else {
        buf = ngx_cpymem(buf, cache_states[p->state->cache_state - 1].data,
                         cache_states[p->state->cache_state - 1].len);
    }

    *buf++ = '/';

    if (p->state->expired == 0) {
        *buf++ = '-';

    } else {
        buf += ngx_snprintf((char *) buf, TIME_T_LEN,
                            TIME_T_FMT, p->state->expired);
    }

    *buf++ = '/';

    if (p->state->bl_time == 0) {
        *buf++ = '-';

    } else {
        buf += ngx_snprintf((char *) buf, TIME_T_LEN,
                            TIME_T_FMT, p->state->bl_time);
    }

    *buf++ = '/';

    *buf++ = '*';

    *buf++ = ' ';

    if (p->state->status == 0) {
        *buf++ = '-';

    } else {
        buf += ngx_snprintf((char *) buf, 4, "%" NGX_UINT_T_FMT,
                            p->state->status);
    }

    *buf++ = '/';

    if (p->state->reason == 0) {
        *buf++ = '-';

    } else {
        buf = ngx_cpymem(buf, cache_reasons[p->state->reason - 1].data,
                         cache_reasons[p->state->reason - 1].len);
    }

    *buf++ = '/';

    if (p->state->reason < NGX_HTTP_PROXY_CACHE_XAE) {
        *buf++ = '-';

    } else {
        buf += ngx_snprintf((char *) buf, TIME_T_LEN,
                            TIME_T_FMT, p->state->expires);
    }

    *buf++ = ' ';
    *buf++ = '*';

    return buf;
}


static u_char *ngx_http_proxy_log_cache_state(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL || p->state->cache_state == 0) {
        *buf = '-';
        return buf + 1;
    }

    return ngx_cpymem(buf, cache_states[p->state->cache_state - 1].data,
                      cache_states[p->state->cache_state - 1].len);
}


static u_char *ngx_http_proxy_log_reason(ngx_http_request_t *r, u_char *buf,
                                         uintptr_t data)
{
    ngx_http_proxy_ctx_t  *p;

    p = ngx_http_get_module_err_ctx(r, ngx_http_proxy_module);

    if (p == NULL || p->state->reason == 0) {
        *buf = '-';
        return buf + 1;
    }

    return ngx_cpymem(buf, cache_reasons[p->state->reason - 1].data,
                      cache_reasons[p->state->reason - 1].len);
}


static ngx_int_t ngx_http_proxy_pre_conf(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_proxy_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->op = NULL;

    op = ngx_http_log_fmt_ops;

    for (op = ngx_http_log_fmt_ops; op->op; op++) {
        if (op->name.len == 0) {
            op = (ngx_http_log_op_name_t *) op->op;
        }
    }

    op->op = (ngx_http_log_op_pt) ngx_http_proxy_log_fmt_ops;

    return NGX_OK;
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

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;

    conf->preserve_host = NGX_CONF_UNSET;
    conf->set_x_real_ip = NGX_CONF_UNSET;
    conf->add_x_forwarded_for = NGX_CONF_UNSET;

    conf->header_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->busy_buffers_size = NGX_CONF_UNSET_SIZE;

    /*
     * "proxy_max_temp_file_size" is hardcoded to 1G for reverse proxy,
     * it should be configurable in the generic proxy
     */
    conf->max_temp_file_size = 1024 * 1024 * 1024;

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

    ngx_conf_merge_value(conf->preserve_host, prev->preserve_host, 0);
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
        conf->max_temp_file_size = 2 * size;

    } else if (conf->max_temp_file_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal or bigger than "
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

    ngx_conf_merge_path_value(conf->cache_path, prev->cache_path,
                              "cache", 1, 2, 0, cf->pool);

    ngx_conf_merge_path_value(conf->temp_path, prev->temp_path,
                              "temp", 1, 2, 0, cf->pool);

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

    return NULL;
}



static char *ngx_http_proxy_set_pass(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_proxy_loc_conf_t *lcf = conf;

    ngx_uint_t                 i, len;
    char                      *err;
    u_char                    *host;
    in_addr_t                  addr;
    ngx_str_t                 *value;
    struct hostent            *h;
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

    /* AF_INET only */

    addr = inet_addr((char *) host);

    if (addr == INADDR_NONE) {
        h = gethostbyname((char *) host);

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
            lcf->peers->peers[i].addr = *(in_addr_t *)(h->h_addr_list[i]);
            lcf->peers->peers[i].port = lcf->upstream->port;

            len = INET_ADDRSTRLEN + lcf->upstream->port_text.len + 1;
            ngx_test_null(lcf->peers->peers[i].addr_port_text.data,
                          ngx_palloc(cf->pool, len),
                          NGX_CONF_ERROR);

            len = ngx_inet_ntop(AF_INET,
                                &lcf->peers->peers[i].addr,
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

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    lcf->upstream->location = &clcf->name;
    clcf->handler = ngx_http_proxy_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

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
                u->default_port = 1;
                u->port = htons(80);
                u->port_text.len = 2;
                u->port_text.data = (u_char *) "80";
                return NULL;
            }

            u->port_text.len = &url->data[i] - u->port_text.data;

            if (u->port_text.len > 0) {
                u->port = (in_port_t) ngx_atoi(u->port_text.data,
                                               u->port_text.len);
                if (u->port > 0) {

                    if (u->port == 80) {
                        u->default_port = 1;
                    }

                    u->port = htons(u->port);
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

    u->uri.data = (u_char *) "/";
    u->uri.len = 1;

    if (u->port_text.data == NULL) {
        u->default_port = 1;
        u->port = htons(80);
        u->port_text.len = 2;
        u->port_text.data = (u_char *) "80";
        return NULL;
    }

    u->port_text.len = &url->data[i] - u->port_text.data;

    if (u->port_text.len > 0) {
        u->port = (in_port_t) ngx_atoi(u->port_text.data, u->port_text.len);
        if (u->port > 0) {
            u->port = htons(u->port);
            return NULL;
        }
    }

    return "invalid port in upstream URL";
}
