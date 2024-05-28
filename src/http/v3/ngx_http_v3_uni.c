
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_v3_parse_uni_t         parse;
    ngx_int_t                       index;
} ngx_http_v3_uni_stream_t;


static void ngx_http_v3_close_uni_stream(ngx_connection_t *c);
static void ngx_http_v3_uni_read_handler(ngx_event_t *rev);
static void ngx_http_v3_uni_dummy_read_handler(ngx_event_t *wev);
static void ngx_http_v3_uni_dummy_write_handler(ngx_event_t *wev);


void
ngx_http_v3_init_uni_stream(ngx_connection_t *c)
{
    uint64_t                   n;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_uni_stream_t  *us;

    h3c = ngx_http_v3_get_session(c);
    if (h3c->hq) {
        ngx_http_v3_finalize_connection(c,
                                        NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                        "uni stream in hq mode");
        c->data = NULL;
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 init uni stream");

    n = c->quic->id >> 2;

    if (n >= NGX_HTTP_V3_MAX_UNI_STREAMS) {
        ngx_http_v3_finalize_connection(c,
                                      NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                      "reached maximum number of uni streams");
        c->data = NULL;
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    ngx_quic_cancelable_stream(c);

    us = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        ngx_http_v3_finalize_connection(c,
                                        NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                        "memory allocation error");
        c->data = NULL;
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    us->index = -1;

    c->data = us;

    c->read->handler = ngx_http_v3_uni_read_handler;
    c->write->handler = ngx_http_v3_uni_dummy_write_handler;

    ngx_http_v3_uni_read_handler(c->read);
}


static void
ngx_http_v3_close_uni_stream(ngx_connection_t *c)
{
    ngx_pool_t                *pool;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_uni_stream_t  *us;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 close stream");

    us = c->data;

    if (us && us->index >= 0) {
        h3c = ngx_http_v3_get_session(c);
        h3c->known_streams[us->index] = NULL;
    }

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


ngx_int_t
ngx_http_v3_register_uni_stream(ngx_connection_t *c, uint64_t type)
{
    ngx_int_t                  index;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_uni_stream_t  *us;

    h3c = ngx_http_v3_get_session(c);

    switch (type) {

    case NGX_HTTP_V3_STREAM_ENCODER:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 encoder stream");
        index = NGX_HTTP_V3_STREAM_CLIENT_ENCODER;
        break;

    case NGX_HTTP_V3_STREAM_DECODER:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 decoder stream");
        index = NGX_HTTP_V3_STREAM_CLIENT_DECODER;
        break;

    case NGX_HTTP_V3_STREAM_CONTROL:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 control stream");
        index = NGX_HTTP_V3_STREAM_CLIENT_CONTROL;

        break;

    default:

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 stream 0x%02xL", type);

        if (h3c->known_streams[NGX_HTTP_V3_STREAM_CLIENT_ENCODER] == NULL
            || h3c->known_streams[NGX_HTTP_V3_STREAM_CLIENT_DECODER] == NULL
            || h3c->known_streams[NGX_HTTP_V3_STREAM_CLIENT_CONTROL] == NULL)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "missing mandatory stream");
            return NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR;
        }

        index = -1;
    }

    if (index >= 0) {
        if (h3c->known_streams[index]) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "stream exists");
            return NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR;
        }

        h3c->known_streams[index] = c;

        us = c->data;
        us->index = index;
    }

    return NGX_OK;
}


static void
ngx_http_v3_uni_read_handler(ngx_event_t *rev)
{
    u_char                     buf[128];
    ssize_t                    n;
    ngx_buf_t                  b;
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_uni_stream_t  *us;

    c = rev->data;
    us = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read handler");

    if (c->close) {
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    ngx_memzero(&b, sizeof(ngx_buf_t));

    while (rev->ready) {

        n = c->recv(c, buf, sizeof(buf));

        if (n == NGX_ERROR) {
            rc = NGX_HTTP_V3_ERR_INTERNAL_ERROR;
            goto failed;
        }

        if (n == 0) {
            if (us->index >= 0) {
                rc = NGX_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM;
                goto failed;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read eof");
            ngx_http_v3_close_uni_stream(c);
            return;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        b.pos = buf;
        b.last = buf + n;

        h3c = ngx_http_v3_get_session(c);
        h3c->total_bytes += n;

        if (ngx_http_v3_check_flood(c) != NGX_OK) {
            ngx_http_v3_close_uni_stream(c);
            return;
        }

        rc = ngx_http_v3_parse_uni(c, &us->parse, &b);

        if (rc == NGX_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 read done");
            ngx_http_v3_close_uni_stream(c);
            return;
        }

        if (rc > 0) {
            goto failed;
        }

        if (rc != NGX_AGAIN) {
            rc = NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR;
            goto failed;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        rc = NGX_HTTP_V3_ERR_INTERNAL_ERROR;
        goto failed;
    }

    return;

failed:

    ngx_http_v3_finalize_connection(c, rc, "stream error");
    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_uni_dummy_read_handler(ngx_event_t *rev)
{
    u_char             ch;
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy read handler");

    if (c->close) {
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    if (rev->ready) {
        if (c->recv(c, &ch, 1) != 0) {
            ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, NULL);
            ngx_http_v3_close_uni_stream(c);
            return;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                        NULL);
        ngx_http_v3_close_uni_stream(c);
    }
}


static void
ngx_http_v3_uni_dummy_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR,
                                        NULL);
        ngx_http_v3_close_uni_stream(c);
    }
}


ngx_connection_t *
ngx_http_v3_get_uni_stream(ngx_connection_t *c, ngx_uint_t type)
{
    u_char                     buf[NGX_HTTP_V3_VARLEN_INT_LEN];
    size_t                     n;
    ngx_int_t                  index;
    ngx_connection_t          *sc;
    ngx_http_v3_session_t     *h3c;
    ngx_http_v3_uni_stream_t  *us;

    switch (type) {
    case NGX_HTTP_V3_STREAM_ENCODER:
        index = NGX_HTTP_V3_STREAM_SERVER_ENCODER;
        break;
    case NGX_HTTP_V3_STREAM_DECODER:
        index = NGX_HTTP_V3_STREAM_SERVER_DECODER;
        break;
    case NGX_HTTP_V3_STREAM_CONTROL:
        index = NGX_HTTP_V3_STREAM_SERVER_CONTROL;
        break;
    default:
        index = -1;
    }

    h3c = ngx_http_v3_get_session(c);

    if (index >= 0) {
        if (h3c->known_streams[index]) {
            return h3c->known_streams[index];
        }
    }

    sc = ngx_quic_open_stream(c, 0);
    if (sc == NULL) {
        goto failed;
    }

    ngx_quic_cancelable_stream(sc);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 create uni stream, type:%ui", type);

    us = ngx_pcalloc(sc->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        goto failed;
    }

    us->index = index;

    sc->data = us;

    sc->read->handler = ngx_http_v3_uni_dummy_read_handler;
    sc->write->handler = ngx_http_v3_uni_dummy_write_handler;

    if (index >= 0) {
        h3c->known_streams[index] = sc;
    }

    n = (u_char *) ngx_http_v3_encode_varlen_int(buf, type) - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (sc->send(sc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    ngx_post_event(sc->read, &ngx_posted_events);

    return sc;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to create server stream");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                    "failed to create server stream");
    if (sc) {
        ngx_http_v3_close_uni_stream(sc);
    }

    return NULL;
}


ngx_int_t
ngx_http_v3_send_settings(ngx_connection_t *c)
{
    u_char                  *p, buf[NGX_HTTP_V3_VARLEN_INT_LEN * 6];
    size_t                   n;
    ngx_connection_t        *cc;
    ngx_http_v3_session_t   *h3c;
    ngx_http_v3_srv_conf_t  *h3scf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 send settings");

    cc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_CONTROL);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    h3scf = ngx_http_v3_get_module_srv_conf(c, ngx_http_v3_module);

    n = ngx_http_v3_encode_varlen_int(NULL,
                                      NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    n += ngx_http_v3_encode_varlen_int(NULL, h3scf->max_table_capacity);
    n += ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_PARAM_BLOCKED_STREAMS);
    n += ngx_http_v3_encode_varlen_int(NULL, h3scf->max_blocked_streams);

    p = (u_char *) ngx_http_v3_encode_varlen_int(buf,
                                                 NGX_HTTP_V3_FRAME_SETTINGS);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p, n);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p,
                                         NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p, h3scf->max_table_capacity);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p,
                                            NGX_HTTP_V3_PARAM_BLOCKED_STREAMS);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p, h3scf->max_blocked_streams);
    n = p - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (cc->send(cc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to send settings");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send settings");
    ngx_http_v3_close_uni_stream(cc);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_send_goaway(ngx_connection_t *c, uint64_t id)
{
    u_char                 *p, buf[NGX_HTTP_V3_VARLEN_INT_LEN * 3];
    size_t                  n;
    ngx_connection_t       *cc;
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 send goaway %uL", id);

    cc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_CONTROL);
    if (cc == NULL) {
        return NGX_ERROR;
    }

    n = ngx_http_v3_encode_varlen_int(NULL, id);
    p = (u_char *) ngx_http_v3_encode_varlen_int(buf, NGX_HTTP_V3_FRAME_GOAWAY);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p, n);
    p = (u_char *) ngx_http_v3_encode_varlen_int(p, id);
    n = p - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (cc->send(cc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to send goaway");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send goaway");
    ngx_http_v3_close_uni_stream(cc);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_send_ack_section(ngx_connection_t *c, ngx_uint_t stream_id)
{
    u_char                  buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    ngx_connection_t       *dc;
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send section acknowledgement %ui", stream_id);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0x80;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, stream_id, 7) - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "failed to send section acknowledgement");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send section acknowledgement");
    ngx_http_v3_close_uni_stream(dc);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_send_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id)
{
    u_char                  buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    ngx_connection_t       *dc;
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send stream cancellation %ui", stream_id);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0x40;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, stream_id, 6) - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to send stream cancellation");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send stream cancellation");
    ngx_http_v3_close_uni_stream(dc);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_send_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc)
{
    u_char                  buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    ngx_connection_t       *dc;
    ngx_http_v3_session_t  *h3c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send insert count increment %ui", inc);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, inc, 6) - buf;

    h3c = ngx_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "failed to send insert count increment");

    ngx_http_v3_finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send insert count increment");
    ngx_http_v3_close_uni_stream(dc);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 cancel stream %ui", stream_id);

    /* we do not use dynamic tables */

    return NGX_OK;
}
