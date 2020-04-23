
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_http_v3_handler_pt)(ngx_connection_t *c, void *data,
    u_char ch);


typedef struct {
    ngx_http_v3_handler_pt          handler;
    void                           *data;
    ngx_int_t                       index;
} ngx_http_v3_uni_stream_t;


static void ngx_http_v3_close_uni_stream(ngx_connection_t *c);
static void ngx_http_v3_read_uni_stream_type(ngx_event_t *rev);
static void ngx_http_v3_uni_read_handler(ngx_event_t *rev);
static void ngx_http_v3_dummy_write_handler(ngx_event_t *wev);
static ngx_connection_t *ngx_http_v3_get_uni_stream(ngx_connection_t *c,
    ngx_uint_t type);


void
ngx_http_v3_handle_client_uni_stream(ngx_connection_t *c)
{
    ngx_http_v3_uni_stream_t  *us;

    ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_CONTROL);
    ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_ENCODER);
    ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 new uni stream id:0x%uxL", c->qs->id);

    us = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    us->index = -1;

    c->data = us;

    c->read->handler = ngx_http_v3_read_uni_stream_type;
    c->write->handler = ngx_http_v3_dummy_write_handler;

    ngx_http_v3_read_uni_stream_type(c->read);
}


static void
ngx_http_v3_close_uni_stream(ngx_connection_t *c)
{
    ngx_pool_t                *pool;
    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_uni_stream_t  *us;

    us = c->data;
    h3c = c->qs->parent->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 close stream");

    if (us->index >= 0) {
        h3c->known_streams[us->index] = NULL;
    }

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static void
ngx_http_v3_read_uni_stream_type(ngx_event_t *rev)
{
    u_char                     ch;
    ssize_t                    n;
    ngx_int_t                  index;
    ngx_connection_t          *c;
    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_uni_stream_t  *us;

    c = rev->data;
    us = c->data;
    h3c = c->qs->parent->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read stream type");

    while (rev->ready) {

        n = c->recv(c, &ch, 1);

        if (n == NGX_ERROR) {
            goto failed;
        }

        if (n == NGX_AGAIN || n != 1) {
            break;
        }

        switch (ch) {

        case NGX_HTTP_V3_STREAM_ENCODER:

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 encoder stream");

            index = NGX_HTTP_V3_STREAM_CLIENT_ENCODER;
            us->handler = ngx_http_v3_parse_encoder;
            n = sizeof(ngx_http_v3_parse_encoder_t);

            break;

        case NGX_HTTP_V3_STREAM_DECODER:

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 decoder stream");

            index = NGX_HTTP_V3_STREAM_CLIENT_DECODER;
            us->handler = ngx_http_v3_parse_decoder;
            n = sizeof(ngx_http_v3_parse_decoder_t);

            break;

        case NGX_HTTP_V3_STREAM_CONTROL:

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 control stream");

            index = NGX_HTTP_V3_STREAM_CLIENT_CONTROL;
            us->handler = ngx_http_v3_parse_control;
            n = sizeof(ngx_http_v3_parse_control_t);

            break;

        default:

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 stream 0x%02xi", (ngx_int_t) ch);
            index = -1;
            n = 0;
        }

        if (index >= 0) {
            if (h3c->known_streams[index]) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0, "stream exists");
                goto failed;
            }

            us->index = index;
            h3c->known_streams[index] = c;
        }

        if (n) {
            us->data = ngx_pcalloc(c->pool, n);
            if (us->data == NULL) {
                goto failed;
            }
        }

        rev->handler = ngx_http_v3_uni_read_handler;
        ngx_http_v3_uni_read_handler(rev);
        return;
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_uni_read_handler(ngx_event_t *rev)
{
    u_char                     buf[128];
    ssize_t                    n;
    ngx_int_t                  rc, i;
    ngx_connection_t          *c;
    ngx_http_v3_uni_stream_t  *us;

    c = rev->data;
    us = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read handler");

    while (rev->ready) {

        n = c->recv(c, buf, sizeof(buf));

        if (n == NGX_ERROR || n == 0) {
            goto failed;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        if (us->handler == NULL) {
            continue;
        }

        for (i = 0; i < n; i++) {

            rc = us->handler(c, us->data, buf[i]);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DONE) {
                goto done;
            }

            /* rc == NGX_AGAIN */
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read done");

failed:

    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_dummy_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_v3_close_uni_stream(c);
    }
}


/* XXX async & buffered stream writes */

static ngx_connection_t *
ngx_http_v3_get_uni_stream(ngx_connection_t *c, ngx_uint_t type)
{
    u_char                     buf[NGX_HTTP_V3_VARLEN_INT_LEN];
    size_t                     n;
    ngx_int_t                  index;
    ngx_connection_t          *sc;
    ngx_http_v3_connection_t  *h3c;
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

    h3c = c->qs->parent->data;

    if (index >= 0) {
        if (h3c->known_streams[index]) {
            return h3c->known_streams[index];
        }
    }

    sc = ngx_quic_create_uni_stream(c);
    if (sc == NULL) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 create uni stream, type:%ui", type);

    us = ngx_pcalloc(sc->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        goto failed;
    }

    us->index = index;

    sc->data = us;

    sc->read->handler = ngx_http_v3_uni_read_handler;
    sc->write->handler = ngx_http_v3_dummy_write_handler;

    h3c->known_streams[index] = sc;

    n = (u_char *) ngx_http_v3_encode_varlen_int(buf, type) - buf;

    if (sc->send(sc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return sc;

failed:

    ngx_http_v3_close_uni_stream(sc);

    return NULL;
}


ngx_int_t
ngx_http_v3_client_ref_insert(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *value)
{
    u_char            *p, buf[NGX_HTTP_V3_PREFIX_INT_LEN * 2];
    size_t             n;
    ngx_connection_t  *ec;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client ref insert, %s[%ui] \"%V\"",
                   dynamic ? "dynamic" : "static", index, value);

    ec = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_ENCODER);
    if (ec == NULL) {
        return NGX_ERROR;
    }

    p = buf;

    *p = (dynamic ? 0x80 : 0xc0);
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, index, 6);

    /* XXX option for huffman? */
    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, value->len, 7);

    n = p - buf;

    if (ec->send(ec, buf, n) != (ssize_t) n) {
        goto failed;
    }

    if (ec->send(ec, value->data, value->len) != (ssize_t) value->len) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_http_v3_close_uni_stream(ec);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_client_insert(ngx_connection_t *c, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *ec;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client insert \"%V\":\"%V\"", name, value);

    ec = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_ENCODER);
    if (ec == NULL) {
        return NGX_ERROR;
    }

    /* XXX option for huffman? */
    buf[0] = 0x40;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, name->len, 5) - buf;

    if (ec->send(ec, buf, n) != (ssize_t) n) {
        goto failed;
    }

    if (ec->send(ec, name->data, name->len) != (ssize_t) name->len) {
        goto failed;
    }

    /* XXX option for huffman? */
    buf[0] = 0;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, value->len, 7) - buf;

    if (ec->send(ec, buf, n) != (ssize_t) n) {
        goto failed;
    }

    if (ec->send(ec, value->data, value->len) != (ssize_t) value->len) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_http_v3_close_uni_stream(ec);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v3_client_set_capacity(ngx_connection_t *c, ngx_uint_t capacity)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *ec;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client set capacity %ui", capacity);

    ec = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_ENCODER);
    if (ec == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0x20;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, capacity, 5) - buf;

    if (ec->send(ec, buf, n) != (ssize_t) n) {
        ngx_http_v3_close_uni_stream(ec);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_client_duplicate(ngx_connection_t *c, ngx_uint_t index)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *ec;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client duplicate %ui", index);

    ec = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_ENCODER);
    if (ec == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, index, 5) - buf;

    if (ec->send(ec, buf, n) != (ssize_t) n) {
        ngx_http_v3_close_uni_stream(ec);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_client_ack_header(ngx_connection_t *c, ngx_uint_t stream_id)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *dc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client ack header %ui", stream_id);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0x80;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, stream_id, 7) - buf;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        ngx_http_v3_close_uni_stream(dc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_client_cancel_stream(ngx_connection_t *c, ngx_uint_t stream_id)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *dc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client cancel stream %ui", stream_id);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0x40;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, stream_id, 6) - buf;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        ngx_http_v3_close_uni_stream(dc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_v3_client_inc_insert_count(ngx_connection_t *c, ngx_uint_t inc)
{
    u_char             buf[NGX_HTTP_V3_PREFIX_INT_LEN];
    size_t             n;
    ngx_connection_t  *dc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 client increment insert count %ui", inc);

    dc = ngx_http_v3_get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NGX_ERROR;
    }

    buf[0] = 0;
    n = (u_char *) ngx_http_v3_encode_prefix_int(buf, inc, 6) - buf;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        ngx_http_v3_close_uni_stream(dc);
        return NGX_ERROR;
    }

    return NGX_OK;
}
