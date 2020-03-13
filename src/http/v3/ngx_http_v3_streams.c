
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V3_CONTROL_STREAM  0x00
#define NGX_HTTP_V3_PUSH_STREAM     0x01
#define NGX_HTTP_V3_ENCODER_STREAM  0x02
#define NGX_HTTP_V3_DECODER_STREAM  0x03


typedef struct {
    uint32_t    signature; /* QSTR */
    u_char      buf[4];

    ngx_uint_t  len;
    ngx_uint_t  type;
    ngx_uint_t  state;
    ngx_uint_t  index;
    ngx_uint_t  offset;

    ngx_str_t   name;
    ngx_str_t   value;

    unsigned    client:1;
    unsigned    dynamic:1;
    unsigned    huffman:1;
} ngx_http_v3_uni_stream_t;


static void ngx_http_v3_close_uni_stream(ngx_connection_t *c);
static void ngx_http_v3_uni_stream_cleanup(void *data);
static void ngx_http_v3_read_uni_stream_type(ngx_event_t *rev);
static void ngx_http_v3_dummy_stream_handler(ngx_event_t *rev);
static void ngx_http_v3_client_encoder_handler(ngx_event_t *rev);
static void ngx_http_v3_client_decoder_handler(ngx_event_t *rev);

static ngx_connection_t *ngx_http_v3_create_uni_stream(ngx_connection_t *c,
    ngx_uint_t type);
static ngx_connection_t *ngx_http_v3_get_server_encoder(ngx_connection_t *c);
static ngx_connection_t *ngx_http_v3_get_server_decoder(ngx_connection_t *c);


void
ngx_http_v3_handle_client_uni_stream(ngx_connection_t *c)
{
    ngx_pool_cleanup_t        *cln;
    ngx_http_v3_uni_stream_t  *us;

    c->log->connection = c->number;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 new uni stream id:0x%uXL", c->qs->id);

    us = ngx_pcalloc(c->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    us->signature = NGX_HTTP_V3_STREAM;
    us->client = 1;
    us->type = (ngx_uint_t) -1;

    c->data = us;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_http_v3_close_uni_stream(c);
        return;
    }

    cln->handler = ngx_http_v3_uni_stream_cleanup;
    cln->data = c;

    c->read->handler = ngx_http_v3_read_uni_stream_type;
    c->read->handler(c->read);
}


static void
ngx_http_v3_close_uni_stream(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static void
ngx_http_v3_uni_stream_cleanup(void *data)
{
    ngx_connection_t  *c = data;

    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_uni_stream_t  *us;

    us = c->data;
    h3c = c->qs->parent->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 close stream");

    switch (us->type) {

    case NGX_HTTP_V3_ENCODER_STREAM:

        if (us->client) {
            h3c->client_encoder = NULL;
        } else {
            h3c->server_encoder = NULL;
        }

        break;

    case NGX_HTTP_V3_DECODER_STREAM:

        if (us->client) {
            h3c->client_decoder = NULL;
        } else {
            h3c->server_decoder = NULL;
        }

        break;
    }
}


static void
ngx_http_v3_read_uni_stream_type(ngx_event_t *rev)
{
    u_char                    *p;
    ssize_t                    n, len;
    ngx_connection_t          *c;
    ngx_http_v3_connection_t  *h3c;
    ngx_http_v3_uni_stream_t  *us;

    c = rev->data;
    us = c->data;
    h3c = c->qs->parent->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 read stream type");

    while (rev->ready) {

        p = &us->buf[us->len];

        if (us->len == 0) {
            len = 1;
        } else {
            len = (us->buf[0] >> 6) + 1 - us->len;
        }

        n = c->recv(c, p, len);

        if (n == NGX_ERROR) {
            goto failed;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        us->len += n;

        if (n != len) {
            break;
        }

        if ((us->buf[0] >> 6) + 1 == us->len) {
            us->type = ngx_http_v3_decode_varlen_int(us->buf);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 stream type:%ui", us->type);

            switch (us->type) {

            case NGX_HTTP_V3_ENCODER_STREAM:
                if (h3c->client_encoder) {
                    goto failed;
                }

                h3c->client_encoder = c;
                rev->handler = ngx_http_v3_client_encoder_handler;
                break;

            case NGX_HTTP_V3_DECODER_STREAM:
                if (h3c->client_decoder) {
                    goto failed;
                }

                h3c->client_decoder = c;
                rev->handler = ngx_http_v3_client_decoder_handler;
                break;

            case NGX_HTTP_V3_CONTROL_STREAM:
            case NGX_HTTP_V3_PUSH_STREAM:

                /* ignore these */

            default:
                rev->handler = ngx_http_v3_dummy_stream_handler;
            }

            rev->handler(rev);
            return;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_dummy_stream_handler(ngx_event_t *rev)
{
    u_char             buf[128];
    ngx_connection_t  *c;

    /* read out and ignore */

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy stream reader");

    while (rev->ready) {
        if (c->recv(c, buf, sizeof(buf)) == NGX_ERROR) {
            goto failed;
        }
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_client_encoder_handler(ngx_event_t *rev)
{
    u_char                     v;
    ssize_t                    n;
    ngx_str_t                  name, value;
    ngx_uint_t                 dynamic, huffman, index, offset;
    ngx_connection_t          *c, *pc;
    ngx_http_v3_uni_stream_t  *st;
    enum {
        sw_start = 0,
        sw_inr_name_index,
        sw_inr_value_length,
        sw_inr_read_value_length,
        sw_inr_value,
        sw_iwnr_name_length,
        sw_iwnr_name,
        sw_iwnr_value_length,
        sw_iwnr_read_value_length,
        sw_iwnr_value,
        sw_capacity,
        sw_duplicate
    } state;

    c = rev->data;
    st = c->data;
    pc = c->qs->parent;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 client encoder");

    state = st->state;
    dynamic = st->dynamic;
    huffman = st->huffman;
    index = st->index;
    offset = st->offset;
    name = st->name;
    value = st->value;

    while (rev->ready) {

        /* XXX limit checks */
        /* XXX buffer input */

        n = c->recv(c, &v, 1);

        if (n == NGX_ERROR || n == 0) {
            goto failed;
        }

        if (n != 1) {
            break;
        }

        /* XXX v -> ch */

        switch (state) {

        case sw_start:

            if (v & 0x80) {
                /* Insert With Name Reference */

                dynamic = (v & 0x40) ? 0 : 1;
                index = v & 0x3f;

                if (index != 0x3f) {
                    state = sw_inr_value_length;
                    break;
                }

                index = 0;
                state = sw_inr_name_index;
                break;
            }

            if (v & 0x40) {
                /*  Insert Without Name Reference */

                huffman = (v & 0x20) ? 1 : 0;
                name.len = v & 0x1f;

                if (name.len != 0x1f) {
                    offset = 0;
                    state = sw_iwnr_name;
                    break;
                }

                name.len = 0;
                state = sw_iwnr_name_length;
                break;
            }

            if (v & 0x20) {
                /*  Set Dynamic Table Capacity */

                index = v & 0x1f;

                if (index != 0x1f) {
                    if (ngx_http_v3_set_capacity(c, index) != NGX_OK) {
                        goto failed;
                    }

                    break;
                }

                index = 0;
                state = sw_capacity;
                break;
            }

            /* Duplicate */

            index = v & 0x1f;

            if (index != 0x1f) {
                if (ngx_http_v3_duplicate(c, index) != NGX_OK) {
                    goto failed;
                }

                break;
            }

            index = 0;
            state = sw_duplicate;
            break;

        case sw_inr_name_index:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x3f;
            state = sw_inr_value_length;
            break;

        case sw_inr_value_length:

            huffman = (v & 0x80) ? 1 : 0;
            value.len = v & 0x7f;

            if (value.len == 0) {
                value.data = NULL;

                if (ngx_http_v3_ref_insert(c, dynamic, index, &value) != NGX_OK)
                {
                    goto failed;
                }

                state = sw_start;
                break;
            }

            if (value.len != 0x7f) {
                value.data = ngx_pnalloc(pc->pool, value.len);
                if (value.data == NULL) {
                    goto failed;
                }

                state = sw_inr_value;
                offset = 0;
                break;
            }

            value.len = 0;
            state = sw_inr_read_value_length;
            break;

        case sw_inr_read_value_length:

            value.len = (value.len << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            value.len += 0x7f;

            value.data = ngx_pnalloc(pc->pool, value.len);
            if (value.data == NULL) {
                goto failed;
            }

            state = sw_inr_value;
            offset = 0;
            break;

        case sw_inr_value:

            value.data[offset++] = v;
            if (offset != value.len) {
                break;
            }

            if (huffman) {
                if (ngx_http_v3_decode_huffman(pc, &value) != NGX_OK) {
                    goto failed;
                }
            }

            if (ngx_http_v3_ref_insert(c, dynamic, index, &value) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;

        case sw_iwnr_name_length:

            name.len = (name.len << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            name.len += 0x1f;

            name.data = ngx_pnalloc(pc->pool, name.len);
            if (name.data == NULL) {
                goto failed;
            }

            offset = 0;
            state = sw_iwnr_name;
            break;

        case sw_iwnr_name:

            name.data[offset++] = v;
            if (offset != name.len) {
                break;
            }

            if (huffman) {
                if (ngx_http_v3_decode_huffman(pc, &name) != NGX_OK) {
                    goto failed;
                }
            }

            state = sw_iwnr_value_length;
            break;

        case sw_iwnr_value_length:

            huffman = (v & 0x80) ? 1 : 0;
            value.len = v & 0x7f;

            if (value.len == 0) {
                value.data = NULL;

                if (ngx_http_v3_insert(c, &name, &value) != NGX_OK) {
                    goto failed;
                }

                state = sw_start;
                break;
            }

            if (value.len != 0x7f) {
                value.data = ngx_pnalloc(pc->pool, value.len);
                if (value.data == NULL) {
                    goto failed;
                }

                offset = 0;
                state = sw_iwnr_value;
                break;
            }

            state = sw_iwnr_read_value_length;
            break;

        case sw_iwnr_read_value_length:

            value.len = (value.len << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            value.data = ngx_pnalloc(pc->pool, value.len);
            if (value.data == NULL) {
                goto failed;
            }

            offset = 0;
            state = sw_iwnr_value;
            break;

        case sw_iwnr_value:

            value.data[offset++] = v;
            if (offset != value.len) {
                break;
            }

            if (huffman) {
                if (ngx_http_v3_decode_huffman(pc, &value) != NGX_OK) {
                    goto failed;
                }
            }

            if (ngx_http_v3_insert(c, &name, &value) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;


        case sw_capacity:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x1f;

            if (ngx_http_v3_set_capacity(c, index) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;

        case sw_duplicate:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x1f;

            if (ngx_http_v3_duplicate(c, index) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;
        }
    }

    st->state = state;
    st->dynamic = dynamic;
    st->huffman = huffman;
    st->index = index;
    st->offset = offset;
    st->name = name;
    st->value = value;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_http_v3_close_uni_stream(c);
}


static void
ngx_http_v3_client_decoder_handler(ngx_event_t *rev)
{
    u_char                     v;
    ssize_t                    n;
    ngx_uint_t                 index;
    ngx_connection_t          *c;
    ngx_http_v3_uni_stream_t  *st;
    enum {
        sw_start = 0,
        sw_ack_header,
        sw_cancel_stream,
        sw_inc_insert_count
    } state;

    c = rev->data;
    st = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 client decoder");

    state = st->state;
    index = st->index;

    while (rev->ready) {

        /* XXX limit checks */
        /* XXX buffer input */

        n = c->recv(c, &v, 1);

        if (n == NGX_ERROR || n == 0) {
            goto failed;
        }

        if (n != 1) {
            break;
        }

        switch (state) {

        case sw_start:

            if (v & 0x80) {
                /* Header Acknowledgement */

                index = v & 0x7f;

                if (index != 0x7f) {
                    if (ngx_http_v3_ack_header(c, index) != NGX_OK) {
                        goto failed;
                    }

                    break;
                }

                index = 0;
                state = sw_ack_header;
                break;
            }

            if (v & 0x40) {
                /*  Stream Cancellation */

                index = v & 0x3f;

                if (index != 0x3f) {
                    if (ngx_http_v3_cancel_stream(c, index) != NGX_OK) {
                        goto failed;
                    }

                    break;
                }

                index = 0;
                state = sw_cancel_stream;
                break;
            }

            /*  Insert Count Increment */

            index = v & 0x3f;

            if (index != 0x3f) {
                if (ngx_http_v3_inc_insert_count(c, index) != NGX_OK) {
                    goto failed;
                }

                break;
            }

            index = 0;
            state = sw_inc_insert_count;
            break;

        case sw_ack_header:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x7f;

            if (ngx_http_v3_ack_header(c, index) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;

        case sw_cancel_stream:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x3f;

            if (ngx_http_v3_cancel_stream(c, index) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;

        case sw_inc_insert_count:

            index = (index << 7) + (v & 0x7f);
            if (v & 0x80) {
                break;
            }

            index += 0x3f;

            if (ngx_http_v3_inc_insert_count(c, index) != NGX_OK) {
                goto failed;
            }

            state = sw_start;
            break;
        }
    }

    st->state = state;
    st->index = index;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto failed;
    }

    return;

failed:

    ngx_http_v3_close_uni_stream(c);
}


/* XXX async & buffered stream writes */

static ngx_connection_t *
ngx_http_v3_create_uni_stream(ngx_connection_t *c, ngx_uint_t type)
{
    u_char                     buf[NGX_HTTP_V3_VARLEN_INT_LEN];
    size_t                     n;
    ngx_connection_t          *sc;
    ngx_pool_cleanup_t        *cln;
    ngx_http_v3_uni_stream_t  *us;

    sc = ngx_quic_create_uni_stream(c->qs->parent);
    if (sc == NULL) {
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 create uni stream, type:%ui", type);

    us = ngx_pcalloc(sc->pool, sizeof(ngx_http_v3_uni_stream_t));
    if (us == NULL) {
        goto failed;
    }

    us->signature = NGX_HTTP_V3_STREAM;
    us->type = type;
    sc->data = us;

    cln = ngx_pool_cleanup_add(sc->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_http_v3_uni_stream_cleanup;
    cln->data = sc;

    n = (u_char *) ngx_http_v3_encode_varlen_int(buf, type) - buf;

    if (sc->send(sc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return sc;

failed:

    ngx_http_v3_close_uni_stream(sc);

    return NULL;
}


static ngx_connection_t *
ngx_http_v3_get_server_encoder(ngx_connection_t *c)
{
    ngx_http_v3_connection_t  *h3c;

    h3c = c->qs->parent->data;

    if (h3c->server_encoder == NULL) {
        h3c->server_encoder = ngx_http_v3_create_uni_stream(c,
                                                   NGX_HTTP_V3_ENCODER_STREAM);
    }

    return h3c->server_encoder;
}


static ngx_connection_t *
ngx_http_v3_get_server_decoder(ngx_connection_t *c)
{
    ngx_http_v3_connection_t  *h3c;

    h3c = c->qs->parent->data;

    if (h3c->server_decoder == NULL) {
        h3c->server_decoder = ngx_http_v3_create_uni_stream(c,
                                                   NGX_HTTP_V3_DECODER_STREAM);
    }

    return h3c->server_decoder;
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

    ec = ngx_http_v3_get_server_encoder(c);
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

    ec = ngx_http_v3_get_server_encoder(c);
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

    ec = ngx_http_v3_get_server_encoder(c);
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

    ec = ngx_http_v3_get_server_encoder(c);
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

    dc = ngx_http_v3_get_server_decoder(c);
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

    dc = ngx_http_v3_get_server_decoder(c);
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

    dc = ngx_http_v3_get_server_decoder(c);
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
