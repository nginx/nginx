
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/* 12.4.  Frames and Frame Types */
#define NGX_QUIC_FT_PADDING                0x00
#define NGX_QUIC_FT_PING                   0x01
#define NGX_QUIC_FT_ACK                    0x02
#define NGX_QUIC_FT_ACK_ECN                0x03
#define NGX_QUIC_FT_RESET_STREAM           0x04
#define NGX_QUIC_FT_STOP_SENDING           0x05
#define NGX_QUIC_FT_CRYPTO                 0x06
#define NGX_QUIC_FT_NEW_TOKEN              0x07
#define NGX_QUIC_FT_STREAM0                0x08
#define NGX_QUIC_FT_STREAM1                0x09
#define NGX_QUIC_FT_STREAM2                0x0A
#define NGX_QUIC_FT_STREAM3                0x0B
#define NGX_QUIC_FT_STREAM4                0x0C
#define NGX_QUIC_FT_STREAM5                0x0D
#define NGX_QUIC_FT_STREAM6                0x0E
#define NGX_QUIC_FT_STREAM7                0x0F
#define NGX_QUIC_FT_MAX_DATA               0x10
#define NGX_QUIC_FT_MAX_STREAM_DATA        0x11
#define NGX_QUIC_FT_MAX_STREAMS            0x12
#define NGX_QUIC_FT_MAX_STREAMS2           0x13 // XXX
#define NGX_QUIC_FT_DATA_BLOCKED           0x14
#define NGX_QUIC_FT_STREAM_DATA_BLOCKED    0x15
#define NGX_QUIC_FT_STREAMS_BLOCKED        0x16
#define NGX_QUIC_FT_STREAMS_BLOCKED2       0x17 // XXX
#define NGX_QUIC_FT_NEW_CONNECTION_ID      0x18
#define NGX_QUIC_FT_RETIRE_CONNECTION_ID   0x19
#define NGX_QUIC_FT_PATH_CHALLENGE         0x1a
#define NGX_QUIC_FT_PATH_RESPONSE          0x1b
#define NGX_QUIC_FT_CONNECTION_CLOSE       0x1c
#define NGX_QUIC_FT_CONNECTION_CLOSE2      0x1d // XXX
#define NGX_QUIC_FT_HANDSHAKE_DONE         0x1e

#define ngx_quic_stream_bit_off(val)  (((val) & 0x04) ? 1 : 0)
#define ngx_quic_stream_bit_len(val)  (((val) & 0x02) ? 1 : 0)
#define ngx_quic_stream_bit_fin(val)  (((val) & 0x01) ? 1 : 0)


#define NGX_QUIC_ERR_NO_ERROR                   0x0
#define NGX_QUIC_ERR_INTERNAL_ERROR             0x1
#define NGX_QUIC_ERR_SERVER_BUSY                0x2
#define NGX_QUIC_ERR_FLOW_CONTROL_ERROR         0x3
#define NGX_QUIC_ERR_STREAM_LIMIT_ERROR         0x4
#define NGX_QUIC_ERR_STREAM_STATE_ERROR         0x5
#define NGX_QUIC_ERR_FINAL_SIZE_ERROR           0x6
#define NGX_QUIC_ERR_FRAME_ENCODING_ERROR       0x7
#define NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR  0x8
#define NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR  0x9
#define NGX_QUIC_ERR_PROTOCOL_VIOLATION         0xA
#define NGX_QUIC_ERR_INVALID_TOKEN              0xB
/* 0xC is not defined */
#define NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED     0xD
#define NGX_QUIC_ERR_CRYPTO_ERROR               0x10

#define NGX_QUIC_ERR_LAST  NGX_QUIC_ERR_CRYPTO_ERROR

/* literal errors indexed by corresponding value */
static char *ngx_quic_errors[] = {
    "NO_ERROR",
    "INTERNAL_ERROR",
    "SERVER_BUSY",
    "FLOW_CONTROL_ERROR",
    "STREAM_LIMIT_ERROR",
    "STREAM_STATE_ERROR",
    "FINAL_SIZE_ERROR",
    "FRAME_ENCODING_ERROR",
    "TRANSPORT_PARAMETER_ERROR",
    "CONNECTION_ID_LIMIT_ERROR",
    "PROTOCOL_VIOLATION",
    "INVALID_TOKEN",
    "",
    "CRYPTO_BUFFER_EXCEEDED",
    "CRYPTO_ERROR",
};


/* TODO: real states, these are stubs */
typedef enum  {
    NGX_QUIC_ST_INITIAL,
    NGX_QUIC_ST_HANDSHAKE,
    NGX_QUIC_ST_APP_DATA
} ngx_quic_state_t;


typedef struct ngx_quic_frame_s  ngx_quic_frame_t;

typedef struct {
    ngx_uint_t                  pn;

    // input
    uint64_t                    largest;
    uint64_t                    delay;
    uint64_t                    range_count;
    uint64_t                    first_range;
    uint64_t                    ranges[20];
    /* ecn counts */
} ngx_quic_ack_frame_t;

typedef struct {
    size_t                      offset;
    size_t                      len;
    u_char                     *data;
} ngx_quic_crypto_frame_t;


typedef struct {
    uint64_t                     seqnum;
    uint64_t                     retire;
    uint64_t                     len;
    u_char                       cid[20];
    u_char                       srt[16];
} ngx_quic_ncid_t;


typedef struct {
    uint8_t                      type;
    uint64_t                     stream_id;
    uint64_t                     offset;
    uint64_t                     length;
    u_char                      *data;
} ngx_quic_stream_frame_t;


typedef struct {
    uint64_t                     error_code;
    uint64_t                     frame_type;
    ngx_str_t                    reason;
} ngx_quic_close_frame_t;


struct ngx_quic_frame_s {
    ngx_uint_t                  type;
    ngx_quic_level_t            level;
    ngx_quic_frame_t           *next;
    union {
        ngx_quic_crypto_frame_t crypto;
        ngx_quic_ack_frame_t    ack;
        ngx_quic_ncid_t         ncid;
        ngx_quic_stream_frame_t stream;
        ngx_quic_close_frame_t  close;
        // more frames
    } u;

    u_char                      info[128]; // for debug purposes
};


struct ngx_quic_connection_s {

    ngx_quic_state_t   state;
    ngx_ssl_t         *ssl;

    ngx_quic_frame_t  *frames;

    ngx_str_t          scid;
    ngx_str_t          dcid;
    ngx_str_t          token;

    /* current packet numbers for each namespace */
    ngx_uint_t         initial_pn;
    ngx_uint_t         handshake_pn;
    ngx_uint_t         appdata_pn;

    ngx_quic_secrets_t secrets;

    /* streams */
    ngx_rbtree_t               stree;
    ngx_rbtree_node_t          stree_sentinel;
    ngx_msec_t                 stream_timeout;
    ngx_connection_handler_pt  stream_handler;
};


typedef struct {
    ngx_rbtree_node_t      node;
    ngx_buf_t             *b;
    ngx_connection_t      *c;
    ngx_quic_stream_t      s;
} ngx_quic_stream_node_t;


static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b);
static ngx_int_t ngx_quic_output(ngx_connection_t *c);

static ngx_int_t ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_quic_header_t *pkt);
static void ngx_quic_close_connection(ngx_connection_t *c);

static ngx_quic_stream_node_t *ngx_quic_stream_lookup(ngx_rbtree_t *rbtree,
    ngx_uint_t key);
static void ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static void ngx_quic_handshake_handler(ngx_event_t *rev);
static ngx_int_t ngx_quic_handshake_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_initial_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_app_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);


#if BORINGSSL_API_VERSION >= 10
static int ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
static int ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
#else
static int ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
#endif
static int ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len);
static int ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn);
static int ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, uint8_t alert);

static ngx_int_t ngx_quic_process_long_header(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_short_header(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_initial_header(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_handshake_header(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

static uint64_t ngx_quic_parse_int(u_char **pos);

static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);

static SSL_QUIC_METHOD quic_method = {
#if BORINGSSL_API_VERSION >= 10
    ngx_quic_set_read_secret,
    ngx_quic_set_write_secret,
#else
    ngx_quic_set_encryption_secrets,
#endif
    ngx_quic_add_handshake_data,
    ngx_quic_flush_flight,
    ngx_quic_send_alert,
};


void
ngx_quic_init_ssl_methods(SSL_CTX* ctx)
{
    SSL_CTX_set_quic_method(ctx, &quic_method);
}


void
ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_msec_t timeout,
    ngx_connection_handler_pt handler)
{
    ngx_buf_t          *b;
    ngx_quic_header_t   pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic handshake");

    c->log->action = "QUIC handshaking";

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    b = c->buffer;

    pkt.raw = b;
    pkt.data = b->start;
    pkt.len = b->last - b->start;

    if (ngx_quic_new_connection(c, ssl, &pkt) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }

    // we don't need stream handler for initial packet processing
    c->quic->stream_handler = handler;
    c->quic->stream_timeout = timeout;

    ngx_add_timer(c->read, timeout);

    c->read->handler = ngx_quic_handshake_handler;

    return;
}


static void
ngx_quic_handshake_handler(ngx_event_t *rev)
{
    ssize_t                 n;
    ngx_connection_t       *c;
    u_char                  buf[512];
    ngx_buf_t               b;

    b.start = buf;
    b.end = buf + 512;
    b.pos = b.last = b.start;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic handshake handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_quic_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_quic_close_connection(c);
        return;
    }

    n = c->recv(c, b.start, b.end - b.start);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        c->read->eof = 1;
        ngx_quic_close_connection(c);
        return;
    }

    b.last += n;

    if (ngx_quic_input(c, &b) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }
}


static void
ngx_quic_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    /* XXX wait for all streams to close */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "close quic connection: %d", c->fd);

    if (c->ssl) {
        (void) ngx_ssl_shutdown(c);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


ngx_connection_t *
ngx_quic_create_uni_stream(ngx_connection_t *c)
{
    /* XXX */
    return NULL;
}


static ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_quic_header_t   pkt;

    if (c->quic == NULL) {
        // XXX: possible?
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "BUG: no QUIC in connection");
        return NGX_ERROR;
    }

    p = b->start;

    do {
        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;

        if (p[0] == 0) {
            /* XXX: no idea WTF is this, just ignore */
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "FIREFOX: ZEROES");
            break;
        }

        // TODO: check current state
        if (p[0] & NGX_QUIC_PKT_LONG) {

            if ((p[0] & 0xf0) == NGX_QUIC_PKT_INITIAL) {
                rc = ngx_quic_initial_input(c, &pkt);

            } else if ((p[0] & 0xf0) == NGX_QUIC_PKT_HANDSHAKE) {
                rc = ngx_quic_handshake_input(c, &pkt);

            } else {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "BUG: unknown quic state");
                return NGX_ERROR;
            }

        } else {
            rc = ngx_quic_app_input(c, &pkt);
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        /* b->pos is at header end, adjust by actual packet length */
        p = b->pos + pkt.len;
        b->pos = p;       /* reset b->pos to the next packet start */

    } while (p < b->last);

    return NGX_OK;
}

static ngx_int_t
ngx_quic_send_packet(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_level_t level, ngx_str_t *payload)
{
    ngx_str_t          res;
    ngx_quic_header_t  pkt;

    static ngx_str_t  initial_token = ngx_null_string;

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    ngx_quic_hexdump0(c->log, "payload", payload->data, payload->len);

    pkt.level = level;
    pkt.dcid = qc->dcid;
    pkt.scid = qc->scid;

    if (level == ssl_encryption_initial) {
        pkt.number = &qc->initial_pn;
        pkt.flags = NGX_QUIC_PKT_INITIAL;
        pkt.secret = &qc->secrets.server.in;
        pkt.token = initial_token;

    } else if (level == ssl_encryption_handshake) {
        pkt.number = &qc->handshake_pn;
        pkt.flags = NGX_QUIC_PKT_HANDSHAKE;
        pkt.secret = &qc->secrets.server.hs;

    } else {
        pkt.number = &qc->appdata_pn;
        pkt.secret = &qc->secrets.server.ad;
    }

    if (ngx_quic_encrypt(c->pool, c->ssl->connection, &pkt, payload, &res)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "packet to send", res.data, res.len);

    c->send(c, res.data, res.len); // TODO: err handling

    (*pkt.number)++;

    return NGX_OK;
}


static size_t
ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack)
{
    size_t  len;

    /* minimal ACK packet */

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
        len += ngx_quic_varint_len(ack->pn);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(ack->pn);

        return len;
    }

    ngx_quic_build_int(&p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(&p, ack->pn);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, ack->pn);

    return 5;
}


static size_t
ngx_quic_create_crypto(u_char *p, ngx_quic_crypto_frame_t *crypto)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_CRYPTO);
        len += ngx_quic_varint_len(crypto->offset);
        len += ngx_quic_varint_len(crypto->len);
        len += crypto->len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(&p, crypto->offset);
    ngx_quic_build_int(&p, crypto->len);
    p = ngx_cpymem(p, crypto->data, crypto->len);

    return p - start;
}


static size_t
ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf)
{
    size_t   len;
    u_char  *start;

    if (!ngx_quic_stream_bit_len(sf->type)) {
#if 0
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "attempt to generate a stream frame without length");
#endif
        // XXX: handle error in caller
        return NGX_ERROR;
    }

    if (p == NULL) {
        len = ngx_quic_varint_len(sf->type);

        if (ngx_quic_stream_bit_off(sf->type)) {
            len += ngx_quic_varint_len(sf->offset);
        }

        len += ngx_quic_varint_len(sf->stream_id);

        /* length is always present in generated frames */
        len += ngx_quic_varint_len(sf->length);

        len += sf->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, sf->type);
    ngx_quic_build_int(&p, sf->stream_id);

    if (ngx_quic_stream_bit_off(sf->type)) {
        ngx_quic_build_int(&p, sf->offset);
    }

    /* length is always present in generated frames */
    ngx_quic_build_int(&p, sf->length);

    p = ngx_cpymem(p, sf->data, sf->length);

    return p - start;
}


size_t
ngx_quic_frame_len(ngx_quic_frame_t *frame)
{
     switch (frame->type) {
        case NGX_QUIC_FT_ACK:
            return ngx_quic_create_ack(NULL, &frame->u.ack);
        case NGX_QUIC_FT_CRYPTO:
            return ngx_quic_create_crypto(NULL, &frame->u.crypto);

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:
            return ngx_quic_create_stream(NULL, &frame->u.stream);
        default:
            /* BUG: unsupported frame type generated */
            return 0;
     }
}


/* pack a group of frames [start; end) into memory p and send as single packet */
ngx_int_t
ngx_quic_frames_send(ngx_connection_t *c, ngx_quic_frame_t *start,
    ngx_quic_frame_t *end, size_t total)
{
    u_char            *p;
    ngx_str_t          out;
    ngx_quic_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sending frames %p...%p", start, end);

    p = ngx_pnalloc(c->pool, total);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out.data = p;

    for (f = start; f != end; f = f->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "frame: %s", f->info);

        switch (f->type) {
        case NGX_QUIC_FT_ACK:
            p += ngx_quic_create_ack(p, &f->u.ack);
            break;

        case NGX_QUIC_FT_CRYPTO:
            p += ngx_quic_create_crypto(p, &f->u.crypto);
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:
            p += ngx_quic_create_stream(p, &f->u.stream);
            break;

        default:
            /* BUG: unsupported frame type generated */
            return NGX_ERROR;
        }
    }

    out.len = p - out.data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "packet ready: %ui bytes at level %d",
                   out.len, start->level);

    // IOVEC/sendmsg_chain ?
    if (ngx_quic_send_packet(c, c->quic, start->level, &out) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    size_t                  len;
    ngx_uint_t              lvl;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (qc->frames == NULL) {
        return NGX_OK;
    }

    lvl = qc->frames->level;
    start = qc->frames;
    f = start;

    do {
        len = 0;

        do {
            /* process same-level group of frames */

            len += ngx_quic_frame_len(f);// TODO: handle overflow, max size

            f = f->next;
        } while (f && f->level == lvl);


        if (ngx_quic_frames_send(c, start, f, len) != NGX_OK) {
            return NGX_ERROR;
        }

        if (f == NULL) {
            break;
        }

        lvl = f->level; // TODO: must not decrease (ever, also between calls)
        start = f;

    } while (1);

    qc->frames = NULL;

    return NGX_OK;
}


#if BORINGSSL_API_VERSION >= 10

static int
ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read secret",
                     rsecret, secret_len, level);

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          rsecret, secret_len,
                                          &c->quic->secrets.client);
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d write secret",
                     wsecret, secret_len, level);

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &c->quic->secrets.server);
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read", rsecret, secret_len, level);
    ngx_quic_hexdump(c->log, "level:%d write", wsecret, secret_len, level);

    rc = ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                        rsecret, secret_len,
                                        &c->quic->secrets.client);
    if (rc != 1) {
        return rc;
    }

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &c->quic->secrets.server);
}

#endif


static void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_frame_t *f;

    if (qc->frames == NULL) {
        qc->frames = frame;
        return;
    }

    for (f = qc->frames; f->next; f = f->next) {
        if (f->next->level > frame->level) {
            break;
        }
    }

    frame->next = f->next;
    f->next = frame;
}


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                   *p;
    ngx_quic_frame_t         *frame;
    ngx_connection_t         *c;
    ngx_quic_connection_t    *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_add_handshake_data");

    frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return 0;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return 0;
    }

    ngx_memcpy(p, data, len);

    frame->level = level;
    frame->type = NGX_QUIC_FT_CRYPTO;
    frame->u.crypto.len = len;
    frame->u.crypto.data = p;

    ngx_sprintf(frame->info, "crypto, generated by SSL len=%ui level=%d", len, level);

    ngx_quic_queue_frame(qc, frame);

    return 1;
}


static int
ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_quic_flush_flight()");

    return 1;
}


static int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_send_alert(), lvl=%d, alert=%d",
                   (int) level, (int) alert);

    return 1;
}


static ngx_int_t
ngx_quic_process_short_header(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char  *p;

    p = pkt->data;

    ngx_quic_hexdump0(c->log, "short input", pkt->data, pkt->len);

    if ((p[0] & NGX_QUIC_PKT_LONG)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "not a short packet");
        return NGX_ERROR;
    }

    pkt->flags = *p++;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flags:%xi", pkt->flags);

    if (ngx_memcmp(p, c->quic->dcid.data, c->quic->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    pkt->dcid.len = c->quic->dcid.len;
    pkt->dcid.data = p;
    p += pkt->dcid.len;

    pkt->raw->pos = p;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_process_long_header(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char  *p;

    p = pkt->data;

    ngx_quic_hexdump0(c->log, "long input", pkt->data, pkt->len);

    if (!(p[0] & NGX_QUIC_PKT_LONG)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "not a long packet");
        return NGX_ERROR;
    }

    pkt->flags = *p++;

    pkt->version = ngx_quic_parse_uint32(p);
    p += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flags:%xi version:%xD", pkt->flags, pkt->version);

    if (pkt->version != quic_version) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unsupported quic version");
        return NGX_ERROR;
    }

    pkt->dcid.len = *p++;
    pkt->dcid.data = p;
    p += pkt->dcid.len;

    pkt->scid.len = *p++;
    pkt->scid.data = p;
    p += pkt->scid.len;

    pkt->raw->pos = p;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_process_initial_header(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char     *p;
    ngx_int_t   plen;

    p = pkt->raw->pos;

    pkt->token.len = ngx_quic_parse_int(&p);
    pkt->token.data = p;

    p += pkt->token.len;

    plen = ngx_quic_parse_int(&p);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);

    if (plen > pkt->data + pkt->len - p) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "truncated initial packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    ngx_quic_hexdump0(c->log, "DCID", pkt->dcid.data, pkt->dcid.len);
    ngx_quic_hexdump0(c->log, "SCID", pkt->scid.data, pkt->scid.len);
    ngx_quic_hexdump0(c->log, "token", pkt->token.data, pkt->token.len);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);

    return NGX_OK;
}

static ngx_int_t
ngx_quic_process_handshake_header(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char     *p;
    ngx_int_t   plen;

    p = pkt->raw->pos;

    plen = ngx_quic_parse_int(&p);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);

    if (plen > pkt->data + pkt->len - p) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "truncated handshake packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);

    return NGX_OK;
}


ssize_t
ngx_quic_read_frame(ngx_connection_t *c, u_char *start, u_char *end,
    ngx_quic_frame_t *frame)
{
    u_char *p;

    size_t npad;

    p = start;

    frame->type = *p++;  // TODO: check overflow (p < end)

    switch (frame->type) {

    case NGX_QUIC_FT_CRYPTO:
        frame->u.crypto.offset = *p++;
        frame->u.crypto.len = ngx_quic_parse_int(&p);
        frame->u.crypto.data = p;
        p += frame->u.crypto.len;

        ngx_quic_hexdump0(c->log, "CRYPTO frame",
                          frame->u.crypto.data, frame->u.crypto.len);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic CRYPTO frame length: %uL off:%uL pp:%p",
                       frame->u.crypto.len, frame->u.crypto.offset,
                       frame->u.crypto.data);
        break;

    case NGX_QUIC_FT_PADDING:
        npad = 0;
        while (p < end && *p == NGX_QUIC_FT_PADDING) { // XXX
            p++; npad++;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "PADDING frame length %uL", npad);

        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ACK frame");

        frame->u.ack.largest = ngx_quic_parse_int(&p);
        frame->u.ack.delay = ngx_quic_parse_int(&p);
        frame->u.ack.range_count =ngx_quic_parse_int(&p);
        frame->u.ack.first_range =ngx_quic_parse_int(&p);

        if (frame->u.ack.range_count) {
            frame->u.ack.ranges[0] = ngx_quic_parse_int(&p);
        }

        if (frame->type ==NGX_QUIC_FT_ACK_ECN) {
            return NGX_ERROR;
        }

        break;

    case NGX_QUIC_FT_PING:
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "PING frame");
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "NCID frame");

        frame->u.ncid.seqnum = ngx_quic_parse_int(&p);
        frame->u.ncid.retire = ngx_quic_parse_int(&p);
        frame->u.ncid.len = *p++;
        ngx_memcpy(frame->u.ncid.cid, p, frame->u.ncid.len);
        p += frame->u.ncid.len;

        ngx_memcpy(frame->u.ncid.srt, p, 16);
        p += 16;

        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "connection close frame");

        frame->u.close.error_code = ngx_quic_parse_int(&p);
        frame->u.close.frame_type = ngx_quic_parse_int(&p); // not in 0x1d CC
        frame->u.close.reason.len = ngx_quic_parse_int(&p);
        frame->u.close.reason.data = p;
        p += frame->u.close.reason.len;

        if (frame->u.close.error_code > NGX_QUIC_ERR_LAST) {
            frame->u.close.error_code = NGX_QUIC_ERR_LAST;
        }
        break;

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "STREAM frame, type: 0x%xi", frame->type);

        frame->u.stream.type = frame->type;

        frame->u.stream.stream_id = ngx_quic_parse_int(&p);
        if (frame->type & 0x04) {
            frame->u.stream.offset = ngx_quic_parse_int(&p);
        } else {
            frame->u.stream.offset = 0;
        }

        if (frame->type & 0x02) {
            frame->u.stream.length = ngx_quic_parse_int(&p);
        } else {
            frame->u.stream.length = end - p; /* up to packet end */
        }

        frame->u.stream.data = p;

        p += frame->u.stream.length;

        break;

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "unknown frame type %xi", frame->type);
        return NGX_ERROR;
    }

    return p - start;
}


static ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    int             sslerr;
    ssize_t         n;
    ngx_ssl_conn_t *ssl_conn;

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));


    if (!SSL_provide_quic_data(ssl_conn, SSL_quic_read_level(ssl_conn),
                               frame->u.crypto.data, frame->u.crypto.len))
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_provide_quic_data() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr == SSL_ERROR_SSL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ssl cipher: %s", SSL_get_cipher(ssl_conn));

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}



static ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    int                     n, sslerr;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    static const uint8_t params[] =
        "\x00\x29"                         /* parameters length: 41 bytes         */
        "\x00\x0e\x00\x01\x05"             /* active connection id limit: 5       */
        "\x00\x04\x00\x04\x80\x98\x96\x80" /* initial max data = 10000000         */
        "\x00\x09\x00\x01\x03"             /* initial max streams uni: 3          */
        "\x00\x08\x00\x01\x10"             /* initial max streams bidi: 16        */
        "\x00\x05\x00\x02\x40\xff"         /* initial max stream bidi local: 255  */
        "\x00\x06\x00\x02\x40\xff"         /* initial max stream bidi remote: 255 */
        "\x00\x07\x00\x02\x40\xff";        /* initial max stream data uni: 255    */

    qc = c->quic;

    if (ngx_ssl_create_connection(qc->ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;

    if (SSL_set_quic_transport_params(ssl_conn, params, sizeof(params) - 1) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                  len;
    ngx_buf_t               *b;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qs = c->qs;
    qc = qs->parent->quic;

    // XXX: get direct pointer from stream structure?
    sn = ngx_quic_stream_lookup(&qc->stree, qs->id);

    if (sn == NULL) {
        return NGX_ERROR;
    }

    // XXX: how to return EOF?

    b = sn->b;

    if (b->last - b->pos == 0) {
        c->read->ready = 0;
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic recv() not ready");
        return NGX_AGAIN; // ?
    }

    len = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, len);

    b->pos += len;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "quic recv: %z of %uz", len, size);

    return len;
}


static ssize_t
ngx_quic_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    u_char                  *p;
    ngx_connection_t        *pc;
    ngx_quic_frame_t        *frame;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic send: %uz", size);

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    // XXX: get direct pointer from stream structure?
    sn = ngx_quic_stream_lookup(&qc->stree, qs->id);

    if (sn == NULL) {
        return NGX_ERROR;
    }

    frame = ngx_pcalloc(pc->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return 0;
    }

    p = ngx_pnalloc(pc->pool, size);
    if (p == NULL) {
        return 0;
    }

    ngx_memcpy(p, buf, size);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM6; /* OFF=1 LEN=1 FIN=0 */

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = size;
    frame->u.stream.data = p;

    c->sent += size;

    ngx_sprintf(frame->info, "stream %xi len=%ui level=%d",
                qs->id, size, frame->level);

    ngx_quic_queue_frame(qc, frame);

    return size;
}


static ngx_chain_t *
ngx_quic_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    size_t      len;
    ssize_t     n;
    ngx_buf_t  *b;

    for ( /* void */; in; in = in->next) {
        b = in->buf;

        if (!ngx_buf_in_memory(b)) {
            continue;
        }

        if (ngx_buf_size(b) == 0) {
            continue;
        }

        len = b->last - b->pos;

        n = ngx_quic_stream_send(c, b->pos, len);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            return in;
        }

        if (n != (ssize_t) len) {
            b->pos += n;
            return in;
        }
    }

    return NULL;
}


/* process all payload from the current packet and generate ack if required */
static ngx_int_t
ngx_quic_payload_handler(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                  *end, *p;
    ssize_t                  len;
    ngx_buf_t               *b;
    ngx_log_t               *log;
    ngx_uint_t               ack_this, do_close;
    ngx_pool_t              *pool;
    ngx_event_t             *rev, *wev;
    ngx_quic_frame_t         frame, *ack_frame;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qc = c->quic;

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    ack_this = 0;
    do_close = 0;

    while (p < end) {

        len = ngx_quic_read_frame(c, p, end, &frame);
        if (len < 0) {
            return NGX_ERROR;
        }

        p += len;

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:

            // TODO: handle ack

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "ACK: { largest=%ui delay=%ui first=%ui count=%ui}",
                           frame.u.ack.largest,
                           frame.u.ack.delay,
                           frame.u.ack.first_range,
                           frame.u.ack.range_count);

            break;

        case NGX_QUIC_FT_CRYPTO:

            if (frame.u.crypto.offset != 0x0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "crypto frame with non-zero offset");
                // TODO: support packet spanning with offsets
                return NGX_ERROR;
            }

            if (ngx_quic_handle_crypto_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            ack_this = 1;

            continue;

        case NGX_QUIC_FT_PADDING:
            continue;

        case NGX_QUIC_FT_PING:
            ack_this = 1;
            continue;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:
            ack_this = 1;
            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "NCID: { seq=%ui retire=%ui len=%ui}",
                           frame.u.ncid.seqnum,
                           frame.u.ncid.retire,
                           frame.u.ncid.len);
            continue;

        case NGX_QUIC_FT_CONNECTION_CLOSE:
            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "CONN.CLOSE: { %s (0x%xi) type=0x%xi reason='%V'}",
                           ngx_quic_errors[frame.u.close.error_code],
                           frame.u.close.error_code,
                           frame.u.close.frame_type,
                           &frame.u.close.reason);

            do_close = 1;
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:

            ack_this = 1;

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "STREAM frame 0x%xi id 0x%xi offset 0x%xi len 0x%xi bits:off=%d len=%d fin=%d",
                           frame.type,
                           frame.u.stream.stream_id,
                           frame.u.stream.offset,
                           frame.u.stream.length,
                           ngx_quic_stream_bit_off(frame.u.stream.type),
                           ngx_quic_stream_bit_len(frame.u.stream.type),
                           ngx_quic_stream_bit_fin(frame.u.stream.type));


            sn = ngx_quic_stream_lookup(&qc->stree, frame.u.stream.stream_id);
            if (sn == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "stream is new");

                sn = ngx_pcalloc(c->pool, sizeof(ngx_quic_stream_node_t));
                if (sn == NULL) {
                    return NGX_ERROR;
                }

                sn->c = ngx_get_connection(-1, c->log); // TODO: free on connection termination
                if (sn->c == NULL) {
                    return NGX_ERROR;
                }

                pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
                if (pool == NULL) {
                    /* XXX free connection */
                    return NGX_ERROR;
                }

                log = ngx_palloc(pool, sizeof(ngx_log_t));
                if (log == NULL) {
                    /* XXX free pool and connection */
                    return NGX_ERROR;
                }

                *log = *c->log;
                pool->log = log;

                sn->c->log = log;
                sn->c->pool = pool;

                sn->c->listening = c->listening;
                sn->c->sockaddr = c->sockaddr;
                sn->c->local_sockaddr = c->local_sockaddr;

                rev = sn->c->read;
                wev = sn->c->write;

                rev->ready = 1;

                rev->log = c->log;
                wev->log = c->log;

                sn->c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

                sn->node.key = frame.u.stream.stream_id;
                sn->b = ngx_create_temp_buf(pool, 16 * 1024); // XXX enough for everyone
                if (sn->b == NULL) {
                    return NGX_ERROR;
                }
                b = sn->b;

                ngx_memcpy(b->start, frame.u.stream.data, frame.u.stream.length);
                b->last = b->start + frame.u.stream.length;

                ngx_rbtree_insert(&qc->stree, &sn->node);

                sn->s.id = frame.u.stream.stream_id;
                sn->s.unidirectional = (sn->s.id & 0x02) ? 1 : 0;
                sn->s.parent = c;
                sn->c->qs = &sn->s;

                sn->c->recv = ngx_quic_stream_recv;
                sn->c->send = ngx_quic_stream_send;
                sn->c->send_chain = ngx_quic_stream_send_chain;

                qc->stream_handler(sn->c);

            } else {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "existing stream");
                b = sn->b;

                if ((size_t) (b->end - b->pos) < frame.u.stream.length) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                 "no space in stream buffer");
                    return NGX_ERROR;
                }

                ngx_memcpy(b->pos, frame.u.stream.data, frame.u.stream.length);
                b->pos += frame.u.stream.length;

                // TODO: ngx_post_event(&c->read, &ngx_posted_events) ???
            }

            ngx_quic_hexdump0(c->log, "STREAM.data",
                              frame.u.stream.data, frame.u.stream.length);
            break;

        default:
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "unexpected frame type 0x%xd in packet", frame.type);
            return NGX_ERROR;
        }
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "trailing garbage in payload: %ui bytes", end - p);
        return NGX_ERROR;
    }

    if (do_close) {
        // TODO: handle stream close
    }

    if (ack_this == 0) {
        /* do not ack packets with ACKs and PADDING */
        return NGX_OK;
    }

    // packet processed, ACK it now if required
    // TODO: if (ack_required) ...  - currently just ack each packet

    ack_frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (ack_frame == NULL) {
        return NGX_ERROR;
    }

    ack_frame->level = pkt->level;
    ack_frame->type = NGX_QUIC_FT_ACK;
    ack_frame->u.ack.pn = pkt->pn;

    ngx_sprintf(ack_frame->info, "ACK for PN=%d from frame handler level=%d", pkt->pn, pkt->level);
    ngx_quic_queue_frame(qc, ack_frame);

    return ngx_quic_output(c);
}


static void
ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_quic_stream_node_t       *qn, *qnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            qn = (ngx_quic_stream_node_t *) &node->color;
            qnt = (ngx_quic_stream_node_t *) &temp->color;

            if (qn->c < qnt->c) {
                p = &temp->left;
            } else {
                p = &temp->right;
            }
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_quic_stream_node_t *
ngx_quic_stream_lookup(ngx_rbtree_t *rbtree, ngx_uint_t key)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (key == node->key) {
            return (ngx_quic_stream_node_t *) node;
        }

        node = (key < node->key) ? node->left : node->right;
    }

    return NULL;
}


static ngx_int_t
ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    if (ngx_buf_size(pkt->raw) < 1200) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "too small UDP datagram");
        return NGX_ERROR;
    }

    if (ngx_quic_process_long_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if ((pkt->flags & 0xf0) != NGX_QUIC_PKT_INITIAL) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid initial packet: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_process_initial_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&qc->stree, &qc->stree_sentinel,
                    ngx_quic_rbtree_insert_stream);

    c->quic = qc;
    qc->ssl = ssl;

    qc->dcid.len = pkt->dcid.len;
    qc->dcid.data = ngx_pnalloc(c->pool, pkt->dcid.len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->dcid.data, pkt->dcid.data, qc->dcid.len);

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pnalloc(c->pool, qc->scid.len);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->scid.data, pkt->scid.data, qc->scid.len);

    qc->token.len = pkt->token.len;
    qc->token.data = ngx_pnalloc(c->pool, qc->token.len);
    if (qc->token.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->token.data, pkt->token.data, qc->token.len);


    if (ngx_quic_set_initial_secret(c->pool, &qc->secrets, &qc->dcid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.in;
    pkt->level = ssl_encryption_initial;

    if (ngx_quic_decrypt(c->pool, NULL, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_initial_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    ssl_conn = c->ssl->connection;

    if (ngx_quic_process_long_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_process_initial_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.in;
    pkt->level = ssl_encryption_initial;

    if (ngx_quic_decrypt(c->pool, ssl_conn, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_handshake_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    ssl_conn = c->ssl->connection;

    /* extract cleartext data into pkt */
    if (ngx_quic_process_long_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->dcid.len != qc->dcid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->dcid.data, qc->dcid.data, qc->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    if (pkt->scid.len != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->scid.data, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scid");
        return NGX_ERROR;
    }

    if ((pkt->flags & 0xf0) != NGX_QUIC_PKT_HANDSHAKE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid packet type: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_process_handshake_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.hs;
    pkt->level = ssl_encryption_handshake;

    if (ngx_quic_decrypt(c->pool, c->ssl->connection, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_app_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (qc->secrets.client.ad.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    if (ngx_quic_process_short_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.ad;
    pkt->level = ssl_encryption_application;

    if (ngx_quic_decrypt(c->pool, c->ssl->connection, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


uint64_t
ngx_quic_parse_int(u_char **pos)
{
    u_char      *p;
    uint64_t     value;
    ngx_uint_t   len;

    p = *pos;
    len = 1 << ((*p & 0xc0) >> 6);
    value = *p++ & 0x3f;

    while (--len) {
        value = (value << 8) + *p++;
    }

    *pos = p;
    return value;
}


void
ngx_quic_build_int(u_char **pos, uint64_t value)
{
    u_char      *p;
    ngx_uint_t   len;//, len2;

    p = *pos;
    len = 0;

    while (value >> ((1 << len) * 8 - 2)) {
        len++;
    }

    *p = len << 6;

//    len2 =
    len = (1 << len);
    len--;
    *p |= value >> (len * 8);
    p++;

    while (len) {
        *p++ = value >> ((len-- - 1) * 8);
    }

    *pos = p;
//    return len2;
}

