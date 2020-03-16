
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define quic_version                  0xff000018

#define NGX_AES_128_GCM_SHA256        0x1301
#define NGX_AES_256_GCM_SHA384        0x1302
#define NGX_CHACHA20_POLY1305_SHA256  0x1303

#define NGX_QUIC_IV_LEN               12

#ifdef OPENSSL_IS_BORINGSSL
#define ngx_quic_cipher_t             EVP_AEAD
#else
#define ngx_quic_cipher_t             EVP_CIPHER
#endif


#if (NGX_HAVE_NONALIGNED)

#define ngx_quic_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_quic_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#define ngx_quic_write_uint16  ngx_quic_write_uint16_aligned
#define ngx_quic_write_uint32  ngx_quic_write_uint32_aligned

#else

#define ngx_quic_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define ngx_quic_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define ngx_quic_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif


#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define ngx_quic_varint_len(value)                                            \
    ((value) <= 63 ? 1 : ((uint32_t)value) <= 16383 ? 2 : ((uint64_t)value) <= 1073741823 ?  4 : 8)


#if (NGX_DEBUG)

#define ngx_quic_hexdump(log, fmt, data, len, ...)                            \
do {                                                                          \
    ngx_int_t  m;                                                             \
    u_char     buf[2048];                                                     \
                                                                              \
    if (log->log_level & NGX_LOG_DEBUG_EVENT) {                               \
        m = ngx_hex_dump(buf, (u_char *) data, ngx_min(len, 1024)) - buf;     \
        ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,                            \
                   "%s: " fmt " %*s%s, len: %uz",                             \
                   __FUNCTION__,  __VA_ARGS__, m, buf,                        \
                   len < 2048 ? "" : "...", len);                             \
    }                                                                         \
} while (0)

#else

#define ngx_quic_hexdump(log, fmt, data, len, ...)

#endif

#define ngx_quic_hexdump0(log, fmt, data, len)                                \
    ngx_quic_hexdump(log, fmt "%s", data, len, "")                            \


/* 17.2.  Long Header Packets */

#define NGX_QUIC_PKT_LONG                  0x80

#define NGX_QUIC_PKT_INITIAL               0xc0
#define NGX_QUIC_PKT_HANDSHAKE             0xe0

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


typedef struct {
    ngx_str_t          secret;
    ngx_str_t          key;
    ngx_str_t          iv;
    ngx_str_t          hp;
} ngx_quic_secret_t;

typedef struct {
    const ngx_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} ngx_quic_ciphers_t;

typedef enum ssl_encryption_level_t  ngx_quic_level_t;

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

    ngx_quic_secret_t  client_in;
    ngx_quic_secret_t  client_hs;
    ngx_quic_secret_t  client_ad;
    ngx_quic_secret_t  server_in;
    ngx_quic_secret_t  server_hs;
    ngx_quic_secret_t  server_ad;

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


typedef struct {
    ngx_quic_secret_t  *secret;
    ngx_uint_t          type;
    ngx_uint_t          *number;
    ngx_uint_t          flags;
    uint32_t            version;
    ngx_str_t           token;
    ngx_quic_level_t    level;

    /* filled in by parser */
    ngx_buf_t          *raw;        /* udp datagram from wire */

    u_char             *data;       /* quic packet */
    size_t              len;

    /* cleartext fields */
    ngx_str_t           dcid;
    ngx_str_t           scid;

    uint64_t            pn;

    ngx_str_t           payload;  /* decrypted payload */

} ngx_quic_header_t;


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
static ngx_int_t ngx_quic_create_long_packet(ngx_connection_t *c,
    ngx_ssl_conn_t *ssl_conn, ngx_quic_header_t *pkt, ngx_str_t *in,
    ngx_str_t *res);
static ngx_int_t ngx_quic_create_short_packet(ngx_connection_t *c,
    ngx_ssl_conn_t *ssl_conn, ngx_quic_header_t *pkt, ngx_str_t *in,
    ngx_str_t *res);
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
static ngx_int_t ngx_quic_initial_secret(ngx_connection_t *c);
static ngx_int_t ngx_quic_decrypt(ngx_connection_t *c, ngx_quic_header_t *pkt);

static uint64_t ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask);
static uint64_t ngx_quic_parse_int(u_char **pos);
static void ngx_quic_build_int(u_char **pos, uint64_t value);

static ngx_int_t ngx_hkdf_extract(u_char *out_key, size_t *out_len,
    const EVP_MD *digest, const u_char *secret, size_t secret_len,
    const u_char *salt, size_t salt_len);
static ngx_int_t ngx_hkdf_expand(u_char *out_key, size_t out_len,
    const EVP_MD *digest, const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len);

static ngx_int_t ngx_quic_hkdf_expand(ngx_connection_t *c, const EVP_MD *digest,
    ngx_str_t *out, ngx_str_t *label, const uint8_t *prk, size_t prk_len);

static ngx_int_t ngx_quic_tls_open(ngx_connection_t *c,
    const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad);
static ngx_int_t ngx_quic_tls_seal(ngx_connection_t *c,
    const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad);

static ngx_int_t ngx_quic_tls_hp(ngx_connection_t *c, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, u_char *out, u_char *in);

static ngx_int_t ngx_quic_ciphers(ngx_connection_t *c,
    ngx_quic_ciphers_t *ciphers, enum ssl_encryption_level_t level);

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

    if (ngx_quic_input(c, NULL, &b) != NGX_OK) {
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


ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_buf_t *b)
{
    u_char             *p;
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

        if (p[0] & NGX_QUIC_PKT_LONG) {
            // TODO: check current state
            if (ngx_quic_handshake_input(c, &pkt) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {

            if (ngx_quic_app_input(c, &pkt) != NGX_OK) {
                return NGX_ERROR;
            }
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

    if (level == ssl_encryption_initial) {
        pkt.number = &qc->initial_pn;
        pkt.flags = NGX_QUIC_PKT_INITIAL;
        pkt.secret = &qc->server_in;
        pkt.token = initial_token;

        if (ngx_quic_create_long_packet(c, c->ssl->connection,
                                        &pkt, payload, &res)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (level == ssl_encryption_handshake) {
        pkt.number = &qc->handshake_pn;
        pkt.flags = NGX_QUIC_PKT_HANDSHAKE;
        pkt.secret = &qc->server_hs;

        if (ngx_quic_create_long_packet(c, c->ssl->connection,
                                        &pkt, payload, &res)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        pkt.number = &qc->appdata_pn;
        pkt.secret = &qc->server_ad;

        if (ngx_quic_create_short_packet(c, c->ssl->connection,
                                         &pkt, payload, &res)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_quic_hexdump0(c->log, "packet to send", res.data, res.len);

    c->send(c, res.data, res.len); // TODO: err handling

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


ngx_int_t
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
    const uint8_t *secret, size_t secret_len)
{
    ngx_int_t            key_len;
    ngx_uint_t           i;
    ngx_connection_t    *c;
    ngx_quic_secret_t   *client;
    ngx_quic_ciphers_t   ciphers;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read", secret, secret_len, level);

    key_len = ngx_quic_ciphers(c, &ciphers, level);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "unexpected cipher");
        return 0;
    }

    switch (level) {

    case ssl_encryption_handshake:
        client = &c->quic->client_hs;
        break;

    case ssl_encryption_application:
        client = &c->quic->client_ad;
        break;

    default:
        return 0;
    }

    client->key.len = key_len;
    client->iv.len = NGX_QUIC_IV_LEN;
    client->hp.len = key_len;

    struct {
        ngx_str_t       label;
        ngx_str_t      *key;
        const uint8_t  *secret;
    } seq[] = {
        { ngx_string("tls13 quic key"), &client->key, secret },
        { ngx_string("tls13 quic iv"),  &client->iv,  secret },
        { ngx_string("tls13 quic hp"),  &client->hp,  secret },
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(c, ciphers.d, seq[i].key, &seq[i].label,
                                 seq[i].secret, secret_len)
            != NGX_OK)
        {
            return 0;
        }
    }

    return 1;
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len)
{
    ngx_int_t            key_len;
    ngx_uint_t           i;
    ngx_connection_t    *c;
    ngx_quic_secret_t   *server;
    ngx_quic_ciphers_t   ciphers;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d write", secret, secret_len, level);

    key_len = ngx_quic_ciphers(c, &ciphers, level);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "unexpected cipher");
        return 0;
    }

    switch (level) {

    case ssl_encryption_handshake:
        server = &c->quic->server_hs;
        break;

    case ssl_encryption_application:
        server = &c->quic->server_ad;
        break;

    default:
        return 0;
    }

    server->key.len = key_len;
    server->iv.len = NGX_QUIC_IV_LEN;
    server->hp.len = key_len;

    struct {
        ngx_str_t       label;
        ngx_str_t      *key;
        const uint8_t  *secret;
    } seq[] = {
        { ngx_string("tls13 quic key"), &server->key, secret },
        { ngx_string("tls13 quic iv"),  &server->iv,  secret },
        { ngx_string("tls13 quic hp"),  &server->hp,  secret },
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(c, ciphers.d, seq[i].key, &seq[i].label,
                                 seq[i].secret, secret_len)
            != NGX_OK)
        {
            return 0;
        }
    }

    return 1;
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len)
{
    ngx_int_t            key_len;
    ngx_uint_t           i;
    ngx_connection_t    *c;
    ngx_quic_secret_t   *client, *server;
    ngx_quic_ciphers_t   ciphers;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read", read_secret, secret_len, level);
    ngx_quic_hexdump(c->log, "level:%d write", write_secret, secret_len, level);

    key_len = ngx_quic_ciphers(c, &ciphers, level);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "unexpected cipher");
        return 0;
    }

    switch (level) {

    case ssl_encryption_handshake:
        client = &c->quic->client_hs;
        server = &c->quic->server_hs;

        break;

    case ssl_encryption_application:
        client = &c->quic->client_ad;
        server = &c->quic->server_ad;

        break;

    default:
        return 0;
    }

    client->key.len = key_len;
    server->key.len = key_len;

    client->iv.len = NGX_QUIC_IV_LEN;
    server->iv.len = NGX_QUIC_IV_LEN;

    client->hp.len = key_len;
    server->hp.len = key_len;

    struct {
        ngx_str_t       label;
        ngx_str_t      *key;
        const uint8_t  *secret;
    } seq[] = {
        { ngx_string("tls13 quic key"), &client->key, read_secret  },
        { ngx_string("tls13 quic iv"),  &client->iv,  read_secret  },
        { ngx_string("tls13 quic hp"),  &client->hp,  read_secret  },
        { ngx_string("tls13 quic key"), &server->key, write_secret },
        { ngx_string("tls13 quic iv"),  &server->iv,  write_secret },
        { ngx_string("tls13 quic hp"),  &server->hp,  write_secret },
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(c, ciphers.d, seq[i].key, &seq[i].label,
                                 seq[i].secret, secret_len)
            != NGX_OK)
        {
            return 0;
        }
    }

    return 1;
}

#endif


static ngx_int_t
ngx_quic_create_long_packet(ngx_connection_t *c, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    u_char                 *p, *pnp, *nonce, *sample, *packet;
    ngx_str_t               ad, out;
    ngx_quic_ciphers_t      ciphers;
    ngx_quic_connection_t  *qc;
    u_char                  mask[16];

    qc = c->quic;

    out.len = payload->len + EVP_GCM_TLS_TAG_LEN;

    ad.data = ngx_alloc(346 /*max header*/, c->log);
    if (ad.data == 0) {
        return NGX_ERROR;
    }

    p = ad.data;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, quic_version);

    *p++ = qc->scid.len;
    p = ngx_cpymem(p, qc->scid.data, qc->scid.len);

    *p++ = qc->dcid.len;
    p = ngx_cpymem(p, qc->dcid.data, qc->dcid.len);

    if (pkt->level == ssl_encryption_initial) {
        ngx_quic_build_int(&p, pkt->token.len);
    }

    ngx_quic_build_int(&p, out.len + 1); // length (inc. pnl)
    pnp = p;

    *p++ = (*pkt->number)++;

    ad.len = p - ad.data;

    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    if (ngx_quic_ciphers(c, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(c->pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake) {
        nonce[11] ^= (*pkt->number - 1);
    }

    ngx_quic_hexdump0(c->log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(c, ciphers.c, pkt->secret, &out, nonce, payload, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(c, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "sample", sample, 16);
    ngx_quic_hexdump0(c->log, "mask", mask, 16);
    ngx_quic_hexdump0(c->log, "hp_key", pkt->secret->hp.data, 16);

    // header protection, pnl = 0
    ad.data[0] ^= mask[0] & 0x0f;
    *pnp ^= mask[1];

    packet = ngx_alloc(ad.len + out.len, c->log);
    if (packet == 0) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(packet, ad.data, ad.len);
    p = ngx_cpymem(p, out.data, out.len);

    res->data = packet;
    res->len = p - packet;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_short_packet(ngx_connection_t *c, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    u_char                 *p, *pnp, *nonce, *sample, *packet;
    ngx_str_t               ad, out;
    ngx_quic_ciphers_t      ciphers;
    ngx_quic_connection_t  *qc;
    u_char                  mask[16];

    qc = c->quic;

    out.len = payload->len + EVP_GCM_TLS_TAG_LEN;

    ad.data = ngx_alloc(25 /*max header*/, c->log);
    if (ad.data == 0) {
        return NGX_ERROR;
    }

    p = ad.data;

    *p++ = 0x40;

    p = ngx_cpymem(p, qc->scid.data, qc->scid.len);

    pnp = p;

    *p++ = (*pkt->number)++;

    ad.len = p - ad.data;

    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    if (ngx_quic_ciphers(c, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(c->pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake
        || pkt->level == ssl_encryption_application)
    {
        nonce[11] ^= (*pkt->number - 1);
    }

    ngx_quic_hexdump0(c->log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(c, ciphers.c, pkt->secret, &out, nonce, payload, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "out", out.data, out.len);

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(c, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "sample", sample, 16);
    ngx_quic_hexdump0(c->log, "mask", mask, 16);
    ngx_quic_hexdump0(c->log, "hp_key", pkt->secret->hp.data, 16);

    // header protection, pnl = 0
    ad.data[0] ^= mask[0] & 0x1f;
    *pnp ^= mask[1];

    packet = ngx_alloc(ad.len + out.len, c->log);
    if (packet == 0) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(packet, ad.data, ad.len);
    p = ngx_cpymem(p, out.data, out.len);

    ngx_quic_hexdump0(c->log, "packet", packet, p - packet);

    res->data = packet;
    res->len = p - packet;

    return NGX_OK;
}


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


static ngx_int_t
ngx_quic_initial_secret(ngx_connection_t *c)
{
    size_t                  is_len;
    uint8_t                 is[SHA256_DIGEST_LENGTH];
    ngx_uint_t              i;
    const EVP_MD           *digest;
    const EVP_CIPHER       *cipher;
    ngx_quic_connection_t  *qc;

    static const uint8_t salt[20] =
        "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7"
        "\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";

    /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */

    cipher = EVP_aes_128_gcm();
    digest = EVP_sha256();

    qc  = c->quic;

    if (ngx_hkdf_extract(is, &is_len, digest, qc->dcid.data, qc->dcid.len,
                         salt, sizeof(salt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_str_t iss = {
        .data = is,
        .len = is_len
    };

    ngx_quic_hexdump0(c->log, "salt", salt, sizeof(salt));
    ngx_quic_hexdump0(c->log, "initial secret", is, is_len);

    /* draft-ietf-quic-tls-23#section-5.2 */
    qc->client_in.secret.len = SHA256_DIGEST_LENGTH;
    qc->server_in.secret.len = SHA256_DIGEST_LENGTH;

    qc->client_in.key.len = EVP_CIPHER_key_length(cipher);
    qc->server_in.key.len = EVP_CIPHER_key_length(cipher);

    qc->client_in.hp.len = EVP_CIPHER_key_length(cipher);
    qc->server_in.hp.len = EVP_CIPHER_key_length(cipher);

    qc->client_in.iv.len = EVP_CIPHER_iv_length(cipher);
    qc->server_in.iv.len = EVP_CIPHER_iv_length(cipher);

    struct {
        ngx_str_t   label;
        ngx_str_t  *key;
        ngx_str_t  *prk;
    } seq[] = {

        /* draft-ietf-quic-tls-23#section-5.2 */
        { ngx_string("tls13 client in"), &qc->client_in.secret, &iss },
        {
            ngx_string("tls13 quic key"),
            &qc->client_in.key,
            &qc->client_in.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &qc->client_in.iv,
            &qc->client_in.secret,
        },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &qc->client_in.hp,
            &qc->client_in.secret,
        },
        { ngx_string("tls13 server in"), &qc->server_in.secret, &iss },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */
            ngx_string("tls13 quic key"),
            &qc->server_in.key,
            &qc->server_in.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &qc->server_in.iv,
            &qc->server_in.secret,
        },
        {
           /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &qc->server_in.hp,
            &qc->server_in.secret,
        },

    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(c, digest, seq[i].key, &seq[i].label,
                                 seq[i].prk->data, seq[i].prk->len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_decrypt(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char               clearflags, *p, *sample;
    uint8_t             *nonce;
    uint64_t             pn;
    ngx_int_t            pnl, rc;
    ngx_str_t            in, ad;
    ngx_quic_ciphers_t   ciphers;
    uint8_t              mask[16];

    if (ngx_quic_ciphers(c, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    p = pkt->raw->pos;

    /* draft-ietf-quic-tls-23#section-5.4.2:
     * the Packet Number field is assumed to be 4 bytes long
     * draft-ietf-quic-tls-23#section-5.4.[34]:
     * AES-Based and ChaCha20-Based header protections sample 16 bytes
     */

    sample = p + 4;

    ngx_quic_hexdump0(c->log, "sample", sample, 16);

    /* header protection */

    if (ngx_quic_tls_hp(c, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->flags & NGX_QUIC_PKT_LONG) {
        clearflags = pkt->flags ^ (mask[0] & 0x0f);

    } else {
        clearflags = pkt->flags ^ (mask[0] & 0x1f);
    }

    pnl = (clearflags & 0x03) + 1;
    pn = ngx_quic_parse_pn(&p, pnl, &mask[1]);

    pkt->pn = pn;

    ngx_quic_hexdump0(c->log, "mask", mask, 5);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clear flags: %xi", clearflags);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet number: %uL, len: %xi", pn, pnl);

    /* packet protection */

    in.data = p;

    if (pkt->flags & NGX_QUIC_PKT_LONG) {
        in.len = pkt->len - pnl;

    } else {
        in.len = pkt->data + pkt->len - p;
    }

    ad.len = p - pkt->data;
    ad.data = ngx_pnalloc(c->pool, ad.len);
    if (ad.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ad.data, pkt->data, ad.len);
    ad.data[0] = clearflags;

    do {
        ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    nonce = ngx_pstrdup(c->pool, &pkt->secret->iv);
    nonce[11] ^= pn;

    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);
    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    rc = ngx_quic_tls_open(c, ciphers.c, pkt->secret, &pkt->payload,
                           nonce, &in, &ad);

    ngx_quic_hexdump0(c->log, "packet payload",
                      pkt->payload.data, pkt->payload.len);

    return rc;
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
        p++;
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
ngx_quic_init_connection(ngx_connection_t *c, ngx_quic_header_t *pkt)
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


    if (ngx_quic_initial_secret(c) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->client_in;
    pkt->level = ssl_encryption_initial;

    if (ngx_quic_decrypt(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c, pkt) != NGX_OK) {
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

    pkt->secret = &qc->client_hs;
    pkt->level = ssl_encryption_handshake;

    if (ngx_quic_decrypt(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_app_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    /* TODO: this is a stub, untested */

    if (ngx_quic_process_short_header(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->client_ad;
    pkt->level = ssl_encryption_application;

    if (ngx_quic_decrypt(c, pkt) != NGX_OK) {
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


static uint64_t
ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask)
{
    u_char      *p;
    uint64_t     value;

    p = *pos;
    value = *p++ ^ *mask++;

    while (--len) {
        value = (value << 8) + (*p++ ^ *mask++);
    }

    *pos = p;
    return value;
}


static ngx_int_t
ngx_hkdf_extract(u_char *out_key, size_t *out_len, const EVP_MD *digest,
    const u_char *secret, size_t secret_len, const u_char *salt,
    size_t salt_len)
{
#ifdef OPENSSL_IS_BORINGSSL
    if (HKDF_extract(out_key, out_len, digest, secret, secret_len, salt,
                     salt_len)
        == 0)
    {
        return NGX_ERROR;
    }
#else

    EVP_PKEY_CTX  *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_derive(pctx, out_key, out_len) <= 0) {
        return NGX_ERROR;
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_hkdf_expand(ngx_connection_t *c, const EVP_MD *digest, ngx_str_t *out,
    ngx_str_t *label, const uint8_t *prk, size_t prk_len)
{
    uint8_t  *p;
    size_t    info_len;
    uint8_t   info[20];

    out->data = ngx_pnalloc(c->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    info_len = 2 + 1 + label->len + 1;

    info[0] = 0;
    info[1] = out->len;
    info[2] = label->len;
    p = ngx_cpymem(&info[3], label->data, label->len);
    *p = '\0';

    if (ngx_hkdf_expand(out->data, out->len, digest,
                        prk, prk_len, info, info_len)
        != NGX_OK)
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "ngx_hkdf_expand(%V) failed", label);
        return NGX_ERROR;
    }

    ngx_quic_hexdump(c->log, "%V info", info, info_len, label);
    ngx_quic_hexdump(c->log, "%V key", out->data, out->len, label);

    return NGX_OK;
}


static ngx_int_t
ngx_hkdf_expand(u_char *out_key, size_t out_len, const EVP_MD *digest,
    const uint8_t *prk, size_t prk_len, const u_char *info, size_t info_len)
{
#ifdef OPENSSL_IS_BORINGSSL
    if (HKDF_expand(out_key, out_len, digest, prk, prk_len, info, info_len)
        == 0)
    {
        return NGX_ERROR;
    }
#else

    EVP_PKEY_CTX  *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_derive(pctx, out_key, &out_len) <= 0) {
        return NGX_ERROR;
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_tls_open(ngx_connection_t *c, const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    out->len = in->len - EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(c->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_open(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_AEAD_CTX_open() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    u_char          *tag;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, out->data, &len, in->data,
                          in->len - EVP_GCM_TLS_TAG_LEN)
        != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;
    tag = in->data + in->len - EVP_GCM_TLS_TAG_LEN;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, out->data + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_DecryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    EVP_CIPHER_CTX_free(ctx);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_tls_seal(ngx_connection_t *c, const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    out->len = in->len + EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(c->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_seal(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_AEAD_CTX_seal() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;

    if (EVP_EncryptFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                            out->data + in->len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed");
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    out->len += EVP_GCM_TLS_TAG_LEN;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_tls_hp(ngx_connection_t *c, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, u_char *out, u_char *in)
{
    int              outlen;
    EVP_CIPHER_CTX  *ctx;
    u_char           zero[5] = {0};

#ifdef OPENSSL_IS_BORINGSSL
    uint32_t counter;

    ngx_memcpy(&counter, in, sizeof(uint32_t));

    if (cipher == (const EVP_CIPHER *) EVP_aead_chacha20_poly1305()) {
        CRYPTO_chacha_20(out, zero, 5, s->hp.data, &in[4], counter);
        return NGX_OK;
    }
#endif

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, s->hp.data, in) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptInit_ex() failed");
        goto failed;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, 5)) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptUpdate() failed");
        goto failed;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + 5, &outlen)) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptFinal_Ex() failed");
        goto failed;
    }

    EVP_CIPHER_CTX_free(ctx);

    return NGX_OK;

failed:

    EVP_CIPHER_CTX_free(ctx);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_ciphers(ngx_connection_t *c, ngx_quic_ciphers_t *ciphers,
    enum ssl_encryption_level_t level)
{
    ngx_int_t  id, len;

    if (level == ssl_encryption_initial) {
        id = NGX_AES_128_GCM_SHA256;

    } else {
        id = SSL_CIPHER_get_id(SSL_get_current_cipher(c->ssl->connection))
             & 0xffff;
    }

    switch (id) {

    case NGX_AES_128_GCM_SHA256:
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->c = EVP_aead_aes_128_gcm();
#else
        ciphers->c = EVP_aes_128_gcm();
#endif
        ciphers->hp = EVP_aes_128_ctr();
        ciphers->d = EVP_sha256();
        len = 16;
        break;

    case NGX_AES_256_GCM_SHA384:
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->c = EVP_aead_aes_256_gcm();
#else
        ciphers->c = EVP_aes_256_gcm();
#endif
        ciphers->hp = EVP_aes_256_ctr();
        ciphers->d = EVP_sha384();
        len = 32;
        break;

    case NGX_CHACHA20_POLY1305_SHA256:
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->c = EVP_aead_chacha20_poly1305();
#else
        ciphers->c = EVP_chacha20_poly1305();
#endif
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->hp = (const EVP_CIPHER *) EVP_aead_chacha20_poly1305();
#else
        ciphers->hp = EVP_chacha20();
#endif
        ciphers->d = EVP_sha256();
        len = 32;
        break;

    default:
        return NGX_ERROR;
    }

    return len;
}
