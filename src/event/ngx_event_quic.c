
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#define quic_version 0xff000018


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
#define NGX_QUIC_FT_STREAM                 0x08 // - 0x0f
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


struct ngx_quic_connection_s {

    ngx_quic_state_t   state;
    ngx_ssl_t         *ssl;

    ngx_str_t          out; // stub for some kind of output queue

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
};


typedef enum ssl_encryption_level_t  ngx_quic_level_t;

typedef struct {
    ngx_quic_secret_t  *secret;
    ngx_uint_t          type;
    ngx_uint_t          *number;
    ngx_uint_t          flags;
    ngx_uint_t          version;
    ngx_str_t          *token;
    ngx_quic_level_t    level;
} ngx_quic_header_t;


static ngx_int_t ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_buf_t *b);
static ngx_int_t ngx_quic_handshake_input(ngx_connection_t *c, ngx_buf_t *b);

static int ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
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
    const EVP_CIPHER *cipher, ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad);
static ngx_int_t ngx_quic_tls_seal(ngx_connection_t *c,
    const EVP_CIPHER *cipher, ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad);

static ngx_int_t ngx_quic_tls_hp(ngx_connection_t *c, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, u_char *out, u_char *in);


static SSL_QUIC_METHOD quic_method = {
    ngx_quic_set_encryption_secrets,
    ngx_quic_add_handshake_data,
    ngx_quic_flush_flight,
    ngx_quic_send_alert,
};


void
ngx_quic_init_ssl_methods(SSL_CTX* ctx)
{
    SSL_CTX_set_quic_method(ctx, &quic_method);
}


ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_buf_t *b)
{
    if (c->quic == NULL) {
        return ngx_quic_new_connection(c, ssl, b); //TODO: change state by results
    }

    switch (c->quic->state) {
    case NGX_QUIC_ST_INITIAL:
    case NGX_QUIC_ST_HANDSHAKE:
        return ngx_quic_handshake_input(c, b);
    default:
        /* application data */
        break;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    /* stub for processing output queue */

    if (c->quic->out.data) {
        c->send(c, c->quic->out.data, c->quic->out.len);
        c->quic->out.data = NULL;
    }

    return NGX_OK;
}


static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len)
{
    u_char             *name;
    ngx_uint_t          i;
    const EVP_MD       *digest;
    const EVP_CIPHER   *cipher;
    ngx_connection_t   *c;
    ngx_quic_secret_t  *client, *server;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    //ngx_ssl_handshake_log(c); // TODO: enable again

    ngx_quic_hexdump(c->log, "level:%d read", read_secret, secret_len, level);
    ngx_quic_hexdump(c->log, "level:%d read", write_secret, secret_len, level);

    name = (u_char *) SSL_get_cipher(ssl_conn);

    if (ngx_strcasecmp(name, (u_char *) "TLS_AES_128_GCM_SHA256") == 0
        || ngx_strcasecmp(name, (u_char *) "(NONE)") == 0)
    {
        cipher = EVP_aes_128_gcm();
        digest = EVP_sha256();

    } else if (ngx_strcasecmp(name, (u_char *) "TLS_AES_256_GCM_SHA384") == 0) {
        cipher = EVP_aes_256_gcm();
        digest = EVP_sha384();

    } else {
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

    client->key.len = EVP_CIPHER_key_length(cipher);
    server->key.len = EVP_CIPHER_key_length(cipher);

    client->iv.len = EVP_CIPHER_iv_length(cipher);
    server->iv.len = EVP_CIPHER_iv_length(cipher);

    client->hp.len = EVP_CIPHER_key_length(cipher);
    server->hp.len = EVP_CIPHER_key_length(cipher);

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

        if (ngx_quic_hkdf_expand(c, digest, seq[i].key, &seq[i].label,
                                 seq[i].secret, secret_len)
            != NGX_OK)
        {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_quic_create_long_packet(ngx_connection_t *c, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    u_char                 *p, *pnp, *name, *nonce, *sample, *packet;
    ngx_str_t               ad, out;
    const EVP_CIPHER       *cipher;
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

    if (pkt->token) { // if pkt->flags & initial ?
        ngx_quic_build_int(&p, pkt->token->len);
    }

    ngx_quic_build_int(&p, out.len + 1); // length (inc. pnl)
    pnp = p;

    *p++ = (*pkt->number)++;

    ad.len = p - ad.data;

    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    name = (u_char *) SSL_get_cipher(ssl_conn);

    if (ngx_strcasecmp(name, (u_char *) "TLS_AES_128_GCM_SHA256") == 0
        || ngx_strcasecmp(name, (u_char *) "(NONE)") == 0)
    {
        cipher = EVP_aes_128_gcm();

    } else if (ngx_strcasecmp(name, (u_char *) "TLS_AES_256_GCM_SHA384") == 0) {
        cipher = EVP_aes_256_gcm();

    } else {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(c->pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake) {
        nonce[11] ^= (*pkt->number - 1);
    }

    ngx_quic_hexdump0(c->log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(c, cipher, pkt->secret, &out, nonce, payload, &ad) != NGX_OK) {
        return NGX_ERROR;
    }

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(c, EVP_aes_128_ecb(), pkt->secret, mask, sample) != NGX_OK) {
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
    u_char                 *p, *pnp, *name, *nonce, *sample, *packet;
    ngx_str_t               ad, out;
    const EVP_CIPHER       *cipher;
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

    name = (u_char *) SSL_get_cipher(ssl_conn);

    if (ngx_strcasecmp(name, (u_char *) "TLS_AES_128_GCM_SHA256") == 0
        || ngx_strcasecmp(name, (u_char *) "(NONE)") == 0)
    {
        cipher = EVP_aes_128_gcm();

    } else if (ngx_strcasecmp(name, (u_char *) "TLS_AES_256_GCM_SHA384") == 0) {
        cipher = EVP_aes_256_gcm();

    } else {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(c->pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake) {
        nonce[11] ^= (*pkt->number - 1);
    }

    ngx_quic_hexdump0(c->log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(c, cipher, pkt->secret, &out, nonce, payload, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "out", out.data, out.len);

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(c, EVP_aes_128_ecb(), pkt->secret, mask, sample)
        != NGX_OK)
    {
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
ngx_quic_create_ack(u_char **p, uint64_t num)
{
    ngx_quic_build_int(p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(p, num);
    ngx_quic_build_int(p, 0);
    ngx_quic_build_int(p, 0);
    ngx_quic_build_int(p, num);
}


static void
ngx_quic_create_crypto(u_char **p, u_char *data, size_t len)
{
    ngx_quic_build_int(p, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(p, 0);
    ngx_quic_build_int(p, len);
    *p = ngx_cpymem(*p, data, len);
}



static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                   *p;
    ngx_str_t                 payload, res;
    ngx_connection_t         *c;
    ngx_quic_header_t         pkt;
    ngx_quic_connection_t    *qc;

    ngx_str_t  initial_token = ngx_null_string;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = c->quic;

    //ngx_ssl_handshake_log(c); // TODO: enable again

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    pkt.level = level;

    payload.data = ngx_alloc(4 + len + 5 /*minimal ACK*/, c->log);
    if (payload.data == 0) {
        return 0;
    }
    p = payload.data;

    ngx_quic_create_crypto(&p, (u_char *) data, len);

    if (level == ssl_encryption_initial) {
        ngx_quic_create_ack(&p, 0);

        pkt.number = &qc->initial_pn;
        pkt.flags = NGX_QUIC_PKT_INITIAL;
        pkt.secret = &qc->server_in;

        pkt.token = &initial_token;

    } else if (level == ssl_encryption_handshake) {
        pkt.number = &qc->handshake_pn;
        pkt.flags = NGX_QUIC_PKT_HANDSHAKE;
        pkt.secret = &qc->server_hs;

        pkt.token = NULL;

    } else {
        pkt.number = &qc->appdata_pn;
        pkt.secret = &qc->server_ad;
    }

    payload.len = p - payload.data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_add_handshake_data: clear_len:%uz",
                   payload.len);

    if (level == ssl_encryption_application) {

        if (ngx_quic_create_short_packet(c, ssl_conn, &pkt, &payload, &res)
            != NGX_OK)
        {
            return 0;
        }

    } else {

        if (ngx_quic_create_long_packet(c, ssl_conn, &pkt, &payload, &res)
            != NGX_OK)
        {
            return 0;
        }
    }

    // TODO: save state of data to send into qc (push into queue)
    qc->out = res;

    if (ngx_quic_output(c) != NGX_OK) {
        return 0;
    }

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
ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_buf_t *b)
{
    int                     n, sslerr;
    ngx_quic_connection_t  *qc;

    if ((b->pos[0] & 0xf0) != NGX_QUIC_PKT_INITIAL) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "invalid initial packet");
        return NGX_ERROR;
    }

    if (ngx_buf_size(b) < 1200) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "too small UDP datagram");
        return NGX_ERROR;
    }

    ngx_int_t flags = *b->pos++;
    uint32_t version = ngx_quic_parse_uint32(b->pos);
    b->pos += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flags:%xi version:%xD", flags, version);

    if (version != quic_version) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unsupported quic version");
        return NGX_ERROR;
    }

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    c->quic = qc;

    qc->dcid.len = *b->pos++;
    qc->dcid.data = ngx_pnalloc(c->pool, qc->dcid.len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(qc->dcid.data, b->pos, qc->dcid.len);
    b->pos += qc->dcid.len;

    qc->scid.len = *b->pos++;
    qc->scid.data = ngx_pnalloc(c->pool, qc->scid.len);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(qc->scid.data, b->pos, qc->scid.len);
    b->pos += qc->scid.len;

    qc->token.len = ngx_quic_parse_int(&b->pos);
    qc->token.data = ngx_pnalloc(c->pool, qc->token.len);
    if (qc->token.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(qc->token.data, b->pos, qc->token.len);
    b->pos += qc->token.len;

    ngx_int_t plen = ngx_quic_parse_int(&b->pos);

    if (plen > b->last - b->pos) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "truncated initial packet");
        return NGX_ERROR;
    }

    /* draft-ietf-quic-tls-23#section-5.4.2:
     * the Packet Number field is assumed to be 4 bytes long
     * draft-ietf-quic-tls-23#section-5.4.[34]:
     * AES-Based and ChaCha20-Based header protections sample 16 bytes
     */
    u_char *sample = b->pos + 4;

    ngx_quic_hexdump0(c->log, "DCID", qc->dcid.data, qc->dcid.len);
    ngx_quic_hexdump0(c->log, "SCID", qc->scid.data, qc->scid.len);
    ngx_quic_hexdump0(c->log, "token", qc->token.data, qc->token.len);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);
    ngx_quic_hexdump0(c->log, "sample", sample, 16);


// initial secret

    size_t                    is_len;
    uint8_t                   is[SHA256_DIGEST_LENGTH];
    ngx_uint_t                i;
    const EVP_MD             *digest;
    const EVP_CIPHER         *cipher;
    static const uint8_t salt[20] =
        "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7"
        "\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";

    /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */

    cipher = EVP_aes_128_gcm();
    digest = EVP_sha256();

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

// header protection

    uint8_t mask[16];
    if (ngx_quic_tls_hp(c, EVP_aes_128_ecb(), &qc->client_in, mask, sample)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    u_char  clearflags = flags ^ (mask[0] & 0x0f);
    ngx_int_t  pnl = (clearflags & 0x03) + 1;
    uint64_t  pn = ngx_quic_parse_pn(&b->pos, pnl, &mask[1]);

    ngx_quic_hexdump0(c->log, "sample", sample, 16);
    ngx_quic_hexdump0(c->log, "mask", mask, 5);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet number: %uL, len: %xi", pn, pnl);

// packet protection

    ngx_str_t in;
    in.data = b->pos;
    in.len = plen - pnl;

    ngx_str_t ad;
    ad.len = b->pos - b->start;
    ad.data = ngx_pnalloc(c->pool, ad.len);
    if (ad.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ad.data, b->start, ad.len);
    ad.data[0] = clearflags;
    ad.data[ad.len - pnl] = (u_char)pn;

    uint8_t *nonce = ngx_pstrdup(c->pool, &qc->client_in.iv);
    nonce[11] ^= pn;

    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);
    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    ngx_str_t  out;

    if (ngx_quic_tls_open(c, EVP_aes_128_gcm(), &qc->client_in, &out, nonce,
                          &in, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "packet payload", out.data, out.len);

    if (out.data[0] != 0x06) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "unexpected frame in initial packet");
        return NGX_ERROR;
    }

    if (out.data[1] != 0x00) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "unexpected CRYPTO offset in initial packet");
        return NGX_ERROR;
    }

    uint8_t *crypto = &out.data[2];
    uint64_t crypto_len = ngx_quic_parse_int(&crypto);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic initial packet CRYPTO length: %uL pp:%p:%p",
                   crypto_len, out.data, crypto);

    if (ngx_ssl_create_connection(ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
        return NGX_ERROR;
    }

    static const uint8_t params[12] = "\x00\x0a\x00\x3a\x00\x01\x00\x00\x09\x00\x01\x03";

    if (SSL_set_quic_transport_params(c->ssl->connection, params,
                                      sizeof(params)) == 0)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(c->ssl->connection),
                   (int) SSL_quic_write_level(c->ssl->connection));

    if (!SSL_provide_quic_data(c->ssl->connection,
                               SSL_quic_read_level(c->ssl->connection),
                               crypto, crypto_len))
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_provide_quic_data() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr == SSL_ERROR_SSL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(c->ssl->connection),
                   (int) SSL_quic_write_level(c->ssl->connection));

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handshake_input(ngx_connection_t *c, ngx_buf_t *bb)
{
    int                     sslerr;
    ssize_t                 n;
    ngx_str_t               out;
    const EVP_CIPHER       *cipher;
    ngx_quic_connection_t  *qc;
    u_char                 *p, *b;

    qc = c->quic;

    n = bb->last - bb->pos;
    p = bb->pos;
    b = bb->start;

    ngx_quic_hexdump0(c->log, "input", buf, n);

    if ((p[0] & 0xf0) != NGX_QUIC_PKT_HANDSHAKE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "invalid packet type");
        return NGX_ERROR;
    }

    ngx_int_t flags = *p++;
    uint32_t version = ngx_quic_parse_uint32(p);
    p += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic flags:%xi version:%xD", flags, version);

    if (version != quic_version) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unsupported quic version");
        return NGX_ERROR;
    }

    if (*p++ != qc->dcid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(p, qc->dcid.data, qc->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    p += qc->dcid.len;

    if (*p++ != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(p, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scid");
        return NGX_ERROR;
    }

    p += qc->scid.len;

    ngx_int_t plen = ngx_quic_parse_int(&p);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet length: %d", plen);

    if (plen > b + n - p) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "truncated handshake packet");
        return NGX_ERROR;
    }

    u_char *sample = p + 4;

    ngx_quic_hexdump0(c->log, "sample", sample, 16);

// header protection

    uint8_t mask[16];
    if (ngx_quic_tls_hp(c, EVP_aes_128_ecb(), &qc->client_hs, mask, sample)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    u_char  clearflags = flags ^ (mask[0] & 0x0f);
    ngx_int_t  pnl = (clearflags & 0x03) + 1;
    uint64_t  pn = ngx_quic_parse_pn(&p, pnl, &mask[1]);

    ngx_quic_hexdump0(c->log, "mask", mask, 5);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clear flags: %xi", clearflags);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet number: %uL, len: %xi", pn, pnl);

// packet protection

    ngx_str_t in;
    in.data = p;
    in.len = plen - pnl;

    ngx_str_t ad;
    ad.len = p - b;
    ad.data = ngx_pnalloc(c->pool, ad.len);
    if (ad.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ad.data, b, ad.len);
    ad.data[0] = clearflags;
    ad.data[ad.len - pnl] = (u_char)pn;

    uint8_t *nonce = ngx_pstrdup(c->pool, &qc->client_hs.iv);
    nonce[11] ^= pn;

    ngx_quic_hexdump0(c->log, "nonce", nonce, 12);
    ngx_quic_hexdump0(c->log, "ad", ad.data, ad.len);

    u_char *name = (u_char *) SSL_get_cipher(c->ssl->connection);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ssl cipher: %s", name);

    if (ngx_strcasecmp(name, (u_char *) "TLS_AES_128_GCM_SHA256") == 0
        || ngx_strcasecmp(name, (u_char *) "(NONE)") == 0)
    {
        cipher = EVP_aes_128_gcm();

    } else if (ngx_strcasecmp(name, (u_char *) "TLS_AES_256_GCM_SHA384") == 0) {
        cipher = EVP_aes_256_gcm();

    } else {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "unexpected cipher");
        return NGX_ERROR;
    }

    if (ngx_quic_tls_open(c, cipher, &qc->client_hs, &out, nonce, &in, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "packet payload", out.data, out.len);

    if (out.data[0] != 0x06) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "non-CRYPTO frame in HS packet, skipping");
        return NGX_OK;
    }

    if (out.data[1] != 0x00) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "not yet supported CRYPTO offset in initial packet");
        return NGX_ERROR;
    }

    uint8_t *crypto = &out.data[2];
    uint64_t crypto_len = ngx_quic_parse_int(&crypto);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic Handshake packet CRYPTO length: %uL pp:%p:%p",
                   crypto_len, out.data, crypto);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(c->ssl->connection),
                   (int) SSL_quic_write_level(c->ssl->connection));

    if (!SSL_provide_quic_data(c->ssl->connection,
                               SSL_quic_read_level(c->ssl->connection),
                               crypto, crypto_len))
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_provide_quic_data() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(c->ssl->connection);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr == SSL_ERROR_SSL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(c->ssl->connection),
                   (int) SSL_quic_write_level(c->ssl->connection));

    // ACK Client Finished

    ngx_str_t                 payload, res;
    ngx_quic_header_t         pkt;
    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    pkt.level = ssl_encryption_handshake;
    pkt.number = &qc->handshake_pn;
    pkt.flags = NGX_QUIC_PKT_HANDSHAKE;
    pkt.secret = &qc->server_hs;

    payload.data = ngx_alloc(5 /*minimal ACK*/, c->log);
    if (payload.data == 0) {
        return 0;
    }

    p = payload.data;
    ngx_quic_create_ack(&p, pn);

    payload.len = p - payload.data;

    if (ngx_quic_create_long_packet(c, c->ssl->connection, &pkt, &payload, &res)
        != NGX_OK)
    {
        return 0;
    }

    qc->out = res;

    if (ngx_quic_output(c) != NGX_OK) {
        return 0;
    }

    return NGX_OK;
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
ngx_quic_tls_open(ngx_connection_t *c, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    out->len = in->len - EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(c->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSLL
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
ngx_quic_tls_seal(ngx_connection_t *c, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    out->len = in->len + EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(c->pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSLL
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

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, s->hp.data, NULL) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptInit_ex() failed");
        goto failed;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, in, 16)) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "EVP_EncryptUpdate() failed");
        goto failed;
    }

    EVP_CIPHER_CTX_free(ctx);

    return NGX_OK;

failed:

    EVP_CIPHER_CTX_free(ctx);

    return NGX_ERROR;
}
