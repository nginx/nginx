
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#if (NGX_QUIC_OPENSSL_COMPAT)

#define NGX_QUIC_COMPAT_RECORD_SIZE          1024

#define NGX_QUIC_COMPAT_SSL_TP_EXT           0x39

#define NGX_QUIC_COMPAT_CLIENT_HANDSHAKE     "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define NGX_QUIC_COMPAT_SERVER_HANDSHAKE     "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define NGX_QUIC_COMPAT_CLIENT_APPLICATION   "CLIENT_TRAFFIC_SECRET_0"
#define NGX_QUIC_COMPAT_SERVER_APPLICATION   "SERVER_TRAFFIC_SECRET_0"


typedef struct {
    ngx_quic_secret_t             secret;
    ngx_uint_t                    cipher;
} ngx_quic_compat_keys_t;


typedef struct {
    ngx_log_t                    *log;

    u_char                        type;
    ngx_str_t                     payload;
    uint64_t                      number;
    ngx_quic_compat_keys_t       *keys;

    enum ssl_encryption_level_t   level;
} ngx_quic_compat_record_t;


struct ngx_quic_compat_s {
    const SSL_QUIC_METHOD        *method;

    enum ssl_encryption_level_t   write_level;

    uint64_t                      read_record;
    ngx_quic_compat_keys_t        keys;

    ngx_str_t                     tp;
    ngx_str_t                     ctp;
};


static void ngx_quic_compat_keylog_callback(const SSL *ssl, const char *line);
static ngx_int_t ngx_quic_compat_set_encryption_secret(ngx_connection_t *c,
    ngx_quic_compat_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
static void ngx_quic_compat_cleanup_encryption_secret(void *data);
static int ngx_quic_compat_add_transport_params_callback(SSL *ssl,
    unsigned int ext_type, unsigned int context, const unsigned char **out,
    size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
static int ngx_quic_compat_parse_transport_params_callback(SSL *ssl,
    unsigned int ext_type, unsigned int context, const unsigned char *in,
    size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);
static void ngx_quic_compat_message_callback(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static size_t ngx_quic_compat_create_header(ngx_quic_compat_record_t *rec,
    u_char *out, ngx_uint_t plain);
static ngx_int_t ngx_quic_compat_create_record(ngx_quic_compat_record_t *rec,
    ngx_str_t *res);


ngx_int_t
ngx_quic_compat_init(ngx_conf_t *cf, SSL_CTX *ctx)
{
    SSL_CTX_set_keylog_callback(ctx, ngx_quic_compat_keylog_callback);

    if (SSL_CTX_has_client_custom_ext(ctx, NGX_QUIC_COMPAT_SSL_TP_EXT)) {
        return NGX_OK;
    }

    if (SSL_CTX_add_custom_ext(ctx, NGX_QUIC_COMPAT_SSL_TP_EXT,
                               SSL_EXT_CLIENT_HELLO
                               |SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                               ngx_quic_compat_add_transport_params_callback,
                               NULL,
                               NULL,
                               ngx_quic_compat_parse_transport_params_callback,
                               NULL)
        == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_add_custom_ext() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_quic_compat_keylog_callback(const SSL *ssl, const char *line)
{
    u_char                        ch, *p, *start, value;
    size_t                        n;
    ngx_uint_t                    write;
    const SSL_CIPHER             *cipher;
    ngx_quic_compat_t            *com;
    ngx_connection_t             *c;
    ngx_quic_connection_t        *qc;
    enum ssl_encryption_level_t   level;
    u_char                        secret[EVP_MAX_MD_SIZE];

    c = ngx_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return;
    }

    p = (u_char *) line;

    for (start = p; *p && *p != ' '; p++);

    n = p - start;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat secret %*s", n, start);

    if (n == sizeof(NGX_QUIC_COMPAT_CLIENT_HANDSHAKE) - 1
        && ngx_strncmp(start, NGX_QUIC_COMPAT_CLIENT_HANDSHAKE, n) == 0)
    {
        level = ssl_encryption_handshake;
        write = 0;

    } else if (n == sizeof(NGX_QUIC_COMPAT_SERVER_HANDSHAKE) - 1
               && ngx_strncmp(start, NGX_QUIC_COMPAT_SERVER_HANDSHAKE, n) == 0)
    {
        level = ssl_encryption_handshake;
        write = 1;

    } else if (n == sizeof(NGX_QUIC_COMPAT_CLIENT_APPLICATION) - 1
               && ngx_strncmp(start, NGX_QUIC_COMPAT_CLIENT_APPLICATION, n)
                  == 0)
    {
        level = ssl_encryption_application;
        write = 0;

    } else if (n == sizeof(NGX_QUIC_COMPAT_SERVER_APPLICATION) - 1
               && ngx_strncmp(start, NGX_QUIC_COMPAT_SERVER_APPLICATION, n)
                   == 0)
    {
        level = ssl_encryption_application;
        write = 1;

    } else {
        return;
    }

    if (*p++ == '\0') {
        return;
    }

    for ( /* void */ ; *p && *p != ' '; p++);

    if (*p++ == '\0') {
        return;
    }

    for (n = 0, start = p; *p; p++) {
        ch = *p;

        if (ch >= '0' && ch <= '9') {
            value = ch - '0';
            goto next;
        }

        ch = (u_char) (ch | 0x20);

        if (ch >= 'a' && ch <= 'f') {
            value = ch - 'a' + 10;
            goto next;
        }

        ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                      "invalid OpenSSL QUIC secret format");

        return;

    next:

        if ((p - start) % 2) {
            secret[n++] += value;

        } else {
            if (n >= EVP_MAX_MD_SIZE) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                              "too big OpenSSL QUIC secret");
                return;
            }

            secret[n] = (value << 4);
        }
    }

    qc = ngx_quic_get_connection(c);
    com = qc->compat;
    cipher = SSL_get_current_cipher(ssl);

    if (write) {
        com->method->set_write_secret((SSL *) ssl, level, cipher, secret, n);
        com->write_level = level;

    } else {
        com->method->set_read_secret((SSL *) ssl, level, cipher, secret, n);
        com->read_record = 0;

        (void) ngx_quic_compat_set_encryption_secret(c, &com->keys, level,
                                                     cipher, secret, n);
    }

    ngx_explicit_memzero(secret, n);
}


static ngx_int_t
ngx_quic_compat_set_encryption_secret(ngx_connection_t *c,
    ngx_quic_compat_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
    ngx_int_t            key_len;
    ngx_str_t            secret_str;
    ngx_uint_t           i;
    ngx_quic_md_t        key;
    ngx_quic_hkdf_t      seq[2];
    ngx_quic_secret_t   *peer_secret;
    ngx_quic_ciphers_t   ciphers;
    ngx_pool_cleanup_t  *cln;

    peer_secret = &keys->secret;

    keys->cipher = SSL_CIPHER_get_id(cipher);

    key_len = ngx_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0, "unexpected cipher");
        return NGX_ERROR;
    }

    key.len = key_len;

    peer_secret->iv.len = NGX_QUIC_IV_LEN;

    secret_str.len = secret_len;
    secret_str.data = (u_char *) secret;

    ngx_quic_hkdf_set(&seq[0], "tls13 key", &key, &secret_str);
    ngx_quic_hkdf_set(&seq[1], "tls13 iv", &peer_secret->iv, &secret_str);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (ngx_quic_hkdf_expand(&seq[i], ciphers.d, c->log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* register cleanup handler once */

    if (peer_secret->ctx) {
        ngx_quic_crypto_cleanup(peer_secret);

    } else {
        cln = ngx_pool_cleanup_add(c->pool, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_quic_compat_cleanup_encryption_secret;
        cln->data = peer_secret;
    }

    if (ngx_quic_crypto_init(ciphers.c, peer_secret, &key, 1, c->log)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    ngx_explicit_memzero(key.data, key.len);

    return NGX_OK;
}


static void
ngx_quic_compat_cleanup_encryption_secret(void *data)
{
    ngx_quic_secret_t *secret = data;

    ngx_quic_crypto_cleanup(secret);
}


static int
ngx_quic_compat_add_transport_params_callback(SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char **out, size_t *outlen, X509 *x,
    size_t chainidx, int *al, void *add_arg)
{
    ngx_connection_t       *c;
    ngx_quic_compat_t      *com;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat add transport params");

    qc = ngx_quic_get_connection(c);
    com = qc->compat;

    *out = com->tp.data;
    *outlen = com->tp.len;

    return 1;
}


static int
ngx_quic_compat_parse_transport_params_callback(SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *in, size_t inlen, X509 *x,
    size_t chainidx, int *al, void *parse_arg)
{
    u_char                 *p;
    ngx_connection_t       *c;
    ngx_quic_compat_t      *com;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat parse transport params");

    qc = ngx_quic_get_connection(c);
    com = qc->compat;

    p = ngx_pnalloc(c->pool, inlen);
    if (p == NULL) {
        return 0;
    }

    ngx_memcpy(p, in, inlen);

    com->ctp.data = p;
    com->ctp.len = inlen;

    return 1;
}


int
SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method)
{
    BIO                    *rbio, *wbio;
    ngx_connection_t       *c;
    ngx_quic_compat_t      *com;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic compat set method");

    qc = ngx_quic_get_connection(c);

    qc->compat = ngx_pcalloc(c->pool, sizeof(ngx_quic_compat_t));
    if (qc->compat == NULL) {
        return 0;
    }

    com = qc->compat;
    com->method = quic_method;

    rbio = BIO_new(BIO_s_mem());
    if (rbio == NULL) {
        return 0;
    }

    wbio = BIO_new(BIO_s_null());
    if (wbio == NULL) {
        BIO_free(rbio);
        return 0;
    }

    SSL_set_bio(ssl, rbio, wbio);

    SSL_set_msg_callback(ssl, ngx_quic_compat_message_callback);

    /* early data is not supported */
    SSL_set_max_early_data(ssl, 0);

    return 1;
}


static void
ngx_quic_compat_message_callback(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    ngx_uint_t                    alert;
    ngx_connection_t             *c;
    ngx_quic_compat_t            *com;
    ngx_quic_connection_t        *qc;
    enum ssl_encryption_level_t   level;

    if (!write_p) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    qc = ngx_quic_get_connection(c);

    if (qc == NULL) {
        /* closing */
        return;
    }

    com = qc->compat;
    level = com->write_level;

    switch (content_type) {

    case SSL3_RT_HANDSHAKE:
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic compat tx %s len:%uz ",
                       ngx_quic_level_name(level), len);

        if (com->method->add_handshake_data(ssl, level, buf, len) != 1) {
            goto failed;
        }

        break;

    case SSL3_RT_ALERT:
        if (len >= 2) {
            alert = ((u_char *) buf)[1];

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat %s alert:%ui len:%uz ",
                           ngx_quic_level_name(level), alert, len);

            if (com->method->send_alert(ssl, level, alert) != 1) {
                goto failed;
            }
        }

        break;
    }

    return;

failed:

    ngx_post_event(&qc->close, &ngx_posted_events);
}


int
SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *data, size_t len)
{
    BIO                       *rbio;
    size_t                     n;
    u_char                    *p;
    ngx_str_t                  res;
    ngx_connection_t          *c;
    ngx_quic_compat_t         *com;
    ngx_quic_connection_t     *qc;
    ngx_quic_compat_record_t   rec;
    u_char                     in[NGX_QUIC_COMPAT_RECORD_SIZE + 1];
    u_char                     out[NGX_QUIC_COMPAT_RECORD_SIZE + 1
                                   + SSL3_RT_HEADER_LENGTH
                                   + NGX_QUIC_TAG_LEN];

    c = ngx_ssl_get_connection(ssl);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic compat rx %s len:%uz",
                   ngx_quic_level_name(level), len);

    qc = ngx_quic_get_connection(c);
    com = qc->compat;
    rbio = SSL_get_rbio(ssl);

    while (len) {
        ngx_memzero(&rec, sizeof(ngx_quic_compat_record_t));

        rec.type = SSL3_RT_HANDSHAKE;
        rec.log = c->log;
        rec.number = com->read_record++;
        rec.keys = &com->keys;
        rec.level = level;

        if (level == ssl_encryption_initial) {
            n = ngx_min(len, 65535);

            rec.payload.len = n;
            rec.payload.data = (u_char *) data;

            ngx_quic_compat_create_header(&rec, out, 1);

            BIO_write(rbio, out, SSL3_RT_HEADER_LENGTH);
            BIO_write(rbio, data, n);

#if defined(NGX_QUIC_DEBUG_CRYPTO) && defined(NGX_QUIC_DEBUG_PACKETS)
            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat record len:%uz %*xs%*xs",
                           n + SSL3_RT_HEADER_LENGTH,
                           (size_t) SSL3_RT_HEADER_LENGTH, out, n, data);
#endif

        } else {
            n = ngx_min(len, NGX_QUIC_COMPAT_RECORD_SIZE);

            p = ngx_cpymem(in, data, n);
            *p++ = SSL3_RT_HANDSHAKE;

            rec.payload.len = p - in;
            rec.payload.data = in;

            res.data = out;

            if (ngx_quic_compat_create_record(&rec, &res) != NGX_OK) {
                return 0;
            }

#if defined(NGX_QUIC_DEBUG_CRYPTO) && defined(NGX_QUIC_DEBUG_PACKETS)
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat record len:%uz %xV", res.len, &res);
#endif

            BIO_write(rbio, res.data, res.len);
        }

        data += n;
        len -= n;
    }

    return 1;
}


static size_t
ngx_quic_compat_create_header(ngx_quic_compat_record_t *rec, u_char *out,
    ngx_uint_t plain)
{
    u_char  type;
    size_t  len;

    len = rec->payload.len;

    if (plain) {
        type = rec->type;

    } else {
        type = SSL3_RT_APPLICATION_DATA;
        len += NGX_QUIC_TAG_LEN;
    }

    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (len >> 8);
    out[4] = len;

    return 5;
}


static ngx_int_t
ngx_quic_compat_create_record(ngx_quic_compat_record_t *rec, ngx_str_t *res)
{
    ngx_str_t           ad, out;
    ngx_quic_secret_t  *secret;
    u_char              nonce[NGX_QUIC_IV_LEN];

    ad.data = res->data;
    ad.len = ngx_quic_compat_create_header(rec, ad.data, 0);

    out.len = rec->payload.len + NGX_QUIC_TAG_LEN;
    out.data = res->data + ad.len;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, rec->log, 0,
                   "quic compat ad len:%uz %xV", ad.len, &ad);
#endif

    secret = &rec->keys->secret;

    ngx_memcpy(nonce, secret->iv.data, secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), rec->number);

    if (ngx_quic_crypto_seal(secret, &out, nonce, &rec->payload, &ad, rec->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    res->len = ad.len + out.len;

    return NGX_OK;
}


int
SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
    size_t params_len)
{
    ngx_connection_t       *c;
    ngx_quic_compat_t      *com;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl);
    qc = ngx_quic_get_connection(c);
    com = qc->compat;

    com->tp.len = params_len;
    com->tp.data = (u_char *) params;

    return 1;
}


void
SSL_get_peer_quic_transport_params(const SSL *ssl, const uint8_t **out_params,
    size_t *out_params_len)
{
    ngx_connection_t       *c;
    ngx_quic_compat_t      *com;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl);
    qc = ngx_quic_get_connection(c);
    com = qc->compat;

    *out_params = com->ctp.data;
    *out_params_len = com->ctp.len;
}

#endif /* NGX_QUIC_OPENSSL_COMPAT */
