
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_QUIC_IV_LEN               12

#define NGX_AES_128_GCM_SHA256        0x1301
#define NGX_AES_256_GCM_SHA384        0x1302
#define NGX_CHACHA20_POLY1305_SHA256  0x1303


#ifdef OPENSSL_IS_BORINGSSL
#define ngx_quic_cipher_t             EVP_AEAD
#else
#define ngx_quic_cipher_t             EVP_CIPHER
#endif

typedef struct {
    const ngx_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} ngx_quic_ciphers_t;


static ngx_int_t ngx_hkdf_expand(u_char *out_key, size_t out_len,
    const EVP_MD *digest, const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len);
static ngx_int_t ngx_hkdf_extract(u_char *out_key, size_t *out_len,
    const EVP_MD *digest, const u_char *secret, size_t secret_len,
    const u_char *salt, size_t salt_len);

static uint64_t ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask);
static ngx_int_t ngx_quic_ciphers(ngx_ssl_conn_t *ssl_conn,
    ngx_quic_ciphers_t *ciphers, enum ssl_encryption_level_t level);

static ngx_int_t ngx_quic_tls_open(ngx_pool_t *pool, const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad);
static ngx_int_t ngx_quic_tls_seal(ngx_pool_t *pool,
    const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad);
static ngx_int_t ngx_quic_tls_hp(ngx_log_t *log, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, u_char *out, u_char *in);
static ngx_int_t ngx_quic_hkdf_expand(ngx_pool_t *pool, const EVP_MD *digest,
    ngx_str_t *out, ngx_str_t *label, const uint8_t *prk, size_t prk_len);

static ngx_int_t ngx_quic_create_long_packet(ngx_pool_t *pool,
    ngx_ssl_conn_t *ssl_conn, ngx_quic_header_t *pkt, ngx_str_t *in,
    ngx_str_t *res);

static ngx_int_t ngx_quic_create_short_packet(ngx_pool_t *pool,
    ngx_ssl_conn_t *ssl_conn, ngx_quic_header_t *pkt, ngx_str_t *in,
    ngx_str_t *res);


static ngx_int_t
ngx_quic_ciphers(ngx_ssl_conn_t *ssl_conn, ngx_quic_ciphers_t *ciphers,
    enum ssl_encryption_level_t level)
{
    ngx_int_t  id, len;

    if (level == ssl_encryption_initial) {
        id = NGX_AES_128_GCM_SHA256;

    } else {
        id = SSL_CIPHER_get_id(SSL_get_current_cipher(ssl_conn)) & 0xffff;
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


ngx_int_t
ngx_quic_set_initial_secret(ngx_pool_t *pool, ngx_quic_secrets_t *qsec,
    ngx_str_t *secret)
{
    size_t             is_len;
    uint8_t            is[SHA256_DIGEST_LENGTH];
    ngx_uint_t         i;
    const EVP_MD      *digest;
    const EVP_CIPHER  *cipher;

    static const uint8_t salt[20] =
        "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7"
        "\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";

    /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */

    cipher = EVP_aes_128_gcm();
    digest = EVP_sha256();

    if (ngx_hkdf_extract(is, &is_len, digest, secret->data, secret->len,
                         salt, sizeof(salt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_str_t iss = {
        .data = is,
        .len = is_len
    };

    ngx_quic_hexdump0(pool->log, "salt", salt, sizeof(salt));
    ngx_quic_hexdump0(pool->log, "initial secret", is, is_len);

    /* draft-ietf-quic-tls-23#section-5.2 */
    qsec->client.in.secret.len = SHA256_DIGEST_LENGTH;
    qsec->server.in.secret.len = SHA256_DIGEST_LENGTH;

    qsec->client.in.key.len = EVP_CIPHER_key_length(cipher);
    qsec->server.in.key.len = EVP_CIPHER_key_length(cipher);

    qsec->client.in.hp.len = EVP_CIPHER_key_length(cipher);
    qsec->server.in.hp.len = EVP_CIPHER_key_length(cipher);

    qsec->client.in.iv.len = EVP_CIPHER_iv_length(cipher);
    qsec->server.in.iv.len = EVP_CIPHER_iv_length(cipher);

    struct {
        ngx_str_t   label;
        ngx_str_t  *key;
        ngx_str_t  *prk;
    } seq[] = {

        /* draft-ietf-quic-tls-23#section-5.2 */
        { ngx_string("tls13 client in"), &qsec->client.in.secret, &iss },
        {
            ngx_string("tls13 quic key"),
            &qsec->client.in.key,
            &qsec->client.in.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &qsec->client.in.iv,
            &qsec->client.in.secret,
        },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &qsec->client.in.hp,
            &qsec->client.in.secret,
        },
        { ngx_string("tls13 server in"), &qsec->server.in.secret, &iss },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */
            ngx_string("tls13 quic key"),
            &qsec->server.in.key,
            &qsec->server.in.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &qsec->server.in.iv,
            &qsec->server.in.secret,
        },
        {
           /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &qsec->server.in.hp,
            &qsec->server.in.secret,
        },

    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(pool, digest, seq[i].key, &seq[i].label,
                                 seq[i].prk->data, seq[i].prk->len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_hkdf_expand(ngx_pool_t *pool, const EVP_MD *digest, ngx_str_t *out,
    ngx_str_t *label, const uint8_t *prk, size_t prk_len)
{
    size_t    info_len;
    uint8_t  *p;
    uint8_t   info[20];

    out->data = ngx_pnalloc(pool, out->len);
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
        ngx_ssl_error(NGX_LOG_INFO, pool->log, 0,
                      "ngx_hkdf_expand(%V) failed", label);
        return NGX_ERROR;
    }

    ngx_quic_hexdump(pool->log, "%V info", info, info_len, label);
    ngx_quic_hexdump(pool->log, "%V key", out->data, out->len, label);

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
ngx_quic_tls_open(ngx_pool_t *pool, const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    ngx_log_t  *log;

    log = pool->log; // TODO: pass log ?

    out->len = in->len - EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX  *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_open(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_open() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    u_char          *tag;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, out->data, &len, in->data,
                          in->len - EVP_GCM_TLS_TAG_LEN)
        != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;
    tag = in->data + in->len - EVP_GCM_TLS_TAG_LEN;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_TAG) failed");
        return NGX_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, out->data + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_DecryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    EVP_CIPHER_CTX_free(ctx);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_tls_seal(ngx_pool_t *pool, const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad)
{
    ngx_log_t  *log;

    log = pool->log; // TODO: pass log ?

    out->len = in->len + EVP_GCM_TLS_TAG_LEN;
    out->data = ngx_pnalloc(pool, out->len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX  *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, s->key.data, s->key.len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_AEAD_CTX_seal(ctx, out->data, &out->len, out->len, nonce, s->iv.len,
                          in->data, in->len, ad->data, ad->len)
        != 1)
    {
        EVP_AEAD_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_seal() failed");
        return NGX_ERROR;
    }

    EVP_AEAD_CTX_free(ctx);
#else
    int              len;
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s->key.data, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;

    if (EVP_EncryptFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                            out->data + in->len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG) failed");
        return NGX_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    out->len += EVP_GCM_TLS_TAG_LEN;
#endif
    return NGX_OK;
}


static ngx_int_t
ngx_quic_tls_hp(ngx_log_t *log, const EVP_CIPHER *cipher,
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
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        goto failed;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, 5)) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        goto failed;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + 5, &outlen)) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptFinal_Ex() failed");
        goto failed;
    }

    EVP_CIPHER_CTX_free(ctx);

    return NGX_OK;

failed:

    EVP_CIPHER_CTX_free(ctx);

    return NGX_ERROR;
}


int
ngx_quic_set_encryption_secret(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *secret,
    size_t secret_len, ngx_quic_peer_secrets_t *qsec)
{
    ngx_int_t            key_len;
    ngx_uint_t           i;
    ngx_quic_secret_t   *peer_secret;
    ngx_quic_ciphers_t   ciphers;

    key_len = ngx_quic_ciphers(ssl_conn, &ciphers, level);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, pool->log, 0, "unexpected cipher");
        return 0;
    }

    switch (level) {

    case ssl_encryption_handshake:
        peer_secret= &qsec->hs;
        break;

    case ssl_encryption_application:
        peer_secret = &qsec->ad;
        break;

    default:
        return 0;
    }

    peer_secret->key.len = key_len;
    peer_secret->iv.len = NGX_QUIC_IV_LEN;
    peer_secret->hp.len = key_len;

    struct {
        ngx_str_t       label;
        ngx_str_t      *key;
        const uint8_t  *secret;
    } seq[] = {
        { ngx_string("tls13 quic key"), &peer_secret->key, secret },
        { ngx_string("tls13 quic iv"),  &peer_secret->iv,  secret },
        { ngx_string("tls13 quic hp"),  &peer_secret->hp,  secret },
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(pool, ciphers.d, seq[i].key, &seq[i].label,
                                 seq[i].secret, secret_len)
            != NGX_OK)
        {
            return 0;
        }
    }

    return 1;
}


static ngx_int_t
ngx_quic_create_long_packet(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    u_char              *p, *pnp, *nonce, *sample, *packet;
    uint64_t             pn;
    ngx_log_t           *log;
    ngx_str_t            ad, out;
    ngx_quic_ciphers_t   ciphers;
    u_char               mask[16];

    log = pool->log;

    out.len = payload->len + EVP_GCM_TLS_TAG_LEN;

    ad.data = ngx_alloc(346 /*max header*/, log);
    if (ad.data == 0) {
        return NGX_ERROR;
    }

    p = ad.data;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, quic_version);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    if (pkt->level == ssl_encryption_initial) {
        ngx_quic_build_int(&p, pkt->token.len);
    }

    ngx_quic_build_int(&p, out.len + 1); // length (inc. pnl)
    pnp = p;

    pn = *pkt->number;

    *p++ = pn;

    ad.len = p - ad.data;

    ngx_quic_hexdump0(log, "ad", ad.data, ad.len);

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake) {
        nonce[11] ^= pn;
    }

    ngx_quic_hexdump0(log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(pool, ciphers.c, pkt->secret, &out,
                          nonce, payload, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(log, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(log, "sample", sample, 16);
    ngx_quic_hexdump0(log, "mask", mask, 16);
    ngx_quic_hexdump0(log, "hp_key", pkt->secret->hp.data, 16);

    // header protection, pnl = 0
    ad.data[0] ^= mask[0] & 0x0f;
    *pnp ^= mask[1];

    packet = ngx_alloc(ad.len + out.len, log);
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
ngx_quic_create_short_packet(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    u_char              *p, *pnp, *nonce, *sample, *packet;
    ngx_log_t           *log;
    ngx_str_t            ad, out;
    ngx_quic_ciphers_t   ciphers;
    u_char               mask[16];

    log = pool->log;

    out.len = payload->len + EVP_GCM_TLS_TAG_LEN;

    ad.data = ngx_alloc(25 /*max header*/, log);
    if (ad.data == 0) {
        return NGX_ERROR;
    }

    p = ad.data;

    *p++ = 0x40;

    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    pnp = p;

    *p++ = (*pkt->number);

    ad.len = p - ad.data;

    ngx_quic_hexdump0(log, "ad", ad.data, ad.len);

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    nonce = ngx_pstrdup(pool, &pkt->secret->iv);
    if (pkt->level == ssl_encryption_handshake
        || pkt->level == ssl_encryption_application)
    {
        nonce[11] ^= *pkt->number;
    }

    ngx_quic_hexdump0(log, "server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump0(log, "nonce", nonce, 12);

    if (ngx_quic_tls_seal(pool, ciphers.c, pkt->secret, &out,
                          nonce, payload, &ad)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(log, "out", out.data, out.len);

    sample = &out.data[3]; // pnl=0
    if (ngx_quic_tls_hp(log, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(log, "sample", sample, 16);
    ngx_quic_hexdump0(log, "mask", mask, 16);
    ngx_quic_hexdump0(log, "hp_key", pkt->secret->hp.data, 16);

    // header protection, pnl = 0
    ad.data[0] ^= mask[0] & 0x1f;
    *pnp ^= mask[1];

    packet = ngx_alloc(ad.len + out.len, log);
    if (packet == 0) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(packet, ad.data, ad.len);
    p = ngx_cpymem(p, out.data, out.len);

    ngx_quic_hexdump0(log, "packet", packet, p - packet);

    res->data = packet;
    res->len = p - packet;

    return NGX_OK;
}

static uint64_t
ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask)
{
    u_char    *p;
    uint64_t   value;

    p = *pos;
    value = *p++ ^ *mask++;

    while (--len) {
        value = (value << 8) + (*p++ ^ *mask++);
    }

    *pos = p;
    return value;
}


ngx_int_t
ngx_quic_encrypt(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt, ngx_str_t *payload, ngx_str_t *res)
{
    if (pkt->level == ssl_encryption_application) {
        return ngx_quic_create_short_packet(pool, ssl_conn, pkt, payload, res);
    }

    return ngx_quic_create_long_packet(pool, ssl_conn, pkt, payload, res);
}


ngx_int_t
ngx_quic_decrypt(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    ngx_quic_header_t *pkt)
{
    u_char               clearflags, *p, *sample;
    uint8_t             *nonce;
    uint64_t             pn;
    ngx_log_t           *log;
    ngx_int_t            pnl, rc;
    ngx_str_t            in, ad;
    ngx_quic_ciphers_t   ciphers;
    uint8_t              mask[16];

    log = pool->log;

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    p = pkt->raw->pos;

    /* draft-ietf-quic-tls-23#section-5.4.2:
     * the Packet Number field is assumed to be 4 bytes long
     * draft-ietf-quic-tls-23#section-5.4.[34]:
     * AES-Based and ChaCha20-Based header protections sample 16 bytes
     */

    sample = p + 4;

    ngx_quic_hexdump0(log, "sample", sample, 16);

    /* header protection */

    if (ngx_quic_tls_hp(log, ciphers.hp, pkt->secret, mask, sample) != NGX_OK) {
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

    ngx_quic_hexdump0(log, "mask", mask, 5);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic clear flags: %xi", clearflags);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic packet number: %uL, len: %xi", pn, pnl);

    /* packet protection */

    in.data = p;

    if (pkt->flags & NGX_QUIC_PKT_LONG) {
        in.len = pkt->len - pnl;

    } else {
        in.len = pkt->data + pkt->len - p;
    }

    ad.len = p - pkt->data;
    ad.data = ngx_pnalloc(pool, ad.len);
    if (ad.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(ad.data, pkt->data, ad.len);
    ad.data[0] = clearflags;

    do {
        ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    nonce = ngx_pstrdup(pool, &pkt->secret->iv);
    nonce[11] ^= pn;

    ngx_quic_hexdump0(log, "nonce", nonce, 12);
    ngx_quic_hexdump0(log, "ad", ad.data, ad.len);

    rc = ngx_quic_tls_open(pool, ciphers.c, pkt->secret, &pkt->payload,
                           nonce, &in, &ad);

    ngx_quic_hexdump0(log, "packet payload",
                      pkt->payload.data, pkt->payload.len);

    return rc;
}

