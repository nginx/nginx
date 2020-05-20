
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

static uint64_t ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask,
    uint64_t *largest_pn);
static void ngx_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn);
static ngx_int_t ngx_quic_ciphers(ngx_ssl_conn_t *ssl_conn,
    ngx_quic_ciphers_t *ciphers, enum ssl_encryption_level_t level);

static ngx_int_t ngx_quic_tls_open(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad, ngx_log_t *log);
static ngx_int_t ngx_quic_tls_seal(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_str_t *out, u_char *nonce, ngx_str_t *in,
    ngx_str_t *ad, ngx_log_t *log);
static ngx_int_t ngx_quic_tls_hp(ngx_log_t *log, const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, u_char *out, u_char *in);
static ngx_int_t ngx_quic_hkdf_expand(ngx_pool_t *pool, const EVP_MD *digest,
    ngx_str_t *out, ngx_str_t *label, const uint8_t *prk, size_t prk_len);

static ngx_int_t ngx_quic_create_long_packet(ngx_quic_header_t *pkt,
    ngx_ssl_conn_t *ssl_conn, ngx_str_t *res);
static ngx_int_t ngx_quic_create_short_packet(ngx_quic_header_t *pkt,
    ngx_ssl_conn_t *ssl_conn, ngx_str_t *res);
static ngx_int_t ngx_quic_create_retry_packet(ngx_quic_header_t *pkt,
    ngx_str_t *res);


static ngx_int_t
ngx_quic_ciphers(ngx_ssl_conn_t *ssl_conn, ngx_quic_ciphers_t *ciphers,
    enum ssl_encryption_level_t level)
{
    ngx_int_t          id, len;
    const SSL_CIPHER  *cipher;

    if (level == ssl_encryption_initial) {
        id = NGX_AES_128_GCM_SHA256;

    } else {
        cipher = SSL_get_current_cipher(ssl_conn);
        if (cipher == NULL) {
            return NGX_ERROR;
        }

        id = SSL_CIPHER_get_id(cipher) & 0xffff;
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
ngx_quic_set_initial_secret(ngx_pool_t *pool, ngx_quic_secret_t *client,
    ngx_quic_secret_t *server, ngx_str_t *secret)
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

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                  "quic ngx_quic_set_initial_secret");
    ngx_quic_hexdump(pool->log, "quic salt", salt, sizeof(salt));
    ngx_quic_hexdump(pool->log, "quic initial secret", is, is_len);
#endif

    /* draft-ietf-quic-tls-23#section-5.2 */
    client->secret.len = SHA256_DIGEST_LENGTH;
    server->secret.len = SHA256_DIGEST_LENGTH;

    client->key.len = EVP_CIPHER_key_length(cipher);
    server->key.len = EVP_CIPHER_key_length(cipher);

    client->hp.len = EVP_CIPHER_key_length(cipher);
    server->hp.len = EVP_CIPHER_key_length(cipher);

    client->iv.len = EVP_CIPHER_iv_length(cipher);
    server->iv.len = EVP_CIPHER_iv_length(cipher);

    struct {
        ngx_str_t   label;
        ngx_str_t  *key;
        ngx_str_t  *prk;
    } seq[] = {

        /* draft-ietf-quic-tls-23#section-5.2 */
        { ngx_string("tls13 client in"), &client->secret, &iss },
        {
            ngx_string("tls13 quic key"),
            &client->key,
            &client->secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &client->iv,
            &client->secret,
        },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &client->hp,
            &client->secret,
        },
        { ngx_string("tls13 server in"), &server->secret, &iss },
        {
            /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.3 */
            ngx_string("tls13 quic key"),
            &server->key,
            &server->secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &server->iv,
            &server->secret,
        },
        {
           /* AEAD_AES_128_GCM prior to handshake, quic-tls-23#section-5.4.1 */
            ngx_string("tls13 quic hp"),
            &server->hp,
            &server->secret,
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

    if (out->data == NULL) {
        out->data = ngx_pnalloc(pool, out->len);
        if (out->data == NULL) {
            return NGX_ERROR;
        }
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

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "quic ngx_quic_hkdf_expand %V keys", label);
    ngx_quic_hexdump(pool->log, "quic info", info, info_len);
    ngx_quic_hexdump(pool->log, "quic key", out->data, out->len);
#endif

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
ngx_quic_tls_open(const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s,
    ngx_str_t *out, u_char *nonce, ngx_str_t *in, ngx_str_t *ad,
    ngx_log_t *log)
{

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
ngx_quic_tls_seal(const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s,
    ngx_str_t *out, u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log)
{

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
    size_t secret_len, ngx_quic_secret_t *peer_secret)
{
    ngx_int_t           key_len;
    ngx_uint_t          i;
    ngx_quic_ciphers_t  ciphers;

    key_len = ngx_quic_ciphers(ssl_conn, &ciphers, level);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, pool->log, 0, "unexpected cipher");
        return 0;
    }

    if (level == ssl_encryption_initial) {
        return 0;
    }

    peer_secret->secret.data = ngx_pnalloc(pool, secret_len);
    if (peer_secret->secret.data == NULL) {
        return NGX_ERROR;
    }

    peer_secret->secret.len = secret_len;
    ngx_memcpy(peer_secret->secret.data, secret, secret_len);

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


ngx_int_t
ngx_quic_key_update(ngx_connection_t *c, ngx_quic_secrets_t *current,
    ngx_quic_secrets_t *next)
{
    ngx_uint_t          i;
    ngx_quic_ciphers_t  ciphers;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic key update");

    if (ngx_quic_ciphers(c->ssl->connection, &ciphers,
                         ssl_encryption_application)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    next->client.secret.len = current->client.secret.len;
    next->client.key.len = current->client.key.len;
    next->client.iv.len = current->client.iv.len;
    next->client.hp = current->client.hp;

    next->server.secret.len = current->server.secret.len;
    next->server.key.len = current->server.key.len;
    next->server.iv.len = current->server.iv.len;
    next->server.hp = current->server.hp;

    struct {
        ngx_str_t   label;
        ngx_str_t  *key;
        ngx_str_t  *secret;
    } seq[] = {
        {
            ngx_string("tls13 quic ku"),
            &next->client.secret,
            &current->client.secret,
        },
        {
            ngx_string("tls13 quic key"),
            &next->client.key,
            &next->client.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &next->client.iv,
            &next->client.secret,
        },
        {
            ngx_string("tls13 quic ku"),
            &next->server.secret,
            &current->server.secret,
        },
        {
            ngx_string("tls13 quic key"),
            &next->server.key,
            &next->server.secret,
        },
        {
            ngx_string("tls13 quic iv"),
            &next->server.iv,
            &next->server.secret,
        },
    };

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {

        if (ngx_quic_hkdf_expand(c->pool, ciphers.d, seq[i].key, &seq[i].label,
                                 seq[i].secret->data, seq[i].secret->len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_long_packet(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
    ngx_str_t *res)
{
    u_char              *pnp, *sample;
    ngx_str_t            ad, out;
    ngx_uint_t           i;
    ngx_quic_ciphers_t   ciphers;
    u_char               nonce[12], mask[16];

    out.len = pkt->payload.len + EVP_GCM_TLS_TAG_LEN;

    ad.data = res->data;
    ad.len = ngx_quic_create_long_header(pkt, ad.data, out.len, &pnp);

    out.data = res->data + ad.len;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ngx_quic_create_long_packet");
    ngx_quic_hexdump(pkt->log, "quic ad", ad.data, ad.len);
#endif

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_memcpy(nonce, pkt->secret->iv.data, pkt->secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), pkt->number);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump(pkt->log, "quic nonce", nonce, 12);
#endif

    if (ngx_quic_tls_seal(ciphers.c, pkt->secret, &out,
                          nonce, &pkt->payload, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sample = &out.data[4 - pkt->num_len];
    if (ngx_quic_tls_hp(pkt->log, ciphers.hp, pkt->secret, mask, sample)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic sample", sample, 16);
    ngx_quic_hexdump(pkt->log, "quic mask", mask, 5);
#endif

    /* quic-tls: 5.4.1.  Header Protection Application */
    ad.data[0] ^= mask[0] & 0x0f;

    for (i = 0; i < pkt->num_len; i++) {
        pnp[i] ^= mask[i + 1];
    }

    res->len = ad.len + out.len;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_short_packet(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
    ngx_str_t *res)
{
    u_char              *pnp, *sample;
    ngx_str_t            ad, out;
    ngx_uint_t           i;
    ngx_quic_ciphers_t   ciphers;
    u_char               nonce[12], mask[16];

    out.len = pkt->payload.len + EVP_GCM_TLS_TAG_LEN;

    ad.data = res->data;
    ad.len = ngx_quic_create_short_header(pkt, ad.data, out.len, &pnp);

    out.data = res->data + ad.len;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ngx_quic_create_short_packet");
    ngx_quic_hexdump(pkt->log, "quic ad", ad.data, ad.len);
#endif

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ngx_quic_create_short_packet: number %L,"
                   " encoded %d:0x%xD", pkt->number, (int) pkt->num_len,
                   pkt->trunc);

    ngx_memcpy(nonce, pkt->secret->iv.data, pkt->secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), pkt->number);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic server_iv", pkt->secret->iv.data, 12);
    ngx_quic_hexdump(pkt->log, "quic nonce", nonce, 12);
#endif

    if (ngx_quic_tls_seal(ciphers.c, pkt->secret, &out,
                          nonce, &pkt->payload, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sample = &out.data[4 - pkt->num_len];
    if (ngx_quic_tls_hp(pkt->log, ciphers.hp, pkt->secret, mask, sample)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic sample", sample, 16);
    ngx_quic_hexdump(pkt->log, "quic mask", mask, 5);
#endif

    /* quic-tls: 5.4.1.  Header Protection Application */
    ad.data[0] ^= mask[0] & 0x1f;

    for (i = 0; i < pkt->num_len; i++) {
        pnp[i] ^= mask[i + 1];
    }

    res->len = ad.len + out.len;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_create_retry_packet(ngx_quic_header_t *pkt, ngx_str_t *res)
{
    u_char              *start;
    ngx_str_t            ad, itag;
    ngx_quic_secret_t    secret;
    ngx_quic_ciphers_t   ciphers;

    /* 5.8.  Retry Packet Integrity */
    static u_char     key[16] =
        "\x4d\x32\xec\xdb\x2a\x21\x33\xc8"
        "\x41\xe4\x04\x3d\xf2\x7d\x44\x30";
    static u_char     nonce[12] =
        "\x4d\x16\x11\xd0\x55\x13"
        "\xa5\x52\xc5\x87\xd5\x75";
    static ngx_str_t  in = ngx_string("");

    ad.data = res->data;
    ad.len = ngx_quic_create_retry_itag(pkt, ad.data, &start);

    itag.data = ad.data + ad.len;
    itag.len = EVP_GCM_TLS_TAG_LEN;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic retry itag", ad.data, ad.len);
#endif

    if (ngx_quic_ciphers(NULL, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    secret.key.len = sizeof(key);
    secret.key.data = key;
    secret.iv.len = sizeof(nonce);

    if (ngx_quic_tls_seal(ciphers.c, &secret, &itag, nonce, &in, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    res->len = itag.data + itag.len - start;
    res->data = start;

    return NGX_OK;
}


static uint64_t
ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask,
    uint64_t *largest_pn)
{
    u_char    *p;
    uint64_t   truncated_pn, expected_pn, candidate_pn;
    uint64_t   pn_nbits, pn_win, pn_hwin, pn_mask;

    pn_nbits = ngx_min(len * 8, 62);

    p = *pos;
    truncated_pn = *p++ ^ *mask++;

    while (--len) {
        truncated_pn = (truncated_pn << 8) + (*p++ ^ *mask++);
    }

    *pos = p;

    expected_pn = *largest_pn + 1;
    pn_win = 1ULL << pn_nbits;
    pn_hwin = pn_win / 2;
    pn_mask = pn_win - 1;

    candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    if ((int64_t) candidate_pn <= (int64_t) (expected_pn - pn_hwin)
        && candidate_pn < (1ULL << 62) - pn_win)
    {
        candidate_pn += pn_win;

    } else if (candidate_pn > expected_pn + pn_hwin
               && candidate_pn >= pn_win)
    {
        candidate_pn -= pn_win;
    }

    *largest_pn = ngx_max((int64_t) *largest_pn, (int64_t) candidate_pn);

    return candidate_pn;
}


static void
ngx_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn)
{
    nonce[len - 4] ^= (pn & 0xff000000) >> 24;
    nonce[len - 3] ^= (pn & 0x00ff0000) >> 16;
    nonce[len - 2] ^= (pn & 0x0000ff00) >> 8;
    nonce[len - 1] ^= (pn & 0x000000ff);
}


ngx_int_t
ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
    ngx_str_t *res)
{
    if (ngx_quic_short_pkt(pkt->flags)) {
        return ngx_quic_create_short_packet(pkt, ssl_conn, res);
    }

    if (ngx_quic_pkt_retry(pkt->flags)) {
        return ngx_quic_create_retry_packet(pkt, res);
    }

    return ngx_quic_create_long_packet(pkt, ssl_conn, res);
}


ngx_int_t
ngx_quic_decrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
    uint64_t *largest_pn)
{
    u_char               clearflags, *p, *sample;
    uint8_t              badflags;
    uint64_t             pn;
    ngx_int_t            pnl, rc, key_phase;
    ngx_str_t            in, ad;
    ngx_quic_secret_t   *secret;
    ngx_quic_ciphers_t   ciphers;
    uint8_t              mask[16], nonce[12];

    if (ngx_quic_ciphers(ssl_conn, &ciphers, pkt->level) == NGX_ERROR) {
        return NGX_ERROR;
    }

    secret = pkt->secret;

    p = pkt->raw->pos;

    /* draft-ietf-quic-tls-23#section-5.4.2:
     * the Packet Number field is assumed to be 4 bytes long
     * draft-ietf-quic-tls-23#section-5.4.[34]:
     * AES-Based and ChaCha20-Based header protections sample 16 bytes
     */

    sample = p + 4;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ngx_quic_decrypt()");
    ngx_quic_hexdump(pkt->log, "quic sample", sample, 16);
#endif

    /* header protection */

    if (ngx_quic_tls_hp(pkt->log, ciphers.hp, secret, mask, sample)
        != NGX_OK)
    {
        pkt->error = NGX_QUIC_ERR_CRYPTO_ERROR;
        return NGX_ERROR;
    }

    if (ngx_quic_long_pkt(pkt->flags)) {
        clearflags = pkt->flags ^ (mask[0] & 0x0f);

    } else {
        clearflags = pkt->flags ^ (mask[0] & 0x1f);
        key_phase = (clearflags & NGX_QUIC_PKT_KPHASE) != 0;

        if (key_phase != pkt->key_phase) {
            secret = pkt->next;
            pkt->key_update = 1;
        }
    }

    pnl = (clearflags & 0x03) + 1;
    pn = ngx_quic_parse_pn(&p, pnl, &mask[1], largest_pn);

    pkt->pn = pn;
    pkt->flags = clearflags;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic mask", mask, 5);
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic clear flags: %xi", clearflags);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet number: %uL, len: %xi", pn, pnl);

    /* packet protection */

    in.data = p;

    if (ngx_quic_long_pkt(pkt->flags)) {
        in.len = pkt->len - pnl;
        badflags = clearflags & NGX_QUIC_PKT_LONG_RESERVED_BIT;

    } else {
        in.len = pkt->data + pkt->len - p;
        badflags = clearflags & NGX_QUIC_PKT_SHORT_RESERVED_BIT;
    }

    ad.len = p - pkt->data;
    ad.data = pkt->plaintext;

    ngx_memcpy(ad.data, pkt->data, ad.len);
    ad.data[0] = clearflags;

    do {
        ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    ngx_memcpy(nonce, secret->iv.data, secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), pn);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(pkt->log, "quic nonce", nonce, 12);
    ngx_quic_hexdump(pkt->log, "quic ad", ad.data, ad.len);
#endif

    pkt->payload.len = in.len - EVP_GCM_TLS_TAG_LEN;

    if (NGX_QUIC_DEFAULT_MAX_PACKET_SIZE - ad.len < pkt->payload.len) {
        return NGX_ERROR;
    }

    pkt->payload.data = pkt->plaintext + ad.len;

    rc = ngx_quic_tls_open(ciphers.c, secret, &pkt->payload,
                           nonce, &in, &ad, pkt->log);

#if defined(NGX_QUIC_DEBUG_CRYPTO) && defined(NGX_QUIC_DEBUG_PACKETS)
    ngx_quic_hexdump(pkt->log, "quic packet payload",
                     pkt->payload.data, pkt->payload.len);
#endif

    if (rc != NGX_OK) {
        pkt->error = NGX_QUIC_ERR_CRYPTO_ERROR;
        return rc;
    }

    if (badflags) {
        /*
         * An endpoint MUST treat receipt of a packet that has
         * a non-zero value for these bits, after removing both
         * packet and header protection, as a connection error
         * of type PROTOCOL_VIOLATION.
         */
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic reserved bit set in packet");
        pkt->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR;
    }

    return NGX_OK;
}

