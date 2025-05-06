
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


/* RFC 9001, 5.4.1.  Header Protection Application: 5-byte mask */
#define NGX_QUIC_HP_LEN               5

#define NGX_QUIC_AES_128_KEY_LEN      16

#define NGX_QUIC_INITIAL_CIPHER       TLS1_3_CK_AES_128_GCM_SHA256


#define ngx_quic_md(str)     { sizeof(str) - 1, str }


static ngx_int_t ngx_hkdf_expand(u_char *out_key, size_t out_len,
    const EVP_MD *digest, const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len);
static ngx_int_t ngx_hkdf_extract(u_char *out_key, size_t *out_len,
    const EVP_MD *digest, const u_char *secret, size_t secret_len,
    const u_char *salt, size_t salt_len);

static uint64_t ngx_quic_parse_pn(u_char **pos, ngx_int_t len, u_char *mask,
    uint64_t *largest_pn);

static ngx_int_t ngx_quic_crypto_open(ngx_quic_secret_t *s, ngx_str_t *out,
    const u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log);
#ifndef OPENSSL_IS_BORINGSSL
static ngx_int_t ngx_quic_crypto_common(ngx_quic_secret_t *s, ngx_str_t *out,
    const u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log);
#endif

static ngx_int_t ngx_quic_crypto_hp_init(const EVP_CIPHER *cipher,
    ngx_quic_secret_t *s, ngx_log_t *log);
static ngx_int_t ngx_quic_crypto_hp(ngx_quic_secret_t *s,
    u_char *out, u_char *in, ngx_log_t *log);
static void ngx_quic_crypto_hp_cleanup(ngx_quic_secret_t *s);

static ngx_int_t ngx_quic_create_packet(ngx_quic_header_t *pkt,
    ngx_str_t *res);
static ngx_int_t ngx_quic_create_retry_packet(ngx_quic_header_t *pkt,
    ngx_str_t *res);


ngx_int_t
ngx_quic_ciphers(ngx_uint_t id, ngx_quic_ciphers_t *ciphers)
{
    ngx_int_t  len;

    switch (id) {

    case TLS1_3_CK_AES_128_GCM_SHA256:
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->c = EVP_aead_aes_128_gcm();
#else
        ciphers->c = EVP_aes_128_gcm();
#endif
        ciphers->hp = EVP_aes_128_ctr();
        ciphers->d = EVP_sha256();
        len = 16;
        break;

    case TLS1_3_CK_AES_256_GCM_SHA384:
#ifdef OPENSSL_IS_BORINGSSL
        ciphers->c = EVP_aead_aes_256_gcm();
#else
        ciphers->c = EVP_aes_256_gcm();
#endif
        ciphers->hp = EVP_aes_256_ctr();
        ciphers->d = EVP_sha384();
        len = 32;
        break;

    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
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

#ifndef OPENSSL_IS_BORINGSSL
    case TLS1_3_CK_AES_128_CCM_SHA256:
        ciphers->c = EVP_aes_128_ccm();
        ciphers->hp = EVP_aes_128_ctr();
        ciphers->d = EVP_sha256();
        len = 16;
        break;
#endif

    default:
        return NGX_ERROR;
    }

    return len;
}


ngx_int_t
ngx_quic_keys_set_initial_secret(ngx_quic_keys_t *keys, ngx_str_t *secret,
    ngx_log_t *log)
{
    size_t               is_len;
    uint8_t              is[SHA256_DIGEST_LENGTH];
    ngx_str_t            iss;
    ngx_uint_t           i;
    const EVP_MD        *digest;
    ngx_quic_md_t        client_key, server_key;
    ngx_quic_hkdf_t      seq[8];
    ngx_quic_secret_t   *client, *server;
    ngx_quic_ciphers_t   ciphers;

    static const uint8_t salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };

    client = &keys->secrets[NGX_QUIC_ENCRYPTION_INITIAL].client;
    server = &keys->secrets[NGX_QUIC_ENCRYPTION_INITIAL].server;

    /*
     * RFC 9001, section 5.  Packet Protection
     *
     * Initial packets use AEAD_AES_128_GCM.  The hash function
     * for HKDF when deriving initial secrets and keys is SHA-256.
     */

    digest = EVP_sha256();
    is_len = SHA256_DIGEST_LENGTH;

    if (ngx_hkdf_extract(is, &is_len, digest, secret->data, secret->len,
                         salt, sizeof(salt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    iss.len = is_len;
    iss.data = is;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic ngx_quic_set_initial_secret");
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic salt len:%uz %*xs", sizeof(salt), sizeof(salt), salt);
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic initial secret len:%uz %*xs", is_len, is_len, is);
#endif

    client->secret.len = SHA256_DIGEST_LENGTH;
    server->secret.len = SHA256_DIGEST_LENGTH;

    client_key.len = NGX_QUIC_AES_128_KEY_LEN;
    server_key.len = NGX_QUIC_AES_128_KEY_LEN;

    client->hp.len = NGX_QUIC_AES_128_KEY_LEN;
    server->hp.len = NGX_QUIC_AES_128_KEY_LEN;

    client->iv.len = NGX_QUIC_IV_LEN;
    server->iv.len = NGX_QUIC_IV_LEN;

    /* labels per RFC 9001, 5.1. Packet Protection Keys */
    ngx_quic_hkdf_set(&seq[0], "tls13 client in", &client->secret, &iss);
    ngx_quic_hkdf_set(&seq[1], "tls13 quic key", &client_key, &client->secret);
    ngx_quic_hkdf_set(&seq[2], "tls13 quic iv", &client->iv, &client->secret);
    ngx_quic_hkdf_set(&seq[3], "tls13 quic hp", &client->hp, &client->secret);
    ngx_quic_hkdf_set(&seq[4], "tls13 server in", &server->secret, &iss);
    ngx_quic_hkdf_set(&seq[5], "tls13 quic key", &server_key, &server->secret);
    ngx_quic_hkdf_set(&seq[6], "tls13 quic iv", &server->iv, &server->secret);
    ngx_quic_hkdf_set(&seq[7], "tls13 quic hp", &server->hp, &server->secret);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (ngx_quic_hkdf_expand(&seq[i], digest, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_ciphers(NGX_QUIC_INITIAL_CIPHER, &ciphers) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (ngx_quic_crypto_init(ciphers.c, client, &client_key, 0, log)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_crypto_init(ciphers.c, server, &server_key, 1, log)
        == NGX_ERROR)
    {
        goto failed;
    }

    if (ngx_quic_crypto_hp_init(ciphers.hp, client, log) == NGX_ERROR) {
        goto failed;
    }

    if (ngx_quic_crypto_hp_init(ciphers.hp, server, log) == NGX_ERROR) {
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_quic_keys_cleanup(keys);

    return NGX_ERROR;
}


ngx_int_t
ngx_quic_hkdf_expand(ngx_quic_hkdf_t *h, const EVP_MD *digest, ngx_log_t *log)
{
    size_t    info_len;
    uint8_t  *p;
    uint8_t   info[20];

    info_len = 2 + 1 + h->label_len + 1;

    info[0] = 0;
    info[1] = h->out_len;
    info[2] = h->label_len;

    p = ngx_cpymem(&info[3], h->label, h->label_len);
    *p = '\0';

    if (ngx_hkdf_expand(h->out, h->out_len, digest,
                        h->prk, h->prk_len, info, info_len)
        != NGX_OK)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "ngx_hkdf_expand(%*s) failed", h->label_len, h->label);
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug5(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic expand \"%*s\" len:%uz %*xs",
                   h->label_len, h->label, h->out_len, h->out_len, h->out);
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

    return NGX_OK;

#else

    EVP_PKEY_CTX  *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, prk_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out_key, &out_len) <= 0) {
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);

    return NGX_OK;

failed:

    EVP_PKEY_CTX_free(pctx);

    return NGX_ERROR;

#endif
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

    return NGX_OK;

#else

    EVP_PKEY_CTX  *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return NGX_ERROR;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out_key, out_len) <= 0) {
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);

    return NGX_OK;

failed:

    EVP_PKEY_CTX_free(pctx);

    return NGX_ERROR;

#endif
}


ngx_int_t
ngx_quic_crypto_init(const ngx_quic_cipher_t *cipher, ngx_quic_secret_t *s,
    ngx_quic_md_t *key, ngx_int_t enc, ngx_log_t *log)
{

#ifdef OPENSSL_IS_BORINGSSL
    EVP_AEAD_CTX  *ctx;

    ctx = EVP_AEAD_CTX_new(cipher, key->data, key->len,
                           EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_new() failed");
        return NGX_ERROR;
    }
#else
    EVP_CIPHER_CTX  *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherInit_ex() failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_mode(cipher) == EVP_CIPH_CCM_MODE
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, NGX_QUIC_TAG_LEN,
                               NULL)
           == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed");
        return NGX_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, s->iv.len, NULL)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_IVLEN) failed");
        return NGX_ERROR;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, NULL, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherInit_ex() failed");
        return NGX_ERROR;
    }
#endif

    s->ctx = ctx;
    return NGX_OK;
}


static ngx_int_t
ngx_quic_crypto_open(ngx_quic_secret_t *s, ngx_str_t *out, const u_char *nonce,
    ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log)
{
#ifdef OPENSSL_IS_BORINGSSL
    if (EVP_AEAD_CTX_open(s->ctx, out->data, &out->len, out->len, nonce,
                          s->iv.len, in->data, in->len, ad->data, ad->len)
        != 1)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_open() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
#else
    return ngx_quic_crypto_common(s, out, nonce, in, ad, log);
#endif
}


ngx_int_t
ngx_quic_crypto_seal(ngx_quic_secret_t *s, ngx_str_t *out, const u_char *nonce,
    ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log)
{
#ifdef OPENSSL_IS_BORINGSSL
    if (EVP_AEAD_CTX_seal(s->ctx, out->data, &out->len, out->len, nonce,
                          s->iv.len, in->data, in->len, ad->data, ad->len)
        != 1)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_AEAD_CTX_seal() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
#else
    return ngx_quic_crypto_common(s, out, nonce, in, ad, log);
#endif
}


#ifndef OPENSSL_IS_BORINGSSL

static ngx_int_t
ngx_quic_crypto_common(ngx_quic_secret_t *s, ngx_str_t *out,
    const u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log)
{
    int                     len, enc;
    ngx_quic_crypto_ctx_t  *ctx;

    ctx = s->ctx;
    enc = EVP_CIPHER_CTX_encrypting(ctx);

    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce, enc) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherInit_ex() failed");
        return NGX_ERROR;
    }

    if (enc == 0) {
        in->len -= NGX_QUIC_TAG_LEN;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, NGX_QUIC_TAG_LEN,
                                in->data + in->len)
            == 0)
        {
            ngx_ssl_error(NGX_LOG_INFO, log, 0,
                          "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed");
            return NGX_ERROR;
        }
    }

    if (EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(ctx)) == EVP_CIPH_CCM_MODE
        && EVP_CipherUpdate(ctx, NULL, &len, NULL, in->len) != 1)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_CipherUpdate(ctx, NULL, &len, ad->data, ad->len) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherUpdate() failed");
        return NGX_ERROR;
    }

    if (EVP_CipherUpdate(ctx, out->data, &len, in->data, in->len) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherUpdate() failed");
        return NGX_ERROR;
    }

    out->len = len;

    if (EVP_CipherFinal_ex(ctx, out->data + out->len, &len) <= 0) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CipherFinal_ex failed");
        return NGX_ERROR;
    }

    out->len += len;

    if (enc == 1) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, NGX_QUIC_TAG_LEN,
                                out->data + out->len)
            == 0)
        {
            ngx_ssl_error(NGX_LOG_INFO, log, 0,
                          "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG) failed");
            return NGX_ERROR;
        }

        out->len += NGX_QUIC_TAG_LEN;
    }

    return NGX_OK;
}

#endif


void
ngx_quic_crypto_cleanup(ngx_quic_secret_t *s)
{
    if (s->ctx) {
#ifdef OPENSSL_IS_BORINGSSL
        EVP_AEAD_CTX_free(s->ctx);
#else
        EVP_CIPHER_CTX_free(s->ctx);
#endif
        s->ctx = NULL;
    }
}


static ngx_int_t
ngx_quic_crypto_hp_init(const EVP_CIPHER *cipher, ngx_quic_secret_t *s,
    ngx_log_t *log)
{
    EVP_CIPHER_CTX  *ctx;

#ifdef OPENSSL_IS_BORINGSSL
    if (cipher == (EVP_CIPHER *) EVP_aead_chacha20_poly1305()) {
        /* no EVP interface */
        s->hp_ctx = NULL;
        return NGX_OK;
    }
#endif

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_CIPHER_CTX_new() failed");
        return NGX_ERROR;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, s->hp.data, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    s->hp_ctx = ctx;
    return NGX_OK;
}


static ngx_int_t
ngx_quic_crypto_hp(ngx_quic_secret_t *s, u_char *out, u_char *in,
    ngx_log_t *log)
{
    int              outlen;
    EVP_CIPHER_CTX  *ctx;

    static const u_char zero[NGX_QUIC_HP_LEN];

    ctx = s->hp_ctx;

#ifdef OPENSSL_IS_BORINGSSL
    uint32_t         cnt;

    if (ctx == NULL) {
        ngx_memcpy(&cnt, in, sizeof(uint32_t));
        CRYPTO_chacha_20(out, zero, NGX_QUIC_HP_LEN, s->hp.data, &in[4], cnt);
        return NGX_OK;
    }
#endif

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, in) != 1) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptInit_ex() failed");
        return NGX_ERROR;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, NGX_QUIC_HP_LEN)) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptUpdate() failed");
        return NGX_ERROR;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + NGX_QUIC_HP_LEN, &outlen)) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "EVP_EncryptFinal_Ex() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_quic_crypto_hp_cleanup(ngx_quic_secret_t *s)
{
    if (s->hp_ctx) {
        EVP_CIPHER_CTX_free(s->hp_ctx);
        s->hp_ctx = NULL;
    }
}


ngx_int_t
ngx_quic_keys_set_encryption_secret(ngx_log_t *log, ngx_uint_t is_write,
    ngx_quic_keys_t *keys, ngx_uint_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len)
{
    ngx_int_t            key_len;
    ngx_str_t            secret_str;
    ngx_uint_t           i;
    ngx_quic_md_t        key;
    ngx_quic_hkdf_t      seq[3];
    ngx_quic_secret_t   *peer_secret;
    ngx_quic_ciphers_t   ciphers;

    peer_secret = is_write ? &keys->secrets[level].server
                           : &keys->secrets[level].client;

    keys->cipher = SSL_CIPHER_get_id(cipher);

    key_len = ngx_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == NGX_ERROR) {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, "unexpected cipher");
        return NGX_ERROR;
    }

    if (sizeof(peer_secret->secret.data) < secret_len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "unexpected secret len: %uz", secret_len);
        return NGX_ERROR;
    }

    peer_secret->secret.len = secret_len;
    ngx_memcpy(peer_secret->secret.data, secret, secret_len);

    key.len = key_len;
    peer_secret->iv.len = NGX_QUIC_IV_LEN;
    peer_secret->hp.len = key_len;

    secret_str.len = secret_len;
    secret_str.data = (u_char *) secret;

    ngx_quic_hkdf_set(&seq[0], "tls13 quic key", &key, &secret_str);
    ngx_quic_hkdf_set(&seq[1], "tls13 quic iv", &peer_secret->iv, &secret_str);
    ngx_quic_hkdf_set(&seq[2], "tls13 quic hp", &peer_secret->hp, &secret_str);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (ngx_quic_hkdf_expand(&seq[i], ciphers.d, log) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_crypto_init(ciphers.c, peer_secret, &key, is_write, log)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_crypto_hp_init(ciphers.hp, peer_secret, log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_explicit_memzero(key.data, key.len);

    return NGX_OK;
}


ngx_uint_t
ngx_quic_keys_available(ngx_quic_keys_t *keys, ngx_uint_t level,
    ngx_uint_t is_write)
{
    if (is_write == 0) {
        return keys->secrets[level].client.ctx != NULL;
    }

    return keys->secrets[level].server.ctx != NULL;
}


void
ngx_quic_keys_discard(ngx_quic_keys_t *keys, ngx_uint_t level)
{
    ngx_quic_secret_t  *client, *server;

    client = &keys->secrets[level].client;
    server = &keys->secrets[level].server;

    ngx_quic_crypto_cleanup(client);
    ngx_quic_crypto_cleanup(server);

    ngx_quic_crypto_hp_cleanup(client);
    ngx_quic_crypto_hp_cleanup(server);

    if (client->secret.len) {
        ngx_explicit_memzero(client->secret.data, client->secret.len);
        client->secret.len = 0;
    }

    if (server->secret.len) {
        ngx_explicit_memzero(server->secret.data, server->secret.len);
        server->secret.len = 0;
    }
}


void
ngx_quic_keys_switch(ngx_connection_t *c, ngx_quic_keys_t *keys)
{
    ngx_quic_secrets_t  *current, *next, tmp;

    current = &keys->secrets[NGX_QUIC_ENCRYPTION_APPLICATION];
    next = &keys->next_key;

    ngx_quic_crypto_cleanup(&current->client);
    ngx_quic_crypto_cleanup(&current->server);

    tmp = *current;
    *current = *next;
    *next = tmp;
}


void
ngx_quic_keys_update(ngx_event_t *ev)
{
    ngx_int_t               key_len;
    ngx_uint_t              i;
    ngx_quic_md_t           client_key, server_key;
    ngx_quic_hkdf_t         seq[6];
    ngx_quic_keys_t        *keys;
    ngx_connection_t       *c;
    ngx_quic_ciphers_t      ciphers;
    ngx_quic_secrets_t     *current, *next;
    ngx_quic_connection_t  *qc;

    c = ev->data;
    qc = ngx_quic_get_connection(c);
    keys = qc->keys;

    current = &keys->secrets[NGX_QUIC_ENCRYPTION_APPLICATION];
    next = &keys->next_key;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic key update");

    c->log->action = "updating keys";

    key_len = ngx_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == NGX_ERROR) {
        goto failed;
    }

    client_key.len = key_len;
    server_key.len = key_len;

    next->client.secret.len = current->client.secret.len;
    next->client.iv.len = NGX_QUIC_IV_LEN;
    next->client.hp = current->client.hp;
    next->client.hp_ctx = current->client.hp_ctx;

    next->server.secret.len = current->server.secret.len;
    next->server.iv.len = NGX_QUIC_IV_LEN;
    next->server.hp = current->server.hp;
    next->server.hp_ctx = current->server.hp_ctx;

    ngx_quic_hkdf_set(&seq[0], "tls13 quic ku",
                      &next->client.secret, &current->client.secret);
    ngx_quic_hkdf_set(&seq[1], "tls13 quic key",
                      &client_key, &next->client.secret);
    ngx_quic_hkdf_set(&seq[2], "tls13 quic iv",
                      &next->client.iv, &next->client.secret);
    ngx_quic_hkdf_set(&seq[3], "tls13 quic ku",
                      &next->server.secret, &current->server.secret);
    ngx_quic_hkdf_set(&seq[4], "tls13 quic key",
                      &server_key, &next->server.secret);
    ngx_quic_hkdf_set(&seq[5], "tls13 quic iv",
                      &next->server.iv, &next->server.secret);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (ngx_quic_hkdf_expand(&seq[i], ciphers.d, c->log) != NGX_OK) {
            goto failed;
        }
    }

    if (ngx_quic_crypto_init(ciphers.c, &next->client, &client_key, 0, c->log)
        == NGX_ERROR)
    {
        goto failed;
    }

    if (ngx_quic_crypto_init(ciphers.c, &next->server, &server_key, 1, c->log)
        == NGX_ERROR)
    {
        goto failed;
    }

    ngx_explicit_memzero(current->client.secret.data,
                         current->client.secret.len);
    ngx_explicit_memzero(current->server.secret.data,
                         current->server.secret.len);

    current->client.secret.len = 0;
    current->server.secret.len = 0;

    ngx_explicit_memzero(client_key.data, client_key.len);
    ngx_explicit_memzero(server_key.data, server_key.len);

    return;

failed:

    ngx_quic_close_connection(c, NGX_ERROR);
}


void
ngx_quic_keys_cleanup(ngx_quic_keys_t *keys)
{
    ngx_uint_t           i;
    ngx_quic_secrets_t  *next;

    for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
        ngx_quic_keys_discard(keys, i);
    }

    next = &keys->next_key;

    ngx_quic_crypto_cleanup(&next->client);
    ngx_quic_crypto_cleanup(&next->server);

    if (next->client.secret.len) {
        ngx_explicit_memzero(next->client.secret.data,
                             next->client.secret.len);
        next->client.secret.len = 0;
    }

    if (next->server.secret.len) {
        ngx_explicit_memzero(next->server.secret.data,
                             next->server.secret.len);
        next->server.secret.len = 0;
    }
}


static ngx_int_t
ngx_quic_create_packet(ngx_quic_header_t *pkt, ngx_str_t *res)
{
    u_char             *pnp, *sample;
    ngx_str_t           ad, out;
    ngx_uint_t          i;
    ngx_quic_secret_t  *secret;
    u_char              nonce[NGX_QUIC_IV_LEN], mask[NGX_QUIC_HP_LEN];

    ad.data = res->data;
    ad.len = ngx_quic_create_header(pkt, ad.data, &pnp);

    out.len = pkt->payload.len + NGX_QUIC_TAG_LEN;
    out.data = res->data + ad.len;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ad len:%uz %xV", ad.len, &ad);
#endif

    secret = &pkt->keys->secrets[pkt->level].server;

    ngx_memcpy(nonce, secret->iv.data, secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), pkt->number);

    if (ngx_quic_crypto_seal(secret, &out, nonce, &pkt->payload, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sample = &out.data[4 - pkt->num_len];
    if (ngx_quic_crypto_hp(secret, mask, sample, pkt->log) != NGX_OK) {
        return NGX_ERROR;
    }

    /* RFC 9001, 5.4.1.  Header Protection Application */
    ad.data[0] ^= mask[0] & ngx_quic_pkt_hp_mask(pkt->flags);

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
    static ngx_quic_md_t  key = ngx_quic_md(
        "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e");
    static const u_char   nonce[NGX_QUIC_IV_LEN] = {
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb
    };
    static ngx_str_t      in = ngx_string("");

    ad.data = res->data;
    ad.len = ngx_quic_create_retry_itag(pkt, ad.data, &start);

    itag.data = ad.data + ad.len;
    itag.len = NGX_QUIC_TAG_LEN;

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic retry itag len:%uz %xV", ad.len, &ad);
#endif

    if (ngx_quic_ciphers(NGX_QUIC_INITIAL_CIPHER, &ciphers) == NGX_ERROR) {
        return NGX_ERROR;
    }

    secret.iv.len = NGX_QUIC_IV_LEN;

    if (ngx_quic_crypto_init(ciphers.c, &secret, &key, 1, pkt->log)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_crypto_seal(&secret, &itag, nonce, &in, &ad, pkt->log)
        != NGX_OK)
    {
        ngx_quic_crypto_cleanup(&secret);
        return NGX_ERROR;
    }

    ngx_quic_crypto_cleanup(&secret);

    res->len = itag.data + itag.len - start;
    res->data = start;

    return NGX_OK;
}


ngx_int_t
ngx_quic_derive_key(ngx_log_t *log, const char *label, ngx_str_t *secret,
    ngx_str_t *salt, u_char *out, size_t len)
{
    size_t         is_len, info_len;
    uint8_t       *p;
    const EVP_MD  *digest;

    uint8_t        is[SHA256_DIGEST_LENGTH];
    uint8_t        info[20];

    digest = EVP_sha256();
    is_len = SHA256_DIGEST_LENGTH;

    if (ngx_hkdf_extract(is, &is_len, digest, secret->data, secret->len,
                         salt->data, salt->len)
        != NGX_OK)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "ngx_hkdf_extract(%s) failed", label);
        return NGX_ERROR;
    }

    info[0] = 0;
    info[1] = len;
    info[2] = ngx_strlen(label);

    info_len = 2 + 1 + info[2] + 1;

    if (info_len >= 20) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "ngx_quic_create_key label \"%s\" too long", label);
        return NGX_ERROR;
    }

    p = ngx_cpymem(&info[3], label, info[2]);
    *p = '\0';

    if (ngx_hkdf_expand(out, len, digest, is, is_len, info, info_len) != NGX_OK)
    {
        ngx_ssl_error(NGX_LOG_INFO, log, 0,
                      "ngx_hkdf_expand(%s) failed", label);
        return NGX_ERROR;
    }

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


void
ngx_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn)
{
    nonce[len - 8] ^= (pn >> 56) & 0x3f;
    nonce[len - 7] ^= (pn >> 48) & 0xff;
    nonce[len - 6] ^= (pn >> 40) & 0xff;
    nonce[len - 5] ^= (pn >> 32) & 0xff;
    nonce[len - 4] ^= (pn >> 24) & 0xff;
    nonce[len - 3] ^= (pn >> 16) & 0xff;
    nonce[len - 2] ^= (pn >> 8) & 0xff;
    nonce[len - 1] ^= pn & 0xff;
}


ngx_int_t
ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_str_t *res)
{
    if (ngx_quic_pkt_retry(pkt->flags)) {
        return ngx_quic_create_retry_packet(pkt, res);
    }

    return ngx_quic_create_packet(pkt, res);
}


ngx_int_t
ngx_quic_decrypt(ngx_quic_header_t *pkt, uint64_t *largest_pn)
{
    u_char             *p, *sample;
    size_t              len;
    uint64_t            pn, lpn;
    ngx_int_t           pnl;
    ngx_str_t           in, ad;
    ngx_uint_t          key_phase;
    ngx_quic_secret_t  *secret;
    uint8_t             nonce[NGX_QUIC_IV_LEN], mask[NGX_QUIC_HP_LEN];

    secret = &pkt->keys->secrets[pkt->level].client;

    p = pkt->raw->pos;
    len = pkt->data + pkt->len - p;

    /*
     * RFC 9001, 5.4.2. Header Protection Sample
     *           5.4.3. AES-Based Header Protection
     *           5.4.4. ChaCha20-Based Header Protection
     *
     * the Packet Number field is assumed to be 4 bytes long
     * AES and ChaCha20 algorithms sample 16 bytes
     */

    if (len < NGX_QUIC_TAG_LEN + 4) {
        return NGX_DECLINED;
    }

    sample = p + 4;

    /* header protection */

    if (ngx_quic_crypto_hp(secret, mask, sample, pkt->log) != NGX_OK) {
        return NGX_DECLINED;
    }

    pkt->flags ^= mask[0] & ngx_quic_pkt_hp_mask(pkt->flags);

    if (ngx_quic_short_pkt(pkt->flags)) {
        key_phase = (pkt->flags & NGX_QUIC_PKT_KPHASE) != 0;

        if (key_phase != pkt->key_phase) {
            if (pkt->keys->next_key.client.ctx != NULL) {
                secret = &pkt->keys->next_key.client;
                pkt->key_update = 1;

            } else {
                /*
                 * RFC 9001,  6.3. Timing of Receive Key Generation.
                 *
                 * Trial decryption to avoid timing side-channel.
                 */
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                               "quic next key missing");
            }
        }
    }

    lpn = *largest_pn;

    pnl = (pkt->flags & 0x03) + 1;
    pn = ngx_quic_parse_pn(&p, pnl, &mask[1], &lpn);

    pkt->pn = pn;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx clearflags:%xd", pkt->flags);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx number:%uL len:%xi", pn, pnl);

    /* packet protection */

    in.data = p;
    in.len = len - pnl;

    ad.len = p - pkt->data;
    ad.data = pkt->plaintext;

    ngx_memcpy(ad.data, pkt->data, ad.len);
    ad.data[0] = pkt->flags;

    do {
        ad.data[ad.len - pnl] = pn >> (8 * (pnl - 1)) % 256;
    } while (--pnl);

    ngx_memcpy(nonce, secret->iv.data, secret->iv.len);
    ngx_quic_compute_nonce(nonce, sizeof(nonce), pn);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ad len:%uz %xV", ad.len, &ad);
#endif

    pkt->payload.len = in.len - NGX_QUIC_TAG_LEN;
    pkt->payload.data = pkt->plaintext + ad.len;

    if (ngx_quic_crypto_open(secret, &pkt->payload, nonce, &in, &ad, pkt->log)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (pkt->payload.len == 0) {
        /*
         * RFC 9000, 12.4.  Frames and Frame Types
         *
         * An endpoint MUST treat receipt of a packet containing no
         * frames as a connection error of type PROTOCOL_VIOLATION.
         */
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic zero-length packet");
        pkt->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR;
    }

    if (pkt->flags & ngx_quic_pkt_rb_mask(pkt->flags)) {
        /*
         * RFC 9000, Reserved Bits
         *
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

#if defined(NGX_QUIC_DEBUG_CRYPTO) && defined(NGX_QUIC_DEBUG_PACKETS)
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet payload len:%uz %xV",
                   pkt->payload.len, &pkt->payload);
#endif

    *largest_pn = lpn;

    return NGX_OK;
}
