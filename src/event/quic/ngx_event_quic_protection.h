
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_event_quic_transport.h>


#define NGX_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)

/* RFC 5116, 5.1/5.3 and RFC 8439, 2.3/2.5 for all supported ciphers */
#define NGX_QUIC_IV_LEN               12
#define NGX_QUIC_TAG_LEN              16

/* largest hash used in TLS is SHA-384 */
#define NGX_QUIC_MAX_MD_SIZE          48


#ifdef OPENSSL_IS_BORINGSSL
#define ngx_quic_cipher_t             EVP_AEAD
#define ngx_quic_crypto_ctx_t         EVP_AEAD_CTX
#else
#define ngx_quic_cipher_t             EVP_CIPHER
#define ngx_quic_crypto_ctx_t         EVP_CIPHER_CTX
#endif


typedef struct {
    size_t                    len;
    u_char                    data[NGX_QUIC_MAX_MD_SIZE];
} ngx_quic_md_t;


typedef struct {
    size_t                    len;
    u_char                    data[NGX_QUIC_IV_LEN];
} ngx_quic_iv_t;


typedef struct {
    ngx_quic_md_t             secret;
    ngx_quic_iv_t             iv;
    ngx_quic_md_t             hp;
    ngx_quic_crypto_ctx_t    *ctx;
    EVP_CIPHER_CTX           *hp_ctx;
} ngx_quic_secret_t;


typedef struct {
    ngx_quic_secret_t         client;
    ngx_quic_secret_t         server;
} ngx_quic_secrets_t;


struct ngx_quic_keys_s {
    ngx_quic_secrets_t        secrets[NGX_QUIC_ENCRYPTION_LAST];
    ngx_quic_secrets_t        next_key;
    ngx_uint_t                cipher;
};


typedef struct {
    const ngx_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} ngx_quic_ciphers_t;


typedef struct {
    size_t                    out_len;
    u_char                   *out;

    size_t                    prk_len;
    const uint8_t            *prk;

    size_t                    label_len;
    const u_char             *label;
} ngx_quic_hkdf_t;

#define ngx_quic_hkdf_set(seq, _label, _out, _prk)                            \
    (seq)->out_len = (_out)->len; (seq)->out = (_out)->data;                  \
    (seq)->prk_len = (_prk)->len, (seq)->prk = (_prk)->data,                  \
    (seq)->label_len = (sizeof(_label) - 1); (seq)->label = (u_char *)(_label);


ngx_int_t ngx_quic_keys_set_initial_secret(ngx_quic_keys_t *keys,
    ngx_str_t *secret, ngx_log_t *log);
ngx_int_t ngx_quic_keys_set_encryption_secret(ngx_log_t *log,
    ngx_uint_t is_write, ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
ngx_uint_t ngx_quic_keys_available(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level, ngx_uint_t is_write);
void ngx_quic_keys_discard(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_switch(ngx_connection_t *c, ngx_quic_keys_t *keys);
void ngx_quic_keys_update(ngx_event_t *ev);
void ngx_quic_keys_cleanup(ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_str_t *res);
ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, uint64_t *largest_pn);
void ngx_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn);
ngx_int_t ngx_quic_ciphers(ngx_uint_t id, ngx_quic_ciphers_t *ciphers);
ngx_int_t ngx_quic_crypto_init(const ngx_quic_cipher_t *cipher,
    ngx_quic_secret_t *s, ngx_quic_md_t *key, ngx_int_t enc, ngx_log_t *log);
ngx_int_t ngx_quic_crypto_seal(ngx_quic_secret_t *s, ngx_str_t *out,
    u_char *nonce, ngx_str_t *in, ngx_str_t *ad, ngx_log_t *log);
void ngx_quic_crypto_cleanup(ngx_quic_secret_t *s);
ngx_int_t ngx_quic_hkdf_expand(ngx_quic_hkdf_t *hkdf, const EVP_MD *digest,
    ngx_log_t *log);


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
