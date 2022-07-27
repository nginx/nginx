
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_event_quic_transport.h>


#define NGX_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)

/* RFC 5116, 5.1 and RFC 8439, 2.3 for all supported ciphers */
#define NGX_QUIC_IV_LEN               12

/* largest hash used in TLS is SHA-384 */
#define NGX_QUIC_MAX_MD_SIZE          48


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
    ngx_quic_md_t             key;
    ngx_quic_iv_t             iv;
    ngx_quic_md_t             hp;
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


ngx_int_t ngx_quic_keys_set_initial_secret(ngx_quic_keys_t *keys,
    ngx_str_t *secret, ngx_log_t *log);
ngx_int_t ngx_quic_keys_set_encryption_secret(ngx_log_t *log,
    ngx_uint_t is_write, ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
ngx_uint_t ngx_quic_keys_available(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_discard(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_switch(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_keys_update(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_str_t *res);
ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, uint64_t *largest_pn);


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
