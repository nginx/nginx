
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_
#define _NGX_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_quic_compat_s  ngx_quic_compat_t;


enum ssl_encryption_level_t {
    ssl_encryption_initial = 0,
    ssl_encryption_early_data,
    ssl_encryption_handshake,
    ssl_encryption_application
};


typedef struct ssl_quic_method_st {
    int (*set_read_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                           const SSL_CIPHER *cipher,
                           const uint8_t *rsecret, size_t secret_len);
    int (*set_write_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                            const SSL_CIPHER *cipher,
                            const uint8_t *wsecret, size_t secret_len);
    int (*add_handshake_data)(SSL *ssl, enum ssl_encryption_level_t level,
                              const uint8_t *data, size_t len);
    int (*flush_flight)(SSL *ssl);
    int (*send_alert)(SSL *ssl, enum ssl_encryption_level_t level,
                      uint8_t alert);
} SSL_QUIC_METHOD;


ngx_int_t ngx_quic_compat_init(ngx_conf_t *cf, SSL_CTX *ctx);

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method);
int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *data, size_t len);
int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
    size_t params_len);
void SSL_get_peer_quic_transport_params(const SSL *ssl,
    const uint8_t **out_params, size_t *out_params_len);

#endif /* _NGX_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_ */
