
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


typedef struct ngx_quic_secret_s {
    ngx_str_t                 secret;
    ngx_str_t                 key;
    ngx_str_t                 iv;
    ngx_str_t                 hp;
} ngx_quic_secret_t;


typedef struct {
    ngx_quic_secret_t         in;
    ngx_quic_secret_t         hs;
    ngx_quic_secret_t         ad;
} ngx_quic_peer_secrets_t;


typedef struct {
    ngx_quic_peer_secrets_t   client;
    ngx_quic_peer_secrets_t   server;
} ngx_quic_secrets_t;


ngx_int_t ngx_quic_set_initial_secret(ngx_pool_t *pool,
    ngx_quic_secrets_t *secrets, ngx_str_t *secret);

int ngx_quic_set_encryption_secret(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *secret, size_t secret_len,
    ngx_quic_peer_secrets_t *qsec);

ssize_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
     ngx_str_t *res);

ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn);


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
