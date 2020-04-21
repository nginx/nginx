
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)


typedef struct ngx_quic_secret_s {
    ngx_str_t                 secret;
    ngx_str_t                 key;
    ngx_str_t                 iv;
    ngx_str_t                 hp;
} ngx_quic_secret_t;


typedef struct {
    ngx_quic_secret_t         client;
    ngx_quic_secret_t         server;
} ngx_quic_secrets_t;


ngx_int_t ngx_quic_set_initial_secret(ngx_pool_t *pool,
    ngx_quic_secret_t *client, ngx_quic_secret_t *server,
    ngx_str_t *secret);

int ngx_quic_set_encryption_secret(ngx_pool_t *pool, ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *secret, size_t secret_len,
    ngx_quic_secret_t *peer_secret);

ngx_int_t ngx_quic_key_update(ngx_connection_t *c,
    ngx_quic_secrets_t *current, ngx_quic_secrets_t *next);

ssize_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
     ngx_str_t *res);

ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, ngx_ssl_conn_t *ssl_conn,
     uint64_t *largest_pn);


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
