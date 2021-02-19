
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_event_quic_transport.h>


#define NGX_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)


ngx_quic_keys_t *ngx_quic_keys_new(ngx_pool_t *pool);
ngx_int_t ngx_quic_keys_set_initial_secret(ngx_pool_t *pool,
    ngx_quic_keys_t *keys, ngx_str_t *secret, uint32_t version);
int ngx_quic_keys_set_encryption_secret(ngx_pool_t *pool, ngx_uint_t is_write,
    ngx_quic_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
ngx_uint_t ngx_quic_keys_available(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_discard(ngx_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void ngx_quic_keys_switch(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_keys_update(ngx_connection_t *c, ngx_quic_keys_t *keys);
ngx_int_t ngx_quic_derive_key(ngx_log_t *log, const char *label,
    ngx_str_t *secret, ngx_str_t *salt, u_char *out, size_t len);
ngx_int_t ngx_quic_encrypt(ngx_quic_header_t *pkt, ngx_str_t *res);
ngx_int_t ngx_quic_decrypt(ngx_quic_header_t *pkt, uint64_t *largest_pn);


#endif /* _NGX_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
