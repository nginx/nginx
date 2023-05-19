
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_TOKENS_H_INCLUDED_
#define _NGX_EVENT_QUIC_TOKENS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

/* RFC 3602, 2.1 and 2.4 for AES-CBC block size and IV length */
#define NGX_QUIC_AES_256_CBC_IV_LEN          16
#define NGX_QUIC_AES_256_CBC_BLOCK_SIZE      16

#define NGX_QUIC_TOKEN_BUF_SIZE             (NGX_QUIC_AES_256_CBC_IV_LEN      \
                                             + NGX_QUIC_MAX_TOKEN_SIZE        \
                                             + NGX_QUIC_AES_256_CBC_BLOCK_SIZE)


ngx_int_t ngx_quic_new_sr_token(ngx_connection_t *c, ngx_str_t *cid,
    u_char *secret, u_char *token);
ngx_int_t ngx_quic_new_token(ngx_log_t *log, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, ngx_str_t *token, ngx_str_t *odcid,
    time_t expires, ngx_uint_t is_retry);
ngx_int_t ngx_quic_validate_token(ngx_connection_t *c,
    u_char *key, ngx_quic_header_t *pkt);

#endif /* _NGX_EVENT_QUIC_TOKENS_H_INCLUDED_ */
