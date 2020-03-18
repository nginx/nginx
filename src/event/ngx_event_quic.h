
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>


#define quic_version        0xff000018  /* draft-24 (ngtcp2) */
//#define quic_version      0xff00001b  /* draft-27 (FFN 76) */


struct ngx_quic_stream_s {
    uint64_t            id;
    ngx_uint_t          unidirectional:1;
    ngx_connection_t   *parent;
    void               *data;
};


void ngx_quic_init_ssl_methods(SSL_CTX* ctx);

void ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_msec_t timeout,
    ngx_connection_handler_pt handler);
ngx_connection_t *ngx_quic_create_uni_stream(ngx_connection_t *c);


/********************************* DEBUG *************************************/

#if (NGX_DEBUG)

#define ngx_quic_hexdump(log, fmt, data, len, ...)                            \
do {                                                                          \
    ngx_int_t  m;                                                             \
    u_char     buf[2048];                                                     \
                                                                              \
    if (log->log_level & NGX_LOG_DEBUG_EVENT) {                               \
        m = ngx_hex_dump(buf, (u_char *) data, ngx_min(len, 1024)) - buf;     \
        ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,                            \
                   "%s: " fmt " %*s%s, len: %uz",                             \
                   __FUNCTION__,  __VA_ARGS__, m, buf,                        \
                   len < 2048 ? "" : "...", len);                             \
    }                                                                         \
} while (0)

#else

#define ngx_quic_hexdump(log, fmt, data, len, ...)

#endif

#define ngx_quic_hexdump0(log, fmt, data, len)                                \
    ngx_quic_hexdump(log, fmt "%s", data, len, "")                            \


#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
