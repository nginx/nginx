
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>


#define quic_version        0xff000018  /* draft-24 (ngtcp2) */
//#define quic_version      0xff00001b  /* draft-27 (FFN 76) */


typedef struct {
    /* configurable */
    ngx_msec_t          max_idle_timeout;
    ngx_msec_t          max_ack_delay;

    ngx_uint_t          max_packet_size;
    ngx_uint_t          initial_max_data;
    ngx_uint_t          initial_max_stream_data_bidi_local;
    ngx_uint_t          initial_max_stream_data_bidi_remote;
    ngx_uint_t          initial_max_stream_data_uni;
    ngx_uint_t          initial_max_streams_bidi;
    ngx_uint_t          initial_max_streams_uni;
    ngx_uint_t          ack_delay_exponent;
    ngx_uint_t          disable_active_migration;
    ngx_uint_t          active_connection_id_limit;

    /* TODO */
    ngx_uint_t          original_connection_id;
    u_char              stateless_reset_token[16];
    void               *preferred_address;
} ngx_quic_tp_t;


struct ngx_quic_stream_s {
    uint64_t            id;
    ngx_uint_t          unidirectional:1;
    ngx_connection_t   *parent;
    void               *data;
};


void ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_msec_t timeout, ngx_connection_handler_pt handler);
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
