
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_QUIC_DRAFT_VERSION               27
#define NGX_QUIC_VERSION  (0xff000000 + NGX_QUIC_DRAFT_VERSION)

#define NGX_QUIC_MAX_SHORT_HEADER            25 /* 1 flags + 20 dcid + 4 pn */
#define NGX_QUIC_MAX_LONG_HEADER             56
    /* 1 flags + 4 version + 2 x (1 + 20) s/dcid + 4 pn + 4 len + token len */

#define NGX_QUIC_DEFAULT_MAX_PACKET_SIZE     65527
#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       25

#define NGX_QUIC_HARDCODED_PTO               1000 /* 1s, TODO: collect */
#define NGX_QUIC_CC_MIN_INTERVAL             1000 /* 1s */

#define NGX_QUIC_MIN_INITIAL_SIZE            1200

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02

#define NGX_QUIC_STREAM_BUFSIZE              16384


typedef struct {
    /* configurable */
    ngx_msec_t                 max_idle_timeout;
    ngx_msec_t                 max_ack_delay;

    size_t                     max_packet_size;
    size_t                     initial_max_data;
    size_t                     initial_max_stream_data_bidi_local;
    size_t                     initial_max_stream_data_bidi_remote;
    size_t                     initial_max_stream_data_uni;
    ngx_uint_t                 initial_max_streams_bidi;
    ngx_uint_t                 initial_max_streams_uni;
    ngx_uint_t                 ack_delay_exponent;
    ngx_uint_t                 disable_active_migration;
    ngx_uint_t                 active_connection_id_limit;

    /* TODO */
    ngx_uint_t                 original_connection_id;
    u_char                     stateless_reset_token[16];
    void                      *preferred_address;
} ngx_quic_tp_t;


typedef struct {
    uint64_t                   sent;
    uint64_t                   received;
    ngx_queue_t                frames;   /* reorder queue */
    size_t                     total;    /* size of buffered data */
} ngx_quic_frames_stream_t;


struct ngx_quic_stream_s {
    ngx_rbtree_node_t          node;
    ngx_connection_t          *parent;
    ngx_connection_t          *c;
    uint64_t                   id;
    ngx_buf_t                 *b;
    ngx_quic_frames_stream_t   fs;
};


void ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_connection_handler_pt handler);
ngx_connection_t *ngx_quic_create_uni_stream(ngx_connection_t *c);


/********************************* DEBUG *************************************/

//#define NGX_QUIC_DEBUG_PACKETS       /* dump packet contents */
//#define NGX_QUIC_DEBUG_FRAMES        /* dump frames contents */
//#define NGX_QUIC_DEBUG_FRAMES_ALLOC  /* log frames alloc/reuse/free */
//#define NGX_QUIC_DEBUG_CRYPTO


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
