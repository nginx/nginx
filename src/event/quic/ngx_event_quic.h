
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_QUIC_DRAFT_VERSION
#define NGX_QUIC_DRAFT_VERSION               29
#endif

#define NGX_QUIC_MAX_SHORT_HEADER            25 /* 1 flags + 20 dcid + 4 pn */
#define NGX_QUIC_MAX_LONG_HEADER             56
    /* 1 flags + 4 version + 2 x (1 + 20) s/dcid + 4 pn + 4 len + token len */

#define NGX_QUIC_MAX_UDP_PAYLOAD_SIZE        65527
#define NGX_QUIC_MAX_UDP_PAYLOAD_OUT         1252
#define NGX_QUIC_MAX_UDP_PAYLOAD_OUT6        1232

#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       25
#define NGX_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NGX_QUIC_SR_KEY_LEN                  32
#define NGX_QUIC_AV_KEY_LEN                  32

#define NGX_QUIC_RETRY_TOKEN_LIFETIME          3 /* seconds */
#define NGX_QUIC_NEW_TOKEN_LIFETIME          600 /* seconds */
#define NGX_QUIC_RETRY_BUFFER_SIZE           256
    /* 1 flags + 4 version + 3 x (1 + 20) s/o/dcid + itag + token(64) */
#define NGX_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

/* quic-recovery, section 6.2.2, kInitialRtt */
#define NGX_QUIC_INITIAL_RTT                 333 /* ms */

/* quic-recovery, section 6.1.1, Packet Threshold */
#define NGX_QUIC_PKT_THR                     3 /* packets */
/* quic-recovery, section 6.1.2, Time Threshold */
#define NGX_QUIC_TIME_THR                    1.125
#define NGX_QUIC_TIME_GRANULARITY            1 /* ms */

#define NGX_QUIC_CC_MIN_INTERVAL             1000 /* 1s */

#define NGX_QUIC_MIN_INITIAL_SIZE            1200

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02

#define NGX_QUIC_STREAM_BUFSIZE              65536

#define NGX_QUIC_MAX_CID_LEN                 20
#define NGX_QUIC_SERVER_CID_LEN              NGX_QUIC_MAX_CID_LEN

#define NGX_QUIC_SR_TOKEN_LEN                16

#define NGX_QUIC_MAX_SERVER_IDS              8

#define NGX_QUIC_BUFFER_SIZE                 4096

#define ngx_quic_get_connection(c)           ((ngx_quic_connection_t *)(c)->udp)


typedef struct {
    /* configurable */
    ngx_msec_t                 max_idle_timeout;
    ngx_msec_t                 max_ack_delay;

    size_t                     max_udp_payload_size;
    size_t                     initial_max_data;
    size_t                     initial_max_stream_data_bidi_local;
    size_t                     initial_max_stream_data_bidi_remote;
    size_t                     initial_max_stream_data_uni;
    ngx_uint_t                 initial_max_streams_bidi;
    ngx_uint_t                 initial_max_streams_uni;
    ngx_uint_t                 ack_delay_exponent;
    ngx_uint_t                 active_connection_id_limit;
    ngx_flag_t                 disable_active_migration;
    ngx_str_t                  original_dcid;
    ngx_str_t                  initial_scid;
    ngx_str_t                  retry_scid;
    u_char                     sr_token[NGX_QUIC_SR_TOKEN_LEN];

    /* TODO */
    void                      *preferred_address;
} ngx_quic_tp_t;


typedef struct {
    ngx_ssl_t                 *ssl;
    ngx_quic_tp_t              tp;
    ngx_flag_t                 retry;
    ngx_flag_t                 require_alpn;
    ngx_str_t                  host_key;
    u_char                     av_token_key[NGX_QUIC_AV_KEY_LEN];
    u_char                     sr_token_key[NGX_QUIC_SR_KEY_LEN];
} ngx_quic_conf_t;


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
    uint64_t                   acked;
    uint64_t                   send_max_data;
    ngx_buf_t                 *b;
    ngx_quic_frames_stream_t   fs;
};


typedef struct ngx_quic_keys_s  ngx_quic_keys_t;


void ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf);
ngx_connection_t *ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi);
void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
ngx_int_t ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err);
uint32_t ngx_quic_version(ngx_connection_t *c);
ngx_int_t ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t len,
    ngx_str_t *dcid);


/********************************* DEBUG *************************************/

/* #define NGX_QUIC_DEBUG_PACKETS */      /* dump packet contents */
/* #define NGX_QUIC_DEBUG_FRAMES */       /* dump frames contents */
/* #define NGX_QUIC_DEBUG_ALLOC */        /* log frames and bufs alloc */
/* #define NGX_QUIC_DEBUG_CRYPTO */

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
