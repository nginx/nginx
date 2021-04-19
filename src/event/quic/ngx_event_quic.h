
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

#define NGX_QUIC_MAX_UDP_PAYLOAD_SIZE        65527

#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       25
#define NGX_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NGX_QUIC_SR_KEY_LEN                  32
#define NGX_QUIC_AV_KEY_LEN                  32

#define NGX_QUIC_SR_TOKEN_LEN                16

#define NGX_QUIC_MIN_INITIAL_SIZE            1200

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02

#define NGX_QUIC_STREAM_BUFSIZE              65536


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


typedef struct ngx_quic_frames_stream_s  ngx_quic_frames_stream_t;

struct ngx_quic_stream_s {
    ngx_rbtree_node_t          node;
    ngx_connection_t          *parent;
    ngx_connection_t          *connection;
    uint64_t                   id;
    uint64_t                   acked;
    uint64_t                   send_max_data;
    ngx_buf_t                 *b;
    ngx_quic_frames_stream_t  *fs;
    ngx_uint_t                 cancelable;  /* unsigned  cancelable:1; */
};


void ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf);
ngx_connection_t *ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi);
void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
void ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
ngx_int_t ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err);
uint32_t ngx_quic_version(ngx_connection_t *c);
ngx_int_t ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t len,
    ngx_str_t *dcid);
ngx_int_t ngx_quic_derive_key(ngx_log_t *log, const char *label,
    ngx_str_t *secret, ngx_str_t *salt, u_char *out, size_t len);

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
