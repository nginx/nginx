
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


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


typedef enum {
    NGX_QUIC_STREAM_SEND_READY = 0,
    NGX_QUIC_STREAM_SEND_SEND,
    NGX_QUIC_STREAM_SEND_DATA_SENT,
    NGX_QUIC_STREAM_SEND_DATA_RECVD,
    NGX_QUIC_STREAM_SEND_RESET_SENT,
    NGX_QUIC_STREAM_SEND_RESET_RECVD
} ngx_quic_stream_send_state_e;


typedef enum {
    NGX_QUIC_STREAM_RECV_RECV = 0,
    NGX_QUIC_STREAM_RECV_SIZE_KNOWN,
    NGX_QUIC_STREAM_RECV_DATA_RECVD,
    NGX_QUIC_STREAM_RECV_DATA_READ,
    NGX_QUIC_STREAM_RECV_RESET_RECVD,
    NGX_QUIC_STREAM_RECV_RESET_READ
} ngx_quic_stream_recv_state_e;


typedef struct {
    ngx_ssl_t                 *ssl;

    ngx_flag_t                 retry;
    ngx_flag_t                 gso_enabled;
    ngx_flag_t                 disable_active_migration;
    ngx_msec_t                 timeout;
    ngx_str_t                  host_key;
    size_t                     mtu;
    size_t                     stream_buffer_size;
    ngx_uint_t                 max_concurrent_streams_bidi;
    ngx_uint_t                 max_concurrent_streams_uni;
    ngx_uint_t                 active_connection_id_limit;
    ngx_int_t                  stream_close_code;
    ngx_int_t                  stream_reject_code_uni;
    ngx_int_t                  stream_reject_code_bidi;

    u_char                     av_token_key[NGX_QUIC_AV_KEY_LEN];
    u_char                     sr_token_key[NGX_QUIC_SR_KEY_LEN];
} ngx_quic_conf_t;


struct ngx_quic_stream_s {
    ngx_rbtree_node_t          node;
    ngx_queue_t                queue;
    ngx_connection_t          *parent;
    ngx_connection_t          *connection;
    uint64_t                   id;
    uint64_t                   acked;
    uint64_t                   send_max_data;
    uint64_t                   recv_max_data;
    uint64_t                   recv_offset;
    uint64_t                   recv_window;
    uint64_t                   recv_last;
    uint64_t                   final_size;
    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_uint_t                 cancelable;  /* unsigned  cancelable:1; */
    ngx_quic_stream_send_state_e  send_state;
    ngx_quic_stream_recv_state_e  recv_state;
};


void ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf);
ngx_connection_t *ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi);
void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
void ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason);
ngx_int_t ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err);
ngx_int_t ngx_quic_shutdown_stream(ngx_connection_t *c, int how);
ngx_int_t ngx_quic_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);
ngx_int_t ngx_quic_handle_write_event(ngx_event_t *wev, size_t lowat);
ngx_int_t ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t len,
    ngx_str_t *dcid);
ngx_int_t ngx_quic_derive_key(ngx_log_t *log, const char *label,
    ngx_str_t *secret, ngx_str_t *salt, u_char *out, size_t len);

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
