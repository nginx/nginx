/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_CONNECTION_H_INCLUDED_
#define _NGX_EVENT_QUIC_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/* #define NGX_QUIC_DEBUG_PACKETS */  /* dump packet contents */
/* #define NGX_QUIC_DEBUG_FRAMES */   /* dump frames contents */
/* #define NGX_QUIC_DEBUG_ALLOC */    /* log frames and bufs alloc */
/* #define NGX_QUIC_DEBUG_CRYPTO */

typedef struct ngx_quic_connection_s  ngx_quic_connection_t;
typedef struct ngx_quic_server_id_s   ngx_quic_server_id_t;
typedef struct ngx_quic_client_id_s   ngx_quic_client_id_t;
typedef struct ngx_quic_send_ctx_s    ngx_quic_send_ctx_t;
typedef struct ngx_quic_socket_s      ngx_quic_socket_t;
typedef struct ngx_quic_path_s        ngx_quic_path_t;
typedef struct ngx_quic_keys_s        ngx_quic_keys_t;

#if (NGX_QUIC_OPENSSL_COMPAT)
#include <ngx_event_quic_openssl_compat.h>
#endif
#include <ngx_event_quic_transport.h>
#include <ngx_event_quic_protection.h>
#include <ngx_event_quic_frames.h>
#include <ngx_event_quic_migration.h>
#include <ngx_event_quic_connid.h>
#include <ngx_event_quic_streams.h>
#include <ngx_event_quic_ssl.h>
#include <ngx_event_quic_tokens.h>
#include <ngx_event_quic_ack.h>
#include <ngx_event_quic_output.h>
#include <ngx_event_quic_socket.h>


/* RFC 9002, 6.2.2.  Handshakes and New Paths: kInitialRtt */
#define NGX_QUIC_INITIAL_RTT                 333 /* ms */

#define NGX_QUIC_UNSET_PN                    (uint64_t) -1

#define NGX_QUIC_SEND_CTX_LAST               (NGX_QUIC_ENCRYPTION_LAST - 1)

/*  0-RTT and 1-RTT data exist in the same packet number space,
 *  so we have 3 packet number spaces:
 *
 *  0 - Initial
 *  1 - Handshake
 *  2 - 0-RTT and 1-RTT
 */
#define ngx_quic_get_send_ctx(qc, level)                                      \
    ((level) == ssl_encryption_initial) ? &((qc)->send_ctx[0])                \
        : (((level) == ssl_encryption_handshake) ? &((qc)->send_ctx[1])       \
                                                 : &((qc)->send_ctx[2]))

#define ngx_quic_get_connection(c)                                            \
    (((c)->udp) ? (((ngx_quic_socket_t *)((c)->udp))->quic) : NULL)

#define ngx_quic_get_socket(c)               ((ngx_quic_socket_t *)((c)->udp))

#define ngx_quic_init_rtt(qc)                                                 \
    (qc)->avg_rtt = NGX_QUIC_INITIAL_RTT;                                     \
    (qc)->rttvar = NGX_QUIC_INITIAL_RTT / 2;                                  \
    (qc)->min_rtt = NGX_TIMER_INFINITE;                                       \
    (qc)->first_rtt = NGX_TIMER_INFINITE;                                     \
    (qc)->latest_rtt = 0;


typedef enum {
    NGX_QUIC_PATH_IDLE = 0,
    NGX_QUIC_PATH_VALIDATING,
    NGX_QUIC_PATH_WAITING,
    NGX_QUIC_PATH_MTUD
} ngx_quic_path_state_e;


struct ngx_quic_client_id_s {
    ngx_queue_t                       queue;
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NGX_QUIC_CID_LEN_MAX];
    u_char                            sr_token[NGX_QUIC_SR_TOKEN_LEN];
    ngx_uint_t                        used;  /* unsigned  used:1; */
};


struct ngx_quic_server_id_s {
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NGX_QUIC_CID_LEN_MAX];
};


struct ngx_quic_path_s {
    ngx_queue_t                       queue;
    struct sockaddr                  *sockaddr;
    ngx_sockaddr_t                    sa;
    socklen_t                         socklen;
    ngx_quic_client_id_t             *cid;
    ngx_quic_path_state_e             state;
    ngx_msec_t                        expires;
    ngx_uint_t                        tries;
    ngx_uint_t                        tag;
    size_t                            mtu;
    size_t                            mtud;
    size_t                            max_mtu;
    off_t                             sent;
    off_t                             received;
    u_char                            challenge[2][8];
    uint64_t                          seqnum;
    uint64_t                          mtu_pnum[NGX_QUIC_PATH_RETRIES];
    ngx_str_t                         addr_text;
    u_char                            text[NGX_SOCKADDR_STRLEN];
    unsigned                          validated:1;
    unsigned                          mtu_unvalidated:1;
};


struct ngx_quic_socket_s {
    ngx_udp_connection_t              udp;
    ngx_quic_connection_t            *quic;
    ngx_queue_t                       queue;
    ngx_quic_server_id_t              sid;
    ngx_sockaddr_t                    sockaddr;
    socklen_t                         socklen;
    ngx_uint_t                        used; /* unsigned  used:1; */
};


typedef struct {
    ngx_rbtree_t                      tree;
    ngx_rbtree_node_t                 sentinel;

    ngx_queue_t                       uninitialized;
    ngx_queue_t                       free;

    uint64_t                          sent;
    uint64_t                          recv_offset;
    uint64_t                          recv_window;
    uint64_t                          recv_last;
    uint64_t                          recv_max_data;
    uint64_t                          send_offset;
    uint64_t                          send_max_data;

    uint64_t                          server_max_streams_uni;
    uint64_t                          server_max_streams_bidi;
    uint64_t                          server_streams_uni;
    uint64_t                          server_streams_bidi;

    uint64_t                          client_max_streams_uni;
    uint64_t                          client_max_streams_bidi;
    uint64_t                          client_streams_uni;
    uint64_t                          client_streams_bidi;

    ngx_uint_t                        initialized;
                                                 /* unsigned  initialized:1; */
} ngx_quic_streams_t;


typedef struct {
    size_t                            in_flight;
    size_t                            window;
    size_t                            ssthresh;
    ngx_msec_t                        recovery_start;
} ngx_quic_congestion_t;


/*
 * RFC 9000, 12.3.  Packet Numbers
 *
 *  Conceptually, a packet number space is the context in which a packet
 *  can be processed and acknowledged.  Initial packets can only be sent
 *  with Initial packet protection keys and acknowledged in packets that
 *  are also Initial packets.
 */
struct ngx_quic_send_ctx_s {
    enum ssl_encryption_level_t       level;

    ngx_quic_buffer_t                 crypto;
    uint64_t                          crypto_sent;

    uint64_t                          pnum;        /* to be sent */
    uint64_t                          largest_ack; /* received from peer */
    uint64_t                          largest_pn;  /* received from peer */

    ngx_queue_t                       frames;      /* generated frames */
    ngx_queue_t                       sending;     /* frames assigned to pkt */
    ngx_queue_t                       sent;        /* frames waiting ACK */

    uint64_t                          pending_ack; /* non sent ack-eliciting */
    uint64_t                          largest_range;
    uint64_t                          first_range;
    ngx_msec_t                        largest_received;
    ngx_msec_t                        ack_delay_start;
    ngx_uint_t                        nranges;
    ngx_quic_ack_range_t              ranges[NGX_QUIC_MAX_RANGES];
    ngx_uint_t                        send_ack;
};


struct ngx_quic_connection_s {
    uint32_t                          version;

    ngx_quic_path_t                  *path;

    ngx_queue_t                       sockets;
    ngx_queue_t                       paths;
    ngx_queue_t                       client_ids;
    ngx_queue_t                       free_sockets;
    ngx_queue_t                       free_paths;
    ngx_queue_t                       free_client_ids;

    ngx_uint_t                        nsockets;
    ngx_uint_t                        nclient_ids;
    uint64_t                          max_retired_seqnum;
    uint64_t                          client_seqnum;
    uint64_t                          server_seqnum;
    uint64_t                          path_seqnum;

    ngx_quic_tp_t                     tp;
    ngx_quic_tp_t                     ctp;

    ngx_quic_send_ctx_t               send_ctx[NGX_QUIC_SEND_CTX_LAST];

    ngx_quic_keys_t                  *keys;

    ngx_quic_conf_t                  *conf;

    ngx_event_t                       push;
    ngx_event_t                       pto;
    ngx_event_t                       close;
    ngx_event_t                       path_validation;
    ngx_event_t                       key_update;

    ngx_msec_t                        last_cc;

    ngx_msec_t                        first_rtt;
    ngx_msec_t                        latest_rtt;
    ngx_msec_t                        avg_rtt;
    ngx_msec_t                        min_rtt;
    ngx_msec_t                        rttvar;

    ngx_uint_t                        pto_count;

    ngx_queue_t                       free_frames;
    ngx_buf_t                        *free_bufs;
    ngx_buf_t                        *free_shadow_bufs;

    ngx_uint_t                        nframes;
#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_uint_t                        nbufs;
    ngx_uint_t                        nshadowbufs;
#endif

#if (NGX_QUIC_OPENSSL_COMPAT)
    ngx_quic_compat_t                *compat;
#endif

    ngx_quic_streams_t                streams;
    ngx_quic_congestion_t             congestion;

    uint64_t                          rst_pnum;    /* first on validated path */

    off_t                             received;

    ngx_uint_t                        error;
    enum ssl_encryption_level_t       error_level;
    ngx_uint_t                        error_ftype;
    const char                       *error_reason;

    ngx_uint_t                        shutdown_code;
    const char                       *shutdown_reason;

    unsigned                          error_app:1;
    unsigned                          send_timer_set:1;
    unsigned                          closing:1;
    unsigned                          shutdown:1;
    unsigned                          draining:1;
    unsigned                          key_phase:1;
    unsigned                          validated:1;
    unsigned                          client_tp_done:1;
};


ngx_int_t ngx_quic_apply_transport_params(ngx_connection_t *c,
    ngx_quic_tp_t *ctp);
void ngx_quic_discard_ctx(ngx_connection_t *c,
    enum ssl_encryption_level_t level);
void ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc);
void ngx_quic_shutdown_quic(ngx_connection_t *c);

#if (NGX_DEBUG)
void ngx_quic_connstate_dbg(ngx_connection_t *c);
#else
#define ngx_quic_connstate_dbg(c)
#endif

#endif /* _NGX_EVENT_QUIC_CONNECTION_H_INCLUDED_ */
