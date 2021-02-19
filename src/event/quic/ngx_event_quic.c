
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_transport.h>
#include <ngx_event_quic_protection.h>
#include <ngx_sha1.h>


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

#define ngx_quic_lost_threshold(qc)                                           \
    ngx_max(NGX_QUIC_TIME_THR * ngx_max((qc)->latest_rtt, (qc)->avg_rtt),     \
            NGX_QUIC_TIME_GRANULARITY)

#define NGX_QUIC_SEND_CTX_LAST  (NGX_QUIC_ENCRYPTION_LAST - 1)

/*
 * 7.4.  Cryptographic Message Buffering
 *       Implementations MUST support buffering at least 4096 bytes of data
 */
#define NGX_QUIC_MAX_BUFFERED    65535

#define NGX_QUIC_STREAM_GONE     (void *) -1

#define NGX_QUIC_UNSET_PN        (uint64_t) -1

/*
 * Endpoints MUST discard packets that are too small to be valid QUIC
 * packets.  With the set of AEAD functions defined in [QUIC-TLS],
 * packets that are smaller than 21 bytes are never valid.
 */
#define NGX_QUIC_MIN_PKT_LEN     21

#define NGX_QUIC_MIN_SR_PACKET   43 /* 5 random + 16 srt + 22 padding */
#define NGX_QUIC_MAX_SR_PACKET   1200

#define NGX_QUIC_MAX_ACK_GAP     2


typedef struct {
    ngx_rbtree_t                      tree;
    ngx_rbtree_node_t                 sentinel;

    uint64_t                          received;
    uint64_t                          sent;
    uint64_t                          recv_max_data;
    uint64_t                          send_max_data;

    uint64_t                          server_max_streams_uni;
    uint64_t                          server_max_streams_bidi;
    uint64_t                          server_streams_uni;
    uint64_t                          server_streams_bidi;

    uint64_t                          client_max_streams_uni;
    uint64_t                          client_max_streams_bidi;
    uint64_t                          client_streams_uni;
    uint64_t                          client_streams_bidi;
} ngx_quic_streams_t;


typedef struct {
    size_t                            in_flight;
    size_t                            window;
    size_t                            ssthresh;
    ngx_msec_t                        recovery_start;
} ngx_quic_congestion_t;


/*
 * 12.3.  Packet Numbers
 *
 *  Conceptually, a packet number space is the context in which a packet
 *  can be processed and acknowledged.  Initial packets can only be sent
 *  with Initial packet protection keys and acknowledged in packets which
 *  are also Initial packets.
*/
typedef struct {
    enum ssl_encryption_level_t       level;

    uint64_t                          pnum;        /* to be sent */
    uint64_t                          largest_ack; /* received from peer */
    uint64_t                          largest_pn;  /* received from peer */

    ngx_queue_t                       frames;
    ngx_queue_t                       sent;

    uint64_t                          pending_ack; /* non sent ack-eliciting */
    uint64_t                          largest_range;
    uint64_t                          first_range;
    ngx_msec_t                        largest_received;
    ngx_msec_t                        ack_delay_start;
    ngx_uint_t                        nranges;
    ngx_quic_ack_range_t              ranges[NGX_QUIC_MAX_RANGES];
    ngx_uint_t                        send_ack;
} ngx_quic_send_ctx_t;


typedef struct {
    ngx_udp_connection_t              udp;

    uint32_t                          version;
    ngx_str_t                         scid;  /* initial client ID */
    ngx_str_t                         dcid;  /* server (our own) ID */
    ngx_str_t                         odcid; /* original server ID */

    struct sockaddr                  *sockaddr;
    socklen_t                         socklen;

    ngx_queue_t                       client_ids;
    ngx_queue_t                       server_ids;
    ngx_queue_t                       free_client_ids;
    ngx_queue_t                       free_server_ids;
    ngx_uint_t                        nclient_ids;
    ngx_uint_t                        nserver_ids;
    uint64_t                          max_retired_seqnum;
    uint64_t                          client_seqnum;
    uint64_t                          server_seqnum;

    ngx_uint_t                        client_tp_done;
    ngx_quic_tp_t                     tp;
    ngx_quic_tp_t                     ctp;

    ngx_quic_send_ctx_t               send_ctx[NGX_QUIC_SEND_CTX_LAST];

    ngx_quic_frames_stream_t          crypto[NGX_QUIC_ENCRYPTION_LAST];

    ngx_quic_keys_t                  *keys;

    ngx_quic_conf_t                  *conf;

    ngx_event_t                       push;
    ngx_event_t                       pto;
    ngx_event_t                       close;
    ngx_msec_t                        last_cc;

    ngx_msec_t                        latest_rtt;
    ngx_msec_t                        avg_rtt;
    ngx_msec_t                        min_rtt;
    ngx_msec_t                        rttvar;

    ngx_uint_t                        pto_count;

    ngx_queue_t                       free_frames;
    ngx_chain_t                      *free_bufs;
    ngx_buf_t                        *free_shadow_bufs;

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_uint_t                        nframes;
    ngx_uint_t                        nbufs;
#endif

    ngx_quic_streams_t                streams;
    ngx_quic_congestion_t             congestion;
    off_t                             received;

    ngx_uint_t                        error;
    enum ssl_encryption_level_t       error_level;
    ngx_uint_t                        error_ftype;
    const char                       *error_reason;

    unsigned                          error_app:1;
    unsigned                          send_timer_set:1;
    unsigned                          closing:1;
    unsigned                          draining:1;
    unsigned                          key_phase:1;
    unsigned                          validated:1;
} ngx_quic_connection_t;


typedef struct {
    ngx_queue_t                       queue;
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NGX_QUIC_CID_LEN_MAX];
    u_char                            sr_token[NGX_QUIC_SR_TOKEN_LEN];
} ngx_quic_client_id_t;


typedef struct {
    ngx_udp_connection_t              udp;
    ngx_queue_t                       queue;
    uint64_t                          seqnum;
    size_t                            len;
    u_char                            id[NGX_QUIC_CID_LEN_MAX];
} ngx_quic_server_id_t;


typedef ngx_int_t (*ngx_quic_frame_handler_pt)(ngx_connection_t *c,
    ngx_quic_frame_t *frame, void *data);


#if BORINGSSL_API_VERSION >= 10
static int ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
static int ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
#else
static int ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
#endif

static int ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len);
static int ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn);
static int ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, uint8_t alert);


static ngx_int_t ngx_quic_apply_transport_params(ngx_connection_t *c,
    ngx_quic_tp_t *ctp);
static ngx_quic_connection_t *ngx_quic_new_connection(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_send_stateless_reset(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_new_sr_token(ngx_connection_t *c, ngx_str_t *cid,
    u_char *secret, u_char *token);
static ngx_int_t ngx_quic_process_stateless_reset(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_negotiate_version(ngx_connection_t *c,
    ngx_quic_header_t *inpkt);
static ngx_int_t ngx_quic_create_server_id(ngx_connection_t *c, u_char *id);
#if (NGX_QUIC_BPF)
static ngx_int_t ngx_quic_bpf_attach_id(ngx_connection_t *c, u_char *id);
#endif
static ngx_int_t ngx_quic_send_retry(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_new_token(ngx_connection_t *c, u_char *key,
    ngx_str_t *token, ngx_str_t *odcid, time_t expires, ngx_uint_t is_retry);
static void ngx_quic_address_hash(ngx_connection_t *c, ngx_uint_t no_port,
    u_char buf[20]);
static ngx_int_t ngx_quic_validate_token(ngx_connection_t *c,
    u_char *key, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);
static ngx_inline size_t ngx_quic_max_udp_payload(ngx_connection_t *c);
static void ngx_quic_input_handler(ngx_event_t *rev);

static void ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc);
static ngx_int_t ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc);
static void ngx_quic_close_timer_handler(ngx_event_t *ev);
static ngx_int_t ngx_quic_close_streams(ngx_connection_t *c,
    ngx_quic_connection_t *qc);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b,
    ngx_quic_conf_t *conf);
static ngx_int_t ngx_quic_process_packet(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_payload(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_send_early_cc(ngx_connection_t *c,
    ngx_quic_header_t *inpkt, ngx_uint_t err, const char *reason);
static void ngx_quic_discard_ctx(ngx_connection_t *c,
    enum ssl_encryption_level_t level);
static ngx_int_t ngx_quic_check_csid(ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_frames(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_ack_packet(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_send_ack_range(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t smallest, uint64_t largest);
static void ngx_quic_drop_ack_ranges(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t pn);
static ngx_int_t ngx_quic_send_ack(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static ngx_int_t ngx_quic_send_cc(ngx_connection_t *c);
static ngx_int_t ngx_quic_send_new_token(ngx_connection_t *c);

static ngx_int_t ngx_quic_handle_ack_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *f);
static ngx_int_t ngx_quic_handle_ack_frame_range(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, uint64_t min, uint64_t max,
    ngx_msec_t *send_time);
static void ngx_quic_rtt_sample(ngx_connection_t *c, ngx_quic_ack_frame_t *ack,
    enum ssl_encryption_level_t level, ngx_msec_t send_time);
static ngx_inline ngx_msec_t ngx_quic_pto(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_handle_stream_ack(ngx_connection_t *c,
    ngx_quic_frame_t *f);

static ngx_int_t ngx_quic_handle_ordered_frame(ngx_connection_t *c,
    ngx_quic_frames_stream_t *fs, ngx_quic_frame_t *frame,
    ngx_quic_frame_handler_pt handler, void *data);
static ngx_int_t ngx_quic_adjust_frame_offset(ngx_connection_t *c,
    ngx_quic_frame_t *f, uint64_t offset_in);
static ngx_int_t ngx_quic_buffer_frame(ngx_connection_t *c,
    ngx_quic_frames_stream_t *stream, ngx_quic_frame_t *f);

static ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
static ngx_int_t ngx_quic_crypto_input(ngx_connection_t *c,
    ngx_quic_frame_t *frame, void *data);
static ngx_int_t ngx_quic_handle_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
static ngx_int_t ngx_quic_stream_input(ngx_connection_t *c,
    ngx_quic_frame_t *frame, void *data);

static ngx_int_t ngx_quic_handle_max_data_frame(ngx_connection_t *c,
    ngx_quic_max_data_frame_t *f);
static ngx_int_t ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f);
static ngx_int_t ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f);
static ngx_int_t ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f);
static ngx_int_t ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f);
static ngx_int_t ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f);
static ngx_int_t ngx_quic_handle_max_streams_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_streams_frame_t *f);
static ngx_int_t ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f);
static ngx_int_t ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_new_conn_id_frame_t *f);
static ngx_int_t ngx_quic_retire_connection_id(ngx_connection_t *c,
    enum ssl_encryption_level_t level, uint64_t seqnum);
static ngx_int_t ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_retire_cid_frame_t *f);
static ngx_int_t ngx_quic_issue_server_ids(ngx_connection_t *c);
static void ngx_quic_clear_temp_server_ids(ngx_connection_t *c);
static ngx_quic_server_id_t *ngx_quic_insert_server_id(ngx_connection_t *c,
    ngx_str_t *id);
static ngx_quic_client_id_t *ngx_quic_alloc_client_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc);
static ngx_quic_server_id_t *ngx_quic_alloc_server_id(ngx_connection_t *c,
    ngx_quic_connection_t *qc);

static void ngx_quic_queue_frame(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *frame);

static ngx_int_t ngx_quic_output(ngx_connection_t *c);
static ngx_uint_t ngx_quic_get_padding_level(ngx_connection_t *c);
static ngx_int_t ngx_quic_generate_ack(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static ssize_t ngx_quic_output_packet(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, u_char *data, size_t max, size_t min);
static ngx_int_t ngx_quic_split_frame(ngx_connection_t *c, ngx_quic_frame_t *f,
    size_t len);
static void ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames);
static ssize_t ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len);

static void ngx_quic_set_packet_number(ngx_quic_header_t *pkt,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_pto_handler(ngx_event_t *ev);
static void ngx_quic_lost_handler(ngx_event_t *ev);
static ngx_int_t ngx_quic_detect_lost(ngx_connection_t *c);
static void ngx_quic_set_lost_timer(ngx_connection_t *c);
static void ngx_quic_resend_frames(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_push_handler(ngx_event_t *ev);

static void ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_quic_stream_t *ngx_quic_find_stream(ngx_rbtree_t *rbtree,
    uint64_t id);
static ngx_quic_stream_t *ngx_quic_create_client_stream(ngx_connection_t *c,
    uint64_t id);
static ngx_quic_stream_t *ngx_quic_create_stream(ngx_connection_t *c,
    uint64_t id, size_t rcvbuf_size);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static size_t ngx_quic_max_stream_flow(ngx_connection_t *c);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_quic_frame_t *ngx_quic_alloc_frame(ngx_connection_t *c);
static void ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame);

static void ngx_quic_congestion_ack(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
static void ngx_quic_congestion_lost(ngx_connection_t *c,
    ngx_quic_frame_t *frame);

static ngx_chain_t *ngx_quic_alloc_buf(ngx_connection_t *c);
static void ngx_quic_free_bufs(ngx_connection_t *c, ngx_chain_t *in);
static ngx_chain_t *ngx_quic_copy_buf(ngx_connection_t *c, u_char *data,
    size_t len);
static ngx_chain_t *ngx_quic_copy_chain(ngx_connection_t *c, ngx_chain_t *in,
    size_t limit);
static ngx_chain_t *ngx_quic_split_bufs(ngx_connection_t *c, ngx_chain_t *in,
    size_t len);


static ngx_core_module_t  ngx_quic_module_ctx = {
    ngx_string("quic"),
    NULL,
    NULL
};


ngx_module_t  ngx_quic_module = {
    NGX_MODULE_V1,
    &ngx_quic_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static SSL_QUIC_METHOD quic_method = {
#if BORINGSSL_API_VERSION >= 10
    ngx_quic_set_read_secret,
    ngx_quic_set_write_secret,
#else
    ngx_quic_set_encryption_secrets,
#endif
    ngx_quic_add_handshake_data,
    ngx_quic_flush_flight,
    ngx_quic_send_alert,
};


#if (NGX_DEBUG)

static void
ngx_quic_log_frame(ngx_log_t *log, ngx_quic_frame_t *f, ngx_uint_t tx)
{
    u_char      *p, *last, *pos, *end;
    ssize_t      n;
    uint64_t     gap, range, largest, smallest;
    ngx_uint_t   i;
    u_char       buf[NGX_MAX_ERROR_STR];

    p = buf;
    last = buf + sizeof(buf);

    switch (f->type) {

    case NGX_QUIC_FT_CRYPTO:
        p = ngx_slprintf(p, last, "CRYPTO len:%uL off:%uL",
                         f->u.crypto.length, f->u.crypto.offset);
        break;

    case NGX_QUIC_FT_PADDING:
        p = ngx_slprintf(p, last, "PADDING");
        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        p = ngx_slprintf(p, last, "ACK n:%ui delay:%uL ",
                         f->u.ack.range_count, f->u.ack.delay);

        if (f->data) {
            pos = f->data->buf->pos;
            end = f->data->buf->last;

        } else {
            pos = NULL;
            end = NULL;
        }

        largest = f->u.ack.largest;
        smallest = f->u.ack.largest - f->u.ack.first_range;

        if (largest == smallest) {
            p = ngx_slprintf(p, last, "%uL", largest);

        } else {
            p = ngx_slprintf(p, last, "%uL-%uL", largest, smallest);
        }

        for (i = 0; i < f->u.ack.range_count; i++) {
            n = ngx_quic_parse_ack_range(log, pos, end, &gap, &range);
            if (n == NGX_ERROR) {
                break;
            }

            pos += n;

            largest = smallest - gap - 2;
            smallest = largest - range;

            if (largest == smallest) {
                p = ngx_slprintf(p, last, " %uL", largest);

            } else {
                p = ngx_slprintf(p, last, " %uL-%uL", largest, smallest);
            }
        }

        if (f->type == NGX_QUIC_FT_ACK_ECN) {
            p = ngx_slprintf(p, last, " ECN counters ect0:%uL ect1:%uL ce:%uL",
                             f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }
        break;

    case NGX_QUIC_FT_PING:
        p = ngx_slprintf(p, last, "PING");
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        p = ngx_slprintf(p, last,
                         "NEW_CONNECTION_ID seq:%uL retire:%uL len:%ud",
                         f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        p = ngx_slprintf(p, last, "RETIRE_CONNECTION_ID seqnum:%uL",
                         f->u.retire_cid.sequence_number);
        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        p = ngx_slprintf(p, last, "CONNECTION_CLOSE%s err:%ui",
                         f->type == NGX_QUIC_FT_CONNECTION_CLOSE ? "" : "_APP",
                         f->u.close.error_code);

        if (f->u.close.reason.len) {
            p = ngx_slprintf(p, last, " %V", &f->u.close.reason);
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {
            p = ngx_slprintf(p, last, " ft:%ui", f->u.close.frame_type);
        }

        break;

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:

        p = ngx_slprintf(p, last, "STREAM id:0x%xL", f->u.stream.stream_id);

        if (f->u.stream.off) {
            p = ngx_slprintf(p, last, " off:%uL", f->u.stream.offset);
        }

        if (f->u.stream.len) {
            p = ngx_slprintf(p, last, " len:%uL", f->u.stream.length);
        }

        if (f->u.stream.fin) {
            p = ngx_slprintf(p, last, " fin:1");
        }

#ifdef NGX_QUIC_DEBUG_FRAMES
        {
            ngx_chain_t  *cl;

            p = ngx_slprintf(p, last, " data:");

            for (cl = f->data; cl; cl = cl->next) {
                p = ngx_slprintf(p, last, "%*xs",
                                 cl->buf->last - cl->buf->pos, cl->buf->pos);
            }
        }
#endif

        break;

    case NGX_QUIC_FT_MAX_DATA:
        p = ngx_slprintf(p, last, "MAX_DATA max_data:%uL on recv",
                         f->u.max_data.max_data);
        break;

    case NGX_QUIC_FT_RESET_STREAM:
        p = ngx_slprintf(p, last, "RESET_STREAM"
                        " id:0x%xL error_code:0x%xL final_size:0x%xL",
                        f->u.reset_stream.id, f->u.reset_stream.error_code,
                        f->u.reset_stream.final_size);
        break;

    case NGX_QUIC_FT_STOP_SENDING:
        p = ngx_slprintf(p, last, "STOP_SENDING id:0x%xL err:0x%xL",
                         f->u.stop_sending.id, f->u.stop_sending.error_code);
        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:
        p = ngx_slprintf(p, last, "STREAMS_BLOCKED limit:%uL bidi:%ui",
                         f->u.streams_blocked.limit, f->u.streams_blocked.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:
        p = ngx_slprintf(p, last, "MAX_STREAMS limit:%uL bidi:%ui",
                         f->u.max_streams.limit, f->u.max_streams.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        p = ngx_slprintf(p, last, "MAX_STREAM_DATA id:0x%xL limit:%uL",
                         f->u.max_stream_data.id, f->u.max_stream_data.limit);
        break;


    case NGX_QUIC_FT_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "DATA_BLOCKED limit:%uL",
                         f->u.data_blocked.limit);
        break;

    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:
        p = ngx_slprintf(p, last, "STREAM_DATA_BLOCKED id:0x%xL limit:%uL",
                         f->u.stream_data_blocked.id,
                         f->u.stream_data_blocked.limit);
        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:
        p = ngx_slprintf(p, last, "PATH_CHALLENGE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_PATH_RESPONSE:
        p = ngx_slprintf(p, last, "PATH_RESPONSE data:0x%*xs",
                         sizeof(f->u.path_challenge.data),
                         f->u.path_challenge.data);
        break;

    case NGX_QUIC_FT_NEW_TOKEN:
        p = ngx_slprintf(p, last, "NEW_TOKEN");
        break;

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        p = ngx_slprintf(p, last, "HANDSHAKE DONE");
        break;

    default:
        p = ngx_slprintf(p, last, "unknown type 0x%xi", f->type);
        break;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0, "quic frame %s %s %*s",
                   tx ? "tx" : "rx", ngx_quic_level_name(f->level),
                   p - buf, buf);
}


static void
ngx_quic_connstate_dbg(ngx_connection_t *c)
{
    u_char                 *p, *last;
    ngx_quic_connection_t  *qc;
    u_char                  buf[NGX_MAX_ERROR_STR];

    p = buf;
    last = p + sizeof(buf);

    qc = ngx_quic_get_connection(c);

    p = ngx_slprintf(p, last, "state:");

    if (qc) {

        if (qc->error) {
            p = ngx_slprintf(p, last, "%s", qc->error_app ? " app" : "");
            p = ngx_slprintf(p, last, " error:%ui", qc->error);

            if (qc->error_reason) {
                p = ngx_slprintf(p, last, " \"%s\"", qc->error_reason);
            }
        }

        p = ngx_slprintf(p, last, "%s", qc->closing ? " closing" : "");
        p = ngx_slprintf(p, last, "%s", qc->draining ? " draining" : "");
        p = ngx_slprintf(p, last, "%s", qc->key_phase ? " kp" : "");
        p = ngx_slprintf(p, last, "%s", qc->validated? " valid" : "");

    } else {
        p = ngx_slprintf(p, last, " early");
    }

    if (c->read->timer_set) {
        p = ngx_slprintf(p, last,
                         qc && qc->send_timer_set ? " send:%M" : " read:%M",
                         c->read->timer.key - ngx_current_msec);
    }

    if (qc) {

        if (qc->push.timer_set) {
            p = ngx_slprintf(p, last, " push:%M",
                             qc->push.timer.key - ngx_current_msec);
        }

        if (qc->pto.timer_set) {
            p = ngx_slprintf(p, last, " pto:%M",
                             qc->pto.timer.key - ngx_current_msec);
        }

        if (qc->close.timer_set) {
            p = ngx_slprintf(p, last, " close:%M",
                             qc->close.timer.key - ngx_current_msec);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic %*s", p - buf, buf);
}

#else

#define ngx_quic_log_frame(log, f, tx)
#define ngx_quic_connstate_dbg(c)

#endif


#if BORINGSSL_API_VERSION >= 10

static int
ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = ngx_quic_get_connection(c);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_read_secret() level:%d", level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    return ngx_quic_keys_set_encryption_secret(c->pool, 0, qc->keys, level,
                                               cipher, rsecret, secret_len);
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = ngx_quic_get_connection(c);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_write_secret() level:%d", level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    return ngx_quic_keys_set_encryption_secret(c->pool, 1, qc->keys, level,
                                               cipher, wsecret, secret_len);
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t       *c;
    const SSL_CIPHER       *cipher;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = ngx_quic_get_connection(c);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_encryption_secrets() level:%d", level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    cipher = SSL_get_current_cipher(ssl_conn);

    if (ngx_quic_keys_set_encryption_secret(c->pool, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != 1)
    {
        return 0;
    }

    if (level == ssl_encryption_early_data) {
        return 1;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    return ngx_quic_keys_set_encryption_secret(c->pool, 1, qc->keys, level,
                                               cipher, wsecret, secret_len);
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                    *p, *end;
    size_t                     client_params_len;
    const uint8_t             *client_params;
    ngx_quic_tp_t              ctp;
    ngx_quic_frame_t          *frame;
    ngx_connection_t          *c;
    ngx_quic_connection_t     *qc;
    ngx_quic_frames_stream_t  *fs;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = ngx_quic_get_connection(c);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_add_handshake_data");

    if (!qc->client_tp_done) {
        /*
         * things to do once during handshake: check ALPN and transport
         * parameters; we want to break handshake if something is wrong
         * here;
         */

#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
        if (qc->conf->require_alpn) {
            unsigned int          len;
            const unsigned char  *data;

            SSL_get0_alpn_selected(ssl_conn, &data, &len);

            if (len == 0) {
                qc->error = 0x100 + SSL_AD_NO_APPLICATION_PROTOCOL;
                qc->error_reason = "unsupported protocol in ALPN extension";

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic unsupported protocol in ALPN extension");
                return 0;
            }
        }
#endif

        SSL_get_peer_quic_transport_params(ssl_conn, &client_params,
                                           &client_params_len);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic SSL_get_peer_quic_transport_params():"
                       " params_len:%ui", client_params_len);

        if (client_params_len == 0) {
            /* quic-tls 8.2 */
            qc->error = NGX_QUIC_ERR_CRYPTO(SSL_AD_MISSING_EXTENSION);
            qc->error_reason = "missing transport parameters";

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "missing transport parameters");
            return 0;
        }

        p = (u_char *) client_params;
        end = p + client_params_len;

        /* defaults for parameters not sent by client */
        ngx_memcpy(&ctp, &qc->ctp, sizeof(ngx_quic_tp_t));

        if (ngx_quic_parse_transport_params(p, end, &ctp, c->log)
            != NGX_OK)
        {
            qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
            qc->error_reason = "failed to process transport parameters";

            return 0;
        }

        if (ngx_quic_apply_transport_params(c, &ctp) != NGX_OK) {
            return 0;
        }

        qc->client_tp_done = 1;
    }

    fs = &qc->crypto[level];

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return 0;
    }

    frame->data = ngx_quic_copy_buf(c, (u_char *) data, len);
    if (frame->data == NGX_CHAIN_ERROR) {
        return 0;
    }

    frame->level = level;
    frame->type = NGX_QUIC_FT_CRYPTO;
    frame->u.crypto.offset = fs->sent;
    frame->u.crypto.length = len;

    fs->sent += len;

    ngx_quic_queue_frame(qc, frame);

    return 1;
}


static int
ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn)
{
#if (NGX_DEBUG)
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_flush_flight()");
#endif
    return 1;
}


static int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_send_alert() lvl:%d  alert:%d",
                   (int) level, (int) alert);

    qc = ngx_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error_level = level;
    qc->error = NGX_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "TLS alert";
    qc->error_app = 0;
    qc->error_ftype = 0;

    if (ngx_quic_send_cc(c) != NGX_OK) {
        return 0;
    }

    return 1;
}


static ngx_int_t
ngx_quic_apply_transport_params(ngx_connection_t *c, ngx_quic_tp_t *ctp)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->scid.len != ctp->initial_scid.len
        || ngx_memcmp(qc->scid.data, ctp->initial_scid.data, qc->scid.len) != 0)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic client initial_source_connection_id mismatch");
        return NGX_ERROR;
    }

    if (ctp->max_udp_payload_size < NGX_QUIC_MIN_INITIAL_SIZE
        || ctp->max_udp_payload_size > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid maximum packet size";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic maximum packet size is invalid");
        return NGX_ERROR;

    } else if (ctp->max_udp_payload_size > ngx_quic_max_udp_payload(c)) {
        ctp->max_udp_payload_size = ngx_quic_max_udp_payload(c);
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic client maximum packet size truncated");
    }

    if (ctp->active_connection_id_limit < 2) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid active_connection_id_limit";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic active_connection_id_limit is invalid");
        return NGX_ERROR;
    }

    if (ctp->ack_delay_exponent > 20) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid ack_delay_exponent";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic ack_delay_exponent is invalid");
        return NGX_ERROR;
    }

    if (ctp->max_ack_delay > 16384) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid max_ack_delay";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic max_ack_delay is invalid");
        return NGX_ERROR;
    }

    if (ctp->max_idle_timeout > 0
        && ctp->max_idle_timeout < qc->tp.max_idle_timeout)
    {
        qc->tp.max_idle_timeout = ctp->max_idle_timeout;
    }

    qc->streams.server_max_streams_bidi = ctp->initial_max_streams_bidi;
    qc->streams.server_max_streams_uni = ctp->initial_max_streams_uni;

    ngx_memcpy(&qc->ctp, ctp, sizeof(ngx_quic_tp_t));

    return NGX_OK;
}


void
ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    rc = ngx_quic_input(c, c->buffer, conf);
    if (rc != NGX_OK) {
        ngx_quic_close_connection(c, rc == NGX_DECLINED ? NGX_DONE : NGX_ERROR);
        return;
    }

    qc = ngx_quic_get_connection(c);

    if (qc == NULL) {
        ngx_quic_close_connection(c, NGX_DONE);
        return;
    }

    ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    ngx_quic_connstate_dbg(c);

    c->read->handler = ngx_quic_input_handler;

    return;
}


static ngx_quic_connection_t *
ngx_quic_new_connection(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    ngx_uint_t              i;
    ngx_quic_tp_t          *ctp;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NULL;
    }

    qc->keys = ngx_quic_keys_new(c->pool);
    if (qc->keys == NULL) {
        return NULL;
    }

    qc->version = pkt->version;

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_queue_init(&qc->send_ctx[i].frames);
        ngx_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = NGX_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = ssl_encryption_initial;
    qc->send_ctx[1].level = ssl_encryption_handshake;
    qc->send_ctx[2].level = ssl_encryption_application;

    for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
        ngx_queue_init(&qc->crypto[i].frames);
    }

    ngx_queue_init(&qc->free_frames);
    ngx_queue_init(&qc->client_ids);
    ngx_queue_init(&qc->server_ids);
    ngx_queue_init(&qc->free_client_ids);
    ngx_queue_init(&qc->free_server_ids);

    qc->avg_rtt = NGX_QUIC_INITIAL_RTT;
    qc->rttvar = NGX_QUIC_INITIAL_RTT / 2;
    qc->min_rtt = NGX_TIMER_INFINITE;

    /*
     * qc->latest_rtt = 0
     * qc->nclient_ids = 0
     * qc->nserver_ids = 0
     * qc->max_retired_seqnum = 0
     */

    qc->received = pkt->raw->last - pkt->raw->start;

    qc->pto.log = c->log;
    qc->pto.data = c;
    qc->pto.handler = ngx_quic_pto_handler;
    qc->pto.cancelable = 1;

    qc->push.log = c->log;
    qc->push.data = c;
    qc->push.handler = ngx_quic_push_handler;
    qc->push.cancelable = 1;

    qc->conf = conf;
    qc->tp = conf->tp;

    if (qc->tp.disable_active_migration) {
        qc->sockaddr = ngx_palloc(c->pool, c->socklen);
        if (qc->sockaddr == NULL) {
            return NULL;
        }

        ngx_memcpy(qc->sockaddr, c->sockaddr, c->socklen);
        qc->socklen = c->socklen;
    }

    ctp = &qc->ctp;

    /* defaults to be used before actual client parameters are received */
    ctp->max_udp_payload_size = ngx_quic_max_udp_payload(c);
    ctp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    qc->streams.recv_max_data = qc->tp.initial_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window = ngx_min(10 * qc->tp.max_udp_payload_size,
                                    ngx_max(2 * qc->tp.max_udp_payload_size,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.recovery_start = ngx_current_msec;

    qc->odcid.len = pkt->odcid.len;
    qc->odcid.data = ngx_pstrdup(c->pool, &pkt->odcid);
    if (qc->odcid.data == NULL) {
        return NULL;
    }

    qc->dcid.len = NGX_QUIC_SERVER_CID_LEN;
    qc->dcid.data = ngx_pnalloc(c->pool, qc->dcid.len);
    if (qc->dcid.data == NULL) {
        return NULL;
    }

    if (ngx_quic_create_server_id(c, qc->dcid.data) != NGX_OK) {
        return NULL;
    }

    qc->tp.original_dcid = qc->odcid;
    qc->tp.initial_scid = qc->dcid;

    if (pkt->validated && pkt->retried) {
        qc->tp.retry_scid.len = pkt->dcid.len;
        qc->tp.retry_scid.data = ngx_pstrdup(c->pool, &pkt->dcid);
        if (qc->tp.retry_scid.data == NULL) {
            return NULL;
        }
    }

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pstrdup(c->pool, &pkt->scid);
    if (qc->scid.data == NULL) {
        return NULL;
    }

    cid = ngx_quic_alloc_client_id(c, qc);
    if (cid == NULL) {
        return NULL;
    }

    cid->seqnum = 0;
    cid->len = pkt->scid.len;
    ngx_memcpy(cid->id, pkt->scid.data, pkt->scid.len);

    ngx_queue_insert_tail(&qc->client_ids, &cid->queue);
    qc->nclient_ids++;
    qc->client_seqnum = 0;

    qc->server_seqnum = NGX_QUIC_UNSET_PN;

    if (ngx_quic_keys_set_initial_secret(c->pool, qc->keys, &pkt->dcid,
                                         qc->version)
        != NGX_OK)
    {
        return NULL;
    }

    c->udp = &qc->udp;

    if (ngx_quic_insert_server_id(c, &qc->odcid) == NULL) {
        return NULL;
    }

    qc->server_seqnum = 0;

    if (ngx_quic_insert_server_id(c, &qc->dcid) == NULL) {
        return NULL;
    }

    qc->validated = pkt->validated;

    return qc;
}


static ngx_int_t
ngx_quic_send_stateless_reset(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    u_char    *token;
    size_t     len, max;
    uint16_t   rndbytes;
    u_char     buf[NGX_QUIC_MAX_SR_PACKET];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic handle stateless reset output");

    if (pkt->len <= NGX_QUIC_MIN_PKT_LEN) {
        return NGX_DECLINED;
    }

    if (pkt->len <= NGX_QUIC_MIN_SR_PACKET) {
        len = pkt->len - 1;

    } else {
        max = ngx_min(NGX_QUIC_MAX_SR_PACKET, pkt->len * 3);

        if (RAND_bytes((u_char *) &rndbytes, sizeof(rndbytes)) != 1) {
            return NGX_ERROR;
        }

        len = (rndbytes % (max - NGX_QUIC_MIN_SR_PACKET + 1))
              + NGX_QUIC_MIN_SR_PACKET;
    }

    if (RAND_bytes(buf, len - NGX_QUIC_SR_TOKEN_LEN) != 1) {
        return NGX_ERROR;
    }

    buf[0] &= ~NGX_QUIC_PKT_LONG;
    buf[0] |= NGX_QUIC_PKT_FIXED_BIT;

    token = &buf[len - NGX_QUIC_SR_TOKEN_LEN];

    if (ngx_quic_new_sr_token(c, &pkt->dcid, conf->sr_token_key, token)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    (void) ngx_quic_send(c, buf, len);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_quic_new_sr_token(ngx_connection_t *c, ngx_str_t *cid, u_char *secret,
    u_char *token)
{
    ngx_str_t tmp;

    tmp.data = secret;
    tmp.len = NGX_QUIC_SR_KEY_LEN;

    if (ngx_quic_derive_key(c->log, "sr_token_key", &tmp, cid, token,
                            NGX_QUIC_SR_TOKEN_LEN)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stateless reset token %*xs",
                    (size_t) NGX_QUIC_SR_TOKEN_LEN, token);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_process_stateless_reset(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *tail, ch;
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /* A stateless reset uses an entire UDP datagram */
    if (pkt->raw->start != pkt->data) {
        return NGX_DECLINED;
    }

    tail = pkt->raw->last - NGX_QUIC_SR_TOKEN_LEN;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (cid->seqnum == 0) {
            /* no stateless reset token in initial connection id */
            continue;
        }

        /* constant time comparison */

        for (ch = 0, i = 0; i < NGX_QUIC_SR_TOKEN_LEN; i++) {
            ch |= tail[i] ^ cid->sr_token[i];
        }

        if (ch == 0) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_quic_negotiate_version(ngx_connection_t *c, ngx_quic_header_t *inpkt)
{
    size_t             len;
    ngx_quic_header_t  pkt;
    static u_char      buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sending version negotiation packet");

    pkt.log = c->log;
    pkt.flags = NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_FIXED_BIT;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;

    len = ngx_quic_create_version_negotiation(&pkt, buf);

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic vnego packet to send len:%uz %*xs", len, len, buf);
#endif

    (void) ngx_quic_send(c, buf, len);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_create_server_id(ngx_connection_t *c, u_char *id)
{
    if (RAND_bytes(id, NGX_QUIC_SERVER_CID_LEN) != 1) {
        return NGX_ERROR;
    }

#if (NGX_QUIC_BPF)
    if (ngx_quic_bpf_attach_id(c, id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "quic bpf failed to generate socket key");
        /* ignore error, things still may work */
    }
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic create server id %*xs",
                   (size_t) NGX_QUIC_SERVER_CID_LEN, id);
    return NGX_OK;
}


#if (NGX_QUIC_BPF)

static ngx_int_t
ngx_quic_bpf_attach_id(ngx_connection_t *c, u_char *id)
{
    int        fd;
    uint64_t   cookie;
    socklen_t  optlen;

    fd = c->listening->fd;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "quic getsockopt(SO_COOKIE) failed");

        return NGX_ERROR;
    }

    ngx_quic_dcid_encode_key(id, cookie);

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_quic_send_retry(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *inpkt)
{
    time_t             expires;
    ssize_t            len;
    ngx_str_t          res, token;
    ngx_quic_header_t  pkt;

    u_char             buf[NGX_QUIC_RETRY_BUFFER_SIZE];
    u_char             dcid[NGX_QUIC_SERVER_CID_LEN];

    expires = ngx_time() + NGX_QUIC_RETRY_TOKEN_LIFETIME;

    if (ngx_quic_new_token(c, conf->av_token_key, &token, &inpkt->dcid,
                           expires, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY;
    pkt.version = inpkt->version;
    pkt.log = c->log;

    pkt.odcid = inpkt->dcid;
    pkt.dcid = inpkt->scid;

    /* TODO: generate routable dcid */
    if (RAND_bytes(dcid, NGX_QUIC_SERVER_CID_LEN) != 1) {
        return NGX_ERROR;
    }

    pkt.scid.len = NGX_QUIC_SERVER_CID_LEN;
    pkt.scid.data = dcid;

    pkt.token = token;

    res.data = buf;

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet to send len:%uz %xV", res.len, &res);
#endif

    len = ngx_quic_send(c, res.data, res.len);
    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "quic retry packet sent to %xV", &pkt.dcid);

    /*
     * quic-transport 17.2.5.1:  A server MUST NOT send more than one Retry
     * packet in response to a single UDP datagram.
     * NGX_DONE will stop quic_input() from processing further
     */
    return NGX_DONE;
}


static ngx_int_t
ngx_quic_new_token(ngx_connection_t *c, u_char *key, ngx_str_t *token,
    ngx_str_t *odcid, time_t exp, ngx_uint_t is_retry)
{
    int                len, iv_len;
    u_char            *p, *iv;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             in[NGX_QUIC_MAX_TOKEN_SIZE];

    ngx_quic_address_hash(c, !is_retry, in);

    p = in + 20;

    p = ngx_cpymem(p, &exp, sizeof(time_t));

    *p++ = is_retry ? 1 : 0;

    if (odcid) {
        *p++ = odcid->len;
        p = ngx_cpymem(p, odcid->data, odcid->len);

    } else {
        *p++ = 0;
    }

    len = p - in;

    cipher = EVP_aes_256_cbc();
    iv_len = EVP_CIPHER_iv_length(cipher);

    token->len = iv_len + len + EVP_CIPHER_block_size(cipher);
    token->data = ngx_pnalloc(c->pool, token->len);
    if (token->data == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    iv = token->data;

    if (RAND_bytes(iv, iv_len) <= 0
        || !EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len = iv_len;

    if (EVP_EncryptUpdate(ctx, token->data + token->len, &len, in, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    if (EVP_EncryptFinal_ex(ctx, token->data + token->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    token->len += len;

    EVP_CIPHER_CTX_free(ctx);

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic new token len:%uz %xV", token->len, token);
#endif

    return NGX_OK;
}


static void
ngx_quic_address_hash(ngx_connection_t *c, ngx_uint_t no_port, u_char buf[20])
{
    size_t                len;
    u_char               *data;
    ngx_sha1_t            sha1;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    len = (size_t) c->socklen;
    data = (u_char *) c->sockaddr;

    if (no_port) {
        switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;

            len = sizeof(struct in6_addr);
            data = sin6->sin6_addr.s6_addr;

            break;
#endif

        case AF_INET:
            sin = (struct sockaddr_in *) c->sockaddr;

            len = sizeof(in_addr_t);
            data = (u_char *) &sin->sin_addr;

            break;
        }
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, data, len);
    ngx_sha1_final(buf, &sha1);
}


static ngx_int_t
ngx_quic_validate_token(ngx_connection_t *c, u_char *key,
    ngx_quic_header_t *pkt)
{
    int                len, tlen, iv_len;
    u_char            *iv, *p;
    time_t             now, exp;
    size_t             total;
    ngx_str_t          odcid;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             addr_hash[20];
    u_char             tdec[NGX_QUIC_MAX_TOKEN_SIZE];

    /* Retry token or NEW_TOKEN in a previous connection */

    cipher = EVP_aes_256_cbc();
    iv = pkt->token.data;
    iv_len = EVP_CIPHER_iv_length(cipher);

    /* sanity checks */

    if (pkt->token.len < (size_t) iv_len + EVP_CIPHER_block_size(cipher)) {
        goto garbage;
    }

    if (pkt->token.len > (size_t) iv_len + NGX_QUIC_MAX_TOKEN_SIZE) {
        goto garbage;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }

    p = pkt->token.data + iv_len;
    len = pkt->token.len - iv_len;

    if (EVP_DecryptUpdate(ctx, tdec, &len, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, tdec + len, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total += tlen;

    EVP_CIPHER_CTX_free(ctx);

    if (total < (20 + sizeof(time_t) + 2)) {
        goto garbage;
    }

    p = tdec + 20;

    ngx_memcpy(&exp, p, sizeof(time_t));
    p += sizeof(time_t);

    pkt->retried = (*p++ == 1);

    ngx_quic_address_hash(c, !pkt->retried, addr_hash);

    if (ngx_memcmp(tdec, addr_hash, 20) != 0) {
        goto bad_token;
    }

    odcid.len = *p++;
    if (odcid.len) {
        if (odcid.len > NGX_QUIC_MAX_CID_LEN) {
            goto bad_token;
        }

        if ((size_t)(tdec + total - p) < odcid.len) {
            goto bad_token;
        }

        odcid.data = p;
        p += odcid.len;
    }

    now = ngx_time();

    if (now > exp) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic expired token");
        return NGX_DECLINED;
    }

    if (odcid.len) {
        pkt->odcid.len = odcid.len;
        pkt->odcid.data = ngx_pstrdup(c->pool, &odcid);
        if (pkt->odcid.data == NULL) {
            return NGX_ERROR;
        }

    } else {
        pkt->odcid = pkt->dcid;
    }

    pkt->validated = 1;

    return NGX_OK;

garbage:

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic garbage token");

    return NGX_ABORT;

bad_token:

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic invalid token");

    return NGX_DECLINED;
}


static ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    u_char                 *p;
    size_t                  clen;
    ssize_t                 len;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (ngx_ssl_create_connection(qc->conf->ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->no_wait_shutdown = 1;

    ssl_conn = c->ssl->connection;

    if (SSL_set_quic_method(ssl_conn, &quic_method) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_method() failed");
        return NGX_ERROR;
    }

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(qc->conf->ssl->ctx)) {
        SSL_set_quic_early_data_enabled(ssl_conn, 1);
    }
#endif

    if (ngx_quic_new_sr_token(c, &qc->dcid, qc->conf->sr_token_key,
                              qc->tp.sr_token)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stateless reset token %*xs",
                   (size_t) NGX_QUIC_SR_TOKEN_LEN, qc->tp.sr_token);

    len = ngx_quic_create_transport_params(NULL, NULL, &qc->tp, &clen);
    /* always succeeds */

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = ngx_quic_create_transport_params(p, p + len, &qc->tp, NULL);
    if (len < 0) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic transport parameters len:%uz %*xs", len, len, p);
#endif

    if (SSL_set_quic_transport_params(ssl_conn, p, len) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }

#if NGX_OPENSSL_QUIC_ZRTT_CTX
    if (SSL_set_quic_early_data_context(ssl_conn, p, clen) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_early_data_context() failed");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static ngx_inline size_t
ngx_quic_max_udp_payload(ngx_connection_t *c)
{
    /* TODO: path MTU discovery */

#if (NGX_HAVE_INET6)
    if (c->sockaddr->sa_family == AF_INET6) {
        return NGX_QUIC_MAX_UDP_PAYLOAD_OUT6;
    }
#endif

    return NGX_QUIC_MAX_UDP_PAYLOAD_OUT;
}


static void
ngx_quic_input_handler(ngx_event_t *rev)
{
    ssize_t                 n;
    ngx_int_t               rc;
    ngx_buf_t               b;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.start = buf;
    b.end = buf + sizeof(buf);
    b.pos = b.last = b.start;
    b.memory = 1;

    c = rev->data;
    qc = ngx_quic_get_connection(c);

    c->log->action = "handling quic input";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "quic client timed out");
        ngx_quic_close_connection(c, NGX_DONE);
        return;
    }

    if (c->close) {
        qc->error_reason = "graceful shutdown";
        ngx_quic_close_connection(c, NGX_OK);
        return;
    }

    n = c->recv(c, b.start, b.end - b.start);

    if (n == NGX_AGAIN) {
        if (qc->closing) {
            ngx_quic_close_connection(c, NGX_OK);
        }
        return;
    }

    if (n == NGX_ERROR) {
        c->read->eof = 1;
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    if (qc->tp.disable_active_migration) {
        if (c->socklen != qc->socklen
            || ngx_memcmp(c->sockaddr, qc->sockaddr, c->socklen) != 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic dropping packet from new address");
            return;
        }
    }

    b.last += n;
    qc->received += n;

    rc = ngx_quic_input(c, &b, NULL);

    if (rc == NGX_ERROR) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    /* rc == NGX_OK */

    qc->send_timer_set = 0;
    ngx_add_timer(rev, qc->tp.max_idle_timeout);

    ngx_quic_connstate_dbg(c);
}


static void
ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc)
{
    ngx_pool_t             *pool;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_close_connection rc:%i", rc);

    qc = ngx_quic_get_connection(c);

    if (qc == NULL) {
        if (rc == NGX_ERROR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close connection early error");
        }

    } else if (ngx_quic_close_quic(c, rc) == NGX_AGAIN) {
        return;
    }

    if (c->ssl) {
        (void) ngx_ssl_shutdown(c);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


static ngx_int_t
ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc)
{
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ngx_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (rc == NGX_DONE) {

            /*
             *  10.2.  Idle Timeout
             *
             *  If the idle timeout is enabled by either peer, a connection is
             *  silently closed and its state is discarded when it remains idle
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic closing %s connection",
                           qc->draining ? "drained" : "idle");

        } else {

            /*
             * 10.3.  Immediate Close
             *
             *  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
             *  to terminate the connection immediately.
             */

            qc->error_level = c->ssl ? SSL_quic_read_level(c->ssl->connection)
                                     : ssl_encryption_initial;

            if (rc == NGX_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic immediate close drain:%d",
                               qc->draining);

                qc->close.log = c->log;
                qc->close.data = c;
                qc->close.handler = ngx_quic_close_timer_handler;
                qc->close.cancelable = 1;

                ctx = ngx_quic_get_send_ctx(qc, qc->error_level);

                ngx_add_timer(&qc->close, 3 * ngx_quic_pto(c, ctx));

                qc->error = NGX_QUIC_ERR_NO_ERROR;

            } else {
                if (qc->error == 0 && !qc->error_app) {
                    qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
                }

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic immediate close due to %s error: %ui %s",
                               qc->error_app ? "app " : "", qc->error,
                               qc->error_reason ? qc->error_reason : "");
            }

            (void) ngx_quic_send_cc(c);

            if (qc->error_level == ssl_encryption_handshake) {
                /* for clients that might not have handshake keys */
                qc->error_level = ssl_encryption_initial;
                (void) ngx_quic_send_cc(c);
            }
        }

        qc->closing = 1;
    }

    if (rc == NGX_ERROR && qc->close.timer_set) {
        /* do not wait for timer in case of fatal error */
        ngx_del_timer(&qc->close);
    }

    if (ngx_quic_close_streams(c, qc) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (qc->push.timer_set) {
        ngx_del_timer(&qc->push);
    }

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    if (qc->push.posted) {
        ngx_delete_posted_event(&qc->push);
    }

    while (!ngx_queue_empty(&qc->server_ids)) {
        q = ngx_queue_head(&qc->server_ids);
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        ngx_queue_remove(q);
        ngx_rbtree_delete(&c->listening->rbtree, &sid->udp.node);
        qc->nserver_ids--;
    }

    if (qc->close.timer_set) {
        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic part of connection is terminated");

    /* may be tested from SSL callback during SSL shutdown */
    c->udp = NULL;

    return NGX_OK;
}


void
ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->error = err;
    qc->error_reason = reason;
    qc->error_app = 1;
    qc->error_ftype = 0;

    ngx_quic_close_connection(c, NGX_ERROR);
}


static void
ngx_quic_close_timer_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic close timer");

    c = ev->data;
    ngx_quic_close_connection(c, NGX_DONE);
}


static ngx_int_t
ngx_quic_close_streams(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_event_t        *rev, *wev;
    ngx_rbtree_t       *tree;
    ngx_rbtree_node_t  *node;
    ngx_quic_stream_t  *qs;

#if (NGX_DEBUG)
    ngx_uint_t          ns;
#endif

    tree = &qc->streams.tree;

    if (tree->root == tree->sentinel) {
        return NGX_OK;
    }

#if (NGX_DEBUG)
    ns = 0;
#endif

    for (node = ngx_rbtree_min(tree->root, tree->sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        qs = (ngx_quic_stream_t *) node;

        rev = qs->c->read;
        rev->error = 1;
        rev->ready = 1;

        wev = qs->c->write;
        wev->error = 1;
        wev->ready = 1;

        ngx_post_event(rev, &ngx_posted_events);

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

#if (NGX_DEBUG)
        ns++;
#endif
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection has %ui active streams", ns);

    return NGX_AGAIN;
}


ngx_int_t
ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err)
{
    ngx_event_t            *wev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_RESET_STREAM;
    frame->u.reset_stream.id = qs->id;
    frame->u.reset_stream.error_code = err;
    frame->u.reset_stream.final_size = c->sent;

    ngx_quic_queue_frame(qc, frame);

    wev = c->write;
    wev->error = 1;
    wev->ready = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b, ngx_quic_conf_t *conf)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_uint_t          good;
    ngx_quic_header_t   pkt;

    good = 0;

    p = b->pos;

    while (p < b->last) {

        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.flags = p[0];
        pkt.raw->pos++;

        rc = ngx_quic_process_packet(c, conf, &pkt);

#if (NGX_DEBUG)
        if (pkt.parsed) {
            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet %s done decr:%d pn:%L perr:%ui rc:%i",
                           ngx_quic_level_name(pkt.level), pkt.decrypted,
                           pkt.pn, pkt.error, rc);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done parse failed rc:%i", rc);
        }
#endif

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_DONE) {
            /* stop further processing */
            return NGX_DECLINED;
        }

        if (rc == NGX_OK) {
            good = 1;
        }

        /* NGX_OK || NGX_DECLINED */

        /*
         * we get NGX_DECLINED when there are no keys [yet] available
         * to decrypt packet.
         * Instead of queueing it, we ignore it and rely on the sender's
         * retransmission:
         *
         * 12.2.  Coalescing Packets:
         *
         * For example, if decryption fails (because the keys are
         * not available or any other reason), the receiver MAY either
         * discard or buffer the packet for later processing and MUST
         * attempt to process the remaining packets.
         *
         * We also skip packets that don't match connection state
         * or cannot be parsed properly.
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos = pkt.data + pkt.len;

        /* firefox workaround: skip zero padding at the end of quic packet */
        while (b->pos < b->last && *(b->pos) == 0) {
            b->pos++;
        }

        p = b->pos;
    }

    return good ? NGX_OK : NGX_DECLINED;
}


static ngx_int_t
ngx_quic_process_packet(ngx_connection_t *c, ngx_quic_conf_t *conf,
    ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    c->log->action = "parsing quic packet";

    rc = ngx_quic_parse_packet(pkt);

    if (rc == NGX_DECLINED || rc == NGX_ERROR) {
        return rc;
    }

    pkt->parsed = 1;

    c->log->action = "processing quic packet";

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet rx dcid len:%uz %xV",
                   pkt->dcid.len, &pkt->dcid);

#if (NGX_DEBUG)
    if (pkt->level != ssl_encryption_application) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic packet rx scid len:%uz %xV",
                       pkt->scid.len, &pkt->scid);
    }

    if (pkt->level == ssl_encryption_initial) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic address validation token len:%uz %xV",
                       pkt->token.len, &pkt->token);
    }
#endif

    qc = ngx_quic_get_connection(c);

    if (qc) {

        if (rc == NGX_ABORT) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic unsupported version: 0x%xD", pkt->version);
            return NGX_DECLINED;
        }

        if (pkt->level != ssl_encryption_application) {

            if (pkt->version != qc->version) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic version mismatch: 0x%xD", pkt->version);
                return NGX_DECLINED;
            }

            if (ngx_quic_check_csid(qc, pkt) != NGX_OK) {
                return NGX_DECLINED;
            }

        } else {

            if (ngx_quic_process_stateless_reset(c, pkt) == NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic stateless reset packet detected");

                qc->draining = 1;
                ngx_quic_close_connection(c, NGX_OK);

                return NGX_OK;
            }
        }

        return ngx_quic_process_payload(c, pkt);
    }

    /* packet does not belong to a connection */

    if (rc == NGX_ABORT) {
        return ngx_quic_negotiate_version(c, pkt);
    }

    if (pkt->level == ssl_encryption_application) {
        return ngx_quic_send_stateless_reset(c, conf, pkt);
    }

    if (pkt->level != ssl_encryption_initial) {
        return NGX_ERROR;
    }

    c->log->action = "processing initial packet";

    if (pkt->dcid.len < NGX_QUIC_CID_LEN_MIN) {
        /* 7.2.  Negotiating Connection IDs */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic too short dcid in initial"
                      " packet: len:%i", pkt->dcid.len);
        return NGX_ERROR;
    }

    /* process retry and initialize connection IDs */

    if (pkt->token.len) {

        rc = ngx_quic_validate_token(c, conf->av_token_key, pkt);

        if (rc == NGX_ERROR) {
            /* internal error */
            return NGX_ERROR;

        } else if (rc == NGX_ABORT) {
            /* token cannot be decrypted */
            return ngx_quic_send_early_cc(c, pkt,
                                          NGX_QUIC_ERR_INVALID_TOKEN,
                                          "cannot decrypt token");
        } else if (rc == NGX_DECLINED) {
            /* token is invalid */

            if (pkt->retried) {
                /* invalid address validation token */
                return ngx_quic_send_early_cc(c, pkt,
                                          NGX_QUIC_ERR_INVALID_TOKEN,
                                          "invalid address validation token");
            } else if (conf->retry) {
                /* invalid NEW_TOKEN */
                return ngx_quic_send_retry(c, conf, pkt);
            }
        }

        /* NGX_OK */

    } else if (conf->retry) {
        return ngx_quic_send_retry(c, conf, pkt);

    } else {
        pkt->odcid = pkt->dcid;
    }

    if (ngx_terminate || ngx_exiting) {
        if (conf->retry) {
            return ngx_quic_send_retry(c, conf, pkt);
        }

        return NGX_ERROR;
    }

    c->log->action = "creating quic connection";

    qc = ngx_quic_new_connection(c, conf, pkt);
    if (qc == NULL) {
        return NGX_ERROR;
    }

    return ngx_quic_process_payload(c, pkt);
}


static ngx_int_t
ngx_quic_process_payload(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);

    qc->error = 0;
    qc->error_reason = 0;

    c->log->action = "decrypting packet";

    if (!ngx_quic_keys_available(qc->keys, pkt->level)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no level %d keys yet, ignoring packet", pkt->level);
        return NGX_DECLINED;
    }

    pkt->keys = qc->keys;
    pkt->key_phase = qc->key_phase;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    rc = ngx_quic_decrypt(pkt, &ctx->largest_pn);
    if (rc != NGX_OK) {
        qc->error = pkt->error;
        qc->error_reason = "failed to decrypt packet";
        return rc;
    }

    pkt->decrypted = 1;

    if (c->ssl == NULL) {
        if (ngx_quic_init_connection(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (pkt->level == ssl_encryption_handshake) {
        /*
         * 4.10.1. The successful use of Handshake packets indicates
         * that no more Initial packets need to be exchanged
         */
        ngx_quic_discard_ctx(c, ssl_encryption_initial);

        if (qc->validated == 0) {
            qc->validated = 1;
            ngx_post_event(&qc->push, &ngx_posted_events);
        }
    }

    if (qc->closing) {
        /*
         * 10.1  Closing and Draining Connection States
         * ... delayed or reordered packets are properly discarded.
         *
         *  An endpoint retains only enough information to generate
         *  a packet containing a CONNECTION_CLOSE frame and to identify
         *  packets as belonging to the connection.
         */

        qc->error_level = pkt->level;
        qc->error = NGX_QUIC_ERR_NO_ERROR;
        qc->error_reason = "connection is closing, packet discarded";
        qc->error_ftype = 0;
        qc->error_app = 0;

        return ngx_quic_send_cc(c);
    }

    pkt->received = ngx_current_msec;

    c->log->action = "handling payload";

    if (pkt->level != ssl_encryption_application) {
        return ngx_quic_handle_frames(c, pkt);
    }

    if (!pkt->key_update) {
        return ngx_quic_handle_frames(c, pkt);
    }

    /* switch keys and generate next on Key Phase change */

    qc->key_phase ^= 1;
    ngx_quic_keys_switch(c, qc->keys);

    rc = ngx_quic_handle_frames(c, pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_quic_keys_update(c, qc->keys);
}


static ngx_int_t
ngx_quic_send_early_cc(ngx_connection_t *c, ngx_quic_header_t *inpkt,
    ngx_uint_t err, const char *reason)
{
    ssize_t            len;
    ngx_str_t          res;
    ngx_quic_frame_t   frame;
    ngx_quic_header_t  pkt;

    static u_char       src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char       dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_memzero(&frame, sizeof(ngx_quic_frame_t));
    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    frame.level = inpkt->level;
    frame.type = NGX_QUIC_FT_CONNECTION_CLOSE;
    frame.u.close.error_code = err;

    frame.u.close.reason.data = (u_char *) reason;
    frame.u.close.reason.len = ngx_strlen(reason);

    len = ngx_quic_create_frame(NULL, &frame);
    if (len > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE) {
        return NGX_ERROR;
    }

    ngx_quic_log_frame(c->log, &frame, 1);

    len = ngx_quic_create_frame(src, &frame);
    if (len == -1) {
        return NGX_ERROR;
    }

    pkt.keys = ngx_quic_keys_new(c->pool);
    if (pkt.keys == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_keys_set_initial_secret(c->pool, pkt.keys, &inpkt->dcid,
                                         inpkt->version)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG
                | NGX_QUIC_PKT_INITIAL;

    pkt.num_len = 1;
    /*
     * pkt.num = 0;
     * pkt.trunc = 0;
     */

    pkt.version = inpkt->version;
    pkt.log = c->log;
    pkt.level = inpkt->level;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;
    pkt.payload.data = src;
    pkt.payload.len = len;

    res.data = dst;

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_send(c, res.data, res.len) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_quic_discard_ctx(ngx_connection_t *c, enum ssl_encryption_level_t level)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_quic_keys_available(qc->keys, level)) {
        return;
    }

    ngx_quic_keys_discard(qc->keys, level);

    qc->pto_count = 0;

    ctx = ngx_quic_get_send_ctx(qc, level);

    while (!ngx_queue_empty(&ctx->sent)) {
        q = ngx_queue_head(&ctx->sent);
        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        ngx_quic_congestion_ack(c, f);
        ngx_quic_free_frame(c, f);
    }

    while (!ngx_queue_empty(&ctx->frames)) {
        q = ngx_queue_head(&ctx->frames);
        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        ngx_quic_congestion_ack(c, f);
        ngx_quic_free_frame(c, f);
    }

    if (level == ssl_encryption_initial) {
        ngx_quic_clear_temp_server_ids(c);
    }

    ctx->send_ack = 0;

    ngx_quic_set_lost_timer(c);
}


static ngx_int_t
ngx_quic_check_csid(ngx_quic_connection_t *qc, ngx_quic_header_t *pkt)
{
    ngx_queue_t           *q;
    ngx_quic_client_id_t  *cid;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (pkt->scid.len == cid->len
            && ngx_memcmp(pkt->scid.data, cid->id, cid->len) == 0)
        {
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic scid");
    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_handle_frames(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    ngx_buf_t               buf;
    ngx_uint_t              do_close;
    ngx_chain_t             chain;
    ngx_quic_frame_t        frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    do_close = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        ngx_memzero(&buf, sizeof(ngx_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = ngx_quic_parse_frame(pkt, p, end, &frame);

        if (len < 0) {
            qc->error = pkt->error;
            return NGX_ERROR;
        }

        ngx_quic_log_frame(c->log, &frame, 0);

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:
            if (ngx_quic_handle_ack_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;

        case NGX_QUIC_FT_PADDING:
            /* no action required */
            continue;

        case NGX_QUIC_FT_CONNECTION_CLOSE:
        case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
            do_close = 1;
            continue;
        }

        /* got there with ack-eliciting packet */
        pkt->need_ack = 1;

        switch (frame.type) {

        case NGX_QUIC_FT_CRYPTO:

            if (ngx_quic_handle_crypto_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PING:
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:

            if (ngx_quic_handle_stream_frame(c, pkt, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_DATA:

            if (ngx_quic_handle_max_data_frame(c, &frame.u.max_data) != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STREAMS_BLOCKED:
        case NGX_QUIC_FT_STREAMS_BLOCKED2:

            if (ngx_quic_handle_streams_blocked_frame(c, pkt,
                                                      &frame.u.streams_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STREAM_DATA_BLOCKED:

            if (ngx_quic_handle_stream_data_blocked_frame(c, pkt,
                                                  &frame.u.stream_data_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_STREAM_DATA:

            if (ngx_quic_handle_max_stream_data_frame(c, pkt,
                                                      &frame.u.max_stream_data)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_RESET_STREAM:

            if (ngx_quic_handle_reset_stream_frame(c, pkt,
                                                   &frame.u.reset_stream)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STOP_SENDING:

            if (ngx_quic_handle_stop_sending_frame(c, pkt,
                                                   &frame.u.stop_sending)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_MAX_STREAMS:
        case NGX_QUIC_FT_MAX_STREAMS2:

            if (ngx_quic_handle_max_streams_frame(c, pkt, &frame.u.max_streams)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PATH_CHALLENGE:

            if (ngx_quic_handle_path_challenge_frame(c, pkt,
                                                     &frame.u.path_challenge)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:

            if (ngx_quic_handle_new_connection_id_frame(c, pkt, &frame.u.ncid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

            if (ngx_quic_handle_retire_connection_id_frame(c, pkt,
                                                           &frame.u.retire_cid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_PATH_RESPONSE:

            /* TODO: handle */
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic frame handler not implemented");
            break;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic missing frame handler");
            return NGX_ERROR;
        }
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic trailing garbage in payload:%ui bytes", end - p);

        qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        return NGX_ERROR;
    }

    if (do_close) {
        qc->draining = 1;
        ngx_quic_close_connection(c, NGX_OK);
    }

    if (ngx_quic_ack_packet(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_ack_packet(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    uint64_t                base, largest, smallest, gs, ge, gap, range, pn;
    uint64_t                prev_pending;
    ngx_uint_t              i, nr;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_ack_range_t   *r;
    ngx_quic_connection_t  *qc;

    c->log->action = "preparing ack";

    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_ack_packet pn:%uL largest %L fr:%uL"
                   " nranges:%ui", pkt->pn, (int64_t) ctx->largest_range,
                   ctx->first_range, ctx->nranges);

    prev_pending = ctx->pending_ack;

    if (pkt->need_ack) {

        ngx_post_event(&qc->push, &ngx_posted_events);

        if (ctx->send_ack == 0) {
            ctx->ack_delay_start = ngx_current_msec;
        }

        ctx->send_ack++;

        if (ctx->pending_ack == NGX_QUIC_UNSET_PN
            || ctx->pending_ack < pkt->pn)
        {
            ctx->pending_ack = pkt->pn;
        }
    }

    base = ctx->largest_range;
    pn = pkt->pn;

    if (base == NGX_QUIC_UNSET_PN) {
        ctx->largest_range = pn;
        ctx->largest_received = pkt->received;
        return NGX_OK;
    }

    if (base == pn) {
        return NGX_OK;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn > base) {

        if (pn - base == 1) {
            ctx->first_range++;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            return NGX_OK;

        } else {
            /* new gap in front of current largest */

            /* no place for new range, send current range as is */
            if (ctx->nranges == NGX_QUIC_MAX_RANGES) {

                if (prev_pending != NGX_QUIC_UNSET_PN) {
                    if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
                        return NGX_ERROR;
                    }
                }

                if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                    ctx->pending_ack = NGX_QUIC_UNSET_PN;
                }
            }

            gap = pn - base - 2;
            range = ctx->first_range;

            ctx->first_range = 0;
            ctx->largest_range = pn;
            ctx->largest_received = pkt->received;

            /* packet is out of order, force send */
            if (pkt->need_ack) {
                ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
            }

            i = 0;

            goto insert;
        }
    }

    /*  pn < base, perform lookup in existing ranges */

    /* packet is out of order */
    if (pkt->need_ack) {
        ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
    }

    if (pn >= smallest && pn <= largest) {
        return NGX_OK;
    }

#if (NGX_SUPPRESS_WARN)
    r = NULL;
#endif

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        ge = smallest - 1;
        gs = ge - r->gap;

        if (pn >= gs && pn <= ge) {

            if (gs == ge) {
                /* gap size is exactly one packet, now filled */

                /* data moves to previous range, current is removed */

                if (i == 0) {
                    ctx->first_range += r->range + 2;

                } else {
                    ctx->ranges[i - 1].range += r->range + 2;
                }

                nr = ctx->nranges - i - 1;
                if (nr) {
                    ngx_memmove(&ctx->ranges[i], &ctx->ranges[i + 1],
                                sizeof(ngx_quic_ack_range_t) * nr);
                }

                ctx->nranges--;

            } else if (pn == gs) {
                /* current gap shrinks from tail (current range grows) */
                r->gap--;
                r->range++;

            } else if (pn == ge) {
                /* current gap shrinks from head (previous range grows) */
                r->gap--;

                if (i == 0) {
                    ctx->first_range++;

                } else {
                    ctx->ranges[i - 1].range++;
                }

            } else {
                /* current gap is split into two parts */

                gap = ge - pn - 1;
                range = 0;

                if (ctx->nranges == NGX_QUIC_MAX_RANGES) {
                    if (prev_pending != NGX_QUIC_UNSET_PN) {
                        if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
                            return NGX_ERROR;
                        }
                    }

                    if (prev_pending == ctx->pending_ack || !pkt->need_ack) {
                        ctx->pending_ack = NGX_QUIC_UNSET_PN;
                    }
                }

                r->gap = pn - gs - 1;
                goto insert;
            }

            return NGX_OK;
        }

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= smallest && pn <= largest) {
            /* this packet number is already known */
            return NGX_OK;
        }

    }

    if (pn == smallest - 1) {
        /* extend first or last range */

        if (i == 0) {
            ctx->first_range++;

        } else {
            r->range++;
        }

        return NGX_OK;
    }

    /* nothing found, add new range at the tail  */

    if (ctx->nranges == NGX_QUIC_MAX_RANGES) {
        /* packet is too old to keep it */

        if (pkt->need_ack) {
            return ngx_quic_send_ack_range(c, ctx, pn, pn);
        }

        return NGX_OK;
    }

    gap = smallest - 2 - pn;
    range = 0;

insert:

    if (ctx->nranges < NGX_QUIC_MAX_RANGES) {
        ctx->nranges++;
    }

    ngx_memmove(&ctx->ranges[i + 1], &ctx->ranges[i],
                sizeof(ngx_quic_ack_range_t) * (ctx->nranges - i - 1));

    ctx->ranges[i].gap = gap;
    ctx->ranges[i].range = range;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_ack_range(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t smallest, uint64_t largest)
{
    ngx_quic_frame_t  *frame;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ctx->level;
    frame->type = NGX_QUIC_FT_ACK;
    frame->u.ack.largest = largest;
    frame->u.ack.delay = 0;
    frame->u.ack.range_count = 0;
    frame->u.ack.first_range = largest - smallest;

    return NGX_OK;
}


static void
ngx_quic_drop_ack_ranges(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t pn)
{
    uint64_t               base;
    ngx_uint_t             i, smallest, largest;
    ngx_quic_ack_range_t  *r;

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_drop_ack_ranges pn:%uL largest:%uL"
                   " fr:%uL nranges:%ui", pn, ctx->largest_range,
                   ctx->first_range, ctx->nranges);

    base = ctx->largest_range;

    if (base == NGX_QUIC_UNSET_PN) {
        return;
    }

    if (ctx->pending_ack != NGX_QUIC_UNSET_PN && pn >= ctx->pending_ack) {
        ctx->pending_ack = NGX_QUIC_UNSET_PN;
    }

    largest = base;
    smallest = largest - ctx->first_range;

    if (pn >= largest) {
        ctx->largest_range = NGX_QUIC_UNSET_PN;
        ctx->first_range = 0;
        ctx->nranges = 0;
        return;
    }

    if (pn >= smallest) {
        ctx->first_range = largest - pn - 1;
        ctx->nranges = 0;
        return;
    }

    for (i = 0; i < ctx->nranges; i++) {
        r = &ctx->ranges[i];

        largest = smallest - r->gap - 2;
        smallest = largest - r->range;

        if (pn >= largest) {
            ctx->nranges = i;
            return;
        }
        if (pn >= smallest) {
            r->range = largest - pn - 1;
            ctx->nranges = i + 1;
            return;
        }
    }
}


static ngx_int_t
ngx_quic_send_ack(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    size_t                  len, left;
    uint64_t                ack_delay;
    ngx_buf_t              *b;
    ngx_uint_t              i;
    ngx_chain_t            *cl, **ll;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ack_delay = ngx_current_msec - ctx->largest_received;
    ack_delay *= 1000;
    ack_delay >>= qc->tp.ack_delay_exponent;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    ll = &frame->data;
    b = NULL;

    for (i = 0; i < ctx->nranges; i++) {
        len = ngx_quic_create_ack_range(NULL, ctx->ranges[i].gap,
                                        ctx->ranges[i].range);

        left = b ? b->end - b->last : 0;

        if (left < len) {
            cl = ngx_quic_alloc_buf(c);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            left = b->end - b->last;

            if (left < len) {
                return NGX_ERROR;
            }
        }

        b->last += ngx_quic_create_ack_range(b->last, ctx->ranges[i].gap,
                                             ctx->ranges[i].range);

        frame->u.ack.ranges_length += len;
    }

    *ll = NULL;

    frame->level = ctx->level;
    frame->type = NGX_QUIC_FT_ACK;
    frame->u.ack.largest = ctx->largest_range;
    frame->u.ack.delay = ack_delay;
    frame->u.ack.range_count = ctx->nranges;
    frame->u.ack.first_range = ctx->first_range;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_cc(ngx_connection_t *c)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->draining) {
        return NGX_OK;
    }

    if (qc->closing
        && ngx_current_msec - qc->last_cc < NGX_QUIC_CC_MIN_INTERVAL)
    {
        /* dot not send CC too often */
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = qc->error_level;
    frame->type = qc->error_app ? NGX_QUIC_FT_CONNECTION_CLOSE_APP
                                : NGX_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = qc->error;
    frame->u.close.frame_type = qc->error_ftype;

    if (qc->error_reason) {
        frame->u.close.reason.len = ngx_strlen(qc->error_reason);
        frame->u.close.reason.data = (u_char *) qc->error_reason;
    }

    ngx_quic_queue_frame(qc, frame);

    qc->last_cc = ngx_current_msec;

    return ngx_quic_output(c);
}


static ngx_int_t
ngx_quic_send_new_token(ngx_connection_t *c)
{
    time_t                  expires;
    ngx_str_t               token;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!qc->conf->retry) {
        return NGX_OK;
    }

    expires = ngx_time() + NGX_QUIC_NEW_TOKEN_LIFETIME;

    if (ngx_quic_new_token(c, qc->conf->av_token_key, &token, NULL, expires, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_NEW_TOKEN;
    frame->u.token.length = token.len;
    frame->u.token.data = token.data;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_ack_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *f)
{
    ssize_t                 n;
    u_char                 *pos, *end;
    uint64_t                min, max, gap, range;
    ngx_msec_t              send_time;
    ngx_uint_t              i;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_ack_frame_t   *ack;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_handle_ack_frame level:%d", pkt->level);

    ack = &f->u.ack;

    /*
     *  If any computed packet number is negative, an endpoint MUST
     *  generate a connection error of type FRAME_ENCODING_ERROR.
     *  (19.3.1)
     */

    if (ack->first_range > ack->largest) {
        qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic invalid first range in ack frame");
        return NGX_ERROR;
    }

    min = ack->largest - ack->first_range;
    max = ack->largest;

    if (ngx_quic_handle_ack_frame_range(c, ctx, min, max, &send_time)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* 13.2.3.  Receiver Tracking of ACK Frames */
    if (ctx->largest_ack < max || ctx->largest_ack == NGX_QUIC_UNSET_PN) {
        ctx->largest_ack = max;
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic updated largest received ack:%uL", max);

        /*
         *  An endpoint generates an RTT sample on receiving an
         *  ACK frame that meets the following two conditions:
         *
         *  - the largest acknowledged packet number is newly acknowledged
         *  - at least one of the newly acknowledged packets was ack-eliciting.
         */

        if (send_time != NGX_TIMER_INFINITE) {
            ngx_quic_rtt_sample(c, ack, pkt->level, send_time);
        }
    }

    if (f->data) {
        pos = f->data->buf->pos;
        end = f->data->buf->last;

    } else {
        pos = NULL;
        end = NULL;
    }

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(pkt->log, pos, end, &gap, &range);
        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
        pos += n;

        if (gap + 2 > min) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic invalid range:%ui in ack frame", i);
            return NGX_ERROR;
        }

        max = min - gap - 2;

        if (range > max) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic invalid range:%ui in ack frame", i);
            return NGX_ERROR;
        }

        min = max - range;

        if (ngx_quic_handle_ack_frame_range(c, ctx, min, max, &send_time)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return ngx_quic_detect_lost(c);
}


static ngx_int_t
ngx_quic_handle_ack_frame_range(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    uint64_t min, uint64_t max, ngx_msec_t *send_time)
{
    ngx_uint_t              found;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    *send_time = NGX_TIMER_INFINITE;
    found = 0;

    q = ngx_queue_last(&ctx->sent);

    while (q != ngx_queue_sentinel(&ctx->sent)) {

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        q = ngx_queue_prev(q);

        if (f->pnum >= min && f->pnum <= max) {
            ngx_quic_congestion_ack(c, f);

            switch (f->type) {
            case NGX_QUIC_FT_ACK:
            case NGX_QUIC_FT_ACK_ECN:
                ngx_quic_drop_ack_ranges(c, ctx, f->u.ack.largest);
                break;

            case NGX_QUIC_FT_STREAM0:
            case NGX_QUIC_FT_STREAM1:
            case NGX_QUIC_FT_STREAM2:
            case NGX_QUIC_FT_STREAM3:
            case NGX_QUIC_FT_STREAM4:
            case NGX_QUIC_FT_STREAM5:
            case NGX_QUIC_FT_STREAM6:
            case NGX_QUIC_FT_STREAM7:
                ngx_quic_handle_stream_ack(c, f);
                break;
            }

            if (f->pnum == max) {
                *send_time = f->last;
            }

            ngx_queue_remove(&f->queue);
            ngx_quic_free_frame(c, f);
            found = 1;
        }
    }

    if (!found) {

        if (max < ctx->pnum) {
            /* duplicate ACK or ACK for non-ack-eliciting frame */
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic ACK for the packet not sent");

        qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        qc->error_ftype = NGX_QUIC_FT_ACK;
        qc->error_reason = "unknown packet number";

        return NGX_ERROR;
    }

    if (!qc->push.timer_set) {
        ngx_post_event(&qc->push, &ngx_posted_events);
    }

    qc->pto_count = 0;

    return NGX_OK;
}


static void
ngx_quic_rtt_sample(ngx_connection_t *c, ngx_quic_ack_frame_t *ack,
    enum ssl_encryption_level_t level, ngx_msec_t send_time)
{
    ngx_msec_t              latest_rtt, ack_delay, adjusted_rtt, rttvar_sample;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    latest_rtt = ngx_current_msec - send_time;
    qc->latest_rtt = latest_rtt;

    if (qc->min_rtt == NGX_TIMER_INFINITE) {
        qc->min_rtt = latest_rtt;
        qc->avg_rtt = latest_rtt;
        qc->rttvar = latest_rtt / 2;

    } else {
        qc->min_rtt = ngx_min(qc->min_rtt, latest_rtt);

        ack_delay = ack->delay * (1 << qc->ctp.ack_delay_exponent) / 1000;

        if (c->ssl->handshaked) {
            ack_delay = ngx_min(ack_delay, qc->ctp.max_ack_delay);
        }

        adjusted_rtt = latest_rtt;

        if (qc->min_rtt + ack_delay < latest_rtt) {
            adjusted_rtt -= ack_delay;
        }

        qc->avg_rtt = 0.875 * qc->avg_rtt + 0.125 * adjusted_rtt;
        rttvar_sample = ngx_abs((ngx_msec_int_t) (qc->avg_rtt - adjusted_rtt));
        qc->rttvar = 0.75 * qc->rttvar + 0.25 * rttvar_sample;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic rtt sample latest:%M min:%M avg:%M var:%M",
                   latest_rtt, qc->min_rtt, qc->avg_rtt, qc->rttvar);
}


static ngx_inline ngx_msec_t
ngx_quic_pto(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_msec_t              duration;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /* PTO calculation: quic-recovery, Appendix 8 */
    duration = qc->avg_rtt;

    duration += ngx_max(4 * qc->rttvar, NGX_QUIC_TIME_GRANULARITY);
    duration <<= qc->pto_count;

    if (qc->congestion.in_flight == 0) { /* no in-flight packets */
        return duration;
    }

    if (ctx->level == ssl_encryption_application && c->ssl->handshaked) {
        duration += qc->ctp.max_ack_delay << qc->pto_count;
    }

    return duration;
}


static void
ngx_quic_handle_stream_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    uint64_t                sent, unacked;
    ngx_event_t            *wev;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    sn = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);
    if (sn == NULL) {
        return;
    }

    wev = sn->c->write;
    sent = sn->c->sent;
    unacked = sent - sn->acked;

    if (unacked >= NGX_QUIC_STREAM_BUFSIZE && wev->active) {
        wev->ready = 1;
        ngx_post_event(wev, &ngx_posted_events);
    }

    sn->acked += f->u.stream.length;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, sn->c->log, 0,
                   "quic stream ack len:%uL acked:%uL unacked:%uL",
                   f->u.stream.length, sn->acked, sent - sn->acked);
}


static ngx_int_t
ngx_quic_handle_ordered_frame(ngx_connection_t *c, ngx_quic_frames_stream_t *fs,
    ngx_quic_frame_t *frame, ngx_quic_frame_handler_pt handler, void *data)
{
    size_t                     full_len;
    ngx_int_t                  rc;
    ngx_queue_t               *q;
    ngx_quic_ordered_frame_t  *f;

    f = &frame->u.ord;

    if (f->offset > fs->received) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic out-of-order frame: expecting:%uL got:%uL",
                       fs->received, f->offset);

        return ngx_quic_buffer_frame(c, fs, frame);
    }

    if (f->offset < fs->received) {

        if (ngx_quic_adjust_frame_offset(c, frame, fs->received)
            == NGX_DONE)
        {
            /* old/duplicate data range */
            return handler == ngx_quic_crypto_input ? NGX_DECLINED : NGX_OK;
        }

        /* intersecting data range, frame modified */
    }

    /* f->offset == fs->received */

    rc = handler(c, frame, data);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;

    } else if (rc == NGX_DONE) {
        /* handler destroyed stream, queue no longer exists */
        return NGX_OK;
    }

    /* rc == NGX_OK */

    fs->received += f->length;

    /* now check the queue if we can continue with buffered frames */

    do {
        q = ngx_queue_head(&fs->frames);
        if (q == ngx_queue_sentinel(&fs->frames)) {
            break;
        }

        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);
        f = &frame->u.ord;

        if (f->offset > fs->received) {
            /* gap found, nothing more to do */
            break;
        }

        full_len = f->length;

        if (f->offset < fs->received) {

            if (ngx_quic_adjust_frame_offset(c, frame, fs->received)
                == NGX_DONE)
            {
                /* old/duplicate data range */
                ngx_queue_remove(q);
                fs->total -= f->length;

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic skipped buffered frame, total:%ui",
                               fs->total);
                ngx_quic_free_frame(c, frame);
                continue;
            }

            /* frame was adjusted, proceed to input */
        }

        /* f->offset == fs->received */

        rc = handler(c, frame, data);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;

        } else if (rc == NGX_DONE) {
            /* handler destroyed stream, queue no longer exists */
            return NGX_OK;
        }

        fs->received += f->length;
        fs->total -= full_len;

        ngx_queue_remove(q);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic consumed buffered frame, total:%ui", fs->total);

        ngx_quic_free_frame(c, frame);

    } while (1);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_adjust_frame_offset(ngx_connection_t *c, ngx_quic_frame_t *frame,
    uint64_t offset_in)
{
    size_t                     tail, n;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_quic_ordered_frame_t  *f;

    f = &frame->u.ord;

    tail = offset_in - f->offset;

    if (tail >= f->length) {
        /* range preceeding already received data or duplicate, ignore */

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic old or duplicate data in ordered frame, ignored");
        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic adjusted ordered frame data start to expected offset");

    /* intersecting range: adjust data size */

    f->offset += tail;
    f->length -= tail;

    for (cl = frame->data; cl; cl = cl->next) {
        b = cl->buf;
        n = ngx_buf_size(b);

        if (n >= tail) {
            b->pos += tail;
            break;
        }

        cl->buf->pos = cl->buf->last;
        tail -= n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_buffer_frame(ngx_connection_t *c, ngx_quic_frames_stream_t *fs,
    ngx_quic_frame_t *frame)
{
    ngx_queue_t               *q;
    ngx_quic_frame_t          *dst, *item;
    ngx_quic_ordered_frame_t  *f, *df;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_buffer_frame");

    f = &frame->u.ord;

    /* frame start offset is in the future, buffer it */

    dst = ngx_quic_alloc_frame(c);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst, frame, sizeof(ngx_quic_frame_t));

    dst->data = ngx_quic_copy_chain(c, frame->data, 0);
    if (dst->data == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    df = &dst->u.ord;

    fs->total += f->length;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ordered frame with unexpected offset:"
                   " buffered total:%ui", fs->total);

    if (ngx_queue_empty(&fs->frames)) {
        ngx_queue_insert_after(&fs->frames, &dst->queue);
        return NGX_OK;
    }

    for (q = ngx_queue_last(&fs->frames);
         q != ngx_queue_sentinel(&fs->frames);
         q = ngx_queue_prev(q))
    {
        item = ngx_queue_data(q, ngx_quic_frame_t, queue);
        f = &item->u.ord;

        if (f->offset < df->offset) {
            ngx_queue_insert_after(q, &dst->queue);
            return NGX_OK;
        }
    }

    ngx_queue_insert_after(&fs->frames, &dst->queue);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                   last;
    ngx_int_t                  rc;
    ngx_quic_send_ctx_t       *ctx;
    ngx_quic_connection_t     *qc;
    ngx_quic_crypto_frame_t   *f;
    ngx_quic_frames_stream_t  *fs;

    qc = ngx_quic_get_connection(c);
    fs = &qc->crypto[pkt->level];
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > fs->received && last - fs->received > NGX_QUIC_MAX_BUFFERED) {
        qc->error = NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return NGX_ERROR;
    }

    rc = ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_crypto_input,
                                       NULL);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* speeding up handshake completion */

    if (pkt->level == ssl_encryption_initial) {
        ctx = ngx_quic_get_send_ctx(qc, pkt->level);

        if (!ngx_queue_empty(&ctx->sent)) {
            ngx_quic_resend_frames(c, ctx);

            ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_handshake);
            while (!ngx_queue_empty(&ctx->sent)) {
                ngx_quic_resend_frames(c, ctx);
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_crypto_input(ngx_connection_t *c, ngx_quic_frame_t *frame, void *data)
{
    int                     n, sslerr;
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic SSL_quic_read_level:%d SSL_quic_write_level:%d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    for (cl = frame->data; cl; cl = cl->next) {
        b = cl->buf;

        if (!SSL_provide_quic_data(ssl_conn, SSL_quic_read_level(ssl_conn),
                                   b->pos, b->last - b->pos))
        {
            ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                          "SSL_provide_quic_data() failed");
            return NGX_ERROR;
        }
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic SSL_quic_read_level:%d SSL_quic_write_level:%d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n <= 0) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (SSL_in_init(ssl_conn)) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ssl cipher:%s", SSL_get_cipher(ssl_conn));

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic handshake completed successfully");

    c->ssl->handshaked = 1;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    /* 12.4 Frames and frame types, figure 8 */
    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_HANDSHAKE_DONE;
    ngx_quic_queue_frame(qc, frame);

    if (ngx_quic_send_new_token(c) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Generating next keys before a key update is received.
     * See quic-tls 9.4 Header Protection Timing Side-Channels.
     */

    if (ngx_quic_keys_update(c, qc->keys) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * 4.10.2 An endpoint MUST discard its handshake keys
     * when the TLS handshake is confirmed
     */
    ngx_quic_discard_ctx(c, ssl_encryption_handshake);

    if (ngx_quic_issue_server_ids(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    size_t                     window;
    uint64_t                   last;
    ngx_buf_t                 *b;
    ngx_pool_t                *pool;
    ngx_connection_t          *sc;
    ngx_quic_stream_t         *sn;
    ngx_quic_connection_t     *qc;
    ngx_quic_stream_frame_t   *f;
    ngx_quic_frames_stream_t  *fs;

    qc = ngx_quic_get_connection(c);
    f = &frame->u.stream;

    if ((f->stream_id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->stream_id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    sn = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->stream_id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;
        fs = &sn->fs;
        b = sn->b;
        window = b->end - b->last;

        if (last > window) {
            qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
            goto cleanup;
        }

        if (ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_stream_input,
                                          sn)
            != NGX_OK)
        {
            goto cleanup;
        }

        sc->listening->handler(sc);

        return NGX_OK;
    }

    fs = &sn->fs;
    b = sn->b;
    window = (b->pos - b->start) + (b->end - b->last);

    if (last > fs->received && last - fs->received > window) {
        qc->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
        return NGX_ERROR;
    }

    return ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_stream_input,
                                         sn);

cleanup:

    pool = sc->pool;

    ngx_close_connection(sc);
    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_stream_input(ngx_connection_t *c, ngx_quic_frame_t *frame, void *data)
{
    uint64_t                  id;
    ngx_buf_t                *b;
    ngx_event_t              *rev;
    ngx_chain_t              *cl;
    ngx_quic_stream_t        *sn;
    ngx_quic_connection_t    *qc;
    ngx_quic_stream_frame_t  *f;

    qc = ngx_quic_get_connection(c);
    sn = data;

    f = &frame->u.stream;
    id = f->stream_id;

    b = sn->b;

    if ((size_t) ((b->pos - b->start) + (b->end - b->last)) < f->length) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no space in stream buffer");
        return NGX_ERROR;
    }

    if ((size_t) (b->end - b->last) < f->length) {
        b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
        b->pos = b->start;
    }

    for (cl = frame->data; cl; cl = cl->next) {
        b->last = ngx_cpymem(b->last, cl->buf->pos,
                             cl->buf->last - cl->buf->pos);
    }

    rev = sn->c->read;
    rev->ready = 1;

    if (f->fin) {
        rev->pending_eof = 1;
    }

    if (rev->active) {
        rev->handler(rev);
    }

    /* check if stream was destroyed by handler */
    if (ngx_quic_find_stream(&qc->streams.tree, id) == NULL) {
        return NGX_DONE;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_max_data_frame(ngx_connection_t *c,
    ngx_quic_max_data_frame_t *f)
{
    ngx_event_t            *wev;
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    tree = &qc->streams.tree;

    if (f->max_data <= qc->streams.send_max_data) {
        return NGX_OK;
    }

    if (qc->streams.sent >= qc->streams.send_max_data) {

        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;
            wev = qs->c->write;

            if (wev->active) {
                wev->ready = 1;
                ngx_post_event(wev, &ngx_posted_events);
            }
        }
    }

    qc->streams.send_max_data = f->max_data;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f)
{
    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stream_data_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_data_blocked_frame_t *f)
{
    size_t                  n;
    ngx_buf_t              *b;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        b = sn->b;
        n = b->end - b->last;

        sn->c->listening->handler(sn->c);

    } else {
        b = sn->b;
        n = sn->fs.received + (b->pos - b->start) + (b->end - b->last);
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = f->id;
    frame->u.max_stream_data.limit = n;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_max_stream_data_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_stream_data_frame_t *f)
{
    uint64_t                sent;
    ngx_event_t            *wev;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        if (f->limit > sn->send_max_data) {
            sn->send_max_data = f->limit;
        }

        sn->c->listening->handler(sn->c);

        return NGX_OK;
    }

    if (f->limit <= sn->send_max_data) {
        return NGX_OK;
    }

    sent = sn->c->sent;

    if (sent >= sn->send_max_data) {
        wev = sn->c->write;

        if (wev->active) {
            wev->ready = 1;
            ngx_post_event(wev, &ngx_posted_events);
        }
    }

    sn->send_max_data = f->limit;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_reset_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_reset_stream_frame_t *f)
{
    ngx_event_t            *rev;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;

        rev = sc->read;
        rev->error = 1;
        rev->ready = 1;

        sc->listening->handler(sc);

        return NGX_OK;
    }

    rev = sn->c->read;
    rev->error = 1;
    rev->ready = 1;

    if (rev->active) {
        rev->handler(rev);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stop_sending_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stop_sending_frame_t *f)
{
    ngx_event_t            *wev;
    ngx_connection_t       *sc;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if ((f->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
        && (f->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0)
    {
        qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
        return NGX_ERROR;
    }

    sn = ngx_quic_find_stream(&qc->streams.tree, f->id);

    if (sn == NULL) {
        sn = ngx_quic_create_client_stream(c, f->id);

        if (sn == NULL) {
            return NGX_ERROR;
        }

        if (sn == NGX_QUIC_STREAM_GONE) {
            return NGX_OK;
        }

        sc = sn->c;

        wev = sc->write;
        wev->error = 1;
        wev->ready = 1;

        sc->listening->handler(sc);

        return NGX_OK;
    }

    wev = sn->c->write;
    wev->error = 1;
    wev->ready = 1;

    if (wev->active) {
        wev->handler(wev);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_max_streams_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_max_streams_frame_t *f)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->bidi) {
        if (qc->streams.server_max_streams_bidi < f->limit) {
            qc->streams.server_max_streams_bidi = f->limit;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_bidi:%uL", f->limit);
        }

    } else {
        if (qc->streams.server_max_streams_uni < f->limit) {
            qc->streams.server_max_streams_uni = f->limit;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic max_streams_uni:%uL", f->limit);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_PATH_RESPONSE;
    frame->u.path_response = *f;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_new_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_new_conn_id_frame_t *f)
{
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid, *item;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (f->seqnum < qc->max_retired_seqnum) {
        /*
         *  An endpoint that receives a NEW_CONNECTION_ID frame with
         *  a sequence number smaller than the Retire Prior To field
         *  of a previously received NEW_CONNECTION_ID frame MUST send
         *  a corresponding RETIRE_CONNECTION_ID frame that retires
         *  the newly received connection  ID, unless it has already
         *  done so for that sequence number.
         */

        if (ngx_quic_retire_connection_id(c, pkt->level, f->seqnum) != NGX_OK) {
            return NGX_ERROR;
        }

        goto retire;
    }

    cid = NULL;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (item->seqnum == f->seqnum) {
            cid = item;
            break;
        }
    }

    if (cid) {
        /*
         * Transmission errors, timeouts and retransmissions might cause the
         * same NEW_CONNECTION_ID frame to be received multiple times
         */

        if (cid->len != f->len
            || ngx_strncmp(cid->id, f->cid, f->len) != 0
            || ngx_strncmp(cid->sr_token, f->srt, NGX_QUIC_SR_TOKEN_LEN) != 0)
        {
            /*
             * ..a sequence number is used for different connection IDs,
             * the endpoint MAY treat that receipt as a connection error
             * of type PROTOCOL_VIOLATION.
             */
            qc->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
            qc->error_reason = "seqnum refers to different connection id/token";
            return NGX_ERROR;
        }

    } else {

        cid = ngx_quic_alloc_client_id(c, qc);
        if (cid == NULL) {
            return NGX_ERROR;
        }

        cid->seqnum = f->seqnum;
        cid->len = f->len;
        ngx_memcpy(cid->id, f->cid, f->len);

        ngx_memcpy(cid->sr_token, f->srt, NGX_QUIC_SR_TOKEN_LEN);

        ngx_queue_insert_tail(&qc->client_ids, &cid->queue);
        qc->nclient_ids++;

        /* always use latest available connection id */
        if (f->seqnum > qc->client_seqnum) {
            qc->scid.len = cid->len;
            qc->scid.data = cid->id;
            qc->client_seqnum = f->seqnum;
        }
    }

retire:

    if (qc->max_retired_seqnum && f->retire <= qc->max_retired_seqnum) {
        /*
         * Once a sender indicates a Retire Prior To value, smaller values sent
         * in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
         * MUST ignore any Retire Prior To fields that do not increase the
         * largest received Retire Prior To value.
         */
        goto done;
    }

    qc->max_retired_seqnum = f->retire;

    q = ngx_queue_head(&qc->client_ids);

    while (q != ngx_queue_sentinel(&qc->client_ids)) {

        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);
        q = ngx_queue_next(q);

        if (cid->seqnum >= f->retire) {
            continue;
        }

        /* this connection id must be retired */

        if (ngx_quic_retire_connection_id(c, pkt->level, cid->seqnum)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_queue_remove(&cid->queue);
        ngx_queue_insert_head(&qc->free_client_ids, &cid->queue);
        qc->nclient_ids--;
    }

done:

    if (qc->nclient_ids > qc->tp.active_connection_id_limit) {
        /*
         * After processing a NEW_CONNECTION_ID frame and
         * adding and retiring active connection IDs, if the number of active
         * connection IDs exceeds the value advertised in its
         * active_connection_id_limit transport parameter, an endpoint MUST
         * close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
         */
        qc->error = NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR;
        qc->error_reason = "too many connection ids received";
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_retire_connection_id(ngx_connection_t *c,
    enum ssl_encryption_level_t level, uint64_t seqnum)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = level;
    frame->type = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
    frame->u.retire_cid.sequence_number = seqnum;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_retire_connection_id_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_retire_cid_frame_t *f)
{
    ngx_queue_t            *q;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    for (q = ngx_queue_head(&qc->server_ids);
         q != ngx_queue_sentinel(&qc->server_ids);
         q = ngx_queue_next(q))
    {
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        if (sid->seqnum == f->sequence_number) {
            ngx_queue_remove(q);
            ngx_queue_insert_tail(&qc->free_server_ids, &sid->queue);
            ngx_rbtree_delete(&c->listening->rbtree, &sid->udp.node);
            qc->nserver_ids--;
            break;
        }
    }

    return ngx_quic_issue_server_ids(c);
}


static ngx_int_t
ngx_quic_issue_server_ids(ngx_connection_t *c)
{
    ngx_str_t               dcid;
    ngx_uint_t              n;
    ngx_quic_frame_t       *frame;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;
    u_char                  id[NGX_QUIC_SERVER_CID_LEN];

    qc = ngx_quic_get_connection(c);

    n = ngx_min(NGX_QUIC_MAX_SERVER_IDS, qc->ctp.active_connection_id_limit);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic issue server ids has:%ui max:%ui", qc->nserver_ids, n);

    while (qc->nserver_ids < n) {
        if (ngx_quic_create_server_id(c, id) != NGX_OK) {
            return NGX_ERROR;
        }

        dcid.len = NGX_QUIC_SERVER_CID_LEN;
        dcid.data = id;

        sid = ngx_quic_insert_server_id(c, &dcid);
        if (sid == NULL) {
            return NGX_ERROR;
        }

        frame = ngx_quic_alloc_frame(c);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_NEW_CONNECTION_ID;
        frame->u.ncid.seqnum = sid->seqnum;
        frame->u.ncid.retire = 0;
        frame->u.ncid.len = NGX_QUIC_SERVER_CID_LEN;
        ngx_memcpy(frame->u.ncid.cid, id, NGX_QUIC_SERVER_CID_LEN);

        if (ngx_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key,
                                  frame->u.ncid.srt)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ngx_quic_queue_frame(qc, frame);
    }

    return NGX_OK;
}


static void
ngx_quic_clear_temp_server_ids(ngx_connection_t *c)
{
    ngx_queue_t            *q, *next;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic clear temp server ids");

    for (q = ngx_queue_head(&qc->server_ids);
         q != ngx_queue_sentinel(&qc->server_ids);
         q = next)
    {
        next = ngx_queue_next(q);
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        if (sid->seqnum != NGX_QUIC_UNSET_PN) {
            continue;
        }

        ngx_queue_remove(q);
        ngx_queue_insert_tail(&qc->free_server_ids, &sid->queue);
        ngx_rbtree_delete(&c->listening->rbtree, &sid->udp.node);
        qc->nserver_ids--;
    }
}


static ngx_quic_server_id_t *
ngx_quic_insert_server_id(ngx_connection_t *c, ngx_str_t *id)
{
    ngx_str_t               dcid;
    ngx_quic_server_id_t   *sid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    sid = ngx_quic_alloc_server_id(c, qc);
    if (sid == NULL) {
        return NULL;
    }

    sid->seqnum = qc->server_seqnum;

    if (qc->server_seqnum != NGX_QUIC_UNSET_PN) {
        qc->server_seqnum++;
    }

    sid->len = id->len;
    ngx_memcpy(sid->id, id->data, id->len);

    ngx_queue_insert_tail(&qc->server_ids, &sid->queue);
    qc->nserver_ids++;

    dcid.data = sid->id;
    dcid.len = sid->len;

    ngx_insert_udp_connection(c, &sid->udp, &dcid);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic insert server id seqnum:%uL id len:%uz %xV",
                   sid->seqnum, id->len, id);

    return sid;
}


static ngx_quic_client_id_t *
ngx_quic_alloc_client_id(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_queue_t           *q;
    ngx_quic_client_id_t  *cid;

    if (!ngx_queue_empty(&qc->free_client_ids)) {

        q = ngx_queue_head(&qc->free_client_ids);
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        ngx_queue_remove(&cid->queue);

        ngx_memzero(cid, sizeof(ngx_quic_client_id_t));

    } else {

        cid = ngx_pcalloc(c->pool, sizeof(ngx_quic_client_id_t));
        if (cid == NULL) {
            return NULL;
        }
    }

    return cid;
}


static ngx_quic_server_id_t *
ngx_quic_alloc_server_id(ngx_connection_t *c, ngx_quic_connection_t *qc)
{
    ngx_queue_t           *q;
    ngx_quic_server_id_t  *sid;

    if (!ngx_queue_empty(&qc->free_server_ids)) {

        q = ngx_queue_head(&qc->free_server_ids);
        sid = ngx_queue_data(q, ngx_quic_server_id_t, queue);

        ngx_queue_remove(&sid->queue);

        ngx_memzero(sid, sizeof(ngx_quic_server_id_t));

    } else {

        sid = ngx_pcalloc(c->pool, sizeof(ngx_quic_server_id_t));
        if (sid == NULL) {
            return NULL;
        }
    }

    return sid;
}


static void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_send_ctx_t  *ctx;

    ctx = ngx_quic_get_send_ctx(qc, frame->level);

    ngx_queue_insert_tail(&ctx->frames, &frame->queue);

    frame->len = ngx_quic_create_frame(NULL, frame);
    /* always succeeds */

    if (qc->closing) {
        return;
    }

    ngx_post_event(&qc->push, &ngx_posted_events);
}


static ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    off_t                   max;
    size_t                  len, min, in_flight;
    ssize_t                 n;
    u_char                 *p;
    ngx_uint_t              i, pad;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "sending frames";

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    in_flight = cg->in_flight;

    for ( ;; ) {
        p = dst;

        len = ngx_min(qc->ctp.max_udp_payload_size,
                      NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

        if (!qc->validated) {
            max = qc->received * 3;
            max = (c->sent >= max) ? 0 : max - c->sent;
            len = ngx_min(len, (size_t) max);
        }

        pad = ngx_quic_get_padding_level(c);

        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

            ctx = &qc->send_ctx[i];

            if (ngx_quic_generate_ack(c, ctx) != NGX_OK) {
                return NGX_ERROR;
            }

            min = (i == pad && p - dst < NGX_QUIC_MIN_INITIAL_SIZE)
                  ? NGX_QUIC_MIN_INITIAL_SIZE - (p - dst) : 0;

            n = ngx_quic_output_packet(c, ctx, p, len, min);
            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            p += n;
            len -= n;
        }

        len = p - dst;
        if (len == 0) {
            break;
        }

        n = ngx_quic_send(c, dst, len);
        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (in_flight != cg->in_flight && !qc->send_timer_set && !qc->closing) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


static ngx_uint_t
ngx_quic_get_padding_level(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    /*
     * 14.1.  Initial Datagram Size
     *
     * Similarly, a server MUST expand the payload of all UDP datagrams
     * carrying ack-eliciting Initial packets to at least the smallest
     * allowed maximum datagram size of 1200 bytes
     */

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_initial);

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->need_ack) {
            ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_handshake);

            if (ngx_queue_empty(&ctx->frames)) {
                return 0;
            }

            return 1;
        }
    }

    return NGX_QUIC_SEND_CTX_LAST;
}


static ngx_int_t
ngx_quic_generate_ack(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_msec_t              delay;
    ngx_quic_connection_t  *qc;

    if (!ctx->send_ack) {
        return NGX_OK;
    }

    if (ctx->level == ssl_encryption_application)  {

        delay = ngx_current_msec - ctx->ack_delay_start;
        qc = ngx_quic_get_connection(c);

        if (ctx->send_ack < NGX_QUIC_MAX_ACK_GAP
            && delay < qc->tp.max_ack_delay)
        {
            if (!qc->push.timer_set && !qc->closing) {
                ngx_add_timer(&qc->push,
                              qc->tp.max_ack_delay - delay);
            }

            return NGX_OK;
        }
    }

    if (ngx_quic_send_ack(c, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->send_ack = 0;

    return NGX_OK;
}


static ssize_t
ngx_quic_output_packet(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    u_char *data, size_t max, size_t min)
{
    size_t                  len, hlen, pad_len;
    u_char                 *p;
    ssize_t                 flen;
    ngx_str_t               out, res;
    ngx_int_t               rc;
    ngx_uint_t              nframes;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_header_t       pkt;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;
    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (ngx_queue_empty(&ctx->frames)) {
        return 0;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic output %s packet max:%uz min:%uz",
                   ngx_quic_level_name(ctx->level), max, min);

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    hlen = (ctx->level == ssl_encryption_application)
           ? NGX_QUIC_MAX_SHORT_HEADER
           : NGX_QUIC_MAX_LONG_HEADER;

    hlen += EVP_GCM_TLS_TAG_LEN;
    hlen -= NGX_QUIC_MAX_CID_LEN - qc->scid.len;

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    now = ngx_current_msec;
    nframes = 0;
    p = src;
    len = 0;

    for (q = ngx_queue_head(&ctx->frames);
         q != ngx_queue_sentinel(&ctx->frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (!pkt.need_ack && f->need_ack && max > cg->window) {
            max = cg->window;
        }

        if (hlen + len >= max) {
            break;
        }

        if (hlen + len + f->len > max) {
            rc = ngx_quic_split_frame(c, f, max - hlen - len);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_DECLINED) {
                break;
            }
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        ngx_quic_log_frame(c->log, f, 1);

        flen = ngx_quic_create_frame(p, f);
        if (flen == -1) {
            return NGX_ERROR;
        }

        len += flen;
        p += flen;

        f->pnum = ctx->pnum;
        f->first = now;
        f->last = now;
        f->plen = 0;

        nframes++;

        if (f->flush) {
            break;
        }
    }

    if (nframes == 0) {
        return 0;
    }

    out.data = src;
    out.len = len;

    pkt.keys = qc->keys;
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT;

    if (ctx->level == ssl_encryption_initial) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL;

    } else if (ctx->level == ssl_encryption_handshake) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE;

    } else {
        if (qc->key_phase) {
            pkt.flags |= NGX_QUIC_PKT_KPHASE;
        }
    }

    ngx_quic_set_packet_number(&pkt, ctx);

    pkt.version = qc->version;
    pkt.log = c->log;
    pkt.level = ctx->level;
    pkt.dcid = qc->scid;
    pkt.scid = qc->dcid;

    pad_len = 4;

    if (min) {
        hlen = EVP_GCM_TLS_TAG_LEN
               + ngx_quic_create_header(&pkt, NULL, out.len, NULL);

        if (min > hlen + pad_len) {
            pad_len = min - hlen;
        }
    }

    if (out.len < pad_len) {
        ngx_memset(p, NGX_QUIC_FT_PADDING, pad_len - out.len);
        out.len = pad_len;
    }

    pkt.payload = out;

    res.data = data;

    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet tx %s bytes:%ui"
                   " need_ack:%d number:%L encoded nl:%d trunc:0x%xD",
                   ngx_quic_level_name(ctx->level), out.len, pkt.need_ack,
                   pkt.number, pkt.num_len, pkt.trunc);

    if (ngx_quic_encrypt(&pkt, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->pnum++;

    if (pkt.need_ack) {
        /* move frames into the sent queue to wait for ack */

        if (!qc->closing) {
            q = ngx_queue_head(&ctx->frames);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);
            f->plen = res.len;

            do {
                q = ngx_queue_head(&ctx->frames);
                ngx_queue_remove(q);
                ngx_queue_insert_tail(&ctx->sent, q);
            } while (--nframes);
        }

        cg->in_flight += res.len;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion send if:%uz", cg->in_flight);
    }

    while (nframes--) {
        q = ngx_queue_head(&ctx->frames);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(q);
        ngx_quic_free_frame(c, f);
    }

    return res.len;
}


static ngx_int_t
ngx_quic_split_frame(ngx_connection_t *c, ngx_quic_frame_t *f, size_t len)
{
    size_t                     shrink;
    ngx_quic_frame_t          *nf;
    ngx_quic_ordered_frame_t  *of, *onf;

    switch (f->type) {
    case NGX_QUIC_FT_CRYPTO:
    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        break;

    default:
        return NGX_DECLINED;
    }

    if ((size_t) f->len <= len) {
        return NGX_OK;
    }

    shrink = f->len - len;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic split frame now:%uz need:%uz shrink:%uz",
                   f->len, len, shrink);

    of = &f->u.ord;

    if (of->length <= shrink) {
        return NGX_DECLINED;
    }

    of->length -= shrink;
    f->len = ngx_quic_create_frame(NULL, f);

    if ((size_t) f->len > len) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "could not split QUIC frame");
        return NGX_ERROR;
    }

    nf = ngx_quic_alloc_frame(c);
    if (nf == NULL) {
        return NGX_ERROR;
    }

    *nf = *f;
    onf = &nf->u.ord;
    onf->offset += of->length;
    onf->length = shrink;
    nf->len = ngx_quic_create_frame(NULL, nf);

    nf->data = ngx_quic_split_bufs(c, f->data, of->length);
    if (nf->data == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ngx_queue_insert_after(&f->queue, &nf->queue);

    return NGX_OK;
}


static void
ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames)
{
    ngx_queue_t       *q;
    ngx_quic_frame_t  *f;

    do {
        q = ngx_queue_head(frames);

        if (q == ngx_queue_sentinel(frames)) {
            break;
        }

        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_quic_free_frame(c, f);
    } while (1);
}


static ssize_t
ngx_quic_send(ngx_connection_t *c, u_char *buf, size_t len)
{
    ngx_buf_t    b;
    ngx_chain_t  cl, *res;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.pos = b.start = buf;
    b.last = b.end = buf + len;
    b.last_buf = 1;
    b.temporary = 1;

    cl.buf = &b;
    cl.next= NULL;

    res = c->send_chain(c, &cl, 0);
    if (res == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    return len;
}


static void
ngx_quic_set_packet_number(ngx_quic_header_t *pkt, ngx_quic_send_ctx_t *ctx)
{
    uint64_t  delta;

    delta = ctx->pnum - ctx->largest_ack;
    pkt->number = ctx->pnum;

    if (delta <= 0x7F) {
        pkt->num_len = 1;
        pkt->trunc = ctx->pnum & 0xff;

    } else if (delta <= 0x7FFF) {
        pkt->num_len = 2;
        pkt->flags |= 0x1;
        pkt->trunc = ctx->pnum & 0xffff;

    } else if (delta <= 0x7FFFFF) {
        pkt->num_len = 3;
        pkt->flags |= 0x2;
        pkt->trunc = ctx->pnum & 0xffffff;

    } else {
        pkt->num_len = 4;
        pkt->flags |= 0x3;
        pkt->trunc = ctx->pnum & 0xffffffff;
    }
}


static void
ngx_quic_pto_handler(ngx_event_t *ev)
{
    ngx_uint_t              i;
    ngx_msec_t              now;
    ngx_queue_t            *q, *next;
    ngx_connection_t       *c;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic pto timer");

    c = ev->data;
    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ngx_queue_empty(&ctx->sent)) {
            continue;
        }

        q = ngx_queue_head(&ctx->sent);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->pnum <= ctx->largest_ack
            && ctx->largest_ack != NGX_QUIC_UNSET_PN)
        {
            continue;
        }

        if ((ngx_msec_int_t) (f->last + ngx_quic_pto(c, ctx) - now) > 0) {
            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic pto %s pto_count:%ui",
                       ngx_quic_level_name(ctx->level), qc->pto_count);

        for (q = ngx_queue_head(&ctx->frames);
             q != ngx_queue_sentinel(&ctx->frames);
             /* void */)
        {
            next = ngx_queue_next(q);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (f->type == NGX_QUIC_FT_PING) {
                ngx_queue_remove(q);
                ngx_quic_free_frame(c, f);
            }

            q = next;
        }

        for (q = ngx_queue_head(&ctx->sent);
             q != ngx_queue_sentinel(&ctx->sent);
             /* void */)
        {
            next = ngx_queue_next(q);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (f->type == NGX_QUIC_FT_PING) {
                ngx_quic_congestion_lost(c, f);
                ngx_queue_remove(q);
                ngx_quic_free_frame(c, f);
            }

            q = next;
        }

        /* enforce 2 udp datagrams */

        f = ngx_quic_alloc_frame(c);
        if (f == NULL) {
            break;
        }

        f->level = ctx->level;
        f->type = NGX_QUIC_FT_PING;
        f->flush = 1;

        ngx_quic_queue_frame(qc, f);

        f = ngx_quic_alloc_frame(c);
        if (f == NULL) {
            break;
        }

        f->level = ctx->level;
        f->type = NGX_QUIC_FT_PING;

        ngx_quic_queue_frame(qc, f);
    }

    qc->pto_count++;

    ngx_quic_connstate_dbg(c);
}


static void
ngx_quic_push_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic push timer");

    c = ev->data;

    if (ngx_quic_output(c) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    ngx_quic_connstate_dbg(c);
}


static
void ngx_quic_lost_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic lost timer");

    c = ev->data;

    if (ngx_quic_detect_lost(c) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
    }

    ngx_quic_connstate_dbg(c);
}


static ngx_int_t
ngx_quic_detect_lost(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_msec_t              now, wait, thr;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;
    thr = ngx_quic_lost_threshold(qc);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ctx->largest_ack == NGX_QUIC_UNSET_PN) {
            continue;
        }

        while (!ngx_queue_empty(&ctx->sent)) {

            q = ngx_queue_head(&ctx->sent);
            start = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (start->pnum > ctx->largest_ack) {
                break;
            }

            wait = start->last + thr - now;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic detect_lost pnum:%uL thr:%M wait:%i level:%d",
                           start->pnum, thr, (ngx_int_t) wait, start->level);

            if ((ngx_msec_int_t) wait > 0
                && ctx->largest_ack - start->pnum < NGX_QUIC_PKT_THR)
            {
                break;
            }

            ngx_quic_resend_frames(c, ctx);
        }
    }

    ngx_quic_set_lost_timer(c);

    return NGX_OK;
}


static void
ngx_quic_set_lost_timer(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_msec_t              now;
    ngx_queue_t            *q;
    ngx_msec_int_t          lost, pto, w;
    ngx_quic_frame_t       *f;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    now = ngx_current_msec;

    lost = -1;
    pto = -1;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ctx = &qc->send_ctx[i];

        if (ngx_queue_empty(&ctx->sent)) {
            continue;
        }

        if (ctx->largest_ack != NGX_QUIC_UNSET_PN) {
            q = ngx_queue_head(&ctx->sent);
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);
            w = (ngx_msec_int_t) (f->last + ngx_quic_lost_threshold(qc) - now);

            if (f->pnum <= ctx->largest_ack) {
                if (w < 0 || ctx->largest_ack - f->pnum >= NGX_QUIC_PKT_THR) {
                    w = 0;
                }

                if (lost == -1 || w < lost) {
                    lost = w;
                }
            }
        }

        q = ngx_queue_last(&ctx->sent);
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        w = (ngx_msec_int_t) (f->last + ngx_quic_pto(c, ctx) - now);

        if (w < 0) {
            w = 0;
        }

        if (pto == -1 || w < pto) {
            pto = w;
        }
    }

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    if (lost != -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic lost timer lost:%M", lost);

        qc->pto.handler = ngx_quic_lost_handler;
        ngx_add_timer(&qc->pto, lost);
        return;
    }

    if (pto != -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic lost timer pto:%M", pto);

        qc->pto.handler = ngx_quic_pto_handler;
        ngx_add_timer(&qc->pto, pto);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic lost timer unset");
}


static void
ngx_quic_resend_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    size_t                  n;
    ngx_buf_t              *b;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    q = ngx_queue_head(&ctx->sent);
    start = ngx_queue_data(q, ngx_quic_frame_t, queue);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic resend packet pnum:%uL", start->pnum);

    ngx_quic_congestion_lost(c, start);

    do {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->pnum != start->pnum) {
            break;
        }

        q = ngx_queue_next(q);

        ngx_queue_remove(&f->queue);

        switch (f->type) {
        case NGX_QUIC_FT_ACK:
        case NGX_QUIC_FT_ACK_ECN:
            if (ctx->level == ssl_encryption_application) {
                /* force generation of most recent acknowledgment */
                ctx->send_ack = NGX_QUIC_MAX_ACK_GAP;
            }

            ngx_quic_free_frame(c, f);
            break;

        case NGX_QUIC_FT_PING:
        case NGX_QUIC_FT_PATH_RESPONSE:
        case NGX_QUIC_FT_CONNECTION_CLOSE:
            ngx_quic_free_frame(c, f);
            break;

        case NGX_QUIC_FT_MAX_DATA:
            f->u.max_data.max_data = qc->streams.recv_max_data;
            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_MAX_STREAMS:
        case NGX_QUIC_FT_MAX_STREAMS2:
            f->u.max_streams.limit = f->u.max_streams.bidi
                                     ? qc->streams.client_max_streams_bidi
                                     : qc->streams.client_max_streams_uni;
            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_MAX_STREAM_DATA:
            sn = ngx_quic_find_stream(&qc->streams.tree,
                                      f->u.max_stream_data.id);
            if (sn == NULL) {
                ngx_quic_free_frame(c, f);
                break;
            }

            b = sn->b;
            n = sn->fs.received + (b->pos - b->start) + (b->end - b->last);

            if (f->u.max_stream_data.limit < n) {
                f->u.max_stream_data.limit = n;
            }

            ngx_quic_queue_frame(qc, f);
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:
            sn = ngx_quic_find_stream(&qc->streams.tree, f->u.stream.stream_id);

            if (sn && sn->c->write->error) {
                /* RESET_STREAM was sent */
                ngx_quic_free_frame(c, f);
                break;
            }

            /* fall through */

        default:
            ngx_queue_insert_tail(&ctx->frames, &f->queue);
        }

    } while (q != ngx_queue_sentinel(&ctx->sent));

    if (qc->closing) {
        return;
    }

    ngx_post_event(&qc->push, &ngx_posted_events);
}


ngx_connection_t *
ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi)
{
    size_t                  rcvbuf_size;
    uint64_t                id;
    ngx_quic_stream_t      *qs, *sn;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    qc = ngx_quic_get_connection(qs->parent);

    if (bidi) {
        if (qc->streams.server_streams_bidi
            >= qc->streams.server_max_streams_bidi)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server bidi streams:%uL",
                           qc->streams.server_streams_bidi);
            return NULL;
        }

        id = (qc->streams.server_streams_bidi << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server bidi stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_bidi,
                       qc->streams.server_max_streams_bidi, id);

        qc->streams.server_streams_bidi++;
        rcvbuf_size = qc->tp.initial_max_stream_data_bidi_local;

    } else {
        if (qc->streams.server_streams_uni
            >= qc->streams.server_max_streams_uni)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server uni streams:%uL",
                           qc->streams.server_streams_uni);
            return NULL;
        }

        id = (qc->streams.server_streams_uni << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED
             | NGX_QUIC_STREAM_UNIDIRECTIONAL;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server uni stream"
                       " streams:%uL max:%uL id:0x%xL",
                       qc->streams.server_streams_uni,
                       qc->streams.server_max_streams_uni, id);

        qc->streams.server_streams_uni++;
        rcvbuf_size = 0;
    }

    sn = ngx_quic_create_stream(qs->parent, id, rcvbuf_size);
    if (sn == NULL) {
        return NULL;
    }

    return sn->c;
}


static void
ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_quic_stream_t   *qn, *qnt;

    for ( ;; ) {
        qn = (ngx_quic_stream_t *) node;
        qnt = (ngx_quic_stream_t *) temp;

        p = (qn->id < qnt->id) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_quic_stream_t *
ngx_quic_find_stream(ngx_rbtree_t *rbtree, uint64_t id)
{
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_quic_stream_t  *qn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        qn = (ngx_quic_stream_t *) node;

        if (id == qn->id) {
            return qn;
        }

        node = (id < qn->id) ? node->left : node->right;
    }

    return NULL;
}


static ngx_quic_stream_t *
ngx_quic_create_client_stream(ngx_connection_t *c, uint64_t id)
{
    size_t                  n;
    uint64_t                min_id;
    ngx_quic_stream_t      *sn;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL is new", id);

    qc = ngx_quic_get_connection(c);

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {

        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_uni) {
                return NGX_QUIC_STREAM_GONE;
            }

            qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_uni) {
            return NGX_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_uni) {
            qc->error = NGX_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_uni << 2)
                 | NGX_QUIC_STREAM_UNIDIRECTIONAL;
        qc->streams.client_streams_uni = (id >> 2) + 1;
        n = qc->tp.initial_max_stream_data_uni;

    } else {

        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            if ((id >> 2) < qc->streams.server_streams_bidi) {
                return NGX_QUIC_STREAM_GONE;
            }

            qc->error = NGX_QUIC_ERR_STREAM_STATE_ERROR;
            return NULL;
        }

        if ((id >> 2) < qc->streams.client_streams_bidi) {
            return NGX_QUIC_STREAM_GONE;
        }

        if ((id >> 2) >= qc->streams.client_max_streams_bidi) {
            qc->error = NGX_QUIC_ERR_STREAM_LIMIT_ERROR;
            return NULL;
        }

        min_id = (qc->streams.client_streams_bidi << 2);
        qc->streams.client_streams_bidi = (id >> 2) + 1;
        n = qc->tp.initial_max_stream_data_bidi_remote;
    }

    if (n < NGX_QUIC_STREAM_BUFSIZE) {
        n = NGX_QUIC_STREAM_BUFSIZE;
    }

    /*
     *   2.1.  Stream Types and Identifiers
     *
     *   Within each type, streams are created with numerically increasing
     *   stream IDs.  A stream ID that is used out of order results in all
     *   streams of that type with lower-numbered stream IDs also being
     *   opened.
     */

    for ( /* void */ ; min_id < id; min_id += 0x04) {

        sn = ngx_quic_create_stream(c, min_id, n);
        if (sn == NULL) {
            return NULL;
        }

        sn->c->listening->handler(sn->c);
    }

    return ngx_quic_create_stream(c, id, n);
}


static ngx_quic_stream_t *
ngx_quic_create_stream(ngx_connection_t *c, uint64_t id, size_t rcvbuf_size)
{
    ngx_log_t              *log;
    ngx_pool_t             *pool;
    ngx_quic_stream_t      *sn;
    ngx_pool_cleanup_t     *cln;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL create", id);

    qc = ngx_quic_get_connection(c);

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        return NULL;
    }

    sn = ngx_pcalloc(pool, sizeof(ngx_quic_stream_t));
    if (sn == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->node.key = id;
    sn->parent = c;
    sn->id = id;

    sn->b = ngx_create_temp_buf(pool, rcvbuf_size);
    if (sn->b == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_queue_init(&sn->fs.frames);

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sn->c = ngx_get_connection(-1, log);
    if (sn->c == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    sn->c->quic = sn;
    sn->c->type = SOCK_STREAM;
    sn->c->pool = pool;
    sn->c->ssl = c->ssl;
    sn->c->sockaddr = c->sockaddr;
    sn->c->listening = c->listening;
    sn->c->addr_text = c->addr_text;
    sn->c->local_sockaddr = c->local_sockaddr;
    sn->c->local_socklen = c->local_socklen;
    sn->c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    sn->c->recv = ngx_quic_stream_recv;
    sn->c->send = ngx_quic_stream_send;
    sn->c->send_chain = ngx_quic_stream_send_chain;

    sn->c->read->log = log;
    sn->c->write->log = log;

    log->connection = sn->c->number;

    if ((id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0
        || (id & NGX_QUIC_STREAM_SERVER_INITIATED))
    {
        sn->c->write->ready = 1;
    }

    if (id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            sn->send_max_data = qc->ctp.initial_max_stream_data_uni;
        }

    } else {
        if (id & NGX_QUIC_STREAM_SERVER_INITIATED) {
            sn->send_max_data = qc->ctp.initial_max_stream_data_bidi_remote;
        } else {
            sn->send_max_data = qc->ctp.initial_max_stream_data_bidi_local;
        }
    }

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sn->c);
        ngx_destroy_pool(pool);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sn->c;

    ngx_rbtree_insert(&qc->streams.tree, &sn->node);

    return sn;
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                 len;
    ngx_buf_t              *b;
    ngx_event_t            *rev;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    b = qs->b;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);
    rev = c->read;

    if (rev->error) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream recv id:0x%xL eof:%d avail:%z",
                   qs->id, rev->pending_eof, b->last - b->pos);

    if (b->pos == b->last) {
        rev->ready = 0;

        if (rev->pending_eof) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv() not ready", qs->id);
        return NGX_AGAIN;
    }

    len = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, len);

    b->pos += len;
    qc->streams.received += len;

    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
        rev->ready = rev->pending_eof;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL recv len:%z of size:%uz",
                   qs->id, len, size);

    if (!rev->pending_eof) {
        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
        frame->u.max_stream_data.id = qs->id;
        frame->u.max_stream_data.limit = qs->fs.received + (b->pos - b->start)
                                         + (b->end - b->last);

        ngx_quic_queue_frame(qc, frame);
    }

    if ((qc->streams.recv_max_data / 2) < qc->streams.received) {

        frame = ngx_quic_alloc_frame(pc);

        if (frame == NULL) {
            return NGX_ERROR;
        }

        qc->streams.recv_max_data *= 2;

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_DATA;
        frame->u.max_data.max_data = qc->streams.recv_max_data;

        ngx_quic_queue_frame(qc, frame);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id:0x%xL recv: increased max_data:%uL",
                       qs->id, qc->streams.recv_max_data);
    }

    return len;
}


static ssize_t
ngx_quic_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_buf_t    b;
    ngx_chain_t  cl;

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.memory = 1;
    b.pos = buf;
    b.last = buf + size;

    cl.buf = &b;
    cl.next = NULL;

    if (ngx_quic_stream_send_chain(c, &cl, 0) == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (b.pos == buf) {
        return NGX_AGAIN;
    }

    return b.pos - buf;
}


static ngx_chain_t *
ngx_quic_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    size_t                  n, flow;
    ngx_event_t            *wev;
    ngx_chain_t            *cl;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);
    wev = c->write;

    if (wev->error) {
        return NGX_CHAIN_ERROR;
    }

    flow = ngx_quic_max_stream_flow(c);
    if (flow == 0) {
        wev->ready = 0;
        return in;
    }

    n = (limit && (size_t) limit < flow) ? (size_t) limit : flow;

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return NGX_CHAIN_ERROR;
    }

    frame->data = ngx_quic_copy_chain(pc, in, n);
    if (frame->data == NGX_CHAIN_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    for (n = 0, cl = frame->data; cl; cl = cl->next) {
        n += ngx_buf_size(cl->buf);
    }

    while (in && ngx_buf_size(in->buf) == 0) {
        in = in->next;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM6; /* OFF=1 LEN=1 FIN=0 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 0;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = n;

    c->sent += n;
    qc->streams.sent += n;

    ngx_quic_queue_frame(qc, frame);

    wev->ready = (n < flow) ? 1 : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send_chain sent:%uz", n);

    return in;
}


static size_t
ngx_quic_max_stream_flow(ngx_connection_t *c)
{
    size_t                  size;
    uint64_t                sent, unacked;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    qc = ngx_quic_get_connection(qs->parent);

    size = NGX_QUIC_STREAM_BUFSIZE;
    sent = c->sent;
    unacked = sent - qs->acked;

    if (qc->streams.send_max_data == 0) {
        qc->streams.send_max_data = qc->ctp.initial_max_data;
    }

    if (unacked >= NGX_QUIC_STREAM_BUFSIZE) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit buffer size");
        return 0;
    }

    if (unacked + size > NGX_QUIC_STREAM_BUFSIZE) {
        size = NGX_QUIC_STREAM_BUFSIZE - unacked;
    }

    if (qc->streams.sent >= qc->streams.send_max_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit MAX_DATA");
        return 0;
    }

    if (qc->streams.sent + size > qc->streams.send_max_data) {
        size = qc->streams.send_max_data - qc->streams.sent;
    }

    if (sent >= qs->send_max_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic send flow hit MAX_STREAM_DATA");
        return 0;
    }

    if (sent + size > qs->send_max_data) {
        size = qs->send_max_data - sent;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send flow:%uz", size);

    return size;
}


static void
ngx_quic_stream_cleanup_handler(void *data)
{
    ngx_connection_t *c = data;

    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->quic;
    pc = qs->parent;
    qc = ngx_quic_get_connection(pc);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL cleanup", qs->id);

    ngx_rbtree_delete(&qc->streams.tree, &qs->node);
    ngx_quic_free_frames(pc, &qs->fs.frames);

    if (qc->closing) {
        /* schedule handler call to continue ngx_quic_close_connection() */
        ngx_post_event(pc->read, &ngx_posted_events);
        return;
    }

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0
        || (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) == 0)
    {
        if (!c->read->pending_eof && !c->read->error) {
            frame = ngx_quic_alloc_frame(pc);
            if (frame == NULL) {
                return;
            }

            frame->level = ssl_encryption_application;
            frame->type = NGX_QUIC_FT_STOP_SENDING;
            frame->u.stop_sending.id = qs->id;
            frame->u.stop_sending.error_code = 0x100; /* HTTP/3 no error */

            ngx_quic_queue_frame(qc, frame);
        }
    }

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = ngx_quic_alloc_frame(pc);
        if (frame == NULL) {
            return;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_STREAMS;

        if (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_uni;
            frame->u.max_streams.bidi = 0;

        } else {
            frame->u.max_streams.limit = ++qc->streams.client_max_streams_bidi;
            frame->u.max_streams.bidi = 1;
        }

        ngx_quic_queue_frame(qc, frame);

        if (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
            /* do not send fin for client unidirectional streams */
            return;
        }
    }

    if (c->write->error) {
        goto error;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id:0x%xL send fin", qs->id);

    frame = ngx_quic_alloc_frame(pc);
    if (frame == NULL) {
        return;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM7; /* OFF=1 LEN=1 FIN=1 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 1;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = 0;

    ngx_quic_queue_frame(qc, frame);

error:

    (void) ngx_quic_output(pc);
}


static ngx_quic_frame_t *
ngx_quic_alloc_frame(ngx_connection_t *c)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_queue_empty(&qc->free_frames)) {

        q = ngx_queue_head(&qc->free_frames);
        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(&frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse frame n:%ui", qc->nframes);
#endif

    } else {
        frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
        if (frame == NULL) {
            return NULL;
        }

#ifdef NGX_QUIC_DEBUG_ALLOC
        ++qc->nframes;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic alloc frame n:%ui", qc->nframes);
#endif
    }

    ngx_memzero(frame, sizeof(ngx_quic_frame_t));

    return frame;
}


static void
ngx_quic_congestion_ack(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_msec_t              timer;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    cg->in_flight -= f->plen;

    timer = f->last - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack recovery win:%uz ss:%z if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);

        return;
    }

    if (cg->window < cg->ssthresh) {
        cg->window += f->plen;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion slow start win:%uz ss:%z if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);

    } else {
        cg->window += qc->tp.max_udp_payload_size * f->plen / cg->window;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion avoidance win:%uz ss:%z if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);
    }

    /* prevent recovery_start from wrapping */

    timer = cg->recovery_start - ngx_current_msec + qc->tp.max_idle_timeout * 2;

    if ((ngx_msec_int_t) timer < 0) {
        cg->recovery_start = ngx_current_msec - qc->tp.max_idle_timeout * 2;
    }
}


static void
ngx_quic_congestion_lost(ngx_connection_t *c, ngx_quic_frame_t *f)
{
    ngx_msec_t              timer;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    if (f->plen == 0) {
        return;
    }

    qc = ngx_quic_get_connection(c);
    cg = &qc->congestion;

    cg->in_flight -= f->plen;
    f->plen = 0;

    timer = f->last - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost recovery win:%uz ss:%z if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);

        return;
    }

    cg->recovery_start = ngx_current_msec;
    cg->window /= 2;

    if (cg->window < qc->tp.max_udp_payload_size * 2) {
        cg->window = qc->tp.max_udp_payload_size * 2;
    }

    cg->ssthresh = cg->window;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic congestion lost win:%uz ss:%z if:%uz",
                   cg->window, cg->ssthresh, cg->in_flight);
}


static void
ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (frame->data) {
        ngx_quic_free_bufs(c, frame->data);
    }

    ngx_queue_insert_head(&qc->free_frames, &frame->queue);

#ifdef NGX_QUIC_DEBUG_ALLOC
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free frame n:%ui", qc->nframes);
#endif
}


uint32_t
ngx_quic_version(ngx_connection_t *c)
{
    uint32_t                version;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    version = qc->version;

    return (version & 0xff000000) == 0xff000000 ? version & 0xff : version;
}


static ngx_chain_t *
ngx_quic_alloc_buf(ngx_connection_t *c)
{
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->free_bufs) {
        cl = qc->free_bufs;
        qc->free_bufs = cl->next;

        b = cl->buf;
        b->pos = b->start;
        b->last = b->start;

#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse buffer n:%ui", qc->nbufs);
#endif

        return cl;
    }

    cl = ngx_alloc_chain_link(c->pool);
    if (cl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(c->pool, NGX_QUIC_BUFFER_SIZE);
    if (b == NULL) {
        return NULL;
    }

    b->tag = (ngx_buf_tag_t) &ngx_quic_alloc_buf;

    cl->buf = b;

#ifdef NGX_QUIC_DEBUG_ALLOC
    ++qc->nbufs;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic alloc buffer n:%ui", qc->nbufs);
#endif

    return cl;
}


static void
ngx_quic_free_bufs(ngx_connection_t *c, ngx_chain_t *in)
{
    ngx_buf_t              *b, *shadow;
    ngx_chain_t            *cl;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    while (in) {
#ifdef NGX_QUIC_DEBUG_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic free buffer n:%ui", qc->nbufs);
#endif

        cl = in;
        in = in->next;
        b = cl->buf;

        if (b->shadow) {
            if (!b->last_shadow) {
                b->recycled = 1;
                ngx_free_chain(c->pool, cl);
                continue;
            }

            do {
                shadow = b->shadow;
                b->shadow = qc->free_shadow_bufs;
                qc->free_shadow_bufs = b;
                b = shadow;
            } while (b->recycled);

            if (b->shadow) {
                b->last_shadow = 1;
                ngx_free_chain(c->pool, cl);
                continue;
            }

            cl->buf = b;
        }

        cl->next = qc->free_bufs;
        qc->free_bufs = cl;
    }
}


static ngx_chain_t *
ngx_quic_copy_buf(ngx_connection_t *c, u_char *data, size_t len)
{
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *out, **ll;

    out = NULL;
    ll = &out;

    while (len) {
        cl = ngx_quic_alloc_buf(c);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        b = cl->buf;
        n = ngx_min((size_t) (b->end - b->last), len);

        b->last = ngx_cpymem(b->last, data, n);

        data += n;
        len -= n;

        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return out;
}


static ngx_chain_t *
ngx_quic_copy_chain(ngx_connection_t *c, ngx_chain_t *in, size_t limit)
{
    size_t        n;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *out, **ll;

    out = NULL;
    ll = &out;

    while (in) {
        if (!ngx_buf_in_memory(in->buf) || ngx_buf_size(in->buf) == 0) {
            in = in->next;
            continue;
        }

        cl = ngx_quic_alloc_buf(c);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        while (in && b->last != b->end) {

            n = ngx_min(in->buf->last - in->buf->pos, b->end - b->last);

            if (limit > 0 && n > limit) {
                n = limit;
            }

            b->last = ngx_cpymem(b->last, in->buf->pos, n);

            in->buf->pos += n;
            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }

            if (limit > 0) {
                if (limit == n) {
                    goto done;
                }

                limit -= n;
            }
        }

    }

done:

    *ll = NULL;

    return out;
}


static ngx_chain_t *
ngx_quic_split_bufs(ngx_connection_t *c, ngx_chain_t *in, size_t len)
{
    size_t                  n;
    ngx_buf_t              *b;
    ngx_chain_t            *out;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    while (in) {
        n = ngx_buf_size(in->buf);

        if (n == len) {
            out = in->next;
            in->next = NULL;
            return out;
        }

        if (n > len) {
            break;
        }

        len -= n;
        in = in->next;
    }

    if (in == NULL) {
        return NULL;
    }

    /* split in->buf by creating shadow bufs which reference it */

    if (in->buf->shadow == NULL) {
        if (qc->free_shadow_bufs) {
            b = qc->free_shadow_bufs;
            qc->free_shadow_bufs = b->shadow;

        } else {
            b = ngx_alloc_buf(c->pool);
            if (b == NULL) {
                return NGX_CHAIN_ERROR;
            }
        }

        *b = *in->buf;
        b->shadow = in->buf;
        b->last_shadow = 1;
        in->buf = b;
    }

    out = ngx_alloc_chain_link(c->pool);
    if (out == NULL) {
        return NGX_CHAIN_ERROR;
    }

    if (qc->free_shadow_bufs) {
        b = qc->free_shadow_bufs;
        qc->free_shadow_bufs = b->shadow;

    } else {
        b = ngx_alloc_buf(c->pool);
        if (b == NULL) {
            ngx_free_chain(c->pool, out);
            return NGX_CHAIN_ERROR;
        }
    }

    out->buf = b;
    out->next = in->next;
    in->next = NULL;

    *b = *in->buf;
    b->last_shadow = 0;
    b->pos = b->pos + len;

    in->buf->shadow = b;
    in->buf->last = in->buf->pos + len;

    return out;
}
