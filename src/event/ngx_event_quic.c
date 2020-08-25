
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_transport.h>
#include <ngx_event_quic_protection.h>


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

#define NGX_QUIC_SEND_CTX_LAST  (NGX_QUIC_ENCRYPTION_LAST - 1)

#define NGX_QUIC_STREAMS_INC     16
#define NGX_QUIC_STREAMS_LIMIT   (1ULL < 60)

/*
 * 7.4.  Cryptographic Message Buffering
 *       Implementations MUST support buffering at least 4096 bytes of data
 */
#define NGX_QUIC_MAX_BUFFERED    65535

#define NGX_QUIC_STREAM_GONE     (void *) -1


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
    ngx_quic_secret_t                 client_secret;
    ngx_quic_secret_t                 server_secret;

    uint64_t                          pnum;        /* to be sent */
    uint64_t                          largest_ack; /* received from peer */
    uint64_t                          largest_pn;  /* received from peer */

    ngx_queue_t                       frames;
    ngx_queue_t                       sent;
} ngx_quic_send_ctx_t;


struct ngx_quic_connection_s {
    ngx_str_t                         scid;
    ngx_str_t                         dcid;
    ngx_str_t                         odcid;
    ngx_str_t                         token;

    ngx_uint_t                        client_tp_done;
    ngx_quic_tp_t                     tp;
    ngx_quic_tp_t                     ctp;

    ngx_quic_send_ctx_t               send_ctx[NGX_QUIC_SEND_CTX_LAST];
    ngx_quic_secrets_t                keys[NGX_QUIC_ENCRYPTION_LAST];
    ngx_quic_secrets_t                next_key;
    ngx_quic_frames_stream_t          crypto[NGX_QUIC_ENCRYPTION_LAST];

    ngx_quic_conf_t                  *conf;

    ngx_ssl_t                        *ssl;

    ngx_event_t                       push;
    ngx_event_t                       pto;
    ngx_event_t                       close;
    ngx_queue_t                       free_frames;
    ngx_msec_t                        last_cc;

    ngx_msec_t                        latest_rtt;
    ngx_msec_t                        avg_rtt;
    ngx_msec_t                        min_rtt;
    ngx_msec_t                        rttvar;

    ngx_uint_t                        pto_count;

#if (NGX_DEBUG)
    ngx_uint_t                        nframes;
#endif

    ngx_quic_streams_t                streams;
    ngx_quic_congestion_t             congestion;
    size_t                            received;

    ngx_uint_t                        error;
    enum ssl_encryption_level_t       error_level;
    ngx_uint_t                        error_ftype;
    const char                       *error_reason;

    unsigned                          error_app:1;
    unsigned                          send_timer_set:1;
    unsigned                          closing:1;
    unsigned                          draining:1;
    unsigned                          key_phase:1;
    unsigned                          in_retry:1;
    unsigned                          initialized:1;
    unsigned                          validated:1;
};


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


static ngx_int_t ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_negotiate_version(ngx_connection_t *c,
    ngx_quic_header_t *inpkt);
static ngx_int_t ngx_quic_new_dcid(ngx_connection_t *c, ngx_str_t *odcid);
static ngx_int_t ngx_quic_retry(ngx_connection_t *c);
static ngx_int_t ngx_quic_new_token(ngx_connection_t *c, ngx_str_t *token);
static ngx_int_t ngx_quic_validate_token(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);
static ngx_inline size_t ngx_quic_max_udp_payload(ngx_connection_t *c);
static void ngx_quic_input_handler(ngx_event_t *rev);

static void ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc);
static ngx_int_t ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc);
static void ngx_quic_close_timer_handler(ngx_event_t *ev);
static ngx_int_t ngx_quic_close_streams(ngx_connection_t *c,
    ngx_quic_connection_t *qc);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b);
static ngx_inline u_char *ngx_quic_skip_zero_padding(ngx_buf_t *b);
static ngx_int_t ngx_quic_retry_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_initial_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handshake_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_early_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_check_peer(ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_app_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_payload_handler(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_send_ack(ngx_connection_t *c, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_ack_delay(ngx_connection_t *c,
    struct timeval *received, enum ssl_encryption_level_t level);
static ngx_int_t ngx_quic_send_cc(ngx_connection_t *c);
static ngx_int_t ngx_quic_send_new_token(ngx_connection_t *c);

static ngx_int_t ngx_quic_handle_ack_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_ack_frame_t *f);
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

static void ngx_quic_queue_frame(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *frame);

static ngx_int_t ngx_quic_output(ngx_connection_t *c);
static ngx_int_t ngx_quic_output_frames(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_free_frames(ngx_connection_t *c, ngx_queue_t *frames);
static ngx_int_t ngx_quic_send_frames(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, ngx_queue_t *frames);

static void ngx_quic_set_packet_number(ngx_quic_header_t *pkt,
    ngx_quic_send_ctx_t *ctx);
static void ngx_quic_pto_handler(ngx_event_t *ev);
static void ngx_quic_lost_handler(ngx_event_t *ev);
static ngx_int_t ngx_quic_detect_lost(ngx_connection_t *c);
static ngx_int_t ngx_quic_resend_frames(ngx_connection_t *c,
    ngx_quic_send_ctx_t *ctx, ngx_quic_frame_t *start);
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
static size_t ngx_quic_max_stream_frame(ngx_quic_connection_t *qc);
static size_t ngx_quic_max_stream_flow(ngx_connection_t *c);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_quic_frame_t *ngx_quic_alloc_frame(ngx_connection_t *c, size_t size);
static void ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame);

static void ngx_quic_congestion_ack(ngx_connection_t *c,
    ngx_quic_frame_t *frame);
static void ngx_quic_congestion_lost(ngx_connection_t *c,
    ngx_quic_frame_t *frame);


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


#if BORINGSSL_API_VERSION >= 10

static int
ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_read_secret() level:%d", level);
    ngx_quic_hexdump(c->log, "quic read secret", rsecret, secret_len);
#endif

    keys = &c->quic->keys[level];

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          rsecret, secret_len,
                                          &keys->client);
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_write_secret() level:%d", level);
    ngx_quic_hexdump(c->log, "quic write secret", wsecret, secret_len);
#endif

    keys = &c->quic->keys[level];

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &keys->server);
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_quic_secrets_t  *keys;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_encryption_secrets() level:%d", level);
    ngx_quic_hexdump(c->log, "quic read", rsecret, secret_len);
#endif

    keys = &c->quic->keys[level];

    rc = ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                        rsecret, secret_len,
                                        &keys->client);
    if (rc != 1) {
        return rc;
    }

    if (level == ssl_encryption_early_data) {
        return 1;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_quic_hexdump(c->log, "quic write", wsecret, secret_len);
#endif

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &keys->server);
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                    *p, *end;
    size_t                     client_params_len, fsize, limit;
    const uint8_t             *client_params;
    ngx_quic_frame_t          *frame;
    ngx_connection_t          *c;
    ngx_quic_connection_t     *qc;
    ngx_quic_frames_stream_t  *fs;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = c->quic;

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

            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

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
                       " params_len %ui", client_params_len);

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

        if (ngx_quic_parse_transport_params(p, end, &qc->ctp, c->log)
            != NGX_OK)
        {
            qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
            qc->error_reason = "failed to process transport parameters";

            return 0;
        }

        if (qc->ctp.max_idle_timeout > 0
            && qc->ctp.max_idle_timeout < qc->tp.max_idle_timeout)
        {
            qc->tp.max_idle_timeout = qc->ctp.max_idle_timeout;
        }

        if (qc->ctp.max_udp_payload_size < NGX_QUIC_MIN_INITIAL_SIZE
            || qc->ctp.max_udp_payload_size > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE)
        {
            qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
            qc->error_reason = "invalid maximum packet size";

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic maximum packet size is invalid");
            return 0;
        }

        if (qc->ctp.max_udp_payload_size > ngx_quic_max_udp_payload(c)) {
            qc->ctp.max_udp_payload_size = ngx_quic_max_udp_payload(c);
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                          "quic client maximum packet size truncated");
        }

#if (NGX_QUIC_DRAFT_VERSION >= 28)
        if (qc->scid.len != qc->ctp.initial_scid.len
            || ngx_memcmp(qc->scid.data, qc->ctp.initial_scid.data,
                          qc->scid.len) != 0)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic client initial_source_connection_id "
                          "mismatch");
            return 0;
        }
#endif

        qc->streams.server_max_streams_bidi = qc->ctp.initial_max_streams_bidi;
        qc->streams.server_max_streams_uni = qc->ctp.initial_max_streams_uni;

        qc->client_tp_done = 1;
    }

    /*
     * we need to fit at least 1 frame into a packet, thus account head/tail;
     * 17 = 1 + 8x2 is max header for CRYPTO frame, with 1 byte for frame type
     */
    limit = qc->ctp.max_udp_payload_size - NGX_QUIC_MAX_LONG_HEADER - 17
            - EVP_GCM_TLS_TAG_LEN;

    fs = &qc->crypto[level];

    p = (u_char *) data;
    end = (u_char *) data + len;

    while (p < end) {

        fsize = ngx_min(limit, (size_t) (end - p));

        frame = ngx_quic_alloc_frame(c, fsize);
        if (frame == NULL) {
            return 0;
        }

        ngx_memcpy(frame->data, p, fsize);

        frame->level = level;
        frame->type = NGX_QUIC_FT_CRYPTO;
        frame->u.crypto.offset = fs->sent;
        frame->u.crypto.length = fsize;
        frame->u.crypto.data = frame->data;

        fs->sent += fsize;
        p += fsize;

        ngx_sprintf(frame->info, "crypto, generated by SSL len=%ui level=%d",
                    fsize, level);

        ngx_quic_queue_frame(qc, frame);
    }

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
                   "quic ngx_quic_send_alert(), lvl=%d, alert=%d",
                   (int) level, (int) alert);

    qc = c->quic;
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


void
ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_conf_t *conf)
{
    ngx_buf_t          *b;
    ngx_quic_header_t   pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic run");

    c->log->action = "QUIC initialization";

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    b = c->buffer;

    pkt.log = c->log;
    pkt.raw = b;
    pkt.data = b->start;
    pkt.len = b->last - b->start;

    if (ngx_quic_new_connection(c, ssl, conf, &pkt) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    ngx_add_timer(c->read, c->quic->in_retry ? NGX_QUIC_RETRY_TIMEOUT
                                             : c->quic->tp.max_idle_timeout);

    c->read->handler = ngx_quic_input_handler;

    return;
}


static ngx_int_t
ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_uint_t              i;
    ngx_quic_tp_t          *ctp;
    ngx_quic_secrets_t     *keys;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    if (ngx_buf_size(pkt->raw) < NGX_QUIC_MIN_INITIAL_SIZE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic UDP datagram is too small for initial packet");
        return NGX_ERROR;
    }

    rc = ngx_quic_parse_long_header(pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    if (pkt->version != NGX_QUIC_VERSION) {
        return ngx_quic_negotiate_version(c, pkt);
    }

    if (!ngx_quic_pkt_in(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic invalid initial packet: 0x%xd", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->dcid.len < NGX_QUIC_CID_LEN_MIN) {
        /* 7.2.  Negotiating Connection IDs */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic too short dcid in initial packet: length %i",
                      pkt->dcid.len);
        return NGX_ERROR;
    }

    c->log->action = "creating new quic connection";

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_queue_init(&qc->send_ctx[i].frames);
        ngx_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = (uint64_t) -1;
        qc->send_ctx[i].largest_ack = (uint64_t) -1;
    }

    for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
        ngx_queue_init(&qc->crypto[i].frames);
    }

    ngx_queue_init(&qc->free_frames);

    qc->avg_rtt = NGX_QUIC_INITIAL_RTT;
    qc->rttvar = NGX_QUIC_INITIAL_RTT / 2;
    qc->min_rtt = NGX_TIMER_INFINITE;

    /*
     * qc->latest_rtt = 0
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

    c->quic = qc;
    qc->ssl = ssl;
    qc->conf = conf;
    qc->tp = conf->tp;

    ctp = &qc->ctp;
    ctp->max_udp_payload_size = ngx_quic_max_udp_payload(c);
    ctp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;

    qc->streams.recv_max_data = qc->tp.initial_max_data;

    qc->streams.client_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.client_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window = ngx_min(10 * qc->tp.max_udp_payload_size,
                                    ngx_max(2 * qc->tp.max_udp_payload_size,
                                            14720));
    qc->congestion.ssthresh = NGX_MAX_SIZE_T_VALUE;
    qc->congestion.recovery_start = ngx_current_msec;

    if (ngx_quic_new_dcid(c, &pkt->dcid) != NGX_OK) {
        return NGX_ERROR;
    }

#if (NGX_QUIC_DRAFT_VERSION >= 28)
    qc->tp.original_dcid = c->quic->odcid;
#endif
    qc->tp.initial_scid = c->quic->dcid;

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pnalloc(c->pool, qc->scid.len);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->scid.data, pkt->scid.data, qc->scid.len);

    keys = &c->quic->keys[ssl_encryption_initial];

    if (ngx_quic_set_initial_secret(c->pool, &keys->client, &keys->server,
                                    &qc->odcid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    qc->initialized = 1;

    if (ngx_terminate || ngx_exiting) {
        qc->error = NGX_QUIC_ERR_CONNECTION_REFUSED;
        return NGX_ERROR;
    }

    if (pkt->token.len) {
        rc = ngx_quic_validate_token(c, pkt);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic invalid token");
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic expired token");
            return ngx_quic_retry(c);
        }

        /* NGX_OK */
        qc->validated = 1;

    } else if (conf->retry) {
        return ngx_quic_retry(c);
    }

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_initial;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    if (ngx_quic_decrypt(pkt, NULL, &ctx->largest_pn) != NGX_OK) {
        qc->error = pkt->error;
        qc->error_reason = "failed to decrypt packet";

        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_payload_handler(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    /* pos is at header end, adjust by actual packet length */
    pkt->raw->pos += pkt->len;

    (void) ngx_quic_skip_zero_padding(pkt->raw);

    return ngx_quic_input(c, pkt->raw);
}


static ngx_int_t
ngx_quic_negotiate_version(ngx_connection_t *c, ngx_quic_header_t *inpkt)
{
    size_t             len;
    ngx_quic_header_t  pkt;

    /* buffer size is calculated assuming a single supported version */
    static u_char      buf[NGX_QUIC_MAX_LONG_HEADER + sizeof(uint32_t)];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sending version negotiation packet");

    pkt.log = c->log;
    pkt.flags = NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_FIXED_BIT;
    pkt.dcid = inpkt->scid;
    pkt.scid = inpkt->dcid;

    len = ngx_quic_create_version_negotiation(&pkt, buf);

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(c->log, "quic vnego packet to send", buf, len);
#endif

    (void) c->send(c, buf, len);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_new_dcid(ngx_connection_t *c, ngx_str_t *odcid)
{
    uint8_t                 len;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (RAND_bytes(&len, sizeof(len)) != 1) {
        return NGX_ERROR;
    }

    len = len % 10 + 10;

    qc->dcid.len = len;
    qc->dcid.data = ngx_pnalloc(c->pool, len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }

    if (RAND_bytes(qc->dcid.data, len) != 1) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(c->log, "quic server CID", qc->dcid.data, qc->dcid.len);
#endif

    qc->odcid.len = odcid->len;
    qc->odcid.data = ngx_pstrdup(c->pool, odcid);
    if (qc->odcid.data == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_retry(ngx_connection_t *c)
{
    ssize_t            len;
    ngx_str_t          res, token;
    ngx_quic_header_t  pkt;
    u_char             buf[NGX_QUIC_RETRY_BUFFER_SIZE];

    if (ngx_quic_new_token(c, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    pkt.flags = NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY;
    pkt.log = c->log;
    pkt.odcid = c->quic->odcid;
    pkt.dcid = c->quic->scid;
    pkt.scid = c->quic->dcid;
    pkt.token = token;

    res.data = buf;

    if (ngx_quic_encrypt(&pkt, NULL, &res) != NGX_OK) {
        return NGX_ERROR;
    }

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(c->log, "quic packet to send", res.data, res.len);
#endif

    len = c->send(c, res.data, res.len);
    if (len == NGX_ERROR || (size_t) len != res.len) {
        return NGX_ERROR;
    }

    c->quic->token = token;
#if (NGX_QUIC_DRAFT_VERSION < 28)
    c->quic->tp.original_dcid = c->quic->odcid;
#endif
    c->quic->tp.retry_scid = c->quic->dcid;
    c->quic->in_retry = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_new_token(ngx_connection_t *c, ngx_str_t *token)
{
    int                   len, iv_len;
    u_char               *data, *p, *key, *iv;
    ngx_msec_t            now;
    EVP_CIPHER_CTX       *ctx;
    const EVP_CIPHER     *cipher;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    u_char                in[NGX_QUIC_MAX_TOKEN_SIZE];

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;

        len = sizeof(struct in6_addr);
        data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        len = ngx_min(c->addr_text.len, NGX_QUIC_MAX_TOKEN_SIZE - sizeof(now));
        data = c->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;

        len = sizeof(in_addr_t);
        data = (u_char *) &sin->sin_addr;

        break;
    }

    p = ngx_cpymem(in, data, len);

    now = ngx_current_msec;
    len += sizeof(now);
    ngx_memcpy(p, &now, sizeof(now));

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

    key = c->quic->conf->token_key;
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
    ngx_quic_hexdump(c->log, "quic new token", token->data, token->len);
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_quic_validate_token(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    int                     len, tlen, iv_len;
    u_char                 *key, *iv, *p, *data;
    ngx_msec_t              msec;
    EVP_CIPHER_CTX         *ctx;
    const EVP_CIPHER       *cipher;
    struct sockaddr_in     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
#endif
    ngx_quic_connection_t  *qc;
    u_char                  tdec[NGX_QUIC_MAX_TOKEN_SIZE];

    if (pkt->token.len == 0) {
        return NGX_ERROR;
    }

    qc = c->quic;

    /* Retry token */

    if (qc->token.len) {
        if (pkt->token.len != qc->token.len) {
            goto bad_token;
        }

        if (ngx_memcmp(pkt->token.data, qc->token.data, pkt->token.len) != 0) {
            goto bad_token;
        }

        return NGX_OK;
    }

    /* NEW_TOKEN in a previous connection */

    cipher = EVP_aes_256_cbc();
    key = c->quic->conf->token_key;
    iv = pkt->token.data;
    iv_len = EVP_CIPHER_iv_length(cipher);

    /* sanity checks */

    if (pkt->token.len < (size_t) iv_len + EVP_CIPHER_block_size(cipher)) {
        goto bad_token;
    }

    if (pkt->token.len > (size_t) iv_len + NGX_QUIC_MAX_TOKEN_SIZE) {
        goto bad_token;
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
        goto bad_token;
    }

    if (EVP_DecryptFinal_ex(ctx, tdec + len, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        goto bad_token;
    }

    EVP_CIPHER_CTX_free(ctx);

    switch (c->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;

        len = sizeof(struct in6_addr);
        data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        len = ngx_min(c->addr_text.len, NGX_QUIC_MAX_TOKEN_SIZE - sizeof(msec));
        data = c->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;

        len = sizeof(in_addr_t);
        data = (u_char *) &sin->sin_addr;

        break;
    }

    if (ngx_memcmp(tdec, data, len) != 0) {
        goto bad_token;
    }

    ngx_memcpy(&msec, tdec + len, sizeof(msec));

    if (ngx_current_msec - msec > NGX_QUIC_RETRY_LIFETIME) {
        return NGX_DECLINED;
    }

    return NGX_OK;

bad_token:

    qc->error = NGX_QUIC_ERR_INVALID_TOKEN;
    qc->error_reason = "invalid_token";

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    u_char                 *p;
    size_t                  clen;
    ssize_t                 len;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (ngx_ssl_create_connection(qc->ssl, c, NGX_SSL_BUFFER) != NGX_OK) {
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;

    if (SSL_set_quic_method(ssl_conn, &quic_method) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_method() failed");
        return NGX_ERROR;
    }

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(qc->ssl->ctx)) {
        SSL_set_quic_early_data_enabled(ssl_conn, 1);
    }
#endif

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
    ngx_quic_hexdump(c->log, "quic transport parameters", p, len);
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
    ngx_buf_t               b;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.start = buf;
    b.end = buf + sizeof(buf);
    b.pos = b.last = b.start;
    b.memory = 1;

    c = rev->data;
    qc = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

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

    b.last += n;
    qc->received += n;

    if (ngx_quic_input(c, &b) != NGX_OK) {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    qc->send_timer_set = 0;
    ngx_add_timer(rev, qc->tp.max_idle_timeout);
}


static void
ngx_quic_close_connection(ngx_connection_t *c, ngx_int_t rc)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_close_connection, rc: %i", rc);

    if (!c->quic || !c->quic->initialized) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                      "quic close connection early error");

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
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ctx = ngx_quic_get_send_ctx(qc, i);
            ngx_quic_free_frames(c, &ctx->sent);
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
                                "quic immediate close, drain = %d",
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
                               "quic immediate close due to %serror: %ui %s",
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

    if (qc->close.timer_set) {
        return NGX_AGAIN;
    }

    for (i = 0; i < NGX_QUIC_ENCRYPTION_LAST; i++) {
        ngx_quic_free_frames(c, &qc->crypto[i].frames);
    }

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_quic_free_frames(c, &qc->send_ctx[i].frames);
        ngx_quic_free_frames(c, &qc->send_ctx[i].sent);
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

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic part of connection is terminated");

    /* may be tested from SSL callback during SSL shutdown */
    c->quic = NULL;

    return NGX_OK;
}


void
ngx_quic_finalize_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;
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


static ngx_int_t
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_quic_header_t   pkt;

    p = b->pos;

    while (p < b->last) {
        c->log->action = "processing quic packet";

        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.flags = p[0];

        if (c->quic->in_retry) {
            return ngx_quic_retry_input(c, &pkt);
        }

        if (ngx_quic_long_pkt(pkt.flags)) {

            if (ngx_quic_pkt_in(pkt.flags)) {
                rc = ngx_quic_initial_input(c, &pkt);

            } else if (ngx_quic_pkt_hs(pkt.flags)) {
                rc = ngx_quic_handshake_input(c, &pkt);

            } else if (ngx_quic_pkt_zrtt(pkt.flags)) {
                rc = ngx_quic_early_input(c, &pkt);

            } else {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic unknown long packet type");
                return NGX_ERROR;
            }

        } else {
            rc = ngx_quic_app_input(c, &pkt);
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
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
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos += pkt.len;
        p = ngx_quic_skip_zero_padding(b);
    }

    return NGX_OK;
}


/* firefox workaround: skip zero padding at the end of quic packet */
static ngx_inline u_char *
ngx_quic_skip_zero_padding(ngx_buf_t *b)
{
    while (b->pos < b->last && *(b->pos) == 0) {
        b->pos++;
    }

    return b->pos;
}


static ngx_int_t
ngx_quic_retry_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_secrets_t     *keys;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "retrying quic connection";

    if (ngx_buf_size(pkt->raw) < NGX_QUIC_MIN_INITIAL_SIZE) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic UDP datagram is too small for initial packet");
        return NGX_OK;
    }

    rc = ngx_quic_parse_long_header(pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    if (pkt->version != NGX_QUIC_VERSION) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic unsupported version: 0x%xD", pkt->version);
        return NGX_ERROR;
    }

    if (ngx_quic_pkt_zrtt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic discard inflight 0-RTT packet");
        return NGX_OK;
    }

    if (!ngx_quic_pkt_in(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic invalid initial packet: 0x%xd", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_new_dcid(c, &pkt->dcid) != NGX_OK) {
        return NGX_ERROR;
    }

    qc = c->quic;
    qc->tp.initial_scid = c->quic->dcid;

    keys = &c->quic->keys[ssl_encryption_initial];

    if (ngx_quic_set_initial_secret(c->pool, &keys->client, &keys->server,
                                    &qc->odcid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    c->quic->in_retry = 0;

    if (ngx_quic_validate_token(c, pkt) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic invalid token");
        return NGX_ERROR;
    }

    qc->validated = 1;

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_initial;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    if (ngx_quic_decrypt(pkt, NULL, &ctx->largest_pn) != NGX_OK) {
        qc->error = pkt->error;
        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_payload_handler(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    /* pos is at header end, adjust by actual packet length */
    pkt->raw->pos += pkt->len;

    (void) ngx_quic_skip_zero_padding(pkt->raw);

    return ngx_quic_input(c, pkt->raw);
}


static ngx_int_t
ngx_quic_initial_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t             rc;
    ngx_ssl_conn_t       *ssl_conn;
    ngx_quic_secrets_t   *keys;
    ngx_quic_send_ctx_t  *ctx;
    static u_char         buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "processing initial quic packet";

    ssl_conn = c->ssl->connection;

    rc = ngx_quic_parse_long_header(pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    if (pkt->version != NGX_QUIC_VERSION) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic unsupported version: 0x%xD", pkt->version);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    keys = &c->quic->keys[ssl_encryption_initial];

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_initial;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(c->quic, pkt->level);

    if (ngx_quic_decrypt(pkt, ssl_conn, &ctx->largest_pn) != NGX_OK) {
        c->quic->error = pkt->error;
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_handshake_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_secrets_t     *keys;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "processing handshake quic packet";

    qc = c->quic;

    keys = &c->quic->keys[ssl_encryption_handshake];

    if (keys->client.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    /* extract cleartext data into pkt */
    rc = ngx_quic_parse_long_header(pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    if (pkt->version != NGX_QUIC_VERSION) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic unsupported version: 0x%xD", pkt->version);
        return NGX_ERROR;
    }

    if (ngx_quic_check_peer(qc, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_parse_handshake_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_handshake;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    if (ngx_quic_decrypt(pkt, c->ssl->connection, &ctx->largest_pn) != NGX_OK) {
        qc->error = pkt->error;
        return NGX_ERROR;
    }

    /*
     * 4.10.1. The successful use of Handshake packets indicates
     * that no more Initial packets need to be exchanged
     */
    ctx = ngx_quic_get_send_ctx(c->quic, ssl_encryption_initial);

    while (!ngx_queue_empty(&ctx->sent)) {
        q = ngx_queue_head(&ctx->sent);
        ngx_queue_remove(q);

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        ngx_quic_congestion_ack(c, f);
        ngx_quic_free_frame(c, f);
    }

    qc->validated = 1;
    qc->pto_count = 0;

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_early_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_secrets_t     *keys;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "processing early data quic packet";

    qc = c->quic;

    /* extract cleartext data into pkt */
    rc = ngx_quic_parse_long_header(pkt);
    if (rc != NGX_OK) {
        return rc;
    }

    if (pkt->version != NGX_QUIC_VERSION) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic unsupported version: 0x%xD", pkt->version);
        return NGX_ERROR;
    }

    if (ngx_quic_check_peer(qc, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_parse_handshake_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    keys = &c->quic->keys[ssl_encryption_early_data];

    if (keys->client.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no 0-RTT keys yet, packet ignored");
        return NGX_DECLINED;
    }


    pkt->secret = &keys->client;
    pkt->level = ssl_encryption_early_data;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    if (ngx_quic_decrypt(pkt, c->ssl->connection, &ctx->largest_pn) != NGX_OK) {
        qc->error = pkt->error;
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_check_peer(ngx_quic_connection_t *qc, ngx_quic_header_t *pkt)
{
    ngx_str_t  *dcid;

    dcid = ngx_quic_pkt_zrtt(pkt->flags) ? &qc->odcid : &qc->dcid;

    if (pkt->dcid.len != dcid->len) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->dcid.data, dcid->data, dcid->len) != 0) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic dcid");
        return NGX_ERROR;
    }

    if (pkt->scid.len != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->scid.data, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic unexpected quic scid");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_app_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_secrets_t     *keys, *next, tmp;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    c->log->action = "processing application data quic packet";

    qc = c->quic;

    keys = &c->quic->keys[ssl_encryption_application];
    next = &c->quic->next_key;

    if (keys->client.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    rc = ngx_quic_parse_short_header(pkt, &qc->dcid);
    if (rc != NGX_OK) {
        return rc;
    }

    pkt->secret = &keys->client;
    pkt->next = &next->client;
    pkt->key_phase = c->quic->key_phase;
    pkt->level = ssl_encryption_application;
    pkt->plaintext = buf;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    rc = ngx_quic_decrypt(pkt, c->ssl->connection, &ctx->largest_pn);

    if (rc != NGX_OK) {
        qc->error = pkt->error;
        return rc;
    }

    ngx_gettimeofday(&pkt->received);

    /* switch keys on Key Phase change */

    if (pkt->key_update) {
        c->quic->key_phase ^= 1;

        tmp = *keys;
        *keys = *next;
        *next = tmp;
    }

    rc = ngx_quic_payload_handler(c, pkt);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* generate next keys */

    if (pkt->key_update) {
        if (ngx_quic_key_update(c, keys, next) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return rc;
}


static ngx_int_t
ngx_quic_payload_handler(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    ngx_uint_t              ack_sent, do_close;
    ngx_quic_frame_t        frame;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

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

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    ack_sent = 0;
    do_close = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        len = ngx_quic_parse_frame(pkt, p, end, &frame);

        if (len < 0) {
            qc->error = pkt->error;
            return NGX_ERROR;
        }

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:
            if (ngx_quic_handle_ack_frame(c, pkt, &frame.u.ack) != NGX_OK) {
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

        if (!ack_sent) {
            if (ngx_quic_send_ack(c, pkt) != NGX_OK) {
                return NGX_ERROR;
            }

            ack_sent = 1;
        }

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

        case NGX_QUIC_FT_NEW_CONNECTION_ID:
        case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        case NGX_QUIC_FT_PATH_CHALLENGE:
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
                      "quic trailing garbage in payload: %ui bytes", end - p);

        qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        return NGX_ERROR;
    }

    if (do_close) {
        qc->draining = 1;
        ngx_quic_close_connection(c, NGX_OK);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_ack(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_frame_t  *frame;

    c->log->action = "generating acknowledgment";

    /* every ACK-eliciting packet is acknowledged, TODO ACK Ranges */

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = (pkt->level == ssl_encryption_early_data)
                   ? ssl_encryption_application
                   : pkt->level;

    frame->type = NGX_QUIC_FT_ACK;
    frame->u.ack.largest = pkt->pn;
    frame->u.ack.delay = ngx_quic_ack_delay(c, &pkt->received, frame->level);

    ngx_sprintf(frame->info, "ACK for PN=%uL from frame handler level=%d",
                pkt->pn, frame->level);
    ngx_quic_queue_frame(c->quic, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_ack_delay(ngx_connection_t *c, struct timeval *received,
    enum ssl_encryption_level_t level)
{
    ngx_int_t       ack_delay;
    struct timeval  tv;

    ack_delay = 0;

    if (level == ssl_encryption_application) {
        ngx_gettimeofday(&tv);
        ack_delay = (tv.tv_sec - received->tv_sec) * 1000000
                    + tv.tv_usec - received->tv_usec;
        ack_delay >>= c->quic->ctp.ack_delay_exponent;
    }

    return ack_delay;
}


static ngx_int_t
ngx_quic_send_cc(ngx_connection_t *c)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (qc->draining) {
        return NGX_OK;
    }

    if (qc->closing
        && ngx_current_msec - qc->last_cc < NGX_QUIC_CC_MIN_INTERVAL)
    {
        /* dot not send CC too often */
        return NGX_OK;
    }

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = qc->error_level;
    frame->type = NGX_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = qc->error;
    frame->u.close.frame_type = qc->error_ftype;
    frame->u.close.app = qc->error_app;

    if (qc->error_reason) {
        frame->u.close.reason.len = ngx_strlen(qc->error_reason);
        frame->u.close.reason.data = (u_char *) qc->error_reason;
    }

    ngx_snprintf(frame->info, sizeof(frame->info) - 1,
                 "CONNECTION_CLOSE%s err:%ui level:%d ft:%ui reason:\"%s\"",
                 qc->error_app ? "_APP" : "", qc->error, qc->error_level,
                 qc->error_ftype, qc->error_reason ? qc->error_reason : "-");

    ngx_quic_queue_frame(c->quic, frame);

    qc->last_cc = ngx_current_msec;

    return ngx_quic_output(c);
}


static ngx_int_t
ngx_quic_send_new_token(ngx_connection_t *c)
{
    ngx_str_t          token;
    ngx_quic_frame_t  *frame;

    if (!c->quic->conf->retry) {
        return NGX_OK;
    }

    if (ngx_quic_new_token(c, &token) != NGX_OK) {
        return NGX_ERROR;
    }

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_NEW_TOKEN;
    frame->u.token.length = token.len;
    frame->u.token.data = token.data;
    ngx_sprintf(frame->info, "NEW_TOKEN");
    ngx_quic_queue_frame(c->quic, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_ack_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_ack_frame_t *ack)
{
    ssize_t                 n;
    u_char                 *pos, *end;
    uint64_t                min, max, gap, range;
    ngx_msec_t              send_time;
    ngx_uint_t              i;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_handle_ack_frame level %d", pkt->level);

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
    if (ctx->largest_ack < max || ctx->largest_ack == (uint64_t) -1) {
        ctx->largest_ack = max;
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic updated largest received ack: %uL", max);

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

    pos = ack->ranges_start;
    end = ack->ranges_end;

    for (i = 0; i < ack->range_count; i++) {

        n = ngx_quic_parse_ack_range(pkt, pos, end, &gap, &range);
        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }
        pos += n;

        if (gap + 2 > min) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                         "quic invalid range %ui in ack frame", i);
            return NGX_ERROR;
        }

        max = min - gap - 2;

        if (range > max) {
            qc->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                         "quic invalid range %ui in ack frame", i);
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
    uint64_t                found_num;
    ngx_uint_t              found;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_connection_t  *qc;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic handle ack range: min:%uL max:%uL", min, max);

    qc = c->quic;

    *send_time = NGX_TIMER_INFINITE;
    found = 0;
    found_num = 0;

    q = ngx_queue_last(&ctx->sent);

    while (q != ngx_queue_sentinel(&ctx->sent)) {

        f = ngx_queue_data(q, ngx_quic_frame_t, queue);
        q = ngx_queue_prev(q);

        if (f->pnum >= min && f->pnum <= max) {
            ngx_quic_congestion_ack(c, f);

            ngx_quic_handle_stream_ack(c, f);

            if (f->pnum > found_num || !found) {
                *send_time = f->last;
                found_num = f->pnum;
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

    qc = c->quic;

    latest_rtt = ngx_current_msec - send_time;
    qc->latest_rtt = latest_rtt;

    if (qc->min_rtt == NGX_TIMER_INFINITE) {
        qc->min_rtt = latest_rtt;
        qc->avg_rtt = latest_rtt;
        qc->rttvar = latest_rtt / 2;

    } else {
        qc->min_rtt = ngx_min(qc->min_rtt, latest_rtt);


        if (level == ssl_encryption_application) {
            ack_delay = ack->delay * (1 << qc->ctp.ack_delay_exponent) / 1000;
            ack_delay = ngx_min(ack_delay, qc->ctp.max_ack_delay);

        } else {
            ack_delay = 0;
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
                   "quic rtt sample: latest %M, min %M, avg %M, var %M",
                   latest_rtt, qc->min_rtt, qc->avg_rtt, qc->rttvar);
}


static ngx_inline ngx_msec_t
ngx_quic_pto(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    ngx_msec_t              duration;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    /* PTO calculation: quic-recovery, Appendix 8 */
    duration = qc->avg_rtt;

    duration += ngx_max(4 * qc->rttvar, NGX_QUIC_TIME_GRANULARITY);
    duration <<= qc->pto_count;

    if (qc->congestion.in_flight == 0) { /* no in-flight packets */
        return duration;
    }

    if (ctx == &qc->send_ctx[2] && c->ssl->handshaked) {
        /* application send space */

        duration += qc->tp.max_ack_delay << qc->pto_count;
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

    if (f->type < NGX_QUIC_FT_STREAM0 || f->type > NGX_QUIC_FT_STREAM7) {
        return;
    }

    qc = c->quic;

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
                   "quic stream ack %uL acked:%uL, unacked:%uL",
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
                       "quic out-of-order frame: expecting %uL got %uL",
                       fs->received, f->offset);

        return ngx_quic_buffer_frame(c, fs, frame);
    }

    if (f->offset < fs->received) {

        if (ngx_quic_adjust_frame_offset(c, frame, fs->received)
            == NGX_DONE)
        {
            /* old/duplicate data range */
            return NGX_OK;
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
                              "quic skipped buffered frame, total %ui",
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
                      "quic consumed buffered frame, total %ui", fs->total);

        ngx_quic_free_frame(c, frame);

    } while (1);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_adjust_frame_offset(ngx_connection_t *c, ngx_quic_frame_t *frame,
    uint64_t offset_in)
{
    size_t                     tail;
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
    f->data += tail;
    f->length -= tail;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_buffer_frame(ngx_connection_t *c, ngx_quic_frames_stream_t *fs,
    ngx_quic_frame_t *frame)
{
    u_char                    *data;
    ngx_queue_t               *q;
    ngx_quic_frame_t          *dst, *item;
    ngx_quic_ordered_frame_t  *f, *df;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_buffer_frame");

    f = &frame->u.ord;

    /* frame start offset is in the future, buffer it */

    dst = ngx_quic_alloc_frame(c, f->length);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    data = dst->data;
    ngx_memcpy(dst, frame, sizeof(ngx_quic_frame_t));
    dst->data = data;

    ngx_memcpy(dst->data, f->data, f->length);

    df = &dst->u.ord;
    df->data = dst->data;

    fs->total += f->length;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "quic ordered frame with unexpected offset:"
                  " buffered, total %ui", fs->total);

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
    ngx_quic_connection_t     *qc;
    ngx_quic_crypto_frame_t   *f;
    ngx_quic_frames_stream_t  *fs;

    qc = c->quic;
    fs = &qc->crypto[pkt->level];
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > fs->received && last - fs->received > NGX_QUIC_MAX_BUFFERED) {
        c->quic->error = NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return NGX_ERROR;
    }

    return ngx_quic_handle_ordered_frame(c, fs, frame, ngx_quic_crypto_input,
                                         NULL);
}


static ngx_int_t
ngx_quic_crypto_input(ngx_connection_t *c, ngx_quic_frame_t *frame, void *data)
{
    int                       n, sslerr;
    ngx_queue_t              *q;
    ngx_ssl_conn_t           *ssl_conn;
    ngx_quic_send_ctx_t      *ctx;
    ngx_quic_crypto_frame_t  *f;

    f = &frame->u.crypto;

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    if (!SSL_provide_quic_data(ssl_conn, SSL_quic_read_level(ssl_conn),
                               f->data, f->length))
    {
        ngx_ssl_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_provide_quic_data() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }

    } else if (n == 1 && !SSL_in_init(ssl_conn)) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic ssl cipher: %s", SSL_get_cipher(ssl_conn));

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic handshake completed successfully");

        c->ssl->handshaked = 1;
        c->ssl->no_wait_shutdown = 1;

        frame = ngx_quic_alloc_frame(c, 0);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        /* 12.4 Frames and frame types, figure 8 */
        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_HANDSHAKE_DONE;
        ngx_sprintf(frame->info, "HANDSHAKE DONE on handshake completed");
        ngx_quic_queue_frame(c->quic, frame);

        if (ngx_quic_send_new_token(c) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * Generating next keys before a key update is received.
         * See quic-tls 9.4 Header Protection Timing Side-Channels.
         */

        if (ngx_quic_key_update(c, &c->quic->keys[ssl_encryption_application],
                                &c->quic->next_key)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * 4.10.2 An endpoint MUST discard its handshake keys
         * when the TLS handshake is confirmed
         */
        ctx = ngx_quic_get_send_ctx(c->quic, ssl_encryption_handshake);

        while (!ngx_queue_empty(&ctx->sent)) {
            q = ngx_queue_head(&ctx->sent);
            ngx_queue_remove(q);

            frame = ngx_queue_data(q, ngx_quic_frame_t, queue);
            ngx_quic_congestion_ack(c, frame);
            ngx_quic_free_frame(c, frame);
        }

        c->quic->pto_count = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

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

    qc = c->quic;
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
            c->quic->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
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
        c->quic->error = NGX_QUIC_ERR_FLOW_CONTROL_ERROR;
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
    ngx_quic_stream_t        *sn;
    ngx_quic_connection_t    *qc;
    ngx_quic_stream_frame_t  *f;

    qc = c->quic;
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

    b->last = ngx_cpymem(b->last, f->data, f->length);

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

    qc = c->quic;
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

    qc = c->quic;

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

    frame = ngx_quic_alloc_frame(c, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame->u.max_stream_data.id = f->id;
    frame->u.max_stream_data.limit = n;

    ngx_sprintf(frame->info, "MAX_STREAM_DATA id:0x%xL limit:%uL level=%d",
                frame->u.max_stream_data.id,
                frame->u.max_stream_data.limit,
                frame->level);

    ngx_quic_queue_frame(c->quic, frame);

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

    qc = c->quic;

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

    qc = c->quic;

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

    qc = c->quic;

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

    qc = c->quic;

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
    ngx_uint_t              i;
    ngx_quic_connection_t  *qc;

    c->log->action = "sending frames";

    qc = c->quic;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        if (ngx_quic_output_frames(c, &qc->send_ctx[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (!qc->send_timer_set && !qc->closing) {
        qc->send_timer_set = 1;
        ngx_add_timer(c->read, qc->tp.max_idle_timeout);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_output_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx)
{
    size_t                  len, hlen;
    ngx_uint_t              need_ack;
    ngx_queue_t            *q, range;
    ngx_quic_frame_t       *f;
    ngx_quic_congestion_t  *cg;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    cg = &qc->congestion;

    if (ngx_queue_empty(&ctx->frames)) {
        return NGX_OK;
    }

    q = ngx_queue_head(&ctx->frames);
    f = ngx_queue_data(q, ngx_quic_frame_t, queue);

    /* all frames in same send_ctx share same level */
    hlen = (f->level == ssl_encryption_application) ? NGX_QUIC_MAX_SHORT_HEADER
                                                    : NGX_QUIC_MAX_LONG_HEADER;
    hlen += EVP_GCM_TLS_TAG_LEN;

    do {
        len = 0;
        need_ack = 0;
        ngx_queue_init(&range);

        do {
            /* process group of frames that fits into packet */
            f = ngx_queue_data(q, ngx_quic_frame_t, queue);

            if (len && hlen + len + f->len > qc->ctp.max_udp_payload_size) {
                break;
            }

            if (f->need_ack) {
                need_ack = 1;
            }

            if (need_ack && cg->in_flight + len + f->len > cg->window) {
                break;
            }

            if (!qc->validated) {
                /*
                 * Prior to validation, endpoints are limited in what they
                 * are able to send.  During the handshake, a server cannot
                 * send more than three times the data it receives;
                 */

                if (((c->sent + len + f->len) / 3) > qc->received) {
                    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "quic hit amplification limit"
                                   " received %uz sent %O",
                                   qc->received, c->sent);
                    break;
                }
            }

            q = ngx_queue_next(q);

            f->first = ngx_current_msec;

            ngx_queue_remove(&f->queue);
            ngx_queue_insert_tail(&range, &f->queue);

            len += f->len;

        } while (q != ngx_queue_sentinel(&ctx->frames));

        if (ngx_queue_empty(&range)) {
            break;
        }

        if (ngx_quic_send_frames(c, ctx, &range) != NGX_OK) {
            return NGX_ERROR;
        }

    } while (q != ngx_queue_sentinel(&ctx->frames));

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


static ngx_int_t
ngx_quic_send_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    ngx_queue_t *frames)
{
    ssize_t                 len;
    u_char                 *p;
    ngx_msec_t              now;
    ngx_str_t               out, res;
    ngx_queue_t            *q;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_header_t       pkt;
    ngx_quic_secrets_t     *keys;
    ngx_quic_connection_t  *qc;
    static ngx_str_t        initial_token = ngx_null_string;
    static u_char           src[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];
    static u_char           dst[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_send_frames");

    ssl_conn = c->ssl ? c->ssl->connection : NULL;

    q = ngx_queue_head(frames);
    start = ngx_queue_data(q, ngx_quic_frame_t, queue);

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    now = ngx_current_msec;

    p = src;
    out.data = src;

    for (q = ngx_queue_head(frames);
         q != ngx_queue_sentinel(frames);
         q = ngx_queue_next(q))
    {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic frame out: %s", f->info);

        len = ngx_quic_create_frame(p, f);
        if (len == -1) {
            return NGX_ERROR;
        }

        if (f->need_ack) {
            pkt.need_ack = 1;
        }

        p += len;
        f->pnum = ctx->pnum;
        f->last = now;
    }

    out.len = p - out.data;

    while (out.len < 4) {
        *p++ = NGX_QUIC_FT_PADDING;
        out.len++;
    }

    qc = c->quic;

    keys = &c->quic->keys[start->level];

    pkt.secret = &keys->server;

    pkt.flags = NGX_QUIC_PKT_FIXED_BIT;

    if (start->level == ssl_encryption_initial) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL;
        pkt.token = initial_token;

    } else if (start->level == ssl_encryption_handshake) {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE;

    } else {
        if (c->quic->key_phase) {
            pkt.flags |= NGX_QUIC_PKT_KPHASE;
        }
    }

    ngx_quic_set_packet_number(&pkt, ctx);

    pkt.log = c->log;
    pkt.level = start->level;
    pkt.dcid = qc->scid;
    pkt.scid = qc->dcid;
    pkt.payload = out;

    res.data = dst;

    ngx_log_debug6(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet ready: %ui bytes at level %d"
                   " need_ack: %d number: %L encoded %d:0x%xD",
                   out.len, start->level, pkt.need_ack, pkt.number,
                   pkt.num_len, pkt.trunc);

    if (ngx_quic_encrypt(&pkt, ssl_conn, &res) != NGX_OK) {
        return NGX_ERROR;
    }

    len = c->send(c, res.data, res.len);
    if (len == NGX_ERROR || (size_t) len != res.len) {
        return NGX_ERROR;
    }

    /* len == NGX_OK || NGX_AGAIN */
    ctx->pnum++;

    if (pkt.need_ack) {
        /* move frames into the sent queue to wait for ack */

        if (qc->closing) {
            /* if we are closing, any ack will be discarded */
            ngx_quic_free_frames(c, frames);

        } else {
            ngx_queue_add(&ctx->sent, frames);
            if (qc->pto.timer_set) {
                ngx_del_timer(&qc->pto);
            }
            ngx_add_timer(&qc->pto, ngx_quic_pto(c, ctx));

            start->plen = len;
        }

        qc->congestion.in_flight += len;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion send if:%uz",
                       qc->congestion.in_flight);
    } else {
        /* no ack is expected for this frames, so we can free them */
        ngx_quic_free_frames(c, frames);
    }

    return NGX_OK;
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
    ngx_queue_t            *q;
    ngx_connection_t       *c;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "quic pto timer");

    c = ev->data;
    qc = c->quic;

    qc->pto_count++;

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ngx_queue_empty(&ctx->sent)) {
            continue;
        }

        q = ngx_queue_head(&ctx->sent);
        start = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (start->pnum <= ctx->largest_ack
            && ctx->largest_ack != (uint64_t) -1)
        {
            continue;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic pto pnum:%uL pto_count:%ui level:%d",
                       start->pnum, c->quic->pto_count, start->level);

        if (ngx_quic_resend_frames(c, ctx, start) != NGX_OK) {
            ngx_quic_close_connection(c, NGX_ERROR);
            return;
        }
    }
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
}


static ngx_int_t
ngx_quic_detect_lost(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_msec_t              now, wait, min_wait, thr;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *start;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    now = ngx_current_msec;

    min_wait = 0;

    thr = NGX_QUIC_TIME_THR * ngx_max(qc->latest_rtt, qc->avg_rtt);
    thr = ngx_max(thr, NGX_QUIC_TIME_GRANULARITY);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {

        ctx = &qc->send_ctx[i];

        if (ctx->largest_ack == (uint64_t) -1) {
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

                if (min_wait == 0 || wait < min_wait) {
                    min_wait = wait;
                }

                break;
            }

            if (ngx_quic_resend_frames(c, ctx, start) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    /* no more preceeding packets */

    if (min_wait == 0) {
        qc->pto.handler = ngx_quic_pto_handler;
        return NGX_OK;
    }

    qc->pto.handler = ngx_quic_lost_handler;

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    ngx_add_timer(&qc->pto, min_wait);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_resend_frames(ngx_connection_t *c, ngx_quic_send_ctx_t *ctx,
    ngx_quic_frame_t *start)
{
    ngx_queue_t       *q, range;
    ngx_quic_frame_t  *f;

    ngx_queue_init(&range);

    /* send frames with same packet number to the wire */

    q = ngx_queue_head(&ctx->sent);

    do {
        f = ngx_queue_data(q, ngx_quic_frame_t, queue);

        if (f->pnum != start->pnum) {
            break;
        }

        q = ngx_queue_next(q);

        ngx_queue_remove(&f->queue);
        ngx_queue_insert_tail(&range, &f->queue);

    } while (q != ngx_queue_sentinel(&ctx->sent));

    ngx_quic_congestion_lost(c, start);

    return ngx_quic_send_frames(c, ctx, &range);
}


ngx_connection_t *
ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi)
{
    size_t                  rcvbuf_size;
    uint64_t                id;
    ngx_quic_stream_t      *qs, *sn;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    qc = qs->parent->quic;

    if (bidi) {
        if (qc->streams.server_streams_bidi
            >= qc->streams.server_max_streams_bidi)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server bidi streams: %uL",
                           qc->streams.server_streams_bidi);
            return NULL;
        }

        id = (qc->streams.server_streams_bidi << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server bidi stream %uL/%uL id:0x%xL",
                       qc->streams.server_streams_bidi,
                       qc->streams.server_max_streams_bidi, id);

        qc->streams.server_streams_bidi++;
        rcvbuf_size = qc->tp.initial_max_stream_data_bidi_local;

    } else {
        if (qc->streams.server_streams_uni
            >= qc->streams.server_max_streams_uni)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic too many server uni streams: %uL",
                           qc->streams.server_streams_uni);
            return NULL;
        }

        id = (qc->streams.server_streams_uni << 2)
             | NGX_QUIC_STREAM_SERVER_INITIATED
             | NGX_QUIC_STREAM_UNIDIRECTIONAL;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic creating server uni stream %uL/%uL id:0x%xL",
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
                   "quic stream id 0x%xL is new", id);

    qc = c->quic;

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
                   "quic stream id 0x%xL create", id);

    qc = c->quic;

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

    sn->c->qs = sn;
    sn->c->type = SOCK_STREAM;
    sn->c->pool = pool;
    sn->c->ssl = c->ssl;
    sn->c->sockaddr = c->sockaddr;
    sn->c->listening = c->listening;
    sn->c->addr_text = c->addr_text;
    sn->c->local_sockaddr = c->local_sockaddr;
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

    ngx_rbtree_insert(&c->quic->streams.tree, &sn->node);

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

    qs = c->qs;
    b = qs->b;
    pc = qs->parent;
    qc = pc->quic;
    rev = c->read;

    if (rev->error) {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id 0x%xL recv: eof:%d, avail:%z",
                   qs->id, rev->pending_eof, b->last - b->pos);

    if (b->pos == b->last) {
        rev->ready = 0;

        if (rev->pending_eof) {
            rev->eof = 1;
            return 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id 0x%xL recv() not ready", qs->id);
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
                   "quic stream id 0x%xL recv: %z of %uz", qs->id, len, size);

    if (!rev->pending_eof) {
        frame = ngx_quic_alloc_frame(pc, 0);
        if (frame == NULL) {
            return NGX_ERROR;
        }

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_STREAM_DATA;
        frame->u.max_stream_data.id = qs->id;
        frame->u.max_stream_data.limit = qs->fs.received + (b->pos - b->start)
                                         + (b->end - b->last);

        ngx_sprintf(frame->info,
                    "MAX_STREAM_DATA id:0x%xL limit:%uL l=%d on recv",
                    frame->u.max_stream_data.id,
                    frame->u.max_stream_data.limit,
                    frame->level);

        ngx_quic_queue_frame(pc->quic, frame);
    }

    if ((qc->streams.recv_max_data / 2) < qc->streams.received) {

        frame = ngx_quic_alloc_frame(pc, 0);

        if (frame == NULL) {
            return NGX_ERROR;
        }

        qc->streams.recv_max_data *= 2;

        frame->level = ssl_encryption_application;
        frame->type = NGX_QUIC_FT_MAX_DATA;
        frame->u.max_data.max_data = qc->streams.recv_max_data;

        ngx_sprintf(frame->info, "MAX_DATA max_data:%uL level=%d on recv",
                    frame->u.max_data.max_data, frame->level);

        ngx_quic_queue_frame(pc->quic, frame);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic stream id 0x%xL recv: increased max data: %uL",
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
    u_char                 *p;
    size_t                  n, max, max_frame, max_flow, max_limit, len;
#if (NGX_DEBUG)
    size_t                  sent;
#endif
    ngx_buf_t              *b;
#if (NGX_DEBUG)
    ngx_uint_t              nframes;
#endif
    ngx_event_t            *wev;
    ngx_chain_t            *cl;
    ngx_connection_t       *pc;
    ngx_quic_frame_t       *frame;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;
    wev = c->write;

    if (wev->error) {
        return NGX_CHAIN_ERROR;
    }

    max_frame = ngx_quic_max_stream_frame(qc);
    max_flow = ngx_quic_max_stream_flow(c);
    max_limit = limit;

#if (NGX_DEBUG)
    sent = 0;
    nframes = 0;
#endif

    for ( ;; ) {
        max = ngx_min(max_frame, max_flow);

        if (limit) {
            max = ngx_min(max, max_limit);
        }

        for (cl = in, n = 0; in; in = in->next) {

            if (!ngx_buf_in_memory(in->buf)) {
                continue;
            }

            n += ngx_buf_size(in->buf);

            if (n > max) {
                n = max;
                break;
            }
        }

        if (n == 0) {
            wev->ready = (max_flow ? 1 : 0);
            break;
        }

        frame = ngx_quic_alloc_frame(pc, n);
        if (frame == NULL) {
            return NGX_CHAIN_ERROR;
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
        frame->u.stream.data = frame->data;

        ngx_sprintf(frame->info, "STREAM id:0x%xL len:%uz level:%d",
                    qs->id, n, frame->level);

        c->sent += n;
        qc->streams.sent += n;
        max_flow -= n;

        if (limit) {
            max_limit -= n;
        }

#if (NGX_DEBUG)
        sent += n;
        nframes++;
#endif

        for (p = frame->data; n > 0; cl = cl->next) {
            b = cl->buf;

            if (!ngx_buf_in_memory(b)) {
                continue;
            }

            len = ngx_min(n, (size_t) (b->last - b->pos));
            p = ngx_cpymem(p, b->pos, len);

            b->pos += len;
            n -= len;
        }

        ngx_quic_queue_frame(qc, frame);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic send_chain sent:%uz, frames:%ui", sent, nframes);

    return in;
}


static size_t
ngx_quic_max_stream_frame(ngx_quic_connection_t *qc)
{
    /*
     * we need to fit at least 1 frame into a packet, thus account head/tail;
     * 25 = 1 + 8x3 is max header for STREAM frame, with 1 byte for frame type
     */

    return qc->ctp.max_udp_payload_size - NGX_QUIC_MAX_SHORT_HEADER - 25
           - EVP_GCM_TLS_TAG_LEN;
}


static size_t
ngx_quic_max_stream_flow(ngx_connection_t *c)
{
    size_t                  size;
    uint64_t                sent, unacked;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qs = c->qs;
    qc = qs->parent->quic;

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
                   "quic send flow: %uz", size);

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

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id 0x%xL cleanup", qs->id);

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
        if (!c->read->eof && !c->read->error) {
            frame = ngx_quic_alloc_frame(pc, 0);
            if (frame == NULL) {
                return;
            }

            frame->level = ssl_encryption_application;
            frame->type = NGX_QUIC_FT_STOP_SENDING;
            frame->u.stop_sending.id = qs->id;
            frame->u.stop_sending.error_code = 0x100; /* HTTP/3 no error */

            ngx_sprintf(frame->info, "STOP_SENDING id:0x%xL err:0x%xL level:%d",
                        qs->id, frame->u.stop_sending.error_code, frame->level);

            ngx_quic_queue_frame(qc, frame);
        }
    }

    if ((qs->id & NGX_QUIC_STREAM_SERVER_INITIATED) == 0) {
        frame = ngx_quic_alloc_frame(pc, 0);
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

        ngx_sprintf(frame->info, "MAX_STREAMS limit:%uL bidi:%ui level=%d",
                    frame->u.max_streams.limit,
                    frame->u.max_streams.bidi,
                    (int) frame->level);

        ngx_quic_queue_frame(qc, frame);

        if (qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL) {
            /* do not send fin for client unidirectional streams */
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stream id 0x%xL send fin", qs->id);

    frame = ngx_quic_alloc_frame(pc, 0);
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
    frame->u.stream.data = NULL;

    ngx_sprintf(frame->info, "stream 0x%xL fin=1 level=%d",
                qs->id, frame->level);

    ngx_quic_queue_frame(qc, frame);

    (void) ngx_quic_output(pc);
}


static ngx_quic_frame_t *
ngx_quic_alloc_frame(ngx_connection_t *c, size_t size)
{
    u_char                 *p;
    ngx_queue_t            *q;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    if (size) {
        p = ngx_alloc(size, c->log);
        if (p == NULL) {
            return NULL;
        }

    } else {
        p = NULL;
    }

    qc = c->quic;

    if (!ngx_queue_empty(&qc->free_frames)) {

        q = ngx_queue_head(&qc->free_frames);
        frame = ngx_queue_data(q, ngx_quic_frame_t, queue);

        ngx_queue_remove(&frame->queue);

#ifdef NGX_QUIC_DEBUG_FRAMES_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic reuse frame n:%ui", qc->nframes);
#endif

    } else {
        frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
        if (frame == NULL) {
            ngx_free(p);
            return NULL;
        }

#if (NGX_DEBUG)
        ++qc->nframes;
#endif

#ifdef NGX_QUIC_DEBUG_FRAMES_ALLOC
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic alloc frame n:%ui", qc->nframes);
#endif
    }

    ngx_memzero(frame, sizeof(ngx_quic_frame_t));

    frame->data = p;

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

    qc = c->quic;
    cg = &qc->congestion;

    cg->in_flight -= f->plen;

    timer = f->last - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion ack recovery win:%uz, ss:%uz, if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);

        return;
    }

    if (cg->window < cg->ssthresh) {
        cg->window += f->plen;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion slow start win:%uz, ss:%uz, if:%uz",
                       cg->window, cg->ssthresh, cg->in_flight);

    } else {
        cg->window += qc->tp.max_udp_payload_size * f->plen / cg->window;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion avoidance win:%uz, ss:%uz, if:%uz",
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

    qc = c->quic;
    cg = &qc->congestion;

    cg->in_flight -= f->plen;

    timer = f->last - cg->recovery_start;

    if ((ngx_msec_int_t) timer <= 0) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic congestion lost recovery win:%uz, ss:%uz, if:%uz",
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
                   "quic congestion lost win:%uz, ss:%uz, if:%uz",
                   cg->window, cg->ssthresh, cg->in_flight);
}


static void
ngx_quic_free_frame(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (frame->data) {
        ngx_free(frame->data);
        frame->data = NULL;
    }

    ngx_queue_insert_head(&qc->free_frames, &frame->queue);

#ifdef NGX_QUIC_DEBUG_FRAMES_ALLOC
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic free frame n:%ui", qc->nframes);
#endif
}
