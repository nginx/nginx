
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_sha1.h>
#include <ngx_event_quic_connection.h>


/*
 * 7.4.  Cryptographic Message Buffering
 *       Implementations MUST support buffering at least 4096 bytes of data
 */
#define NGX_QUIC_MAX_BUFFERED    65535


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


static ngx_int_t ngx_quic_apply_transport_params(ngx_connection_t *c,
    ngx_quic_tp_t *ctp);
static ngx_quic_connection_t *ngx_quic_new_connection(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_stateless_reset(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static void ngx_quic_address_hash(ngx_connection_t *c, ngx_uint_t no_port,
    u_char buf[20]);
static ngx_int_t ngx_quic_validate_token(ngx_connection_t *c,
    u_char *key, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);
static void ngx_quic_input_handler(ngx_event_t *rev);

static ngx_int_t ngx_quic_close_quic(ngx_connection_t *c, ngx_int_t rc);
static void ngx_quic_close_timer_handler(ngx_event_t *ev);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b,
    ngx_quic_conf_t *conf);
static ngx_int_t ngx_quic_process_packet(ngx_connection_t *c,
    ngx_quic_conf_t *conf, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_process_payload(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static void ngx_quic_discard_ctx(ngx_connection_t *c,
    enum ssl_encryption_level_t level);
static ngx_int_t ngx_quic_check_csid(ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_frames(ngx_connection_t *c,
    ngx_quic_header_t *pkt);


static ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_frame_t *frame);
ngx_int_t ngx_quic_crypto_input(ngx_connection_t *c,
    ngx_quic_frame_t *frame, void *data);

static void ngx_quic_push_handler(ngx_event_t *ev);


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

void
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

        p = ngx_slprintf(p, last, "%s", qc->shutdown ? " shutdown" : "");
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

    if (pkt->validated && pkt->retried) {
        qc->tp.retry_scid.len = pkt->dcid.len;
        qc->tp.retry_scid.data = ngx_pstrdup(c->pool, &pkt->dcid);
        if (qc->tp.retry_scid.data == NULL) {
            return NULL;
        }
    }

    if (ngx_quic_keys_set_initial_secret(c->pool, qc->keys, &pkt->dcid,
                                         qc->version)
        != NGX_OK)
    {
        return NULL;
    }

    qc->validated = pkt->validated;

    if (ngx_quic_setup_connection_ids(c, qc, pkt) != NGX_OK) {
        return NULL;
    }

    return qc;
}


ngx_int_t
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


ngx_int_t
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

#if BORINGSSL_API_VERSION >= 13
    SSL_set_quic_use_legacy_codepoint(ssl_conn, qc->version != 1);
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


static void
ngx_quic_input_handler(ngx_event_t *rev)
{
    ngx_int_t               rc;
    ngx_buf_t              *b;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic input handler");

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

    if (!rev->ready) {
        if (qc->closing) {
            ngx_quic_close_connection(c, NGX_OK);
        }
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

    b = c->udp->dgram->buffer;

    qc->received += (b->last - b->pos);

    rc = ngx_quic_input(c, b, NULL);

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


void
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


void
ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_uint_t err,
    const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->shutdown = 1;
    qc->shutdown_code = err;
    qc->shutdown_reason = reason;

    ngx_quic_shutdown_quic(c);
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

        case NGX_QUIC_FT_PATH_RESPONSE:

            if (ngx_quic_handle_path_response_frame(c, pkt,
                                                    &frame.u.path_response)
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


ngx_int_t
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


void
ngx_quic_shutdown_quic(ngx_connection_t *c)
{
    ngx_rbtree_t           *tree;
    ngx_rbtree_node_t      *node;
    ngx_quic_stream_t      *qs;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->closing) {
        return;
    }

    tree = &qc->streams.tree;

    if (tree->root != tree->sentinel) {
        for (node = ngx_rbtree_min(tree->root, tree->sentinel);
             node;
             node = ngx_rbtree_next(tree, node))
        {
            qs = (ngx_quic_stream_t *) node;

            if (!qs->cancelable) {
                return;
            }
        }
    }

    ngx_quic_finalize_connection(c, qc->shutdown_code, qc->shutdown_reason);
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
