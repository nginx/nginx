
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


/*
 * RFC 9000, 7.5.  Cryptographic Message Buffering
 *
 * Implementations MUST support buffering at least 4096 bytes of data
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
static int ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, uint8_t alert);
static ngx_int_t ngx_quic_crypto_input(ngx_connection_t *c, ngx_chain_t *data);


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

    if (ngx_quic_keys_set_encryption_secret(c->pool, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != NGX_OK)
    {
        return 0;
    }

    if (level == ssl_encryption_early_data) {
        if (ngx_quic_init_streams(c) != NGX_OK) {
            return 0;
        }
    }

    return 1;
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

    if (ngx_quic_keys_set_encryption_secret(c->pool, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NGX_OK)
    {
        return 0;
    }

    return 1;
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
        != NGX_OK)
    {
        return 0;
    }

    if (level == ssl_encryption_early_data) {
        if (ngx_quic_init_streams(c) != NGX_OK) {
            return 0;
        }

        return 1;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    if (ngx_quic_keys_set_encryption_secret(c->pool, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NGX_OK)
    {
        return 0;
    }

    return 1;
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                 *p, *end;
    size_t                  client_params_len;
    const uint8_t          *client_params;
    ngx_quic_tp_t           ctp;
    ngx_quic_frame_t       *frame;
    ngx_connection_t       *c;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
    unsigned int            alpn_len;
    const unsigned char    *alpn_data;
#endif

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

         SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

         if (alpn_len == 0) {
             qc->error = 0x100 + SSL_AD_NO_APPLICATION_PROTOCOL;
             qc->error_reason = "unsupported protocol in ALPN extension";

             ngx_log_error(NGX_LOG_INFO, c->log, 0,
                           "quic unsupported protocol in ALPN extension");
             return 0;
         }

#endif

        SSL_get_peer_quic_transport_params(ssl_conn, &client_params,
                                           &client_params_len);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic SSL_get_peer_quic_transport_params():"
                       " params_len:%ui", client_params_len);

        if (client_params_len == 0) {
            /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */
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

    ctx = ngx_quic_get_send_ctx(qc, level);

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
    frame->u.crypto.offset = ctx->crypto_sent;
    frame->u.crypto.length = len;

    ctx->crypto_sent += len;

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
                   "quic ngx_quic_send_alert() level:%s alert:%d",
                   ngx_quic_level_name(level), (int) alert);

    /* already closed on regular shutdown */

    qc = ngx_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error = NGX_QUIC_ERR_CRYPTO(alert);

    return 1;
}


ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                  last;
    ngx_chain_t              *cl;
    ngx_quic_send_ctx_t      *ctx;
    ngx_quic_connection_t    *qc;
    ngx_quic_crypto_frame_t  *f;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, pkt->level);
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > ctx->crypto.offset + NGX_QUIC_MAX_BUFFERED) {
        qc->error = NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return NGX_ERROR;
    }

    if (last <= ctx->crypto.offset) {
        if (pkt->level == ssl_encryption_initial) {
            /* speeding up handshake completion */

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

    if (f->offset == ctx->crypto.offset) {
        if (ngx_quic_crypto_input(c, frame->data) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_quic_skip_buffer(c, &ctx->crypto, last);

    } else {
        if (ngx_quic_write_buffer(c, &ctx->crypto, frame->data, f->length,
                                  f->offset)
            == NGX_CHAIN_ERROR)
        {
            return NGX_ERROR;
        }
    }

    cl = ngx_quic_read_buffer(c, &ctx->crypto, (uint64_t) -1);

    if (cl) {
        if (ngx_quic_crypto_input(c, cl) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_quic_free_chain(c, cl);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_crypto_input(ngx_connection_t *c, ngx_chain_t *data)
{
    int                     n, sslerr;
    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic SSL_quic_read_level:%d SSL_quic_write_level:%d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    for (cl = data; cl; cl = cl->next) {
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
            qc->error_reason = "handshake failed";
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

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_HANDSHAKE_DONE;
    ngx_quic_queue_frame(qc, frame);

    if (qc->conf->retry) {
        if (ngx_quic_send_new_token(c, qc->path) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /*
     * RFC 9001, 9.5.  Header Protection Timing Side Channels
     *
     * Generating next keys before a key update is received.
     */

    if (ngx_quic_keys_update(c, qc->keys) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * RFC 9001, 4.9.2.  Discarding Handshake Keys
     *
     * An endpoint MUST discard its Handshake keys
     * when the TLS handshake is confirmed.
     */
    ngx_quic_discard_ctx(c, ssl_encryption_handshake);

    /* start accepting clients on negotiated number of server ids */
    if (ngx_quic_create_sockets(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_init_streams(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    u_char                 *p;
    size_t                  clen;
    ssize_t                 len;
    ngx_str_t               dcid;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_socket_t      *qsock;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (ngx_ssl_create_connection(qc->conf->ssl, c, 0) != NGX_OK) {
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

#if (BORINGSSL_API_VERSION >= 13 && BORINGSSL_API_VERSION < 15)
    SSL_set_quic_use_legacy_codepoint(ssl_conn, 0);
#endif

    qsock = ngx_quic_get_socket(c);

    dcid.data = qsock->sid.id;
    dcid.len = qsock->sid.len;

    if (ngx_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key, qc->tp.sr_token)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

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

#if BORINGSSL_API_VERSION >= 11
    if (SSL_set_quic_early_data_context(ssl_conn, p, clen) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_early_data_context() failed");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
