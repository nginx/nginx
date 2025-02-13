
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


#if (NGX_QUIC_OPENSSL_API)

static int ngx_quic_cbs_send(ngx_ssl_conn_t *ssl_conn,
    const unsigned char *data, size_t len, size_t *consumed, void *arg);
static int ngx_quic_cbs_recv_rcd(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **data, size_t *bytes_read, void *arg);
static int ngx_quic_cbs_release_rcd(ngx_ssl_conn_t *ssl_conn,
    size_t bytes_read, void *arg);
static int ngx_quic_cbs_yield_secret(ngx_ssl_conn_t *ssl_conn, uint32_t level,
    int direction, const unsigned char *secret, size_t secret_len, void *arg);
static int ngx_quic_cbs_got_transport_params(ngx_ssl_conn_t *ssl_conn,
    const unsigned char *params, size_t params_len, void *arg);
static int ngx_quic_cbs_alert(ngx_ssl_conn_t *ssl_conn, unsigned char alert,
    void *arg);

#else /* NGX_QUIC_BORINGSSL_API || NGX_QUIC_QUICTLS_API */

static ngx_inline ngx_uint_t ngx_quic_map_encryption_level(
    enum ssl_encryption_level_t ssl_level);

#if (NGX_QUIC_BORINGSSL_API)
static int ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
static int ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
#else /* NGX_QUIC_QUICTLS_API */
static int ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
#endif

static int ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const uint8_t *data, size_t len);
static int ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn);
static int ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, uint8_t alert);

#endif

static ngx_int_t ngx_quic_handshake(ngx_connection_t *c);
static ngx_int_t ngx_quic_crypto_provide(ngx_connection_t *c, ngx_uint_t level);


#if (NGX_QUIC_OPENSSL_API)

static int
ngx_quic_cbs_send(ngx_ssl_conn_t *ssl_conn,
    const unsigned char *data, size_t len, size_t *consumed, void *arg)
{
    ngx_connection_t  *c = arg;

    ngx_chain_t            *out;
    unsigned int            alpn_len;
    ngx_quic_frame_t       *frame;
    const unsigned char    *alpn_data;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_send len:%uz", len);

    qc = ngx_quic_get_connection(c);

    *consumed = 0;

    SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

    if (alpn_len == 0) {
        qc->error = NGX_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL);
        qc->error_reason = "missing ALPN extension";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic missing ALPN extension");
        return 1;
    }

    if (!qc->client_tp_done) {
        /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */
        qc->error = NGX_QUIC_ERR_CRYPTO(SSL_AD_MISSING_EXTENSION);
        qc->error_reason = "missing transport parameters";

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "missing transport parameters");
        return 1;
    }

    ctx = ngx_quic_get_send_ctx(qc, qc->write_level);

    out = ngx_quic_copy_buffer(c, (u_char *) data, len);
    if (out == NGX_CHAIN_ERROR) {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame->data = out;
    frame->level = qc->write_level;
    frame->type = NGX_QUIC_FT_CRYPTO;
    frame->u.crypto.offset = ctx->crypto_sent;
    frame->u.crypto.length = len;

    ctx->crypto_sent += len;
    *consumed = len;

    ngx_quic_queue_frame(qc, frame);

    return 1;
}


static int
ngx_quic_cbs_recv_rcd(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **data, size_t *bytes_read, void *arg)
{
    ngx_connection_t  *c = arg;

    ngx_buf_t              *b;
    ngx_chain_t            *cl;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_recv_rcd");

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, qc->read_level);

    for (cl = ctx->crypto.chain; cl; cl = cl->next) {
        b = cl->buf;

        if (b->sync) {
            /* hole */

            *bytes_read = 0;

            break;
        }

        *data = b->pos;
        *bytes_read = b->last - b->pos;

        break;
    }

    return 1;
}


static int
ngx_quic_cbs_release_rcd(ngx_ssl_conn_t *ssl_conn, size_t bytes_read, void *arg)
{
    ngx_connection_t  *c = arg;

    ngx_chain_t            *cl;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_release_rcd len:%uz", bytes_read);

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, qc->read_level);

    cl = ngx_quic_read_buffer(c, &ctx->crypto, bytes_read);
    if (cl == NGX_CHAIN_ERROR) {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    ngx_quic_free_chain(c, cl);

    return 1;
}


static int
ngx_quic_cbs_yield_secret(ngx_ssl_conn_t *ssl_conn, uint32_t ssl_level,
    int direction, const unsigned char *secret, size_t secret_len, void *arg)
{
    ngx_connection_t  *c = arg;

    ngx_uint_t              level;
    const SSL_CIPHER       *cipher;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_yield_secret() level:%uD", ssl_level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic %s secret len:%uz %*xs",
                   direction ? "write" : "read", secret_len,
                   secret_len, secret);
#endif

    qc = ngx_quic_get_connection(c);
    cipher = SSL_get_current_cipher(ssl_conn);

    switch (ssl_level) {
    case OSSL_RECORD_PROTECTION_LEVEL_NONE:
        level = NGX_QUIC_ENCRYPTION_INITIAL;
        break;
    case OSSL_RECORD_PROTECTION_LEVEL_EARLY:
        level = NGX_QUIC_ENCRYPTION_EARLY_DATA;
        break;
    case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE:
        level = NGX_QUIC_ENCRYPTION_HANDSHAKE;
        break;
    default: /* OSSL_RECORD_PROTECTION_LEVEL_APPLICATION */
        level = NGX_QUIC_ENCRYPTION_APPLICATION;
        break;
    }

    if (ngx_quic_keys_set_encryption_secret(c->log, direction, qc->keys, level,
                                            cipher, secret, secret_len)
        != NGX_OK)
    {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    if (direction) {
        qc->write_level = level;

    } else {
        qc->read_level = level;
    }

    return 1;
}


static int
ngx_quic_cbs_got_transport_params(ngx_ssl_conn_t *ssl_conn,
    const unsigned char *params, size_t params_len, void *arg)
{
    ngx_connection_t  *c = arg;

    u_char                 *p, *end;
    ngx_quic_tp_t           ctp;
    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_got_transport_params() len:%uz",
                   params_len);

    qc = ngx_quic_get_connection(c);

    /* defaults for parameters not sent by client */
    ngx_memcpy(&ctp, &qc->ctp, sizeof(ngx_quic_tp_t));

    p = (u_char *) params;
    end = p + params_len;

    if (ngx_quic_parse_transport_params(p, end, &ctp, c->log) != NGX_OK) {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "failed to process transport parameters";

        return 1;
    }

    if (ngx_quic_apply_transport_params(c, &ctp) != NGX_OK) {
        return 1;
    }

    qc->client_tp_done = 1;

    return 1;
}


static int
ngx_quic_cbs_alert(ngx_ssl_conn_t *ssl_conn, unsigned char alert, void *arg)
{
    ngx_connection_t  *c = arg;

    ngx_quic_connection_t  *qc;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_cbs_alert() alert:%d", (int) alert);

    /* already closed on regular shutdown */

    qc = ngx_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error = NGX_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "handshake failed";

    return 1;
}


#else /* NGX_QUIC_BORINGSSL_API || NGX_QUIC_QUICTLS_API */


static ngx_inline ngx_uint_t
ngx_quic_map_encryption_level(enum ssl_encryption_level_t ssl_level)
{
    switch (ssl_level) {
    case ssl_encryption_initial:
        return NGX_QUIC_ENCRYPTION_INITIAL;
    case ssl_encryption_early_data:
        return NGX_QUIC_ENCRYPTION_EARLY_DATA;
    case ssl_encryption_handshake:
        return NGX_QUIC_ENCRYPTION_HANDSHAKE;
    default: /* ssl_encryption_application */
        return NGX_QUIC_ENCRYPTION_APPLICATION;
    }
}


#if (NGX_QUIC_BORINGSSL_API)

static int
ngx_quic_set_read_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    ngx_uint_t              level;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl_conn);
    qc = ngx_quic_get_connection(c);
    level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_read_secret() level:%d", ssl_level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    if (ngx_quic_keys_set_encryption_secret(c->log, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != NGX_OK)
    {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
    }

    return 1;
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_uint_t              level;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl_conn);
    qc = ngx_quic_get_connection(c);
    level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_write_secret() level:%d", ssl_level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    if (ngx_quic_keys_set_encryption_secret(c->log, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NGX_OK)
    {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
    }

    return 1;
}

#else /* NGX_QUIC_QUICTLS_API */

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_uint_t              level;
    ngx_connection_t       *c;
    const SSL_CIPHER       *cipher;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl_conn);
    qc = ngx_quic_get_connection(c);
    level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_set_encryption_secrets() level:%d",
                   ssl_level);
#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    cipher = SSL_get_current_cipher(ssl_conn);

    if (ngx_quic_keys_set_encryption_secret(c->log, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != NGX_OK)
    {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    if (level == NGX_QUIC_ENCRYPTION_EARLY_DATA) {
        return 1;
    }

#ifdef NGX_QUIC_DEBUG_CRYPTO
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    if (ngx_quic_keys_set_encryption_secret(c->log, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NGX_OK)
    {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
    }

    return 1;
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, const uint8_t *data, size_t len)
{
    u_char                 *p, *end;
    size_t                  client_params_len;
    ngx_uint_t              level;
    ngx_chain_t            *out;
    unsigned int            alpn_len;
    const uint8_t          *client_params;
    ngx_quic_tp_t           ctp;
    ngx_quic_frame_t       *frame;
    ngx_connection_t       *c;
    const unsigned char    *alpn_data;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl_conn);
    qc = ngx_quic_get_connection(c);
    level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_add_handshake_data");

    if (!qc->client_tp_done) {
        /*
         * things to do once during handshake: check ALPN and transport
         * parameters; we want to break handshake if something is wrong
         * here;
         */

        SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

        if (alpn_len == 0) {
            if (qc->error == 0) {
                qc->error = NGX_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL);
                qc->error_reason = "missing ALPN extension";

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic missing ALPN extension");
            }

            return 1;
        }

        SSL_get_peer_quic_transport_params(ssl_conn, &client_params,
                                           &client_params_len);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic SSL_get_peer_quic_transport_params():"
                       " params_len:%ui", client_params_len);

        if (client_params_len == 0) {
            /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */

            if (qc->error == 0) {
                qc->error = NGX_QUIC_ERR_CRYPTO(SSL_AD_MISSING_EXTENSION);
                qc->error_reason = "missing transport parameters";

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "missing transport parameters");
            }

            return 1;
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

            return 1;
        }

        if (ngx_quic_apply_transport_params(c, &ctp) != NGX_OK) {
            return 1;
        }

        qc->client_tp_done = 1;
    }

    ctx = ngx_quic_get_send_ctx(qc, level);

    out = ngx_quic_copy_buffer(c, (u_char *) data, len);
    if (out == NGX_CHAIN_ERROR) {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        return 1;
    }

    frame->data = out;
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

    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_flush_flight()");
#endif
    return 1;
}


static int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t ssl_level, uint8_t alert)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection(ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ngx_quic_send_alert() level:%d alert:%d",
                   ssl_level, (int) alert);

    /* already closed on regular shutdown */

    qc = ngx_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error = NGX_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "handshake failed";

    return 1;
}

#endif


ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_frame_t *frame)
{
    uint64_t                  last;
    ngx_quic_send_ctx_t      *ctx;
    ngx_quic_connection_t    *qc;
    ngx_quic_crypto_frame_t  *f;

    qc = ngx_quic_get_connection(c);

    if (!ngx_quic_keys_available(qc->keys, pkt->level, 0)) {
        return NGX_OK;
    }

    ctx = ngx_quic_get_send_ctx(qc, pkt->level);
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > ctx->crypto.offset + NGX_QUIC_MAX_BUFFERED) {
        qc->error = NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return NGX_ERROR;
    }

    if (last <= ctx->crypto.offset) {
        if (pkt->level == NGX_QUIC_ENCRYPTION_INITIAL) {
            /* speeding up handshake completion */

            if (!ngx_queue_empty(&ctx->sent)) {
                ngx_quic_resend_frames(c, ctx);

                ctx = ngx_quic_get_send_ctx(qc, NGX_QUIC_ENCRYPTION_HANDSHAKE);
                while (!ngx_queue_empty(&ctx->sent)) {
                    ngx_quic_resend_frames(c, ctx);
                }
            }
        }

        return NGX_OK;
    }

    if (ngx_quic_write_buffer(c, &ctx->crypto, frame->data, f->length,
                              f->offset)
        == NGX_CHAIN_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_crypto_provide(c, pkt->level) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_handshake(c);
}


static ngx_int_t
ngx_quic_handshake(ngx_connection_t *c)
{
    int                     n, sslerr;
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (qc->error) {
        return NGX_ERROR;
    }

    if (n <= 0) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {

            if (c->ssl->handshake_rejected) {
                ngx_connection_error(c, 0, "handshake rejected");
                ERR_clear_error();

                return NGX_ERROR;
            }

            ngx_ssl_connection_error(c, sslerr, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }
    }

    if (!SSL_is_init_finished(ssl_conn)) {
        if (ngx_quic_keys_available(qc->keys, NGX_QUIC_ENCRYPTION_EARLY_DATA, 0)
            && qc->client_tp_done)
        {
            if (ngx_quic_init_streams(c) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        return NGX_OK;
    }

#if (NGX_DEBUG)
    ngx_ssl_handshake_log(c);
#endif

    c->ssl->handshaked = 1;

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = NGX_QUIC_ENCRYPTION_APPLICATION;
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

    ngx_post_event(&qc->key_update, &ngx_posted_events);

    /*
     * RFC 9001, 4.9.2.  Discarding Handshake Keys
     *
     * An endpoint MUST discard its Handshake keys
     * when the TLS handshake is confirmed.
     */
    ngx_quic_discard_ctx(c, NGX_QUIC_ENCRYPTION_HANDSHAKE);

    ngx_quic_discover_path_mtu(c, qc->path);

    /* start accepting clients on negotiated number of server ids */
    if (ngx_quic_create_sockets(c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_init_streams(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_crypto_provide(ngx_connection_t *c, ngx_uint_t level)
{
#if (NGX_QUIC_BORINGSSL_API || NGX_QUIC_QUICTLS_API)

    ngx_buf_t                    *b;
    ngx_chain_t                  *out, *cl;
    ngx_quic_send_ctx_t          *ctx;
    ngx_quic_connection_t        *qc;
    enum ssl_encryption_level_t   ssl_level;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, level);

    out = ngx_quic_read_buffer(c, &ctx->crypto, (uint64_t) -1);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    switch (level) {
    case NGX_QUIC_ENCRYPTION_INITIAL:
        ssl_level = ssl_encryption_initial;
        break;
    case NGX_QUIC_ENCRYPTION_EARLY_DATA:
        ssl_level = ssl_encryption_early_data;
        break;
    case NGX_QUIC_ENCRYPTION_HANDSHAKE:
        ssl_level = ssl_encryption_handshake;
        break;
    default: /* NGX_QUIC_ENCRYPTION_APPLICATION */
        ssl_level = ssl_encryption_application;
        break;
    }

    for (cl = out; cl; cl = cl->next) {
        b = cl->buf;

        if (!SSL_provide_quic_data(c->ssl->connection, ssl_level, b->pos,
                                   b->last - b->pos))
        {
            ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                          "SSL_provide_quic_data() failed");
            return NGX_ERROR;
        }
    }

    ngx_quic_free_chain(c, out);

#endif

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

#if (NGX_QUIC_OPENSSL_API)
    static const OSSL_DISPATCH  qtdis[] = {

        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
          (void (*)(void)) ngx_quic_cbs_send },

        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
          (void (*)(void)) ngx_quic_cbs_recv_rcd },

        { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
          (void (*)(void)) ngx_quic_cbs_release_rcd },

        { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
          (void (*)(void)) ngx_quic_cbs_yield_secret },

        { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
          (void (*)(void)) ngx_quic_cbs_got_transport_params },

        { OSSL_FUNC_SSL_QUIC_TLS_ALERT,
          (void (*)(void)) ngx_quic_cbs_alert },

        { 0, NULL }
    };
#else /* NGX_QUIC_BORINGSSL_API || NGX_QUIC_QUICTLS_API */
    static SSL_QUIC_METHOD  quic_method;
#endif

    qc = ngx_quic_get_connection(c);

    if (ngx_ssl_create_connection(qc->conf->ssl, c, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->no_wait_shutdown = 1;

    ssl_conn = c->ssl->connection;

#if (NGX_QUIC_OPENSSL_API)

    if (SSL_set_quic_tls_cbs(ssl_conn, qtdis, c) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                      "quic SSL_set_quic_tls_cbs() failed");
        return NGX_ERROR;
    }

    if (SSL_CTX_get_max_early_data(qc->conf->ssl->ctx)) {
        SSL_set_quic_tls_early_data_enabled(ssl_conn, 1);
    }

#else /* NGX_QUIC_BORINGSSL_API || NGX_QUIC_QUICTLS_API */

    if (!quic_method.send_alert) {
#if (NGX_QUIC_BORINGSSL_API)
        quic_method.set_read_secret = ngx_quic_set_read_secret;
        quic_method.set_write_secret = ngx_quic_set_write_secret;
#else
        quic_method.set_encryption_secrets = ngx_quic_set_encryption_secrets;
#endif
        quic_method.add_handshake_data = ngx_quic_add_handshake_data;
        quic_method.flush_flight = ngx_quic_flush_flight;
        quic_method.send_alert = ngx_quic_send_alert;
    }

    if (SSL_set_quic_method(ssl_conn, &quic_method) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                      "quic SSL_set_quic_method() failed");
        return NGX_ERROR;
    }

#if (NGX_QUIC_QUICTLS_API)
    if (SSL_CTX_get_max_early_data(qc->conf->ssl->ctx)) {
        SSL_set_quic_early_data_enabled(ssl_conn, 1);
    }
#endif

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

#if (NGX_QUIC_OPENSSL_API)
    if (SSL_set_quic_tls_transport_params(ssl_conn, p, len) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                      "quic SSL_set_quic_tls_transport_params() failed");
        return NGX_ERROR;
    }
#else
    if (SSL_set_quic_transport_params(ssl_conn, p, len) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                      "quic SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }
#endif

#ifdef OPENSSL_IS_BORINGSSL
    if (SSL_set_quic_early_data_context(ssl_conn, p, clen) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
                      "quic SSL_set_quic_early_data_context() failed");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}
