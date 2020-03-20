
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_rbtree_node_t                  node;
    ngx_buf_t                         *b;
    ngx_connection_t                  *c;
    ngx_quic_stream_t                  s;
} ngx_quic_stream_node_t;


typedef struct {
    ngx_rbtree_t                      tree;
    ngx_rbtree_node_t                 sentinel;
    ngx_msec_t                        timeout;
    ngx_connection_handler_pt         handler;

    ngx_uint_t                        id_counter;
} ngx_quic_streams_t;


struct ngx_quic_connection_s {
    ngx_str_t                         scid;
    ngx_str_t                         dcid;
    ngx_str_t                         token;

    ngx_quic_tp_t                     tp;

    /* current packet numbers  for each namespace */
    ngx_uint_t                        initial_pn;
    ngx_uint_t                        handshake_pn;
    ngx_uint_t                        appdata_pn;

    ngx_quic_secrets_t                secrets;
    ngx_ssl_t                        *ssl;
    ngx_quic_frame_t                 *frames;

    ngx_quic_streams_t                streams;
    ngx_uint_t                        max_data;
};


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
    ngx_quic_tp_t *tp, ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_init_connection(ngx_connection_t *c);
static void ngx_quic_handshake_handler(ngx_event_t *rev);
static void ngx_quic_close_connection(ngx_connection_t *c);

static ngx_int_t ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b);
static ngx_int_t ngx_quic_initial_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handshake_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_app_input(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_payload_handler(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

static ngx_int_t ngx_quic_handle_ack_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_ack_frame_t *f);
static ngx_int_t ngx_quic_handle_crypto_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_crypto_frame_t *frame);
static ngx_int_t ngx_quic_handle_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_frame_t *frame);
static ngx_int_t ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f);

static void ngx_quic_queue_frame(ngx_quic_connection_t *qc,
    ngx_quic_frame_t *frame);

static ngx_int_t ngx_quic_output(ngx_connection_t *c);
ngx_int_t ngx_quic_frames_send(ngx_connection_t *c, ngx_quic_frame_t *start,
    ngx_quic_frame_t *end, size_t total);
static ngx_int_t ngx_quic_send_packet(ngx_connection_t *c,
    ngx_quic_connection_t *qc, enum ssl_encryption_level_t level,
    ngx_str_t *payload);


static void ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_quic_stream_node_t *ngx_quic_find_stream(ngx_rbtree_t *rbtree,
    ngx_uint_t key);
static ngx_quic_stream_node_t *ngx_quic_create_stream(ngx_connection_t *c,
    ngx_uint_t id);
static ssize_t ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf,
    size_t size);
static ssize_t ngx_quic_stream_send(ngx_connection_t *c, u_char *buf,
    size_t size);
static void ngx_quic_stream_cleanup_handler(void *data);
static ngx_chain_t *ngx_quic_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);


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
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read secret",
                     rsecret, secret_len, level);

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          rsecret, secret_len,
                                          &c->quic->secrets.client);
}


static int
ngx_quic_set_write_secret(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d write secret",
                     wsecret, secret_len, level);

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &c->quic->secrets.server);
}

#else

static int
ngx_quic_set_encryption_secrets(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_quic_hexdump(c->log, "level:%d read", rsecret, secret_len, level);
    ngx_quic_hexdump(c->log, "level:%d write", wsecret, secret_len, level);

    rc = ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                        rsecret, secret_len,
                                        &c->quic->secrets.client);
    if (rc != 1) {
        return rc;
    }

    return ngx_quic_set_encryption_secret(c->pool, ssl_conn, level,
                                          wsecret, secret_len,
                                          &c->quic->secrets.server);
}

#endif


static int
ngx_quic_add_handshake_data(ngx_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                 *p;
    ngx_quic_frame_t       *frame;
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
    qc = c->quic;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_add_handshake_data");

    frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return 0;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return 0;
    }

    ngx_memcpy(p, data, len);

    frame->level = level;
    frame->type = NGX_QUIC_FT_CRYPTO;
    frame->u.crypto.len = len;
    frame->u.crypto.data = p;

    ngx_sprintf(frame->info, "crypto, generated by SSL len=%ui level=%d", len, level);

    ngx_quic_queue_frame(qc, frame);

    return 1;
}


static int
ngx_quic_flush_flight(ngx_ssl_conn_t *ssl_conn)
{
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_quic_flush_flight()");

    return 1;
}


static int
ngx_quic_send_alert(ngx_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    ngx_connection_t  *c;
    ngx_quic_frame_t  *frame;

    c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_quic_send_alert(), lvl=%d, alert=%d",
                   (int) level, (int) alert);

    frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return 0;
    }

    frame->level = level;
    frame->type = NGX_QUIC_FT_CONNECTION_CLOSE;
    frame->u.close.error_code = 0x100 + alert;

    ngx_quic_queue_frame(c->quic, frame);

    if (ngx_quic_output(c) != NGX_OK) {
        return 0;
    }

    return 1;
}


void
ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_msec_t timeout, ngx_connection_handler_pt handler)
{
    ngx_buf_t          *b;
    ngx_quic_header_t   pkt;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic handshake");

    c->log->action = "QUIC handshaking";

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));

    b = c->buffer;

    pkt.log = c->log;
    pkt.raw = b;
    pkt.data = b->start;
    pkt.len = b->last - b->start;

    if (ngx_quic_new_connection(c, ssl, tp, &pkt) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }

    // we don't need stream handler for initial packet processing
    c->quic->streams.handler = handler;
    c->quic->streams.timeout = timeout;

    ngx_add_timer(c->read, timeout);

    c->read->handler = ngx_quic_handshake_handler;

    return;
}


static ngx_int_t
ngx_quic_new_connection(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_quic_tp_t *tp,
    ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    if (ngx_buf_size(pkt->raw) < 1200) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "too small UDP datagram");
        return NGX_ERROR;
    }

    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ngx_quic_pkt_in(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid initial packet: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    c->quic = qc;
    qc->ssl = ssl;
    qc->tp = *tp;

    qc->dcid.len = pkt->dcid.len;
    qc->dcid.data = ngx_pnalloc(c->pool, pkt->dcid.len);
    if (qc->dcid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->dcid.data, pkt->dcid.data, qc->dcid.len);

    qc->scid.len = pkt->scid.len;
    qc->scid.data = ngx_pnalloc(c->pool, qc->scid.len);
    if (qc->scid.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->scid.data, pkt->scid.data, qc->scid.len);

    qc->token.len = pkt->token.len;
    qc->token.data = ngx_pnalloc(c->pool, qc->token.len);
    if (qc->token.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(qc->token.data, pkt->token.data, qc->token.len);


    if (ngx_quic_set_initial_secret(c->pool, &qc->secrets, &qc->dcid)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.in;
    pkt->level = ssl_encryption_initial;

    if (ngx_quic_decrypt(c->pool, NULL, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_init_connection(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_init_connection(ngx_connection_t *c)
{
    int                     n, sslerr;
    u_char                 *p;
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
                      "SSL_set_quic_method() failed");
        return NGX_ERROR;
    }

    len = ngx_quic_create_transport_params(NULL, NULL, &qc->tp);
    /* always succeeds */

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    len = ngx_quic_create_transport_params(p, p + len, &qc->tp);
    if (len < 0) {
        return NGX_ERROR;
    }

    if (SSL_set_quic_transport_params(ssl_conn, p, len) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "SSL_set_quic_transport_params() failed");
        return NGX_ERROR;
    }

    n = SSL_do_handshake(ssl_conn);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == -1) {
        sslerr = SSL_get_error(ssl_conn, n);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}


static void
ngx_quic_handshake_handler(ngx_event_t *rev)
{
    ssize_t            n;
    ngx_buf_t          b;
    ngx_connection_t  *c;

    u_char             buf[512];

    b.start = buf;
    b.end = buf + 512;
    b.pos = b.last = b.start;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic handshake handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_quic_close_connection(c);
        return;
    }

    ngx_add_timer(rev, c->quic->streams.timeout);

    if (c->close) {
        ngx_quic_close_connection(c);
        return;
    }

    n = c->recv(c, b.start, b.end - b.start);

    if (n == NGX_AGAIN) {
        return;
    }

    if (n == NGX_ERROR) {
        c->read->eof = 1;
        ngx_quic_close_connection(c);
        return;
    }

    b.last += n;

    if (ngx_quic_input(c, &b) != NGX_OK) {
        ngx_quic_close_connection(c);
        return;
    }
}


static void
ngx_quic_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    /* XXX wait for all streams to close */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "close quic connection: %d", c->fd);

    if (c->ssl) {
        (void) ngx_ssl_shutdown(c);
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
ngx_quic_input(ngx_connection_t *c, ngx_buf_t *b)
{
    u_char             *p;
    ngx_int_t           rc;
    ngx_quic_header_t   pkt;

    if (c->quic == NULL) {
        // XXX: possible?
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "BUG: no QUIC in connection");
        return NGX_ERROR;
    }

    p = b->start;

    do {
        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.flags = p[0];

        if (pkt.flags == 0) {
            /* XXX: no idea WTF is this, just ignore */
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "FIREFOX: ZEROES");
            break;
        }

        // TODO: check current state
        if (ngx_quic_long_pkt(pkt.flags)) {

            if (ngx_quic_pkt_in(pkt.flags)) {
                rc = ngx_quic_initial_input(c, &pkt);

            } else if (ngx_quic_pkt_hs(pkt.flags)) {
                rc = ngx_quic_handshake_input(c, &pkt);

            } else {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "BUG: unknown quic state");
                return NGX_ERROR;
            }

        } else {
            rc = ngx_quic_app_input(c, &pkt);
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        /* b->pos is at header end, adjust by actual packet length */
        p = b->pos + pkt.len;
        b->pos = p;       /* reset b->pos to the next packet start */

    } while (p < b->last);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_initial_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_ssl_conn_t         *ssl_conn;
    ngx_quic_connection_t  *qc;

    qc = c->quic;
    ssl_conn = c->ssl->connection;

    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_quic_parse_initial_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.in;
    pkt->level = ssl_encryption_initial;

    if (ngx_quic_decrypt(c->pool, ssl_conn, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_handshake_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    /* extract cleartext data into pkt */
    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->dcid.len != qc->dcid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->dcid.data, qc->dcid.data, qc->dcid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    if (pkt->scid.len != qc->scid.len) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scidl");
        return NGX_ERROR;
    }

    if (ngx_memcmp(pkt->scid.data, qc->scid.data, qc->scid.len) != 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "unexpected quic scid");
        return NGX_ERROR;
    }

    if (!ngx_quic_pkt_hs(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "invalid packet type: 0x%xi", pkt->flags);
        return NGX_ERROR;
    }

    if (ngx_quic_parse_handshake_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.hs;
    pkt->level = ssl_encryption_handshake;

    if (ngx_quic_decrypt(c->pool, c->ssl->connection, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_app_input(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (qc->secrets.client.ad.key.len == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "no read keys yet, packet ignored");
        return NGX_DECLINED;
    }

    if (ngx_quic_parse_short_header(pkt, &qc->dcid) != NGX_OK) {
        return NGX_ERROR;
    }

    pkt->secret = &qc->secrets.client.ad;
    pkt->level = ssl_encryption_application;

    if (ngx_quic_decrypt(c->pool, c->ssl->connection, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_quic_payload_handler(c, pkt);
}


static ngx_int_t
ngx_quic_payload_handler(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *end, *p;
    ssize_t                 len;
    ngx_uint_t              ack_this, do_close;
    ngx_quic_frame_t        frame, *ack_frame;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    ack_this = 0;
    do_close = 0;

    while (p < end) {

        len = ngx_quic_parse_frame(pkt, p, end, &frame);

        if (len == NGX_DECLINED) {
            /* TODO: handle protocol violation:
             *       such frame not allowed in this packet
             */
            return NGX_ERROR;
        }

        if (len < 0) {
            return NGX_ERROR;
        }

        p += len;

        switch (frame.type) {

        case NGX_QUIC_FT_ACK:
            if (ngx_quic_handle_ack_frame(c, pkt, &frame.u.ack) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_CRYPTO:

            if (ngx_quic_handle_crypto_frame(c, pkt, &frame.u.crypto)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        case NGX_QUIC_FT_PADDING:
            break;

        case NGX_QUIC_FT_PING:
            ack_this = 1;
            break;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:
            ack_this = 1;
            break;

        case NGX_QUIC_FT_CONNECTION_CLOSE:

            do_close = 1;
            break;

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:

            if (ngx_quic_handle_stream_frame(c, pkt, &frame.u.stream)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        case NGX_QUIC_FT_MAX_DATA:
            c->quic->max_data = frame.u.max_data.max_data;
            ack_this = 1;
            break;

        case NGX_QUIC_FT_RESET_STREAM:
            /* TODO: handle */
            break;

        case NGX_QUIC_FT_STOP_SENDING:
            /* TODO: handle; need ack ? */
            break;

        case NGX_QUIC_FT_STREAMS_BLOCKED:
        case NGX_QUIC_FT_STREAMS_BLOCKED2:

            if (ngx_quic_handle_streams_blocked_frame(c, pkt,
                                                      &frame.u.streams_blocked)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            ack_this = 1;
            break;

        default:
            return NGX_ERROR;
        }
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "trailing garbage in payload: %ui bytes", end - p);
        return NGX_ERROR;
    }

    if (do_close) {
        // TODO: handle stream close
    }

    if (ack_this == 0) {
        /* do not ack packets with ACKs and PADDING */
        return NGX_OK;
    }

    // packet processed, ACK it now if required
    // TODO: if (ack_required) ...  - currently just ack each packet

    ack_frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (ack_frame == NULL) {
        return NGX_ERROR;
    }

    ack_frame->level = pkt->level;
    ack_frame->type = NGX_QUIC_FT_ACK;
    ack_frame->u.ack.pn = pkt->pn;

    ngx_sprintf(ack_frame->info, "ACK for PN=%d from frame handler level=%d", pkt->pn, pkt->level);
    ngx_quic_queue_frame(qc, ack_frame);

    return ngx_quic_output(c);
}


static ngx_int_t
ngx_quic_handle_ack_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_ack_frame_t *f)
{
    /* TODO: handle ACK here */
    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_crypto_frame(ngx_connection_t *c, ngx_quic_header_t *pkt,
    ngx_quic_crypto_frame_t *f)
{
    int              sslerr;
    ssize_t          n;
    ngx_ssl_conn_t  *ssl_conn;

    if (f->offset != 0x0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "crypto frame with non-zero offset");
        // TODO: add support for crypto frames spanning packets
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    if (!SSL_provide_quic_data(ssl_conn, SSL_quic_read_level(ssl_conn),
                               f->data, f->len))
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

        if (sslerr == SSL_ERROR_SSL) {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic ssl cipher: %s", SSL_get_cipher(ssl_conn));

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_quic_read_level: %d, SSL_quic_write_level: %d",
                   (int) SSL_quic_read_level(ssl_conn),
                   (int) SSL_quic_write_level(ssl_conn));

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_stream_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_stream_frame_t *f)
{
    ngx_buf_t               *b;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qc = c->quic;

    sn = ngx_quic_find_stream(&qc->streams.tree, f->stream_id);

    if (sn) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "existing stream");
        b = sn->b;

        if ((size_t) (b->end - b->pos) < f->length) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "no space in stream buffer");
            return NGX_ERROR;
        }

        ngx_memcpy(b->pos, f->data, f->length);
        b->pos += f->length;

        // TODO: notify

        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "stream is new");

    sn = ngx_quic_create_stream(c, f->stream_id);
    if (sn == NULL) {
        return NGX_ERROR;
    }

    b = sn->b;

    ngx_memcpy(b->start, f->data, f->length);
    b->last = b->start + f->length;

    qc->streams.handler(sn->c);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_streams_blocked_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_streams_blocked_frame_t *f)
{
    ngx_quic_frame_t  *frame;

    frame = ngx_pcalloc(c->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_MAX_STREAMS;
    frame->u.max_streams.limit = f->limit * 2;
    frame->u.max_streams.bidi = f->bidi;

    ngx_sprintf(frame->info, "MAX_STREAMS limit:%d bidi:%d level=%d",
                (int) frame->u.max_streams.limit,
                (int) frame->u.max_streams.bidi,
                frame->level);

    ngx_quic_queue_frame(c->quic, frame);

    return NGX_OK;
}


static void
ngx_quic_queue_frame(ngx_quic_connection_t *qc, ngx_quic_frame_t *frame)
{
    ngx_quic_frame_t *f;

    if (qc->frames == NULL) {
        qc->frames = frame;
        return;
    }

    for (f = qc->frames; f->next; f = f->next) {
        if (f->next->level > frame->level) {
            break;
        }
    }

    frame->next = f->next;
    f->next = frame;
}


static ngx_int_t
ngx_quic_output(ngx_connection_t *c)
{
    size_t                  len;
    ngx_uint_t              lvl;
    ngx_quic_frame_t       *f, *start;
    ngx_quic_connection_t  *qc;

    qc = c->quic;

    if (qc->frames == NULL) {
        return NGX_OK;
    }

    lvl = qc->frames->level;
    start = qc->frames;
    f = start;

    do {
        len = 0;

        do {
            /* process same-level group of frames */

            len += ngx_quic_create_frame(NULL, NULL, f);// TODO: handle overflow, max size

            f = f->next;
        } while (f && f->level == lvl);


        if (ngx_quic_frames_send(c, start, f, len) != NGX_OK) {
            return NGX_ERROR;
        }

        if (f == NULL) {
            break;
        }

        lvl = f->level; // TODO: must not decrease (ever, also between calls)
        start = f;

    } while (1);

    qc->frames = NULL;

    return NGX_OK;
}


/* pack a group of frames [start; end) into memory p and send as single packet */
ngx_int_t
ngx_quic_frames_send(ngx_connection_t *c, ngx_quic_frame_t *start,
    ngx_quic_frame_t *end, size_t total)
{
    ssize_t            len;
    u_char            *p;
    ngx_str_t          out;
    ngx_quic_frame_t  *f;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sending frames %p...%p", start, end);

    p = ngx_pnalloc(c->pool, total);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out.data = p;

    for (f = start; f != end; f = f->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "frame: %s", f->info);

        len = ngx_quic_create_frame(p, p + total, f);
        if (len == -1) {
            return NGX_ERROR;
        }

        p += len;
    }

    out.len = p - out.data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "packet ready: %ui bytes at level %d",
                   out.len, start->level);

    // IOVEC/sendmsg_chain ?
    if (ngx_quic_send_packet(c, c->quic, start->level, &out) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_send_packet(ngx_connection_t *c, ngx_quic_connection_t *qc,
    enum ssl_encryption_level_t level, ngx_str_t *payload)
{
    ngx_str_t         res;
    ngx_quic_header_t pkt;

    pkt.log = c->log;

    static ngx_str_t  initial_token = ngx_null_string;

    ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
    ngx_quic_hexdump0(c->log, "payload", payload->data, payload->len);

    pkt.level = level;
    pkt.dcid = qc->dcid;
    pkt.scid = qc->scid;

    if (level == ssl_encryption_initial) {
        pkt.number = &qc->initial_pn;
        pkt.flags = NGX_QUIC_PKT_INITIAL;
        pkt.secret = &qc->secrets.server.in;
        pkt.token = initial_token;

    } else if (level == ssl_encryption_handshake) {
        pkt.number = &qc->handshake_pn;
        pkt.flags = NGX_QUIC_PKT_HANDSHAKE;
        pkt.secret = &qc->secrets.server.hs;

    } else {
        pkt.number = &qc->appdata_pn;
        pkt.secret = &qc->secrets.server.ad;
    }

    if (ngx_quic_encrypt(c->pool, c->ssl->connection, &pkt, payload, &res)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_quic_hexdump0(c->log, "packet to send", res.data, res.len);

    c->send(c, res.data, res.len); // TODO: err handling

    (*pkt.number)++;

    return NGX_OK;
}


ngx_connection_t *
ngx_quic_create_uni_stream(ngx_connection_t *c)
{
    ngx_uint_t               id;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qs = c->qs;
    qc = qs->parent->quic;

    /*
     * A stream ID is a 62-bit integer that is unique for all streams
     * on a connection.
     *
     * 0x3  | Server-Initiated, Unidirectional
     */
    id = (qc->streams.id_counter << 2) | 0x3;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "creating server uni stream #%ui id %ui",
                   qc->streams.id_counter, id);

    qc->streams.id_counter++;

    sn = ngx_quic_create_stream(qs->parent, id);
    if (sn == NULL) {
        return NULL;
    }

    return sn->c;
}


static void
ngx_quic_rbtree_insert_stream(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_quic_stream_node_t   *qn, *qnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            qn = (ngx_quic_stream_node_t *) &node->color;
            qnt = (ngx_quic_stream_node_t *) &temp->color;

            if (qn->c < qnt->c) {
                p = &temp->left;
            } else {
                p = &temp->right;
            }
        }

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


static ngx_quic_stream_node_t *
ngx_quic_find_stream(ngx_rbtree_t *rbtree, ngx_uint_t key)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (key == node->key) {
            return (ngx_quic_stream_node_t *) node;
        }

        node = (key < node->key) ? node->left : node->right;
    }

    return NULL;
}


static ngx_quic_stream_node_t *
ngx_quic_create_stream(ngx_connection_t *c, ngx_uint_t id)
{
    ngx_log_t               *log;
    ngx_pool_t              *pool;
    ngx_event_t             *rev, *wev;
    ngx_pool_cleanup_t      *cln;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qc = c->quic;

    sn = ngx_pcalloc(c->pool, sizeof(ngx_quic_stream_node_t));
    if (sn == NULL) {
        return NULL;
    }

    sn->c = ngx_get_connection(-1, c->log); // TODO: free on connection termination
    if (sn->c == NULL) {
        return NULL;
    }

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, c->log);
    if (pool == NULL) {
        /* XXX free connection */
        // TODO: add pool cleanup handdler
        return NULL;
    }

    log = ngx_palloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        /* XXX free pool and connection */
        return NULL;
    }

    *log = *c->log;
    pool->log = log;

    sn->c->log = log;
    sn->c->pool = pool;

    sn->c->listening = c->listening;
    sn->c->sockaddr = c->sockaddr;
    sn->c->local_sockaddr = c->local_sockaddr;
    sn->c->addr_text = c->addr_text;

    rev = sn->c->read;
    wev = sn->c->write;

    rev->ready = 1;

    rev->log = c->log;
    wev->log = c->log;

    sn->c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    sn->node.key =id;
    sn->b = ngx_create_temp_buf(pool, 16 * 1024); // XXX enough for everyone
    if (sn->b == NULL) {
        return NULL;
    }

    ngx_rbtree_insert(&qc->streams.tree, &sn->node);

    sn->s.id = id;
    sn->s.unidirectional = (sn->s.id & 0x02) ? 1 : 0;
    sn->s.parent = c;
    sn->c->qs = &sn->s;

    sn->c->recv = ngx_quic_stream_recv;
    sn->c->send = ngx_quic_stream_send;
    sn->c->send_chain = ngx_quic_stream_send_chain;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        ngx_close_connection(sn->c);
        ngx_destroy_pool(pool);
        return NULL;
    }

    cln->handler = ngx_quic_stream_cleanup_handler;
    cln->data = sn->c;

    return sn;
}


static ssize_t
ngx_quic_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                  len;
    ngx_buf_t               *b;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    qs = c->qs;
    qc = qs->parent->quic;

    // XXX: get direct pointer from stream structure?
    sn = ngx_quic_find_stream(&qc->streams.tree, qs->id);

    if (sn == NULL) {
        return NGX_ERROR;
    }

    // XXX: how to return EOF?

    b = sn->b;

    if (b->last - b->pos == 0) {
        c->read->ready = 0;
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic recv() not ready");
        return NGX_AGAIN; // ?
    }

    len = ngx_min(b->last - b->pos, (ssize_t) size);

    ngx_memcpy(buf, b->pos, len);

    b->pos += len;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "quic recv: %z of %uz", len, size);

    return len;
}


static ssize_t
ngx_quic_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    u_char                  *p;
    ngx_connection_t        *pc;
    ngx_quic_frame_t        *frame;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic send: %uz", size);

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    // XXX: get direct pointer from stream structure?
    sn = ngx_quic_find_stream(&qc->streams.tree, qs->id);

    if (sn == NULL) {
        return NGX_ERROR;
    }

    frame = ngx_pcalloc(pc->pool, sizeof(ngx_quic_frame_t));
    if (frame == NULL) {
        return 0;
    }

    p = ngx_pnalloc(pc->pool, size);
    if (p == NULL) {
        return 0;
    }

    ngx_memcpy(p, buf, size);

    frame->level = ssl_encryption_application;
    frame->type = NGX_QUIC_FT_STREAM6; /* OFF=1 LEN=1 FIN=0 */
    frame->u.stream.off = 1;
    frame->u.stream.len = 1;
    frame->u.stream.fin = 0;

    frame->u.stream.type = frame->type;
    frame->u.stream.stream_id = qs->id;
    frame->u.stream.offset = c->sent;
    frame->u.stream.length = size;
    frame->u.stream.data = p;

    c->sent += size;

    ngx_sprintf(frame->info, "stream %xi len=%ui level=%d",
                qs->id, size, frame->level);

    ngx_quic_queue_frame(qc, frame);

    return size;
}


static void
ngx_quic_stream_cleanup_handler(void *data)
{
    ngx_connection_t *c = data;

    ngx_connection_t        *pc;
    ngx_quic_frame_t        *frame;
    ngx_quic_stream_t       *qs;
    ngx_quic_connection_t   *qc;
    ngx_quic_stream_node_t  *sn;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic send fin");

    qs = c->qs;
    pc = qs->parent;
    qc = pc->quic;

    if ((qs->id & 0x03) == 0x02) {
        /* do not send fin for client unidirectional streams */
        return;
    }

    // XXX: get direct pointer from stream structure?
    sn = ngx_quic_find_stream(&qc->streams.tree, qs->id);

    if (sn == NULL) {
        return;
    }

    frame = ngx_pcalloc(pc->pool, sizeof(ngx_quic_frame_t));
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

    ngx_sprintf(frame->info, "stream %xi fin=1 level=%d", qs->id, frame->level);

    ngx_quic_queue_frame(qc, frame);
}


static ngx_chain_t *
ngx_quic_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    size_t      len;
    ssize_t     n;
    ngx_buf_t  *b;

    for ( /* void */; in; in = in->next) {
        b = in->buf;

        if (!ngx_buf_in_memory(b)) {
            continue;
        }

        if (ngx_buf_size(b) == 0) {
            continue;
        }

        len = b->last - b->pos;

        n = ngx_quic_stream_send(c, b->pos, len);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            return in;
        }

        if (n != (ssize_t) len) {
            b->pos += n;
            return in;
        }
    }

    return NULL;
}
