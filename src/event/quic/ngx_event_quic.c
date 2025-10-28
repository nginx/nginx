
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


static ngx_quic_connection_t *ngx_quic_new_connection(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_stateless_reset(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static void ngx_quic_read_handler(ngx_event_t *rev);
static void ngx_quic_write_handler(ngx_event_t *wev);
static void ngx_quic_close_handler(ngx_event_t *ev);

static ngx_int_t ngx_quic_handle_packet(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_payload(ngx_connection_t *c,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_check_csid(ngx_quic_connection_t *qc,
    ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_handle_frames(ngx_connection_t *c,
    ngx_quic_header_t *pkt);

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
        p = ngx_slprintf(p, last, "%s", qc->lingering ? " lingering" : "");
        p = ngx_slprintf(p, last, "%s", qc->closing ? " closing" : "");
        p = ngx_slprintf(p, last, "%s", qc->draining ? " draining" : "");
        p = ngx_slprintf(p, last, "%s", qc->key_phase ? " kp" : "");

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


ngx_int_t
ngx_quic_apply_transport_params(ngx_connection_t *c, ngx_quic_tp_t *ctp)
{
    ngx_str_t               scid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    scid.data = qc->path->cid->id;
    scid.len = qc->path->cid->len;

    if (scid.len != ctp->initial_scid.len
        || ngx_memcmp(scid.data, ctp->initial_scid.data, scid.len) != 0)
    {
        qc->error = NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
        qc->error_reason = "invalid initial_source_connection_id";

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

    if (ctp->max_ack_delay >= 16384) {
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

    qc->streams.local_max_streams_bidi = ctp->initial_max_streams_bidi;
    qc->streams.local_max_streams_uni = ctp->initial_max_streams_uni;

    ngx_memcpy(&qc->ctp, ctp, sizeof(ngx_quic_tp_t));

    return NGX_OK;
}


ngx_int_t
ngx_quic_create_connection(ngx_quic_conf_t *conf, ngx_connection_t *c,
    ngx_uint_t flags)
{
    ngx_quic_t             *quic;
    ngx_quic_connection_t  *qc;

    qc = ngx_pcalloc(c->pool, sizeof(ngx_quic_connection_t));
    if (qc == NULL) {
        return NGX_ERROR;
    }

    qc->conf = conf;
    qc->is_server = (flags & NGX_SSL_CLIENT) ? 0 : 1;

    quic = ngx_palloc(c->pool, sizeof(ngx_quic_t));
    if (quic == NULL) {
        return NGX_ERROR;
    }

    quic->connection = qc;
    quic->stream = NULL;

    c->quic = quic;
    c->start_time = ngx_current_msec;

    if (qc->is_server) {
        /* initialize server during handshake to save resources */
        return NGX_OK;
    }

    if (ngx_quic_new_connection(c, NULL) == NULL) {
        return NGX_ERROR;
    }

    return ngx_quic_init_connection(c, flags);
}


ngx_int_t
ngx_quic_handshake(ngx_connection_t *c)
{
    ngx_int_t               rc;
    ngx_quic_connection_t  *qc;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic handshake");

    if (c->buffer) {
        rc = ngx_quic_handle_datagram(c, c->buffer);

    } else {
        rc = ngx_quic_do_handshake(c);
    }

    if (rc != NGX_OK) {
        if (c->ssl) {
            c->ssl->no_wait_shutdown = 1;
        }

        return NGX_ERROR;
    }

    /* quic connection is now initialized */
    qc = ngx_quic_get_connection(c);

    ngx_add_timer(&qc->close, qc->tp.max_idle_timeout);

    ngx_quic_connstate_dbg(c);

    c->read->handler = ngx_quic_read_handler;
    c->write->handler = ngx_quic_write_handler;

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return c->ssl->handshaked ? NGX_OK : NGX_AGAIN;
}


static ngx_quic_connection_t *
ngx_quic_new_connection(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_str_t              *secret, scid;
    ngx_uint_t              i;
    ngx_quic_tp_t          *ctp;
    ngx_quic_conf_t        *conf;
    ngx_quic_connection_t  *qc;
    u_char                  scid_buf[NGX_QUIC_SERVER_CID_LEN];

    qc = c->quic->connection;
    conf = qc->conf;

    qc->keys = ngx_pcalloc(c->pool, sizeof(ngx_quic_keys_t));
    if (qc->keys == NULL) {
        return NULL;
    }

    if (ngx_quic_init_transport_params(&qc->tp, conf) != NGX_OK) {
        return NULL;
    }

    if (pkt == NULL) {
        /* client */

        if (RAND_bytes(scid_buf, NGX_QUIC_SERVER_CID_LEN) != 1) {
            return NULL;
        }

        scid.data = scid_buf;
        scid.len = NGX_QUIC_SERVER_CID_LEN;
        secret = &scid;

        qc->validated = 1;
        qc->version = 0x01;

    } else {
        secret = &pkt->dcid;
        scid = pkt->scid;

        qc->validated = pkt->validated;
        qc->version = pkt->version;

        if (pkt->validated && pkt->retried) {
            qc->tp.retry_scid.len = pkt->dcid.len;
            qc->tp.retry_scid.data = ngx_pstrdup(c->pool, &pkt->dcid);
            if (qc->tp.retry_scid.data == NULL) {
                return NULL;
            }
        }

        qc->tp.original_dcid.len = pkt->odcid.len;
        qc->tp.original_dcid.data = ngx_pstrdup(c->pool, &pkt->odcid);
        if (qc->tp.original_dcid.data == NULL) {
            return NULL;
        }
    }

    ngx_rbtree_init(&qc->streams.tree, &qc->streams.sentinel,
                    ngx_quic_rbtree_insert_stream);

    for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
        ngx_queue_init(&qc->send_ctx[i].frames);
        ngx_queue_init(&qc->send_ctx[i].sending);
        ngx_queue_init(&qc->send_ctx[i].sent);
        qc->send_ctx[i].largest_pn = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_ack = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].largest_range = NGX_QUIC_UNSET_PN;
        qc->send_ctx[i].pending_ack = NGX_QUIC_UNSET_PN;
    }

    qc->send_ctx[0].level = NGX_QUIC_ENCRYPTION_INITIAL;
    qc->send_ctx[1].level = NGX_QUIC_ENCRYPTION_HANDSHAKE;
    qc->send_ctx[2].level = NGX_QUIC_ENCRYPTION_APPLICATION;

    ngx_queue_init(&qc->free_frames);

    ngx_quic_init_rtt(qc);

    qc->pto.log = ngx_cycle->log;
    qc->pto.data = c;
    qc->pto.handler = ngx_quic_pto_handler;

    qc->push.log = ngx_cycle->log;
    qc->push.data = c;
    qc->push.handler = ngx_quic_push_handler;

    qc->close.log = ngx_cycle->log;
    qc->close.data = c;
    qc->close.handler = ngx_quic_close_handler;

    qc->path_validation.log = ngx_cycle->log;
    qc->path_validation.data = c;
    qc->path_validation.handler = ngx_quic_path_handler;

    qc->key_update.log = ngx_cycle->log;
    qc->key_update.data = c;
    qc->key_update.handler = ngx_quic_keys_update;

    qc->conf = conf;

    ctp = &qc->ctp;

    /* defaults to be used before actual client parameters are received */
    ctp->max_udp_payload_size = NGX_QUIC_MAX_UDP_PAYLOAD_SIZE;
    ctp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    ctp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
    ctp->active_connection_id_limit = 2;

    ngx_queue_init(&qc->streams.uninitialized);
    ngx_queue_init(&qc->streams.free);

    qc->streams.recv_max_data = qc->tp.initial_max_data;
    qc->streams.recv_window = qc->streams.recv_max_data;

    qc->streams.remote_max_streams_uni = qc->tp.initial_max_streams_uni;
    qc->streams.remote_max_streams_bidi = qc->tp.initial_max_streams_bidi;

    qc->congestion.window = ngx_min(10 * NGX_QUIC_MIN_INITIAL_SIZE,
                                    ngx_max(2 * NGX_QUIC_MIN_INITIAL_SIZE,
                                            14720));
    qc->congestion.ssthresh = (size_t) -1;
    qc->congestion.mtu = NGX_QUIC_MIN_INITIAL_SIZE;
    qc->congestion.recovery_start = ngx_current_msec - 1;

    qc->max_frames = (conf->max_concurrent_streams_uni
                      + conf->max_concurrent_streams_bidi)
                     * conf->stream_buffer_size / 2000;

    if (ngx_quic_keys_set_initial_secret(qc->keys, secret, qc->is_server,
                                         c->log)
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_quic_open_sockets(c, qc, &scid, pkt ? &pkt->dcid : NULL) != NGX_OK)
    {
        ngx_quic_keys_cleanup(qc->keys);
        return NULL;
    }

    if (qc->validated) {
        qc->path->validated = 1;
    }

    c->idle = 1;

    qc->initialized = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic connection created");

    return qc;
}


static ngx_int_t
ngx_quic_handle_stateless_reset(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    u_char                 *tail, ch;
    ngx_uint_t              i;
    ngx_queue_t            *q;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    /* A stateless reset uses an entire UDP datagram */
    if (!pkt->first) {
        return NGX_DECLINED;
    }

    tail = pkt->raw->last - NGX_QUIC_SR_TOKEN_LEN;

    for (q = ngx_queue_head(&qc->client_ids);
         q != ngx_queue_sentinel(&qc->client_ids);
         q = ngx_queue_next(q))
    {
        cid = ngx_queue_data(q, ngx_quic_client_id_t, queue);

        if (cid->seqnum == 0 || !cid->used) {
            /*
             * No stateless reset token in initial connection id.
             * Don't accept a token from an unused connection id.
             */
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


static void
ngx_quic_read_handler(ngx_event_t *rev)
{
    ssize_t            n;
    ngx_buf_t          buf;
    ngx_connection_t  *c;
    static u_char      buffer[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0, "quic read handler");

    c = rev->data;

    c->log->action = "handling quic input";

    while (rev->ready) {
        n = c->recv(c, buffer, sizeof(buffer));

        if (n <= 0) {
            break;
        }

        ngx_memzero(&buf, sizeof(ngx_buf_t));

        buf.pos = buffer;
        buf.last = buffer + n;
        buf.start = buf.pos;
        buf.end = buffer + sizeof(buffer);

        if (ngx_quic_handle_datagram(c, &buf) == NGX_ERROR) {
            ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR,
                               "datagram handling error");
            break;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR, "socket error");
    }

    ngx_quic_end_handler(c);
}


static void
ngx_quic_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic write handler");

    ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
}


void
ngx_quic_end_handler(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    ngx_quic_connstate_dbg(c);

    if (c->ssl == NULL || c->ssl->handler == NULL) {
        return;
    }

    qc = ngx_quic_get_connection(c);

    if (!c->ssl->handshaked && qc->error == 0) {
        return;
    }

    c->ssl->handler(c);
}


ngx_int_t
ngx_quic_shutdown(ngx_connection_t *c)
{
    ngx_uint_t              i, no_wait;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    if (c->quic->stream) {
        /* QUIC stream */
        return NGX_OK;
    }

    qc = ngx_quic_get_connection(c);

    if (!qc->initialized) {
        goto quic_done;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic close %s",
                   qc->lingering || qc->closing ? "resumed": "initiated");

    no_wait = (c->ssl == NULL || c->ssl->no_wait_shutdown) ? 1 : 0;

    if (!no_wait && !qc->closing) {
        if (ngx_quic_linger_streams(c) == NGX_AGAIN) {

            if (!qc->lingering) {
                ngx_add_timer(&qc->close, 3000);
                qc->lingering = 1;
            }

            return NGX_AGAIN;
        }
    }

    if (!qc->closing) {

        /* drop packets from retransmit queues, no ack is expected */
        for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
            ngx_quic_free_frames(c, &qc->send_ctx[i].frames);
            ngx_quic_free_frames(c, &qc->send_ctx[i].sent);
        }

        if (qc->close.timer_set) {
            ngx_del_timer(&qc->close);
        }

        if (qc->error == NGX_QUIC_ERR_CLOSE) {

            /*
             * RFC 9000, 10.1.  Idle Timeout
             *
             *  If a max_idle_timeout is specified by either endpoint in its
             *  transport parameters (Section 18.2), the connection is silently
             *  closed and its state is discarded when it remains idle
             */

            /* this case also handles some errors from ngx_quic_handshake() */

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close silent drain:%d timedout:%d",
                           qc->draining, c->read->timedout);
        } else {

            /*
             * RFC 9000, 10.2.  Immediate Close
             *
             *  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
             *  to terminate the connection immediately.
             */

            if (qc->error == 0) {
                ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR,
                                   "internal error");
            }

            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic close immediate term:%ui drain:%d "
                           "%serror:%ui \"%s\"",
                           no_wait, qc->draining,
                           qc->error_app ? "app " : "", qc->error,
                           qc->error_reason ? qc->error_reason : "");

            for (i = 0; i < NGX_QUIC_SEND_CTX_LAST; i++) {
                ctx = &qc->send_ctx[i];

                if (!ngx_quic_keys_available(qc->keys, ctx->level, 1)) {
                    continue;
                }

                qc->error_level = ctx->level;
                (void) ngx_quic_send_cc(c);

                if (!no_wait) {
                    ngx_add_timer(&qc->close, 3 * ngx_quic_pto(c, ctx));
                }
            }
        }

        qc->lingering = 0;
        qc->closing = 1;
    }

    if (no_wait && qc->close.timer_set) {
        ngx_del_timer(&qc->close);
    }

    if (ngx_quic_close_streams(c) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (qc->push.timer_set) {
        ngx_del_timer(&qc->push);
    }

    if (qc->pto.timer_set) {
        ngx_del_timer(&qc->pto);
    }

    if (qc->path_validation.timer_set) {
        ngx_del_timer(&qc->path_validation);
    }

    if (qc->push.posted) {
        ngx_delete_posted_event(&qc->push);
    }

    if (qc->key_update.posted) {
        ngx_delete_posted_event(&qc->key_update);
    }

    if (qc->close.timer_set) {
        return NGX_AGAIN;
    }

    if (qc->close.posted) {
        ngx_delete_posted_event(&qc->close);
    }

    ngx_quic_close_sockets(c);

    ngx_quic_keys_cleanup(qc->keys);

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic close completed");

    /* may be tested from SSL callback during SSL shutdown */
    c->udp = NULL;

quic_done:

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        (void) ngx_ssl_shutdown(c);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    return NGX_OK;
}


void
ngx_quic_set_error(ngx_connection_t *c, ngx_uint_t err, const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->error) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic error %ui \"%s\"",
                   err, reason);

    qc->error = err;
    qc->error_reason = reason;
    qc->error_ftype = 0;
}


void
ngx_quic_set_app_error(ngx_connection_t *c, ngx_uint_t err, const char *reason)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (qc->error) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic app error %ui \"%s\"",
                   err, reason);

    qc->error = err;
    qc->error_reason = reason;
    qc->error_app = 1;
    qc->error_ftype = 0;
}


ngx_uint_t
ngx_quic_get_error(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    return qc->error;
}


void
ngx_quic_reject_streams(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->shutdown = 1;
}


static void
ngx_quic_close_handler(ngx_event_t *ev)
{
    ngx_connection_t       *c;
    ngx_quic_connection_t  *qc;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic close handler");

    if (ev->timedout) {
        ev->timedout = 0;
        ngx_quic_set_error(c, NGX_QUIC_ERR_CLOSE, "");

        qc = ngx_quic_get_connection(c);
        if (qc->lingering) {
            c->ssl->no_wait_shutdown = 1;
        }
    }

    ngx_quic_end_handler(c);
}


ngx_int_t
ngx_quic_handle_datagram(ngx_connection_t *c, ngx_buf_t *b)
{
    size_t                  size;
    u_char                 *p, *start;
    ngx_int_t               rc;
    ngx_uint_t              good;
    ngx_quic_path_t        *path;
    ngx_quic_header_t       pkt;
    ngx_quic_connection_t  *qc;

    good = 0;
    path = NULL;

    size = b->last - b->pos;
    p = start = b->pos;

    qc = ngx_quic_get_connection(c);
    qc->received += size;

    while (p < b->last) {

        ngx_memzero(&pkt, sizeof(ngx_quic_header_t));
        pkt.raw = b;
        pkt.data = p;
        pkt.len = b->last - p;
        pkt.log = c->log;
        pkt.first = (p == start) ? 1 : 0;
        pkt.path = path;
        pkt.flags = p[0];
        pkt.raw->pos++;

        rc = ngx_quic_handle_packet(c, &pkt);

#if (NGX_DEBUG)
        if (pkt.parsed) {
            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done rc:%i level:%s"
                           " decr:%d pn:%L perr:%ui",
                           rc, ngx_quic_level_name(pkt.level),
                           pkt.decrypted, pkt.pn, pkt.error);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "quic packet done rc:%i parse failed", rc);
        }
#endif

        if (rc == NGX_ERROR || rc == NGX_DONE) {
            return rc;
        }

        if (rc == NGX_OK) {
            good = 1;
        }

        path = pkt.path; /* preserve packet path from 1st packet */

        /* NGX_OK || NGX_DECLINED */

        /*
         * we get NGX_DECLINED when there are no keys [yet] available
         * to decrypt packet.
         * Instead of queueing it, we ignore it and rely on the sender's
         * retransmission:
         *
         * RFC 9000, 12.2.  Coalescing Packets
         *
         * For example, if decryption fails (because the keys are
         * not available or for any other reason), the receiver MAY either
         * discard or buffer the packet for later processing and MUST
         * attempt to process the remaining packets.
         *
         * We also skip packets that don't match connection state
         * or cannot be parsed properly.
         */

        /* b->pos is at header end, adjust by actual packet length */
        b->pos = pkt.data + pkt.len;

        p = b->pos;
    }

    if (!good) {
        return NGX_DONE;
    }

    if ((uint64_t) (c->sent + qc->received) / 8 >
        (qc->streams.sent + qc->streams.recv_last) + 1048576)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "quic flood detected");

        qc->error = NGX_QUIC_ERR_INTERNAL_ERROR;
        qc->error_reason = "QUIC flood detected";
        return NGX_ERROR;
    }

    qc->send_timer_set = 0;
    ngx_add_timer(&qc->close, qc->tp.max_idle_timeout);

    return NGX_OK;
}


static ngx_int_t
ngx_quic_handle_packet(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_conf_t        *conf;
    ngx_quic_socket_t      *qsock;
    ngx_quic_client_id_t   *cid;
    ngx_quic_connection_t  *qc;

    c->log->action = "parsing quic packet";

    rc = ngx_quic_parse_packet(pkt);

    if (rc == NGX_ERROR) {
        return NGX_DECLINED;
    }

    pkt->parsed = 1;

    c->log->action = "handling quic packet";

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "quic packet rx dcid len:%uz %xV",
                   pkt->dcid.len, &pkt->dcid);

#if (NGX_DEBUG)
    if (pkt->level != NGX_QUIC_ENCRYPTION_APPLICATION) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic packet rx scid len:%uz %xV",
                       pkt->scid.len, &pkt->scid);
    }

    if (pkt->level == NGX_QUIC_ENCRYPTION_INITIAL) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic address validation token len:%uz %xV",
                       pkt->token.len, &pkt->token);
    }
#endif

    qc = ngx_quic_get_connection(c);

    if (qc->initialized) {

        if (rc == NGX_ABORT) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "quic unsupported version: 0x%xD", pkt->version);
            return NGX_DECLINED;
        }

        if (pkt->level != NGX_QUIC_ENCRYPTION_APPLICATION) {

            if (pkt->version != qc->version) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic version mismatch: 0x%xD", pkt->version);
                return NGX_DECLINED;
            }

            if (pkt->first) {
                qsock = ngx_quic_get_socket(c);

                if (ngx_cmp_sockaddr(&qsock->sockaddr.sockaddr, qsock->socklen,
                                     qc->path->sockaddr, qc->path->socklen, 1)
                    != NGX_OK)
                {
                    /* packet comes from unknown path, possibly migration */
                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                   "quic too early migration attempt");
                    return NGX_DONE;
                }
            }

            if (qc->is_server) {
                if (ngx_quic_check_csid(qc, pkt) != NGX_OK) {
                    return NGX_DECLINED;
                }
            }
        }

        rc = ngx_quic_handle_payload(c, pkt);

        if (rc == NGX_OK
            && !qc->is_server
            && !qc->scid_set
            && pkt->level == NGX_QUIC_ENCRYPTION_INITIAL)
        {
            /* RFC 9000, 7.2. Negotiating Connection IDs
             *
             * After processing the first Initial packet, each endpoint sets
             * the Destination Connection ID field in subsequent packets it
             * sends to the value of the Source Connection ID field that it
             * received.
             */

            qc->scid_set = 1;

            cid = qc->path->cid;
            ngx_memcpy(cid->id, pkt->scid.data, pkt->scid.len);
            cid->len = pkt->scid.len;
        }

        if (rc == NGX_DECLINED
            && pkt->level == NGX_QUIC_ENCRYPTION_APPLICATION)
        {
            if (ngx_quic_handle_stateless_reset(c, pkt) == NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "quic stateless reset packet detected");

                qc->draining = 1;
                qc->error = NGX_QUIC_ERR_CLOSE;

                return NGX_OK;
            }
        }

        return rc;
    }

    /* connection has not been initialized yet */

    conf = c->quic->connection->conf;

    if (rc == NGX_ABORT) {
        return ngx_quic_negotiate_version(c, pkt);
    }

    if (pkt->level == NGX_QUIC_ENCRYPTION_APPLICATION) {
        return ngx_quic_send_stateless_reset(c, conf, pkt);
    }

    if (pkt->level != NGX_QUIC_ENCRYPTION_INITIAL) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "quic expected initial, got handshake");
        return NGX_ERROR;
    }

    c->log->action = "handling initial packet";

    if (pkt->dcid.len < NGX_QUIC_CID_LEN_MIN) {
        /* RFC 9000, 7.2.  Negotiating Connection IDs */
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

    qc = ngx_quic_new_connection(c, pkt);
    if (qc == NULL) {
        return NGX_ERROR;
    }

    return ngx_quic_handle_payload(c, pkt);
}


static ngx_int_t
ngx_quic_handle_payload(ngx_connection_t *c, ngx_quic_header_t *pkt)
{
    ngx_int_t               rc;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;
    static u_char           buf[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

    qc = ngx_quic_get_connection(c);

    c->log->action = "decrypting packet";

    if (!ngx_quic_keys_available(qc->keys, pkt->level, 0)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no %s keys, ignoring packet",
                      ngx_quic_level_name(pkt->level));
        return NGX_DECLINED;
    }

#if (NGX_QUIC_QUICTLS_API)
    /* QuicTLS provides app read keys before completing handshake */

    if (pkt->level == NGX_QUIC_ENCRYPTION_APPLICATION && !c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "quic no %s keys ready, ignoring packet",
                      ngx_quic_level_name(pkt->level));
        return NGX_DECLINED;
    }
#endif

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

    c->log->action = "handling decrypted packet";

    if (pkt->path == NULL) {
        rc = ngx_quic_set_path(c, pkt);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (c->ssl == NULL) {
        if (ngx_quic_init_connection(c, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (pkt->level == NGX_QUIC_ENCRYPTION_HANDSHAKE) {
        /*
         * RFC 9001, 4.9.1.  Discarding Initial Keys
         *
         * The successful use of Handshake packets indicates
         * that no more Initial packets need to be exchanged
         */
        ngx_quic_discard_ctx(c, NGX_QUIC_ENCRYPTION_INITIAL);

        if (!qc->path->validated) {
            qc->path->validated = 1;
            ngx_quic_path_dbg(c, "in handshake", qc->path);
            ngx_post_event(&qc->push, &ngx_posted_events);
        }
    }

    if (pkt->level == NGX_QUIC_ENCRYPTION_APPLICATION) {
        /*
         * RFC 9001, 4.9.3.  Discarding 0-RTT Keys
         *
         * After receiving a 1-RTT packet, servers MUST discard
         * 0-RTT keys within a short time
         */
        ngx_quic_keys_discard(qc->keys, NGX_QUIC_ENCRYPTION_EARLY_DATA);
    }

    if (qc->closing) {
        /*
         * RFC 9000, 10.2.  Immediate Close
         *
         * ... delayed or reordered packets are properly discarded.
         *
         *  In the closing state, an endpoint retains only enough information
         *  to generate a packet containing a CONNECTION_CLOSE frame and to
         *  identify packets as belonging to the connection.
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

    if (pkt->level != NGX_QUIC_ENCRYPTION_APPLICATION) {
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

    ngx_post_event(&qc->key_update, &ngx_posted_events);

    return NGX_OK;
}


void
ngx_quic_discard_ctx(ngx_connection_t *c, ngx_uint_t level)
{
    ngx_queue_t            *q;
    ngx_quic_frame_t       *f;
    ngx_quic_socket_t      *qsock;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    if (!ngx_quic_keys_available(qc->keys, level, 0)
        && !ngx_quic_keys_available(qc->keys, level, 1))
    {
        return;
    }

    ngx_quic_keys_discard(qc->keys, level);

    qc->pto_count = 0;

    ctx = ngx_quic_get_send_ctx(qc, level);

    ngx_quic_free_buffer(c, &ctx->crypto);

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
        ngx_quic_free_frame(c, f);
    }

    if (level == NGX_QUIC_ENCRYPTION_INITIAL) {
        /* close temporary listener with initial dcid */
        qsock = ngx_quic_find_socket(c, NGX_QUIC_UNSET_PN);
        if (qsock) {
            ngx_quic_close_socket(c, qsock);
        }
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
    ngx_uint_t              do_close, nonprobing;
    ngx_chain_t             chain;
    ngx_quic_frame_t        frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    p = pkt->payload.data;
    end = p + pkt->payload.len;

    do_close = 0;
    nonprobing = 0;

    while (p < end) {

        c->log->action = "parsing frames";

        ngx_memzero(&frame, sizeof(ngx_quic_frame_t));
        ngx_memzero(&buf, sizeof(ngx_buf_t));
        buf.temporary = 1;

        chain.buf = &buf;
        chain.next = NULL;
        frame.data = &chain;

        len = ngx_quic_parse_frame(pkt, p, end, &frame, qc->is_server);

        if (len < 0) {
            qc->error = pkt->error;
            return NGX_ERROR;
        }

        ngx_quic_log_frame(c->log, &frame, 0);

        c->log->action = "handling frames";

        p += len;

        switch (frame.type) {
        /* probing frames */
        case NGX_QUIC_FT_PADDING:
        case NGX_QUIC_FT_PATH_CHALLENGE:
        case NGX_QUIC_FT_PATH_RESPONSE:
        case NGX_QUIC_FT_NEW_CONNECTION_ID:
            break;

        /* non-probing frames */
        default:
            nonprobing = 1;
            break;
        }

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

        case NGX_QUIC_FT_NEW_TOKEN:

            if (ngx_quic_handle_new_token_frame(c, &frame) != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_STREAM:

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

        case NGX_QUIC_FT_DATA_BLOCKED:

            if (ngx_quic_handle_data_blocked_frame(c, pkt,
                                                   &frame.u.data_blocked)
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

            if (ngx_quic_handle_path_response_frame(c, &frame.u.path_response)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_NEW_CONNECTION_ID:

            if (ngx_quic_handle_new_connection_id_frame(c, &frame.u.ncid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

            if (ngx_quic_handle_retire_connection_id_frame(c,
                                                           &frame.u.retire_cid)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            break;

        case NGX_QUIC_FT_HANDSHAKE_DONE:

            if (ngx_quic_handle_handshake_done_frame(c) != NGX_OK) {
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
        qc->error = NGX_QUIC_ERR_CLOSE;
    }

    if (pkt->path != qc->path && nonprobing) {

        /*
         * RFC 9000, 9.2.  Initiating Connection Migration
         *
         * An endpoint can migrate a connection to a new local
         * address by sending packets containing non-probing frames
         * from that address.
         */
        if (ngx_quic_handle_migration(c, pkt) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_ack_packet(c, pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_quic_push_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "quic push handler");

    if (ngx_quic_output(c) != NGX_OK) {
        ngx_quic_set_error(c, NGX_QUIC_ERR_INTERNAL_ERROR, "output error");
    }

    ngx_quic_end_handler(c);
}
