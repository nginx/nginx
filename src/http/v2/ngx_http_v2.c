
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v2_module.h>


/* errors */
#define NGX_HTTP_V2_NO_ERROR                     0x0
#define NGX_HTTP_V2_PROTOCOL_ERROR               0x1
#define NGX_HTTP_V2_INTERNAL_ERROR               0x2
#define NGX_HTTP_V2_FLOW_CTRL_ERROR              0x3
#define NGX_HTTP_V2_SETTINGS_TIMEOUT             0x4
#define NGX_HTTP_V2_STREAM_CLOSED                0x5
#define NGX_HTTP_V2_SIZE_ERROR                   0x6
#define NGX_HTTP_V2_REFUSED_STREAM               0x7
#define NGX_HTTP_V2_CANCEL                       0x8
#define NGX_HTTP_V2_COMP_ERROR                   0x9
#define NGX_HTTP_V2_CONNECT_ERROR                0xa
#define NGX_HTTP_V2_ENHANCE_YOUR_CALM            0xb
#define NGX_HTTP_V2_INADEQUATE_SECURITY          0xc
#define NGX_HTTP_V2_HTTP_1_1_REQUIRED            0xd

/* frame sizes */
#define NGX_HTTP_V2_SETTINGS_ACK_SIZE            0
#define NGX_HTTP_V2_RST_STREAM_SIZE              4
#define NGX_HTTP_V2_PRIORITY_SIZE                5
#define NGX_HTTP_V2_PING_SIZE                    8
#define NGX_HTTP_V2_GOAWAY_SIZE                  8
#define NGX_HTTP_V2_WINDOW_UPDATE_SIZE           4

#define NGX_HTTP_V2_SETTINGS_PARAM_SIZE          6

/* settings fields */
#define NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING    0x1
#define NGX_HTTP_V2_ENABLE_PUSH_SETTING          0x2
#define NGX_HTTP_V2_MAX_STREAMS_SETTING          0x3
#define NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING     0x4
#define NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING       0x5

#define NGX_HTTP_V2_FRAME_BUFFER_SIZE            24

#define NGX_HTTP_V2_ROOT                         (void *) -1


static void ngx_http_v2_read_handler(ngx_event_t *rev);
static void ngx_http_v2_write_handler(ngx_event_t *wev);
static void ngx_http_v2_handle_connection(ngx_http_v2_connection_t *h2c);
static void ngx_http_v2_lingering_close(ngx_connection_t *c);
static void ngx_http_v2_lingering_close_handler(ngx_event_t *rev);

static u_char *ngx_http_v2_state_preface(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_preface_end(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_head(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_data(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_read_data(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_headers(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_header_block(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_field_len(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_field_huff(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_field_raw(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_field_skip(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_process_header(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_header_complete(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_handle_continuation(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
static u_char *ngx_http_v2_state_priority(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_rst_stream(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_settings(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_settings_params(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_push_promise(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_ping(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_goaway(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_window_update(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_continuation(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_complete(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_skip_padded(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_skip(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *ngx_http_v2_state_save(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
static u_char *ngx_http_v2_state_headers_save(ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
static u_char *ngx_http_v2_connection_error(ngx_http_v2_connection_t *h2c,
    ngx_uint_t err);

static ngx_int_t ngx_http_v2_parse_int(ngx_http_v2_connection_t *h2c,
    u_char **pos, u_char *end, ngx_uint_t prefix);

static ngx_http_v2_stream_t *ngx_http_v2_create_stream(
    ngx_http_v2_connection_t *h2c);
static ngx_http_v2_node_t *ngx_http_v2_get_node_by_id(
    ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_uint_t alloc);
static ngx_http_v2_node_t *ngx_http_v2_get_closed_node(
    ngx_http_v2_connection_t *h2c);
#define ngx_http_v2_index_size(h2scf)  (h2scf->streams_index_mask + 1)
#define ngx_http_v2_index(h2scf, sid)  ((sid >> 1) & h2scf->streams_index_mask)

static ngx_int_t ngx_http_v2_send_settings(ngx_http_v2_connection_t *h2c);
static ngx_int_t ngx_http_v2_settings_frame_handler(
    ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
static ngx_int_t ngx_http_v2_send_window_update(ngx_http_v2_connection_t *h2c,
    ngx_uint_t sid, size_t window);
static ngx_int_t ngx_http_v2_send_rst_stream(ngx_http_v2_connection_t *h2c,
    ngx_uint_t sid, ngx_uint_t status);
static ngx_int_t ngx_http_v2_send_goaway(ngx_http_v2_connection_t *h2c,
    ngx_uint_t status);

static ngx_http_v2_out_frame_t *ngx_http_v2_get_frame(
    ngx_http_v2_connection_t *h2c, size_t length, ngx_uint_t type,
    u_char flags, ngx_uint_t sid);
static ngx_int_t ngx_http_v2_frame_handler(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame);

static ngx_int_t ngx_http_v2_pseudo_header(ngx_http_request_t *r,
    ngx_http_v2_header_t *header);
static ngx_int_t ngx_http_v2_parse_path(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v2_parse_method(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v2_parse_scheme(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v2_parse_authority(ngx_http_request_t *r,
    ngx_str_t *value);
static ngx_int_t ngx_http_v2_construct_request_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_v2_cookie(ngx_http_request_t *r,
    ngx_http_v2_header_t *header);
static ngx_int_t ngx_http_v2_construct_cookie_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_v2_construct_host_header(ngx_http_request_t *r);
static void ngx_http_v2_run_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v2_process_request_body(ngx_http_request_t *r,
    u_char *pos, size_t size, ngx_uint_t last, ngx_uint_t flush);
static ngx_int_t ngx_http_v2_filter_request_body(ngx_http_request_t *r);
static void ngx_http_v2_read_client_request_body_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_v2_terminate_stream(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_stream_t *stream, ngx_uint_t status);
static void ngx_http_v2_close_stream_handler(ngx_event_t *ev);
static void ngx_http_v2_retry_close_stream_handler(ngx_event_t *ev);
static void ngx_http_v2_handle_connection_handler(ngx_event_t *rev);
static void ngx_http_v2_idle_handler(ngx_event_t *rev);
static void ngx_http_v2_finalize_connection(ngx_http_v2_connection_t *h2c,
    ngx_uint_t status);

static ngx_int_t ngx_http_v2_adjust_windows(ngx_http_v2_connection_t *h2c,
    ssize_t delta);
static void ngx_http_v2_set_dependency(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_node_t *node, ngx_uint_t depend, ngx_uint_t exclusive);
static void ngx_http_v2_node_children_update(ngx_http_v2_node_t *node);

static void ngx_http_v2_pool_cleanup(void *data);


static ngx_http_v2_handler_pt ngx_http_v2_frame_states[] = {
    ngx_http_v2_state_data,               /* NGX_HTTP_V2_DATA_FRAME */
    ngx_http_v2_state_headers,            /* NGX_HTTP_V2_HEADERS_FRAME */
    ngx_http_v2_state_priority,           /* NGX_HTTP_V2_PRIORITY_FRAME */
    ngx_http_v2_state_rst_stream,         /* NGX_HTTP_V2_RST_STREAM_FRAME */
    ngx_http_v2_state_settings,           /* NGX_HTTP_V2_SETTINGS_FRAME */
    ngx_http_v2_state_push_promise,       /* NGX_HTTP_V2_PUSH_PROMISE_FRAME */
    ngx_http_v2_state_ping,               /* NGX_HTTP_V2_PING_FRAME */
    ngx_http_v2_state_goaway,             /* NGX_HTTP_V2_GOAWAY_FRAME */
    ngx_http_v2_state_window_update,      /* NGX_HTTP_V2_WINDOW_UPDATE_FRAME */
    ngx_http_v2_state_continuation        /* NGX_HTTP_V2_CONTINUATION_FRAME */
};

#define NGX_HTTP_V2_FRAME_STATES                                              \
    (sizeof(ngx_http_v2_frame_states) / sizeof(ngx_http_v2_handler_pt))


void
ngx_http_v2_init(ngx_event_t *rev)
{
    u_char                    *p, *end;
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_http_connection_t     *hc;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_v2_main_conf_t   *h2mcf;
    ngx_http_v2_connection_t  *h2c;
    ngx_http_core_srv_conf_t  *cscf;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "init http2 connection");

    c->log->action = "processing HTTP/2 connection";

    h2mcf = ngx_http_get_module_main_conf(hc->conf_ctx, ngx_http_v2_module);

    if (h2mcf->recv_buffer == NULL) {
        h2mcf->recv_buffer = ngx_palloc(ngx_cycle->pool,
                                        h2mcf->recv_buffer_size);
        if (h2mcf->recv_buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    h2c = ngx_pcalloc(c->pool, sizeof(ngx_http_v2_connection_t));
    if (h2c == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    h2c->connection = c;
    h2c->http_connection = hc;

    h2c->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    h2c->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    h2c->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;

    h2c->frame_size = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;

    h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

    h2c->priority_limit = ngx_max(h2scf->concurrent_streams, 100);

    h2c->pool = ngx_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln->handler = ngx_http_v2_pool_cleanup;
    cln->data = h2c;

    h2c->streams_index = ngx_pcalloc(c->pool, ngx_http_v2_index_size(h2scf)
                                              * sizeof(ngx_http_v2_node_t *));
    if (h2c->streams_index == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    if (ngx_http_v2_send_settings(h2c) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    if (ngx_http_v2_send_window_update(h2c, 0, NGX_HTTP_V2_MAX_WINDOW
                                               - NGX_HTTP_V2_DEFAULT_WINDOW)
        == NGX_ERROR)
    {
        ngx_http_close_connection(c);
        return;
    }

    h2c->state.handler = ngx_http_v2_state_preface;

    ngx_queue_init(&h2c->waiting);
    ngx_queue_init(&h2c->dependencies);
    ngx_queue_init(&h2c->closed);

    c->data = h2c;

    if (ngx_exiting) {
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
        return;
    }

    rev->handler = ngx_http_v2_read_handler;
    c->write->handler = ngx_http_v2_write_handler;

    if (!rev->timer_set) {
        cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                            ngx_http_core_module);
        ngx_add_timer(rev, cscf->client_header_timeout);
    }

    c->idle = 1;
    ngx_reusable_connection(c, 0);

    if (c->buffer) {
        p = c->buffer->pos;
        end = c->buffer->last;

        do {
            p = h2c->state.handler(h2c, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

        h2c->total_bytes += p - c->buffer->pos;
        c->buffer->pos = p;
    }

    ngx_http_v2_read_handler(rev);
}


static void
ngx_http_v2_read_handler(ngx_event_t *rev)
{
    u_char                    *p, *end;
    size_t                     available;
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_http_v2_main_conf_t   *h2mcf;
    ngx_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 read handler");

    h2c->blocked = 1;
    h2c->new_streams = 0;

    if (c->close) {
        c->close = 0;

        if (c->error) {
            ngx_http_v2_finalize_connection(h2c, 0);
            return;
        }

        if (!h2c->processing) {
            ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
            return;
        }

        if (!h2c->goaway) {
            h2c->goaway = 1;

            if (ngx_http_v2_send_goaway(h2c, NGX_HTTP_V2_NO_ERROR)
                == NGX_ERROR)
            {
                ngx_http_v2_finalize_connection(h2c, 0);
                return;
            }

            if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
                ngx_http_v2_finalize_connection(h2c, 0);
                return;
            }
        }

        h2c->blocked = 0;

        return;
    }

    h2mcf = ngx_http_get_module_main_conf(h2c->http_connection->conf_ctx,
                                          ngx_http_v2_module);

    available = h2mcf->recv_buffer_size - NGX_HTTP_V2_STATE_BUFFER_SIZE;

    do {
        p = h2mcf->recv_buffer;
        end = ngx_cpymem(p, h2c->state.buffer, h2c->state.buffer_used);

        n = c->recv(c, end, available);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0 && (h2c->state.incomplete || h2c->processing)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        }

        if (n == 0 || n == NGX_ERROR) {
            c->error = 1;
            ngx_http_v2_finalize_connection(h2c, 0);
            return;
        }

        end += n;

        h2c->state.buffer_used = 0;
        h2c->state.incomplete = 0;

        do {
            p = h2c->state.handler(h2c, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

        h2c->total_bytes += n;

        if (h2c->total_bytes / 8 > h2c->payload_bytes + 1048576) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "http2 flood detected");
            ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    if (h2c->last_out && ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        ngx_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    ngx_http_v2_handle_connection(h2c);
}


static void
ngx_http_v2_write_handler(ngx_event_t *wev)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_v2_connection_t  *h2c;

    c = wev->data;
    h2c = c->data;

    if (wev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 write event timed out");
        c->error = 1;
        c->timedout = 1;
        ngx_http_v2_finalize_connection(h2c, 0);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 write handler");

    if (h2c->last_out == NULL && !c->buffered) {

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        ngx_http_v2_handle_connection(h2c);
        return;
    }

    h2c->blocked = 1;

    rc = ngx_http_v2_send_output_queue(h2c);

    if (rc == NGX_ERROR) {
        ngx_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_http_v2_handle_connection(h2c);
}


ngx_int_t
ngx_http_v2_send_output_queue(ngx_http_v2_connection_t *h2c)
{
    int                        tcp_nodelay;
    ngx_chain_t               *cl;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_v2_out_frame_t   *out, *frame, *fn;
    ngx_http_core_loc_conf_t  *clcf;

    c = h2c->connection;
    wev = c->write;

    if (c->error) {
        goto error;
    }

    if (!wev->ready) {
        return NGX_AGAIN;
    }

    cl = NULL;
    out = NULL;

    for (frame = h2c->last_out; frame; frame = fn) {
        frame->last->next = cl;
        cl = frame->first;

        fn = frame->next;
        frame->next = out;
        out = frame;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame out: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    cl = c->send_chain(c, cl, 0);

    if (cl == NGX_CHAIN_ERROR) {
        goto error;
    }

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        goto error;
    }

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            goto error;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
        goto error;
    }

    for ( /* void */ ; out; out = fn) {
        fn = out->next;

        if (out->handler(h2c, out) != NGX_OK) {
            out->blocked = 1;
            break;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame sent: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    frame = NULL;

    for ( /* void */ ; out; out = fn) {
        fn = out->next;
        out->next = frame;
        frame = out;
    }

    h2c->last_out = frame;

    if (!wev->ready) {
        ngx_add_timer(wev, clcf->send_timeout);
        return NGX_AGAIN;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    return NGX_OK;

error:

    c->error = 1;

    if (!h2c->blocked) {
        ngx_post_event(wev, &ngx_posted_events);
    }

    return NGX_ERROR;
}


static void
ngx_http_v2_handle_connection(ngx_http_v2_connection_t *h2c)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    if (h2c->last_out || h2c->processing) {
        return;
    }

    c = h2c->connection;

    if (c->error) {
        ngx_http_close_connection(c);
        return;
    }

    if (c->buffered) {
        h2c->blocked = 1;

        rc = ngx_http_v2_send_output_queue(h2c);

        h2c->blocked = 0;

        if (rc == NGX_ERROR) {
            ngx_http_close_connection(c);
            return;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        /* rc == NGX_OK */
    }

    if (h2c->goaway) {
        ngx_http_v2_lingering_close(c);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, clcf->keepalive_timeout);
    }

    ngx_reusable_connection(c, 1);

    if (h2c->state.incomplete) {
        return;
    }

    ngx_destroy_pool(h2c->pool);

    h2c->pool = NULL;
    h2c->free_frames = NULL;
    h2c->frames = 0;
    h2c->free_fake_connections = NULL;

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;

    c->write->handler = ngx_http_empty_handler;
    c->read->handler = ngx_http_v2_idle_handler;

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
}


static void
ngx_http_v2_lingering_close(ngx_connection_t *c)
{
    ngx_event_t               *rev, *wev;
    ngx_http_v2_connection_t  *h2c;
    ngx_http_core_loc_conf_t  *clcf;

    h2c = c->data;

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (clcf->lingering_close == NGX_HTTP_LINGERING_OFF) {
        ngx_http_close_connection(c);
        return;
    }

    if (h2c->lingering_time == 0) {
        h2c->lingering_time = ngx_time()
                              + (time_t) (clcf->lingering_time / 1000);
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_int_t  rc;

        rc = ngx_ssl_shutdown(c);

        if (rc == NGX_ERROR) {
            ngx_http_close_connection(c);
            return;
        }

        if (rc == NGX_AGAIN) {
            c->ssl->handler = ngx_http_v2_lingering_close;
            return;
        }
    }
#endif

    rev = c->read;
    rev->handler = ngx_http_v2_lingering_close_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    }

    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_http_close_connection(c);
        return;
    }

    c->close = 0;
    ngx_reusable_connection(c, 1);

    ngx_add_timer(rev, clcf->lingering_timeout);

    if (rev->ready) {
        ngx_http_v2_lingering_close_handler(rev);
    }
}


static void
ngx_http_v2_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_v2_connection_t  *h2c;
    u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    h2c = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http2 lingering close handler");

    if (rev->timedout || c->close) {
        ngx_http_close_connection(c);
        return;
    }

    timer = (ngx_msec_t) h2c->lingering_time - (ngx_msec_t) ngx_time();
    if ((ngx_msec_int_t) timer <= 0) {
        ngx_http_close_connection(c);
        return;
    }

    do {
        n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_connection(c);
            return;
        }

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);
    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
}


static u_char *
ngx_http_v2_state_preface(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = NGX_HTTP_V2_PREFACE_START;

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_preface);
    }

    if (ngx_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "invalid connection preface");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    return ngx_http_v2_state_preface_end(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
ngx_http_v2_state_preface_end(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = NGX_HTTP_V2_PREFACE_END;

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_preface_end);
    }

    if (ngx_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "invalid connection preface");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 preface verified");

    return ngx_http_v2_state_head(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
ngx_http_v2_state_head(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    uint32_t    head;
    ngx_uint_t  type;

    if (end - pos < NGX_HTTP_V2_FRAME_HEADER_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_head);
    }

    head = ngx_http_v2_parse_uint32(pos);

    h2c->state.length = ngx_http_v2_parse_length(head);
    h2c->state.flags = pos[4];

    h2c->state.sid = ngx_http_v2_parse_sid(&pos[5]);

    pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;

    type = ngx_http_v2_parse_type(head);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame type:%ui f:%Xd l:%uz sid:%ui",
                   type, h2c->state.flags, h2c->state.length, h2c->state.sid);

    if (type >= NGX_HTTP_V2_FRAME_STATES) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent frame with unknown type %ui", type);
        return ngx_http_v2_state_skip(h2c, pos, end);
    }

    return ngx_http_v2_frame_states[type](h2c, pos, end);
}


static u_char *
ngx_http_v2_state_data(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t                 size;
    ngx_http_v2_node_t    *node;
    ngx_http_v2_stream_t  *stream;

    size = h2c->state.length;

    if (h2c->state.flags & NGX_HTTP_V2_PADDED_FLAG) {

        if (h2c->state.length == 0) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: 0");

            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }

        if (end - pos == 0) {
            return ngx_http_v2_state_save(h2c, pos, end,
                                          ngx_http_v2_state_data);
        }

        h2c->state.padding = *pos++;

        if (h2c->state.padding >= size) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: %uz, padding: %uz",
                          size, h2c->state.padding);

            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= 1 + h2c->state.padding;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 DATA frame");

    if (h2c->state.sid == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (size > h2c->recv_window) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received DATA frame length %uz, available window %uz",
                      size, h2c->recv_window);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->recv_window -= size;

    if (h2c->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4) {

        if (ngx_http_v2_send_window_update(h2c, 0, NGX_HTTP_V2_MAX_WINDOW
                                                   - h2c->recv_window)
            == NGX_ERROR)
        {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    }

    node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream = node->stream;

    if (size > stream->recv_window) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client violated flow control for stream %ui: "
                      "received DATA frame length %uz, available window %uz",
                      node->id, size, stream->recv_window);

        if (ngx_http_v2_terminate_stream(h2c, stream,
                                         NGX_HTTP_V2_FLOW_CTRL_ERROR)
            == NGX_ERROR)
        {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream->recv_window -= size;

    if (stream->no_flow_control
        && stream->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
    {
        if (ngx_http_v2_send_window_update(h2c, node->id,
                                           NGX_HTTP_V2_MAX_WINDOW
                                           - stream->recv_window)
            == NGX_ERROR)
        {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    }

    if (stream->in_closed) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame for half-closed stream %ui",
                      node->id);

        if (ngx_http_v2_terminate_stream(h2c, stream,
                                         NGX_HTTP_V2_STREAM_CLOSED)
            == NGX_ERROR)
        {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    h2c->state.stream = stream;

    return ngx_http_v2_state_read_data(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_read_data(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    ngx_buf_t               *buf;
    ngx_int_t                rc;
    ngx_connection_t        *fc;
    ngx_http_request_t      *r;
    ngx_http_v2_stream_t    *stream;
    ngx_http_v2_srv_conf_t  *h2scf;

    stream = h2c->state.stream;

    if (stream == NULL) {
        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (stream->skip_data) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    r = stream->request;
    fc = r->connection;

    if (r->reading_body && !r->request_body_no_buffering) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    size = end - pos;

    if (size >= h2c->state.length) {
        size = h2c->state.length;
        stream->in_closed = h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG;
    }

    h2c->payload_bytes += size;

    if (r->request_body) {
        rc = ngx_http_v2_process_request_body(r, pos, size,
                                              stream->in_closed, 0);

        if (rc != NGX_OK && rc != NGX_AGAIN) {
            stream->skip_data = 1;
            ngx_http_finalize_request(r, rc);
        }

        ngx_http_run_posted_requests(fc);

    } else if (size) {
        buf = stream->preread;

        if (buf == NULL) {
            h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);

            buf = ngx_create_temp_buf(r->pool, h2scf->preread_size);
            if (buf == NULL) {
                return ngx_http_v2_connection_error(h2c,
                                                    NGX_HTTP_V2_INTERNAL_ERROR);
            }

            stream->preread = buf;
        }

        if (size > (size_t) (buf->end - buf->last)) {
            ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
                          "http2 preread buffer overflow");
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        buf->last = ngx_cpymem(buf->last, pos, size);
    }

    pos += size;
    h2c->state.length -= size;

    if (h2c->state.length) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_read_data);
    }

    if (h2c->state.padding) {
        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_headers(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                     size;
    ngx_uint_t                 padded, priority, depend, dependency, excl,
                               weight;
    ngx_uint_t                 status;
    ngx_http_v2_node_t        *node;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_core_loc_conf_t  *clcf;

    padded = h2c->state.flags & NGX_HTTP_V2_PADDED_FLAG;
    priority = h2c->state.flags & NGX_HTTP_V2_PRIORITY_FLAG;

    size = 0;

    if (padded) {
        size++;
    }

    if (priority) {
        size += sizeof(uint32_t) + 1;
    }

    if (h2c->state.length < size) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect length %uz",
                      h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->state.length == size) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with empty header block");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->goaway) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 HEADERS frame");
        return ngx_http_v2_state_skip(h2c, pos, end);
    }

    if ((size_t) (end - pos) < size) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_headers);
    }

    h2c->state.length -= size;

    if (padded) {
        h2c->state.padding = *pos++;

        if (h2c->state.padding > h2c->state.length) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded HEADERS frame "
                          "with incorrect length: %uz, padding: %uz",
                          h2c->state.length, h2c->state.padding);

            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= h2c->state.padding;
    }

    depend = 0;
    excl = 0;
    weight = NGX_HTTP_V2_DEFAULT_WEIGHT;

    if (priority) {
        dependency = ngx_http_v2_parse_uint32(pos);

        depend = dependency & 0x7fffffff;
        excl = dependency >> 31;
        weight = pos[4] + 1;

        pos += sizeof(uint32_t) + 1;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 HEADERS frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid % 2 == 0 || h2c->state.sid <= h2c->last_sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect identifier "
                      "%ui, the last was %ui", h2c->state.sid, h2c->last_sid);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->last_sid = h2c->state.sid;

    h2c->state.pool = ngx_create_pool(1024, h2c->connection->log);
    if (h2c->state.pool == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    cscf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    h2c->state.header_limit = cscf->large_client_header_buffers.size
                              * cscf->large_client_header_buffers.num;

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    if (h2c->processing >= h2scf->concurrent_streams) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "concurrent streams exceeded %ui", h2c->processing);

        status = NGX_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (h2c->new_streams++ >= 2 * h2scf->concurrent_streams) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many streams at once");

        status = NGX_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (!h2c->settings_ack
        && !(h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG)
        && h2scf->preread_size < NGX_HTTP_V2_DEFAULT_WINDOW)
    {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent stream with data "
                      "before settings were acknowledged");

        status = NGX_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    if (node->parent) {
        ngx_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream = ngx_http_v2_create_stream(h2c);
    if (stream == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = stream;

    stream->pool = h2c->state.pool;
    h2c->state.keep_pool = 1;

    stream->request->request_length = h2c->state.length;

    stream->in_closed = h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG;
    stream->node = node;

    node->stream = stream;

    if (priority || node->parent == NULL) {
        node->weight = weight;
        ngx_http_v2_set_dependency(h2c, node, depend, excl);
    }

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (clcf->keepalive_timeout == 0
        || h2c->connection->requests >= clcf->keepalive_requests
        || ngx_current_msec - h2c->connection->start_time
           > clcf->keepalive_time)
    {
        h2c->goaway = 1;

        if (ngx_http_v2_send_goaway(h2c, NGX_HTTP_V2_NO_ERROR) == NGX_ERROR) {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return ngx_http_v2_state_header_block(h2c, pos, end);

rst_stream:

    if (h2c->refused_streams++ > ngx_max(h2scf->concurrent_streams, 100)) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many refused streams");
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_NO_ERROR);
    }

    if (ngx_http_v2_send_rst_stream(h2c, h2c->state.sid, status) != NGX_OK) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    return ngx_http_v2_state_header_block(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_header_block(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    u_char      ch;
    ngx_int_t   value;
    ngx_uint_t  indexed, size_update, prefix;

    if (end - pos < 1) {
        return ngx_http_v2_state_headers_save(h2c, pos, end,
                                              ngx_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < NGX_HTTP_V2_INT_OCTETS)
    {
        return ngx_http_v2_handle_continuation(h2c, pos, end,
                                               ngx_http_v2_state_header_block);
    }

    size_update = 0;
    indexed = 0;

    ch = *pos;

    if (ch >= (1 << 7)) {
        /* indexed header field */
        indexed = 1;
        prefix = ngx_http_v2_prefix(7);

    } else if (ch >= (1 << 6)) {
        /* literal header field with incremental indexing */
        h2c->state.index = 1;
        prefix = ngx_http_v2_prefix(6);

    } else if (ch >= (1 << 5)) {
        /* dynamic table size update */
        size_update = 1;
        prefix = ngx_http_v2_prefix(5);

    } else if (ch >= (1 << 4)) {
        /* literal header field never indexed */
        prefix = ngx_http_v2_prefix(4);

    } else {
        /* literal header field without indexing */
        prefix = ngx_http_v2_prefix(4);
    }

    value = ngx_http_v2_parse_int(h2c, &pos, end, prefix);

    if (value < 0) {
        if (value == NGX_AGAIN) {
            return ngx_http_v2_state_headers_save(h2c, pos, end,
                                               ngx_http_v2_state_header_block);
        }

        if (value == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent header block with too long %s value",
                          size_update ? "size update" : "header index");

            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (indexed) {
        if (ngx_http_v2_get_indexed_header(h2c, value, 0) != NGX_OK) {
            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        return ngx_http_v2_state_process_header(h2c, pos, end);
    }

    if (size_update) {
        if (ngx_http_v2_table_size(h2c, value) != NGX_OK) {
            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        return ngx_http_v2_state_header_complete(h2c, pos, end);
    }

    if (value == 0) {
        h2c->state.parse_name = 1;

    } else if (ngx_http_v2_get_indexed_header(h2c, value, 1) != NGX_OK) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
    }

    h2c->state.parse_value = 1;

    return ngx_http_v2_state_field_len(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_field_len(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                     alloc;
    ngx_int_t                  len;
    ngx_uint_t                 huff;
    ngx_http_core_srv_conf_t  *cscf;

    if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < NGX_HTTP_V2_INT_OCTETS)
    {
        return ngx_http_v2_handle_continuation(h2c, pos, end,
                                               ngx_http_v2_state_field_len);
    }

    if (h2c->state.length < 1) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < 1) {
        return ngx_http_v2_state_headers_save(h2c, pos, end,
                                              ngx_http_v2_state_field_len);
    }

    huff = *pos >> 7;
    len = ngx_http_v2_parse_int(h2c, &pos, end, ngx_http_v2_prefix(7));

    if (len < 0) {
        if (len == NGX_AGAIN) {
            return ngx_http_v2_state_headers_save(h2c, pos, end,
                                                  ngx_http_v2_state_field_len);
        }

        if (len == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                        "client sent header field with too long length value");

            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 %s string, len:%i",
                   huff ? "encoded" : "raw", len);

    cscf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if ((size_t) len > cscf->large_client_header_buffers.size) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent too large header field");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.field_rest = len;

    if (h2c->state.stream == NULL && !h2c->state.index) {
        return ngx_http_v2_state_field_skip(h2c, pos, end);
    }

    alloc = (huff ? len * 8 / 5 : len) + 1;

    h2c->state.field_start = ngx_pnalloc(h2c->state.pool, alloc);
    if (h2c->state.field_start == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.field_end = h2c->state.field_start;

    if (huff) {
        return ngx_http_v2_state_field_huff(h2c, pos, end);
    }

    return ngx_http_v2_state_field_raw(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_field_huff(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    if (ngx_http_huff_decode(&h2c->state.field_state, pos, size,
                             &h2c->state.field_end,
                             h2c->state.field_rest == 0,
                             h2c->connection->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid encoded header field");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
    }

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return ngx_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return ngx_http_v2_state_headers_save(h2c, pos, end,
                                              ngx_http_v2_state_field_huff);
    }

    if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    return ngx_http_v2_handle_continuation(h2c, pos, end,
                                           ngx_http_v2_state_field_huff);
}


static u_char *
ngx_http_v2_state_field_raw(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    h2c->state.field_end = ngx_cpymem(h2c->state.field_end, pos, size);

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return ngx_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return ngx_http_v2_state_headers_save(h2c, pos, end,
                                              ngx_http_v2_state_field_raw);
    }

    if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    return ngx_http_v2_handle_continuation(h2c, pos, end,
                                           ngx_http_v2_state_field_raw);
}


static u_char *
ngx_http_v2_state_field_skip(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    pos += size;

    if (h2c->state.field_rest == 0) {
        return ngx_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_field_skip);
    }

    if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    return ngx_http_v2_handle_continuation(h2c, pos, end,
                                           ngx_http_v2_state_field_skip);
}


static u_char *
ngx_http_v2_state_process_header(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_table_elt_t            *h;
    ngx_connection_t           *fc;
    ngx_http_header_t          *hh;
    ngx_http_request_t         *r;
    ngx_http_v2_header_t       *header;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    header = &h2c->state.header;

    if (h2c->state.parse_name) {
        h2c->state.parse_name = 0;

        header->name.len = h2c->state.field_end - h2c->state.field_start;
        header->name.data = h2c->state.field_start;

        if (header->name.len == 0) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent zero header name length");

            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        return ngx_http_v2_state_field_len(h2c, pos, end);
    }

    if (h2c->state.parse_value) {
        h2c->state.parse_value = 0;

        header->value.len = h2c->state.field_end - h2c->state.field_start;
        header->value.data = h2c->state.field_start;
    }

    len = header->name.len + header->value.len;

    if (len > h2c->state.header_limit) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent too large header");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.header_limit -= len;

    if (h2c->state.index) {
        if (ngx_http_v2_add_header(h2c, header) != NGX_OK) {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->state.index = 0;
    }

    if (h2c->state.stream == NULL) {
        return ngx_http_v2_state_header_complete(h2c, pos, end);
    }

    r = h2c->state.stream->request;
    fc = r->connection;

    /* TODO Optimization: validate headers while parsing. */
    if (ngx_http_v23_validate_header(r, &header->name, &header->value)
        != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        goto error;
    }

    if (header->name.data[0] == ':') {
        rc = ngx_http_v2_pseudo_header(r, header);

        if (rc == NGX_OK) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http2 header: \":%V: %V\"",
                           &header->name, &header->value);

            return ngx_http_v2_state_header_complete(h2c, pos, end);
        }

        if (rc == NGX_ABORT) {
            goto error;
        }

        if (rc == NGX_DECLINED) {
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            goto error;
        }

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    if (r->invalid_header) {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->ignore_invalid_headers) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", &header->name);

            return ngx_http_v2_state_header_complete(h2c, pos, end);
        }
    }

    if (header->name.len == cookie.len
        && ngx_memcmp(header->name.data, cookie.data, cookie.len) == 0)
    {
        if (ngx_http_v2_cookie(r, header) != NGX_OK) {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

    } else {
        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }

        h->key.len = header->name.len;
        h->key.data = header->name.data;

        /*
         * TODO Optimization: precalculate hash
         * and handler for indexed headers.
         */
        h->hash = ngx_hash_key(h->key.data, h->key.len);

        h->value.len = header->value.len;
        h->value.data = header->value.data;

        h->lowcase_key = h->key.data;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            goto error;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header: \"%V: %V\"",
                   &header->name, &header->value);

    return ngx_http_v2_state_header_complete(h2c, pos, end);

error:

    h2c->state.stream = NULL;

    ngx_http_run_posted_requests(fc);

    return ngx_http_v2_state_header_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_header_complete(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_http_v2_stream_t  *stream;

    if (h2c->state.length) {
        if (end - pos > 0) {
            h2c->state.handler = ngx_http_v2_state_header_block;
            return pos;
        }

        return ngx_http_v2_state_headers_save(h2c, pos, end,
                                              ngx_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)) {
        return ngx_http_v2_handle_continuation(h2c, pos, end,
                                             ngx_http_v2_state_header_complete);
    }

    stream = h2c->state.stream;

    if (stream) {
        ngx_http_v2_run_request(stream->request);
    }

    if (!h2c->state.keep_pool) {
        ngx_destroy_pool(h2c->state.pool);
    }

    h2c->state.pool = NULL;
    h2c->state.keep_pool = 0;

    if (h2c->state.padding) {
        return ngx_http_v2_state_skip_padded(h2c, pos, end);
    }

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_handle_continuation(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, ngx_http_v2_handler_pt handler)
{
    u_char    *p;
    size_t     len, skip;
    uint32_t   head;

    len = h2c->state.length;

    if (h2c->state.padding && (size_t) (end - pos) > len) {
        skip = ngx_min(h2c->state.padding, (end - pos) - len);

        h2c->state.padding -= skip;

        p = pos;
        pos += skip;
        ngx_memmove(pos, p, len);
    }

    if ((size_t) (end - pos) < len + NGX_HTTP_V2_FRAME_HEADER_SIZE) {
        return ngx_http_v2_state_headers_save(h2c, pos, end, handler);
    }

    p = pos + len;

    head = ngx_http_v2_parse_uint32(p);

    if (ngx_http_v2_parse_type(head) != NGX_HTTP_V2_CONTINUATION_FRAME) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
             "client sent inappropriate frame while CONTINUATION was expected");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->state.flags |= p[4];

    if (h2c->state.sid != ngx_http_v2_parse_sid(&p[5])) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                    "client sent CONTINUATION frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    p = pos;
    pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;

    ngx_memcpy(pos, p, len);

    len = ngx_http_v2_parse_length(head);

    h2c->state.length += len;

    if (h2c->state.stream) {
        h2c->state.stream->request->request_length += len;
    }

    h2c->state.handler = handler;
    return pos;
}


static u_char *
ngx_http_v2_state_priority(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_uint_t           depend, dependency, excl, weight;
    ngx_http_v2_node_t  *node;

    if (h2c->state.length != NGX_HTTP_V2_PRIORITY_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect length %uz",
                      h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (--h2c->priority_limit == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many PRIORITY frames");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    if (end - pos < NGX_HTTP_V2_PRIORITY_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_priority);
    }

    dependency = ngx_http_v2_parse_uint32(pos);

    depend = dependency & 0x7fffffff;
    excl = dependency >> 31;
    weight = pos[4] + 1;

    pos += NGX_HTTP_V2_PRIORITY_SIZE;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PRIORITY frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    node->weight = weight;

    if (node->stream == NULL) {
        if (node->parent == NULL) {
            h2c->closed_nodes++;

        } else {
            ngx_queue_remove(&node->reuse);
        }

        ngx_queue_insert_tail(&h2c->closed, &node->reuse);
    }

    ngx_http_v2_set_dependency(h2c, node, depend, excl);

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_rst_stream(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_uint_t             status;
    ngx_event_t           *ev;
    ngx_connection_t      *fc;
    ngx_http_v2_node_t    *node;
    ngx_http_v2_stream_t  *stream;

    if (h2c->state.length != NGX_HTTP_V2_RST_STREAM_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect length %uz",
                      h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NGX_HTTP_V2_RST_STREAM_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_rst_stream);
    }

    status = ngx_http_v2_parse_uint32(pos);

    pos += NGX_HTTP_V2_RST_STREAM_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 RST_STREAM frame, sid:%ui status:%ui",
                   h2c->state.sid, status);

    if (h2c->state.sid == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return ngx_http_v2_state_complete(h2c, pos, end);
    }

    stream = node->stream;

    stream->in_closed = 1;
    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    switch (status) {

    case NGX_HTTP_V2_CANCEL:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client canceled stream %ui", h2c->state.sid);
        break;

    case NGX_HTTP_V2_INTERNAL_ERROR:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui due to internal error",
                      h2c->state.sid);
        break;

    default:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui with status %ui",
                      h2c->state.sid, status);
        break;
    }

    ev = fc->read;
    ev->handler(ev);

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_settings(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 SETTINGS frame");

    if (h2c->state.sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.flags == NGX_HTTP_V2_ACK_FLAG) {

        if (h2c->state.length != 0) {
            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client sent SETTINGS frame with the ACK flag "
                          "and nonzero length");

            return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }

        h2c->settings_ack = 1;

        return ngx_http_v2_state_complete(h2c, pos, end);
    }

    if (h2c->state.length % NGX_HTTP_V2_SETTINGS_PARAM_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect length %uz",
                      h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    return ngx_http_v2_state_settings_params(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_settings_params(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ssize_t                   window_delta;
    ngx_uint_t                id, value;
    ngx_http_v2_out_frame_t  *frame;

    window_delta = 0;

    while (h2c->state.length) {
        if (end - pos < NGX_HTTP_V2_SETTINGS_PARAM_SIZE) {
            return ngx_http_v2_state_save(h2c, pos, end,
                                          ngx_http_v2_state_settings_params);
        }

        h2c->state.length -= NGX_HTTP_V2_SETTINGS_PARAM_SIZE;

        id = ngx_http_v2_parse_uint16(pos);
        value = ngx_http_v2_parse_uint32(&pos[2]);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 setting %ui:%ui", id, value);

        switch (id) {

        case NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING:

            if (value > NGX_HTTP_V2_MAX_WINDOW) {
                ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "INITIAL_WINDOW_SIZE value %ui", value);

                return ngx_http_v2_connection_error(h2c,
                                                  NGX_HTTP_V2_FLOW_CTRL_ERROR);
            }

            window_delta = value - h2c->init_window;
            break;

        case NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING:

            if (value > NGX_HTTP_V2_MAX_FRAME_SIZE
                || value < NGX_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "MAX_FRAME_SIZE value %ui", value);

                return ngx_http_v2_connection_error(h2c,
                                                    NGX_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->frame_size = value;
            break;

        case NGX_HTTP_V2_ENABLE_PUSH_SETTING:

            if (value > 1) {
                ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "ENABLE_PUSH value %ui", value);

                return ngx_http_v2_connection_error(h2c,
                                                    NGX_HTTP_V2_PROTOCOL_ERROR);
            }

            break;

        case NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING:

            h2c->table_update = 1;
            break;

        default:
            break;
        }

        pos += NGX_HTTP_V2_SETTINGS_PARAM_SIZE;
    }

    frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_SETTINGS_ACK_SIZE,
                                  NGX_HTTP_V2_SETTINGS_FRAME,
                                  NGX_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    ngx_http_v2_queue_ordered_frame(h2c, frame);

    if (window_delta) {
        h2c->init_window += window_delta;

        if (ngx_http_v2_adjust_windows(h2c, window_delta) != NGX_OK) {
            return ngx_http_v2_connection_error(h2c,
                                                NGX_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_push_promise(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent PUSH_PROMISE frame");

    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
ngx_http_v2_state_ping(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    if (h2c->state.length != NGX_HTTP_V2_PING_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect length %uz",
                      h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NGX_HTTP_V2_PING_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_ping);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PING frame");

    if (h2c->state.sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.flags & NGX_HTTP_V2_ACK_FLAG) {
        return ngx_http_v2_state_skip(h2c, pos, end);
    }

    frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_PING_SIZE,
                                  NGX_HTTP_V2_PING_FRAME,
                                  NGX_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    buf = frame->first->buf;

    buf->last = ngx_cpymem(buf->last, pos, NGX_HTTP_V2_PING_SIZE);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return ngx_http_v2_state_complete(h2c, pos + NGX_HTTP_V2_PING_SIZE, end);
}


static u_char *
ngx_http_v2_state_goaway(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
#if (NGX_DEBUG)
    ngx_uint_t  last_sid, error;
#endif

    if (h2c->state.length < NGX_HTTP_V2_GOAWAY_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame "
                      "with incorrect length %uz", h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NGX_HTTP_V2_GOAWAY_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_goaway);
    }

    if (h2c->state.sid) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame with incorrect identifier");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

#if (NGX_DEBUG)
    h2c->state.length -= NGX_HTTP_V2_GOAWAY_SIZE;

    last_sid = ngx_http_v2_parse_sid(pos);
    error = ngx_http_v2_parse_uint32(&pos[4]);

    pos += NGX_HTTP_V2_GOAWAY_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 GOAWAY frame: last sid %ui, error %ui",
                   last_sid, error);
#endif

    return ngx_http_v2_state_skip(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_window_update(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                 window;
    ngx_event_t           *wev;
    ngx_queue_t           *q;
    ngx_http_v2_node_t    *node;
    ngx_http_v2_stream_t  *stream;

    if (h2c->state.length != NGX_HTTP_V2_WINDOW_UPDATE_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect length %uz", h2c->state.length);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NGX_HTTP_V2_WINDOW_UPDATE_SIZE) {
        return ngx_http_v2_state_save(h2c, pos, end,
                                      ngx_http_v2_state_window_update);
    }

    window = ngx_http_v2_parse_window(pos);

    pos += NGX_HTTP_V2_WINDOW_UPDATE_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 WINDOW_UPDATE frame sid:%ui window:%uz",
                   h2c->state.sid, window);

    if (window == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect window increment 0");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.sid) {
        node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

        if (node == NULL || node->stream == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "unknown http2 stream");

            return ngx_http_v2_state_complete(h2c, pos, end);
        }

        stream = node->stream;

        if (window > (size_t) (NGX_HTTP_V2_MAX_WINDOW - stream->send_window)) {

            ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                          "client violated flow control for stream %ui: "
                          "received WINDOW_UPDATE frame "
                          "with window increment %uz "
                          "not allowed for window %z",
                          h2c->state.sid, window, stream->send_window);

            if (ngx_http_v2_terminate_stream(h2c, stream,
                                             NGX_HTTP_V2_FLOW_CTRL_ERROR)
                == NGX_ERROR)
            {
                return ngx_http_v2_connection_error(h2c,
                                                    NGX_HTTP_V2_INTERNAL_ERROR);
            }

            return ngx_http_v2_state_complete(h2c, pos, end);
        }

        stream->send_window += window;

        if (stream->exhausted) {
            stream->exhausted = 0;

            wev = stream->request->connection->write;

            wev->active = 0;
            wev->ready = 1;

            if (!wev->delayed) {
                wev->handler(wev);
            }
        }

        return ngx_http_v2_state_complete(h2c, pos, end);
    }

    if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received WINDOW_UPDATE frame "
                      "with window increment %uz "
                      "not allowed for window %uz",
                      window, h2c->send_window);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->send_window += window;

    while (!ngx_queue_empty(&h2c->waiting)) {
        q = ngx_queue_head(&h2c->waiting);

        ngx_queue_remove(q);

        stream = ngx_queue_data(q, ngx_http_v2_stream_t, queue);

        stream->waiting = 0;

        wev = stream->request->connection->write;

        wev->active = 0;
        wev->ready = 1;

        if (!wev->delayed) {
            wev->handler(wev);

            if (h2c->send_window == 0) {
                break;
            }
        }
    }

    return ngx_http_v2_state_complete(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_continuation(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent unexpected CONTINUATION frame");

    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
ngx_http_v2_state_complete(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame complete pos:%p end:%p", pos, end);

    if (pos > end) {
        ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
                      "receive buffer overrun");

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = NULL;
    h2c->state.handler = ngx_http_v2_state_head;

    return pos;
}


static u_char *
ngx_http_v2_state_skip_padded(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    h2c->state.length += h2c->state.padding;
    h2c->state.padding = 0;

    return ngx_http_v2_state_skip(h2c, pos, end);
}


static u_char *
ngx_http_v2_state_skip(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size < h2c->state.length) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 frame skip %uz of %uz", size, h2c->state.length);

        h2c->state.length -= size;
        return ngx_http_v2_state_save(h2c, end, end, ngx_http_v2_state_skip);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame skip %uz", h2c->state.length);

    return ngx_http_v2_state_complete(h2c, pos + h2c->state.length, end);
}


static u_char *
ngx_http_v2_state_save(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end,
    ngx_http_v2_handler_pt handler)
{
    size_t  size;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame state save pos:%p end:%p handler:%p",
                   pos, end, handler);

    size = end - pos;

    if (size > NGX_HTTP_V2_STATE_BUFFER_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
                      "state buffer overflow: %uz bytes required", size);

        return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    ngx_memcpy(h2c->state.buffer, pos, size);

    h2c->state.buffer_used = size;
    h2c->state.handler = handler;
    h2c->state.incomplete = 1;

    return end;
}


static u_char *
ngx_http_v2_state_headers_save(ngx_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, ngx_http_v2_handler_pt handler)
{
    ngx_event_t               *rev;
    ngx_http_request_t        *r;
    ngx_http_core_srv_conf_t  *cscf;

    if (h2c->state.stream) {
        r = h2c->state.stream->request;
        rev = r->connection->read;

        if (!rev->timer_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, cscf->client_header_timeout);
        }
    }

    return ngx_http_v2_state_save(h2c, pos, end, handler);
}


static u_char *
ngx_http_v2_connection_error(ngx_http_v2_connection_t *h2c,
    ngx_uint_t err)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 state connection error");

    ngx_http_v2_finalize_connection(h2c, err);

    return NULL;
}


static ngx_int_t
ngx_http_v2_parse_int(ngx_http_v2_connection_t *h2c, u_char **pos, u_char *end,
    ngx_uint_t prefix)
{
    u_char      *start, *p;
    ngx_uint_t   value, octet, shift;

    start = *pos;
    p = start;

    value = *p++ & prefix;

    if (value != prefix) {
        if (h2c->state.length == 0) {
            return NGX_ERROR;
        }

        h2c->state.length--;

        *pos = p;
        return value;
    }

    if (end - start > NGX_HTTP_V2_INT_OCTETS) {
        end = start + NGX_HTTP_V2_INT_OCTETS;
    }

    for (shift = 0; p != end; shift += 7) {
        octet = *p++;

        value += (octet & 0x7f) << shift;

        if (octet < 128) {
            if ((size_t) (p - start) > h2c->state.length) {
                return NGX_ERROR;
            }

            h2c->state.length -= p - start;

            *pos = p;
            return value;
        }
    }

    if ((size_t) (end - start) >= h2c->state.length) {
        return NGX_ERROR;
    }

    if (end == start + NGX_HTTP_V2_INT_OCTETS) {
        return NGX_DECLINED;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v2_send_settings(ngx_http_v2_connection_t *h2c)
{
    size_t                    len;
    ngx_buf_t                *buf;
    ngx_chain_t              *cl;
    ngx_http_v2_srv_conf_t   *h2scf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send SETTINGS frame");

    frame = ngx_palloc(h2c->pool, sizeof(ngx_http_v2_out_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(h2c->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    len = NGX_HTTP_V2_SETTINGS_PARAM_SIZE * 3;

    buf = ngx_create_temp_buf(h2c->pool, NGX_HTTP_V2_FRAME_HEADER_SIZE + len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_v2_settings_frame_handler;
    frame->stream = NULL;
#if (NGX_DEBUG)
    frame->length = len;
#endif
    frame->blocked = 0;

    buf->last = ngx_http_v2_write_len_and_type(buf->last, len,
                                               NGX_HTTP_V2_SETTINGS_FRAME);

    *buf->last++ = NGX_HTTP_V2_NO_FLAG;

    buf->last = ngx_http_v2_write_sid(buf->last, 0);

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    buf->last = ngx_http_v2_write_uint16(buf->last,
                                         NGX_HTTP_V2_MAX_STREAMS_SETTING);
    buf->last = ngx_http_v2_write_uint32(buf->last,
                                         h2scf->concurrent_streams);

    buf->last = ngx_http_v2_write_uint16(buf->last,
                                         NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
    buf->last = ngx_http_v2_write_uint32(buf->last, h2scf->preread_size);

    buf->last = ngx_http_v2_write_uint16(buf->last,
                                         NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING);
    buf->last = ngx_http_v2_write_uint32(buf->last,
                                         NGX_HTTP_V2_MAX_FRAME_SIZE);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_settings_frame_handler(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    ngx_free_chain(h2c->pool, frame->first);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_send_window_update(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
    size_t window)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send WINDOW_UPDATE frame sid:%ui, window:%uz",
                   sid, window);

    frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_WINDOW_UPDATE_SIZE,
                                  NGX_HTTP_V2_WINDOW_UPDATE_FRAME,
                                  NGX_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    buf->last = ngx_http_v2_write_uint32(buf->last, window);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_send_rst_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
    ngx_uint_t status)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send RST_STREAM frame sid:%ui, status:%ui",
                   sid, status);

    frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_RST_STREAM_SIZE,
                                  NGX_HTTP_V2_RST_STREAM_FRAME,
                                  NGX_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    buf->last = ngx_http_v2_write_uint32(buf->last, status);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_send_goaway(ngx_http_v2_connection_t *h2c, ngx_uint_t status)
{
    ngx_buf_t                *buf;
    ngx_http_v2_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send GOAWAY frame: last sid %ui, error %ui",
                   h2c->last_sid, status);

    frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_GOAWAY_SIZE,
                                  NGX_HTTP_V2_GOAWAY_FRAME,
                                  NGX_HTTP_V2_NO_FLAG, 0);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    buf->last = ngx_http_v2_write_sid(buf->last, h2c->last_sid);
    buf->last = ngx_http_v2_write_uint32(buf->last, status);

    ngx_http_v2_queue_blocked_frame(h2c, frame);

    return NGX_OK;
}


static ngx_http_v2_out_frame_t *
ngx_http_v2_get_frame(ngx_http_v2_connection_t *h2c, size_t length,
    ngx_uint_t type, u_char flags, ngx_uint_t sid)
{
    ngx_buf_t                *buf;
    ngx_pool_t               *pool;
    ngx_http_v2_out_frame_t  *frame;

    frame = h2c->free_frames;

    if (frame) {
        h2c->free_frames = frame->next;

        buf = frame->first->buf;
        buf->pos = buf->start;

        frame->blocked = 0;

    } else if (h2c->frames < 10000) {
        pool = h2c->pool ? h2c->pool : h2c->connection->pool;

        frame = ngx_pcalloc(pool, sizeof(ngx_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        frame->first = ngx_alloc_chain_link(pool);
        if (frame->first == NULL) {
            return NULL;
        }

        buf = ngx_create_temp_buf(pool, NGX_HTTP_V2_FRAME_BUFFER_SIZE);
        if (buf == NULL) {
            return NULL;
        }

        buf->last_buf = 1;

        frame->first->buf = buf;
        frame->last = frame->first;

        frame->handler = ngx_http_v2_frame_handler;

        h2c->frames++;

    } else {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

#if (NGX_DEBUG)
    if (length > NGX_HTTP_V2_FRAME_BUFFER_SIZE - NGX_HTTP_V2_FRAME_HEADER_SIZE)
    {
        ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }
#endif

    frame->length = length;

    buf->last = ngx_http_v2_write_len_and_type(buf->pos, length, type);

    *buf->last++ = flags;

    buf->last = ngx_http_v2_write_sid(buf->last, sid);

    return frame;
}


static ngx_int_t
ngx_http_v2_frame_handler(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    frame->next = h2c->free_frames;
    h2c->free_frames = frame;

    h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    return NGX_OK;
}


static ngx_http_v2_stream_t *
ngx_http_v2_create_stream(ngx_http_v2_connection_t *h2c)
{
    ngx_log_t                 *log;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_core_srv_conf_t  *cscf;

    fc = h2c->free_fake_connections;

    if (fc) {
        h2c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(h2c->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(h2c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(h2c->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    ngx_memcpy(log, h2c->connection->log, sizeof(ngx_log_t));

    log->data = ctx;
    log->action = "reading client request headers";

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_v2_close_stream_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, h2c->connection, sizeof(ngx_connection_t));

    fc->data = h2c->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    r = ngx_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    ngx_str_set(&r->http_protocol, "HTTP/2.0");

    r->http_version = NGX_HTTP_VERSION_20;
    r->valid_location = 1;

    fc->data = r;
    h2c->connection->requests++;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->stream = stream;

    stream->request = r;
    stream->connection = h2c;

    h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);

    stream->send_window = h2c->init_window;
    stream->recv_window = h2scf->preread_size;

    h2c->processing++;

    h2c->priority_limit += h2scf->concurrent_streams;

    if (h2c->connection->read->timer_set) {
        ngx_del_timer(h2c->connection->read);
    }

    return stream;
}


static ngx_http_v2_node_t *
ngx_http_v2_get_node_by_id(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
    ngx_uint_t alloc)
{
    ngx_uint_t               index;
    ngx_http_v2_node_t      *node;
    ngx_http_v2_srv_conf_t  *h2scf;

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    index = ngx_http_v2_index(h2scf, sid);

    for (node = h2c->streams_index[index]; node; node = node->index) {

        if (node->id == sid) {
            return node;
        }
    }

    if (!alloc) {
        return NULL;
    }

    if (h2c->closed_nodes < 32) {
        node = ngx_pcalloc(h2c->connection->pool, sizeof(ngx_http_v2_node_t));
        if (node == NULL) {
            return NULL;
        }

    } else {
        node = ngx_http_v2_get_closed_node(h2c);
    }

    node->id = sid;

    ngx_queue_init(&node->children);

    node->index = h2c->streams_index[index];
    h2c->streams_index[index] = node;

    return node;
}


static ngx_http_v2_node_t *
ngx_http_v2_get_closed_node(ngx_http_v2_connection_t *h2c)
{
    ngx_uint_t               weight;
    ngx_queue_t             *q, *children;
    ngx_http_v2_node_t      *node, **next, *n, *parent, *child;
    ngx_http_v2_srv_conf_t  *h2scf;

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    h2c->closed_nodes--;

    q = ngx_queue_head(&h2c->closed);

    ngx_queue_remove(q);

    node = ngx_queue_data(q, ngx_http_v2_node_t, reuse);

    next = &h2c->streams_index[ngx_http_v2_index(h2scf, node->id)];

    for ( ;; ) {
        n = *next;

        if (n == node) {
            *next = n->index;
            break;
        }

        next = &n->index;
    }

    ngx_queue_remove(&node->queue);

    weight = 0;

    for (q = ngx_queue_head(&node->children);
         q != ngx_queue_sentinel(&node->children);
         q = ngx_queue_next(q))
    {
        child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
        weight += child->weight;
    }

    parent = node->parent;

    for (q = ngx_queue_head(&node->children);
         q != ngx_queue_sentinel(&node->children);
         q = ngx_queue_next(q))
    {
        child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
        child->parent = parent;
        child->weight = node->weight * child->weight / weight;

        if (child->weight == 0) {
            child->weight = 1;
        }
    }

    if (parent == NGX_HTTP_V2_ROOT) {
        node->rank = 0;
        node->rel_weight = 1.0;

        children = &h2c->dependencies;

    } else {
        node->rank = parent->rank;
        node->rel_weight = parent->rel_weight;

        children = &parent->children;
    }

    ngx_http_v2_node_children_update(node);
    ngx_queue_add(children, &node->children);

    ngx_memzero(node, sizeof(ngx_http_v2_node_t));

    return node;
}


static ngx_int_t
ngx_http_v2_pseudo_header(ngx_http_request_t *r, ngx_http_v2_header_t *header)
{
    header->name.len--;
    header->name.data++;

    switch (header->name.len) {
    case 4:
        if (ngx_memcmp(header->name.data, "path", sizeof("path") - 1)
            == 0)
        {
            return ngx_http_v2_parse_path(r, &header->value);
        }

        break;

    case 6:
        if (ngx_memcmp(header->name.data, "method", sizeof("method") - 1)
            == 0)
        {
            return ngx_http_v2_parse_method(r, &header->value);
        }

        if (ngx_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
            == 0)
        {
            return ngx_http_v2_parse_scheme(r, &header->value);
        }

        break;

    case 9:
        if (ngx_memcmp(header->name.data, "authority", sizeof("authority") - 1)
            == 0)
        {
            return ngx_http_v2_parse_authority(r, &header->value);
        }

        break;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \":%V\"",
                  &header->name);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_v2_parse_path(ngx_http_request_t *r, ngx_str_t *value)
{
    if (r->unparsed_uri.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return NGX_DECLINED;
    }

    r->uri_start = value->data;
    r->uri_end = value->data + value->len;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"", value);

        return NGX_DECLINED;
    }

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_request_uri()
         */
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_parse_method(ngx_http_request_t *r, ngx_str_t *value)
{
    size_t         k, len;
    ngx_uint_t     n;
    const u_char  *p, *m;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static const struct {
        u_char            len;
        const u_char      method[11];
        uint32_t          value;
    } tests[] = {
        { 3, "GET",       NGX_HTTP_GET },
        { 4, "POST",      NGX_HTTP_POST },
        { 4, "HEAD",      NGX_HTTP_HEAD },
        { 7, "OPTIONS",   NGX_HTTP_OPTIONS },
        { 8, "PROPFIND",  NGX_HTTP_PROPFIND },
        { 3, "PUT",       NGX_HTTP_PUT },
        { 5, "MKCOL",     NGX_HTTP_MKCOL },
        { 6, "DELETE",    NGX_HTTP_DELETE },
        { 4, "COPY",      NGX_HTTP_COPY },
        { 4, "MOVE",      NGX_HTTP_MOVE },
        { 9, "PROPPATCH", NGX_HTTP_PROPPATCH },
        { 4, "LOCK",      NGX_HTTP_LOCK },
        { 6, "UNLOCK",    NGX_HTTP_UNLOCK },
        { 5, "PATCH",     NGX_HTTP_PATCH },
        { 5, "TRACE",     NGX_HTTP_TRACE },
        { 7, "CONNECT",   NGX_HTTP_CONNECT }
    }, *test;

    if (r->method_name.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return NGX_DECLINED;
    }

    r->method_name.len = value->len;
    r->method_name.data = value->data;

    len = r->method_name.len;
    n = sizeof(tests) / sizeof(tests[0]);
    test = tests;

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return NGX_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return NGX_DECLINED;
        }

        p++;

    } while (--len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_parse_scheme(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char      c, ch;
    ngx_uint_t  i;

    if (r->schema.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :scheme header");

        return NGX_DECLINED;
    }

    if (value->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :scheme header");

        return NGX_DECLINED;
    }

    for (i = 0; i < value->len; i++) {
        ch = value->data[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if (((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            && i > 0)
        {
            continue;
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :scheme header: \"%V\"", value);

        return NGX_DECLINED;
    }

    r->schema = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_parse_authority(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_int_t  rc;

    if (r->host_start) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate \":authority\" header");
        return NGX_DECLINED;
    }

    r->host_start = value->data;
    r->host_end = value->data + value->len;

    rc = ngx_http_validate_host(value, r->pool, 0);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid \":authority\" header");
        return NGX_DECLINED;
    }

    if (rc == NGX_ERROR) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ABORT;
    }

    if (ngx_http_set_virtual_server(r, value) == NGX_ERROR) {
        /*
         * request has been finalized already
         * in ngx_http_set_virtual_server()
         */
        return NGX_ABORT;
    }

    r->headers_in.server = *value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_construct_request_line(ngx_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/2.0";

    if (r->method_name.len == 0
        || r->schema.len == 0
        || r->unparsed_uri.len == 0)
    {
        if (r->method_name.len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :method header");

        } else if (r->schema.len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :scheme header");

        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent no :path header");
        }

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = ngx_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    ngx_memcpy(p, ending, sizeof(ending));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 request line: \"%V\"", &r->request_line);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_cookie(ngx_http_request_t *r, ngx_http_v2_header_t *header)
{
    ngx_str_t    *val;
    ngx_array_t  *cookies;

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        cookies = ngx_array_create(r->pool, 2, sizeof(ngx_str_t));
        if (cookies == NULL) {
            return NGX_ERROR;
        }

        r->stream->cookies = cookies;
    }

    val = ngx_array_push(cookies);
    if (val == NULL) {
        return NGX_ERROR;
    }

    val->len = header->value.len;
    val->data = header->value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    ngx_str_t                  *vals;
    ngx_uint_t                  i;
    ngx_array_t                *cookies;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_header_line()
         */
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_construct_host_header(ngx_http_request_t *r)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t host = ngx_string("host");

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash('h', 'o'), 's'), 't');

    h->key.len = host.len;
    h->key.data = host.data;

    h->value.len = r->host_end - r->host_start;
    h->value.data = r->host_start;

    h->lowcase_key = host.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_host()
         */
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_v2_run_request(ngx_http_request_t *r)
{
    ngx_str_t                  host;
    ngx_connection_t          *fc;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_v2_connection_t  *h2c;

    fc = r->connection;

    h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);

    if (!h2scf->enable && !r->http_connection->addr_conf->http2) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client attempted to request the server name "
                      "for which the negotiated protocol is disabled");

        ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
        goto failed;
    }

    if (ngx_http_v2_construct_request_line(r) != NGX_OK) {
        goto failed;
    }

    if (ngx_http_v2_construct_cookie_header(r) != NGX_OK) {
        goto failed;
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (r->headers_in.server.len == 0) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client sent neither \":authority\" nor \"Host\" header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        goto failed;
    }

    if (r->host_end) {

        host.len = r->host_end - r->host_start;
        host.data = r->host_start;

        if (r->headers_in.host) {
            if (r->headers_in.host->value.len != host.len
                || ngx_memcmp(r->headers_in.host->value.data, host.data,
                              host.len)
                   != 0)
            {
                ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                              "client sent \":authority\" and \"Host\" headers "
                              "with different values");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                goto failed;
            }

        } else {
            /* compatibility for $http_host */

            if (ngx_http_v2_construct_host_header(r) != NGX_OK) {
                goto failed;
            }
        }
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                          "client sent invalid \"Content-Length\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            goto failed;
        }

        if (r->headers_in.content_length_n > 0 && r->stream->in_closed) {
            ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                          "client prematurely closed stream");

            r->stream->skip_data = 1;

            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            goto failed;
        }

    } else if (!r->stream->in_closed) {
        r->headers_in.chunked = 1;
    }

    if (r->method == NGX_HTTP_CONNECT) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0, "client sent CONNECT method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        goto failed;
    }

    if (r->method == NGX_HTTP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0, "client sent TRACE method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        goto failed;
    }

    h2c = r->stream->connection;

    h2c->payload_bytes += r->request_length;

    ngx_http_process_request(r);

failed:

    ngx_http_run_posted_requests(fc);
}


ngx_int_t
ngx_http_v2_read_request_body(ngx_http_request_t *r)
{
    off_t                      len;
    size_t                     size;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_v2_connection_t  *h2c;

    stream = r->stream;
    rb = r->request_body;

    if (stream->skip_data) {
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return NGX_OK;
    }

    rb->rest = 1;

    /* set rb->filter_need_buffering */

    rc = ngx_http_top_request_body_filter(r, NULL);

    if (rc != NGX_OK) {
        stream->skip_data = 1;
        return rc;
    }

    h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    len = r->headers_in.content_length_n;

    if (len < 0 || len > (off_t) clcf->client_body_buffer_size) {
        len = clcf->client_body_buffer_size;

    } else {
        len++;
    }

    if (r->request_body_no_buffering || rb->filter_need_buffering) {

        /*
         * We need a room to store data up to the stream's initial window size,
         * at least until this window will be exhausted.
         */

        if (len < (off_t) h2scf->preread_size) {
            len = h2scf->preread_size;
        }

        if (len > NGX_HTTP_V2_MAX_WINDOW) {
            len = NGX_HTTP_V2_MAX_WINDOW;
        }
    }

    rb->buf = ngx_create_temp_buf(r->pool, (size_t) len);

    if (rb->buf == NULL) {
        stream->skip_data = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf = stream->preread;

    if (stream->in_closed) {
        if (!rb->filter_need_buffering) {
            r->request_body_no_buffering = 0;
        }

        if (buf) {
            rc = ngx_http_v2_process_request_body(r, buf->pos,
                                                  buf->last - buf->pos, 1, 0);
            ngx_pfree(r->pool, buf->start);

        } else {
            rc = ngx_http_v2_process_request_body(r, NULL, 0, 1, 0);
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        r->read_event_handler = ngx_http_v2_read_client_request_body_handler;
        r->write_event_handler = ngx_http_request_empty_handler;

        return NGX_AGAIN;
    }

    if (buf) {
        rc = ngx_http_v2_process_request_body(r, buf->pos,
                                              buf->last - buf->pos, 0, 0);

        ngx_pfree(r->pool, buf->start);

        if (rc != NGX_OK && rc != NGX_AGAIN) {
            stream->skip_data = 1;
            return rc;
        }
    }

    if (r->request_body_no_buffering || rb->filter_need_buffering) {
        size = (size_t) len - h2scf->preread_size;

    } else {
        stream->no_flow_control = 1;
        size = NGX_HTTP_V2_MAX_WINDOW - stream->recv_window;
    }

    if (size) {
        if (ngx_http_v2_send_window_update(stream->connection,
                                           stream->node->id, size)
            == NGX_ERROR)
        {
            stream->skip_data = 1;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        h2c = stream->connection;

        if (!h2c->blocked) {
            if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
                stream->skip_data = 1;
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        stream->recv_window += size;
    }

    if (!buf) {
        ngx_add_timer(r->connection->read, clcf->client_body_timeout);
    }

    r->read_event_handler = ngx_http_v2_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v2_process_request_body(ngx_http_request_t *r, u_char *pos,
    size_t size, ngx_uint_t last, ngx_uint_t flush)
{
    size_t                     n;
    ngx_int_t                  rc;
    ngx_connection_t          *fc;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    fc = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 process request body");

    if (size == 0 && !last && !flush) {
        return NGX_AGAIN;
    }

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end && size) {

                if (r->request_body_no_buffering) {

                    /* should never happen due to flow control */

                    ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
                                  "no space in http2 body buffer");

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* update chains */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                               "http2 body update chains");

                rc = ngx_http_v2_filter_request_body(r);

                if (rc != NGX_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
                                  "busy buffers after request body flush");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            /* copy body data to the buffer */

            n = rb->buf->end - rb->buf->last;

            if (n > size) {
                n = size;
            }

            if (n > 0) {
                rb->buf->last = ngx_cpymem(rb->buf->last, pos, n);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 request body recv %uz", n);

            pos += n;
            size -= n;

            if (size == 0 && last) {
                rb->rest = 0;
            }

            if (size == 0) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 request body rest %O", rb->rest);

        if (flush) {
            rc = ngx_http_v2_filter_request_body(r);

            if (rc != NGX_OK) {
                return rc;
            }
        }

        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        if (size == 0) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(fc->read, clcf->client_body_timeout);

            if (!flush) {
                ngx_post_event(fc->read, &ngx_posted_events);
            }

            return NGX_AGAIN;
        }
    }

    if (fc->read->timer_set) {
        ngx_del_timer(fc->read);
    }

    if (r->request_body_no_buffering) {
        if (!flush) {
            ngx_post_event(fc->read, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (r->headers_in.chunked) {
        r->headers_in.content_length_n = rb->received;
    }

    r->read_event_handler = ngx_http_block_reading;
    rb->post_handler(r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_filter_request_body(ngx_http_request_t *r)
{
    ngx_buf_t                 *b, *buf;
    ngx_int_t                  rc;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;
    buf = rb->buf;

    if (buf->pos == buf->last && (rb->rest || rb->last_sent)) {
        cl = NULL;
        goto update;
    }

    cl = ngx_chain_get_free_buf(r->pool, &rb->free);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    ngx_memzero(b, sizeof(ngx_buf_t));

    if (buf->pos != buf->last) {
        r->request_length += buf->last - buf->pos;
        rb->received += buf->last - buf->pos;

        if (r->headers_in.content_length_n != -1) {
            if (rb->received > r->headers_in.content_length_n) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return NGX_HTTP_BAD_REQUEST;
            }

        } else {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            if (clcf->client_max_body_size
                && rb->received > clcf->client_max_body_size)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked body: "
                              "%O bytes", rb->received);

                return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }

        b->temporary = 1;
        b->pos = buf->pos;
        b->last = buf->last;
        b->start = b->pos;
        b->end = b->last;

        buf->pos = buf->last;
    }

    if (!rb->rest) {
        if (r->headers_in.content_length_n != -1
            && r->headers_in.content_length_n != rb->received)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);

            return NGX_HTTP_BAD_REQUEST;
        }

        b->last_buf = 1;
        rb->last_sent = 1;
    }

    b->tag = (ngx_buf_tag_t) &ngx_http_v2_filter_request_body;
    b->flush = r->request_body_no_buffering;

update:

    rc = ngx_http_top_request_body_filter(r, cl);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
                            (ngx_buf_tag_t) &ngx_http_v2_filter_request_body);

    return rc;
}


static void
ngx_http_v2_read_client_request_body_handler(ngx_http_request_t *r)
{
    size_t                     window;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_connection_t          *fc;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_connection_t  *h2c;

    fc = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read client request body handler");

    if (fc->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");

        fc->timedout = 1;
        r->stream->skip_data = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (fc->error) {
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    rc = ngx_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        r->stream->skip_data = 1;
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc == NGX_OK) {
        return;
    }

    if (r->stream->no_flow_control) {
        return;
    }

    if (r->request_body->rest == 0) {
        return;
    }

    if (r->request_body->busy != NULL) {
        return;
    }

    stream = r->stream;
    h2c = stream->connection;

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    window = buf->end - buf->start;

    if (h2c->state.stream == stream) {
        window -= h2c->state.length;
    }

    if (window <= stream->recv_window) {
        if (window < stream->recv_window) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");

            stream->skip_data = 1;

            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (ngx_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == NGX_ERROR)
    {
        stream->skip_data = 1;
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    stream->recv_window = window;

    if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        stream->skip_data = 1;
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


ngx_int_t
ngx_http_v2_read_unbuffered_request_body(ngx_http_request_t *r)
{
    size_t                     window;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_connection_t          *fc;
    ngx_http_v2_stream_t      *stream;
    ngx_http_v2_connection_t  *h2c;

    stream = r->stream;
    fc = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read unbuffered request body");

    if (fc->read->timedout) {
        if (stream->recv_window) {
            stream->skip_data = 1;
            fc->timedout = 1;

            return NGX_HTTP_REQUEST_TIME_OUT;
        }

        fc->read->timedout = 0;
    }

    if (fc->error) {
        stream->skip_data = 1;
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        stream->skip_data = 1;
        return rc;
    }

    if (rc == NGX_OK) {
        return NGX_OK;
    }

    if (r->request_body->rest == 0) {
        return NGX_AGAIN;
    }

    if (r->request_body->busy != NULL) {
        return NGX_AGAIN;
    }

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    window = buf->end - buf->start;
    h2c = stream->connection;

    if (h2c->state.stream == stream) {
        window -= h2c->state.length;
    }

    if (window <= stream->recv_window) {
        if (window < stream->recv_window) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");
            stream->skip_data = 1;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_AGAIN;
    }

    if (ngx_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == NGX_ERROR)
    {
        stream->skip_data = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        stream->skip_data = 1;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    stream->recv_window = window;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v2_terminate_stream(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_stream_t *stream, ngx_uint_t status)
{
    ngx_event_t       *rev;
    ngx_connection_t  *fc;

    if (stream->rst_sent) {
        return NGX_OK;
    }

    if (ngx_http_v2_send_rst_stream(h2c, stream->node->id, status)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    stream->rst_sent = 1;
    stream->skip_data = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    rev->handler(rev);

    return NGX_OK;
}


void
ngx_http_v2_close_stream(ngx_http_v2_stream_t *stream, ngx_int_t rc)
{
    ngx_pool_t                *pool;
    ngx_event_t               *ev;
    ngx_connection_t          *fc;
    ngx_http_v2_node_t        *node;
    ngx_http_v2_connection_t  *h2c;

    h2c = stream->connection;
    node = stream->node;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 close stream %ui, queued %ui, processing %ui",
                   node->id, stream->queued, h2c->processing);

    fc = stream->request->connection;

    if (stream->queued) {
        fc->error = 1;
        fc->write->handler = ngx_http_v2_retry_close_stream_handler;
        fc->read->handler = ngx_http_v2_retry_close_stream_handler;
        return;
    }

    if (!stream->rst_sent && !h2c->connection->error) {

        if (!stream->out_closed) {
            if (ngx_http_v2_send_rst_stream(h2c, node->id,
                                      fc->timedout ? NGX_HTTP_V2_PROTOCOL_ERROR
                                                   : NGX_HTTP_V2_INTERNAL_ERROR)
                != NGX_OK)
            {
                h2c->connection->error = 1;
            }

        } else if (!stream->in_closed) {
            if (ngx_http_v2_send_rst_stream(h2c, node->id, NGX_HTTP_V2_NO_ERROR)
                != NGX_OK)
            {
                h2c->connection->error = 1;
            }
        }
    }

    if (h2c->state.stream == stream) {
        h2c->state.stream = NULL;
    }

    node->stream = NULL;

    ngx_queue_insert_tail(&h2c->closed, &node->reuse);
    h2c->closed_nodes++;

    /*
     * This pool keeps decoded request headers which can be used by log phase
     * handlers in ngx_http_free_request().
     *
     * The pointer is stored into local variable because the stream object
     * will be destroyed after a call to ngx_http_free_request().
     */
    pool = stream->pool;

    h2c->frames -= stream->frames;

    ngx_http_free_request(stream->request, rc);

    if (pool != h2c->state.pool) {
        ngx_destroy_pool(pool);

    } else {
        /* pool will be destroyed when the complete header is parsed */
        h2c->state.keep_pool = 0;
    }

    ev = fc->read;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->posted) {
        ngx_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->posted) {
        ngx_delete_posted_event(ev);
    }

    fc->data = h2c->free_fake_connections;
    h2c->free_fake_connections = fc;

    h2c->processing--;

    if (h2c->processing || h2c->blocked) {
        return;
    }

    ev = h2c->connection->read;

    ev->handler = ngx_http_v2_handle_connection_handler;
    ngx_post_event(ev, &ngx_posted_events);
}


static void
ngx_http_v2_close_stream_handler(ngx_event_t *ev)
{
    ngx_connection_t    *fc;
    ngx_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 close stream handler");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");

        fc->timedout = 1;

        ngx_http_v2_close_stream(r->stream, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_http_v2_close_stream(r->stream, 0);
}


static void
ngx_http_v2_retry_close_stream_handler(ngx_event_t *ev)
{
    ngx_connection_t    *fc;
    ngx_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 retry close stream handler");

    ngx_http_v2_close_stream(r->stream, 0);
}


static void
ngx_http_v2_handle_connection_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_v2_connection_t  *h2c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http2 handle connection handler");

    c = rev->data;
    h2c = c->data;

    if (c->error) {
        ngx_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rev->handler = ngx_http_v2_read_handler;

    if (rev->ready) {
        ngx_http_v2_read_handler(rev);
        return;
    }

    if (h2c->last_out && ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
        ngx_http_v2_finalize_connection(h2c, 0);
        return;
    }

    ngx_http_v2_handle_connection(c->data);
}


static void
ngx_http_v2_idle_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_http_v2_srv_conf_t    *h2scf;
    ngx_http_v2_connection_t  *h2c;
    ngx_http_core_loc_conf_t  *clcf;

    c = rev->data;
    h2c = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 idle handler");

    if (rev->timedout || c->close) {
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "idle connection", &c->addr_text);
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_http_close_connection(c);
            return;
        }
    }

#endif

    clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (h2c->idle++ > 10 * clcf->keepalive_requests) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
        return;
    }

    c->destroyed = 0;
    ngx_reusable_connection(c, 0);

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    h2c->pool = ngx_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    c->write->handler = ngx_http_v2_write_handler;

    rev->handler = ngx_http_v2_read_handler;
    ngx_http_v2_read_handler(rev);
}


static void
ngx_http_v2_finalize_connection(ngx_http_v2_connection_t *h2c,
    ngx_uint_t status)
{
    ngx_uint_t               i, size;
    ngx_event_t             *ev;
    ngx_connection_t        *c, *fc;
    ngx_http_request_t      *r;
    ngx_http_v2_node_t      *node;
    ngx_http_v2_stream_t    *stream;
    ngx_http_v2_srv_conf_t  *h2scf;

    c = h2c->connection;

    h2c->blocked = 1;

    if (!c->error && !h2c->goaway) {
        h2c->goaway = 1;

        if (ngx_http_v2_send_goaway(h2c, status) != NGX_ERROR) {
            (void) ngx_http_v2_send_output_queue(h2c);
        }
    }

    if (!h2c->processing) {
        goto done;
    }

    c->read->handler = ngx_http_empty_handler;
    c->write->handler = ngx_http_empty_handler;

    h2c->last_out = NULL;

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    size = ngx_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            stream->waiting = 0;

            r = stream->request;
            fc = r->connection;

            fc->error = 1;

            if (stream->queued) {
                stream->queued = 0;

                ev = fc->write;
                ev->active = 0;
                ev->ready = 1;

            } else {
                ev = fc->read;
            }

            ev->eof = 1;
            ev->handler(ev);
        }
    }

    h2c->blocked = 0;

    if (h2c->processing) {
        c->error = 1;
        return;
    }

done:

    if (c->error) {
        ngx_http_close_connection(c);
        return;
    }

    ngx_http_v2_lingering_close(c);
}


static ngx_int_t
ngx_http_v2_adjust_windows(ngx_http_v2_connection_t *h2c, ssize_t delta)
{
    ngx_uint_t               i, size;
    ngx_event_t             *wev;
    ngx_http_v2_node_t      *node;
    ngx_http_v2_stream_t    *stream;
    ngx_http_v2_srv_conf_t  *h2scf;

    h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         ngx_http_v2_module);

    size = ngx_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            if (delta > 0
                && stream->send_window
                      > (ssize_t) (NGX_HTTP_V2_MAX_WINDOW - delta))
            {
                if (ngx_http_v2_terminate_stream(h2c, stream,
                                                 NGX_HTTP_V2_FLOW_CTRL_ERROR)
                    == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            stream->send_window += delta;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui adjusted window: %z",
                           node->id, stream->send_window);

            if (stream->send_window > 0 && stream->exhausted) {
                stream->exhausted = 0;

                wev = stream->request->connection->write;

                wev->active = 0;
                wev->ready = 1;

                if (!wev->delayed) {
                    wev->handler(wev);
                }
            }
        }
    }

    return NGX_OK;
}


static void
ngx_http_v2_set_dependency(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_node_t *node, ngx_uint_t depend, ngx_uint_t exclusive)
{
    ngx_queue_t         *children, *q;
    ngx_http_v2_node_t  *parent, *child, *next;

    parent = depend ? ngx_http_v2_get_node_by_id(h2c, depend, 0) : NULL;

    if (parent == NULL) {
        parent = NGX_HTTP_V2_ROOT;

        if (depend != 0) {
            exclusive = 0;
        }

        node->rank = 1;
        node->rel_weight = (1.0 / 256) * node->weight;

        children = &h2c->dependencies;

    } else {
        if (node->parent != NULL) {

            for (next = parent->parent;
                 next != NGX_HTTP_V2_ROOT && next->rank >= node->rank;
                 next = next->parent)
            {
                if (next != node) {
                    continue;
                }

                ngx_queue_remove(&parent->queue);
                ngx_queue_insert_after(&node->queue, &parent->queue);

                parent->parent = node->parent;

                if (node->parent == NGX_HTTP_V2_ROOT) {
                    parent->rank = 1;
                    parent->rel_weight = (1.0 / 256) * parent->weight;

                } else {
                    parent->rank = node->parent->rank + 1;
                    parent->rel_weight = (node->parent->rel_weight / 256)
                                         * parent->weight;
                }

                if (!exclusive) {
                    ngx_http_v2_node_children_update(parent);
                }

                break;
            }
        }

        node->rank = parent->rank + 1;
        node->rel_weight = (parent->rel_weight / 256) * node->weight;

        if (parent->stream == NULL) {
            ngx_queue_remove(&parent->reuse);
            ngx_queue_insert_tail(&h2c->closed, &parent->reuse);
        }

        children = &parent->children;
    }

    if (exclusive) {
        for (q = ngx_queue_head(children);
             q != ngx_queue_sentinel(children);
             q = ngx_queue_next(q))
        {
            child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
            child->parent = node;
        }

        ngx_queue_add(&node->children, children);
        ngx_queue_init(children);
    }

    if (node->parent != NULL) {
        ngx_queue_remove(&node->queue);
    }

    ngx_queue_insert_tail(children, &node->queue);

    node->parent = parent;

    ngx_http_v2_node_children_update(node);
}


static void
ngx_http_v2_node_children_update(ngx_http_v2_node_t *node)
{
    ngx_queue_t         *q;
    ngx_http_v2_node_t  *child;

    for (q = ngx_queue_head(&node->children);
         q != ngx_queue_sentinel(&node->children);
         q = ngx_queue_next(q))
    {
        child = ngx_queue_data(q, ngx_http_v2_node_t, queue);

        child->rank = node->rank + 1;
        child->rel_weight = (node->rel_weight / 256) * child->weight;

        ngx_http_v2_node_children_update(child);
    }
}


static void
ngx_http_v2_pool_cleanup(void *data)
{
    ngx_http_v2_connection_t  *h2c = data;

    if (h2c->state.pool) {
        ngx_destroy_pool(h2c->state.pool);
    }

    if (h2c->pool) {
        ngx_destroy_pool(h2c->pool);
    }
}
