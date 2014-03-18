
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_spdy_module.h>

#include <zlib.h>


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    *(uint32_t *) m == (c3 << 24 | c2 << 16 | c1 << 8 | c0)                   \
        && m[4] == c4

#else

#define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

#endif


#if (NGX_HAVE_NONALIGNED)

#define ngx_spdy_frame_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_spdy_frame_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#else

#define ngx_spdy_frame_parse_uint16(p) ((p)[0] << 8 | (p)[1])
#define ngx_spdy_frame_parse_uint32(p)                                        \
    ((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif

#define ngx_spdy_frame_parse_sid(p)                                           \
    (ngx_spdy_frame_parse_uint32(p) & 0x7fffffff)


#define ngx_spdy_ctl_frame_check(h)                                           \
    (((h) & 0xffffff00) == ngx_spdy_ctl_frame_head(0))
#define ngx_spdy_data_frame_check(h)                                          \
    (!((h) & (uint32_t) NGX_SPDY_CTL_BIT << 31))

#define ngx_spdy_ctl_frame_type(h)   ((h) & 0x000000ff)
#define ngx_spdy_frame_flags(p)      ((p) >> 24)
#define ngx_spdy_frame_length(p)     ((p) & 0x00ffffff)


#define NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE  4096
#define NGX_SPDY_CTL_FRAME_BUFFER_SIZE     16

#define NGX_SPDY_PROTOCOL_ERROR            1
#define NGX_SPDY_INVALID_STREAM            2
#define NGX_SPDY_REFUSED_STREAM            3
#define NGX_SPDY_UNSUPPORTED_VERSION       4
#define NGX_SPDY_CANCEL                    5
#define NGX_SPDY_INTERNAL_ERROR            6
#define NGX_SPDY_FLOW_CONTROL_ERROR        7

#define NGX_SPDY_SETTINGS_MAX_STREAMS      4

#define NGX_SPDY_SETTINGS_FLAG_PERSIST     0x01

typedef struct {
    ngx_uint_t    hash;
    u_char        len;
    u_char        header[7];
    ngx_int_t   (*handler)(ngx_http_request_t *r);
} ngx_http_spdy_request_header_t;


static void ngx_http_spdy_read_handler(ngx_event_t *rev);
static void ngx_http_spdy_write_handler(ngx_event_t *wev);
static void ngx_http_spdy_handle_connection(ngx_http_spdy_connection_t *sc);

static u_char *ngx_http_spdy_state_detect_settings(
    ngx_http_spdy_connection_t *sc, u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_head(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_syn_stream(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers_error(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers_skip(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_data(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_rst_stream(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_ping(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_skip(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_settings(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_noop(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_complete(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_save(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end, ngx_http_spdy_handler_pt handler);
static u_char *ngx_http_spdy_state_protocol_error(
    ngx_http_spdy_connection_t *sc);
static u_char *ngx_http_spdy_state_internal_error(
    ngx_http_spdy_connection_t *sc);

static ngx_int_t ngx_http_spdy_send_rst_stream(ngx_http_spdy_connection_t *sc,
    ngx_uint_t sid, ngx_uint_t status, ngx_uint_t priority);
static ngx_int_t ngx_http_spdy_send_settings(ngx_http_spdy_connection_t *sc);
static ngx_int_t ngx_http_spdy_settings_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);
static ngx_http_spdy_out_frame_t *ngx_http_spdy_get_ctl_frame(
    ngx_http_spdy_connection_t *sc, size_t size, ngx_uint_t priority);
static ngx_int_t ngx_http_spdy_ctl_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);

static ngx_http_spdy_stream_t *ngx_http_spdy_create_stream(
    ngx_http_spdy_connection_t *sc, ngx_uint_t id, ngx_uint_t priority);
static ngx_http_spdy_stream_t *ngx_http_spdy_get_stream_by_id(
    ngx_http_spdy_connection_t *sc, ngx_uint_t sid);
#define ngx_http_spdy_streams_index_size(sscf)  (sscf->streams_index_mask + 1)
#define ngx_http_spdy_stream_index(sscf, sid)                                 \
    ((sid >> 1) & sscf->streams_index_mask)

static ngx_int_t ngx_http_spdy_parse_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_alloc_large_header_buffer(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_handle_request_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_method(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_scheme(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_url(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_version(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_construct_request_line(ngx_http_request_t *r);
static void ngx_http_spdy_run_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_init_request_body(ngx_http_request_t *r);

static void ngx_http_spdy_handle_connection_handler(ngx_event_t *rev);
static void ngx_http_spdy_keepalive_handler(ngx_event_t *rev);
static void ngx_http_spdy_finalize_connection(ngx_http_spdy_connection_t *sc,
    ngx_int_t rc);

static void ngx_http_spdy_pool_cleanup(void *data);

static void *ngx_http_spdy_zalloc(void *opaque, u_int items, u_int size);
static void ngx_http_spdy_zfree(void *opaque, void *address);


static const u_char ngx_http_spdy_dict[] =
    "options" "get" "head" "post" "put" "delete" "trace"
    "accept" "accept-charset" "accept-encoding" "accept-language"
    "authorization" "expect" "from" "host"
    "if-modified-since" "if-match" "if-none-match" "if-range"
    "if-unmodifiedsince" "max-forwards" "proxy-authorization"
    "range" "referer" "te" "user-agent"
    "100" "101" "200" "201" "202" "203" "204" "205" "206"
    "300" "301" "302" "303" "304" "305" "306" "307"
    "400" "401" "402" "403" "404" "405" "406" "407" "408" "409" "410"
    "411" "412" "413" "414" "415" "416" "417"
    "500" "501" "502" "503" "504" "505"
    "accept-ranges" "age" "etag" "location" "proxy-authenticate" "public"
    "retry-after" "server" "vary" "warning" "www-authenticate" "allow"
    "content-base" "content-encoding" "cache-control" "connection" "date"
    "trailer" "transfer-encoding" "upgrade" "via" "warning"
    "content-language" "content-length" "content-location"
    "content-md5" "content-range" "content-type" "etag" "expires"
    "last-modified" "set-cookie"
    "Monday" "Tuesday" "Wednesday" "Thursday" "Friday" "Saturday" "Sunday"
    "Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"
    "chunked" "text/html" "image/png" "image/jpg" "image/gif"
    "application/xml" "application/xhtml" "text/plain" "public" "max-age"
    "charset=iso-8859-1" "utf-8" "gzip" "deflate" "HTTP/1.1" "status"
    "version" "url";


static ngx_http_spdy_request_header_t ngx_http_spdy_request_headers[] = {
    { 0, 6, "method", ngx_http_spdy_parse_method },
    { 0, 6, "scheme", ngx_http_spdy_parse_scheme },
    { 0, 3, "url", ngx_http_spdy_parse_url },
    { 0, 7, "version", ngx_http_spdy_parse_version },
};

#define NGX_SPDY_REQUEST_HEADERS                                              \
    (sizeof(ngx_http_spdy_request_headers)                                    \
     / sizeof(ngx_http_spdy_request_header_t))


void
ngx_http_spdy_init(ngx_event_t *rev)
{
    int                          rc;
    ngx_connection_t            *c;
    ngx_pool_cleanup_t          *cln;
    ngx_http_connection_t       *hc;
    ngx_http_spdy_srv_conf_t    *sscf;
    ngx_http_spdy_main_conf_t   *smcf;
    ngx_http_spdy_connection_t  *sc;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "init spdy request");

    c->log->action = "processing SPDY";

    smcf = ngx_http_get_module_main_conf(hc->conf_ctx, ngx_http_spdy_module);

    if (smcf->recv_buffer == NULL) {
        smcf->recv_buffer = ngx_palloc(ngx_cycle->pool, smcf->recv_buffer_size);
        if (smcf->recv_buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    sc = ngx_pcalloc(c->pool, sizeof(ngx_http_spdy_connection_t));
    if (sc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    sc->connection = c;
    sc->http_connection = hc;

    sc->handler = ngx_http_spdy_state_detect_settings;

    sc->zstream_in.zalloc = ngx_http_spdy_zalloc;
    sc->zstream_in.zfree = ngx_http_spdy_zfree;
    sc->zstream_in.opaque = sc;

    rc = inflateInit(&sc->zstream_in);
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "inflateInit() failed: %d", rc);
        ngx_http_close_connection(c);
        return;
    }

    sc->zstream_out.zalloc = ngx_http_spdy_zalloc;
    sc->zstream_out.zfree = ngx_http_spdy_zfree;
    sc->zstream_out.opaque = sc;

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_spdy_module);

    rc = deflateInit2(&sc->zstream_out, (int) sscf->headers_comp,
                      Z_DEFLATED, 11, 4, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "deflateInit2() failed: %d", rc);
        ngx_http_close_connection(c);
        return;
    }

    rc = deflateSetDictionary(&sc->zstream_out, ngx_http_spdy_dict,
                              sizeof(ngx_http_spdy_dict));
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "deflateSetDictionary() failed: %d", rc);
        ngx_http_close_connection(c);
        return;
    }

    sc->pool = ngx_create_pool(sscf->pool_size, sc->connection->log);
    if (sc->pool == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln->handler = ngx_http_spdy_pool_cleanup;
    cln->data = sc;

    sc->streams_index = ngx_pcalloc(sc->pool,
                                    ngx_http_spdy_streams_index_size(sscf)
                                    * sizeof(ngx_http_spdy_stream_t *));
    if (sc->streams_index == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->data = sc;

    rev->handler = ngx_http_spdy_read_handler;
    c->write->handler = ngx_http_spdy_write_handler;

    ngx_http_spdy_read_handler(rev);
}


static void
ngx_http_spdy_read_handler(ngx_event_t *rev)
{
    u_char                      *p, *end;
    size_t                       available;
    ssize_t                      n;
    ngx_connection_t            *c;
    ngx_http_spdy_main_conf_t   *smcf;
    ngx_http_spdy_connection_t  *sc;

    c = rev->data;
    sc = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy read handler");

    sc->blocked = 1;

    smcf = ngx_http_get_module_main_conf(sc->http_connection->conf_ctx,
                                         ngx_http_spdy_module);

    available = smcf->recv_buffer_size - 2 * NGX_SPDY_STATE_BUFFER_SIZE;

    do {
        p = smcf->recv_buffer;

        ngx_memcpy(p, sc->buffer, NGX_SPDY_STATE_BUFFER_SIZE);
        end = p + sc->buffer_used;

        n = c->recv(c, end, available);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0 && (sc->waiting || sc->processing)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed prematurely connection");
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_http_spdy_finalize_connection(sc,
                                              NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        end += n;

        sc->buffer_used = 0;
        sc->waiting = 0;

        do {
            p = sc->handler(sc, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

    } while (rev->ready);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    sc->blocked = 0;

    if (sc->processing) {
        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        return;
    }

    ngx_http_spdy_handle_connection(sc);
}


static void
ngx_http_spdy_write_handler(ngx_event_t *wev)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_http_spdy_stream_t      *stream, *s, *sn;
    ngx_http_spdy_connection_t  *sc;

    c = wev->data;
    sc = c->data;

    if (wev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy write event timed out");
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy write handler");

    sc->blocked = 2;

    rc = ngx_http_spdy_send_output_queue(sc);

    if (rc == NGX_ERROR) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    stream = NULL;

    for (s = sc->last_stream; s; s = sn) {
         sn = s->next;
         s->next = stream;
         stream = s;
    }

    sc->last_stream = NULL;

    sc->blocked = 1;

    for ( /* void */ ; stream; stream = sn) {
        sn = stream->next;
        stream->handled = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy run stream %ui", stream->id);

        wev = stream->request->connection->write;
        wev->handler(wev);
    }

    sc->blocked = 0;

    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_http_spdy_handle_connection(sc);
}


ngx_int_t
ngx_http_spdy_send_output_queue(ngx_http_spdy_connection_t *sc)
{
    ngx_chain_t                *cl;
    ngx_event_t                *wev;
    ngx_connection_t           *c;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_spdy_out_frame_t  *out, *frame, *fn;

    c = sc->connection;

    if (c->error) {
        return NGX_ERROR;
    }

    wev = c->write;

    if (!wev->ready) {
        return NGX_OK;
    }

    cl = NULL;
    out = NULL;

    for (frame = sc->last_out; frame; frame = fn) {
        frame->last->next = cl;
        cl = frame->first;

        fn = frame->next;
        frame->next = out;
        out = frame;

        ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy frame out: %p sid:%ui prio:%ui bl:%ui size:%uz",
                       out, out->stream ? out->stream->id : 0, out->priority,
                       out->blocked, out->size);
    }

    cl = c->send_chain(c, cl, 0);

    if (cl == NGX_CHAIN_ERROR) {
        c->error = 1;

        if (!sc->blocked) {
            ngx_post_event(wev, &ngx_posted_events);
        }

        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(sc->http_connection->conf_ctx,
                                        ngx_http_core_module);

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        return NGX_ERROR; /* FIXME */
    }

    if (cl) {
        ngx_add_timer(wev, clcf->send_timeout);

    } else {
        if (wev->timer_set) {
            ngx_del_timer(wev);
        }
    }

    for ( /* void */ ; out; out = out->next) {
        if (out->handler(sc, out) != NGX_OK) {
            out->blocked = 1;
            out->priority = NGX_SPDY_HIGHEST_PRIORITY;
            break;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy frame sent: %p sid:%ui bl:%ui size:%uz",
                       out, out->stream ? out->stream->id : 0,
                       out->blocked, out->size);
    }

    frame = NULL;

    for ( /* void */ ; out; out = fn) {
        fn = out->next;
        out->next = frame;
        frame = out;
    }

    sc->last_out = frame;

    return NGX_OK;
}


static void
ngx_http_spdy_handle_connection(ngx_http_spdy_connection_t *sc)
{
    ngx_connection_t          *c;
    ngx_http_spdy_srv_conf_t  *sscf;

    if (sc->last_out || sc->processing) {
        return;
    }

    c = sc->connection;

    if (c->error) {
        ngx_http_close_connection(c);
        return;
    }

    if (c->buffered) {
        return;
    }

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);
    if (sc->waiting) {
        ngx_add_timer(c->read, sscf->recv_timeout);
        return;
    }

    if (ngx_terminate || ngx_exiting) {
        ngx_http_close_connection(c);
        return;
    }

    ngx_destroy_pool(sc->pool);

    sc->pool = NULL;
    sc->free_ctl_frames = NULL;
    sc->free_fake_connections = NULL;

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;
    c->idle = 1;
    ngx_reusable_connection(c, 1);

    c->write->handler = ngx_http_empty_handler;
    c->read->handler = ngx_http_spdy_keepalive_handler;

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_add_timer(c->read, sscf->keepalive_timeout);
}


static u_char *
ngx_http_spdy_state_detect_settings(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end)
{
    if (end - pos < NGX_SPDY_FRAME_HEADER_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_detect_settings);
    }

    /*
     * Since this is the first frame in a buffer,
     * then it is properly aligned
     */

    if (*(uint32_t *) pos == htonl(ngx_spdy_ctl_frame_head(NGX_SPDY_SETTINGS)))
    {
        sc->length = ngx_spdy_frame_length(htonl(((uint32_t *) pos)[1]));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy SETTINGS frame received, size: %uz", sc->length);

        pos += NGX_SPDY_FRAME_HEADER_SIZE;

        return ngx_http_spdy_state_settings(sc, pos, end);
    }

    ngx_http_spdy_send_settings(sc);

    return ngx_http_spdy_state_head(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_head(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    uint32_t  head, flen;

    if (end - pos < NGX_SPDY_FRAME_HEADER_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_head);
    }

    head = ngx_spdy_frame_parse_uint32(pos);

    pos += sizeof(uint32_t);

    flen = ngx_spdy_frame_parse_uint32(pos);

    sc->flags = ngx_spdy_frame_flags(flen);
    sc->length = ngx_spdy_frame_length(flen);

    pos += sizeof(uint32_t);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy process frame head:%08Xd f:%ui l:%ui",
                   head, sc->flags, sc->length);

    if (ngx_spdy_ctl_frame_check(head)) {
        switch (ngx_spdy_ctl_frame_type(head)) {

        case NGX_SPDY_SYN_STREAM:
            return ngx_http_spdy_state_syn_stream(sc, pos, end);

        case NGX_SPDY_SYN_REPLY:
            return ngx_http_spdy_state_protocol_error(sc);

        case NGX_SPDY_RST_STREAM:
            return ngx_http_spdy_state_rst_stream(sc, pos, end);

        case NGX_SPDY_SETTINGS:
            return ngx_http_spdy_state_skip(sc, pos, end);

        case NGX_SPDY_NOOP:
            return ngx_http_spdy_state_noop(sc, pos, end);

        case NGX_SPDY_PING:
            return ngx_http_spdy_state_ping(sc, pos, end);

        case NGX_SPDY_GOAWAY:
            return ngx_http_spdy_state_skip(sc, pos, end); /* TODO */

        case NGX_SPDY_HEADERS:
            return ngx_http_spdy_state_protocol_error(sc);

        default: /* TODO logging */
            return ngx_http_spdy_state_skip(sc, pos, end);
        }
    }

    if (ngx_spdy_data_frame_check(head)) {
        sc->stream = ngx_http_spdy_get_stream_by_id(sc, head);
        return ngx_http_spdy_state_data(sc, pos, end);
    }


    /* TODO version & type check */
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy unknown frame");

    return ngx_http_spdy_state_protocol_error(sc);
}


static u_char *
ngx_http_spdy_state_syn_stream(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_uint_t                 sid, prio;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    if (end - pos < NGX_SPDY_SYN_STREAM_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_syn_stream);
    }

    if (sc->length <= NGX_SPDY_SYN_STREAM_SIZE) {
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    sc->length -= NGX_SPDY_SYN_STREAM_SIZE;

    sid = ngx_spdy_frame_parse_sid(pos);
    prio = pos[8] >> 6;

    pos += NGX_SPDY_SYN_STREAM_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy SYN_STREAM frame sid:%ui prio:%ui", sid, prio);

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    if (sc->processing >= sscf->concurrent_streams) {

        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "spdy concurrent streams excessed %ui", sc->processing);

        if (ngx_http_spdy_send_rst_stream(sc, sid, NGX_SPDY_REFUSED_STREAM,
                                          prio)
            != NGX_OK)
        {
            return ngx_http_spdy_state_internal_error(sc);
        }

        return ngx_http_spdy_state_headers_skip(sc, pos, end);
    }

    stream = ngx_http_spdy_create_stream(sc, sid, prio);
    if (stream == NULL) {
        return ngx_http_spdy_state_internal_error(sc);
    }

    stream->in_closed = (sc->flags & NGX_SPDY_FLAG_FIN) ? 1 : 0;

    stream->request->request_length = NGX_SPDY_FRAME_HEADER_SIZE
                                      + NGX_SPDY_SYN_STREAM_SIZE
                                      + sc->length;

    sc->stream = stream;

    sc->last_sid = sid;

    return ngx_http_spdy_state_headers(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_headers(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    int                  z;
    size_t               size;
    ngx_buf_t           *buf;
    ngx_int_t            rc;
    ngx_uint_t           complete;
    ngx_http_request_t  *r;

    size = end - pos;

    if (size == 0) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers);
    }

    if (size >= sc->length) {
        size = sc->length;
        complete = 1;

    } else {
        complete = 0;
    }

    r = sc->stream->request;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy process HEADERS %uz of %uz", size, sc->length);

    buf = r->header_in;

    sc->zstream_in.next_in = pos;
    sc->zstream_in.avail_in = size;
    sc->zstream_in.next_out = buf->last;
    sc->zstream_in.avail_out = buf->end - buf->last - 1;

    z = inflate(&sc->zstream_in, Z_NO_FLUSH);

    if (z == Z_NEED_DICT) {
        z = inflateSetDictionary(&sc->zstream_in, ngx_http_spdy_dict,
                                 sizeof(ngx_http_spdy_dict));
        if (z != Z_OK) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "spdy inflateSetDictionary() failed: %d", z);
            ngx_http_spdy_close_stream(sc->stream, 0);
            return ngx_http_spdy_state_protocol_error(sc);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "spdy inflateSetDictionary(): %d", z);

        z = sc->zstream_in.avail_in ? inflate(&sc->zstream_in, Z_NO_FLUSH)
                                    : Z_OK;
    }

    if (z != Z_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "spdy inflate() failed: %d", z);
        ngx_http_spdy_close_stream(sc->stream, 0);
        return ngx_http_spdy_state_protocol_error(sc);
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   sc->zstream_in.next_in, sc->zstream_in.next_out,
                   sc->zstream_in.avail_in, sc->zstream_in.avail_out,
                   z);

    sc->length -= sc->zstream_in.next_in - pos;
    pos = sc->zstream_in.next_in;

    buf->last = sc->zstream_in.next_out;

    if (r->headers_in.headers.part.elts == NULL) {

        if (buf->last - buf->pos < NGX_SPDY_NV_NUM_SIZE) {
            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_headers);
        }

        sc->headers = ngx_spdy_frame_parse_uint16(buf->pos);

        buf->pos += NGX_SPDY_NV_NUM_SIZE;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "spdy headers count: %ui", sc->headers);

        if (ngx_list_init(&r->headers_in.headers, r->pool, sc->headers + 3,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            ngx_http_spdy_close_stream(sc->stream,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
            return ngx_http_spdy_state_headers_error(sc, pos, end);
        }

        if (ngx_array_init(&r->headers_in.cookies, r->pool, 2,
                           sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            ngx_http_spdy_close_stream(sc->stream,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
            return ngx_http_spdy_state_headers_error(sc, pos, end);
        }
    }

    while (sc->headers) {

        rc = ngx_http_spdy_parse_header(r);

        switch (rc) {

        case NGX_DONE:
            sc->headers--;

        case NGX_OK:
            break;

        case NGX_AGAIN:

            if (sc->zstream_in.avail_in) {

                rc = ngx_http_spdy_alloc_large_header_buffer(r);

                if (rc == NGX_DECLINED) {
                    /* TODO logging */
                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    return ngx_http_spdy_state_headers_error(sc, pos, end);
                }

                if (rc != NGX_OK) {
                    ngx_http_spdy_close_stream(sc->stream,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return ngx_http_spdy_state_headers_error(sc, pos, end);
                }

                buf = r->header_in;

                sc->zstream_in.next_out = buf->last;
                sc->zstream_in.avail_out = buf->end - buf->last - 1;

                z = inflate(&sc->zstream_in, Z_NO_FLUSH);

                if (z != Z_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "spdy inflate() failed: %d", z);
                    ngx_http_spdy_close_stream(sc->stream, 0);
                    return ngx_http_spdy_state_protocol_error(sc);
                }

                sc->length -= sc->zstream_in.next_in - pos;
                pos = sc->zstream_in.next_in;

                buf->last = sc->zstream_in.next_out;

                continue;
            }

            if (complete) {
                /* TODO: improve error message */
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "spdy again while last chunk");
                ngx_http_spdy_close_stream(sc->stream, 0);
                return ngx_http_spdy_state_protocol_error(sc);
            }

            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_headers);

        case NGX_HTTP_PARSE_INVALID_REQUEST:

            /* TODO: improve error message */
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header line");

            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

            return ngx_http_spdy_state_headers_error(sc, pos, end);

        default: /* NGX_HTTP_PARSE_INVALID_HEADER */

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid HEADERS spdy frame");
            ngx_http_spdy_close_stream(sc->stream, NGX_HTTP_BAD_REQUEST);
            return ngx_http_spdy_state_protocol_error(sc);
        }

        /* a header line has been parsed successfully */

        rc = ngx_http_spdy_handle_request_header(r);

        if (rc != NGX_OK) {
            if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent invalid HEADERS spdy frame");
                ngx_http_spdy_close_stream(sc->stream, NGX_HTTP_BAD_REQUEST);
                return ngx_http_spdy_state_protocol_error(sc);
            }

            if (rc == NGX_HTTP_PARSE_INVALID_REQUEST) {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            }

            return ngx_http_spdy_state_headers_error(sc, pos, end);
        }
    }

    if (buf->pos != buf->last) {
        /* TODO: improve error message */
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "end %ui %p %p", complete, buf->pos, buf->last);
        ngx_http_spdy_close_stream(sc->stream, NGX_HTTP_BAD_REQUEST);
        return ngx_http_spdy_state_protocol_error(sc);
    }

    if (!complete) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers);
    }

    ngx_http_spdy_run_request(r);

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_headers_error(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    if (sc->connection->error) {
        return ngx_http_spdy_state_internal_error(sc);
    }

    return ngx_http_spdy_state_headers_skip(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_headers_skip(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    int     n;
    size_t  size;
    u_char  buffer[NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE];

    if (sc->length == 0) {
        return ngx_http_spdy_state_complete(sc, pos, end);
    }

    size = end - pos;

    if (size == 0) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers_skip);
    }

    sc->zstream_in.next_in = pos;
    sc->zstream_in.avail_in = (size < sc->length) ? size : sc->length;

    while (sc->zstream_in.avail_in) {
        sc->zstream_in.next_out = buffer;
        sc->zstream_in.avail_out = NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE;

        n = inflate(&sc->zstream_in, Z_NO_FLUSH);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy inflate(): %d", n);

        if (n != Z_OK) {
            /* TODO: logging */
            return ngx_http_spdy_state_protocol_error(sc);
        }
    }

    pos = sc->zstream_in.next_in;

    if (size < sc->length) {
        sc->length -= size;
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers_skip);
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_data(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_uint_t                 complete;
    ngx_temp_file_t           *tf;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    stream = sc->stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy DATA frame");

    if (stream == NULL) {
        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    if (stream->in_closed) {
        /* TODO log */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    if (stream->skip_data) {

        if (sc->flags & NGX_SPDY_FLAG_FIN) {
            stream->in_closed = 1;
        }

        /* TODO log and accounting */
        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    size = end - pos;

    if (size >= sc->length) {
        size = sc->length;
        complete = 1;

    } else {
        sc->length -= size;
        complete = 0;
    }

    r = stream->request;

    if (r->request_body == NULL
        && ngx_http_spdy_init_request_body(r) != NGX_OK)
    {
        stream->skip_data = NGX_SPDY_DATA_INTERNAL_ERROR;
        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    rb = r->request_body;
    tf = rb->temp_file;
    buf = rb->buf;

    if (size) {
        rb->rest += size;

        if (r->headers_in.content_length_n != -1
            && r->headers_in.content_length_n < rb->rest)
        {
            /* TODO logging */
            stream->skip_data = NGX_SPDY_DATA_ERROR;
            goto error;

        } else {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            if (clcf->client_max_body_size
                && clcf->client_max_body_size < rb->rest)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked "
                              "body: %O bytes",
                              rb->rest);

                stream->skip_data = NGX_SPDY_DATA_ERROR;
                goto error;
            }
        }

        if (tf) {
            buf->start = pos;
            buf->pos = pos;

            pos += size;

            buf->end = pos;
            buf->last = pos;

            n = ngx_write_chain_to_temp_file(tf, rb->bufs);

            /* TODO: n == 0 or not complete and level event */

            if (n == NGX_ERROR) {
                stream->skip_data = NGX_SPDY_DATA_INTERNAL_ERROR;
                goto error;
            }

            tf->offset += n;

        } else {
            buf->last = ngx_cpymem(buf->last, pos, size);
            pos += size;
        }

        r->request_length += size;
    }

    if (!complete) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_data);
    }

    if (sc->flags & NGX_SPDY_FLAG_FIN) {

        stream->in_closed = 1;

        if (tf) {
            ngx_memzero(buf, sizeof(ngx_buf_t));

            buf->in_file = 1;
            buf->file_last = tf->file.offset;
            buf->file = &tf->file;

            rb->buf = NULL;
        }

        if (r->headers_in.content_length_n < 0) {
            r->headers_in.content_length_n = rb->rest;
        }

        if (rb->post_handler) {
            rb->post_handler(r);
        }
    }

    return ngx_http_spdy_state_complete(sc, pos, end);

error:

    if (rb->post_handler) {

        if (stream->skip_data == NGX_SPDY_DATA_ERROR) {
            rc = (r->headers_in.content_length_n == -1)
                 ? NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                 : NGX_HTTP_BAD_REQUEST;

        } else {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_finalize_request(r, rc);
    }

    return ngx_http_spdy_state_skip(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_rst_stream(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_uint_t               sid, status;
    ngx_event_t             *ev;
    ngx_connection_t        *fc;
    ngx_http_request_t      *r;
    ngx_http_spdy_stream_t  *stream;

    if (end - pos < NGX_SPDY_RST_STREAM_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_rst_stream);
    }

    if (sc->length != NGX_SPDY_RST_STREAM_SIZE) {
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    sid = ngx_spdy_frame_parse_sid(pos);

    pos += NGX_SPDY_SID_SIZE;

    status = ngx_spdy_frame_parse_uint32(pos);

    pos += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy RST_STREAM sid:%ui st:%ui", sid, status);


    switch (status) {

    case NGX_SPDY_PROTOCOL_ERROR:
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);

    case NGX_SPDY_INVALID_STREAM:
        /* TODO */
        break;

    case NGX_SPDY_REFUSED_STREAM:
        /* TODO */
        break;

    case NGX_SPDY_UNSUPPORTED_VERSION:
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);

    case NGX_SPDY_CANCEL:
    case NGX_SPDY_INTERNAL_ERROR:
        stream = ngx_http_spdy_get_stream_by_id(sc, sid);
        if (stream == NULL) {
            /* TODO false cancel */
            break;
        }

        stream->in_closed = 1;
        stream->out_closed = 1;

        r = stream->request;

        fc = r->connection;
        fc->error = 1;

        ev = fc->read;
        ev->handler(ev);

        break;

    case NGX_SPDY_FLOW_CONTROL_ERROR:
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);

    default:
        /* TODO */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_ping(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_http_spdy_out_frame_t  *frame;

    if (end - pos < NGX_SPDY_PING_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_ping);
    }

    if (sc->length != NGX_SPDY_PING_SIZE) {
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy PING frame");

    frame = ngx_http_spdy_get_ctl_frame(sc, NGX_SPDY_PING_SIZE,
                                        NGX_SPDY_HIGHEST_PRIORITY);
    if (frame == NULL) {
        return ngx_http_spdy_state_internal_error(sc);
    }

    buf = frame->first->buf;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_PING);
    p = ngx_spdy_frame_write_flags_and_len(p, 0, NGX_SPDY_PING_SIZE);

    p = ngx_cpymem(p, pos, NGX_SPDY_PING_SIZE);

    buf->last = p;

    ngx_http_spdy_queue_frame(sc, frame);

    pos += NGX_SPDY_PING_SIZE;

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_skip(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size < sc->length) {
        sc->length -= size;
        return ngx_http_spdy_state_save(sc, end, end,
                                        ngx_http_spdy_state_skip);
    }

    return ngx_http_spdy_state_complete(sc, pos + sc->length, end);
}


static u_char *
ngx_http_spdy_state_settings(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_uint_t                 v;
    ngx_http_spdy_srv_conf_t  *sscf;

    if (sc->headers == 0) {

        if (end - pos < NGX_SPDY_SETTINGS_NUM_SIZE) {
            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_settings);
        }

        sc->headers = ngx_spdy_frame_parse_uint32(pos);

        pos += NGX_SPDY_SETTINGS_NUM_SIZE;
        sc->length -= NGX_SPDY_SETTINGS_NUM_SIZE;

        if (sc->length < sc->headers * NGX_SPDY_SETTINGS_PAIR_SIZE) {
            /* TODO logging */
            return ngx_http_spdy_state_protocol_error(sc);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy SETTINGS frame consists of %ui entries",
                       sc->headers);
    }

    while (sc->headers) {
        if (end - pos < NGX_SPDY_SETTINGS_PAIR_SIZE) {
            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_settings);
        }

        sc->headers--;

        if (pos[0] != NGX_SPDY_SETTINGS_MAX_STREAMS) {
            pos += NGX_SPDY_SETTINGS_PAIR_SIZE;
            sc->length -= NGX_SPDY_SETTINGS_PAIR_SIZE;
            continue;
        }

        v = ngx_spdy_frame_parse_uint32(pos + NGX_SPDY_SETTINGS_IDF_SIZE);

        sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                            ngx_http_spdy_module);

        if (v != sscf->concurrent_streams) {
            ngx_http_spdy_send_settings(sc);
        }

        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    ngx_http_spdy_send_settings(sc);

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_noop(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    if (sc->length) {
        /* TODO logging */
        return ngx_http_spdy_state_protocol_error(sc);
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_complete(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    sc->handler = ngx_http_spdy_state_head;
    return pos;
}


static u_char *
ngx_http_spdy_state_save(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end, ngx_http_spdy_handler_pt handler)
{
#if 1
    if (end - pos > NGX_SPDY_STATE_BUFFER_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, sc->connection->log, 0,
                      "spdy state buffer overflow: "
                      "%i bytes required", end - pos);
        return ngx_http_spdy_state_internal_error(sc);
    }
#endif

    ngx_memcpy(sc->buffer, pos, NGX_SPDY_STATE_BUFFER_SIZE);

    sc->buffer_used = end - pos;
    sc->handler = handler;
    sc->waiting = 1;

    return end;
}


static u_char *
ngx_http_spdy_state_protocol_error(ngx_http_spdy_connection_t *sc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy state protocol error");

    /* TODO */
    ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);
    return NULL;
}


static u_char *
ngx_http_spdy_state_internal_error(ngx_http_spdy_connection_t *sc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy state internal error");

    /* TODO */
    ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return NULL;
}


static ngx_int_t
ngx_http_spdy_send_rst_stream(ngx_http_spdy_connection_t *sc, ngx_uint_t sid,
    ngx_uint_t status, ngx_uint_t priority)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_http_spdy_out_frame_t  *frame;

    if (sc->connection->error) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy write RST_STREAM sid:%ui st:%ui", sid, status);

    frame = ngx_http_spdy_get_ctl_frame(sc, NGX_SPDY_RST_STREAM_SIZE,
                                        priority);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_RST_STREAM);
    p = ngx_spdy_frame_write_flags_and_len(p, 0, NGX_SPDY_RST_STREAM_SIZE);

    p = ngx_spdy_frame_write_sid(p, sid);
    p = ngx_spdy_frame_aligned_write_uint32(p, status);

    buf->last = p;

    ngx_http_spdy_queue_frame(sc, frame);

    return NGX_OK;
}


#if 0
static ngx_int_t
ngx_http_spdy_send_goaway(ngx_http_spdy_connection_t *sc)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_http_spdy_out_frame_t  *frame;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy create GOAWAY sid:%ui", sc->last_sid);

    frame = ngx_http_spdy_get_ctl_frame(sc, NGX_SPDY_GOAWAY_SIZE,
                                        NGX_SPDY_HIGHEST_PRIORITY);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_GOAWAY);
    p = ngx_spdy_frame_write_flags_and_len(p, 0, NGX_SPDY_GOAWAY_SIZE);

    p = ngx_spdy_frame_write_sid(p, sc->last_sid);

    buf->last = p;

    ngx_http_spdy_queue_frame(sc, frame);

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_spdy_send_settings(ngx_http_spdy_connection_t *sc)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_pool_t                 *pool;
    ngx_chain_t                *cl;
    ngx_http_spdy_srv_conf_t   *sscf;
    ngx_http_spdy_out_frame_t  *frame;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy create SETTINGS frame");

    pool = sc->connection->pool;

    frame = ngx_palloc(pool, sizeof(ngx_http_spdy_out_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    buf = ngx_create_temp_buf(pool, NGX_SPDY_FRAME_HEADER_SIZE
                                    + NGX_SPDY_SETTINGS_NUM_SIZE
                                    + NGX_SPDY_SETTINGS_PAIR_SIZE);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_spdy_settings_frame_handler;
#if (NGX_DEBUG)
    frame->stream = NULL;
    frame->size = NGX_SPDY_FRAME_HEADER_SIZE
                  + NGX_SPDY_SETTINGS_NUM_SIZE
                  + NGX_SPDY_SETTINGS_PAIR_SIZE;
#endif
    frame->priority = NGX_SPDY_HIGHEST_PRIORITY;
    frame->blocked = 0;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_SETTINGS);
    p = ngx_spdy_frame_write_flags_and_len(p, NGX_SPDY_FLAG_CLEAR_SETTINGS,
                                              NGX_SPDY_SETTINGS_NUM_SIZE
                                              + NGX_SPDY_SETTINGS_PAIR_SIZE);

    p = ngx_spdy_frame_aligned_write_uint32(p, 1);
    p = ngx_spdy_frame_aligned_write_uint32(p,
                                            NGX_SPDY_SETTINGS_MAX_STREAMS << 24
                                            | NGX_SPDY_SETTINGS_FLAG_PERSIST);

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    p = ngx_spdy_frame_aligned_write_uint32(p, sscf->concurrent_streams);

    buf->last = p;

    ngx_http_spdy_queue_frame(sc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_http_spdy_settings_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    ngx_free_chain(sc->pool, frame->first);

    return NGX_OK;
}


static ngx_http_spdy_out_frame_t *
ngx_http_spdy_get_ctl_frame(ngx_http_spdy_connection_t *sc, size_t size,
    ngx_uint_t priority)
{
    ngx_chain_t                *cl;
    ngx_http_spdy_out_frame_t  *frame;

    frame = sc->free_ctl_frames;

    if (frame) {
        sc->free_ctl_frames = frame->free;

        cl = frame->first;
        cl->buf->pos = cl->buf->start;

    } else {
        frame = ngx_palloc(sc->pool, sizeof(ngx_http_spdy_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        cl = ngx_alloc_chain_link(sc->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = ngx_create_temp_buf(sc->pool,
                                      NGX_SPDY_CTL_FRAME_BUFFER_SIZE);
        if (cl->buf == NULL) {
            return NULL;
        }

        cl->buf->last_buf = 1;

        frame->first = cl;
        frame->last = cl;
        frame->handler = ngx_http_spdy_ctl_frame_handler;
    }

    frame->free = NULL;

#if (NGX_DEBUG)
    if (size > NGX_SPDY_CTL_FRAME_BUFFER_SIZE - NGX_SPDY_FRAME_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, sc->pool->log, 0,
                      "requested control frame is too big: %z", size);
        return NULL;
    }

    frame->stream = NULL;
    frame->size = size;
#endif

    frame->priority = priority;
    frame->blocked = 0;

    return frame;
}


static ngx_int_t
ngx_http_spdy_ctl_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    frame->free = sc->free_ctl_frames;
    sc->free_ctl_frames = frame;

    return NGX_OK;
}


static ngx_http_spdy_stream_t *
ngx_http_spdy_create_stream(ngx_http_spdy_connection_t *sc, ngx_uint_t id,
    ngx_uint_t priority)
{
    ngx_log_t                 *log;
    ngx_uint_t                 index;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_spdy_srv_conf_t  *sscf;

    fc = sc->free_fake_connections;

    if (fc) {
        sc->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(sc->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(sc->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(sc->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(sc->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(sc->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
    }

    ngx_memcpy(log, sc->connection->log, sizeof(ngx_log_t));

    log->data = ctx;

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_empty_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, sc->connection, sizeof(ngx_connection_t));

    fc->data = sc->http_connection;
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

    r->valid_location = 1;

    fc->data = r;
    sc->connection->requests++;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_spdy_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->spdy_stream = stream;

    stream->id = id;
    stream->request = r;
    stream->connection = sc;
    stream->priority = priority;

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_spdy_module);

    index = ngx_http_spdy_stream_index(sscf, id);

    stream->index = sc->streams_index[index];
    sc->streams_index[index] = stream;

    sc->processing++;

    return stream;
}


static ngx_http_spdy_stream_t *
ngx_http_spdy_get_stream_by_id(ngx_http_spdy_connection_t *sc,
    ngx_uint_t sid)
{
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    stream = sc->streams_index[ngx_http_spdy_stream_index(sscf, sid)];

    while (stream) {
        if (stream->id == sid) {
            return stream;
        }

        stream = stream->index;
    }

    return NULL;
}


static ngx_int_t
ngx_http_spdy_parse_header(ngx_http_request_t *r)
{
    u_char                     *p, *end, ch;
    ngx_uint_t                  len, hash;
    ngx_http_core_srv_conf_t   *cscf;

    enum {
        sw_name_len = 0,
        sw_name,
        sw_value_len,
        sw_value
    } state;

    state = r->state;

    p = r->header_in->pos;
    end = r->header_in->last;

    switch (state) {

    case sw_name_len:

        if (end - p < NGX_SPDY_NV_NLEN_SIZE) {
            return NGX_AGAIN;
        }

        len = ngx_spdy_frame_parse_uint16(p);

        if (!len) {
            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        p += NGX_SPDY_NV_NLEN_SIZE;

        r->header_name_end = p + len;
        r->lowcase_index = len;
        r->invalid_header = 0;

        state = sw_name;

        /* fall through */

    case sw_name:

        if (r->header_name_end > end) {
            break;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        r->header_name_start = p;

        hash = 0;

        for ( /* void */ ; p != r->header_name_end; p++) {

            ch = *p;

            hash = ngx_hash(hash, ch);

            if ((ch >= 'a' && ch <= 'z')
                || (ch == '-')
                || (ch >= '0' && ch <= '9')
                || (ch == '_' && cscf->underscores_in_headers))
            {
                continue;
            }

            switch (ch) {
            case '\0':
            case LF:
            case CR:
            case ':':
                return NGX_HTTP_PARSE_INVALID_REQUEST;
            }

            if (ch >= 'A' && ch <= 'Z') {
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            r->invalid_header = 1;
        }

        r->header_hash = hash;

        state = sw_value_len;

        /* fall through */

    case sw_value_len:

        if (end - p < NGX_SPDY_NV_VLEN_SIZE) {
            break;
        }

        len = ngx_spdy_frame_parse_uint16(p);

        if (!len) {
            return NGX_ERROR;
        }

        p += NGX_SPDY_NV_VLEN_SIZE;

        r->header_end = p + len;

        state = sw_value;

        /* fall through */

    case sw_value:

        if (r->header_end > end) {
            break;
        }

        r->header_start = p;

        for ( /* void */ ; p != r->header_end; p++) {

            ch = *p;

            if (ch == '\0') {

                if (p == r->header_start) {
                    return NGX_ERROR;
                }

                r->header_size = p - r->header_start;
                r->header_in->pos = p + 1;

                return NGX_OK;
            }

            if (ch == CR || ch == LF) {
                return NGX_HTTP_PARSE_INVALID_HEADER;
            }
        }

        r->header_size = p - r->header_start;
        r->header_in->pos = p;

        r->state = 0;

        return NGX_DONE;
    }

    r->header_in->pos = p;
    r->state = state;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_spdy_alloc_large_header_buffer(ngx_http_request_t *r)
{
    u_char                    *old, *new;
    size_t                     rest;
    ngx_buf_t                 *buf;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy alloc large header buffer");

    stream = r->spdy_stream;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (stream->header_buffers
        == (ngx_uint_t) cscf->large_client_header_buffers.num)
    {
        return NGX_DECLINED;
    }

    rest = r->header_in->last - r->header_in->pos;

    if (rest >= cscf->large_client_header_buffers.size) {
        return NGX_DECLINED;
    }

    buf = ngx_create_temp_buf(r->pool, cscf->large_client_header_buffers.size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy large header alloc: %p %uz",
                   buf->pos, buf->end - buf->last);

    old = r->header_in->pos;
    new = buf->pos;

    if (rest) {
        buf->last = ngx_cpymem(new, old, rest);
    }

    if (r->header_name_end > old) {
        r->header_name_end = new + (r->header_name_end - old);

    } else if (r->header_end > old) {
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = buf;

    stream->header_buffers++;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_handle_request_header(ngx_http_request_t *r)
{
    ngx_uint_t                       i;
    ngx_table_elt_t                 *h;
    ngx_http_core_srv_conf_t        *cscf;
    ngx_http_spdy_request_header_t  *sh;

    if (r->invalid_header) {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (cscf->ignore_invalid_headers) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%*s\"",
                          r->header_end - r->header_name_start,
                          r->header_name_start);
            return NGX_OK;
        }

    } else {
        for (i = 0; i < NGX_SPDY_REQUEST_HEADERS; i++) {
            sh = &ngx_http_spdy_request_headers[i];

            if (sh->hash != r->header_hash
                || sh->len != r->lowcase_index
                || ngx_strncmp(sh->header, r->header_name_start,
                               r->lowcase_index)
                   != 0)
            {
                continue;
            }

            return sh->handler(r);
        }
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_spdy_close_stream(r->spdy_stream,
                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = r->header_hash;

    h->key.len = r->lowcase_index;
    h->key.data = r->header_name_start;
    h->key.data[h->key.len] = '\0';

    h->value.len = r->header_size;
    h->value.data = r->header_start;
    h->value.data[h->value.len] = '\0';

    h->lowcase_key = h->key.data;

    return NGX_OK;
}


void
ngx_http_spdy_request_headers_init()
{
    ngx_uint_t                       i;
    ngx_http_spdy_request_header_t  *h;

    for (i = 0; i < NGX_SPDY_REQUEST_HEADERS; i++) {
        h = &ngx_http_spdy_request_headers[i];
        h->hash = ngx_hash_key(h->header, h->len);
    }
}


static ngx_int_t
ngx_http_spdy_parse_method(ngx_http_request_t *r)
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
        { 5, "TRACE",     NGX_HTTP_TRACE }
    }, *test;

    if (r->method_name.len) {
        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    len = r->header_size;

    r->method_name.len = len;
    r->method_name.data = r->header_start;

    test = tests;
    n = sizeof(tests) / sizeof(tests[0]);

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
        if ((*p < 'A' || *p > 'Z') && *p != '_') {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method");
            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }

        p++;

    } while (--len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_scheme(ngx_http_request_t *r)
{
    if (r->schema_start) {
        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    r->schema_start = r->header_start;
    r->schema_end = r->header_end;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_url(ngx_http_request_t *r)
{
    if (r->unparsed_uri.len) {
        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    r->uri_start = r->header_start;
    r->uri_end = r->header_end;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_version(ngx_http_request_t *r)
{
    u_char  *p, ch;

    if (r->http_protocol.len) {
        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    p = r->header_start;

    if (r->header_size < 8 || !(ngx_str5cmp(p, 'H', 'T', 'T', 'P', '/'))) {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    ch = *(p + 5);

    if (ch < '1' || ch > '9') {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    r->http_major = ch - '0';

    for (p += 6; p != r->header_end - 2; p++) {

        ch = *p;

        if (ch < '0' || ch > '9') {
            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }

        r->http_major = r->http_major * 10 + ch - '0';
    }

    if (*p != '.') {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    ch = *(p + 1);

    if (ch < '0' || ch > '9') {
        return NGX_HTTP_PARSE_INVALID_REQUEST;
    }

    r->http_minor = ch - '0';

    for (p += 2; p != r->header_end; p++) {

        ch = *p;

        if (ch < '0' || ch > '9') {
            return NGX_HTTP_PARSE_INVALID_REQUEST;
        }

        r->http_minor = r->http_minor * 10 + ch - '0';
    }

    r->http_protocol.len = r->header_size;
    r->http_protocol.data = r->header_start;
    r->http_version = r->http_major * 1000 + r->http_minor;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_construct_request_line(ngx_http_request_t *r)
{
    u_char  *p;

    if (r->method_name.len == 0
        || r->unparsed_uri.len == 0
        || r->http_protocol.len == 0)
    {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len + 1
                          + r->http_protocol.len;

    p = ngx_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    *p++ = ' ';

    ngx_memcpy(p, r->http_protocol.data, r->http_protocol.len + 1);

    /* some modules expect the space character after method name */
    r->method_name.data = r->request_line.data;

    return NGX_OK;
}


static void
ngx_http_spdy_run_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    if (ngx_http_spdy_construct_request_line(r) != NGX_OK) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy http request line: \"%V\"", &r->request_line);

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0 ;; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        hh = ngx_hash_find(&cmcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh && hh->handler(r, &h[i], hh->offset) != NGX_OK) {
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http header: \"%V: %V\"", &h[i].key, &h[i].value);
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (ngx_http_process_request_header(r) != NGX_OK) {
        return;
    }

    ngx_http_process_request(r);
}


static ngx_int_t
ngx_http_spdy_init_request_body(ngx_http_request_t *r)
{
    ngx_buf_t                 *buf;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        return NGX_ERROR;
    }

    r->request_body = rb;

    if (r->spdy_stream->in_closed) {
        return NGX_OK;
    }

    rb->rest = r->headers_in.content_length_n;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->request_body_in_file_only
        || rb->rest > (off_t) clcf->client_body_buffer_size
        || rb->rest < 0)
    {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (r->spdy_stream->in_closed
            && ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                    tf->persistent, tf->clean, tf->access)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

        buf = ngx_calloc_buf(r->pool);
        if (buf == NULL) {
            return NGX_ERROR;
        }

    } else {

        if (rb->rest == 0) {
            return NGX_OK;
        }

        buf = ngx_create_temp_buf(r->pool, (size_t) rb->rest);
        if (buf == NULL) {
            return NGX_ERROR;
        }
    }

    rb->buf = buf;

    rb->bufs = ngx_alloc_chain_link(r->pool);
    if (rb->bufs == NULL) {
        return NGX_ERROR;
    }

    rb->bufs->buf = buf;
    rb->bufs->next = NULL;

    rb->rest = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_spdy_read_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    ngx_http_spdy_stream_t  *stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy read request body");

    stream = r->spdy_stream;

    switch (stream->skip_data) {

    case NGX_SPDY_DATA_DISCARD:
        post_handler(r);
        return NGX_OK;

    case NGX_SPDY_DATA_ERROR:
        if (r->headers_in.content_length_n == -1) {
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        } else {
            return NGX_HTTP_BAD_REQUEST;
        }

    case NGX_SPDY_DATA_INTERNAL_ERROR:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!r->request_body && ngx_http_spdy_init_request_body(r) != NGX_OK) {
        stream->skip_data = NGX_SPDY_DATA_INTERNAL_ERROR;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stream->in_closed) {
        post_handler(r);
        return NGX_OK;
    }

    r->request_body->post_handler = post_handler;

    return NGX_AGAIN;
}


void
ngx_http_spdy_close_stream(ngx_http_spdy_stream_t *stream, ngx_int_t rc)
{
    ngx_event_t                  *ev;
    ngx_connection_t             *fc;
    ngx_http_spdy_stream_t      **index, *s;
    ngx_http_spdy_srv_conf_t     *sscf;
    ngx_http_spdy_connection_t   *sc;

    sc = stream->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy close stream %ui, processing %ui",
                   stream->id, sc->processing);

    if (!stream->out_closed) {
        if (ngx_http_spdy_send_rst_stream(sc, stream->id,
                                          NGX_SPDY_INTERNAL_ERROR,
                                          stream->priority)
            != NGX_OK)
        {
            sc->connection->error = 1;
        }
    }

    if (sc->stream == stream) {
        sc->stream = NULL;
    }

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    index = sc->streams_index + ngx_http_spdy_stream_index(sscf, stream->id);

    for ( ;; ) {
        s = *index;

        if (s == NULL) {
            break;
        }

        if (s == stream) {
            *index = s->index;
            break;
        }

        index = &s->index;
    }

    fc = stream->request->connection;

    ngx_http_free_request(stream->request, rc);

    ev = fc->read;

    if (ev->active || ev->disabled) {
        ngx_del_event(ev, NGX_READ_EVENT, 0);
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->prev) {
        ngx_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->active || ev->disabled) {
        ngx_del_event(ev, NGX_WRITE_EVENT, 0);
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->prev) {
        ngx_delete_posted_event(ev);
    }

    fc->data = sc->free_fake_connections;
    sc->free_fake_connections = fc;

    sc->processing--;

    if (sc->processing || sc->blocked) {
        return;
    }

    ev = sc->connection->read;

    ev->handler = ngx_http_spdy_handle_connection_handler;
    ngx_post_event(ev, &ngx_posted_events);
}


static void
ngx_http_spdy_handle_connection_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    rev->handler = ngx_http_spdy_read_handler;

    if (rev->ready) {
        ngx_http_spdy_read_handler(rev);
        return;
    }

    c = rev->data;

    ngx_http_spdy_handle_connection(c->data);
}


static void
ngx_http_spdy_keepalive_handler(ngx_event_t *rev)
{
    ngx_connection_t            *c;
    ngx_http_spdy_srv_conf_t    *sscf;
    ngx_http_spdy_connection_t  *sc;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "spdy keepalive handler");

    if (rev->timedout || c->close) {
        ngx_http_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
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

    c->destroyed = 0;
    c->idle = 0;
    ngx_reusable_connection(c, 0);

    sc = c->data;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    sc->pool = ngx_create_pool(sscf->pool_size, sc->connection->log);
    if (sc->pool == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    sc->streams_index = ngx_pcalloc(sc->pool,
                                    ngx_http_spdy_streams_index_size(sscf)
                                    * sizeof(ngx_http_spdy_stream_t *));
    if (sc->streams_index == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->write->handler = ngx_http_spdy_write_handler;

    rev->handler = ngx_http_spdy_read_handler;
    ngx_http_spdy_read_handler(rev);
}


static void
ngx_http_spdy_finalize_connection(ngx_http_spdy_connection_t *sc,
    ngx_int_t rc)
{
    ngx_uint_t                 i, size;
    ngx_event_t               *ev;
    ngx_connection_t          *c, *fc;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_spdy_srv_conf_t  *sscf;

    c = sc->connection;

    if (!sc->processing) {
        ngx_http_close_connection(c);
        return;
    }

    c->error = 1;
    c->read->handler = ngx_http_empty_handler;

    sc->last_out = NULL;

    sc->blocked = 1;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    size = ngx_http_spdy_streams_index_size(sscf);

    for (i = 0; i < size; i++) {
        stream = sc->streams_index[i];

        while (stream) {
            r = stream->request;

            fc = r->connection;
            fc->error = 1;

            if (stream->waiting) {
                r->blocked -= stream->waiting;
                stream->waiting = 0;
                ev = fc->write;

            } else {
                ev = fc->read;
            }

            stream = stream->index;

            ev->eof = 1;
            ev->handler(ev);
        }
    }

    sc->blocked = 0;

    if (sc->processing) {
        return;
    }

    ngx_http_close_connection(c);
}


static void
ngx_http_spdy_pool_cleanup(void *data)
{
    ngx_http_spdy_connection_t  *sc = data;

    if (sc->pool) {
        ngx_destroy_pool(sc->pool);
    }
}


static void *
ngx_http_spdy_zalloc(void *opaque, u_int items, u_int size)
{
    ngx_http_spdy_connection_t *sc = opaque;

    return ngx_palloc(sc->connection->pool, items * size);
}


static void
ngx_http_spdy_zfree(void *opaque, void *address)
{
#if 0
    ngx_http_spdy_connection_t *sc = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy zfree: %p", address);
#endif
}
