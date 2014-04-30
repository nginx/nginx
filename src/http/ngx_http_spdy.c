
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
#define ngx_spdy_frame_parse_delta(p)                                         \
    (ngx_spdy_frame_parse_uint32(p) & 0x7fffffff)


#define ngx_spdy_ctl_frame_check(h)                                           \
    (((h) & 0xffff0000) == ngx_spdy_ctl_frame_head(0))
#define ngx_spdy_data_frame_check(h)                                          \
    (!((h) & (uint32_t) NGX_SPDY_CTL_BIT << 31))

#define ngx_spdy_ctl_frame_type(h)   ((h) & 0x0000ffff)
#define ngx_spdy_frame_flags(p)      ((p) >> 24)
#define ngx_spdy_frame_length(p)     ((p) & 0x00ffffff)
#define ngx_spdy_frame_id(p)         ((p) & 0x00ffffff)


#define NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE  4096
#define NGX_SPDY_CTL_FRAME_BUFFER_SIZE     16

#define NGX_SPDY_PROTOCOL_ERROR            1
#define NGX_SPDY_INVALID_STREAM            2
#define NGX_SPDY_REFUSED_STREAM            3
#define NGX_SPDY_UNSUPPORTED_VERSION       4
#define NGX_SPDY_CANCEL                    5
#define NGX_SPDY_INTERNAL_ERROR            6
#define NGX_SPDY_FLOW_CONTROL_ERROR        7
#define NGX_SPDY_STREAM_IN_USE             8
#define NGX_SPDY_STREAM_ALREADY_CLOSED     9
/* deprecated                              10 */
#define NGX_SPDY_FRAME_TOO_LARGE           11

#define NGX_SPDY_SETTINGS_MAX_STREAMS      4
#define NGX_SPDY_SETTINGS_INIT_WINDOW      7

#define NGX_SPDY_SETTINGS_FLAG_PERSIST     0x01
#define NGX_SPDY_SETTINGS_FLAG_PERSISTED   0x02

#define NGX_SPDY_MAX_WINDOW                NGX_MAX_INT32_VALUE
#define NGX_SPDY_CONNECTION_WINDOW         65536
#define NGX_SPDY_INIT_STREAM_WINDOW        65536
#define NGX_SPDY_STREAM_WINDOW             NGX_SPDY_MAX_WINDOW

typedef struct {
    ngx_uint_t    hash;
    u_char        len;
    u_char        header[7];
    ngx_int_t   (*handler)(ngx_http_request_t *r);
} ngx_http_spdy_request_header_t;


static void ngx_http_spdy_read_handler(ngx_event_t *rev);
static void ngx_http_spdy_write_handler(ngx_event_t *wev);
static void ngx_http_spdy_handle_connection(ngx_http_spdy_connection_t *sc);

static u_char *ngx_http_spdy_proxy_protocol(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_head(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_syn_stream(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers_skip(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_headers_error(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_window_update(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_data(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_read_data(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_rst_stream(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_ping(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_skip(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_settings(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_complete(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);
static u_char *ngx_http_spdy_state_save(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end, ngx_http_spdy_handler_pt handler);

static u_char *ngx_http_spdy_state_inflate_error(
    ngx_http_spdy_connection_t *sc, int rc);
static u_char *ngx_http_spdy_state_protocol_error(
    ngx_http_spdy_connection_t *sc);
static u_char *ngx_http_spdy_state_internal_error(
    ngx_http_spdy_connection_t *sc);

static ngx_int_t ngx_http_spdy_send_window_update(
    ngx_http_spdy_connection_t *sc, ngx_uint_t sid, ngx_uint_t delta);
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
static ngx_int_t ngx_http_spdy_parse_host(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_path(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_parse_version(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_construct_request_line(ngx_http_request_t *r);
static void ngx_http_spdy_run_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_spdy_init_request_body(ngx_http_request_t *r);

static ngx_int_t ngx_http_spdy_terminate_stream(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_stream_t *stream, ngx_uint_t status);

static void ngx_http_spdy_close_stream_handler(ngx_event_t *ev);

static void ngx_http_spdy_handle_connection_handler(ngx_event_t *rev);
static void ngx_http_spdy_keepalive_handler(ngx_event_t *rev);
static void ngx_http_spdy_finalize_connection(ngx_http_spdy_connection_t *sc,
    ngx_int_t rc);

static ngx_int_t ngx_http_spdy_adjust_windows(ngx_http_spdy_connection_t *sc,
    ssize_t delta);

static void ngx_http_spdy_pool_cleanup(void *data);

static void *ngx_http_spdy_zalloc(void *opaque, u_int items, u_int size);
static void ngx_http_spdy_zfree(void *opaque, void *address);


static const u_char ngx_http_spdy_dict[] = {
    0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69,   /* - - - - o p t i */
    0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,   /* o n s - - - - h */
    0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70,   /* e a d - - - - p */
    0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,   /* o s t - - - - p */
    0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65,   /* u t - - - - d e */
    0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,   /* l e t e - - - - */
    0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00,   /* t r a c e - - - */
    0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,   /* - a c c e p t - */
    0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70,   /* - - - a c c e p */
    0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   /* t - c h a r s e */
    0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63,   /* t - - - - a c c */
    0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   /* e p t - e n c o */
    0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f,   /* d i n g - - - - */
    0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,   /* a c c e p t - l */
    0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00,   /* a n g u a g e - */
    0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,   /* - - - a c c e p */
    0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73,   /* t - r a n g e s */
    0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,   /* - - - - a g e - */
    0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77,   /* - - - a l l o w */
    0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,   /* - - - - a u t h */
    0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,   /* o r i z a t i o */
    0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,   /* n - - - - c a c */
    0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72,   /* h e - c o n t r */
    0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,   /* o l - - - - c o */
    0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,   /* n n e c t i o n */
    0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,   /* - - - - c o n t */
    0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65,   /* e n t - b a s e */
    0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,   /* - - - - c o n t */
    0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,   /* e n t - e n c o */
    0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,   /* d i n g - - - - */
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,   /* c o n t e n t - */
    0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,   /* l a n g u a g e */
    0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74,   /* - - - - c o n t */
    0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,   /* e n t - l e n g */
    0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f,   /* t h - - - - c o */
    0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,   /* n t e n t - l o */
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00,   /* c a t i o n - - */
    0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   /* - - c o n t e n */
    0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00,   /* t - m d 5 - - - */
    0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,   /* - c o n t e n t */
    0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00,   /* - r a n g e - - */
    0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,   /* - - c o n t e n */
    0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00,   /* t - t y p e - - */
    0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,   /* - - d a t e - - */
    0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00,   /* - - e t a g - - */
    0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,   /* - - e x p e c t */
    0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69,   /* - - - - e x p i */
    0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,   /* r e s - - - - f */
    0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68,   /* r o m - - - - h */
    0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,   /* o s t - - - - i */
    0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00,   /* f - m a t c h - */
    0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,   /* - - - i f - m o */
    0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73,   /* d i f i e d - s */
    0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,   /* i n c e - - - - */
    0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d,   /* i f - n o n e - */
    0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,   /* m a t c h - - - */
    0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67,   /* - i f - r a n g */
    0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,   /* e - - - - i f - */
    0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69,   /* u n m o d i f i */
    0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,   /* e d - s i n c e */
    0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74,   /* - - - - l a s t */
    0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,   /* - m o d i f i e */
    0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63,   /* d - - - - l o c */
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,   /* a t i o n - - - */
    0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72,   /* - m a x - f o r */
    0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,   /* w a r d s - - - */
    0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00,   /* - p r a g m a - */
    0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,   /* - - - p r o x y */
    0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,   /* - a u t h e n t */
    0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,   /* i c a t e - - - */
    0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61,   /* - p r o x y - a */
    0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,   /* u t h o r i z a */
    0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05,   /* t i o n - - - - */
    0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,   /* r a n g e - - - */
    0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72,   /* - r e f e r e r */
    0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,   /* - - - - r e t r */
    0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00,   /* y - a f t e r - */
    0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,   /* - - - s e r v e */
    0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00,   /* r - - - - t e - */
    0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,   /* - - - t r a i l */
    0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72,   /* e r - - - - t r */
    0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,   /* a n s f e r - e */
    0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,   /* n c o d i n g - */
    0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,   /* - - - u p g r a */
    0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73,   /* d e - - - - u s */
    0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,   /* e r - a g e n t */
    0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79,   /* - - - - v a r y */
    0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,   /* - - - - v i a - */
    0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69,   /* - - - w a r n i */
    0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,   /* n g - - - - w w */
    0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e,   /* w - a u t h e n */
    0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,   /* t i c a t e - - */
    0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,   /* - - m e t h o d */
    0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,   /* - - - - g e t - */
    0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,   /* - - - s t a t u */
    0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,   /* s - - - - 2 0 0 */
    0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76,   /* - O K - - - - v */
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,   /* e r s i o n - - */
    0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,   /* - - H T T P - 1 */
    0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,   /* - 1 - - - - u r */
    0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62,   /* l - - - - p u b */
    0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,   /* l i c - - - - s */
    0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69,   /* e t - c o o k i */
    0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,   /* e - - - - k e e */
    0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00,   /* p - a l i v e - */
    0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,   /* - - - o r i g i */
    0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32,   /* n 1 0 0 1 0 1 2 */
    0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,   /* 0 1 2 0 2 2 0 5 */
    0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30,   /* 2 0 6 3 0 0 3 0 */
    0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,   /* 2 3 0 3 3 0 4 3 */
    0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37,   /* 0 5 3 0 6 3 0 7 */
    0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,   /* 4 0 2 4 0 5 4 0 */
    0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34,   /* 6 4 0 7 4 0 8 4 */
    0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,   /* 0 9 4 1 0 4 1 1 */
    0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31,   /* 4 1 2 4 1 3 4 1 */
    0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,   /* 4 4 1 5 4 1 6 4 */
    0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34,   /* 1 7 5 0 2 5 0 4 */
    0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,   /* 5 0 5 2 0 3 - N */
    0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f,   /* o n - A u t h o */
    0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,   /* r i t a t i v e */
    0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61,   /* - I n f o r m a */
    0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,   /* t i o n 2 0 4 - */
    0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,   /* N o - C o n t e */
    0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,   /* n t 3 0 1 - M o */
    0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d,   /* v e d - P e r m */
    0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,   /* a n e n t l y 4 */
    0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52,   /* 0 0 - B a d - R */
    0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,   /* e q u e s t 4 0 */
    0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68,   /* 1 - U n a u t h */
    0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,   /* o r i z e d 4 0 */
    0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64,   /* 3 - F o r b i d */
    0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,   /* d e n 4 0 4 - N */
    0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64,   /* o t - F o u n d */
    0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,   /* 5 0 0 - I n t e */
    0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72,   /* r n a l - S e r */
    0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,   /* v e r - E r r o */
    0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74,   /* r 5 0 1 - N o t */
    0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,   /* - I m p l e m e */
    0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20,   /* n t e d 5 0 3 - */
    0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,   /* S e r v i c e - */
    0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61,   /* U n a v a i l a */
    0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,   /* b l e J a n - F */
    0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41,   /* e b - M a r - A */
    0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,   /* p r - M a y - J */
    0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41,   /* u n - J u l - A */
    0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,   /* u g - S e p t - */
    0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20,   /* O c t - N o v - */
    0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,   /* D e c - 0 0 - 0 */
    0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e,   /* 0 - 0 0 - M o n */
    0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,   /* - - T u e - - W */
    0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c,   /* e d - - T h u - */
    0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,   /* - F r i - - S a */
    0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,   /* t - - S u n - - */
    0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,   /* G M T c h u n k */
    0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f,   /* e d - t e x t - */
    0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,   /* h t m l - i m a */
    0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69,   /* g e - p n g - i */
    0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,   /* m a g e - j p g */
    0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67,   /* - i m a g e - g */
    0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   /* i f - a p p l i */
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   /* c a t i o n - x */
    0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,   /* m l - a p p l i */
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78,   /* c a t i o n - x */
    0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,   /* h t m l - x m l */
    0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c,   /* - t e x t - p l */
    0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,   /* a i n - t e x t */
    0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72,   /* - j a v a s c r */
    0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,   /* i p t - p u b l */
    0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,   /* i c p r i v a t */
    0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,   /* e m a x - a g e */
    0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65,   /* - g z i p - d e */
    0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,   /* f l a t e - s d */
    0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,   /* c h c h a r s e */
    0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,   /* t - u t f - 8 c */
    0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69,   /* h a r s e t - i */
    0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,   /* s o - 8 8 5 9 - */
    0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a,   /* 1 - u t f - - - */
    0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e          /* - e n q - 0 -   */
};


static ngx_http_spdy_request_header_t ngx_http_spdy_request_headers[] = {
    { 0, 6, "method", ngx_http_spdy_parse_method },
    { 0, 6, "scheme", ngx_http_spdy_parse_scheme },
    { 0, 4, "host", ngx_http_spdy_parse_host },
    { 0, 4, "path", ngx_http_spdy_parse_path },
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "init spdy request");

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

    sc->send_window = NGX_SPDY_CONNECTION_WINDOW;
    sc->recv_window = NGX_SPDY_CONNECTION_WINDOW;

    sc->init_window = NGX_SPDY_INIT_STREAM_WINDOW;

    sc->handler = hc->proxy_protocol ? ngx_http_spdy_proxy_protocol
                                     : ngx_http_spdy_state_head;

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

    if (ngx_http_spdy_send_settings(sc) == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    if (ngx_http_spdy_send_window_update(sc, 0, NGX_SPDY_MAX_WINDOW
                                                - sc->recv_window)
        == NGX_ERROR)
    {
        ngx_http_close_connection(c);
        return;
    }

    sc->recv_window = NGX_SPDY_MAX_WINDOW;

    ngx_queue_init(&sc->waiting);
    ngx_queue_init(&sc->posted);

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

        if (n == 0 && (sc->incomplete || sc->processing)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_http_spdy_finalize_connection(sc,
                                              NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        end += n;

        sc->buffer_used = 0;
        sc->incomplete = 0;

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

    if (sc->last_out && ngx_http_spdy_send_output_queue(sc) == NGX_ERROR) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);
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
    ngx_queue_t                 *q;
    ngx_connection_t            *c;
    ngx_http_spdy_stream_t      *stream;
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

    sc->blocked = 1;

    rc = ngx_http_spdy_send_output_queue(sc);

    if (rc == NGX_ERROR) {
        ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    while (!ngx_queue_empty(&sc->posted)) {
        q = ngx_queue_head(&sc->posted);

        ngx_queue_remove(q);

        stream = ngx_queue_data(q, ngx_http_spdy_stream_t, queue);

        stream->handled = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "run spdy stream %ui", stream->id);

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
                       "spdy frame out: %p sid:%ui prio:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->id : 0, out->priority,
                       out->blocked, out->length);
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

    for ( /* void */ ; out; out = fn) {
        fn = out->next;

        if (out->handler(sc, out) != NGX_OK) {
            out->blocked = 1;
            out->priority = NGX_SPDY_HIGHEST_PRIORITY;
            break;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "spdy frame sent: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->id : 0,
                       out->blocked, out->length);
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
    if (sc->incomplete) {
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
ngx_http_spdy_proxy_protocol(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_log_t  *log;

    log = sc->connection->log;
    log->action = "reading PROXY protocol";

    pos = ngx_proxy_protocol_parse(sc->connection, pos, end);

    log->action = "processing SPDY";

    if (pos == NULL) {
        return ngx_http_spdy_state_protocol_error(sc);
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_head(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    uint32_t    head, flen;
    ngx_uint_t  type;

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
                   "process spdy frame head:%08XD f:%Xd l:%uz",
                   head, sc->flags, sc->length);

    if (ngx_spdy_ctl_frame_check(head)) {
        type = ngx_spdy_ctl_frame_type(head);

        switch (type) {

        case NGX_SPDY_SYN_STREAM:
            return ngx_http_spdy_state_syn_stream(sc, pos, end);

        case NGX_SPDY_SYN_REPLY:
            ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                          "client sent unexpected SYN_REPLY frame");
            return ngx_http_spdy_state_protocol_error(sc);

        case NGX_SPDY_RST_STREAM:
            return ngx_http_spdy_state_rst_stream(sc, pos, end);

        case NGX_SPDY_SETTINGS:
            return ngx_http_spdy_state_settings(sc, pos, end);

        case NGX_SPDY_PING:
            return ngx_http_spdy_state_ping(sc, pos, end);

        case NGX_SPDY_GOAWAY:
            return ngx_http_spdy_state_skip(sc, pos, end); /* TODO */

        case NGX_SPDY_HEADERS:
            ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                          "client sent unexpected HEADERS frame");
            return ngx_http_spdy_state_protocol_error(sc);

        case NGX_SPDY_WINDOW_UPDATE:
            return ngx_http_spdy_state_window_update(sc, pos, end);

        default:
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy control frame with unknown type %ui", type);
            return ngx_http_spdy_state_skip(sc, pos, end);
        }
    }

    if (ngx_spdy_data_frame_check(head)) {
        sc->stream = ngx_http_spdy_get_stream_by_id(sc, head);
        return ngx_http_spdy_state_data(sc, pos, end);
    }

    ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                  "client sent invalid frame");

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
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent SYN_STREAM frame with incorrect length %uz",
                      sc->length);

        return ngx_http_spdy_state_protocol_error(sc);
    }

    sc->length -= NGX_SPDY_SYN_STREAM_SIZE;

    sid = ngx_spdy_frame_parse_sid(pos);
    prio = pos[8] >> 5;

    pos += NGX_SPDY_SYN_STREAM_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy SYN_STREAM frame sid:%ui prio:%ui", sid, prio);

    if (sid % 2 == 0 || sid <= sc->last_sid) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent SYN_STREAM frame "
                      "with invalid Stream-ID %ui", sid);

        stream = ngx_http_spdy_get_stream_by_id(sc, sid);

        if (stream) {
            if (ngx_http_spdy_terminate_stream(sc, stream,
                                               NGX_SPDY_PROTOCOL_ERROR)
                != NGX_OK)
            {
                return ngx_http_spdy_state_internal_error(sc);
            }
        }

        return ngx_http_spdy_state_protocol_error(sc);
    }

    sc->last_sid = sid;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    if (sc->processing >= sscf->concurrent_streams) {

        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "concurrent streams exceeded %ui", sc->processing);

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
    ngx_http_request_t  *r;

    size = end - pos;

    if (size == 0) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers);
    }

    if (size > sc->length) {
        size = sc->length;
    }

    r = sc->stream->request;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "process spdy header block %uz of %uz", size, sc->length);

    buf = r->header_in;

    sc->zstream_in.next_in = pos;
    sc->zstream_in.avail_in = size;
    sc->zstream_in.next_out = buf->last;

    /* one byte is reserved for null-termination of the last header value */
    sc->zstream_in.avail_out = buf->end - buf->last - 1;

    z = inflate(&sc->zstream_in, Z_NO_FLUSH);

    if (z == Z_NEED_DICT) {
        z = inflateSetDictionary(&sc->zstream_in, ngx_http_spdy_dict,
                                 sizeof(ngx_http_spdy_dict));

        if (z != Z_OK) {
            if (z == Z_DATA_ERROR) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent SYN_STREAM frame with header "
                              "block encoded using wrong dictionary: %ul",
                              (u_long) sc->zstream_in.adler);

                return ngx_http_spdy_state_protocol_error(sc);
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "inflateSetDictionary() failed: %d", z);

            return ngx_http_spdy_state_internal_error(sc);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "spdy inflateSetDictionary(): %d", z);

        z = sc->zstream_in.avail_in ? inflate(&sc->zstream_in, Z_NO_FLUSH)
                                    : Z_OK;
    }

    if (z != Z_OK) {
        return ngx_http_spdy_state_inflate_error(sc, z);
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

            if (sc->length == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "premature end of spdy header block");

                return ngx_http_spdy_state_headers_error(sc, pos, end);
            }

            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_headers);
        }

        sc->entries = ngx_spdy_frame_parse_uint32(buf->pos);

        buf->pos += NGX_SPDY_NV_NUM_SIZE;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "spdy header block has %ui entries",
                       sc->entries);

        if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            ngx_http_spdy_close_stream(sc->stream,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
            return ngx_http_spdy_state_headers_skip(sc, pos, end);
        }

        if (ngx_array_init(&r->headers_in.cookies, r->pool, 2,
                           sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            ngx_http_spdy_close_stream(sc->stream,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
            return ngx_http_spdy_state_headers_skip(sc, pos, end);
        }
    }

    while (sc->entries) {

        rc = ngx_http_spdy_parse_header(r);

        switch (rc) {

        case NGX_DONE:
            sc->entries--;

        case NGX_OK:
            break;

        case NGX_AGAIN:

            if (sc->zstream_in.avail_in) {

                rc = ngx_http_spdy_alloc_large_header_buffer(r);

                if (rc == NGX_DECLINED) {
                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    return ngx_http_spdy_state_headers_skip(sc, pos, end);
                }

                if (rc != NGX_OK) {
                    ngx_http_spdy_close_stream(sc->stream,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return ngx_http_spdy_state_headers_skip(sc, pos, end);
                }

                /* null-terminate the last processed header name or value */
                *buf->pos = '\0';

                buf = r->header_in;

                sc->zstream_in.next_out = buf->last;

                /* one byte is reserved for null-termination */
                sc->zstream_in.avail_out = buf->end - buf->last - 1;

                z = inflate(&sc->zstream_in, Z_NO_FLUSH);

                if (z != Z_OK) {
                    return ngx_http_spdy_state_inflate_error(sc, z);
                }

                sc->length -= sc->zstream_in.next_in - pos;
                pos = sc->zstream_in.next_in;

                buf->last = sc->zstream_in.next_out;

                continue;
            }

            if (sc->length == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "premature end of spdy header block");

                return ngx_http_spdy_state_headers_error(sc, pos, end);
            }

            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_headers);

        case NGX_HTTP_PARSE_INVALID_HEADER:
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return ngx_http_spdy_state_headers_skip(sc, pos, end);

        default: /* NGX_ERROR */
            return ngx_http_spdy_state_headers_error(sc, pos, end);
        }

        /* a header line has been parsed successfully */

        rc = ngx_http_spdy_handle_request_header(r);

        if (rc != NGX_OK) {
            if (rc == NGX_HTTP_PARSE_INVALID_HEADER) {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return ngx_http_spdy_state_headers_skip(sc, pos, end);
            }

            if (rc != NGX_ABORT) {
                ngx_http_spdy_close_stream(sc->stream,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return ngx_http_spdy_state_headers_skip(sc, pos, end);
        }
    }

    if (buf->pos != buf->last || sc->zstream_in.avail_in) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "incorrect number of spdy header block entries");

        return ngx_http_spdy_state_headers_error(sc, pos, end);
    }

    if (sc->length) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_headers);
    }

    /* null-terminate the last header value */
    *buf->pos = '\0';

    ngx_http_spdy_run_request(r);

    return ngx_http_spdy_state_complete(sc, pos, end);
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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy header block skip %uz of %uz", size, sc->length);

    sc->zstream_in.next_in = pos;
    sc->zstream_in.avail_in = (size < sc->length) ? size : sc->length;

    while (sc->zstream_in.avail_in) {
        sc->zstream_in.next_out = buffer;
        sc->zstream_in.avail_out = NGX_SPDY_SKIP_HEADERS_BUFFER_SIZE;

        n = inflate(&sc->zstream_in, Z_NO_FLUSH);

        if (n != Z_OK) {
            return ngx_http_spdy_state_inflate_error(sc, n);
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
ngx_http_spdy_state_headers_error(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_http_spdy_stream_t  *stream;

    stream = sc->stream;

    ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                  "client sent SYN_STREAM frame for stream %ui "
                  "with invalid header block", stream->id);

    if (ngx_http_spdy_send_rst_stream(sc, stream->id, NGX_SPDY_PROTOCOL_ERROR,
                                      stream->priority)
        != NGX_OK)
    {
        return ngx_http_spdy_state_internal_error(sc);
    }

    stream->out_closed = 1;

    ngx_http_spdy_close_stream(stream, NGX_HTTP_BAD_REQUEST);

    return ngx_http_spdy_state_headers_skip(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_window_update(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    size_t                   delta;
    ngx_uint_t               sid;
    ngx_event_t             *wev;
    ngx_queue_t             *q;
    ngx_http_spdy_stream_t  *stream;

    if (end - pos < NGX_SPDY_WINDOW_UPDATE_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_window_update);
    }

    if (sc->length != NGX_SPDY_WINDOW_UPDATE_SIZE) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect length %uz", sc->length);

        return ngx_http_spdy_state_protocol_error(sc);
    }

    sid = ngx_spdy_frame_parse_sid(pos);

    pos += NGX_SPDY_SID_SIZE;

    delta = ngx_spdy_frame_parse_delta(pos);

    pos += NGX_SPDY_DELTA_SIZE;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy WINDOW_UPDATE sid:%ui delta:%ui", sid, delta);

    if (sid) {
        stream = ngx_http_spdy_get_stream_by_id(sc, sid);

        if (stream == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "unknown spdy stream");

            return ngx_http_spdy_state_complete(sc, pos, end);
        }

        if (stream->send_window > (ssize_t) (NGX_SPDY_MAX_WINDOW - delta)) {

            ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                          "client violated flow control for stream %ui: "
                          "received WINDOW_UPDATE frame with delta %uz "
                          "not allowed for window %z",
                          sid, delta, stream->send_window);

            if (ngx_http_spdy_terminate_stream(sc, stream,
                                               NGX_SPDY_FLOW_CONTROL_ERROR)
                == NGX_ERROR)
            {
                return ngx_http_spdy_state_internal_error(sc);
            }

            return ngx_http_spdy_state_complete(sc, pos, end);
        }

        stream->send_window += delta;

        if (stream->exhausted) {
            stream->exhausted = 0;

            wev = stream->request->connection->write;

            if (!wev->timer_set) {
                wev->delayed = 0;
                wev->handler(wev);
            }
        }

    } else {
        sc->send_window += delta;

        if (sc->send_window > NGX_SPDY_MAX_WINDOW) {
            ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                          "client violated connection flow control: "
                          "received WINDOW_UPDATE frame with delta %uz "
                          "not allowed for window %uz",
                          delta, sc->send_window);

            return ngx_http_spdy_state_protocol_error(sc);
        }

        while (!ngx_queue_empty(&sc->waiting)) {
            q = ngx_queue_head(&sc->waiting);

            ngx_queue_remove(q);

            stream = ngx_queue_data(q, ngx_http_spdy_stream_t, queue);

            stream->handled = 0;

            wev = stream->request->connection->write;

            if (!wev->timer_set) {
                wev->delayed = 0;
                wev->handler(wev);

                if (sc->send_window == 0) {
                    break;
                }
            }
        }
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_data(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_http_spdy_stream_t  *stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy DATA frame");

    if (sc->length > sc->recv_window) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client violated connection flow control: "
                      "received DATA frame length %uz, available window %uz",
                      sc->length, sc->recv_window);

        return ngx_http_spdy_state_protocol_error(sc);
    }

    sc->recv_window -= sc->length;

    if (sc->recv_window < NGX_SPDY_MAX_WINDOW / 4) {

        if (ngx_http_spdy_send_window_update(sc, 0,
                                             NGX_SPDY_MAX_WINDOW
                                             - sc->recv_window)
            == NGX_ERROR)
        {
            return ngx_http_spdy_state_internal_error(sc);
        }

        sc->recv_window = NGX_SPDY_MAX_WINDOW;
    }

    stream = sc->stream;

    if (stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "unknown spdy stream");

        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    if (sc->length > stream->recv_window) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client violated flow control for stream %ui: "
                      "received DATA frame length %uz, available window %uz",
                      stream->id, sc->length, stream->recv_window);

        if (ngx_http_spdy_terminate_stream(sc, stream,
                                           NGX_SPDY_FLOW_CONTROL_ERROR)
            == NGX_ERROR)
        {
            return ngx_http_spdy_state_internal_error(sc);
        }

        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    stream->recv_window -= sc->length;

    if (stream->recv_window < NGX_SPDY_STREAM_WINDOW / 4) {

        if (ngx_http_spdy_send_window_update(sc, stream->id,
                                             NGX_SPDY_STREAM_WINDOW
                                             - stream->recv_window)
            == NGX_ERROR)
        {
            return ngx_http_spdy_state_internal_error(sc);
        }

        stream->recv_window = NGX_SPDY_STREAM_WINDOW;
    }

    if (stream->in_closed) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent DATA frame for half-closed stream %ui",
                      stream->id);

        if (ngx_http_spdy_terminate_stream(sc, stream,
                                           NGX_SPDY_STREAM_ALREADY_CLOSED)
            == NGX_ERROR)
        {
            return ngx_http_spdy_state_internal_error(sc);
        }

        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    return ngx_http_spdy_state_read_data(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_read_data(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *buf;
    ngx_int_t                  rc;
    ngx_temp_file_t           *tf;
    ngx_http_request_t        *r;
    ngx_http_spdy_stream_t    *stream;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    stream = sc->stream;

    if (stream == NULL) {
        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    if (stream->skip_data) {

        if (sc->flags & NGX_SPDY_FLAG_FIN) {
            stream->in_closed = 1;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "skipping spdy DATA frame, reason: %d",
                       stream->skip_data);

        return ngx_http_spdy_state_skip(sc, pos, end);
    }

    size = end - pos;

    if (size > sc->length) {
        size = sc->length;
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
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client intended to send body data "
                          "larger than declared");

            stream->skip_data = NGX_SPDY_DATA_ERROR;
            goto error;

        } else {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

            if (clcf->client_max_body_size
                && clcf->client_max_body_size < rb->rest)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "client intended to send "
                              "too large chunked body: %O bytes", rb->rest);

                stream->skip_data = NGX_SPDY_DATA_ERROR;
                goto error;
            }
        }

        sc->length -= size;

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

    if (sc->length) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_read_data);
    }

    if (sc->flags & NGX_SPDY_FLAG_FIN) {

        stream->in_closed = 1;

        if (r->headers_in.content_length_n < 0) {
            r->headers_in.content_length_n = rb->rest;

        } else if (r->headers_in.content_length_n != rb->rest) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->rest, r->headers_in.content_length_n);

            stream->skip_data = NGX_SPDY_DATA_ERROR;
            goto error;
        }

        if (tf) {
            ngx_memzero(buf, sizeof(ngx_buf_t));

            buf->in_file = 1;
            buf->file_last = tf->file.offset;
            buf->file = &tf->file;

            rb->buf = NULL;
        }

        if (rb->post_handler) {
            r->read_event_handler = ngx_http_block_reading;
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
    ngx_http_spdy_stream_t  *stream;

    if (end - pos < NGX_SPDY_RST_STREAM_SIZE) {
        return ngx_http_spdy_state_save(sc, pos, end,
                                        ngx_http_spdy_state_rst_stream);
    }

    if (sc->length != NGX_SPDY_RST_STREAM_SIZE) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect length %uz",
                      sc->length);

        return ngx_http_spdy_state_protocol_error(sc);
    }

    sid = ngx_spdy_frame_parse_sid(pos);

    pos += NGX_SPDY_SID_SIZE;

    status = ngx_spdy_frame_parse_uint32(pos);

    pos += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy RST_STREAM sid:%ui st:%ui", sid, status);

    stream = ngx_http_spdy_get_stream_by_id(sc, sid);

    if (stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "unknown spdy stream");

        return ngx_http_spdy_state_complete(sc, pos, end);
    }

    stream->in_closed = 1;
    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    switch (status) {

    case NGX_SPDY_CANCEL:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client canceled stream %ui", sid);
        break;

    case NGX_SPDY_INTERNAL_ERROR:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui due to internal error",
                      sid);
        break;

    default:
        ngx_log_error(NGX_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui with status %ui",
                      sid, status);
        break;
    }

    ev = fc->read;
    ev->handler(ev);

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
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent PING frame with incorrect length %uz",
                      sc->length);

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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy frame skip %uz of %uz", size, sc->length);

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
    ngx_uint_t  fid, val;

    if (sc->entries == 0) {

        if (end - pos < NGX_SPDY_SETTINGS_NUM_SIZE) {
            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_settings);
        }

        sc->entries = ngx_spdy_frame_parse_uint32(pos);

        pos += NGX_SPDY_SETTINGS_NUM_SIZE;
        sc->length -= NGX_SPDY_SETTINGS_NUM_SIZE;

        if (sc->length < sc->entries * NGX_SPDY_SETTINGS_PAIR_SIZE) {
            ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                          "client sent SETTINGS frame with incorrect "
                          "length %uz or number of entries %ui",
                          sc->length, sc->entries);

            return ngx_http_spdy_state_protocol_error(sc);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy SETTINGS frame has %ui entries", sc->entries);
    }

    while (sc->entries) {
        if (end - pos < NGX_SPDY_SETTINGS_PAIR_SIZE) {
            return ngx_http_spdy_state_save(sc, pos, end,
                                            ngx_http_spdy_state_settings);
        }

        sc->entries--;
        sc->length -= NGX_SPDY_SETTINGS_PAIR_SIZE;

        fid = ngx_spdy_frame_parse_uint32(pos);

        pos += NGX_SPDY_SETTINGS_FID_SIZE;

        val = ngx_spdy_frame_parse_uint32(pos);

        pos += NGX_SPDY_SETTINGS_VAL_SIZE;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                       "spdy SETTINGS entry fl:%ui id:%ui val:%ui",
                       ngx_spdy_frame_flags(fid), ngx_spdy_frame_id(fid), val);

        if (ngx_spdy_frame_flags(fid) == NGX_SPDY_SETTINGS_FLAG_PERSISTED) {
            continue;
        }

        switch (ngx_spdy_frame_id(fid)) {

        case NGX_SPDY_SETTINGS_INIT_WINDOW:

            if (val > NGX_SPDY_MAX_WINDOW) {
                ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                              "client sent SETTINGS frame with "
                              "incorrect INIT_WINDOW value: %ui", val);

                return ngx_http_spdy_state_protocol_error(sc);
            }

            if (ngx_http_spdy_adjust_windows(sc, val - sc->init_window)
                != NGX_OK)
            {
                return ngx_http_spdy_state_internal_error(sc);
            }

            sc->init_window = val;

            continue;
        }
    }

    return ngx_http_spdy_state_complete(sc, pos, end);
}


static u_char *
ngx_http_spdy_state_complete(ngx_http_spdy_connection_t *sc, u_char *pos,
    u_char *end)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy frame complete pos:%p end:%p", pos, end);

    sc->handler = ngx_http_spdy_state_head;
    sc->stream = NULL;

    return pos;
}


static u_char *
ngx_http_spdy_state_save(ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end, ngx_http_spdy_handler_pt handler)
{
    size_t  size;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy frame state save pos:%p end:%p handler:%p",
                   pos, end, handler);

    size = end - pos;

    if (size > NGX_SPDY_STATE_BUFFER_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, sc->connection->log, 0,
                      "state buffer overflow: %uz bytes required", size);

        return ngx_http_spdy_state_internal_error(sc);
    }

    ngx_memcpy(sc->buffer, pos, NGX_SPDY_STATE_BUFFER_SIZE);

    sc->buffer_used = size;
    sc->handler = handler;
    sc->incomplete = 1;

    return end;
}


static u_char *
ngx_http_spdy_state_inflate_error(ngx_http_spdy_connection_t *sc, int rc)
{
    if (rc == Z_DATA_ERROR || rc == Z_STREAM_END) {
        ngx_log_error(NGX_LOG_INFO, sc->connection->log, 0,
                      "client sent SYN_STREAM frame with "
                      "corrupted header block, inflate() failed: %d", rc);

        return ngx_http_spdy_state_protocol_error(sc);
    }

    ngx_log_error(NGX_LOG_ERR, sc->connection->log, 0,
                  "inflate() failed: %d", rc);

    return ngx_http_spdy_state_internal_error(sc);
}


static u_char *
ngx_http_spdy_state_protocol_error(ngx_http_spdy_connection_t *sc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy state protocol error");

    if (sc->stream) {
        sc->stream->out_closed = 1;
        ngx_http_spdy_close_stream(sc->stream, NGX_HTTP_BAD_REQUEST);
    }

    ngx_http_spdy_finalize_connection(sc, NGX_HTTP_CLIENT_CLOSED_REQUEST);

    return NULL;
}


static u_char *
ngx_http_spdy_state_internal_error(ngx_http_spdy_connection_t *sc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy state internal error");

    if (sc->stream) {
        sc->stream->out_closed = 1;
        ngx_http_spdy_close_stream(sc->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    ngx_http_spdy_finalize_connection(sc, NGX_HTTP_INTERNAL_SERVER_ERROR);

    return NULL;
}


static ngx_int_t
ngx_http_spdy_send_window_update(ngx_http_spdy_connection_t *sc, ngx_uint_t sid,
    ngx_uint_t delta)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_http_spdy_out_frame_t  *frame;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy send WINDOW_UPDATE sid:%ui delta:%ui", sid, delta);

    frame = ngx_http_spdy_get_ctl_frame(sc, NGX_SPDY_WINDOW_UPDATE_SIZE,
                                        NGX_SPDY_HIGHEST_PRIORITY);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    buf = frame->first->buf;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_WINDOW_UPDATE);
    p = ngx_spdy_frame_write_flags_and_len(p, 0, NGX_SPDY_WINDOW_UPDATE_SIZE);

    p = ngx_spdy_frame_write_sid(p, sid);
    p = ngx_spdy_frame_aligned_write_uint32(p, delta);

    buf->last = p;

    ngx_http_spdy_queue_frame(sc, frame);

    return NGX_OK;
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
                   "spdy send RST_STREAM sid:%ui st:%ui", sid, status);

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
                   "spdy send GOAWAY sid:%ui", sc->last_sid);

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
    ngx_chain_t                *cl;
    ngx_http_spdy_srv_conf_t   *sscf;
    ngx_http_spdy_out_frame_t  *frame;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy send SETTINGS frame");

    frame = ngx_palloc(sc->pool, sizeof(ngx_http_spdy_out_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(sc->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    buf = ngx_create_temp_buf(sc->pool, NGX_SPDY_FRAME_HEADER_SIZE
                                        + NGX_SPDY_SETTINGS_NUM_SIZE
                                        + 2 * NGX_SPDY_SETTINGS_PAIR_SIZE);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_spdy_settings_frame_handler;
    frame->stream = NULL;
#if (NGX_DEBUG)
    frame->length = NGX_SPDY_SETTINGS_NUM_SIZE
                    + 2 * NGX_SPDY_SETTINGS_PAIR_SIZE;
#endif
    frame->priority = NGX_SPDY_HIGHEST_PRIORITY;
    frame->blocked = 0;

    p = buf->pos;

    p = ngx_spdy_frame_write_head(p, NGX_SPDY_SETTINGS);
    p = ngx_spdy_frame_write_flags_and_len(p, NGX_SPDY_FLAG_CLEAR_SETTINGS,
                                           NGX_SPDY_SETTINGS_NUM_SIZE
                                           + 2 * NGX_SPDY_SETTINGS_PAIR_SIZE);

    p = ngx_spdy_frame_aligned_write_uint32(p, 2);

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    p = ngx_spdy_frame_write_flags_and_id(p, 0, NGX_SPDY_SETTINGS_MAX_STREAMS);
    p = ngx_spdy_frame_aligned_write_uint32(p, sscf->concurrent_streams);

    p = ngx_spdy_frame_write_flags_and_id(p, 0, NGX_SPDY_SETTINGS_INIT_WINDOW);
    p = ngx_spdy_frame_aligned_write_uint32(p, NGX_SPDY_STREAM_WINDOW);

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
ngx_http_spdy_get_ctl_frame(ngx_http_spdy_connection_t *sc, size_t length,
    ngx_uint_t priority)
{
    ngx_chain_t                *cl;
    ngx_http_spdy_out_frame_t  *frame;

    frame = sc->free_ctl_frames;

    if (frame) {
        sc->free_ctl_frames = frame->next;

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
        frame->stream = NULL;
    }

#if (NGX_DEBUG)
    if (length > NGX_SPDY_CTL_FRAME_BUFFER_SIZE - NGX_SPDY_FRAME_HEADER_SIZE) {
        ngx_log_error(NGX_LOG_ALERT, sc->pool->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }

    frame->length = length;
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

    frame->next = sc->free_ctl_frames;
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
    rev->handler = ngx_http_spdy_close_stream_handler;
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

    stream->send_window = sc->init_window;
    stream->recv_window = NGX_SPDY_STREAM_WINDOW;

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
    ngx_uint_t                  hash;
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

        r->lowcase_index = ngx_spdy_frame_parse_uint32(p);

        if (r->lowcase_index == 0) {
            return NGX_ERROR;
        }

        /* null-terminate the previous header value */
        *p = '\0';

        p += NGX_SPDY_NV_NLEN_SIZE;

        r->invalid_header = 0;

        state = sw_name;

        /* fall through */

    case sw_name:

        if ((ngx_uint_t) (end - p) < r->lowcase_index) {
            break;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        r->header_name_start = p;
        r->header_name_end = p + r->lowcase_index;

        if (p[0] == ':') {
            p++;
        }

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
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent invalid header name: \"%*s\"",
                              r->lowcase_index, r->header_name_start);

                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            if (ch >= 'A' && ch <= 'Z') {
                return NGX_ERROR;
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

        r->lowcase_index = ngx_spdy_frame_parse_uint32(p);

        /* null-terminate header name */
        *p = '\0';

        p += NGX_SPDY_NV_VLEN_SIZE;

        state = sw_value;

        /* fall through */

    case sw_value:

        if ((ngx_uint_t) (end - p) < r->lowcase_index) {
            break;
        }

        r->header_start = p;

        while (r->lowcase_index--) {
            ch = *p;

            if (ch == '\0') {

                if (p == r->header_start) {
                    return NGX_ERROR;
                }

                r->header_end = p;
                r->header_in->pos = p + 1;

                return NGX_OK;
            }

            if (ch == CR || ch == LF) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent header \"%*s\" with "
                              "invalid value: \"%*s\\%c...\"",
                              r->header_name_end - r->header_name_start,
                              r->header_name_start,
                              p - r->header_start,
                              r->header_start,
                              ch == CR ? 'r' : 'n');

                return NGX_HTTP_PARSE_INVALID_HEADER;
            }

            p++;
        }

        r->header_end = p;
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
    u_char                    *old, *new, *p;
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
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too large request");

        return NGX_DECLINED;
    }

    rest = r->header_in->last - r->header_in->pos;

    /*
     * equality is prohibited since one more byte is needed
     * for null-termination
     */
    if (rest >= cscf->large_client_header_buffers.size) {
        p = r->header_in->pos;

        if (rest > NGX_MAX_ERROR_STR - 300) {
            rest = NGX_MAX_ERROR_STR - 300;
            p[rest++] = '.'; p[rest++] = '.'; p[rest++] = '.';
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too long header name or value: \"%*s\"",
                      rest, p);

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

    }

    if (r->header_name_start[0] == ':') {
        r->header_name_start++;

        for (i = 0; i < NGX_SPDY_REQUEST_HEADERS; i++) {
            sh = &ngx_http_spdy_request_headers[i];

            if (sh->hash != r->header_hash
                || sh->len != r->header_name_end - r->header_name_start
                || ngx_strncmp(sh->header, r->header_name_start, sh->len) != 0)
            {
                continue;
            }

            return sh->handler(r);
        }

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid header name: \":%*s\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start);

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = r->header_hash;

    h->key.len = r->header_name_end - r->header_name_start;
    h->key.data = r->header_name_start;

    h->value.len = r->header_end - r->header_start;
    h->value.data = r->header_start;

    h->lowcase_key = h->key.data;

    return NGX_OK;
}


void
ngx_http_spdy_request_headers_init(void)
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
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    len = r->header_end - r->header_start;

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
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return NGX_HTTP_PARSE_INVALID_HEADER;
        }

        p++;

    } while (--len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_scheme(ngx_http_request_t *r)
{
    if (r->schema_start) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :schema header");

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    r->schema_start = r->header_start;
    r->schema_end = r->header_end;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_host(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;

    if (r->headers_in.host) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :host header");

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    r->headers_in.host = h;

    h->hash = r->header_hash;

    h->key.len = r->header_name_end - r->header_name_start;
    h->key.data = r->header_name_start;

    h->value.len = r->header_end - r->header_start;
    h->value.data = r->header_start;

    h->lowcase_key = h->key.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_parse_path(ngx_http_request_t *r)
{
    if (r->unparsed_uri.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    r->uri_start = r->header_start;
    r->uri_end = r->header_end;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid URI: \"%*s\"",
                      r->uri_end - r->uri_start, r->uri_start);

        return NGX_HTTP_PARSE_INVALID_HEADER;
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
ngx_http_spdy_parse_version(ngx_http_request_t *r)
{
    u_char  *p, ch;

    if (r->http_protocol.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :version header");

        return NGX_HTTP_PARSE_INVALID_HEADER;
    }

    p = r->header_start;

    if (r->header_end - p < 8 || !(ngx_str5cmp(p, 'H', 'T', 'T', 'P', '/'))) {
        goto invalid;
    }

    ch = *(p + 5);

    if (ch < '1' || ch > '9') {
        goto invalid;
    }

    r->http_major = ch - '0';

    for (p += 6; p != r->header_end - 2; p++) {

        ch = *p;

        if (ch == '.') {
            break;
        }

        if (ch < '0' || ch > '9') {
            goto invalid;
        }

        r->http_major = r->http_major * 10 + ch - '0';
    }

    if (*p != '.') {
        goto invalid;
    }

    ch = *(p + 1);

    if (ch < '0' || ch > '9') {
        goto invalid;
    }

    r->http_minor = ch - '0';

    for (p += 2; p != r->header_end; p++) {

        ch = *p;

        if (ch < '0' || ch > '9') {
            goto invalid;
        }

        r->http_minor = r->http_minor * 10 + ch - '0';
    }

    r->http_protocol.len = r->header_end - r->header_start;
    r->http_protocol.data = r->header_start;
    r->http_version = r->http_major * 1000 + r->http_minor;

    return NGX_OK;

invalid:

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent invalid http version: \"%*s\"",
                  r->header_end - r->header_start, r->header_start);

    return NGX_HTTP_PARSE_INVALID_HEADER;
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
        ngx_http_spdy_close_stream(r->spdy_stream,
                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
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
                       "spdy http header: \"%V: %V\"", &h[i].key, &h[i].value);
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (ngx_http_process_request_header(r) != NGX_OK) {
        return;
    }

    if (r->headers_in.content_length_n > 0 && r->spdy_stream->in_closed) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client prematurely closed stream");

        r->spdy_stream->skip_data = NGX_SPDY_DATA_ERROR;

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
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

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_request_empty_handler;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_spdy_terminate_stream(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_stream_t *stream, ngx_uint_t status)
{
    ngx_event_t       *rev;
    ngx_connection_t  *fc;

    if (ngx_http_spdy_send_rst_stream(sc, stream->id, status,
                                      NGX_SPDY_HIGHEST_PRIORITY)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    rev->handler(rev);

    return NGX_OK;
}


static void
ngx_http_spdy_close_stream_handler(ngx_event_t *ev)
{
    ngx_connection_t    *fc;
    ngx_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy close stream handler");

    ngx_http_spdy_close_stream(r->spdy_stream, 0);
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

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy close stream %ui, queued %ui, processing %ui",
                   stream->id, stream->queued, sc->processing);

    fc = stream->request->connection;

    if (stream->queued) {
        fc->write->handler = ngx_http_spdy_close_stream_handler;
        return;
    }

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

    ngx_http_free_request(stream->request, rc);

    ev = fc->read;

    if (ev->active || ev->disabled) {
        ngx_log_error(NGX_LOG_ALERT, sc->connection->log, 0,
                      "fake read event was activated");
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->prev) {
        ngx_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->active || ev->disabled) {
        ngx_log_error(NGX_LOG_ALERT, sc->connection->log, 0,
                      "fake write event was activated");
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
    c->write->handler = ngx_http_empty_handler;

    sc->last_out = NULL;

    sc->blocked = 1;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    size = ngx_http_spdy_streams_index_size(sscf);

    for (i = 0; i < size; i++) {
        stream = sc->streams_index[i];

        while (stream) {
            stream->handled = 0;

            r = stream->request;
            fc = r->connection;

            fc->error = 1;

            if (stream->queued) {
                stream->queued = 0;

                ev = fc->write;
                ev->delayed = 0;

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


static ngx_int_t
ngx_http_spdy_adjust_windows(ngx_http_spdy_connection_t *sc, ssize_t delta)
{
    ngx_uint_t                 i, size;
    ngx_event_t               *wev;
    ngx_http_spdy_stream_t    *stream, *sn;
    ngx_http_spdy_srv_conf_t  *sscf;

    sscf = ngx_http_get_module_srv_conf(sc->http_connection->conf_ctx,
                                        ngx_http_spdy_module);

    size = ngx_http_spdy_streams_index_size(sscf);

    for (i = 0; i < size; i++) {

        for (stream = sc->streams_index[i]; stream; stream = sn) {
            sn = stream->index;

            if (delta > 0
                && stream->send_window
                      > (ssize_t) (NGX_SPDY_MAX_WINDOW - delta))
            {
                if (ngx_http_spdy_terminate_stream(sc, stream,
                                                   NGX_SPDY_FLOW_CONTROL_ERROR)
                    == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                continue;
            }

            stream->send_window += delta;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy:%ui adjust window:%z",
                           stream->id, stream->send_window);

            if (stream->send_window > 0 && stream->exhausted) {
                stream->exhausted = 0;

                wev = stream->request->connection->write;

                if (!wev->timer_set) {
                    wev->delayed = 0;
                    wev->handler(wev);
                }
            }
        }
    }

    return NGX_OK;
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
