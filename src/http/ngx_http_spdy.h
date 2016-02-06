/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_HTTP_SPDY_H_INCLUDED_
#define _NGX_HTTP_SPDY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>


#define NGX_SPDY_VERSION              3

#define NGX_SPDY_NPN_ADVERTISE        "\x08spdy/3.1"
#define NGX_SPDY_NPN_NEGOTIATED       "spdy/3.1"

#define NGX_SPDY_STATE_BUFFER_SIZE    16

#define NGX_SPDY_CTL_BIT              1

#define NGX_SPDY_SYN_STREAM           1
#define NGX_SPDY_SYN_REPLY            2
#define NGX_SPDY_RST_STREAM           3
#define NGX_SPDY_SETTINGS             4
#define NGX_SPDY_PING                 6
#define NGX_SPDY_GOAWAY               7
#define NGX_SPDY_HEADERS              8
#define NGX_SPDY_WINDOW_UPDATE        9

#define NGX_SPDY_FRAME_HEADER_SIZE    8

#define NGX_SPDY_SID_SIZE             4
#define NGX_SPDY_DELTA_SIZE           4

#define NGX_SPDY_SYN_STREAM_SIZE      10
#define NGX_SPDY_SYN_REPLY_SIZE       4
#define NGX_SPDY_RST_STREAM_SIZE      8
#define NGX_SPDY_PING_SIZE            4
#define NGX_SPDY_GOAWAY_SIZE          8
#define NGX_SPDY_WINDOW_UPDATE_SIZE   8
#define NGX_SPDY_NV_NUM_SIZE          4
#define NGX_SPDY_NV_NLEN_SIZE         4
#define NGX_SPDY_NV_VLEN_SIZE         4
#define NGX_SPDY_SETTINGS_NUM_SIZE    4
#define NGX_SPDY_SETTINGS_FID_SIZE    4
#define NGX_SPDY_SETTINGS_VAL_SIZE    4

#define NGX_SPDY_SETTINGS_PAIR_SIZE                                           \
    (NGX_SPDY_SETTINGS_FID_SIZE + NGX_SPDY_SETTINGS_VAL_SIZE)

#define NGX_SPDY_HIGHEST_PRIORITY     0
#define NGX_SPDY_LOWEST_PRIORITY      7

#define NGX_SPDY_FLAG_FIN             0x01
#define NGX_SPDY_FLAG_UNIDIRECTIONAL  0x02
#define NGX_SPDY_FLAG_CLEAR_SETTINGS  0x01

#define NGX_SPDY_MAX_FRAME_SIZE       ((1 << 24) - 1)

#define NGX_SPDY_DATA_DISCARD         1
#define NGX_SPDY_DATA_ERROR           2
#define NGX_SPDY_DATA_INTERNAL_ERROR  3


typedef struct ngx_http_spdy_connection_s   ngx_http_spdy_connection_t;
typedef struct ngx_http_spdy_out_frame_s    ngx_http_spdy_out_frame_t;


typedef u_char *(*ngx_http_spdy_handler_pt) (ngx_http_spdy_connection_t *sc,
    u_char *pos, u_char *end);

struct ngx_http_spdy_connection_s {
    ngx_connection_t                *connection;
    ngx_http_connection_t           *http_connection;

    ngx_uint_t                       processing;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    ngx_queue_t                      waiting;

    u_char                           buffer[NGX_SPDY_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    ngx_http_spdy_handler_pt         handler;

    z_stream                         zstream_in;
    z_stream                         zstream_out;

    ngx_pool_t                      *pool;

    ngx_http_spdy_out_frame_t       *free_ctl_frames;
    ngx_connection_t                *free_fake_connections;

    ngx_http_spdy_stream_t         **streams_index;

    ngx_http_spdy_out_frame_t       *last_out;

    ngx_queue_t                      posted;

    ngx_http_spdy_stream_t          *stream;

    ngx_uint_t                       entries;
    size_t                           length;
    u_char                           flags;

    ngx_uint_t                       last_sid;

    unsigned                         blocked:1;
    unsigned                         incomplete:1;
};


struct ngx_http_spdy_stream_s {
    ngx_uint_t                       id;
    ngx_http_request_t              *request;
    ngx_http_spdy_connection_t      *connection;
    ngx_http_spdy_stream_t          *index;

    ngx_uint_t                       header_buffers;
    ngx_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_http_spdy_out_frame_t       *free_frames;
    ngx_chain_t                     *free_data_headers;
    ngx_chain_t                     *free_bufs;

    ngx_queue_t                      queue;

    unsigned                         priority:3;
    unsigned                         handled:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         skip_data:2;
};


struct ngx_http_spdy_out_frame_s {
    ngx_http_spdy_out_frame_t       *next;
    ngx_chain_t                     *first;
    ngx_chain_t                     *last;
    ngx_int_t                      (*handler)(ngx_http_spdy_connection_t *sc,
                                        ngx_http_spdy_out_frame_t *frame);

    ngx_http_spdy_stream_t          *stream;
    size_t                           length;

    ngx_uint_t                       priority;
    unsigned                         blocked:1;
    unsigned                         fin:1;
};


static ngx_inline void
ngx_http_spdy_queue_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_http_spdy_out_frame_t  **out;

    for (out = &sc->last_out; *out; out = &(*out)->next)
    {
        /*
         * NB: higher values represent lower priorities.
         */
        if (frame->priority >= (*out)->priority) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static ngx_inline void
ngx_http_spdy_queue_blocked_frame(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_http_spdy_out_frame_t  **out;

    for (out = &sc->last_out; *out; out = &(*out)->next)
    {
        if ((*out)->blocked) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


void ngx_http_spdy_init(ngx_event_t *rev);
void ngx_http_spdy_request_headers_init(void);

ngx_int_t ngx_http_spdy_read_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler);

void ngx_http_spdy_close_stream(ngx_http_spdy_stream_t *stream, ngx_int_t rc);

ngx_int_t ngx_http_spdy_send_output_queue(ngx_http_spdy_connection_t *sc);


#define ngx_spdy_frame_aligned_write_uint16(p, s)                             \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_spdy_frame_aligned_write_uint32(p, s)                             \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#if (NGX_HAVE_NONALIGNED)

#define ngx_spdy_frame_write_uint16  ngx_spdy_frame_aligned_write_uint16
#define ngx_spdy_frame_write_uint32  ngx_spdy_frame_aligned_write_uint32

#else

#define ngx_spdy_frame_write_uint16(p, s)                                     \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define ngx_spdy_frame_write_uint32(p, s)                                     \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif


#define ngx_spdy_ctl_frame_head(t)                                            \
    ((uint32_t) NGX_SPDY_CTL_BIT << 31 | NGX_SPDY_VERSION << 16 | (t))

#define ngx_spdy_frame_write_head(p, t)                                       \
    ngx_spdy_frame_aligned_write_uint32(p, ngx_spdy_ctl_frame_head(t))

#define ngx_spdy_frame_write_flags_and_len(p, f, l)                           \
    ngx_spdy_frame_aligned_write_uint32(p, (f) << 24 | (l))
#define ngx_spdy_frame_write_flags_and_id(p, f, i)                            \
    ngx_spdy_frame_aligned_write_uint32(p, (f) << 24 | (i))

#define ngx_spdy_frame_write_sid     ngx_spdy_frame_aligned_write_uint32
#define ngx_spdy_frame_write_window  ngx_spdy_frame_aligned_write_uint32

#endif /* _NGX_HTTP_SPDY_H_INCLUDED_ */
