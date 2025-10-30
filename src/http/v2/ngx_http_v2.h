/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_HTTP_V2_H_INCLUDED_
#define _NGX_HTTP_V2_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V2_ALPN_PROTO           "\x02h2"

#define NGX_HTTP_V2_STATE_BUFFER_SIZE    16

#define NGX_HTTP_V2_DEFAULT_FRAME_SIZE   (1 << 14)
#define NGX_HTTP_V2_MAX_FRAME_SIZE       ((1 << 24) - 1)

#define NGX_HTTP_V2_INT_OCTETS           4
#define NGX_HTTP_V2_MAX_FIELD                                                 \
    (127 + (1 << (NGX_HTTP_V2_INT_OCTETS - 1) * 7) - 1)

#define NGX_HTTP_V2_FRAME_HEADER_SIZE    9

/* frame types */
#define NGX_HTTP_V2_DATA_FRAME           0x0
#define NGX_HTTP_V2_HEADERS_FRAME        0x1
#define NGX_HTTP_V2_PRIORITY_FRAME       0x2
#define NGX_HTTP_V2_RST_STREAM_FRAME     0x3
#define NGX_HTTP_V2_SETTINGS_FRAME       0x4
#define NGX_HTTP_V2_PUSH_PROMISE_FRAME   0x5
#define NGX_HTTP_V2_PING_FRAME           0x6
#define NGX_HTTP_V2_GOAWAY_FRAME         0x7
#define NGX_HTTP_V2_WINDOW_UPDATE_FRAME  0x8
#define NGX_HTTP_V2_CONTINUATION_FRAME   0x9

/* frame flags */
#define NGX_HTTP_V2_NO_FLAG              0x00
#define NGX_HTTP_V2_ACK_FLAG             0x01
#define NGX_HTTP_V2_END_STREAM_FLAG      0x01
#define NGX_HTTP_V2_END_HEADERS_FLAG     0x04
#define NGX_HTTP_V2_PADDED_FLAG          0x08
#define NGX_HTTP_V2_PRIORITY_FLAG        0x20

#define NGX_HTTP_V2_MAX_WINDOW           ((1U << 31) - 1)
#define NGX_HTTP_V2_DEFAULT_WINDOW       65535

#define NGX_HTTP_V2_DEFAULT_WEIGHT       16


typedef struct ngx_http_v2_connection_s   ngx_http_v2_connection_t;
typedef struct ngx_http_v2_node_s         ngx_http_v2_node_t;
typedef struct ngx_http_v2_out_frame_s    ngx_http_v2_out_frame_t;


typedef u_char *(*ngx_http_v2_handler_pt) (ngx_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);


typedef struct {
    ngx_flag_t                       enable;
    size_t                           pool_size;
    ngx_uint_t                       concurrent_streams;
    size_t                           preread_size;
    ngx_uint_t                       streams_index_mask;
} ngx_http_v2_srv_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_str_t                        value;
} ngx_http_v2_header_t;


typedef struct {
    ngx_uint_t                       sid;
    size_t                           length;
    size_t                           padding;
    unsigned                         flags:8;

    unsigned                         incomplete:1;
    unsigned                         keep_pool:1;

    /* HPACK */
    unsigned                         parse_name:1;
    unsigned                         parse_value:1;
    unsigned                         index:1;
    ngx_http_v2_header_t             header;
    size_t                           header_limit;
    u_char                           field_state;
    u_char                          *field_start;
    u_char                          *field_end;
    size_t                           field_rest;
    ngx_pool_t                      *pool;

    ngx_http_v2_stream_t            *stream;

    u_char                           buffer[NGX_HTTP_V2_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    ngx_http_v2_handler_pt           handler;
} ngx_http_v2_state_t;



typedef struct {
    ngx_http_v2_header_t           **entries;

    ngx_uint_t                       added;
    ngx_uint_t                       deleted;
    ngx_uint_t                       reused;
    ngx_uint_t                       allocated;

    size_t                           size;
    size_t                           free;
    u_char                          *storage;
    u_char                          *pos;
} ngx_http_v2_hpack_t;


struct ngx_http_v2_connection_s {
    ngx_connection_t                *connection;
    ngx_http_connection_t           *http_connection;

    off_t                            total_bytes;
    off_t                            payload_bytes;

    ngx_uint_t                       processing;
    ngx_uint_t                       frames;
    ngx_uint_t                       idle;
    ngx_uint_t                       new_streams;
    ngx_uint_t                       refused_streams;
    ngx_uint_t                       priority_limit;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    size_t                           frame_size;

    ngx_queue_t                      waiting;

    ngx_http_v2_state_t              state;

    ngx_http_v2_hpack_t              hpack;

    ngx_pool_t                      *pool;

    ngx_http_v2_out_frame_t         *free_frames;
    ngx_connection_t                *free_fake_connections;

    ngx_http_v2_node_t             **streams_index;

    ngx_http_v2_out_frame_t         *last_out;

    ngx_queue_t                      dependencies;
    ngx_queue_t                      closed;

    ngx_uint_t                       closed_nodes;
    ngx_uint_t                       last_sid;

    time_t                           lingering_time;

    unsigned                         settings_ack:1;
    unsigned                         table_update:1;
    unsigned                         blocked:1;
    unsigned                         goaway:1;
};


struct ngx_http_v2_node_s {
    ngx_uint_t                       id;
    ngx_http_v2_node_t              *index;
    ngx_http_v2_node_t              *parent;
    ngx_queue_t                      queue;
    ngx_queue_t                      children;
    ngx_queue_t                      reuse;
    ngx_uint_t                       rank;
    ngx_uint_t                       weight;
    double                           rel_weight;
    ngx_http_v2_stream_t            *stream;
};


struct ngx_http_v2_stream_s {
    ngx_http_request_t              *request;
    ngx_http_v2_connection_t        *connection;
    ngx_http_v2_node_t              *node;

    ngx_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_buf_t                       *preread;

    ngx_uint_t                       frames;

    ngx_http_v2_out_frame_t         *free_frames;
    ngx_chain_t                     *free_frame_headers;
    ngx_chain_t                     *free_bufs;

    ngx_queue_t                      queue;

    ngx_array_t                     *cookies;

    ngx_pool_t                      *pool;

    unsigned                         initialized:1;
    unsigned                         waiting:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         rst_sent:1;
    unsigned                         no_flow_control:1;
    unsigned                         skip_data:1;
};


struct ngx_http_v2_out_frame_s {
    ngx_http_v2_out_frame_t         *next;
    ngx_chain_t                     *first;
    ngx_chain_t                     *last;
    ngx_int_t                      (*handler)(ngx_http_v2_connection_t *h2c,
                                        ngx_http_v2_out_frame_t *frame);

    ngx_http_v2_stream_t            *stream;
    size_t                           length;

    unsigned                         blocked:1;
    unsigned                         fin:1;
};


static ngx_inline void
ngx_http_v2_queue_frame(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }

        if ((*out)->stream->node->rank < frame->stream->node->rank
            || ((*out)->stream->node->rank == frame->stream->node->rank
                && (*out)->stream->node->rel_weight
                   >= frame->stream->node->rel_weight))
        {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static ngx_inline void
ngx_http_v2_queue_blocked_frame(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    ngx_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static ngx_inline void
ngx_http_v2_queue_ordered_frame(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_out_frame_t *frame)
{
    frame->next = h2c->last_out;
    h2c->last_out = frame;
}


void ngx_http_v2_init(ngx_event_t *rev);

ngx_int_t ngx_http_v2_read_request_body(ngx_http_request_t *r);
ngx_int_t ngx_http_v2_read_unbuffered_request_body(ngx_http_request_t *r);

void ngx_http_v2_close_stream(ngx_http_v2_stream_t *stream, ngx_int_t rc);

ngx_int_t ngx_http_v2_send_output_queue(ngx_http_v2_connection_t *h2c);


ngx_str_t *ngx_http_v2_get_static_name(ngx_uint_t index);
ngx_str_t *ngx_http_v2_get_static_value(ngx_uint_t index);

ngx_int_t ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c,
    ngx_uint_t index, ngx_uint_t name_only);
ngx_int_t ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header);
ngx_int_t ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size);


#define ngx_http_v2_prefix(bits)  ((1 << (bits)) - 1)


#if (NGX_HAVE_NONALIGNED)

#define ngx_http_v2_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_http_v2_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#else

#define ngx_http_v2_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define ngx_http_v2_parse_uint32(p)                                           \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif

#define ngx_http_v2_parse_length(p)  ((p) >> 8)
#define ngx_http_v2_parse_type(p)    ((p) & 0xff)
#define ngx_http_v2_parse_sid(p)     (ngx_http_v2_parse_uint32(p) & 0x7fffffff)
#define ngx_http_v2_parse_window(p)  (ngx_http_v2_parse_uint32(p) & 0x7fffffff)


#define ngx_http_v2_write_uint16_aligned(p, s)                                \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
#define ngx_http_v2_write_uint32_aligned(p, s)                                \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#if (NGX_HAVE_NONALIGNED)

#define ngx_http_v2_write_uint16  ngx_http_v2_write_uint16_aligned
#define ngx_http_v2_write_uint32  ngx_http_v2_write_uint32_aligned

#else

#define ngx_http_v2_write_uint16(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define ngx_http_v2_write_uint32(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif

#define ngx_http_v2_write_len_and_type(p, l, t)                               \
    ngx_http_v2_write_uint32_aligned(p, (l) << 8 | (t))

#define ngx_http_v2_write_sid  ngx_http_v2_write_uint32


#define ngx_http_v2_indexed(i)      (128 + (i))
#define ngx_http_v2_inc_indexed(i)  (64 + (i))

#define ngx_http_v2_write_name(dst, src, len, tmp)                            \
    ngx_http_v2_string_encode(dst, src, len, tmp, 1)
#define ngx_http_v2_write_value(dst, src, len, tmp)                           \
    ngx_http_v2_string_encode(dst, src, len, tmp, 0)

#define NGX_HTTP_V2_ENCODE_RAW            0
#define NGX_HTTP_V2_ENCODE_HUFF           0x80

#define NGX_HTTP_V2_AUTHORITY_INDEX       1

#define NGX_HTTP_V2_METHOD_INDEX          2
#define NGX_HTTP_V2_METHOD_GET_INDEX      2
#define NGX_HTTP_V2_METHOD_POST_INDEX     3

#define NGX_HTTP_V2_PATH_INDEX            4
#define NGX_HTTP_V2_PATH_ROOT_INDEX       4

#define NGX_HTTP_V2_SCHEME_HTTP_INDEX     6
#define NGX_HTTP_V2_SCHEME_HTTPS_INDEX    7

#define NGX_HTTP_V2_STATUS_INDEX          8
#define NGX_HTTP_V2_STATUS_200_INDEX      8
#define NGX_HTTP_V2_STATUS_204_INDEX      9
#define NGX_HTTP_V2_STATUS_206_INDEX      10
#define NGX_HTTP_V2_STATUS_304_INDEX      11
#define NGX_HTTP_V2_STATUS_400_INDEX      12
#define NGX_HTTP_V2_STATUS_404_INDEX      13
#define NGX_HTTP_V2_STATUS_500_INDEX      14

#define NGX_HTTP_V2_CONTENT_LENGTH_INDEX  28
#define NGX_HTTP_V2_CONTENT_TYPE_INDEX    31
#define NGX_HTTP_V2_DATE_INDEX            33
#define NGX_HTTP_V2_LAST_MODIFIED_INDEX   44
#define NGX_HTTP_V2_LOCATION_INDEX        46
#define NGX_HTTP_V2_SERVER_INDEX          54
#define NGX_HTTP_V2_VARY_INDEX            59

#define NGX_HTTP_V2_PREFACE_START         "PRI * HTTP/2.0\r\n"
#define NGX_HTTP_V2_PREFACE_END           "\r\nSM\r\n\r\n"
#define NGX_HTTP_V2_PREFACE               NGX_HTTP_V2_PREFACE_START           \
                                          NGX_HTTP_V2_PREFACE_END


u_char *ngx_http_v2_string_encode(u_char *dst, u_char *src, size_t len,
    u_char *tmp, ngx_uint_t lower);

ngx_int_t ngx_http_v2_proxy_handler(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_v2_module;


#endif /* _NGX_HTTP_V2_H_INCLUDED_ */
