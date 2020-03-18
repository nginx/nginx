
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_WIRE_H_INCLUDED_
#define _NGX_EVENT_QUIC_WIRE_H_INCLUDED_


#include <ngx_event_openssl.h>


/* 17.2.  Long Header Packets */
#define NGX_QUIC_PKT_LONG                       0x80

#define NGX_QUIC_PKT_INITIAL                    0xC0
#define NGX_QUIC_PKT_HANDSHAKE                  0xE0

/* 12.4.  Frames and Frame Types */
#define NGX_QUIC_FT_PADDING                     0x00
#define NGX_QUIC_FT_PING                        0x01
#define NGX_QUIC_FT_ACK                         0x02
#define NGX_QUIC_FT_ACK_ECN                     0x03
#define NGX_QUIC_FT_RESET_STREAM                0x04
#define NGX_QUIC_FT_STOP_SENDING                0x05
#define NGX_QUIC_FT_CRYPTO                      0x06
#define NGX_QUIC_FT_NEW_TOKEN                   0x07
#define NGX_QUIC_FT_STREAM0                     0x08
#define NGX_QUIC_FT_STREAM1                     0x09
#define NGX_QUIC_FT_STREAM2                     0x0A
#define NGX_QUIC_FT_STREAM3                     0x0B
#define NGX_QUIC_FT_STREAM4                     0x0C
#define NGX_QUIC_FT_STREAM5                     0x0D
#define NGX_QUIC_FT_STREAM6                     0x0E
#define NGX_QUIC_FT_STREAM7                     0x0F
#define NGX_QUIC_FT_MAX_DATA                    0x10
#define NGX_QUIC_FT_MAX_STREAM_DATA             0x11
#define NGX_QUIC_FT_MAX_STREAMS                 0x12
#define NGX_QUIC_FT_MAX_STREAMS2                0x13 // XXX
#define NGX_QUIC_FT_DATA_BLOCKED                0x14
#define NGX_QUIC_FT_STREAM_DATA_BLOCKED         0x15
#define NGX_QUIC_FT_STREAMS_BLOCKED             0x16
#define NGX_QUIC_FT_STREAMS_BLOCKED2            0x17 // XXX
#define NGX_QUIC_FT_NEW_CONNECTION_ID           0x18
#define NGX_QUIC_FT_RETIRE_CONNECTION_ID        0x19
#define NGX_QUIC_FT_PATH_CHALLENGE              0x1A
#define NGX_QUIC_FT_PATH_RESPONSE               0x1B
#define NGX_QUIC_FT_CONNECTION_CLOSE            0x1C
#define NGX_QUIC_FT_CONNECTION_CLOSE2           0x1D // XXX
#define NGX_QUIC_FT_HANDSHAKE_DONE              0x1E

/* 22.4.  QUIC Transport Error Codes Registry */
#define NGX_QUIC_ERR_NO_ERROR                   0x00
#define NGX_QUIC_ERR_INTERNAL_ERROR             0x01
#define NGX_QUIC_ERR_SERVER_BUSY                0x02
#define NGX_QUIC_ERR_FLOW_CONTROL_ERROR         0x03
#define NGX_QUIC_ERR_STREAM_LIMIT_ERROR         0x04
#define NGX_QUIC_ERR_STREAM_STATE_ERROR         0x05
#define NGX_QUIC_ERR_FINAL_SIZE_ERROR           0x06
#define NGX_QUIC_ERR_FRAME_ENCODING_ERROR       0x07
#define NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR  0x08
#define NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR  0x09
#define NGX_QUIC_ERR_PROTOCOL_VIOLATION         0x0A
#define NGX_QUIC_ERR_INVALID_TOKEN              0x0B
/* 0xC is not defined */
#define NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED     0x0D
#define NGX_QUIC_ERR_CRYPTO_ERROR               0x10

#define NGX_QUIC_ERR_LAST  NGX_QUIC_ERR_CRYPTO_ERROR


typedef struct {
    ngx_uint_t                                  pn;
    uint64_t                                    largest;
    uint64_t                                    delay;
    uint64_t                                    range_count;
    uint64_t                                    first_range;
    uint64_t                                    ranges[20];
    /* TODO: ecn counts */
} ngx_quic_ack_frame_t;


typedef struct {
    size_t                                      offset;
    size_t                                      len;
    u_char                                     *data;
} ngx_quic_crypto_frame_t;


typedef struct {
    uint64_t                                    seqnum;
    uint64_t                                    retire;
    uint64_t                                    len;
    u_char                                      cid[20];
    u_char                                      srt[16];
} ngx_quic_new_conn_id_frame_t;


typedef struct {
    uint8_t                                     type;
    uint64_t                                    stream_id;
    uint64_t                                    offset;
    uint64_t                                    length;
    unsigned                                    off:1;
    unsigned                                    len:1;
    unsigned                                    fin:1;
    u_char                                     *data;
} ngx_quic_stream_frame_t;


typedef struct {
    uint64_t                                    error_code;
    uint64_t                                    frame_type;
    ngx_str_t                                   reason;
} ngx_quic_close_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    error_code;
    uint64_t                                    final_size;
} ngx_quic_reset_stream_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    error_code;
} ngx_quic_stop_sending_frame_t;


typedef struct ngx_quic_frame_s                 ngx_quic_frame_t;

struct ngx_quic_frame_s {
    ngx_uint_t                                  type;
    enum ssl_encryption_level_t                 level;
    ngx_quic_frame_t                           *next;
    union {
        ngx_quic_ack_frame_t                    ack;
        ngx_quic_crypto_frame_t                 crypto;
        ngx_quic_new_conn_id_frame_t            ncid;
        ngx_quic_stream_frame_t                 stream;
        ngx_quic_close_frame_t                  close;
        ngx_quic_reset_stream_frame_t           reset_stream;
        ngx_quic_stop_sending_frame_t           stop_sending;
    } u;
    u_char                                      info[128]; // for debug
};


typedef struct {
    ngx_log_t                                  *log;

    struct ngx_quic_secret_s                   *secret;
    ngx_uint_t                                  type;
    ngx_uint_t                                  *number;
    ngx_uint_t                                  flags;
    uint32_t                                    version;
    ngx_str_t                                   token;
    enum ssl_encryption_level_t                 level;

    /* filled in by parser */
    ngx_buf_t                                  *raw;   /* udp datagram */

    u_char                                     *data;  /* quic packet */
    size_t                                      len;

    /* cleartext fields */
    ngx_str_t                                   dcid;
    ngx_str_t                                   scid;
    uint64_t                                    pn;
    ngx_str_t                                   payload;  /* decrypted */
} ngx_quic_header_t;


u_char *ngx_quic_error_text(uint64_t error_code);

ngx_int_t ngx_quic_parse_long_header(ngx_quic_header_t *pkt);
size_t ngx_quic_create_long_header(ngx_quic_header_t *pkt, ngx_str_t *out,
    size_t pkt_len, u_char **pnp);

ngx_int_t ngx_quic_parse_short_header(ngx_quic_header_t *pkt,
    ngx_str_t *dcid);
ngx_int_t ngx_quic_parse_initial_header(ngx_quic_header_t *pkt);
ngx_int_t ngx_quic_parse_handshake_header(ngx_quic_header_t *pkt);

ssize_t ngx_quic_parse_frame(u_char *start, u_char *end,
    ngx_quic_frame_t *frame);
ssize_t ngx_quic_create_frame(u_char *p, u_char *end, ngx_quic_frame_t *f);
size_t ngx_quic_frame_len(ngx_quic_frame_t *frame);

#endif /* _NGX_EVENT_QUIC_WIRE_H_INCLUDED_ */
