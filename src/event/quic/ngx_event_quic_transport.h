
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_TRANSPORT_H_INCLUDED_
#define _NGX_EVENT_QUIC_TRANSPORT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * RFC 9000, 17.2.  Long Header Packets
 *           17.3.  Short Header Packets
 *
 * QUIC flags in first byte
 */
#define NGX_QUIC_PKT_LONG       0x80  /* header form */
#define NGX_QUIC_PKT_FIXED_BIT  0x40
#define NGX_QUIC_PKT_TYPE       0x30  /* in long packet */
#define NGX_QUIC_PKT_KPHASE     0x04  /* in short packet */

#define ngx_quic_long_pkt(flags)  ((flags) & NGX_QUIC_PKT_LONG)
#define ngx_quic_short_pkt(flags)  (((flags) & NGX_QUIC_PKT_LONG) == 0)

/* Long packet types */
#define NGX_QUIC_PKT_INITIAL    0x00
#define NGX_QUIC_PKT_ZRTT       0x10
#define NGX_QUIC_PKT_HANDSHAKE  0x20
#define NGX_QUIC_PKT_RETRY      0x30

#define ngx_quic_pkt_in(flags)                                                \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_INITIAL)
#define ngx_quic_pkt_zrtt(flags)                                              \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_ZRTT)
#define ngx_quic_pkt_hs(flags)                                                \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_HANDSHAKE)
#define ngx_quic_pkt_retry(flags)                                             \
    (((flags) & NGX_QUIC_PKT_TYPE) == NGX_QUIC_PKT_RETRY)

#define ngx_quic_pkt_rb_mask(flags)                                           \
    (ngx_quic_long_pkt(flags) ? 0x0C : 0x18)
#define ngx_quic_pkt_hp_mask(flags)                                           \
    (ngx_quic_long_pkt(flags) ? 0x0F : 0x1F)

#define ngx_quic_level_name(lvl)                                              \
    (lvl == NGX_QUIC_ENCRYPTION_APPLICATION) ? "app"                          \
        : (lvl == NGX_QUIC_ENCRYPTION_INITIAL) ? "init"                       \
            : (lvl == NGX_QUIC_ENCRYPTION_HANDSHAKE) ? "hs" : "early"

#define NGX_QUIC_MAX_CID_LEN                             20
#define NGX_QUIC_SERVER_CID_LEN                          NGX_QUIC_MAX_CID_LEN

/* 12.4.  Frames and Frame Types */
#define NGX_QUIC_FT_PADDING                              0x00
#define NGX_QUIC_FT_PING                                 0x01
#define NGX_QUIC_FT_ACK                                  0x02
#define NGX_QUIC_FT_ACK_ECN                              0x03
#define NGX_QUIC_FT_RESET_STREAM                         0x04
#define NGX_QUIC_FT_STOP_SENDING                         0x05
#define NGX_QUIC_FT_CRYPTO                               0x06
#define NGX_QUIC_FT_NEW_TOKEN                            0x07
#define NGX_QUIC_FT_STREAM                               0x08
#define NGX_QUIC_FT_STREAM1                              0x09
#define NGX_QUIC_FT_STREAM2                              0x0A
#define NGX_QUIC_FT_STREAM3                              0x0B
#define NGX_QUIC_FT_STREAM4                              0x0C
#define NGX_QUIC_FT_STREAM5                              0x0D
#define NGX_QUIC_FT_STREAM6                              0x0E
#define NGX_QUIC_FT_STREAM7                              0x0F
#define NGX_QUIC_FT_MAX_DATA                             0x10
#define NGX_QUIC_FT_MAX_STREAM_DATA                      0x11
#define NGX_QUIC_FT_MAX_STREAMS                          0x12
#define NGX_QUIC_FT_MAX_STREAMS2                         0x13
#define NGX_QUIC_FT_DATA_BLOCKED                         0x14
#define NGX_QUIC_FT_STREAM_DATA_BLOCKED                  0x15
#define NGX_QUIC_FT_STREAMS_BLOCKED                      0x16
#define NGX_QUIC_FT_STREAMS_BLOCKED2                     0x17
#define NGX_QUIC_FT_NEW_CONNECTION_ID                    0x18
#define NGX_QUIC_FT_RETIRE_CONNECTION_ID                 0x19
#define NGX_QUIC_FT_PATH_CHALLENGE                       0x1A
#define NGX_QUIC_FT_PATH_RESPONSE                        0x1B
#define NGX_QUIC_FT_CONNECTION_CLOSE                     0x1C
#define NGX_QUIC_FT_CONNECTION_CLOSE_APP                 0x1D
#define NGX_QUIC_FT_HANDSHAKE_DONE                       0x1E

#define NGX_QUIC_FT_LAST  NGX_QUIC_FT_HANDSHAKE_DONE

/* 22.5.  QUIC Transport Error Codes Registry */
#define NGX_QUIC_ERR_NO_ERROR                            0x00
#define NGX_QUIC_ERR_INTERNAL_ERROR                      0x01
#define NGX_QUIC_ERR_CONNECTION_REFUSED                  0x02
#define NGX_QUIC_ERR_FLOW_CONTROL_ERROR                  0x03
#define NGX_QUIC_ERR_STREAM_LIMIT_ERROR                  0x04
#define NGX_QUIC_ERR_STREAM_STATE_ERROR                  0x05
#define NGX_QUIC_ERR_FINAL_SIZE_ERROR                    0x06
#define NGX_QUIC_ERR_FRAME_ENCODING_ERROR                0x07
#define NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR           0x08
#define NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR           0x09
#define NGX_QUIC_ERR_PROTOCOL_VIOLATION                  0x0A
#define NGX_QUIC_ERR_INVALID_TOKEN                       0x0B
#define NGX_QUIC_ERR_APPLICATION_ERROR                   0x0C
#define NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED              0x0D
#define NGX_QUIC_ERR_KEY_UPDATE_ERROR                    0x0E
#define NGX_QUIC_ERR_AEAD_LIMIT_REACHED                  0x0F
#define NGX_QUIC_ERR_NO_VIABLE_PATH                      0x10

#define NGX_QUIC_ERR_CRYPTO_ERROR                       0x100

#define NGX_QUIC_ERR_CRYPTO(e)  (NGX_QUIC_ERR_CRYPTO_ERROR + (e))

/* The special code to close connection without any response */
#define NGX_QUIC_ERR_CLOSE                         0x10000000


/* 22.3.  QUIC Transport Parameters Registry */
#define NGX_QUIC_TP_ORIGINAL_DCID                        0x00
#define NGX_QUIC_TP_MAX_IDLE_TIMEOUT                     0x01
#define NGX_QUIC_TP_SR_TOKEN                             0x02
#define NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE                 0x03
#define NGX_QUIC_TP_INITIAL_MAX_DATA                     0x04
#define NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL   0x05
#define NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE  0x06
#define NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI          0x07
#define NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI             0x08
#define NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI              0x09
#define NGX_QUIC_TP_ACK_DELAY_EXPONENT                   0x0A
#define NGX_QUIC_TP_MAX_ACK_DELAY                        0x0B
#define NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION             0x0C
#define NGX_QUIC_TP_PREFERRED_ADDRESS                    0x0D
#define NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT           0x0E
#define NGX_QUIC_TP_INITIAL_SCID                         0x0F
#define NGX_QUIC_TP_RETRY_SCID                           0x10

#define NGX_QUIC_CID_LEN_MIN                                8
#define NGX_QUIC_CID_LEN_MAX                               20

#define NGX_QUIC_MAX_RANGES                                10


typedef struct {
    uint64_t                                    gap;
    uint64_t                                    range;
} ngx_quic_ack_range_t;


typedef struct {
    uint64_t                                    largest;
    uint64_t                                    delay;
    uint64_t                                    range_count;
    uint64_t                                    first_range;
    uint64_t                                    ect0;
    uint64_t                                    ect1;
    uint64_t                                    ce;
    uint64_t                                    ranges_length;
} ngx_quic_ack_frame_t;


typedef struct {
    uint64_t                                    seqnum;
    uint64_t                                    retire;
    uint8_t                                     len;
    u_char                                      cid[NGX_QUIC_CID_LEN_MAX];
    u_char                                      srt[NGX_QUIC_SR_TOKEN_LEN];
} ngx_quic_new_conn_id_frame_t;


typedef struct {
    uint64_t                                    length;
} ngx_quic_new_token_frame_t;

/*
 * common layout for CRYPTO and STREAM frames;
 * conceptually, CRYPTO frame is also a stream
 * frame lacking some properties
 */
typedef struct {
    uint64_t                                    offset;
    uint64_t                                    length;
} ngx_quic_ordered_frame_t;

typedef ngx_quic_ordered_frame_t  ngx_quic_crypto_frame_t;


typedef struct {
    /* initial fields same as in ngx_quic_ordered_frame_t */
    uint64_t                                    offset;
    uint64_t                                    length;

    uint64_t                                    stream_id;
    unsigned                                    off:1;
    unsigned                                    len:1;
    unsigned                                    fin:1;
} ngx_quic_stream_frame_t;


typedef struct {
    uint64_t                                    max_data;
} ngx_quic_max_data_frame_t;


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


typedef struct {
    uint64_t                                    limit;
    ngx_uint_t                                  bidi;  /* unsigned: bidi:1 */
} ngx_quic_streams_blocked_frame_t;


typedef struct {
    uint64_t                                    limit;
    ngx_uint_t                                  bidi;  /* unsigned: bidi:1 */
} ngx_quic_max_streams_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    limit;
} ngx_quic_max_stream_data_frame_t;


typedef struct {
    uint64_t                                    limit;
} ngx_quic_data_blocked_frame_t;


typedef struct {
    uint64_t                                    id;
    uint64_t                                    limit;
} ngx_quic_stream_data_blocked_frame_t;


typedef struct {
    uint64_t                                    sequence_number;
} ngx_quic_retire_cid_frame_t;


typedef struct {
    u_char                                      data[8];
} ngx_quic_path_challenge_frame_t;


typedef struct ngx_quic_frame_s                 ngx_quic_frame_t;

struct ngx_quic_frame_s {
    ngx_uint_t                                  type;
    ngx_uint_t                                  level;
    ngx_queue_t                                 queue;
    uint64_t                                    pnum;
    size_t                                      plen;
    ngx_msec_t                                  send_time;
    ssize_t                                     len;
    unsigned                                    need_ack:1;
    unsigned                                    pkt_need_ack:1;
    unsigned                                    ignore_congestion:1;
    unsigned                                    ignore_loss:1;

    ngx_chain_t                                *data;
    union {
        ngx_quic_ack_frame_t                    ack;
        ngx_quic_crypto_frame_t                 crypto;
        ngx_quic_ordered_frame_t                ord;
        ngx_quic_new_conn_id_frame_t            ncid;
        ngx_quic_new_token_frame_t              token;
        ngx_quic_stream_frame_t                 stream;
        ngx_quic_max_data_frame_t               max_data;
        ngx_quic_close_frame_t                  close;
        ngx_quic_reset_stream_frame_t           reset_stream;
        ngx_quic_stop_sending_frame_t           stop_sending;
        ngx_quic_streams_blocked_frame_t        streams_blocked;
        ngx_quic_max_streams_frame_t            max_streams;
        ngx_quic_max_stream_data_frame_t        max_stream_data;
        ngx_quic_data_blocked_frame_t           data_blocked;
        ngx_quic_stream_data_blocked_frame_t    stream_data_blocked;
        ngx_quic_retire_cid_frame_t             retire_cid;
        ngx_quic_path_challenge_frame_t         path_challenge;
        ngx_quic_path_challenge_frame_t         path_response;
    } u;
};


typedef struct {
    ngx_log_t                                  *log;
    ngx_quic_path_t                            *path;

    ngx_quic_keys_t                            *keys;

    ngx_msec_t                                  received;
    uint64_t                                    number;
    uint8_t                                     num_len;
    uint32_t                                    trunc;
    uint8_t                                     flags;
    uint32_t                                    version;
    ngx_str_t                                   token;
    ngx_uint_t                                  level;
    ngx_uint_t                                  error;

    /* filled in by parser */
    ngx_buf_t                                  *raw;   /* udp datagram */

    u_char                                     *data;  /* quic packet */
    size_t                                      len;

    /* cleartext fields */
    ngx_str_t                                   odcid; /* retry packet tag */
    u_char                                      odcid_buf[NGX_QUIC_MAX_CID_LEN];
    ngx_str_t                                   dcid;
    ngx_str_t                                   scid;
    uint64_t                                    pn;
    u_char                                     *plaintext;
    ngx_str_t                                   payload; /* decrypted data */

    unsigned                                    need_ack:1;
    unsigned                                    key_phase:1;
    unsigned                                    key_update:1;
    unsigned                                    parsed:1;
    unsigned                                    decrypted:1;
    unsigned                                    validated:1;
    unsigned                                    retried:1;
    unsigned                                    first:1;
    unsigned                                    rebound:1;
    unsigned                                    path_challenged:1;
} ngx_quic_header_t;


typedef struct {
    ngx_msec_t                 max_idle_timeout;
    ngx_msec_t                 max_ack_delay;

    size_t                     max_udp_payload_size;
    size_t                     initial_max_data;
    size_t                     initial_max_stream_data_bidi_local;
    size_t                     initial_max_stream_data_bidi_remote;
    size_t                     initial_max_stream_data_uni;
    ngx_uint_t                 initial_max_streams_bidi;
    ngx_uint_t                 initial_max_streams_uni;
    ngx_uint_t                 ack_delay_exponent;
    ngx_uint_t                 active_connection_id_limit;
    ngx_flag_t                 disable_active_migration;

    ngx_str_t                  original_dcid;
    ngx_str_t                  initial_scid;
    ngx_str_t                  retry_scid;
    u_char                     sr_token[NGX_QUIC_SR_TOKEN_LEN];

    /* TODO */
    void                      *preferred_address;
} ngx_quic_tp_t;


ngx_int_t ngx_quic_parse_packet(ngx_quic_header_t *pkt);

size_t ngx_quic_create_version_negotiation(ngx_quic_header_t *pkt, u_char *out);

size_t ngx_quic_payload_size(ngx_quic_header_t *pkt, size_t pkt_len);

size_t ngx_quic_create_header(ngx_quic_header_t *pkt, u_char *out,
    u_char **pnp);

size_t ngx_quic_create_retry_itag(ngx_quic_header_t *pkt, u_char *out,
    u_char **start);

ssize_t ngx_quic_parse_frame(ngx_quic_header_t *pkt, u_char *start, u_char *end,
    ngx_quic_frame_t *frame, ngx_uint_t is_server);
ssize_t ngx_quic_create_frame(u_char *p, ngx_quic_frame_t *f);

ssize_t ngx_quic_parse_ack_range(ngx_log_t *log, u_char *start,
    u_char *end, uint64_t *gap, uint64_t *range);
size_t ngx_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range);

ngx_int_t ngx_quic_init_transport_params(ngx_quic_tp_t *tp,
    ngx_quic_conf_t *qcf);
ngx_int_t ngx_quic_parse_transport_params(u_char *p, u_char *end,
    ngx_quic_tp_t *tp, ngx_uint_t is_server, ngx_log_t *log);
ssize_t ngx_quic_create_transport_params(u_char *p, u_char *end,
    ngx_quic_tp_t *tp, size_t *clen, ngx_uint_t is_server);

void ngx_quic_dcid_encode_key(u_char *dcid, uint64_t key);

#endif /* _NGX_EVENT_QUIC_TRANSPORT_H_INCLUDED_ */
