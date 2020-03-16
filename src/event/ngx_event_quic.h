
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <ngx_event_openssl.h>


#define quic_version                       0xff000018  /* draft-24 */

/* 17.2.  Long Header Packets */

#define NGX_QUIC_PKT_LONG                  0x80

#define NGX_QUIC_PKT_INITIAL               0xc0
#define NGX_QUIC_PKT_HANDSHAKE             0xe0


#if (NGX_HAVE_NONALIGNED)

#define ngx_quic_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define ngx_quic_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#define ngx_quic_write_uint16  ngx_quic_write_uint16_aligned
#define ngx_quic_write_uint32  ngx_quic_write_uint32_aligned

#else

#define ngx_quic_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define ngx_quic_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define ngx_quic_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif


#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define ngx_quic_varint_len(value)                                            \
     ((value) <= 63 ? 1                                                       \
     : ((uint32_t) value) <= 16383 ? 2                                        \
     : ((uint64_t) value) <= 1073741823 ?  4                                  \
     : 8)


struct ngx_quic_stream_s {
    uint64_t            id;
    ngx_uint_t          unidirectional:1;
    ngx_connection_t   *parent;
    void               *data;
};

typedef struct ngx_quic_secret_s ngx_quic_secret_t;
typedef enum ssl_encryption_level_t  ngx_quic_level_t;

typedef struct {
    ngx_quic_secret_t  *secret;
    ngx_uint_t          type;
    ngx_uint_t          *number;
    ngx_uint_t          flags;
    uint32_t            version;
    ngx_str_t           token;
    ngx_quic_level_t    level;

    /* filled in by parser */
    ngx_buf_t          *raw;        /* udp datagram from wire */

    u_char             *data;       /* quic packet */
    size_t              len;

    /* cleartext fields */
    ngx_str_t           dcid;
    ngx_str_t           scid;

    uint64_t            pn;

    ngx_str_t           payload;  /* decrypted payload */

} ngx_quic_header_t;

void ngx_quic_build_int(u_char **pos, uint64_t value);

void ngx_quic_init_ssl_methods(SSL_CTX* ctx);

void ngx_quic_run(ngx_connection_t *c, ngx_ssl_t *ssl, ngx_msec_t timeout,
    ngx_connection_handler_pt handler);
ngx_connection_t *ngx_quic_create_uni_stream(ngx_connection_t *c);


/********************************* DEBUG *************************************/

#if (NGX_DEBUG)

#define ngx_quic_hexdump(log, fmt, data, len, ...)                            \
do {                                                                          \
    ngx_int_t  m;                                                             \
    u_char     buf[2048];                                                     \
                                                                              \
    if (log->log_level & NGX_LOG_DEBUG_EVENT) {                               \
        m = ngx_hex_dump(buf, (u_char *) data, ngx_min(len, 1024)) - buf;     \
        ngx_log_debug(NGX_LOG_DEBUG_EVENT, log, 0,                            \
                   "%s: " fmt " %*s%s, len: %uz",                             \
                   __FUNCTION__,  __VA_ARGS__, m, buf,                        \
                   len < 2048 ? "" : "...", len);                             \
    }                                                                         \
} while (0)

#else

#define ngx_quic_hexdump(log, fmt, data, len, ...)

#endif

#define ngx_quic_hexdump0(log, fmt, data, len)                                \
    ngx_quic_hexdump(log, fmt "%s", data, len, "")                            \


#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
