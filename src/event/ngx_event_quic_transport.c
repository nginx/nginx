
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


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


static uint64_t ngx_quic_parse_int(u_char **pos);
static void ngx_quic_build_int(u_char **pos, uint64_t value);

static size_t ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack);
static size_t ngx_quic_create_crypto(u_char *p,
    ngx_quic_crypto_frame_t *crypto);
static size_t ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf);


/* literal errors indexed by corresponding value */
static char *ngx_quic_errors[] = {
    "NO_ERROR",
    "INTERNAL_ERROR",
    "SERVER_BUSY",
    "FLOW_CONTROL_ERROR",
    "STREAM_LIMIT_ERROR",
    "STREAM_STATE_ERROR",
    "FINAL_SIZE_ERROR",
    "FRAME_ENCODING_ERROR",
    "TRANSPORT_PARAMETER_ERROR",
    "CONNECTION_ID_LIMIT_ERROR",
    "PROTOCOL_VIOLATION",
    "INVALID_TOKEN",
    "",
    "CRYPTO_BUFFER_EXCEEDED",
    "CRYPTO_ERROR",
};


static uint64_t
ngx_quic_parse_int(u_char **pos)
{
    u_char      *p;
    uint64_t     value;
    ngx_uint_t   len;

    p = *pos;
    len = 1 << ((*p & 0xc0) >> 6);
    value = *p++ & 0x3f;

    while (--len) {
        value = (value << 8) + *p++;
    }

    *pos = p;
    return value;
}


static void
ngx_quic_build_int(u_char **pos, uint64_t value)
{
    u_char      *p;
    ngx_uint_t   len;//, len2;

    p = *pos;
    len = 0;

    while (value >> ((1 << len) * 8 - 2)) {
        len++;
    }

    *p = len << 6;

//    len2 =
    len = (1 << len);
    len--;
    *p |= value >> (len * 8);
    p++;

    while (len) {
        *p++ = value >> ((len-- - 1) * 8);
    }

    *pos = p;
//    return len2;
}


u_char *
ngx_quic_error_text(uint64_t error_code)
{
    return (u_char *) ngx_quic_errors[error_code];
}


ngx_int_t
ngx_quic_parse_long_header(ngx_quic_header_t *pkt)
{
    u_char  *p;

    p = pkt->data;

    ngx_quic_hexdump0(pkt->log, "long input", pkt->data, pkt->len);

    if (!(p[0] & NGX_QUIC_PKT_LONG)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "not a long packet");
        return NGX_ERROR;
    }

    pkt->flags = *p++;

    pkt->version = ngx_quic_parse_uint32(p);
    p += sizeof(uint32_t);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic flags:%xi version:%xD", pkt->flags, pkt->version);

    if (pkt->version != quic_version) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "unsupported quic version");
        return NGX_ERROR;
    }

    pkt->dcid.len = *p++;
    pkt->dcid.data = p;
    p += pkt->dcid.len;

    pkt->scid.len = *p++;
    pkt->scid.data = p;
    p += pkt->scid.len;

    pkt->raw->pos = p;

    return NGX_OK;
}


size_t
ngx_quic_create_long_header(ngx_quic_header_t *pkt, ngx_str_t *out,
    size_t pkt_len, u_char **pnp)
{
    u_char    *p, *start;

    p = start = out->data;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, quic_version);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    if (pkt->level == ssl_encryption_initial) {
        ngx_quic_build_int(&p, pkt->token.len);
    }

    ngx_quic_build_int(&p, pkt_len + 1); // length (inc. pnl)

    *pnp = p;

    *p++ = (uint64_t) (*pkt->number);

    return p - start;
}


ngx_int_t
ngx_quic_parse_short_header(ngx_quic_header_t *pkt, ngx_str_t *dcid)
{
    u_char  *p;

    p = pkt->data;

    ngx_quic_hexdump0(pkt->log, "short input", pkt->data, pkt->len);

    if ((p[0] & NGX_QUIC_PKT_LONG)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "not a short packet");
        return NGX_ERROR;
    }

    pkt->flags = *p++;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic flags:%xi", pkt->flags);

    if (ngx_memcmp(p, dcid->data, dcid->len) != 0) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    pkt->dcid.len = dcid->len;
    pkt->dcid.data = p;
    p += pkt->dcid.len;

    pkt->raw->pos = p;

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_initial_header(ngx_quic_header_t *pkt)
{
    u_char     *p;
    ngx_int_t   plen;

    p = pkt->raw->pos;

    pkt->token.len = ngx_quic_parse_int(&p);
    pkt->token.data = p;

    p += pkt->token.len;

    plen = ngx_quic_parse_int(&p);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %d", plen);

    if (plen > pkt->data + pkt->len - p) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "truncated initial packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    ngx_quic_hexdump0(pkt->log, "DCID", pkt->dcid.data, pkt->dcid.len);
    ngx_quic_hexdump0(pkt->log, "SCID", pkt->scid.data, pkt->scid.len);
    ngx_quic_hexdump0(pkt->log, "token", pkt->token.data, pkt->token.len);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %d", plen);

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_handshake_header(ngx_quic_header_t *pkt)
{
    u_char     *p;
    ngx_int_t   plen;

    p = pkt->raw->pos;

    plen = ngx_quic_parse_int(&p);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %d", plen);

    if (plen > pkt->data + pkt->len - p) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "truncated handshake packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet length: %d", plen);

    return NGX_OK;
}


#define ngx_quic_stream_bit_off(val)  (((val) & 0x04) ? 1 : 0)
#define ngx_quic_stream_bit_len(val)  (((val) & 0x02) ? 1 : 0)
#define ngx_quic_stream_bit_fin(val)  (((val) & 0x01) ? 1 : 0)

ssize_t
ngx_quic_parse_frame(u_char *start, u_char *end, ngx_quic_frame_t *frame)
{
    u_char *p;

    size_t npad;

    p = start;

    frame->type = *p++;  // TODO: check overflow (p < end)

    switch (frame->type) {

    case NGX_QUIC_FT_CRYPTO:
        frame->u.crypto.offset = *p++;
        frame->u.crypto.len = ngx_quic_parse_int(&p);
        frame->u.crypto.data = p;
        p += frame->u.crypto.len;

        break;

    case NGX_QUIC_FT_PADDING:
        npad = 0;
        while (p < end && *p == NGX_QUIC_FT_PADDING) { // XXX
            p++; npad++;
        }

        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        frame->u.ack.largest = ngx_quic_parse_int(&p);
        frame->u.ack.delay = ngx_quic_parse_int(&p);
        frame->u.ack.range_count =ngx_quic_parse_int(&p);
        frame->u.ack.first_range =ngx_quic_parse_int(&p);

        if (frame->u.ack.range_count) {
            frame->u.ack.ranges[0] = ngx_quic_parse_int(&p);
        }

        if (frame->type ==NGX_QUIC_FT_ACK_ECN) {
            return NGX_ERROR;
        }

        break;

    case NGX_QUIC_FT_PING:
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:

        frame->u.ncid.seqnum = ngx_quic_parse_int(&p);
        frame->u.ncid.retire = ngx_quic_parse_int(&p);
        frame->u.ncid.len = *p++;
        ngx_memcpy(frame->u.ncid.cid, p, frame->u.ncid.len);
        p += frame->u.ncid.len;

        ngx_memcpy(frame->u.ncid.srt, p, 16);
        p += 16;

        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:

        frame->u.close.error_code = ngx_quic_parse_int(&p);
        frame->u.close.frame_type = ngx_quic_parse_int(&p); // not in 0x1d CC
        frame->u.close.reason.len = ngx_quic_parse_int(&p);
        frame->u.close.reason.data = p;
        p += frame->u.close.reason.len;

        if (frame->u.close.error_code > NGX_QUIC_ERR_LAST) {
            frame->u.close.error_code = NGX_QUIC_ERR_LAST;
        }
        break;

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:

        frame->u.stream.type = frame->type;

        frame->u.stream.off = ngx_quic_stream_bit_off(frame->type);
        frame->u.stream.len = ngx_quic_stream_bit_len(frame->type);
        frame->u.stream.fin = ngx_quic_stream_bit_fin(frame->type);

        frame->u.stream.stream_id = ngx_quic_parse_int(&p);
        if (frame->type & 0x04) {
            frame->u.stream.offset = ngx_quic_parse_int(&p);
        } else {
            frame->u.stream.offset = 0;
        }

        if (frame->type & 0x02) {
            frame->u.stream.length = ngx_quic_parse_int(&p);
        } else {
            frame->u.stream.length = end - p; /* up to packet end */
        }

        frame->u.stream.data = p;

        p += frame->u.stream.length;

        break;

    default:
        return NGX_ERROR;
    }

    return p - start;
}


ssize_t
ngx_quic_create_frame(u_char *p, u_char *end, ngx_quic_frame_t *f)
{
    // TODO: handle end arg

    switch (f->type) {
    case NGX_QUIC_FT_ACK:
        return ngx_quic_create_ack(p, &f->u.ack);

    case NGX_QUIC_FT_CRYPTO:
        return ngx_quic_create_crypto(p, &f->u.crypto);

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        return ngx_quic_create_stream(p, &f->u.stream);

    default:
        /* BUG: unsupported frame type generated */
        return NGX_ERROR;
    }
}


size_t
ngx_quic_frame_len(ngx_quic_frame_t *frame)
{
     switch (frame->type) {
        case NGX_QUIC_FT_ACK:
            return ngx_quic_create_ack(NULL, &frame->u.ack);
        case NGX_QUIC_FT_CRYPTO:
            return ngx_quic_create_crypto(NULL, &frame->u.crypto);

        case NGX_QUIC_FT_STREAM0:
        case NGX_QUIC_FT_STREAM1:
        case NGX_QUIC_FT_STREAM2:
        case NGX_QUIC_FT_STREAM3:
        case NGX_QUIC_FT_STREAM4:
        case NGX_QUIC_FT_STREAM5:
        case NGX_QUIC_FT_STREAM6:
        case NGX_QUIC_FT_STREAM7:
            return ngx_quic_create_stream(NULL, &frame->u.stream);
        default:
            /* BUG: unsupported frame type generated */
            return 0;
     }
}


static size_t
ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack)
{
    size_t  len;

    /* minimal ACK packet */

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
        len += ngx_quic_varint_len(ack->pn);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(ack->pn);

        return len;
    }

    ngx_quic_build_int(&p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(&p, ack->pn);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, ack->pn);

    return 5;
}


static size_t
ngx_quic_create_crypto(u_char *p, ngx_quic_crypto_frame_t *crypto)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_CRYPTO);
        len += ngx_quic_varint_len(crypto->offset);
        len += ngx_quic_varint_len(crypto->len);
        len += crypto->len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(&p, crypto->offset);
    ngx_quic_build_int(&p, crypto->len);
    p = ngx_cpymem(p, crypto->data, crypto->len);

    return p - start;
}


static size_t
ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf)
{
    size_t   len;
    u_char  *start;

    if (!sf->len) {
#if 0
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "attempt to generate a stream frame without length");
#endif
        // XXX: handle error in caller
        return NGX_ERROR;
    }

    if (p == NULL) {
        len = ngx_quic_varint_len(sf->type);

        if (sf->off) {
            len += ngx_quic_varint_len(sf->offset);
        }

        len += ngx_quic_varint_len(sf->stream_id);

        /* length is always present in generated frames */
        len += ngx_quic_varint_len(sf->length);

        len += sf->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, sf->type);
    ngx_quic_build_int(&p, sf->stream_id);

    if (sf->off) {
        ngx_quic_build_int(&p, sf->offset);
    }

    /* length is always present in generated frames */
    ngx_quic_build_int(&p, sf->length);

    p = ngx_cpymem(p, sf->data, sf->length);

    return p - start;
}
