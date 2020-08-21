
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_transport.h>


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

#define ngx_quic_write_uint24(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
     (p)[1] = (u_char) ((s) >> 8),                                            \
     (p)[2] = (u_char)  (s),                                                  \
     (p) + 3)

#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define ngx_quic_varint_len(value)                                            \
     ((value) <= 63 ? 1                                                       \
     : ((uint32_t) value) <= 16383 ? 2                                        \
     : ((uint64_t) value) <= 1073741823 ?  4                                  \
     : 8)


static u_char *ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);
static void ngx_quic_build_int(u_char **pos, uint64_t value);

static u_char *ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value);
static u_char *ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value);
static u_char *ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len,
    u_char **out);
static u_char *ngx_quic_copy_bytes(u_char *pos, u_char *end, size_t len,
    u_char *dst);

static ngx_int_t ngx_quic_frame_allowed(ngx_quic_header_t *pkt,
    ngx_uint_t frame_type);
static size_t ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack);
static size_t ngx_quic_create_crypto(u_char *p,
    ngx_quic_crypto_frame_t *crypto);
static size_t ngx_quic_create_hs_done(u_char *p);
static size_t ngx_quic_create_new_token(u_char *p,
    ngx_quic_new_token_frame_t *token);
static size_t ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf);
static size_t ngx_quic_create_max_streams(u_char *p,
    ngx_quic_max_streams_frame_t *ms);
static size_t ngx_quic_create_max_stream_data(u_char *p,
    ngx_quic_max_stream_data_frame_t *ms);
static size_t ngx_quic_create_max_data(u_char *p,
    ngx_quic_max_data_frame_t *md);
static size_t ngx_quic_create_close(u_char *p, ngx_quic_close_frame_t *cl);

static ngx_int_t ngx_quic_parse_transport_param(u_char *p, u_char *end,
    uint16_t id, ngx_quic_tp_t *dst);


/* currently only single version (selected at compile-time) is supported */
uint32_t  ngx_quic_versions[] = {
    NGX_QUIC_VERSION
};

#define NGX_QUIC_NVERSIONS \
    (sizeof(ngx_quic_versions) / sizeof(ngx_quic_versions[0]))


/* literal errors indexed by corresponding value */
static char *ngx_quic_errors[] = {
    "NO_ERROR",
    "INTERNAL_ERROR",
    "CONNECTION_REFUSED",
    "FLOW_CONTROL_ERROR",
    "STREAM_LIMIT_ERROR",
    "STREAM_STATE_ERROR",
    "FINAL_SIZE_ERROR",
    "FRAME_ENCODING_ERROR",
    "TRANSPORT_PARAMETER_ERROR",
    "CONNECTION_ID_LIMIT_ERROR",
    "PROTOCOL_VIOLATION",
    "INVALID_TOKEN",
    "APPLICATION_ERROR",
    "CRYPTO_BUFFER_EXCEEDED",
    "KEY_UPDATE_ERROR",
};


static ngx_inline u_char *
ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out)
{
    u_char      *p;
    uint64_t     value;
    ngx_uint_t   len;

    if (pos >= end) {
        return NULL;
    }

    p = pos;
    len = 1 << ((*p & 0xc0) >> 6);

    value = *p++ & 0x3f;

    if ((size_t)(end - p) < (len - 1)) {
        return NULL;
    }

    while (--len) {
        value = (value << 8) + *p++;
    }

    *out = value;

    return p;
}


static ngx_inline u_char *
ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value)
{
    if ((size_t)(end - pos) < 1) {
        return NULL;
    }

    *value = *pos;

    return pos + 1;
}


static ngx_inline u_char *
ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value)
{
    if ((size_t)(end - pos) < sizeof(uint32_t)) {
        return NULL;
    }

    *value = ngx_quic_parse_uint32(pos);

    return pos + sizeof(uint32_t);
}


static ngx_inline u_char *
ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len, u_char **out)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    *out = pos;

    return pos + len;
}


static u_char *
ngx_quic_copy_bytes(u_char *pos, u_char *end, size_t len, u_char *dst)
{
    if ((size_t)(end - pos) < len) {
        return NULL;
    }

    ngx_memcpy(dst, pos, len);

    return pos + len;
}


static void
ngx_quic_build_int(u_char **pos, uint64_t value)
{
    u_char      *p;
    ngx_uint_t   bits, len;

    p = *pos;
    bits = 0;

    while (value >> ((8 << bits) - 2)) {
        bits++;
    }

    len = (1 << bits);

    while (len--) {
        *p++ = value >> (len * 8);
    }

    **pos |= bits << 6;
    *pos = p;
}


u_char *
ngx_quic_error_text(uint64_t error_code)
{
    if (error_code >= NGX_QUIC_ERR_CRYPTO_ERROR) {
        return (u_char *) "handshake error";
    }

    if (error_code >= NGX_QUIC_ERR_LAST) {
        return (u_char *) "unknown error";
    }

    return (u_char *) ngx_quic_errors[error_code];
}


ngx_int_t
ngx_quic_parse_long_header(ngx_quic_header_t *pkt)
{
    u_char   *p, *end;
    uint8_t   idlen;

    p = pkt->data;
    end = pkt->data + pkt->len;

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_long_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic not a long packet");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read version");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic long packet flags:%xd version:%xD",
                   pkt->flags, pkt->version);

    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NGX_DECLINED;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid len");
        return NGX_ERROR;
    }

    if (idlen > NGX_QUIC_CID_LEN_MAX) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet dcid is too long");
        return NGX_ERROR;
    }

    pkt->dcid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid");
        return NGX_ERROR;
    }

    p = ngx_quic_read_uint8(p, end, &idlen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read scid len");
        return NGX_ERROR;
    }

    if (idlen > NGX_QUIC_CID_LEN_MAX) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet scid is too long");
        return NGX_ERROR;
    }

    pkt->scid.len = idlen;

    p = ngx_quic_read_bytes(p, end, idlen, &pkt->scid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read scid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


size_t
ngx_quic_create_version_negotiation(ngx_quic_header_t *pkt, u_char *out)
{
    u_char      *p, *start;
    ngx_uint_t   i;

    p = start = out;

    *p++ = pkt->flags;

    /*
     * The Version field of a Version Negotiation packet
     * MUST be set to 0x00000000
     */
    p = ngx_quic_write_uint32(p, 0);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    for (i = 0; i < NGX_QUIC_NVERSIONS; i++) {
        p = ngx_quic_write_uint32(p, ngx_quic_versions[i]);
    }

    return p - start;
}


size_t
ngx_quic_create_long_header(ngx_quic_header_t *pkt, u_char *out,
    size_t pkt_len, u_char **pnp)
{
    u_char  *p, *start;

    p = start = out;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, NGX_QUIC_VERSION);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    if (pkt->level == ssl_encryption_initial) {
        ngx_quic_build_int(&p, pkt->token.len);
    }

    ngx_quic_build_int(&p, pkt_len + pkt->num_len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = ngx_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = ngx_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = ngx_quic_write_uint32(p, pkt->trunc);
        break;
    }

    return p - start;
}


size_t
ngx_quic_create_short_header(ngx_quic_header_t *pkt, u_char *out,
    size_t pkt_len, u_char **pnp)
{
    u_char  *p, *start;

    p = start = out;

    *p++ = pkt->flags;

    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *pnp = p;

    switch (pkt->num_len) {
    case 1:
        *p++ = pkt->trunc;
        break;
    case 2:
        p = ngx_quic_write_uint16(p, pkt->trunc);
        break;
    case 3:
        p = ngx_quic_write_uint24(p, pkt->trunc);
        break;
    case 4:
        p = ngx_quic_write_uint32(p, pkt->trunc);
        break;
    }

    return p - start;
}


size_t
ngx_quic_create_retry_itag(ngx_quic_header_t *pkt, u_char *out,
    u_char **start)
{
    u_char  *p;

    p = out;

    *p++ = pkt->odcid.len;
    p = ngx_cpymem(p, pkt->odcid.data, pkt->odcid.len);

    *start = p;

    *p++ = 0xff;

    p = ngx_quic_write_uint32(p, NGX_QUIC_VERSION);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    p = ngx_cpymem(p, pkt->token.data, pkt->token.len);

    return p - out;
}


ngx_int_t
ngx_quic_parse_short_header(ngx_quic_header_t *pkt, ngx_str_t *dcid)
{
    u_char  *p, *end;

    p = pkt->data;
    end = pkt->data + pkt->len;

    p = ngx_quic_read_uint8(p, end, &pkt->flags);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read flags");
        return NGX_ERROR;
    }

    if (!ngx_quic_short_pkt(pkt->flags)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic not a short packet");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic short packet flags:%xd", pkt->flags);

    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NGX_DECLINED;
    }

    if (ngx_memcmp(p, dcid->data, dcid->len) != 0) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "unexpected quic dcid");
        return NGX_ERROR;
    }

    pkt->dcid.len = dcid->len;

    p = ngx_quic_read_bytes(p, end, dcid->len, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_initial_header(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   varint;

    p = pkt->raw->pos;

    end = pkt->raw->last;

    pkt->log->action = "parsing quic initial header";

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic failed to parse token length");
        return NGX_ERROR;
    }

    pkt->token.len = varint;

    p = ngx_quic_read_bytes(p, end, pkt->token.len, &pkt->token.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet too small to read token data");
        return NGX_ERROR;
    }

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic initial packet length: %uL", varint);

    if (varint > (uint64_t) ((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic truncated initial packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = varint;

#ifdef NGX_QUIC_DEBUG_PACKETS
    ngx_quic_hexdump(pkt->log, "quic DCID", pkt->dcid.data, pkt->dcid.len);
    ngx_quic_hexdump(pkt->log, "quic SCID", pkt->scid.data, pkt->scid.len);
    ngx_quic_hexdump(pkt->log, "quic token", pkt->token.data, pkt->token.len);
#endif

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_handshake_header(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   plen;

    p = pkt->raw->pos;
    end = pkt->raw->last;

    pkt->log->action = "parsing quic handshake header";

    p = ngx_quic_parse_int(p, end, &plen);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic handshake packet length: %uL", plen);

    if (plen > (uint64_t)((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic truncated handshake packet");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = plen;

    return NGX_OK;
}


#define ngx_quic_stream_bit_off(val)  (((val) & 0x04) ? 1 : 0)
#define ngx_quic_stream_bit_len(val)  (((val) & 0x02) ? 1 : 0)
#define ngx_quic_stream_bit_fin(val)  (((val) & 0x01) ? 1 : 0)

ssize_t
ngx_quic_parse_frame(ngx_quic_header_t *pkt, u_char *start, u_char *end,
    ngx_quic_frame_t *f)
{
    u_char      *p;
    uint64_t     varint;
    ngx_uint_t   i;

    p = start;

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        pkt->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                     "quic failed to obtain quic frame type");
        return NGX_ERROR;
    }

    f->type = varint;

    if (ngx_quic_frame_allowed(pkt, f->type) != NGX_OK) {
        pkt->error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR;
    }

    switch (f->type) {

    case NGX_QUIC_FT_CRYPTO:

        p = ngx_quic_parse_int(p, end, &f->u.crypto.offset);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.crypto.length);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_read_bytes(p, end, f->u.crypto.length, &f->u.crypto.data);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: CRYPTO length: %uL off:%uL",
                       f->u.crypto.length, f->u.crypto.offset);

        break;

    case NGX_QUIC_FT_PADDING:

        while (p < end && *p == NGX_QUIC_FT_PADDING) {
            p++;
        }

        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        if (!((p = ngx_quic_parse_int(p, end, &f->u.ack.largest))
              && (p = ngx_quic_parse_int(p, end, &f->u.ack.delay))
              && (p = ngx_quic_parse_int(p, end, &f->u.ack.range_count))
              && (p = ngx_quic_parse_int(p, end, &f->u.ack.first_range))))
        {
            goto error;
        }

        f->u.ack.ranges_start = p;

        /* process all ranges to get bounds, values are ignored */
        for (i = 0; i < f->u.ack.range_count; i++) {

            p = ngx_quic_parse_int(p, end, &varint);
            if (p) {
                p = ngx_quic_parse_int(p, end, &varint);
            }

            if (p == NULL) {
                goto error;
            }
        }

        f->u.ack.ranges_end = p;

        ngx_log_debug4(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in ACK largest:%uL delay:%uL"
                       " count:%uL first:%uL", f->u.ack.largest,
                       f->u.ack.delay,
                       f->u.ack.range_count,
                       f->u.ack.first_range);

        if (f->type == NGX_QUIC_FT_ACK_ECN) {

            if (!((p = ngx_quic_parse_int(p, end, &f->u.ack.ect0))
                  && (p = ngx_quic_parse_int(p, end, &f->u.ack.ect1))
                  && (p = ngx_quic_parse_int(p, end, &f->u.ack.ce))))
            {
                goto error;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                           "quic ACK ECN counters: %uL %uL %uL",
                           f->u.ack.ect0, f->u.ack.ect1, f->u.ack.ce);
        }

        break;

    case NGX_QUIC_FT_PING:
        break;

    case NGX_QUIC_FT_NEW_CONNECTION_ID:

        p = ngx_quic_parse_int(p, end, &f->u.ncid.seqnum);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.ncid.retire);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_read_uint8(p, end, &f->u.ncid.len);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_copy_bytes(p, end, f->u.ncid.len, f->u.ncid.cid);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_copy_bytes(p, end, 16, f->u.ncid.srt);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: NCID seq:%uL retire:%uL len:%ud",
                       f->u.ncid.seqnum, f->u.ncid.retire, f->u.ncid.len);
        break;

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:

        p = ngx_quic_parse_int(p, end, &f->u.close.error_code);
        if (p == NULL) {
            goto error;
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {
            p = ngx_quic_parse_int(p, end, &f->u.close.frame_type);
            if (p == NULL) {
                goto error;
            }
        }

        p = ngx_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            goto error;
        }

        f->u.close.reason.len = varint;

        p = ngx_quic_read_bytes(p, end, f->u.close.reason.len,
                                &f->u.close.reason.data);
        if (p == NULL) {
            goto error;
        }

        if (f->type == NGX_QUIC_FT_CONNECTION_CLOSE) {

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                          "quic frame in CONNECTION_CLOSE"
                          " err:%s code:0x%xL type:0x%xL reason:'%V'",
                           ngx_quic_error_text(f->u.close.error_code),
                           f->u.close.error_code, f->u.close.frame_type,
                           &f->u.close.reason);
        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                          "quic frame in: CONNECTION_CLOSE_APP:"
                          " code:0x%xL reason:'%V'",
                           f->u.close.error_code, &f->u.close.reason);
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

        f->u.stream.type = f->type;

        f->u.stream.off = ngx_quic_stream_bit_off(f->type);
        f->u.stream.len = ngx_quic_stream_bit_len(f->type);
        f->u.stream.fin = ngx_quic_stream_bit_fin(f->type);

        p = ngx_quic_parse_int(p, end, &f->u.stream.stream_id);
        if (p == NULL) {
            goto error;
        }

        if (f->type & 0x04) {
            p = ngx_quic_parse_int(p, end, &f->u.stream.offset);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.offset = 0;
        }

        if (f->type & 0x02) {
            p = ngx_quic_parse_int(p, end, &f->u.stream.length);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.length = end - p; /* up to packet end */
        }

        p = ngx_quic_read_bytes(p, end, f->u.stream.length,
                                &f->u.stream.data);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: STREAM type:0x%xi id:0x%xL offset:0x%xL "
                       "len:0x%xL bits off:%d len:%d fin:%d",
                       f->type, f->u.stream.stream_id, f->u.stream.offset,
                       f->u.stream.length, f->u.stream.off, f->u.stream.len,
                       f->u.stream.fin);

#ifdef NGX_QUIC_DEBUG_FRAMES
            ngx_quic_hexdump(pkt->log, "quic STREAM frame",
                             f->u.stream.data, f->u.stream.length);
#endif
        break;

    case NGX_QUIC_FT_MAX_DATA:

        p = ngx_quic_parse_int(p, end, &f->u.max_data.max_data);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: MAX_DATA max_data:%uL",
                       f->u.max_data.max_data);
        break;

    case NGX_QUIC_FT_RESET_STREAM:

        if (!((p = ngx_quic_parse_int(p, end, &f->u.reset_stream.id))
              && (p = ngx_quic_parse_int(p, end, &f->u.reset_stream.error_code))
              && (p = ngx_quic_parse_int(p, end,
                                         &f->u.reset_stream.final_size))))
        {
            goto error;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: RESET_STREAM"
                       " id:0x%xL error_code:0x%xL final_size:0x%xL",
                       f->u.reset_stream.id, f->u.reset_stream.error_code,
                       f->u.reset_stream.final_size);
        break;

    case NGX_QUIC_FT_STOP_SENDING:

        p = ngx_quic_parse_int(p, end, &f->u.stop_sending.id);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.stop_sending.error_code);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: STOP_SENDING id:0x%xL error_code:0x%xL",
                       f->u.stop_sending.id, f->u.stop_sending.error_code);

        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:

        p = ngx_quic_parse_int(p, end, &f->u.streams_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        f->u.streams_blocked.bidi =
                              (f->type == NGX_QUIC_FT_STREAMS_BLOCKED) ? 1 : 0;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: STREAMS_BLOCKED limit:%uL bidi:%ui",
                       f->u.streams_blocked.limit,
                       f->u.streams_blocked.bidi);

        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:

        p = ngx_quic_parse_int(p, end, &f->u.max_streams.limit);
        if (p == NULL) {
            goto error;
        }

        f->u.max_streams.bidi = (f->type == NGX_QUIC_FT_MAX_STREAMS) ? 1 : 0;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: MAX_STREAMS limit:%uL bidi:%ui",
                       f->u.max_streams.limit,
                       f->u.max_streams.bidi);
        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:

        p = ngx_quic_parse_int(p, end, &f->u.max_stream_data.id);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end,  &f->u.max_stream_data.limit);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: MAX_STREAM_DATA id:0x%xL limit:%uL",
                       f->u.max_stream_data.id,
                       f->u.max_stream_data.limit);
        break;

    case NGX_QUIC_FT_DATA_BLOCKED:

        p = ngx_quic_parse_int(p, end, &f->u.data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: DATA_BLOCKED limit:%uL",
                       f->u.data_blocked.limit);
        break;

    case NGX_QUIC_FT_STREAM_DATA_BLOCKED:

        p = ngx_quic_parse_int(p, end, &f->u.stream_data_blocked.id);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.stream_data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: STREAM_DATA_BLOCKED"
                       " id:0x%xL limit:%uL",
                       f->u.stream_data_blocked.id,
                       f->u.stream_data_blocked.limit);
        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

        p = ngx_quic_parse_int(p, end, &f->u.retire_cid.sequence_number);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: RETIRE_CONNECTION_ID"
                       " sequence_number:%uL",
                       f->u.retire_cid.sequence_number);
        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_challenge.data);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: PATH_CHALLENGE");

#ifdef NGX_QUIC_DEBUG_FRAMES
        ngx_quic_hexdump(pkt->log, "quic PATH_CHALLENGE frame data",
                         f->u.path_challenge.data, 8);
#endif
        break;

    case NGX_QUIC_FT_PATH_RESPONSE:

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_response.data);
        if (p == NULL) {
            goto error;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                       "quic frame in: PATH_RESPONSE");

#ifdef NGX_QUIC_DEBUG_FRAMES
        ngx_quic_hexdump(pkt->log, "quic PATH_RESPONSE frame data",
                         f->u.path_response.data, 8);
#endif
        break;

    default:
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic unknown frame type 0x%xi", f->type);
        return NGX_ERROR;
    }

    return p - start;

error:

    pkt->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                  "quic failed to parse frame type 0x%xi", f->type);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_frame_allowed(ngx_quic_header_t *pkt, ngx_uint_t frame_type)
{
    uint8_t  ptype;

    /* frame permissions per packet: 4 bits: IH01: 12.4, Table 3 */
    static uint8_t ngx_quic_frame_masks[] = {
         /* PADDING  */              0xF,
         /* PING */                  0xF,
         /* ACK */                   0xD,
         /* ACK_ECN */               0xD,
         /* RESET_STREAM */          0x3,
         /* STOP_SENDING */          0x3,
         /* CRYPTO */                0xD,
         /* NEW_TOKEN */             0x0, /* only sent by server */
         /* STREAM0 */               0x3,
         /* STREAM1 */               0x3,
         /* STREAM2 */               0x3,
         /* STREAM3 */               0x3,
         /* STREAM4 */               0x3,
         /* STREAM5 */               0x3,
         /* STREAM6 */               0x3,
         /* STREAM7 */               0x3,
         /* MAX_DATA */              0x3,
         /* MAX_STREAM_DATA */       0x3,
         /* MAX_STREAMS */           0x3,
         /* MAX_STREAMS2 */          0x3,
         /* DATA_BLOCKED */          0x3,
         /* STREAM_DATA_BLOCKED */   0x3,
         /* STREAMS_BLOCKED */       0x3,
         /* STREAMS_BLOCKED2 */      0x3,
         /* NEW_CONNECTION_ID */     0x3,
         /* RETIRE_CONNECTION_ID */  0x3,
         /* PATH_CHALLENGE */        0x3,
         /* PATH_RESPONSE */         0x3,
#if (NGX_QUIC_DRAFT_VERSION >= 28)
         /* CONNECTION_CLOSE */      0xF,
         /* CONNECTION_CLOSE2 */     0x3,
#else
         /* CONNECTION_CLOSE */      0xD,
         /* CONNECTION_CLOSE2 */     0x1,
#endif
         /* HANDSHAKE_DONE */        0x0, /* only sent by server */
    };

    if (ngx_quic_long_pkt(pkt->flags)) {

        if (ngx_quic_pkt_in(pkt->flags)) {
            ptype = 8; /* initial */

        } else if (ngx_quic_pkt_hs(pkt->flags)) {
            ptype = 4; /* handshake */

        } else {
            ptype = 2; /* zero-rtt */
        }

    } else {
        ptype = 1; /* application data */
    }

    if (ptype & ngx_quic_frame_masks[frame_type]) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                  "quic frame type 0x%xi is not "
                  "allowed in packet with flags 0x%xd",
                  frame_type, pkt->flags);

    return NGX_DECLINED;
}


ssize_t
ngx_quic_parse_ack_range(ngx_quic_header_t *pkt, u_char *start, u_char *end,
    uint64_t *gap, uint64_t *range)
{
    u_char  *p;

    p = start;

    p = ngx_quic_parse_int(p, end, gap);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic failed to parse ack frame gap");
        return NGX_ERROR;
    }

    p = ngx_quic_parse_int(p, end, range);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic failed to parse ack frame range");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic ACK range: gap %uL range %uL", *gap, *range);

    return p - start;
}


ssize_t
ngx_quic_create_frame(u_char *p, ngx_quic_frame_t *f)
{
    /*
     *  QUIC-recovery, section 2:
     *
     *  Ack-eliciting Frames:  All frames other than ACK, PADDING, and
     *  CONNECTION_CLOSE are considered ack-eliciting.
     */
    f->need_ack = 1;

    switch (f->type) {
    case NGX_QUIC_FT_ACK:
        f->need_ack = 0;
        return ngx_quic_create_ack(p, &f->u.ack);

    case NGX_QUIC_FT_CRYPTO:
        return ngx_quic_create_crypto(p, &f->u.crypto);

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        return ngx_quic_create_hs_done(p);

    case NGX_QUIC_FT_NEW_TOKEN:
        return ngx_quic_create_new_token(p, &f->u.token);

    case NGX_QUIC_FT_STREAM0:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:
        return ngx_quic_create_stream(p, &f->u.stream);

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        f->need_ack = 0;
        return ngx_quic_create_close(p, &f->u.close);

    case NGX_QUIC_FT_MAX_STREAMS:
        return ngx_quic_create_max_streams(p, &f->u.max_streams);

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        return ngx_quic_create_max_stream_data(p, &f->u.max_stream_data);

    case NGX_QUIC_FT_MAX_DATA:
        return ngx_quic_create_max_data(p, &f->u.max_data);

    default:
        /* BUG: unsupported frame type generated */
        return NGX_ERROR;
    }
}


static size_t
ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack)
{
    size_t   len;
    u_char  *start;

    /* minimal ACK packet */

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
        len += ngx_quic_varint_len(ack->largest);
        len += ngx_quic_varint_len(ack->delay);
        len += ngx_quic_varint_len(0);
        len += ngx_quic_varint_len(ack->first_range);

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(&p, ack->largest);
    ngx_quic_build_int(&p, ack->delay);
    ngx_quic_build_int(&p, 0);
    ngx_quic_build_int(&p, ack->first_range);

    return p - start;
}


static size_t
ngx_quic_create_crypto(u_char *p, ngx_quic_crypto_frame_t *crypto)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_CRYPTO);
        len += ngx_quic_varint_len(crypto->offset);
        len += ngx_quic_varint_len(crypto->length);
        len += crypto->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(&p, crypto->offset);
    ngx_quic_build_int(&p, crypto->length);
    p = ngx_cpymem(p, crypto->data, crypto->length);

    return p - start;
}


static size_t
ngx_quic_create_hs_done(u_char *p)
{
    u_char  *start;

    if (p == NULL) {
        return ngx_quic_varint_len(NGX_QUIC_FT_HANDSHAKE_DONE);
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_HANDSHAKE_DONE);

    return p - start;
}


static size_t
ngx_quic_create_new_token(u_char *p, ngx_quic_new_token_frame_t *token)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_NEW_TOKEN);
        len += ngx_quic_varint_len(token->length);
        len += token->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_NEW_TOKEN);
    ngx_quic_build_int(&p, token->length);
    p = ngx_cpymem(p, token->data, token->length);

    return p - start;
}


static size_t
ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf)
{
    size_t   len;
    u_char  *start;

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


static size_t
ngx_quic_create_max_streams(u_char *p, ngx_quic_max_streams_frame_t *ms)
{
    size_t       len;
    u_char      *start;
    ngx_uint_t   type;

    type = ms->bidi ?  NGX_QUIC_FT_MAX_STREAMS : NGX_QUIC_FT_MAX_STREAMS2;

    if (p == NULL) {
        len = ngx_quic_varint_len(type);
        len += ngx_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, type);
    ngx_quic_build_int(&p, ms->limit);

    return p - start;
}


static ngx_int_t
ngx_quic_parse_transport_param(u_char *p, u_char *end, uint16_t id,
    ngx_quic_tp_t *dst)
{
    uint64_t   varint;
    ngx_str_t  str;

    varint = 0;
    ngx_str_null(&str);

    switch (id) {

    case NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
        /* zero-length option */
        if (end - p != 0) {
            return NGX_ERROR;
        }
        dst->disable_active_migration = 1;
        return NGX_OK;

    case NGX_QUIC_TP_MAX_IDLE_TIMEOUT:
    case NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
    case NGX_QUIC_TP_INITIAL_MAX_DATA:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
    case NGX_QUIC_TP_ACK_DELAY_EXPONENT:
    case NGX_QUIC_TP_MAX_ACK_DELAY:
    case NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:

        p = ngx_quic_parse_int(p, end, &varint);
        if (p == NULL) {
            return NGX_ERROR;
        }
        break;

    case NGX_QUIC_TP_INITIAL_SCID:

        str.len = end - p;
        p = ngx_quic_read_bytes(p, end, str.len, &str.data);
        break;

    default:
        return NGX_DECLINED;
    }

    switch (id) {

    case NGX_QUIC_TP_MAX_IDLE_TIMEOUT:
        dst->max_idle_timeout = varint;
        break;

    case NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
        dst->max_udp_payload_size = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_DATA:
        dst->initial_max_data = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        dst->initial_max_stream_data_bidi_local = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        dst->initial_max_stream_data_bidi_remote = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
        dst->initial_max_stream_data_uni = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
        dst->initial_max_streams_bidi = varint;
        break;

    case NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
        dst->initial_max_streams_uni = varint;
        break;

    case NGX_QUIC_TP_ACK_DELAY_EXPONENT:
        dst->ack_delay_exponent = varint;
        break;

    case NGX_QUIC_TP_MAX_ACK_DELAY:
        dst->max_ack_delay = varint;
        break;

    case NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
        dst->active_connection_id_limit = varint;
        break;

    case NGX_QUIC_TP_INITIAL_SCID:
        dst->initial_scid = str;
        break;

    default:
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_parse_transport_params(u_char *p, u_char *end, ngx_quic_tp_t *tp,
    ngx_log_t *log)
{
    uint64_t   id, len;
    ngx_int_t  rc;

    while (p < end) {
        p = ngx_quic_parse_int(p, end, &id);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic failed to parse transport param id");
            return NGX_ERROR;
        }

        switch (id) {
        case NGX_QUIC_TP_ORIGINAL_DCID:
        case NGX_QUIC_TP_PREFERRED_ADDRESS:
        case NGX_QUIC_TP_RETRY_SCID:
        case NGX_QUIC_TP_STATELESS_RESET_TOKEN:
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic client sent forbidden transport param"
                          " id 0x%xL", id);
            return NGX_ERROR;
        }

        p = ngx_quic_parse_int(p, end, &len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                         "quic failed to parse"
                         " transport param id 0x%xL length", id);
            return NGX_ERROR;
        }

        rc = ngx_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id 0x%xL data", id);
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic unknown transport param id 0x%xL, skipped", id);
        }

        p += len;
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "quic trailing garbage in"
                      " transport parameters: %ui bytes",
                      end - p);
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic transport parameters parsed ok");

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp disable active migration: %ui",
                   tp->disable_active_migration);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp idle_timeout: %ui",
                   tp->max_idle_timeout);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_udp_payload_size: %ui",
                   tp->max_udp_payload_size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp max_data: %ui",
                   tp->initial_max_data);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_local: %ui",
                   tp->initial_max_stream_data_bidi_local);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_remote: %ui",
                   tp->initial_max_stream_data_bidi_remote);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_uni: %ui",
                   tp->initial_max_stream_data_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_bidi: %ui",
                   tp->initial_max_streams_bidi);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_uni: %ui",
                   tp->initial_max_streams_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp ack_delay_exponent: %ui",
                   tp->ack_delay_exponent);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp max_ack_delay: %ui",
                   tp->max_ack_delay);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp active_connection_id_limit: %ui",
                   tp->active_connection_id_limit);

#if (NGX_QUIC_DRAFT_VERSION >= 28)
    ngx_quic_hexdump(log, "quic tp initial_source_connection_id:",
                     tp->initial_scid.data, tp->initial_scid.len);
#endif

    return NGX_OK;
}


static size_t
ngx_quic_create_max_stream_data(u_char *p, ngx_quic_max_stream_data_frame_t *ms)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_MAX_STREAM_DATA);
        len += ngx_quic_varint_len(ms->id);
        len += ngx_quic_varint_len(ms->limit);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_MAX_STREAM_DATA);
    ngx_quic_build_int(&p, ms->id);
    ngx_quic_build_int(&p, ms->limit);

    return p - start;
}


static size_t
ngx_quic_create_max_data(u_char *p, ngx_quic_max_data_frame_t *md)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_MAX_DATA);
        len += ngx_quic_varint_len(md->max_data);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_MAX_DATA);
    ngx_quic_build_int(&p, md->max_data);

    return p - start;
}


ssize_t
ngx_quic_create_transport_params(u_char *pos, u_char *end, ngx_quic_tp_t *tp,
    size_t *clen)
{
    u_char  *p;
    size_t   len;

#define ngx_quic_tp_len(id, value)                                            \
    ngx_quic_varint_len(id)                                                   \
    + ngx_quic_varint_len(value)                                              \
    + ngx_quic_varint_len(ngx_quic_varint_len(value))

#define ngx_quic_tp_vint(id, value)                                           \
    do {                                                                      \
        ngx_quic_build_int(&p, id);                                           \
        ngx_quic_build_int(&p, ngx_quic_varint_len(value));                   \
        ngx_quic_build_int(&p, value);                                        \
    } while (0)

#define ngx_quic_tp_strlen(id, value)                                         \
    ngx_quic_varint_len(id)                                                   \
    + ngx_quic_varint_len(value.len)                                          \
    + value.len

#define ngx_quic_tp_str(id, value)                                            \
    do {                                                                      \
        ngx_quic_build_int(&p, id);                                           \
        ngx_quic_build_int(&p, value.len);                                    \
        p = ngx_cpymem(p, value.data, value.len);                             \
    } while (0)

    p = pos;

    len = ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_DATA, tp->initial_max_data);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                           tp->initial_max_streams_uni);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                           tp->initial_max_streams_bidi);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                           tp->initial_max_stream_data_bidi_local);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                           tp->initial_max_stream_data_bidi_remote);

    len += ngx_quic_tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                           tp->initial_max_stream_data_uni);

    len += ngx_quic_tp_len(NGX_QUIC_TP_MAX_IDLE_TIMEOUT,
                           tp->max_idle_timeout);

    if (clen) {
        *clen = len;
    }

    len += ngx_quic_tp_len(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                           tp->active_connection_id_limit);

#if (NGX_QUIC_DRAFT_VERSION >= 28)
    len += ngx_quic_tp_strlen(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    len += ngx_quic_tp_strlen(NGX_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        len += ngx_quic_tp_strlen(NGX_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }
#else
    if (tp->original_dcid.len) {
        len += ngx_quic_tp_strlen(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    }
#endif

    if (pos == NULL) {
        return len;
    }

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_DATA,
                     tp->initial_max_data);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                     tp->initial_max_streams_uni);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                     tp->initial_max_streams_bidi);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                     tp->initial_max_stream_data_bidi_local);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                     tp->initial_max_stream_data_bidi_remote);

    ngx_quic_tp_vint(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
                     tp->initial_max_stream_data_uni);

    ngx_quic_tp_vint(NGX_QUIC_TP_MAX_IDLE_TIMEOUT,
                     tp->max_idle_timeout);

    ngx_quic_tp_vint(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                     tp->active_connection_id_limit);

#if (NGX_QUIC_DRAFT_VERSION >= 28)
    ngx_quic_tp_str(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    ngx_quic_tp_str(NGX_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        ngx_quic_tp_str(NGX_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }
#else
    if (tp->original_dcid.len) {
        ngx_quic_tp_str(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    }
#endif

    return p - pos;
}


static size_t
ngx_quic_create_close(u_char *p, ngx_quic_close_frame_t *cl)
{
    size_t       len;
    u_char      *start;
    ngx_uint_t   type;

    type = cl->app ? NGX_QUIC_FT_CONNECTION_CLOSE_APP
                   : NGX_QUIC_FT_CONNECTION_CLOSE;

    if (p == NULL) {
        len = ngx_quic_varint_len(type);
        len += ngx_quic_varint_len(cl->error_code);

        if (!cl->app) {
            len += ngx_quic_varint_len(cl->frame_type);
        }

        len += ngx_quic_varint_len(cl->reason.len);
        len += cl->reason.len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, type);
    ngx_quic_build_int(&p, cl->error_code);

    if (!cl->app) {
        ngx_quic_build_int(&p, cl->frame_type);
    }

    ngx_quic_build_int(&p, cl->reason.len);
    p = ngx_cpymem(p, cl->reason.data, cl->reason.len);

    return p - start;
}
