
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_LONG_DCID_LEN_OFFSET  5
#define NGX_QUIC_LONG_DCID_OFFSET      6
#define NGX_QUIC_SHORT_DCID_OFFSET     1

#define NGX_QUIC_STREAM_FRAME_FIN      0x01
#define NGX_QUIC_STREAM_FRAME_LEN      0x02
#define NGX_QUIC_STREAM_FRAME_OFF      0x04


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

#define ngx_quic_write_uint64(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))

#define ngx_quic_write_uint24(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
     (p)[1] = (u_char) ((s) >> 8),                                            \
     (p)[2] = (u_char)  (s),                                                  \
     (p) + 3)

#define ngx_quic_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define ngx_quic_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define ngx_quic_build_int_set(p, value, len, bits)                           \
    (*(p)++ = ((value >> ((len) * 8)) & 0xff) | ((bits) << 6))


static u_char *ngx_quic_parse_int(u_char *pos, u_char *end, uint64_t *out);
static ngx_uint_t ngx_quic_varint_len(uint64_t value);
static void ngx_quic_build_int(u_char **pos, uint64_t value);

static u_char *ngx_quic_read_uint8(u_char *pos, u_char *end, uint8_t *value);
static u_char *ngx_quic_read_uint32(u_char *pos, u_char *end, uint32_t *value);
static u_char *ngx_quic_read_bytes(u_char *pos, u_char *end, size_t len,
    u_char **out);
static u_char *ngx_quic_copy_bytes(u_char *pos, u_char *end, size_t len,
    u_char *dst);

static ngx_int_t ngx_quic_parse_short_header(ngx_quic_header_t *pkt,
    size_t dcid_len);
static ngx_int_t ngx_quic_parse_long_header(ngx_quic_header_t *pkt);
static ngx_int_t ngx_quic_supported_version(uint32_t version);
static ngx_int_t ngx_quic_parse_long_header_v1(ngx_quic_header_t *pkt);

static size_t ngx_quic_create_long_header(ngx_quic_header_t *pkt, u_char *out,
    u_char **pnp);
static size_t ngx_quic_create_short_header(ngx_quic_header_t *pkt, u_char *out,
    u_char **pnp);

static ngx_int_t ngx_quic_frame_allowed(ngx_quic_header_t *pkt,
    ngx_uint_t frame_type);
static size_t ngx_quic_create_ping(u_char *p);
static size_t ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack,
    ngx_chain_t *ranges);
static size_t ngx_quic_create_reset_stream(u_char *p,
    ngx_quic_reset_stream_frame_t *rs);
static size_t ngx_quic_create_stop_sending(u_char *p,
    ngx_quic_stop_sending_frame_t *ss);
static size_t ngx_quic_create_crypto(u_char *p,
    ngx_quic_crypto_frame_t *crypto, ngx_chain_t *data);
static size_t ngx_quic_create_hs_done(u_char *p);
static size_t ngx_quic_create_new_token(u_char *p,
    ngx_quic_new_token_frame_t *token, ngx_chain_t *data);
static size_t ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf,
    ngx_chain_t *data);
static size_t ngx_quic_create_max_streams(u_char *p,
    ngx_quic_max_streams_frame_t *ms);
static size_t ngx_quic_create_max_stream_data(u_char *p,
    ngx_quic_max_stream_data_frame_t *ms);
static size_t ngx_quic_create_max_data(u_char *p,
    ngx_quic_max_data_frame_t *md);
static size_t ngx_quic_create_path_challenge(u_char *p,
    ngx_quic_path_challenge_frame_t *pc);
static size_t ngx_quic_create_path_response(u_char *p,
    ngx_quic_path_challenge_frame_t *pc);
static size_t ngx_quic_create_new_connection_id(u_char *p,
    ngx_quic_new_conn_id_frame_t *rcid);
static size_t ngx_quic_create_retire_connection_id(u_char *p,
    ngx_quic_retire_cid_frame_t *rcid);
static size_t ngx_quic_create_close(u_char *p, ngx_quic_frame_t *f);

static ngx_int_t ngx_quic_parse_transport_param(u_char *p, u_char *end,
    uint16_t id, ngx_quic_tp_t *dst);


uint32_t  ngx_quic_versions[] = {
    /* QUICv1 */
    0x00000001,
};

#define NGX_QUIC_NVERSIONS \
    (sizeof(ngx_quic_versions) / sizeof(ngx_quic_versions[0]))


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
    len = 1 << (*p >> 6);

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


static ngx_inline ngx_uint_t
ngx_quic_varint_len(uint64_t value)
{
    if (value < (1 << 6)) {
        return 1;
    }

    if (value < (1 << 14)) {
        return 2;
    }

    if (value < (1 << 30)) {
        return 4;
    }

    return 8;
}


static ngx_inline void
ngx_quic_build_int(u_char **pos, uint64_t value)
{
    u_char  *p;

    p = *pos;

    if (value < (1 << 6)) {
        ngx_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 14)) {
        ngx_quic_build_int_set(p, value, 1, 1);
        ngx_quic_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 30)) {
        ngx_quic_build_int_set(p, value, 3, 2);
        ngx_quic_build_int_set(p, value, 2, 0);
        ngx_quic_build_int_set(p, value, 1, 0);
        ngx_quic_build_int_set(p, value, 0, 0);

    } else {
        ngx_quic_build_int_set(p, value, 7, 3);
        ngx_quic_build_int_set(p, value, 6, 0);
        ngx_quic_build_int_set(p, value, 5, 0);
        ngx_quic_build_int_set(p, value, 4, 0);
        ngx_quic_build_int_set(p, value, 3, 0);
        ngx_quic_build_int_set(p, value, 2, 0);
        ngx_quic_build_int_set(p, value, 1, 0);
        ngx_quic_build_int_set(p, value, 0, 0);
    }

    *pos = p;
}


ngx_int_t
ngx_quic_parse_packet(ngx_quic_header_t *pkt)
{
    if (!ngx_quic_long_pkt(pkt->flags)) {
        pkt->level = NGX_QUIC_ENCRYPTION_APPLICATION;

        if (ngx_quic_parse_short_header(pkt, NGX_QUIC_SERVER_CID_LEN) != NGX_OK)
        {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ngx_quic_parse_long_header(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pkt->version == 0) {
        /* version negotiation */
        return NGX_ERROR;
    }

    if (!ngx_quic_supported_version(pkt->version)) {
        return NGX_ABORT;
    }

    if (ngx_quic_parse_long_header_v1(pkt) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_parse_short_header(ngx_quic_header_t *pkt, size_t dcid_len)
{
    u_char  *p, *end;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx short flags:%xd", pkt->flags);

    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NGX_ERROR;
    }

    pkt->dcid.len = dcid_len;

    p = ngx_quic_read_bytes(p, end, dcid_len, &pkt->dcid.data);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read dcid");
        return NGX_ERROR;
    }

    pkt->raw->pos = p;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_parse_long_header(ngx_quic_header_t *pkt)
{
    u_char   *p, *end;
    uint8_t   idlen;

    p = pkt->raw->pos;
    end = pkt->data + pkt->len;

    p = ngx_quic_read_uint32(p, end, &pkt->version);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic packet is too small to read version");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx long flags:%xd version:%xD",
                   pkt->flags, pkt->version);

    if (!(pkt->flags & NGX_QUIC_PKT_FIXED_BIT)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic fixed bit is not set");
        return NGX_ERROR;
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


static ngx_int_t
ngx_quic_supported_version(uint32_t version)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_QUIC_NVERSIONS; i++) {
        if (ngx_quic_versions[i] == version) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_quic_parse_long_header_v1(ngx_quic_header_t *pkt)
{
    u_char    *p, *end;
    uint64_t   varint;

    p = pkt->raw->pos;
    end = pkt->raw->last;

    pkt->log->action = "parsing quic long header";

    if (ngx_quic_pkt_in(pkt->flags)) {

        if (pkt->len < NGX_QUIC_MIN_INITIAL_SIZE) {
            ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                          "quic UDP datagram is too small for initial packet");
            return NGX_DECLINED;
        }

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

        pkt->level = NGX_QUIC_ENCRYPTION_INITIAL;

    } else if (ngx_quic_pkt_zrtt(pkt->flags)) {
        pkt->level = NGX_QUIC_ENCRYPTION_EARLY_DATA;

    } else if (ngx_quic_pkt_hs(pkt->flags)) {
        pkt->level = NGX_QUIC_ENCRYPTION_HANDSHAKE;

    } else {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic bad packet type");
        return NGX_DECLINED;
    }

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic bad packet length");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                   "quic packet rx %s len:%uL",
                   ngx_quic_level_name(pkt->level), varint);

    if (varint > (uint64_t) ((pkt->data + pkt->len) - p)) {
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0, "quic truncated %s packet",
                      ngx_quic_level_name(pkt->level));
        return NGX_ERROR;
    }

    pkt->raw->pos = p;
    pkt->len = p + varint - pkt->data;

    return NGX_OK;
}


ngx_int_t
ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t n,
    ngx_str_t *dcid)
{
    size_t  len, offset;

    if (n == 0) {
        goto failed;
    }

    if (ngx_quic_long_pkt(*data)) {
        if (n < NGX_QUIC_LONG_DCID_LEN_OFFSET + 1) {
            goto failed;
        }

        len = data[NGX_QUIC_LONG_DCID_LEN_OFFSET];
        offset = NGX_QUIC_LONG_DCID_OFFSET;

    } else {
        len = NGX_QUIC_SERVER_CID_LEN;
        offset = NGX_QUIC_SHORT_DCID_OFFSET;
    }

    if (n < len + offset) {
        goto failed;
    }

    dcid->len = len;
    dcid->data = &data[offset];

    return NGX_OK;

failed:

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0, "quic malformed packet");

    return NGX_ERROR;
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


/* returns the amount of payload quic packet of "pkt_len" size may fit or 0 */
size_t
ngx_quic_payload_size(ngx_quic_header_t *pkt, size_t pkt_len)
{
    size_t  len;

    if (ngx_quic_short_pkt(pkt->flags)) {

        len = 1 + pkt->dcid.len + pkt->num_len + NGX_QUIC_TAG_LEN;
        if (len > pkt_len) {
            return 0;
        }

        return pkt_len - len;
    }

    /* flags, version, dcid and scid with lengths and zero-length token */
    len = 5 + 2 + pkt->dcid.len + pkt->scid.len
          + (pkt->level == NGX_QUIC_ENCRYPTION_INITIAL ? 1 : 0);

    if (len > pkt_len) {
        return 0;
    }

    /* (pkt_len - len) is 'remainder' packet length (see RFC 9000, 17.2) */
    len += ngx_quic_varint_len(pkt_len - len)
           + pkt->num_len + NGX_QUIC_TAG_LEN;

    if (len > pkt_len) {
        return 0;
    }

    return pkt_len - len;
}


size_t
ngx_quic_create_header(ngx_quic_header_t *pkt, u_char *out, u_char **pnp)
{
    return ngx_quic_short_pkt(pkt->flags)
           ? ngx_quic_create_short_header(pkt, out, pnp)
           : ngx_quic_create_long_header(pkt, out, pnp);
}


static size_t
ngx_quic_create_long_header(ngx_quic_header_t *pkt, u_char *out,
    u_char **pnp)
{
    size_t   rem_len;
    u_char  *p, *start;

    rem_len = pkt->num_len + pkt->payload.len + NGX_QUIC_TAG_LEN;

    if (out == NULL) {
        return 5 + 2 + pkt->dcid.len + pkt->scid.len
               + ngx_quic_varint_len(rem_len) + pkt->num_len
               + (pkt->level == NGX_QUIC_ENCRYPTION_INITIAL ? 1 : 0);
    }

    p = start = out;

    *p++ = pkt->flags;

    p = ngx_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    if (pkt->level == NGX_QUIC_ENCRYPTION_INITIAL) {
        ngx_quic_build_int(&p, 0);
    }

    ngx_quic_build_int(&p, rem_len);

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


static size_t
ngx_quic_create_short_header(ngx_quic_header_t *pkt, u_char *out,
    u_char **pnp)
{
    u_char  *p, *start;

    if (out == NULL) {
        return 1 + pkt->dcid.len + pkt->num_len;
    }

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

    p = ngx_quic_write_uint32(p, pkt->version);

    *p++ = pkt->dcid.len;
    p = ngx_cpymem(p, pkt->dcid.data, pkt->dcid.len);

    *p++ = pkt->scid.len;
    p = ngx_cpymem(p, pkt->scid.data, pkt->scid.len);

    p = ngx_cpymem(p, pkt->token.data, pkt->token.len);

    return p - out;
}


ssize_t
ngx_quic_parse_frame(ngx_quic_header_t *pkt, u_char *start, u_char *end,
    ngx_quic_frame_t *f)
{
    u_char      *p;
    uint64_t     varint;
    ngx_buf_t   *b;
    ngx_uint_t   i;

    b = f->data->buf;

    p = start;

    p = ngx_quic_parse_int(p, end, &varint);
    if (p == NULL) {
        pkt->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic failed to obtain quic frame type");
        return NGX_ERROR;
    }

    if (varint > NGX_QUIC_FT_LAST) {
        pkt->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic unknown frame type 0x%xL", varint);
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

        p = ngx_quic_read_bytes(p, end, f->u.crypto.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        break;

    case NGX_QUIC_FT_PADDING:

        while (p < end && *p == NGX_QUIC_FT_PADDING) {
            p++;
        }

        break;

    case NGX_QUIC_FT_ACK:
    case NGX_QUIC_FT_ACK_ECN:

        p = ngx_quic_parse_int(p, end, &f->u.ack.largest);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.ack.delay);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.ack.range_count);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.ack.first_range);
        if (p == NULL) {
            goto error;
        }

        b->pos = p;

        /* process all ranges to get bounds, values are ignored */
        for (i = 0; i < f->u.ack.range_count; i++) {

            p = ngx_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }

            p = ngx_quic_parse_int(p, end, &varint);
            if (p == NULL) {
                goto error;
            }
        }

        b->last = p;

        f->u.ack.ranges_length = b->last - b->pos;

        if (f->type == NGX_QUIC_FT_ACK_ECN) {

            p = ngx_quic_parse_int(p, end, &f->u.ack.ect0);
            if (p == NULL) {
                goto error;
            }

            p = ngx_quic_parse_int(p, end, &f->u.ack.ect1);
            if (p == NULL) {
                goto error;
            }

            p = ngx_quic_parse_int(p, end, &f->u.ack.ce);
            if (p == NULL) {
                goto error;
            }

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pkt->log, 0,
                           "quic ACK ECN counters ect0:%uL ect1:%uL ce:%uL",
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

        if (f->u.ncid.retire > f->u.ncid.seqnum) {
            goto error;
        }

        p = ngx_quic_read_uint8(p, end, &f->u.ncid.len);
        if (p == NULL) {
            goto error;
        }

        if (f->u.ncid.len < 1 || f->u.ncid.len > NGX_QUIC_CID_LEN_MAX) {
            goto error;
        }

        p = ngx_quic_copy_bytes(p, end, f->u.ncid.len, f->u.ncid.cid);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_copy_bytes(p, end, NGX_QUIC_SR_TOKEN_LEN, f->u.ncid.srt);
        if (p == NULL) {
            goto error;
        }

        break;

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:

        p = ngx_quic_parse_int(p, end, &f->u.retire_cid.sequence_number);
        if (p == NULL) {
            goto error;
        }

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

        break;

    case NGX_QUIC_FT_STREAM:
    case NGX_QUIC_FT_STREAM1:
    case NGX_QUIC_FT_STREAM2:
    case NGX_QUIC_FT_STREAM3:
    case NGX_QUIC_FT_STREAM4:
    case NGX_QUIC_FT_STREAM5:
    case NGX_QUIC_FT_STREAM6:
    case NGX_QUIC_FT_STREAM7:

        f->u.stream.fin = (f->type & NGX_QUIC_STREAM_FRAME_FIN) ? 1 : 0;

        p = ngx_quic_parse_int(p, end, &f->u.stream.stream_id);
        if (p == NULL) {
            goto error;
        }

        if (f->type & NGX_QUIC_STREAM_FRAME_OFF) {
            f->u.stream.off = 1;

            p = ngx_quic_parse_int(p, end, &f->u.stream.offset);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.off = 0;
            f->u.stream.offset = 0;
        }

        if (f->type & NGX_QUIC_STREAM_FRAME_LEN) {
            f->u.stream.len = 1;

            p = ngx_quic_parse_int(p, end, &f->u.stream.length);
            if (p == NULL) {
                goto error;
            }

        } else {
            f->u.stream.len = 0;
            f->u.stream.length = end - p; /* up to packet end */
        }

        p = ngx_quic_read_bytes(p, end, f->u.stream.length, &b->pos);
        if (p == NULL) {
            goto error;
        }

        b->last = p;

        f->type = NGX_QUIC_FT_STREAM;
        break;

    case NGX_QUIC_FT_MAX_DATA:

        p = ngx_quic_parse_int(p, end, &f->u.max_data.max_data);
        if (p == NULL) {
            goto error;
        }

        break;

    case NGX_QUIC_FT_RESET_STREAM:

        p = ngx_quic_parse_int(p, end, &f->u.reset_stream.id);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.reset_stream.error_code);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.reset_stream.final_size);
        if (p == NULL) {
            goto error;
        }

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

        break;

    case NGX_QUIC_FT_STREAMS_BLOCKED:
    case NGX_QUIC_FT_STREAMS_BLOCKED2:

        p = ngx_quic_parse_int(p, end, &f->u.streams_blocked.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.streams_blocked.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.streams_blocked.bidi =
                              (f->type == NGX_QUIC_FT_STREAMS_BLOCKED) ? 1 : 0;
        break;

    case NGX_QUIC_FT_MAX_STREAMS:
    case NGX_QUIC_FT_MAX_STREAMS2:

        p = ngx_quic_parse_int(p, end, &f->u.max_streams.limit);
        if (p == NULL) {
            goto error;
        }

        if (f->u.max_streams.limit > 0x1000000000000000) {
            goto error;
        }

        f->u.max_streams.bidi = (f->type == NGX_QUIC_FT_MAX_STREAMS) ? 1 : 0;

        break;

    case NGX_QUIC_FT_MAX_STREAM_DATA:

        p = ngx_quic_parse_int(p, end, &f->u.max_stream_data.id);
        if (p == NULL) {
            goto error;
        }

        p = ngx_quic_parse_int(p, end, &f->u.max_stream_data.limit);
        if (p == NULL) {
            goto error;
        }

        break;

    case NGX_QUIC_FT_DATA_BLOCKED:

        p = ngx_quic_parse_int(p, end, &f->u.data_blocked.limit);
        if (p == NULL) {
            goto error;
        }

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

        break;

    case NGX_QUIC_FT_PATH_CHALLENGE:

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_challenge.data);
        if (p == NULL) {
            goto error;
        }

        break;

    case NGX_QUIC_FT_PATH_RESPONSE:

        p = ngx_quic_copy_bytes(p, end, 8, f->u.path_response.data);
        if (p == NULL) {
            goto error;
        }

        break;

    default:
        ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                      "quic unknown frame type 0x%xi", f->type);
        return NGX_ERROR;
    }

    f->level = pkt->level;
#if (NGX_DEBUG)
    f->pnum = pkt->pn;
#endif

    return p - start;

error:

    pkt->error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;

    ngx_log_error(NGX_LOG_INFO, pkt->log, 0,
                  "quic failed to parse frame type:0x%xi", f->type);

    return NGX_ERROR;
}


static ngx_int_t
ngx_quic_frame_allowed(ngx_quic_header_t *pkt, ngx_uint_t frame_type)
{
    uint8_t  ptype;

    /*
     * RFC 9000, 12.4. Frames and Frame Types: Table 3
     *
     * Frame permissions per packet: 4 bits: IH01
     */
    static uint8_t ngx_quic_frame_masks[] = {
         /* PADDING  */              0xF,
         /* PING */                  0xF,
         /* ACK */                   0xD,
         /* ACK_ECN */               0xD,
         /* RESET_STREAM */          0x3,
         /* STOP_SENDING */          0x3,
         /* CRYPTO */                0xD,
         /* NEW_TOKEN */             0x0, /* only sent by server */
         /* STREAM */                0x3,
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
         /* PATH_RESPONSE */         0x1,
         /* CONNECTION_CLOSE */      0xF,
         /* CONNECTION_CLOSE2 */     0x3,
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
ngx_quic_parse_ack_range(ngx_log_t *log, u_char *start, u_char *end,
    uint64_t *gap, uint64_t *range)
{
    u_char  *p;

    p = start;

    p = ngx_quic_parse_int(p, end, gap);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "quic failed to parse ack frame gap");
        return NGX_ERROR;
    }

    p = ngx_quic_parse_int(p, end, range);
    if (p == NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "quic failed to parse ack frame range");
        return NGX_ERROR;
    }

    return p - start;
}


size_t
ngx_quic_create_ack_range(u_char *p, uint64_t gap, uint64_t range)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(gap);
        len += ngx_quic_varint_len(range);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, gap);
    ngx_quic_build_int(&p, range);

    return p - start;
}


ssize_t
ngx_quic_create_frame(u_char *p, ngx_quic_frame_t *f)
{
    /*
     *  RFC 9002, 2.  Conventions and Definitions
     *
     *  Ack-eliciting frames:  All frames other than ACK, PADDING, and
     *  CONNECTION_CLOSE are considered ack-eliciting.
     */
    f->need_ack = 1;

    switch (f->type) {
    case NGX_QUIC_FT_PING:
        return ngx_quic_create_ping(p);

    case NGX_QUIC_FT_ACK:
        f->need_ack = 0;
        return ngx_quic_create_ack(p, &f->u.ack, f->data);

    case NGX_QUIC_FT_RESET_STREAM:
        return ngx_quic_create_reset_stream(p, &f->u.reset_stream);

    case NGX_QUIC_FT_STOP_SENDING:
        return ngx_quic_create_stop_sending(p, &f->u.stop_sending);

    case NGX_QUIC_FT_CRYPTO:
        return ngx_quic_create_crypto(p, &f->u.crypto, f->data);

    case NGX_QUIC_FT_HANDSHAKE_DONE:
        return ngx_quic_create_hs_done(p);

    case NGX_QUIC_FT_NEW_TOKEN:
        return ngx_quic_create_new_token(p, &f->u.token, f->data);

    case NGX_QUIC_FT_STREAM:
        return ngx_quic_create_stream(p, &f->u.stream, f->data);

    case NGX_QUIC_FT_CONNECTION_CLOSE:
    case NGX_QUIC_FT_CONNECTION_CLOSE_APP:
        f->need_ack = 0;
        return ngx_quic_create_close(p, f);

    case NGX_QUIC_FT_MAX_STREAMS:
        return ngx_quic_create_max_streams(p, &f->u.max_streams);

    case NGX_QUIC_FT_MAX_STREAM_DATA:
        return ngx_quic_create_max_stream_data(p, &f->u.max_stream_data);

    case NGX_QUIC_FT_MAX_DATA:
        return ngx_quic_create_max_data(p, &f->u.max_data);

    case NGX_QUIC_FT_PATH_CHALLENGE:
        return ngx_quic_create_path_challenge(p, &f->u.path_challenge);

    case NGX_QUIC_FT_PATH_RESPONSE:
        return ngx_quic_create_path_response(p, &f->u.path_response);

    case NGX_QUIC_FT_NEW_CONNECTION_ID:
        return ngx_quic_create_new_connection_id(p, &f->u.ncid);

    case NGX_QUIC_FT_RETIRE_CONNECTION_ID:
        return ngx_quic_create_retire_connection_id(p, &f->u.retire_cid);

    default:
        /* BUG: unsupported frame type generated */
        return NGX_ERROR;
    }
}


static size_t
ngx_quic_create_ping(u_char *p)
{
    u_char  *start;

    if (p == NULL) {
        return ngx_quic_varint_len(NGX_QUIC_FT_PING);
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_PING);

    return p - start;
}


static size_t
ngx_quic_create_ack(u_char *p, ngx_quic_ack_frame_t *ack, ngx_chain_t *ranges)
{
    size_t      len;
    u_char     *start;
    ngx_buf_t  *b;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
        len += ngx_quic_varint_len(ack->largest);
        len += ngx_quic_varint_len(ack->delay);
        len += ngx_quic_varint_len(ack->range_count);
        len += ngx_quic_varint_len(ack->first_range);
        len += ack->ranges_length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(&p, ack->largest);
    ngx_quic_build_int(&p, ack->delay);
    ngx_quic_build_int(&p, ack->range_count);
    ngx_quic_build_int(&p, ack->first_range);

    while (ranges) {
        b = ranges->buf;
        p = ngx_cpymem(p, b->pos, b->last - b->pos);
        ranges = ranges->next;
    }

    return p - start;
}


static size_t
ngx_quic_create_reset_stream(u_char *p, ngx_quic_reset_stream_frame_t *rs)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_RESET_STREAM);
        len += ngx_quic_varint_len(rs->id);
        len += ngx_quic_varint_len(rs->error_code);
        len += ngx_quic_varint_len(rs->final_size);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_RESET_STREAM);
    ngx_quic_build_int(&p, rs->id);
    ngx_quic_build_int(&p, rs->error_code);
    ngx_quic_build_int(&p, rs->final_size);

    return p - start;
}


static size_t
ngx_quic_create_stop_sending(u_char *p, ngx_quic_stop_sending_frame_t *ss)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_STOP_SENDING);
        len += ngx_quic_varint_len(ss->id);
        len += ngx_quic_varint_len(ss->error_code);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_STOP_SENDING);
    ngx_quic_build_int(&p, ss->id);
    ngx_quic_build_int(&p, ss->error_code);

    return p - start;
}


static size_t
ngx_quic_create_crypto(u_char *p, ngx_quic_crypto_frame_t *crypto,
    ngx_chain_t *data)
{
    size_t      len;
    u_char     *start;
    ngx_buf_t  *b;

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

    while (data) {
        b = data->buf;
        p = ngx_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

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
ngx_quic_create_new_token(u_char *p, ngx_quic_new_token_frame_t *token,
    ngx_chain_t *data)
{
    size_t      len;
    u_char     *start;
    ngx_buf_t  *b;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_NEW_TOKEN);
        len += ngx_quic_varint_len(token->length);
        len += token->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_NEW_TOKEN);
    ngx_quic_build_int(&p, token->length);

    while (data) {
        b = data->buf;
        p = ngx_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}


static size_t
ngx_quic_create_stream(u_char *p, ngx_quic_stream_frame_t *sf,
    ngx_chain_t *data)
{
    size_t      len;
    u_char     *start, type;
    ngx_buf_t  *b;

    type = NGX_QUIC_FT_STREAM;

    if (sf->off) {
        type |= NGX_QUIC_STREAM_FRAME_OFF;
    }

    if (sf->len) {
        type |= NGX_QUIC_STREAM_FRAME_LEN;
    }

    if (sf->fin) {
        type |= NGX_QUIC_STREAM_FRAME_FIN;
    }

    if (p == NULL) {
        len = ngx_quic_varint_len(type);
        len += ngx_quic_varint_len(sf->stream_id);

        if (sf->off) {
            len += ngx_quic_varint_len(sf->offset);
        }

        if (sf->len) {
            len += ngx_quic_varint_len(sf->length);
        }

        len += sf->length;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, type);
    ngx_quic_build_int(&p, sf->stream_id);

    if (sf->off) {
        ngx_quic_build_int(&p, sf->offset);
    }

    if (sf->len) {
        ngx_quic_build_int(&p, sf->length);
    }

    while (data) {
        b = data->buf;
        p = ngx_cpymem(p, b->pos, b->last - b->pos);
        data = data->next;
    }

    return p - start;
}


static size_t
ngx_quic_create_max_streams(u_char *p, ngx_quic_max_streams_frame_t *ms)
{
    size_t       len;
    u_char      *start;
    ngx_uint_t   type;

    type = ms->bidi ? NGX_QUIC_FT_MAX_STREAMS : NGX_QUIC_FT_MAX_STREAMS2;

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
        str.data = p;
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
        case NGX_QUIC_TP_SR_TOKEN:
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic client sent forbidden transport param"
                          " id:0x%xL", id);
            return NGX_ERROR;
        }

        p = ngx_quic_parse_int(p, end, &len);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id:0x%xL length", id);
            return NGX_ERROR;
        }

        if ((size_t) (end - p) < len) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id:0x%xL, data length %uL too long",
                          id, len);
            return NGX_ERROR;
        }

        rc = ngx_quic_parse_transport_param(p, p + len, id, tp);

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, log, 0,
                          "quic failed to parse"
                          " transport param id:0x%xL data", id);
            return NGX_ERROR;
        }

        if (rc == NGX_DECLINED) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                          "quic %s transport param id:0x%xL, skipped",
                          (id % 31 == 27) ? "reserved" : "unknown", id);
        }

        p += len;
    }

    if (p != end) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "quic trailing garbage in"
                      " transport parameters: bytes:%ui",
                      end - p);
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic transport parameters parsed ok");

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp disable active migration: %ui",
                   tp->disable_active_migration);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp idle_timeout:%ui",
                   tp->max_idle_timeout);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_udp_payload_size:%ui",
                   tp->max_udp_payload_size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp max_data:%ui",
                   tp->initial_max_data);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_local:%ui",
                   tp->initial_max_stream_data_bidi_local);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_bidi_remote:%ui",
                   tp->initial_max_stream_data_bidi_remote);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp max_stream_data_uni:%ui",
                   tp->initial_max_stream_data_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_bidi:%ui",
                   tp->initial_max_streams_bidi);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial_max_streams_uni:%ui",
                   tp->initial_max_streams_uni);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp ack_delay_exponent:%ui",
                   tp->ack_delay_exponent);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "quic tp max_ack_delay:%ui",
                   tp->max_ack_delay);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp active_connection_id_limit:%ui",
                   tp->active_connection_id_limit);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                   "quic tp initial source_connection_id len:%uz %xV",
                   tp->initial_scid.len, &tp->initial_scid);

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


static size_t
ngx_quic_create_path_challenge(u_char *p, ngx_quic_path_challenge_frame_t *pc)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_PATH_CHALLENGE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_PATH_CHALLENGE);
    p = ngx_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}


static size_t
ngx_quic_create_path_response(u_char *p, ngx_quic_path_challenge_frame_t *pc)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_PATH_RESPONSE);
        len += sizeof(pc->data);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_PATH_RESPONSE);
    p = ngx_cpymem(p, &pc->data, sizeof(pc->data));

    return p - start;
}


static size_t
ngx_quic_create_new_connection_id(u_char *p, ngx_quic_new_conn_id_frame_t *ncid)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_NEW_CONNECTION_ID);
        len += ngx_quic_varint_len(ncid->seqnum);
        len += ngx_quic_varint_len(ncid->retire);
        len++;
        len += ncid->len;
        len += NGX_QUIC_SR_TOKEN_LEN;
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_NEW_CONNECTION_ID);
    ngx_quic_build_int(&p, ncid->seqnum);
    ngx_quic_build_int(&p, ncid->retire);
    *p++ = ncid->len;
    p = ngx_cpymem(p, ncid->cid, ncid->len);
    p = ngx_cpymem(p, ncid->srt, NGX_QUIC_SR_TOKEN_LEN);

    return p - start;
}


static size_t
ngx_quic_create_retire_connection_id(u_char *p,
    ngx_quic_retire_cid_frame_t *rcid)
{
    size_t   len;
    u_char  *start;

    if (p == NULL) {
        len = ngx_quic_varint_len(NGX_QUIC_FT_RETIRE_CONNECTION_ID);
        len += ngx_quic_varint_len(rcid->sequence_number);
        return len;
    }

    start = p;

    ngx_quic_build_int(&p, NGX_QUIC_FT_RETIRE_CONNECTION_ID);
    ngx_quic_build_int(&p, rcid->sequence_number);

    return p - start;
}


ngx_int_t
ngx_quic_init_transport_params(ngx_quic_tp_t *tp, ngx_quic_conf_t *qcf)
{
    ngx_uint_t  nstreams;

    ngx_memzero(tp, sizeof(ngx_quic_tp_t));

    /*
     * set by ngx_memzero():
     *
     *     tp->disable_active_migration = 0;
     *     tp->original_dcid = { 0, NULL };
     *     tp->initial_scid = { 0, NULL };
     *     tp->retry_scid = { 0, NULL };
     *     tp->sr_token = { 0 }
     *     tp->sr_enabled = 0
     *     tp->preferred_address = NULL
     */

    tp->max_idle_timeout = qcf->idle_timeout;

    tp->max_udp_payload_size = NGX_QUIC_MAX_UDP_PAYLOAD_SIZE;

    nstreams = qcf->max_concurrent_streams_bidi
               + qcf->max_concurrent_streams_uni;

    tp->initial_max_data = nstreams * qcf->stream_buffer_size;
    tp->initial_max_stream_data_bidi_local = qcf->stream_buffer_size;
    tp->initial_max_stream_data_bidi_remote = qcf->stream_buffer_size;
    tp->initial_max_stream_data_uni = qcf->stream_buffer_size;

    tp->initial_max_streams_bidi = qcf->max_concurrent_streams_bidi;
    tp->initial_max_streams_uni = qcf->max_concurrent_streams_uni;

    tp->max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
    tp->ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;

    tp->active_connection_id_limit = qcf->active_connection_id_limit;
    tp->disable_active_migration = qcf->disable_active_migration;

    return NGX_OK;
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

    len += ngx_quic_tp_len(NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                           tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        len += ngx_quic_varint_len(NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        len += ngx_quic_varint_len(0);
    }

    len += ngx_quic_tp_len(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                           tp->active_connection_id_limit);

    /* transport parameters listed above will be saved in 0-RTT context */
    if (clen) {
        *clen = len;
    }

    len += ngx_quic_tp_len(NGX_QUIC_TP_MAX_ACK_DELAY,
                           tp->max_ack_delay);

    len += ngx_quic_tp_len(NGX_QUIC_TP_ACK_DELAY_EXPONENT,
                           tp->ack_delay_exponent);

    len += ngx_quic_tp_strlen(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    len += ngx_quic_tp_strlen(NGX_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        len += ngx_quic_tp_strlen(NGX_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    len += ngx_quic_varint_len(NGX_QUIC_TP_SR_TOKEN);
    len += ngx_quic_varint_len(NGX_QUIC_SR_TOKEN_LEN);
    len += NGX_QUIC_SR_TOKEN_LEN;

    if (pos == NULL) {
        return len;
    }

    p = pos;

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

    ngx_quic_tp_vint(NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                     tp->max_udp_payload_size);

    if (tp->disable_active_migration) {
        ngx_quic_build_int(&p, NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        ngx_quic_build_int(&p, 0);
    }

    ngx_quic_tp_vint(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
                     tp->active_connection_id_limit);

    ngx_quic_tp_vint(NGX_QUIC_TP_MAX_ACK_DELAY,
                     tp->max_ack_delay);

    ngx_quic_tp_vint(NGX_QUIC_TP_ACK_DELAY_EXPONENT,
                     tp->ack_delay_exponent);

    ngx_quic_tp_str(NGX_QUIC_TP_ORIGINAL_DCID, tp->original_dcid);
    ngx_quic_tp_str(NGX_QUIC_TP_INITIAL_SCID, tp->initial_scid);

    if (tp->retry_scid.len) {
        ngx_quic_tp_str(NGX_QUIC_TP_RETRY_SCID, tp->retry_scid);
    }

    ngx_quic_build_int(&p, NGX_QUIC_TP_SR_TOKEN);
    ngx_quic_build_int(&p, NGX_QUIC_SR_TOKEN_LEN);
    p = ngx_cpymem(p, tp->sr_token, NGX_QUIC_SR_TOKEN_LEN);

    return p - pos;
}


static size_t
ngx_quic_create_close(u_char *p, ngx_quic_frame_t *f)
{
    size_t                   len;
    u_char                  *start;
    ngx_quic_close_frame_t  *cl;

    cl = &f->u.close;

    if (p == NULL) {
        len = ngx_quic_varint_len(f->type);
        len += ngx_quic_varint_len(cl->error_code);

        if (f->type != NGX_QUIC_FT_CONNECTION_CLOSE_APP) {
            len += ngx_quic_varint_len(cl->frame_type);
        }

        len += ngx_quic_varint_len(cl->reason.len);
        len += cl->reason.len;

        return len;
    }

    start = p;

    ngx_quic_build_int(&p, f->type);
    ngx_quic_build_int(&p, cl->error_code);

    if (f->type != NGX_QUIC_FT_CONNECTION_CLOSE_APP) {
        ngx_quic_build_int(&p, cl->frame_type);
    }

    ngx_quic_build_int(&p, cl->reason.len);
    p = ngx_cpymem(p, cl->reason.data, cl->reason.len);

    return p - start;
}


void
ngx_quic_dcid_encode_key(u_char *dcid, uint64_t key)
{
    (void) ngx_quic_write_uint64(dcid, key);
}
