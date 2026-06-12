/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_module.h>
#include <ngx_http_proxy_v2_frame.h>


static ngx_int_t ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_settings(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_ping(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_inline ngx_int_t ngx_http_proxy_v2_cached(ngx_http_request_t *r);


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) ctx->rest) {
        ctx->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += ctx->rest;
    ctx->rest = 0;
    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_payload(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b, ngx_uint_t body)
{
    ngx_int_t             rc;
    ngx_http_upstream_t  *u;

    if (body && ctx->state == ngx_http_proxy_v2_st_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            ctx->rest -= b->last - b->pos;
            b->pos = b->last;
            return NGX_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;
        ctx->state = ngx_http_proxy_v2_st_start;

        if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
            ctx->done = 1;
        }

        return NGX_DONE;
    }

    u = r->upstream;

    if ((u->peer.connection == NULL || ngx_http_proxy_v2_cached(r))
        && ctx->type != NGX_HTTP_V2_HEADERS_FRAME
        && ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME)
    {
        rc = ngx_http_proxy_v2_skip_frame(ctx, b);
        return (rc == NGX_OK) ? NGX_DONE : rc;
    }

    switch (ctx->type) {

    case NGX_HTTP_V2_RST_STREAM_FRAME:
        return ngx_http_proxy_v2_parse_rst_stream(r, ctx, b);

    case NGX_HTTP_V2_GOAWAY_FRAME:
        return ngx_http_proxy_v2_parse_goaway(r, ctx, b);

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
        return ngx_http_proxy_v2_parse_window_update(r, ctx, b);

    case NGX_HTTP_V2_SETTINGS_FRAME:
        return ngx_http_proxy_v2_parse_settings(r, ctx, b);

    case NGX_HTTP_V2_PING_FRAME:
        return ngx_http_proxy_v2_parse_ping(r, ctx, b);

    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:
        return NGX_OK;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:
        rc = ngx_http_proxy_v2_parse_header(r, ctx, b);

        if (rc == NGX_AGAIN && ctx->rest == 0) {
            ctx->state = ngx_http_proxy_v2_st_start;
            return NGX_DONE;
        }

        if (body && rc == NGX_HTTP_PARSE_HEADER_DONE) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            if (body) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header");
            }
        }

        return rc;

    case NGX_HTTP_V2_DATA_FRAME:

        if (!body) {
            break;
        }

        /*
         * data frame:
         *
         * +---------------+
         * |Pad Length? (8)|
         * +---------------+-----------------------------------------------+
         * |                            Data (*)                         ...
         * +---------------------------------------------------------------+
         * |                           Padding (*)                       ...
         * +---------------------------------------------------------------+
         */

        if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            ctx->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return NGX_ERROR;
            }

            return NGX_DONE;
        }

        if (ctx->padding == ctx->rest) {

            if (ctx->padding) {
                ctx->state = ngx_http_proxy_v2_st_padding;

            } else {
                ctx->state = ngx_http_proxy_v2_st_start;

                if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                    ctx->done = 1;
                }
            }

            return NGX_DONE;
        }

        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        return NGX_OK;

    default:
        break;
    }

    rc = ngx_http_proxy_v2_skip_frame(ctx, b);

    return (rc == NGX_OK) ? NGX_DONE : rc;
}


ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char                     ch, *p;
    ngx_http_proxy_v2_state_e  state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_proxy_v2_st_start:
            ctx->rest = ch << 16;
            state = ngx_http_proxy_v2_st_length_2;
            break;

        case ngx_http_proxy_v2_st_length_2:
            ctx->rest |= ch << 8;
            state = ngx_http_proxy_v2_st_length_3;
            break;

        case ngx_http_proxy_v2_st_length_3:
            ctx->rest |= ch;

            if (ctx->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_st_type;
            break;

        case ngx_http_proxy_v2_st_type:
            ctx->type = ch;
            state = ngx_http_proxy_v2_st_flags;
            break;

        case ngx_http_proxy_v2_st_flags:
            ctx->flags = ch;
            state = ngx_http_proxy_v2_st_stream_id;
            break;

        case ngx_http_proxy_v2_st_stream_id:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_st_stream_id_2;
            break;

        case ngx_http_proxy_v2_st_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = ngx_http_proxy_v2_st_stream_id_3;
            break;

        case ngx_http_proxy_v2_st_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = ngx_http_proxy_v2_st_stream_id_4;
            break;

        case ngx_http_proxy_v2_st_stream_id_4:
            ctx->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

            b->pos = p + 1;

            ctx->state = ngx_http_proxy_v2_st_payload;
            ctx->frame_state = 0;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
        case ngx_http_proxy_v2_st_padding:
            break;
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    state = ctx->frame_state;

    if (state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy parse header: start");

        if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1;
            ctx->fragment_state = 0;
            ctx->header_limit = r->upstream->conf->buffer_size;

            min = (ctx->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->padding = 0;
        ctx->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                ctx->padding = ch;

                if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        ctx->rest -= p - b->pos;
        b->pos = p;

        ctx->frame_state = state;
        return NGX_AGAIN;

    fragment:

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return NGX_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = ngx_http_proxy_v2_parse_fragment(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            return NGX_OK;
        }

        /* rc == NGX_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return NGX_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = ngx_http_proxy_v2_st_start;

        if (ctx->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return NGX_ERROR;
            }

            ctx->parsing_headers = 0;

            return NGX_HTTP_PARSE_HEADER_DONE;
        }

        return NGX_AGAIN;
    }

    /* unreachable */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      len, size;
    ngx_uint_t  index, size_update;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    /* header block fragment */

#if 0
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest - ctx->padding;
    }

    state = ctx->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy indexed header: %ui", index);

                ctx->index = index;
                ctx->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy table size update: %ui",
                               size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header never indexed: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                             "http proxy literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NGX_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NGX_ERROR;
            }

            if (ctx->index > 61) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header index: %ui", ctx->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            if (ctx->name.len > ctx->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length: %uz",
                              ctx->name.len);
                return NGX_ERROR;
            }

            ctx->name.data = ngx_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->name.data[ctx->name.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                ngx_str_set(&ctx->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NGX_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            if (ctx->value.len > ctx->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length: %uz",
                              ctx->value.len);
                return NGX_ERROR;
            }

            ctx->value.data = ngx_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return NGX_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (ngx_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
                ctx->value.data[ctx->value.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    done:

        p++;
        ctx->rest -= p - b->pos;
        ctx->fragment_state = sw_start;
        b->pos = p;

        if (ctx->index) {
            ctx->name = *ngx_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *ngx_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (ngx_http_proxy_v2_validate_header_name(r, &ctx->name)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (ngx_http_proxy_v2_validate_header_value(r, &ctx->value)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NGX_ERROR;
            }
        }

        len = ctx->name.len + ctx->value.len;

        if (len > ctx->header_limit) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        ctx->header_limit -= len;

        return NGX_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return NGX_AGAIN;
    }

    return NGX_DONE;
}


static ngx_inline ngx_int_t
ngx_http_proxy_v2_cached(ngx_http_request_t *r)
{
#if (NGX_HTTP_CACHE)
    return r->cached;
#else
    return 0;
#endif
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return NGX_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return NGX_ERROR;
        }

        if (ch <= 0x20 || ch == 0x7f) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_goaway(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->rest < 8) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            ctx->stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            ctx->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   ctx->error, ctx->stream_id);

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            ctx->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            ctx->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            ctx->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_settings(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_id,
        sw_id_2,
        sw_value,
        sw_value_2,
        sw_value_3,
        sw_value_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
            if (ctx->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              ctx->rest);
                return NGX_ERROR;
            }

            ctx->state = ngx_http_proxy_v2_st_start;

            return NGX_OK;
        }

        if (ctx->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }

        if (ctx->free == NULL && ctx->settings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many settings frames");
            return NGX_ERROR;
        }

    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            ctx->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            ctx->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            ctx->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            ctx->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            ctx->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            ctx->setting_value |= ch;
            state = sw_id;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy setting: %ui %ui",
                           ctx->setting_id, ctx->setting_value);

            p++;
            ctx->rest -= p - b->pos;
            ctx->frame_state = state;
            b->pos = p;

            return NGX_OK;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_ping(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_data_2,
        sw_data_3,
        sw_data_4,
        sw_data_5,
        sw_data_6,
        sw_data_7,
        sw_data_8
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NGX_ERROR;
        }

        if (ctx->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NGX_ERROR;
        }

        if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            return NGX_ERROR;
        }

        if (ctx->free == NULL && ctx->pings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many ping frames");
            return NGX_ERROR;
        }

    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            ctx->ping_data[state] = ch;
            state++;

        } else {
            ctx->ping_data[7] = ch;
            state = sw_start;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy ping");
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}
