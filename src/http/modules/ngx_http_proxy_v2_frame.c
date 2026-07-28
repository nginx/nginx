
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_frame.h>


typedef enum {
    ngx_http_proxy_v2_data_start = 0,
    ngx_http_proxy_v2_data_payload,
    ngx_http_proxy_v2_data_padding
} ngx_http_proxy_v2_data_state_e;


typedef enum {
    ngx_http_proxy_v2_headers_start = 0,
    ngx_http_proxy_v2_headers_padding_length,
    ngx_http_proxy_v2_headers_dependency,
    ngx_http_proxy_v2_headers_dependency_2,
    ngx_http_proxy_v2_headers_dependency_3,
    ngx_http_proxy_v2_headers_dependency_4,
    ngx_http_proxy_v2_headers_weight,
    ngx_http_proxy_v2_headers_fragment,
    ngx_http_proxy_v2_headers_padding
} ngx_http_proxy_v2_headers_state_e;


ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b,
    ngx_log_t *log)
{
    u_char                     ch, *p;
    ngx_http_proxy_v2_state_e  state;

    state = parse->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_proxy_v2_st_start:
            parse->rest = ch << 16;
            state = ngx_http_proxy_v2_st_length_2;
            break;

        case ngx_http_proxy_v2_st_length_2:
            parse->rest |= ch << 8;
            state = ngx_http_proxy_v2_st_length_3;
            break;

        case ngx_http_proxy_v2_st_length_3:
            parse->rest |= ch;

            if (parse->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too large http2 frame: %uz",
                              parse->rest);
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_st_type;
            break;

        case ngx_http_proxy_v2_st_type:
            parse->type = ch;
            state = ngx_http_proxy_v2_st_flags;
            break;

        case ngx_http_proxy_v2_st_flags:
            parse->flags = ch;
            state = ngx_http_proxy_v2_st_stream_id;
            break;

        case ngx_http_proxy_v2_st_stream_id:
            parse->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_st_stream_id_2;
            break;

        case ngx_http_proxy_v2_st_stream_id_2:
            parse->stream_id |= ch << 16;
            state = ngx_http_proxy_v2_st_stream_id_3;
            break;

        case ngx_http_proxy_v2_st_stream_id_3:
            parse->stream_id |= ch << 8;
            state = ngx_http_proxy_v2_st_stream_id_4;
            break;

        case ngx_http_proxy_v2_st_stream_id_4:
            parse->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           parse->type, parse->rest, parse->flags,
                           parse->stream_id);

            b->pos = p + 1;

            parse->state = ngx_http_proxy_v2_st_payload;
            parse->frame_state = 0;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
            break;
        }
    }

    b->pos = p;
    parse->state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) parse->rest) {
        parse->rest -= b->last - b->pos;
        b->pos = b->last;

        return NGX_AGAIN;
    }

    b->pos += parse->rest;
    parse->rest = 0;
    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_data(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b,
    ngx_log_t *log)
{
    ngx_http_proxy_v2_data_state_e  state;

    state = parse->frame_state;

    if (state == ngx_http_proxy_v2_data_start) {
        parse->padding = 0;

        if (parse->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (parse->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            parse->padding = *b->pos++;
            parse->rest--;

            if (parse->padding > parse->rest) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              parse->padding, parse->rest);
                return NGX_ERROR;
            }
        }

        state = ngx_http_proxy_v2_data_payload;
        parse->frame_state = state;
    }

    if (state == ngx_http_proxy_v2_data_payload) {

        if (parse->rest > parse->padding) {
            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            return NGX_OK;
        }

        state = ngx_http_proxy_v2_data_padding;
        parse->frame_state = state;
    }

    if (b->last - b->pos < (ssize_t) parse->rest) {
        parse->rest -= b->last - b->pos;
        b->pos = b->last;

        return NGX_AGAIN;
    }

    b->pos += parse->rest;
    parse->rest = 0;
    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_DONE;
}


ngx_int_t
ngx_http_proxy_v2_parse_headers(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b,
    ngx_log_t *log)
{
    u_char                              ch, *p, *last;
    size_t                              min;
    ngx_http_proxy_v2_headers_state_e   state;

    state = parse->frame_state;

    if (state == ngx_http_proxy_v2_headers_padding) {
        return ngx_http_proxy_v2_parse_headers_padding(parse, b);
    }

    if (state == ngx_http_proxy_v2_headers_fragment) {
        return NGX_OK;
    }

    if (state == ngx_http_proxy_v2_headers_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy parse header: start");

        parse->padding = 0;

        if (parse->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            parse->frame_state = ngx_http_proxy_v2_headers_fragment;
            return NGX_OK;
        }

        min = (parse->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
              + (parse->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

        if (parse->rest < min) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent headers frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }

        if (parse->flags & NGX_HTTP_V2_PADDED_FLAG) {
            state = ngx_http_proxy_v2_headers_padding_length;

        } else if (parse->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
            state = ngx_http_proxy_v2_headers_dependency;

        } else {
            parse->frame_state = ngx_http_proxy_v2_headers_fragment;
            return NGX_OK;
        }

        parse->frame_state = state;
    }

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
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

        case ngx_http_proxy_v2_headers_padding_length:

            parse->padding = ch;

            if (parse->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = ngx_http_proxy_v2_headers_dependency;
                break;
            }

            goto fragment;

        case ngx_http_proxy_v2_headers_dependency:
            state = ngx_http_proxy_v2_headers_dependency_2;
            break;

        case ngx_http_proxy_v2_headers_dependency_2:
            state = ngx_http_proxy_v2_headers_dependency_3;
            break;

        case ngx_http_proxy_v2_headers_dependency_3:
            state = ngx_http_proxy_v2_headers_dependency_4;
            break;

        case ngx_http_proxy_v2_headers_dependency_4:
            state = ngx_http_proxy_v2_headers_weight;
            break;

        case ngx_http_proxy_v2_headers_weight:
            goto fragment;

        /* suppress warning */
        case ngx_http_proxy_v2_headers_start:
        case ngx_http_proxy_v2_headers_fragment:
        case ngx_http_proxy_v2_headers_padding:
            break;
        }
    }

    parse->rest -= p - b->pos;
    b->pos = p;
    parse->frame_state = state;

    return NGX_AGAIN;

fragment:

    p++;
    parse->rest -= p - b->pos;
    b->pos = p;

    if (parse->padding > parse->rest) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "upstream sent http2 frame with too long "
                      "padding: %d in frame %uz",
                      parse->padding, parse->rest);
        return NGX_ERROR;
    }

    parse->frame_state = ngx_http_proxy_v2_headers_fragment;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_headers_padding(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b)
{
    parse->frame_state = ngx_http_proxy_v2_headers_padding;

    if (b->last - b->pos < (ssize_t) parse->rest) {
        parse->rest -= b->last - b->pos;
        b->pos = b->last;

        return NGX_AGAIN;
    }

    b->pos += parse->rest;
    parse->rest = 0;
    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_DONE;
}


ngx_int_t
ngx_http_proxy_v2_parse_rst_stream(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log)
{
    u_char  ch, *p, *last;

    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    state = parse->frame_state;

    if (state == sw_start) {
        if (parse->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            parse->rst_stream_error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            parse->rst_stream_error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            parse->rst_stream_error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            parse->rst_stream_error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy error: %ui",
                           parse->rst_stream_error);

            break;
        }
    }

    parse->rest -= p - b->pos;
    parse->frame_state = state;
    b->pos = p;

    if (parse->rest > 0) {
        return NGX_AGAIN;
    }

    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_goaway(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b,
    ngx_log_t *log)
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

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    state = parse->frame_state;

    if (state == sw_start) {

        if (parse->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          parse->stream_id);
            return NGX_ERROR;
        }

        if (parse->rest < 8) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            parse->goaway_stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            parse->goaway_stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            parse->goaway_stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            parse->goaway_stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            parse->goaway_error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            parse->goaway_error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            parse->goaway_error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            parse->goaway_error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    parse->rest -= p - b->pos;
    parse->frame_state = state;
    b->pos = p;

    if (parse->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   parse->goaway_error, parse->goaway_stream_id);

    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log)
{
    u_char  ch, *p, *last;

    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    state = parse->frame_state;

    if (state == sw_start) {
        if (parse->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy window update byte: %02Xd s:%d",
                       ch, state);
#endif

        switch (state) {

        case sw_start:
            parse->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            parse->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            parse->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            parse->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    parse->rest -= p - b->pos;
    parse->frame_state = state;
    b->pos = p;

    if (parse->rest > 0) {
        return NGX_AGAIN;
    }

    parse->state = ngx_http_proxy_v2_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http proxy window update: %ui",
                   parse->window_update);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_parse_t *parse, ngx_buf_t *b,
    ngx_log_t *log)
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

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    state = parse->frame_state;

    if (state == sw_start) {

        if (parse->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          parse->stream_id);
            return NGX_ERROR;
        }

        if (parse->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            parse->ping_data[state] = ch;
            state++;

        } else {
            parse->ping_data[7] = ch;
            state = sw_start;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy ping");
        }
    }

    parse->rest -= p - b->pos;
    parse->frame_state = state;
    b->pos = p;

    if (parse->rest > 0) {
        return NGX_AGAIN;
    }

    parse->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_parse_settings(ngx_http_proxy_v2_parse_t *parse,
    ngx_buf_t *b, ngx_log_t *log)
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

    if (b->last - b->pos < (ssize_t) parse->rest) {
        last = b->last;

    } else {
        last = b->pos + parse->rest;
    }

    state = parse->frame_state;

    if (state == sw_start) {

        if (parse->stream_id) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          parse->stream_id);
            return NGX_ERROR;
        }

        if (parse->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy settings ack");

            if (parse->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              parse->rest);
                return NGX_ERROR;
            }

            parse->state = ngx_http_proxy_v2_st_start;

            return NGX_DONE;
        }

        if (parse->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          parse->rest);
            return NGX_ERROR;
        }

        if (parse->rest == 0) {
            parse->state = ngx_http_proxy_v2_st_start;

            return NGX_DONE;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http proxy settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            parse->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            parse->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            parse->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            parse->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            parse->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            parse->setting_value |= ch;
            state = sw_id;

            p++;
            parse->rest -= p - b->pos;
            parse->frame_state = state;
            b->pos = p;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http proxy setting: %ui %ui",
                           parse->setting_id, parse->setting_value);

            if (parse->rest == 0) {
                parse->state = ngx_http_proxy_v2_st_start;
            }

            return NGX_OK;
        }
    }

    parse->rest -= p - b->pos;
    parse->frame_state = state;
    b->pos = p;

    return NGX_AGAIN;
}
