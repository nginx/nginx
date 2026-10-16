
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_frame.h>


enum {
    ngx_http_proxy_v2_frame_length = 0,
    ngx_http_proxy_v2_frame_length_2,
    ngx_http_proxy_v2_frame_length_3,
    ngx_http_proxy_v2_frame_type,
    ngx_http_proxy_v2_frame_flags,
    ngx_http_proxy_v2_frame_stream_id,
    ngx_http_proxy_v2_frame_stream_id_2,
    ngx_http_proxy_v2_frame_stream_id_3,
    ngx_http_proxy_v2_frame_stream_id_4
};


ngx_int_t
ngx_http_proxy_v2_frame_parse(ngx_http_proxy_v2_frame_parse_t *parse,
    ngx_buf_t *b)
{
    u_char      ch, *p;
    ngx_uint_t  state;

    state = parse->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        case ngx_http_proxy_v2_frame_length:
            parse->length = (size_t) ch << 16;
            state = ngx_http_proxy_v2_frame_length_2;
            break;

        case ngx_http_proxy_v2_frame_length_2:
            parse->length |= (size_t) ch << 8;
            state = ngx_http_proxy_v2_frame_length_3;
            break;

        case ngx_http_proxy_v2_frame_length_3:
            parse->length |= ch;

            if (parse->length > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_frame_type;
            break;

        case ngx_http_proxy_v2_frame_type:
            parse->type = ch;
            state = ngx_http_proxy_v2_frame_flags;
            break;

        case ngx_http_proxy_v2_frame_flags:
            parse->flags = ch;
            state = ngx_http_proxy_v2_frame_stream_id;
            break;

        case ngx_http_proxy_v2_frame_stream_id:
            parse->stream_id = (ngx_uint_t) (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_frame_stream_id_2;
            break;

        case ngx_http_proxy_v2_frame_stream_id_2:
            parse->stream_id |= (ngx_uint_t) ch << 16;
            state = ngx_http_proxy_v2_frame_stream_id_3;
            break;

        case ngx_http_proxy_v2_frame_stream_id_3:
            parse->stream_id |= (ngx_uint_t) ch << 8;
            state = ngx_http_proxy_v2_frame_stream_id_4;
            break;

        case ngx_http_proxy_v2_frame_stream_id_4:
            parse->stream_id |= ch;

            b->pos = p + 1;
            parse->state = ngx_http_proxy_v2_frame_length;

            return NGX_OK;
        }
    }

    b->pos = p;
    parse->state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_proxy_v2_frame_parse_ping(ngx_http_proxy_v2_frame_parse_t *parse,
    ngx_buf_t *b, u_char *data)
{
    if (parse->type != NGX_HTTP_V2_PING_FRAME
        || parse->stream_id != 0
        || parse->length != NGX_HTTP_PROXY_V2_PING_SIZE
        || b->last - b->pos < NGX_HTTP_V2_FRAME_HEADER_SIZE
                              + NGX_HTTP_PROXY_V2_PING_SIZE)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(data, b->pos + NGX_HTTP_V2_FRAME_HEADER_SIZE,
               NGX_HTTP_PROXY_V2_PING_SIZE);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_frame_parse_window_update(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b,
    ngx_uint_t *increment)
{
    u_char  *p;

    if (parse->type != NGX_HTTP_V2_WINDOW_UPDATE_FRAME
        || parse->length != 4
        || b->last - b->pos < NGX_HTTP_V2_FRAME_HEADER_SIZE + 4)
    {
        return NGX_ERROR;
    }

    p = b->pos + NGX_HTTP_V2_FRAME_HEADER_SIZE;

    *increment = (ngx_uint_t) (p[0] & 0x7f) << 24;
    *increment |= (ngx_uint_t) p[1] << 16;
    *increment |= (ngx_uint_t) p[2] << 8;
    *increment |= p[3];

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_frame_parse_settings(
    ngx_http_proxy_v2_frame_parse_t *parse, ngx_buf_t *b,
    ngx_http_proxy_v2_settings_t *settings)
{
    u_char      *p, *last;
    ngx_uint_t   id, value;

    ngx_memzero(settings, sizeof(ngx_http_proxy_v2_settings_t));

    if (parse->type != NGX_HTTP_V2_SETTINGS_FRAME
        || parse->stream_id != 0
        || b->last - b->pos < (ssize_t) (NGX_HTTP_V2_FRAME_HEADER_SIZE
                                         + parse->length))
    {
        return NGX_ERROR;
    }

    if (parse->flags & NGX_HTTP_V2_ACK_FLAG) {
        if (parse->length != 0) {
            return NGX_ERROR;
        }

        settings->ack = 1;
        return NGX_OK;
    }

    if (parse->length % 6 != 0) {
        return NGX_ERROR;
    }

    p = b->pos + NGX_HTTP_V2_FRAME_HEADER_SIZE;
    last = p + parse->length;

    while (p < last) {
        id = (ngx_uint_t) p[0] << 8;
        id |= p[1];

        value = (ngx_uint_t) p[2] << 24;
        value |= (ngx_uint_t) p[3] << 16;
        value |= (ngx_uint_t) p[4] << 8;
        value |= p[5];

        if (id == 0x03) {
            settings->max_concurrent_streams = value;
            settings->max_concurrent_streams_set = 1;

        } else if (id == 0x04) {
            if (value > NGX_HTTP_V2_MAX_WINDOW) {
                return NGX_ERROR;
            }

            settings->initial_window = value;
            settings->initial_window_set = 1;
        }

        p += 6;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_frame_parse_goaway(ngx_http_proxy_v2_frame_parse_t *parse,
    ngx_buf_t *b, ngx_http_proxy_v2_goaway_t *goaway)
{
    u_char  *p;

    if (parse->type != NGX_HTTP_V2_GOAWAY_FRAME
        || parse->stream_id != 0
        || parse->length < 8
        || b->last - b->pos < (ssize_t) (NGX_HTTP_V2_FRAME_HEADER_SIZE
                                         + parse->length))
    {
        return NGX_ERROR;
    }

    p = b->pos + NGX_HTTP_V2_FRAME_HEADER_SIZE;

    goaway->last_stream_id = (ngx_uint_t) (p[0] & 0x7f) << 24;
    goaway->last_stream_id |= (ngx_uint_t) p[1] << 16;
    goaway->last_stream_id |= (ngx_uint_t) p[2] << 8;
    goaway->last_stream_id |= p[3];

    goaway->error = (ngx_uint_t) p[4] << 24;
    goaway->error |= (ngx_uint_t) p[5] << 16;
    goaway->error |= (ngx_uint_t) p[6] << 8;
    goaway->error |= p[7];

    goaway->debug.len = parse->length - 8;
    goaway->debug.data = p + 8;

    return NGX_OK;
}
