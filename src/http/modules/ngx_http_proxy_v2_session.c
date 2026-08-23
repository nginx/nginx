
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


void
ngx_http_proxy_v2_session_init(ngx_http_proxy_v2_session_t *s)
{
    s->frame_parse.state = 0;

    s->connection = NULL;
    s->request = NULL;
    s->input = NULL;

    s->output_pos = s->output;
    s->output_last = s->output;

    s->frame_size = 0;

    s->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    s->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    s->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    s->last_stream_id = 1;
    s->peer_last_stream_id = 0;
    s->goaway_error = 0;
    s->connection_error = 0;

    s->frame_header = 0;
    s->frame_ready = 0;
    s->frame_error = 0;
    s->frame_dispatched = 0;
    s->output_blocked = 0;
    s->goaway = 0;
}


void
ngx_http_proxy_v2_session_attach(ngx_http_proxy_v2_session_t *s,
    ngx_connection_t *c, ngx_http_request_t *r)
{
    s->connection = c;
    s->request = r;
}


void
ngx_http_proxy_v2_session_detach(ngx_http_proxy_v2_session_t *s,
    ngx_http_request_t *r)
{
    if (s->request == r) {
        s->request = NULL;
    }
}


void
ngx_http_proxy_v2_session_frame_done(ngx_http_proxy_v2_session_t *s)
{
    ngx_buf_t  *b;

    b = s->input;

    b->pos = b->start;
    b->last = b->start;

    s->frame_size = 0;
    s->frame_header = 0;
    s->frame_ready = 0;
    s->frame_error = 0;
    s->frame_dispatched = 0;
}


ngx_int_t
ngx_http_proxy_v2_session_process_ping(ngx_http_proxy_v2_session_t *s)
{
    u_char  data[NGX_HTTP_PROXY_V2_PING_SIZE];
    u_char *p;

    if (ngx_http_proxy_v2_frame_parse_ping(&s->frame_parse, s->input, data)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid ping frame");
        return NGX_ERROR;
    }

    if (s->frame_parse.flags & NGX_HTTP_V2_ACK_FLAG) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy ping ack");

        ngx_http_proxy_v2_session_frame_done(s);
        return NGX_OK;
    }

    if (s->output_pos != s->output_last) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "http proxy session output is busy");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy send ping ack");

    p = s->output;

    *p++ = 0;
    *p++ = 0;
    *p++ = NGX_HTTP_PROXY_V2_PING_SIZE;
    *p++ = NGX_HTTP_V2_PING_FRAME;
    *p++ = NGX_HTTP_V2_ACK_FLAG;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    p = ngx_cpymem(p, data, NGX_HTTP_PROXY_V2_PING_SIZE);

    s->output_pos = s->output;
    s->output_last = p;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_window_update(
    ngx_http_proxy_v2_session_t *s)
{
    ngx_uint_t   n;

    if (ngx_http_proxy_v2_frame_parse_window_update(&s->frame_parse, s->input,
                                                    &n)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid connection window update frame");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy connection window update: %ui", n);

    if (n == 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent zero window update");
        return NGX_ERROR;
    }

    if (n > NGX_HTTP_V2_MAX_WINDOW - s->send_window) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent too large connection window update");
        return NGX_ERROR;
    }

    s->send_window += n;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_settings(ngx_http_proxy_v2_session_t *s,
    ssize_t *window_update)
{
    u_char                        *p;
    ngx_http_proxy_v2_settings_t  settings;

    if (ngx_http_proxy_v2_frame_parse_settings(&s->frame_parse, s->input,
                                               &settings)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid settings frame");
        return NGX_ERROR;
    }

    *window_update = 0;

    if (settings.ack) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy settings ack");

        ngx_http_proxy_v2_session_frame_done(s);
        return NGX_OK;
    }

    if (settings.initial_window_set) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "http proxy initial stream window: %ui",
                       settings.initial_window);

        *window_update = (ssize_t) settings.initial_window
                         - (ssize_t) s->init_window;
        s->init_window = settings.initial_window;
    }

    if (s->output_pos != s->output_last) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "http proxy session output is busy");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy send settings ack");

    p = s->output;

    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = NGX_HTTP_V2_SETTINGS_FRAME;
    *p++ = NGX_HTTP_V2_ACK_FLAG;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    s->output_pos = s->output;
    s->output_last = p;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_process_goaway(ngx_http_proxy_v2_session_t *s)
{
    ngx_http_proxy_v2_goaway_t  goaway;

    if (ngx_http_proxy_v2_frame_parse_goaway(&s->frame_parse, s->input,
                                             &goaway)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid goaway frame");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   goaway.error, goaway.last_stream_id);

    s->peer_last_stream_id = goaway.last_stream_id;
    s->goaway_error = goaway.error;
    s->goaway = 1;

    ngx_http_proxy_v2_session_frame_done(s);

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_session_send(ngx_http_proxy_v2_session_t *s)
{
    ssize_t  n;

    while (s->output_pos < s->output_last) {
        n = s->connection->send(s->connection, s->output_pos,
                                s->output_last - s->output_pos);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        s->output_pos += n;
    }

    s->output_pos = s->output;
    s->output_last = s->output;

    return NGX_OK;
}
