
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


ngx_int_t
ngx_quic_handle_path_challenge_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f)
{
    ngx_quic_frame_t       *frame;
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->level = pkt->level;
    frame->type = NGX_QUIC_FT_PATH_RESPONSE;
    frame->u.path_response = *f;

    ngx_quic_queue_frame(qc, frame);

    return NGX_OK;
}


ngx_int_t
ngx_quic_handle_path_response_frame(ngx_connection_t *c,
    ngx_quic_header_t *pkt, ngx_quic_path_challenge_frame_t *f)
{
    /* TODO */
    return NGX_OK;
}

