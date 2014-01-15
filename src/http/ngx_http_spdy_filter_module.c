
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_spdy_module.h>

#include <zlib.h>


#define ngx_http_spdy_nv_nsize(h)  (NGX_SPDY_NV_NLEN_SIZE + sizeof(h) - 1)
#define ngx_http_spdy_nv_vsize(h)  (NGX_SPDY_NV_VLEN_SIZE + sizeof(h) - 1)

#define ngx_http_spdy_nv_write_num   ngx_spdy_frame_write_uint16
#define ngx_http_spdy_nv_write_nlen  ngx_spdy_frame_write_uint16
#define ngx_http_spdy_nv_write_vlen  ngx_spdy_frame_write_uint16

#define ngx_http_spdy_nv_write_name(p, h)                                     \
    ngx_cpymem(ngx_http_spdy_nv_write_nlen(p, sizeof(h) - 1), h, sizeof(h) - 1)

#define ngx_http_spdy_nv_write_val(p, h)                                      \
    ngx_cpymem(ngx_http_spdy_nv_write_vlen(p, sizeof(h) - 1), h, sizeof(h) - 1)


static ngx_chain_t *ngx_http_spdy_send_chain(ngx_connection_t *fc,
    ngx_chain_t *in, off_t limit);

static ngx_inline ngx_int_t ngx_http_spdy_filter_send(
    ngx_connection_t *fc, ngx_http_spdy_stream_t *stream);

static ngx_chain_t *ngx_http_spdy_filter_get_shadow(
    ngx_http_spdy_stream_t *stream, ngx_buf_t *buf, off_t offset, off_t size);
static ngx_http_spdy_out_frame_t *ngx_http_spdy_filter_get_data_frame(
    ngx_http_spdy_stream_t *stream, size_t len, ngx_chain_t *first,
    ngx_chain_t *last);

static ngx_int_t ngx_http_spdy_syn_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);
static ngx_int_t ngx_http_spdy_data_frame_handler(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_out_frame_t *frame);
static ngx_inline void ngx_http_spdy_handle_frame(
    ngx_http_spdy_stream_t *stream, ngx_http_spdy_out_frame_t *frame);
static ngx_inline void ngx_http_spdy_handle_stream(
    ngx_http_spdy_connection_t *sc, ngx_http_spdy_stream_t *stream);

static void ngx_http_spdy_filter_cleanup(void *data);

static ngx_int_t ngx_http_spdy_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_spdy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_spdy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_spdy_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_spdy_filter_module_ctx,      /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_spdy_header_filter(ngx_http_request_t *r)
{
    int                           rc;
    size_t                        len;
    u_char                       *p, *buf, *last;
    ngx_buf_t                    *b;
    ngx_str_t                     host;
    ngx_uint_t                    i, j, count, port;
    ngx_chain_t                  *cl;
    ngx_list_part_t              *part, *pt;
    ngx_table_elt_t              *header, *h;
    ngx_connection_t             *c;
    ngx_http_cleanup_t           *cln;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_core_srv_conf_t     *cscf;
    ngx_http_spdy_stream_t       *stream;
    ngx_http_spdy_out_frame_t    *frame;
    ngx_http_spdy_connection_t   *sc;
    struct sockaddr_in           *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
#endif
    u_char                        addr[NGX_SOCKADDR_STRLEN];

    if (!r->spdy_stream) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "spdy header filter");

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NGX_OK;
    }

    c = r->connection;

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case NGX_HTTP_OK:
    case NGX_HTTP_PARTIAL_CONTENT:
        break;

    case NGX_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        break;

    case NGX_HTTP_NO_CONTENT:
        r->header_only = 1;

        ngx_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        /* fall through */

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
    }

    len = NGX_SPDY_NV_NUM_SIZE
          + ngx_http_spdy_nv_nsize("version")
          + ngx_http_spdy_nv_vsize("HTTP/1.1")
          + ngx_http_spdy_nv_nsize("status")
          + (r->headers_out.status_line.len
             ? NGX_SPDY_NV_VLEN_SIZE + r->headers_out.status_line.len
             : ngx_http_spdy_nv_vsize("418"));

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->headers_out.server == NULL) {
        len += ngx_http_spdy_nv_nsize("server");
        len += clcf->server_tokens ? ngx_http_spdy_nv_vsize(NGINX_VER)
                                   : ngx_http_spdy_nv_vsize("nginx");
    }

    if (r->headers_out.date == NULL) {
        len += ngx_http_spdy_nv_nsize("date")
               + ngx_http_spdy_nv_vsize("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.content_type.len) {
        len += ngx_http_spdy_nv_nsize("content-type")
               + NGX_SPDY_NV_VLEN_SIZE + r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += ngx_http_spdy_nv_nsize("content-length")
               + NGX_SPDY_NV_VLEN_SIZE + NGX_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += ngx_http_spdy_nv_nsize("last-modified")
               + ngx_http_spdy_nv_vsize("Wed, 31 Dec 1986 10:00:00 GMT");
    }

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = NGX_SOCKADDR_STRLEN;
            host.data = addr;

            if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
            port = ntohs(sin6->sin6_port);
            break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            port = 0;
            break;
#endif
        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            port = ntohs(sin->sin_port);
            break;
        }

        len += ngx_http_spdy_nv_nsize("location")
               + ngx_http_spdy_nv_vsize("https://")
               + host.len
               + r->headers_out.location->value.len;

        if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        ngx_str_null(&host);
        port = 0;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += NGX_SPDY_NV_NLEN_SIZE + header[i].key.len
               + NGX_SPDY_NV_VLEN_SIZE  + header[i].value.len;
    }

    buf = ngx_alloc(len, r->pool->log);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    last = buf + NGX_SPDY_NV_NUM_SIZE;

    last = ngx_http_spdy_nv_write_name(last, "version");
    last = ngx_http_spdy_nv_write_val(last, "HTTP/1.1");

    last = ngx_http_spdy_nv_write_name(last, "status");

    if (r->headers_out.status_line.len) {
        last = ngx_http_spdy_nv_write_vlen(last,
                                           r->headers_out.status_line.len);
        last = ngx_cpymem(last, r->headers_out.status_line.data,
                          r->headers_out.status_line.len);
    } else {
        last = ngx_http_spdy_nv_write_vlen(last, 3);
        last = ngx_sprintf(last, "%03ui", r->headers_out.status);
    }

    count = 2;

    if (r->headers_out.server == NULL) {
        last = ngx_http_spdy_nv_write_name(last, "server");
        last = clcf->server_tokens
               ? ngx_http_spdy_nv_write_val(last, NGINX_VER)
               : ngx_http_spdy_nv_write_val(last, "nginx");

        count++;
    }

    if (r->headers_out.date == NULL) {
        last = ngx_http_spdy_nv_write_name(last, "date");

        last = ngx_http_spdy_nv_write_vlen(last, ngx_cached_http_time.len);

        last = ngx_cpymem(last, ngx_cached_http_time.data,
                          ngx_cached_http_time.len);

        count++;
    }

    if (r->headers_out.content_type.len) {

        last = ngx_http_spdy_nv_write_name(last, "content-type");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, r->headers_out.content_type.data,
                          r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            last = ngx_cpymem(last, "; charset=", sizeof("; charset=") - 1);

            last = ngx_cpymem(last, r->headers_out.charset.data,
                              r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = last - p;
            r->headers_out.content_type.data = p;
        }

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           r->headers_out.content_type.len);

        count++;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        last = ngx_http_spdy_nv_write_name(last, "content-length");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_sprintf(p, "%O", r->headers_out.content_length_n);

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        last = ngx_http_spdy_nv_write_name(last, "last-modified");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_http_time(p, r->headers_out.last_modified_time);

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    if (host.data) {

        last = ngx_http_spdy_nv_write_name(last, "location");

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, "http", sizeof("http") - 1);

#if (NGX_HTTP_SSL)
        if (c->ssl) {
            *last++ ='s';
        }
#endif

        *last++ = ':'; *last++ = '/'; *last++ = '/';

        last = ngx_cpymem(last, host.data, host.len);

        if (port) {
            last = ngx_sprintf(last, ":%ui", port);
        }

        last = ngx_cpymem(last, r->headers_out.location->value.data,
                          r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "location");

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           r->headers_out.location->value.len);

        count++;
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0 || header[i].hash == 2) {
            continue;
        }

        if ((header[i].key.len == 6
             && ngx_strncasecmp(header[i].key.data,
                                (u_char *) "status", 6) == 0)
            || (header[i].key.len == 7
                && ngx_strncasecmp(header[i].key.data,
                                   (u_char *) "version", 7) == 0))
        {
            header[i].hash = 0;
            continue;
        }

        last = ngx_http_spdy_nv_write_nlen(last, header[i].key.len);

        ngx_strlow(last, header[i].key.data, header[i].key.len);
        last += header[i].key.len;

        p = last + NGX_SPDY_NV_VLEN_SIZE;

        last = ngx_cpymem(p, header[i].value.data, header[i].value.len);

        pt = part;
        h = header;

        for (j = i + 1; /* void */; j++) {

            if (j >= pt->nelts) {
                if (pt->next == NULL) {
                    break;
                }

                pt = pt->next;
                h = pt->elts;
                j = 0;
            }

            if (h[j].hash == 0 || h[j].hash == 2
                || h[j].key.len != header[i].key.len
                || ngx_strncasecmp(header[i].key.data, h[j].key.data,
                                   header[i].key.len))
            {
                continue;
            }

            *last++ = '\0';

            last = ngx_cpymem(last, h[j].value.data, h[j].value.len);

            h[j].hash = 2;
        }

        (void) ngx_http_spdy_nv_write_vlen(p - NGX_SPDY_NV_VLEN_SIZE,
                                           last - p);

        count++;
    }

    (void) ngx_http_spdy_nv_write_num(buf, count);

    stream = r->spdy_stream;
    sc = stream->connection;

    len = last - buf;

    b = ngx_create_temp_buf(r->pool, NGX_SPDY_FRAME_HEADER_SIZE
                                     + NGX_SPDY_SYN_REPLY_SIZE
                                     + deflateBound(&sc->zstream_out, len));
    if (b == NULL) {
        ngx_free(buf);
        return NGX_ERROR;
    }

    b->last += NGX_SPDY_FRAME_HEADER_SIZE + NGX_SPDY_SYN_REPLY_SIZE;

    sc->zstream_out.next_in = buf;
    sc->zstream_out.avail_in = len;
    sc->zstream_out.next_out = b->last;
    sc->zstream_out.avail_out = b->end - b->last;

    rc = deflate(&sc->zstream_out, Z_SYNC_FLUSH);

    ngx_free(buf);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "spdy deflate() failed: %d", rc);
        return NGX_ERROR;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "spdy deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   sc->zstream_out.next_in, sc->zstream_out.next_out,
                   sc->zstream_out.avail_in, sc->zstream_out.avail_out,
                   rc);

    b->last = sc->zstream_out.next_out;

    p = b->pos;
    p = ngx_spdy_frame_write_head(p, NGX_SPDY_SYN_REPLY);

    len = b->last - b->pos;

    r->header_size = len;

    if (r->header_only) {
        b->last_buf = 1;
        p = ngx_spdy_frame_write_flags_and_len(p, NGX_SPDY_FLAG_FIN,
                                             len - NGX_SPDY_FRAME_HEADER_SIZE);
    } else {
        p = ngx_spdy_frame_write_flags_and_len(p, 0,
                                             len - NGX_SPDY_FRAME_HEADER_SIZE);
    }

    (void) ngx_spdy_frame_write_sid(p, stream->id);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    frame = ngx_palloc(r->pool, sizeof(ngx_http_spdy_out_frame_t));
    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->first = cl;
    frame->last = cl;
    frame->handler = ngx_http_spdy_syn_frame_handler;
    frame->free = NULL;
    frame->stream = stream;
    frame->size = len;
    frame->priority = stream->priority;
    frame->blocked = 1;
    frame->fin = r->header_only;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "spdy:%ui create SYN_REPLY frame %p: size:%uz",
                   stream->id, frame, frame->size);

    ngx_http_spdy_queue_blocked_frame(sc, frame);

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_spdy_filter_cleanup;
    cln->data = stream;

    stream->queued = 1;

    c->send_chain = ngx_http_spdy_send_chain;
    c->need_last_buf = 1;

    return ngx_http_spdy_filter_send(c, stream);
}


static ngx_chain_t *
ngx_http_spdy_send_chain(ngx_connection_t *fc, ngx_chain_t *in, off_t limit)
{
    off_t                       size, offset;
    size_t                      rest, frame_size;
    ngx_chain_t                *cl, *out, **ln;
    ngx_http_request_t         *r;
    ngx_http_spdy_stream_t     *stream;
    ngx_http_spdy_loc_conf_t   *slcf;
    ngx_http_spdy_out_frame_t  *frame;

    r = fc->data;
    stream = r->spdy_stream;

    if (in == NULL) {

        if (stream->queued) {
            fc->write->delayed = 1;
        } else {
            fc->buffered &= ~NGX_SPDY_BUFFERED;
        }

        return NULL;
    }

    size = ngx_buf_size(in->buf);

    if (in->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_filter_get_shadow) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        cl->buf = in->buf;
        in->buf = cl->buf->shadow;

        offset = ngx_buf_in_memory(in->buf)
                 ? (cl->buf->pos - in->buf->pos)
                 : (cl->buf->file_pos - in->buf->file_pos);

        cl->next = stream->free_bufs;
        stream->free_bufs = cl;

    } else {
        offset = 0;
    }

#if (NGX_SUPPRESS_WARN)
    cl = NULL;
#endif

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_spdy_module);

    frame_size = (limit && limit <= (off_t) slcf->chunk_size)
                 ? (size_t) limit
                 : slcf->chunk_size;

    for ( ;; ) {
        ln = &out;
        rest = frame_size;

        while ((off_t) rest >= size) {

            if (offset) {
                cl = ngx_http_spdy_filter_get_shadow(stream, in->buf,
                                                     offset, size);
                if (cl == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                offset = 0;

            } else {
                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_CHAIN_ERROR;
                }

                cl->buf = in->buf;
            }

            *ln = cl;
            ln = &cl->next;

            rest -= (size_t) size;
            in = in->next;

            if (in == NULL) {
                frame_size -= rest;
                rest = 0;
                break;
            }

            size = ngx_buf_size(in->buf);
        }

        if (rest) {
            cl = ngx_http_spdy_filter_get_shadow(stream, in->buf,
                                                 offset, rest);
            if (cl == NULL) {
                return NGX_CHAIN_ERROR;
            }

            cl->buf->flush = 0;
            cl->buf->last_buf = 0;

            *ln = cl;

            offset += rest;
            size -= rest;
        }

        frame = ngx_http_spdy_filter_get_data_frame(stream, frame_size,
                                                    out, cl);
        if (frame == NULL) {
            return NGX_CHAIN_ERROR;
        }

        ngx_http_spdy_queue_frame(stream->connection, frame);

        stream->queued++;

        if (in == NULL) {
            break;
        }

        if (limit) {
            limit -= frame_size;

            if (limit == 0) {
                break;
            }

            if (limit < (off_t) slcf->chunk_size) {
                frame_size = (size_t) limit;
            }
        }
    }

    if (offset) {
        cl = ngx_http_spdy_filter_get_shadow(stream, in->buf, offset, size);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        in->buf = cl->buf;
        ngx_free_chain(r->pool, cl);
    }

    if (ngx_http_spdy_filter_send(fc, stream) == NGX_ERROR) {
        return NGX_CHAIN_ERROR;
    }

    return in;
}


static ngx_chain_t *
ngx_http_spdy_filter_get_shadow(ngx_http_spdy_stream_t *stream, ngx_buf_t *buf,
    off_t offset, off_t size)
{
    ngx_buf_t    *chunk;
    ngx_chain_t  *cl;

    cl = ngx_chain_get_free_buf(stream->request->pool, &stream->free_bufs);
    if (cl == NULL) {
        return NULL;
    }

    chunk = cl->buf;

    ngx_memcpy(chunk, buf, sizeof(ngx_buf_t));

    chunk->tag = (ngx_buf_tag_t) &ngx_http_spdy_filter_get_shadow;
    chunk->shadow = buf;

    if (ngx_buf_in_memory(chunk)) {
        chunk->pos += offset;
        chunk->last = chunk->pos + size;
    }

    if (chunk->in_file) {
        chunk->file_pos += offset;
        chunk->file_last = chunk->file_pos + size;
    }

    return cl;
}


static ngx_http_spdy_out_frame_t *
ngx_http_spdy_filter_get_data_frame(ngx_http_spdy_stream_t *stream,
    size_t len, ngx_chain_t *first, ngx_chain_t *last)
{
    u_char                     *p;
    ngx_buf_t                  *buf;
    ngx_uint_t                  flags;
    ngx_chain_t                *cl;
    ngx_http_spdy_out_frame_t  *frame;


    frame = stream->free_frames;

    if (frame) {
        stream->free_frames = frame->free;

    } else {
        frame = ngx_palloc(stream->request->pool,
                           sizeof(ngx_http_spdy_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }
    }

    flags = last->buf->last_buf ? NGX_SPDY_FLAG_FIN : 0;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "spdy:%ui create DATA frame %p: len:%uz flags:%ui",
                   stream->id, frame, len, flags);

    if (len || flags) {

        cl = ngx_chain_get_free_buf(stream->request->pool,
                                    &stream->free_data_headers);
        if (cl == NULL) {
            return NULL;
        }

        buf = cl->buf;

        if (buf->start) {
            p = buf->start;
            buf->pos = p;

            p += NGX_SPDY_SID_SIZE;

            (void) ngx_spdy_frame_write_flags_and_len(p, flags, len);

        } else {
            p = ngx_palloc(stream->request->pool, NGX_SPDY_FRAME_HEADER_SIZE);
            if (p == NULL) {
                return NULL;
            }

            buf->pos = p;
            buf->start = p;

            p = ngx_spdy_frame_write_sid(p, stream->id);
            p = ngx_spdy_frame_write_flags_and_len(p, flags, len);

            buf->last = p;
            buf->end = p;

            buf->tag = (ngx_buf_tag_t) &ngx_http_spdy_filter_get_data_frame;
            buf->memory = 1;
        }

        cl->next = first;
        first = cl;
    }

    frame->first = first;
    frame->last = last;
    frame->handler = ngx_http_spdy_data_frame_handler;
    frame->free = NULL;
    frame->stream = stream;
    frame->size = NGX_SPDY_FRAME_HEADER_SIZE + len;
    frame->priority = stream->priority;
    frame->blocked = 0;
    frame->fin = last->buf->last_buf;

    return frame;
}


static ngx_inline ngx_int_t
ngx_http_spdy_filter_send(ngx_connection_t *fc, ngx_http_spdy_stream_t *stream)
{
    stream->blocked = 1;

    if (ngx_http_spdy_send_output_queue(stream->connection) == NGX_ERROR) {
        fc->error = 1;
        return NGX_ERROR;
    }

    stream->blocked = 0;

    if (stream->queued) {
        fc->buffered |= NGX_SPDY_BUFFERED;
        fc->write->delayed = 1;
        return NGX_AGAIN;
    }

    fc->buffered &= ~NGX_SPDY_BUFFERED;

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_syn_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_buf_t               *buf;
    ngx_http_spdy_stream_t  *stream;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NGX_AGAIN;
    }

    stream = frame->stream;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy:%ui SYN_REPLY frame %p was sent", stream->id, frame);

    ngx_free_chain(stream->request->pool, frame->first);

    ngx_http_spdy_handle_frame(stream, frame);

    ngx_http_spdy_handle_stream(sc, stream);

    return NGX_OK;
}


static ngx_int_t
ngx_http_spdy_data_frame_handler(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_buf_t               *buf;
    ngx_chain_t             *cl, *ln;
    ngx_http_spdy_stream_t  *stream;

    stream = frame->stream;

    cl = frame->first;

    if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_filter_get_data_frame) {

        if (cl->buf->pos != cl->buf->last) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy:%ui DATA frame %p was sent partially",
                           stream->id, frame);

            return NGX_AGAIN;
        }

        ln = cl->next;

        cl->next = stream->free_data_headers;
        stream->free_data_headers = cl;

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

    for ( ;; ) {
        if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_filter_get_shadow) {
            buf = cl->buf->shadow;

            if (ngx_buf_in_memory(buf)) {
                buf->pos = cl->buf->pos;
            }

            if (buf->in_file) {
                buf->file_pos = cl->buf->file_pos;
            }
        }

        if (ngx_buf_size(cl->buf) != 0) {

            if (cl != frame->first) {
                frame->first = cl;
                ngx_http_spdy_handle_stream(sc, stream);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                           "spdy:%ui DATA frame %p was sent partially",
                           stream->id, frame);

            return NGX_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_spdy_filter_get_shadow) {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;

        } else {
            ngx_free_chain(stream->request->pool, cl);
        }

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->connection->log, 0,
                   "spdy:%ui DATA frame %p was sent", stream->id, frame);

    stream->request->header_size += NGX_SPDY_FRAME_HEADER_SIZE;

    ngx_http_spdy_handle_frame(stream, frame);

    ngx_http_spdy_handle_stream(sc, stream);

    return NGX_OK;
}


static ngx_inline void
ngx_http_spdy_handle_frame(ngx_http_spdy_stream_t *stream,
    ngx_http_spdy_out_frame_t *frame)
{
    ngx_http_request_t  *r;

    r = stream->request;

    r->connection->sent += frame->size;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    frame->free = stream->free_frames;
    stream->free_frames = frame;

    stream->queued--;
}


static ngx_inline void
ngx_http_spdy_handle_stream(ngx_http_spdy_connection_t *sc,
    ngx_http_spdy_stream_t *stream)
{
    ngx_event_t  *wev;

    if (stream->handled || stream->blocked) {
        return;
    }

    wev = stream->request->connection->write;

    if (!wev->timer_set) {
        wev->delayed = 0;

        stream->handled = 1;

        stream->next = sc->last_stream;
        sc->last_stream = stream;
    }
}


static void
ngx_http_spdy_filter_cleanup(void *data)
{
    ngx_http_spdy_stream_t *stream = data;

    ngx_http_spdy_out_frame_t  *frame, **fn;

    if (stream->queued == 0) {
        return;
    }

    fn = &stream->connection->last_out;

    for ( ;; ) {
        frame = *fn;

        if (frame == NULL) {
            break;
        }

        if (frame->stream == stream && !frame->blocked) {
            stream->queued--;

            *fn = frame->next;
            continue;
        }

        fn = &frame->next;
    }
}


static ngx_int_t
ngx_http_spdy_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_spdy_header_filter;

    return NGX_OK;
}
