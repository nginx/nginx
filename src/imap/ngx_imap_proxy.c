
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_imap.h>


static void ngx_imap_proxy_block_read(ngx_event_t *rev);
static void ngx_imap_proxy_greeting_handler(ngx_event_t *rev);
static void ngx_imap_proxy_init_handler(ngx_event_t *wev);
static void ngx_imap_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_imap_proxy_read_response(ngx_imap_session_t *s);
static void ngx_imap_proxy_handler(ngx_event_t *ev);
static void ngx_imap_proxy_close_session(ngx_imap_session_t *s);


void ngx_imap_proxy_init(ngx_imap_session_t *s)
{
    ngx_int_t              rc;
    ngx_peers_t           *peers;
    ngx_imap_proxy_ctx_t  *p;

    if (!(p = ngx_pcalloc(s->connection->pool, sizeof(ngx_imap_proxy_ctx_t)))) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    s->proxy = p;

    /**/

    if (!(peers = ngx_pcalloc(s->connection->pool, sizeof(ngx_peers_t)))) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    p->upstream.peers = peers;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    peers->number = 1;
    peers->max_fails = 1;
    peers->peers[0].addr = inet_addr("81.19.69.70");
    peers->peers[0].addr_port_text.len = sizeof("81.19.69.70:110") - 1;
    peers->peers[0].addr_port_text.data = "81.19.69.70:110";
    peers->peers[0].port = htons(110);

    rc = ngx_event_connect_peer(&p->upstream);

    if (rc == NGX_ERROR) {
        ngx_imap_proxy_close_session(s);
        return;
    }

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->event_handler = ngx_imap_proxy_block_read;
    p->upstream.connection->read->event_handler =
                                               ngx_imap_proxy_greeting_handler;
    p->upstream.connection->write->event_handler = ngx_imap_proxy_dummy_handler;
}


static void ngx_imap_proxy_block_read(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0, "imap proxy block read");

    if (ngx_handle_read_event(rev, 0) == NGX_ERROR) {
        c = rev->data;
        s = c->data;

        ngx_imap_proxy_close_session(s);
    }
}


static void ngx_imap_proxy_greeting_handler(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_buf_t           *b;
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, rev->log, 0,
                   "imap proxy greeting handler");

    c = rev->data;
    s = c->data;

    if (s->proxy->buffer == NULL) {
        s->proxy->buffer = ngx_create_temp_buf(c->pool, /* STUB */ 4096);
        if (s->proxy->buffer == NULL) {
            ngx_imap_proxy_close_session(s);
            return;
        }
    }

    rc = ngx_imap_proxy_read_response(s);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_OK) {
        s->connection->read->event_handler = ngx_imap_proxy_handler;
        s->connection->write->event_handler = ngx_imap_proxy_handler;
        rev->event_handler = ngx_imap_proxy_handler;
        c->write->event_handler = ngx_imap_proxy_handler;

        b = s->proxy->buffer;
        b->pos = b->start;
        b->last = b->start;

        if (ngx_handle_read_event(s->connection->read, 0) == NGX_ERROR) {
            ngx_imap_proxy_close_session(s);
            return;
        }

        if (s->connection->read->ready) {
            ngx_imap_proxy_handler(s->connection->read);
        }

        return;
    }

    /* TODO: ngx_imap_proxy_finalize_session(s, NGX_IMAP_INTERNAL_ERROR) */
    ngx_imap_proxy_close_session(s);
}


static void ngx_imap_proxy_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, ev->log, 0, "imap proxy dummy handler");
}


static ngx_int_t ngx_imap_proxy_read_response(ngx_imap_session_t *s)
{
    u_char     *p;
    ssize_t     n;
    ngx_buf_t  *b;

    b = s->proxy->buffer;

    n = ngx_recv(s->proxy->upstream.connection, b->last, b->end - b->last);

    if (n == NGX_ERROR || n == 0) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 5) {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return NGX_IMAP_PROXY_INVALID;
        }

        return NGX_AGAIN;
    }

    p = b->pos;

    if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
        return NGX_OK;
    }

    if (p[0] == '-' && p[1] == 'E' && p[2] == 'R' && p[3] == 'R') {
        return NGX_IMAP_PROXY_ERROR;
    }

    *(b->last - 2) = '\0';
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "upstream sent invalid greeting line: \"%s\"", p);

    return NGX_IMAP_PROXY_INVALID;
}


static void ngx_imap_proxy_handler(ngx_event_t *ev)
{
    size_t               size;
    ssize_t              n;
    ngx_buf_t           *b;
    ngx_uint_t           data, do_write;
    ngx_connection_t    *c, *src, *dst;
    ngx_imap_session_t  *s;

    c = ev->data;
    s = c->data;

    if (c == s->connection) {
        src = c;
        dst = s->proxy->upstream.connection;
        b = s->buffer;

    } else {
        src = c;
        dst = s->connection;
        b = s->proxy->buffer;
    }

    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_IMAP, ev->log, 0,
                   "imap proxy handler: %d, #%d > #%d",
                   do_write, src->fd, dst->fd);

    do {
        data = 0;

        if (do_write == 1) {

            size = b->last - b->pos;

            if (dst->write->ready && size) {
                n = ngx_send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_imap_proxy_close_session(s);
                    return;
                }

                if (n > 0) {
                    data = 1;
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }

                if (n == NGX_AGAIN || n < (ssize_t) size) {
                    dst->write->available = 0;
                    if (ngx_handle_write_event(dst->write, NGX_LOWAT_EVENT)
                                                                  == NGX_ERROR)
                    {
                        ngx_imap_proxy_close_session(s);
                        return;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (src->read->ready && size) {
            n = ngx_recv(src, b->last, size);

            if (n == NGX_ERROR || n == 0) {
                ngx_imap_proxy_close_session(s);
                return;
            }

            if (n > 0) {
                data = 1;
                do_write = 1;
                b->last += n;
            }

            if (n == NGX_AGAIN || n < (ssize_t) size) {
                if (ngx_handle_read_event(src->read, 0) == NGX_ERROR) {
                    ngx_imap_proxy_close_session(s);
                    return;
                }
            }
        }

    } while (data);
}


static void ngx_imap_proxy_close_session(ngx_imap_session_t *s)
{
    if (ngx_close_socket(s->proxy->upstream.connection->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    ngx_imap_close_connection(s->connection);
}
