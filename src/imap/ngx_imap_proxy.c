
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>


static void ngx_imap_proxy_close_session(ngx_imap_session_t *s);


void ngx_imap_proxy_handler(ngx_event_t *ev)
{
    ssize_t              n;
    ngx_buf_t           *b;
    ngx_uint_t           data, do_write;
    ngx_connection_t    *c, *src, *dst;
    ngx_imap_session_t  *s;

    c = ev->data;
    s = c->data;

    if (c == s->connection) {
        src = c;
        dst = s->proxy->connection;
        b = s->proxy->downstream_buffer;

    } else {
        src = s->proxy->connection;
        dst = c;
        b = s->proxy->upstream_buffer;
    }

    do_write = ev->write ? 1 : 0;

    do {
        data = 0;

        if (do_write == 1) {
            if (dst->write->ready && b->pos < b->last) {
                n = ngx_send(dst, b->pos, b->last - b->pos);

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
            }
        }

        if (src->read->ready && b->last < b->end) {
            n = ngx_recv(src, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                ngx_imap_proxy_close_session(s);
                return;
            }

            if (n > 0) {
                data = 1;
                do_write = 1;
                b->last += n;
            }
        }

    } while (data);
}


static void ngx_imap_proxy_close_session(ngx_imap_session_t *s)
{
}
