
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>
#include <nginx.h>


static void ngx_imap_init_session(ngx_event_t *rev);


static char pop3_greeting[] = "+OK " NGINX_VER " ready" CRLF;
static char imap_greeting[] = "* OK " NGINX_VER " ready" CRLF;


void ngx_imap_init_connection(ngx_connection_t *c)
{
    char       *greeting;
    ssize_t     size;
    ngx_int_t   n;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "imap init connection");

    c->log_error = NGX_ERROR_INFO;

    greeting = pop3_greeting;
    size = sizeof(pop3_greeting) - 1;

    n = ngx_send(c, greeting, size);

    if (n < size) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_imap_close_connection(c);
        return;
    }

    c->read->event_handler = ngx_imap_init_session;

    ngx_add_timer(c->read, /* STUB */ 60000);

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_imap_close_connection(c);
    }
}


static void ngx_imap_init_session(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_imap_session_t  *s;

    c = rev->data;

    if (!(s = ngx_pcalloc(c->pool, sizeof(ngx_imap_session_t)))) {
        ngx_imap_close_connection(c);
        return;
    }

    c->data = s;
    s->connection = c;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    s->buffer = ngx_create_temp_buf(s->connection->pool, /* STUB */ 4096);
    if (s->buffer == NULL) {
        ngx_imap_close_connection(s->connection);
        return;
    }

    ngx_imap_proxy_init(s);
}


void ngx_imap_close_connection(ngx_connection_t *c)
{
    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "close imap connection: %d", c->fd);

    ngx_close_connection(c);
}
