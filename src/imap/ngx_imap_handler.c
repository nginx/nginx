
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_imap.h>
#include <nginx.h>


static void ngx_imap_auth_state(ngx_event_t *rev);


static char pop3_greeting[] = "+OK " NGINX_VER " ready" CRLF;
static char imap_greeting[] = "* OK " NGINX_VER " ready" CRLF;


void ngx_imap_init_connection(ngx_connection_t *c)
{
    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "imap init connection");

    c->log_error = NGX_ERROR_INFO;

    rc = ngx_send(c, pop3_greeting, sizeof(pop3_greeting) - 1);

    if (rc == NGX_ERROR) {
        ngx_imap_close_connection(c);
        return;
    }

    c->read->event_handler = ngx_imap_auth_state;

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_imap_close_connection(c);
        return;
    }
}


static void ngx_imap_auth_state(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    ngx_imap_close_connection(c);
}


void ngx_imap_close_connection(ngx_connection_t *c)
{
    ngx_log_debug1(NGX_LOG_DEBUG_IMAP, c->log, 0,
                   "close imap connection: %d", c->fd);

    ngx_close_connection(c);
}
