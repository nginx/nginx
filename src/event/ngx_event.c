
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_string.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_array.h>
#include <ngx_listen.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_accept.h>

#include <ngx_select_module.h>

#if (HAVE_POLL)
#include <ngx_poll_module.h>
#endif

#if (HAVE_DEVPOLL)
#include <ngx_devpoll_module.h>
#endif

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif

#if (HAVE_AIO)
#include <ngx_aio_module.h>
#endif

#if (HAVE_IOCP)
#include <ngx_event_acceptex.h>
#include <ngx_iocp_module.h>
#endif


ngx_connection_t    *ngx_connections;
ngx_event_t         *ngx_read_events, *ngx_write_events;

#if !(USE_KQUEUE)

ngx_event_type_e     ngx_event_type;

int                  ngx_event_flags;

ngx_event_actions_t  ngx_event_actions;

/* ngx_event_type_e order */
static int (*ngx_event_init[]) (int max_connections, ngx_log_t *log) = {
    ngx_select_init,
#if (HAVE_POLL)
    ngx_poll_init,
#endif
#if (HAVE_DEVPOLL)
    ngx_devpoll_init,
#endif
#if (HAVE_KQUEUE)
    ngx_kqueue_init,
#endif
#if (HAVE_AIO)
    ngx_aio_init,
#endif
#if (HAVE_IOCP)
    ngx_iocp_init
#endif
};

#endif /* USE_KQUEUE */


void ngx_pre_thread(ngx_array_t *ls, ngx_pool_t *pool, ngx_log_t *log)
{
    int  i, fd;

    ngx_listen_t      *s;
    ngx_event_t       *ev;
    ngx_connection_t  *c;

    /* STUB */
    int max_connections = 512;

#if 0
    ngx_event_type = NGX_POLL_EVENT_N;
#endif
#if 1
    ngx_event_type = NGX_KQUEUE_EVENT_N;
#endif
#if 0
    ngx_event_type = NGX_DEVPOLL_EVENT_N;
#endif
#if 0
    ngx_event_type = NGX_AIO_EVENT_N;
#endif
#if 0
    ngx_event_type = NGX_IOCP_EVENT_N;
#endif

    if (ngx_init_events(max_connections, log) == NGX_ERROR) {
        exit(1);
    }

    ngx_connections = ngx_alloc(sizeof(ngx_connection_t)
                                                       * max_connections, log);
    ngx_read_events = ngx_alloc(sizeof(ngx_event_t) * max_connections, log);
    ngx_write_events = ngx_alloc(sizeof(ngx_event_t) * max_connections, log);

    /* for each listening socket */
    s = (ngx_listen_t *) ls->elts;
    for (i = 0; i < ls->nelts; i++) {

        fd = s[i].fd;

        c = &ngx_connections[fd];
        ev = &ngx_read_events[fd];

        ngx_memzero(c, sizeof(ngx_connection_t));
        ngx_memzero(ev, sizeof(ngx_event_t));

        c->fd = fd;
        c->family = s[i].family;
        c->socklen = s[i].socklen;
        c->sockaddr = ngx_palloc(pool, s[i].socklen);
        c->addr = s[i].addr;
        c->addr_text = s[i].addr_text;
        c->addr_text_max_len = s[i].addr_text_max_len;
        c->post_accept_timeout = s[i].post_accept_timeout;

        c->handler = s[i].handler;
        c->ctx = s[i].ctx;
        c->servers = s[i].servers;
        c->log = s[i].log;
        c->pool_size = s[i].pool_size;

        ngx_test_null(ev->log,
                      ngx_palloc(pool, sizeof(ngx_log_t)), /* void */ ; );
        ngx_memcpy(ev->log, c->log, sizeof(ngx_log_t));
        c->read = ev;
        ev->data = c;
        ev->index = NGX_INVALID_INDEX;
#if 0
        ev->listening = 1;
#endif

        ev->available = 0;

#if (HAVE_DEFERRED_ACCEPT)
        ev->deferred_accept = s[i].deferred_accept;
#endif

#if (HAVE_IOCP)

        if (ngx_event_flags & NGX_HAVE_IOCP_EVENT) {
            ev->event_handler = &ngx_event_acceptex;

            /* LOOK: we call ngx_iocp_add_event() also
               in ngx_event_post_acceptex() */
            if (ngx_iocp_add_event(ev) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ngx_event_post_acceptex(&s[i], 1);

        } else {
            ev->event_handler = &ngx_event_accept;
        }

#else

        ev->event_handler = &ngx_event_accept;
        ngx_add_event(ev, NGX_READ_EVENT, 0);

#endif
    }
}

void ngx_worker(ngx_log_t *log)
{
    for ( ;; ) {
        ngx_log_debug(log, "ngx_worker cycle");

        ngx_process_events(log);
    }
}
