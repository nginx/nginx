
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


static int ngx_aio_init(ngx_cycle_t *cycle);
static void ngx_aio_done(ngx_cycle_t *cycle);
static int ngx_aio_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_aio_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_aio_del_connection(ngx_connection_t *c, u_int flags);
static int ngx_aio_process_events(ngx_cycle_t *cycle);


ngx_os_io_t ngx_os_aio = {
    ngx_aio_read,
    ngx_aio_read_chain,
    ngx_aio_write,
    ngx_aio_write_chain,
    NGX_HAVE_ZEROCOPY
};


static ngx_str_t      aio_name = ngx_string("aio");

ngx_event_module_t  ngx_aio_module_ctx = {
    &aio_name,
    NULL,                                  /* create configuration */
    NULL,                                  /* init configuration */

    {
        ngx_aio_add_event,                 /* add an event */
        ngx_aio_del_event,                 /* delete an event */
        NULL,                              /* enable an event */
        NULL,                              /* disable an event */
        NULL,                              /* add an connection */
        ngx_aio_del_connection,            /* delete an connection */
        NULL,                              /* process the changes */
        ngx_aio_process_events,            /* process the events */
        ngx_aio_init,                      /* init the events */
        ngx_aio_done                       /* done the events */
    }

};

ngx_module_t  ngx_aio_module = {
    NGX_MODULE,
    &ngx_aio_module_ctx,                   /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init process */
};



#if (HAVE_KQUEUE)

static int ngx_aio_init(ngx_cycle_t *cycle)
{
    if (ngx_kqueue_module_ctx.actions.init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_io = ngx_os_aio;

    ngx_event_flags = NGX_USE_AIO_EVENT;
    ngx_event_actions = ngx_aio_module_ctx.actions;


    return NGX_OK;
}


static void ngx_aio_done(ngx_cycle_t *cycle)
{
    ngx_kqueue_module_ctx.actions.done(cycle);
}


/* The event adding and deleting are needed for the listening sockets */

static int ngx_aio_add_event(ngx_event_t *ev, int event, u_int flags)
{
    return ngx_kqueue_module_ctx.actions.add(ev, event, flags);
}


static int ngx_aio_del_event(ngx_event_t *ev, int event, u_int flags)
{
    return ngx_kqueue_module_ctx.actions.del(ev, event, flags);
}


static int ngx_aio_del_connection(ngx_connection_t *c, u_int flags)
{
    int  rc;

    if (c->read->active == 0 && c->write->active == 0) {
        return NGX_OK;
    }

    rc = aio_cancel(c->fd, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "aio_cancel: %d", rc);

    if (rc == AIO_CANCELED) {
        c->read->active = c->write->active = 0;
        return NGX_OK;
    }

    if (rc == AIO_ALLDONE) {
        c->read->active = c->write->active = 0;
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "aio_cancel() returned AIO_ALLDONE");
        return NGX_OK;
    }

    if (rc == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "aio_cancel() failed");
        return NGX_ERROR;
    }

    if (rc == AIO_NOTCANCELED) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "aio_cancel() returned AIO_NOTCANCELED");

        return NGX_ERROR;
    }

    return NGX_OK;
}


static int ngx_aio_process_events(ngx_cycle_t *cycle)
{
    return ngx_kqueue_module_ctx.actions.process_events(cycle);
}

#endif /* HAVE_KQUEUE */


#if 0

/* 1 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    listen via SIGIO;
    aio_* via SIGxxx;

    sigsuspend()/sigwaitinfo()/sigtimedwait();
}

/* 2 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    unmask signal

    listen via SIGIO;

    /* BUG: SIGIO can be delivered before aio_*() */

    aio_suspend()/aiowait()/aio_waitcomplete() with timeout

    mask signal

    if (ngx_socket_errno == NGX_EINTR)
        look listen
        select()/accept() nb listen sockets
    else
        aio
}

/* 3 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
#if 0
    unmask signal

    /* BUG: AIO signal can be delivered before select() */

    select(listen);

    mask signal
#endif

    pselect(listen, mask);

    if (ngx_socket_errno == NGX_EINTR)
        look ready array
}

void aio_sig_handler(int signo, siginfo_t *siginfo, void *context)
{
    push siginfo->si_value.sival_ptr
}

#endif
