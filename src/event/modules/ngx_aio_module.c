
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_aio.h>

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


static int ngx_aio_init(ngx_log_t *log);
static void ngx_aio_done(ngx_log_t *log);
static int ngx_aio_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_aio_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_aio_process_events(ngx_log_t *log);


ngx_os_io_t ngx_os_aio = {
    ngx_aio_read,
    NULL,
    ngx_aio_write,
    ngx_aio_write_chain,
    NGX_HAVE_ZEROCOPY
};


static ngx_str_t      aio_name = ngx_string("aio");

ngx_event_module_t  ngx_aio_module_ctx = {
    NGX_EVENT_MODULE,
    &aio_name,
    NULL,                                  /* create configuration */
    NULL,                                  /* init configuration */

    {
        ngx_aio_add_event,                 /* add an event */
        ngx_aio_del_event,                 /* delete an event */
        NULL,                              /* enable an event */
        NULL,                              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        ngx_aio_process_events,            /* process the events */
        ngx_aio_init,                      /* init the events */
        ngx_aio_done                       /* done the events */
    }

};

ngx_module_t  ngx_aio_module = {
    &ngx_aio_module_ctx,                   /* module context */
    0,                                     /* module index */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE_TYPE,                 /* module type */
    NULL                                   /* init module */
};



#if (HAVE_KQUEUE)

static int ngx_aio_init(ngx_log_t *log)
{
    if (ngx_kqueue_module_ctx.actions.init(log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_event_flags = NGX_HAVE_AIO_EVENT|NGX_USE_AIO_EVENT;
    ngx_event_actions = ngx_aio_module_ctx.actions;
    ngx_io = ngx_os_aio;


    return NGX_OK;
}


static void ngx_aio_done(ngx_log_t *log)
{
    ngx_kqueue_module_ctx.actions.done(log);
}


/* The event adding and deleteing are needed for the listening sockets */

static int ngx_aio_add_event(ngx_event_t *ev, int event, u_int flags)
{
    return ngx_kqueue_module_ctx.actions.add(ev, event, flags);
}


static int ngx_aio_del_event(ngx_event_t *ev, int event, u_int flags)
{
    return ngx_kqueue_module_ctx.actions.del(ev, event, flags);
}


static int ngx_aio_process_events(ngx_log_t *log)
{
    return ngx_kqueue_module_ctx.actions.process(log);
}

#endif


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
