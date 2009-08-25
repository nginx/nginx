
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern ngx_event_module_t  ngx_kqueue_module_ctx;


static ngx_int_t ngx_aio_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_aio_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_aio_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_aio_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_aio_del_connection(ngx_connection_t *c, ngx_uint_t flags);
static ngx_int_t ngx_aio_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);


ngx_os_io_t ngx_os_aio = {
    ngx_aio_read,
    ngx_aio_read_chain,
    NULL,
    ngx_aio_write,
    ngx_aio_write_chain,
    0
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
    NGX_MODULE_V1,
    &ngx_aio_module_ctx,                   /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_KQUEUE)

static ngx_int_t
ngx_aio_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    if (ngx_kqueue_module_ctx.actions.init(cycle, timer) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_io = ngx_os_aio;

    ngx_event_flags = NGX_USE_AIO_EVENT;
    ngx_event_actions = ngx_aio_module_ctx.actions;


    return NGX_OK;
}


static void
ngx_aio_done(ngx_cycle_t *cycle)
{
    ngx_kqueue_module_ctx.actions.done(cycle);
}


/* the event adding and deleting are needed for the listening sockets */

static ngx_int_t
ngx_aio_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    return ngx_kqueue_module_ctx.actions.add(ev, event, flags);
}


static ngx_int_t
ngx_aio_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    return ngx_kqueue_module_ctx.actions.del(ev, event, flags);
}


static ngx_int_t
ngx_aio_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int  rc;

    if (c->read->active == 0 && c->write->active == 0) {
        return NGX_OK;
    }

    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    rc = aio_cancel(c->fd, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "aio_cancel: %d", rc);

    if (rc == AIO_CANCELED) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    if (rc == AIO_ALLDONE) {
        c->read->active = 0;
        c->write->active = 0;
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


static ngx_int_t
ngx_aio_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    return ngx_kqueue_module_ctx.actions.process_events(cycle, timer, flags);
}

#endif /* NGX_HAVE_KQUEUE */
