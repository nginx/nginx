
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_iocp_module.h>


static ngx_int_t ngx_iocp_init(ngx_cycle_t *cycle);
static void ngx_iocp_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_iocp_add_event(ngx_event_t *ev, int event, u_int key);
static ngx_int_t ngx_iocp_del_connection(ngx_connection_t *c, u_int flags);
static ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle);
static void *ngx_iocp_create_conf(ngx_cycle_t *cycle);
static char *ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_str_t      iocp_name = ngx_string("iocp");

static ngx_command_t  ngx_iocp_commands[] = {

    {ngx_string("iocp_threads"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_iocp_conf_t, threads),
     NULL},

    {ngx_string("post_acceptex"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_iocp_conf_t, post_acceptex),
     NULL},

    {ngx_string("acceptex_read"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     0,
     offsetof(ngx_iocp_conf_t, acceptex_read),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_iocp_module_ctx = {
    &iocp_name,
    ngx_iocp_create_conf,                  /* create configuration */
    ngx_iocp_init_conf,                    /* init configuration */

    {
        ngx_iocp_add_event,                /* add an event */
        NULL,                              /* delete an event */
        NULL,                              /* enable an event */
        NULL,                              /* disable an event */
        NULL,                              /* add an connection */
        ngx_iocp_del_connection,           /* delete an connection */
        NULL,                              /* process the changes */
        ngx_iocp_process_events,           /* process the events */
        ngx_iocp_init,                     /* init the events */
        ngx_iocp_done                      /* done the events */
    }

};

ngx_module_t  ngx_iocp_module = {
    NGX_MODULE_V1,
    &ngx_iocp_module_ctx,                  /* module context */
    ngx_iocp_commands,                     /* module directives */
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


ngx_os_io_t ngx_iocp_io = {
    ngx_overlapped_wsarecv,
    NULL,
    NULL,
    ngx_overlapped_wsasend_chain,
    0
};


static HANDLE  iocp;


static ngx_int_t
ngx_iocp_init(ngx_cycle_t *cycle)
{
    ngx_iocp_conf_t  *cf;

    cf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);

    if (iocp == NULL) {
        iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
                                      cf->threads);
    }

    if (iocp == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    ngx_io = ngx_iocp_io;

    ngx_event_actions = ngx_iocp_module_ctx.actions;

    ngx_event_flags = NGX_USE_AIO_EVENT|NGX_USE_IOCP_EVENT;

    return NGX_OK;
}


static void
ngx_iocp_done(ngx_cycle_t *cycle)
{
    if (CloseHandle(iocp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "iocp CloseHandle() failed");
    }

    iocp = NULL;
}


static ngx_int_t
ngx_iocp_add_event(ngx_event_t *ev, int event, u_int key)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    c->read->active = 1;
    c->write->active = 1;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "iocp add: fd:%d k:%d ov:%p", c->fd, key, &ev->ovlp);

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, key, 0) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iocp_del_connection(ngx_connection_t *c, u_int flags)
{
#if 0
    if (flags & NGX_CLOSE_EVENT) {
        return NGX_OK;
    }

    if (CancelIo((HANDLE) c->fd) == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "CancelIo() failed");
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static
ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle)
{
    int                rc;
    u_int              key;
    u_long             bytes;
    ngx_err_t          err;
    ngx_msec_t         timer;
    ngx_event_t       *ev;
    struct timeval     tv;
    ngx_epoch_msec_t   delta;
    ngx_event_ovlp_t  *ovlp;

    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec;

    if (timer == 0) {
        timer = INFINITE;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "iocp timer: %d", timer);

    rc = GetQueuedCompletionStatus(iocp, &bytes, (LPDWORD) &key,
                                   (LPOVERLAPPED *) &ovlp, timer);

    if (rc == 0) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "iocp: %d b:%d k:%d ov:%p", rc, bytes, key, ovlp);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

    if (timer != INFINITE) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "iocp timer: %d, delta: %d", timer, (int) delta);
    }

    if (err) {
        if (ovlp == NULL) {
            if (err != WAIT_TIMEOUT) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                              "GetQueuedCompletionStatus() failed");

                return NGX_ERROR;
            }

            if (timer != INFINITE && delta) {
                ngx_event_expire_timers((ngx_msec_t) delta);
            }

            return NGX_OK;
        }

        ovlp->error = err;
    }

    if (ovlp == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "GetQueuedCompletionStatus() returned no operation");
        return NGX_ERROR;
    }


    ev = ovlp->event;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err, "iocp event:%p", ev);


    if (err == ERROR_NETNAME_DELETED /* the socket was closed */
        || err == ERROR_OPERATION_ABORTED /* the operation was canceled */)
    {

        /*
         * the WSA_OPERATION_ABORTED completion notification
         * for a file descriptor that was closed
         */

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err,
                       "iocp: aborted event %p", ev); 

        if (timer != INFINITE && delta) {
            ngx_event_expire_timers((ngx_msec_t) delta);
        }

        return NGX_OK;
    }

    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      "GetQueuedCompletionStatus() returned operation error");
    }

    switch (key) {

    case NGX_IOCP_ACCEPT:
        if (bytes) {
            ev->ready = 1;
        }
        break;

    case NGX_IOCP_IO:
        ev->complete = 1;
        ev->ready = 1;
        break;

    case NGX_IOCP_CONNECT:
        ev->ready = 1;
    }

    ev->available = bytes;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "iocp event handler: %p", ev->handler);

    ev->handler(ev);

    if (timer != INFINITE && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}


static void *
ngx_iocp_create_conf(ngx_cycle_t *cycle)
{
    ngx_iocp_conf_t  *cf;

    cf = ngx_palloc(cycle->pool, sizeof(ngx_iocp_conf_t));
    if (cf == NULL) {
        return NGX_CONF_ERROR;
    }

    cf->threads = NGX_CONF_UNSET;
    cf->post_acceptex = NGX_CONF_UNSET;
    cf->acceptex_read = NGX_CONF_UNSET;

    return cf;
}


static char *
ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_iocp_conf_t *cf = conf;

    ngx_conf_init_value(cf->threads, 0);
    ngx_conf_init_value(cf->post_acceptex, 10);
    ngx_conf_init_value(cf->acceptex_read, 1);

    return NGX_CONF_OK;
}
