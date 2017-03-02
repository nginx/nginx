
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_iocp_module.h>


static ngx_int_t ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static ngx_thread_value_t __stdcall ngx_iocp_timer(void *data);
static void ngx_iocp_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t key);
static ngx_int_t ngx_iocp_del_connection(ngx_connection_t *c, ngx_uint_t flags);
static ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);
static void *ngx_iocp_create_conf(ngx_cycle_t *cycle);
static char *ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_str_t      iocp_name = ngx_string("iocp");

static ngx_command_t  ngx_iocp_commands[] = {

    { ngx_string("iocp_threads"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, threads),
      NULL },

    { ngx_string("post_acceptex"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_iocp_conf_t, post_acceptex),
      NULL },

    { ngx_string("acceptex_read"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_iocp_conf_t, acceptex_read),
      NULL },

      ngx_null_command
};


static ngx_event_module_t  ngx_iocp_module_ctx = {
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
        NULL,                              /* trigger a notify */
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
    ngx_udp_overlapped_wsarecv,
    NULL,
    NULL,
    NULL,
    ngx_overlapped_wsasend_chain,
    0
};


static HANDLE      iocp;
static ngx_tid_t   timer_thread;
static ngx_msec_t  msec;


static ngx_int_t
ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_iocp_conf_t  *cf;

    cf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);

    if (iocp == NULL) {
        iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
                                      cf->threads);
    }

    if (iocp == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    ngx_io = ngx_iocp_io;

    ngx_event_actions = ngx_iocp_module_ctx.actions;

    ngx_event_flags = NGX_USE_IOCP_EVENT;

    if (timer == 0) {
        return NGX_OK;
    }

    /*
     * The waitable timer could not be used, because
     * GetQueuedCompletionStatus() does not set a thread to alertable state
     */

    if (timer_thread == NULL) {

        msec = timer;

        if (ngx_create_thread(&timer_thread, ngx_iocp_timer, &msec, cycle->log)
            != 0)
        {
            return NGX_ERROR;
        }
    }

    ngx_event_flags |= NGX_USE_TIMER_EVENT;

    return NGX_OK;
}


static ngx_thread_value_t __stdcall
ngx_iocp_timer(void *data)
{
    ngx_msec_t  timer = *(ngx_msec_t *) data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "THREAD %p %p", &msec, data);

    for ( ;; ) {
        Sleep(timer);

        ngx_time_update();
#if 1
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer");
#endif
    }

#if defined(__WATCOMC__) || defined(__GNUC__)
    return 0;
#endif
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
ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t key)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    c->read->active = 1;
    c->write->active = 1;

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "iocp add: fd:%d k:%ui ov:%p", c->fd, key, &ev->ovlp);

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, key, 0) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iocp_del_connection(ngx_connection_t *c, ngx_uint_t flags)
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
ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                rc;
    u_int              key;
    u_long             bytes;
    ngx_err_t          err;
    ngx_msec_t         delta;
    ngx_event_t       *ev;
    ngx_event_ovlp_t  *ovlp;

    if (timer == NGX_TIMER_INFINITE) {
        timer = INFINITE;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "iocp timer: %M", timer);

    rc = GetQueuedCompletionStatus(iocp, &bytes, (PULONG_PTR) &key,
                                   (LPOVERLAPPED *) &ovlp, (u_long) timer);

    if (rc == 0) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    delta = ngx_current_msec;

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "iocp: %d b:%d k:%d ov:%p", rc, bytes, key, ovlp);

    if (timer != INFINITE) {
        delta = ngx_current_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "iocp timer: %M, delta: %M", timer, delta);
    }

    if (err) {
        if (ovlp == NULL) {
            if (err != WAIT_TIMEOUT) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                              "GetQueuedCompletionStatus() failed");

                return NGX_ERROR;
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
