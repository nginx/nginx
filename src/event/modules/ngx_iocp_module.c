
/*
 * Copyright (C) 2002-2003 Igor Sysoev, http://sysoev.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_iocp_module.h>


static int ngx_iocp_init(ngx_cycle_t *cycle);
static void ngx_iocp_done(ngx_cycle_t *cycle);
static int ngx_iocp_add_event(ngx_event_t *ev, int event, u_int key);
static int ngx_iocp_del_connection(ngx_connection_t *c);
static int ngx_iocp_process_events(ngx_log_t *log);
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

    {ngx_string("acceptex"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_iocp_conf_t, acceptex),
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
        ngx_iocp_process_events,           /* process the events */
        ngx_iocp_init,                     /* init the events */
        ngx_iocp_done                      /* done the events */
    }

};

ngx_module_t  ngx_iocp_module = {
    NGX_MODULE,
    &ngx_iocp_module_ctx,                  /* module context */
    ngx_iocp_commands,                     /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static HANDLE  iocp;


static int ngx_iocp_init(ngx_cycle_t *cycle)
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

    if (ngx_event_timer_init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_iocp_module_ctx.actions;

    ngx_event_flags = NGX_USE_AIO_EVENT|NGX_USE_IOCP_EVENT;

    return NGX_OK;
}


static void ngx_iocp_done(ngx_cycle_t *cycle)
{
    if (CloseHandle(iocp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "iocp CloseHandle() failed");
    }

    iocp = NULL;

    ngx_event_timer_done(cycle);
}


static int ngx_iocp_add_event(ngx_event_t *ev, int event, u_int key)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    c->read->active = 1;
    c->write->active = 1;

    ngx_log_debug(ev->log, "iocp add: %d, %d:%08x" _ c->fd _ key _ &ev->ovlp);

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, key, 0) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static int ngx_iocp_del_connection(ngx_connection_t *c)
{
    if (CancelIo((HANDLE) c->fd) == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "CancelIo() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static int ngx_iocp_process_events(ngx_log_t *log)
{
    int                rc;
    u_int              key;
    size_t             bytes;
    ngx_err_t          err;
    ngx_msec_t         timer, delta;
    ngx_event_t       *ev;
    ngx_event_ovlp_t  *ovlp;

    timer = ngx_event_find_timer();

    if (timer) {
        delta = ngx_msec();

    } else {
        timer = INFINITE;
        delta = 0;
    }

    ngx_log_debug(log, "iocp timer: %d" _ timer);

    rc = GetQueuedCompletionStatus(iocp, &bytes, (LPDWORD) &key,
                                   (LPOVERLAPPED *) &ovlp, timer);

    ngx_log_debug(log, "iocp: %d, %d, %d:%08x" _ rc _ bytes _ key _ ovlp);

    if (rc == 0) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    if (timer != INFINITE) {
        delta = ngx_msec() - delta;
        ngx_event_expire_timers(delta);
    }

    if (err) {
        if (ovlp == NULL) {
            if (err != WAIT_TIMEOUT) {
                ngx_log_error(NGX_LOG_ALERT, log, err,
                              "GetQueuedCompletionStatus() failed");

                return NGX_ERROR;
            }

        } else {
            ovlp->error = err;
        }
    }

    if (ovlp) {
        ev = ovlp->event;

ngx_log_debug(log, "iocp ev: %08x" _ ev);

        switch (key) {
        case NGX_IOCP_IO:
            ev->ready = 1;
            break;

        case NGX_IOCP_ACCEPT:
            if (bytes) {
                ev->ready = 1;
            }
            break;
        }

        ev->available = bytes;

ngx_log_debug(log, "iocp ev handler: %08x" _ ev->event_handler);

        ev->event_handler(ev);
    }

    return NGX_OK;
}


static void *ngx_iocp_create_conf(ngx_cycle_t *cycle)
{
    ngx_iocp_conf_t  *cf;

    ngx_test_null(cf, ngx_palloc(cycle->pool, sizeof(ngx_iocp_conf_t)),
                  NGX_CONF_ERROR);

    cf->threads = NGX_CONF_UNSET;
    cf->acceptex = NGX_CONF_UNSET;
    cf->acceptex_read = NGX_CONF_UNSET;

    return cf;
}


static char *ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_iocp_conf_t *cf = conf;

    ngx_conf_init_value(cf->threads, 0);
    ngx_conf_init_value(cf->acceptex, 10);
    ngx_conf_init_value(cf->acceptex_read, 1);

    return NGX_CONF_OK;
}
