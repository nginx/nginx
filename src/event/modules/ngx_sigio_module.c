
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (TEST_BUILD_SIGIO)

#define F_SETSIG  10

#define POLL_IN   POLLIN
#define POLL_OUT  POLLOUT

#endif


typedef struct {
    int  signo;
} ngx_sigio_conf_t;


static int ngx_sigio_init(ngx_cycle_t *cycle);
static void ngx_sigio_done(ngx_cycle_t *cycle);
static int ngx_sigio_add_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_sigio_del_event(ngx_event_t *ev, int event, u_int flags);
static int ngx_sigio_add_connection(ngx_connection_t *c);
static int ngx_sigio_del_connection(ngx_connection_t *c);
static int ngx_sigio_process_events(ngx_log_t *log);

static void *ngx_sigio_create_conf(ngx_cycle_t *cycle);
static char *ngx_sigio_init_conf(ngx_cycle_t *cycle, void *conf);


static sigset_t  set;


static ngx_str_t      sigio_name = ngx_string("sigio");

static ngx_command_t  ngx_sigio_commands[] = {

    {ngx_string("sigio_signal"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_sigio_conf_t, signo),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_sigio_module_ctx = {
    &sigio_name,
    ngx_sigio_create_conf,               /* create configuration */
    ngx_sigio_init_conf,                 /* init configuration */

    {
        ngx_sigio_add_event,             /* add an event */
        ngx_sigio_del_event,             /* delete an event */
        ngx_sigio_add_event,             /* enable an event */
        ngx_sigio_del_event,             /* disable an event */
        ngx_sigio_add_connection,        /* add an connection */
        ngx_sigio_del_connection,        /* delete an connection */
        ngx_sigio_process_events,        /* process the events */
        ngx_sigio_init,                  /* init the events */
        ngx_sigio_done,                  /* done the events */
    }

};

ngx_module_t  ngx_sigio_module = {
    NGX_MODULE,
    &ngx_sigio_module_ctx,               /* module context */
    ngx_sigio_commands,                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static int ngx_sigio_init(ngx_cycle_t *cycle)
{
    ngx_sigio_conf_t  *sgcf;

    sgcf = ngx_event_get_conf(cycle->conf_ctx, ngx_sigio_module);

    sigemptyset(&set);
    sigaddset(&set, sgcf->signo);
    sigaddset(&set, SIGIO);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigprocmask() failed");
        return NGX_ERROR;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_sigio_module_ctx.actions;

    ngx_event_flags = NGX_USE_SIGIO_EVENT;

    return NGX_OK;
}


static void ngx_sigio_done(ngx_cycle_t *cycle)
{
}


static int ngx_sigio_add_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t    *c;

    c = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sigio add event: fd:%d ev:%04X", c->fd, event);

    return NGX_OK;
}


static int ngx_sigio_del_event(ngx_event_t *ev, int event, u_int flags)
{
    ngx_connection_t    *c;

    c = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sigio del event: fd:%d ev:%04X", c->fd, event);

    return NGX_OK;
}


static int ngx_sigio_add_connection(ngx_connection_t *c)
{
    ngx_sigio_conf_t  *sgcf;

    sgcf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_sigio_module);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sigio add connection: fd:%d signo:%d", c->fd, sgcf->signo);

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK|O_ASYNC) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETSIG, sgcf->signo) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETSIG) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETOWN, ngx_getpid()) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETOWN) failed");
        return NGX_ERROR;
    }

#if (HAVE_ONESIGFD)
    if (fcntl(c->fd, F_SETAUXFL, O_ONESIGFD) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETAUXFL) failed");
        return NGX_ERROR;
    }
#endif

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


static int ngx_sigio_del_connection(ngx_connection_t *c)
{
    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


int ngx_sigio_process_events(ngx_log_t *log)
{
    int                 signo;
    ngx_int_t           instance, i;
    size_t              n;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **cycle;
    siginfo_t           si;
    struct timeval      tv;
    struct timespec     ts;
    struct sigaction    sa;
    ngx_connection_t   *c;
    ngx_epoch_msec_t    delta;
    ngx_sigio_conf_t   *sgcf;

    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec;

    if (timer) {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "sigio timer: %d", timer);

    if (timer) {
        signo = sigtimedwait(&set, &si, &ts);
    } else {
        signo = sigwaitinfo(&set, &si);
    }

    if (signo == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ngx_start_msec;

    if (err == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, err,
                      timer ? "sigtimedwait() failed" : "sigwaitinfo() failed");
        return NGX_ERROR;
    }

    if (timer) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "sigio timer: %d, delta: %d", timer, (int) delta);
    }

    sgcf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_sigio_module);

    if (signo == sgcf->signo) {

        /* STUB: old_cycles */
        c = &ngx_cycle->connections[si.si_fd];

        if (si.si_band & POLL_IN) {
            if (!c->read->active) {
                continue;
            }

            c->read->ready = 1;
            c->read->event_handler(c->read);
        }

        if (si.si_band & POLL_OUT) {
            if (!c->read->active) {
                continue;
            }

            c->read->ready = 1;
            c->read->event_handler(c->read);
        }

    } else if (signo == SIGIO) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "signal queue overflowed: "
                      "SIGIO, fd:%d, band:%d", si.si_fd, si.si_band);

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_sigaction = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sgcf->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigaction queue overflowed: "
                          "SIGIO, fd:%d, band:%d", si.si_fd, si.si_band);
        }

    } else {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      timer ?  "sigtimedwait() returned unexpected signal: %d":
                               "sigwaitinfo() returned unexpected signal: %d",
                      signo);
            return NGX_ERROR;
        }
    }






    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                       "sigio: fd:%d ev:%04X d:" PTR_FMT,
                       c->fd, event_list[i].events, event_list[i].data);

        if (c->read->instance != instance) {

            /*
             * it's a stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                           "sigio: stale event " PTR_FMT, c);
            continue;
        }

        if (event_list[i].events & EPOLLOUT) {
            if (!c->write->active) {
                continue;
            }

            c->write->ready = 1;
            c->write->event_handler(c->write);
        }

        if (event_list[i].events & (EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "sigio_wait() error on fd:%d ev:%d",
                          c->fd, event_list[i].events);
            continue;
        }

        if (event_list[i].events & ~(EPOLLIN|EPOLLOUT)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "sigio_wait() returned strange events on fd:%d ev:%d",
                          c->fd, event_list[i].events);
        }

    }

    if (timer != (ngx_msec_t) -1 && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}


static void *ngx_sigio_create_conf(ngx_cycle_t *cycle)
{
    ngx_sigio_conf_t  *sgcf;

    ngx_test_null(sgcf, ngx_palloc(cycle->pool, sizeof(ngx_sigio_conf_t)),
                  NGX_CONF_ERROR);

    sgcf->events = NGX_CONF_UNSET;

    return epcf;
}


static char *ngx_sigio_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_sigio_conf_t  *sgcf = conf;

    /* LinuxThreads uses the first 3 RT signals */
    ngx_conf_init_unsigned_value(sgcf->signo, SIGRTMIN + 10);

    return NGX_CONF_OK;
}
