
/*
 * Copyright (C) 2002-2004 Igor Sysoev, http://sysoev.ru/en/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (TEST_BUILD_RTSIG)

#define F_SETSIG  10
#define SIGRTMIN  33
#define si_fd     __spare__[0]

int sigtimedwait(const sigset_t *set, siginfo_t *info,
                 const struct timespec *timeout);


int sigtimedwait(const sigset_t *set, siginfo_t *info,
                 const struct timespec *timeout)
{
    return -1;
}

#endif


typedef struct {
    int  signo;
} ngx_rtsig_conf_t;


extern ngx_event_module_t  ngx_poll_module_ctx;

static int ngx_rtsig_init(ngx_cycle_t *cycle);
static void ngx_rtsig_done(ngx_cycle_t *cycle);
static int ngx_rtsig_add_connection(ngx_connection_t *c);
static int ngx_rtsig_del_connection(ngx_connection_t *c, u_int flags);
static int ngx_rtsig_process_events(ngx_log_t *log);
static int ngx_rtsig_process_overflow(ngx_log_t *log);

static void *ngx_rtsig_create_conf(ngx_cycle_t *cycle);
static char *ngx_rtsig_init_conf(ngx_cycle_t *cycle, void *conf);


static sigset_t  set;


static ngx_str_t      rtsig_name = ngx_string("rtsig");

static ngx_command_t  ngx_rtsig_commands[] = {

    {ngx_string("rtsig_signo"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_rtsig_conf_t, signo),
     NULL},

    ngx_null_command
};


ngx_event_module_t  ngx_rtsig_module_ctx = {
    &rtsig_name,
    ngx_rtsig_create_conf,               /* create configuration */
    ngx_rtsig_init_conf,                 /* init configuration */

    {
        NULL,                            /* add an event */
        NULL,                            /* delete an event */
        NULL,                            /* enable an event */
        NULL,                            /* disable an event */
        ngx_rtsig_add_connection,        /* add an connection */
        ngx_rtsig_del_connection,        /* delete an connection */
        ngx_rtsig_process_events,        /* process the events */
        ngx_rtsig_init,                  /* init the events */
        ngx_rtsig_done,                  /* done the events */
    }

};

ngx_module_t  ngx_rtsig_module = {
    NGX_MODULE,
    &ngx_rtsig_module_ctx,               /* module context */
    ngx_rtsig_commands,                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static int ngx_rtsig_init(ngx_cycle_t *cycle)
{
    ngx_rtsig_conf_t  *rtscf;

    if (ngx_poll_module_ctx.actions.init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    rtscf = ngx_event_get_conf(cycle->conf_ctx, ngx_rtsig_module);

    sigemptyset(&set);
    sigaddset(&set, rtscf->signo);
    sigaddset(&set, SIGIO);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigprocmask() failed");
        return NGX_ERROR;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_rtsig_module_ctx.actions;

    ngx_event_flags = NGX_USE_SIGIO_EVENT;

    return NGX_OK;
}


static void ngx_rtsig_done(ngx_cycle_t *cycle)
{
    ngx_poll_module_ctx.actions.done(cycle);
}


static int ngx_rtsig_add_connection(ngx_connection_t *c)
{
    ngx_rtsig_conf_t  *rtscf;

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "rtsig add connection: fd:%d signo:%d", c->fd, rtscf->signo);

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK|O_ASYNC) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETSIG, rtscf->signo) == -1) {
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


static int ngx_rtsig_del_connection(ngx_connection_t *c, u_int flags)
{
    if (!(flags & NGX_CLOSE_EVENT)) {
        if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                          "fcntl(O_RDWR|O_NONBLOCK) failed");
            return NGX_ERROR;
        }
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


int ngx_rtsig_process_events(ngx_log_t *log)
{
    int                 signo;
    ngx_int_t           instance, i;
    size_t              n;
    ngx_msec_t          timer;
    ngx_err_t           err;
    ngx_cycle_t       **cycle;
    siginfo_t           si;
    struct timeval      tv;
    struct timespec     ts, *tp;
    struct sigaction    sa;
    ngx_connection_t   *c;
    ngx_epoch_msec_t    delta;
    ngx_rtsig_conf_t   *rtscf;

    timer = ngx_event_find_timer();
    ngx_old_elapsed_msec = ngx_elapsed_msec;

    if (timer) {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;

    } else {
        tp = NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0, "rtsig timer: %d", timer);

    /* Linux sigwaitinfo() is sigtimedwait() with the NULL timeout pointer */

    signo = sigtimedwait(&set, &si, tp);

    if (signo == -1) {
        err = ngx_errno;
    } else {
        err = 0;
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000 - ngx_start_msec;

    if (err) {
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      log, err, "sigtimedwait() failed");
        return NGX_ERROR;
    }

    if (timer) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
                       "rtsig timer: %d, delta: %d", timer, (int) delta);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                   "signo:%d fd:%d band:%X", signo, si.si_fd, si.si_band);

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    if (signo == rtscf->signo) {

        /* TODO: old_cycles */
        c = &ngx_cycle->connections[si.si_fd];

        /* TODO: stale signals */

        if (si.si_band & (POLLIN|POLLHUP|POLLERR)) {
            if (c->read->active) {
                c->read->ready = 1;
                c->read->event_handler(c->read);
            }
        }

        if (si.si_band & (POLLOUT|POLLHUP|POLLERR)) {
            if (c->write->active) {
                c->write->ready = 1;
                c->write->event_handler(c->write);
            }
        }

    } else if (signo == SIGIO) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "signal queue overflowed: "
                      "SIGIO, fd:%d, band:%X", si.si_fd, si.si_band);

        /* TODO: flush all the used RT signals */

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        if (sigaction(rtscf->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigaction(%d, SIG_DFL) failed", rtscf->signo);
        }

        ngx_event_actions = ngx_poll_module_ctx.actions;
        ngx_event_actions.process = ngx_rtsig_process_overflow;
        ngx_event_flags = NGX_OVERFLOW_EVENT
                          |NGX_USE_LEVEL_EVENT|NGX_USE_ONESHOT_EVENT;

        /* STUB: add events. WHAT to do with fcntl()s ? */


    } else {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "sigtimedwait() returned unexpected signal: %d", signo);
        return NGX_ERROR;
    }

    if (timer != (ngx_msec_t) -1 && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    return NGX_OK;
}


static int ngx_rtsig_process_overflow(ngx_log_t *log)
{
    if (ngx_poll_module_ctx.actions.process(log) == NGX_OK) {
        ngx_event_actions = ngx_rtsig_module_ctx.actions;
        ngx_event_flags = NGX_USE_SIGIO_EVENT;
    }

    return NGX_OK;
}


static void *ngx_rtsig_create_conf(ngx_cycle_t *cycle)
{
    ngx_rtsig_conf_t  *rtscf;

    ngx_test_null(rtscf, ngx_palloc(cycle->pool, sizeof(ngx_rtsig_conf_t)),
                  NGX_CONF_ERROR);

    rtscf->signo = NGX_CONF_UNSET;

    return rtscf;
}


static char *ngx_rtsig_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rtsig_conf_t  *rtscf = conf;

    /* LinuxThreads use the first 3 RT signals */
    ngx_conf_init_value(rtscf->signo, SIGRTMIN + 10);

    return NGX_CONF_OK;
}
