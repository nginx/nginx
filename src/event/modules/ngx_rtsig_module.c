
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (TEST_BUILD_RTSIG)

#define F_SETSIG       10
#define SIGRTMIN       33
#define si_fd          __spare__[0]
#define KERN_RTSIGNR   30
#define KERN_RTSIGMAX  31

int sigtimedwait(const sigset_t *set, siginfo_t *info,
                 const struct timespec *timeout)
{
    return -1;
}

int ngx_linux_rtsig_max;

#endif


typedef struct {
    int        signo;
    ngx_int_t  overflow_events;
    ngx_int_t  overflow_test;
    ngx_int_t  overflow_threshold;
} ngx_rtsig_conf_t;


extern ngx_event_module_t  ngx_poll_module_ctx;

static ngx_int_t ngx_rtsig_init(ngx_cycle_t *cycle);
static void ngx_rtsig_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_rtsig_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_rtsig_del_connection(ngx_connection_t *c, u_int flags);
static ngx_int_t ngx_rtsig_process_events(ngx_cycle_t *cycle);
static ngx_int_t ngx_rtsig_process_overflow(ngx_cycle_t *cycle);

static void *ngx_rtsig_create_conf(ngx_cycle_t *cycle);
static char *ngx_rtsig_init_conf(ngx_cycle_t *cycle, void *conf);
static char *ngx_check_ngx_overflow_threshold_bounds(ngx_conf_t *cf,
                                                     void *post, void *data);


static sigset_t        set;
static ngx_uint_t      overflow, overflow_current;
static struct pollfd  *overflow_list;


static ngx_str_t      rtsig_name = ngx_string("rtsig");

static ngx_conf_num_bounds_t  ngx_overflow_threshold_bounds = {
    ngx_check_ngx_overflow_threshold_bounds, 2, 10
};


static ngx_command_t  ngx_rtsig_commands[] = {

    {ngx_string("rtsig_signo"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_rtsig_conf_t, signo),
     NULL},

    {ngx_string("rtsig_overflow_events"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_rtsig_conf_t, overflow_events),
     NULL},

    {ngx_string("rtsig_overflow_test"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_rtsig_conf_t, overflow_test),
     NULL},

    {ngx_string("rtsig_overflow_threshold"),
     NGX_EVENT_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     0,
     offsetof(ngx_rtsig_conf_t, overflow_threshold),
     &ngx_overflow_threshold_bounds},

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
        NULL,                            /* process the changes */
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
    NULL                                   /* init process */
};


static ngx_int_t ngx_rtsig_init(ngx_cycle_t *cycle)
{
    ngx_rtsig_conf_t  *rtscf;

    if (ngx_poll_module_ctx.actions.init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    rtscf = ngx_event_get_conf(cycle->conf_ctx, ngx_rtsig_module);

    sigemptyset(&set);
    sigaddset(&set, rtscf->signo);
    sigaddset(&set, rtscf->signo + 1);
    sigaddset(&set, SIGIO);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigprocmask() failed");
        return NGX_ERROR;
    }

    if (overflow_list) {
        ngx_free(overflow_list);
    }

    overflow_list = ngx_alloc(sizeof(struct pollfd) * rtscf->overflow_events,
                              cycle->log);
    if (overflow_list == NULL) {
        return NGX_ERROR;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_rtsig_module_ctx.actions;

    ngx_event_flags = NGX_USE_RTSIG_EVENT|NGX_HAVE_GREEDY_EVENT;

    return NGX_OK;
}


static void ngx_rtsig_done(ngx_cycle_t *cycle)
{
    ngx_poll_module_ctx.actions.done(cycle);
}


static ngx_int_t ngx_rtsig_add_connection(ngx_connection_t *c)
{
    int                signo;
    ngx_rtsig_conf_t  *rtscf;

    if (c->read->accept && c->read->disabled) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "rtsig enable connection: fd:%d", c->fd);

        if (fcntl(c->fd, F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                          "fcntl(F_SETOWN) failed");
            return NGX_ERROR;
        }

        c->read->active = 1;
        c->read->disabled = 0;
    }

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    signo = rtscf->signo + c->read->instance;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "rtsig add connection: fd:%d signo:%d", c->fd, signo);

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK|O_ASYNC) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETSIG, signo) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETSIG) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETOWN, ngx_pid) == -1) {
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


static ngx_int_t ngx_rtsig_del_connection(ngx_connection_t *c, u_int flags)
{
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "rtsig del connection: fd:%d", c->fd);

    if ((flags & NGX_DISABLE_EVENT) && c->read->accept) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "rtsig disable connection: fd:%d", c->fd);

        c->read->active = 0;
        c->read->disabled = 1;
        return NGX_OK;
    }

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK) failed");
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


ngx_int_t ngx_rtsig_process_events(ngx_cycle_t *cycle)
{
    int                 signo;
    ngx_int_t           instance, i;
    ngx_uint_t          expire;
    size_t              n;
    ngx_msec_t          timer;
    ngx_err_t           err;
    siginfo_t           si;
    ngx_event_t        *rev, *wev;
    struct timeval      tv;
    struct timespec     ts, *tp;
    struct sigaction    sa;
    ngx_epoch_msec_t    delta;
    ngx_connection_t   *c;
    ngx_rtsig_conf_t   *rtscf;

    if (overflow) {
        timer = 0;
        expire = 0;

    } else {
        for ( ;; ) {
            timer = ngx_event_find_timer();

#if (NGX_THREADS)

            if (timer == NGX_TIMER_ERROR) {
                return NGX_ERROR;
            }

            if (timer == NGX_TIMER_INFINITE || timer > 500) {
                timer = 500;
                break;
            }

#endif

            if (timer != 0) {
                break;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "rtsig expired timer");

            ngx_event_expire_timers((ngx_msec_t)
                                    (ngx_elapsed_msec - ngx_old_elapsed_msec));

            if (ngx_posted_events && ngx_threaded) {
                ngx_wakeup_worker_thread(cycle);
            }
        }

        expire = 1;

        if (ngx_accept_mutex) {
            if (ngx_accept_disabled > 0) {
                ngx_accept_disabled--;

            } else {
                ngx_accept_mutex_held = 0;

                if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (ngx_accept_mutex_held == 0
                    && (timer == NGX_TIMER_INFINITE
                        || timer > ngx_accept_mutex_delay))
                {
                    timer = ngx_accept_mutex_delay;
                    expire = 0;
                } 
            }
        }
    }

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;
        expire = 0;

    } else {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
    }

    ngx_old_elapsed_msec = ngx_elapsed_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "rtsig timer: %d", timer);

    /* Linux's sigwaitinfo() is sigtimedwait() with the NULL timeout pointer */

    signo = sigtimedwait(&set, &si, tp);

    if (signo == -1) {
        err = ngx_errno;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err,
                       "rtsig signo:%d", signo);

        if (err == NGX_EAGAIN) {

            if (timer == NGX_TIMER_INFINITE) {
                ngx_accept_mutex_unlock();
                ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                              "sigtimedwait() returned EAGAIN without timeout");
                return NGX_ERROR;
            }

            err = 0;
        }

    } else {
        err = 0;
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "rtsig signo:%d fd:%d band:%X",
                       signo, si.si_fd, si.si_band);
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    delta = ngx_elapsed_msec;
    ngx_elapsed_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000
                                          + tv.tv_usec / 1000 - ngx_start_msec;

    if (err) {
        ngx_accept_mutex_unlock();
        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "sigtimedwait() failed");
        return NGX_ERROR;
    }

    if (timer != NGX_TIMER_INFINITE) {
        delta = ngx_elapsed_msec - delta;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "rtsig timer: %d, delta: %d", timer, (int) delta);
    }

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    if (signo == rtscf->signo || signo == rtscf->signo + 1) {

        if (overflow && (ngx_uint_t) si.si_fd > overflow_current) {
            return NGX_OK;
        }

        /* TODO: old_cycles */

        c = &ngx_cycle->connections[si.si_fd];

        instance = signo - rtscf->signo;

        rev = c->read;

        if (c->read->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_accept_mutex_unlock();

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "rtsig: stale event " PTR_FMT, c);

            return NGX_OK;
        }

        if (si.si_band & (POLLIN|POLLHUP|POLLERR)) {
            if (rev->active) {

                if (ngx_threaded && !rev->accept) {
                    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                        ngx_accept_mutex_unlock();
                        return NGX_ERROR;
                    }

                    rev->posted_ready = 1;
                    ngx_post_event(rev);

                    ngx_mutex_unlock(ngx_posted_events_mutex);

                } else {
                    rev->ready = 1;

                    if (!ngx_threaded && !ngx_accept_mutex_held) {
                        rev->event_handler(rev);

                    } else if (rev->accept) {
                        if (ngx_accept_disabled <= 0) {
                            rev->event_handler(rev);
                        }

                    } else {
                        ngx_post_event(rev); 
                    }
                }
            }
        }

        wev = c->write;

        if (si.si_band & (POLLOUT|POLLHUP|POLLERR)) {
            if (wev->active) {

                if (ngx_threaded) {
                    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
                        ngx_accept_mutex_unlock();
                        return NGX_ERROR;
                    }

                    wev->posted_ready = 1;
                    ngx_post_event(wev);

                    ngx_mutex_unlock(ngx_posted_events_mutex);

                } else {
                    wev->ready = 1;

                    if (!ngx_threaded && !ngx_accept_mutex_held) {
                        wev->event_handler(wev);

                    } else {
                        ngx_post_event(wev);
                    }
                }
            }
        }

    } else if (signo == SIGIO) {
        ngx_accept_mutex_unlock();

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "rt signal queue overflowed");

        /* flush the RT signal queue */

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);

        if (sigaction(rtscf->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(%d, SIG_DFL) failed", rtscf->signo);
        }

        if (sigaction(rtscf->signo + 1, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(%d, SIG_DFL) failed", rtscf->signo + 1);
        }

        overflow = 1;
        overflow_current = 0;
        ngx_event_actions.process_events = ngx_rtsig_process_overflow;

        return NGX_ERROR;

    } else if (signo != -1) {
        ngx_accept_mutex_unlock();

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "sigtimedwait() returned unexpected signal: %d", signo);

        return NGX_ERROR;
    }

    ngx_accept_mutex_unlock();

    if (expire && delta) {
        ngx_event_expire_timers((ngx_msec_t) delta);
    }

    if (ngx_posted_events) {
        if (ngx_threaded) {
            ngx_wakeup_worker_thread(cycle);

        } else {
            ngx_event_process_posted(cycle);
        }
    }

    if (signo == -1) {
        return NGX_AGAIN;
    } else {
        return NGX_OK;
    }
}


/* TODO: old cylces */

static ngx_int_t ngx_rtsig_process_overflow(ngx_cycle_t *cycle)
{
    int                name[2], rtsig_max, rtsig_nr, events, ready;
    size_t             len;
    ngx_int_t          tested, n, i;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;
    ngx_rtsig_conf_t  *rtscf;

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    tested = 0;

    for ( ;; ) {

        n = 0;
        while (n < rtscf->overflow_events) {

            if (overflow_current == cycle->connection_n) {
                break;
            }

            c = &cycle->connections[overflow_current++];

            if (c->fd == -1) {
                continue;
            }

            events = 0;

            if (c->read->active && c->read->event_handler) {
                events |= POLLIN;
            }

            if (c->write->active && c->write->event_handler) {
                events |= POLLOUT;
            }

            if (events == 0) {
                continue;
            }

            overflow_list[n].fd = c->fd;
            overflow_list[n].events = events;
            overflow_list[n].revents = 0;
            n++;
        }

        if (n == 0) {
            break;
        }

        for ( ;; ) {
            ready = poll(overflow_list, n, 0);

            if (ready == -1) {
                err = ngx_errno;
                ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                              cycle->log, 0,
                              "poll() failed while the overflow recover");

                if (err == NGX_EINTR) {
                    continue;
                }
            }

            break;
        }

        if (ready <= 0) {
            continue;
        }

        if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
            return NGX_ERROR;
        }

        for (i = 0; i < n; i++) {
            c = &cycle->connections[overflow_list[i].fd];

            rev = c->read;

            if (rev->active
                && !rev->closed
                && rev->event_handler
                && (overflow_list[i].revents
                                          & (POLLIN|POLLERR|POLLHUP|POLLNVAL)))
            {
                tested++;

                if (ngx_threaded) {
                    rev->posted_ready = 1;
                    ngx_post_event(rev);

                } else {
                    rev->ready = 1;
                    rev->event_handler(rev); 
                }
            }

            wev = c->write;

            if (wev->active
                && !wev->closed
                && wev->event_handler
                && (overflow_list[i].revents
                                         & (POLLOUT|POLLERR|POLLHUP|POLLNVAL)))
            {
                tested++;

                if (ngx_threaded) {
                    wev->posted_ready = 1;
                    ngx_post_event(wev);

                } else {
                    wev->ready = 1;
                    wev->event_handler(wev); 
                }
            }
        }

        ngx_mutex_unlock(ngx_posted_events_mutex);

        if (tested >= rtscf->overflow_test) {

            if (ngx_linux_rtsig_max) {

                /*
                 * Check the current rt queue length to prevent
                 * the new overflow.
                 *
                 * Learn the /proc/sys/kernel/rtsig-max value because
                 * it can be changed sisnce the last checking.
                 */

                name[0] = CTL_KERN;
                name[1] = KERN_RTSIGMAX;
                len = sizeof(rtsig_max);
                if (sysctl(name, sizeof(name), &rtsig_max, &len, NULL, 0) == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, errno,
                                  "sysctl(KERN_RTSIGMAX) failed");
                    return NGX_ERROR;
                }

                name[0] = CTL_KERN;
                name[1] = KERN_RTSIGNR;
                len = sizeof(rtsig_nr);
                if (sysctl(name, sizeof(name), &rtsig_nr, &len, NULL, 0) == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, errno,
                                  "sysctl(KERN_RTSIGNR) failed");
                    return NGX_ERROR;
                }

                /*
                 * drain the rt signal queue if the /proc/sys/kernel/rtsig-nr
                 * is bigger than
                 *    /proc/sys/kernel/rtsig-max / rtsig_overflow_threshold
                 */

                if (rtsig_max / rtscf->overflow_threshold < rtsig_nr) {
                    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "rtsig queue state: %d/%d",
                                   rtsig_nr, rtsig_max);
                    while (ngx_rtsig_process_events(cycle) == NGX_OK) {
                        /* void */
                    }
                }

            } else {

                /*
                 * Linux has not KERN_RTSIGMAX since 2.6.6-mm2
                 * so drain the rt signal queue unconditionally
                 */

                while (ngx_rtsig_process_events(cycle) == NGX_OK) { /* void */ }
            }

            tested = 0;
        }
    }

    if (ngx_posted_events) {
        if (ngx_threaded) {
            ngx_wakeup_worker_thread(cycle);

        } else {
            ngx_event_process_posted(cycle);
        }
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "rt signal queue overflow recovered");

    overflow = 0;
    ngx_event_actions.process_events = ngx_rtsig_process_events;

    return NGX_OK;
}


static void *ngx_rtsig_create_conf(ngx_cycle_t *cycle)
{
    ngx_rtsig_conf_t  *rtscf;

    ngx_test_null(rtscf, ngx_palloc(cycle->pool, sizeof(ngx_rtsig_conf_t)),
                  NGX_CONF_ERROR);

    rtscf->signo = NGX_CONF_UNSET;
    rtscf->overflow_events = NGX_CONF_UNSET;
    rtscf->overflow_test = NGX_CONF_UNSET;
    rtscf->overflow_threshold = NGX_CONF_UNSET;

    return rtscf;
}


static char *ngx_rtsig_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rtsig_conf_t  *rtscf = conf;

    /* LinuxThreads use the first 3 RT signals */
    ngx_conf_init_value(rtscf->signo, SIGRTMIN + 10);

    ngx_conf_init_value(rtscf->overflow_events, 16);
    ngx_conf_init_value(rtscf->overflow_test, 32);
    ngx_conf_init_value(rtscf->overflow_threshold, 10);

    return NGX_CONF_OK;
}


static char *ngx_check_ngx_overflow_threshold_bounds(ngx_conf_t *cf,
                                                     void *post, void *data)
{
    if (ngx_linux_rtsig_max) {
        return ngx_conf_check_num_bounds(cf, post, data);
    }

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"rtsig_overflow_threshold\" is not supported "
                       "since Linux 2.6.6-mm2, ignored");

    return NGX_CONF_OK;
}
