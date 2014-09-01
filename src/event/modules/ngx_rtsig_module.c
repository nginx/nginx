
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_RTSIG)

#if (NGX_DARWIN)

#define SIGRTMIN       33
#define si_fd          __pad[0]

#else

#ifdef  SIGRTMIN
#define si_fd          _reason.__spare__.__spare2__[0]
#else
#define SIGRTMIN       33
#define si_fd          __spare__[0]
#endif

#endif

#define F_SETSIG       10
#define KERN_RTSIGNR   30
#define KERN_RTSIGMAX  31

int sigtimedwait(const sigset_t *set, siginfo_t *info,
                 const struct timespec *timeout);

int sigtimedwait(const sigset_t *set, siginfo_t *info,
                 const struct timespec *timeout)
{
    return -1;
}

int ngx_linux_rtsig_max;

#endif


typedef struct {
    ngx_uint_t  signo;
    ngx_uint_t  overflow_events;
    ngx_uint_t  overflow_test;
    ngx_uint_t  overflow_threshold;
} ngx_rtsig_conf_t;


extern ngx_event_module_t  ngx_poll_module_ctx;

static ngx_int_t ngx_rtsig_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_rtsig_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_rtsig_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_rtsig_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_rtsig_process_events(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags);
static ngx_int_t ngx_rtsig_process_overflow(ngx_cycle_t *cycle,
    ngx_msec_t timer, ngx_uint_t flags);

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

    { ngx_string("rtsig_signo"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_rtsig_conf_t, signo),
      NULL },

    { ngx_string("rtsig_overflow_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_rtsig_conf_t, overflow_events),
      NULL },

    { ngx_string("rtsig_overflow_test"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_rtsig_conf_t, overflow_test),
      NULL },

    { ngx_string("rtsig_overflow_threshold"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_rtsig_conf_t, overflow_threshold),
      &ngx_overflow_threshold_bounds },

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
    NGX_MODULE_V1,
    &ngx_rtsig_module_ctx,               /* module context */
    ngx_rtsig_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtsig_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_rtsig_conf_t  *rtscf;

    rtscf = ngx_event_get_conf(cycle->conf_ctx, ngx_rtsig_module);

    sigemptyset(&set);
    sigaddset(&set, (int) rtscf->signo);
    sigaddset(&set, (int) rtscf->signo + 1);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGALRM);

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

    ngx_event_flags = NGX_USE_RTSIG_EVENT
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_FD_EVENT;

    return NGX_OK;
}


static void
ngx_rtsig_done(ngx_cycle_t *cycle)
{
    ngx_free(overflow_list);

    overflow_list = NULL;
}


static ngx_int_t
ngx_rtsig_add_connection(ngx_connection_t *c)
{
    ngx_uint_t         signo;
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
                   "rtsig add connection: fd:%d signo:%ui", c->fd, signo);

    if (fcntl(c->fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(O_RDWR|O_NONBLOCK|O_ASYNC) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETSIG, (int) signo) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETSIG) failed");
        return NGX_ERROR;
    }

    if (fcntl(c->fd, F_SETOWN, ngx_pid) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "fcntl(F_SETOWN) failed");
        return NGX_ERROR;
    }

#if (NGX_HAVE_ONESIGFD)
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


static ngx_int_t
ngx_rtsig_del_connection(ngx_connection_t *c, ngx_uint_t flags)
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


static ngx_int_t
ngx_rtsig_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                 signo;
    ngx_int_t           instance;
    ngx_err_t           err;
    siginfo_t           si;
    ngx_event_t        *rev, *wev;
    ngx_queue_t        *queue;
    struct timespec     ts, *tp;
    struct sigaction    sa;
    ngx_connection_t   *c;
    ngx_rtsig_conf_t   *rtscf;

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;

    } else {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "rtsig timer: %M", timer);

    /* Linux's sigwaitinfo() is sigtimedwait() with the NULL timeout pointer */

    signo = sigtimedwait(&set, &si, tp);

    if (signo == -1) {
        err = ngx_errno;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err,
                       "rtsig signo:%d", signo);

        if (flags & NGX_UPDATE_TIME) {
            ngx_time_update();
        }

        if (err == NGX_EAGAIN) {

            /* timeout */

            if (timer != NGX_TIMER_INFINITE) {
                return NGX_AGAIN;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "sigtimedwait() returned EAGAIN without timeout");
            return NGX_ERROR;
        }

        ngx_log_error((err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT,
                      cycle->log, err, "sigtimedwait() failed");
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "rtsig signo:%d fd:%d band:%04Xd",
                   signo, si.si_fd, si.si_band);

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    if (signo == (int) rtscf->signo || signo == (int) rtscf->signo + 1) {

        if (overflow && (ngx_uint_t) si.si_fd > overflow_current) {
            return NGX_OK;
        }

        c = ngx_cycle->files[si.si_fd];

        if (c == NULL) {

            /* the stale event */

            return NGX_OK;
        }

        instance = signo - (int) rtscf->signo;

        rev = c->read;

        if (rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "rtsig: stale event %p", c);

            return NGX_OK;
        }

        if ((si.si_band & (POLLIN|POLLHUP|POLLERR)) && rev->active) {

            rev->ready = 1;

            if (flags & NGX_POST_EVENTS) {
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;

                ngx_post_event(rev, queue);

            } else {
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((si.si_band & (POLLOUT|POLLHUP|POLLERR)) && wev->active) {

            wev->ready = 1;

            if (flags & NGX_POST_EVENTS) {
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                wev->handler(wev);
            }
        }

        return NGX_OK;

    } else if (signo == SIGALRM) {

        ngx_time_update();

        return NGX_OK;

    } else if (signo == SIGIO) {

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

    }

    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                  "sigtimedwait() returned unexpected signal: %d", signo);

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtsig_process_overflow(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
    int                name[2], rtsig_max, rtsig_nr, events, ready;
    size_t             len;
    ngx_err_t          err;
    ngx_uint_t         tested, n, i;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;
    ngx_rtsig_conf_t  *rtscf;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "rtsig process overflow");

    rtscf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_rtsig_module);

    tested = 0;

    for ( ;; ) {

        n = 0;
        while (n < rtscf->overflow_events) {

            if (overflow_current == cycle->connection_n) {
                break;
            }

            c = cycle->files[overflow_current++];

            if (c == NULL || c->fd == -1) {
                continue;
            }

            events = 0;

            if (c->read->active && c->read->handler) {
                events |= POLLIN;
            }

            if (c->write->active && c->write->handler) {
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

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "rtsig overflow poll:%d", ready);

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

        for (i = 0; i < n; i++) {
            c = cycle->files[overflow_list[i].fd];

            if (c == NULL) {
                continue;
            }

            rev = c->read;

            if (rev->active
                && !rev->closed
                && rev->handler
                && (overflow_list[i].revents
                                          & (POLLIN|POLLERR|POLLHUP|POLLNVAL)))
            {
                tested++;

                rev->ready = 1;

                if (flags & NGX_POST_EVENTS) {
                    queue = rev->accept ? &ngx_posted_accept_events
                                        : &ngx_posted_events;

                    ngx_post_event(rev, queue);

                } else {
                    rev->handler(rev);
                }
            }

            wev = c->write;

            if (wev->active
                && !wev->closed
                && wev->handler
                && (overflow_list[i].revents
                                         & (POLLOUT|POLLERR|POLLHUP|POLLNVAL)))
            {
                tested++;

                wev->ready = 1;

                if (flags & NGX_POST_EVENTS) {
                    ngx_post_event(wev, &ngx_posted_events);

                } else {
                    wev->handler(wev);
                }
            }
        }

        if (tested >= rtscf->overflow_test) {

            if (ngx_linux_rtsig_max) {

                /*
                 * Check the current rt queue length to prevent
                 * the new overflow.
                 *
                 * learn the "/proc/sys/kernel/rtsig-max" value because
                 * it can be changed since the last checking
                 */

                name[0] = CTL_KERN;
                name[1] = KERN_RTSIGMAX;
                len = sizeof(rtsig_max);

                if (sysctl(name, 2, &rtsig_max, &len, NULL, 0) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, errno,
                                  "sysctl(KERN_RTSIGMAX) failed");
                    return NGX_ERROR;
                }

                /* name[0] = CTL_KERN; */
                name[1] = KERN_RTSIGNR;
                len = sizeof(rtsig_nr);

                if (sysctl(name, 2, &rtsig_nr, &len, NULL, 0) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, errno,
                                  "sysctl(KERN_RTSIGNR) failed");
                    return NGX_ERROR;
                }

                /*
                 * drain the rt signal queue if the /"proc/sys/kernel/rtsig-nr"
                 * is bigger than
                 *    "/proc/sys/kernel/rtsig-max" / "rtsig_overflow_threshold"
                 */

                if (rtsig_max / (int) rtscf->overflow_threshold < rtsig_nr) {
                    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "rtsig queue state: %d/%d",
                                   rtsig_nr, rtsig_max);
                    while (ngx_rtsig_process_events(cycle, 0, flags) == NGX_OK)
                    {
                        /* void */
                    }
                }

            } else {

                /*
                 * Linux has not KERN_RTSIGMAX since 2.6.6-mm2
                 * so drain the rt signal queue unconditionally
                 */

                while (ngx_rtsig_process_events(cycle, 0, flags) == NGX_OK) {
                    /* void */
                }
            }

            tested = 0;
        }
    }

    if (flags & NGX_UPDATE_TIME) {
        ngx_time_update();
    }

    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                  "rt signal queue overflow recovered");

    overflow = 0;
    ngx_event_actions.process_events = ngx_rtsig_process_events;

    return NGX_OK;
}


static void *
ngx_rtsig_create_conf(ngx_cycle_t *cycle)
{
    ngx_rtsig_conf_t  *rtscf;

    rtscf = ngx_palloc(cycle->pool, sizeof(ngx_rtsig_conf_t));
    if (rtscf == NULL) {
        return NULL;
    }

    rtscf->signo = NGX_CONF_UNSET;
    rtscf->overflow_events = NGX_CONF_UNSET;
    rtscf->overflow_test = NGX_CONF_UNSET;
    rtscf->overflow_threshold = NGX_CONF_UNSET;

    return rtscf;
}


static char *
ngx_rtsig_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_rtsig_conf_t  *rtscf = conf;

    /* LinuxThreads use the first 3 RT signals */
    ngx_conf_init_uint_value(rtscf->signo, SIGRTMIN + 10);

    ngx_conf_init_uint_value(rtscf->overflow_events, 16);
    ngx_conf_init_uint_value(rtscf->overflow_test, 32);
    ngx_conf_init_uint_value(rtscf->overflow_threshold, 10);

    return NGX_CONF_OK;
}


static char *
ngx_check_ngx_overflow_threshold_bounds(ngx_conf_t *cf, void *post, void *data)
{
    if (ngx_linux_rtsig_max) {
        return ngx_conf_check_num_bounds(cf, post, data);
    }

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"rtsig_overflow_threshold\" is not supported "
                       "since Linux 2.6.6-mm2, ignored");

    return NGX_CONF_OK;
}
