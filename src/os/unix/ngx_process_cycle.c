
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
                                       ngx_int_t type);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_childs(ngx_cycle_t *cycle);
static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_channel_handler(ngx_event_t *ev);
#if (NGX_THREADS)
static void ngx_wakeup_worker_threads(ngx_cycle_t *cycle);
static void *ngx_worker_thread_cycle(void *data);
#endif


ngx_uint_t    ngx_process;
ngx_pid_t     ngx_pid;
ngx_uint_t    ngx_threaded;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
ngx_uint_t    ngx_exiting;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


#if (NGX_THREADS)
volatile ngx_thread_t  ngx_threads[NGX_MAX_THREADS];
ngx_int_t              ngx_threads_n;
#endif


u_char  master_process[] = "master process";


void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    sigset_t           set;
    struct timeval     tv;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < ctx->argc; i++) {
        size += ngx_strlen(ctx->argv[i]) + 1;
    }

    title = ngx_palloc(cycle->pool, size);

    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ctx->argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ctx->argv[i], size);
    }

    ngx_setproctitle(title);


    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);

    ngx_new_binary = 0;
    delay = 0;
    live = 1;

    for ( ;; ) {
        if (delay) {
            delay *= 2;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "temination cycle: %d", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        ngx_gettimeofday(&tv);
        ngx_time_update(tv.tv_sec);

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "wake up");

        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap childs");

            live = ngx_reap_childs(cycle);
        }

        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_exit(cycle, ctx);
        }

        if (ngx_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (delay > 1000) {
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (ngx_quit) {
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
            continue;
        }

        if (ngx_timer) {
            ngx_timer = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            if (ngx_new_binary) {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "start new workers");

                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_noaccepting = 0;

                continue;
            }

            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            live = 1;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ctx->argv);
        }

        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }
}


void ngx_single_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_uint_t  i;

#if 0
    ngx_setproctitle("single worker process");
#endif

    ngx_init_temp_number();

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_terminate || ngx_quit) {
            ngx_master_exit(cycle, ctx);
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
                                       ngx_int_t type)
{
    ngx_int_t         i;
    ngx_channel_t     ch;
    struct itimerval  itv;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "start worker processes");

    ch.command = NGX_CMD_OPEN_CHANNEL;

    while (n--) {
        ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL,
                          "worker process", type);

        ch.pid = ngx_processes[ngx_process_slot].pid;
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];

        for (i = 0; i < ngx_last_process; i++) {

            if (i == ngx_process_slot
                || ngx_processes[i].pid == -1
                || ngx_processes[i].channel[0] == -1)
            {
                continue;
            }

            ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "pass channel s:%d pid:" PID_T_FMT
                           " fd:%d to s:%d pid:" PID_T_FMT " fd:%d",
                           ch.slot, ch.pid, ch.fd,
                           i, ngx_processes[i].pid,
                           ngx_processes[i].channel[0]);

            /* TODO: NGX_AGAIN */

            ngx_write_channel(ngx_processes[i].channel[0],
                              &ch, sizeof(ngx_channel_t), cycle->log);
        }
    }

    /*
     * we have to limit the maximum life time of the worker processes
     * by 10 days because our millisecond event timer is limited
     * by 24 days on 32-bit platforms
     */

    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = 10 * 24 * 60 * 60;
    itv.it_value.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "setitimer() failed");
    }
}


static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;


    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d " PID_T_FMT " e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_respawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].just_respawn) {
            ngx_processes[i].just_respawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (ngx_write_channel(ngx_processes[i].channel[0],
                           &ch, sizeof(ngx_channel_t), cycle->log) == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (" PID_T_FMT ", %d)" ,
                       ngx_processes[i].pid, signo);

        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%d, %d) failed",
                          ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


static ngx_uint_t ngx_reap_childs(ngx_cycle_t *cycle)
{
    ngx_int_t      i, n;
    ngx_uint_t     live;
    ngx_channel_t  ch;

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d " PID_T_FMT " e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_respawn);

        if (ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].exited) {

            if (!ngx_processes[i].detached) {
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "pass close channel s:%d pid:" PID_T_FMT
                       " to:" PID_T_FMT, ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            if (ngx_processes[i].respawn
                && !ngx_processes[i].exiting
                && !ngx_terminate
                && !ngx_quit)
            {
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                                                                  == NGX_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "can not respawn %s", ngx_processes[i].name);
                    continue;
                }

                live = 1;

                continue;
            }

            if (ngx_processes[i].pid == ngx_new_binary) {
                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                ngx_processes[i].pid = -1;
            }

        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exit");

    ngx_destroy_pool(cycle->pool);

    exit(0);
}


static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    sigset_t           set;
    ngx_err_t          err;
    ngx_int_t          n;
    ngx_uint_t         i;
    struct timeval     tv;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;
    ngx_connection_t  *c;


    ngx_gettimeofday(&tv);

    ngx_start_msec = (ngx_epoch_msec_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;
    ngx_old_elapsed_msec = 0;
    ngx_elapsed_msec = 0;


    ngx_process = NGX_PROCESS_WORKER;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->group != (gid_t) NGX_CONF_UNSET) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }
    }

    if (ccf->user != (uid_t) NGX_CONF_UNSET) {
        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }

#if (HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    ngx_init_temp_number();

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */ 
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].remain = 0;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < ngx_last_process; n++) {

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() failed");
        }
    }

    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                                             ngx_channel_handler) == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }

    ngx_setproctitle("worker process");

#if (NGX_THREADS)

    if (ngx_time_mutex_init(cycle->log) == NGX_ERROR) {
        /* fatal */
        exit(2);
    }

    if (ngx_threads_n) {
        if (ngx_init_threads(ngx_threads_n,
                                   ccf->thread_stack_size, cycle) == NGX_ERROR)
        {
            /* fatal */
            exit(2);
        }

        err = ngx_thread_key_create(&ngx_core_tls_key);
        if (err != 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          ngx_thread_key_create_n " failed");
            /* fatal */
            exit(2);
        }

        for (n = 0; n < ngx_threads_n; n++) {

            if (!(ngx_threads[n].cv = ngx_cond_init(cycle->log))) {
                /* fatal */
                exit(2);
            }

            if (ngx_create_thread((ngx_tid_t *) &ngx_threads[n].tid,
                                  ngx_worker_thread_cycle,
                                  (void *) &ngx_threads[n], cycle->log) != 0)
            {
                /* fatal */
                exit(2);
            }
        }
    }

#endif

    for ( ;; ) {
        if (ngx_exiting
            && ngx_event_timer_rbtree == &ngx_event_timer_sentinel)
        {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");


#if (NGX_THREADS)
            ngx_terminate = 1;

            ngx_wakeup_worker_threads(cycle);
#endif

            /*
             * we do not destroy cycle->pool here because a signal handler
             * that uses cycle->log can be called at this point
             */
            exit(0);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");

#if (NGX_THREADS)
            ngx_wakeup_worker_threads(cycle);
#endif

            /*
             * we do not destroy cycle->pool here because a signal handler
             * that uses cycle->log can be called at this point
             */
            exit(0);
        }

        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                ngx_close_listening_sockets(cycle);
                ngx_exiting = 1;
            }
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopen logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}


static void ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %d", n);

    if (n <= 0) {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "channel command: %d", ch.command);

    switch (ch.command) {

    case NGX_CMD_QUIT:
        ngx_quit = 1;
        break;

    case NGX_CMD_TERMINATE:
        ngx_terminate = 1;
        break;

    case NGX_CMD_REOPEN:
        ngx_reopen = 1;
        break;

    case NGX_CMD_OPEN_CHANNEL:

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "get channel s:%d pid:" PID_T_FMT " fd:%d",
                       ch.slot, ch.pid, ch.fd);

        ngx_processes[ch.slot].pid = ch.pid;
        ngx_processes[ch.slot].channel[0] = ch.fd;
        break;

    case NGX_CMD_CLOSE_CHANNEL:

        ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "close channel s:%d pid:" PID_T_FMT " our:" PID_T_FMT
                       " fd:%d",
                       ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                       ngx_processes[ch.slot].channel[0]);

        if (close(ngx_processes[ch.slot].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "close() failed");
        }

        ngx_processes[ch.slot].channel[0] = -1;
        break;
    }
}


#if (NGX_THREADS)

static void ngx_wakeup_worker_threads(ngx_cycle_t *cycle)
{
    ngx_int_t   i;
    ngx_uint_t  live;

    for ( ;; ) {

        live = 0;

        for (i = 0; i < ngx_threads_n; i++) {
            if (ngx_threads[i].state < NGX_THREAD_EXIT) {
                ngx_cond_signal(ngx_threads[i].cv);

                if (ngx_threads[i].cv->tid == (ngx_tid_t) -1) {
                    ngx_threads[i].state = NGX_THREAD_DONE;
                } else {
                    live = 1;
                }
            }

            if (ngx_threads[i].state == NGX_THREAD_EXIT) {
                ngx_thread_join(ngx_threads[i].tid, NULL);
                ngx_threads[i].state = NGX_THREAD_DONE;
            }
        }

        if (live == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "all worker threads are joined");

            /* STUB */
            ngx_done_events(cycle);
            ngx_mutex_destroy(ngx_event_timer_mutex);
            ngx_mutex_destroy(ngx_posted_events_mutex);

            return;
        }

        ngx_sched_yield();
    }
}


static void* ngx_worker_thread_cycle(void *data)
{
    ngx_thread_t  *thr = data;

    sigset_t          set;
    ngx_err_t         err;
    ngx_core_tls_t   *tls;
    ngx_cycle_t      *cycle;
    struct timeval    tv;

    thr->cv->tid = ngx_thread_self();

    cycle = (ngx_cycle_t *) ngx_cycle;

    sigemptyset(&set);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    err = ngx_thread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_sigmask_n " failed");
        return (void *) 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "thread " TID_T_FMT " started", ngx_thread_self());

    ngx_setthrtitle("worker thread");

    if (!(tls = ngx_calloc(sizeof(ngx_core_tls_t), cycle->log))) {
        return (void *) 1;
    }

    err = ngx_thread_set_tls(ngx_core_tls_key, tls);
    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_set_tls_n " failed");
        return (void *) 1;
    }

    if (ngx_mutex_lock(ngx_posted_events_mutex) == NGX_ERROR) {
        return (void *) 1;
    }

    for ( ;; ) {
        thr->state = NGX_THREAD_FREE;

        if (ngx_cond_wait(thr->cv, ngx_posted_events_mutex) == NGX_ERROR) {
            return (void *) 1;
        }

        if (ngx_terminate) {
            thr->state = NGX_THREAD_EXIT;

            ngx_mutex_unlock(ngx_posted_events_mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "thread %d is done", ngx_thread_self());

            return (void *) 0;
        }

        thr->state = NGX_THREAD_BUSY;

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (void *) 1;
        }

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (void *) 1;
        }

        if (ngx_process_changes) {
            if (ngx_process_changes(cycle, 1) == NGX_ERROR) {
                return (void *) 1;
            }
        }
    }
}

#endif
