
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
#if (NGX_THREADS)
static int ngx_worker_thread_cycle(void *data);
#endif


ngx_int_t     ngx_process;
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_new_binary;
ngx_int_t     ngx_inherited;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_timer;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
sig_atomic_t  ngx_noaccept;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;
sig_atomic_t  ngx_change_binary;


/* TODO: broken NGX_PROCESS_SINGLE */

void ngx_master_process_cycle(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    int                signo;
    sigset_t           set;
    struct timeval     tv;
    struct itimerval   itv;
    ngx_uint_t         i, live;
    ngx_msec_t         delay;
    ngx_core_conf_t   *ccf;

    if (ngx_process == NGX_PROCESS_MASTER) {
        sigemptyset(&set);
        sigaddset(&set, SIGCHLD);
        sigaddset(&set, SIGALRM);
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
    }

    ngx_setproctitle("master process");

    ngx_new_binary = 0;
    delay = 0;
    signo = 0;
    live = 0;

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "new cycle");

        ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                               ngx_core_module);

        if (ccf->worker_processes == NGX_CONF_UNSET) {
            ccf->worker_processes = 1;
        }

        if (ngx_process == NGX_PROCESS_MASTER) {
            for (i = 0; i < (ngx_uint_t) ccf->worker_processes; i++) {
                ngx_spawn_process(cycle, ngx_worker_process_cycle, NULL,
                                  "worker process", NGX_PROCESS_RESPAWN);
            }

            /*
             * we have to limit the maximum life time of the worker processes
             * by 1 month because our millisecond event timer is limited
             * by 49 days on 32-bit platforms
             */

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = 30 * 24 * 60 * 60;
            itv.it_value.tv_usec = 0;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }

            live = 1;

        } else {
            ngx_init_temp_number();

            for (i = 0; ngx_modules[i]; i++) {
                if (ngx_modules[i]->init_process) {
                    if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {
                        /* fatal */
                        exit(2);
                    }
                }
            }
        }


        /* a cycle with the same configuration because a new one is invalid */

        for ( ;; ) {

            /* an event loop */

            for ( ;; ) {

                if (ngx_process == NGX_PROCESS_MASTER) {
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

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "sigsuspend");

                    sigsuspend(&set);

                    ngx_gettimeofday(&tv);
                    ngx_time_update(tv.tv_sec);

                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "wake up");

                } else { /* NGX_PROCESS_SINGLE */
                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "worker cycle");

                    ngx_process_events(cycle);
                    live = 0;
                }

                if (ngx_reap) {
                    ngx_reap = 0;
                    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                   "reap childs");

                    live = 0;
                    for (i = 0; i < ngx_last_process; i++) {

                        ngx_log_debug5(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                                       "child: " PID_T_FMT
                                       " e:%d t:%d d:%d r:%d",
                                       ngx_processes[i].pid,
                                       ngx_processes[i].exiting,
                                       ngx_processes[i].exited,
                                       ngx_processes[i].detached,
                                       ngx_processes[i].respawn);

                        if (ngx_processes[i].exited) {

                            if (ngx_processes[i].respawn
                                && !ngx_processes[i].exiting
                                && !ngx_terminate
                                && !ngx_quit)
                            {
                                 if (ngx_spawn_process(cycle,
                                                       ngx_processes[i].proc,
                                                       ngx_processes[i].data,
                                                       ngx_processes[i].name, i)
                                                                  == NGX_ERROR)
                                 {
                                     ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                                   "can not respawn %s",
                                                   ngx_processes[i].name);
                                     continue;
                                 }

                                 live = 1;

                                 continue;
                            }

                            if (ngx_processes[i].pid == ngx_new_binary) {
                                ngx_new_binary = 0;

                                /* TODO: if (ngx_noaccept) ngx_configure = 1 */
                            }

                            if (i != --ngx_last_process) {
                                ngx_processes[i--] =
                                               ngx_processes[ngx_last_process];
                            }

                        } else if (ngx_processes[i].exiting
                                   || !ngx_processes[i].detached)
                        {
                            live = 1;
                        }
                    }
                }

                if (!live && (ngx_terminate || ngx_quit)) {
                    ngx_master_exit(cycle, ctx);
                }

                if (ngx_terminate) {
                    if (delay == 0) {
                        delay = 50;
                    }

                    if (delay > 1000) {
                        signo = SIGKILL;
                    } else {
                        signo = ngx_signal_value(NGX_TERMINATE_SIGNAL);
                    }

                } else if (ngx_quit) {
                    signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

                } else if (ngx_timer) {
                    signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

                } else {

                    if (ngx_noaccept) {
                        signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
                    }

                    if (ngx_change_binary) {
                        ngx_change_binary = 0;
                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "changing binary");
                        ngx_new_binary = ngx_exec_new_binary(cycle, ctx->argv);
                    }

                    if (ngx_reconfigure) {
                        signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "reconfiguring");
                    }

                    if (ngx_reopen) {
                        if (ngx_process == NGX_PROCESS_MASTER) {
                            signo = ngx_signal_value(NGX_REOPEN_SIGNAL);
                            ngx_reopen = 0;

                        } else { /* NGX_PROCESS_SINGLE */
                            ngx_reopen = 0;
                        }

                        ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                                      "reopening logs");
                        ngx_reopen_files(cycle, ccf->user);
                    }
                }

                if (signo) {
                    for (i = 0; i < ngx_last_process; i++) {

                        if (ngx_processes[i].detached) {
                            continue;
                        }

                        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                       "kill (" PID_T_FMT ", %d)" ,
                                       ngx_processes[i].pid, signo);

                        if (kill(ngx_processes[i].pid, signo) == -1) {
                            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                          "kill(%d, %d) failed",
                                          ngx_processes[i].pid, signo);
                            continue;
                        }

                        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                            ngx_processes[i].exiting = 1;
                        }
                    }

                    signo = 0;
                }

                if (ngx_reopen || ngx_reconfigure || ngx_timer) {
                    break;
                }
            }

            if (ngx_reopen) {
                ngx_reopen = 0;

            } else if (ngx_timer) {
                ngx_timer = 0;

            } else if (ngx_noaccept) {
                ngx_noaccept = 0;
                ngx_reconfigure = 0;

            } else {
                cycle = ngx_init_cycle(cycle);
                if (cycle == NULL) {
                    cycle = (ngx_cycle_t *) ngx_cycle;
                    continue;
                }

                ngx_cycle = cycle;
                ngx_reconfigure = 0;
            }

            break;
        }
    }
}


static void ngx_master_exit(ngx_cycle_t *cycle, ngx_master_ctx_t *ctx)
{
    u_char  *name;

    if (ngx_inherited && getppid() > 1) {
        name = ctx->pid.name.data;

    } else {
        name = ctx->name;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exit");
    exit(0);
}


static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    sigset_t          set;
    ngx_uint_t        i;
    ngx_listening_t  *ls;
    ngx_core_conf_t  *ccf;
#if (NGX_THREADS)
    ngx_tid_t         tid;
#endif

    ngx_process = NGX_PROCESS_WORKER;
    ngx_last_process = 0;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->group != (gid_t) NGX_CONF_UNSET) {
        if (setuid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }
    }

    if (ccf->user != (uid_t) NGX_CONF_UNSET && geteuid() == 0) {
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

    ngx_setproctitle("worker process");

#if (NGX_THREADS)

    if (ngx_init_threads(5, 128 * 1024 * 1024, cycle) == NGX_ERROR) {
        /* fatal */
        exit(2);
    }

    for (i = 0; i < 1; i++) {
        if (ngx_create_thread(&tid, ngx_worker_thread_cycle,
                              cycle, cycle->log) != 0)
        {
            /* fatal */
            exit(2);
        }
    }

#endif

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_quit) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");
            break;
        }

        if (ngx_reopen) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopen logs");
            ngx_reopen_files(cycle, -1);
            ngx_reopen = 0;
        }
    }

    ngx_close_listening_sockets(cycle);

    for ( ;; ) {
        if (ngx_event_timer_rbtree == &ngx_event_timer_sentinel) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exiting");
            exit(0);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events(cycle);

        if (ngx_reopen) {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopen logs");
            ngx_reopen_files(cycle, -1);
            ngx_reopen = 0;
        }
    }
}


#if (NGX_THREADS)

int ngx_worker_thread_cycle(void *data)
{
    ngx_cycle_t *cycle = data;

    ngx_err_t       err;
    sigset_t        set;
    struct timeval  tv;

    sigfillset(&set);
    sigdelset(&set, SIGALRM);
    sigdelset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigdelset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

    err = ngx_thread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_sigmask_n " failed");
        return 1;
    }


    /* STUB */

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, ngx_errno,
                   "thread %d started", ngx_thread_self());

    ngx_setproctitle("worker thread");

    sleep(5);

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, ngx_errno,
                   "thread %d done", ngx_thread_self());

    return 1;
}

#endif
