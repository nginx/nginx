

void ngx_posix_master_cycle(ngx_cycle_t *cycle)
{
    static ngx_int_t   sent;
    static ngx_msec_t  delay = 125;

    if (ngx_process == NGX_PROCESS_MASTER) {
        if (sent) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "sent signal cycle");

            if (sigprocmask(SIG_UNBLOCK, &set, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "sigprocmask() failed");
                continue;
            }

            /*
             * there is very big chance that the pending signals
             * would be delivered right on the sigprocmask() return
             */

            if (!ngx_signal) {

                if (delay < 15000) {
                    delay *= 2;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "msleep %d", delay);

                ngx_msleep(delay);

                ngx_gettimeofday(&tv);
                ngx_time_update(tv.tv_sec);

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "wake up");
            }

            if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "sigprocmask() failed");
            }

            ngx_signal = 0;

        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "sigsuspend");

            sigsuspend(&wset);

            ngx_gettimeofday(&tv);
            ngx_time_update(tv.tv_sec);

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "wake up");
        }

    } else { /* NGX_PROCESS_SINGLE */
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "worker cycle");

        ngx_process_events(cycle->log);
    }

    if (ngx_reap) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reap childs");

        live = 0;
        for (i = 0; i < ngx_last_process; i++) {

            ngx_log_debug6(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "child: " PID_T_FMT
                           " s:%d e:%d t:%d d:%d r:%d",
                           ngx_processes[i].pid,
                           ngx_processes[i].signal,
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
                     }

                     continue;
                }

                if (ngx_processes[i].pid == ngx_new_binary) {
                    ngx_new_binary = 0;
                }

                if (i != --ngx_last_process) {
                    ngx_processes[i--] =
                                               ngx_processes[ngx_last_process];
                }

            } else if (!ngx_processes[i].detached
                       && (ngx_terminate || ngx_quit))
            {
                live = 1;

            } else if (ngx_processes[i].exiting) {
                live = 1;
            }
        }

        if (!live) {
            if (ngx_terminate || ngx_quit) {

                if (ngx_inherited && getppid() > 1) {
                    name = ctx->pid.name.data;

                } else {
                    name = ctx->name;
                }

                if (ngx_delete_file(name) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log,
                                  ngx_errno,
                                  ngx_delete_file_n
                                  " \"%s\" failed", name);
                }

                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "exit");
                exit(0);

            } else {
                sent = 0;
            }
        }
    }

    if (ngx_terminate) {
        if (delay > 10000) {
            signo = SIGKILL;
        } else {
            signo = ngx_signal_value(NGX_TERMINATE_SIGNAL);
        }

    } else if (ngx_quit) {
        signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

    } else {

        if (ngx_noaccept) {
            signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
        }

        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ctx->argv);
        }

        if (ngx_reconfigure) {
            signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reconfiguring");
        }

        if (ngx_reopen) {
            /* STUB */
            signo = ngx_signal_value(NGX_SHUTDOWN_SIGNAL);

            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle);
        }
    }

    if (signo) {
        for (i = 0; i < ngx_last_process; i++) {

            if (!ngx_processes[i].detached) {
                ngx_processes[i].signal = signo;

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT,
                               cycle->log, 0,
                               "signal " PID_T_FMT " %d",
                               ngx_processes[i].pid, signo);
            }
        }

        delay = 125;
        signo = 0;
    }

    for (i = 0; i < ngx_last_process; i++) {

        if (ngx_processes[i].signal == 0) {
            continue;
        }

        if (ccf->kqueue_signal != 1) {
            sent = 1;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (" PID_T_FMT ", %d)" ,
                       ngx_processes[i].pid,
                       ngx_processes[i].signal);

        if (kill(ngx_processes[i].pid, ngx_processes[i].signal) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%d, %d) failed",
                          ngx_processes[i].pid, ngx_processes[i].signal);
            continue;
        }

        if (ngx_processes[i].signal != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}
