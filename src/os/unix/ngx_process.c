
#include <ngx_config.h>
#include <ngx_core.h>


static void ngx_exec_proc(ngx_cycle_t *cycle, void *data);

ngx_uint_t     ngx_last_process;
ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
                            ngx_spawn_proc_pt proc, void *data,
                            char *name, ngx_int_t respawn)
{
    sigset_t   set, oset;
    ngx_pid_t  pid;

    if (respawn < 0) {
        sigemptyset(&set);
        sigaddset(&set, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &set, &oset) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigprocmask() failed while spawning %s", name);
            return NGX_ERROR;
        }
    }

    pid = fork();

    if (pid == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
    }

    if (pid == -1 || pid == 0) {
        if (sigprocmask(SIG_SETMASK, &oset, &set) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigprocmask() failed while spawning %s", name);
            return NGX_ERROR;
        }
    }

    switch (pid) {
    case -1:
        return NGX_ERROR;

    case 0:
        ngx_pid = ngx_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "spawn %s: " PID_T_FMT, name, pid);

    if (respawn >= 0) {
        ngx_processes[respawn].pid = pid;
        ngx_processes[respawn].exited = 0;
        return pid;
    }

    ngx_processes[ngx_last_process].pid = pid;
    ngx_processes[ngx_last_process].proc = proc;
    ngx_processes[ngx_last_process].data = data;
    ngx_processes[ngx_last_process].name = name;
    ngx_processes[ngx_last_process].respawn =
                                      (respawn == NGX_PROCESS_RESPAWN) ? 1 : 0;
    ngx_processes[ngx_last_process].detached =
                                     (respawn == NGX_PROCESS_DETACHED) ? 1 : 0;
    ngx_processes[ngx_last_process].exited = 0;
    ngx_processes[ngx_last_process].exiting = 0;
    ngx_last_process++;

    if (sigprocmask(SIG_SETMASK, &oset, &set) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed while spawning %s", name);
        return NGX_ERROR;
    }

    return pid;
}


ngx_pid_t ngx_exec(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_exec_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void ngx_exec_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


#if 0

void ngx_signal_processes(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_last_process; i++) {

        if (ngx_processes[i].signal0 == 0) {
            continue;
        }

#if 0
        if (ngx_processes[i].exited) {
            if (i != --ngx_last_process) {
                ngx_processes[i--] = ngx_processes[ngx_last_process];
            }
            continue;
        }
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (" PID_T_FMT ", %d)" ,
                       ngx_processes[i].pid, ngx_processes[i].signal0);

        if (kill(ngx_processes[i].pid, ngx_processes[i].signal0) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%d, %d) failed",
                          ngx_processes[i].pid, ngx_processes[i].signal0);
            continue;
        }

        if (ngx_processes[i].signal0 != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}

#endif


void ngx_respawn_processes(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    for (i = 0; i < ngx_last_process; i++) {

        if (ngx_processes[i].exiting || !ngx_processes[i].exited) {
            continue;
        }

        if (!ngx_processes[i].respawn) {
            if (i != --ngx_last_process) {
                ngx_processes[i--] = ngx_processes[ngx_last_process];
            }
            continue;
        }

        if (ngx_spawn_process(cycle,
                              ngx_processes[i].proc, ngx_processes[i].data,
                              ngx_processes[i].name, i) == NGX_ERROR)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "can not respawn %s", ngx_processes[i].name);
        }
    }
}


void ngx_process_get_status()
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_uint_t       i, one;
    struct timeval   tv;
    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, errno,
                          "waitpid() failed");
            return;
        }

        one = 1;
        process = "";

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (i == ngx_last_process) {
            process = "unknown process";
        }

        if (WTERMSIG(status)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s " PID_T_FMT " exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");

        } else {
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "%s " PID_T_FMT " exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s " PID_T_FMT
                          " exited with fatal code %d and could not respawn",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }
    }
}
