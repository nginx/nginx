
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);

ngx_uint_t     ngx_last_process;
ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
                            ngx_spawn_proc_pt proc, void *data,
                            char *name, ngx_int_t respawn)
{
    ngx_pid_t  pid;

    pid = fork();

    if (pid == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
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
    ngx_processes[ngx_last_process].exited = 0;
    ngx_processes[ngx_last_process].exiting = 0;

    switch (respawn) {

    case NGX_PROCESS_RESPAWN:
        ngx_processes[ngx_last_process].respawn = 1;
        ngx_processes[ngx_last_process].just_respawn = 0;
        ngx_processes[ngx_last_process].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[ngx_last_process].respawn = 1;
        ngx_processes[ngx_last_process].just_respawn = 1;
        ngx_processes[ngx_last_process].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[ngx_last_process].respawn = 0;
        ngx_processes[ngx_last_process].just_respawn = 0;
        ngx_processes[ngx_last_process].detached = 1;
        break;
    }

    ngx_last_process++;

    return pid;
}


ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
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


        if (ngx_accept_mutex_ptr) {

            /*
             * unlock the accept mutex if the abnormally exited process
             * held it
             */

            ngx_atomic_cmp_set(ngx_accept_mutex_ptr, pid, 0);
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
