
#include <ngx_config.h>
#include <ngx_core.h>


void testone(ngx_log_t *log)
{
    ngx_log_debug(log, "child process");
    ngx_msleep(5000);
    exit(0);
}


int ngx_spawn_process(ngx_log_t *log)
{
    pid_t     pid;
    sigset_t  set, oset; 

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &set, &oset) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "sigprocmask() failed");
    }

    pid = fork();

    if (pid == -1 || pid == 0) {
        if (sigprocmask(SIG_SETMASK, &oset, &set) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigprocmask() failed");
        }
    }

    switch (pid) {
    case -1:
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "fork() failed");
        return NGX_ERROR;

    case 0:
        testone(log);
        break;

    default:
    }

ngx_log_debug(log, "parent process, child: " PID_FMT _ pid);

    /* book keeping */

    if (sigprocmask(SIG_SETMASK, &oset, &set) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "sigprocmask() failed");
    }

    return NGX_OK;
}


void ngx_sigchld_handler(int signo)
{
    int             status, one;
    pid_t           pid;
    ngx_err_t       err;
    struct timeval  tv;

    ngx_gettimeofday(&tv);

    if (ngx_cached_time != tv.tv_sec) {
        ngx_cached_time = tv.tv_sec;
        ngx_time_update();
    }

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

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "process " PID_FMT " exited with code %d", pid, status);

        /* TODO: restart handler */

#if 0
        ngx_msleep(2000);
#endif

#if 0
        ngx_spawn_process(ngx_cycle->log);
#endif
    }
}
