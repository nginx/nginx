
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;
int  ngx_inherited_nonblocking;


void ngx_restart_signal_handler(int signo);
void ngx_rotate_signal_handler(int signo);


int ngx_posix_init(ngx_log_t *log)
{
    struct sigaction sa;
    struct rlimit  rlmt;

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "sigaction(SIGPIPE, SIG_IGN) failed");
        return NGX_ERROR;
    }

    sa.sa_handler = ngx_restart_signal_handler;
    if (sigaction(ngx_signal_value(NGX_RESTART_SIGNAL), &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "sigaction(SIG" ngx_value(NGX_RESTART_SIGNAL) ") failed");
        return NGX_ERROR;
    }

    sa.sa_handler = ngx_rotate_signal_handler;
    if (sigaction(ngx_signal_value(NGX_ROTATE_SIGNAL), &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "sigaction(SIG" ngx_value(NGX_ROTATE_SIGNAL) ") failed");
        return NGX_ERROR;
    }


    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed)");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %qd:%qd",
                  rlmt.rlim_cur, rlmt.rlim_max);

    ngx_max_sockets = rlmt.rlim_cur;

#if (HAVE_INHERITED_NONBLOCK)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    return NGX_OK;
}


void ngx_restart_signal_handler(int signo)
{
    restart = 1;
}


void ngx_rotate_signal_handler(int signo)
{
    rotate = 1;
}


int ngx_posix_post_conf_init(ngx_log_t *log)
{
    ngx_fd_t  pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
