
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;
int  ngx_inherited_nonblocking;


void ngx_signal_handler(int signo);


typedef struct {
     int     signo;
     char   *signame;
     char   *action;
     void  (*handler)(int signo);
} ngx_signal_t;


ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      ", reconfiguring",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      ", reopen logs",
      ngx_signal_handler },

    { ngx_signal_value(NGX_INTERRUPT_SIGNAL),
      "SIG" ngx_value(NGX_INTERRUPT_SIGNAL),
      ", exiting",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      ", exiting",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      ", shutdowning",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      ", changing binary",
      ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGPIPE, "SIGPIPE, SIG_IGN", NULL, SIG_IGN },

    { 0, NULL, NULL, NULL }
};


int ngx_posix_init(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct rlimit      rlmt;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed)");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "getrlimit(RLIMIT_NOFILE): " RLIM_T_FMT ":" RLIM_T_FMT,
                  rlmt.rlim_cur, rlmt.rlim_max);

    ngx_max_sockets = rlmt.rlim_cur;

#if (HAVE_INHERITED_NONBLOCK)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    return NGX_OK;
}


void ngx_signal_handler(int signo)
{
    struct timeval   tv;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    err = ngx_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    ngx_gettimeofday(&tv);
    ngx_time_update(tv.tv_sec);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "signal %d (%s) received%s",
                  signo, sig->signame, sig->action);

    switch (signo) {

    case SIGCHLD:
        ngx_process_get_status();
        break;

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ngx_quit = 1;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
    case ngx_signal_value(NGX_INTERRUPT_SIGNAL):
        ngx_terminate = 1;
        break;

    case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        ngx_reconfigure = 1;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ngx_reopen = 1;
        break;

    case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        ngx_change_binary = 1;
        break;
    }

    ngx_set_errno(err);
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
