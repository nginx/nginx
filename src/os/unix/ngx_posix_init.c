
#include <ngx_config.h>
#include <ngx_core.h>


int  ngx_max_sockets;
int  ngx_inherited_nonblocking;


void ngx_signal_handler(int signo);
void ngx_exit_signal_handler(int signo);
void ngx_restart_signal_handler(int signo);
void ngx_rotate_signal_handler(int signo);


typedef struct {
     int     signo;
     char   *signame;
     char   *action;
     void  (*handler)(int signo);
} ngx_signal_t;


ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RESTART_SIGNAL),
      "SIG" ngx_value(NGX_RESTART_SIGNAL),
      "restarting",
      ngx_signal_handler },

    { ngx_signal_value(NGX_ROTATE_SIGNAL),
      "SIG" ngx_value(NGX_ROTATE_SIGNAL),
      "reopen logs",
      ngx_signal_handler },

    { ngx_signal_value(NGX_INTERRUPT_SIGNAL),
      "SIG" ngx_value(NGX_INTERRUPT_SIGNAL),
      "exiting",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "shutdowning",
      ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", NULL, ngx_sigchld_handler },

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
    char          *name;
    ngx_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    /* STUB */
    name = strsignal(signo);
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "signal #%d (%s: %s) received, %s",
                  signo, sig->signame, name, sig->action);

    switch (signo) {

    /* STUB */
    case SIGQUIT:
    case SIGABRT:

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
    case ngx_signal_value(NGX_INTERRUPT_SIGNAL):
        done = 1;
        break;

    case ngx_signal_value(NGX_RESTART_SIGNAL):
        restart = 1;
        break;

    case ngx_signal_value(NGX_ROTATE_SIGNAL):
        rotate = 1;
        break;
    }
}


void ngx_exit_signal_handler(int signo)
{
    char *s;

    s = strsignal(signo);
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "%s signal received, exiting", s);
    done = 1;
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
