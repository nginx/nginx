
#include <ngx_config.h>
#include <ngx_core.h>


int ngx_unix_init(ngx_log_t *log)
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


    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed)");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %qd:%qd",
                  rlmt.rlim_cur, rlmt.rlim_max);


#if 0
    RLIM_INFINITY
    max_connections =< rlmt.rlim_cur;
#endif

    return NGX_OK;
}
