
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_log.h>

/* daemon in Linux */

int ngx_daemon(ngx_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        ngx_log_error(NGX_LOG_ALERT, log, errno, "fork() failed");
        return NGX_ERROR;

    case 0:
        break;

    default:
        exit(0);
    }

    if (setsid() == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "setsid() failed");
        return NGX_ERROR;
    }

#if (__SVR4 || linux)

    /* need HUP IGN ? check in Solaris and Linux */

    switch (fork()) {
    case -1:
        ngx_log_error(NGX_LOG_ALERT, log, errno, "fork() failed");
        return NGX_ERROR;

    case 0:
        break;

    default:
        exit(0);
    }

#endif

    umask(0);

#if 0
    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "open(\"/dev/null\") failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "dup2(STDIN) failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "dup2(STDOUT) failed");
        return NGX_ERROR;
    }

    if (dup2(fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }
#endif

    return NGX_OK;
}
