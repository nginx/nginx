
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>

#if (HAVE_KQUEUE)
#include <ngx_kqueue_module.h>
#endif


int ngx_aio_init(int max_connections, ngx_log_t *log)
{
#if (HAVE_KQUEUE)

    int  rc;

    rc = ngx_kqueue_init(max_connections, log);

    ngx_event_flags = NGX_HAVE_AIO_EVENT|NGX_USE_AIO_EVENT;
    ngx_write_chain_proc = ngx_aio_write_chain;

    return rc;

#endif
}





#if 0
/* 1 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    listen via SIGIO;
    aio_* via SIGxxx;

    sigsuspend()/sigwaitinfo()/sigtimedwait();
}

/* 2 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    unmask signal

    listen via SIGIO;

    /* BUG: SIGIO can be delivered before aio_*() */

    aio_suspend()/aiowait()/aio_waitcomplete() with timeout

    mask signal

    if (ngx_socket_errno == NGX_EINTR)
        look listen
        select()/accept() nb listen sockets
    else
        aio
}

/* 3 */
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    unmask signal

    /* BUG: AIO signal can be delivered before select() */

    select(listen);

    mask signal

    if (ngx_socket_errno == NGX_EINTR)
        look ready array
}

void aio_sig_handler(int signo, siginfo_t *siginfo, void *context)
{
    push siginfo->si_value.sival_ptr
}
#endif
