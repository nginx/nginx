
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_log.h>
#include <ngx_errno.h>
#include <ngx_time.h>
#include <ngx_connection.h>
#include <ngx_event.h>
#include <ngx_event_timer.h>

#include <ngx_iocp_module.h>


int ngx_iocp_threads = 0;;


static HANDLE        iocp;
static ngx_event_t  *timer_queue;


int ngx_iocp_init(int max_connections, ngx_log_t *log)
{
    iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                  NULL, 0, ngx_iocp_threads);

    if (iocp == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    timer_queue = ngx_event_init_timer(log);
    if (timer_queue == NULL) {
        return NGX_ERROR;
    }

    ngx_event_actions.process = ngx_iocp_process_events;

    ngx_event_flags = NGX_HAVE_AIO_EVENT|NGX_HAVE_IOCP_EVENT;

    return NGX_OK;
}


int ngx_iocp_add_event(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(ev->log, "iocp: %d, %08x:%08x" _ c->fd _ ev _ &ev->ovlp);

    if (CreateIoCompletionPort((HANDLE) c->fd, iocp, (DWORD) ev, 0) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "CreateIoCompletionPort() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


int ngx_iocp_process_events(ngx_log_t *log)
{
    int                rc;
    size_t             bytes;
    ngx_err_t          err;
    ngx_msec_t         timer, delta;
    ngx_event_t       *ev, *e;
    ngx_event_ovlp_t  *ovlp;

    ngx_log_debug(log, "iocp");

    timer = ngx_event_find_timer();

    if (timer) {
        delta = ngx_msec();

    } else {
        timer = INFINITE;
        delta = 0;
    }

    ngx_log_debug(log, "iocp timer: %d" _ timer);

#if 1
    rc = GetQueuedCompletionStatus(iocp, &bytes, (LPDWORD) &e,
                                   (LPOVERLAPPED *) &ovlp, timer);
    ngx_log_debug(log, "iocp: %d, %d:%08x:%08x" _ rc _ bytes _ e _ ovlp);
    if (rc == 0) {
#else
    if (GetQueuedCompletionStatus(iocp, &bytes, (LPDWORD) &e,
                                  (LPOVERLAPPED *) &ovlp, timer) == 0) {
#endif
        err = ngx_errno;

        if (ovlp == NULL) {
            if (err != WAIT_TIMEOUT) {
                ngx_log_error(NGX_LOG_ALERT, log, err,
                              "GetQueuedCompletionStatus() failed");

                return NGX_ERROR;
            }

        } else {
            ovlp->error = err;
        }
    }

    if (timer != INFINITE) {
        delta = ngx_msec() - delta;
        ngx_event_expire_timers(delta);
    }

    if (ovlp) {
        ev = ovlp->event;

ngx_log_debug(log, "iocp ev: %08x" _ ev);

        if (ev == e) {
            /* it's not AcceptEx() completion */
            ev->ready = 1;
            ev->available = bytes;
        }

ngx_log_debug(log, "iocp ev: %08x" _ ev->event_handler);

        ev->event_handler(ev);
    }

    return NGX_OK;
}
