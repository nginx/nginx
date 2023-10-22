
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_MAX_PENDING_CONN  10


static CRITICAL_SECTION  connect_lock;
static int               nconnects;
static ngx_connection_t  pending_connects[NGX_MAX_PENDING_CONN];

static HANDLE            pending_connect_event;

__declspec(thread) int                nevents = 0;
__declspec(thread) WSAEVENT           events[WSA_MAXIMUM_WAIT_EVENTS + 1];
__declspec(thread) ngx_connection_t  *conn[WSA_MAXIMUM_WAIT_EVENTS + 1];



int ngx_iocp_wait_connect(ngx_connection_t *c)
{
    for ( ;; ) {
        EnterCriticalSection(&connect_lock);

        if (nconnects < NGX_MAX_PENDING_CONN) {
            pending_connects[--nconnects] = c;
            LeaveCriticalSection(&connect_lock);

            if (SetEvent(pending_connect_event) == 0) {
                ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                              "SetEvent() failed");
                return NGX_ERROR;

            break;
        }

        LeaveCriticalSection(&connect_lock);
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "max number of pending connect()s is %d",
                      NGX_MAX_PENDING_CONN);
        msleep(100);
    }

    if (!started) {
        if (ngx_iocp_new_thread(1) == NGX_ERROR) {
            return NGX_ERROR;
        }
        started = 1;
    }

    return NGX_OK;
}


int ngx_iocp_new_thread(int main)
{
    u_int  id;

    if (main) {
        pending_connect_event = CreateEvent(NULL, 0, 1, NULL);
        if (pending_connect_event == INVALID_HANDLE_VALUE) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                          "CreateThread() failed");
            return NGX_ERROR;
        }
    }

    if (CreateThread(NULL, 0, ngx_iocp_wait_events, main, 0, &id)
                                                       == INVALID_HANDLE_VALUE)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "CreateThread() failed");
        return NGX_ERROR;
    }

    SetEvent(event) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "SetEvent() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


int ngx_iocp_new_connect()
{
    EnterCriticalSection(&connect_lock);
    c = pending_connects[--nconnects];
    LeaveCriticalSection(&connect_lock);

    conn[nevents] = c;

    events[nevents] = WSACreateEvent();
    if (events[nevents] == INVALID_HANDLE_VALUE) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      "WSACreateEvent() failed");
        return NGX_ERROR;
    }

    if (WSAEventSelect(c->fd, events[nevents], FD_CONNECT) == -1)
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      "WSAEventSelect() failed");
        return NGX_ERROR;
    }

    nevents++;

    return NGX_OK;
}


void ngx_iocp_wait_events(int main)
{
    WSANETWORKEVENTS  ne;

    nevents = 1;
    events[0] = pending_connect_event;
    conn[0] = NULL;

    for ( ;; ) {
        offset = (nevents == WSA_MAXIMUM_WAIT_EVENTS + 1) ? 1 : 0;
        timeout = (nevents == 1 && !first) ? 60000 : INFINITE;

        n = WSAWaitForMultipleEvents(nevents - offset, events[offset],
                                     0, timeout, 0);
        if (n == WAIT_FAILED) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                          "WSAWaitForMultipleEvents() failed");
            continue;
        }

        if (n == WAIT_TIMEOUT) {
            if (nevents == 2 && !main) {
                ExitThread(0);
            }

            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "WSAWaitForMultipleEvents() "
                          "returned unexpected WAIT_TIMEOUT");
            continue;
        }

        n -= WSA_WAIT_EVENT_0;

        if (events[n] == NULL) {

            /* the pending_connect_event */

            if (nevents == WSA_MAXIMUM_WAIT_EVENTS) {
                ngx_iocp_new_thread(0);
            } else {
                ngx_iocp_new_connect();
            }

            continue;
        }

        if (WSAEnumNetworkEvents(c[n].fd, events[n], &ne) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                          "WSAEnumNetworkEvents() failed");
            continue;
        }

        if (ne.lNetworkEvents & FD_CONNECT) {
            conn[n].write->ovlp.error = ne.iErrorCode[FD_CONNECT_BIT];

            if (PostQueuedCompletionStatus(iocp, 0, NGX_IOCP_CONNECT,
                                           &conn[n].write->ovlp) == 0)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "PostQueuedCompletionStatus() failed");
                continue;
            }

            if (n < nevents) {
                conn[n] = conn[nevents];
                events[n] = events[nevents];
            }

            nevents--;
            continue;
        }

        if (ne.lNetworkEvents & FD_ACCEPT) {

            /* CHECK ERROR ??? */

            ngx_event_post_acceptex(conn[n].listening, 1);
            continue;
        }

        ngx_log_error(NGX_LOG_ALERT, c[n].log, 0,
                      "WSAWaitForMultipleEvents() "
                      "returned unexpected network event %ul",
                      ne.lNetworkEvents);
    }
}
