

    event = WSACreateEvent(void);
    WSAEventSelect(s, event, FD_ACCEPT);


int ngx_overlapped_process_events(ngx_log_t *log)
{
    if (acceptex)
        n = SleepEx(timer, 1);
    else
        n = WSAWaitForMultipleEvents(nevents, events, 0, timer, 1);

    if (n == WSA_WAIT_TIMEOUT)
        close some event;

    if (n == WSA_IO_COMPLETION)
        again

    /* try it with AcceptEx() on NT to detect connected sockets */
    if (!acceptex) {
        WSAEnumNetworkEvents(
            sockets[n - WSA_WAIT_EVENT_0],
            events[n - WSA_WAIT_EVENT_0],
            net_events);

        if (net_events.lNetworkEvents & FD_ACCEPT) {
            if (net_events.iErrorCode[FD_ACCEPT_BIT] != 0)
                accept error
                again

            ngx_event_accept(); OR post AcceptEx();
        }
    }
}

void CALLBACK overlapped_completion_procedure(DWORD error, DWORD nbytes,
                         LPWSAOVERLAPPED overlapped, DWORD flags)
{
    run event handler
}
