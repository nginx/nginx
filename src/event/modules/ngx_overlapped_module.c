
int ngx_overlapped_process_events(ngx_log_t *log)
{
    if (acceptex)
        event = SleepEx(timer, 1);
    else
        event = WSAWaitForMultipleEvents(n_events, events, 0, timer, 1);

    if (event == WSA_IO_COMPLETION)
        look ready array
}

void CALLBACK overlapped_completion_procedure(DWORD error, DWORD nbytes,
                         LPWSAOVERLAPPED overlapped, DWORD flags)
{
    push overlapped;
}
