
int ngx_posix_aio_process_events(ngx_log_t *log)
{
    unmask signal

    listen via signal;

    aio_suspend()/aiowait()/aio_waitcomplete();

    mask signal

    if (ngx_socket_errno == NGX_EINTR)
        look listen
        select()/accept() nb listen sockets
    else
        aio
}

int ngx_posix_aio_process_events(ngx_log_t *log)
{
    unmask signal

    /* BUG: signal can be delivered before select() */

    select(listen);

    mask signal

    if (ngx_socket_errno == NGX_EINTR)
        look ready array
}

void aio_sig_handler(int signo, siginfo_t *siginfo, void *context)
{
    push siginfo->si_value.sival_ptr
}

