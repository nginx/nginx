
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

