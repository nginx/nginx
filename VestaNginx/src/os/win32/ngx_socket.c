
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


int
ngx_nonblocking(ngx_socket_t s)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_blocking(ngx_socket_t s)
{
    unsigned long  nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_socket_nread(ngx_socket_t s, int *n)
{
    unsigned long  nread;

    if (ioctlsocket(s, FIONREAD, &nread) == -1) {
        return -1;
    }

    *n = nread;

    return 0;
}


int
ngx_tcp_push(ngx_socket_t s)
{
    return 0;
}
