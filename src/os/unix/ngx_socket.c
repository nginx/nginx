
#include <ngx_config.h>
#include <ngx_core.h>


/*
   ioctl(FIONBIO) set blocking mode with one syscall only while
   fcntl(F_SETFL, ~O_NONBLOCK) need to know previous state
   using fcntl(F_GETFL).

   ioctl() and fcntl() are syscalls on FreeBSD, Solaris 7/8 and Linux
*/


#if (HAVE_FIONBIO)

int ngx_nonblocking(ngx_socket_t s)
{
    unsigned long  nb = 1;

    return ioctl(s, FIONBIO, &nb);
}


int ngx_blocking(ngx_socket_t s)
{
    unsigned long  nb = 0;

    return ioctl(s, FIONBIO, &nb);
}

#endif


#ifdef __FreeBSD__

int ngx_tcp_nopush(ngx_socket_t s)
{
    int  tcp_nopush;

    tcp_nopush = 1;

    return setsockopt(s, IPPROTO_TCP, TCP_NOPUSH,
                      (const void *) &tcp_nopush, sizeof(int));
}


int ngx_tcp_push(ngx_socket_t s)
{
    int  tcp_nopush;

    tcp_nopush = 0;

    return setsockopt(s, IPPROTO_TCP, TCP_NOPUSH,
                      (const void *) &tcp_nopush, sizeof(int));
}

#elif __linux__

int ngx_tcp_nopush(ngx_socket_t s)
{
    int  cork;

    cork = 1;

    return setsockopt(s, IPPROTO_TCP, TCP_CORK,
                      (const void *) &cork, sizeof(int));
}

int ngx_tcp_push(ngx_socket_t s)
{
    int  cork;

    cork = 0;

    return setsockopt(s, IPPROTO_TCP, TCP_CORK,
                      (const void *) &cork, sizeof(int));
}

#else

int ngx_tcp_nopush(ngx_socket_t s)
{
    return NGX_OK;
}

int ngx_tcp_push(ngx_socket_t s)
{
    return NGX_OK;
}

#endif
