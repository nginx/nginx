
#include <ngx_socket.h>


/*
   ioctl(FIONBIO) set blocking mode with one syscall only while
   fcntl(F_SETFL, ~O_NONBLOCK) need to know previous state
   using fcntl(F_GETFL).

   ioctl() and fcntl() are syscalls on FreeBSD, Solaris 7/8 and Linux
*/

#if 1

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
