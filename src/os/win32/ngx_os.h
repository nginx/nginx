#ifndef _NGX_OS_H_INCLUDED_
#define _NGX_OS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_IO_SENDFILE    1
#define NGX_IO_ZEROCOPY    2

#if (HAVE_SENDFILE)
#define NGX_HAVE_SENDFILE  NGX_IO_SENDFILE
#else
#define NGX_HAVE_SENDFILE  0
#endif

#if (HAVE_ZEROCOPY)
#define NGX_HAVE_ZEROCOPY  NGX_IO_ZEROCOPY
#else
#define NGX_HAVE_ZEROCOPY  0
#endif



typedef struct {
    ssize_t       (*recv)(ngx_connection_t *c, u_char *buf, size_t size);
    ssize_t       (*recv_chain)(ngx_connection_t *c, ngx_chain_t *in);
    ssize_t       (*send)(ngx_connection_t *c, u_char *buf, size_t size);
    ngx_chain_t  *(*send_chain)(ngx_connection_t *c, ngx_chain_t *in);
    int             flags;
} ngx_os_io_t;


int ngx_os_init(ngx_log_t *log);

ssize_t ngx_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain);
ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in);
ngx_chain_t *ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in);


extern ngx_os_io_t  ngx_os_io;
extern int          ngx_max_sockets;
extern int          ngx_inherited_nonblocking;
extern int          ngx_win32_version;



#endif /* _NGX_OS_H_INCLUDED_ */

