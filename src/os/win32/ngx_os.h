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


typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in);
typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
                                          off_t limit);

typedef struct {
    ngx_recv_pt        recv;
    ngx_recv_chain_pt  recv_chain;
    ngx_send_pt        send;
    ngx_send_chain_pt  send_chain;
    ngx_uint_t         flags;
} ngx_os_io_t;


int ngx_os_init(ngx_log_t *log);

ssize_t ngx_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain);
ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit);
ngx_chain_t *ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
                                          off_t limit);


extern ngx_os_io_t  ngx_os_io;
extern int          ngx_ncpu;
extern int          ngx_max_sockets;
extern int          ngx_inherited_nonblocking;
extern int          ngx_win32_version;



#endif /* _NGX_OS_H_INCLUDED_ */

