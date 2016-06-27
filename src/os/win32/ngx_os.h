
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_OS_H_INCLUDED_
#define _NGX_OS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_IO_SENDFILE    1


typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

typedef struct {
    ngx_recv_pt        recv;
    ngx_recv_chain_pt  recv_chain;
    ngx_recv_pt        udp_recv;
    ngx_send_pt        send;
    ngx_send_chain_pt  send_chain;
    ngx_uint_t         flags;
} ngx_os_io_t;


ngx_int_t ngx_os_init(ngx_log_t *log);
void ngx_os_status(ngx_log_t *log);
ngx_int_t ngx_os_signal_process(ngx_cycle_t *cycle, char *sig, ngx_pid_t pid);

ssize_t ngx_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_udp_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_udp_overlapped_wsarecv(ngx_connection_t *c, u_char *buf,
    size_t size);
ssize_t ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit);
ssize_t ngx_wsasend(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_overlapped_wsasend(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
ngx_chain_t *ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

void ngx_cdecl ngx_event_log(ngx_err_t err, const char *fmt, ...);


extern ngx_os_io_t  ngx_os_io;
extern ngx_uint_t   ngx_ncpu;
extern ngx_uint_t   ngx_max_wsabufs;
extern ngx_int_t    ngx_max_sockets;
extern ngx_uint_t   ngx_inherited_nonblocking;
extern ngx_uint_t   ngx_tcp_nodelay_and_tcp_nopush;
extern ngx_uint_t   ngx_win32_version;
extern char         ngx_unique[];


#endif /* _NGX_OS_H_INCLUDED_ */
