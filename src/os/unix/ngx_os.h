
/*
 * Copyright (C) Igor Sysoev
 */


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


void ngx_debug_init();
ngx_int_t ngx_os_init(ngx_log_t *log);
void ngx_os_status(ngx_log_t *log);
ngx_int_t ngx_daemon(ngx_log_t *log);
ngx_int_t ngx_posix_init(ngx_log_t *log);
void ngx_posix_status(ngx_log_t *log);
ngx_int_t ngx_posix_post_conf_init(ngx_log_t *log);


ssize_t ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *entry);
ssize_t ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in,
                              off_t limit);


extern ngx_os_io_t  ngx_os_io;
extern ngx_int_t    ngx_ncpu;
extern ngx_int_t    ngx_max_sockets;
extern ngx_int_t    ngx_inherited_nonblocking;

#define ngx_stderr_fileno  STDERR_FILENO

#ifdef __FreeBSD__
#include <ngx_freebsd.h>
#endif


#ifdef __linux__
#include <ngx_linux.h>
#endif


#ifdef SOLARIS
#include <ngx_solaris.h>
#endif


#endif /* _NGX_OS_H_INCLUDED_ */
