
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_FREEBSD_H_INCLUDED_
#define _NGX_FREEBSD_H_INCLUDED_


ngx_chain_t *ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

extern int         ngx_freebsd_kern_osreldate;
extern int         ngx_freebsd_hw_ncpu;
extern u_long      ngx_freebsd_net_inet_tcp_sendspace;

extern ngx_uint_t  ngx_freebsd_sendfile_nbytes_bug;
extern ngx_uint_t  ngx_freebsd_use_tcp_nopush;
extern ngx_uint_t  ngx_freebsd_debug_malloc;


#endif /* _NGX_FREEBSD_H_INCLUDED_ */
