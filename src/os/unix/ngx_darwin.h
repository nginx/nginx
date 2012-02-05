
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_DARWIN_H_INCLUDED_
#define _NGX_DARWIN_H_INCLUDED_


ngx_chain_t *ngx_darwin_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

extern int       ngx_darwin_kern_osreldate;
extern int       ngx_darwin_hw_ncpu;
extern u_long    ngx_darwin_net_inet_tcp_sendspace;


#endif /* _NGX_DARWIN_H_INCLUDED_ */
