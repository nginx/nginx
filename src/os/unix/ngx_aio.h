
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_AIO_H_INCLUDED_
#define _NGX_AIO_H_INCLUDED_


#include <ngx_core.h>


ssize_t ngx_aio_read(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_aio_read_chain(ngx_connection_t *c, ngx_chain_t *cl);
ssize_t ngx_aio_write(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_aio_write_chain(ngx_connection_t *c, ngx_chain_t *in,
                                 off_t limit);


#endif /* _NGX_AIO_H_INCLUDED_ */
