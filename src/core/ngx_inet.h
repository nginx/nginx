
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


typedef struct {
    in_addr_t  addr;
    in_addr_t  mask;
} ngx_inet_cidr_t;


size_t ngx_sock_ntop(int family, struct sockaddr *addr, u_char *text,
                     size_t len);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);

ngx_int_t ngx_ptocidr(ngx_str_t *text, void *cidr);


#endif /* _NGX_INET_H_INCLUDED_ */
