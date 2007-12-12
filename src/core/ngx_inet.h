
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    in_addr_t         addr;
    in_addr_t         mask;
} ngx_inet_cidr_t;


typedef union {
    in_addr_t         in_addr;
} ngx_url_addr_t;


typedef struct {
    struct sockaddr  *sockaddr;
    socklen_t         socklen;
    ngx_str_t         name;
} ngx_peer_addr_t;


typedef struct {
    ngx_int_t         type;

    ngx_str_t         url;
    ngx_str_t         host;
    ngx_str_t         uri;

    in_port_t         port;
    in_port_t         default_port;

    unsigned          listen:1;
    unsigned          uri_part:1;
    unsigned          no_resolve:1;
    unsigned          one_addr:1;

    unsigned          wildcard:1;
    unsigned          no_port:1;
    unsigned          unix_socket:1;

    ngx_url_addr_t    addr;

    ngx_peer_addr_t  *addrs;
    ngx_uint_t        naddrs;

    char             *err;
} ngx_url_t;


size_t ngx_sock_ntop(int family, struct sockaddr *sa, u_char *text, size_t len);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
ngx_int_t ngx_ptocidr(ngx_str_t *text, void *cidr);
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);



#endif /* _NGX_INET_H_INCLUDED_ */
