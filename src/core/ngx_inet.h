
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    in_addr_t  addr;
    in_addr_t  mask;
} ngx_inet_cidr_t;


typedef struct {
    ngx_str_t     name;           /* "schema:host:port/uri" */
    ngx_str_t     url;            /* "host:port/uri" */
    ngx_str_t     host;
    ngx_str_t     uri;
    ngx_str_t     host_header;    /* "host:port" */
    ngx_str_t     port_text;      /* "port" */

    in_port_t     port;

    in_port_t     default_port_value;

    unsigned      default_port:1;
    unsigned      wildcard:1;

    unsigned      uri_part:1;
    unsigned      port_only:1;
} ngx_inet_upstream_t;


size_t ngx_sock_ntop(int family, struct sockaddr *sa, u_char *text,
                     size_t len);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);

ngx_int_t ngx_ptocidr(ngx_str_t *text, void *cidr);

ngx_peers_t *ngx_inet_upstream_parse(ngx_conf_t *cf, ngx_inet_upstream_t *u);
char *ngx_inet_parse_host_port(ngx_inet_upstream_t *u);


#endif /* _NGX_INET_H_INCLUDED_ */
