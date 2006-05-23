
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_PARSE_URL_INET   1
#define NGX_PARSE_URL_UNIX   2


typedef struct {
    in_addr_t  addr;
    in_addr_t  mask;
} ngx_inet_cidr_t;


typedef struct {
    struct sockaddr    *sockaddr;
    socklen_t           socklen;

    ngx_str_t           name;
    char               *uri_separator;

    ngx_uint_t          weight;

    ngx_uint_t          fails;
    time_t              accessed;

    ngx_uint_t          max_fails;
    time_t              fail_timeout;

#if (NGX_SSL)
    ngx_ssl_session_t  *ssl_session;
#endif
} ngx_peer_t;


struct ngx_peers_s {
    ngx_uint_t          current;
    ngx_uint_t          weight;

    ngx_uint_t          number;
    ngx_uint_t          last_cached;

 /* ngx_mutex_t        *mutex; */
    ngx_connection_t  **cached;

    ngx_peer_t          peer[1];
};


typedef struct {
    ngx_int_t     type;

    ngx_peers_t  *peers;

    ngx_str_t     url;
    ngx_str_t     host;
    ngx_str_t     host_header;
    ngx_str_t     port;
    ngx_str_t     uri;

    in_port_t     portn;
    in_port_t     default_portn;

    unsigned      listen:1;
    unsigned      uri_part:1;
    unsigned      upstream:1;

    unsigned      default_port:1;
    unsigned      wildcard:1;

    char         *err;
} ngx_url_t;


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
    unsigned      virtual:1;
} ngx_inet_upstream_t;


size_t ngx_sock_ntop(int family, struct sockaddr *sa, u_char *text,
                     size_t len);
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);

ngx_int_t ngx_ptocidr(ngx_str_t *text, void *cidr);

ngx_peers_t *ngx_inet_upstream_parse(ngx_conf_t *cf, ngx_inet_upstream_t *u);
ngx_peers_t *ngx_inet_resolve_peer(ngx_conf_t *cf, ngx_str_t *name,
    in_port_t port);
char *ngx_inet_parse_host_port(ngx_inet_upstream_t *u);
ngx_int_t ngx_parse_url(ngx_conf_t *cf, ngx_url_t *u);


#endif /* _NGX_INET_H_INCLUDED_ */
