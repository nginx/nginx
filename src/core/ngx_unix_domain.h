
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_UNIX_DOMAIN_H_INCLUDED_
#define _NGX_UNIX_DOMAIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_str_t     name;           /* "schema:unix:path:/uri" */
    ngx_str_t     url;            /* "unix:path:/uri" */
    ngx_str_t     uri;

    ngx_uint_t    uri_part;       /* unsigned  uri_part:1; */
} ngx_unix_domain_upstream_t;


ngx_peers_t *ngx_unix_upstream_parse(ngx_conf_t *cf,
                                     ngx_unix_domain_upstream_t *u);


#endif /* _NGX_UNIX_DOMAIN_H_INCLUDED_ */

