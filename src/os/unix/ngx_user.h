
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_USER_H_INCLUDED_
#define _NGX_USER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef uid_t  ngx_uid_t;
typedef gid_t  ngx_gid_t;


ngx_int_t ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);



#endif /* _NGX_USER_H_INCLUDED_ */
