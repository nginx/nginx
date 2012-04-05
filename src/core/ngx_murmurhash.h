
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_MURMURHASH_H_INCLUDED_
#define _NGX_MURMURHASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


uint32_t ngx_murmur_hash2(u_char *data, size_t len);


#endif /* _NGX_MURMURHASH_H_INCLUDED_ */
