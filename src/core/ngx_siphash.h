
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SIPHASH_H_INCLUDED_
#define _NGX_SIPHASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


uint64_t ngx_siphash(uint64_t k0, uint64_t k1, u_char *data, size_t len);


#endif /* _NGX_SIPHASH_H_INCLUDED_ */
