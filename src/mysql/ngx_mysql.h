
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_MYSQL_H_INCLUDED_
#define _NGX_MYSQL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_peer_connection_t   peer;
} ngx_mysql_t;


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED && 0)

#define ngx_m16toh(n)   (*(uint32_t *) n & 0x0000ffff)
#define ngx_m24toh(n)   (*(uint32_t *) n & 0x00ffffff)
#define ngx_m32toh(n)   *(uint32_t *) n

#else

#define ngx_m16toh(n)   (n[0] | n[1] << 8)
#define ngx_m24toh(n)   (n[0] | n[1] << 8 | n[2] << 16)
#define ngx_m32toh(n)   (n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24)

#endif


#endif /* _NGX_MYSQL_H_INCLUDED_ */
