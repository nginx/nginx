
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CRC32_H_INCLUDED_
#define _NGX_CRC32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


extern uint32_t  *ngx_crc32_table_short;
extern uint32_t   ngx_crc32_table256[];


static ngx_inline uint32_t
ngx_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = ngx_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = ngx_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static ngx_inline uint32_t
ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


ngx_int_t ngx_crc32_init(void);


#endif /* _NGX_CRC32_H_INCLUDED_ */
