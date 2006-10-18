
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CRC32_H_INCLUDED_
#define _NGX_CRC32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


extern uint32_t  ngx_crc32_table[];


static ngx_inline uint32_t
ngx_crc32(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = ngx_crc32_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#endif /* _NGX_CRC32_H_INCLUDED_ */
