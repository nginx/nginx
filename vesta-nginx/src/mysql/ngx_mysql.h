
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_MYSQL_H_INCLUDED_
#define _NGX_MYSQL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct ngx_mysql_s  ngx_mysql_t;

typedef void (*ngx_mysql_handler_pt)(ngx_mysql_t *m);


struct ngx_mysql_s {
    ngx_peer_connection_t   peer;

    ngx_buf_t              *buf;
    ngx_pool_t             *pool;

    ngx_str_t              *login;
    ngx_str_t              *passwd;
    ngx_str_t              *database;

    ngx_str_t               query;

    ngx_uint_t              pktn;

    ngx_mysql_handler_pt    handler;
    void                   *data;
    ngx_int_t               state;

};


#define NGX_MYSQL_CMDPKT_LEN  5


#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED && 0)

#define ngx_m16toh(n)      (*(uint32_t *) n & 0x0000ffff)
#define ngx_m24toh(n)      (*(uint32_t *) n & 0x00ffffff)
#define ngx_m32toh(n)      *(uint32_t *) n

#define ngx_htom16(n, m)   *(uint16_t *) n = (uint16_t) ((m) & 0xffff)

#define ngx_htom24(n, m)   (n)[0] = (u_char) ((m) & 0xff);                   \
                           (n)[1] = (u_char) (((m) >> 8) & 0xff);            \
                           (n)[2] = (u_char) (((m) >> 16) & 0xff)

#define ngx_htom32(n, m)   *(uint32_t *) (n) = (m)

#else

#define ngx_m16toh(n)      (n[0] | n[1] << 8)
#define ngx_m24toh(n)      (n[0] | n[1] << 8 | n[2] << 16)
#define ngx_m32toh(n)      (n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24)

#define ngx_htom16(n, m)   (n)[0] = (u_char) (m); (n)[1] = (u_char) ((m) >> 8)

#define ngx_htom24(n, m)   (n)[0] = (u_char) ((m) & 0xff);                   \
                           (n)[1] = (u_char) (((m) >> 8) & 0xff);            \
                           (n)[2] = (u_char) (((m) >> 16) & 0xff)

#define ngx_htom32(n, m)   (n)[0] = (u_char) ((m) & 0xff);                   \
                           (n)[1] = (u_char) (((m) >> 8) & 0xff);            \
                           (n)[2] = (u_char) (((m) >> 16) & 0xff);           \
                           (n)[3] = (u_char) (((m) >> 24) & 0xff)

#endif


ngx_int_t ngx_mysql_connect(ngx_mysql_t *m);
ngx_int_t ngx_mysql_query(ngx_mysql_t *m);


#endif /* _NGX_MYSQL_H_INCLUDED_ */
