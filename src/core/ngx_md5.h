
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_MD5_H_INCLUDED_
#define _NGX_MD5_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_MD5)

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif


typedef MD5_CTX  ngx_md5_t;


#if (NGX_OPENSSL_MD5)

#define ngx_md5_init    MD5_Init
#define ngx_md5_update  MD5_Update
#define ngx_md5_final   MD5_Final

#else

#define ngx_md5_init    MD5Init
#define ngx_md5_update  MD5Update
#define ngx_md5_final   MD5Final

#endif


#else /* !NGX_HAVE_MD5 */


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} ngx_md5_t;


void ngx_md5_init(ngx_md5_t *ctx);
void ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size);
void ngx_md5_final(u_char result[16], ngx_md5_t *ctx);


#endif

#endif /* _NGX_MD5_H_INCLUDED_ */
