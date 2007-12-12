
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_MD5_H_INCLUDED_
#define _NGX_MD5_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


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


#endif /* _NGX_MD5_H_INCLUDED_ */
