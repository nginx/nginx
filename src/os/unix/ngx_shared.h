
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_SHARED_H_INCLUDED_
#define _NGX_SHARED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


void *ngx_create_shared_memory(size_t size, ngx_log_t *log);


#endif /* _NGX_SHARED_H_INCLUDED_ */
