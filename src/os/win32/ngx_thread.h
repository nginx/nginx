
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef HANDLE  ngx_tid_t;
typedef DWORD   ngx_thread_value_t;


ngx_err_t ngx_create_thread(ngx_tid_t *tid,
    ngx_thread_value_t (__stdcall *func)(void *arg), void *arg, ngx_log_t *log);
ngx_int_t ngx_init_threads(int n, size_t size, ngx_cycle_t *cycle);

#define ngx_log_tid                 GetCurrentThreadId()
#define NGX_TID_T_FMT               "%ud"


extern ngx_int_t  ngx_threads_n;


#endif /* _NGX_THREAD_H_INCLUDED_ */
