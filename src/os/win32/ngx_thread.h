
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_THREAD_H_INCLUDED_
#define _NGX_THREAD_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_THREADS)

#define ngx_thread_volatile  volatile

#else /* !NGX_THREADS */

#define ngx_thread_volatile

#define ngx_log_tid  0
#define TID_T_FMT    "%d"

#define ngx_mutex_lock(m)     NGX_OK
#define ngx_mutex_unlock(m)

#endif


#endif /* _NGX_THREAD_H_INCLUDED_ */
