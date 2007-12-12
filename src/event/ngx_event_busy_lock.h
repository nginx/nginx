
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_BUSY_LOCK_H_INCLUDED_
#define _NGX_EVENT_BUSY_LOCK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

typedef struct ngx_event_busy_lock_ctx_s  ngx_event_busy_lock_ctx_t;

struct ngx_event_busy_lock_ctx_s {
    ngx_event_t                *event;
    ngx_event_handler_pt        handler;
    void                       *data;
    ngx_msec_t                  timer;

    unsigned                    locked:1;
    unsigned                    waiting:1;
    unsigned                    cache_updated:1;

    char                       *md5;
    ngx_int_t                   slot;

    ngx_event_busy_lock_ctx_t  *next;
};


typedef struct {
    u_char                     *md5_mask;
    char                       *md5;
    ngx_uint_t                  cacheable;

    ngx_uint_t                  busy;
    ngx_uint_t                  max_busy;

    ngx_uint_t                  waiting;
    ngx_uint_t                  max_waiting;

    ngx_event_busy_lock_ctx_t  *events;
    ngx_event_busy_lock_ctx_t  *last;

#if (NGX_THREADS)
    ngx_mutex_t                *mutex;
#endif
} ngx_event_busy_lock_t;


ngx_int_t ngx_event_busy_lock(ngx_event_busy_lock_t *bl,
    ngx_event_busy_lock_ctx_t *ctx);
ngx_int_t ngx_event_busy_lock_cacheable(ngx_event_busy_lock_t *bl,
    ngx_event_busy_lock_ctx_t *ctx);
void ngx_event_busy_unlock(ngx_event_busy_lock_t *bl,
    ngx_event_busy_lock_ctx_t *ctx);
void ngx_event_busy_lock_cancel(ngx_event_busy_lock_t *bl,
    ngx_event_busy_lock_ctx_t *ctx);


#endif /* _NGX_EVENT_BUSY_LOCK_H_INCLUDED_ */
