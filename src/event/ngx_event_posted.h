
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define ngx_post_event(ev, queue)                                             \
                                                                              \
    if (ev->prev == NULL) {                                                   \
        ev->next = *queue;                                                    \
        ev->prev = queue;                                                     \
        *queue = ev;                                                          \
                                                                              \
        if (ev->next) {                                                       \
            ev->next->prev = &ev->next;                                       \
        }                                                                     \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "post event %p", ev);  \
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,                        \
                       "update posted event %p", ev);                         \
    }


#define ngx_delete_posted_event(ev)                                           \
                                                                              \
    *(ev->prev) = ev->next;                                                   \
                                                                              \
    if (ev->next) {                                                           \
        ev->next->prev = ev->prev;                                            \
    }                                                                         \
                                                                              \
    ev->prev = NULL;                                                          \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,                            \
                   "delete posted event %p", ev);



void ngx_event_process_posted(ngx_cycle_t *cycle, ngx_event_t **posted);


extern ngx_event_t  *ngx_posted_accept_events;
extern ngx_event_t  *ngx_posted_events;


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
