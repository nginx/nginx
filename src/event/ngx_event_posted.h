
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define ngx_post_event(ev)                                                    \
            if (ev->prev == NULL) {                                           \
                ev->next = (ngx_event_t *) ngx_posted_events;                 \
                ev->prev = (ngx_event_t **) &ngx_posted_events;               \
                ngx_posted_events = ev;                                       \
                if (ev->next) {                                               \
                    ev->next->prev = &ev->next;                               \
                }                                                             \
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,                \
                               "post event " PTR_FMT, ev);                    \
            } else  {                                                         \
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,                \
                               "update posted event " PTR_FMT, ev);           \
            }

#define ngx_delete_posted_event(ev)                                           \
        *(ev->prev) = ev->next;                                               \
        if (ev->next) {                                                       \
            ev->next->prev = ev->prev;                                        \
        }                                                                     \
        ev->prev = NULL;                                                      \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,                        \
                       "delete posted event " PTR_FMT, ev);



void ngx_event_process_posted(ngx_cycle_t *cycle);
void ngx_wakeup_worker_thread(ngx_cycle_t *cycle);

extern ngx_thread_volatile ngx_event_t  *ngx_posted_events;


#if (NGX_THREADS)
ngx_int_t ngx_event_thread_process_posted(ngx_cycle_t *cycle);

extern ngx_mutex_t                      *ngx_posted_events_mutex;
#endif


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
