#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_posted_events_s  ngx_posted_event_t;

struct ngx_posted_events_s {
    ngx_event_t         *event;
    ngx_posted_event_t  *next;

    unsigned             instance:1;
    unsigned             ready:1;
    unsigned             timedout:1;
    unsigned             complete:1;
};


#define ngx_post_event(ev)                                                    \
            if (!ev->posted) {                                                \
                ev->next = (ngx_event_t *) ngx_posted_events;                 \
                ngx_posted_events = ev;                                       \
                ev->posted = 1;                                               \
            }

/*
\
   ngx_log_debug3(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, \
               "POST: %08X %08X %08X", ngx_posted_events, \
               (ngx_posted_events ? ngx_posted_events->next: 0), \
               ((ngx_posted_events && ngx_posted_events->next) ? \
                               ngx_posted_events->next->next: 0)); \
\
*/

/*
\
{ int i; ngx_event_t *e;\
  e = (ngx_event_t *) ngx_posted_events; \
for (i = 0; e && i < 10; e = e->next, i++) { \
   ngx_log_debug2(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, \
                  "POST: %d %08X", i, e);\
}} \
\
*/


void ngx_event_process_posted(ngx_cycle_t *cycle);

extern ngx_thread_volatile ngx_event_t  *ngx_posted_events;


#if (NGX_THREADS)
ngx_int_t ngx_event_thread_process_posted(ngx_cycle_t *cycle);

extern ngx_mutex_t                      *ngx_posted_events_mutex;
extern ngx_cond_t                       *ngx_posted_events_cv;
#endif


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
