#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>


ngx_event_t *ngx_event_init_timer(ngx_log_t *log);
void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer);
int ngx_event_find_timer(void);
void ngx_event_expire_timers(ngx_msec_t timer);


extern ngx_event_t  *ngx_timer_queue;


ngx_inline static void ngx_event_del_timer(ngx_event_t *ev)
{
#if (NGX_DEBUG_EVENT)
    /* STUB - we can not cast (ngx_connection_t *) here */
    ngx_log_debug(ev->log, "del timer: %d" _ *(int *)(ev->data));
#endif

    if (ev->timer_prev) {
        ev->timer_prev->timer_next = ev->timer_next;
    }

    if (ev->timer_next) {
        ev->timer_next->timer_delta += ev->timer_delta;
        ev->timer_next->timer_prev = ev->timer_prev;
        ev->timer_next = NULL;
    }

    if (ev->timer_prev) {
        ev->timer_prev = NULL;
    }
}


#endif _NGX_EVENT_TIMER_H_INCLUDED_
