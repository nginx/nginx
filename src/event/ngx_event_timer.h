#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_


#include <ngx_config.h>

#include <ngx_log.h>
#include <ngx_connection.h>
#include <ngx_event.h>


int ngx_event_init_timer(ngx_log_t *log);
void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer);

extern ngx_event_t  *ngx_timer_queue;
extern int           ngx_timer_hash_size;


ngx_inline static int ngx_event_get_timer()
{
    int         i;
    ngx_msec_t  timer;

    timer = NGX_MAX_MSEC;

    for (i = 0; i < ngx_timer_hash_size; i++) {
        if (ngx_timer_queue[i].timer_next != &ngx_timer_queue[i]) {
            if (timer > ngx_timer_queue[i].timer_next->timer_delta) {
                timer = ngx_timer_queue[i].timer_next->timer_delta;
            }
        }
    }

    if (timer == NGX_MAX_MSEC) {
        return 0;
    } else {
        return timer;
    }
}


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
