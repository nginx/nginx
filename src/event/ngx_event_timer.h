#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


int  ngx_event_timer_init(ngx_cycle_t *cycle);
void ngx_event_timer_done(ngx_cycle_t *cycle);
void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer);
int  ngx_event_find_timer(void);
void ngx_event_set_timer_delta(ngx_msec_t timer);
void ngx_event_expire_timers(ngx_msec_t timer);



ngx_inline static void ngx_event_del_timer(ngx_event_t *ev)
{
#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = ev->data;
    ngx_log_debug(ev->log, "del timer: %d:%d" _ c->fd _ ev->write);
#endif

    if (!ev->timer_next || !ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already deleted");
        return;
    }

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

    ev->timer_set = 0;
}


#endif /* _NGX_EVENT_TIMER_H_INCLUDED_ */
