#ifndef _NGX_EVENT_TIMER_H_INCLUDED_
#define _NGX_EVENT_TIMER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * 32 bit key value resolution
 *
 * 1 msec - 49 days
 * 10 msec - 1 years 4 months
 * 50 msec - 6 years 10 months
 * 100 msec - 13 years 8 months
 */

#define NGX_TIMER_RESOLUTION  50


int  ngx_event_timer_init(ngx_cycle_t *cycle);
void ngx_event_timer_done(ngx_cycle_t *cycle);
ngx_msec_t ngx_event_find_timer(void);
void ngx_event_expire_timers(ngx_msec_t timer);

#if 0
int  ngx_event_timer_init(ngx_cycle_t *cycle);
void ngx_event_timer_done(ngx_cycle_t *cycle);
void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer);
int  ngx_event_find_timer(void);
void ngx_event_set_timer_delta(ngx_msec_t timer);
void ngx_event_expire_timers(ngx_msec_t timer);
#endif


extern ngx_rbtree_t  *ngx_event_timer_rbtree;


ngx_inline static void ngx_event_del_timer(ngx_event_t *ev)
{
    ngx_rbtree_delete(&ngx_event_timer_rbtree,
                      (ngx_rbtree_t *) &ev->rbtree_key);

    ev->timer_set = 0;
}


ngx_inline static void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    ev->rbtree_key = (ngx_int_t)
                             (ngx_elapsed_msec + timer) / NGX_TIMER_RESOLUTION;

    ngx_rbtree_insert(&ngx_event_timer_rbtree,
                      (ngx_rbtree_t *) &ev->rbtree_key);

    ev->timer_set = 1;
}


#if 0

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

#endif


#endif /* _NGX_EVENT_TIMER_H_INCLUDED_ */
