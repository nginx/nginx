
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_connection.h>
#include <ngx_event.h>

#include <ngx_event_timer.h>

/* STUB */
#define NGX_TIMER_HASH_SIZE  5

ngx_event_t  *ngx_timer_queue;
int           ngx_timer_hash_size;
static int    ngx_timer_cur_queue;


int ngx_event_init_timer(ngx_log_t *log)
{
    int  i;

    ngx_timer_hash_size = NGX_TIMER_HASH_SIZE;
    ngx_timer_cur_queue = 0;

    ngx_test_null(ngx_timer_queue,
                  ngx_alloc(ngx_timer_hash_size * sizeof(ngx_event_t), log),
                  NGX_ERROR);

    for (i = 0; i < ngx_timer_hash_size; i++) {
        ngx_timer_queue[i].timer_prev = &ngx_timer_queue[i];
        ngx_timer_queue[i].timer_next = &ngx_timer_queue[i];
    }

    return NGX_OK;
}


void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t  *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d" _ c->fd _ timer);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

#if (NGX_DEBUG_EVENT)
    ngx_log_debug(ev->log, "timer slot: %d" _ ngx_timer_cur_queue);
#endif

    for (e = ngx_timer_queue[ngx_timer_cur_queue].timer_next;
         e != &ngx_timer_queue[ngx_timer_cur_queue] && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ngx_timer_cur_queue++;
    if (ngx_timer_cur_queue >= ngx_timer_hash_size) {
        ngx_timer_cur_queue = 0;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}


void ngx_event_expire_timers(ngx_msec_t timer)
{
    int           i;
    ngx_msec_t    delta;
    ngx_event_t  *ev;

    for (i = 0; i < ngx_timer_hash_size; i++) {

        delta = timer;

        for ( ;; ) {
            ev = ngx_timer_queue[i].timer_next;

            if (ev == &ngx_timer_queue[i]) {
                break;
            }

            if (ev->timer_delta > delta) {
                ev->timer_delta -= delta;
                break;
            }

            delta -= ev->timer_delta;

            ngx_del_timer(ev);
            ev->timedout = 1;

            if (ev->event_handler(ev) == NGX_ERROR) {
                ev->close_handler(ev);
            }
        }
    }
}
