
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


int ngx_event_init_timer(ngx_log_t *log)
{
    int  i;

    ngx_timer_hash_size = NGX_TIMER_HASH_SIZE;

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
    int           n;
    ngx_event_t  *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = (ngx_connection_t *) ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d" _ c->fd _ timer);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

    n = timer % ngx_timer_hash_size;

    for (e = ngx_timer_queue[n].timer_next;
         e != &ngx_timer_queue[n] && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}
