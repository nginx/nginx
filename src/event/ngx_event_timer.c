
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_event_t  *ngx_timer_queue;
static int           ngx_timer_cur_queue;
static int           ngx_timer_queue_num;


int ngx_event_timer_init(ngx_log_t *log)
{
    int                i;
    ngx_event_t       *new_queue;
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(ngx_event_module);

    if (ngx_timer_queue_num < ecf->timer_queues) {
        ngx_test_null(new_queue,
                      ngx_alloc(ecf->timer_queues * sizeof(ngx_event_t), log),
                      NGX_ERROR);

        for (i = 0; i < ngx_timer_queue_num; i++) {
            new_queue[i] = ngx_timer_queue[i];
        }

        if (ngx_timer_queue) {
            ngx_free(ngx_timer_queue);
        }

        ngx_timer_queue = new_queue;

        ngx_timer_queue_num = ecf->timer_queues;
        ngx_timer_cur_queue = 0;

        for (/* void */; i < ngx_timer_queue_num; i++) {
            ngx_timer_queue[i].timer_prev = &ngx_timer_queue[i];
            ngx_timer_queue[i].timer_next = &ngx_timer_queue[i];
        }
    }

    return NGX_OK;;
}


void ngx_event_timer_done(ngx_log_t *log)
{
    ngx_free(ngx_timer_queue);
    ngx_timer_queue = NULL;
}


void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t  *e;

#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c = ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d, slot: %d" _
                  c->fd _ timer _ ngx_timer_cur_queue);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

    for (e = ngx_timer_queue[ngx_timer_cur_queue].timer_next;
         e != &ngx_timer_queue[ngx_timer_cur_queue] && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ngx_timer_cur_queue++;
    if (ngx_timer_cur_queue >= ngx_timer_queue_num) {
        ngx_timer_cur_queue = 0;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;
}


int ngx_event_find_timer(void)
{
    int         i;
    ngx_msec_t  timer;

    timer = NGX_MAX_MSEC;

    for (i = 0; i < ngx_timer_queue_num; i++) {
        if (ngx_timer_queue[i].timer_next == &ngx_timer_queue[i]) {
            continue;
        }

        if (timer > ngx_timer_queue[i].timer_next->timer_delta) {
            timer = ngx_timer_queue[i].timer_next->timer_delta;
        }
    }

    if (timer == NGX_MAX_MSEC) {
        return 0;
    } else {
        return timer;
    }
}


void ngx_event_expire_timers(ngx_msec_t timer)
{
    int           i;
    ngx_msec_t    delta;
    ngx_event_t  *ev;

    for (i = 0; i < ngx_timer_queue_num; i++) {

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
            ev->timer_set = 0;

            if (ev->delayed) {
                ev->delayed = 0;
                if (ev->ready == 0) {
                    continue;
                }

            } else {
                ev->timedout = 1;
            }

            ev->event_handler(ev);
        }
    }
}
