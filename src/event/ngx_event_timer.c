
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_rbtree_t  *ngx_event_timer_rbtree;
ngx_rbtree_t   ngx_event_timer_sentinel;


int ngx_event_timer_init(ngx_cycle_t *cycle)
{
    ngx_event_timer_rbtree = &ngx_event_timer_sentinel;
    ngx_event_timer_sentinel.left = &ngx_event_timer_sentinel;
    ngx_event_timer_sentinel.right = &ngx_event_timer_sentinel;
    ngx_event_timer_sentinel.parent = &ngx_event_timer_sentinel;

    return NGX_OK;
}


void ngx_event_timer_done(ngx_cycle_t *cycle)
{
}


ngx_msec_t ngx_event_find_timer(void)
{
    ngx_rbtree_t  *node;

    node = ngx_rbtree_min(ngx_event_timer_rbtree, &ngx_event_timer_sentinel);

    if (node == &ngx_event_timer_sentinel) {
        return 0;

    } else {
        return (ngx_msec_t)
                         (node->key * NGX_TIMER_RESOLUTION - ngx_elapsed_msec);
    }
}


void ngx_event_expire_timers(ngx_msec_t timer)
{
    ngx_event_t   *ev;
    ngx_rbtree_t  *node;

    for ( ;; ) {
        node = ngx_rbtree_min(ngx_event_timer_rbtree,
                              &ngx_event_timer_sentinel);

        if (node == &ngx_event_timer_sentinel) {
            break;
        }

        if ((ngx_msec_t) node->key <= (ngx_msec_t)
                         (ngx_old_elapsed_msec + timer) / NGX_TIMER_RESOLUTION)
        {
            ev = (ngx_event_t *)
                           ((char *) node - offsetof(ngx_event_t, rbtree_key));

            ngx_del_timer(ev);

            if (ev->delayed) {
                ev->delayed = 0;
                if (ev->ready == 0) {
                    continue;
                }

            } else {
                ev->timedout = 1;
            }

            ev->event_handler(ev);
            continue;
        }

        break;
    }
}


#if 0

/* TODO: in multithreaded enviroment all timer operations must be
   protected by the single mutex */


#if 0
static ngx_event_t  *ngx_timer_queue, ngx_temp_timer_queue;
static int           ngx_expire_timers;
#endif

static ngx_event_t  *ngx_timer_queue;
static ngx_msec_t   *ngx_timer_delta;
static int           ngx_timer_cur_queue;
static int           ngx_timer_queue_num;


int ngx_event_timer_init(ngx_cycle_t *cycle)
{
    ngx_int_t          i;
    ngx_msec_t        *new_delta;
    ngx_event_t       *new_queue;
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ngx_timer_queue_num < ecf->timer_queues) {
        ngx_test_null(new_queue,
                      ngx_alloc(ecf->timer_queues * sizeof(ngx_event_t),
                                cycle->log),
                      NGX_ERROR);

        for (i = 0; i < ngx_timer_queue_num; i++) {
            new_queue[i] = ngx_timer_queue[i];
        }

        if (ngx_timer_queue) {
            ngx_free(ngx_timer_queue);
        }

        ngx_timer_queue = new_queue;

        ngx_test_null(new_delta,
                      ngx_calloc(ecf->timer_queues * sizeof(ngx_msec_t),
                                 cycle->log),
                      NGX_ERROR);

        for (i = 0; i < ngx_timer_queue_num; i++) {
            new_delta[i] = ngx_timer_delta[i];
        }

        if (ngx_timer_delta) {
            ngx_free(ngx_timer_delta);
        }

        ngx_timer_delta = new_delta;

        ngx_timer_queue_num = ecf->timer_queues;
        ngx_timer_cur_queue = 0;

        for (/* void */; i < ngx_timer_queue_num; i++) {
            ngx_timer_queue[i].timer_prev = &ngx_timer_queue[i];
            ngx_timer_queue[i].timer_next = &ngx_timer_queue[i];
        }

    } else if (ngx_timer_queue_num > ecf->timer_queues) {
        /* STUB */
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "NOT READY: timer");
        exit(1);
    }

#if 0
    ngx_temp_timer_queue.timer_prev = &ngx_temp_timer_queue;
    ngx_temp_timer_queue.timer_next = &ngx_temp_timer_queue;
#endif

    return NGX_OK;;
}


void ngx_event_timer_done(ngx_cycle_t *cycle)
{
    ngx_free(ngx_timer_queue);
    ngx_timer_queue = NULL;

    ngx_free(ngx_timer_delta);
    ngx_timer_delta = NULL;

    ngx_timer_queue_num = 0;
}


void ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
{
    ngx_event_t  *e, *queue;
#if (NGX_DEBUG_EVENT)
    ngx_connection_t *c;
#endif

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

#if (NGX_DEBUG_EVENT)
    c = ev->data;
    ngx_log_debug(ev->log, "set timer: %d:%d:%d, slot: %d" _
                  c->fd _ ev->write _ timer _ ngx_timer_cur_queue);
#endif

    if (ev->timer_next || ev->timer_prev) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "timer already set");
        return;
    }

    queue = &ngx_timer_queue[ngx_timer_cur_queue];
    timer += ngx_timer_delta[ngx_timer_cur_queue++];

    if (ngx_timer_cur_queue >= ngx_timer_queue_num) {
        ngx_timer_cur_queue = 0;
    }


#if 0
    if (ngx_expire_timers) {
        queue = &ngx_temp_timer_queue;

    } else {
        queue = &ngx_timer_queue[ngx_timer_cur_queue++];

        if (ngx_timer_cur_queue >= ngx_timer_queue_num) {
            ngx_timer_cur_queue = 0;
        }
    }
#endif

    for (e = queue->timer_next;
         e != queue && timer > e->timer_delta;
         e = e->timer_next)
    {
        timer -= e->timer_delta;
    }

    ev->timer_delta = timer;

    ev->timer_next = e;
    ev->timer_prev = e->timer_prev;

    e->timer_prev->timer_next = ev;
    e->timer_prev = ev;

    ev->timer_set = 1;

    return;
}


int ngx_event_find_timer(void)
{
    ngx_int_t   i;
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
    }

    return timer;
}


void ngx_event_set_timer_delta(ngx_msec_t timer)
{
    ngx_int_t  i;

    for (i = 0; i < ngx_timer_queue_num; i++) {
        ngx_timer_delta[i] = timer;
    }
}


/* void ngx_event_expire_timers() */
void ngx_event_expire_timers(ngx_msec_t timer)
{
    ngx_int_t     i;
#if 0
    ngx_msec_t    delta;
#endif
    ngx_event_t  *ev;

#if 0
    ngx_expire_timers = 1;
#endif

    for (i = 0; i < ngx_timer_queue_num; i++) {

#if 0
        delta = timer;
#endif

        for ( ;; ) {
            ev = ngx_timer_queue[i].timer_next;

            if (ev == &ngx_timer_queue[i]) {
                break;
            }

            if (ev->timer_delta > ngx_timer_delta[i]) {
                ev->timer_delta -= ngx_timer_delta[i];
                break;
            }

            ngx_timer_delta[i] -= ev->timer_delta;

#if 0
            if (ev->timer_delta > delta) {
                ev->timer_delta -= delta;
                break;
            }

            delta -= ev->timer_delta;
#endif

            ngx_del_timer(ev);

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

        ngx_timer_delta[i] = 0;
    }

#if 0
    ngx_expire_timers = 0;

    if (ngx_temp_timer_queue.timer_next == &ngx_temp_timer_queue) {
        return;
    }

    timer = 0;

    while (ngx_temp_timer_queue.timer_next != &ngx_temp_timer_queue) {
        timer += ngx_temp_timer_queue.timer_next->timer_delta;
        ev = ngx_temp_timer_queue.timer_next;

#if (NGX_DEBUG_EVENT)
        ngx_log_debug(ev->log, "process temp timer queue");
#endif

        ngx_del_timer(ev);
        ngx_add_timer(ev, timer);
    }
#endif
}


#endif
