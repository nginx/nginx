

void ngx_add_timer(ngx_event_t *ev, ngx_msec_t timer)
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

    n = timer % ngx_timer_hash_size;

    for (e = timer_queue[n].timer_next;
         e != &timer_queue[n] && timer > e->timer_delta;
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
