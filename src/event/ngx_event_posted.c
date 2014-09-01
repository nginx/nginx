
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_event_t  *ngx_posted_accept_events;
ngx_event_t  *ngx_posted_events;


void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_event_t **posted)
{
    ngx_event_t  *ev;

    for ( ;; ) {

        ev = *posted;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        if (ev == NULL) {
            return;
        }

        ngx_delete_posted_event(ev);

        ev->handler(ev);
    }
}
