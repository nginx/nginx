#ifndef _NGX_KQUEUE_MODULE_H_INCLUDED_
#define _NGX_KQUEUE_MODULE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_event.h>

void ngx_kqueue_init(int max_connections, ngx_log_t *log);
int ngx_kqueue_add_event(ngx_event_t *ev, int event, u_int flags);
int ngx_kqueue_del_event(ngx_event_t *ev, int event);
int ngx_kqueue_set_event(ngx_event_t *ev, int filter, u_int flags);
void ngx_kqueue_add_timer(ngx_event_t *ev, ngx_msec_t timer);
int ngx_kqueue_process_events(ngx_log_t *log);


#endif /* _NGX_KQUEUE_MODULE_H_INCLUDED_ */
