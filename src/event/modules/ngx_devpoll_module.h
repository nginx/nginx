#ifndef _NGX_DEVPOLL_MODULE_H_INCLUDED_
#define _NGX_DEVPOLL_MODULE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_event.h>

int ngx_devpoll_init(int max_connections, ngx_log_t *log);
int ngx_devpoll_add_event(ngx_event_t *ev, int event, u_int flags);
int ngx_devpoll_del_event(ngx_event_t *ev, int event, u_int flags);
void ngx_devpoll_add_timer(ngx_event_t *ev, ngx_msec_t timer);
int ngx_devpoll_process_events(ngx_log_t *log);


#if 0
/* DEBUG */
#define POLLREMOVE   0x0800
#define DP_POLL      0xD001

struct dvpoll {
    struct pollfd* dp_fds;
    int dp_nfds;
    int dp_timeout;
};

#endif


#endif /* _NGX_DEVPOLL_MODULE_H_INCLUDED_ */
