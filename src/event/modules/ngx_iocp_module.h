#ifndef _NGX_IOCP_MODULE_H_INCLUDED_
#define _NGX_IOCP_MODULE_H_INCLUDED_


#include <ngx_types.h>
#include <ngx_log.h>
#include <ngx_event.h>


int ngx_iocp_init(int max_connections, ngx_log_t *log);
int ngx_iocp_add_event(ngx_event_t *ev);
int ngx_iocp_process_events(ngx_log_t *log);


#endif /* _NGX_IOCP_MODULE_H_INCLUDED_ */
