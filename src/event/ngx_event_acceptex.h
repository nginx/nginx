#ifndef _NGX_EVENT_ACCEPTEX_H_INCLUDED_
#define _NGX_EVENT_ACCEPTEX_H_INCLUDED_


#include <ngx_listen.h>
#include <ngx_event.h>


int ngx_event_acceptex(ngx_event_t *ev);
int ngx_event_post_acceptex(ngx_listen_t *ls, int n);


#endif /* _NGX_EVENT_ACCEPTEX_H_INCLUDED_ */
