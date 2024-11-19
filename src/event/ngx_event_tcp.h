
/*
 * Copyright (C) Andy Pan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_TCP_H_INCLUDED_
#define _NGX_EVENT_TCP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

int ngx_tcp_keepalive(ngx_socket_t s, int idle, int interval, int count);

#endif /* _NGX_EVENT_TCP_H_INCLUDED_ */
