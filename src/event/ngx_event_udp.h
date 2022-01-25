
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_UDP_H_INCLUDED_
#define _NGX_EVENT_UDP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if !(NGX_WIN32)
void ngx_event_recvmsg(ngx_event_t *ev);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif

void ngx_delete_udp_connection(void *data);


#endif /* _NGX_EVENT_UDP_H_INCLUDED_ */
