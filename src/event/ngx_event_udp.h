
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_UDP_H_INCLUDED_
#define _NGX_EVENT_UDP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if !(NGX_WIN32)

typedef struct {
    ngx_buf_t                 *buffer;
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
} ngx_udp_dgram_t;


struct ngx_udp_connection_s {
    ngx_rbtree_node_t          node;
    ngx_connection_t          *connection;
    ngx_str_t                  key;
    ngx_udp_dgram_t           *dgram;
};


void ngx_event_recvmsg(ngx_event_t *ev);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
void ngx_insert_udp_connection(ngx_connection_t *c, ngx_udp_connection_t *udp,
    ngx_str_t *key);

#endif

void ngx_delete_udp_connection(void *data);


#endif /* _NGX_EVENT_UDP_H_INCLUDED_ */
