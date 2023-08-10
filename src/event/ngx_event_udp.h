
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_UDP_H_INCLUDED_
#define _NGX_EVENT_UDP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if !(NGX_WIN32)

#if ((NGX_HAVE_MSGHDR_MSG_CONTROL)                                            \
     && (NGX_HAVE_IP_SENDSRCADDR || NGX_HAVE_IP_RECVDSTADDR                   \
         || NGX_HAVE_IP_PKTINFO                                               \
         || (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)))
#define NGX_HAVE_ADDRINFO_CMSG  1

#endif


#if (NGX_HAVE_ADDRINFO_CMSG)

typedef union {
#if (NGX_HAVE_IP_SENDSRCADDR || NGX_HAVE_IP_RECVDSTADDR)
    struct in_addr        addr;
#endif

#if (NGX_HAVE_IP_PKTINFO)
    struct in_pktinfo     pkt;
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo    pkt6;
#endif
} ngx_addrinfo_t;

size_t ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);
ngx_int_t ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);

#endif

void ngx_event_recvmsg(ngx_event_t *ev);
ssize_t ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif

void ngx_delete_udp_connection(void *data);


#endif /* _NGX_EVENT_UDP_H_INCLUDED_ */
