
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static ngx_chain_t *ngx_udp_output_chain_to_iovec(ngx_iovec_t *vec,
    ngx_chain_t *in, ngx_log_t *log);
static ssize_t ngx_sendmsg_vec(ngx_connection_t *c, ngx_iovec_t *vec);


ngx_chain_t *
ngx_udp_unix_sendmsg_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ssize_t        n;
    off_t          send;
    ngx_chain_t   *cl;
    ngx_event_t   *wev;
    ngx_iovec_t    vec;
    struct iovec   iovs[NGX_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = NGX_IOVS_PREALLOCATE;

    for ( ;; ) {

        /* create the iovec and coalesce the neighbouring bufs */

        cl = ngx_udp_output_chain_to_iovec(&vec, in, c->log);

        if (cl == NGX_CHAIN_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "file buf in sendmsg "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            return NGX_CHAIN_ERROR;
        }

        if (cl == in) {
            return in;
        }

        send += vec.size;

        n = ngx_sendmsg_vec(c, &vec);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            wev->ready = 0;
            return in;
        }

        c->sent += n;

        in = ngx_chain_update_sent(in, n);

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static ngx_chain_t *
ngx_udp_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in, ngx_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    ngx_uint_t     n, flush;
    ngx_chain_t   *cl;
    struct iovec  *iov;

    cl = in;
    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;
    flush = 0;

    for ( /* void */ ; in && !flush; in = in->next) {

        if (in->buf->flush || in->buf->last_buf) {
            flush = 1;
        }

        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!ngx_buf_in_memory(in->buf)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            return NGX_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "too many parts in a datagram");
                return NGX_CHAIN_ERROR;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    if (!flush) {
#if (NGX_SUPPRESS_WARN)
        vec->size = 0;
        vec->count = 0;
#endif
        return cl;
    }

    /* zero-sized datagram; pretend to have at least 1 iov */
    if (n == 0) {
        iov = &vec->iovs[n++];
        iov->iov_base = NULL;
        iov->iov_len = 0;
    }

    vec->count = n;
    vec->size = total;

    return in;
}


static ssize_t
ngx_sendmsg_vec(ngx_connection_t *c, ngx_iovec_t *vec)
{
    struct msghdr    msg;

#if (NGX_HAVE_ADDRINFO_CMSG)
    struct cmsghdr  *cmsg;
    u_char           msg_control[CMSG_SPACE(sizeof(ngx_addrinfo_t))];
#endif

    ngx_memzero(&msg, sizeof(struct msghdr));

    if (c->socklen) {
        msg.msg_name = c->sockaddr;
        msg.msg_namelen = c->socklen;
    }

    msg.msg_iov = vec->iovs;
    msg.msg_iovlen = vec->count;

#if (NGX_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {

        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        ngx_memzero(msg_control, sizeof(msg_control));

        cmsg = CMSG_FIRSTHDR(&msg);

        msg.msg_controllen = ngx_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    return ngx_sendmsg(c, &msg, 0);
}


#if (NGX_HAVE_ADDRINFO_CMSG)

size_t
ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
{
    size_t                len;
#if (NGX_HAVE_IP_SENDSRCADDR)
    struct in_addr       *addr;
    struct sockaddr_in   *sin;
#elif (NGX_HAVE_IP_PKTINFO)
    struct in_pktinfo    *pkt;
    struct sockaddr_in   *sin;
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo   *pkt6;
    struct sockaddr_in6  *sin6;
#endif


#if (NGX_HAVE_IP_SENDSRCADDR) || (NGX_HAVE_IP_PKTINFO)

    if (local_sockaddr->sa_family == AF_INET) {

        cmsg->cmsg_level = IPPROTO_IP;

#if (NGX_HAVE_IP_SENDSRCADDR)

        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
        len = CMSG_SPACE(sizeof(struct in_addr));

        sin = (struct sockaddr_in *) local_sockaddr;

        addr = (struct in_addr *) CMSG_DATA(cmsg);
        *addr = sin->sin_addr;

#elif (NGX_HAVE_IP_PKTINFO)

        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        len = CMSG_SPACE(sizeof(struct in_pktinfo));

        sin = (struct sockaddr_in *) local_sockaddr;

        pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
        ngx_memzero(pkt, sizeof(struct in_pktinfo));
        pkt->ipi_spec_dst = sin->sin_addr;

#endif
        return len;
    }

#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    if (local_sockaddr->sa_family == AF_INET6) {

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        len = CMSG_SPACE(sizeof(struct in6_pktinfo));

        sin6 = (struct sockaddr_in6 *) local_sockaddr;

        pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        ngx_memzero(pkt6, sizeof(struct in6_pktinfo));
        pkt6->ipi6_addr = sin6->sin6_addr;

        return len;
    }
#endif

    return 0;
}


ngx_int_t
ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
{

#if (NGX_HAVE_IP_RECVDSTADDR)
    struct in_addr       *addr;
    struct sockaddr_in   *sin;
#elif (NGX_HAVE_IP_PKTINFO)
    struct in_pktinfo    *pkt;
    struct sockaddr_in   *sin;
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo   *pkt6;
    struct sockaddr_in6  *sin6;
#endif


 #if (NGX_HAVE_IP_RECVDSTADDR)

    if (cmsg->cmsg_level == IPPROTO_IP
        && cmsg->cmsg_type == IP_RECVDSTADDR
        && local_sockaddr->sa_family == AF_INET)
    {
        addr = (struct in_addr *) CMSG_DATA(cmsg);
        sin = (struct sockaddr_in *) local_sockaddr;
        sin->sin_addr = *addr;

        return NGX_OK;
    }

#elif (NGX_HAVE_IP_PKTINFO)

    if (cmsg->cmsg_level == IPPROTO_IP
        && cmsg->cmsg_type == IP_PKTINFO
        && local_sockaddr->sa_family == AF_INET)
    {
        pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
        sin = (struct sockaddr_in *) local_sockaddr;
        sin->sin_addr = pkt->ipi_addr;

        return NGX_OK;
    }

#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)

    if (cmsg->cmsg_level == IPPROTO_IPV6
        && cmsg->cmsg_type == IPV6_PKTINFO
        && local_sockaddr->sa_family == AF_INET6)
    {
        pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        sin6 = (struct sockaddr_in6 *) local_sockaddr;
        sin6->sin6_addr = pkt6->ipi6_addr;

        return NGX_OK;
    }

#endif

    return NGX_DECLINED;
}

#endif


ssize_t
ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags)
{
    ssize_t    n;
    ngx_err_t  err;
#if (NGX_DEBUG)
    size_t      size;
    ngx_uint_t  i;
#endif

eintr:

    n = sendmsg(c->fd, msg, flags);

    if (n == -1) {
        err = ngx_errno;

        switch (err) {
        case NGX_EAGAIN:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() not ready");
            return NGX_AGAIN;

        case NGX_EINTR:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            ngx_connection_error(c, err, "sendmsg() failed");
            return NGX_ERROR;
        }
    }

#if (NGX_DEBUG)
    for (i = 0, size = 0; i < (size_t) msg->msg_iovlen; i++) {
        size += msg->msg_iov[i].iov_len;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "sendmsg: %z of %uz", n, size);
#endif

    return n;
}
