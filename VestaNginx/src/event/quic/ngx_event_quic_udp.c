
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


static void ngx_quic_close_accepted_connection(ngx_connection_t *c);
static ngx_connection_t *ngx_quic_lookup_connection(ngx_listening_t *ls,
    ngx_str_t *key, struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
ngx_quic_recvmsg(ngx_event_t *ev)
{
    ssize_t             n;
    ngx_str_t           key;
    ngx_buf_t           buf;
    ngx_log_t          *log;
    ngx_err_t           err;
    socklen_t           socklen, local_socklen;
    ngx_event_t        *rev, *wev;
    struct iovec        iov[1];
    struct msghdr       msg;
    ngx_sockaddr_t      sa, lsa;
    struct sockaddr    *sockaddr, *local_sockaddr;
    ngx_listening_t    *ls;
    ngx_event_conf_t   *ecf;
    ngx_connection_t   *c, *lc;
    ngx_quic_socket_t  *qsock;
    static u_char       buffer[NGX_QUIC_MAX_UDP_PAYLOAD_SIZE];

#if (NGX_HAVE_ADDRINFO_CMSG)
    u_char             msg_control[CMSG_SPACE(sizeof(ngx_addrinfo_t))];
#endif

    if (ev->timedout) {
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "quic recvmsg on %V, ready: %d",
                   &ls->addr_text, ev->available);

    do {
        ngx_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(ngx_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NGX_HAVE_ADDRINFO_CMSG)
        if (ls->wildcard) {
            msg.msg_control = &msg_control;
            msg.msg_controllen = sizeof(msg_control);

            ngx_memzero(&msg_control, sizeof(msg_control));
        }
#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "quic recvmsg() not ready");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "quic recvmsg() failed");

            return;
        }

#if (NGX_HAVE_ADDRINFO_CMSG)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "quic recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            socklen = sizeof(ngx_sockaddr_t);
        }

#if (NGX_HAVE_UNIX_DOMAIN)

        if (sockaddr->sa_family == AF_UNIX) {
            struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

            if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
                || saun->sun_path[0] == '\0')
            {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                               "unbound unix socket");
                goto next;
            }
        }

#endif

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (NGX_HAVE_ADDRINFO_CMSG)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            ngx_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (ngx_get_srcaddr_cmsg(cmsg, local_sockaddr) == NGX_OK) {
                    break;
                }
            }
        }

#endif

        if (ngx_quic_get_packet_dcid(ev->log, buffer, n, &key) != NGX_OK) {
            goto next;
        }

        c = ngx_quic_lookup_connection(ls, &key, local_sockaddr, local_socklen);

        if (c) {

#if (NGX_DEBUG)
            if (c->log->log_level & NGX_LOG_DEBUG_EVENT) {
                ngx_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "quic recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            ngx_memzero(&buf, sizeof(ngx_buf_t));

            buf.pos = buffer;
            buf.last = buffer + n;
            buf.start = buf.pos;
            buf.end = buffer + sizeof(buffer);

            qsock = ngx_quic_get_socket(c);

            ngx_memcpy(&qsock->sockaddr, sockaddr, socklen);
            qsock->socklen = socklen;

            c->udp->buffer = &buf;

            rev = c->read;
            rev->ready = 1;
            rev->active = 0;

            rev->handler(rev);

            if (c->udp) {
                c->udp->buffer = NULL;
            }

            rev->ready = 0;
            rev->active = 1;

            goto next;
        }

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        c = ngx_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_quic_close_accepted_connection(c);
            return;
        }

        c->sockaddr = ngx_palloc(c->pool, NGX_SOCKADDRLEN);
        if (c->sockaddr == NULL) {
            ngx_quic_close_accepted_connection(c);
            return;
        }

        ngx_memcpy(c->sockaddr, sockaddr, socklen);

        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_quic_close_accepted_connection(c);
            return;
        }

        *log = ls->log;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = ngx_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                ngx_quic_close_accepted_connection(c);
                return;
            }

            ngx_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = ngx_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            ngx_quic_close_accepted_connection(c);
            return;
        }

        c->buffer->last = ngx_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        c->start_time = ngx_current_msec;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_quic_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_quic_close_accepted_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA quic recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
ngx_quic_close_accepted_connection(ngx_connection_t *c)
{
    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


static ngx_connection_t *
ngx_quic_lookup_connection(ngx_listening_t *ls, ngx_str_t *key,
    struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t            hash;
    ngx_int_t           rc;
    ngx_connection_t   *c;
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_quic_socket_t  *qsock;

    if (key->len == 0) {
        return NULL;
    }

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;
    hash = ngx_crc32_long(key->data, key->len);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        qsock = (ngx_quic_socket_t *) node;

        rc = ngx_memn2cmp(key->data, qsock->sid.id, key->len, qsock->sid.len);

        c = qsock->udp.connection;

        if (rc == 0 && ls->wildcard) {
            rc = ngx_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            c->udp = &qsock->udp;
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}
