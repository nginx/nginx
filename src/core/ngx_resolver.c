
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_RESOLVER_UDP_SIZE   4096


typedef struct {
    u_char  ident_hi;
    u_char  ident_lo;
    u_char  flags_hi;
    u_char  flags_lo;
    u_char  nqs_hi;
    u_char  nqs_lo;
    u_char  nan_hi;
    u_char  nan_lo;
    u_char  nns_hi;
    u_char  nns_lo;
    u_char  nar_hi;
    u_char  nar_lo;
} ngx_resolver_hdr_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
} ngx_resolver_qs_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
    u_char  ttl[4];
    u_char  len_hi;
    u_char  len_lo;
} ngx_resolver_an_t;


#define ngx_resolver_node(n)                                                 \
    (ngx_resolver_node_t *)                                                  \
        ((u_char *) (n) - offsetof(ngx_resolver_node_t, node))


ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);


static void ngx_resolver_cleanup(void *data);
static void ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree);
static ngx_int_t ngx_resolve_name_locked(ngx_resolver_t *r,
    ngx_resolver_ctx_t *ctx);
static void ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree,
    ngx_queue_t *queue);
static ngx_int_t ngx_resolver_send_query(ngx_resolver_t *r,
    ngx_resolver_node_t *rn);
static ngx_int_t ngx_resolver_create_name_query(ngx_resolver_node_t *rn,
    ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_resolver_create_addr_query(ngx_resolver_node_t *rn,
    ngx_resolver_ctx_t *ctx);
static void ngx_resolver_resend_handler(ngx_event_t *ev);
static time_t ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree,
    ngx_queue_t *queue);
static void ngx_resolver_read_response(ngx_event_t *rev);
static void ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf,
    size_t n);
static void ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
    ngx_uint_t nan, ngx_uint_t ans);
static void ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan);
static ngx_resolver_node_t *ngx_resolver_lookup_name(ngx_resolver_t *r,
    ngx_str_t *name, uint32_t hash);
static ngx_resolver_node_t *ngx_resolver_lookup_addr(ngx_resolver_t *r,
    in_addr_t addr);
static void ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name,
    u_char *buf, u_char *src, u_char *last);
static void ngx_resolver_timeout_handler(ngx_event_t *ev);
static void ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn);
static void *ngx_resolver_alloc(ngx_resolver_t *r, size_t size);
static void *ngx_resolver_calloc(ngx_resolver_t *r, size_t size);
static void ngx_resolver_free(ngx_resolver_t *r, void *p);
static void ngx_resolver_free_locked(ngx_resolver_t *r, void *p);
static void *ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size);
static ngx_addr_t *ngx_resolver_export(ngx_resolver_t *r,
    ngx_resolver_node_t *rn, ngx_uint_t rotate);
static u_char *ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len);

#if (NGX_HAVE_INET6)
static void ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_resolver_node_t *ngx_resolver_lookup_addr6(ngx_resolver_t *r,
    struct in6_addr *addr, uint32_t hash);
#endif


ngx_resolver_t *
ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n)
{
    ngx_str_t              s;
    ngx_url_t              u;
    ngx_uint_t             i, j;
    ngx_resolver_t        *r;
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *uc;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_resolver_cleanup;

    r = ngx_calloc(sizeof(ngx_resolver_t), cf->log);
    if (r == NULL) {
        return NULL;
    }

    cln->data = r;

    r->event = ngx_calloc(sizeof(ngx_event_t), cf->log);
    if (r->event == NULL) {
        return NULL;
    }

    ngx_rbtree_init(&r->name_rbtree, &r->name_sentinel,
                    ngx_resolver_rbtree_insert_value);

    ngx_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
                    ngx_rbtree_insert_value);

    ngx_queue_init(&r->name_resend_queue);
    ngx_queue_init(&r->addr_resend_queue);

    ngx_queue_init(&r->name_expire_queue);
    ngx_queue_init(&r->addr_expire_queue);

#if (NGX_HAVE_INET6)
    r->ipv6 = 1;

    ngx_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel,
                    ngx_resolver_rbtree_insert_addr6_value);

    ngx_queue_init(&r->addr6_resend_queue);

    ngx_queue_init(&r->addr6_expire_queue);
#endif

    r->event->handler = ngx_resolver_resend_handler;
    r->event->data = r;
    r->event->log = &cf->cycle->new_log;
    r->ident = -1;

    r->resend_timeout = 5;
    r->expire = 30;
    r->valid = 0;

    r->log = &cf->cycle->new_log;
    r->log_level = NGX_LOG_ERR;

    if (n) {
        if (ngx_array_init(&r->udp_connections, cf->pool, n,
                           sizeof(ngx_udp_connection_t))
            != NGX_OK)
        {
            return NULL;
        }
    }

    for (i = 0; i < n; i++) {
        if (ngx_strncmp(names[i].data, "valid=", 6) == 0) {
            s.len = names[i].len - 6;
            s.data = names[i].data + 6;

            r->valid = ngx_parse_time(&s, 1);

            if (r->valid == (time_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

#if (NGX_HAVE_INET6)
        if (ngx_strncmp(names[i].data, "ipv6=", 5) == 0) {

            if (ngx_strcmp(&names[i].data[5], "on") == 0) {
                r->ipv6 = 1;

            } else if (ngx_strcmp(&names[i].data[5], "off") == 0) {
                r->ipv6 = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }
#endif

        ngx_memzero(&u, sizeof(ngx_url_t));

        u.url = names[i];
        u.default_port = 53;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in resolver \"%V\"",
                                   u.err, &u.url);
            }

            return NULL;
        }

        uc = ngx_array_push_n(&r->udp_connections, u.naddrs);
        if (uc == NULL) {
            return NULL;
        }

        ngx_memzero(uc, u.naddrs * sizeof(ngx_udp_connection_t));

        for (j = 0; j < u.naddrs; j++) {
            uc[j].sockaddr = u.addrs[j].sockaddr;
            uc[j].socklen = u.addrs[j].socklen;
            uc[j].server = u.addrs[j].name;
        }
    }

    return r;
}


static void
ngx_resolver_cleanup(void *data)
{
    ngx_resolver_t  *r = data;

    ngx_uint_t             i;
    ngx_udp_connection_t  *uc;

    if (r) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "cleanup resolver");

        ngx_resolver_cleanup_tree(r, &r->name_rbtree);

        ngx_resolver_cleanup_tree(r, &r->addr_rbtree);

#if (NGX_HAVE_INET6)
        ngx_resolver_cleanup_tree(r, &r->addr6_rbtree);
#endif

        if (r->event) {
            ngx_free(r->event);
        }


        uc = r->udp_connections.elts;

        for (i = 0; i < r->udp_connections.nelts; i++) {
            if (uc[i].connection) {
                ngx_close_connection(uc[i].connection);
            }
        }

        ngx_free(r);
    }
}


static void
ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree)
{
    ngx_resolver_ctx_t   *ctx, *next;
    ngx_resolver_node_t  *rn;

    while (tree->root != tree->sentinel) {

        rn = ngx_resolver_node(ngx_rbtree_min(tree->root, tree->sentinel));

        ngx_queue_remove(&rn->queue);

        for (ctx = rn->waiting; ctx; ctx = next) {
            next = ctx->next;

            if (ctx->event) {
                ngx_resolver_free(r, ctx->event);
            }

            ngx_resolver_free(r, ctx);
        }

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


ngx_resolver_ctx_t *
ngx_resolve_start(ngx_resolver_t *r, ngx_resolver_ctx_t *temp)
{
    in_addr_t            addr;
    ngx_resolver_ctx_t  *ctx;

    if (temp) {
        addr = ngx_inet_addr(temp->name.data, temp->name.len);

        if (addr != INADDR_NONE) {
            temp->resolver = r;
            temp->state = NGX_OK;
            temp->naddrs = 1;
            temp->addrs = &temp->addr;
            temp->addr.sockaddr = (struct sockaddr *) &temp->sin;
            temp->addr.socklen = sizeof(struct sockaddr_in);
            ngx_memzero(&temp->sin, sizeof(struct sockaddr_in));
            temp->sin.sin_family = AF_INET;
            temp->sin.sin_addr.s_addr = addr;
            temp->quick = 1;

            return temp;
        }
    }

    if (r->udp_connections.nelts == 0) {
        return NGX_NO_RESOLVER;
    }

    ctx = ngx_resolver_calloc(r, sizeof(ngx_resolver_ctx_t));

    if (ctx) {
        ctx->resolver = r;
    }

    return ctx;
}


ngx_int_t
ngx_resolve_name(ngx_resolver_ctx_t *ctx)
{
    ngx_int_t        rc;
    ngx_resolver_t  *r;

    r = ctx->resolver;

    if (ctx->name.len > 0 && ctx->name.data[ctx->name.len - 1] == '.') {
        ctx->name.len--;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\"", &ctx->name);

    if (ctx->quick) {
        ctx->handler(ctx);
        return NGX_OK;
    }

    /* lock name mutex */

    rc = ngx_resolve_name_locked(r, ctx);

    if (rc == NGX_OK) {
        return NGX_OK;
    }

    /* unlock name mutex */

    if (rc == NGX_AGAIN) {
        return NGX_OK;
    }

    /* NGX_ERROR */

    if (ctx->event) {
        ngx_resolver_free(r, ctx->event);
    }

    ngx_resolver_free(r, ctx);

    return NGX_ERROR;
}


void
ngx_resolve_name_done(ngx_resolver_ctx_t *ctx)
{
    uint32_t              hash;
    ngx_resolver_t       *r;
    ngx_resolver_ctx_t   *w, **p;
    ngx_resolver_node_t  *rn;

    r = ctx->resolver;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve name done: %i", ctx->state);

    if (ctx->quick) {
        return;
    }

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    /* lock name mutex */

    if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {

        hash = ngx_crc32_short(ctx->name.data, ctx->name.len);

        rn = ngx_resolver_lookup_name(r, &ctx->name, hash);

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }
        }

        ngx_log_error(NGX_LOG_ALERT, r->log, 0,
                      "could not cancel %V resolving", &ctx->name);
    }

done:

    ngx_resolver_expire(r, &r->name_rbtree, &r->name_expire_queue);

    /* unlock name mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        ngx_resolver_free_locked(r, ctx->event);
    }

    ngx_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */
}


static ngx_int_t
ngx_resolve_name_locked(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx)
{
    uint32_t              hash;
    ngx_int_t             rc;
    ngx_uint_t            naddrs;
    ngx_addr_t           *addrs;
    ngx_resolver_ctx_t   *next;
    ngx_resolver_node_t  *rn;

    ngx_strlow(ctx->name.data, ctx->name.data, ctx->name.len);

    hash = ngx_crc32_short(ctx->name.data, ctx->name.len);

    rn = ngx_resolver_lookup_name(r, &ctx->name, hash);

    if (rn) {

        if (rn->valid >= ngx_time()) {

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            ngx_queue_remove(&rn->queue);

            rn->expire = ngx_time() + r->expire;

            ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);

            naddrs = (rn->naddrs == (u_short) -1) ? 0 : rn->naddrs;
#if (NGX_HAVE_INET6)
            naddrs += (rn->naddrs6 == (u_short) -1) ? 0 : rn->naddrs6;
#endif

            if (naddrs) {

                if (naddrs == 1 && rn->naddrs == 1) {
                    addrs = NULL;

                } else {
                    addrs = ngx_resolver_export(r, rn, 1);
                    if (addrs == NULL) {
                        return NGX_ERROR;
                    }
                }

                ctx->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    ctx->state = NGX_OK;
                    ctx->naddrs = naddrs;

                    if (addrs == NULL) {
                        ctx->addrs = &ctx->addr;
                        ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                        ctx->addr.socklen = sizeof(struct sockaddr_in);
                        ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                        ctx->sin.sin_family = AF_INET;
                        ctx->sin.sin_addr.s_addr = rn->u.addr;

                    } else {
                        ctx->addrs = addrs;
                    }

                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                if (addrs != NULL) {
                    ngx_resolver_free(r, addrs->sockaddr);
                    ngx_resolver_free(r, addrs);
                }

                return NGX_OK;
            }

            /* NGX_RESOLVE_CNAME */

            if (ctx->recursion++ < NGX_RESOLVER_MAX_RECURSION) {

                ctx->name.len = rn->cnlen;
                ctx->name.data = rn->u.cname;

                return ngx_resolve_name_locked(r, ctx);
            }

            ctx->next = rn->waiting;
            rn->waiting = NULL;

            /* unlock name mutex */

            do {
                ctx->state = NGX_RESOLVE_NXDOMAIN;
                next = ctx->next;

                ctx->handler(ctx);

                ctx = next;
            } while (ctx);

            return NGX_OK;
        }

        if (rn->waiting) {

            if (ctx->event == NULL) {
                ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
                if (ctx->event == NULL) {
                    return NGX_ERROR;
                }

                ctx->event->handler = ngx_resolver_timeout_handler;
                ctx->event->data = ctx;
                ctx->event->log = r->log;
                ctx->ident = -1;

                ngx_add_timer(ctx->event, ctx->timeout);
            }

            ctx->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NGX_AGAIN;

            return NGX_AGAIN;
        }

        ngx_queue_remove(&rn->queue);

        /* lock alloc mutex */

        if (rn->query) {
            ngx_resolver_free_locked(r, rn->query);
            rn->query = NULL;
#if (NGX_HAVE_INET6)
            rn->query6 = NULL;
#endif
        }

        if (rn->cnlen) {
            ngx_resolver_free_locked(r, rn->u.cname);
        }

        if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
            ngx_resolver_free_locked(r, rn->u.addrs);
        }

#if (NGX_HAVE_INET6)
        if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
            ngx_resolver_free_locked(r, rn->u6.addrs6);
        }
#endif

        /* unlock alloc mutex */

    } else {

        rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
        if (rn == NULL) {
            return NGX_ERROR;
        }

        rn->name = ngx_resolver_dup(r, ctx->name.data, ctx->name.len);
        if (rn->name == NULL) {
            ngx_resolver_free(r, rn);
            return NGX_ERROR;
        }

        rn->node.key = hash;
        rn->nlen = (u_short) ctx->name.len;
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ngx_rbtree_insert(&r->name_rbtree, &rn->node);
    }

    rc = ngx_resolver_create_name_query(rn, ctx);

    if (rc == NGX_ERROR) {
        goto failed;
    }

    if (rc == NGX_DECLINED) {
        ngx_rbtree_delete(&r->name_rbtree, &rn->node);

        ngx_resolver_free(r, rn->query);
        ngx_resolver_free(r, rn->name);
        ngx_resolver_free(r, rn);

        ctx->state = NGX_RESOLVE_NXDOMAIN;
        ctx->handler(ctx);

        return NGX_OK;
    }

    rn->naddrs = (u_short) -1;
#if (NGX_HAVE_INET6)
    rn->naddrs6 = r->ipv6 ? (u_short) -1 : 0;
#endif

    if (ngx_resolver_send_query(r, rn) != NGX_OK) {
        goto failed;
    }

    if (ctx->event == NULL) {
        ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
        if (ctx->event == NULL) {
            goto failed;
        }

        ctx->event->handler = ngx_resolver_timeout_handler;
        ctx->event->data = ctx;
        ctx->event->log = r->log;
        ctx->ident = -1;

        ngx_add_timer(ctx->event, ctx->timeout);
    }

    if (ngx_queue_empty(&r->name_resend_queue)) {
        ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = ngx_time() + r->resend_timeout;

    ngx_queue_insert_head(&r->name_resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->valid = 0;
    rn->ttl = NGX_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    ctx->state = NGX_AGAIN;

    return NGX_AGAIN;

failed:

    ngx_rbtree_delete(&r->name_rbtree, &rn->node);

    if (rn->query) {
        ngx_resolver_free(r, rn->query);
    }

    ngx_resolver_free(r, rn->name);

    ngx_resolver_free(r, rn);

    return NGX_ERROR;
}


ngx_int_t
ngx_resolve_addr(ngx_resolver_ctx_t *ctx)
{
    u_char               *name;
    in_addr_t             addr;
    ngx_queue_t          *resend_queue, *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_t       *r;
    struct sockaddr_in   *sin;
    ngx_resolver_node_t  *rn;
#if (NGX_HAVE_INET6)
    uint32_t              hash;
    struct sockaddr_in6  *sin6;
#endif

#if (NGX_SUPPRESS_WARN)
    addr = 0;
#if (NGX_HAVE_INET6)
    hash = 0;
    sin6 = NULL;
#endif
#endif

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
        hash = ngx_crc32_short(sin6->sin6_addr.s6_addr, 16);

        /* lock addr mutex */

        rn = ngx_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);

        tree = &r->addr6_rbtree;
        resend_queue = &r->addr6_resend_queue;
        expire_queue = &r->addr6_expire_queue;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) ctx->addr.sockaddr;
        addr = ntohl(sin->sin_addr.s_addr);

        /* lock addr mutex */

        rn = ngx_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        resend_queue = &r->addr_resend_queue;
        expire_queue = &r->addr_expire_queue;
    }

    if (rn) {

        if (rn->valid >= ngx_time()) {

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            ngx_queue_remove(&rn->queue);

            rn->expire = ngx_time() + r->expire;

            ngx_queue_insert_head(expire_queue, &rn->queue);

            name = ngx_resolver_dup(r, rn->name, rn->nlen);
            if (name == NULL) {
                goto failed;
            }

            ctx->name.len = rn->nlen;
            ctx->name.data = name;

            /* unlock addr mutex */

            ctx->state = NGX_OK;

            ctx->handler(ctx);

            ngx_resolver_free(r, name);

            return NGX_OK;
        }

        if (rn->waiting) {

            ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
            if (ctx->event == NULL) {
                return NGX_ERROR;
            }

            ctx->event->handler = ngx_resolver_timeout_handler;
            ctx->event->data = ctx;
            ctx->event->log = r->log;
            ctx->ident = -1;

            ngx_add_timer(ctx->event, ctx->timeout);

            ctx->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = NGX_AGAIN;

            /* unlock addr mutex */

            return NGX_OK;
        }

        ngx_queue_remove(&rn->queue);

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

    } else {
        rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
        if (rn == NULL) {
            goto failed;
        }

        switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            rn->addr6 = sin6->sin6_addr;
            rn->node.key = hash;
            break;
#endif

        default: /* AF_INET */
            rn->node.key = addr;
        }

        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ngx_rbtree_insert(tree, &rn->node);
    }

    if (ngx_resolver_create_addr_query(rn, ctx) != NGX_OK) {
        goto failed;
    }

    rn->naddrs = (u_short) -1;
#if (NGX_HAVE_INET6)
    rn->naddrs6 = (u_short) -1;
#endif

    if (ngx_resolver_send_query(r, rn) != NGX_OK) {
        goto failed;
    }

    ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
    if (ctx->event == NULL) {
        goto failed;
    }

    ctx->event->handler = ngx_resolver_timeout_handler;
    ctx->event->data = ctx;
    ctx->event->log = r->log;
    ctx->ident = -1;

    ngx_add_timer(ctx->event, ctx->timeout);

    if (ngx_queue_empty(resend_queue)) {
        ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = ngx_time() + r->resend_timeout;

    ngx_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->name = NULL;
    rn->nlen = 0;
    rn->valid = 0;
    rn->ttl = NGX_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    /* unlock addr mutex */

    ctx->state = NGX_AGAIN;

    return NGX_OK;

failed:

    if (rn) {
        ngx_rbtree_delete(tree, &rn->node);

        if (rn->query) {
            ngx_resolver_free(r, rn->query);
        }

        ngx_resolver_free(r, rn);
    }

    /* unlock addr mutex */

    if (ctx->event) {
        ngx_resolver_free(r, ctx->event);
    }

    ngx_resolver_free(r, ctx);

    return NGX_ERROR;
}


void
ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx)
{
    in_addr_t             addr;
    ngx_queue_t          *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_t       *r;
    ngx_resolver_ctx_t   *w, **p;
    struct sockaddr_in   *sin;
    ngx_resolver_node_t  *rn;
#if (NGX_HAVE_INET6)
    uint32_t              hash;
    struct sockaddr_in6  *sin6;
#endif

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;
        break;
#endif

    default: /* AF_INET */
        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolve addr done: %i", ctx->state);

    if (ctx->event && ctx->event->timer_set) {
        ngx_del_timer(ctx->event);
    }

    /* lock addr mutex */

    if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {

        switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
            hash = ngx_crc32_short(sin6->sin6_addr.s6_addr, 16);
            rn = ngx_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) ctx->addr.sockaddr;
            addr = ntohl(sin->sin_addr.s_addr);
            rn = ngx_resolver_lookup_addr(r, addr);
        }

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }
        }

        {
            u_char     text[NGX_SOCKADDR_STRLEN];
            ngx_str_t  addrtext;

            addrtext.data = text;
            addrtext.len = ngx_sock_ntop(ctx->addr.sockaddr, ctx->addr.socklen,
                                         text, NGX_SOCKADDR_STRLEN, 0);

            ngx_log_error(NGX_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &addrtext);
        }
    }

done:

    ngx_resolver_expire(r, tree, expire_queue);

    /* unlock addr mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        ngx_resolver_free_locked(r, ctx->event);
    }

    ngx_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */
}


static void
ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
{
    time_t                now;
    ngx_uint_t            i;
    ngx_queue_t          *q;
    ngx_resolver_node_t  *rn;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver expire");

    now = ngx_time();

    for (i = 0; i < 2; i++) {
        if (ngx_queue_empty(queue)) {
            return;
        }

        q = ngx_queue_last(queue);

        rn = ngx_queue_data(q, ngx_resolver_node_t, queue);

        if (now <= rn->expire) {
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver expire \"%*s\"", (size_t) rn->nlen, rn->name);

        ngx_queue_remove(q);

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


static ngx_int_t
ngx_resolver_send_query(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    ssize_t                n;
    ngx_udp_connection_t  *uc;

    uc = r->udp_connections.elts;

    uc = &uc[r->last_connection++];
    if (r->last_connection == r->udp_connections.nelts) {
        r->last_connection = 0;
    }

    if (uc->connection == NULL) {

        uc->log = *r->log;
        uc->log.handler = ngx_resolver_log_error;
        uc->log.data = uc;
        uc->log.action = "resolving";

        if (ngx_udp_connect(uc) != NGX_OK) {
            return NGX_ERROR;
        }

        uc->connection->data = r;
        uc->connection->read->handler = ngx_resolver_read_response;
        uc->connection->read->resolver = 1;
    }

    if (rn->naddrs == (u_short) -1) {
        n = ngx_send(uc->connection, rn->query, rn->qlen);

        if (n == -1) {
            return NGX_ERROR;
        }

        if ((size_t) n != (size_t) rn->qlen) {
            ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "send() incomplete");
            return NGX_ERROR;
        }
    }

#if (NGX_HAVE_INET6)
    if (rn->query6 && rn->naddrs6 == (u_short) -1) {
        n = ngx_send(uc->connection, rn->query6, rn->qlen);

        if (n == -1) {
            return NGX_ERROR;
        }

        if ((size_t) n != (size_t) rn->qlen) {
            ngx_log_error(NGX_LOG_CRIT, &uc->log, 0, "send() incomplete");
            return NGX_ERROR;
        }
    }
#endif

    return NGX_OK;
}


static void
ngx_resolver_resend_handler(ngx_event_t *ev)
{
    time_t           timer, atimer, ntimer;
#if (NGX_HAVE_INET6)
    time_t           a6timer;
#endif
    ngx_resolver_t  *r;

    r = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver resend handler");

    /* lock name mutex */

    ntimer = ngx_resolver_resend(r, &r->name_rbtree, &r->name_resend_queue);

    /* unlock name mutex */

    /* lock addr mutex */

    atimer = ngx_resolver_resend(r, &r->addr_rbtree, &r->addr_resend_queue);

    /* unlock addr mutex */

#if (NGX_HAVE_INET6)

    /* lock addr6 mutex */

    a6timer = ngx_resolver_resend(r, &r->addr6_rbtree, &r->addr6_resend_queue);

    /* unlock addr6 mutex */

#endif

    timer = ntimer;

    if (timer == 0) {
        timer = atimer;

    } else if (atimer) {
        timer = ngx_min(timer, atimer);
    }

#if (NGX_HAVE_INET6)

    if (timer == 0) {
        timer = a6timer;

    } else if (a6timer) {
        timer = ngx_min(timer, a6timer);
    }

#endif

    if (timer) {
        ngx_add_timer(r->event, (ngx_msec_t) (timer * 1000));
    }
}


static time_t
ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
{
    time_t                now;
    ngx_queue_t          *q;
    ngx_resolver_node_t  *rn;

    now = ngx_time();

    for ( ;; ) {
        if (ngx_queue_empty(queue)) {
            return 0;
        }

        q = ngx_queue_last(queue);

        rn = ngx_queue_data(q, ngx_resolver_node_t, queue);

        if (now < rn->expire) {
            return rn->expire - now;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver resend \"%*s\" %p",
                       (size_t) rn->nlen, rn->name, rn->waiting);

        ngx_queue_remove(q);

        if (rn->waiting) {

            (void) ngx_resolver_send_query(r, rn);

            rn->expire = now + r->resend_timeout;

            ngx_queue_insert_head(queue, q);

            continue;
        }

        ngx_rbtree_delete(tree, &rn->node);

        ngx_resolver_free_node(r, rn);
    }
}


static void
ngx_resolver_read_response(ngx_event_t *rev)
{
    ssize_t            n;
    ngx_connection_t  *c;
    u_char             buf[NGX_RESOLVER_UDP_SIZE];

    c = rev->data;

    do {
        n = ngx_udp_recv(c, buf, NGX_RESOLVER_UDP_SIZE);

        if (n < 0) {
            return;
        }

        ngx_resolver_process_response(c->data, buf, n);

    } while (rev->ready);
}


static void
ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf, size_t n)
{
    char                 *err;
    ngx_uint_t            i, times, ident, qident, flags, code, nqs, nan,
                          qtype, qclass;
#if (NGX_HAVE_INET6)
    ngx_uint_t            qident6;
#endif
    ngx_queue_t          *q;
    ngx_resolver_qs_t    *qs;
    ngx_resolver_hdr_t   *response;
    ngx_resolver_node_t  *rn;

    if (n < sizeof(ngx_resolver_hdr_t)) {
        goto short_response;
    }

    response = (ngx_resolver_hdr_t *) buf;

    ident = (response->ident_hi << 8) + response->ident_lo;
    flags = (response->flags_hi << 8) + response->flags_lo;
    nqs = (response->nqs_hi << 8) + response->nqs_lo;
    nan = (response->nan_hi << 8) + response->nan_lo;

    ngx_log_debug6(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response %ui fl:%04Xui %ui/%ui/%ud/%ud",
                   ident, flags, nqs, nan,
                   (response->nns_hi << 8) + response->nns_lo,
                   (response->nar_hi << 8) + response->nar_lo);

    /* response to a standard query */
    if ((flags & 0xf870) != 0x8000) {
        ngx_log_error(r->log_level, r->log, 0,
                      "invalid DNS response %ui fl:%04Xui", ident, flags);
        return;
    }

    code = flags & 0xf;

    if (code == NGX_RESOLVE_FORMERR) {

        times = 0;

        for (q = ngx_queue_head(&r->name_resend_queue);
             q != ngx_queue_sentinel(&r->name_resend_queue) && times++ < 100;
             q = ngx_queue_next(q))
        {
            rn = ngx_queue_data(q, ngx_resolver_node_t, queue);
            qident = (rn->query[0] << 8) + rn->query[1];

            if (qident == ident) {
                goto dns_error_name;
            }

#if (NGX_HAVE_INET6)
            if (rn->query6) {
                qident6 = (rn->query6[0] << 8) + rn->query6[1];

                if (qident6 == ident) {
                    goto dns_error_name;
                }
            }
#endif
        }

        goto dns_error;
    }

    if (code > NGX_RESOLVE_REFUSED) {
        goto dns_error;
    }

    if (nqs != 1) {
        err = "invalid number of questions in DNS response";
        goto done;
    }

    i = sizeof(ngx_resolver_hdr_t);

    while (i < (ngx_uint_t) n) {
        if (buf[i] == '\0') {
            goto found;
        }

        i += 1 + buf[i];
    }

    goto short_response;

found:

    if (i++ == sizeof(ngx_resolver_hdr_t)) {
        err = "zero-length domain name in DNS response";
        goto done;
    }

    if (i + sizeof(ngx_resolver_qs_t) + nan * (2 + sizeof(ngx_resolver_an_t))
        > (ngx_uint_t) n)
    {
        goto short_response;
    }

    qs = (ngx_resolver_qs_t *) &buf[i];

    qtype = (qs->type_hi << 8) + qs->type_lo;
    qclass = (qs->class_hi << 8) + qs->class_lo;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response qt:%ui cl:%ui", qtype, qclass);

    if (qclass != 1) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unknown query class %ui in DNS response", qclass);
        return;
    }

    switch (qtype) {

    case NGX_RESOLVE_A:
#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:
#endif

        ngx_resolver_process_a(r, buf, n, ident, code, qtype, nan,
                               i + sizeof(ngx_resolver_qs_t));

        break;

    case NGX_RESOLVE_PTR:

        ngx_resolver_process_ptr(r, buf, n, ident, code, nan);

        break;

    default:
        ngx_log_error(r->log_level, r->log, 0,
                      "unknown query type %ui in DNS response", qtype);
        return;
    }

    return;

short_response:

    err = "short DNS response";

done:

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

dns_error_name:

    ngx_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui, name:\"%*s\"",
                  code, ngx_resolver_strerror(code), ident,
                  rn->nlen, rn->name);
    return;

dns_error:

    ngx_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui",
                  code, ngx_resolver_strerror(code), ident);
    return;
}


static void
ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t last,
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
    ngx_uint_t nan, ngx_uint_t ans)
{
    char                 *err;
    u_char               *cname;
    size_t                len;
    int32_t               ttl;
    uint32_t              hash;
    in_addr_t            *addr;
    ngx_str_t             name;
    ngx_addr_t           *addrs;
    ngx_uint_t            type, class, qident, naddrs, a, i, n, start;
#if (NGX_HAVE_INET6)
    struct in6_addr      *addr6;
#endif
    ngx_resolver_an_t    *an;
    ngx_resolver_ctx_t   *ctx, *next;
    ngx_resolver_node_t  *rn;

    if (ngx_resolver_copy(r, &name, buf,
                          buf + sizeof(ngx_resolver_hdr_t), buf + last)
        != NGX_OK)
    {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = ngx_crc32_short(name.data, name.len);

    /* lock name mutex */

    rn = ngx_resolver_lookup_name(r, &name, hash);

    if (rn == NULL) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected response for %V", &name);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    switch (qtype) {

#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:

        if (rn->query6 == NULL || rn->naddrs6 != (u_short) -1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected response for %V", &name);
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query6[0] << 8) + rn->query6[1];

        break;
#endif

    default: /* NGX_RESOLVE_A */

        if (rn->query == NULL || rn->naddrs != (u_short) -1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected response for %V", &name);
            ngx_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query[0] << 8) + rn->query[1];
    }

    if (ident != qident) {
        ngx_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui response for %V, expect %ui",
                      ident, &name, qident);
        ngx_resolver_free(r, name.data);
        goto failed;
    }

    ngx_resolver_free(r, name.data);

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {

#if (NGX_HAVE_INET6)
        switch (qtype) {

        case NGX_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs) {
                goto export;
            }

            break;

        default: /* NGX_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs6) {
                goto export;
            }
        }
#endif

        code = NGX_RESOLVE_NXDOMAIN;
    }

    if (code) {

#if (NGX_HAVE_INET6)
        switch (qtype) {

        case NGX_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }

            break;

        default: /* NGX_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        ngx_queue_remove(&rn->queue);

        ngx_rbtree_delete(&r->name_rbtree, &rn->node);

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            next = ctx->next;

            ctx->handler(ctx);
        }

        ngx_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    naddrs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < last) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(ngx_resolver_an_t) >= last) {
            goto short_response;
        }

        an = (ngx_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = ngx_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(ngx_resolver_an_t);

        switch (type) {

        case NGX_RESOLVE_A:

            if (qtype != NGX_RESOLVE_A) {
                err = "unexpected A record in DNS response";
                goto invalid;
            }

            if (len != 4) {
                err = "invalid A record in DNS response";
                goto invalid;
            }

            if (i + 4 > last) {
                goto short_response;
            }

            naddrs++;

            break;

#if (NGX_HAVE_INET6)
        case NGX_RESOLVE_AAAA:

            if (qtype != NGX_RESOLVE_AAAA) {
                err = "unexpected AAAA record in DNS response";
                goto invalid;
            }

            if (len != 16) {
                err = "invalid AAAA record in DNS response";
                goto invalid;
            }

            if (i + 16 > last) {
                goto short_response;
            }

            naddrs++;

            break;
#endif

        case NGX_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case NGX_RESOLVE_DNAME:

            break;

        default:

            ngx_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui", type);
        }

        i += len;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "resolver naddrs:%ui cname:%p ttl:%uD",
                   naddrs, cname, rn->ttl);

    if (naddrs) {

        switch (qtype) {

#if (NGX_HAVE_INET6)
        case NGX_RESOLVE_AAAA:

            if (naddrs == 1) {
                addr6 = &rn->u6.addr6;
                rn->naddrs6 = 1;

            } else {
                addr6 = ngx_resolver_alloc(r, naddrs * sizeof(struct in6_addr));
                if (addr6 == NULL) {
                    goto failed;
                }

                rn->u6.addrs6 = addr6;
                rn->naddrs6 = (u_short) naddrs;
            }

#if (NGX_SUPPRESS_WARN)
            addr = NULL;
#endif

            break;
#endif

        default: /* NGX_RESOLVE_A */

            if (naddrs == 1) {
                addr = &rn->u.addr;
                rn->naddrs = 1;

            } else {
                addr = ngx_resolver_alloc(r, naddrs * sizeof(in_addr_t));
                if (addr == NULL) {
                    goto failed;
                }

                rn->u.addrs = addr;
                rn->naddrs = (u_short) naddrs;
            }

#if (NGX_HAVE_INET6 && NGX_SUPPRESS_WARN)
            addr6 = NULL;
#endif
        }

        n = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (ngx_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(ngx_resolver_an_t);

            if (type == NGX_RESOLVE_A) {

                addr[n] = htonl((buf[i] << 24) + (buf[i + 1] << 16)
                                + (buf[i + 2] << 8) + (buf[i + 3]));

                if (++n == naddrs) {

#if (NGX_HAVE_INET6)
                    if (rn->naddrs6 == (u_short) -1) {
                        goto next;
                    }
#endif

                    break;
                }
            }

#if (NGX_HAVE_INET6)
            else if (type == NGX_RESOLVE_AAAA) {

                ngx_memcpy(addr6[n].s6_addr, &buf[i], 16);

                if (++n == naddrs) {

                    if (rn->naddrs == (u_short) -1) {
                        goto next;
                    }

                    break;
                }
            }
#endif

            i += len;
        }
    }

    switch (qtype) {

#if (NGX_HAVE_INET6)
    case NGX_RESOLVE_AAAA:

        if (rn->naddrs6 == (u_short) -1) {
            rn->naddrs6 = 0;
        }

        break;
#endif

    default: /* NGX_RESOLVE_A */

        if (rn->naddrs == (u_short) -1) {
            rn->naddrs = 0;
        }
    }

    if (rn->naddrs != (u_short) -1
#if (NGX_HAVE_INET6)
        && rn->naddrs6 != (u_short) -1
#endif
        && rn->naddrs
#if (NGX_HAVE_INET6)
           + rn->naddrs6
#endif
           > 0)
    {

#if (NGX_HAVE_INET6)
    export:
#endif

        naddrs = rn->naddrs;
#if (NGX_HAVE_INET6)
        naddrs += rn->naddrs6;
#endif

        if (naddrs == 1 && rn->naddrs == 1) {
            addrs = NULL;

        } else {
            addrs = ngx_resolver_export(r, rn, 0);
            if (addrs == NULL) {
                goto failed;
            }
        }

        ngx_queue_remove(&rn->queue);

        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = NGX_OK;
            ctx->naddrs = naddrs;

            if (addrs == NULL) {
                ctx->addrs = &ctx->addr;
                ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                ctx->addr.socklen = sizeof(struct sockaddr_in);
                ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                ctx->sin.sin_family = AF_INET;
                ctx->sin.sin_addr.s_addr = rn->u.addr;

            } else {
                ctx->addrs = addrs;
            }

            next = ctx->next;

            ctx->handler(ctx);
        }

        if (addrs != NULL) {
            ngx_resolver_free(r, addrs->sockaddr);
            ngx_resolver_free(r, addrs);
        }

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        return;
    }

    if (cname) {

        /* CNAME only */

        if (rn->naddrs == (u_short) -1
#if (NGX_HAVE_INET6)
            || rn->naddrs6 == (u_short) -1
#endif
            )
        {
            goto next;
        }

        if (ngx_resolver_copy(r, &name, buf, cname, buf + last) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        ngx_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

        rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = ngx_time() + r->expire;

        ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {
            ctx->name = name;

            (void) ngx_resolve_name_locked(r, ctx);
        }

        ngx_resolver_free(r, rn->query);
        rn->query = NULL;
#if (NGX_HAVE_INET6)
        rn->query6 = NULL;
#endif

        /* unlock name mutex */

        return;
    }

    ngx_log_error(r->log_level, r->log, 0,
                  "no A or CNAME types in DNS response");
    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

failed:

next:

    /* unlock name mutex */

    return;
}


static void
ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
    ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan)
{
    char                 *err;
    size_t                len;
    u_char                text[NGX_SOCKADDR_STRLEN];
    in_addr_t             addr;
    int32_t               ttl;
    ngx_int_t             octet;
    ngx_str_t             name;
    ngx_uint_t            i, mask, qident, class;
    ngx_queue_t          *expire_queue;
    ngx_rbtree_t         *tree;
    ngx_resolver_an_t    *an;
    ngx_resolver_ctx_t   *ctx, *next;
    ngx_resolver_node_t  *rn;
#if (NGX_HAVE_INET6)
    uint32_t              hash;
    ngx_int_t             digit;
    struct in6_addr       addr6;
#endif

    if (ngx_resolver_copy(r, NULL, buf,
                          buf + sizeof(ngx_resolver_hdr_t), buf + n)
        != NGX_OK)
    {
        return;
    }

    /* AF_INET */

    addr = 0;
    i = sizeof(ngx_resolver_hdr_t);

    for (mask = 0; mask < 32; mask += 8) {
        len = buf[i++];

        octet = ngx_atoi(&buf[i], len);
        if (octet == NGX_ERROR || octet > 255) {
            goto invalid_in_addr_arpa;
        }

        addr += octet << mask;
        i += len;
    }

    if (ngx_strcasecmp(&buf[i], (u_char *) "\7in-addr\4arpa") == 0) {
        i += sizeof("\7in-addr\4arpa");

        /* lock addr mutex */

        rn = ngx_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;

        addr = htonl(addr);
        name.len = ngx_inet_ntop(AF_INET, &addr, text, NGX_SOCKADDR_STRLEN);
        name.data = text;

        goto valid;
    }

invalid_in_addr_arpa:

#if (NGX_HAVE_INET6)

    i = sizeof(ngx_resolver_hdr_t);

    for (octet = 15; octet >= 0; octet--) {
        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = ngx_hextoi(&buf[i++], 1);
        if (digit == NGX_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] = (u_char) digit;

        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = ngx_hextoi(&buf[i++], 1);
        if (digit == NGX_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] += (u_char) (digit * 16);
    }

    if (ngx_strcasecmp(&buf[i], (u_char *) "\3ip6\4arpa") == 0) {
        i += sizeof("\3ip6\4arpa");

        /* lock addr mutex */

        hash = ngx_crc32_short(addr6.s6_addr, 16);
        rn = ngx_resolver_lookup_addr6(r, &addr6, hash);

        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;

        name.len = ngx_inet6_ntop(addr6.s6_addr, text, NGX_SOCKADDR_STRLEN);
        name.data = text;

        goto valid;
    }

invalid_ip6_arpa:
#endif

    ngx_log_error(r->log_level, r->log, 0,
                  "invalid in-addr.arpa or ip6.arpa name in DNS response");
    return;

valid:

    if (rn == NULL || rn->query == NULL) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected response for %V", &name);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        ngx_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui response for %V, expect %ui",
                      ident, &name, qident);
        goto failed;
    }

    if (code == 0 && nan == 0) {
        code = NGX_RESOLVE_NXDOMAIN;
    }

    if (code) {
        next = rn->waiting;
        rn->waiting = NULL;

        ngx_queue_remove(&rn->queue);

        ngx_rbtree_delete(tree, &rn->node);

        /* unlock addr mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            next = ctx->next;

            ctx->handler(ctx);
        }

        ngx_resolver_free_node(r, rn);

        return;
    }

    i += sizeof(ngx_resolver_qs_t);

    if (i + 2 + sizeof(ngx_resolver_an_t) >= n) {
        goto short_response;
    }

    /* compression pointer to *.arpa */

    if (buf[i] != 0xc0 || buf[i + 1] != sizeof(ngx_resolver_hdr_t)) {
        err = "invalid in-addr.arpa or ip6.arpa name in DNS response";
        goto invalid;
    }

    an = (ngx_resolver_an_t *) &buf[i + 2];

    class = (an->class_hi << 8) + an->class_lo;
    len = (an->len_hi << 8) + an->len_lo;
    ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
        + (an->ttl[2] << 8) + (an->ttl[3]);

    if (class != 1) {
        ngx_log_error(r->log_level, r->log, 0,
                      "unexpected RR class %ui", class);
        goto failed;
    }

    if (ttl < 0) {
        ttl = 0;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                  "resolver qt:%ui cl:%ui len:%uz",
                  (an->type_hi << 8) + an->type_lo,
                  class, len);

    i += 2 + sizeof(ngx_resolver_an_t);

    if (i + len > n) {
        goto short_response;
    }

    if (ngx_resolver_copy(r, &name, buf, buf + i, buf + n) != NGX_OK) {
        goto failed;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver an:%V", &name);

    if (name.len != (size_t) rn->nlen
        || ngx_strncmp(name.data, rn->name, name.len) != 0)
    {
        if (rn->nlen) {
            ngx_resolver_free(r, rn->name);
        }

        rn->nlen = (u_short) name.len;
        rn->name = name.data;

        name.data = ngx_resolver_dup(r, rn->name, name.len);
        if (name.data == NULL) {
            goto failed;
        }
    }

    ngx_queue_remove(&rn->queue);

    rn->valid = ngx_time() + (r->valid ? r->valid : ttl);
    rn->expire = ngx_time() + r->expire;

    ngx_queue_insert_head(expire_queue, &rn->queue);

    next = rn->waiting;
    rn->waiting = NULL;

    /* unlock addr mutex */

    while (next) {
        ctx = next;
        ctx->state = NGX_OK;
        ctx->name = name;
        next = ctx->next;

        ctx->handler(ctx);
    }

    ngx_resolver_free(r, name.data);

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock addr mutex */

    ngx_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock addr mutex */

    return;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_name(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn;

    node = r->name_rbtree.root;
    sentinel = r->name_rbtree.sentinel;

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

        rn = ngx_resolver_node(node);

        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static ngx_resolver_node_t *
ngx_resolver_lookup_addr(ngx_resolver_t *r, in_addr_t addr)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = r->addr_rbtree.root;
    sentinel = r->addr_rbtree.sentinel;

    while (node != sentinel) {

        if (addr < node->key) {
            node = node->left;
            continue;
        }

        if (addr > node->key) {
            node = node->right;
            continue;
        }

        /* addr == node->key */

        return ngx_resolver_node(node);
    }

    /* not found */

    return NULL;
}


#if (NGX_HAVE_INET6)

static ngx_resolver_node_t *
ngx_resolver_lookup_addr6(ngx_resolver_t *r, struct in6_addr *addr,
    uint32_t hash)
{
    ngx_int_t             rc;
    ngx_rbtree_node_t    *node, *sentinel;
    ngx_resolver_node_t  *rn;

    node = r->addr6_rbtree.root;
    sentinel = r->addr6_rbtree.sentinel;

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

        rn = ngx_resolver_node(node);

        rc = ngx_memcmp(addr, &rn->addr6, 16);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

#endif


static void
ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);

            p = (ngx_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


#if (NGX_HAVE_INET6)

static void
ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = ngx_resolver_node(node);
            rn_temp = ngx_resolver_node(temp);

            p = (ngx_memcmp(&rn->addr6, &rn_temp->addr6, 16)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

#endif


static ngx_int_t
ngx_resolver_create_name_query(ngx_resolver_node_t *rn, ngx_resolver_ctx_t *ctx)
{
    u_char              *p, *s;
    size_t               len, nlen;
    ngx_uint_t           ident;
#if (NGX_HAVE_INET6)
    ngx_resolver_t      *r;
#endif
    ngx_resolver_qs_t   *qs;
    ngx_resolver_hdr_t  *query;

    nlen = ctx->name.len ? (1 + ctx->name.len + 1) : 1;

    len = sizeof(ngx_resolver_hdr_t) + nlen + sizeof(ngx_resolver_qs_t);

#if (NGX_HAVE_INET6)
    r = ctx->resolver;

    p = ngx_resolver_alloc(ctx->resolver, r->ipv6 ? len * 2 : len);
#else
    p = ngx_resolver_alloc(ctx->resolver, len);
#endif
    if (p == NULL) {
        return NGX_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

#if (NGX_HAVE_INET6)
    if (r->ipv6) {
        rn->query6 = p + len;
    }
#endif

    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                   "resolve: \"%V\" A %i", &ctx->name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(ngx_resolver_hdr_t) + nlen;

    qs = (ngx_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = NGX_RESOLVE_A;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* convert "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (ctx->name.len == 0)  {
        return NGX_DECLINED;
    }

    for (s = ctx->name.data + ctx->name.len - 1; s >= ctx->name.data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return NGX_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return NGX_DECLINED;
    }

    *p = (u_char) len;

#if (NGX_HAVE_INET6)
    if (!r->ipv6) {
        return NGX_OK;
    }

    p = rn->query6;

    ngx_memcpy(p, rn->query, rn->qlen);

    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                   "resolve: \"%V\" AAAA %i", &ctx->name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    p += sizeof(ngx_resolver_hdr_t) + nlen;

    qs = (ngx_resolver_qs_t *) p;

    qs->type_lo = NGX_RESOLVE_AAAA;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_create_addr_query(ngx_resolver_node_t *rn, ngx_resolver_ctx_t *ctx)
{
    u_char               *p, *d;
    size_t                len;
    in_addr_t             addr;
    ngx_int_t             n;
    ngx_uint_t            ident;
    ngx_resolver_hdr_t   *query;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        len = sizeof(ngx_resolver_hdr_t)
              + 64 + sizeof(".ip6.arpa.") - 1
              + sizeof(ngx_resolver_qs_t);

        break;
#endif

    default: /* AF_INET */
        len = sizeof(ngx_resolver_hdr_t)
              + sizeof(".255.255.255.255.in-addr.arpa.") - 1
              + sizeof(ngx_resolver_qs_t);
    }

    p = ngx_resolver_alloc(ctx->resolver, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    rn->query = p;
    query = (ngx_resolver_hdr_t *) p;

    ident = ngx_random();

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(ngx_resolver_hdr_t);

    switch (ctx->addr.sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;

        for (n = 15; n >= 0; n--) {
            p = ngx_sprintf(p, "\1%xd\1%xd",
                            sin6->sin6_addr.s6_addr[n] & 0xf,
                            (sin6->sin6_addr.s6_addr[n] >> 4) & 0xf);
        }

        p = ngx_cpymem(p, "\3ip6\4arpa\0", 10);

        break;
#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) ctx->addr.sockaddr;
        addr = ntohl(sin->sin_addr.s_addr);

        for (n = 0; n < 32; n += 8) {
            d = ngx_sprintf(&p[1], "%ud", (addr >> n) & 0xff);
            *p = (u_char) (d - &p[1]);
            p = d;
        }

        p = ngx_cpymem(p, "\7in-addr\4arpa\0", 14);
    }

    /* query type "PTR", IN query class */
    p = ngx_cpymem(p, "\0\14\0\1", 4);

    rn->qlen = (u_short) (p - rn->query);

    return NGX_OK;
}


static ngx_int_t
ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name, u_char *buf, u_char *src,
    u_char *last)
{
    char        *err;
    u_char      *p, *dst;
    ssize_t      len;
    ngx_uint_t   i, n;

    p = src;
    len = -1;

    /*
     * compression pointers allow to create endless loop, so we set limit;
     * 128 pointers should be enough to store 255-byte name
     */

    for (i = 0; i < 128; i++) {
        n = *p++;

        if (n == 0) {
            goto done;
        }

        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *p;
            p = &buf[n];

        } else {
            len += 1 + n;
            p = &p[n];
        }

        if (p >= last) {
            err = "name is out of response";
            goto invalid;
        }
    }

    err = "compression pointers loop";

invalid:

    ngx_log_error(r->log_level, r->log, 0, err);

    return NGX_ERROR;

done:

    if (name == NULL) {
        return NGX_OK;
    }

    if (len == -1) {
        ngx_str_null(name);
        return NGX_OK;
    }

    dst = ngx_resolver_alloc(r, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    name->data = dst;

    n = *src++;

    for ( ;; ) {
        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *src;
            src = &buf[n];

            n = *src++;

        } else {
            ngx_strlow(dst, src, n);
            dst += n;
            src += n;

            n = *src++;

            if (n != 0) {
                *dst++ = '.';
            }
        }

        if (n == 0) {
            name->len = dst - name->data;
            return NGX_OK;
        }
    }
}


static void
ngx_resolver_timeout_handler(ngx_event_t *ev)
{
    ngx_resolver_ctx_t  *ctx;

    ctx = ev->data;

    ctx->state = NGX_RESOLVE_TIMEDOUT;

    ctx->handler(ctx);
}


static void
ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn)
{
    /* lock alloc mutex */

    if (rn->query) {
        ngx_resolver_free_locked(r, rn->query);
    }

    if (rn->name) {
        ngx_resolver_free_locked(r, rn->name);
    }

    if (rn->cnlen) {
        ngx_resolver_free_locked(r, rn->u.cname);
    }

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        ngx_resolver_free_locked(r, rn->u.addrs);
    }

#if (NGX_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        ngx_resolver_free_locked(r, rn->u6.addrs6);
    }
#endif

    ngx_resolver_free_locked(r, rn);

    /* unlock alloc mutex */
}


static void *
ngx_resolver_alloc(ngx_resolver_t *r, size_t size)
{
    u_char  *p;

    /* lock alloc mutex */

    p = ngx_alloc(size, r->log);

    /* unlock alloc mutex */

    return p;
}


static void *
ngx_resolver_calloc(ngx_resolver_t *r, size_t size)
{
    u_char  *p;

    p = ngx_resolver_alloc(r, size);

    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


static void
ngx_resolver_free(ngx_resolver_t *r, void *p)
{
    /* lock alloc mutex */

    ngx_free(p);

    /* unlock alloc mutex */
}


static void
ngx_resolver_free_locked(ngx_resolver_t *r, void *p)
{
    ngx_free(p);
}


static void *
ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size)
{
    void  *dst;

    dst = ngx_resolver_alloc(r, size);

    if (dst == NULL) {
        return dst;
    }

    ngx_memcpy(dst, src, size);

    return dst;
}


static ngx_addr_t *
ngx_resolver_export(ngx_resolver_t *r, ngx_resolver_node_t *rn,
    ngx_uint_t rotate)
{
    ngx_addr_t            *dst;
    ngx_uint_t             d, i, j, n;
    u_char               (*sockaddr)[NGX_SOCKADDRLEN];
    in_addr_t             *addr;
    struct sockaddr_in    *sin;
#if (NGX_HAVE_INET6)
    struct in6_addr       *addr6;
    struct sockaddr_in6   *sin6;
#endif

    n = rn->naddrs;
#if (NGX_HAVE_INET6)
    n += rn->naddrs6;
#endif

    dst = ngx_resolver_calloc(r, n * sizeof(ngx_addr_t));
    if (dst == NULL) {
        return NULL;
    }

    sockaddr = ngx_resolver_calloc(r, n * NGX_SOCKADDRLEN);
    if (sockaddr == NULL) {
        ngx_resolver_free(r, dst);
        return NULL;
    }

    i = 0;
    d = rotate ? ngx_random() % n : 0;

    if (rn->naddrs) {
        j = rotate ? ngx_random() % rn->naddrs : 0;

        addr = (rn->naddrs == 1) ? &rn->u.addr : rn->u.addrs;

        do {
            sin = (struct sockaddr_in *) sockaddr[d];
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = addr[j++];
            dst[d].sockaddr = (struct sockaddr *) sin;
            dst[d++].socklen = sizeof(struct sockaddr_in);

            if (d == n) {
                d = 0;
            }

            if (j == rn->naddrs) {
                j = 0;
            }
        } while (++i < rn->naddrs);
    }

#if (NGX_HAVE_INET6)
    if (rn->naddrs6) {
        j = rotate ? ngx_random() % rn->naddrs6 : 0;

        addr6 = (rn->naddrs6 == 1) ? &rn->u6.addr6 : rn->u6.addrs6;

        do {
            sin6 = (struct sockaddr_in6 *) sockaddr[d];
            sin6->sin6_family = AF_INET6;
            ngx_memcpy(sin6->sin6_addr.s6_addr, addr6[j++].s6_addr, 16);
            dst[d].sockaddr = (struct sockaddr *) sin6;
            dst[d++].socklen = sizeof(struct sockaddr_in6);

            if (d == n) {
                d = 0;
            }

            if (j == rn->naddrs6) {
                j = 0;
            }
        } while (++i < n);
    }
#endif

    return dst;
}


char *
ngx_resolver_strerror(ngx_int_t err)
{
    static char *errors[] = {
        "Format error",     /* FORMERR */
        "Server failure",   /* SERVFAIL */
        "Host not found",   /* NXDOMAIN */
        "Unimplemented",    /* NOTIMP */
        "Operation refused" /* REFUSED */
    };

    if (err > 0 && err < 6) {
        return errors[err - 1];
    }

    if (err == NGX_RESOLVE_TIMEDOUT) {
        return "Operation timed out";
    }

    return "Unknown error";
}


static u_char *
ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_udp_connection_t  *uc;

    p = buf;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    uc = log->data;

    if (uc) {
        p = ngx_snprintf(p, len, ", resolver: %V", &uc->server);
    }

    return p;
}


ngx_int_t
ngx_udp_connect(ngx_udp_connection_t *uc)
{
    int                rc;
    ngx_int_t          event;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c;

    s = ngx_socket(uc->sockaddr->sa_family, SOCK_DGRAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &uc->log, 0, "UDP socket %d", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, &uc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    c = ngx_get_connection(s, &uc->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, &uc->log, ngx_socket_errno,
                          ngx_close_socket_n "failed");
        }

        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, &uc->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &uc->log;
    wev->log = &uc->log;

    uc->connection = c;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, &uc->log, 0,
                   "connect to %V, fd:%d #%uA", &uc->server, s, c->number);

    rc = connect(s, uc->sockaddr, uc->socklen);

    /* TODO: aio, iocp */

    if (rc == -1) {
        ngx_log_error(NGX_LOG_CRIT, &uc->log, ngx_socket_errno,
                      "connect() failed");

        goto failed;
    }

    /* UDP sockets are always ready to write */
    wev->ready = 1;

    if (ngx_add_event) {

        event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
                    /* kqueue, epoll */                 NGX_CLEAR_EVENT:
                    /* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
                    /* eventport event type has no meaning: oneshot only */

        if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
            goto failed;
        }

    } else {
        /* rtsig */

        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }

    return NGX_OK;

failed:

    ngx_close_connection(c);
    uc->connection = NULL;

    return NGX_ERROR;
}
