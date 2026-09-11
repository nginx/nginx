
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


static void ngx_event_expire_timer_tree(ngx_rbtree_t *tree,
    ngx_rbtree_key_t now);
static ngx_int_t ngx_event_timer_tree_empty(ngx_rbtree_t *tree);


ngx_rbtree_t              ngx_event_precise_timer_rbtree;
static ngx_rbtree_node_t  ngx_event_precise_timer_sentinel;

ngx_rbtree_t              ngx_event_timer_rbtree;
static ngx_rbtree_node_t  ngx_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

ngx_int_t
ngx_event_timer_init(ngx_log_t *log)
{
    ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    ngx_rbtree_init(&ngx_event_precise_timer_rbtree,
                    &ngx_event_precise_timer_sentinel,
                    ngx_rbtree_insert_timer_value);

    return NGX_OK;
}


ngx_msec_t
ngx_event_find_timer(void)
{
    ngx_msec_int_t      timer;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
        return NGX_TIMER_INFINITE;
    }

    root = ngx_event_timer_rbtree.root;
    sentinel = ngx_event_timer_rbtree.sentinel;

    node = ngx_rbtree_min(root, sentinel);

    timer = (ngx_msec_int_t) (node->key - ngx_current_msec);

    return (ngx_msec_t) (timer > 0 ? timer : 0);
}


ngx_usec_t
ngx_event_find_precise_timer(void)
{
    ngx_rbtree_key_int_t   timer;
    ngx_rbtree_node_t     *node, *root, *sentinel;

    root = ngx_event_precise_timer_rbtree.root;
    sentinel = ngx_event_precise_timer_rbtree.sentinel;

    if (root == sentinel) {
        return NGX_PRECISE_TIMER_INFINITE;
    }

    node = ngx_rbtree_min(root, sentinel);
    timer = (ngx_rbtree_key_int_t)
                           (node->key - (ngx_rbtree_key_t) ngx_monotonic_usec());

    return (ngx_usec_t) (timer > 0 ? timer : 0);
}


ngx_msec_t
ngx_event_timer_timeout(ngx_msec_t timer)
{
    ngx_usec_t  precise;
    ngx_msec_t  rounded;

    precise = ngx_event_find_precise_timer();

    if (precise == NGX_PRECISE_TIMER_INFINITE) {
        return timer;
    }

    /* Round up on event backends without sub-millisecond waits. */

    rounded = precise / 1000 + (precise % 1000 != 0);

    return ngx_min(timer, rounded);
}


void
ngx_event_add_precise_timer(ngx_event_t *ev, ngx_usec_t timer)
{
    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    ev->timer.key = ngx_monotonic_usec() + timer;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "event precise timer add: %d: %uL",
                   ngx_event_ident(ev->data), timer);

    ngx_rbtree_insert(&ngx_event_precise_timer_rbtree, &ev->timer);

    ev->timer_set = 1;
    ev->timer_precise = 1;
}


void
ngx_event_expire_timers(void)
{
    ngx_event_expire_timer_tree(&ngx_event_timer_rbtree, ngx_current_msec);

    if (ngx_event_precise_timer_rbtree.root
        != ngx_event_precise_timer_rbtree.sentinel)
    {
        ngx_event_expire_timer_tree(&ngx_event_precise_timer_rbtree,
                                   ngx_monotonic_usec());
    }
}


static void
ngx_event_expire_timer_tree(ngx_rbtree_t *tree, ngx_rbtree_key_t now)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = tree->sentinel;

    for ( ;; ) {
        root = tree->root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        /* node->key > now */

        if ((ngx_rbtree_key_int_t) (node->key - now) > 0) {
            return;
        }

        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "event timer del: %d: %M",
                       ngx_event_ident(ev->data), ev->timer.key);

        ngx_rbtree_delete(tree, &ev->timer);

#if (NGX_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;
        ev->timer_precise = 0;

        ev->timedout = 1;

        ev->handler(ev);
    }
}


ngx_int_t
ngx_event_no_timers_left(void)
{
    if (ngx_event_timer_tree_empty(&ngx_event_timer_rbtree) != NGX_OK) {
        return NGX_AGAIN;
    }

    return ngx_event_timer_tree_empty(&ngx_event_precise_timer_rbtree);
}


static ngx_int_t
ngx_event_timer_tree_empty(ngx_rbtree_t *tree)
{
    ngx_event_t        *ev;
    ngx_rbtree_node_t  *node, *root, *sentinel;

    sentinel = tree->sentinel;
    root = tree->root;

    if (root == sentinel) {
        return NGX_OK;
    }

    for (node = ngx_rbtree_min(root, sentinel);
         node;
         node = ngx_rbtree_next(tree, node))
    {
        ev = ngx_rbtree_data(node, ngx_event_t, timer);

        if (!ev->cancelable) {
            return NGX_AGAIN;
        }
    }

    /* only cancelable timers left */

    return NGX_OK;
}
