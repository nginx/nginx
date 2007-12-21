
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * open file cache caches
 *    open file handles with stat() info;
 *    directories stat() info;
 *    files and directories errors: not found, access denied, etc.
 */


static void ngx_open_file_cache_cleanup(void *data);
static void ngx_open_file_cleanup(void *data);
static void ngx_close_cached_file(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_log_t *log);
static ngx_int_t ngx_open_and_stat_file(u_char *name, ngx_open_file_info_t *of,
    ngx_log_t *log);
static void ngx_expire_old_cached_files(ngx_open_file_cache_t *cache,
    ngx_uint_t n, ngx_log_t *log);
static void ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_open_file_cache_remove(ngx_event_t *ev);


ngx_open_file_cache_t *
ngx_open_file_cache_init(ngx_pool_t *pool, ngx_uint_t max, time_t inactive)
{
    ngx_pool_cleanup_t     *cln;
    ngx_open_file_cache_t  *cache;

    cache = ngx_palloc(pool, sizeof(ngx_open_file_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
                    ngx_open_file_cache_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    cache->current = 0;
    cache->max = max;
    cache->inactive = inactive;

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_open_file_cache_cleanup;
    cln->data = cache;

    return cache;
}


static void
ngx_open_file_cache_cleanup(void *data)
{
    ngx_open_file_cache_t  *cache = data;

    ngx_queue_t             *q;
    ngx_cached_open_file_t  *file;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "open file cache cleanup");

    for ( ;; ) {

        if (ngx_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = ngx_queue_last(&cache->expire_queue);

        file = ngx_queue_data(q, ngx_cached_open_file_t, queue);

        ngx_queue_remove(q);

        ngx_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "delete cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            file->count = 0;
            ngx_close_cached_file(cache, file, ngx_cycle->log);

        } else {
            ngx_free(file->name);
            ngx_free(file);
        }
    }

    if (cache->current) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "%d items still leave in open file cache",
                      cache->current);
    }

    if (cache->rbtree.root != cache->rbtree.sentinel) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "rbtree still is not empty in open file cache");

    }
}


ngx_int_t
ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool)
{
    time_t                          now;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_pool_cleanup_t             *cln;
    ngx_cached_open_file_t         *file;
    ngx_pool_cleanup_file_t        *clnf;
    ngx_open_file_cache_event_t    *fev;
    ngx_open_file_cache_cleanup_t  *ofcln;

    of->err = 0;

    if (cache == NULL) {

        cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_open_and_stat_file(name->data, of, pool->log);

        if (rc == NGX_OK && !of->is_dir) {
            cln->handler = ngx_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = of->fd;
            clnf->name = name->data;
            clnf->log = pool->log;
        }

        return rc;
    }

    cln = ngx_pool_cleanup_add(pool, sizeof(ngx_open_file_cache_cleanup_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_long(name->data, name->len);

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

    now = ngx_time();

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

        do {
            file = (ngx_cached_open_file_t *) node;

            rc = ngx_strcmp(name->data, file->name);

            if (rc == 0) {

                ngx_queue_remove(&file->queue);

                if (file->event || now - file->created < of->retest) {
                    if (file->err == 0) {
                        of->fd = file->fd;
                        of->uniq = file->uniq;
                        of->mtime = file->mtime;
                        of->size = file->size;

                        of->is_dir = file->is_dir;
                        of->is_file = file->is_file;
                        of->is_link = file->is_link;
                        of->is_exec = file->is_exec;

                        if (!file->is_dir) {
                            file->count++;
                        }

                    } else {
                        of->err = file->err;
                    }

                    goto found;
                }

                ngx_log_debug4(NGX_LOG_DEBUG_CORE, pool->log, 0,
                               "retest open file: %s, fd:%d, c:%d, e:%d",
                               file->name, file->fd, file->count, file->err);

                if (file->is_dir) {

                    /*
                     * chances that directory became file are very small
                     * so test_dir flag allows to use a single ngx_file_info()
                     * syscall instead of three syscalls
                     */

                    of->test_dir = 1;
                }

                rc = ngx_open_and_stat_file(name->data, of, pool->log);

                if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
                    goto failed;
                }

                if (of->is_dir) {
                    if (file->is_dir || file->err) {
                        goto update;
                    }

                    /* file became directory */

                } else if (of->err == 0) {  /* file */

                    if (file->is_dir || file->err) {
                        goto update;
                    }

                    if (of->uniq == file->uniq
                        && of->mtime == file->mtime
                        && of->size == file->size)
                    {
                        if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
                            ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                                          ngx_close_file_n " \"%s\" failed",
                                          name->data);
                        }

                        of->fd = file->fd;
                        file->count++;

                        goto renew;
                    }

                    /* file was changed */

                } else { /* error to cache */

                    if (file->err || file->is_dir) {
                        goto update;
                    }

                    /* file was removed, etc. */
                }

                if (file->count == 0) {
                    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
                        ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                                      ngx_close_file_n " \"%s\" failed",
                                      name->data);
                    }

                    goto update;
                }

                ngx_rbtree_delete(&cache->rbtree, &file->node);

                cache->current--;

                file->close = 1;

                goto create;
            }

            node = (rc < 0) ? node->left : node->right;

        } while (node != sentinel && hash == node->key);

        break;
    }

    /* not found */

    file = NULL;

    rc = ngx_open_and_stat_file(name->data, of, pool->log);

    if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
        goto failed;
    }

create:

    if (cache->current >= cache->max) {
        ngx_expire_old_cached_files(cache, 0, pool->log);
    }

    file = ngx_alloc(sizeof(ngx_cached_open_file_t), pool->log);

    if (file == NULL) {
        goto failed;
    }

    file->name = ngx_alloc(name->len + 1, pool->log);

    if (file->name == NULL) {
        ngx_free(file);
        file = NULL;
        goto failed;
    }

    ngx_cpystrn(file->name, name->data, name->len + 1);

    file->node.key = hash;

    ngx_rbtree_insert(&cache->rbtree, &file->node);

    cache->current++;

    file->count = 0;

update:

    if (of->events
        && (ngx_event_flags & NGX_USE_VNODE_EVENT)
        && of->fd != NGX_INVALID_FILE)
    {
        file->event = ngx_calloc(sizeof(ngx_event_t), pool->log);
        if (file->event== NULL) {
            goto failed;
        }

        fev = ngx_alloc(sizeof(ngx_open_file_cache_event_t), pool->log);
        if (fev == NULL) {
            goto failed;
        }

        fev->fd = of->fd;
        fev->file = file;
        fev->cache = cache;

        file->event->handler = ngx_open_file_cache_remove;
        file->event->data = fev;

        /*
         * although vnode event may be called while ngx_cycle->poll
         * destruction; however, cleanup procedures are run before any
         * memory freeing and events will be canceled.
         */

        file->event->log = ngx_cycle->log;

        if (ngx_add_event(file->event, NGX_VNODE_EVENT, NGX_ONESHOT_EVENT)
            != NGX_OK)
        {
            ngx_free(file->event->data);
            ngx_free(file->event);
            goto failed;
        }

    } else {
        file->event = NULL;
    }

    file->fd = of->fd;
    file->err = of->err;

    if (of->err == 0) {
        file->uniq = of->uniq;
        file->mtime = of->mtime;
        file->size = of->size;

        file->close = 0;

        file->is_dir = of->is_dir;
        file->is_file = of->is_file;
        file->is_link = of->is_link;
        file->is_exec = of->is_exec;

        if (!of->is_dir) {
            file->count++;
        }
    }

renew:

    file->created = now;

found:

    file->accessed = now;

    ngx_queue_insert_head(&cache->expire_queue, &file->queue);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "cached open file: %s, fd:%d, c:%d, e:%d",
                   file->name, file->fd, file->count, file->err);

    if (of->err == 0) {

        if (!of->is_dir) {
            cln->handler = ngx_open_file_cleanup;
            ofcln = cln->data;

            ofcln->cache = cache;
            ofcln->file = file;
            ofcln->log = pool->log;
        }

        return NGX_OK;
    }

    return NGX_ERROR;

failed:

    if (file && file->count == 0) {
        ngx_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", file->name);
        }

        ngx_free(file->name);
        ngx_free(file);
    }

    if (of->fd != NGX_INVALID_FILE) {
        if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name->data);
        }
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_open_and_stat_file(u_char *name, ngx_open_file_info_t *of, ngx_log_t *log)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;

    of->fd = NGX_INVALID_FILE;

    if (of->test_dir) {

        if (ngx_file_info(name, &fi) == -1) {
            of->err = ngx_errno;

            return NGX_ERROR;
        }

        of->uniq = ngx_file_uniq(&fi);
        of->mtime = ngx_file_mtime(&fi);
        of->size = ngx_file_size(&fi);
        of->is_dir = ngx_is_dir(&fi);
        of->is_file = ngx_is_file(&fi);
        of->is_link = ngx_is_link(&fi);
        of->is_exec = ngx_is_exec(&fi);

        if (of->is_dir) {
            return NGX_OK;
        }
    }

    fd = ngx_open_file(name, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        of->err = ngx_errno;
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", name);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        return NGX_ERROR;
    }

    if (ngx_is_dir(&fi)) {
        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name);
        }

        fd = NGX_INVALID_FILE;
    }

    of->fd = fd;
    of->uniq = ngx_file_uniq(&fi);
    of->mtime = ngx_file_mtime(&fi);
    of->size = ngx_file_size(&fi);
    of->is_dir = ngx_is_dir(&fi);
    of->is_file = ngx_is_file(&fi);
    of->is_link = ngx_is_link(&fi);
    of->is_exec = ngx_is_exec(&fi);

    return NGX_OK;
}


static void
ngx_open_file_cleanup(void *data)
{
    ngx_open_file_cache_cleanup_t  *c = data;

    c->file->count--;

    ngx_close_cached_file(c->cache, c->file, c->log);

    /* drop one or two expired open files */
    ngx_expire_old_cached_files(c->cache, 1, c->log);
}


static void
ngx_close_cached_file(ngx_open_file_cache_t *cache,
    ngx_cached_open_file_t *file, ngx_log_t *log)
{
    ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                   "close cached open file: %s, fd:%d, c:%d, %d",
                   file->name, file->fd, file->count, file->close);

    if (!file->close) {

        file->accessed = ngx_time();

        ngx_queue_remove(&file->queue);

        ngx_queue_insert_head(&cache->expire_queue, &file->queue);

        return;
    }

    if (file->event) {
        (void) ngx_del_event(file->event, NGX_VNODE_EVENT,
                             file->count ? NGX_FLUSH_EVENT : NGX_CLOSE_EVENT);

        ngx_free(file->event->data);
        ngx_free(file->event);
        file->event = NULL;
    }

    if (file->count) {
        return;
    }

    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name);
    }

    ngx_free(file->name);
    ngx_free(file);
}


static void
ngx_expire_old_cached_files(ngx_open_file_cache_t *cache, ngx_uint_t n,
    ngx_log_t *log)
{
    time_t                   now;
    ngx_queue_t             *q;
    ngx_cached_open_file_t  *file;

    now = ngx_time();

    /*
     * n == 1 deletes one or two inactive files
     * n == 0 deletes least recently used file by force
     *        and one or two inactive files
     */

    while (n < 3) {

        if (ngx_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = ngx_queue_last(&cache->expire_queue);

        file = ngx_queue_data(q, ngx_cached_open_file_t, queue);

        if (n++ != 0 && now - file->accessed <= cache->inactive) {
            return;
        }

        ngx_queue_remove(q);

        ngx_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                       "expire cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            ngx_close_cached_file(cache, file, log);

        } else {
            ngx_free(file->name);
            ngx_free(file);
        }
    }
}


static void
ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (ngx_cached_open_file_t *) node;
            file_temp = (ngx_cached_open_file_t *) temp;

            p = (ngx_strcmp(file->name, file_temp->name) < 0)
                    ? &temp->left : &temp->right;
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


static void
ngx_open_file_cache_remove(ngx_event_t *ev)
{
    ngx_cached_open_file_t       *file;
    ngx_open_file_cache_event_t  *fev;

    fev = ev->data;
    file = fev->file;

    ngx_queue_remove(&file->queue);

    ngx_rbtree_delete(&fev->cache->rbtree, &file->node);

    fev->cache->current--;

    /* NGX_ONESHOT_EVENT was already deleted */
    file->event = NULL;

    file->close = 1;

    ngx_close_cached_file(fev->cache, file, ev->log);

    /* free memory only when fev->cache and fev->file are already not needed */

    ngx_free(ev->data);
    ngx_free(ev);
}
