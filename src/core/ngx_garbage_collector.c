
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_garbage_collector.h>


int ngx_garbage_collector_temp_handler(ngx_gc_t *ctx, ngx_str_t *name,
                                       ngx_dir_t *dir);


static int ngx_collect_garbage(ngx_gc_t *ctx, ngx_str_t *dname, int level);



#if 0

{
    ngx_test_null(cycle->timer_events,
                  ngx_alloc(sizeof(ngx_event_t) * TIMERS, cycle->log),
                  NGX_ERROR);

    ngx_event_timer_init(cycle);
}


void garbage_collector()
{
    ngx_msec_t        timer;
    struct timeval    tv;
    ngx_epoch_msec_t  delta;

    for ( ;; ) {
        timer = ngx_event_find_timer();

        ngx_gettimeofday(&tv);
        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000;

        msleep(timer);

        ngx_gettimeofday(&tv);

        ngx_cached_time = tv.tv_sec;
        ngx_time_update();

        delta = tv.tv_sec * 1000 + tv.tv_usec / 1000 - delta;

        ngx_event_expire_timers((ngx_msec_t) delta);
    }
}

#endif


void stub_init(ngx_cycle_t *cycle)
{
    ngx_uint_t    i;
    ngx_gc_t      ctx;
    ngx_path_t  **path;

    path = cycle->pathes.elts;
    for (i = 0; i < cycle->pathes.nelts; i++) {
        ctx.path = path[i];
        ctx.log = cycle->log;
        ctx.handler = path[i]->gc_handler;

        ngx_collect_garbage(&ctx, &path[i]->name, 0);
    }
}


static int ngx_collect_garbage(ngx_gc_t *ctx, ngx_str_t *dname, int level)
{
    int         rc;
    u_char     *last;
    size_t      len;
    ngx_err_t   err;
    ngx_str_t   fname, buf;
    ngx_dir_t   dir;

    buf.len = 0;
#if (NGX_SUPPRESS_WARN)
    buf.data = NULL;
    fname.data = NULL;
#endif

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "gc dir \"%s\":%d", dname->data, dname->len);

    if (ngx_open_dir(dname, &dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_open_dir_n " \"%s\" failed", dname->data);
        return NGX_ERROR;
    }

    for ( ;; ) {
        ngx_set_errno(0);
        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, ctx->log, err,
                              ngx_read_dir_n " \"%s\" failed", dname->data);
                rc = NGX_ERROR;

            } else {
                rc = NGX_OK;
            }

            break;
        }

        len = ngx_de_namelen(&dir);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                      "gc name \"%s\":%d", ngx_de_name(&dir), len);

        if (len == 1 && ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        if (len == 2
            && ngx_de_name(&dir)[0] == '.'
            && ngx_de_name(&dir)[1] == '.')
        {
            continue;
        }

        fname.len = dname->len + 1+ len;

        if (fname.len + NGX_DIR_MASK_LEN > buf.len) {

            if (buf.len) {
                ngx_free(buf.data);
            }

            buf.len = dname->len + 1 + len + NGX_DIR_MASK_LEN;

            if (!(buf.data = ngx_alloc(buf.len + 1, ctx->log))) {
                return NGX_ABORT;
            }
        }

        last = ngx_cpymem(buf.data, dname->data, dname->len);
        *last++ = '/';
        ngx_memcpy(last, ngx_de_name(&dir), len + 1);
        fname.data = buf.data;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                       "gc path: \"%s\"", fname.data);

        if (!dir.info_valid) {
            if (ngx_de_info(fname.data, &dir) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                              ngx_de_info_n " \"%s\" failed", fname.data);
                continue;
            }
        }

        if (ngx_de_is_dir(&dir)) {

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                           "gc enter dir \"%s\"", fname.data);

            if (level == -1
                   /* there can not be directory on the last level */
                || level == NGX_MAX_PATH_LEVEL
                   /* an directory from the old path hierarchy */
                || len != ctx->path->level[level])
            {
                if (ngx_collect_garbage(ctx, &fname, -1) == NGX_ABORT) {
                    return NGX_ABORT;
                }

                fname.data[fname.len] = '\0';

                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                              "delete old hierachy directory \"%s\"",
                              fname.data);

                if (ngx_delete_dir(fname.data) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                                  ngx_delete_dir_n " \"%s\" failed",
                                  fname.data);
                } else {
                    ctx->deleted++;
                    ctx->freed += ngx_de_size(&dir);
                }

                continue;
            }

            if (ngx_collect_garbage(ctx, &fname, level + 1) == NGX_ABORT) {
                return NGX_ABORT;
            }

        } else if (ngx_de_is_file(&dir)) {

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                           "gc file \"%s\"", fname.data);

            if (level == -1
                || (level < NGX_MAX_PATH_LEVEL && ctx->path->level[level] != 0))
            {
                if (ngx_delete_file(fname.data) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                                  ngx_delete_file_n " \"%s\" failed",
                                  fname.data);
                } else {
                    ctx->deleted++;
                    ctx->freed += ngx_de_size(&dir);
                }

                continue;
            }

            if (ctx->handler(ctx, &fname, &dir) == NGX_ABORT) {
                return NGX_ABORT;
            }

        } else {
            ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                          "\"%s\" has unknown file type, deleting", fname.data);

            if (ngx_delete_file(fname.data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                              ngx_delete_file_n " \"%s\" failed", fname.data);
            } else {
                ctx->deleted++;
                ctx->freed += ngx_de_size(&dir);
            }
        }
    }

    if (buf.len) {
        ngx_free(buf.data);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", fname.data);
    }

    return rc;
}


int ngx_garbage_collector_temp_handler(ngx_gc_t *ctx, ngx_str_t *name,
                                       ngx_dir_t *dir)
{
    /*
     * We use mtime only and do not use atime because:
     *    on NTFS access time has a resolution of 1 hour,
     *    on NT FAT access time has a resolution of 1 day,
     *    Unices have the mount option "noatime".
     */

    if (ngx_time() - ngx_de_mtime(dir) < 3600) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                  "delete stale temporary \"%s\"", name->data);

    if (ngx_delete_file(name->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name->data);
        return NGX_ERROR;
    }

    ctx->deleted++;
    ctx->freed += ngx_de_size(dir);

    return NGX_OK;
}
