
#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_gc_s  ngx_gc_t;

typedef int (*ngx_gc_handler_pt) (ngx_gc_t *ctx, ngx_str_t *name,
                                  ngx_file_info_t *fi);

struct ngx_gc_s {
    ngx_path_t         *path;
    u_int               deleted;
    off_t               freed;
    ngx_gc_handler_pt   handler;
    ngx_log_t          *log;
};


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


void stub_init(ngx_log_t *log)
{
    ngx_gc_t    *ctx;
    ngx_path_t   path;

    if (!(ctx = ngx_alloc(sizeof(ngx_gc_t), log))) {
        return;
    }

    path.name.len = 4;
    path.name.data = "temp";
    path.len = 5;
    path.level[0] = 1;
    path.level[1] = 2;
    path.level[2] = 0;

    ctx->path = &path;
    ctx->log = log;

    ngx_collect_garbage(ctx, &path.name, 0);
}


static int ngx_collect_garbage(ngx_gc_t *ctx, ngx_str_t *dname, int level)
{
    int               nlen;
    char             *last;
    ngx_str_t         fname;
    ngx_dir_t        *dir;
    ngx_dirent_t     *de;
    ngx_file_info_t   fi;

    fname.len = 0;

ngx_log_debug(ctx->log, "dir %s" _ dname->data);

    dir = ngx_open_dir(dname->data);

    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
                     ngx_open_dir_n " \"%s\" failed", dname->data);
        return NGX_ERROR;
    }

    for ( ;; ) {
        de = ngx_read_dir(dir);

        if (de == NULL) {
            if (fname.len) {
                ngx_free(fname.data);
            }
            break;
        }

ngx_log_debug(ctx->log, "file %s" _ de->d_name);

#ifdef __FreeBSD__
        nlen = de->d_namlen;
#else
        nlen = ngx_strlen(de->d_name);
#endif

        if (nlen == 1 && de->d_name[0] == '.') {
            continue;
        }

        if (nlen == 2 && de->d_name[0] == '.' && de->d_name[1] == '.') {
            continue;
        }

        if (dname->len + 1 + nlen > fname.len) {
            if (fname.len) {
                ngx_free(fname.data);
            }

            fname.len = dname->len + 1 + nlen;

            if (!(fname.data = ngx_alloc(fname.len + 1, ctx->log))) {
                return NGX_ABORT;
            }
        }

        last = ngx_cpymem(fname.data, dname->data, dname->len);
        *last++ = '/';
        ngx_memcpy(last, de->d_name, nlen + 1);

ngx_log_debug(ctx->log, "de %s" _ fname.data);

        if (ngx_file_type(fname.data, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                          ngx_file_type_n " \"%s\" failed", fname.data);
            continue;
        }

        if (ngx_is_dir((&fi))) {

ngx_log_debug(ctx->log, "enter %s" _ fname.data);

            if (level == -1
                   /* there can not be directory on the last level */
                || level == NGX_MAX_PATH_LEVEL
                   /* an directory from the old path hierarchy */
                || nlen != ctx->path->level[level])
            {
                if (ngx_collect_garbage(ctx, &fname, -1) == NGX_ABORT) {
                    return NGX_ABORT;
                }

                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0,
                              "delete old hierachy directory \"%s\"",
                              fname.data);

                if (ngx_delete_dir(fname.data) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                                  ngx_delete_dir_n " \"%s\" failed",
                                  fname.data);
                } else {
                    ctx->deleted++;
                    ctx->freed += ngx_file_size((&fi));
                }

                continue;
            }

            if (ngx_collect_garbage(ctx, &fname, level + 1) == NGX_ABORT) {
                return NGX_ABORT;
            }

        } else if (ngx_is_file((&fi))) {

            if (level == -1
                || (level < NGX_MAX_PATH_LEVEL && ctx->path->level[level] != 0))
            {
                if (ngx_delete_file(fname.data) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                                  ngx_delete_file_n " \"%s\" failed",
                                  fname.data);
                } else {
                    ctx->deleted++;
                    ctx->freed += ngx_file_size((&fi));
                }

                continue;
            }

            if (ctx->handler(ctx, &fname, &fi) == NGX_ABORT) {
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
                ctx->freed += ngx_file_size((&fi));
            }
        }
    }

    return NGX_OK;
}


int ngx_garbage_collector_temp_handler(ngx_gc_t *ctx, ngx_str_t *name,
                                       ngx_file_info_t *fi)
{
    /*
     * we use mtime only and do not use atime because:
     *    on NTFS access time has a resolution of 1 hour,
     *    on NT FAT access time has a resolution of 1 day,
     *    Unices have mount option "noatime"
     */

    if (ngx_cached_time - ngx_file_mtime(fi) < 3600) {
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
    ctx->freed += ngx_file_size(fi);
    return NGX_OK;
}
