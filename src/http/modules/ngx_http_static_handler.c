
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_cache_hash_t  *redirect_cache;
} ngx_http_static_loc_conf_t;


static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);
static void *ngx_http_static_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_static_merge_loc_conf(ngx_conf_t *cf,
                                            void *parent, void *child);
static ngx_int_t ngx_http_static_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_static_commands[] = {

#if (NGX_HTTP_CACHE)

    { ngx_string("redirect_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_set_cache_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_static_loc_conf_t, redirect_cache),
      NULL },

#endif

      ngx_null_command
};



ngx_http_module_t  ngx_http_static_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    
    ngx_http_static_create_loc_conf,       /* create location configuration */
    ngx_http_static_merge_loc_conf         /* merge location configuration */
};  


ngx_module_t  ngx_http_static_module = {
    NGX_MODULE,
    &ngx_http_static_module_ctx,           /* module context */
    ngx_http_static_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_static_init,                  /* init module */
    NULL                                   /* init child */
};


static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                      *last;
    ngx_fd_t                     fd;
    ngx_int_t                    rc;
    ngx_uint_t                   level;
    ngx_str_t                    name, location;
    ngx_err_t                    err;
    ngx_log_t                   *log;
    ngx_buf_t                   *b;
    ngx_chain_t                  out;
    ngx_file_info_t              fi;
    ngx_http_cleanup_t          *file_cleanup, *redirect_cleanup;
    ngx_http_log_ctx_t          *ctx;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_static_loc_conf_t  *slcf;
#if (NGX_HTTP_CACHE)
    uint32_t                     file_crc, redirect_crc;
    ngx_http_cache_t            *file, *redirect;
#endif

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        return rc;
    }

#if (NGX_HTTP_CACHE)

    /*
     * there is a valid cached open file, i.e by the index handler,
     * and it should be already registered in r->cleanup
     */

    if (r->cache && !r->cache->expired) {
        return ngx_http_send_cached(r);
    }

#endif

    log = r->connection->log;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * make a file name, reserve 2 bytes for a trailing '/'
     * in a possible redirect and for the last '\0'
     */

    if (clcf->alias) {
        name.data = ngx_palloc(r->pool, clcf->root.len + r->uri.len + 2
                                        - clcf->name.len);
        if (name.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        last = ngx_cpymem(name.data, clcf->root.data, clcf->root.len);
        last = ngx_cpystrn(last, r->uri.data + clcf->name.len,
                           r->uri.len + 1 - clcf->name.len);

        name.len = last - name.data;

        location.data = ngx_palloc(r->pool, r->uri.len + 2);
        if (location.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        last = ngx_cpystrn(location.data, r->uri.data, r->uri.len + 1);

#if 0
        /*
         * aliases usually have trailling "/",
         * set it in the start of the possible redirect
         */

        if (*location.data != '/') {
            location.data--;
        }
#endif

        location.len = last - location.data + 1;

    } else {
        name.data = ngx_palloc(r->pool, clcf->root.len + r->uri.len + 2);
        if (name.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        location.data = ngx_cpymem(name.data, clcf->root.data, clcf->root.len);
        last = ngx_cpystrn(location.data, r->uri.data, r->uri.len + 1);

        name.len = last - name.data;
        location.len = last - location.data + 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", name.data);


    /* allocate cleanups */

    if (!(file_cleanup = ngx_push_array(&r->cleanup))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    file_cleanup->valid = 0;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_static_module);
    if (slcf->redirect_cache) {
        if (!(redirect_cleanup = ngx_push_array(&r->cleanup))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        redirect_cleanup->valid = 0;

    } else {
        redirect_cleanup = NULL;
    }

#if (NGX_HTTP_CACHE)

    /* look up an open files cache */

    if (clcf->open_files) {
        file = ngx_http_cache_get(clcf->open_files, file_cleanup,
                                  &name, &file_crc);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http open file cache get: " PTR_FMT, file);

        if (file && !file->expired) {
            r->cache = file;
            return ngx_http_send_cached(r);
        }

    } else {
        file = NULL;
    }


    /* look up an redirect cache */

    if (slcf->redirect_cache) {
        redirect = ngx_http_cache_get(slcf->redirect_cache, redirect_cleanup,
                                      &name, &redirect_crc);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http redirect cache get: " PTR_FMT, redirect);

        if (redirect && !redirect->expired) {

            /*
             * We do not copy a cached value so the cache entry is locked
             * until the end of the request.  In a single threaded model
             * the redirected request should complete before other event
             * will be processed.  In a multithreaded model this locking
             * should keep more popular redirects in cache.
             */

            if (!(r->headers_out.location =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->headers_out.location->value = redirect->data.value;

            return NGX_HTTP_MOVED_PERMANENTLY;
        }

    } else {
        redirect = NULL;
    }

#endif

    /* open file */

#if (WIN9X)

    /* TODO: redirect cache */

    if (ngx_win32_version < NGX_WIN_NT) {

        /*
         * there is no way to open a file or a directory in Win9X with
         * one syscall because Win9X has no FILE_FLAG_BACKUP_SEMANTICS flag
         * so we need to check its type before the opening
         */

        if (ngx_file_info(name.data, &fi) == NGX_FILE_ERROR) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ERR, log, err,
                          ngx_file_info_n " \"%s\" failed", name.data);

            if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
                return NGX_HTTP_NOT_FOUND;

            } else if (err == NGX_EACCES) {
                return NGX_HTTP_FORBIDDEN;

            } else {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_is_dir(&fi)) {
            ngx_log_debug(log, "HTTP DIR: '%s'" _ name.data);

            if (!(r->headers_out.location =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            *last++ = '/';
            *last = '\0';
            r->headers_out.location->value.len = last - location;
            r->headers_out.location->value.data = location;

            return NGX_HTTP_MOVED_PERMANENTLY;
        }
    }

#endif


    fd = ngx_open_file(name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;

        } else if (err == NGX_EACCES) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, log, err,
                      ngx_open_file_n " \"%s\" failed", name.data);

        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", fd);

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      ngx_fd_info_n " \"%s\" failed", name.data);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name.data);
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_is_dir(&fi)) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name.data);
        }

        *last++ = '/';
        *last = '\0';

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->value = location;

#if (NGX_HTTP_CACHE)

        if (slcf->redirect_cache) {
            if (redirect) {
                if (location.len == redirect->data.value.len
                    && ngx_memcmp(redirect->data.value.data, location.data,
                                                            location.len) == 0)
                {
                    redirect->accessed = ngx_cached_time;
                    redirect->updated = ngx_cached_time;

                    /*
                     * we can unlock the cache entry because
                     * we have the local copy anyway
                     */

                    ngx_http_cache_unlock(slcf->redirect_cache, redirect, log);
                    redirect_cleanup->valid = 0;

                    return NGX_HTTP_MOVED_PERMANENTLY;
                }
            }

            location.len++;
            redirect = ngx_http_cache_alloc(slcf->redirect_cache, redirect,
                                            redirect_cleanup,
                                            &name, redirect_crc,
                                            &location, log);
            location.len--;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "http redirect cache alloc: " PTR_FMT, redirect);

            if (redirect) {
                redirect->fd = NGX_INVALID_FILE;
                redirect->accessed = ngx_cached_time;
                redirect->last_modified = 0;
                redirect->updated = ngx_cached_time;
                redirect->memory = 1;
                ngx_http_cache_unlock(slcf->redirect_cache, redirect, log);
                redirect_cleanup->valid = 0;
            }

        }

#endif

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(WIN32) /* the not regular files are probably Unix specific */

    if (!ngx_is_file(&fi)) {
        ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
                      "%s is not a regular file", name.data);

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", name.data);
        }

        return NGX_HTTP_NOT_FOUND;
    }

#endif


#if (NGX_HTTP_CACHE)

    if (clcf->open_files) {

#if (NGX_USE_HTTP_FILE_CACHE_UNIQ)

        if (file && file->uniq == ngx_file_uniq(&fi)) {
            if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed", name.data);
            }
            file->accessed = ngx_cached_time;
            file->updated = ngx_cached_time;
            file->expired = 0;
            r->cache = file;

            return ngx_http_send_cached(r);

        } else {
            if (file) {
                ngx_http_cache_unlock(clcf->open_files, file, log);
                file = NULL;
            }

            file = ngx_http_cache_alloc(clcf->open_files, file,
                                        file_cleanup,
                                        &name, file_crc, NULL, log);
            if (file) {
                file->uniq = ngx_file_uniq(&fi);
            }
        }

#else
        file = ngx_http_cache_alloc(clcf->open_files, file,
                                    file_cleanup,
                                    &name, file_crc, NULL, log);
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http open file cache alloc: " PTR_FMT, file);

        if (file) {
            file->fd = fd;
            file->data.size = ngx_file_size(&fi);
            file->accessed = ngx_cached_time;
            file->last_modified = ngx_file_mtime(&fi);
            file->updated = ngx_cached_time;
            r->cache = file;
        }

        return ngx_http_send_cached(r);
    }

#endif

    ctx = log->data;
    ctx->action = "sending response to client";

    file_cleanup->data.file.fd = fd;
    file_cleanup->data.file.name = name.data;
    file_cleanup->valid = 1;
    file_cleanup->cache = 0;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_file_size(&fi);
    r->headers_out.last_modified_time = ngx_file_mtime(&fi);

    if (r->headers_out.content_length_n == 0) {
        r->header_only = 1;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if (NGX_SUPPRESS_WARN)
    b = NULL;
#endif

    if (!r->header_only) {
        /* we need to allocate all before the header would be sent */

        if (!(b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t)))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (!(b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t)))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->filter_allow_ranges = 1;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->in_file = 1;

    if (!r->main) {
        b->last_buf = 1;
    }

    b->file_pos = 0;
    b->file_last = ngx_file_size(&fi);

    b->file->fd = fd;
    b->file->log = log;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static void *ngx_http_static_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_static_loc_conf_t  *conf;

    if (!(conf = ngx_palloc(cf->pool, sizeof(ngx_http_static_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    conf->redirect_cache = NULL;

    return conf;
}


static char *ngx_http_static_merge_loc_conf(ngx_conf_t *cf,
                                            void *parent, void *child)
{
    ngx_http_static_loc_conf_t  *prev = parent;
    ngx_http_static_loc_conf_t  *conf = child;

    if (conf->redirect_cache == NULL) {
        conf->redirect_cache = prev->redirect_cache;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_static_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    
    h = ngx_push_array(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_static_handler;

    return NGX_OK;
}
