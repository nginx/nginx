
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static int ngx_http_static_handler(ngx_http_request_t *r);
static int ngx_http_static_init(ngx_cycle_t *cycle);


static ngx_command_t  ngx_http_static_commands[] = {

    ngx_null_command
};



ngx_http_module_t  ngx_http_static_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};  


ngx_module_t  ngx_http_static_module = {
    NGX_MODULE,
    &ngx_http_static_module_ctx,           /* module context */
    ngx_http_static_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_static_init,                  /* init module */
    NULL                                   /* init child */
};


ngx_int_t ngx_http_static_translate_handler(ngx_http_request_t *r)
{
    char                      *location, *last, *path;
    uint32_t                   crc;
    ngx_int_t                  rc, level;
    ngx_str_t                  name;
    ngx_err_t                  err;
    ngx_http_cache_t          *cache;
    ngx_http_cache_conf_t     *ccf;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);


    if (r->uri.data[r->uri.len - 1] == '/') {

        /* there is no index handler */

        if (!(path = ngx_palloc(r->pool, clcf->doc_root.len + r->uri.len))) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_cpystrn(ngx_cpymem(path, clcf->doc_root.data, clcf->doc_root.len),
                    r->uri.data, r->uri.len + 1);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "directory index of \"%s\" is forbidden", path);

        return NGX_HTTP_FORBIDDEN;
    }


    /* "+ 2" is for a trailing '/' in a possible redirect and '\0' */
    ngx_test_null(name.data,
                  ngx_palloc(r->pool, clcf->doc_root.len + r->uri.len + 2),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    location = ngx_cpymem(name.data, clcf->doc_root.data, clcf->doc_root.len);
    last = ngx_cpystrn(location, r->uri.data, r->uri.len + 1);

    ngx_log_debug(r->connection->log, "HTTP filename: '%s'" _ data);


    if (r->cache == NULL) {

        /* look up an open files cache */

        ccf = ngx_http_get_module_loc_conf(r, ngx_http_cache_module);

        if (ccf->open_files) {
            cache = ngx_http_cache_get(ccf->open_files, &name, &crc);

            ngx_log_debug(r->connection->log, "cache get: %x" _ cache);

            if (cache
                && ((ngx_event_flags & NGX_HAVE_KQUEUE_EVENT)
                    || ccf->open_files->update
                                          >= ngx_cached_time - cache->updated))
            {
                r->cache = cache;
                r->content_handler = ngx_http_static_handler;

                return NGX_OK;
            }

        } else {
            cache = NULL;
        }

    } else {
        cache = r->cache;
    }


#if (WIN9X)

    if (ngx_win32_version < NGX_WIN_NT) {

        /*
         * there is no way to open a file or a directory in Win9X with
         * one syscall because Win9X has no FILE_FLAG_BACKUP_SEMANTICS flag
         * so we need to check its type before the opening
         */

        if (ngx_file_info(name.data, &r->file.info) == NGX_FILE_ERROR) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
                          ngx_file_info_n " \"%s\" failed", name.data);

            if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
                return NGX_HTTP_NOT_FOUND;

            } else if (err == NGX_EACCES) {
                return NGX_HTTP_FORBIDDEN;

            } else {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (ngx_is_dir(&r->file.info)) {
            ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ name.data);

            if (!(r->headers_out.location =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            *last++ = '/';
            *last = '\0';
            r->headers_out.location->key.len = 8;
            r->headers_out.location->key.data = "Location" ;
            r->headers_out.location->value.len = last - location;
            r->headers_out.location->value.data = location;

            return NGX_HTTP_MOVED_PERMANENTLY;
        }
    }

#endif


    if (r->file.fd == NGX_INVALID_FILE) {
        r->file.fd = ngx_open_file(r->file.name.data,
                                   NGX_FILE_RDONLY, NGX_FILE_OPEN);
    }

    if (r->file.fd == NGX_INVALID_FILE) {
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

        ngx_log_error(level, r->connection->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", r->file.name.data);

        return rc;
    }

ngx_log_debug(r->connection->log, "FILE: %d" _ r->file.fd);

    if (!r->file.info_valid) {
        if (ngx_fd_info(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_fd_info_n " \"%s\" failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              r->file.name.data);
            }

            r->file.fd = NGX_INVALID_FILE;

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.info_valid = 1;
    }

    if (ccf->open_files) {
        if (cache == NULL) {
            cache = ngx_http_cache_alloc(ccf->open_files, &r->file.name, crc,
                                         r->connection->log);
        }

ngx_log_debug(r->connection->log, "cache alloc: %x" _ cache);

        if (cache) {
            cache->fd = r->file.fd;
            cache->data.size = ngx_file_size(&r->file.info);
            cache->accessed = ngx_time();
            cache->last_modified = ngx_file_mtime(&r->file.info);
            cache->updated = ngx_time();
        }
    }

    if (ngx_is_dir(&r->file.info)) {
ngx_log_debug(r->connection->log, "HTTP DIR: '%s'" _ r->file.name.data);

        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", r->file.name.data);
        }

        r->file.fd = NGX_INVALID_FILE;
        r->file.info_valid = 0;

        if (!(r->headers_out.location =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *last++ = '/';
        *last = '\0';
#if 0
        r->headers_out.location->key.len = 8;
        r->headers_out.location->key.data = "Location" ;
#endif
        r->headers_out.location->value.len = last - location;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(WIN32) /* the not regular files are probably Unix specific */

    if (!ngx_is_file(&r->file.info)) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                      "%s is not a regular file", r->file.name.data);

        if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR)
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_file_n " %s failed", r->file.name.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    r->content_handler = ngx_http_static_handler;

    return NGX_OK;
}


static int ngx_http_static_handler(ngx_http_request_t *r)
{
    int                        rc, key, i;
    ngx_log_e                  level;
    ngx_err_t                  err;
    ngx_hunk_t                *h;
    ngx_chain_t                out;
    ngx_http_type_t           *type;
    ngx_http_cleanup_t        *cleanup;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    rc = ngx_http_discard_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ctx = r->connection->log->data;
    ctx->action = "sending response to client";

    if (!(cleanup = ngx_push_array(&r->cleanup))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->file.fd == NGX_INVALID_FILE) {
        r->file.fd = ngx_open_file(r->file.name.data,
                                   NGX_FILE_RDONLY, NGX_FILE_OPEN);

        if (r->file.fd == NGX_INVALID_FILE) {
            err = ngx_errno;

            if (err == NGX_ENOENT || err == NGX_ENOTDIR) {
                level = NGX_LOG_ERR;
                rc = NGX_HTTP_NOT_FOUND;

            } else {
                level = NGX_LOG_CRIT;
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_log_error(level, r->connection->log, ngx_errno,
                          ngx_open_file_n " %s failed", r->file.name.data);
            return rc;
        }
    }

    cleanup->data.file.fd = r->file.fd;
    cleanup->data.file.name = r->file.name.data;
    cleanup->cache = 0;

    if (!r->file.info_valid) {
        if (ngx_fd_info(r->file.fd, &r->file.info) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_fd_info_n " %s failed", r->file.name.data);

            if (ngx_close_file(r->file.fd) == NGX_FILE_ERROR)
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                              ngx_close_file_n " %s failed", r->file.name.data);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->file.info_valid = 1;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_file_size(&r->file.info);
    r->headers_out.last_modified_time = ngx_file_mtime(&r->file.info);

    if (!(r->headers_out.content_type =
                   ngx_http_add_header(&r->headers_out, ngx_http_headers_out)))
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.content_type->key.len = 0;
    r->headers_out.content_type->key.data = NULL;
    r->headers_out.content_type->value.len = 0;
    r->headers_out.content_type->value.data = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r->exten.len) {
        ngx_http_types_hash_key(key, r->exten);

        type = (ngx_http_type_t *) clcf->types[key].elts;
        for (i = 0; i < clcf->types[key].nelts; i++) {
            if (r->exten.len != type[i].exten.len) {
                continue;
            }

            if (ngx_strcasecmp(r->exten.data, type[i].exten.data) == 0) {
                r->headers_out.content_type->value.len = type[i].type.len;
                r->headers_out.content_type->value.data = type[i].type.data;

                break;
            }
        }
    }

    if (r->headers_out.content_type->value.len == 0) {
        r->headers_out.content_type->value.len = clcf->default_type.len;
        r->headers_out.content_type->value.data = clcf->default_type.data;
    }

    /* we need to allocate all before the header would be sent */

    ngx_test_null(h, ngx_pcalloc(r->pool, sizeof(ngx_hunk_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    ngx_test_null(h->file, ngx_pcalloc(r->pool, sizeof(ngx_file_t)),
                  NGX_HTTP_INTERNAL_SERVER_ERROR);

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    h->type = r->main ? NGX_HUNK_FILE : NGX_HUNK_FILE|NGX_HUNK_LAST;

    h->file_pos = 0;
    h->file_last = ngx_file_size(&r->file.info);

    h->file->fd = r->file.fd;
    h->file->log = r->connection->log;

    out.hunk = h;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static int ngx_http_static_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_conf_ctx_t        *ctx;
    ngx_http_core_main_conf_t  *cmcf;
    
    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    
    ngx_test_null(h, ngx_push_array(
                             &cmcf->phases[NGX_HTTP_TRANSLATE_PHASE].handlers),
                  NGX_ERROR);
    *h = ngx_http_static_translate_handler;

    return NGX_OK;
}

