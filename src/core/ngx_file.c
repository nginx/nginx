
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


static ngx_atomic_uint_t  ngx_temp_number;
static ngx_atomic_uint_t  ngx_random_number;


ssize_t
ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain)
{
    ngx_int_t  rc;

    if (tf->file.fd == NGX_INVALID_FILE) {
        rc = ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                  tf->persistent, tf->mode);

        if (rc == NGX_ERROR || rc == NGX_AGAIN) {
            return rc;
        }

        if (tf->log_level) {
            ngx_log_error(tf->log_level, tf->file.log, 0, "%s %V",
                          tf->warn, &tf->file.name);
        }
    }

    return ngx_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
}


ngx_int_t
ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path, ngx_pool_t *pool,
    ngx_uint_t persistent, ngx_uint_t mode)
{
    ngx_err_t                 err;
    ngx_atomic_uint_t         n;
    ngx_pool_cleanup_t       *cln;
    ngx_pool_cleanup_file_t  *clnf;

    file->name.len = path->name.len + 1 + path->len + NGX_ATOMIC_T_LEN;

    file->name.data = ngx_palloc(pool, file->name.len + 1);
    if (file->name.data == NULL) {
        return NGX_ERROR;
    }

#if 0
    for (i = 0; i < file->name.len; i++) {
         file->name.data[i] = 'X';
    }
#endif

    ngx_memcpy(file->name.data, path->name.data, path->name.len);

    n = ngx_next_temp_number(0);

    for ( ;; ) {
        (void) ngx_sprintf(file->name.data + path->name.len + 1 + path->len,
                           "%0muA%Z", n);

        ngx_create_hashed_filename(file, path);

        cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        file->fd = ngx_open_tempfile(file->name.data, persistent, mode);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

        if (file->fd != NGX_INVALID_FILE) {

            cln->handler = ngx_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return NGX_OK;
        }

        err = ngx_errno;

        if (err == NGX_EEXIST) {
            n = ngx_next_temp_number(1);
            continue;
        }

        if ((path->level[0] == 0)
            || (err != NGX_ENOENT
#if (NGX_WIN32)
                && err != NGX_ENOTDIR
#endif
            ))
        {
            ngx_log_error(NGX_LOG_CRIT, file->log, err,
                          ngx_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return NGX_ERROR;
        }

        if (ngx_create_path(file, path) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
}


void
ngx_create_hashed_filename(ngx_file_t *file, ngx_path_t *path)
{
    size_t      name, pos, level;
    ngx_uint_t  i;

    name = file->name.len;
    pos = path->name.len + 1;

    file->name.data[path->name.len + path->len]  = '/';

    for (i = 0; i < 3; i++) {
        level = path->level[i];

        if (level == 0) {
            break;
        }

        name -= level;
        file->name.data[pos - 1] = '/';
        ngx_memcpy(&file->name.data[pos], &file->name.data[name], level);
        pos += level + 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "hashed path: %s", file->name.data);
}


ngx_int_t
ngx_create_path(ngx_file_t *file, ngx_path_t *path)
{
    size_t      pos;
    ngx_err_t   err;
    ngx_uint_t  i;

    pos = path->name.len;

    for (i = 0; i < 3; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                       "temp file: \"%s\"", file->name.data);

        if (ngx_create_dir(file->name.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, file->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              file->name.data);
                return NGX_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return NGX_OK;
}


ngx_err_t
ngx_create_full_path(u_char *dir, ngx_uint_t access)
{
    u_char     *p, ch;
    ngx_err_t   err;

    for (p = dir + 1; *p; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (ngx_create_dir(dir, access) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                return err;
            }
        }

        *p = '/';
    }

    return 0;
}


void
ngx_init_temp_number(void)
{
    ngx_temp_number = 0;
    ngx_random_number = 123456;
}


ngx_atomic_uint_t
ngx_next_temp_number(ngx_uint_t collision)
{
    if (collision) {
        ngx_temp_number += ngx_random_number;
    }

    return ngx_temp_number++;
}


char *
ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t      level;
    ngx_str_t   *value;
    ngx_uint_t   i, n;
    ngx_path_t  *path, **slot;

    slot = (ngx_path_t **) (p + cmd->offset);

    if (*slot) {
        return "is duplicate";
    }

    path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &path->name) == NGX_ERROR) {
        return NULL;
    }

    path->len = 0;
    path->cleaner = (ngx_gc_handler_pt) cmd->post;
    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
        level = ngx_atoi(value[n].data, value[n].len);
        if (level == NGX_ERROR || level == 0) {
            return "invalid value";
        }

        path->level[i] = level;
        path->len += level + 1;
    }

    while (i < 3) {
        path->level[i++] = 0;
    }

    *slot = path;

    if (ngx_add_path(cf, slot) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot)
{
    ngx_uint_t   i, n;
    ngx_path_t  *path, **p;

    path = *slot;

    p = cf->cycle->pathes.elts;
    for (i = 0; i < cf->cycle->pathes.nelts; i++) {
        if (p[i]->name.len == path->name.len
            && ngx_strcmp(p[i]->name.data, path->name.data) == 0)
        {
            for (n = 0; n < 3; n++) {
                if (p[i]->level[n] != path->level[n]) {
                    if (path->conf_file == NULL) {
                        if (p[i]->conf_file == NULL) {
                            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "the default path name \"%V\" has "
                                      "the same name as another default path, "
                                      "but the different levels, you need to "
                                      "redefine one of them in http section",
                                      &p[i]->name);
                            return NGX_ERROR;
                        }

                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "the path name \"%V\" in %s:%ui has "
                                      "the same name as default path, but "
                                      "the different levels, you need to "
                                      "define default path in http section",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                        return NGX_ERROR;
                    }

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                      "the same path name \"%V\" in %s:%ui "
                                      "has the different levels than",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                    return NGX_ERROR;
                }

                if (p[i]->level[n] == 0) {
                    break;
                }
            }

            *slot = p[i];

            return NGX_OK;
        }
    }

    p = ngx_array_push(&cf->cycle->pathes);
    if (p == NULL) {
        return NGX_ERROR;
    }

    *p = path;

    return NGX_OK;
}


ngx_int_t
ngx_create_pathes(ngx_cycle_t *cycle, ngx_uid_t user)
{
    ngx_err_t         err;
    ngx_uint_t        i;
    ngx_path_t      **path;
#if !(NGX_WIN32)
    ngx_file_info_t   fi;
#endif

    path = cycle->pathes.elts;
    for (i = 0; i < cycle->pathes.nelts; i++) {

        if (ngx_create_dir(path[i]->name.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              path[i]->name.data);
                return NGX_ERROR;
            }
        }

        if (user == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
            continue;
        }

#if !(NGX_WIN32)

        if (ngx_file_info((const char *) path[i]->name.data, &fi) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          ngx_file_info_n " \"%s\" failed", path[i]->name.data);
            return NGX_ERROR;
        }

        if (fi.st_uid != user) {
            if (chown((const char *) path[i]->name.data, user, -1) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "chown(\"%s\", %d) failed",
                              path[i]->name.data, user);
                return NGX_ERROR;
            }
        }

        if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))
                                                  != (S_IRUSR|S_IWUSR|S_IXUSR))
        {
            fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);

            if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "chmod() \"%s\" failed", path[i]->name.data);
                return NGX_ERROR;
            }
        }

#endif
    }

    return NGX_OK;
}
