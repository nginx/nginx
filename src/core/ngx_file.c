
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_array.h>
#include <ngx_file.h>
#include <ngx_files.h>


static int ngx_temp_number;
static int ngx_random;


int ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path,
                         ngx_pool_t *pool, int persistent)
{
    int        num;
    ngx_err_t  err;

    file->name.len = path->name.len + 1 + path->len + 10;

    ngx_test_null(file->name.data, ngx_palloc(pool, file->name.len + 1),
                  NGX_ERROR);

#if 0
    for (i = 0; i < file->name.len; i++) {
         file->name.data[i] = 'X';
    }
#endif

    ngx_memcpy(file->name.data, path->name.data, path->name.len);

    num = ngx_next_temp_number(0);

    for ( ;; ) {
        ngx_snprintf(file->name.data + path->name.len + 1 + path->len, 11,
                     "%010u", num);

        ngx_create_hashed_filename(file, path);

#if 0
#if (WIN32)
        file->fd = CreateFile(file->name.data,
                        GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                        NULL,
                        CREATE_NEW,
                        persistent ? 0:
                            FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,
                        NULL);
#else
        file->fd = open(file->name.data, O_CREAT|O_EXCL|O_WRONLY, 0600);
#endif
#endif

        file->fd = ngx_open_tempfile(file->name.data, persistent);

ngx_log_debug(file->log, "temp fd: %d" _ file->fd);

        if (file->fd != NGX_INVALID_FILE) {
            return NGX_OK;
        }

        err = ngx_errno;

        if (err == NGX_EEXIST) {
            num = ngx_next_temp_number(1);
            continue;
        }

        if (err != NGX_ENOENT
#if (WIN32_NEED_TEST)
            && err != NGX_ENOTDIR
#endif
        ) {
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


void ngx_create_hashed_filename(ngx_file_t *file, ngx_path_t *path)
{
    int        i, name, pos, level;

    name = file->name.len;
    pos = path->name.len + 1;

    file->name.data[path->name.len + path->len]  = '/';

    for (i = 0; i < 3; i++) {
        level = path->level[i];

        if (level == 0) {
            break;
        }

        ngx_log_debug(file->log, "temp: %s" _ file->name.data);

        name -= level;
        file->name.data[pos - 1] = '/';
        ngx_memcpy(&file->name.data[pos], &file->name.data[name], level);
        pos += level + 1;
    }

    ngx_log_debug(file->log, "temp: %s" _ file->name.data);
}


int ngx_create_path(ngx_file_t *file, ngx_path_t *path)
{
    int        i, pos;
    ngx_err_t  err;

    pos = path->name.len;

    for (i = 0; i < 3; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        ngx_log_debug(file->log, "temp: %s" _ file->name.data);

        if (ngx_mkdir(file->name.data) == NGX_FILE_ERROR) {
            err = ngx_errno;
            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, file->log, err,
                              ngx_mkdir_n " \"%s\" failed", file->name.data);
                return NGX_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return NGX_OK;
}


void ngx_init_temp_number()
{
    ngx_random = 0;

    ngx_temp_number = ngx_random;

    while (ngx_random < 10000) {
        ngx_random = 123456;
    }
}


int ngx_next_temp_number(int collision)
{
    if (collision) {
        ngx_temp_number += ngx_random;
    }

    return ngx_temp_number++;
}
