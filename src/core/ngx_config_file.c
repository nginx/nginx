
#include <ngx_config.h>

#include <ngx_core.h>

#include <ngx_config_file.h>


static int argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2
};

#if 0

int ngx_conf_parse(ngx_conf_t *cf, char *filename)
{
    int    rc;
    char  *error;
    ngx_fd_t  fd;
    ngx_conf_file_t  *prev;

    if (filename) {

        fd = ngx_open_file(filename, NGX_FILE_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          "ngx_conf_open: "
                          ngx_open_file_n " %s failed", filename);
            return NGX_ERROR;
        }

        prev = cf->file;
        ngx_test_null(cf->file, ngx_palloc(cf->pool, sizeof(ngx_conf_file_t)),
                      NGX_ERROR);

        cf->file->fd = fd;
        cf->file->name = filename;
        cf->file->line = 1;
        cf->file->pos = 0;
    }

    for ( ;; ) {
        rc = ngx_conf_read_token(cf);

        /* ??? NGX_OK, NGX_ERROR, NGX_CONF_FILE_DONE, NGX_CONF_BLOCK_DONE */

        if (rc != NGX_OK) {
            return rc;
        }

        /* ????
           "listen address:port;"
           "location /images/ {" */

        if (cf->handler) {

            if (*(cf->handler)(cf) == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

        cmd = ngx_conf_find_token(cf);
        if (cmd == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unknown directive \"%s\" in %s:%d",
                          cf->name, cf->file->name, cf->file->line);
            return NGX_ERROR;
        }

        if (cmd->type & argument_number[cf->args->nelts]) {
            error = cmd->set(cf, cmd->offset, cf->args);

            if (error) {
                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                               "%s in directive \"%s\" in %s:%d",
                               error, cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }
        }

#if 0
        if (cmd->type == NGX_CONF_CONTAINER) {
            ngx_conf_parse(cf, cmd->container, NULL);

        } else if (cmd->type == NGX_CONF_FLAG) {

            if (cf->args->nelts != 1) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid number of arguments "
                              "in directive \"%s\" in %s:%d",
                              cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }

            if (ngx_strcasecmp(cf->args->elts[0], "on") == 0) {
                flag = 1;

            } else if (ngx_strcasecmp(cf->args->elts[0], "off") == 0) {
                flag = 0;

            } else {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid flag in directive \"%s\" in %s:%d",
                              cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }

            rv = cmd->set(cf, cmd->offset, flag);
            if (rv) {
                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                               "%s in directive \"%s\" in %s:%d",
                               rv, cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }

        } else if (cmd->type & argument_number[args->nelts]) {
            rv = cmd->set(cf, cmd->offset, cf->args);
            if (rv) {
                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                               "%s in directive \"%s\" in %s:%d",
                               rv, cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }

        } else {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "invalid number of arguments "
                          "in directive \"%s\" in %s:%d",
                          cf->name, cf->file->name, cf->file->line);
            return NGX_ERROR;
        }
    }
#endif

    if (filename) {
        cf->file = prev;

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                          ngx_close_file_n " %s failed", cf->name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}    

#endif

#if 0

int ngx_conf_read_token(ngx_conf_t *cf)
{
    char        *start, ch, *src, *dst;
    int          n, need_space, last_space, len, quoted, s_quoted, d_quoted;
    ngx_hunk_t  *h;

    need_space = 0;
    last_space = 1;
    len = 0;
    quoted = s_quoted = d_quoted = 0;

    cf->args->nelts = 0;
    h = cf->conf_file->hunk;

    for (start = h->pos.mem; /* end_of_file */ ; h->pos.mem++) {

        if (h->pos.mem >= h->last.mem) {
            if (h->pos.mem - start) {
                ngx_memcpy(h->start, start, h->pos.mem - start);
            }

            n = ngx_read_file(cf->conf_file->file,
                              h->start + (h->pos.mem - start),
                              h->end - (h->start + (h->pos.mem - start)),
                              cf->conf_file->file.offset);

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            h->pos.mem = h->start + (h->pos.mem - start);
            start = h->start;
            h->last.mem = h->pos.mem + n;
        }

        ch = *h->pos.mem;

        if (ch == LF) {
            cf->conf_file->line++;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        len++;

        if (last_space) {
            start = h->pos.mem;

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                start++;
                continue;
            }
        }

        if (ch = '\\') {
            quoted = 1;
            continue;
        }

        if (d_quoted) {

            if (ch == '"') {
                d_quoted = 0;
                need_space = 1;
                last_space = 1;
                continue;
            }

        } else if (s_quoted) {

            if (ch == '\'') {
                s_quoted = 0;
                need_space = 1;
                last_space = 1;
                continue;
            }

        } else {

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                ngx_test_null(word, ngx_push_array(cf->args), NGX_ERROR);
                ngx_test_null(word->data, ngx_palloc(cf->temp_pool, len + 1),
                              NGX_ERROR);
                word->len = len;

                for (dst = word->data, src = start; src < h->pos; /* void */) {
                    if (*src == '\\')
                        src++;
                    *dst++ = *src++;
                }
                *dst = '\0';

                need_space = 0;
                last_space = 1;
                continue;
            }

            if (need_space) {
                return NGX_ERROR;
            }

            if (ch == ';') {
                return NGX_OK;
            }

            if (ch == '{') {
                return NGX_OK;
            }

            if (ch == '}') {
                return NGX_BLOCK_DONE;
            }

            if (last_space) {
                if (ch == '"') {
                    d_quoted = 1;
                    continue;
                }

                if (ch == '\'') {
                    s_quoted = 1;
                    continue;
                }
            }

            last_space = 0;
        }
    }
}

#endif

char *ngx_conf_set_size_slot(char *conf, int offset, char *value)
{
    int size;

    size = atoi(value);
    if (size < 0)
        return "value must be greater or equal to zero";

    *(int *) (conf + offset) = size;
    return NULL;
}

char *ngx_conf_set_time_slot(char *conf, int offset, char *value)
{
    int size;

    size = atoi(value);
    if (size < 0)
        return "value must be greater or equal to zero";

    *(int *) (conf + offset) = size;
    return NULL;
}
