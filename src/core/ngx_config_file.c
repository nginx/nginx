
#include <ngx_config.h>

#include <ngx_core.h>

#include <ngx_config_file.h>


static int argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2
};

#if 1

int ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
{
    int    rc;
    char  *error;
    ngx_fd_t  fd;
    ngx_conf_file_t  *prev;

    if (filename) {

        fd = ngx_open_file(filename->data, NGX_FILE_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          "ngx_conf_file: "
                          ngx_open_file_n " %s failed", filename->data);
            return NGX_ERROR;
        }

        prev = cf->conf_file;
        ngx_test_null(cf->conf_file,
                      ngx_palloc(cf->pool, sizeof(ngx_conf_file_t)),
                      NGX_ERROR);

        if (ngx_stat_fd(fd, &cf->conf_file->file.info) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          "ngx_conf_file: "
                          ngx_stat_fd_n " %s failed", filename->data);
        }

        ngx_test_null(cf->conf_file->hunk,
                      ngx_create_temp_hunk(cf->pool, 1024, 0, 0),
                      NGX_ERROR);

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.log = cf->log;;
        cf->conf_file->line = 1;
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

            if ((*cf->handler)(cf) == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

#if 0
        cmd = ngx_conf_find_token(cf);
        if (cmd == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unknown directive \"%s\" in %s:%d",
                          cf->name, cf->file->name, cf->file->line);
            return NGX_ERROR;
        }

        if (cmd->type & argument_number[cf->args->nelts - 1]) {
            error = cmd->set(cf, cmd->offset, cf->args);

            if (error) {
                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                               "%s in directive \"%s\" in %s:%d",
                               error, cf->name, cf->file->name, cf->file->line);
                return NGX_ERROR;
            }
        }
#endif

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
#endif
    }

    if (filename) {
        cf->conf_file = prev;

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          cf->conf_file->file.name.data);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif

#if 1

int ngx_conf_read_token(ngx_conf_t *cf)
{
    char        *start, ch, *src, *dst;
    int          found, need_space, last_space, len, quoted, s_quoted, d_quoted;
    ssize_t      n;
    ngx_str_t   *word;
    ngx_hunk_t  *h;

    found = 0;
    need_space = 0;
    last_space = 1;
    quoted = s_quoted = d_quoted = 0;

    cf->args->nelts = 0;
    h = cf->conf_file->hunk;
    start = h->pos.mem;

ngx_log_debug(cf->log, "TOKEN START");

    for ( ;; ) {

        if (h->pos.mem >= h->last.mem) {
            if (cf->conf_file->file.offset
                                  >= ngx_file_size(cf->conf_file->file.info)) {
                return NGX_FILE_DONE;
            }

            if (h->pos.mem - start) {
                ngx_memcpy(h->start, start, h->pos.mem - start);
            }

            n = ngx_read_file(&cf->conf_file->file,
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

        ch = *h->pos.mem++;

#if 0
ngx_log_debug(cf->log, "%d:%d:%d:%d:%d '%c'" _
              last_space _ need_space _
              quoted _ s_quoted _ d_quoted _ ch);
#endif

        if (ch == LF) {
            cf->conf_file->line++;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';' || ch == '{') {
                return NGX_OK;
            }

            return NGX_ERROR;
        }

        if (last_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            start = h->pos.mem - 1;

            switch (ch) {

            case ';':
            case '{':
                return NGX_OK;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{') {
                last_space = 1;
                found = 1;
            }

            if (found) {
                ngx_test_null(word, ngx_push_array(cf->args), NGX_ERROR);
                ngx_test_null(word->data,
                              ngx_palloc(cf->pool, h->pos.mem - start + 1),
                              NGX_ERROR);

                for (dst = word->data, src = start, len = 0;
                     src < h->pos.mem - 1;
                     len++)
                {
                    if (*src == '\\') {
                        src++;
                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

ngx_log_debug(cf->log, "FOUND %d:'%s'" _ word->len _ word->data);

                if (ch == ';' || ch == '{') {
                    return NGX_OK;
                }

                found = 0;
            }
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
