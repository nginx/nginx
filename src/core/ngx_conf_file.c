
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_conf_file.h>


static int argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2
};

static int ngx_conf_read_token(ngx_conf_t *cf);


char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
{
    int               i, rc, found;
    char             *rv;
    void             *conf, **pconf;
    ngx_str_t        *name;
    ngx_fd_t          fd;
    ngx_conf_file_t  *prev;
    ngx_command_t    *cmd;

    if (filename) {

        fd = ngx_open_file(filename->data, NGX_FILE_RDONLY);
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          "ngx_conf_file: "
                          ngx_open_file_n " %s failed", filename->data);
            return NGX_CONF_ERROR;
        }

        prev = cf->conf_file;
        ngx_test_null(cf->conf_file,
                      ngx_palloc(cf->pool, sizeof(ngx_conf_file_t)),
                      NGX_CONF_ERROR);

        if (ngx_stat_fd(fd, &cf->conf_file->file.info) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          "ngx_conf_file: "
                          ngx_stat_fd_n " %s failed", filename->data);
        }

        ngx_test_null(cf->conf_file->hunk,
                      ngx_create_temp_hunk(cf->pool, 1024, 0, 0),
                      NGX_CONF_ERROR);

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.log = cf->log;;
        cf->conf_file->line = 1;
    }

    for ( ;; ) {
        rc = ngx_conf_read_token(cf);

        /* NGX_OK, NGX_ERROR, NGX_CONF_FILE_DONE, NGX_CONF_BLOCK_DONE */

ngx_log_debug(cf->log, "token %d" _ rc);

        if (rc == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (rc != NGX_OK) {
            return NGX_CONF_OK;
        }

        if (cf->handler) {

            if ((*cf->handler)(cf) == NGX_CONF_ERROR) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        name = (ngx_str_t *) cf->args->elts;
        found = 0;

        for (i = 0; !found && ngx_modules[i]; i++) {
            if (ngx_modules[i]->type != NULL
                && ngx_modules[i]->type != cf->type)
            {
                continue;
            }

            cmd = ngx_modules[i]->commands;
            if (cmd == NULL) {
                continue;
            }

            while (cmd->name.len) {
                if (name->len == cmd->name.len
                    && ngx_strcmp(name->data, cmd->name.data) == 0)
                {

ngx_log_debug(cf->log, "command '%s'" _ cmd->name.data);

                    if (!(cmd->type & argument_number[cf->args->nelts - 1])) {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "invalid number arguments in "
                                      "directive \"%s\" in %s:%d",
                                      name->data,
                                      cf->conf_file->file.name.data,
                                      cf->conf_file->line);
                        return NGX_CONF_ERROR;
                    }

                    conf = NULL;
                    if (cf->ctx) {
                        pconf = *(void **) ((char *) cf->ctx + cmd->conf);

                        if (pconf) {
                            conf = pconf[ngx_modules[i]->index];
                        }
                    }

                    rv = cmd->set(cf, cmd, conf);

ngx_log_debug(cf->log, "rv: %d" _ rv);

                    if (rv == NGX_CONF_OK) {
                        found = 1;
                        break;

                    } else if (rv == NGX_CONF_ERROR) {
                        return NGX_CONF_ERROR;

                    } else {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                     "%s", rv);
                        return NGX_CONF_ERROR;
                    }
                }

                cmd++;
            }
        }

        if (!found) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unknown directive \"%s\" in %s:%d",
                          name->data,
                          cf->conf_file->file.name.data,
                          cf->conf_file->line);

            return NGX_CONF_ERROR;
        }
    }

    if (filename) {
        cf->conf_file = prev;

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          cf->conf_file->file.name.data);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static int ngx_conf_read_token(ngx_conf_t *cf)
{
    char        *start, ch, *src, *dst;
    int          len;
    int          found, need_space, last_space, sharp_comment;
    int          quoted, s_quoted, d_quoted;
    ssize_t      n;
    ngx_str_t   *word;
    ngx_hunk_t  *h;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    quoted = s_quoted = d_quoted = 0;

    cf->args->nelts = 0;
    h = cf->conf_file->hunk;
    start = h->pos.mem;

ngx_log_debug(cf->log, "TOKEN START");

    for ( ;; ) {

        if (h->pos.mem >= h->last.mem) {
            if (cf->conf_file->file.offset
                                  >= ngx_file_size(cf->conf_file->file.info)) {
                return NGX_CONF_FILE_DONE;
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

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
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
                if (cf->args->nelts == 0) {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                  "unexpected '%c' in %s:%d",
                                  ch, cf->conf_file->file.name.data,
                                  cf->conf_file->line);
                    return NGX_ERROR;
                }

                return NGX_OK;

            case '}':
                if (cf->args->nelts > 0) {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                  "unexpected '}' in %s:%d",
                                  cf->conf_file->file.name.data,
                                  cf->conf_file->line);
                    return NGX_ERROR;
                }

                return NGX_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

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


char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    ngx_str_t  *field, *value;

    field = (ngx_str_t *) conf + cmd->offset;
    value = (ngx_str_t *) cf->args->elts;

    field->len = value->len;
    field->data = value->data;

    return NGX_CONF_OK;
}


char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    int         size;
    ngx_str_t  *value;

    value = (ngx_str_t *) cf->args->elts;

    size = atoi(value[1].data);
    if (size < 0) {
        return "value must be greater or equal to zero";
    }

    *(int *) (conf + cmd->offset) = size;

    return NGX_CONF_OK;
}


char *ngx_conf_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, char *conf)
{
    int         size;
    ngx_str_t  *value;

    value = (ngx_str_t *) cf->args->elts;

    size = atoi(value[1].data);
    if (size < 0) {
        return "value must be greater or equal to zero";
    }

    *(int *) (conf + cmd->offset) = size;

    return NGX_CONF_OK;
}
