
#include <ngx_config.h>
#include <ngx_core.h>



#define MAX_CONF_ERRSTR  256

/* Ten fixed arguments */

static int argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7,
    NGX_CONF_TAKE8,
    NGX_CONF_TAKE9,
};

static int ngx_conf_read_token(ngx_conf_t *cf);


char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
{
    int               m, rc, found, valid;
    char             *rv;
    void             *conf, **confp;
    ngx_str_t        *name;
    ngx_fd_t          fd;
    ngx_conf_file_t  *prev;
    ngx_command_t    *cmd;

#if (NGX_SUPPRESS_WARN)
    fd = NGX_INVALID_FILE;
    prev = NULL;
#endif

    if (filename) {

        /* open configuration file */

        fd = ngx_open_file(filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN);
        if (fd == NGX_INVALID_FILE) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          ngx_open_file_n " %s failed", filename->data);
            return NGX_CONF_ERROR;
        }

        prev = cf->conf_file;
        ngx_test_null(cf->conf_file,
                      ngx_palloc(cf->pool, sizeof(ngx_conf_file_t)),
                      NGX_CONF_ERROR);

        if (ngx_stat_fd(fd, &cf->conf_file->file.info) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                          ngx_stat_fd_n " %s failed", filename->data);
        }

        ngx_test_null(cf->conf_file->hunk,
                      ngx_create_temp_hunk(cf->pool, 1024),
                      NGX_CONF_ERROR);

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.offset = 0;
        cf->conf_file->file.log = cf->log;;
        cf->conf_file->line = 1;
    }

    for ( ;; ) {
        rc = ngx_conf_read_token(cf);

        /* ngx_conf_read_token() returns NGX_OK, NGX_ERROR,
           NGX_CONF_FILE_DONE or NGX_CONF_BLOCK_DONE */

#if 0
ngx_log_debug(cf->log, "token %d" _ rc);
#endif

        if (rc == NGX_ERROR) {
            break;
        }

        if (rc != NGX_OK) {
            break;
        }

        if (cf->handler) {

            /* custom handler, i.e. used in http "types { ... }" directive */

            rv = (*cf->handler)(cf, NULL, cf->handler_conf);
            if (rv == NGX_CONF_OK) {
                continue;

            } else if (rv == NGX_CONF_ERROR) {
                rc = NGX_ERROR;
                break;

            } else {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                             "%s in %s:%d",
                             rv,
                             cf->conf_file->file.name.data,
                             cf->conf_file->line);
                rc = NGX_ERROR;
                break;
            }
        }

        name = (ngx_str_t *) cf->args->elts;
        found = 0;

        for (m = 0; rc != NGX_ERROR && !found && ngx_modules[m]; m++) {

            /* look up the directive in the appropriate modules */

            if (ngx_modules[m]->type != NGX_CONF_MODULE
                && ngx_modules[m]->type != cf->module_type)
            {
                continue;
            }

            cmd = ngx_modules[m]->commands;
            if (cmd == NULL) {
                continue;
            }

            while (cmd->name.len) {
                if (name->len == cmd->name.len
                    && ngx_strcmp(name->data, cmd->name.data) == 0)
                {

                    found = 1;
#if 0
ngx_log_debug(cf->log, "command '%s'" _ cmd->name.data);
#endif
                    /* is the directive's location right ? */

                    if ((cmd->type & cf->cmd_type) == 0) {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "directive \"%s\" in %s:%d "
                                      "is not allowed here",
                                      name->data,
                                      cf->conf_file->file.name.data,
                                      cf->conf_file->line);
                        rc = NGX_ERROR;
                        break;
                    }

                    /* is the directive's argument count right ? */

                    if (cmd->type & NGX_CONF_ANY) {
                        valid = 1;

                    } else if (cmd->type & NGX_CONF_FLAG) {

                        if (cf->args->nelts == 2) {
                            valid = 1;
                        } else {
                            valid = 0;
                        }

                    } else if (cmd->type & NGX_CONF_1MORE) {

                        if (cf->args->nelts != 1) {
                            valid = 1;
                        } else {
                            valid = 0;
                        }

                    } else if (cf->args->nelts <= 10
                               && (cmd->type
                                   & argument_number[cf->args->nelts - 1]))
                    {
                        valid = 1;

                    } else {
                        valid = 0;
                    }

                    if (!valid) {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "invalid number arguments in "
                                      "directive \"%s\" in %s:%d",
                                      name->data,
                                      cf->conf_file->file.name.data,
                                      cf->conf_file->line);
                        rc = NGX_ERROR;
                        break;
                    }

                    /* set up the directive's configuration context */

                    conf = NULL;

                    if (cf->module_type == NGX_CORE_MODULE) {
                        conf = &(((void **) cf->ctx)[ngx_modules[m]->index]);

                    } else if (cf->ctx) {
                        confp = *(void **) ((char *) cf->ctx + cmd->conf);

                        if (confp) {
                            conf = confp[ngx_modules[m]->ctx_index];
                        }
                    }

                    rv = cmd->set(cf, cmd, conf);

#if 0
ngx_log_debug(cf->log, "rv: %d" _ rv);
#endif

                    if (rv == NGX_CONF_OK) {
                        break;

                    } else if (rv == NGX_CONF_ERROR) {
                        rc = NGX_ERROR;
                        break;

                    } else {
                        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                                      "\"%s\" directive %s in %s:%d",
                                      name->data, rv,
                                      cf->conf_file->file.name.data,
                                      cf->conf_file->line);

                        rc = NGX_ERROR;
                        break;
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

            rc = NGX_ERROR;
            break;
        }

        if (rc == NGX_ERROR) {
            break;
        }
    }

    if (filename) {
        cf->conf_file = prev;

        if (ngx_close_file(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
                          ngx_close_file_n " %s failed",
                          cf->conf_file->file.name.data);
            return NGX_CONF_ERROR;
        }
    }

    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
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
    start = h->pos;

#if 0
ngx_log_debug(cf->log, "TOKEN START");
#endif

    for ( ;; ) {

        if (h->pos >= h->last) {
            if (cf->conf_file->file.offset
                                  >= ngx_file_size(cf->conf_file->file.info)) {
                return NGX_CONF_FILE_DONE;
            }

            if (h->pos - start) {
                ngx_memcpy(h->start, start, h->pos - start);
            }

            n = ngx_read_file(&cf->conf_file->file,
                              h->start + (h->pos - start),
                              h->end - (h->start + (h->pos - start)),
                              cf->conf_file->file.offset);

            if (n == NGX_ERROR) {
                return NGX_ERROR;
            }

            h->pos = h->start + (h->pos - start);
            start = h->start;
            h->last = h->pos + n;
        }

        ch = *h->pos++;

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

            start = h->pos - 1;

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
                              ngx_palloc(cf->pool, h->pos - start + 1),
                              NGX_ERROR);

                for (dst = word->data, src = start, len = 0;
                     src < h->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        src++;
                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

#if 0
ngx_log_debug(cf->log, "FOUND %d:'%s'" _ word->len _ word->data);
#endif

                if (ch == ';' || ch == '{') {
                    return NGX_OK;
                }

                found = 0;
            }
        }
    }
}


ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name)
{
    int               i;
    ngx_open_file_t  *file;

    if (name) {
        file = cycle->open_files.elts;
        for (i = 0; i < cycle->open_files.nelts; i++) {
            if (name->len != file[i].name.len) {
                continue;
            }

            if (ngx_strcmp(name->data, file[i].name.data) == 0) {
                return &file[i];
            }
        }
    }

    ngx_test_null(file, ngx_push_array(&cycle->open_files), NULL);
    file->fd = NGX_INVALID_FILE;
    if (name) {
        file->name = *name;
    }

    return file;
}


void ngx_conf_log_error(int level, ngx_conf_t *cf, ngx_err_t err,
                        char *fmt, ...)
{
    int      len;
    char     errstr[MAX_CONF_ERRSTR];
    va_list  args;

    va_start(args, fmt);
    len = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    if (err) {
        len += ngx_snprintf(errstr + len, sizeof(errstr) - len - 1,
                            " (%d: ", err);
        len += ngx_strerror_r(err, errstr + len, sizeof(errstr) - len - 1);
        errstr[len++] = ')';
        errstr[len++] = '\0';
    }

    ngx_log_error(level, cf->log, 0, "%s in %s:%d",
                  errstr, cf->conf_file->file.name.data, cf->conf_file->line);
}


char *ngx_conf_set_core_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    return ngx_conf_set_flag_slot(cf, cmd, *(void **)conf);
}


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int         flag;
    ngx_str_t  *value;


    if (*(int *) (p + cmd->offset) != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    if (ngx_strcasecmp(value[1].data, "on") == 0) {
        flag = 1;

    } else if (ngx_strcasecmp(value[1].data, "off") == 0) {
        flag = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    *(int *) (p + cmd->offset) = flag;

    return NGX_CONF_OK;
}


char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t  *field, *value;

    field = (ngx_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    *field = value[1];

    return NGX_CONF_OK;
}


char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int              *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (int *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;
    *np = ngx_atoi(value[1].data, value[1].len);
    if (*np == NGX_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int              *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (int *) (p + cmd->offset);
    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    *np = ngx_parse_size(&value[1]);
    if (*np == NGX_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int              *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (int *) (p + cmd->offset);
    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    *np = ngx_parse_time(&value[1], 0);
    if (*np == NGX_ERROR) {
        return "invalid value";
    }

    if (*np == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 597 hours";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int              *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (int *) (p + cmd->offset);
    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    *np = ngx_parse_time(&value[1], 1);
    if (*np == NGX_ERROR) {
        return "invalid value";
    }

    if (*np == NGX_PARSE_LARGE_TIME) {
        return "value must be less than 68 years";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;

    ngx_str_t   *value;
    ngx_bufs_t  *bufs;


    bufs = (ngx_bufs_t *) (p + cmd->offset);
    if (bufs->num) {
        return "is duplicate";
    }

    value = (ngx_str_t *) cf->args->elts;

    bufs->num = ngx_atoi(value[1].data, value[1].len);
    if (bufs->num == NGX_ERROR || bufs->num == 0) {
        return "invalid value";
    }

    bufs->size = ngx_parse_size(&value[2]);
    if (bufs->size == NGX_ERROR || bufs->size == 0) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    int                 *np, i, m;
    ngx_str_t           *value;
    ngx_conf_bitmask_t  *mask;


    np = (int *) (p + cmd->offset);
    value = (ngx_str_t *) cf->args->elts;
    mask = cmd->post;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                && ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


char *ngx_conf_unsupported(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return "unsupported on this platform";
}


char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data)
{
    ngx_conf_num_bounds_t *bounds = post;
    int *np = data;

    if (*np >= bounds->low && (u_int) *np <= (u_int) bounds->high) {
        return NGX_CONF_OK;
    }

    return "invalid value";
}
