
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static u_char *ngx_http_log_addr(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data);
static u_char *ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data);
static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data);
static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data);
static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data);
static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf,
                                    uintptr_t data);
static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
                                   uintptr_t data);
static u_char *ngx_http_log_length(ngx_http_request_t *r, u_char *buf,
                                   uintptr_t data);
static u_char *ngx_http_log_apache_length(ngx_http_request_t *r, u_char *buf,
                                          uintptr_t data);
static u_char *ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
                                      uintptr_t data);
static u_char *ngx_http_log_connection_header_out(ngx_http_request_t *r,
                                                  u_char *buf, uintptr_t data);
static u_char *ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r,
                                                         u_char *buf,
                                                         uintptr_t data);
static u_char *ngx_http_log_unknown_header_in(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data);
static u_char *ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data);
static u_char *ngx_http_log_unknown_header_out(ngx_http_request_t *r, u_char *buf,
                                               uintptr_t data);

static ngx_int_t ngx_http_log_pre_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf);
static ngx_int_t ngx_http_log_parse_format(ngx_conf_t *cf, ngx_array_t *ops,
                                           ngx_str_t *line);


static ngx_command_t  ngx_http_log_commands[] = {

    {ngx_string("log_format"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
     ngx_http_log_set_format,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},

    {ngx_string("access_log"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
     ngx_http_log_set_log,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command
};


ngx_http_module_t  ngx_http_log_module_ctx = {
    ngx_http_log_pre_conf,                 /* pre conf */

    ngx_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_loc_conf,          /* create location configration */
    ngx_http_log_merge_loc_conf            /* merge location configration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


static ngx_str_t http_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_str_t ngx_http_combined_fmt =
    ngx_string("%addr - - [%time] \"%request\" %status %apache_length "
               "\"%{Referer}i\" \"%{User-Agent}i\"");


ngx_http_log_op_name_t ngx_http_log_fmt_ops[] = {
    { ngx_string("addr"), INET_ADDRSTRLEN - 1, ngx_http_log_addr },
    { ngx_string("conn"), NGX_INT32_LEN, ngx_http_log_connection },
    { ngx_string("pipe"), 1, ngx_http_log_pipe },
    { ngx_string("time"), sizeof("28/Sep/1970:12:00:00") - 1,
                          ngx_http_log_time },
    { ngx_string("msec"), TIME_T_LEN + 4, ngx_http_log_msec },
    { ngx_string("request"), 0, ngx_http_log_request },
    { ngx_string("status"), 3, ngx_http_log_status },
    { ngx_string("length"), NGX_OFF_T_LEN, ngx_http_log_length },
    { ngx_string("apache_length"), NGX_OFF_T_LEN, ngx_http_log_apache_length },
    { ngx_string("i"), NGX_HTTP_LOG_ARG, ngx_http_log_header_in },
    { ngx_string("o"), NGX_HTTP_LOG_ARG, ngx_http_log_header_out },
    { ngx_null_string, 0, NULL }
};


ngx_int_t ngx_http_log_handler(ngx_http_request_t *r)
{
    ngx_uint_t                i, l;
    uintptr_t                 data;
    u_char                   *line, *p;
    size_t                    len;
    ngx_http_log_t           *log;
    ngx_http_log_op_t        *op;
    ngx_http_log_loc_conf_t  *lcf;
#if (WIN32)
    u_long                    written;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log handler");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);

    if (lcf->off) {
        return NGX_OK;
    }

    log = lcf->logs->elts;
    for (l = 0; l < lcf->logs->nelts; l++) {

        len = 0;
        op = log[l].ops->elts;
        for (i = 0; i < log[l].ops->nelts; i++) {
            if (op[i].len == 0) {
                len += (size_t) op[i].op(r, NULL, op[i].data);

            } else {
                len += op[i].len;
            }
        }

#if (WIN32)
        len += 2;
#else
        len++;
#endif

        ngx_test_null(line, ngx_palloc(r->pool, len), NGX_ERROR);
        p = line;

        for (i = 0; i < log[l].ops->nelts; i++) {
            if (op[i].op == NGX_HTTP_LOG_COPY_SHORT) {
                len = op[i].len;
                data = op[i].data;
                while (len--) {
                    *p++ = (char) (data & 0xff);
                    data >>= 8;
                }

            } else if (op[i].op == NGX_HTTP_LOG_COPY_LONG) {
                p = ngx_cpymem(p, (void *) op[i].data, op[i].len);

            } else {
                p = op[i].op(r, p, op[i].data);
            }
        }

#if (WIN32)
        *p++ = CR; *p++ = LF;
        WriteFile(log[l].file->fd, line, p - line, &written, NULL);
#else
        *p++ = LF;
        write(log[l].file->fd, line, p - line);
#endif
    }

    return NGX_OK;
}


static u_char *ngx_http_log_addr(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data)
{
    return ngx_cpymem(buf, r->connection->addr_text.data,
                      r->connection->addr_text.len);
}


static u_char *ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
                                     uintptr_t data)
{
    return buf + ngx_snprintf((char *) buf, NGX_INT_T_LEN + 1,
                              "%" NGX_UINT_T_FMT,
                              r->connection->number);
}


static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}


static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
                                 uintptr_t data)
{
    struct timeval  tv;

    ngx_gettimeofday(&tv);

    return buf + ngx_snprintf((char *) buf, TIME_T_LEN + 5, "%ld.%03ld",
                              tv.tv_sec, tv.tv_usec / 1000);
}


static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf,
                                    uintptr_t data)
{
    if (buf == NULL) {
        /* find the request line length */
        return (u_char *) r->request_line.len;
    }

    return ngx_cpymem(buf, r->request_line.data, r->request_line.len);
}


static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
                                   uintptr_t data)
{
    return buf + ngx_snprintf((char *) buf, 4, "%" NGX_UINT_T_FMT,
                        r->err_status ? r->err_status : r->headers_out.status);
}


static u_char *ngx_http_log_length(ngx_http_request_t *r, u_char *buf,
                                   uintptr_t data)
{
    return buf + ngx_snprintf((char *) buf, NGX_OFF_T_LEN + 1, OFF_T_FMT,
                              r->connection->sent);
}


static u_char *ngx_http_log_apache_length(ngx_http_request_t *r, u_char *buf,
                                          uintptr_t data)
{
    return buf + ngx_snprintf((char *) buf, NGX_OFF_T_LEN + 1, OFF_T_FMT,
                              r->connection->sent - r->header_size);
}


static u_char *ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
                                      uintptr_t data)
{
    ngx_uint_t          i;
    ngx_str_t          *s;
    ngx_table_elt_t    *h;
    ngx_http_log_op_t  *op;

    if (r) {
        h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

        if (h == NULL) {

            /* no header */

            if (buf) {
                *buf = '-';
            }

            return buf + 1;
        }

        if (buf == NULL) {
            /* find the header length */
            return (u_char *) h->value.len;
        }

        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /* find an offset while a format string compilation */

    op = (ngx_http_log_op_t *) buf;
    s = (ngx_str_t *) data;

    op->len = 0;

    for (i = 0; ngx_http_headers_in[i].name.len != 0; i++) {
        if (ngx_http_headers_in[i].name.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_in[i].name.data, s->data, s->len)
                                                                          == 0)
        {
            op->op = ngx_http_log_header_in;
            op->data = ngx_http_headers_in[i].offset;
            return NULL;
        }
    }

    op->op = ngx_http_log_unknown_header_in;
    op->data = (uintptr_t) s;

    return NULL;
}


static u_char *ngx_http_log_unknown_header_in(ngx_http_request_t *r,
                                              u_char *buf, uintptr_t data)
{
    ngx_uint_t        i;
    ngx_str_t        *s;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    s = (ngx_str_t *) data;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, s->data, s->len) == 0) {
            if (buf == NULL) {
                /* find the header length */
                return (u_char *) h[i].value.len;
            }

            return ngx_cpymem(buf, h[i].value.data, h[i].value.len);
        }
    }

    /* no header */

    if (buf) {
        *buf = '-';
    }

    return buf + 1;
}


static u_char *ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
                                       uintptr_t data)
{
    ngx_uint_t          i;
    ngx_str_t          *s;
    ngx_table_elt_t    *h;
    ngx_http_log_op_t  *op;

    if (r) {

        /* run-time execution */

        if (r->http_version < NGX_HTTP_VERSION_10) {
            if (buf) {
                *buf = '-';
            }

            return buf + 1;
        }

        h = *(ngx_table_elt_t **) ((char *) &r->headers_out + data);

        if (h == NULL) {

            /*
             * No header pointer was found.
             * However, some headers: "Date", "Server", "Content-Length",
             * and "Last-Modified" have a special handling in the header filter
             * but we do not set up their pointers in the filter because
             * they are too seldom needed to be logged.
             */

            if (data == offsetof(ngx_http_headers_out_t, date)) {
                if (buf == NULL) {
                    return (u_char *) ngx_cached_http_time.len;
                }
                return ngx_cpymem(buf, ngx_cached_http_time.data,
                                  ngx_cached_http_time.len);
            }

            if (data == offsetof(ngx_http_headers_out_t, server)) {
                if (buf == NULL) {
                    return (u_char *) (sizeof(NGINX_VER) - 1);
                }
                return ngx_cpymem(buf, NGINX_VER, sizeof(NGINX_VER) - 1);
            }

            if (data == offsetof(ngx_http_headers_out_t, content_length)) {
                if (r->headers_out.content_length_n == -1) {
                    if (buf) {
                        *buf = '-';
                    }
                    return buf + 1;
                }

                if (buf == NULL) {
                    return (u_char *) NGX_OFF_T_LEN;
                }
                return buf + ngx_snprintf((char *) buf,
                                          NGX_OFF_T_LEN + 2, OFF_T_FMT,
                                          r->headers_out.content_length_n);
            }

            if (data == offsetof(ngx_http_headers_out_t, last_modified)) {
                if (r->headers_out.last_modified_time == -1) {
                    if (buf) {
                        *buf = '-';
                    }
                    return buf + 1;
                }

                if (buf == NULL) {
                    return (u_char *)
                                   sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
                }
                return buf + ngx_http_time(buf,
                                           r->headers_out.last_modified_time);
            }

            if (buf) {
                *buf = '-';
            }

            return buf + 1;
        }

        if (buf == NULL) {
            /* find the header length */
            return (u_char *) h->value.len;
        }

        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /* find an offset while a format string compilation */

    op = (ngx_http_log_op_t *) buf;
    s = (ngx_str_t *) data;

    op->len = 0;

    for (i = 0; ngx_http_headers_out[i].name.len != 0; i++) {
        if (ngx_http_headers_out[i].name.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_out[i].name.data, s->data, s->len)
                                                                          == 0)
        {
            op->op = ngx_http_log_header_out;
            op->data = ngx_http_headers_out[i].offset;
            return NULL;
        }
    }

    if (s->len == sizeof("Connection") - 1
        && ngx_strncasecmp(s->data, "Connection", s->len) == 0)
    {
        op->op = ngx_http_log_connection_header_out;
        op->data = (uintptr_t) NULL;
        return NULL;
    }

    if (s->len == sizeof("Transfer-Encoding") - 1
        && ngx_strncasecmp(s->data, "Transfer-Encoding", s->len) == 0) {
        op->op = ngx_http_log_transfer_encoding_header_out;
        op->data = (uintptr_t) NULL;
        return NULL;
    }

    op->op = ngx_http_log_unknown_header_out;
    op->data = (uintptr_t) s;

    return NULL;
}


static u_char *ngx_http_log_connection_header_out(ngx_http_request_t *r,
                                                  u_char *buf, uintptr_t data)
{
    if (buf == NULL) {
        return (u_char *) ((r->keepalive) ? sizeof("keep-alive") - 1:
                                            sizeof("close") - 1);
    }

    if (r->keepalive) {
        return ngx_cpymem(buf, "keep-alive", sizeof("keep-alive") - 1);

    } else {
        return ngx_cpymem(buf, "close", sizeof("close") - 1);
    }
}


static u_char *ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r,
                                                         u_char *buf,
                                                         uintptr_t data)
{
    if (buf == NULL) {
        return (u_char *) ((r->chunked) ? sizeof("chunked") - 1 : 1);
    }

    if (r->chunked) {
        return ngx_cpymem(buf, "chunked", sizeof("chunked") - 1);
    }

    *buf = '-';

    return buf + 1;
}


static u_char *ngx_http_log_unknown_header_out(ngx_http_request_t *r,
                                               u_char *buf,
                                               uintptr_t data)
{
    ngx_uint_t        i;
    ngx_str_t        *s;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    s = (ngx_str_t *) data;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len != s->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, s->data, s->len) == 0) {
            if (buf == NULL) {
                /* find the header length */
                return (u_char *) h[i].value.len;
            }

            return ngx_cpymem(buf, h[i].value.data, h[i].value.len);
        }
    }

    /* no header */

    if (buf) {
        *buf = '-';
    }

    return buf + 1;
}


static ngx_int_t ngx_http_log_pre_conf(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->op = NULL;

    return NGX_OK;
}


static void *ngx_http_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_log_main_conf_t  *conf;

    char       *rc;
    ngx_str_t  *value;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    ngx_init_array(conf->formats, cf->pool, 5, sizeof(ngx_http_log_fmt_t),
                  NGX_CONF_ERROR);

    cf->args->nelts = 0;

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    value->len = sizeof("combined") - 1;
    value->data = (u_char *) "combined";

    if (!(value = ngx_push_array(cf->args))) {
        return NGX_CONF_ERROR;
    }

    *value = ngx_http_combined_fmt;

    rc = ngx_http_log_set_format(cf, NULL, conf);
    if (rc != NGX_CONF_OK) {
        return NULL;
    }

    return conf;
}


static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_log_loc_conf_t  *conf;

    if (!(conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t)))) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                         void *child)
{
    ngx_http_log_loc_conf_t *prev = parent;
    ngx_http_log_loc_conf_t *conf = child;

    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if (conf->logs == NULL) {

        if (conf->off) {
            return NGX_CONF_OK;
        }

        if (prev->logs) {
            conf->logs = prev->logs;

        } else {

            if (prev->off) {
                conf->off = prev->off;
                return NGX_CONF_OK;
            }

            conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
            if (conf->logs == NULL) {
                return NGX_CONF_ERROR;
            }

            if (!(log = ngx_array_push(conf->logs))) {
                return NGX_CONF_ERROR;
            }

            log->file = ngx_conf_open_file(cf->cycle, &http_access_log);
            if (log->file == NULL) {
                return NGX_CONF_ERROR;
            }

            lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
            fmt = lmcf->formats.elts;

            /* the default "combined" format */
            log->ops = fmt[0].ops;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf)
{
    ngx_http_log_loc_conf_t *llcf = conf;

    ngx_uint_t                 i;
    ngx_str_t                 *value, name;
    ngx_http_log_t            *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        return NGX_CONF_OK;
    }

    if (llcf->logs == NULL) {
        llcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
        if (llcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if (!(log = ngx_array_push(llcf->logs))) {
        return NGX_CONF_ERROR;
    }

    if (!(log->file = ngx_conf_open_file(cf->cycle, &value[1]))) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        name = value[2];
    } else {
        name.len = sizeof("combined") - 1;
        name.data = (u_char *) "combined";
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->ops = fmt[i].ops;
            return NGX_CONF_OK;
        }
    }

    return NGX_CONF_OK;
}


static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_http_log_main_conf_t *lmcf = conf;

    ngx_uint_t                  s, f, invalid;
    u_char                     *data, *p, *fname;
    size_t                      i, len, fname_len;
    ngx_str_t                  *value, arg, *a;
    ngx_http_log_op_t          *op;
    ngx_http_log_fmt_t         *fmt;
    ngx_http_log_op_name_t     *name;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (f = 0; f < lmcf->formats.nelts; f++) {
        if (fmt[f].name.len == value[1].len
            && ngx_strcmp(fmt->name.data, value[1].data) == 0)
        {
            return "duplicate \"log_format\" name";
        }
    }

    if (!(fmt = ngx_push_array(&lmcf->formats))) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    if (!(fmt->ops = ngx_create_array(cf->pool, 20,
                                      sizeof(ngx_http_log_op_t)))) {
        return NGX_CONF_ERROR;
    }

    invalid = 0;
    data = NULL;

    for (s = 2; s < cf->args->nelts && !invalid; s++) {

        i = 0;

        while (i < value[s].len) {

            if (!(op = ngx_push_array(fmt->ops))) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '%') {
                i++;

                if (i == value[s].len) {
                    invalid = 1;
                    break;
                }

                if (value[s].data[i] == '{') {
                    i++;

                    arg.data = &value[s].data[i];

                    while (i < value[s].len && value[s].data[i] != '}') {
                        i++;
                    }

                    arg.len = &value[s].data[i] - arg.data;

                    if (i == value[s].len || arg.len == 0) {
                        invalid = 1;
                        break;
                    }

                    i++;

                } else {
                    arg.len = 0;
                }

                fname = &value[s].data[i];

                while (i < value[s].len
                       && ((value[s].data[i] >= 'a' && value[s].data[i] <= 'z')
                           || value[s].data[i] == '_'))
                {
                    i++;
                }

                fname_len = &value[s].data[i] - fname;

                if (fname_len == 0) {
                    invalid = 1;
                    break;
                }

                for (name = ngx_http_log_fmt_ops; name->op; name++) {
                    if (name->name.len == 0) {
                        name = (ngx_http_log_op_name_t *) name->op;
                    }

                    if (name->name.len == fname_len
                        && ngx_strncmp(name->name.data, fname, fname_len) == 0)
                    {
                        if (name->len != NGX_HTTP_LOG_ARG) {
                            if (arg.len) {
                                fname[fname_len] = '\0';
                                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" must not have argument",
                                               data);
                                return NGX_CONF_ERROR;
                            }

                            op->len = name->len;
                            op->op = name->op;
                            op->data = 0;

                            break;
                        }

                        if (arg.len == 0) {
                            fname[fname_len] = '\0';
                            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" requires argument", 
                                               data);
                            return NGX_CONF_ERROR;
                        }

                        if (!(a = ngx_palloc(cf->pool, sizeof(ngx_str_t)))) {
                            return NGX_CONF_ERROR;
                        }

                        *a = arg;
                        name->op(NULL, (u_char *) op, (uintptr_t) a);

                        break;
                    }
                }

                if (name->name.len == 0) {
                    invalid = 1;
                    break;
                }

            } else {
                i++;

                while (i < value[s].len && value[s].data[i] != '%') {
                    i++;
                }

                len = &value[s].data[i] - data;

                if (len) {

                    op->len = len;

                    if (len <= sizeof(uintptr_t)) {
                        op->op = NGX_HTTP_LOG_COPY_SHORT;
                        op->data = 0;

                        while (len--) {
                            op->data <<= 8;
                            op->data |= data[len];
                        }

                    } else {
                        op->op = NGX_HTTP_LOG_COPY_LONG;

                        if (!(p = ngx_palloc(cf->pool, len))) {
                            return NGX_CONF_ERROR;
                        }

                        ngx_memcpy(p, data, len);
                        op->data = (uintptr_t) p;
                    }
                }
            }
        }
    }

    if (invalid) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%s\"", data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
