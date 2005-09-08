
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


static u_char *ngx_http_log_addr(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_apache_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static u_char *ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

static size_t ngx_http_log_request_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_request(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

static ngx_int_t ngx_http_log_header_in_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_header_in_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static size_t ngx_http_log_unknown_header_in_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_unknown_header_in(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static ngx_int_t ngx_http_log_header_out_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_header_out_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);
static size_t ngx_http_log_unknown_header_out_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_unknown_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static u_char *ngx_http_log_connection_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);
static u_char *ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r,
    u_char *buf, ngx_http_log_op_t *op);

static ngx_table_elt_t *ngx_http_log_unknown_header(ngx_list_t *headers,
    ngx_str_t *value);

static ngx_int_t ngx_http_log_variable_compile(ngx_conf_t *cf,
    ngx_http_log_op_t *op, ngx_str_t *value);
static size_t ngx_http_log_variable_getlen(ngx_http_request_t *r,
    uintptr_t data);
static u_char *ngx_http_log_variable(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);


static ngx_int_t ngx_http_log_set_formats(ngx_conf_t *cf);
static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_log_commands[] = {

    { ngx_string("log_format"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_log_set_format,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_log_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_log_module_ctx = {
    ngx_http_log_set_formats,              /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_log_create_loc_conf,          /* create location configration */
    ngx_http_log_merge_loc_conf            /* merge location configration */
};


ngx_module_t  ngx_http_log_module = {
    NGX_MODULE_V1,
    &ngx_http_log_module_ctx,              /* module context */
    ngx_http_log_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t http_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_str_t ngx_http_combined_fmt =
    ngx_string("%addr - - [%time] \"%request\" %status %apache_length "
               "\"%{Referer}i\" \"%{User-Agent}i\"");


ngx_http_log_op_name_t ngx_http_log_fmt_ops[] = {
    { ngx_string("addr"), INET_ADDRSTRLEN - 1, NULL, NULL, ngx_http_log_addr },
    { ngx_string("conn"), NGX_ATOMIC_T_LEN, NULL, NULL,
                          ngx_http_log_connection },
    { ngx_string("pipe"), 1, NULL, NULL, ngx_http_log_pipe },
    { ngx_string("time"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          NULL, NULL, ngx_http_log_time },
    { ngx_string("msec"), NGX_TIME_T_LEN + 4, NULL, NULL, ngx_http_log_msec },
    { ngx_string("request_time"), NGX_TIME_T_LEN, NULL, NULL,
                          ngx_http_log_request_time },
    { ngx_string("status"), 3, NULL, NULL, ngx_http_log_status },
    { ngx_string("length"), NGX_OFF_T_LEN, NULL, NULL, ngx_http_log_length },
    { ngx_string("apache_length"), NGX_OFF_T_LEN,
                          NULL, NULL, ngx_http_log_apache_length },
    { ngx_string("request_length"), NGX_SIZE_T_LEN,
                          NULL, NULL, ngx_http_log_request_length },

    { ngx_string("request"), 0, NULL,
                          ngx_http_log_request_getlen,
                          ngx_http_log_request },

    { ngx_string("i"), 0, ngx_http_log_header_in_compile, NULL,
                          ngx_http_log_header_in },
    { ngx_string("o"), 0, ngx_http_log_header_out_compile, NULL,
                          ngx_http_log_header_out },
    { ngx_string("v"), 0, ngx_http_log_variable_compile, NULL,
                          ngx_http_log_variable },

    { ngx_null_string, 0, NULL, NULL, NULL }
};


ngx_int_t
ngx_http_log_handler(ngx_http_request_t *r)
{
    ngx_uint_t                i, l;
    u_char                   *line, *p;
    size_t                    len;
    ngx_http_log_t           *log;
    ngx_http_log_op_t        *op;
    ngx_http_log_loc_conf_t  *lcf;
#if (NGX_WIN32)
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
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

#if (NGX_WIN32)
        len += 2;
#else
        len++;
#endif

        line = ngx_palloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        for (i = 0; i < log[l].ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

#if (NGX_WIN32)
        *p++ = CR; *p++ = LF;
        WriteFile(log[l].file->fd, line, p - line, &written, NULL);
#else
        *p++ = LF;
        write(log[l].file->fd, line, p - line);
#endif
    }

    return NGX_OK;
}


static u_char *
ngx_http_log_copy_short(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
ngx_http_log_copy_long(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
ngx_http_log_addr(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, r->connection->addr_text.data,
                      r->connection->addr_text.len);
}


static u_char *
ngx_http_log_connection(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui", r->connection->number);
}


static u_char *
ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static u_char *
ngx_http_log_time(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, ngx_cached_http_log_time.data,
                      ngx_cached_http_log_time.len);
}


static u_char *
ngx_http_log_msec(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    struct timeval  tv;

    ngx_gettimeofday(&tv);

    return ngx_sprintf(buf, "%l.%03l", tv.tv_sec, tv.tv_usec / 1000);
}


static u_char *
ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    time_t  elapsed;

    elapsed = ngx_time() - r->start_time;

    return ngx_sprintf(buf, "%T", elapsed);
}


static size_t
ngx_http_log_request_getlen(ngx_http_request_t *r, uintptr_t data)
{
    return r->request_line.len;
}


static u_char *
ngx_http_log_request(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_cpymem(buf, r->request_line.data, r->request_line.len);
}


static u_char *
ngx_http_log_status(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%ui",
                       r->err_status ? r->err_status : r->headers_out.status);
}


static u_char *
ngx_http_log_length(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%O", r->connection->sent);
}


static u_char *
ngx_http_log_apache_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    off_t  length;

    length = r->connection->sent - r->header_size;

    if (length > 0) {
        return ngx_sprintf(buf, "%O", length);
    }

    *buf = '0';

    return buf + 1;
}


static u_char *
ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    return ngx_sprintf(buf, "%z", r->request_length);
}


static ngx_int_t
ngx_http_log_header_in_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_uint_t  i;

    op->len = 0;

    for (i = 0; ngx_http_headers_in[i].name.len != 0; i++) {

        if (ngx_http_headers_in[i].name.len != value->len) {
            continue;
        }

        /* STUB: "Cookie" speacial handling */
        if (ngx_http_headers_in[i].offset == 0) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_in[i].name.data, value->data,
                            value->len) == 0)
        {
            op->getlen = ngx_http_log_header_in_getlen;
            op->run = ngx_http_log_header_in;
            op->data = ngx_http_headers_in[i].offset;

            return NGX_OK;
        }
    }

    op->getlen = ngx_http_log_unknown_header_in_getlen;
    op->run = ngx_http_log_unknown_header_in;
    op->data = (uintptr_t) value;

    return NGX_OK;
}


static size_t
ngx_http_log_header_in_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_in + op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static size_t
ngx_http_log_unknown_header_in_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_in.headers, (ngx_str_t *) data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_unknown_header_in(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_in.headers,
                                    (ngx_str_t *) op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_int_t
ngx_http_log_header_out_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_uint_t  i;

    op->len = 0;

    for (i = 0; ngx_http_headers_out[i].name.len != 0; i++) {

        if (ngx_http_headers_out[i].name.len != value->len) {
            continue;
        }

        if (ngx_strncasecmp(ngx_http_headers_out[i].name.data, value->data,
                            value->len) == 0)
        {
            op->getlen = ngx_http_log_header_out_getlen;
            op->run = ngx_http_log_header_out;
            op->data = ngx_http_headers_out[i].offset;

            return NGX_OK;
        }
    }

    if (value->len == sizeof("Connection") - 1
        && ngx_strncasecmp(value->data, "Connection", value->len) == 0)
    {
        op->len = sizeof("keep-alive") - 1;
        op->getlen = NULL;
        op->run = ngx_http_log_connection_header_out;
        op->data = 0;
        return NGX_OK;
    }

    if (value->len == sizeof("Transfer-Encoding") - 1
        && ngx_strncasecmp(value->data, "Transfer-Encoding", value->len) == 0)
    {
        op->len = sizeof("chunked") - 1;
        op->getlen = NULL;
        op->run = ngx_http_log_transfer_encoding_header_out;
        op->data = 0;
        return NGX_OK;
    }

    op->getlen = ngx_http_log_unknown_header_out_getlen;
    op->run = ngx_http_log_unknown_header_out;
    op->data = (uintptr_t) value;

    return NGX_OK;
}


static size_t
ngx_http_log_header_out_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_out + data);

    if (h) {
        return h->value.len;
    }

    /*
     * No header pointer was found.
     * However, some headers: "Date", "Server", "Content-Length",
     * and "Last-Modified" have a special handling in the header filter,
     * but we do not set up their pointers in the filter,
     * because they are too seldom needed to be logged.
     */

    if (data == offsetof(ngx_http_headers_out_t, date)) {
        return ngx_cached_http_time.len;
    }

    if (data == offsetof(ngx_http_headers_out_t, server)) {
        return (sizeof(NGINX_VER) - 1);
    }

    if (data == offsetof(ngx_http_headers_out_t, content_length)) {
        if (r->headers_out.content_length_n == -1) {
            return 1;
        }

        return NGX_OFF_T_LEN;
    }

    if (data == offsetof(ngx_http_headers_out_t, last_modified)) {
        if (r->headers_out.last_modified_time == -1) {
            return 1;
        }

        return sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    }

    return 1;
}


static u_char *
ngx_http_log_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = *(ngx_table_elt_t **) ((char *) &r->headers_out + op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    /*
     * No header pointer was found.
     * However, some headers: "Date", "Server", "Content-Length",
     * and "Last-Modified" have a special handling in the header filter,
     * but we do not set up their pointers in the filter,
     * because they are too seldom needed to be logged.
     */

    if (op->data == offsetof(ngx_http_headers_out_t, date)) {
        return ngx_cpymem(buf, ngx_cached_http_time.data,
                          ngx_cached_http_time.len);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, server)) {
        return ngx_cpymem(buf, NGINX_VER, sizeof(NGINX_VER) - 1);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, content_length)) {
        if (r->headers_out.content_length_n == -1) {
            *buf = '-';

            return buf + 1;
        }

        return ngx_sprintf(buf, "%O", r->headers_out.content_length_n);
    }

    if (op->data == offsetof(ngx_http_headers_out_t, last_modified)) {
        if (r->headers_out.last_modified_time == -1) {
            *buf = '-';

            return buf + 1;
        }

        return ngx_http_time(buf, r->headers_out.last_modified_time);
    }

    *buf = '-';

    return buf + 1;
}


static size_t
ngx_http_log_unknown_header_out_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_out.headers,
                                    (ngx_str_t *) data);

    if (h) {
        return h->value.len;
    }

    return 1;
}


static u_char *
ngx_http_log_unknown_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    ngx_table_elt_t  *h;

    h = ngx_http_log_unknown_header(&r->headers_out.headers,
                                    (ngx_str_t *) op->data);

    if (h) {
        return ngx_cpymem(buf, h->value.data, h->value.len);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_table_elt_t *
ngx_http_log_unknown_header(ngx_list_t *headers, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &headers->part;
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

        if (h[i].key.len != value->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, value->data, value->len) == 0) {
            return &h[i];
        }
    }

    return NULL;
}


static u_char *
ngx_http_log_connection_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    if (r->keepalive) {
        return ngx_cpymem(buf, "keep-alive", sizeof("keep-alive") - 1);

    } else {
        return ngx_cpymem(buf, "close", sizeof("close") - 1);
    }
}


static u_char *
ngx_http_log_transfer_encoding_header_out(ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op)
{
    if (r->chunked) {
        return ngx_cpymem(buf, "chunked", sizeof("chunked") - 1);
    }

    *buf = '-';

    return buf + 1;
}


static ngx_int_t 
ngx_http_log_variable_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
    ngx_str_t *value)
{
    ngx_int_t  index;

    index = ngx_http_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;
    op->getlen = ngx_http_log_variable_getlen;
    op->run = ngx_http_log_variable;
    op->data = index;

    return NGX_OK;
}


static size_t
ngx_http_log_variable_getlen(ngx_http_request_t *r, uintptr_t data)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, data);

    if (value == NULL
        || value == NGX_HTTP_VAR_NOT_FOUND
        || value->text.len == 0)
    {
        return 1;
    }

    return value->text.len;
}


static u_char *
ngx_http_log_variable(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
{
    ngx_http_variable_value_t  *value;

    value = ngx_http_get_indexed_variable(r, op->data);

    if (value == NULL
        || value == NGX_HTTP_VAR_NOT_FOUND
        || value->text.len == 0)
    {
        *buf = '-';
        return buf + 1;
    }

    return ngx_cpymem(buf, value->text.data, value->text.len);
}


static ngx_int_t
ngx_http_log_set_formats(ngx_conf_t *cf)
{
    ngx_http_log_op_name_t  *op;

    for (op = ngx_http_log_fmt_ops; op->name.len; op++) { /* void */ }
    op->run = NULL;

    return NGX_OK;
}


static void *
ngx_http_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_log_main_conf_t  *conf;

    char       *rc;
    ngx_str_t  *value;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(ngx_http_log_fmt_t))
                                                                  == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    cf->args->nelts = 0;

    value = ngx_array_push(cf->args);
    if (value == NULL) {
        return NGX_CONF_ERROR;
    }

    value = ngx_array_push(cf->args);
    if (value == NULL) {
        return NGX_CONF_ERROR;
    }

    value->len = sizeof("combined") - 1;
    value->data = (u_char *) "combined";

    value = ngx_array_push(cf->args);
    if (value == NULL) {
        return NGX_CONF_ERROR;
    }

    *value = ngx_http_combined_fmt;

    rc = ngx_http_log_set_format(cf, NULL, conf);
    if (rc != NGX_CONF_OK) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_log_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_log_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}


static char *
ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
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

            log = ngx_array_push(conf->logs);
            if (log == NULL) {
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


static char *
ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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

    log = ngx_array_push(llcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
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

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown log format \"%V\"", &name);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->ops = ngx_array_create(cf->pool, 20, sizeof(ngx_http_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    invalid = 0;
    data = NULL;
    arg.data = NULL;

    for (s = 2; s < cf->args->nelts && !invalid; s++) {

        i = 0;

        while (i < value[s].len) {

            op = ngx_array_push(fmt->ops);
            if (op == NULL) {
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

                for (name = ngx_http_log_fmt_ops; name->run; name++) {
                    if (name->name.len == 0) {
                        name = (ngx_http_log_op_name_t *) name->run;
                    }

                    if (name->name.len == fname_len
                        && ngx_strncmp(name->name.data, fname, fname_len) == 0)
                    {
                        if (name->compile == NULL) {
                            if (arg.len) {
                                fname[fname_len] = '\0';
                                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                               "\"%s\" must not have argument",
                                               data);
                                return NGX_CONF_ERROR;
                            }

                            op->len = name->len;
                            op->getlen = name->getlen;
                            op->run = name->run;
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

                        a = ngx_palloc(cf->pool, sizeof(ngx_str_t));
                        if (a == NULL) {
                            return NGX_CONF_ERROR;
                        }

                        *a = arg;
                        if (name->compile(cf, op, a) == NGX_ERROR) {
                            return NGX_CONF_ERROR;
                        }

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
                    op->getlen = NULL;

                    if (len <= sizeof(uintptr_t)) {
                        op->run = ngx_http_log_copy_short;
                        op->data = 0;

                        while (len--) {
                            op->data <<= 8;
                            op->data |= data[len];
                        }

                    } else {
                        op->run = ngx_http_log_copy_long;

                        p = ngx_palloc(cf->pool, len);
                        if (p == NULL) {
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
