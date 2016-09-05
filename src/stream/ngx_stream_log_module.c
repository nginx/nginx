
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#if (NGX_ZLIB)
#include <zlib.h>
#endif


typedef struct ngx_stream_log_op_s  ngx_stream_log_op_t;

typedef u_char *(*ngx_stream_log_op_run_pt) (ngx_stream_session_t *s,
    u_char *buf, ngx_stream_log_op_t *op);

typedef size_t (*ngx_stream_log_op_getlen_pt) (ngx_stream_session_t *s,
    uintptr_t data);


struct ngx_stream_log_op_s {
    size_t                       len;
    ngx_stream_log_op_getlen_pt  getlen;
    ngx_stream_log_op_run_pt     run;
    uintptr_t                    data;
};


typedef struct {
    ngx_str_t                    name;
    ngx_array_t                 *flushes;
    ngx_array_t                 *ops;        /* array of ngx_stream_log_op_t */
} ngx_stream_log_fmt_t;


typedef struct {
    ngx_array_t                  formats;    /* array of ngx_stream_log_fmt_t */
} ngx_stream_log_main_conf_t;


typedef struct {
    u_char                      *start;
    u_char                      *pos;
    u_char                      *last;

    ngx_event_t                 *event;
    ngx_msec_t                   flush;
    ngx_int_t                    gzip;
} ngx_stream_log_buf_t;


typedef struct {
    ngx_array_t                 *lengths;
    ngx_array_t                 *values;
} ngx_stream_log_script_t;


typedef struct {
    ngx_open_file_t             *file;
    ngx_stream_log_script_t     *script;
    time_t                       disk_full_time;
    time_t                       error_log_time;
    ngx_syslog_peer_t           *syslog_peer;
    ngx_stream_log_fmt_t        *format;
    ngx_stream_complex_value_t  *filter;
} ngx_stream_log_t;


typedef struct {
    ngx_array_t                 *logs;       /* array of ngx_stream_log_t */

    ngx_open_file_cache_t       *open_file_cache;
    time_t                       open_file_cache_valid;
    ngx_uint_t                   open_file_cache_min_uses;

    ngx_uint_t                   off;        /* unsigned  off:1 */
} ngx_stream_log_srv_conf_t;


typedef struct {
    ngx_str_t                    name;
    size_t                       len;
    ngx_stream_log_op_run_pt     run;
} ngx_stream_log_var_t;


static void ngx_stream_log_write(ngx_stream_session_t *s, ngx_stream_log_t *log,
    u_char *buf, size_t len);
static ssize_t ngx_stream_log_script_write(ngx_stream_session_t *s,
    ngx_stream_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (NGX_ZLIB)
static ssize_t ngx_stream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
    ngx_int_t level, ngx_log_t *log);

static void *ngx_stream_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void ngx_stream_log_gzip_free(void *opaque, void *address);
#endif

static void ngx_stream_log_flush(ngx_open_file_t *file, ngx_log_t *log);
static void ngx_stream_log_flush_handler(ngx_event_t *ev);

static ngx_int_t ngx_stream_log_variable_compile(ngx_conf_t *cf,
    ngx_stream_log_op_t *op, ngx_str_t *value);
static size_t ngx_stream_log_variable_getlen(ngx_stream_session_t *s,
    uintptr_t data);
static u_char *ngx_stream_log_variable(ngx_stream_session_t *s, u_char *buf,
    ngx_stream_log_op_t *op);
static uintptr_t ngx_stream_log_escape(u_char *dst, u_char *src, size_t size);


static void *ngx_stream_log_create_main_conf(ngx_conf_t *cf);
static void *ngx_stream_log_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_log_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_log_compile_format(ngx_conf_t *cf,
    ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
static char *ngx_stream_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_stream_log_init(ngx_conf_t *cf);


static ngx_command_t  ngx_stream_log_commands[] = {

    { ngx_string("log_format"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_2MORE,
      ngx_stream_log_set_format,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_log"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_log_set_log,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("open_log_file_cache"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1234,
      ngx_stream_log_open_file_cache,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_log_init,                   /* postconfiguration */

    ngx_stream_log_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_log_create_srv_conf,        /* create server configuration */
    ngx_stream_log_merge_srv_conf          /* merge server configuration */
};


ngx_module_t  ngx_stream_log_module = {
    NGX_MODULE_V1,
    &ngx_stream_log_module_ctx,            /* module context */
    ngx_stream_log_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_log_handler(ngx_stream_session_t *s)
{
    u_char                     *line, *p;
    size_t                      len, size;
    ssize_t                     n;
    ngx_str_t                   val;
    ngx_uint_t                  i, l;
    ngx_stream_log_t           *log;
    ngx_stream_log_op_t        *op;
    ngx_stream_log_buf_t       *buffer;
    ngx_stream_log_srv_conf_t  *lscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log handler");

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_log_module);

    if (lscf->off || lscf->logs == NULL) {
        return NGX_OK;
    }

    log = lscf->logs->elts;
    for (l = 0; l < lscf->logs->nelts; l++) {

        if (log[l].filter) {
            if (ngx_stream_complex_value(s, log[l].filter, &val) != NGX_OK) {
                return NGX_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        if (ngx_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        ngx_stream_script_flush_no_cacheable_variables(s,
                                                       log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(s, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + ngx_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += NGX_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        if (buffer) {

            if (len > (size_t) (buffer->last - buffer->pos)) {

                ngx_stream_log_write(s, &log[l], buffer->start,
                                     buffer->pos - buffer->start);

                buffer->pos = buffer->start;
            }

            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                if (buffer->event && p == buffer->start) {
                    ngx_add_timer(buffer->event, buffer->flush);
                }

                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(s, p, &op[i]);
                }

                ngx_linefeed(p);

                buffer->pos = p;

                continue;
            }

            if (buffer->event && buffer->event->timer_set) {
                ngx_del_timer(buffer->event);
            }
        }

    alloc_line:

        line = ngx_pnalloc(s->connection->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        if (log[l].syslog_peer) {
            p = ngx_syslog_add_header(log[l].syslog_peer, line);
        }

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(s, p, &op[i]);
        }

        if (log[l].syslog_peer) {

            size = p - line;

            n = ngx_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        ngx_linefeed(p);

        ngx_stream_log_write(s, &log[l], line, p - line);
    }

    return NGX_OK;
}


static void
ngx_stream_log_write(ngx_stream_session_t *s, ngx_stream_log_t *log,
    u_char *buf, size_t len)
{
    u_char                *name;
    time_t                 now;
    ssize_t                n;
    ngx_err_t              err;
#if (NGX_ZLIB)
    ngx_stream_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {
        name = log->file->name.data;

#if (NGX_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = ngx_stream_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                    s->connection->log);
        } else {
            n = ngx_write_fd(log->file->fd, buf, len);
        }
#else
        n = ngx_write_fd(log->file->fd, buf, len);
#endif

    } else {
        name = NULL;
        n = ngx_stream_log_script_write(s, log->script, &name, buf, len);
    }

    if (n == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (n == -1) {
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}


static ssize_t
ngx_stream_log_script_write(ngx_stream_session_t *s,
    ngx_stream_log_script_t *script, u_char **name, u_char *buf, size_t len)
{
    ssize_t                     n;
    ngx_str_t                   log;
    ngx_open_file_info_t        of;
    ngx_stream_log_srv_conf_t  *lscf;

    if (ngx_stream_script_run(s, &log, script->lengths->elts, 1,
                              script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log \"%s\"", log.data);

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_log_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.log = 1;
    of.valid = lscf->open_file_cache_valid;
    of.min_uses = lscf->open_file_cache_min_uses;
    of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;

    if (ngx_open_cached_file(lscf->open_file_cache, &log, &of,
                             s->connection->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log #%d", of.fd);

    n = ngx_write_fd(of.fd, buf, len);

    return n;
}


#if (NGX_ZLIB)

static ssize_t
ngx_stream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len, ngx_int_t level,
    ngx_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    ngx_err_t    err;
    ngx_pool_t  *pool;

    wbits = MAX_WBITS;
    memlevel = MAX_MEM_LEVEL - 1;

    while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }

    /*
     * This is a formula from deflateBound() for conservative upper bound of
     * compressed data plus 18 bytes of gzip wrapper.
     */

    size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    ngx_memzero(&zstream, sizeof(z_stream));

    pool = ngx_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = ngx_stream_log_gzip_alloc;
    zstream.zfree = ngx_stream_log_gzip_free;
    zstream.opaque = pool;

    out = ngx_pnalloc(pool, size);
    if (out == NULL) {
        goto done;
    }

    zstream.next_in = buf;
    zstream.avail_in = len;
    zstream.next_out = out;
    zstream.avail_out = size;

    rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
                      Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = ngx_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? ngx_errno : 0;

        ngx_destroy_pool(pool);

        ngx_set_errno(err);
        return -1;
    }

done:

    ngx_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
ngx_stream_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    ngx_pool_t *pool = opaque;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pool->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return ngx_palloc(pool, items * size);
}


static void
ngx_stream_log_gzip_free(void *opaque, void *address)
{
#if 0
    ngx_pool_t *pool = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pool->log, 0,
                   "gzip free: %p", address);
#endif
}

#endif


static void
ngx_stream_log_flush(ngx_open_file_t *file, ngx_log_t *log)
{
    size_t                 len;
    ssize_t                n;
    ngx_stream_log_buf_t  *buffer;

    buffer = file->data;

    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (NGX_ZLIB)
    if (buffer->gzip) {
        n = ngx_stream_log_gzip(file->fd, buffer->start, len, buffer->gzip,
                                log);
    } else {
        n = ngx_write_fd(file->fd, buffer->start, len);
    }
#else
    n = ngx_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    buffer->pos = buffer->start;

    if (buffer->event && buffer->event->timer_set) {
        ngx_del_timer(buffer->event);
    }
}


static void
ngx_stream_log_flush_handler(ngx_event_t *ev)
{
    ngx_open_file_t       *file;
    ngx_stream_log_buf_t  *buffer;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "stream log buffer flush handler");

    if (ev->timedout) {
        ngx_stream_log_flush(ev->data, ev->log);
        return;
    }

    /* cancel the flush timer for graceful shutdown */

    file = ev->data;
    buffer = file->data;

    buffer->event = NULL;
}


static u_char *
ngx_stream_log_copy_short(ngx_stream_session_t *s, u_char *buf,
    ngx_stream_log_op_t *op)
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
ngx_stream_log_copy_long(ngx_stream_session_t *s, u_char *buf,
    ngx_stream_log_op_t *op)
{
    return ngx_cpymem(buf, (u_char *) op->data, op->len);
}


static ngx_int_t
ngx_stream_log_variable_compile(ngx_conf_t *cf, ngx_stream_log_op_t *op,
    ngx_str_t *value)
{
    ngx_int_t  index;

    index = ngx_stream_get_variable_index(cf, value);
    if (index == NGX_ERROR) {
        return NGX_ERROR;
    }

    op->len = 0;
    op->getlen = ngx_stream_log_variable_getlen;
    op->run = ngx_stream_log_variable;
    op->data = index;

    return NGX_OK;
}


static size_t
ngx_stream_log_variable_getlen(ngx_stream_session_t *s, uintptr_t data)
{
    uintptr_t                     len;
    ngx_stream_variable_value_t  *value;

    value = ngx_stream_get_indexed_variable(s, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = ngx_stream_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
ngx_stream_log_variable(ngx_stream_session_t *s, u_char *buf,
    ngx_stream_log_op_t *op)
{
    ngx_stream_variable_value_t  *value;

    value = ngx_stream_get_indexed_variable(s, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return ngx_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) ngx_stream_log_escape(buf, value->data, value->len);
    }
}


static uintptr_t
ngx_stream_log_escape(u_char *dst, u_char *src, size_t size)
{
    ngx_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


static void *
ngx_stream_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_log_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&conf->formats, cf->pool, 4,
                       sizeof(ngx_stream_log_fmt_t))
        != NGX_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
ngx_stream_log_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_log_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->open_file_cache = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_stream_log_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_log_srv_conf_t *prev = parent;
    ngx_stream_log_srv_conf_t *conf = child;

    if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {

        conf->open_file_cache = prev->open_file_cache;
        conf->open_file_cache_valid = prev->open_file_cache_valid;
        conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;

        if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
            conf->open_file_cache = NULL;
        }
    }

    if (conf->logs || conf->off) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    return NGX_CONF_OK;
}


static char *
ngx_stream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_log_srv_conf_t *lscf = conf;

    ssize_t                              size;
    ngx_int_t                            gzip;
    ngx_uint_t                           i, n;
    ngx_msec_t                           flush;
    ngx_str_t                           *value, name, s;
    ngx_stream_log_t                    *log;
    ngx_syslog_peer_t                   *peer;
    ngx_stream_log_buf_t                *buffer;
    ngx_stream_log_fmt_t                *fmt;
    ngx_stream_script_compile_t          sc;
    ngx_stream_log_main_conf_t          *lmcf;
    ngx_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lscf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (lscf->logs == NULL) {
        lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_stream_log_t));
        if (lscf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_log_module);

    log = ngx_array_push(lscf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_stream_log_t));


    if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    n = ngx_stream_script_variables_count(&value[1]);

    if (n == 0) {
        log->file = ngx_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        log->script = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_script_t));
        if (log->script == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&sc, sizeof(ngx_stream_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_stream_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

process_formats:

    if (cf->args->nelts >= 3) {
        name = value[2];

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "log format is not specified");
        return NGX_CONF_ERROR;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR || size == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = ngx_parse_time(&s, 0);

            if (flush == (ngx_msec_t) NGX_ERROR || flush == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (NGX_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = ngx_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return NGX_CONF_ERROR;
            }

            continue;

#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "nginx was built without zlib support");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                           sizeof(ngx_stream_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (flush && size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size) {

        if (log->script) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return NGX_CONF_ERROR;
        }

        if (log->syslog_peer) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return NGX_CONF_ERROR;
        }

        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return NGX_CONF_ERROR;
            }

            return NGX_CONF_OK;
        }

        buffer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_buf_t));
        if (buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->start = ngx_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {
            buffer->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
            if (buffer->event == NULL) {
                return NGX_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = ngx_stream_log_flush_handler;
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = ngx_stream_log_flush;
        log->file->data = buffer;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_log_main_conf_t *lmcf = conf;

    ngx_str_t             *value;
    ngx_uint_t             i;
    ngx_stream_log_fmt_t  *fmt;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->flushes = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
    if (fmt->flushes == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_stream_log_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_stream_log_compile_format(cf, fmt->flushes, fmt->ops,
                                         cf->args, 2);
}


static char *
ngx_stream_log_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
    ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
{
    u_char                *data, *p, ch;
    size_t                 i, len;
    ngx_str_t             *value, var;
    ngx_int_t             *flush;
    ngx_uint_t             bracket;
    ngx_stream_log_op_t   *op;

    value = args->elts;

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = ngx_array_push(ops);
            if (op == NULL) {
                return NGX_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                if (ngx_stream_log_variable_compile(cf, op, &var) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }

                if (flushes) {

                    flush = ngx_array_push(flushes);
                    if (flush == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    *flush = op->data; /* variable index */
                }

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = ngx_stream_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = ngx_stream_log_copy_long;

                    p = ngx_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ngx_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static char *
ngx_stream_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_log_srv_conf_t *lscf = conf;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max, min_uses;
    ngx_uint_t   i;

    if (lscf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = ngx_parse_time(&s, 1);
            if (valid == (time_t) NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {

            lscf->open_file_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    if (lscf->open_file_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    lscf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);

    if (lscf->open_file_cache) {

        lscf->open_file_cache_valid = valid;
        lscf->open_file_cache_min_uses = min_uses;

        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_stream_log_init(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    cmcf->access_log_handler = ngx_stream_log_handler;

    return NGX_OK;
}
