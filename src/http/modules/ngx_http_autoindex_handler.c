
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if 0

typedef struct {
    ngx_buf_t     *buf;
    size_t         size;
    ngx_pool_t    *pool;
    size_t         alloc_size;
    ngx_chain_t  **last_out;
} ngx_http_autoindex_ctx_t;

#endif


typedef struct {
    ngx_str_t      name;
    ngx_uint_t     escape;
    ngx_uint_t     dir;
    time_t         mtime;
    off_t          size;
} ngx_http_autoindex_entry_t;


typedef struct {
    ngx_flag_t     enable;
} ngx_http_autoindex_loc_conf_t;


#define NGX_HTTP_AUTOINDEX_NAME_LEN  50


static int ngx_http_autoindex_cmp_entries(const void *one, const void *two);
static ngx_int_t ngx_http_autoindex_error(ngx_http_request_t *r,
    ngx_dir_t *dir, u_char *name);
static ngx_int_t ngx_http_autoindex_init(ngx_cycle_t *cycle);
static void *ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_autoindex_commands[] = {

    { ngx_string("autoindex"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_autoindex_loc_conf_t, enable),
      NULL },

      ngx_null_command
};


ngx_http_module_t  ngx_http_autoindex_module_ctx = {
    NULL,                                  /* pre conf */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_autoindex_create_loc_conf,    /* create location configration */
    ngx_http_autoindex_merge_loc_conf      /* merge location configration */
};


ngx_module_t  ngx_http_autoindex_module = {
    NGX_MODULE,
    &ngx_http_autoindex_module_ctx,        /* module context */ 
    ngx_http_autoindex_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    ngx_http_autoindex_init,               /* init module */
    NULL                                   /* init process */
};


static u_char title[] =
"<html>" CRLF
"<head><title>Index of "
;


static u_char header[] =
"</title></head>" CRLF
"<body bgcolor=\"white\">" CRLF
"<h1>Index of "
;

static u_char tail[] =
"</body>" CRLF
"</html>" CRLF
;


static ngx_int_t
ngx_http_autoindex_handler(ngx_http_request_t *r)
{
    u_char                         *last;
    size_t                          len;
    ngx_tm_t                        tm;
    ngx_int_t                       rc;
    ngx_uint_t                      i, level;
    ngx_err_t                       err;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;
    ngx_str_t                       dname, fname;
    ngx_dir_t                       dir;
    ngx_pool_t                     *pool;
    ngx_array_t                     entries;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_autoindex_entry_t     *entry;
    ngx_http_autoindex_loc_conf_t  *alcf;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    /* TODO: Win32 */
    if (r->zero_in_uri) {
        return NGX_DECLINED;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);

    if (!alcf->enable) {
        return NGX_DECLINED;
    }

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->alias) {
        dname.data = ngx_palloc(pool, clcf->root.len + r->uri.len
                                                     + NGX_DIR_MASK_LEN + 1
                                                     - clcf->name.len);
        if (dname.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    
        last = ngx_cpymem(dname.data, clcf->root.data, clcf->root.len);
        last = ngx_cpystrn(last, r->uri.data + clcf->name.len,
                           r->uri.len - clcf->name.len + 1);

    } else {
        dname.data = ngx_palloc(pool, clcf->root.len + r->uri.len
                                                     + NGX_DIR_MASK_LEN);
        if (dname.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        last = ngx_cpymem(dname.data, clcf->root.data, clcf->root.len);
        last = ngx_cpystrn(last, r->uri.data, r->uri.len);
    }

    dname.len = last - dname.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", dname.data);


    if (ngx_open_dir(&dname, &dir) == NGX_ERROR) {
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

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", dname.data);

        return rc;
    }

#if (NGX_SUPPRESS_WARN)
    /* MSVC thinks 'entries' may be used without having been initialized */
    ngx_memzero(&entries, sizeof(ngx_array_t));
#endif

    if (ngx_array_init(&entries, pool, 50, sizeof(ngx_http_autoindex_entry_t))
                                                                  == NGX_ERROR)
    {
        return ngx_http_autoindex_error(r, &dir, dname.data);
    }

    fname.len = 0;
#if (NGX_SUPPRESS_WARN)
    fname.data = NULL;
#endif

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            err = ngx_errno;

            if (err == NGX_ENOMOREFILES) {
                rc = NGX_OK;

            } else {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                              ngx_read_dir_n " \"%s\" failed", dname.data);
                return ngx_http_autoindex_error(r, &dir, dname.data);
            }

            break; 
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", ngx_de_name(&dir));

        len = ngx_de_namelen(&dir);

        if (len == 1 && ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        if (len == 2
            && ngx_de_name(&dir)[0] == '.'
            && ngx_de_name(&dir)[1] == '.')
        {
            continue;
        }

        if (!dir.valid_info) {

            if (dname.len + 1 + len > fname.len) {
                fname.len = dname.len + 1 + len + 32;

                if (!(fname.data = ngx_palloc(pool, fname.len))) {
                    return ngx_http_autoindex_error(r, &dir, dname.data);
                }

                last = ngx_cpystrn(fname.data, dname.data,
                                   dname.len + 1);
                *last++ = '/';
            }

            ngx_cpystrn(last, ngx_de_name(&dir), len + 1);

            if (ngx_de_info(fname.data, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                                  ngx_de_info_n " \"%s\" failed", fname.data);
                    return ngx_http_autoindex_error(r, &dir, dname.data);
                }

                if (ngx_de_link_info(fname.data, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                                  ngx_de_link_info_n " \"%s\" failed",
                                  fname.data);
                    return ngx_http_autoindex_error(r, &dir, dname.data);
                }
            }
        }

        if (!(entry = ngx_array_push(&entries))) {
            return ngx_http_autoindex_error(r, &dir, dname.data);
        }

        entry->name.len = len;        
        entry->escape = 2 * ngx_escape_uri(NULL, ngx_de_name(&dir), len,
                                           NGX_ESCAPE_HTML);

        if (!(entry->name.data = ngx_palloc(pool, len + entry->escape + 1))) {
            return ngx_http_autoindex_error(r, &dir, dname.data);
        }

        ngx_cpystrn(entry->name.data, ngx_de_name(&dir), len + 1);

        entry->dir = ngx_de_is_dir(&dir);
        entry->mtime = ngx_de_mtime(&dir);
        entry->size = ngx_de_size(&dir);
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", dname.data);
    }

    len = sizeof(title) - 1
          + r->uri.len
          + sizeof(header) - 1
          + r->uri.len
          + sizeof("</h1>") - 1
          + sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1
          + sizeof("</pre><hr>") - 1
          + sizeof(tail) - 1;

    entry = entries.elts;
    for (i = 0; i < entries.nelts; i++) {
        len += sizeof("<a href=\"") - 1
               + 1                                          /* 1 is for "/" */
               + entry[i].name.len + entry[i].escape
               + sizeof("\">") - 1
               + NGX_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
               + sizeof("</a>") - 1
               + sizeof(" 28-Sep-1970 12:00 ") - 1
               + 19
               + 2;
    }

    if (!(b = ngx_create_temp_buf(r->pool, len))) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (entries.nelts > 1) {
        ngx_qsort(entry, (size_t) entries.nelts,
                  sizeof(ngx_http_autoindex_entry_t),
                  ngx_http_autoindex_cmp_entries);
    }

    b->last = ngx_cpymem(b->last, title, sizeof(title) - 1);
    b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
    b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
    b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
    b->last = ngx_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);

    b->last = ngx_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
                         sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);

    for (i = 0; i < entries.nelts; i++) {
        b->last = ngx_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);

        if (entry[i].escape) {
            ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           NGX_ESCAPE_HTML);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = ngx_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        b->last = ngx_cpystrn(b->last, entry[i].name.data,
                              NGX_HTTP_AUTOINDEX_NAME_LEN + 1);

        len = entry[i].name.len;

        if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = ngx_cpymem(b->last - 3, "..&gt;</a>",
                                 sizeof("..&gt;</a>") - 1);

        } else {
            if (entry[i].dir && NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = ngx_cpymem(b->last, "</a>", sizeof("</a>") - 1);
            ngx_memset(b->last, ' ', NGX_HTTP_AUTOINDEX_NAME_LEN - len);
            b->last += NGX_HTTP_AUTOINDEX_NAME_LEN - len;
        }

        *b->last++ = ' ';

        ngx_gmtime(entry[i].mtime, &tm);

        b->last = ngx_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
                              tm.ngx_tm_mday,
                              months[tm.ngx_tm_mon - 1],
                              tm.ngx_tm_year,
                              tm.ngx_tm_hour,
                              tm.ngx_tm_min);

        if (entry[i].dir) {
            b->last = ngx_cpymem(b->last,  "                  -",
                                 sizeof("                  -") - 1);

        } else {
            b->last = ngx_sprintf(b->last, "%19O", entry[i].size);
        }

        *b->last++ = CR;
        *b->last++ = LF;
    }

    /* TODO: free temporary pool */

    b->last = ngx_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);

    b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    r->headers_out.content_type = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.content_type == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.content_type->key.len = 0;
    r->headers_out.content_type->key.data = NULL;
    r->headers_out.content_type->value.len = sizeof("text/html") - 1;
    r->headers_out.content_type->value.data = (u_char *) "text/html";

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (!r->main) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static int
ngx_http_autoindex_cmp_entries(const void *one, const void *two)
{
    ngx_http_autoindex_entry_t *first = (ngx_http_autoindex_entry_t *) one;
    ngx_http_autoindex_entry_t *second = (ngx_http_autoindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) ngx_strcmp(first->name.data, second->name.data);
}


#if 0

static ngx_buf_t *
ngx_http_autoindex_alloc(ngx_http_autoindex_ctx_t *ctx, size_t size)
{
    ngx_chain_t  *cl;

    if (ctx->buf) {

        if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
            return ctx->buf;
        }

        ctx->size += ctx->buf->last - ctx->buf->pos;
    }

    if (!(ctx->buf = ngx_create_temp_buf(ctx->pool, ctx->alloc_size))) {
        return NULL;
    }

    if (!(cl = ngx_alloc_chain_link(ctx->pool))) {
        return NULL;
    }

    cl->buf = ctx->buf;
    cl->next = NULL;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return ctx->buf;
}

#endif


static ngx_int_t
ngx_http_autoindex_error(ngx_http_request_t *r, ngx_dir_t *dir, u_char *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%s\" failed", name);
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_http_autoindex_init(ngx_cycle_t *cycle)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_autoindex_handler;

    return NGX_OK;
}


static void *
ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_autoindex_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_autoindex_loc_conf_t *prev = parent;
    ngx_http_autoindex_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}
