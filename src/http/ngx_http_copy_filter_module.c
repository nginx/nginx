
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_bufs_t  bufs;
} ngx_http_copy_filter_conf_t;


#if (NGX_HAVE_FILE_AIO)
static void ngx_http_copy_aio_handler(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
static void ngx_http_copy_aio_event_handler(ngx_event_t *ev);
#if (NGX_HAVE_AIO_SENDFILE)
static void ngx_http_copy_aio_sendfile_event_handler(ngx_event_t *ev);
#endif
#endif

static void *ngx_http_copy_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_copy_filter_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_copy_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_copy_filter_commands[] = {

    { ngx_string("output_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_copy_filter_conf_t, bufs),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_copy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_copy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_copy_filter_create_conf,      /* create location configuration */
    ngx_http_copy_filter_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_copy_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_copy_filter_module_ctx,      /* module context */
    ngx_http_copy_filter_commands,         /* module directives */
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


static ngx_http_output_body_filter_pt    ngx_http_next_filter;


static ngx_int_t
ngx_http_copy_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_output_chain_ctx_t       *ctx;
    ngx_http_core_loc_conf_t     *clcf;
    ngx_http_copy_filter_conf_t  *conf;

    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: \"%V?%V\"", &r->uri, &r->args);

    ctx = ngx_http_get_module_ctx(r, ngx_http_copy_filter_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_copy_filter_module);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_copy_filter_module);
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ctx->sendfile = c->sendfile;
        ctx->need_in_memory = r->main_filter_need_in_memory
                              || r->filter_need_in_memory;
        ctx->need_in_temp = r->filter_need_temporary;

        ctx->alignment = clcf->directio_alignment;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (ngx_buf_tag_t) &ngx_http_copy_filter_module;

        ctx->output_filter = (ngx_output_chain_filter_pt) ngx_http_next_filter;
        ctx->filter_ctx = r;

#if (NGX_HAVE_FILE_AIO)
        if (ngx_file_aio) {
            if (clcf->aio) {
                ctx->aio_handler = ngx_http_copy_aio_handler;
            }
#if (NGX_HAVE_AIO_SENDFILE)
            c->aio_sendfile = (clcf->aio == NGX_HTTP_AIO_SENDFILE);
#endif
        }
#endif

        if (in && in->buf && ngx_buf_size(in->buf)) {
            r->request_output = 1;
        }
    }

#if (NGX_HAVE_FILE_AIO)
    ctx->aio = r->aio;
#endif

    for ( ;; ) {
        rc = ngx_output_chain(ctx, in);

        if (ctx->in == NULL) {
            r->buffered &= ~NGX_HTTP_COPY_BUFFERED;

        } else {
            r->buffered |= NGX_HTTP_COPY_BUFFERED;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);

#if (NGX_HAVE_FILE_AIO && NGX_HAVE_AIO_SENDFILE)

        if (c->busy_sendfile) {
            ssize_t                n;
            off_t                  offset;
            ngx_file_t            *file;
            ngx_http_ephemeral_t  *e;

            file = c->busy_sendfile->file;
            offset = c->busy_sendfile->file_pos;

            if (file->aio) {
                c->aio_sendfile = (offset != file->aio->last_offset);
                file->aio->last_offset = offset;

                if (c->aio_sendfile == 0) {
                    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                                  "sendfile(%V) returned busy again",
                                  &file->name);
                }
            }

            c->busy_sendfile = NULL;
            e = (ngx_http_ephemeral_t *) &r->uri_start;

            n = ngx_file_aio_read(file, &e->aio_preload, 1, offset, r->pool);

            if (n > 0) {
                in = NULL;
                continue;
            }

            rc = n;

            if (file->aio) {
                file->aio->data = r;
                file->aio->handler = ngx_http_copy_aio_sendfile_event_handler;

                r->main->blocked++;
                r->aio = 1;
            }
        }
#endif

        return rc;
    }
}


#if (NGX_HAVE_FILE_AIO)

static void
ngx_http_copy_aio_handler(ngx_output_chain_ctx_t *ctx, ngx_file_t *file)
{
    ngx_http_request_t *r;

    r = ctx->filter_ctx;

    file->aio->data = r;
    file->aio->handler = ngx_http_copy_aio_event_handler;

    r->main->blocked++;
    r->aio = 1;
    ctx->aio = 1;
}


static void
ngx_http_copy_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t     *aio;
    ngx_http_request_t  *r;

    aio = ev->data;
    r = aio->data;

    r->main->blocked--;
    r->aio = 0;

    r->connection->write->handler(r->connection->write);
}


#if (NGX_HAVE_AIO_SENDFILE)

static void
ngx_http_copy_aio_sendfile_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t     *aio;
    ngx_http_request_t  *r;

    aio = ev->data;
    r = aio->data;

    r->main->blocked--;
    r->aio = 0;
    ev->complete = 0;

    r->connection->write->handler(r->connection->write);
}

#endif
#endif


static void *
ngx_http_copy_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_copy_filter_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_copy_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bufs.num = 0;

    return conf;
}


static char *
ngx_http_copy_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_copy_filter_conf_t *prev = parent;
    ngx_http_copy_filter_conf_t *conf = child;

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 1, 32768);

    return NULL;
}


static ngx_int_t
ngx_http_copy_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_copy_filter;

    return NGX_OK;
}

