
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_bufs_t  bufs;
} ngx_http_output_filter_conf_t;


typedef struct {

    /*
     * NOTE: we do not need now to store hunk in ctx,
     * it's needed for the future NGX_FILE_AIO_READ support only
     */

    ngx_hunk_t    *hunk;

    ngx_chain_t   *in;
    ngx_chain_t   *out;
    ngx_chain_t  **last_out;
    ngx_chain_t   *free;
    ngx_chain_t   *busy;

    int            hunks;
} ngx_http_output_filter_ctx_t;


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src);
static void *ngx_http_output_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_output_filter_merge_conf(ngx_conf_t *cf,
                                               void *parent, void *child);


static ngx_command_t  ngx_http_output_filter_commands[] = {

    {ngx_string("output_buffers"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
     ngx_conf_set_bufs_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_output_filter_conf_t, bufs),
     NULL},

    ngx_null_command
};


static ngx_http_module_t  ngx_http_output_filter_module_ctx = {
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_output_filter_create_conf,    /* create location configuration */
    ngx_http_output_filter_merge_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_output_filter_module = {
    NGX_MODULE,
    &ngx_http_output_filter_module_ctx,    /* module context */
    ngx_http_output_filter_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init module */
    NULL                                   /* init child */
};


#define ngx_next_filter  (*ngx_http_top_body_filter)

#define need_to_copy(r, hunk)                                             \
            (((r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY)                \
               && (hunk->type & NGX_HUNK_IN_MEMORY) == 0)                 \
             || ((r->filter & NGX_HTTP_FILTER_NEED_TEMP)                  \
                  && (hunk->type & (NGX_HUNK_MEMORY|NGX_HUNK_MMAP))))



int ngx_http_output_filter(ngx_http_request_t *r, ngx_hunk_t *hunk)
{
    int                             rc, last;
    ssize_t                         size;
    ngx_chain_t                     out, *ce, **le;
    ngx_http_output_filter_ctx_t   *ctx;
    ngx_http_output_filter_conf_t  *conf;

    ctx = ngx_http_get_module_ctx(r->main ? r->main : r,
                                            ngx_http_output_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_output_filter_module,
                            sizeof(ngx_http_output_filter_ctx_t), NGX_ERROR);
        ctx->last_out = &ctx->out;
    }

    /*
     * the short path for the case when the chain ctx->in is empty
     * and there's no hunk or the hunk does not require the copy
     */

    if (ctx->in == NULL) {

        if (hunk == NULL) {
            return ngx_next_filter(r, NULL);
        }

        if (!need_to_copy(r, hunk)) {
            out.hunk = hunk;
            out.next = NULL;
            return ngx_next_filter(r, &out);
        }
    }

    /* add the incoming hunk to the chain ctx->in */

    if (hunk) {
        le = &ctx->in;

        for (ce = ctx->in; ce; ce = ce->next) {
            le = &ce->next;
        }

        ngx_add_hunk_to_chain(ce, hunk, r->pool, NGX_ERROR);
        *le = ce;
    }

    conf = ngx_http_get_module_loc_conf(r->main ? r->main : r,
                                        ngx_http_output_filter_module);

    last = NGX_NONE;

    for ( ;; ) {

        while (ctx->in) {

            if (!need_to_copy(r, ctx->in->hunk)) {

                /* move the chain entry to the chain ctx->out */

                ce = ctx->in;
                ctx->in = ce->next;

                *ctx->last_out = ce;
                ctx->last_out = &ce->next;
                ce->next = NULL;

                continue;
            }

            if (ctx->hunk == NULL) {

                /* get the free hunk */

                if (ctx->free) {
                    ctx->hunk = ctx->free->hunk;
                    ctx->free = ctx->free->next;

                } else if (ctx->hunks < conf->bufs.num) {
                    ngx_test_null(ctx->hunk,
                                  ngx_create_temp_hunk(r->pool, conf->bufs.size,
                                                       0, 0),
                                  NGX_ERROR);
                    ctx->hunk->type |= NGX_HUNK_RECYCLED;
                    ctx->hunks++;

                } else {
                    break;
                }
            }

            rc = ngx_http_output_filter_copy_hunk(ctx->hunk, ctx->in->hunk);

            if (rc == NGX_ERROR) {
                return rc;
            }

#if (NGX_FILE_AIO_READ)
            if (rc == NGX_AGAIN) {
                return rc;
            }
#endif

            if (ctx->in->hunk->type & NGX_HUNK_IN_MEMORY) {
                size = ctx->in->hunk->last - ctx->in->hunk->pos;

            } else {
                size = (size_t) (ctx->in->hunk->file_last
                                                    - ctx->in->hunk->file_pos);
            }

            /* delete the completed hunk from the chain ctx->in */

            if (size == 0) {
                ctx->in = ctx->in->next;
            }

            ngx_add_hunk_to_chain(ce, ctx->hunk, r->pool, NGX_ERROR);
            *ctx->last_out = ce;
            ctx->last_out = &ce->next;
            ctx->hunk = NULL;
        }

        if (ctx->out == NULL && last != NGX_NONE) {
            return last;
        }

        last = ngx_next_filter(r, ctx->out);

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out);
        ctx->last_out = &ctx->out;
    }
}


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src)
{
    ssize_t  n, size;

    if (src->type & NGX_HUNK_IN_MEMORY) {
        size = src->last - src->pos;
    } else {
        size = (size_t) (src->file_last - src->file_pos);
    }

    if (size > (dst->end - dst->pos)) {
        size = dst->end - dst->pos;
    }

    if (src->type & NGX_HUNK_IN_MEMORY) {
        ngx_memcpy(dst->pos, src->pos, size);
        src->pos += size;
        dst->last += size;

        if (src->type & NGX_HUNK_FILE) {
            src->file_pos += size;
        }

        if ((src->type & NGX_HUNK_LAST) && src->pos == src->last) {
            dst->type |= NGX_HUNK_LAST;
        }

    } else {
        n = ngx_read_file(src->file, dst->pos, size, src->file_pos);

if (n == 0) {
ngx_log_debug(src->file->log, "READ: %qd:%qd %X:%X %X:%X" _
              src->file_pos _ src->file_last _
              dst->pos _ dst->last _ dst->start _ dst->end);
}

        if (n == NGX_ERROR) {
            return n;
        }

#if (NGX_FILE_AIO_READ)
        if (n == NGX_AGAIN) {
            return n;
        }
#endif

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, src->file->log, 0,
                          ngx_read_file_n " reads only %d of %d from file",
                          n, size);
            if (n == 0) {
                return NGX_ERROR;
            }
        }

        src->file_pos += n;
        dst->last += n;

        if ((src->type & NGX_HUNK_LAST) && src->file_pos == src->file_last) {
            dst->type |= NGX_HUNK_LAST;
        }
    }

    return NGX_OK;
}


static void *ngx_http_output_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_output_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_palloc(cf->pool, sizeof(ngx_http_output_filter_conf_t)),
                  NULL);

    conf->bufs.num = 0;

    return conf;
}


static char *ngx_http_output_filter_merge_conf(ngx_conf_t *cf,
                                               void *parent, void *child)
{
    ngx_http_output_filter_conf_t *prev = parent;
    ngx_http_output_filter_conf_t *conf = child;

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 2, 32768);

    return NULL;
}
