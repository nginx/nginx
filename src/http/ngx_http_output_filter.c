
#include <ngx_config.h>

#include <ngx_core.h>
#include <ngx_files.h>
#include <ngx_string.h>
#include <ngx_hunk.h>
#include <ngx_conf_file.h>

#include <ngx_http.h>
#include <ngx_http_config.h>
#include <ngx_http_output_filter.h>


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src);
static void *ngx_http_output_filter_create_conf(ngx_pool_t *pool);
static char *ngx_http_output_filter_merge_conf(ngx_pool_t *pool,
                                               void *parent, void *child);


static ngx_command_t  ngx_http_output_filter_commands[] = {

    {ngx_string("output_buffer"),
     NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_output_filter_conf_t, hunk_size)},

    {ngx_string(""), 0, NULL, 0, 0}
};


static ngx_http_module_t  ngx_http_output_filter_module_ctx = {
    NGX_HTTP_MODULE,

    NULL,                                  /* create server config */
    NULL,                                  /* init server config */
    ngx_http_output_filter_create_conf,    /* create location config */
    ngx_http_output_filter_merge_conf,     /* merge location config */

    NULL,                                  /* translate handler */

    NULL,                                  /* output header filter */
    NULL,                                  /* next output header filter */
    (int (*)(ngx_http_request_t *, ngx_chain_t *))
        ngx_http_output_filter,            /* output body filter */
    NULL                                   /* next output body filter */
};


ngx_module_t  ngx_http_output_filter_module = {
    0,                                     /* module index */
    &ngx_http_output_filter_module_ctx,    /* module context */
    ngx_http_output_filter_commands,       /* module directives */
    NGX_HTTP_MODULE_TYPE,                  /* module type */
    NULL                                   /* init module */
};


int ngx_http_output_filter(ngx_http_request_t *r, ngx_hunk_t *hunk)
{
    int      rc, once;
    size_t   size;
    ssize_t  n;
    ngx_chain_t  *ce;
    ngx_http_output_filter_ctx_t  *ctx;
    ngx_http_output_filter_conf_t *conf;

    ctx = (ngx_http_output_filter_ctx_t *)
                    ngx_http_get_module_ctx(r->main ? r->main : r,
                                            ngx_http_output_filter_module);

    if (ctx == NULL) {
        ngx_http_create_ctx(r, ctx, ngx_http_output_filter_module,
                            sizeof(ngx_http_output_filter_ctx_t));
    }

    if (hunk && (hunk->type & NGX_HUNK_LAST)) {
        ctx->last = 1;
    }

    for (once = 1; once || ctx->in; once = 0) {

         /* input chain is not empty */
        if (ctx->in) {

            /* add hunk to input chain */
            if (once && hunk) {
                for (ce = ctx->in; ce->next; ce = ce->next) {
                    /* void */ ;
                }

                ngx_add_hunk_to_chain(ce->next, hunk, r->pool, NGX_ERROR);
            }

            /* our hunk is still busy */
            if (ctx->hunk->pos.mem < ctx->hunk->last.mem) {
                rc = ngx_http_output_filter_module_ctx.
                                              next_output_body_filter(r, NULL);

            /* our hunk is free */
            } else {
                ctx->out.hunk = ctx->hunk;

                rc = ngx_http_output_filter_copy_hunk(ctx->hunk, ctx->in->hunk);
#if (NGX_FILE_AIO_READ)
                if (rc == NGX_AGAIN) {
                    return rc;
                }
#endif
                if (rc == NGX_ERROR) {
                    return rc;
                }

                /* whole hunk is copied so we send to next filter chain part
                   up to next hunk that need to be copied */
                if (ctx->in->hunk->pos.mem == ctx->in->hunk->last.mem) {
                    ctx->out.next = ctx->in->next;

                    for (ce = ctx->in->next; ce; ce = ce->next) {
                        if (ce->hunk->type & NGX_HUNK_FILE) {
                            break;
                        }

                        if ((ce->hunk->type & (NGX_HUNK_MEMORY|NGX_HUNK_MMAP))
                            && (r->filter & NGX_HTTP_FILTER_NEED_TEMP))
                        {
                            break;
                        }
                    }

                    ctx->out.next = ce;

                } else {
                    ctx->out.next = NULL;
                }

                rc = ngx_http_output_filter_module_ctx.
                                         next_output_body_filter(r, &ctx->out);
            }

            /* delete completed hunks from input chain */
            for (ce = ctx->in; ce; ce = ce->next) {
                 if (ce->hunk->pos.file == ce->hunk->last.file) {
                     ctx->in = ce->next;
                 }
            }

            if (rc == NGX_OK && ctx->hunk) {
                ctx->hunk->pos.mem = ctx->hunk->last.mem = ctx->hunk->start;
            } else {
                return rc;
            }

        /* input chain is empty */
        } else {

            if (hunk == NULL) {
                rc = ngx_http_output_filter_module_ctx.
                                              next_output_body_filter(r, NULL);

            } else {

                /* we need to copy hunk to our hunk */
                if (((r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY)
                        && (hunk->type & NGX_HUNK_FILE))
                    || ((r->filter & NGX_HTTP_FILTER_NEED_TEMP)
                        && (hunk->type & (NGX_HUNK_MEMORY|NGX_HUNK_MMAP)))
                   ) {

                    /* out hunk is still busy */
                    if (ctx->hunk && ctx->hunk->pos.mem < ctx->hunk->last.mem) {
                        ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                              NGX_ERROR);

                        rc = ngx_http_output_filter_module_ctx.
                                              next_output_body_filter(r, NULL);

                    } else {
                        if (ctx->hunk == NULL) {

                            if (hunk->type & NGX_HUNK_LAST) {

                                conf = (ngx_http_output_filter_conf_t *)
                                            ngx_http_get_module_loc_conf(
                                                r->main ? r->main : r,
                                                ngx_http_output_filter_module);

                                size = hunk->last.mem - hunk->pos.mem;
                                if (size > conf->hunk_size) {
                                    size = conf->hunk_size;
                                }

                            } else {
                                size = conf->hunk_size;
                            }

                            ngx_test_null(ctx->hunk,
                                          ngx_create_temp_hunk(r->pool, size,
                                                               50, 50),
                                          NGX_ERROR);
                            ctx->hunk->type |= NGX_HUNK_RECYCLED;

                            rc = ngx_http_output_filter_copy_hunk(ctx->hunk,
                                                                  hunk);
#if (NGX_FILE_AIO_READ)
                            if (rc == NGX_AGAIN) {
                                /* add hunk to input chain */
                                ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                                      NGX_ERROR);

                                return rc;
                            }
#endif
                            if (rc == NGX_ERROR) {
                                return rc;
                            }

                            if (hunk->pos.mem < hunk->last.mem) {
                                ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                                      NGX_ERROR);
                            }

                            ctx->out.hunk = ctx->hunk;
                            ctx->out.next = NULL;

                            rc = ngx_http_output_filter_module_ctx.
                                         next_output_body_filter(r, &ctx->out);
                        }
                    }

                } else {
                    ctx->out.hunk = hunk;
                    ctx->out.next = NULL;

                    rc = ngx_http_output_filter_module_ctx.
                                         next_output_body_filter(r, &ctx->out);
                }
            }
        }

        if (rc == NGX_OK && ctx->hunk)
            ctx->hunk->pos.mem = ctx->hunk->last.mem = ctx->hunk->start;
    }

    if (rc == NGX_OK && ctx->last) {
        return NGX_OK;
    }

    if (rc == NGX_OK) {
        if (ctx->hunk) {
            ctx->hunk->pos.mem = ctx->hunk->last.mem = ctx->hunk->start;
        }
#if (NGX_LEVEL_EVENT)
        ngx_del_event(r->connection->write, NGX_WRITE_EVENT);
#endif
    }

    return rc;
}


static int ngx_http_output_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src)
{
    size_t   size;
    ssize_t  n;

    size = src->last.mem - src->pos.mem;
    if (size > dst->end - dst->pos.mem) {
        size = dst->end - dst->pos.mem;
    }

    if (src->type & NGX_HUNK_FILE) {
        n = ngx_read_file(src->file, dst->pos.mem, size, src->pos.file);

        if (n == NGX_ERROR) {
            return n;

#if (NGX_FILE_AIO_READ)
        } else if (n == NGX_AGAIN) {
            return n;
#endif

        } else {
            ngx_assert((n == size), /* void */ ; , src->file->log,
                       ngx_read_file_n " reads only %d of %d" _
                       n _ size);
        }

        src->pos.mem += n;
        dst->last.mem += n;

    } else {
        ngx_memcpy(src->pos.mem, dst->pos.mem, size);

        src->pos.mem += size;
        dst->last.mem += size;
    }

    if (src->type & NGX_HUNK_LAST) {
        dst->type |= NGX_HUNK_LAST;
    }

    return NGX_OK;
}


static void *ngx_http_output_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_output_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_output_filter_conf_t)),
                  NULL);

    conf->hunk_size = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_output_filter_merge_conf(ngx_pool_t *pool,
                                               void *parent, void *child)
{
    ngx_http_output_filter_conf_t *prev =
                                      (ngx_http_output_filter_conf_t *) parent;
    ngx_http_output_filter_conf_t *conf =
                                       (ngx_http_output_filter_conf_t *) child;

    ngx_conf_merge(conf->hunk_size, prev->hunk_size, 32768);

    return NULL;
}
