

#include <ngx_hunk.h>
#include <ngx_http.h>
#include <ngx_http_filter.h>


ngx_http_module_t  ngx_http_filter_module;


/* STUB */
static ngx_http_filter_ctx_t module_ctx;

void ngx_http_filter_init()
{
     module_ctx.hunk_size = 32 * 1024;
     module_ctx.out.hunk = NULL;
     module_ctx.out.next = NULL;
     module_ctx.next_filter = ngx_http_write_filter;

     ngx_http_filter_module.ctx = &module_ctx;
}
/* */


/*
int ngx_http_filter(ngx_http_request_t *r, ngx_chain_t *in)
*/

/*
    flags NGX_HUNK_RECYCLED, NGX_HUNK_FLUSH, NGX_HUNK_LAST
*/

int ngx_http_filter(ngx_http_request_t *r, ngx_hunk_t *hunk)
{
    int      rc;
    size_t   size;
    ssize_t  n;
    ngx_chain_t  *ce;
    ngx_http_filter_ctx_t  *ctx;

    ctx = (ngx_http_filter_ctx_t *)
                              ngx_get_module_ctx(r->main ? r->main : r,
                                                      &ngx_http_filter_module);

    if (hunk && (hunk->type & NGX_HUNK_LAST))
        ctx->last = 1;

    /* input chain is not empty */
    if (ctx->in) {

        while (ctx->in) {

            /* add hunk to input chain */
            if (hunk) {
                for (ce = ctx->in; ce->next; ce = ce->next)
                    /* void */ ;

                ngx_add_hunk_to_chain(ce->next, hunk, r->pool,
                                      NGX_ERROR);
            }

            /* our hunk is still busy */
            if (ctx->hunk->pos.mem < ctx->hunk->last.mem) {
                rc = ctx->next_filter(r, NULL);

            /* our hunk is free */
            } else {
                ctx->out.hunk = ctx->hunk;

                rc = ngx_http_filter_copy_hunk(ctx->hunk, ctx->in->hunk);
#if (NGX_FILE_AIO)
                if (rc == NGX_AGAIN)
                    return rc;
#endif
                if (rc == NGX_ERROR)
                    return rc;

                /* whole hunk is copied so we send to next filter chain part
                   up to next hunk that need to be copied */
                if (ctx->in->hunk->pos.mem == ctx->in->hunk->last.mem) {
                    ctx->out.next = ctx->in->next;

                    for (ce = ctx->in->next; ce; ce = ce->next) {
                        if (ce->type & NGX_HUNK_FILE)
                            break;

                        if ((ce->type & NGX_HUNK_MEMORY|NGX_HUNK_MMAP)
                            && (r->filter & NGX_HTTP_FILTER_NEED_TEMP))
                            break;
                    }

                    ctx->out.next = ce;

                } else {
                    ctx->out.next = NULL;
                }

                rc = ctx->next_filter(r, &ctx->out);
            }

            if (rc == NGX_OK)
                ctx->hunk->pos.mem = ctx->hunk->last.mem = ctx->hunk->start;
            else
                return rc;
        }

    /* input chain is empty */
    } else {

        if (hunk == NULL) {
            rc = ctx->next_filter(r, NULL);

        } else {

            /* we need to copy hunk to our hunk */
            if (((r->filter & NGX_HTTP_FILTER_NEED_IN_MEMORY)
                    && (hunk->type & NGX_HUNK_FILE))
                || ((r->filter & NGX_HTTP_FILTER_NEED_TEMP)
                    && (hunk->type & NGX_HUNK_MEMORY|NGX_HUNK_MMAP))
               ) {

                /* out hunk is still busy */
                if (ctx->hunk && ctx->hunk->pos.mem < ctx->hunk->last.mem) {
                    ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                          NGX_ERROR);

                    rc = ctx->next_filter(r, NULL);

                } else {
                    if (ctx->hunk == NULL) {

                        if (hunk->type & NGX_HUNK_LAST) {
                            size = hunk->last.mem - hunk->pos.mem;
                            if (size > ctx->hunk_size)
                                size = ctx->hunk_size;

                        } else {
                            size = ctx->hunk_size;
                        }

                        ngx_test_null(ctx->hunk,
                                      ngx_create_temp_hunk(r->pool, size,
                                          50, 50),
                                      NGX_ERROR);

                        rc = ngx_http_filter_copy_hunk(ctx->hunk,
                                                       ctx->in->hunk);
#if (NGX_FILE_AIO)
                        if (rc == NGX_AGAIN) {
                            /* add hunk to input chain */
                            ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                                  NGX_ERROR);

                            return rc;
                        }
#endif
                        if (rc == NGX_ERROR)
                            return rc;

                        if (ctx->in->hunk->pos.mem < ctx->in->hunk->last.mem)
                            ngx_add_hunk_to_chain(ctx->in, hunk, r->pool,
                                                  NGX_ERROR);

                        ctx->out.hunk = ctx->hunk;
                        ctx->out.next = NULL;

                        rc = ctx->next_filter(r, &ctx->out);
                    }
                }

            } else {
                ctx->out.hunk = hunk;
                ctx->out.next = NULL;

                rc = ctx->next_filter(r, &ctx->out);

            }
        }
    }

    if (rc == NGX_OK && ctx->last) {
        /* STUB */
        return NGX_ERROR;
    }

    if (rc == NGX_OK) {
        ctx->hunk->pos.mem = ctx->hunk->last.mem = ctx->hunk->start;
#if level_event
        ngx_del_event(r->connection->write, NGX_WRITE_EVENT);
#endif
    }

    return rc;
}


int ngx_http_filter_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src, ngx_log_t *log)
{
    size_t  size;

    size = hunk->last.mem - hunk->pos.mem;
    if (size > dst->end - dst->pos.mem)
        size = dst->end - dst->pos.mem;

    if (src->type & NGX_HUNK_FILE) {
        n = ngx_read_file(src->handle, dst->pos.mem, size);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          ngx_read_file_n " failed for client");
            return NGX_ERROR;

        } else {
            ngx_assert((n == size), /* void */ ; , log,
                       ngx_read_file_n " reads only %d of %d for client" _
                       n _ size);
        }

        src->pos.mem += n;
        dst->last.mem += n;

    } else {
        ngx_memcpy(src->pos.mem, dst->pos.mem, size);

        src->pos.mem += size;
        dst->last.mem += size;
    }

    return NGX_OK;
}





    /* if no hunk is passed and there is no our hunk
       or our hunk is still busy then call next filter */
    if (hunk == NULL
        && (ctx->hunk == NULL
            || ((ctx->hunk != NULL)
                && (ctx->hunk->pos.mem < ctx->hunk->last.mem))
           )
       )
        ctx->next_filter(r, NULL);
    }
}
