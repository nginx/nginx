
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_NONE      1


ngx_inline static int ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx,
                                                    ngx_hunk_t *hunk);
static int ngx_output_chain_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src,
                                      u_int sendfile);


int ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    int           rc, last;
    size_t        size, hsize;
    ngx_chain_t  *cl, *out, **last_out;

    /*
     * the short path for the case when the chain ctx->in is empty
     * and the incoming chain is empty too or it has the single hunk
     * that does not require the copy
     */

    if (ctx->in == NULL) {

        if (in == NULL) {
            return ctx->output_filter(ctx->output_ctx, in);
        }

        if (in->next == NULL
            && (!ngx_output_chain_need_to_copy(ctx, in->hunk)))
        {
            return ctx->output_filter(ctx->output_ctx, in);
        }
    }

    /* add the incoming hunk to the chain ctx->in */

    if (in) {
        if (ngx_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    last = NGX_NONE;
    out = NULL;
    last_out = &out;

    for ( ;; ) {

        while (ctx->in) {

            if (!ngx_output_chain_need_to_copy(ctx, ctx->in->hunk)) {

                /* move the chain link to the chain out */

                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            if (ctx->hunk == NULL) {

                /* get the free hunk */

                if (ctx->free) {
                    ctx->hunk = ctx->free->hunk;
                    ctx->free = ctx->free->next;

                } else if (ctx->hunks < ctx->bufs.num) {

                    size = ctx->bufs.size;

                    if (ctx->in->hunk->type & NGX_HUNK_LAST) {

                        hsize = ngx_hunk_size(ctx->in->hunk);

                        if (hsize < ctx->bufs.size) {

                           /*
                            * allocate small temp hunk for the small last hunk
                            * or its small last part
                            */

                            size = hsize;

                        } else if (ctx->bufs.num == 1
                                   && (hsize < ctx->bufs.size
                                                     + (ctx->bufs.size >> 2)))
                        {
                            /*
                             * allocate a temp hunk that equals
                             * to the last hunk if the last hunk size is lesser
                             * than 1.25 of bufs.size and a temp hunk is single
                             */

                            size = hsize;
                        }
                    }

                    ngx_test_null(ctx->hunk,
                                  ngx_create_temp_hunk(ctx->pool, size),
                                  NGX_ERROR);
                    ctx->hunk->tag = ctx->tag;
                    ctx->hunk->type |= NGX_HUNK_RECYCLED;
                    ctx->hunks++;

                } else {
                    break;
                }
            }

            rc = ngx_output_chain_copy_hunk(ctx->hunk, ctx->in->hunk,
                                            ctx->sendfile);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (rc == NGX_AGAIN) {
                if (out) {
                    break;
                }
                return rc;
            }

            /* delete the completed hunk from the chain ctx->in */

            if (ngx_hunk_size(ctx->in->hunk) == 0) {
                ctx->in = ctx->in->next;
            }

            ngx_alloc_link_and_set_hunk(cl, ctx->hunk, ctx->pool, NGX_ERROR);
            *last_out = cl;
            last_out = &cl->next;
            ctx->hunk = NULL;

            if (ctx->free == NULL) {
                break;
            }
        }

        if (out == NULL && last != NGX_NONE) {
            return last;
        }

        last = ctx->output_filter(ctx->output_ctx, out);

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &out, ctx->tag);
        last_out = &out;
    }
}


ngx_inline static int ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx,
                                                    ngx_hunk_t *hunk)
{
    if (ngx_hunk_special(hunk)) {
        return 0;
    }

    if (!ctx->sendfile) {
        if (!(hunk->type & NGX_HUNK_IN_MEMORY)) {
            return 1;
        }

        hunk->type &= ~NGX_HUNK_FILE;
    }

    if (ctx->need_in_memory && (!(hunk->type & NGX_HUNK_IN_MEMORY))) {
        return 1;
    }


    if (ctx->need_in_temp && (hunk->type & (NGX_HUNK_MEMORY|NGX_HUNK_MMAP))) {
        return 1;
    }

    return 0;
}


static int ngx_output_chain_copy_hunk(ngx_hunk_t *dst, ngx_hunk_t *src,
                                      u_int sendfile)
{
    size_t   size;
    ssize_t  n;

    size = ngx_hunk_size(src);

    if (size > (size_t) (dst->end - dst->pos)) {
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

        if (n == NGX_ERROR) {
            return n;
        }

#if (NGX_FILE_AIO_READ)
        if (n == NGX_AGAIN) {
            return n;
        }
#endif

        if ((size_t) n != size) {
            ngx_log_error(NGX_LOG_ALERT, src->file->log, 0,
                          ngx_read_file_n " reads only %d of %d from file",
                          n, size);
            if (n == 0) {
                return NGX_ERROR;
            }
        }

        src->file_pos += n;
        dst->last += n;

        if (!sendfile) {
            dst->type &= ~NGX_HUNK_FILE;
        }

        if ((src->type & NGX_HUNK_LAST) && src->file_pos == src->file_last) {
            dst->type |= NGX_HUNK_LAST;
        }
    }

    return NGX_OK;
}


int ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;

    ngx_chain_t  *cl;


    for (/* void */; in; in = in->next) {
        ngx_alloc_link_and_set_hunk(cl, in->hunk, ctx->pool, NGX_ERROR);
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    ctx->out = ngx_write_chain(ctx->connection, ctx->out);

    if (ctx->out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;
        return NGX_OK;
    }

    return NGX_AGAIN;
}
