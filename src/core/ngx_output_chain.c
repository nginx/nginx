
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_NONE      1


ngx_inline static ngx_int_t
    ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
static ngx_int_t ngx_output_chain_copy_buf(ngx_buf_t *dst, ngx_buf_t *src,
                                           ngx_uint_t sendfile);


ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
{
    int           rc, last;
    size_t        size, bsize;
    ngx_chain_t  *cl, *out, **last_out;

    /*
     * the short path for the case when the ctx->in chain is empty
     * and the incoming chain is empty too or it has the single buf
     * that does not require the copy
     */

    if (ctx->in == NULL) {

        if (in == NULL) {
            return ctx->output_filter(ctx->filter_ctx, in);
        }

        if (in->next == NULL
            && (!ngx_output_chain_need_to_copy(ctx, in->buf)))
        {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */

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

            /*
             * cycle while there are the ctx->in bufs
             * or there are the free output bufs to copy in
             */

            bsize = ngx_buf_size(ctx->in->buf);

            if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {

                ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf");

                ctx->in = ctx->in->next;

                continue;
            }

            if (!ngx_output_chain_need_to_copy(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            if (ctx->buf == NULL) {

                /* get the free buf */

                if (ctx->free) {
                    ctx->buf = ctx->free->buf;
                    ctx->free = ctx->free->next;

                } else if (out || ctx->allocated == ctx->bufs.num) {

                    break;

                } else {

                    size = ctx->bufs.size;

                    if (ctx->in->buf->last_buf) {

                        if (bsize < ctx->bufs.size) {

                           /*
                            * allocate small temp buf for the small last buf
                            * or its small last part
                            */

                            size = bsize;

                        } else if (ctx->bufs.num == 1
                                   && (bsize < ctx->bufs.size
                                                     + (ctx->bufs.size >> 2)))
                        {
                            /*
                             * allocate a temp buf that equals
                             * to the last buf if the last buf size is lesser
                             * than 1.25 of bufs.size and a temp buf is single
                             */

                            size = bsize;
                        }
                    }

                    if (!(ctx->buf = ngx_create_temp_buf(ctx->pool, size))) {
                        return NGX_ERROR;
                    }

                    ctx->buf->tag = ctx->tag;
                    ctx->buf->recycled = 1;
                    ctx->allocated++;
                }
            }

            rc = ngx_output_chain_copy_buf(ctx->buf, ctx->in->buf,
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

            /* delete the completed buf from the ctx->in chain */

            if (ngx_buf_size(ctx->in->buf) == 0) {
                ctx->in = ctx->in->next;
            }

            ngx_alloc_link_and_set_buf(cl, ctx->buf, ctx->pool, NGX_ERROR);
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != NGX_NONE) {
            return last;
        }

        last = ctx->output_filter(ctx->filter_ctx, out);

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &out, ctx->tag);
        last_out = &out;

        if (last == NGX_ERROR) {
            return last;
        }
    }
}


ngx_inline static ngx_int_t
    ngx_output_chain_need_to_copy(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
{
    if (ngx_buf_special(buf)) {
        return 0;
    }

    if (!ctx->sendfile) {
        if (!ngx_buf_in_memory(buf)) {
            return 1;
        }

        buf->in_file = 0;
    }

    if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
        return 1;
    }

    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 1;
    }

    return 0;
}


static ngx_int_t ngx_output_chain_copy_buf(ngx_buf_t *dst, ngx_buf_t *src,
                                           ngx_uint_t sendfile)
{
    size_t   size;
    ssize_t  n;

    size = ngx_buf_size(src);

    if (size > (size_t) (dst->end - dst->pos)) {
        size = dst->end - dst->pos;
    }

    if (ngx_buf_in_memory(src)) {
        ngx_memcpy(dst->pos, src->pos, size);
        src->pos += size;
        dst->last += size;

        if (src->in_file) {
            src->file_pos += size;
        }

        if (src->last_buf && src->pos == src->last) {
            dst->last_buf = 1;
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
            dst->in_file = 0;
        }

        if (src->last_buf && src->file_pos == src->file_last) {
            dst->last_buf = 1;
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_chain_writer(void *data, ngx_chain_t *in)
{
    ngx_chain_writer_ctx_t *ctx = data;

    ngx_chain_t  *cl;


    for (/* void */; in; in = in->next) {

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                       "WRITER buf: %d", ngx_buf_size(in->buf));

        ngx_alloc_link_and_set_buf(cl, in->buf, ctx->pool, NGX_ERROR);
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                   "WRITER0: %X", ctx->out);

    ctx->out = ngx_send_chain(ctx->connection, ctx->out, ctx->limit);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->connection->log, 0,
                   "WRITER1: %X", ctx->out);

    if (ctx->out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;
        return NGX_OK;
    }

    return NGX_AGAIN;
}
