


ngx_http_module_t  ngx_http_filter_module;


/* STUB */
static ngx_http_filter_ctx_t module_ctx;

void ngx_http_filter_init()
{
     module_ctx.buffer_output = 10240;
     module_ctx.out = NULL;
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
    enum { NO = 0, COPY, FILE } temp;

    ngx_http_write_ctx_t  *ctx;

    ctx = (ngx_http_filter_ctx_t *)
                              ngx_get_module_ctx(r->main ? r->main : r,
                                                      &ngx_http_filter_module);



    if (hunk == NULL)
        if (in == NULL)
            next_filter(NULL);
        else





    if (hunk != NULL)
        if (in == NULL)
            if (temp == NO)
                fast_chain = hunk;
                next_filter(fast_chain);
            else
                if (ctx->hunk busy)
                    add hunk to ctx->in
                    next_filter(NULL);
                else
                    if (hunk > ctx->hunk)
                        copy hunk part to ctx->hunk
                        add hunk to ctx->in
                    else
                        copy hunk to ctx->hunk
                    fast_chain = ctx->hunk
                    next_filter(fast_chain);

        else /* in != NULL */
           add hunk to ctx->in





            



    if ((r->filter & NGX_FILT_NEED_IN_MEMORY) && (hunk->type & NGX_HUNK_FILE))
        temp = FILE;

    else if ((r->filter & NGX_FILT_NEED_TEMP)
             && (hunk->type & NGX_HUNK_MEMORY|NGX_HUNK_MMAP))
        temp = COPY;

    if (temp) {
        size = hunk->last.mem - hunk->pos.mem;

        if (hunk->type & NGX_HUNK_LAST) {
            if (size > ctx->hunk_size)
                size = ctx->hunk_size;

            hunk_size = size;

        } else {
            hunk_size = ctx->hunk_size;
        }
    }

    if (!ctx->hunk)
        ngx_test_null(ctx->hunk, ngx_create_temp_hunk(hunk_size), ...);

    if (temp == FILE) {
        n = ngx_read_file(hunk->fd, ctx->hunk->pos.mem, size);

        if (n == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_read_file_n " failed for client");
            return -1;

        } else {
            ngx_assert((n == size), /* void */ ; ,
                       r->connection->log, 0,
                       ngx_read_file_n " reads only %d of %d for client",
                       n, size);
        }

        hunk->pos.mem += n;
        ctx->hunk->last.mem += n;

    } else if (temp == COPY) {
        ngx_memcpy(ctx->hunk->pos.mem, hunk->pos.mem, size);

        hunk->pos.mem += size;
        ctx->hunk->last.mem += size;
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

    /* hunk != NULL || ctx->hunk->pos.mem == ctx->hunk->last.mem */

    /* find last link of saved chain */
    prev = &ctx->out;
    for (ch = ctx->out; ch; ch = ch->next) {
        prev = &ch->next;
    }

    if hunk
        if need our hunk - alloc it and add to our queue
        else add hunk to our queue

/*
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "old chunk: %x %qx %qd" _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & NGX_HUNK_FLUSH)
            flush = size;

        if (ch->hunk->type & NGX_HUNK_LAST)
            last = 1;
    }
*/

    /* add new chain to existent one */
    for (/* void */; in; in = in->next) {
        ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)),
                      NGX_HTTP_FILTER_ERROR);

        ch->hunk = h;
        ch->next = NULL;
        *prev = ch;
        prev = &ch->next;
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "new chunk: %x %qx %qd" _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & NGX_HUNK_FLUSH)
            flush = size;

        if (ch->hunk->type & NGX_HUNK_LAST)
            last = 1;
    }





/*
    !(HAVE_SENDFILE) == NGX_FILT_NEED_IN_MEMORY
*/

    if ((r->filter & NGX_FILT_NEED_IN_MEMORY) && (h->type & NGX_HUNK_FILE)) {

        size = h->last.mem - h->pos.mem;
        if (size > ctx->hunk_size)
            size = ctx->hunk_size;

        if (!ctx->hunk)
            ngx_test_null(ctx->hunk, ngx_create_temp_hunk(size), ...);

        ngx_read_file(h->fd, ctx->hunk->pos.mem, size);

        h->hunk->pos.mem += size;
    }

    if ((r->filter & NGX_FILT_NEED_TEMP)
        && (h->type & NGX_HUNK_MEMORY|NGX_HUNK_MMAP))
    {
        size = h->last.mem - h->pos.mem;
        if (size > ctx->hunk_size)
            size = ctx->hunk_size;

        if (!ctx->hunk)
            ngx_test_null(ctx->hunk, ngx_create_temp_hunk(size), ...);

        ngx_memcpy(ctx->hunk->pos.mem, h->pos.mem, size);

        h->hunk->pos.mem += size;
    }






    rc = ctx->next_filter(r, ch);

    /* STUB */
    rc = ngx_http_write_filter(r, ch);
}
