
#include <ngx_config.h>

#include <ngx_hunk.h>
#include <ngx_http.h>
#include <ngx_http_filter.h>
#include <ngx_event_write.h>

#include <ngx_http_write_filter.h>


ngx_http_module_t  ngx_http_write_filter_module;


/* STUB */
static ngx_http_write_filter_ctx_t module_ctx;

void ngx_http_write_filter_init()
{
     module_ctx.buffer_output = 10240;
     module_ctx.out = NULL;

     ngx_http_write_filter_module.ctx = &module_ctx;
}
/* */


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int    last;
    off_t  size, flush;
    ngx_chain_t  *ch, **prev, *chain;
    ngx_http_write_filter_ctx_t  *ctx;

    ctx = (ngx_http_write_filter_ctx_t *)
                              ngx_get_module_ctx(r->main ? r->main : r,
                                                 &ngx_http_write_filter_module);
    size = flush = 0;
    last = 0;
    prev = &ctx->out;

    /* find size, flush point and last link of saved chain */
    for (ch = ctx->out; ch; ch = ch->next) {
        prev = &ch->next;
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "old chunk: %x " QX_FMT " " QD_FMT _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & NGX_HUNK_FLUSH)
            flush = size;

        if (ch->hunk->type & NGX_HUNK_LAST)
            last = 1;
    }

    /* add new chain to existent one */
    for (/* void */; in; in = in->next) {
        ngx_test_null(ch, ngx_palloc(r->pool, sizeof(ngx_chain_t)), NGX_ERROR);

        ch->hunk = in->hunk;
        ch->next = NULL;
        *prev = ch;
        prev = &ch->next;
        size += ch->hunk->last.file - ch->hunk->pos.file;

        ngx_log_debug(r->connection->log, "new chunk: %x " QX_FMT " " QD_FMT _
                      ch->hunk->type _ ch->hunk->pos.file _
                      ch->hunk->last.file - ch->hunk->pos.file);

        if (ch->hunk->type & NGX_HUNK_FLUSH)
            flush = size;

        if (ch->hunk->type & NGX_HUNK_LAST)
            last = 1;
    }

    if (!last && flush == 0 && size < ctx->buffer_output)
        return NGX_OK;

    chain = ngx_event_write(r->connection, ctx->out, flush);
    if (chain == (ngx_chain_t *) -1)
        return NGX_ERROR;

    ctx->out = chain;

    return (chain ? NGX_AGAIN : NGX_OK);
}
