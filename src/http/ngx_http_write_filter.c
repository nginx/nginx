
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hunk.h>
#include <ngx_event_write.h>
#include <ngx_http.h>
#include <ngx_http_output_filter.h>
#include <ngx_http_write_filter.h>


ngx_http_module_t  ngx_http_write_filter_module = {
    NGX_HTTP_MODULE
};


/* STUB */
/* */


int ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int    last;
    off_t  size, flush;
    ngx_chain_t  *ch, **prev, *chain;
    ngx_http_write_filter_ctx_t  *ctx;
    ngx_http_write_filter_conf_t *conf;


    ctx = (ngx_http_write_filter_ctx_t *)
                              ngx_get_module_ctx(r->main ? r->main : r,
                                                 ngx_http_write_filter_module);
    if (ctx == NULL)
        ngx_test_null(ctx,
                      ngx_pcalloc(r->pool, sizeof(ngx_http_write_filter_ctx_t)),
                      NGX_ERROR);

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

        if (ch->hunk->type & NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)
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

        if (ch->hunk->type & NGX_HUNK_FLUSH|NGX_HUNK_RECYCLED)
            flush = size;

        if (ch->hunk->type & NGX_HUNK_LAST)
            last = 1;
    }

    conf = (ngx_http_write_filter_conf_t *)
                   ngx_get_module_loc_conf(r->main ? r->main : r,
                                                ngx_http_write_filter_module);

    if (!last && flush == 0 && size < conf->buffer_output)
        return NGX_OK;

    chain = ngx_event_write(r->connection, ctx->out, flush);
    if (chain == (ngx_chain_t *) -1)
        return NGX_ERROR;

    ctx->out = chain;

    ngx_log_debug(r->connection->log, "write filter %x" _ chain);

    return (chain ? NGX_AGAIN : NGX_OK);
}


static void *ngx_http_write_filter_create_conf(ngx_pool_t *pool)
{
    ngx_http_write_filter_conf_t *conf;

    ngx_test_null(conf,
                  ngx_pcalloc(pool, sizeof(ngx_http_write_filter_conf_t)),
                  NULL);

    conf->buffer_output = 16384;
}

static void *ngx_http_write_filter_set_hunk_size(ngx_pool_t *pool, void *conf,
                                                  char *size)
{
    ngx_http_write_filter_conf_t *cf = (ngx_http_write_filter_conf_t *) conf;

    cf->buffer_output = atoi(size);
    if (cf->buffer_output <= 0)
        return "Error";

    cf->buffer_output *= 1024;
    return NULL;
}

